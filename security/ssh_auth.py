"""SSH authentication log ingestion and persistent multi-window risk scoring.

PCAP is intentionally not an input here: ordinary SSH encryption does not
expose authentication results.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from shared.event_model import NormalizedEvent

WINDOWS = (60, 900, 3600, 86400)
_AUTH = re.compile(r"(?P<result>Failed|Accepted) (?P<method>password|publickey) for (?P<user>invalid user )?(?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+", re.I)
_INVALID = re.compile(r"Invalid user (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I)


@dataclass(frozen=True)
class AuthenticationEvent:
    timestamp: float
    source_ip: str
    username: str
    result: str
    method: str
    target_host: str
    event_type: str
    raw_source: str = ""

    def validate(self) -> "AuthenticationEvent":
        ipaddress.ip_address(self.source_ip)
        if not math.isfinite(float(self.timestamp)):
            raise ValueError("timestamp must be finite")
        if self.result not in {"SUCCESS", "FAILURE"}:
            raise ValueError("result must be SUCCESS or FAILURE")
        if self.method not in {"password", "publickey", "unknown"}:
            raise ValueError("unsupported authentication method")
        if not self.source_ip or not self.target_host:
            raise ValueError("source_ip and target_host are required")
        return self


def _timestamp(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def parse_json_event(value: dict | str) -> AuthenticationEvent:
    obj = json.loads(value) if isinstance(value, str) else value
    method = str(obj.get("method", obj.get("authentication_method", "unknown"))).lower()
    method = {"public-key":"publickey", "public_key":"publickey"}.get(method, method)
    result = str(obj.get("result", "")).upper()
    event_type = str(obj.get("event_type", "SSH_AUTH_" + result))
    return AuthenticationEvent(
        timestamp=_timestamp(obj["timestamp"]), source_ip=str(obj["source_ip"]),
        username=str(obj.get("username", "")), result=result, method=method,
        target_host=str(obj.get("target_host", obj.get("host", "localhost"))),
        event_type=event_type, raw_source="json",
    ).validate()


def parse_auth_log_line(line: str, *, year: int | None = None, target_host: str = "localhost") -> AuthenticationEvent | None:
    """Parse common OpenSSH auth.log / journal message forms."""
    match = _AUTH.search(line)
    event_type = ""
    if match:
        accepted = match.group("result").lower() == "accepted"
        result = "SUCCESS" if accepted else "FAILURE"
        method = match.group("method").lower()
        username = match.group("username")
        source_ip = match.group("ip")
        event_type = ("SSH_AUTH_INVALID_USER" if match.group("user") else
                      f"SSH_AUTH_{result}_{method.upper()}")
    else:
        invalid = _INVALID.search(line)
        if not invalid:
            return None
        result, method = "FAILURE", "unknown"
        username, source_ip = invalid.group("username"), invalid.group("ip")
        event_type = "SSH_AUTH_INVALID_USER"
    # journalctl -o short-iso and ISO-prefixed records have full timestamps.
    iso = re.match(r"^(\d{4}-\d\d-\d\d[T ][^ ]+)", line)
    if iso:
        stamp = _timestamp(iso.group(1))
    else:
        # auth.log syslog timestamp has no year/timezone; assume local machine
        # year and UTC because the collector must be configured to UTC for accuracy.
        syslog = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)", line)
        if not syslog:
            return None
        stamp = datetime.strptime(f"{year or datetime.now().year} {syslog.group(1)}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return AuthenticationEvent(stamp, source_ip, username, result, method, target_host, event_type, line.rstrip()).validate()


def read_auth_log(path: str | Path, *, target_host: str = "localhost") -> Iterator[AuthenticationEvent]:
    """Read standard auth.log; the caller can persist its cursor for tailing."""
    with Path(path).open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            event = parse_auth_log_line(line, target_host=target_host)
            if event:
                yield event


def read_journal(*, target_host: str = "localhost", since: str = "") -> Iterator[AuthenticationEvent]:
    """Read sshd journal records when systemd/journalctl is available."""
    command = ["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-o", "short-iso"]
    if since:
        command.extend(["--since", since])
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    for line in result.stdout.splitlines():
        event = parse_auth_log_line(line, target_host=target_host)
        if event:
            yield event


def ingest_events(conn, events: Iterable[AuthenticationEvent], *, half_life_seconds: float = 3600.0) -> list[dict]:
    """Persist deduplicated events and append a risk snapshot per new event."""
    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be positive")
    emitted = []
    for event in events:
        event.validate()
        fingerprint = hashlib.sha256(json.dumps(asdict(event), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        cur = conn.execute("""INSERT OR IGNORE INTO authentication_events
            (event_fingerprint,timestamp,source_ip,username,result,method,target_host,event_type,raw_source,inserted_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""", (fingerprint,event.timestamp,event.source_ip,event.username,event.result,event.method,event.target_host,event.event_type,event.raw_source,time.time()))
        if cur.rowcount == 0:
            continue
        cutoff = event.timestamp - max(WINDOWS)
        rows = conn.execute("SELECT timestamp,source_ip,username,result FROM authentication_events WHERE timestamp BETWEEN ? AND ?", (cutoff,event.timestamp)).fetchall()
        counts = {str(w): sum(r["result"] == "FAILURE" and event.timestamp-r["timestamp"] <= w for r in rows) for w in WINDOWS}
        # Decaying contributions retain historical evidence while avoiding hard lockout.
        risk = sum((2.0 if r["result"] == "FAILURE" else 0.0) * (0.5 ** ((event.timestamp-r["timestamp"])/half_life_seconds)) for r in rows)
        fail_rows = [r for r in rows if r["result"] == "FAILURE"]
        risk += min(2.0, max(0, len({r['source_ip'] for r in fail_rows})-1) * 0.35)
        risk += min(2.0, max(0, len({r['username'] for r in fail_rows})-1) * 0.25)
        reason = "failed authentication" if event.result == "FAILURE" else "successful authentication"
        if event.result == "SUCCESS" and counts["3600"] >= 5:
            risk += 2.0
            reason = "successful authentication following repeated failures"
        risk = round(min(100.0, risk), 4)
        conn.execute("INSERT INTO risk_history(timestamp,score,source_ip,username,window_counts,reason) VALUES (?,?,?,?,?,?)", (event.timestamp,risk,event.source_ip,event.username,json.dumps(counts,sort_keys=True),reason))
        emitted.append({"event": event, "risk_score": risk, "window_counts": counts, "reason": reason})
    conn.commit()
    return emitted


def ingest_auth_log(conn, path: str | Path, *, target_host: str = "localhost") -> list[dict]:
    """Convenience full read; unique fingerprints make safe re-reads idempotent."""
    return ingest_events(conn, read_auth_log(path, target_host=target_host))


def ingest_auth_log_incremental(conn, path: str | Path, *, target_host: str = "localhost") -> list[dict]:
    """Tail appended bytes and restart safely when the file is rotated/truncated."""
    source = Path(path)
    stat = source.stat()
    device, inode = str(getattr(stat, "st_dev", "")), str(getattr(stat, "st_ino", ""))
    cursor = conn.execute("SELECT device_id,inode_id,byte_offset FROM auth_log_cursors WHERE path=?", (str(source.resolve()),)).fetchone()
    offset = int(cursor["byte_offset"]) if cursor and cursor["device_id"] == device and cursor["inode_id"] == inode and stat.st_size >= cursor["byte_offset"] else 0
    with source.open("rb") as fh:
        fh.seek(offset)
        data = fh.read()
    last_newline = data.rfind(b"\n")
    complete, consumed = (data[:last_newline + 1], last_newline + 1) if last_newline >= 0 else (b"", 0)
    lines = complete.decode("utf-8", errors="replace").splitlines()
    events = [event for line in lines if (event := parse_auth_log_line(line, target_host=target_host))]
    out = ingest_events(conn, events)
    conn.execute("""INSERT INTO auth_log_cursors(path,device_id,inode_id,byte_offset,updated_at) VALUES (?,?,?,?,?)
        ON CONFLICT(path) DO UPDATE SET device_id=excluded.device_id,inode_id=excluded.inode_id,byte_offset=excluded.byte_offset,updated_at=excluded.updated_at""",
        (str(source.resolve()),device,inode,offset+consumed,time.time()))
    conn.commit()
    return out


def ingest_jsonl(conn, path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as fh:
        events = (parse_json_event(line) for line in fh if line.strip())
        return ingest_events(conn, events)


def risk_events(ingested: Iterable[dict], *, alert_threshold: float = 10.0) -> list[NormalizedEvent]:
    """Convert high-risk host-log evidence to canonical brute-force alerts."""
    alerts = []
    for item in ingested:
        event: AuthenticationEvent = item["event"]
        score = float(item["risk_score"])
        suspicious_success = event.result == "SUCCESS" and "following repeated failures" in item["reason"]
        if (event.result != "FAILURE" and not suspicious_success) or score < alert_threshold:
            continue
        counts = item["window_counts"]
        alerts.append(NormalizedEvent(
            timestamp=event.timestamp, source_ip=event.source_ip, destination_ip=event.target_host,
            protocol="TCP", event_type="SSH_SUSPICIOUS_SUCCESS" if suspicious_success else "SSH_BRUTE_FORCE", attack_stage="CREDENTIAL_ATTACK",
            evidence_source="HOST_AUTH_LOG", destination_port=22,
            severity="CRITICAL" if suspicious_success or score >= 25 else "HIGH" if score >= 15 else "MEDIUM",
            evidence_score=min(1.0, score/40.0), evidence={"risk_score": score, "username": event.username,
                "authentication_method": event.method, "event_type": event.event_type,
                "observation_windows": counts, "source": "OpenSSH authentication log"},
        ).validate())
    return alerts
