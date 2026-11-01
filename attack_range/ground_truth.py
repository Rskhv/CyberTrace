"""
CyberTrace — Attack Range module: ground-truth action logger.

This is the Attack Range sub-team's (Shaurya's) primary INTERFACE to the
rest of the system. While the three controlled scenarios run, this logger
records an authoritative, attacker-side account of *what was done and when*.

That record is used in exactly one place: evaluation (synopsis §12), where
Rishav's correlation engine compares its reconstructed timeline against this
log. It is NEVER read by the detectors or the correlation engine at run time.

Outputs (both describe the same actions):
  * JSON Lines  — one action per line, appended durably as actions happen.
                  Human-readable, diff-friendly, needs no DB.
  * SQLite      — a single `ground_truth` table (this module owns it; it is
                  separate from the `alerts`/`incidents` tables that the
                  detection/forensics modules own). Can live in its own file
                  or inside the shared cybertrace.db — the table name does
                  not collide with anyone else's.

Dependencies: Python standard library only (no third-party packages), so a
teammate can import and test this without the lab or any attack tooling.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterator, List, Optional, Sequence

# Import the SHARED vocabulary so ground-truth records stay aligned with the
# detector/correlation side. Support running both as a package and as a loose
# script (teammates may just copy the folder).
try:
    from ..shared.event_model import SCENARIO_TO_EVENT_TYPE
except (ImportError, ValueError):  # pragma: no cover - fallback for flat layout
    try:
        from shared.event_model import SCENARIO_TO_EVENT_TYPE
    except ImportError:
        # Last-resort mirror so the logger still runs if shared/ is absent.
        # Values match the canonical EVENT_TYPES in shared/event_model.py.
        SCENARIO_TO_EVENT_TYPE = {
            "recon": "PORT_SCAN",
            "ssh_bruteforce": "SSH_BRUTE_FORCE",
            "exploit": "EXPLOITATION",
        }

GROUND_TRUTH_SCHEMA_VERSION = "1.0.0"

STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_ABORTED = "aborted"


def _utc_iso(epoch: float) -> str:
    """ISO-8601 (with trailing Z) for a UTC instant given as epoch seconds."""
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


@dataclass
class GroundTruthAction:
    """One recorded attacker action.

    Field names are the ground-truth contract consumed by evaluation. The
    `expected_event_type` deliberately uses the SHARED EVENT_TYPES vocabulary
    so Rishav's engine can line each action up with the detector that should
    have fired for it.
    """

    action_id: int
    run_id: str
    scenario: str                       # "recon" | "ssh_bruteforce" | "exploit"
    technique: str                      # e.g. "tcp_syn_scan", "vsftpd_234_backdoor"
    tool: str                           # "nmap" | "hydra" | "metasploit" | ...
    expected_event_type: str            # from SHARED EVENT_TYPES
    src_ip: str                         # attacker (Kali)
    dst_ip: str                         # target (Metasploitable2)
    dst_ports: List[int]                # port(s) the action targeted
    protocol: str                       # "tcp" | "udp" | ...
    intent: str                         # plain-language description
    start_epoch: float
    end_epoch: Optional[float] = None
    start_utc: str = ""
    end_utc: Optional[str] = None
    status: str = STATUS_COMPLETED
    command: str = ""                   # for reproducibility (redact secrets!)
    notes: str = ""
    extra: dict = field(default_factory=dict)

    def duration_s(self) -> Optional[float]:
        if self.end_epoch is None:
            return None
        return round(self.end_epoch - self.start_epoch, 6)


# Column order for the SQLite `ground_truth` table. dst_ports/extra are stored
# as JSON text; everything else is a scalar.
_SQLITE_COLUMNS: Sequence[str] = (
    "action_id", "run_id", "scenario", "technique", "tool",
    "expected_event_type", "src_ip", "dst_ip", "dst_ports", "protocol",
    "intent", "start_epoch", "end_epoch", "start_utc", "end_utc",
    "status", "command", "notes", "duration_s", "extra",
)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS ground_truth (
    action_id            INTEGER NOT NULL,
    run_id               TEXT    NOT NULL,
    scenario             TEXT    NOT NULL,
    technique            TEXT    NOT NULL,
    tool                 TEXT    NOT NULL,
    expected_event_type  TEXT    NOT NULL,
    src_ip               TEXT    NOT NULL,
    dst_ip               TEXT    NOT NULL,
    dst_ports            TEXT    NOT NULL,   -- JSON array
    protocol             TEXT    NOT NULL,
    intent               TEXT,
    start_epoch          REAL    NOT NULL,
    end_epoch            REAL,
    start_utc            TEXT    NOT NULL,
    end_utc              TEXT,
    status               TEXT    NOT NULL,
    command              TEXT,
    notes                TEXT,
    duration_s           REAL,
    extra                TEXT,               -- JSON object
    PRIMARY KEY (run_id, action_id)
);
"""

# Indexed the same way the synopsis asks the traffic tables to be, so the
# evaluation joins (by time / IP / port) stay cheap.
_CREATE_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_gt_start ON ground_truth (start_epoch);",
    "CREATE INDEX IF NOT EXISTS idx_gt_src ON ground_truth (src_ip);",
    "CREATE INDEX IF NOT EXISTS idx_gt_dst ON ground_truth (dst_ip);",
)


class GroundTruthLogger:
    """Records attacker actions to JSONL (+ optional SQLite).

    Typical use::

        gt = GroundTruthLogger(out_dir="artifacts/run1")
        with gt.action(scenario="recon", technique="tcp_syn_scan",
                       tool="nmap", src_ip="10.10.10.5", dst_ip="10.10.10.20",
                       dst_ports=[1, 65535], intent="SYN scan all TCP ports"):
            run_the_tool(...)        # start/end timestamps captured for you
        gt.close()

    Thread-safe for the modest concurrency of a scenario runner.
    """

    def __init__(
        self,
        out_dir: str,
        run_id: Optional[str] = None,
        jsonl_name: str = "ground_truth.jsonl",
        sqlite_path: Optional[str] = None,
        write_sqlite: bool = True,
    ) -> None:
        self.out_dir = out_dir
        self.run_id = run_id or f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
        os.makedirs(out_dir, exist_ok=True)

        self.jsonl_path = os.path.join(out_dir, jsonl_name)
        self._lock = threading.Lock()
        self._next_id = 1
        self._actions: List[GroundTruthAction] = []

        # Fresh JSONL for this logger instance.
        self._jsonl_fh = open(self.jsonl_path, "w", encoding="utf-8")

        self._conn: Optional[sqlite3.Connection] = None
        if write_sqlite:
            self.sqlite_path = sqlite_path or os.path.join(out_dir, "ground_truth.db")
            self._conn = sqlite3.connect(self.sqlite_path)
            self._conn.execute(_CREATE_TABLE_SQL)
            for stmt in _CREATE_INDEX_SQL:
                self._conn.execute(stmt)
            self._conn.commit()
        else:
            self.sqlite_path = None

    # -- recording ----------------------------------------------------------

    def record(
        self,
        *,
        scenario: str,
        technique: str,
        tool: str,
        src_ip: str,
        dst_ip: str,
        dst_ports: Sequence[int],
        intent: str,
        protocol: str = "tcp",
        start_epoch: Optional[float] = None,
        end_epoch: Optional[float] = None,
        status: str = STATUS_COMPLETED,
        command: str = "",
        notes: str = "",
        expected_event_type: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> GroundTruthAction:
        """Record a fully-formed action (both timestamps already known)."""
        now = time.time()
        start_epoch = now if start_epoch is None else start_epoch
        if expected_event_type is None:
            expected_event_type = SCENARIO_TO_EVENT_TYPE.get(scenario, "")

        with self._lock:
            action = GroundTruthAction(
                action_id=self._next_id,
                run_id=self.run_id,
                scenario=scenario,
                technique=technique,
                tool=tool,
                expected_event_type=expected_event_type,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_ports=list(dst_ports),
                protocol=protocol,
                intent=intent,
                start_epoch=start_epoch,
                end_epoch=end_epoch,
                start_utc=_utc_iso(start_epoch),
                end_utc=_utc_iso(end_epoch) if end_epoch is not None else None,
                status=status,
                command=command,
                notes=notes,
                extra=dict(extra or {}),
            )
            self._next_id += 1
            self._actions.append(action)
            self._write_jsonl(action)
            self._write_sqlite(action)
            return action

    @contextmanager
    def action(
        self,
        *,
        scenario: str,
        technique: str,
        tool: str,
        src_ip: str,
        dst_ip: str,
        dst_ports: Sequence[int],
        intent: str,
        protocol: str = "tcp",
        command: str = "",
        notes: str = "",
        expected_event_type: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> Iterator[GroundTruthAction]:
        """Context manager that stamps start on enter and end on exit.

        If the wrapped block raises, the action is still recorded with
        status="failed" and the exception text appended to notes, then the
        exception is re-raised. This guarantees every attempted action lands
        in the ground-truth log — successes and failures alike.
        """
        start_epoch = time.time()
        err: Optional[BaseException] = None
        try:
            # Placeholder recorded on exit; yield a light handle for notes.
            handle = _ActionHandle()
            yield handle
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            err = exc
            raise
        finally:
            end_epoch = time.time()
            status = STATUS_COMPLETED if err is None else STATUS_FAILED
            final_notes = notes
            if err is not None:
                final_notes = (notes + " | " if notes else "") + f"{type(err).__name__}: {err}"
            merged_extra = dict(extra or {})
            merged_extra.update(handle.extra)
            self.record(
                scenario=scenario,
                technique=technique,
                tool=tool,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_ports=dst_ports,
                intent=intent,
                protocol=protocol,
                start_epoch=start_epoch,
                end_epoch=end_epoch,
                status=status,
                command=command or handle.command,
                notes=final_notes,
                expected_event_type=expected_event_type,
                extra=merged_extra,
            )

    # -- persistence helpers ------------------------------------------------

    def _write_jsonl(self, action: GroundTruthAction) -> None:
        row = asdict(action)
        row["duration_s"] = action.duration_s()
        self._jsonl_fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._jsonl_fh.flush()
        os.fsync(self._jsonl_fh.fileno())

    def _write_sqlite(self, action: GroundTruthAction) -> None:
        if self._conn is None:
            return
        row = asdict(action)
        row["duration_s"] = action.duration_s()
        row["dst_ports"] = json.dumps(action.dst_ports)
        row["extra"] = json.dumps(action.extra, ensure_ascii=False)
        placeholders = ", ".join(f":{c}" for c in _SQLITE_COLUMNS)
        self._conn.execute(
            f"INSERT OR REPLACE INTO ground_truth "
            f"({', '.join(_SQLITE_COLUMNS)}) VALUES ({placeholders})",
            {c: row[c] for c in _SQLITE_COLUMNS},
        )
        self._conn.commit()

    # -- introspection / teardown ------------------------------------------

    @property
    def actions(self) -> List[GroundTruthAction]:
        return list(self._actions)

    def summary(self) -> dict:
        by_scenario: dict = {}
        for a in self._actions:
            by_scenario.setdefault(a.scenario, {"total": 0, "completed": 0, "failed": 0})
            by_scenario[a.scenario]["total"] += 1
            if a.status == STATUS_COMPLETED:
                by_scenario[a.scenario]["completed"] += 1
            elif a.status == STATUS_FAILED:
                by_scenario[a.scenario]["failed"] += 1
        return {
            "run_id": self.run_id,
            "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
            "action_count": len(self._actions),
            "by_scenario": by_scenario,
            "jsonl_path": self.jsonl_path,
            "sqlite_path": self.sqlite_path,
        }

    def close(self) -> None:
        with self._lock:
            if self._jsonl_fh and not self._jsonl_fh.closed:
                self._jsonl_fh.close()
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> "GroundTruthLogger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


@dataclass
class _ActionHandle:
    """Handle yielded inside `action(...)` so a block can attach a command
    string or extra key/values that end up on the recorded action."""

    command: str = ""
    extra: dict = field(default_factory=dict)

    def set_command(self, cmd: str) -> None:
        self.command = cmd

    def add_extra(self, **kv) -> None:
        self.extra.update(kv)


def load_jsonl(path: str) -> List[dict]:
    """Read a ground-truth JSONL file back into a list of dicts (for tests
    and for the evaluation step)."""
    out: List[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
