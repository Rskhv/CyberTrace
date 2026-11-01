"""Local Nmap agent that refuses to run without a valid signed manifest."""
from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import subprocess
import time
from pathlib import Path

from .crypto import verify_scan_authorization


def execute_authorized_scan(bundle: dict, public_key_pem: bytes, *, scanner_id: str,
                            target: str, ports: list[int], scan_type: str,
                            replay_db: str | Path, nmap_binary: str = "nmap",
                            dry_run: bool = False, now: float | None = None,
                            environment: str = "lab") -> list[str]:
    m = bundle.get("manifest", {})
    flags = {"SYN": "-sS", "CONNECT": "-sT", "UDP": "-sU"}
    if scan_type.upper() not in flags:
        raise ValueError("supported scan types: SYN, CONNECT, UDP")
    try:
        target_ip = ipaddress.ip_address(target)
        subnet = ipaddress.ip_network(m.get("permitted_subnet", ""), strict=False)
    except ValueError as exc:
        raise ValueError("invalid target or authorization subnet") from exc
    if target_ip not in subnet:
        raise PermissionError("target is outside the permitted subnet")
    if target != m.get("target_ip"):
        raise PermissionError("requested target does not match signed target")
    db = sqlite3.connect(replay_db)
    db.execute("CREATE TABLE IF NOT EXISTS used_nonces(nonce TEXT PRIMARY KEY, used_at REAL NOT NULL)")
    seen = db.execute("SELECT 1 FROM used_nonces WHERE nonce=?", (m.get("unique_nonce"),)).fetchone() is not None
    valid, reason = verify_scan_authorization(bundle, public_key_pem, now=now, scanner_id=scanner_id,
        target_ip=target, ports=ports, protocol="UDP" if scan_type.upper()=="UDP" else "TCP",
        scan_type=scan_type, nonce_seen=seen, environment=m.get("environment"), allowed_environment=environment)
    if not valid:
        db.close()
        raise PermissionError(f"scan authorization rejected: {reason}")
    # A dry run only previews execution. Real runs consume nonce before invoking
    # Nmap so an external scanner failure cannot permit replay.
    if not dry_run:
        db.execute("INSERT INTO used_nonces(nonce,used_at) VALUES (?,?)", (m["unique_nonce"], time.time()))
        db.commit()
    db.close()
    command = [nmap_binary, flags[scan_type.upper()], "-p", ",".join(map(str, ports)), target]
    if not dry_run:
        subprocess.run(command, check=True)
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--scanner-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", required=True, help="comma-separated destination ports")
    parser.add_argument("--scan-type", choices=("SYN", "CONNECT", "UDP"), default="SYN")
    parser.add_argument("--replay-db", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--environment", default="lab")
    args = parser.parse_args()
    command = execute_authorized_scan(json.loads(Path(args.authorization).read_text()), Path(args.public_key).read_bytes(),
        scanner_id=args.scanner_id, target=args.target, ports=[int(p) for p in args.ports.split(",")],
        scan_type=args.scan_type, replay_db=args.replay_db, dry_run=args.dry_run, environment=args.environment)
    print(json.dumps({"status": "AUTHORIZED_DRY_RUN" if args.dry_run else "SCAN_COMPLETED", "command": command}))


if __name__ == "__main__":
    main()
