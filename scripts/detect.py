#!/usr/bin/env python3
"""
CyberTrace — Stage 3 CLI: run the rule-based detectors over a parsed DB.

Reads packets/flows already stored by Stage 2 (scripts/parse_pcap.py) and writes
normalized events into the `alerts` table.

Usage:
    python scripts/detect.py --db cybertrace.db
    python scripts/detect.py --db cybertrace.db --min-distinct-ports 20 --ssh-min-attempts 8
    python scripts/detect.py --db cybertrace.db --no-store      # preview only
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import database as db
from detection_pipeline.detectors import DetectorConfig, run_detectors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberTrace detectors (Stage 3)")
    ap.add_argument("--db", required=True, help="SQLite DB produced by Stage 2")
    ap.add_argument("--no-store", action="store_true", help="detect but do not write alerts")
    # a few common threshold overrides (everything else uses DetectorConfig defaults)
    ap.add_argument("--min-distinct-ports", type=int)
    ap.add_argument("--min-syn-count", type=int)
    ap.add_argument("--scan-window-seconds", type=float)
    ap.add_argument("--ssh-min-attempts", type=int)
    ap.add_argument("--ssh-window-seconds", type=float)
    args = ap.parse_args(argv)

    overrides = {
        "min_distinct_ports": args.min_distinct_ports,
        "min_syn_count": args.min_syn_count,
        "scan_window_seconds": args.scan_window_seconds,
        "ssh_min_attempts": args.ssh_min_attempts,
        "ssh_window_seconds": args.ssh_window_seconds,
    }
    overrides = {k: v for k, v in overrides.items() if v is not None}
    config = DetectorConfig.from_dict(overrides) if overrides else DetectorConfig()

    if not os.path.exists(args.db):
        print(f"error: DB not found: {args.db}", file=sys.stderr)
        return 2

    conn = db.connect(args.db)
    try:
        events = run_detectors(conn, config=config, store=not args.no_store)
    finally:
        conn.close()

    print(f"Detectors run on {args.db} — {len(events)} event(s)"
          f"{' (not stored)' if args.no_store else ' stored to alerts'}\n")
    by_type = {}
    for e in events:
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
    for t, n in sorted(by_type.items()):
        print(f"  {t}: {n}")
    print()
    for e in events:
        print(f"[{e.event_type}] {e.source_ip} -> {e.destination_ip} "
              f"stage={e.attack_stage} severity={e.severity} "
              f"evidence_score={e.evidence_score}")
        print(f"    evidence: {json.dumps(e.evidence)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
