#!/usr/bin/env python3
"""Run Stages 4–7 over Stage 3 alerts, persist incidents, and export timelines."""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import database as db
from cybertrace_forensics.integration import reconstruct_database


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/cybertrace.db", help="shared SQLite database")
    parser.add_argument("--threshold", type=float, default=0.70, help="Stage 5 correlation threshold")
    parser.add_argument("--export-dir", default="data/evaluation", help="baseline/proposed timeline CSV directory")
    args = parser.parse_args(argv)
    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0 and 1")
    if not os.path.exists(args.db):
        parser.error(f"database not found: {args.db}; initialize and run Stages 2–3 first")
    conn = db.connect(args.db)
    try:
        result = reconstruct_database(conn, threshold=args.threshold, export_dir=args.export_dir)
    finally:
        conn.close()
    print(f"Events read: {result['event_count']}")
    print(f"Evidence-aware incidents stored: {len(result['persisted']['incidents'])}")
    print(f"Evidence-aware links stored: {result['persisted']['correlation_count']}")
    print(f"Inferred stages: {len(result['inferred_events'])}")
    print(f"Evaluation exports: {args.export_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
