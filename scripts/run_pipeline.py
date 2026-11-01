#!/usr/bin/env python3
"""Run Stages 2–7 over one or more PCAPs in the shared SQLite database."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybertrace_forensics.integration import reconstruct_database
from detection_pipeline.detectors import run_detectors
from detection_pipeline.pipeline import run_pipeline as parse_pcap
from shared import database as db


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", action="append", required=True,
                        help="PCAP/PCAPNG path; repeat for recon, SSH, exploit, and baseline captures")
    parser.add_argument("--db", default="data/cybertrace.db", help="shared SQLite path (use a fresh path per trial)")
    parser.add_argument("--xml-dir", help="optional directory for per-capture XML exports")
    parser.add_argument("--threshold", type=float, default=0.70)
    parser.add_argument("--packet-limit", type=int)
    parser.add_argument("--export-dir", default="data/evaluation")
    args = parser.parse_args(argv)
    if not 0 <= args.threshold <= 1:
        parser.error("--threshold must be in [0, 1]")
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if args.xml_dir:
        Path(args.xml_dir).mkdir(parents=True, exist_ok=True)

    for pcap in args.pcap:
        xml_path = None
        if args.xml_dir:
            xml_path = str(Path(args.xml_dir) / f"{Path(pcap).stem}.xml")
        summary = parse_pcap(pcap, str(db_path), xml_path=xml_path, limit=args.packet_limit)
        print(summary.format())
        print()

    conn = db.connect(str(db_path))
    try:
        events = run_detectors(conn, store=True)
        reconstruction = reconstruct_database(conn, threshold=args.threshold, export_dir=args.export_dir)
    finally:
        conn.close()
    print(f"Stage 3 detections stored: {len(events)}")
    print(f"Stages 4–7 incidents stored: {len(reconstruction['persisted']['incidents'])}")
    print(f"Evidence-aware links stored: {reconstruction['persisted']['correlation_count']}")
    print(f"Stages 6 inferred events: {len(reconstruction['inferred_events'])}")
    print(f"Database: {db_path}")
    print(f"Evaluation exports: {args.export_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
