#!/usr/bin/env python3
"""
CyberTrace — Stage 2 CLI: parse a PCAP into the SQLite store (+ optional XML).

Usage:
    python scripts/parse_pcap.py --pcap data/pcaps/test.pcap
    python scripts/parse_pcap.py --pcap capture.pcapng --db cybertrace.db --xml out.xml
    python scripts/parse_pcap.py --pcap big.pcap --limit 5000

Steps: validate path -> parse packets -> build flows -> store in SQLite ->
optionally write XML -> print a summary. Requires pyshark + tshark to read a
real capture; everything downstream of parsing is stdlib only.
"""

from __future__ import annotations

import argparse
import os
import sys

# Allow running as a loose script (python scripts/parse_pcap.py).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_pipeline.pipeline import run_pipeline
from detection_pipeline.pcap_parser import PcapError


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberTrace PCAP parser (Stage 2)")
    ap.add_argument("--pcap", required=True, help="path to .pcap/.pcapng file")
    ap.add_argument("--db", default="cybertrace.db", help="SQLite DB path (default: cybertrace.db)")
    ap.add_argument("--xml", default=None, help="optional XML output path")
    ap.add_argument("--limit", type=int, default=None, help="max packets to parse")
    args = ap.parse_args(argv)

    try:
        summary = run_pipeline(args.pcap, db_path=args.db, xml_path=args.xml, limit=args.limit)
    except PcapError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(summary.format())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
