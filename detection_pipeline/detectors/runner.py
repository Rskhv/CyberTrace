"""
Stage 3 detector runner.

Loads parsed packets from SQLite, runs the three rule-based detectors, and
stores every emitted NormalizedEvent into the `alerts` table. Produces no
correlation — that is Stage 4+.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List, Optional

from shared import database as db
from shared.event_model import NormalizedEvent

from ..pipeline import load_packet_records
from .config import DetectorConfig
from .port_scan import detect_port_scans
from .ssh_brute_force import detect_ssh_brute_force
from .exploitation import detect_exploitation

# Ordered recon -> credential -> exploitation (the lifecycle order).
DETECTORS = [detect_port_scans, detect_ssh_brute_force, detect_exploitation]


def register_detector(detector) -> None:
    """Register an additional rule with the common (packets, config) contract."""
    if not callable(detector):
        raise TypeError("detector must be callable")
    if detector not in DETECTORS:
        DETECTORS.append(detector)


def detect(packets, config: Optional[DetectorConfig] = None) -> List[NormalizedEvent]:
    """Run all detectors over an in-memory packet list (no DB). Pure function."""
    cfg = config or DetectorConfig()
    events: List[NormalizedEvent] = []
    for detector in DETECTORS:
        events.extend(detector(packets, cfg))
    events.sort(key=lambda e: e.timestamp)
    return events


def run_detectors(conn, config: Optional[DetectorConfig] = None,
                  store: bool = True) -> List[NormalizedEvent]:
    """Load packets from SQLite, detect, and (by default) persist to `alerts`.
    Returns the emitted events (with event_id set when stored)."""
    packets = load_packet_records(conn)
    by_capture = defaultdict(list)
    for packet in packets:
        by_capture[packet.pcap_file or "__unspecified_capture__"].append(packet)
    events = []
    for capture, capture_packets in by_capture.items():
        capture_events = detect(capture_packets, config)
        for event in capture_events:
            event.evidence.setdefault("pcap_file", capture if capture != "__unspecified_capture__" else None)
        events.extend(capture_events)
    events.sort(key=lambda event: event.timestamp)
    if store:
        for ev in events:
            db.insert_event(conn, ev)
    return events
