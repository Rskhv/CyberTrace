"""
Stage 3 detector 2 — SSH CONNECTION ANOMALY (network metadata only).

Repeated SYNs to port 22 show connection activity only. They cannot establish
authentication failures because SSH payloads are encrypted.

Emits: event_type=SSH_CONNECTION_ANOMALY, attack_stage=SERVICE_DISCOVERY.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from shared.event_model import NormalizedEvent, iso_utc

from ..flow import build_flows
from ..packet_record import PacketRecord
from .config import DetectorConfig
from ._common import clamp01, is_pure_syn, severity_from_score


def detect_ssh_brute_force(packets: List[PacketRecord], config: DetectorConfig
                           ) -> List[NormalizedEvent]:
    cfg = config
    events: List[NormalizedEvent] = []

    # Connection attempts = SYN initiations to the SSH port, grouped by (src,dst).
    by_pair: Dict[tuple, List[PacketRecord]] = defaultdict(list)
    for p in packets:
        if is_pure_syn(p) and p.destination_port == cfg.ssh_port and p.source_ip and p.destination_ip:
            by_pair[(p.source_ip, p.destination_ip)].append(p)

    # Pre-compute SSH flow durations per (src,dst) for the short-lived signal.
    ssh_flows = [f for f in build_flows(packets)
                 if f.protocol == "TCP" and f.destination_port == cfg.ssh_port]
    durations_by_pair: Dict[tuple, List[float]] = defaultdict(list)
    for f in ssh_flows:
        durations_by_pair[(f.source_ip, f.destination_ip)].append(f.duration)

    for (src, dst), pkts in by_pair.items():
        pkts.sort(key=lambda x: x.timestamp)

        # Sliding window: most attempts within ssh_window_seconds.
        left = 0
        best = None  # (attempts, win_start, win_end, l, r)
        for right in range(len(pkts)):
            while pkts[right].timestamp - pkts[left].timestamp > cfg.ssh_window_seconds:
                left += 1
            attempts = right - left + 1
            if attempts >= cfg.ssh_min_attempts and (best is None or attempts > best[0]):
                best = (attempts, pkts[left].timestamp, pkts[right].timestamp, left, right)

        if best is None:
            continue

        attempts, win_start, win_end, l, r = best
        window_pkts = pkts[l:r + 1]
        packet_ids = [p.packet_id for p in window_pkts if p.packet_id is not None]

        durations = durations_by_pair.get((src, dst), [])
        short_lived = sum(1 for d in durations if d <= cfg.ssh_short_session_seconds)
        short_ratio = (short_lived / len(durations)) if durations else 0.0

        # Evidence score from real features: attempt count over threshold,
        # nudged up by the fraction of short-lived sessions.
        base = clamp01(attempts / (2.0 * cfg.ssh_min_attempts))
        score = round(clamp01(0.7 * base + 0.3 * short_ratio + 0.3), 3)

        events.append(NormalizedEvent(
            timestamp=win_start,
            source_ip=src,
            destination_ip=dst,
            protocol="TCP",
            event_type="SSH_CONNECTION_ANOMALY",
            attack_stage="SERVICE_DISCOVERY",
            evidence_source="PCAP",
            source_port=None,
            destination_port=cfg.ssh_port,
            severity=severity_from_score(score),
            packet_ids=packet_ids,
            flow_id=None,
            evidence_score=score,
            confidence_score=0.0,
            status="DETECTED",
            evidence={
                "attempts": attempts,
                "window_seconds": round(win_end - win_start, 3),
                "window_start_utc": iso_utc(win_start),
                "short_lived_sessions": short_lived,
                "total_ssh_sessions": len(durations),
                "ssh_port": cfg.ssh_port,
                "target": dst,
                "limitation": "PCAP connection counts cannot establish SSH authentication failures",
            },
        ))

    return events
