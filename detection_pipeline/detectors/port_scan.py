"""
Stage 3 detector 1 — PORT SCAN (reconnaissance).

Signal: a single source sends many SYN initiations to many distinct destination
ports in a short time window, mostly without completing the TCP handshake — the
shape an Nmap SYN scan leaves. Operates on the parsed packets (from SQLite).

Emits: event_type=PORT_SCAN, attack_stage=RECON, status=DETECTED.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from shared.event_model import NormalizedEvent, iso_utc

from ..packet_record import PacketRecord
from .config import DetectorConfig
from ._common import clamp01, is_pure_syn, severity_from_score


def detect_port_scans(packets: List[PacketRecord], config: DetectorConfig
                      ) -> List[NormalizedEvent]:
    cfg = config
    events: List[NormalizedEvent] = []

    # Group SYN initiations by (source_ip, destination_ip) — a scan targets one
    # host across many ports.
    by_pair: Dict[tuple, List[PacketRecord]] = defaultdict(list)
    for p in packets:
        if is_pure_syn(p) and p.source_ip and p.destination_ip and p.destination_port is not None:
            by_pair[(p.source_ip, p.destination_ip)].append(p)

    for (src, dst), pkts in by_pair.items():
        pkts.sort(key=lambda x: x.timestamp)

        # Sliding time window (two pointers) to find the window with the most
        # distinct destination ports within scan_window_seconds.
        left = 0
        port_counts: Dict[int, int] = defaultdict(int)
        best = None  # (distinct, syn_count, win_start, win_end, l, r)
        for right in range(len(pkts)):
            port_counts[pkts[right].destination_port] += 1
            while pkts[right].timestamp - pkts[left].timestamp > cfg.scan_window_seconds:
                port_counts[pkts[left].destination_port] -= 1
                if port_counts[pkts[left].destination_port] == 0:
                    del port_counts[pkts[left].destination_port]
                left += 1
            distinct = len(port_counts)
            syn_count = right - left + 1
            if distinct >= cfg.min_distinct_ports and syn_count >= cfg.min_syn_count:
                if best is None or distinct > best[0]:
                    best = (distinct, syn_count, pkts[left].timestamp,
                            pkts[right].timestamp, left, right)

        if best is None:
            continue

        distinct, syn_count, win_start, win_end, l, r = best
        window_pkts = pkts[l:r + 1]
        packet_ids = [p.packet_id for p in window_pkts if p.packet_id is not None]
        ports = sorted({p.destination_port for p in window_pkts})

        # Evidence score (0..1) from real features: how far distinct-port count
        # exceeds the threshold (saturating at 3x the threshold).
        score = clamp01(distinct / (3.0 * cfg.min_distinct_ports))
        score = round(max(score, 0.5), 3)  # meeting the threshold is already notable

        events.append(NormalizedEvent(
            timestamp=win_start,
            source_ip=src,
            destination_ip=dst,
            protocol="TCP",
            event_type="PORT_SCAN",
            attack_stage="RECON",
            evidence_source="PCAP",
            source_port=None,
            destination_port=None,
            severity=severity_from_score(score),
            packet_ids=packet_ids,
            flow_id=None,
            evidence_score=score,
            confidence_score=0.0,
            status="DETECTED",
            evidence={
                "distinct_ports": distinct,
                "syn_count": syn_count,
                "window_seconds": round(win_end - win_start, 3),
                "window_start_utc": iso_utc(win_start),
                "window_end_utc": iso_utc(win_end),
                "ports_sample": ports[:50],
                "target": dst,
            },
        ))

    return events
