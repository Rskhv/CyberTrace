"""Shared helpers for the Stage-3 detectors."""

from __future__ import annotations

from typing import Iterable, List, Optional

from ..packet_record import PacketRecord, has_flag


def severity_from_score(score: float) -> str:
    """Map an evidence score in [0,1] to a severity label."""
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def is_pure_syn(pkt: PacketRecord) -> bool:
    """TCP packet with SYN set and ACK clear — a connection initiation."""
    return pkt.protocol == "TCP" and has_flag(pkt.tcp_flags, "SYN") and not has_flag(pkt.tcp_flags, "ACK")


def packet_ids_for(packets: Iterable[PacketRecord], src_ip, dst_ip,
                   dst_port: Optional[int] = None) -> List[int]:
    """Collect DB packet_ids matching a src/dst (+optional dst port)."""
    ids = []
    for p in packets:
        if p.packet_id is None:
            continue
        if p.source_ip == src_ip and p.destination_ip == dst_ip and (
            dst_port is None or p.destination_port == dst_port
        ):
            ids.append(p.packet_id)
    return ids
