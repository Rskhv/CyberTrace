"""
CyberTrace — Detection Pipeline: flow generation.

Groups PacketRecords into flows by the directional 5-tuple
(source_ip, destination_ip, source_port, destination_port, protocol), and
derives per-flow and capture-level statistics the Stage-3 detectors will use.

Only the Stage-1 `flows` columns are persisted to SQLite; the richer derived
fields (packets/sec, byte count, TCP flag counts) live on the FlowRecord and
are included in the XML export, not forced into the fixed flows schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .packet_record import PacketRecord, has_flag


@dataclass
class FlowRecord:
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    start_time: float
    end_time: float
    packet_count: int
    byte_count: int = 0
    flag_counts: Dict[str, int] = field(default_factory=dict)  # TCP only

    @property
    def duration(self) -> float:
        return round(self.end_time - self.start_time, 6)

    @property
    def packets_per_sec(self) -> float:
        d = self.duration
        return round(self.packet_count / d, 3) if d > 0 else float(self.packet_count)

    def to_flow_row(self) -> dict:
        """Dict of the persisted (Stage-1) flow columns."""
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "packet_count": self.packet_count,
            "duration": self.duration,
        }


class FlowBuilder:
    """Accumulates packets and emits FlowRecords grouped by 5-tuple."""

    def __init__(self) -> None:
        self._flows: Dict[Tuple, dict] = {}

    def add(self, pkt: PacketRecord) -> None:
        key = pkt.five_tuple()
        f = self._flows.get(key)
        if f is None:
            f = {
                "start": pkt.timestamp,
                "end": pkt.timestamp,
                "count": 0,
                "bytes": 0,
                "flags": {},
            }
            self._flows[key] = f
        f["start"] = min(f["start"], pkt.timestamp)
        f["end"] = max(f["end"], pkt.timestamp)
        f["count"] += 1
        f["bytes"] += int(pkt.packet_length or 0)
        if pkt.protocol == "TCP" and pkt.tcp_flags:
            for name in pkt.tcp_flags.split(","):
                if name:
                    f["flags"][name] = f["flags"].get(name, 0) + 1

    def build(self) -> List[FlowRecord]:
        out: List[FlowRecord] = []
        for (src_ip, dst_ip, src_port, dst_port, proto), f in self._flows.items():
            out.append(
                FlowRecord(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                    start_time=f["start"],
                    end_time=f["end"],
                    packet_count=f["count"],
                    byte_count=f["bytes"],
                    flag_counts=dict(f["flags"]),
                )
            )
        out.sort(key=lambda fr: (fr.start_time, str(fr.source_ip), fr.destination_port or -1))
        return out


def build_flows(packets: Iterable[PacketRecord]) -> List[FlowRecord]:
    """Convenience: build all flows from an iterable of packets."""
    b = FlowBuilder()
    for p in packets:
        b.add(p)
    return b.build()


# -- capture-level derived statistics ---------------------------------------

def distinct_dst_ports_per_source(packets: Iterable[PacketRecord]) -> Dict[str, int]:
    """Map source_ip -> count of distinct destination ports it contacted.
    A high value is the key signal the Stage-3 port-scan detector keys on."""
    seen: Dict[str, set] = {}
    for p in packets:
        if p.source_ip is None or p.destination_port is None:
            continue
        seen.setdefault(p.source_ip, set()).add(p.destination_port)
    return {ip: len(ports) for ip, ports in seen.items()}


def tcp_handshake_counts(packets: Iterable[PacketRecord]) -> Tuple[int, int]:
    """Return (completed, incomplete) TCP connection counts.

    Heuristic, lab-appropriate: for each direction-independent TCP connection,
    a connection is 'completed' if a SYN,ACK was observed (the server answered
    the handshake), and 'incomplete' if a SYN was seen but no SYN,ACK ever was
    (the pattern a SYN scan leaves). Connections with neither are ignored.
    """
    saw_syn: Dict = {}
    saw_synack: Dict = {}
    for p in packets:
        if p.protocol != "TCP" or not p.tcp_flags:
            continue
        key = p.connection_key()
        syn = has_flag(p.tcp_flags, "SYN")
        ack = has_flag(p.tcp_flags, "ACK")
        if syn and ack:
            saw_synack[key] = True
        elif syn:
            saw_syn[key] = True
    completed = sum(1 for k in saw_synack)
    incomplete = sum(1 for k in saw_syn if k not in saw_synack)
    return completed, incomplete
