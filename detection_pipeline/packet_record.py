"""
CyberTrace — Detection Pipeline: the parsed-packet record.

PacketRecord is the parser's output unit: one per packet, protocol-agnostic,
with every field optional so a packet that isn't TCP/UDP (ARP, ICMP, a packet
missing an IP layer) still produces a valid record instead of crashing.

Keeping this as a plain dataclass (no PyShark import) is what lets flow
generation, storage, and XML export be unit-tested with synthetic records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# TCP flag bit -> name, in canonical display order.
_TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


def decode_tcp_flags(raw) -> Optional[str]:
    """Turn a TCP flags value into a readable string like "SYN" or "SYN,ACK".

    Accepts an int, a hex string ("0x0012"), or None. Returns None if the value
    can't be interpreted, so callers never crash on a missing/odd field.
    """
    if raw is None:
        return None
    try:
        value = int(raw, 16) if isinstance(raw, str) else int(raw)
    except (ValueError, TypeError):
        return None
    names = [name for bit, name in _TCP_FLAG_BITS if value & bit]
    return ",".join(names) if names else ""


def has_flag(tcp_flags: Optional[str], flag: str) -> bool:
    """True if a decoded tcp_flags string contains `flag` (e.g. "SYN")."""
    if not tcp_flags:
        return False
    return flag in tcp_flags.split(",")


@dataclass
class PacketRecord:
    """One parsed packet, before it is written to the `packets` table."""

    timestamp: float
    protocol: str = "OTHER"                 # TCP / UDP / ICMP / OTHER
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    tcp_flags: Optional[str] = None         # decoded, e.g. "SYN,ACK"
    packet_length: Optional[int] = None
    frame_number: Optional[int] = None
    pcap_file: Optional[str] = None
    packet_id: Optional[int] = None         # packets.packet_id, set when loaded from DB

    def five_tuple(self):
        """Directional 5-tuple key used to group packets into flows."""
        return (
            self.source_ip,
            self.destination_ip,
            self.source_port,
            self.destination_port,
            self.protocol,
        )

    def connection_key(self):
        """Direction-independent key (both endpoints) for pairing the two
        halves of a TCP connection when judging handshake completion."""
        a = (self.source_ip, self.source_port)
        b = (self.destination_ip, self.destination_port)
        lo, hi = sorted([a, b], key=lambda x: (str(x[0]), x[1] or -1))
        return (lo, hi, self.protocol)
