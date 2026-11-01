"""
CyberTrace — Detection Pipeline: PCAP parser (PyShark/tshark).

Converts a .pcap/.pcapng file into a stream of PacketRecords. PyShark (and the
tshark binary it drives) are imported lazily inside parse_pcap(), so importing
this module — and unit-testing flow/storage/XML with synthetic records — needs
neither installed. They are required only to parse a real capture.

Every field extraction is defensive: a packet missing an IP layer, ports, or
flags yields a PacketRecord with those fields set to None rather than raising.
"""

from __future__ import annotations

import os
from typing import Iterator, Optional

from .packet_record import PacketRecord, decode_tcp_flags

VALID_EXTENSIONS = (".pcap", ".pcapng", ".cap")


class PcapError(RuntimeError):
    pass


def validate_pcap_path(path: str) -> str:
    """Raise PcapError if the path is missing or not a capture file."""
    if not path:
        raise PcapError("no PCAP path given")
    if not os.path.exists(path):
        raise PcapError(f"PCAP file not found: {path}")
    if not os.path.isfile(path):
        raise PcapError(f"not a file: {path}")
    ext = os.path.splitext(path)[1].lower()
    if ext not in VALID_EXTENSIONS:
        raise PcapError(f"unexpected extension {ext!r}; expected one of {VALID_EXTENSIONS}")
    return path


def _safe(getter, cast=None):
    """Run a field getter, returning None on any failure (missing layer/attr)."""
    try:
        val = getter()
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if val is None:
        return None
    if cast is not None:
        try:
            return cast(val)
        except (ValueError, TypeError):
            return None
    return val


def _classify_protocol(pkt) -> str:
    transport = _safe(lambda: pkt.transport_layer)
    if transport in ("TCP", "UDP"):
        return transport
    # transport_layer is None for ICMP etc.; check the layer stack.
    try:
        layers = {l.layer_name.upper() for l in pkt.layers}
    except Exception:  # noqa: BLE001 - PyShark layer access is best-effort
        layers = set()
    if "ICMP" in layers or "ICMPV6" in layers:
        return "ICMP"
    return "OTHER"


def _extract(pkt, pcap_file: Optional[str]) -> PacketRecord:
    protocol = _classify_protocol(pkt)

    source_ip = _safe(lambda: pkt.ip.src) or _safe(lambda: pkt.ipv6.src)
    destination_ip = _safe(lambda: pkt.ip.dst) or _safe(lambda: pkt.ipv6.dst)

    source_port = destination_port = None
    tcp_flags = None
    if protocol in ("TCP", "UDP"):
        layer = protocol.lower()
        source_port = _safe(lambda: pkt[layer].srcport, cast=int)
        destination_port = _safe(lambda: pkt[layer].dstport, cast=int)
        if protocol == "TCP":
            tcp_flags = decode_tcp_flags(_safe(lambda: pkt.tcp.flags))

    return PacketRecord(
        timestamp=_safe(lambda: float(pkt.sniff_timestamp)) or 0.0,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        tcp_flags=tcp_flags,
        packet_length=_safe(lambda: pkt.length, cast=int),
        frame_number=_safe(lambda: pkt.number, cast=int),
        pcap_file=os.path.basename(pcap_file) if pcap_file else None,
    )


def parse_pcap(path: str, limit: Optional[int] = None) -> Iterator[PacketRecord]:
    """Yield a PacketRecord per packet in the capture.

    Requires PyShark and the tshark binary. `limit` caps the number of packets
    (useful for a quick sanity run on a large capture).
    """
    validate_pcap_path(path)
    try:
        import pyshark  # noqa: PLC0415 - intentional lazy import
    except ImportError as e:  # pragma: no cover
        raise PcapError(
            "pyshark is not installed. Install it on the capture/analysis host "
            "(pip install pyshark) along with the tshark binary (apt install tshark)."
        ) from e

    cap = pyshark.FileCapture(path, keep_packets=False)
    try:
        for i, pkt in enumerate(cap):
            if limit is not None and i >= limit:
                break
            yield _extract(pkt, path)
    finally:
        try:
            cap.close()
        except Exception:  # noqa: BLE001
            pass
