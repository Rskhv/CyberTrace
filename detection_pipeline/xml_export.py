"""
CyberTrace — Detection Pipeline: XML export.

Writes structured packet + flow information to an XML file for human inspection
and interchange. SQLite remains the main queryable store; this is a secondary,
readable view (synopsis Stage 5 / Stage 2 requirement).

Uses only xml.etree.ElementTree (stdlib).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List, Optional
from xml.dom import minidom

from .flow import FlowRecord
from .packet_record import PacketRecord


def _set(el: ET.Element, name: str, value) -> None:
    """Attach a child element with text, skipping None (keeps the XML clean)."""
    if value is None:
        return
    child = ET.SubElement(el, name)
    child.text = str(value)


def build_tree(
    packets: List[PacketRecord],
    flows: List[FlowRecord],
    pcap_file: Optional[str] = None,
) -> ET.ElementTree:
    root = ET.Element("cybertrace")
    cap = ET.SubElement(root, "capture")
    if pcap_file:
        cap.set("pcap_file", pcap_file)
    cap.set("packet_count", str(len(packets)))
    cap.set("flow_count", str(len(flows)))

    pkts_el = ET.SubElement(root, "packets")
    for p in packets:
        pe = ET.SubElement(pkts_el, "packet")
        if p.frame_number is not None:
            pe.set("frame", str(p.frame_number))
        _set(pe, "timestamp", p.timestamp)
        _set(pe, "protocol", p.protocol)
        _set(pe, "source_ip", p.source_ip)
        _set(pe, "destination_ip", p.destination_ip)
        _set(pe, "source_port", p.source_port)
        _set(pe, "destination_port", p.destination_port)
        _set(pe, "tcp_flags", p.tcp_flags)
        _set(pe, "packet_length", p.packet_length)

    flows_el = ET.SubElement(root, "flows")
    for f in flows:
        fe = ET.SubElement(flows_el, "flow")
        _set(fe, "source_ip", f.source_ip)
        _set(fe, "destination_ip", f.destination_ip)
        _set(fe, "source_port", f.source_port)
        _set(fe, "destination_port", f.destination_port)
        _set(fe, "protocol", f.protocol)
        _set(fe, "start_time", f.start_time)
        _set(fe, "end_time", f.end_time)
        _set(fe, "duration", f.duration)
        _set(fe, "packet_count", f.packet_count)
        _set(fe, "byte_count", f.byte_count)
        _set(fe, "packets_per_sec", f.packets_per_sec)
        if f.flag_counts:
            flags_el = ET.SubElement(fe, "tcp_flag_counts")
            for name, n in sorted(f.flag_counts.items()):
                fc = ET.SubElement(flags_el, "flag")
                fc.set("name", name)
                fc.text = str(n)

    return ET.ElementTree(root)


def export_xml(
    packets: List[PacketRecord],
    flows: List[FlowRecord],
    out_path: str,
    pcap_file: Optional[str] = None,
) -> str:
    """Write the packets/flows XML to out_path (pretty-printed). Returns path."""
    tree = build_tree(packets, flows, pcap_file)
    rough = ET.tostring(tree.getroot(), encoding="utf-8")
    pretty = minidom.parseString(rough).toprettyxml(indent="  ", encoding="utf-8")
    with open(out_path, "wb") as fh:
        fh.write(pretty)
    return out_path
