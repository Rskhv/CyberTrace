"""
CyberTrace — Detection Pipeline: Stage 2 orchestration.

PCAP -> PacketRecords -> SQLite packets -> flows -> SQLite flows -> optional XML.

This module intentionally produces NO alerts — detection is Stage 3. It only
fills the `packets` and `flows` tables and (optionally) writes an XML view.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from shared import database as db

from .flow import (
    FlowRecord,
    build_flows,
    distinct_dst_ports_per_source,
    tcp_handshake_counts,
)
from .packet_record import PacketRecord
from .xml_export import export_xml


@dataclass
class ParseSummary:
    pcap_file: Optional[str]
    packets_parsed: int = 0
    flows_created: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0
    tcp_completed: int = 0
    tcp_incomplete: int = 0
    distinct_ports_per_source: Dict[str, int] = field(default_factory=dict)
    db_path: Optional[str] = None
    xml_path: Optional[str] = None

    def format(self) -> str:
        lines = [
            f"PCAP file:        {self.pcap_file}",
            f"Packets parsed:   {self.packets_parsed}",
            f"Flows created:    {self.flows_created}",
            f"TCP packets:      {self.tcp_packets}",
            f"UDP packets:      {self.udp_packets}",
            f"ICMP packets:     {self.icmp_packets}",
            f"Other packets:    {self.other_packets}",
            f"TCP handshakes:   {self.tcp_completed} completed / {self.tcp_incomplete} incomplete",
        ]
        if self.distinct_ports_per_source:
            top = sorted(self.distinct_ports_per_source.items(),
                         key=lambda kv: kv[1], reverse=True)[:5]
            lines.append("Distinct dst ports per source (top 5):")
            for ip, n in top:
                lines.append(f"    {ip}: {n}")
        if self.db_path:
            lines.append(f"SQLite:           {self.db_path}")
        if self.xml_path:
            lines.append(f"XML:              {self.xml_path}")
        return "\n".join(lines)


def load_packet_records(conn) -> List[PacketRecord]:
    """Read the packets table back into PacketRecords (with packet_id set),
    ordered by time. This is the input the Stage-3 detectors operate on."""
    rows = conn.execute(
        "SELECT * FROM packets ORDER BY timestamp, packet_id"
    ).fetchall()
    out: List[PacketRecord] = []
    for r in rows:
        out.append(PacketRecord(
            timestamp=r["timestamp"],
            protocol=r["protocol"] or "OTHER",
            source_ip=r["source_ip"],
            destination_ip=r["destination_ip"],
            source_port=r["source_port"],
            destination_port=r["destination_port"],
            tcp_flags=r["tcp_flags"],
            packet_length=r["packet_length"],
            frame_number=r["frame_number"],
            pcap_file=r["pcap_file"],
            packet_id=r["packet_id"],
        ))
    return out


def store_packets(conn, records: List[PacketRecord]) -> List[int]:
    """Insert PacketRecords into the packets table; return assigned packet_ids."""
    ids = []
    for r in records:
        ids.append(db.insert_packet(
            conn,
            timestamp=r.timestamp,
            source_ip=r.source_ip,
            destination_ip=r.destination_ip,
            source_port=r.source_port,
            destination_port=r.destination_port,
            protocol=r.protocol,
            tcp_flags=r.tcp_flags,
            packet_length=r.packet_length,
            frame_number=r.frame_number,
            pcap_file=r.pcap_file,
        ))
    return ids


def store_flows(conn, flows: List[FlowRecord]) -> List[int]:
    """Insert FlowRecords into the flows table; return assigned flow_ids."""
    ids = []
    for f in flows:
        row = f.to_flow_row()
        ids.append(db.insert_flow(conn, **row))
    return ids


def summarize(records: List[PacketRecord], flows: List[FlowRecord],
              pcap_file: Optional[str]) -> ParseSummary:
    s = ParseSummary(pcap_file=pcap_file,
                     packets_parsed=len(records), flows_created=len(flows))
    for r in records:
        if r.protocol == "TCP":
            s.tcp_packets += 1
        elif r.protocol == "UDP":
            s.udp_packets += 1
        elif r.protocol == "ICMP":
            s.icmp_packets += 1
        else:
            s.other_packets += 1
    s.tcp_completed, s.tcp_incomplete = tcp_handshake_counts(records)
    s.distinct_ports_per_source = distinct_dst_ports_per_source(records)
    return s


def run_pipeline(
    pcap_path: str,
    db_path: str,
    xml_path: Optional[str] = None,
    limit: Optional[int] = None,
) -> ParseSummary:
    """Full Stage-2 run against a real PCAP (requires pyshark + tshark)."""
    from .pcap_parser import parse_pcap, validate_pcap_path  # lazy (pyshark)

    validate_pcap_path(pcap_path)
    records = list(parse_pcap(pcap_path, limit=limit))
    flows = build_flows(records)

    conn = db.init_db(db_path)
    try:
        store_packets(conn, records)
        store_flows(conn, flows)
    finally:
        conn.close()

    if xml_path:
        export_xml(records, flows, xml_path, pcap_file=os.path.basename(pcap_path))

    summary = summarize(records, flows, os.path.basename(pcap_path))
    summary.db_path = db_path
    summary.xml_path = xml_path
    return summary
