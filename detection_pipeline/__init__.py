"""CyberTrace Detection Pipeline module (Manan).

Stage 2 surface — PCAP parsing, flow generation, storage, XML export.
(Stage 3 will add the rule-based detectors to this same package.)
"""

from .packet_record import PacketRecord, decode_tcp_flags
from .flow import FlowRecord, FlowBuilder, build_flows
from .pipeline import (
    run_pipeline,
    store_packets,
    store_flows,
    load_packet_records,
    ParseSummary,
)
from .xml_export import export_xml
from .detectors import DetectorConfig, run_detectors
from .detectors import detect_port_scans, detect_ssh_brute_force, detect_exploitation

__all__ = [
    "PacketRecord",
    "decode_tcp_flags",
    "FlowRecord",
    "FlowBuilder",
    "build_flows",
    "run_pipeline",
    "store_packets",
    "store_flows",
    "load_packet_records",
    "ParseSummary",
    "export_xml",
    "DetectorConfig",
    "run_detectors",
    "detect_port_scans",
    "detect_ssh_brute_force",
    "detect_exploitation",
]
