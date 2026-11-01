"""
Stage 2 tests — PCAP parsing pipeline (flow generation, storage, XML).

Runnable with no lab, no tshark, no pyshark (stdlib only):

    cd cybertrace
    python -m unittest discover -s tests -v

The parser's PyShark dependency is isolated, so these tests drive the flow,
storage, and XML logic with SYNTHETIC in-memory PacketRecords — no fabricated
PCAP files. A guarded test covers path validation and the "pyshark missing"
error path.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import database as db
from detection_pipeline.packet_record import PacketRecord, decode_tcp_flags
from detection_pipeline.flow import (
    build_flows,
    distinct_dst_ports_per_source,
    tcp_handshake_counts,
)
from detection_pipeline.pipeline import store_packets, store_flows, summarize
from detection_pipeline.xml_export import export_xml
from detection_pipeline.pcap_parser import validate_pcap_path, PcapError


def syn(ts, src, dst, sport, dport, flags="SYN", length=74, proto="TCP", frame=None):
    return PacketRecord(
        timestamp=ts, protocol=proto, source_ip=src, destination_ip=dst,
        source_port=sport, destination_port=dport, tcp_flags=flags,
        packet_length=length, frame_number=frame, pcap_file="synthetic.pcap",
    )


class TestTcpFlagDecoding(unittest.TestCase):
    def test_decode(self):
        self.assertEqual(decode_tcp_flags(0x02), "SYN")
        self.assertEqual(decode_tcp_flags("0x0012"), "SYN,ACK")
        self.assertEqual(decode_tcp_flags(0x10), "ACK")
        self.assertEqual(decode_tcp_flags(0x00), "")
        self.assertIsNone(decode_tcp_flags(None))
        self.assertIsNone(decode_tcp_flags("not-hex"))


class TestFlowGeneration(unittest.TestCase):
    def test_grouping_by_five_tuple(self):
        # Two packets same 5-tuple -> one flow; different dst port -> another.
        pkts = [
            syn(1.0, "10.0.0.5", "10.0.0.9", 40000, 22, frame=1),
            syn(1.4, "10.0.0.5", "10.0.0.9", 40000, 22, flags="ACK", frame=2),
            syn(1.6, "10.0.0.5", "10.0.0.9", 40001, 23, frame=3),
        ]
        flows = build_flows(pkts)
        self.assertEqual(len(flows), 2)
        first = [f for f in flows if f.destination_port == 22][0]
        self.assertEqual(first.packet_count, 2)
        self.assertAlmostEqual(first.duration, 0.4, places=3)
        self.assertEqual(first.flag_counts.get("SYN"), 1)
        self.assertEqual(first.flag_counts.get("ACK"), 1)
        self.assertGreater(first.packets_per_sec, 0)

    def test_distinct_ports_signature_of_scan(self):
        # One source hitting 100 distinct ports (SYN only) = classic scan shape.
        pkts = [syn(1.0 + i * 0.001, "10.0.0.5", "10.0.0.9", 50000 + i, p, frame=i)
                for i, p in enumerate(range(1, 101))]
        dpps = distinct_dst_ports_per_source(pkts)
        self.assertEqual(dpps["10.0.0.5"], 100)

    def test_tcp_handshake_counts(self):
        # Completed: SYN then SYN,ACK on the reverse direction.
        completed_pkts = [
            syn(1.0, "10.0.0.5", "10.0.0.9", 40000, 22, flags="SYN"),
            syn(1.1, "10.0.0.9", "10.0.0.5", 22, 40000, flags="SYN,ACK"),
        ]
        # Incomplete: SYN with no SYN,ACK ever (scan).
        incomplete_pkts = [syn(2.0, "10.0.0.5", "10.0.0.9", 41000, 80, flags="SYN")]
        completed, incomplete = tcp_handshake_counts(completed_pkts + incomplete_pkts)
        self.assertEqual(completed, 1)
        self.assertEqual(incomplete, 1)

    def test_non_tcp_handled(self):
        pkts = [
            PacketRecord(timestamp=1.0, protocol="UDP", source_ip="10.0.0.5",
                         destination_ip="10.0.0.9", source_port=5353,
                         destination_port=53, packet_length=90),
            PacketRecord(timestamp=1.1, protocol="ICMP", source_ip="10.0.0.5",
                         destination_ip="10.0.0.9", packet_length=98),
            PacketRecord(timestamp=1.2, protocol="OTHER", packet_length=60),  # e.g. ARP
        ]
        flows = build_flows(pkts)  # must not raise on None ports / no flags
        self.assertEqual(len(flows), 3)


class TestStorageAndSummary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cybertrace_s2_")
        self.db_path = os.path.join(self.tmp, "s2.db")
        self.conn = db.init_db(self.db_path)

    def tearDown(self):
        self.conn.close()

    def _dataset(self):
        pkts = [
            syn(1.0, "10.0.0.5", "10.0.0.9", 40000, 22, flags="SYN", frame=1),
            syn(1.2, "10.0.0.9", "10.0.0.5", 22, 40000, flags="SYN,ACK", frame=2),
            PacketRecord(timestamp=1.3, protocol="UDP", source_ip="10.0.0.5",
                         destination_ip="10.0.0.9", source_port=5353,
                         destination_port=53, packet_length=90, frame_number=3,
                         pcap_file="synthetic.pcap"),
        ]
        return pkts, build_flows(pkts)

    def test_packets_and_flows_persist(self):
        pkts, flows = self._dataset()
        pkt_ids = store_packets(self.conn, pkts)
        flow_ids = store_flows(self.conn, flows)
        self.assertEqual(len(pkt_ids), 3)
        self.assertEqual(len(flow_ids), len(flows))

        n_pkt = self.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        n_flow = self.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        self.assertEqual(n_pkt, 3)
        self.assertEqual(n_flow, len(flows))

        # a stored packet keeps its fields, including the Stage-2 frame_number
        row = self.conn.execute(
            "SELECT * FROM packets WHERE destination_port = 22 AND tcp_flags = 'SYN'"
        ).fetchone()
        self.assertEqual(row["protocol"], "TCP")
        self.assertEqual(row["frame_number"], 1)
        self.assertEqual(row["pcap_file"], "synthetic.pcap")

        # no alerts were produced in Stage 2
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)

    def test_summary_counts(self):
        pkts, flows = self._dataset()
        s = summarize(pkts, flows, "synthetic.pcap")
        self.assertEqual(s.packets_parsed, 3)
        self.assertEqual(s.tcp_packets, 2)
        self.assertEqual(s.udp_packets, 1)
        self.assertEqual(s.tcp_completed, 1)
        self.assertEqual(s.tcp_incomplete, 0)

    def test_xml_export_is_wellformed(self):
        pkts, flows = self._dataset()
        xml_path = os.path.join(self.tmp, "out.xml")
        export_xml(pkts, flows, xml_path, pcap_file="synthetic.pcap")
        self.assertTrue(os.path.exists(xml_path))
        tree = ET.parse(xml_path)              # raises if malformed
        root = tree.getroot()
        self.assertEqual(root.tag, "cybertrace")
        self.assertEqual(len(root.find("packets").findall("packet")), 3)
        self.assertEqual(root.find("capture").get("pcap_file"), "synthetic.pcap")


class TestParserValidation(unittest.TestCase):
    def test_rejects_missing_and_bad_extension(self):
        with self.assertRaises(PcapError):
            validate_pcap_path("/nonexistent/path/capture.pcap")
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        tmp.close()
        with self.assertRaises(PcapError):
            validate_pcap_path(tmp.name)
        os.unlink(tmp.name)

    def test_parse_requires_pyshark_or_valid_path(self):
        # parse_pcap on a bad path must raise PcapError before importing pyshark.
        from detection_pipeline.pcap_parser import parse_pcap
        with self.assertRaises(PcapError):
            list(parse_pcap("/nope/missing.pcap"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
