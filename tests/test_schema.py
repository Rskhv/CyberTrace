"""
Stage 1 test — database schema + normalized event model.

Runnable with no lab, no network, stdlib only:

    cd cybertrace
    python -m unittest discover -s tests -v
      (or)
    python tests/test_schema.py

Covers the Stage 1 checklist:
  1. initialize the database
  2. insert a sample packet
  3. insert a sample flow
  4. insert a normalized event
  5. retrieve the event
  6. verify all fields
Plus: model validation, the alerts<->NormalizedEvent round-trip, and a
foreign-key demo across incidents / alerts / event_correlations.
All data is synthetic.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import database as db
from shared.event_model import (
    ATTACK_STAGES,
    EVENT_STATUSES,
    EVENT_TYPES,
    NormalizedEvent,
)


class TestStage1Schema(unittest.TestCase):
    def setUp(self):
        self.db_path = os.path.join(tempfile.mkdtemp(prefix="cybertrace_db_"), "test.db")
        self.conn = db.init_db(self.db_path)

    def tearDown(self):
        self.conn.close()

    # 1. initialize the database
    def test_all_tables_exist(self):
        names = {
            r["name"]
            for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        self.assertTrue({"packets", "flows", "alerts", "event_correlations", "incidents"}.issubset(names))

    def test_insert_and_retrieve_full_pipeline(self):
        # 2. insert a sample packet
        packet_id = db.insert_packet(
            self.conn,
            timestamp=1_000_000.000,
            source_ip="10.10.10.5",
            destination_ip="10.10.10.20",
            source_port=44321,
            destination_port=22,
            protocol="TCP",
            tcp_flags="SYN",
            packet_length=74,
            pcap_file="ssh_bruteforce.pcap",
        )
        self.assertEqual(packet_id, 1)
        pkt = db.get_packet(self.conn, packet_id)
        self.assertEqual(pkt["destination_port"], 22)
        self.assertEqual(pkt["tcp_flags"], "SYN")

        # 3. insert a sample flow
        flow_id = db.insert_flow(
            self.conn,
            source_ip="10.10.10.5",
            destination_ip="10.10.10.20",
            source_port=44321,
            destination_port=22,
            protocol="TCP",
            start_time=1_000_000.0,
            end_time=1_000_002.5,
            packet_count=12,
        )
        flow = db.get_flow(self.conn, flow_id)
        self.assertEqual(flow["packet_count"], 12)
        self.assertAlmostEqual(flow["duration"], 2.5, places=3)  # derived

        # 4. insert a normalized event (references the packet + flow above)
        event = NormalizedEvent(
            timestamp=1_000_001.25,
            source_ip="10.10.10.5",
            destination_ip="10.10.10.20",
            protocol="TCP",
            event_type="SSH_BRUTE_FORCE",
            attack_stage="CREDENTIAL_ATTACK",
            evidence_source="PCAP",
            source_port=44321,
            destination_port=22,
            severity="HIGH",
            packet_ids=[packet_id],
            flow_id=flow_id,
            evidence_score=0.82,
            confidence_score=0.0,
            status="DETECTED",
        )
        event_id = db.insert_event(self.conn, event)
        self.assertEqual(event.event_id, event_id)

        # 5. retrieve the event
        got = db.get_event(self.conn, event_id)
        self.assertIsNotNone(got)

        # 6. verify ALL fields round-tripped exactly
        self.assertEqual(got.event_id, event_id)
        self.assertEqual(got.timestamp, 1_000_001.25)
        self.assertEqual(got.source_ip, "10.10.10.5")
        self.assertEqual(got.destination_ip, "10.10.10.20")
        self.assertEqual(got.source_port, 44321)
        self.assertEqual(got.destination_port, 22)
        self.assertEqual(got.protocol, "TCP")
        self.assertEqual(got.event_type, "SSH_BRUTE_FORCE")
        self.assertEqual(got.attack_stage, "CREDENTIAL_ATTACK")
        self.assertEqual(got.severity, "HIGH")
        self.assertEqual(got.evidence_source, "PCAP")
        self.assertEqual(got.packet_ids, [packet_id])   # JSON array round-trip
        self.assertEqual(got.flow_id, flow_id)
        self.assertAlmostEqual(got.evidence_score, 0.82)
        self.assertAlmostEqual(got.confidence_score, 0.0)
        self.assertEqual(got.status, "DETECTED")

    def test_vocabularies_are_canonical(self):
        self.assertIn("SSH_CONNECTION_ANOMALY", EVENT_TYPES)
        self.assertIn("SSH_BRUTE_FORCE", EVENT_TYPES)
        self.assertEqual(
            ATTACK_STAGES,
            ("RECON", "SERVICE_DISCOVERY", "CREDENTIAL_ATTACK", "EXPLOITATION"),
        )
        self.assertEqual(EVENT_STATUSES, ("DETECTED", "INFERRED", "CORRELATED"))

    def test_model_validation_rejects_bad_values(self):
        bad = NormalizedEvent(
            timestamp=1.0, source_ip="a", destination_ip="b", protocol="TCP",
            event_type="NOT_A_TYPE", attack_stage="RECON", evidence_source="PCAP",
        )
        with self.assertRaises(ValueError):
            bad.validate()

        bad_score = NormalizedEvent(
            timestamp=1.0, source_ip="a", destination_ip="b", protocol="TCP",
            event_type="PORT_SCAN", attack_stage="RECON", evidence_source="PCAP",
            evidence_score=1.5,
        )
        with self.assertRaises(ValueError):
            bad_score.validate()

    def test_foreign_keys_enforced(self):
        import sqlite3

        # An event referencing a non-existent flow must be rejected (FK on).
        orphan = NormalizedEvent(
            timestamp=1.0, source_ip="a", destination_ip="b", protocol="TCP",
            event_type="PORT_SCAN", attack_stage="RECON", evidence_source="PCAP",
            flow_id=99999,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            db.insert_event(self.conn, orphan)

    def test_incident_and_correlation_fk_demo(self):
        # Two events, an incident, and a correlation linking them — proves the
        # schema supports the later correlation pipeline end to end.
        flow_id = db.insert_flow(self.conn, source_ip="10.10.10.5",
                                 destination_ip="10.10.10.20", protocol="TCP",
                                 start_time=1.0, end_time=2.0, packet_count=1)
        e1 = NormalizedEvent(timestamp=1.0, source_ip="10.10.10.5",
                             destination_ip="10.10.10.20", protocol="TCP",
                             event_type="PORT_SCAN", attack_stage="RECON",
                             evidence_source="PCAP", flow_id=flow_id)
        e2 = NormalizedEvent(timestamp=5.0, source_ip="10.10.10.5",
                             destination_ip="10.10.10.20", protocol="TCP",
                             event_type="EXPLOITATION", attack_stage="EXPLOITATION",
                             evidence_source="PCAP", flow_id=flow_id)
        id1 = db.insert_event(self.conn, e1)
        id2 = db.insert_event(self.conn, e2)

        incident_id = db.insert_incident(
            self.conn, start_time=1.0, end_time=5.0, status="DETECTED",
            event_sequence=[id1, id2], summary="recon -> exploitation",
        )
        corr_id = db.insert_correlation(
            self.conn, source_event_id=id1, target_event_id=id2,
            incident_id=incident_id, total_score=0.0,
            explanation="same src/dst within window",
        )
        self.assertGreater(corr_id, 0)
        row = self.conn.execute(
            "SELECT * FROM event_correlations WHERE correlation_id = ?", (corr_id,)
        ).fetchone()
        self.assertEqual(row["incident_id"], incident_id)
        self.assertEqual(row["source_event_id"], id1)
        self.assertEqual(row["target_event_id"], id2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
