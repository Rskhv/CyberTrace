"""
Stage 3 tests — rule-based detectors.

Stdlib only, synthetic packets (no lab, no tshark). Covers the Stage-3 checklist:
  * obvious port scan           -> detected
  * normal traffic              -> not detected
  * repeated SSH attempts       -> detected
  * normal SSH usage            -> not detected
  * suspicious vuln-service      -> detected
  * normal FTP (no backdoor)    -> not detected
Plus: evidence_score bounds, and a DB integration run that stores alerts.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import database as db
from detection_pipeline.packet_record import PacketRecord
from detection_pipeline.detectors import (
    DetectorConfig,
    detect_port_scans,
    detect_ssh_brute_force,
    detect_exploitation,
    detect,
    run_detectors,
)

CFG = DetectorConfig()


def tcp(ts, src, dst, sport, dport, flags="SYN", length=74, pid=None):
    return PacketRecord(timestamp=ts, protocol="TCP", source_ip=src,
                        destination_ip=dst, source_port=sport, destination_port=dport,
                        tcp_flags=flags, packet_length=length, packet_id=pid)


class TestPortScan(unittest.TestCase):
    def test_obvious_scan_detected(self):
        # One source, 40 distinct ports, SYN only, within 2s.
        pkts = [tcp(100.0 + i * 0.05, "10.0.0.5", "10.0.0.9", 50000 + i, p, pid=i + 1)
                for i, p in enumerate(range(1, 41))]
        events = detect_port_scans(pkts, CFG)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e.event_type, "PORT_SCAN")
        self.assertEqual(e.attack_stage, "RECON")
        self.assertEqual(e.status, "DETECTED")
        self.assertGreaterEqual(e.evidence["distinct_ports"], CFG.min_distinct_ports)
        self.assertTrue(0.0 <= e.evidence_score <= 1.0)
        self.assertTrue(e.packet_ids)  # evidence packet ids carried through

    def test_normal_traffic_not_detected(self):
        # A handful of ports only — well under the threshold.
        pkts = [tcp(100.0 + i, "10.0.0.5", "10.0.0.9", 50000 + i, 80 + i, pid=i + 1)
                for i in range(3)]
        self.assertEqual(detect_port_scans(pkts, CFG), [])

    def test_window_matters(self):
        # 40 ports but spread over 400s — not within scan_window_seconds.
        pkts = [tcp(100.0 + i * 10.0, "10.0.0.5", "10.0.0.9", 50000 + i, p, pid=i + 1)
                for i, p in enumerate(range(1, 41))]
        self.assertEqual(detect_port_scans(pkts, CFG), [])


class TestSshBruteForce(unittest.TestCase):
    def test_repeated_attempts_detected(self):
        pkts = [tcp(200.0 + i * 1.0, "10.0.0.5", "10.0.0.9", 40000 + i, 22, pid=i + 1)
                for i in range(12)]
        events = detect_ssh_brute_force(pkts, CFG)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e.event_type, "SSH_BRUTE_FORCE")
        self.assertEqual(e.attack_stage, "CREDENTIAL_ATTACK")
        self.assertEqual(e.destination_port, 22)
        self.assertGreaterEqual(e.evidence["attempts"], CFG.ssh_min_attempts)
        self.assertTrue(0.0 <= e.evidence_score <= 1.0)

    def test_normal_ssh_not_detected(self):
        # Two legitimate logins — under ssh_min_attempts.
        pkts = [tcp(200.0, "10.0.0.5", "10.0.0.9", 40000, 22, pid=1),
                tcp(260.0, "10.0.0.5", "10.0.0.9", 40001, 22, pid=2)]
        self.assertEqual(detect_ssh_brute_force(pkts, CFG), [])


class TestExploitation(unittest.TestCase):
    def test_vsftpd_backdoor_detected(self):
        # Connect to FTP (21), then a backdoor connection on 6200 shortly after.
        pkts = [
            tcp(300.0, "10.0.0.5", "10.0.0.9", 45000, 21, flags="SYN", pid=1),
            tcp(300.1, "10.0.0.5", "10.0.0.9", 45000, 21, flags="ACK", length=200, pid=2),
            tcp(301.5, "10.0.0.5", "10.0.0.9", 45010, 6200, flags="SYN", pid=3),
            tcp(301.6, "10.0.0.5", "10.0.0.9", 45010, 6200, flags="ACK", length=300, pid=4),
        ]
        events = detect_exploitation(pkts, CFG)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e.event_type, "EXPLOITATION")
        self.assertEqual(e.attack_stage, "EXPLOITATION")
        self.assertEqual(e.evidence["vuln_port"], 21)
        self.assertEqual(e.evidence["backdoor_port"], 6200)
        self.assertTrue(0.0 <= e.evidence_score <= 1.0)

    def test_normal_ftp_not_detected(self):
        # FTP traffic with NO backdoor follow-up — must not fire.
        pkts = [
            tcp(300.0, "10.0.0.5", "10.0.0.9", 45000, 21, flags="SYN", pid=1),
            tcp(300.1, "10.0.0.9", "10.0.0.5", 21, 45000, flags="SYN,ACK", pid=2),
            tcp(300.2, "10.0.0.5", "10.0.0.9", 45000, 21, flags="ACK", length=120, pid=3),
        ]
        self.assertEqual(detect_exploitation(pkts, CFG), [])


class TestRunnerAndStorage(unittest.TestCase):
    def test_full_run_stores_alerts(self):
        # Build a capture with all three attack shapes + benign noise.
        pkts = []
        pid = 0

        def add(ts, src, dst, sp, dp, flags="SYN", length=74):
            nonlocal pid
            pid += 1
            pkts.append(tcp(ts, src, dst, sp, dp, flags, length, pid=pid))

        # scan: 30 ports
        for i, p in enumerate(range(1, 31)):
            add(100.0 + i * 0.05, "10.0.0.5", "10.0.0.9", 50000 + i, p)
        # ssh brute: 10 attempts
        for i in range(10):
            add(200.0 + i, "10.0.0.5", "10.0.0.9", 41000 + i, 22)
        # exploitation: 21 then 6200
        add(300.0, "10.0.0.5", "10.0.0.9", 46000, 21, "SYN")
        add(301.0, "10.0.0.5", "10.0.0.9", 46010, 6200, "SYN")

        db_path = os.path.join(tempfile.mkdtemp(prefix="cybertrace_s3_"), "s3.db")
        conn = db.init_db(db_path)
        try:
            # store packets so detectors load them from SQLite
            from detection_pipeline.pipeline import store_packets
            store_packets(conn, pkts)
            events = run_detectors(conn, config=CFG, store=True)

            types = {e.event_type for e in events}
            self.assertEqual(types, {"PORT_SCAN", "SSH_BRUTE_FORCE", "EXPLOITATION"})

            # alerts persisted, with evidence JSON round-tripping
            rows = conn.execute("SELECT event_type, evidence_score, evidence FROM alerts").fetchall()
            self.assertEqual(len(rows), 3)
            for r in rows:
                self.assertTrue(0.0 <= r["evidence_score"] <= 1.0)
                self.assertTrue(r["evidence"].startswith("{"))

            # every stored event got an event_id
            for e in events:
                self.assertIsNotNone(e.event_id)
        finally:
            conn.close()

    def test_detect_is_pure_without_db(self):
        # detect() works on an in-memory list with packet_id=None (no DB).
        pkts = [PacketRecord(timestamp=100.0 + i * 0.05, protocol="TCP",
                             source_ip="10.0.0.5", destination_ip="10.0.0.9",
                             source_port=50000 + i, destination_port=p, tcp_flags="SYN")
                for i, p in enumerate(range(1, 31))]
        events = detect(pkts, CFG)
        self.assertTrue(any(e.event_type == "PORT_SCAN" for e in events))


if __name__ == "__main__":
    unittest.main(verbosity=2)
