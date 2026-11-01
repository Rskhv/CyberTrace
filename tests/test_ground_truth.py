"""
Runnable test for the Attack Range module's INTERFACE — the ground-truth log.

Any teammate can run this with no lab, no root, and none of the attack tools:

    cd cybertrace
    python -m unittest discover -s tests -v
      (or)
    python tests/test_ground_truth.py

It exercises the ground-truth logger end to end:
  * a successful action recorded via the context manager,
  * a failing action still recorded (status="failed") with the exception
    re-raised,
  * a dry-run scenario plan built WITHOUT running any tool,
  * JSONL and SQLite outputs agree and carry the shared event-type vocabulary,
  * isolation check correctly rejects a non-isolated target.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_range.ground_truth import GroundTruthLogger, load_jsonl
from attack_range.isolation_check import check_isolation
from attack_range.scenarios import recon_nmap, ssh_bruteforce, exploit_metasploit
from shared.event_model import EVENT_TYPES, SCENARIO_TO_EVENT_TYPE


class TestGroundTruthLogger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cybertrace_gt_")

    def test_context_manager_records_success_and_failure(self):
        gt = GroundTruthLogger(out_dir=self.tmp, run_id="run-test")

        with gt.action(
            scenario="recon", technique="tcp_syn_scan", tool="nmap",
            src_ip="10.10.10.5", dst_ip="10.10.10.20", dst_ports=[],
            intent="scan", extra={"port_spec": "1-1024"},
        ) as h:
            h.add_extra(returncode=0)

        # A failing action must still be recorded, then re-raise.
        with self.assertRaises(RuntimeError):
            with gt.action(
                scenario="exploit", technique="vsftpd_234_backdoor",
                tool="metasploit", src_ip="10.10.10.5", dst_ip="10.10.10.20",
                dst_ports=[21], intent="exploit",
            ):
                raise RuntimeError("boom")

        gt.close()

        rows = load_jsonl(gt.jsonl_path)
        self.assertEqual(len(rows), 2)

        recon, exploit = rows
        # action_ids are sequential and start at 1
        self.assertEqual(recon["action_id"], 1)
        self.assertEqual(exploit["action_id"], 2)
        # statuses
        self.assertEqual(recon["status"], "completed")
        self.assertEqual(exploit["status"], "failed")
        self.assertIn("RuntimeError: boom", exploit["notes"])
        # shared vocabulary alignment
        self.assertEqual(recon["expected_event_type"], SCENARIO_TO_EVENT_TYPE["recon"])
        self.assertIn(recon["expected_event_type"], EVENT_TYPES)
        # timestamps present and ordered
        self.assertIsNotNone(recon["end_epoch"])
        self.assertGreaterEqual(recon["end_epoch"], recon["start_epoch"])
        self.assertTrue(recon["start_utc"].endswith("Z"))

    def test_sqlite_matches_jsonl(self):
        gt = GroundTruthLogger(out_dir=self.tmp, run_id="run-sql")
        gt.record(
            scenario="ssh_bruteforce", technique="ssh_dictionary_attack",
            tool="hydra", src_ip="10.10.10.5", dst_ip="10.10.10.20",
            dst_ports=[22], intent="brute force",
            start_epoch=1000.0, end_epoch=1002.5,
        )
        gt.close()

        rows = load_jsonl(gt.jsonl_path)
        self.assertEqual(len(rows), 1)

        conn = sqlite3.connect(gt.sqlite_path)
        conn.row_factory = sqlite3.Row
        db_rows = conn.execute("SELECT * FROM ground_truth").fetchall()
        conn.close()

        self.assertEqual(len(db_rows), 1)
        r = db_rows[0]
        self.assertEqual(r["scenario"], "ssh_bruteforce")
        self.assertEqual(r["dst_ip"], "10.10.10.20")
        self.assertEqual(json.loads(r["dst_ports"]), [22])
        self.assertAlmostEqual(r["duration_s"], 2.5, places=3)
        self.assertEqual(r["expected_event_type"], "SSH_BRUTE_FORCE")

    def test_summary_counts(self):
        gt = GroundTruthLogger(out_dir=self.tmp, run_id="run-sum", write_sqlite=False)
        gt.record(scenario="recon", technique="t", tool="nmap",
                  src_ip="10.10.10.5", dst_ip="10.10.10.20", dst_ports=[],
                  intent="x", end_epoch=1.0, start_epoch=0.0)
        gt.record(scenario="recon", technique="t", tool="nmap",
                  src_ip="10.10.10.5", dst_ip="10.10.10.20", dst_ports=[],
                  intent="x", status="failed", end_epoch=1.0, start_epoch=0.0)
        s = gt.summary()
        gt.close()
        self.assertEqual(s["action_count"], 2)
        self.assertEqual(s["by_scenario"]["recon"], {"total": 2, "completed": 1, "failed": 1})


class TestScenarioPlans(unittest.TestCase):
    """Plans are pure: they build the command without running any tool."""

    CFG = {
        "lab": {"attacker_ip": "10.10.10.5", "target_ip": "10.10.10.20"},
        "output": {"artifacts_dir": tempfile.mkdtemp(prefix="cybertrace_plan_")},
        "scenarios": {
            "recon": {"ports": "1-1024", "nmap_extra": ["-sS", "-sV"]},
            "ssh_bruteforce": {"port": 22, "username": "msfadmin",
                               "wordlist": "attack_range/wordlists/lab_ssh.txt"},
            "exploit": {"port": 21, "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor"},
        },
    }

    def test_recon_plan(self):
        p = recon_nmap.plan(self.CFG)
        self.assertEqual(p["tool"], "nmap")
        self.assertEqual(p["command"][0], "nmap")
        self.assertIn("10.10.10.20", p["command"])
        self.assertEqual(p["extra"]["port_spec"], "1-1024")

    def test_ssh_plan(self):
        p = ssh_bruteforce.plan(self.CFG)
        self.assertEqual(p["tool"], "hydra")
        self.assertEqual(p["dst_ports"], [22])
        self.assertIn("ssh", p["command"])

    def test_exploit_plan_writes_resource_script(self):
        p = exploit_metasploit.plan(self.CFG)
        self.assertEqual(p["tool"], "metasploit")
        rc = p["extra"]["resource_script"]
        self.assertTrue(os.path.exists(rc))
        with open(rc) as fh:
            body = fh.read()
        self.assertIn("set RHOSTS 10.10.10.20", body)
        self.assertIn("exploit/unix/ftp/vsftpd_234_backdoor", body)


class TestIsolationCheck(unittest.TestCase):
    def test_rejects_public_target(self):
        # 8.8.8.8 is public and outside the lab subnet -> must fail.
        report = check_isolation(
            lab_subnet="10.10.10.0/24", attacker_ip="10.10.10.5",
            target_ip="8.8.8.8", probe_internet=False,
        )
        self.assertFalse(report.ok)

    def test_accepts_isolated_target(self):
        report = check_isolation(
            lab_subnet="10.10.10.0/24", attacker_ip="10.10.10.5",
            target_ip="10.10.10.20", probe_internet=False,
        )
        self.assertTrue(report.ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
