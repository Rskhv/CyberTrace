import sqlite3
import tempfile
import unittest
from pathlib import Path

from forensics_dashboard.evaluation import evaluate, write_results
from forensics_dashboard.repository import CyberTraceRepository


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.truth = [
            {"scenario_id": "case-1", "attack_type": "PORT_SCAN", "start_time": "2026-01-01T10:00:00+00:00",
             "end_time": "2026-01-01T10:00:10+00:00", "expected_sequence": "RECON>SERVICE_DISCOVERY>EXPLOITATION"},
            {"scenario_id": "case-1", "attack_type": "EXPLOITATION", "start_time": "2026-01-01T10:00:00+00:00",
             "end_time": "2026-01-01T10:00:10+00:00", "expected_sequence": "RECON>SERVICE_DISCOVERY>EXPLOITATION"},
            {"scenario_id": "benign-1", "attack_type": "BENIGN", "start_time": "2026-01-01T11:00:00+00:00",
             "end_time": "2026-01-01T11:05:00+00:00"},
        ]

    def test_detection_and_reconstruction_scores(self):
        predictions = [
            {"incident_id": "case-1", "timestamp": "2026-01-01T10:00:04+00:00", "event_type": "PORT_SCAN",
             "attack_stage": "RECON", "status": "DETECTED"},
            {"incident_id": "case-1", "timestamp": "2026-01-01T10:00:05+00:00", "event_type": "SERVICE_DISCOVERY",
             "attack_stage": "SERVICE_DISCOVERY", "status": "INFERRED"},
            {"incident_id": "case-1", "timestamp": "2026-01-01T10:00:06+00:00", "event_type": "EXPLOITATION",
             "attack_stage": "EXPLOITATION", "status": "DETECTED"},
        ]
        score = evaluate(self.truth, predictions, predictions)["baseline"]
        self.assertEqual(score["tp"], 2)
        self.assertEqual(score["fn"], 0)
        self.assertEqual(score["fp"], 0)
        self.assertEqual(score["reconstruction_accuracy"], 1)
        self.assertEqual(score["missing_step_recovery_accuracy"], 1)
        self.assertEqual(score["detection_latency_seconds"], 5)

    def test_empty_labels_do_not_fabricate_scores(self):
        score = evaluate([], [], [])["proposed"]
        self.assertIsNone(score["reconstruction_accuracy"])
        self.assertIsNone(score["detection_latency_seconds"])
        self.assertEqual(score["recall"], 0)

    def test_results_csv_is_written(self):
        result = evaluate(self.truth, [], [])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evaluation_results.csv"
            write_results(result, path, parsing_total=20, parsing_correct=19)
            content = path.read_text(encoding="utf-8")
            self.assertIn("pcap_parsing_accuracy", content)
            self.assertIn("0.95", content)


class RepositoryTests(unittest.TestCase):
    def test_reads_shared_tables_without_modifying_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cybertrace.db"
            with sqlite3.connect(db) as connection:
                connection.executescript("""
                    CREATE TABLE packets(packet_id INTEGER);
                    CREATE TABLE flows(flow_id INTEGER);
                    CREATE TABLE alerts(event_id TEXT, incident_id TEXT, timestamp TEXT, event_type TEXT, status TEXT);
                    CREATE TABLE incidents(incident_id TEXT, start_time TEXT, end_time TEXT, confidence_score REAL);
                    CREATE TABLE event_correlations(correlation_id TEXT, incident_id TEXT, total_score REAL);
                    INSERT INTO packets VALUES (1);
                    INSERT INTO incidents VALUES ('case-1','t0','t1',0.9);
                """)
            connection.close()
            snapshot = CyberTraceRepository(db).snapshot()
            self.assertEqual(snapshot["counts"]["packets"], 1)
            self.assertEqual(snapshot["counts"]["incidents"], 1)
            with sqlite3.connect(db) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
            connection.close()

    def test_missing_database_returns_empty_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = CyberTraceRepository(Path(tmp) / "missing.db").snapshot()
        self.assertFalse(snapshot["available"])
        self.assertEqual(snapshot["counts"]["events"], 0)


if __name__ == "__main__":
    unittest.main()
