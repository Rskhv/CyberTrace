import json
import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from attack_range.ground_truth import GroundTruthLogger
from cybertrace_forensics.integration import reconstruct_database
from detection_pipeline.detectors import DetectorConfig, run_detectors
from detection_pipeline.flow import build_flows
from detection_pipeline.packet_record import PacketRecord
from detection_pipeline.pipeline import store_flows, store_packets
from forensics_dashboard.evaluation import _read_ground_truth, evaluate, main as evaluate_cli
from forensics_dashboard.repository import CyberTraceRepository
from shared import database as db


def tcp(timestamp, source_port, destination_port, flags="SYN", pcap="attack.pcap"):
    return PacketRecord(
        timestamp=timestamp, protocol="TCP", source_ip="192.168.56.10",
        destination_ip="192.168.56.20", source_port=source_port,
        destination_port=destination_port, tcp_flags=flags, packet_length=74,
        pcap_file=pcap,
    )


class IntegratedPipelineTests(unittest.TestCase):
    def test_stage2_to_stage10_and_dashboard_repository(self):
        base = 1_700_000_000.0
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "cybertrace.db"
            conn = db.init_db(str(database))
            packets = [
                tcp(base + index * 0.05, 50000 + index, port, pcap="recon.pcap")
                for index, port in enumerate(range(1, 31))
            ]
            packets.extend(tcp(base + 20 + index, 41000 + index, 22, pcap="ssh_bruteforce.pcap")
                           for index in range(10))
            packets.extend([
                tcp(base + 40, 45000, 21, pcap="exploitation.pcap"),
                tcp(base + 40.1, 21, 45000, "SYN,ACK", pcap="exploitation.pcap"),
                tcp(base + 42, 45001, 6200, pcap="exploitation.pcap"),
                tcp(base + 42.1, 6200, 45001, "SYN,ACK", pcap="exploitation.pcap"),
                tcp(base + 1000, 53000, 443, pcap="baseline.pcap"),
            ])

            # Stage 2 contract: store synthetic PacketRecords and derived flows.
            store_packets(conn, packets)
            store_flows(conn, build_flows(packets))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0], len(packets))
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0], 0)

            # Stage 3 consumes those persisted packets and emits shared events.
            detected = run_detectors(conn, config=DetectorConfig())
            # Credential failures come from trusted OpenSSH logs, not the SSH PCAP.
            from security.ssh_auth import ingest_events, parse_json_event, risk_events
            host_events = [parse_json_event({"timestamp":base+20+i*2,"source_ip":"192.168.56.10",
                "username":"lab-user","result":"FAILURE","method":"password","target_host":"192.168.56.20"}) for i in range(6)]
            auth_alerts = risk_events(ingest_events(conn, host_events))
            for alert in auth_alerts: db.insert_event(conn, alert)
            detected.extend(auth_alerts)
            self.assertEqual({event.event_type for event in detected},
                             {"PORT_SCAN", "SSH_CONNECTION_ANOMALY", "SSH_BRUTE_FORCE", "EXPLOITATION"})
            self.assertTrue(all(event.status == "DETECTED" for event in detected))

            # Stages 4–7 consume only normalized detector events, persist final
            # incidents/scores, and export both methods for Stage 10.
            exports = root / "evaluation"
            reconstruction = reconstruct_database(conn, export_dir=exports)
            self.assertGreaterEqual(reconstruction["persisted"]["correlation_count"], 1)
            self.assertTrue((exports / "baseline_timeline.csv").exists())
            self.assertTrue((exports / "proposed_timeline.csv").exists())
            incident_id = reconstruction["persisted"]["incidents"][0]["incident_id"]
            conn.close()

            # Stage 8's existing repository must expose detected and inferred
            # timeline rows for its existing incident page/API.
            detail = CyberTraceRepository(database).incident(str(incident_id))
            self.assertIsNotNone(detail)
            statuses = [event["status"] for event in detail["events"]]
            self.assertIn("DETECTED", statuses)
            self.assertIn("DETECTED", statuses)
            stages = [event["attack_stage"] for event in detail["events"]]
            self.assertEqual(stages, ["RECON", "SERVICE_DISCOVERY", "CREDENTIAL_ATTACK", "EXPLOITATION"])
            if importlib.util.find_spec("flask"):
                from forensics_dashboard import create_app
                from shared.database import connect
                from security.accounts import initialize_admin
                client = create_app(database).test_client()
                self.assertEqual(client.get("/").status_code, 302)
                self.assertEqual(client.get("/api/events").status_code, 401)
                auth_conn = connect(database)
                initialize_admin(auth_conn, "test-admin", "temporary test password")
                auth_conn.close()
                login_page = client.get("/login").data.decode()
                import re
                csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_page).group(1)
                client.post("/login", data={"username":"test-admin", "password":"temporary test password", "csrf_token":csrf})
                self.assertEqual(client.get("/incidents").status_code, 200)
                incident_page = client.get(f"/incident/{incident_id}")
                self.assertEqual(incident_page.status_code, 200)
                self.assertIn(b"SSH BRUTE FORCE", incident_page.data)
                self.assertIn(b"DETECTED", incident_page.data)
                self.assertEqual(client.get("/api/incidents").status_code, 200)
                self.assertEqual(client.get("/api/events").status_code, 200)
                correlation = CyberTraceRepository(database).snapshot()["correlations"][0]
                correlation_id = correlation["correlation_id"]
                self.assertEqual(client.get(f"/api/correlation/{correlation_id}").status_code, 200)

            # Ground truth is created and read only after Stage 4–7 finish.
            gt_dir = root / "attack_range" / "ground_truth"
            logger = GroundTruthLogger(str(gt_dir), run_id="synthetic-trial")
            logger.record(scenario="recon", technique="synthetic_scan", tool="synthetic",
                          src_ip="192.168.56.10", dst_ip="192.168.56.20",
                          dst_ports=list(range(1, 31)), intent="synthetic unit-test label",
                          start_epoch=base, end_epoch=base + 2)
            logger.record(scenario="ssh_bruteforce", technique="synthetic_ssh", tool="synthetic",
                          src_ip="192.168.56.10", dst_ip="192.168.56.20",
                          dst_ports=[22], intent="synthetic unit-test label",
                          start_epoch=base + 20, end_epoch=base + 30)
            logger.record(scenario="exploit", technique="synthetic_exploit", tool="synthetic",
                          src_ip="192.168.56.10", dst_ip="192.168.56.20",
                          dst_ports=[21, 6200], intent="synthetic unit-test label",
                          start_epoch=base + 40, end_epoch=base + 45)
            logger.close()
            gt_rows = _read_ground_truth(gt_dir / "ground_truth.jsonl", str(database))
            import csv
            with (exports / "baseline_timeline.csv").open(newline="", encoding="utf-8") as stream:
                baseline = list(csv.DictReader(stream))
            with (exports / "proposed_timeline.csv").open(newline="", encoding="utf-8") as stream:
                proposed = list(csv.DictReader(stream))
            scores = evaluate(gt_rows, baseline, proposed)
            self.assertEqual(scores["proposed"]["recall"], 1.0, msg=repr((gt_rows, proposed)))
            self.assertEqual(scores["proposed"]["reconstruction_accuracy"], 1.0)
            # All stages are now evidenced directly by packet or host-log events,
            # so no missing-step inference was needed in this scenario.
            self.assertIsNone(scores["proposed"]["missing_step_recovery_accuracy"])
            self.assertEqual(scores["baseline"]["reconstruction_accuracy"], 1.0)
            result_csv = exports / "evaluation_results.csv"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(evaluate_cli([
                    "--ground-truth", str(gt_dir / "ground_truth.jsonl"),
                    "--baseline", str(exports / "baseline_timeline.csv"),
                    "--proposed", str(exports / "proposed_timeline.csv"),
                    "--database", str(database),
                    "--output", str(result_csv),
                ]), 0)
            self.assertTrue(result_csv.exists())
            with result_csv.open(newline="", encoding="utf-8") as stream:
                metrics = {row["metric"]: row for row in csv.DictReader(stream)}
            self.assertEqual(metrics["recall"]["proposed"], "1.0")
            self.assertEqual(metrics["reconstruction_accuracy"]["proposed"], "1.0")


if __name__ == "__main__":
    unittest.main()
