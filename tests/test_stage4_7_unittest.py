"""Run the supplied Stage 4–7 pytest-style checks under unittest as well."""
import unittest
from datetime import datetime, timezone, timedelta

from cybertrace_forensics.incident import build_incidents
from cybertrace_forensics.inference import InferredEvent
from cybertrace_forensics.models import Event
from .test_baseline import test_baseline_correlates_related_events, test_baseline_rejects_distant_events
from .test_inference import test_missing_service_discovery_is_inferred
from .test_forensics_pipeline import test_pipeline_runs
from .test_scoring import test_strong_correlation, test_scores_are_bounded


class SuppliedStage47Tests(unittest.TestCase):
    def test_baseline_correlates_related_events(self):
        test_baseline_correlates_related_events()

    def test_baseline_rejects_distant_events(self):
        test_baseline_rejects_distant_events()

    def test_missing_service_discovery_is_inferred(self):
        test_missing_service_discovery_is_inferred()

    def test_pipeline_runs(self):
        test_pipeline_runs()

    def test_strong_correlation(self):
        test_strong_correlation()

    def test_scores_are_bounded(self):
        test_scores_are_bounded()

    def test_inferred_event_is_not_copied_to_a_later_incident(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            Event("a", start, "192.0.2.1", "192.0.2.2", event_type="PORT_SCAN", attack_stage="RECON"),
            Event("b", start + timedelta(hours=1), "192.0.2.1", "192.0.2.2",
                  event_type="PORT_SCAN", attack_stage="RECON"),
        ]
        inferred = InferredEvent(
            event_id="inf-a",
            attack_stage="SERVICE_DISCOVERY",
            event_type="SERVICE_DISCOVERY",
            status="INFERRED",
            start_time=start,
            end_time=start + timedelta(seconds=20),
            source_ip="192.0.2.1",
            destination_ip="192.0.2.2",
            destination_port=None,
            evidence_source="INFERRED",
            packet_ids=[],
            reason="test inference",
        )
        incidents = build_incidents(events, [], inferred_events=[inferred])
        self.assertEqual([len(incident.events) for incident in incidents], [2, 1])
