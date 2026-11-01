from datetime import datetime, timezone, timedelta

from cybertrace_forensics.evidence import correlate_evidence_aware
from cybertrace_forensics.inference import infer_missing_stages
from cybertrace_forensics.models import Event


def make(eid, seconds, stage):
    return Event(
        event_id=eid,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        destination_port=21,
        event_type=stage,
        attack_stage=stage,
        evidence_score=0.95,
    )


def test_missing_service_discovery_is_inferred():
    events = [
        make("A", 0, "RECON"),
        make("B", 30, "EXPLOITATION"),
    ]
    correlations = correlate_evidence_aware(events, threshold=0.50)
    inferred = infer_missing_stages(events, correlations)
    stages = [x.attack_stage for x in inferred]
    assert "SERVICE_DISCOVERY" in stages
    assert all(x.status == "INFERRED" for x in inferred)
    assert all(x.packet_ids == [] for x in inferred)
