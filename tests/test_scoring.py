from datetime import datetime, timezone, timedelta

from cybertrace_forensics.models import Event
from cybertrace_forensics.scoring import calculate_correlation_score


def event(eid, seconds, stage, evidence=0.9, port=22):
    return Event(
        event_id=eid,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source_ip="192.168.56.10",
        destination_ip="192.168.56.20",
        destination_port=port,
        event_type=stage,
        attack_stage=stage,
        evidence_score=evidence,
    )


def test_strong_correlation():
    result = calculate_correlation_score(
        event("A", 0, "RECON"),
        event("B", 10, "SERVICE_DISCOVERY"),
    )
    assert 0 <= result["total"] <= 1
    assert result["stage"] > 0.5
    assert result["evidence"] > 0.5


def test_scores_are_bounded():
    result = calculate_correlation_score(
        event("A", 0, "RECON", evidence=2),
        event("B", 1, "EXPLOITATION", evidence=-1),
    )
    for key in ["temporal", "ip", "port", "stage", "evidence", "total"]:
        assert 0 <= result[key] <= 1
