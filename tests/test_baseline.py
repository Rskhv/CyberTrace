from datetime import datetime, timezone, timedelta

from cybertrace_forensics.baseline import correlate_baseline
from cybertrace_forensics.models import Event


def make(eid, seconds, src="10.0.0.1", dst="10.0.0.2"):
    return Event(
        event_id=eid,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source_ip=src,
        destination_ip=dst,
        destination_port=22,
        event_type="TEST",
    )


def test_baseline_correlates_related_events():
    result = correlate_baseline([make("A", 0), make("B", 20)])
    assert len(result) == 1


def test_baseline_rejects_distant_events():
    result = correlate_baseline([make("A", 0), make("B", 1000)])
    assert result == []
