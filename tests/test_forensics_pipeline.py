from datetime import datetime, timezone, timedelta

from cybertrace_forensics.pipeline import reconstruct_incidents


def make(eid, seconds, stage):
    return {
        "event_id": eid,
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": stage,
        "attack_stage": stage,
        "evidence_source": "demo.pcap",
        "severity": "HIGH",
        "packet_ids": [1, 2],
        "evidence_score": 0.9,
    }


def test_pipeline_runs():
    result = reconstruct_incidents([
        make("A", 0, "RECON"),
        make("B", 30, "EXPLOITATION"),
    ])
    assert "baseline" in result
    assert "evidence_correlations" in result
    assert "inferred_events" in result
    assert "incidents" in result
