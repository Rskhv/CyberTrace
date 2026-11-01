"""Stage 6: missing-step-tolerant reconstruction."""

from dataclasses import dataclass

from .config import CORRELATION_THRESHOLD
from .models import Event, coerce_event
from .stage_model import StageGraph


@dataclass
class InferredEvent:
    event_id: str
    attack_stage: str
    event_type: str
    status: str
    start_time: object
    end_time: object
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    evidence_source: str
    packet_ids: list
    reason: str


def infer_missing_stages(events, correlations, stage_graph: StageGraph | None = None):
    graph = stage_graph or StageGraph()
    normalized = sorted((coerce_event(e) for e in events), key=lambda e: e.timestamp)
    by_id = {e.event_id: e for e in normalized}
    inferred = []

    for correlation in correlations:
        a = by_id.get(correlation.source_event_id)
        b = by_id.get(correlation.target_event_id)
        if not a or not b:
            continue

        if correlation.total_score < CORRELATION_THRESHOLD:
            continue

        missing = graph.intermediate_stages(a.attack_stage, b.attack_stage)
        # Do not infer a step that already has direct packet-backed evidence
        # between these observations.
        already_observed = {
            event.attack_stage
            for event in normalized
            if event.event_id not in {a.event_id, b.event_id}
            and a.timestamp < event.timestamp < b.timestamp
            and event.status != "INFERRED"
            and (not a.source_ip or not event.source_ip or event.source_ip == a.source_ip)
            and (not b.destination_ip or not event.destination_ip or event.destination_ip == b.destination_ip)
        }
        missing = [stage for stage in missing if stage not in already_observed]
        if not missing:
            continue

        for stage in missing:
            inferred.append(
                InferredEvent(
                    event_id=f"INFERRED-{a.event_id}-{b.event_id}-{stage}",
                    attack_stage=stage,
                    event_type=stage,
                    status="INFERRED",
                    start_time=a.timestamp,
                    end_time=b.timestamp,
                    source_ip=a.source_ip if a.source_ip == b.source_ip else None,
                    destination_ip=a.destination_ip if a.destination_ip == b.destination_ip else None,
                    destination_port=None,
                    evidence_source="INFERRED",
                    packet_ids=[],
                    reason=(
                        f"Potential intermediate stage between strongly correlated "
                        f"{a.attack_stage or a.event_type} and {b.attack_stage or b.event_type}; "
                        f"{stage} is defined as an intermediate stage in the configured attack path. "
                        "No direct PCAP evidence is claimed."
                    ),
                )
            )

    # De-duplicate inferred stages that arise from overlapping correlation
    # edges for the same source/target pair.
    unique = {}
    for item in inferred:
        unique.setdefault((item.attack_stage, item.source_ip, item.destination_ip), item)
    return list(unique.values())
