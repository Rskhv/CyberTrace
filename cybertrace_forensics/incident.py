"""Stage 7: incident reconstruction."""

from dataclasses import dataclass, field

from .models import Event, coerce_event


@dataclass
class Incident:
    incident_id: str
    start_time: object
    end_time: object
    source_ip: str | None
    destination_ip: str | None
    confidence_score: float
    events: list = field(default_factory=list)


def build_incidents(events, correlations, inferred_events=None):
    normalized = sorted((coerce_event(e) for e in events), key=lambda e: e.timestamp)
    inferred_events = inferred_events or []

    by_id = {e.event_id: e for e in normalized}
    parent = {e.event_id: e.event_id for e in normalized}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for c in correlations:
        if c.source_event_id in parent and c.target_event_id in parent:
            union(c.source_event_id, c.target_event_id)

    groups = {}
    for event in normalized:
        groups.setdefault(find(event.event_id), []).append(event)

    incidents = []
    for index, group in enumerate(groups.values(), start=1):
        group.sort(key=lambda e: e.timestamp)
        relevant_correlations = [
            c for c in correlations
            if c.source_event_id in {e.event_id for e in group}
            and c.target_event_id in {e.event_id for e in group}
        ]

        # BaselineCorrelation intentionally has no numeric score; baseline
        # incident confidence is therefore derived only from attached events.
        scores = [getattr(c, "total_score", 0.0) for c in relevant_correlations]
        evidence_scores = [
            e.evidence_score for e in group
            if e.evidence_score is not None
        ]

        components = scores + evidence_scores
        confidence = sum(components) / len(components) if components else 0.0

        related_inferred = []
        for item in inferred_events:
            if item.source_ip and item.destination_ip:
                same_hosts = any(
                    e.source_ip == item.source_ip and e.destination_ip == item.destination_ip
                    for e in group
                )
                within_group_window = (
                    item.start_time <= group[-1].timestamp
                    and item.end_time >= group[0].timestamp
                )
                if same_hosts and within_group_window:
                    related_inferred.append(item)

        incidents.append(
            Incident(
                incident_id=f"INC-{index:03d}",
                start_time=group[0].timestamp,
                end_time=group[-1].timestamp,
                source_ip=group[0].source_ip,
                destination_ip=group[0].destination_ip,
                confidence_score=round(confidence, 4),
                events=group + related_inferred,
            )
        )

    return incidents
