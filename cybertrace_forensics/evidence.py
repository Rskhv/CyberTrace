"""Stage 5: evidence-aware correlation."""

from dataclasses import dataclass

from .config import CORRELATION_THRESHOLD
from .models import Event, coerce_event
from .scoring import calculate_correlation_score
from .stage_model import StageGraph


@dataclass
class EvidenceCorrelation:
    source_event_id: str
    target_event_id: str
    temporal_score: float
    ip_score: float
    port_score: float
    stage_score: float
    evidence_score: float
    total_score: float
    explanation: str


def correlate_evidence_aware(
    events,
    threshold: float = CORRELATION_THRESHOLD,
    stage_graph: StageGraph | None = None,
):
    normalized = sorted((coerce_event(e) for e in events), key=lambda e: e.timestamp)
    correlations = []

    for i, a in enumerate(normalized):
        for b in normalized[i + 1:]:
            scores = calculate_correlation_score(a, b, stage_graph=stage_graph)

            # A zero temporal score means the events are outside the
            # configured correlation window.
            if scores["temporal"] <= 0:
                continue

            if scores["total"] >= threshold:
                correlations.append(
                    EvidenceCorrelation(
                        source_event_id=a.event_id,
                        target_event_id=b.event_id,
                        temporal_score=scores["temporal"],
                        ip_score=scores["ip"],
                        port_score=scores["port"],
                        stage_score=scores["stage"],
                        evidence_score=scores["evidence"],
                        total_score=scores["total"],
                        explanation=scores["explanation"],
                    )
                )
    return correlations
