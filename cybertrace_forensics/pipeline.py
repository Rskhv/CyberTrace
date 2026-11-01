"""Convenience integration entry point for stages 4–7."""

from .baseline import correlate_baseline
from .evidence import correlate_evidence_aware
from .incident import build_incidents
from .inference import infer_missing_stages
from .stage_model import StageGraph


def reconstruct_incidents(events, threshold=0.70):
    """Run stages 4–7 over normalized detection events.

    This function intentionally accepts normalized events and does not know
    how they were generated.
    """
    stage_graph = StageGraph()

    baseline = correlate_baseline(events)
    evidence = correlate_evidence_aware(
        events,
        threshold=threshold,
        stage_graph=stage_graph,
    )
    inferred = infer_missing_stages(
        events,
        evidence,
        stage_graph=stage_graph,
    )
    incidents = build_incidents(
        events,
        evidence,
        inferred_events=inferred,
    )

    return {
        "baseline": baseline,
        "evidence_correlations": evidence,
        "inferred_events": inferred,
        "incidents": incidents,
    }
