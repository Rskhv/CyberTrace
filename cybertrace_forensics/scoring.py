"""Explainable scoring functions for evidence-aware correlation."""

from datetime import datetime
from math import exp

from .config import CORRELATION_TIME_WINDOW_SECONDS, CORRELATION_WEIGHTS
from .models import Event
from .stage_model import StageGraph


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def calculate_temporal_score(a: Event, b: Event, max_seconds: float = CORRELATION_TIME_WINDOW_SECONDS) -> float:
    delta = abs((b.timestamp - a.timestamp).total_seconds())
    if delta > max_seconds:
        return 0.0
    return _clamp(exp(-delta / max(max_seconds, 1.0)))


def calculate_ip_score(a: Event, b: Event) -> float:
    score = 0.0
    comparisons = 0
    if a.source_ip and b.source_ip:
        comparisons += 1
        score += 1.0 if a.source_ip == b.source_ip else 0.0
    if a.destination_ip and b.destination_ip:
        comparisons += 1
        score += 1.0 if a.destination_ip == b.destination_ip else 0.0
    if not comparisons:
        return 0.0
    return score / comparisons


def calculate_port_score(a: Event, b: Event) -> float:
    if a.destination_port is None or b.destination_port is None:
        return 0.0
    if a.destination_port == b.destination_port:
        return 1.0
    # A reconnaissance event targeting the later service is still related.
    if a.attack_stage in {"RECON", "SERVICE_DISCOVERY"}:
        return 0.35
    return 0.10


def calculate_stage_score(a: Event, b: Event, stage_graph: StageGraph | None = None) -> float:
    graph = stage_graph or StageGraph()
    return graph.transition_score(a.attack_stage, b.attack_stage)


def calculate_evidence_score(a: Event, b: Event) -> float:
    values = [v for v in (a.evidence_score, b.evidence_score) if v is not None]
    if not values:
        return 0.0
    return _clamp(sum(values) / len(values))


def calculate_correlation_score(
    a: Event,
    b: Event,
    stage_graph: StageGraph | None = None,
    weights: dict[str, float] | None = None,
) -> dict:
    weights = weights or CORRELATION_WEIGHTS
    components = {
        "temporal": calculate_temporal_score(a, b),
        "ip": calculate_ip_score(a, b),
        "port": calculate_port_score(a, b),
        "stage": calculate_stage_score(a, b, stage_graph),
        "evidence": calculate_evidence_score(a, b),
    }
    total = sum(components[key] * weights[key] for key in components)
    total = _clamp(total)

    reasons = []
    if components["temporal"] >= 0.7:
        reasons.append("close temporal proximity")
    if components["ip"] >= 0.75:
        reasons.append("matching source/destination IP relationship")
    if components["port"] >= 0.7:
        reasons.append("compatible service/port relationship")
    if components["stage"] >= 0.7:
        reasons.append("valid attack-stage transition")
    if components["evidence"] >= 0.7:
        reasons.append("strong supporting PCAP evidence")

    explanation = (
        "Correlated because " + ", ".join(reasons) + "."
        if reasons
        else "Correlation is supported only weakly by the available event relationships."
    )

    return {
        **components,
        "total": total,
        "explanation": explanation,
    }
