"""Stage 4: baseline IP/port/time correlation."""

from dataclasses import dataclass
from datetime import timedelta

from .config import BASELINE_TIME_WINDOW_SECONDS
from .models import Event, coerce_event


@dataclass
class BaselineCorrelation:
    source_event_id: str
    target_event_id: str
    incident_key: tuple
    reason: str


def correlate_baseline(events, time_window_seconds: float = BASELINE_TIME_WINDOW_SECONDS):
    normalized = sorted((coerce_event(e) for e in events), key=lambda e: e.timestamp)
    correlations = []

    for i, a in enumerate(normalized):
        for b in normalized[i + 1:]:
            delta = (b.timestamp - a.timestamp).total_seconds()
            if delta < 0 or delta > time_window_seconds:
                continue

            same_source = bool(a.source_ip and a.source_ip == b.source_ip)
            same_target = bool(a.destination_ip and a.destination_ip == b.destination_ip)
            compatible_port = (
                a.destination_port is not None
                and b.destination_port is not None
                and a.destination_port == b.destination_port
            )

            # The baseline is deliberately simple. It links events when
            # there is a shared network identity plus temporal proximity.
            if (same_source and same_target) or (same_source and compatible_port):
                reasons = []
                if same_source:
                    reasons.append("same source IP")
                if same_target:
                    reasons.append("same destination IP")
                if compatible_port:
                    reasons.append("same destination port")
                correlations.append(
                    BaselineCorrelation(
                        source_event_id=a.event_id,
                        target_event_id=b.event_id,
                        incident_key=(
                            a.source_ip,
                            a.destination_ip,
                        ),
                        reason=" + ".join(reasons) + " + within time window",
                    )
                )
    return correlations
