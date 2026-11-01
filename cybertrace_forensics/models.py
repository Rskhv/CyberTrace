"""Small shared models used by this module."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    event_id: str
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    event_type: str = ""
    attack_stage: str | None = None
    evidence_source: str | None = None
    severity: str | None = None
    packet_ids: list[int] = field(default_factory=list)
    flow_id: str | None = None
    evidence_score: float | None = None
    status: str = "DETECTED"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        timestamp = data["timestamp"]
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return cls(
            event_id=str(data["event_id"]),
            timestamp=timestamp,
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            source_port=data.get("source_port"),
            destination_port=data.get("destination_port"),
            protocol=data.get("protocol"),
            event_type=data.get("event_type", ""),
            attack_stage=data.get("attack_stage"),
            evidence_source=data.get("evidence_source"),
            severity=data.get("severity"),
            packet_ids=list(data.get("packet_ids") or []),
            flow_id=data.get("flow_id"),
            evidence_score=data.get("evidence_score"),
            status=data.get("status", "DETECTED"),
            metadata=dict(data.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "event_type": self.event_type,
            "attack_stage": self.attack_stage,
            "evidence_source": self.evidence_source,
            "severity": self.severity,
            "packet_ids": self.packet_ids,
            "flow_id": self.flow_id,
            "evidence_score": self.evidence_score,
            "status": self.status,
            "metadata": self.metadata,
        }


def coerce_event(value: Event | dict[str, Any]) -> Event:
    return value if isinstance(value, Event) else Event.from_dict(value)
