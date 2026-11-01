"""
CyberTrace — SHARED normalized event model (canonical, Stage 1).

⚠️  SHARED CONTRACT (owned jointly by the team).
    Every detector (Stage 3) and the correlation engine (Stage 4+) MUST
    produce / consume this exact NormalizedEvent shape. Do NOT rename fields
    or change the controlled vocabularies without announcing it to the team
    and bumping SCHEMA_VERSION.

A NormalizedEvent maps 1:1 to a row in the `alerts` table (see schema.sql):
every field here is a column there, with `packet_ids` stored as a JSON array.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

SCHEMA_VERSION = "2.0.0"  # Stage 1 canonical model

# -- Controlled vocabularies -------------------------------------------------

# What kind of activity an event represents (one per detector in Stage 3).
EVENT_TYPES = (
    "PORT_SCAN",
    "SSH_BRUTE_FORCE",
    "EXPLOITATION",
)

# Where an event sits in the attack lifecycle. SERVICE_DISCOVERY is defined
# now for completeness (service/version probing) though no Stage-3 detector
# emits it yet.
ATTACK_STAGES = (
    "RECON",
    "SERVICE_DISCOVERY",
    "CREDENTIAL_ATTACK",
    "EXPLOITATION",
)

# Lifecycle of an event. Only DETECTED is produced in Stage 3; INFERRED and
# CORRELATED are populated later by the correlation engine (not implemented yet).
EVENT_STATUSES = (
    "DETECTED",
    "INFERRED",
    "CORRELATED",
)

# Ordered low -> high so severities can be compared numerically if needed.
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Where the evidence behind the event came from.
EVIDENCE_SOURCES = ("PCAP", "GROUND_TRUTH")

PROTOCOLS = ("TCP", "UDP", "ICMP", "OTHER")

# -- Convenience maps (used by detectors and by the Attack Range) ------------

# Default attack stage for each event type.
EVENT_TYPE_TO_STAGE = {
    "PORT_SCAN": "RECON",
    "SSH_BRUTE_FORCE": "CREDENTIAL_ATTACK",
    "EXPLOITATION": "EXPLOITATION",
}

# Attack-Range scenario key -> canonical event type / attack stage. Lets the
# ground-truth log (Stage 0) speak the same vocabulary the detectors emit.
SCENARIO_TO_EVENT_TYPE = {
    "recon": "PORT_SCAN",
    "ssh_bruteforce": "SSH_BRUTE_FORCE",
    "exploit": "EXPLOITATION",
}
SCENARIO_TO_ATTACK_STAGE = {
    "recon": "RECON",
    "ssh_bruteforce": "CREDENTIAL_ATTACK",
    "exploit": "EXPLOITATION",
}


def iso_utc(timestamp: float) -> str:
    """Human-readable UTC ISO-8601 (trailing Z) for an epoch-seconds value."""
    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


@dataclass
class NormalizedEvent:
    """The single event shape every detector emits and every later stage reads.

    Required (positional) fields carry the identity of the event; the rest have
    sensible defaults so a detector only has to set what it actually measured.
    `timestamp` is epoch seconds (UTC). `packet_ids` / `flow_id` point back at
    the supporting evidence rows in the `packets` / `flows` tables.
    """

    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str                       # one of PROTOCOLS
    event_type: str                     # one of EVENT_TYPES
    attack_stage: str                   # one of ATTACK_STAGES
    evidence_source: str                # one of EVIDENCE_SOURCES

    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    severity: str = "MEDIUM"            # one of SEVERITIES
    packet_ids: List[int] = field(default_factory=list)
    flow_id: Optional[int] = None
    evidence_score: float = 0.0         # 0..1, computed from real features
    confidence_score: float = 0.0       # 0..1, set later (correlation); 0 in Stage 3
    status: str = "DETECTED"            # one of EVENT_STATUSES
    evidence: dict = field(default_factory=dict)  # detector-specific support (Stage 3)
    event_id: Optional[int] = None      # assigned by the DB on insert

    # ---- validation -------------------------------------------------------

    def validate(self) -> "NormalizedEvent":
        if self.protocol not in PROTOCOLS:
            raise ValueError(f"protocol {self.protocol!r} not in {PROTOCOLS}")
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"event_type {self.event_type!r} not in {EVENT_TYPES}")
        if self.attack_stage not in ATTACK_STAGES:
            raise ValueError(f"attack_stage {self.attack_stage!r} not in {ATTACK_STAGES}")
        if self.evidence_source not in EVIDENCE_SOURCES:
            raise ValueError(f"evidence_source {self.evidence_source!r} not in {EVIDENCE_SOURCES}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity {self.severity!r} not in {SEVERITIES}")
        if self.status not in EVENT_STATUSES:
            raise ValueError(f"status {self.status!r} not in {EVENT_STATUSES}")
        for name in ("evidence_score", "confidence_score"):
            v = getattr(self, name)
            if not (0.0 <= float(v) <= 1.0):
                raise ValueError(f"{name} must be in [0, 1], got {v}")
        return self

    # ---- (de)serialization to the `alerts` table --------------------------

    # Column order of the `alerts` table (see schema.sql).
    ALERT_COLUMNS = (
        "event_id", "timestamp", "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol", "event_type",
        "attack_stage", "severity", "evidence_source", "packet_ids",
        "flow_id", "evidence_score", "confidence_score", "status", "evidence",
    )

    def to_alert_row(self) -> dict:
        """Dict keyed by `alerts` columns; packet_ids serialized to JSON text."""
        row = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "event_type": self.event_type,
            "attack_stage": self.attack_stage,
            "severity": self.severity,
            "evidence_source": self.evidence_source,
            "packet_ids": json.dumps(list(self.packet_ids)),
            "flow_id": self.flow_id,
            "evidence_score": self.evidence_score,
            "confidence_score": self.confidence_score,
            "status": self.status,
            "evidence": json.dumps(self.evidence or {}),
        }
        return row

    @classmethod
    def from_alert_row(cls, row) -> "NormalizedEvent":
        """Rebuild a NormalizedEvent from a sqlite3.Row / mapping."""
        d = dict(row)
        pkt = d.get("packet_ids") or "[]"
        ev = d.get("evidence") or "{}"
        return cls(
            timestamp=d["timestamp"],
            source_ip=d["source_ip"],
            destination_ip=d["destination_ip"],
            protocol=d["protocol"],
            event_type=d["event_type"],
            attack_stage=d["attack_stage"],
            evidence_source=d["evidence_source"],
            source_port=d.get("source_port"),
            destination_port=d.get("destination_port"),
            severity=d.get("severity", "MEDIUM"),
            packet_ids=json.loads(pkt) if isinstance(pkt, str) else list(pkt),
            flow_id=d.get("flow_id"),
            evidence_score=d.get("evidence_score", 0.0),
            confidence_score=d.get("confidence_score", 0.0),
            status=d.get("status", "DETECTED"),
            evidence=json.loads(ev) if isinstance(ev, str) else dict(ev),
            event_id=d.get("event_id"),
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_utc"] = iso_utc(self.timestamp)
        return d
