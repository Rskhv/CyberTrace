"""Adapters between the shared SQLite contracts and Stages 4–7."""
from __future__ import annotations

import csv
import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared import database as db
from shared.event_model import NormalizedEvent

from .baseline import correlate_baseline
from .incident import build_incidents
from .models import Event
from .pipeline import reconstruct_incidents


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_for_forensics(event: NormalizedEvent) -> dict[str, Any]:
    """Convert Stage 1–3 epoch/event objects to the Stage 4–7 event contract."""
    return {
        "event_id": str(event.event_id),
        "timestamp": _iso(event.timestamp),
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "event_type": event.event_type,
        "attack_stage": event.attack_stage,
        "evidence_source": event.evidence_source,
        "severity": event.severity,
        "packet_ids": list(event.packet_ids or []),
        "flow_id": str(event.flow_id) if event.flow_id is not None else None,
        "evidence_score": event.evidence_score,
        "confidence_score": event.confidence_score,
        "status": event.status,
        "metadata": dict(event.evidence or {}),
    }


def load_events(conn: sqlite3.Connection) -> list[NormalizedEvent]:
    return db.list_events(conn)


def _event_row(event: Any, incident_id: str) -> dict[str, Any]:
    if isinstance(event, Event):
        row = event.to_dict()
        row["timestamp"] = _iso(event.timestamp)
        row["incident_id"] = incident_id
        return row
    row = asdict(event) if is_dataclass(event) else dict(event)
    start = row.get("start_time", row.get("timestamp"))
    end = row.get("end_time", start)
    # Inferred stages span the observed events. Place them midway for a stable,
    # chronological presentation while retaining the full inference interval.
    if isinstance(start, datetime) and isinstance(end, datetime):
        stamp = start + (end - start) / 2
    else:
        stamp = start
    row["timestamp"] = _iso(stamp)
    row["inference_start"] = _iso(start)
    row["inference_end"] = _iso(end)
    row["incident_id"] = incident_id
    row["packet_ids"] = []
    row["flow_id"] = None
    row["evidence_source"] = "INFERRED"
    row["evidence"] = {"reason": row.get("reason", ""), "direct_pcap_evidence": False}
    return row


def _timeline_rows(incidents: list[Any], label_prefix: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, incident in enumerate(incidents, start=1):
        label = f"{label_prefix}-{index:03d}"
        timeline = [_event_row(event, label) for event in incident.events]
        timeline.sort(key=lambda row: row["timestamp"])
        rows.extend(timeline)
    return rows


def _write_timeline(path: str | Path, rows: list[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    columns = ("incident_id", "timestamp", "event_id", "event_type", "attack_stage", "status",
               "source_ip", "destination_ip", "source_port", "destination_port", "evidence_source",
               "evidence_score", "packet_ids", "flow_id")
    with target.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "packet_ids": json.dumps(row.get("packet_ids", []))})


def _inferred_row(item: Any) -> dict[str, Any]:
    start, end = item.start_time, item.end_time
    midpoint = start + (end - start) / 2
    return {
        "event_id": item.event_id,
        "timestamp": _iso(midpoint),
        "event_type": item.event_type,
        "attack_stage": item.attack_stage,
        "status": "INFERRED",
        "source_ip": item.source_ip,
        "destination_ip": item.destination_ip,
        "destination_port": item.destination_port,
        "protocol": None,
        "evidence_source": "INFERRED",
        "packet_ids": [],
        "flow_id": None,
        "evidence_score": None,
        "reason": item.reason,
        "inference_start": _iso(start),
        "inference_end": _iso(end),
    }


def persist_reconstruction(conn: sqlite3.Connection, events: list[NormalizedEvent], result: dict[str, Any]) -> dict[str, Any]:
    """Persist proposed Stage 5–7 output using the existing Stage 1 schema.

    Replaces only incidents previously written by this adapter, identified by
    the `stage4_7:` summary prefix; detections and unrelated incidents remain.
    """
    old_ids = [row[0] for row in conn.execute(
        "SELECT incident_id FROM incidents WHERE summary LIKE 'stage4_7:%'").fetchall()]
    if old_ids:
        conn.executemany("DELETE FROM event_correlations WHERE incident_id = ?", ((iid,) for iid in old_ids))
        conn.executemany("DELETE FROM incidents WHERE incident_id = ?", ((iid,) for iid in old_ids))
    conn.commit()

    event_id_by_string = {str(event.event_id): int(event.event_id) for event in events if event.event_id is not None}
    incident_by_event: dict[str, int] = {}
    stored_incidents: list[dict[str, Any]] = []
    all_inferred = {item.event_id: _inferred_row(item) for item in result["inferred_events"]}
    for incident in result["incidents"]:
        detected_ids = [event_id_by_string[str(event.event_id)] for event in incident.events
                        if isinstance(event, Event) and str(event.event_id) in event_id_by_string]
        incident_inferred = [all_inferred[event.event_id] for event in incident.events
                             if getattr(event, "status", None) == "INFERRED" and event.event_id in all_inferred]
        edge_pairs = {(str(edge.source_event_id), str(edge.target_event_id))
                      for edge in result["evidence_correlations"]}
        group_ids = {str(item) for item in detected_ids}
        is_correlated = any(a in group_ids and b in group_ids for a, b in edge_pairs)
        summary = json.dumps({
            "module": "stage4_7",
            "incident_label": incident.incident_id,
            "text": f"Reconstructed from {len(detected_ids)} detected event(s).",
            "inferred_events": incident_inferred,
        }, ensure_ascii=False)
        incident_db_id = db.insert_incident(
            conn,
            start_time=incident.start_time.timestamp(),
            end_time=incident.end_time.timestamp(),
            confidence_score=incident.confidence_score,
            status="CORRELATED" if is_correlated else "DETECTED",
            event_sequence=detected_ids,
            summary=f"stage4_7:{summary}",
        )
        for event_id in detected_ids:
            incident_by_event[str(event_id)] = incident_db_id
        stored_incidents.append({"incident_id": incident_db_id, "label": incident.incident_id,
                                 "event_ids": detected_ids, "inferred_events": incident_inferred})

    stored_correlations = 0
    for edge in result["evidence_correlations"]:
        incident_id = incident_by_event.get(str(edge.source_event_id))
        if incident_id is None or incident_by_event.get(str(edge.target_event_id)) != incident_id:
            continue
        db.insert_correlation(
            conn,
            incident_id=incident_id,
            source_event_id=int(edge.source_event_id),
            target_event_id=int(edge.target_event_id),
            temporal_score=edge.temporal_score,
            ip_score=edge.ip_score,
            port_score=edge.port_score,
            stage_score=edge.stage_score,
            evidence_score=edge.evidence_score,
            total_score=edge.total_score,
            explanation=edge.explanation,
        )
        stored_correlations += 1
    return {"incidents": stored_incidents, "correlation_count": stored_correlations}


def reconstruct_database(conn: sqlite3.Connection, threshold: float = 0.70,
                         export_dir: str | Path | None = None, persist: bool = True) -> dict[str, Any]:
    events = load_events(conn)
    stage_events = [normalize_for_forensics(event) for event in events]
    result = reconstruct_incidents(stage_events, threshold=threshold)
    # Baseline shares Stage 7's timeline formatting but keeps the original
    # baseline IP/port/time relationship algorithm and never receives GT data.
    baseline_edges = correlate_baseline(stage_events)
    baseline_incidents = build_incidents(stage_events, baseline_edges, inferred_events=[])
    persisted = persist_reconstruction(conn, events, result) if persist else {"incidents": [], "correlation_count": 0}
    baseline_rows = _timeline_rows(baseline_incidents, "BASE")
    proposed_rows = _timeline_rows(result["incidents"], "PROP")
    if export_dir is not None:
        export_dir = Path(export_dir)
        _write_timeline(export_dir / "baseline_timeline.csv", baseline_rows)
        _write_timeline(export_dir / "proposed_timeline.csv", proposed_rows)
    return {**result, "baseline_incidents": baseline_incidents, "baseline_rows": baseline_rows,
            "proposed_rows": proposed_rows, "persisted": persisted, "event_count": len(events)}
