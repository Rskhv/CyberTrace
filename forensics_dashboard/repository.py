"""Read-only adapter for the shared CyberTrace SQLite database.

The database is owned by the pipeline team. This module deliberately discovers
columns at runtime and never creates, migrates, or writes shared tables.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TABLES = {
    "packets": ("packets",),
    "flows": ("flows",),
    "events": ("alerts", "events"),
    "incidents": ("incidents",),
    "correlations": ("event_correlations", "correlations"),
}


def _decode(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return value
    return parsed


def _timestamp_display(value: Any) -> Any:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return value


def _timestamp_sort_key(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return 0.0


class CyberTraceRepository:
    """Read dashboard summaries from an existing SQLite database file."""

    def __init__(self, database: str | Path):
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(f"file:{self.database.resolve().as_posix()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _find_table(connection: sqlite3.Connection, names: tuple[str, ...]) -> str | None:
        existing = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        return next((name for name in names if name in existing), None)

    def _rows(self, connection: sqlite3.Connection, names: tuple[str, ...], limit: int = 500) -> list[dict[str, Any]]:
        table = self._find_table(connection, names)
        if table is None:
            return []
        # Table names are selected only from the fixed allowlist above.
        return [dict(row) for row in connection.execute(f'SELECT * FROM "{table}" LIMIT ?', (limit,))]

    def snapshot(self) -> dict[str, Any]:
        if not self.database.exists():
            return {"available": False, "database": str(self.database), "counts": {key: 0 for key in TABLES},
                    "incidents": [], "events": [], "correlations": []}
        with closing(self._connect()) as connection:
            result: dict[str, Any] = {"available": True, "database": str(self.database), "counts": {}}
            for key, names in TABLES.items():
                table = self._find_table(connection, names)
                result["counts"][key] = 0 if table is None else connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            result["incidents"] = self._rows(connection, TABLES["incidents"])
            result["events"] = self._rows(connection, TABLES["events"])
            result["correlations"] = self._rows(connection, TABLES["correlations"])
        return result

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        snapshot = self.snapshot()
        if not snapshot["available"]:
            return None
        match = next((row for row in snapshot["incidents"]
                      if str(row.get("incident_id", row.get("id", ""))) == incident_id), None)
        if match is None:
            return None
        iid = match.get("incident_id", match.get("id"))
        events = [row for row in snapshot["events"]
                  if str(row.get("incident_id", "")) == str(iid)]
        # Stage 1 stores ordered alert IDs; compatible schemas may store richer arrays.
        sequence = _decode(match.get("timeline", match.get("event_sequence")))
        if isinstance(sequence, list) and not events:
            by_id = {str(row.get("event_id", row.get("id"))): row for row in snapshot["events"]}
            events = [item if isinstance(item, dict) else by_id[str(item)]
                      for item in sequence if isinstance(item, dict) or str(item) in by_id]
        summary = match.get("summary", "")
        if isinstance(summary, str) and summary.startswith("stage4_7:"):
            metadata = _decode(summary[len("stage4_7:"):])
            if isinstance(metadata, dict):
                events.extend(metadata.get("inferred_events", []))
                match["summary_text"] = metadata.get("text", "")
                match["incident_label"] = metadata.get("incident_label")
        events.sort(key=lambda row: _timestamp_sort_key(row.get("timestamp", row.get("start_time", 0))))
        for event in events:
            if "timestamp" in event:
                event["timestamp_display"] = _timestamp_display(event["timestamp"])
        match["start_time_display"] = _timestamp_display(match.get("start_time"))
        match["end_time_display"] = _timestamp_display(match.get("end_time"))
        correlations = [row for row in snapshot["correlations"]
                        if str(row.get("incident_id", "")) == str(iid)]
        return {"incident": match, "events": events, "correlations": correlations}
