"""Flask UI and JSON endpoints for forensic incident review."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template

from .repository import CyberTraceRepository


def _dashboard_snapshot(repository: CyberTraceRepository) -> dict[str, Any]:
    snapshot = repository.snapshot()
    for incident in snapshot["incidents"]:
        incident["start_time_display"] = _display_timestamp(incident.get("start_time"))
        incident["end_time_display"] = _display_timestamp(incident.get("end_time"))
    return snapshot


def _display_timestamp(value: Any) -> Any:
    if isinstance(value, (int, float)):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return value


def create_app(database: str | Path | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    db_path = database or os.environ.get("CYBERTRACE_DB", "data/cybertrace.db")
    repository = CyberTraceRepository(db_path)
    app.config["CYBERTRACE_REPOSITORY"] = repository

    @app.get("/")
    def dashboard() -> str:
        return render_template("dashboard.html", snapshot=_dashboard_snapshot(repository))

    @app.get("/incidents")
    def incidents() -> str:
        return render_template("incidents.html", snapshot=_dashboard_snapshot(repository))

    @app.get("/incident/<incident_id>")
    def incident_page(incident_id: str) -> str:
        item = repository.incident(incident_id)
        if item is None:
            abort(404)
        return render_template("incident.html", item=item)

    @app.get("/api/incidents")
    def api_incidents() -> Any:
        return jsonify(repository.snapshot()["incidents"])

    @app.get("/api/events")
    def api_events() -> Any:
        return jsonify(repository.snapshot()["events"])

    @app.get("/api/correlation/<correlation_id>")
    def api_correlation(correlation_id: str) -> Any:
        rows = repository.snapshot()["correlations"]
        row = next((r for r in rows if str(r.get("correlation_id", r.get("id", ""))) == correlation_id), None)
        if row is None:
            abort(404)
        return jsonify(row)

    return app
