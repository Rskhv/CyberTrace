"""Flask UI and JSON endpoints for forensic incident review."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import secrets
import time
from functools import wraps
from flask import Flask, abort, jsonify, render_template, request, session, redirect, url_for, current_app

from .repository import CyberTraceRepository
from shared.database import connect, init_db
from security.accounts import authenticate, create_user, has_permission
from security.crypto import append_audit_record, verify_evidence, verify_audit_chain, verify_audit_checkpoint


def _permission_required(permission: str):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            uid = session.get("user_id")
            if not uid: return redirect(url_for("login", next=request.path)) if not request.path.startswith("/api/") else (jsonify({"error":"authentication required"}),401)
            conn = connect(current_app.config["CYBERTRACE_DB_PATH"])
            try: allowed = has_permission(conn, int(uid), permission)
            finally: conn.close()
            if not allowed: abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorate


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
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = init_db(str(db_path)); conn.close()
    secret = os.environ.get("CYBERTRACE_SECRET_KEY")
    if not secret:
        secret = secrets.token_urlsafe(48)
    repository = CyberTraceRepository(db_path)
    app.config["CYBERTRACE_REPOSITORY"] = repository
    app.config["CYBERTRACE_DB_PATH"] = str(db_path)
    app.secret_key = secret
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=os.environ.get("CYBERTRACE_COOKIE_SECURE", "0") == "1",
                      PERMANENT_SESSION_LIFETIME=1800)

    @app.context_processor
    def inject_security_context():
        if session.get("user_id"):
            session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return {"csrf_token":session.get("csrf_token", ""), "username":session.get("username")}

    @app.before_request
    def enforce_csrf():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            token = session.get("csrf_token")
            provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not token or not provided or not secrets.compare_digest(token, provided):
                abort(400, description="CSRF validation failed")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.get("/login")
    def login():
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("login.html", csrf_token=session["csrf_token"], error=None)

    @app.post("/login")
    def login_submit():
        conn = connect(app.config["CYBERTRACE_DB_PATH"])
        try: user = authenticate(conn, request.form.get("username", ""), request.form.get("password", ""))
        finally: conn.close()
        if not user:
            session["csrf_token"] = secrets.token_urlsafe(32)
            return render_template("login.html", csrf_token=session["csrf_token"], error="Invalid credentials or login temporarily limited."), 401
        session.clear(); session.permanent = True
        session["user_id"], session["username"], session["roles"] = user["user_id"], user["username"], user["roles"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        conn = connect(app.config["CYBERTRACE_DB_PATH"])
        try: append_audit_record(conn, actor=user["username"], action="dashboard.login", record={"roles":user["roles"]})
        finally: conn.close()
        destination = request.args.get("next", "")
        return redirect(destination if destination.startswith("/") and not destination.startswith("//") else url_for("dashboard"))

    @app.post("/logout")
    def logout():
        username = session.get("username", "unknown")
        conn = connect(app.config["CYBERTRACE_DB_PATH"])
        try: append_audit_record(conn, actor=username, action="dashboard.logout", record={})
        finally: conn.close()
        session.clear()
        return redirect(url_for("login"))

    @app.post("/api/users")
    @_permission_required("users.manage")
    def register_user():
        conn = connect(app.config["CYBERTRACE_DB_PATH"])
        try:
            body = request.get_json(force=True)
            uid = create_user(conn, body["username"], body["password"], body["roles"])
            append_audit_record(conn, actor=session.get("username", "unknown"), action="users.create", record={"user_id":uid,"roles":body["roles"]})
        except (KeyError, ValueError) as exc:
            abort(400, description=str(exc))
        finally: conn.close()
        return jsonify({"user_id":uid}), 201

    @app.get("/api/users")
    @_permission_required("users.manage")
    def list_users():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try:
            rows=conn.execute("""SELECT u.user_id,u.username,u.active,u.created_at,group_concat(r.name) roles
                FROM users u LEFT JOIN user_roles ur USING(user_id) LEFT JOIN roles r USING(role_id)
                GROUP BY u.user_id ORDER BY u.username""").fetchall()
            return jsonify([dict(row) for row in rows])
        finally: conn.close()

    @app.get("/api/security/overview")
    @_permission_required("dashboard.view")
    def security_overview():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try:
            result={}
            for name,table in (("authentication_events","authentication_events"),("active_authorizations","scan_authorizations"),("response_actions","response_actions"),("audit_records","audit_log")):
                result[name]=conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            result["active_restrictions"]=conn.execute("SELECT COUNT(*) FROM blocked_sources WHERE status='ACTIVE'").fetchone()[0]
            return jsonify(result)
        finally: conn.close()

    @app.get("/api/security/authentication")
    @_permission_required("incidents.view")
    def security_authentication():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try: return jsonify([dict(r) for r in conn.execute("SELECT auth_event_id,timestamp,source_ip,username,result,method,target_host,event_type FROM authentication_events ORDER BY timestamp DESC LIMIT 500")])
        finally: conn.close()

    @app.get("/api/security/risk")
    @_permission_required("incidents.view")
    def security_risk():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try: return jsonify([dict(r) for r in conn.execute("SELECT risk_id,timestamp,score,source_ip,username,window_counts,reason FROM risk_history ORDER BY timestamp DESC LIMIT 500")])
        finally: conn.close()

    @app.get("/api/security/authorizations")
    @_permission_required("scans.approve")
    def security_authorizations():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try: return jsonify([dict(r) for r in conn.execute("SELECT authorization_id,scan_id,scanner_id,target_ip,permitted_ports,permitted_protocols,permitted_scan_types,issued_at,expires_at,status FROM scan_authorizations ORDER BY issued_at DESC LIMIT 500")])
        finally: conn.close()

    @app.get("/api/security/responses")
    @_permission_required("response.review")
    def security_responses():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try: return jsonify([dict(r) for r in conn.execute("SELECT * FROM response_actions ORDER BY executed_at DESC LIMIT 500")])
        finally: conn.close()

    @app.get("/api/security/audit")
    @_permission_required("audit.read")
    def security_audit():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try: return jsonify([dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT 1000")])
        finally: conn.close()

    @app.post("/api/security/evidence/verify")
    @_permission_required("signatures.verify")
    def verify_evidence_api():
        body=request.get_json(force=True); conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try:
            row=conn.execute("SELECT * FROM evidence_manifests WHERE manifest_id=?",(body.get("manifest_id"),)).fetchone()
            if not row: abort(404)
            key=conn.execute("SELECT public_material FROM cryptographic_keys WHERE key_id=? AND revoked_at IS NULL",(row["key_id"],)).fetchone()
            if not key or not key[0]: return jsonify({"status":"UNKNOWN_KEY"})
            import json
            status=verify_evidence(row["evidence_path"],{"manifest":json.loads(row["manifest"]),"signature":row["signature"]},key[0].encode())
            return jsonify({"status":status,"sha256":row["sha256"]})
        finally: conn.close()

    @app.post("/api/security/audit/verify")
    @_permission_required("audit.read")
    def verify_audit_api():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try:
            import os
            raw=os.environ.get("CYBERTRACE_AUDIT_HMAC_KEY")
            hmac_key=raw.encode() if raw else None
            valid,bad_id=verify_audit_chain(conn,hmac_key=hmac_key)
            if not valid: return jsonify({"status":"INVALID","record_id":bad_id})
            checkpoint=conn.execute("SELECT key_id FROM audit_checkpoints ORDER BY checkpoint_id DESC LIMIT 1").fetchone()
            if checkpoint:
                key=conn.execute("SELECT public_material FROM cryptographic_keys WHERE key_id=? AND revoked_at IS NULL",(checkpoint[0],)).fetchone()
                if not key or not key[0]: return jsonify({"status":"UNKNOWN_KEY"})
                if not verify_audit_checkpoint(conn,key[0].encode()): return jsonify({"status":"INVALID_CHECKPOINT"})
            return jsonify({"status":"VALID"})
        finally: conn.close()

    @app.get("/security")
    @_permission_required("dashboard.view")
    def security_console():
        conn=connect(app.config["CYBERTRACE_DB_PATH"])
        try:
            uid=int(session["user_id"])
            perms={p:has_permission(conn,uid,p) for p in ("incidents.view","network.review","scans.approve","response.review","audit.read","users.manage","keys.manage","signatures.verify")}
            sections={}
            if perms["incidents.view"]:
                sections["SSH authentication history"]=[dict(r) for r in conn.execute("SELECT timestamp,source_ip,username,result,method,target_host,event_type FROM authentication_events ORDER BY timestamp DESC LIMIT 100")]
                sections["Risk score history"]=[dict(r) for r in conn.execute("SELECT timestamp,score,source_ip,username,window_counts,reason FROM risk_history ORDER BY timestamp DESC LIMIT 100")]
            if perms["network.review"]:
                sections["Detected network events"]=[dict(r) for r in conn.execute("SELECT event_id,timestamp,event_type,source_ip,destination_ip,destination_port,severity,evidence_score FROM alerts ORDER BY timestamp DESC LIMIT 100")]
            if perms["scans.approve"]:
                sections["Authorized scans"]=[dict(r) for r in conn.execute("SELECT authorization_id,scan_id,scanner_id,target_ip,permitted_ports,issued_at,expires_at,status FROM scan_authorizations ORDER BY issued_at DESC LIMIT 100")]
            if perms["response.review"]:
                sections["Firewall response actions"]=[dict(r) for r in conn.execute("SELECT * FROM response_actions ORDER BY executed_at DESC LIMIT 100")]
                sections["Active firewall restrictions"]=[dict(r) for r in conn.execute("SELECT source_ip,interface,created_at,expires_at,status FROM blocked_sources WHERE status='ACTIVE'")]
            if perms["audit.read"]:
                sections["Audit logs"]=[dict(r) for r in conn.execute("SELECT audit_id,timestamp,actor,action,previous_hash,record_hash FROM audit_log ORDER BY audit_id DESC LIMIT 100")]
            if perms["users.manage"]:
                sections["User and access management"]=[dict(r) for r in conn.execute("SELECT u.user_id,u.username,u.active,group_concat(r.name) roles FROM users u LEFT JOIN user_roles ur USING(user_id) LEFT JOIN roles r USING(role_id) GROUP BY u.user_id")]
            if perms["keys.manage"] or perms["signatures.verify"]:
                sections["Key management status"]=[dict(r) for r in conn.execute("SELECT key_id,purpose,algorithm,created_at,expires_at,revoked_at FROM cryptographic_keys ORDER BY created_at DESC")]
            if perms["signatures.verify"]:
                sections["Evidence integrity records"]=[dict(r) for r in conn.execute("SELECT manifest_id,evidence_path,sha256,key_id,created_at FROM evidence_manifests ORDER BY created_at DESC LIMIT 100")]
            return render_template("security.html",sections=sections,username=session.get("username"),csrf_token=session.get("csrf_token",""))
        finally: conn.close()

    @app.get("/")
    @_permission_required("dashboard.view")
    def dashboard() -> str:
        return render_template("dashboard.html", snapshot=_dashboard_snapshot(repository))

    @app.get("/incidents")
    @_permission_required("incidents.view")
    def incidents() -> str:
        return render_template("incidents.html", snapshot=_dashboard_snapshot(repository))

    @app.get("/incident/<incident_id>")
    @_permission_required("incidents.view")
    def incident_page(incident_id: str) -> str:
        item = repository.incident(incident_id)
        if item is None:
            abort(404)
        return render_template("incident.html", item=item)

    @app.get("/api/incidents")
    @_permission_required("incidents.view")
    def api_incidents() -> Any:
        return jsonify(repository.snapshot()["incidents"])

    @app.get("/api/events")
    @_permission_required("network.review")
    def api_events() -> Any:
        return jsonify(repository.snapshot()["events"])

    @app.get("/api/correlation/<correlation_id>")
    @_permission_required("incidents.view")
    def api_correlation(correlation_id: str) -> Any:
        rows = repository.snapshot()["correlations"]
        row = next((r for r in rows if str(r.get("correlation_id", r.get("id", ""))) == correlation_id), None)
        if row is None:
            abort(404)
        return jsonify(row)

    return app
