"""Map normalized evidence to auditable response decisions."""
from __future__ import annotations
import time

def evaluate(event, *, authorized_scan: bool = False, incident_id: str | None = None,
             initiating_identity: str = "system", high_confidence: float = 0.85,
             restriction_seconds: int = 900) -> dict:
    kind = event.event_type
    score = float(event.evidence_score)
    if kind == "PORT_SCAN" and authorized_scan:
        action, reason = "ALLOW", "signed scan authorization verified"
    elif kind == "AUTHORIZED_RECONNAISSANCE":
        action, reason = "ALLOW", "signed scan authorization and scanner identity verified"
    elif kind == "PORT_SCAN" and score >= high_confidence:
        action, reason = "TEMPORARY_RESTRICTION", "high-confidence scan evidence"
    elif kind in {"PORT_SCAN", "UNAUTHORIZED_RECONNAISSANCE", "AUTHORIZATION_VIOLATION", "SSH_CONNECTION_ANOMALY"}:
        action, reason = "MONITOR_AND_ALERT", "network evidence merits review"
    elif kind == "SSH_BRUTE_FORCE":
        action, reason = ("TEMPORARY_RESTRICTION", "high authentication risk") if score >= high_confidence else ("ALERT", "authentication failure evidence")
    elif kind == "EXPLOITATION":
        action, reason = "TEMPORARY_RESTRICTION", "lab-specific exploitation heuristic matched"
    else:
        action, reason = "MONITOR", "no configured response rule"
    return {"event_id":event.event_id,"incident_id":incident_id,"source_ip":event.source_ip,
            "action":action,"reason":reason,"executed_at":time.time(),
            "expires_at":time.time()+restriction_seconds if action == "TEMPORARY_RESTRICTION" else None,
            "result":"POLICY_ONLY","initiated_by":initiating_identity}

def persist_action(conn, decision: dict) -> int:
    cur=conn.execute("""INSERT INTO response_actions(event_id,incident_id,source_ip,action,reason,executed_at,expires_at,result,initiated_by)
        VALUES(?,?,?,?,?,?,?,?,?)""",(decision.get("event_id"),decision.get("incident_id"),decision.get("source_ip"),decision["action"],decision["reason"],decision["executed_at"],decision.get("expires_at"),decision["result"],decision["initiated_by"]))
    conn.commit()
    from security.crypto import append_audit_record
    append_audit_record(conn, actor=decision.get("initiated_by", "system"), action="response.action",
        record={"response_id":int(cur.lastrowid),"event_id":decision.get("event_id"),"incident_id":decision.get("incident_id"),
                "source_ip":decision.get("source_ip"),"action":decision["action"],"reason":decision["reason"],"result":decision["result"]})
    return int(cur.lastrowid)
