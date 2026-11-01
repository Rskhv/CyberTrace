"""Correlate detected port-scan evidence with a signed, out-of-band manifest."""
from __future__ import annotations
from shared.event_model import NormalizedEvent
from .crypto import verify_scan_authorization

def classify_observed_scan(event: NormalizedEvent, bundle: dict | None, public_key_pem: bytes | None,
                           *, authenticated_scanner_id: str | None, scan_type: str = "SYN",
                           now: float | None = None, nonce_seen: bool = False,
                           environment: str | None = None, expected_environment: str | None = None,
                           risk_level: float = 0.0, max_risk: float = 100.0) -> NormalizedEvent:
    """Classify a detected scan. Source IP is never treated as identity proof.

    `authenticated_scanner_id` must come from a trusted controller channel
    (such as mTLS); passing None always prevents authorized classification.
    """
    if event.event_type != "PORT_SCAN":
        raise ValueError("scan classification requires a detected PORT_SCAN event")
    reason = "NO_SIGNED_AUTHORIZATION"
    kind = "UNAUTHORIZED_RECONNAISSANCE"
    evidence = {"classification_basis":"signed out-of-band authorization plus authenticated scanner identity",
                "source_ip_is_identity":False}
    if bundle and public_key_pem:
        manifest=bundle.get("manifest",{})
        observed_ports=event.evidence.get("ports_sample",[])
        ports_complete=event.evidence.get("distinct_ports",len(observed_ports)) <= len(observed_ports)
        valid, reason = verify_scan_authorization(bundle,public_key_pem,now=now,
            scanner_id=authenticated_scanner_id,target_ip=event.destination_ip,ports=observed_ports,
            protocol=event.protocol,scan_type=scan_type,nonce_seen=nonce_seen,environment=environment,
            allowed_environment=expected_environment,risk_level=risk_level,max_risk=max_risk)
        if authenticated_scanner_id is None:
            valid,reason=False,"SCANNER_IDENTITY_UNVERIFIED"
        elif not ports_complete:
            valid,reason=False,"OBSERVED_PORT_SET_INCOMPLETE"
        if not valid:
            kind="AUTHORIZATION_VIOLATION" if reason in {"INVALID_SIGNATURE","EXPIRED_OR_NOT_YET_VALID","REPLAYED_NONCE","TARGET_MISMATCH","PORT_OUT_OF_SCOPE","PROTOCOL_OUT_OF_SCOPE","SCAN_TYPE_OUT_OF_SCOPE","SCANNER_MISMATCH","ENVIRONMENT_MISMATCH","RISK_TOO_HIGH"} else "UNAUTHORIZED_RECONNAISSANCE"
        else:
            kind="AUTHORIZED_RECONNAISSANCE"
        evidence.update({"authorization_id":manifest.get("authorization_id"),"scan_id":manifest.get("scan_id"),
                         "scanner_id":authenticated_scanner_id,"authorization_reason":reason})
    return NormalizedEvent(timestamp=event.timestamp,source_ip=event.source_ip,destination_ip=event.destination_ip,
        protocol=event.protocol,event_type=kind,attack_stage="RECON",evidence_source=event.evidence_source,
        destination_port=None,severity="INFO" if kind=="AUTHORIZED_RECONNAISSANCE" else event.severity,
        packet_ids=list(event.packet_ids),flow_id=event.flow_id,evidence_score=event.evidence_score,
        confidence_score=event.confidence_score,status=event.status,
        evidence={**event.evidence,**evidence}).validate()
