"""Standard cryptographic primitives used by CyberTrace security services."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
import ipaddress
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_ed25519_keypair(private_path: str | Path, public_path: str | Path) -> None:
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite existing signing key material")
    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def sign_manifest(manifest: dict, private_key_pem: bytes) -> str:
    private = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("expected Ed25519 private key")
    return base64.b64encode(private.sign(canonical_json(manifest))).decode("ascii")


def verify_manifest(manifest: dict, signature: str, public_key_pem: bytes) -> bool:
    try:
        public = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public, Ed25519PublicKey):
            return False
        public.verify(base64.b64decode(signature, validate=True), canonical_json(manifest))
        return True
    except Exception:
        return False


def create_scan_authorization(*, signer_id: str, private_key_pem: bytes, scanner_id: str, target_ip: str,
                              permitted_subnet: str, permitted_ports: list[int], protocols: list[str],
                              scan_types: list[str], environment: str = "lab", ttl_seconds: int = 900, now: float | None = None) -> dict:
    if ttl_seconds < 1 or ttl_seconds > 86400:
        raise ValueError("ttl_seconds must be in 1..86400")
    issued = float(now if now is not None else time.time())
    try:
        address=ipaddress.ip_address(target_ip); network=ipaddress.ip_network(permitted_subnet,strict=False)
    except (ValueError,TypeError) as exc: raise ValueError("invalid target IP or subnet") from exc
    if address not in network: raise ValueError("target_ip must be inside permitted_subnet")
    port_list=sorted({int(p) for p in permitted_ports})
    if not port_list or any(p<1 or p>65535 for p in port_list): raise ValueError("permitted_ports must be valid TCP/UDP ports")
    protocol_list=sorted({str(p).upper() for p in protocols})
    if not protocol_list or not set(protocol_list).issubset({"TCP","UDP"}): raise ValueError("protocols must include TCP and/or UDP")
    type_list=sorted({str(t).upper() for t in scan_types})
    if not type_list or not set(type_list).issubset({"SYN","CONNECT","UDP"}): raise ValueError("unsupported scan type")
    manifest = {"authorization_id": str(uuid.uuid4()), "scan_id": str(uuid.uuid4()),
                "signer_id":signer_id,"scanner_id": scanner_id, "target_ip": target_ip, "permitted_subnet": permitted_subnet,
                "permitted_ports": port_list,
                "permitted_protocols": protocol_list,
                "permitted_scan_types": type_list,"environment":environment,
                "issued_at": issued, "expires_at": issued + ttl_seconds, "unique_nonce": secrets.token_urlsafe(24)}
    return {"manifest": manifest, "signature": sign_manifest(manifest, private_key_pem), "signer_id": signer_id}


def verify_scan_authorization(bundle: dict, public_key_pem: bytes, *, now: float | None = None,
                              scanner_id: str | None = None, target_ip: str | None = None,
                              ports: list[int] | None = None, protocol: str | None = None,
                              scan_type: str | None = None, nonce_seen: bool = False,
                              environment: str | None = None, allowed_environment: str | None = None,
                              risk_level: float = 0.0, max_risk: float = 100.0) -> tuple[bool, str]:
    m = bundle.get("manifest", {})
    if not verify_manifest(m, bundle.get("signature", ""), public_key_pem): return False, "INVALID_SIGNATURE"
    current = float(now if now is not None else time.time())
    if current < float(m.get("issued_at", 0)) or current >= float(m.get("expires_at", 0)): return False, "EXPIRED_OR_NOT_YET_VALID"
    if nonce_seen: return False, "REPLAYED_NONCE"
    if scanner_id and m.get("scanner_id") != scanner_id: return False, "SCANNER_MISMATCH"
    if target_ip and m.get("target_ip") != target_ip: return False, "TARGET_MISMATCH"
    if ports and not set(ports).issubset(set(m.get("permitted_ports", []))): return False, "PORT_OUT_OF_SCOPE"
    if protocol and protocol.upper() not in m.get("permitted_protocols", []): return False, "PROTOCOL_OUT_OF_SCOPE"
    if scan_type and scan_type.upper() not in m.get("permitted_scan_types", []): return False, "SCAN_TYPE_OUT_OF_SCOPE"
    if allowed_environment and environment != allowed_environment: return False, "ENVIRONMENT_MISMATCH"
    if risk_level > max_risk: return False, "RISK_TOO_HIGH"
    return True, "AUTHORIZED"


def encrypt_bytes(data: bytes, key: bytes, *, key_id: str) -> dict:
    if len(key) != 32: raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(12)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, data, key_id.encode())
    return {"algorithm": "AES-256-GCM", "key_id": key_id, "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext_and_tag[:-16]).decode(),
            "tag": base64.b64encode(ciphertext_and_tag[-16:]).decode()}


def decrypt_bytes(envelope: dict, key: bytes) -> bytes:
    if envelope.get("algorithm") != "AES-256-GCM" or len(key) != 32: raise ValueError("invalid envelope or key")
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    tag = base64.b64decode(envelope["tag"], validate=True)
    return AESGCM(key).decrypt(nonce, ciphertext + tag, envelope["key_id"].encode())


def append_audit_record(conn, *, actor: str, action: str, record: dict, hmac_key: bytes | None = None) -> int:
    if hmac_key is None and os.environ.get("CYBERTRACE_AUDIT_HMAC_KEY"):
        hmac_key=os.environ["CYBERTRACE_AUDIT_HMAC_KEY"].encode()
    canonical = canonical_json({"actor": actor, "action": action, "record": record})
    previous = conn.execute("SELECT record_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1").fetchone()
    prev_hash = previous[0] if previous else "0" * 64
    digest = hashlib.sha256(bytes.fromhex(prev_hash) + canonical).hexdigest()
    stored = json.loads(canonical)
    if hmac_key:
        stored["hmac_sha256"] = hmac.new(hmac_key, canonical, hashlib.sha256).hexdigest()
    cur = conn.execute("INSERT INTO audit_log(timestamp,actor,action,record,previous_hash,record_hash) VALUES (?,?,?,?,?,?)",
                       (time.time(), actor, action, json.dumps(stored, sort_keys=True, separators=(",", ":")), prev_hash, digest))
    conn.commit()
    return int(cur.lastrowid)


def verify_audit_chain(conn, *, hmac_key: bytes | None = None) -> tuple[bool, int | None]:
    previous = "0" * 64
    for row in conn.execute("SELECT * FROM audit_log ORDER BY audit_id"):
        stored = json.loads(row["record"])
        provided_hmac = stored.pop("hmac_sha256", None)
        canonical = canonical_json(stored)
        expected = hashlib.sha256(bytes.fromhex(previous) + canonical).hexdigest()
        if row["previous_hash"] != previous or not hmac.compare_digest(row["record_hash"], expected): return False, int(row["audit_id"])
        if hmac_key is not None and (not provided_hmac or not hmac.compare_digest(provided_hmac, hmac.new(hmac_key, canonical, hashlib.sha256).hexdigest())): return False, int(row["audit_id"])
        previous = expected
    return True, None


def create_evidence_manifest(file_path: str | Path, details: dict, private_key_pem: bytes, *, key_id: str) -> dict:
    path=Path(file_path)
    manifest={"manifest_id":str(uuid.uuid4()),"path":path.name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
              "details":details,"created_at":time.time(),"key_id":key_id}
    return {"manifest":manifest,"signature":sign_manifest(manifest,private_key_pem)}


def store_evidence_manifest(conn, file_path: str | Path, bundle: dict) -> str:
    manifest=bundle["manifest"]
    conn.execute("INSERT INTO evidence_manifests(manifest_id,evidence_path,sha256,manifest,key_id,signature,created_at) VALUES(?,?,?,?,?,?,?)",
        (manifest["manifest_id"],str(Path(file_path).resolve()),manifest["sha256"],json.dumps(manifest,sort_keys=True,separators=(",",":")),manifest["key_id"],bundle["signature"],manifest["created_at"]))
    conn.commit(); return manifest["manifest_id"]


def verify_evidence(file_path: str | Path, bundle: dict, public_key_pem: bytes) -> str:
    path=Path(file_path); manifest=bundle.get("manifest",{})
    if not path.exists(): return "UNKNOWN"
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest,str(manifest.get("sha256",""))): return "INVALID"
    return "VALID" if verify_manifest(manifest,bundle.get("signature",""),public_key_pem) else "INVALID"


def sign_audit_checkpoint(conn, private_key_pem: bytes, *, key_id: str) -> int:
    row=conn.execute("SELECT audit_id,record_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1").fetchone()
    if not row: raise ValueError("audit chain is empty")
    payload={"audit_id":int(row[0]),"chain_hash":str(row[1]),"key_id":key_id}
    signature=sign_manifest(payload,private_key_pem)
    cur=conn.execute("INSERT INTO audit_checkpoints(audit_id,chain_hash,key_id,signature,created_at) VALUES(?,?,?,?,?)",(payload["audit_id"],payload["chain_hash"],key_id,signature,time.time()))
    conn.commit(); return int(cur.lastrowid)


def verify_audit_checkpoint(conn, public_key_pem: bytes) -> bool:
    checkpoint=conn.execute("SELECT * FROM audit_checkpoints ORDER BY checkpoint_id DESC LIMIT 1").fetchone()
    if not checkpoint: return False
    row=conn.execute("SELECT record_hash FROM audit_log WHERE audit_id=?",(checkpoint["audit_id"],)).fetchone()
    if not row or row[0] != checkpoint["chain_hash"]: return False
    payload={"audit_id":int(checkpoint["audit_id"]),"chain_hash":checkpoint["chain_hash"],"key_id":checkpoint["key_id"]}
    return verify_manifest(payload,checkpoint["signature"],public_key_pem)


def rsa_pss_sign(data: bytes, private_key_pem: bytes) -> str:
    key=serialization.load_pem_private_key(private_key_pem,password=None)
    if not isinstance(key,rsa.RSAPrivateKey): raise ValueError("expected RSA private key")
    sig=key.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    return base64.b64encode(sig).decode("ascii")


def rsa_pss_verify(data: bytes, signature: str, public_key_pem: bytes) -> bool:
    try:
        key=serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key,rsa.RSAPublicKey): return False
        key.verify(base64.b64decode(signature,validate=True),data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        return True
    except Exception: return False
