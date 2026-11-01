"""File/environment-backed key handling. Key bytes never enter SQLite."""
from __future__ import annotations
import base64, hashlib, os, secrets, time
from pathlib import Path

def generate_aes_key(path: str | Path) -> str:
    p=Path(path)
    if p.exists(): raise FileExistsError("refusing to overwrite key file")
    key=secrets.token_bytes(32)
    p.parent.mkdir(parents=True,exist_ok=True); p.write_text(base64.b64encode(key).decode()+"\n",encoding="ascii")
    try: os.chmod(p,0o600)
    except OSError: pass
    return "aes-"+hashlib.sha256(key).hexdigest()[:16]

def load_key(*, env_name: str | None = None, path: str | Path | None = None) -> bytes:
    if env_name and os.environ.get(env_name):
        raw=os.environ[env_name].strip()
        try: key=base64.b64decode(raw,validate=True)
        except Exception: key=raw.encode()
    elif path:
        p=Path(path)
        if os.name != "nt" and p.stat().st_mode & 0o077: raise PermissionError("key file must not be accessible to group/other users")
        key=base64.b64decode(p.read_text().strip(),validate=True)
    else: raise ValueError("provide a key environment variable or protected key file")
    if len(key)!=32: raise ValueError("key must be exactly 32 bytes")
    return key

def record_key(conn, *, key_id: str, purpose: str, algorithm: str, public_material: str | None = None, expires_at: float | None = None):
    conn.execute("INSERT INTO cryptographic_keys(key_id,purpose,algorithm,public_material,created_at,expires_at) VALUES(?,?,?,?,?,?)",(key_id,purpose,algorithm,public_material,time.time(),expires_at)); conn.commit()

def revoke_key(conn, key_id: str):
    cur=conn.execute("UPDATE cryptographic_keys SET revoked_at=? WHERE key_id=? AND revoked_at IS NULL",(time.time(),key_id)); conn.commit()
    if not cur.rowcount: raise KeyError("key not found or already revoked")

def rotate_aes_key(old_path: str | Path, new_path: str | Path) -> tuple[str, str]:
    old_key=base64.b64decode(Path(old_path).read_text().strip(),validate=True)
    old_id="aes-"+hashlib.sha256(old_key).hexdigest()[:16]
    new_id=generate_aes_key(new_path)
    return old_id,new_id
