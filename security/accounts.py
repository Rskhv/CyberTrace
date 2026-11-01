"""Password hashing, role assignment, and persistent login throttling."""
from __future__ import annotations
import base64, hashlib, hmac, os, time

ROLES = {"ADMINISTRATOR", "SECURITY_ANALYST", "NETWORK_OPERATOR", "AUDITOR"}

def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    salt = os.urandom(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(derived).decode())

def verify_password(password: str, encoded: str) -> bool:
    try:
        name, n, r, p, salt_b64, expected_b64 = encoded.split("$")
        if name != "scrypt": return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(expected_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def create_user(conn, username: str, password: str, roles: list[str]) -> int:
    username = username.strip()
    if not username or len(username) > 128: raise ValueError("invalid username")
    chosen = {role.upper() for role in roles}
    if not chosen or not chosen.issubset(ROLES): raise ValueError("invalid role")
    cur = conn.execute("INSERT INTO users(username,password_hash,created_at) VALUES (?,?,?)", (username,hash_password(password),time.time()))
    uid = int(cur.lastrowid)
    conn.executemany("INSERT INTO user_roles(user_id,role_id) SELECT ?,role_id FROM roles WHERE name=?", [(uid,r) for r in sorted(chosen)])
    conn.commit()
    return uid

def authenticate(conn, username: str, password: str, *, now: float | None = None, max_attempts: int = 8, window: int = 300):
    current = now or time.time()
    recent = conn.execute("SELECT COUNT(*) FROM login_attempts WHERE username=? AND attempted_at>=? AND succeeded=0", (username,current-window)).fetchone()[0]
    user = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    ok = recent < max_attempts and user is not None and verify_password(password, user["password_hash"])
    conn.execute("INSERT INTO login_attempts(username,attempted_at,succeeded) VALUES (?,?,?)", (username,current,int(ok)))
    conn.commit()
    if not ok: return None
    roles = [r[0] for r in conn.execute("SELECT roles.name FROM roles JOIN user_roles USING(role_id) WHERE user_roles.user_id=?", (user["user_id"],))]
    return {"user_id":user["user_id"],"username":username,"roles":roles}

def has_permission(conn, user_id: int, permission: str) -> bool:
    return conn.execute("""SELECT 1 FROM user_roles ur JOIN role_permissions rp USING(role_id)
        JOIN permissions p USING(permission_id) WHERE ur.user_id=? AND p.name=? LIMIT 1""", (user_id,permission)).fetchone() is not None

def initialize_admin(conn, username: str, password: str) -> int:
    count = conn.execute("SELECT COUNT(*) FROM user_roles ur JOIN roles r USING(role_id) WHERE r.name='ADMINISTRATOR'").fetchone()[0]
    if count: raise RuntimeError("administrator already initialized")
    return create_user(conn, username, password, ["ADMINISTRATOR"])
