CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS authentication_events (
    auth_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_fingerprint TEXT NOT NULL UNIQUE,
    timestamp REAL NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT,
    result TEXT NOT NULL CHECK (result IN ('SUCCESS','FAILURE')),
    method TEXT NOT NULL,
    target_host TEXT,
    event_type TEXT NOT NULL,
    raw_source TEXT,
    inserted_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_events_time ON authentication_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_src_time ON authentication_events(source_ip,timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_user_time ON authentication_events(username,timestamp);
CREATE TABLE IF NOT EXISTS auth_log_cursors (
    path TEXT PRIMARY KEY,
    device_id TEXT,
    inode_id TEXT,
    byte_offset INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_history (
    risk_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    score REAL NOT NULL,
    source_ip TEXT,
    username TEXT,
    window_counts TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_time ON risk_history(timestamp);

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS roles (role_id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS permissions (permission_id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, role_id)
);
CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    attempted_at REAL NOT NULL,
    succeeded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time ON login_attempts(username,attempted_at);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY(role_id, permission_id)
);
INSERT OR IGNORE INTO roles(role_id,name) VALUES
 (1,'ADMINISTRATOR'),(2,'SECURITY_ANALYST'),(3,'NETWORK_OPERATOR'),(4,'AUDITOR');
INSERT OR IGNORE INTO permissions(permission_id,name) VALUES
 (1,'dashboard.view'),(2,'incidents.view'),(3,'evidence.view'),(4,'reports.generate'),
 (5,'signatures.verify'),(6,'audit.read'),(7,'users.manage'),(8,'keys.manage'),
 (9,'scans.approve'),(10,'policies.manage'),(11,'firewall.manage'),(12,'network.review'),(13,'response.review');
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY(role_id, permission_id)
);
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
 SELECT 1,permission_id FROM permissions;
INSERT OR IGNORE INTO role_permissions(role_id,permission_id) VALUES
 (2,1),(2,2),(2,3),(2,4),(2,5),(3,1),(3,12),(3,9),(3,13),(4,1),(4,5),(4,6);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    record TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(timestamp);
