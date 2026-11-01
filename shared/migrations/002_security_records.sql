CREATE TABLE IF NOT EXISTS registered_scanners (
    scanner_id TEXT PRIMARY KEY,
    public_key_pem TEXT NOT NULL,
    environment TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_authorizations (
    authorization_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    scanner_id TEXT NOT NULL REFERENCES registered_scanners(scanner_id),
    target_ip TEXT NOT NULL,
    permitted_subnet TEXT NOT NULL,
    permitted_ports TEXT NOT NULL,
    permitted_protocols TEXT NOT NULL,
    permitted_scan_types TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    unique_nonce TEXT NOT NULL UNIQUE,
    signing_key_id TEXT REFERENCES cryptographic_keys(key_id),
    manifest TEXT NOT NULL,
    signature TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
);
CREATE TABLE IF NOT EXISTS response_actions (
    response_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    incident_id INTEGER,
    source_ip TEXT,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    executed_at REAL NOT NULL,
    expires_at REAL,
    result TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    FOREIGN KEY(event_id) REFERENCES alerts(event_id) ON DELETE SET NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS blocked_sources (
    source_ip TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cryptographic_keys (
    key_id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_material TEXT,
    created_at REAL NOT NULL,
    expires_at REAL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS evidence_manifests (
    manifest_id TEXT PRIMARY KEY,
    evidence_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    manifest TEXT NOT NULL,
    key_id TEXT NOT NULL REFERENCES cryptographic_keys(key_id),
    signature TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL,
    chain_hash TEXT NOT NULL,
    key_id TEXT NOT NULL REFERENCES cryptographic_keys(key_id),
    signature TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authz_scanner ON scan_authorizations(scanner_id,status);
CREATE INDEX IF NOT EXISTS idx_response_expires ON response_actions(expires_at);
