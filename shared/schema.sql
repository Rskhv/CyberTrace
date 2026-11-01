-- CyberTrace — SHARED SQLite schema (Stage 1).
--
-- Supports the full later pipeline:
--   PCAP -> packets -> flows -> alerts (normalized events)
--        -> event_correlations -> incidents
--
-- Table ownership (for the 3-person team):
--   packets, flows   : Detection Pipeline (parser, Stage 2)
--   alerts           : Detection Pipeline (detectors, Stage 3)
--   event_correlations, incidents : Forensics (correlation, Stage 4+)
-- Stage 1 only creates the structure; no detection/correlation logic yet.
--
-- Enable FK enforcement per-connection with:  PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- 1. packets : one row per parsed packet
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS packets (
    packet_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        REAL    NOT NULL,          -- epoch seconds (UTC)
    source_ip        TEXT,
    destination_ip   TEXT,
    source_port      INTEGER,
    destination_port INTEGER,
    protocol         TEXT,                       -- TCP / UDP / ICMP / OTHER
    tcp_flags        TEXT,                       -- e.g. "SYN", "SYN,ACK" (NULL if n/a)
    packet_length    INTEGER,
    frame_number     INTEGER,                    -- original capture frame number (Stage 2)
    pcap_file        TEXT                        -- source PCAP filename
);

-- ---------------------------------------------------------------------------
-- 2. flows : packets grouped by 5-tuple
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flows (
    flow_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip        TEXT,
    destination_ip   TEXT,
    source_port      INTEGER,
    destination_port INTEGER,
    protocol         TEXT,
    start_time       REAL,                       -- epoch seconds
    end_time         REAL,
    packet_count     INTEGER DEFAULT 0,
    duration         REAL                        -- end_time - start_time (s)
);

-- ---------------------------------------------------------------------------
-- 3. incidents : a correlated, multi-stage group of events
--    (created before alerts/correlations so their FKs can reference it)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    incident_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time       REAL,
    end_time         REAL,
    confidence_score REAL    DEFAULT 0.0,        -- 0..1
    status           TEXT    DEFAULT 'DETECTED',
    event_sequence   TEXT,                       -- JSON array of event_ids, ordered
    summary          TEXT
);

-- ---------------------------------------------------------------------------
-- 4. alerts : normalized security events (1:1 with NormalizedEvent)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    event_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        REAL    NOT NULL,           -- epoch seconds (UTC)
    source_ip        TEXT,
    destination_ip   TEXT,
    source_port      INTEGER,
    destination_port INTEGER,
    protocol         TEXT,
    event_type       TEXT    NOT NULL,           -- PORT_SCAN / SSH_BRUTE_FORCE / EXPLOITATION
    attack_stage     TEXT    NOT NULL,           -- RECON / SERVICE_DISCOVERY / CREDENTIAL_ATTACK / EXPLOITATION
    severity         TEXT    DEFAULT 'MEDIUM',
    evidence_source  TEXT    DEFAULT 'PCAP',     -- PCAP / GROUND_TRUTH
    packet_ids       TEXT    DEFAULT '[]',       -- JSON array of packets.packet_id
    flow_id          INTEGER,                    -- FK -> flows.flow_id (nullable)
    evidence_score   REAL    DEFAULT 0.0,        -- 0..1
    confidence_score REAL    DEFAULT 0.0,        -- 0..1 (set during correlation)
    status           TEXT    DEFAULT 'DETECTED', -- DETECTED / INFERRED / CORRELATED
    evidence         TEXT    DEFAULT '{}',       -- JSON: detector-specific supporting evidence (Stage 3)
    FOREIGN KEY (flow_id) REFERENCES flows (flow_id) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------------
-- 5. event_correlations : scored links between two events within an incident
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_correlations (
    correlation_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id      INTEGER,                    -- FK -> incidents.incident_id
    source_event_id  INTEGER NOT NULL,           -- FK -> alerts.event_id
    target_event_id  INTEGER NOT NULL,           -- FK -> alerts.event_id
    temporal_score   REAL    DEFAULT 0.0,
    ip_score         REAL    DEFAULT 0.0,
    port_score       REAL    DEFAULT 0.0,
    stage_score      REAL    DEFAULT 0.0,
    evidence_score   REAL    DEFAULT 0.0,
    total_score      REAL    DEFAULT 0.0,
    explanation      TEXT,
    FOREIGN KEY (incident_id)     REFERENCES incidents (incident_id) ON DELETE CASCADE,
    FOREIGN KEY (source_event_id) REFERENCES alerts (event_id)       ON DELETE CASCADE,
    FOREIGN KEY (target_event_id) REFERENCES alerts (event_id)       ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Indexes for the correlation queries the later stages run (by time/IP/port).
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_packets_ts   ON packets (timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src  ON packets (source_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dport ON packets (destination_port);

CREATE INDEX IF NOT EXISTS idx_flows_src    ON flows (source_ip);
CREATE INDEX IF NOT EXISTS idx_flows_5tuple ON flows (source_ip, destination_ip, source_port, destination_port, protocol);

CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src   ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dport ON alerts (destination_port);
CREATE INDEX IF NOT EXISTS idx_alerts_type  ON alerts (event_type);

CREATE INDEX IF NOT EXISTS idx_corr_incident ON event_correlations (incident_id);
