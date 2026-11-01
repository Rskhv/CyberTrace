"""
CyberTrace — SHARED database layer (Stage 1).

Thin, dependency-free (stdlib `sqlite3`) helpers over schema.sql:

  * connect()/init_db()        — open a DB with FK enforcement on
  * insert_packet/get_packet   — packets table
  * insert_flow/get_flow       — flows table
  * insert_event/get_event     — alerts table (NormalizedEvent <-> row)
  * insert_incident            — incidents table
  * insert_correlation         — event_correlations table

Stage 1 provides structure + CRUD only; no parsing, detection, or correlation
logic lives here. Later stages call these helpers to persist their output.

CLI:
    python -m shared.database --init cybertrace.db     # create tables
    python -m shared.database --schema                 # print schema.sql
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from typing import List, Optional

try:
    from .event_model import NormalizedEvent
except (ImportError, ValueError):  # pragma: no cover - flat-layout fallback
    from event_model import NormalizedEvent  # type: ignore

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


# -- connection management ---------------------------------------------------

def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with foreign keys enforced and Row access by name."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str, schema_path: str = SCHEMA_PATH) -> sqlite3.Connection:
    """Create all tables from schema.sql (idempotent) and return the connection."""
    with open(schema_path, "r", encoding="utf-8") as fh:
        ddl = fh.read()
    conn = connect(db_path)
    conn.executescript(ddl)
    conn.commit()
    return conn


# -- packets -----------------------------------------------------------------

def insert_packet(
    conn: sqlite3.Connection,
    *,
    timestamp: float,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    protocol: Optional[str] = None,
    tcp_flags: Optional[str] = None,
    packet_length: Optional[int] = None,
    frame_number: Optional[int] = None,
    pcap_file: Optional[str] = None,
) -> int:
    cur = conn.execute(
        """INSERT INTO packets
           (timestamp, source_ip, destination_ip, source_port, destination_port,
            protocol, tcp_flags, packet_length, frame_number, pcap_file)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, source_ip, destination_ip, source_port, destination_port,
         protocol, tcp_flags, packet_length, frame_number, pcap_file),
    )
    conn.commit()
    return int(cur.lastrowid)


def get_packet(conn: sqlite3.Connection, packet_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM packets WHERE packet_id = ?", (packet_id,)).fetchone()


# -- flows -------------------------------------------------------------------

def insert_flow(
    conn: sqlite3.Connection,
    *,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    protocol: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    packet_count: int = 0,
    duration: Optional[float] = None,
) -> int:
    if duration is None and start_time is not None and end_time is not None:
        duration = round(end_time - start_time, 6)
    cur = conn.execute(
        """INSERT INTO flows
           (source_ip, destination_ip, source_port, destination_port, protocol,
            start_time, end_time, packet_count, duration)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (source_ip, destination_ip, source_port, destination_port, protocol,
         start_time, end_time, packet_count, duration),
    )
    conn.commit()
    return int(cur.lastrowid)


def get_flow(conn: sqlite3.Connection, flow_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM flows WHERE flow_id = ?", (flow_id,)).fetchone()


# -- alerts (normalized events) ----------------------------------------------

def insert_event(conn: sqlite3.Connection, event: NormalizedEvent) -> int:
    """Validate and persist a NormalizedEvent into the alerts table.
    Sets and returns the assigned event_id."""
    event.validate()
    row = event.to_alert_row()
    cols = [c for c in NormalizedEvent.ALERT_COLUMNS if c != "event_id"]
    placeholders = ", ".join("?" for _ in cols)
    cur = conn.execute(
        f"INSERT INTO alerts ({', '.join(cols)}) VALUES ({placeholders})",
        tuple(row[c] for c in cols),
    )
    conn.commit()
    event.event_id = int(cur.lastrowid)
    return event.event_id


def get_event(conn: sqlite3.Connection, event_id: int) -> Optional[NormalizedEvent]:
    row = conn.execute("SELECT * FROM alerts WHERE event_id = ?", (event_id,)).fetchone()
    return NormalizedEvent.from_alert_row(row) if row is not None else None


def list_events(conn: sqlite3.Connection) -> List[NormalizedEvent]:
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp, event_id").fetchall()
    return [NormalizedEvent.from_alert_row(r) for r in rows]


# -- incidents / correlations (structure only in Stage 1) --------------------

def insert_incident(
    conn: sqlite3.Connection,
    *,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    confidence_score: float = 0.0,
    status: str = "DETECTED",
    event_sequence: Optional[List[int]] = None,
    summary: Optional[str] = None,
) -> int:
    cur = conn.execute(
        """INSERT INTO incidents
           (start_time, end_time, confidence_score, status, event_sequence, summary)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (start_time, end_time, confidence_score, status,
         json.dumps(event_sequence or []), summary),
    )
    conn.commit()
    return int(cur.lastrowid)


def insert_correlation(
    conn: sqlite3.Connection,
    *,
    source_event_id: int,
    target_event_id: int,
    incident_id: Optional[int] = None,
    temporal_score: float = 0.0,
    ip_score: float = 0.0,
    port_score: float = 0.0,
    stage_score: float = 0.0,
    evidence_score: float = 0.0,
    total_score: float = 0.0,
    explanation: Optional[str] = None,
) -> int:
    cur = conn.execute(
        """INSERT INTO event_correlations
           (incident_id, source_event_id, target_event_id, temporal_score,
            ip_score, port_score, stage_score, evidence_score, total_score, explanation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (incident_id, source_event_id, target_event_id, temporal_score,
         ip_score, port_score, stage_score, evidence_score, total_score, explanation),
    )
    conn.commit()
    return int(cur.lastrowid)


# -- introspection -----------------------------------------------------------

def dump_schema(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type IN ('table','index') "
        "AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY type DESC, name"
    ).fetchall()
    return "\n\n".join(r["sql"] for r in rows)


# -- CLI ---------------------------------------------------------------------

def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberTrace database utility")
    ap.add_argument("--init", metavar="DB_PATH", help="create tables in DB_PATH")
    ap.add_argument("--schema", action="store_true", help="print schema.sql and exit")
    args = ap.parse_args(argv)

    if args.schema:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
            print(fh.read())
        return 0
    if args.init:
        conn = init_db(args.init)
        print(f"Initialized CyberTrace DB at {args.init}")
        print("\nTables:")
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ):
            print(f"  - {r['name']}")
        conn.close()
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
