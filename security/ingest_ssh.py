"""Ingest trusted OpenSSH authentication logs into CyberTrace."""
import argparse
from shared.database import init_db
from shared.database import insert_event
from .ssh_auth import ingest_auth_log_incremental, ingest_jsonl, risk_events

def main():
    p=argparse.ArgumentParser(); p.add_argument("--db",required=True); source=p.add_mutually_exclusive_group(required=True)
    source.add_argument("--auth-log"); source.add_argument("--jsonl"); p.add_argument("--target-host",default="localhost"); a=p.parse_args()
    conn=init_db(a.db)
    try:
        rows=ingest_jsonl(conn,a.jsonl) if a.jsonl else ingest_auth_log_incremental(conn,a.auth_log,target_host=a.target_host)
        alerts=risk_events(rows)
        for alert in alerts: insert_event(conn, alert)
        print(f"new_auth_events={len(rows)} brute_force_alerts={len(alerts)}")
    finally: conn.close()

if __name__ == "__main__": main()
