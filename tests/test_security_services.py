import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from shared.database import init_db
from security.accounts import authenticate, create_user, has_permission
from security.crypto import (append_audit_record, create_scan_authorization, decrypt_bytes,
    encrypt_bytes, generate_ed25519_keypair, verify_audit_chain, verify_manifest,
    verify_scan_authorization)
from security.ssh_auth import (ingest_events, parse_auth_log_line, parse_json_event,
    risk_events)


class SecurityServicesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.conn = init_db(str(self.root / "security.db"))

    def tearDown(self):
        self.conn.close(); self.temp.cleanup()

    def test_auth_log_parser_and_incremental_risk_deduplication(self):
        event = parse_auth_log_line("2026-11-01T10:00:00+00:00 host sshd[1]: Failed password for invalid user guest from 10.1.0.5 port 4000 ssh2")
        self.assertEqual(event.event_type, "SSH_AUTH_INVALID_USER")
        self.assertEqual(event.username, "guest")
        events = [parse_json_event({"timestamp": 1793527200+i*20,"source_ip":"10.1.0.5","username":"root","result":"FAILURE","method":"password","target_host":"10.1.0.8"}) for i in range(6)]
        first = ingest_events(self.conn, events)
        second = ingest_events(self.conn, events)
        self.assertEqual(len(first), 6); self.assertEqual(second, [])
        self.assertTrue(any(e.event_type == "SSH_BRUTE_FORCE" for e in risk_events(first)))

    def test_explicit_log_rotation_cursor_restarts_on_inode_change(self):
        from security.ssh_auth import ingest_auth_log_incremental
        log = self.root / "auth.log"
        log.write_text("2026-11-01T10:00:00+00:00 host sshd: Failed password for root from 10.0.0.1 port 22 ssh2\n")
        self.assertEqual(len(ingest_auth_log_incremental(self.conn, log)), 1)
        with log.open("a") as stream: stream.write("2026-11-01T10:01:00+00:00 host sshd: Accepted publickey for root from 10.0.0.2 port 22 ssh2\n")
        self.assertEqual(len(ingest_auth_log_incremental(self.conn, log)), 1)
        self.assertEqual(len(ingest_auth_log_incremental(self.conn, log)), 0)

    def test_passwords_are_scrypt_hashed_and_role_checked(self):
        uid = create_user(self.conn, "analyst", "long demo password value", ["SECURITY_ANALYST"])
        row = self.conn.execute("SELECT password_hash FROM users WHERE user_id=?", (uid,)).fetchone()
        self.assertTrue(row[0].startswith("scrypt$"))
        self.assertIsNone(authenticate(self.conn, "analyst", "wrong password value"))
        self.assertIsNotNone(authenticate(self.conn, "analyst", "long demo password value"))
        self.assertTrue(has_permission(self.conn, uid, "incidents.view"))
        self.assertFalse(has_permission(self.conn, uid, "users.manage"))

    def test_signed_authorization_scope_and_replay(self):
        private, public = self.root / "admin.pem", self.root / "admin.pub"
        generate_ed25519_keypair(private, public)
        bundle = create_scan_authorization(signer_id="lab-admin", private_key_pem=private.read_bytes(), scanner_id="scanner-a", target_ip="10.0.0.9", permitted_subnet="10.0.0.0/24", permitted_ports=[22,80], protocols=["TCP"], scan_types=["SYN"], now=100, ttl_seconds=60)
        ok, _ = verify_scan_authorization(bundle, public.read_bytes(), now=110, scanner_id="scanner-a", target_ip="10.0.0.9", ports=[22], protocol="TCP", scan_type="SYN")
        self.assertTrue(ok)
        ok, reason = verify_scan_authorization(bundle, public.read_bytes(), now=110, ports=[23])
        self.assertFalse(ok); self.assertEqual(reason,"PORT_OUT_OF_SCOPE")
        self.assertTrue(verify_manifest(bundle["manifest"], bundle["signature"], public.read_bytes()))
        from security.scan_correlation import classify_observed_scan
        from shared.event_model import NormalizedEvent
        detected=NormalizedEvent(timestamp=110,source_ip="10.0.0.2",destination_ip="10.0.0.9",protocol="TCP",event_type="PORT_SCAN",attack_stage="RECON",evidence_source="PCAP",evidence_score=.8,evidence={"ports_sample":[22],"distinct_ports":1})
        self.assertEqual(classify_observed_scan(detected,bundle,public.read_bytes(),authenticated_scanner_id=None,now=110).event_type,"UNAUTHORIZED_RECONNAISSANCE")
        self.assertEqual(classify_observed_scan(detected,bundle,public.read_bytes(),authenticated_scanner_id="scanner-a",now=110,environment="lab",expected_environment="lab").event_type,"AUTHORIZED_RECONNAISSANCE")
        from security.scanner_agent import execute_authorized_scan
        replay_db=self.root/"replay.db"
        execute_authorized_scan(bundle,public.read_bytes(),scanner_id="scanner-a",target="10.0.0.9",ports=[22],scan_type="SYN",replay_db=replay_db,dry_run=True,now=110)
        with patch("security.scanner_agent.subprocess.run"):
            execute_authorized_scan(bundle,public.read_bytes(),scanner_id="scanner-a",target="10.0.0.9",ports=[22],scan_type="SYN",replay_db=replay_db,now=110)
        with self.assertRaises(PermissionError):
            execute_authorized_scan(bundle,public.read_bytes(),scanner_id="scanner-a",target="10.0.0.9",ports=[22],scan_type="SYN",replay_db=replay_db,dry_run=True,now=110)

    def test_aes_gcm_and_audit_chain_detect_tampering(self):
        key = bytes(range(32)); envelope=encrypt_bytes(b"capture bytes",key,key_id="evidence-1")
        self.assertEqual(decrypt_bytes(envelope,key),b"capture bytes")
        with self.assertRaises(Exception): decrypt_bytes(envelope,bytes(reversed(range(32))))
        append_audit_record(self.conn,actor="admin",action="test",record={"x":1},hmac_key=b"audit key")
        self.assertEqual(verify_audit_chain(self.conn,hmac_key=b"audit key"),(True,None))
        self.conn.execute("UPDATE audit_log SET record='{}'"); self.conn.commit()
        valid, bad_id=verify_audit_chain(self.conn,hmac_key=b"audit key")
        self.assertFalse(valid); self.assertEqual(bad_id,1)


if __name__ == "__main__": unittest.main()
