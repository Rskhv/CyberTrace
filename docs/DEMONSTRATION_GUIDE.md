# Demonstration guide

## Initial setup

```powershell
python -m pip install -r requirements.txt
python -m shared.database --init data/cybertrace.db
python -m security.setup_admin --db data/cybertrace.db --username admin
```

Set `CYBERTRACE_SECRET_KEY` to a random secret of at least 32 bytes for stable sessions and `CYBERTRACE_COOKIE_SECURE=1` behind HTTPS. Start locally with `python -m forensics_dashboard`; local Flask is HTTP only and is not a production deployment.

## Reproducible service demonstrations

- **A, authorized scan:** create an Ed25519 key pair and signed manifest with `security.crypto.create_scan_authorization`, save JSON, then run the scanner agent command in `SCAN_AUTHORIZATION.md` first with `--dry-run`. Expected output is `AUTHORIZED_DRY_RUN`; expired, replayed, out-of-subnet or out-of-scope requests raise a refusal.
- **B, unauthorized scan:** run an ordinary Nmap scan only against the isolated lab target. Parse its PCAP; expected event is evidence-backed `PORT_SCAN`. Evaluate it with `response_engine.policy.evaluate`; expected action is alert/monitor or a policy-only restriction request based on confidence. The adapter's default result is `DRY_RUN`.
- **C, slow SSH brute force:** append repeated failed-auth JSON lines to a fixture and run `python -m security.ingest_ssh --db data/cybertrace.db --jsonl fixture.jsonl`. Expected history persists across 1m/15m/1h/24h views and risk decays with a one-hour half-life. Re-ingestion adds no duplicates.
- **D, valid public key:** log in from Kali to the hardened Ubuntu target using the permitted Ed25519 key. Forward the Ubuntu auth log; expected host event is successful `publickey`, with no brute-force event absent earlier failures.
- **E, controlled exploitation:** run the existing controlled Metasploitable2 vsftpd scenario from `attack_range/run_all.py`, then use the established `scripts/run_pipeline.py` workflow. Expected detector event is specifically the vsftpd 2.3.4 port-21/6200 heuristic; broader exploitation is not claimed.
- **F, evidence modification:** use `encrypt_bytes`/`decrypt_bytes`, then `create_evidence_manifest` and `verify_evidence`. Expected altered bytes report `INVALID`; wrong AES key fails authenticated decryption. `verify_audit_chain` detects modified audit rows.
- **G, dashboard denial:** request `/` without a session; expected redirect to `/login`; `/api/events` returns 401. Initialize an admin with the setup command, sign in, and verify analyst/admin permission boundaries.

Capture screenshots of the authorized agent dry-run and refusal, scanner PCAP plus event, risk history rows, Ubuntu key login and auth event, exploitation alert, evidence verification before/after alteration, and unauthenticated/login dashboard responses. No VM scenarios were run as part of this repository change.
