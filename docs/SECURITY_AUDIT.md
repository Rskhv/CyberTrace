# CyberTrace security audit

## Scope and baseline

Reviewed the repository's Python modules, SQLite schema, detector configuration, Flask routes, requirements, tests, and README. The existing project is a staged pipeline: isolated attack-range capture and ground truth; packet parsing and normalized events; rule detectors; Stage 4–7 correlation/reconstruction; then a read-oriented Flask dashboard and evaluation pipeline. `shared.NormalizedEvent` and `shared/schema.sql` are the main compatibility contracts.

Baseline: `python -m unittest discover -s tests -v` — **46 tests passed** when `TEMP` and `TMP` point to a workspace-local directory. With the sandbox default temp path, 18 tests errored because the OS denied writes in that temp location; this was environmental, not a project assertion failure.

## Existing thresholds and data contracts

- Port scan: 15 distinct destination ports and 15 SYN initiations within 10 seconds (`detection_pipeline/detectors/config.py`). SYN only; no long-window, UDP, or flag scan signal.
- SSH: 5 SYN initiations to port 22 within 60 seconds, with short flow duration as a weak signal. This is not authentication evidence and cannot establish password failures from encrypted SSH PCAP.
- Exploitation: a TCP connection to port 21 followed by a same-host-pair connection to port 6200 within 20 seconds; explicitly narrow to the Metasploitable2 vsftpd lab heuristic.
- SQLite currently stores `packets`, `flows`, `alerts`, `incidents`, and `event_correlations`. Foreign keys are enabled per connection; Stage 4–7 extends `incidents.summary` rather than changing the event model. Detection is isolated by PCAP filename.
- Runtime dependencies are Flask, PyYAML, and PyShark. There is no migration framework, password hashing, CSRF, login, RBAC, audit chain, cryptographic key management, authorization manifest, or response engine.

## Risks and limitations found

1. Port 22 connection bursts are mislabeled `SSH_BRUTE_FORCE` despite having no authentication result.
2. Dashboard HTML and JSON routes are unauthenticated; no session policy, CSRF defense, security headers, or access control exists.
3. The SQLite database is plaintext; evidence files and reports have no integrity/signature envelope.
4. No identity-bound scan authorization exists; source IP is the only network identity available in PCAP.
5. Detection and response are currently separate only because response is absent. No safe lab-scoped firewall adapter exists.
6. The port scan detector misses connect/FIN/NULL/Xmas/UDP and slow scans. The vsftpd rule is deliberately narrow and cannot provide universal exploit detection.
7. No versioned schema migrations or security-specific tests are present. Existing normalization vocabulary is deliberately small and must be versioned when extended.
8. PCAP cannot reveal encrypted SSH credentials, usernames, authentication results, administrator identity, or cryptographic authorization signatures carried out-of-band.

## Planned incremental changes

1. Add versioned additive database migrations and an SSH authentication log/JSON collector with persistent deduplication and decaying multi-window risk. Keep connection anomalies explicitly distinct from credential brute force.
2. Improve evidence-backed network scan indicators and make exploitation rule registration configurable while preserving the lab-specific heuristic.
3. Add cryptographic utilities for canonical Ed25519 authorization/evidence manifests, AES-GCM evidence encryption, and chained audit records.
4. Add a scanner authorization verifier/agent and ABAC scope checks; PCAP correlation remains a separate controller operation and cannot infer scanner identity from IP alone.
5. Add role-based dashboard authentication and a dry-run-first, lab-scoped response adapter. Live firewall action requires explicit deployment configuration and Linux privileges.
6. Document deployment, SSH hardening, VM setup, threat model, and demonstration workflow. SQLCipher availability is environment-dependent; standard SQLite remains unencrypted unless a SQLCipher build is deployed.

## Migration requirements

Preserve all current tables and rows. Apply ordered SQL migrations tracked by `schema_migrations`; add new tables/indexes only. Do not store plaintext passwords or private keys in SQLite. Existing alerts remain readable. If event vocabulary changes, retain old persisted values and bump the normalized schema version.

## Dependencies to add

Use a maintained cryptography package for Ed25519, AES-GCM, and RSA-PSS; use a maintained Argon2 implementation for password hashes; add Flask-WTF or equivalent for CSRF and a rate limiting package or an equivalent persistent limiter. Keep each dependency pinned by supported major version in `requirements.txt` after implementation.

## Features that PCAP alone cannot achieve

PCAP alone cannot prove human/scanner identity, whether an SSH password or public key succeeded, username or authentication method inside encrypted SSH, or that an administrator signed a scan. Those facts need trusted host logs and signed out-of-band authorization records. PCAP can provide traffic evidence to correlate with those records, subject to capture coverage and clock accuracy.
