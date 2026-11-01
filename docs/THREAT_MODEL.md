# Threat model

## Assets

PCAP and host authentication evidence, incidents and ground truth, scan authorization keys/manifests, dashboard credentials and sessions, audit records, and lab firewall state.

## Threats and controls

- Forged/replayed scan authorization: Ed25519 signature, expiry, nonce store, target/port/type scope checks. Local nonce state is not distributed and scanner-to-controller mTLS is absent.
- Password guessing against dashboard: salted scrypt, persistent username throttling, CSRF, role checks, secure cookie attributes. Availability still depends on deployment/proxy controls.
- Evidence alteration: SHA-256 manifests and Ed25519 signatures; AES-GCM envelopes support confidentiality when operators actually wrap files and protect keys.
- Audit tampering: chained SHA-256 and optional HMAC; separately protected signed checkpoints are needed to resist full database rewrite.
- False positives and unsafe response: evidence thresholds, explicit authorization policy, dry-run default, lab subnet/interface allowlists, reversible expiry fields. No automatic cleanup service is supplied.
- Ground-truth leakage: evaluator only; do not mount ground-truth into detector runtime.

## Assumptions and residual risks

The host, Python runtime, clocks, administrator key files, log transport, and VirtualBox isolation are trusted. An attacker controlling these can forge host logs, steal keys, rewrite an unanchored database, or escape the intended observation boundary. PCAP cannot prove identity or encrypted SSH authentication outcomes. SQLite is not encrypted by this project. HTTPS must be provided by a configured local TLS reverse proxy.
