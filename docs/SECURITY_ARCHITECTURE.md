# Security architecture

CyberTrace keeps the existing pipeline: PCAP and trusted SSH host logs enter separate collectors, both produce evidence-bearing events, and the shared `alerts` table feeds the existing Stage 4–7 incident reconstruction and Flask repository. Ground truth remains evaluation-only.

## Security modules

- `security/ssh_auth.py`: OpenSSH auth.log, systemd journal and JSON event parsing; incremental file cursor; rotation handling; idempotent event hashes; multi-window risk history.
- `security/accounts.py`: scrypt password storage, role membership, permission checks and persistent login throttling.
- `security/crypto.py`: Ed25519 signatures, canonical manifests, AES-256-GCM envelopes, SHA-256 evidence fingerprints, HMAC/hash-chain audit records, signed checkpoints, and RSA-PSS demonstration.
- `security/scanner_agent.py`: local authorization verifier and Nmap invocation gate.
- `security/scan_correlation.py`: reusable authorization classifier for observed port-scan events; it requires externally authenticated scanner identity.
- `response_engine/`: policy decision module and a Linux iptables adapter. It is dry-run by default; detection itself never launches firewall commands.
- `shared/migrations/`: additive, ordered migrations preserve current packet, flow, alert, incident and correlation rows.

## Identity and trust boundaries

Dashboard authentication is session based, protected with CSRF tokens, server-side permission checks and role grants. Scanner authorization comes from an administrator-signed manifest. PCAP source addresses are correlation evidence only; they do not prove scanner identity. The current scanner agent is local and does not yet provide a controller mTLS channel.

Host authentication logs must arrive from the SSH target through a trusted channel. PCAP cannot reveal SSH username, password, authentication method or result. Keep ground-truth JSONL inaccessible to detection and use it only in evaluation.

## Deployment boundary

The Flask development server does not provide deployment HTTPS. Put it behind a local-CA TLS reverse proxy and set `CYBERTRACE_COOKIE_SECURE=1`. Store `CYBERTRACE_SECRET_KEY`, audit HMAC secret, encryption key and signing private keys outside the repository with owner-only access. SQLCipher is not wired into this standard `sqlite3` application; default SQLite files remain plaintext.

Example Nginx TLS termination (install a local-CA certificate and key first):

```nginx
server {
    listen 443 ssl;
    server_name cybertrace.lab;
    ssl_certificate /etc/nginx/tls/cybertrace.crt;
    ssl_certificate_key /etc/nginx/tls/cybertrace.key;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```
