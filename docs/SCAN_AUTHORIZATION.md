# Signed scan authorization

Generate administrator Ed25519 keys with `security.crypto.generate_ed25519_keypair`. Keep the private PEM outside Git and distribute the public key to the scanner out of band. Build a manifest with `create_scan_authorization(...)`; it includes unique authorization and scan IDs, scanner identity, exact target, permitted subnet/ports/protocols/types, issue and expiry times, and a random nonce.

Save the returned object as JSON. Invoke the agent only against a target in the isolated lab:

```powershell
python -m security.scanner_agent --authorization auth.json --public-key admin.pub --scanner-id lab-scanner --target 192.168.56.20 --ports 22,80 --scan-type SYN --replay-db data/scanner-replay.db --dry-run
```

After reviewing the command and VM isolation, omit `--dry-run` to execute Nmap. The local replay database consumes a nonce before execution. A separate replay database on another agent will not share replay state. The signed manifest is an out-of-band authorization; normal TCP packets cannot carry the administrator's signature. `security.scan_correlation.classify_observed_scan` independently validates observed ports, target, time, scope and scanner identity if a trusted channel supplies that identity. This classifier is not wired into the packet pipeline, and mTLS is not implemented, so source IP alone never labels traffic authorized.
