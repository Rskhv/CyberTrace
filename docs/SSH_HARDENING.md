# SSH hardening for the modern Ubuntu demonstration target

Keep Metasploitable2 as the intentionally vulnerable comparison. Create a separate supported Ubuntu Server VM on the isolated host-only/internal network. Generate a client key with `ssh-keygen -t ed25519`, install its public key for a dedicated permitted user, and verify key login from the Kali VM before changing server policy.

Set in an SSH drop-in under `/etc/ssh/sshd_config.d/`:

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers cybertrace-demo
LogLevel VERBOSE
```

Validate using `sshd -t`, then reload `ssh`. Retain console access while validating. Ubuntu commonly writes authentication events to `/var/log/auth.log` and the systemd journal. On the Ubuntu target, securely forward that log or copy the relevant lines to the CyberTrace host, then run `python -m security.ingest_ssh --db data/cybertrace.db --auth-log /path/to/auth.log --target-host ubuntu-ssh` or use `--jsonl` for a structured test fixture. Repeated reads are deduplicated.

Do not assume Metasploitable2 supports current key or host-key algorithms. SSH password attempts cannot be inspected from ordinary PCAP.
