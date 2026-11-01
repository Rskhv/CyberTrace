# Active response

`response_engine.policy.evaluate(event, ...)` produces an auditable decision without side effects. `persist_action` records it in `response_actions`. Authorized scans map to allow; lower confidence network activity maps to monitor/alert; high confidence, high authentication risk and the lab-specific exploitation event can request a temporary restriction.

`LabIptables` is the Linux adapter. It validates the source address against configured lab networks and requires an explicitly allowed isolated interface. It defaults to dry-run and reports the exact command. Live execution requires `dry_run=False`, Linux `iptables`, privileges, and deployment configuration. Removal requires an administrator override. Expiry is recorded for a separate cleanup worker; no cleanup daemon is included yet. Windows enforcement and target isolation are not implemented. Never turn on automated blocking outside the explicitly configured isolated range.
