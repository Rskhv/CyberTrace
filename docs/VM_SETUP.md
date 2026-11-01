# Isolated VM setup

Use VirtualBox host-only or internal networking only. Place Kali, Metasploitable2, Ubuntu SSH, and the CyberTrace collector on a dedicated private subnet with no bridged adapter or route to public networks. Configure the subnet and interface in `attack_range/config.yaml` from `attack_range/config.example.yaml`; run `python -m attack_range.run_all --config attack_range/config.yaml --dry-run` and review the isolation preflight before any scenario.

Capture traffic on the lab interface only. Keep ground-truth logs separate from detector inputs. Use modern Ubuntu for successful Ed25519 login and password-disabled tests; use Metasploitable2 only for controlled vulnerable-service demonstrations. Exact VM import and host-only adapter names vary by host and VirtualBox version, so verify each address and route before attack tooling is run.
