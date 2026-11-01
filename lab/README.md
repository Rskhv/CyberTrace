# Stage 9 lab capture handoff

The Attack Range owner configures and verifies an isolated VirtualBox host-only/internal network before running any scenario. The example addresses in the prompt are not defaults: pass the actual target address explicitly and confirm it belongs to the isolated lab. Do not run these commands against public, campus, or third-party systems.

From the monitoring VM, run `bash lab/capture_tshark.sh <scenario> <interface> [duration-seconds]`. It writes a separate PCAPNG beneath `data/pcaps/` for `nmap_scan`, `ssh_bruteforce`, `exploitation`, or `benign`. Start capture before the scenario and stop it after the activity. Keep captures and the ground-truth log per trial.

Example controlled activity commands (replace the target and credentials with lab-owned values):

```sh
# Reconnaissance; explicit TCP ports keep the lab experiment bounded.
nmap -sS -sV -p 1-1024 <METASPLOITABLE2_LAB_IP>

# Only use a small, purpose-built lab wordlist against the intentionally vulnerable SSH service.
hydra -l <LAB_USERNAME> -P <LAB_WORDLIST> -t 2 -f ssh://<METASPLOITABLE2_LAB_IP>
```

For exploitation, the synopsis's example is the intentionally vulnerable vsftpd 2.3.4 service. The lab owner should record the exact Metasploit module, target, payload, and outcome in the ground-truth log and follow the module's documented safe lab procedure. This repository does not automate exploit execution.

Record UTC timestamps and scenario labels in `ground_truth_template.csv`; use one row per attack action and one `BENIGN` row per benign observation window. `expected_sequence` is an ordered `>`-separated list of stages, for example `RECON>SERVICE_DISCOVERY>CREDENTIAL_ATTACK>EXPLOITATION`. Ground truth is an evaluation-only input. It must not be configured as an input to parsing, detection, correlation, or dashboard runtime code.

This is a handoff helper, not the Attack Range module. The environment was not available in this workspace, so no capture or attack was executed here.
