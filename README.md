# CyberTrace

CyberTrace parses isolated-lab PCAP captures, detects three attack patterns, reconstructs incidents, displays them in the existing forensic dashboard, and evaluates the result against the Attack Range's evaluation-only ground-truth log.

## Pipeline modules

- attack_range/ — Stage 0 lab checks, controlled scenarios, per-scenario PCAP capture, and ground-truth JSONL.
- shared/ — Stage 1 canonical NormalizedEvent model and SQLite schema/CRUD.
- detection_pipeline/ — Stage 2 packet/flow/XML parsing and Stage 3 rule-based detectors. Database-backed detection runs each source PCAP separately so traffic from separate scenarios cannot cross-trigger a detector.
- cybertrace_forensics/ — Stages 4–7 baseline/evidence-aware correlation, missing-step inference, incident construction, and the SQLite integration adapter. This package does not provide another web dashboard.
- forensics_dashboard/ — existing Stages 8–10 Flask dashboard and evaluator, retained and connected to the shared SQLite schema and Stage 7 output.
- lab/ — Stage 9 capture handoff helper/documentation.

## Install

Python 3.10 or later is recommended.

~~~sh
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux/Kali:
source .venv/bin/activate
python -m pip install -r requirements.txt
~~~

Parsing real captures also requires the system tshark binary. The parser's PyShark import is lazy, so synthetic tests and the rest of the pipeline can run without it.

## Run the integrated pipeline

1. On the Attack Range VM, configure the isolated host-only/internal lab. Copy attack_range/config.example.yaml to attack_range/config.yaml, set the real lab-only subnet, attacker/target addresses and capture interface, then run the isolation preflight. Never use public, campus, or third-party targets.

~~~sh
python -m attack_range.run_all --config attack_range/config.yaml --dry-run
# Only after confirming the VM network is isolated:
python -m attack_range.run_all --config attack_range/config.yaml
~~~

This produces a run folder such as artifacts/run-<timestamp>/ground_truth.jsonl and the shared capture files artifacts/pcaps/recon.pcap, ssh_bruteforce.pcap, and exploit.pcap. Capture a benign baseline separately as artifacts/pcaps/baseline.pcap for false-positive evaluation. Ground truth is not read during parsing, detection, or reconstruction.

2. Parse all scenario captures, detect within each PCAP, run Stages 4–7, and export both timelines:

~~~sh
python scripts/run_pipeline.py --pcap artifacts/pcaps/recon.pcap --pcap artifacts/pcaps/ssh_bruteforce.pcap --pcap artifacts/pcaps/exploit.pcap --pcap artifacts/pcaps/baseline.pcap --db data/cybertrace.db --xml-dir data/xml --export-dir data/evaluation
~~~

Use a fresh database path for each trial: the script appends new packet/alert rows, while Stage 4–7 replaces only its own prior reconstructed incident/link rows.

Equivalent individual commands are available: initialize with python -m shared.database --init data/cybertrace.db, parse with python scripts/parse_pcap.py --pcap <capture> --db data/cybertrace.db --xml data/xml/<name>.xml, detect with python scripts/detect.py --db data/cybertrace.db, and reconstruct with python scripts/reconstruct.py --db data/cybertrace.db --export-dir data/evaluation.

3. View the Stage 7 incidents in the existing Stage 8 dashboard:

~~~sh
# Windows PowerShell:
$env:CYBERTRACE_DB = "data/cybertrace.db"
# Linux/Kali:
export CYBERTRACE_DB=data/cybertrace.db
python -m forensics_dashboard
~~~

Open http://127.0.0.1:5000. Existing routes remain: /, /incidents, /incident/<id>, /api/incidents, /api/events, and /api/correlation/<id>. Detected events remain DETECTED; inferred timeline steps are displayed as INFERRED, with no synthetic packet IDs or PCAP evidence.

4. Evaluate the actual exported pipeline output against the Attack Range log:

~~~sh
python -m forensics_dashboard.evaluation --ground-truth artifacts/run-<timestamp>/ground_truth.jsonl --baseline data/evaluation/baseline_timeline.csv --proposed data/evaluation/proposed_timeline.csv --database data/cybertrace.db --output data/evaluation/evaluation_results.csv
~~~

The JSONL input is read only by this evaluation command. If the database contains packets from a capture whose filename includes baseline, the evaluator derives its benign time window from those packet rows. It reports precision, recall, F1, false-positive rate when benign labels exist, timeline reconstruction accuracy, missing-step recovery, detection latency, optional PCAP parsing accuracy, and SQLite read-query time. Parsing accuracy can be added with --parsing-total N --parsing-correct M, using an independent tshark packet/field comparison. Missing measurements are left blank rather than fabricated.

## Security services

Schema migrations run additively when `shared.database.init_db()` initializes a database. Existing packets, flows, alerts, incidents and correlations are retained. For an existing database, use the regular pipeline or dashboard startup once to apply migrations.

Initialize the first dashboard administrator interactively (no default password is supplied):

~~~sh
python -m security.setup_admin --db data/cybertrace.db --username admin
~~~

Set `CYBERTRACE_SECRET_KEY` to a generated random secret before deployment. Set `CYBERTRACE_COOKIE_SECURE=1` only when the dashboard is served through HTTPS. The Flask development server remains HTTP. The dashboard requires login; roles and permissions are checked server-side. `/security` and `/api/security/*` expose role-filtered security views.

OpenSSH authentication logs are ingested independently of packet parsing:

~~~sh


python -m security.ingest_ssh --db data/cybertrace.db --auth-log /var/log/auth.log --target-host ubuntu-ssh
python -m security.ingest_ssh --db data/cybertrace.db --jsonl fixtures/ssh-events.jsonl

~~~

The auth.log command uses an incremental cursor and handles file replacement/truncation; JSONL is idempotent by event fingerprint. Actual SSH brute-force alerts require host authentication failure evidence. Port 22 PCAP bursts are labeled `SSH_CONNECTION_ANOMALY`.

Create an Ed25519 administrator key and sign a scan manifest:

~~~sh
python -m security.authorize_scan keygen --private secrets/admin-ed25519.pem --public secrets/admin-ed25519.pub
python -m security.authorize_scan authorize --private secrets/admin-ed25519.pem --signer-id lab-admin --scanner-id kali-lab --target 192.168.56.20 --subnet 192.168.56.0/24 --ports 22,80 --protocols TCP --scan-types SYN,CONNECT --environment lab --output artifacts/scan-auth.json
python -m security.scanner_agent --authorization artifacts/scan-auth.json --public-key secrets/admin-ed25519.pub --scanner-id kali-lab --target 192.168.56.20 --ports 22,80 --scan-type SYN --replay-db data/scanner-replay.db --dry-run
~~~

Use AES-GCM evidence envelopes and Ed25519 evidence manifests from `security.crypto`; key loading and generation helpers are in `security.key_management`. Standard SQLite and existing evidence files remain plaintext unless the operator explicitly encrypts them. See [the security architecture](docs/SECURITY_ARCHITECTURE.md), [the demo guide](docs/DEMONSTRATION_GUIDE.md), and other docs in `docs/` for deployment and limits. Live firewall action remains opt-in, Linux-only, lab-scoped and dry-run by default.

## Tests

~~~sh
python -m unittest discover -s tests -v
~~~

The suite uses synthetic PacketRecord data and requires no VM, attack tool, capture, or real PCAP. It verifies the Stage 2→3→4–7→8 repository→10 evaluation handoff. The supplied Stages 4–7 pytest-style checks are also invoked by the unittest discovery suite.

## Integration contracts

- shared.NormalizedEvent is the canonical Stage 3 → Stage 4 event model; Stage 4–7 receives a small adapter mapping with ISO-8601 timestamps.
- The shared DB remains the system of record: packets, flows, alerts, event_correlations, and incidents.
- Stage 7 stores the ordered detected alert IDs in incidents.event_sequence; its inferred-event explanations are serialized in the existing summary text column with a stage4_7: marker. The Stage 8 repository expands that metadata into timeline rows without altering the shared schema.
- data/evaluation/baseline_timeline.csv and proposed_timeline.csv are generated from the actual normalized alerts by Stage 4–7. Stage 10 scores those exports and does not participate in detection or correlation.
- Stage 3 consumes pcap_file as a capture boundary, matching the Attack Range's separate per-scenario captures. Events from distinct PCAPs are combined only after detection.
