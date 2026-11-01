#!/usr/bin/env python3
"""
CyberTrace — Attack Range orchestrator.

Runs the full ground-truth generation pass:

    1. Load lab config.
    2. Isolation preflight (aborts unless the lab looks isolated).
    3. For each enabled scenario, in order:
         start tshark capture  ->  run scenario  ->  stop capture
       producing one labeled PCAP per scenario in the shared pcap_dir.
    4. Write the ground-truth action log (JSONL + SQLite) and a run manifest.

Usage:
    python -m attack_range.run_all --config attack_range/config.yaml
    python -m attack_range.run_all --config attack_range/config.yaml --dry-run
    python -m attack_range.run_all --config attack_range/config.yaml --no-capture

--dry-run     prints the resolved plan and records nothing (no tools run).
--no-capture  runs scenarios without tshark (useful if the Detection Pipeline
              teammate captures separately).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# Support `python -m attack_range.run_all` and `python attack_range/run_all.py`.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from attack_range.ground_truth import GroundTruthLogger
    from attack_range.isolation_check import assert_isolated
    from attack_range.capture import PacketCapture, tshark_available
    from attack_range.scenarios import ALL_SCENARIOS
else:
    from .ground_truth import GroundTruthLogger
    from .isolation_check import assert_isolated
    from .capture import PacketCapture, tshark_available
    from .scenarios import ALL_SCENARIOS


def load_config(path: str) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load the config (pip install pyyaml)")
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    for key in ("lab", "output", "scenarios"):
        if key not in cfg:
            raise ValueError(f"config missing required section: {key!r}")
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberTrace Attack Range orchestrator")
    ap.add_argument("--config", required=True, help="path to lab config YAML")
    ap.add_argument("--dry-run", action="store_true", help="print plan, run nothing")
    ap.add_argument("--no-capture", action="store_true", help="skip tshark capture")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    lab = cfg["lab"]
    out = cfg["output"]

    # 2. Isolation preflight -------------------------------------------------
    report = assert_isolated(
        lab_subnet=lab["subnet"],
        attacker_ip=lab["attacker_ip"],
        target_ip=lab["target_ip"],
        probe_internet=bool(lab.get("probe_internet", True)) and not args.dry_run,
        strict=bool(lab.get("strict_isolation", True)) and not args.dry_run,
    )
    print(report.as_text())
    print()

    # 3. Run scenarios -------------------------------------------------------
    run_id = f"run-{_dt.datetime.now(_dt.timezone.utc):%Y%m%dT%H%M%SZ}"
    run_dir = os.path.join(out["artifacts_dir"], run_id)
    pcap_dir = out.get("pcap_dir", os.path.join(run_dir, "pcaps"))
    iface = lab.get("monitor_iface", "eth1")
    use_capture = not args.no_capture and not args.dry_run

    if use_capture and not tshark_available():
        print("WARNING: tshark not found — continuing without capture.", file=sys.stderr)
        use_capture = False

    gt = GroundTruthLogger(out_dir=run_dir, run_id=run_id)
    print(f"Ground-truth run_id = {gt.run_id}")
    print(f"Artifacts dir       = {run_dir}")
    print(f"PCAP dir (shared)   = {pcap_dir}\n")

    for scenario in ALL_SCENARIOS:
        name = scenario.NAME
        sc_cfg = cfg["scenarios"].get(name, {})
        if not sc_cfg.get("enabled", True):
            print(f"- skipping disabled scenario: {name}")
            continue

        print(f"- scenario: {name}")
        try:
            if use_capture:
                with PacketCapture(iface=iface, pcap_dir=pcap_dir, name=name) as cap:
                    scenario.run(cfg, gt, dry_run=args.dry_run)
                print(f"    pcap: {cap.pcap_path}")
            else:
                scenario.run(cfg, gt, dry_run=args.dry_run)
        except FileNotFoundError as e:
            # A missing tool / wordlist: the failed action is already in the
            # ground-truth log; report and keep going with the other scenarios.
            print(f"    !! {name} could not run: {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"    !! {name} errored: {e}", file=sys.stderr)

    # 4. Finish --------------------------------------------------------------
    summary = gt.summary()
    gt.close()

    if not args.dry_run:
        manifest = {
            "run_id": gt.run_id,
            "created_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "config": args.config,
            "pcap_dir": pcap_dir,
            "captured": use_capture,
            "ground_truth": summary,
            "isolation": [
                {"check": n, "passed": p, "detail": d} for (n, p, d) in report.checks
            ],
        }
        manifest_path = os.path.join(run_dir, "run_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        print(f"\nManifest: {manifest_path}")

    print("\nSummary:")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
