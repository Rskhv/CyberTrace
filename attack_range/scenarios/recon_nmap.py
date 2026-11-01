"""Scenario 1 — reconnaissance (Nmap TCP SYN scan + service/version detection).

Generates the port-scan traffic the Detection Pipeline's port-scan detector is
meant to flag. Runs from the Kali attacker VM against the single lab target.
"""

from __future__ import annotations

import os

from ._runner import run_planned, tool_available

NAME = "recon"
TOOL = "nmap"


def plan(cfg: dict) -> dict:
    lab = cfg["lab"]
    sc = cfg["scenarios"]["recon"]
    ports = str(sc.get("ports", "1-1024"))
    extra_flags = list(sc.get("nmap_extra", ["-sS", "-sV", "-T4"]))
    out_prefix = os.path.join(cfg["output"]["artifacts_dir"], "tool_logs", "nmap_recon")

    command = (
        ["nmap", *extra_flags, "-p", ports, lab["target_ip"], "-oN", out_prefix + ".txt"]
    )
    return {
        "scenario": NAME,
        "technique": "tcp_syn_scan+service_detection",
        "tool": TOOL,
        "dst_ports": [],  # a sweep across many ports; see extra.port_spec
        "protocol": "tcp",
        "intent": f"TCP SYN scan + service/version detection of {lab['target_ip']} ports {ports}",
        "command": command,
        "extra": {"port_spec": ports, "flags": extra_flags},
    }


def run(cfg: dict, gt, dry_run: bool = False):
    os.makedirs(os.path.join(cfg["output"]["artifacts_dir"], "tool_logs"), exist_ok=True)
    if not dry_run and not tool_available("nmap"):
        raise FileNotFoundError("nmap not found on PATH (install on the Kali attacker VM)")
    timeout = float(cfg["scenarios"]["recon"].get("timeout_s", 600))
    return run_planned(plan(cfg), cfg, gt, dry_run=dry_run, timeout=timeout)
