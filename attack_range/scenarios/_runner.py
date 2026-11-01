"""Shared helpers for the three scenario runners.

Each scenario module exposes:
    NAME                       -> short scenario key ("recon" | ...)
    plan(cfg) -> dict          -> the resolved action (command + metadata),
                                  built from config, WITHOUT running anything
    run(cfg, gt, dry_run=...)  -> execute the planned action and record it to
                                  the ground-truth logger

Keeping `plan` pure (no side effects) is what makes `--dry-run` and the unit
test possible without the lab or the attack tools installed.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

# How much tool output to keep in the ground-truth `extra` for reproducibility
# (full output stays in the operator's terminal / tool log files).
_TAIL_CHARS = 2000


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def _tail(text: Optional[str]) -> str:
    if not text:
        return ""
    return text[-_TAIL_CHARS:]


def exec_cmd(cmd: List[str], timeout: float) -> subprocess.CompletedProcess:
    """Run a command, capturing output. Raises FileNotFoundError if the tool
    binary is missing (so the orchestrator can report it cleanly), and turns a
    timeout into a returncode of 124 rather than an exception (a brute-force or
    long scan hitting its budget is a normal, recordable outcome)."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=124,
            stdout=(e.stdout.decode() if isinstance(e.stdout, bytes) else e.stdout) or "",
            stderr=((e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr) or "")
            + "\n[timed out]",
        )


def run_planned(
    plan: dict,
    cfg: dict,
    gt,
    dry_run: bool,
    timeout: float,
) -> Optional[subprocess.CompletedProcess]:
    """Execute a planned action and record it in the ground-truth log.

    The action is recorded as `completed` whenever it was performed, regardless
    of the tool's exit code — ground truth records that the attacker action
    *happened*, not whether the tool "succeeded". The exit code and output tail
    are stashed in `extra` for later inspection. A missing tool binary surfaces
    as a `failed` action (the context manager captures the exception).
    """
    lab = cfg["lab"]
    cmd = plan["command"]
    printable = " ".join(cmd)

    if dry_run:
        print(f"  [dry-run] {plan['scenario']}: {printable}")
        return None

    with gt.action(
        scenario=plan["scenario"],
        technique=plan["technique"],
        tool=plan["tool"],
        src_ip=lab["attacker_ip"],
        dst_ip=lab["target_ip"],
        dst_ports=plan["dst_ports"],
        protocol=plan.get("protocol", "tcp"),
        intent=plan["intent"],
        command=printable,
        extra=dict(plan.get("extra", {})),
    ) as handle:
        proc = exec_cmd(cmd, timeout=timeout)
        handle.add_extra(
            returncode=proc.returncode,
            stdout_tail=_tail(proc.stdout),
            stderr_tail=_tail(proc.stderr),
        )
    return proc
