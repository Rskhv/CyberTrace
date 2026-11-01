"""
CyberTrace — Detection Pipeline: detector configuration (Stage 3).

All detector thresholds live here, in one dataclass, so nothing is hard-coded
throughout the detection code. Override values per run (CLI flags) or load from
a dict. Defaults are tuned for the small, isolated lab in the synopsis, not for
production traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Tuple


@dataclass
class DetectorConfig:
    # -- Port-scan detector --------------------------------------------------
    # A source that hits at least MIN_DISTINCT_PORTS distinct destination ports
    # with at least MIN_SYN_COUNT SYN initiations inside SCAN_WINDOW_SECONDS.
    min_distinct_ports: int = 15
    min_syn_count: int = 15
    scan_window_seconds: float = 10.0

    # -- SSH brute-force detector -------------------------------------------
    # A source making at least SSH_MIN_ATTEMPTS connection attempts to the SSH
    # port inside SSH_WINDOW_SECONDS; sessions shorter than
    # SSH_SHORT_SESSION_SECONDS count as "short-lived" (strengthens evidence).
    ssh_port: int = 22
    ssh_min_attempts: int = 5
    ssh_window_seconds: float = 60.0
    ssh_short_session_seconds: float = 5.0

    # -- Exploitation detector (lab-specific heuristic) ----------------------
    # Connection to a known vulnerable service port, followed shortly by a
    # suspicious secondary connection between the same two hosts on a backdoor
    # port (the vsftpd 2.3.4 backdoor on Metasploitable2 binds 6200).
    vuln_ports: Tuple[int, ...] = (21,)
    backdoor_ports: Tuple[int, ...] = (6200,)
    exploit_followup_window_seconds: float = 20.0
    exploit_min_bytes: int = 0            # optional data-volume floor (0 = off)

    @classmethod
    def from_dict(cls, d: dict) -> "DetectorConfig":
        """Build a config from a dict, ignoring unknown keys; tuples coerced."""
        known = {f.name for f in fields(cls)}
        kw = {}
        for k, v in (d or {}).items():
            if k not in known:
                continue
            if k in ("vuln_ports", "backdoor_ports") and v is not None:
                kw[k] = tuple(int(x) for x in v)
            else:
                kw[k] = v
        return cls(**kw)
