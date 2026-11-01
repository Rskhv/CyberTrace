"""
CyberTrace — Attack Range module: isolation preflight.

Before ANY attack scenario runs, this module verifies the lab is actually
isolated, so controlled attacks can never reach the campus network or the
internet. `assert_isolated()` is called first by the orchestrator; if a check
fails in strict mode it raises IsolationError and nothing runs.

Checks performed:
  1. Target IP is in a private (RFC 1918 / CGNAT) range.
  2. Target IP is inside the configured lab subnet.
  3. Attacker IP is inside the configured lab subnet.
  4. The host has no usable route to the public internet (best-effort):
     a short TCP connect to a public address MUST fail.

These are safety rails, not security guarantees — they are meant to catch
an operator mistake (wrong VM network mode, a bridged adapter left on)
before traffic is generated, which is exactly the failure the synopsis's
"confirm the segment has no route to the campus network or internet"
step guards against.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Sequence


class IsolationError(RuntimeError):
    """Raised when the lab does not look isolated and strict mode is on."""


# Addresses a connect() attempt is made to. We *require* these to be
# unreachable. (No data is sent; the socket is closed immediately.)
_PUBLIC_PROBES: Sequence[tuple] = (
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
)


@dataclass
class IsolationReport:
    ok: bool
    checks: List[tuple]  # list of (name, passed: bool, detail: str)

    def as_text(self) -> str:
        lines = ["Isolation preflight:"]
        for name, passed, detail in self.checks:
            mark = "PASS" if passed else "FAIL"
            lines.append(f"  [{mark}] {name}: {detail}")
        lines.append(f"  => {'ISOLATED' if self.ok else 'NOT ISOLATED'}")
        return "\n".join(lines)


def _is_private(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _in_subnet(ip: str, subnet: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)


def _internet_reachable(timeout: float = 2.0) -> bool:
    for host, port in _PUBLIC_PROBES:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True  # got out — NOT isolated
        except OSError:
            continue
    return False


def check_isolation(
    lab_subnet: str,
    attacker_ip: str,
    target_ip: str,
    probe_internet: bool = True,
) -> IsolationReport:
    """Run all checks and return a report (does not raise)."""
    checks: List[tuple] = []

    try:
        priv = _is_private(target_ip)
        checks.append(("target is private IP", priv, f"{target_ip}"))
    except ValueError as e:
        checks.append(("target is private IP", False, f"invalid IP: {e}"))

    try:
        in_net = _in_subnet(target_ip, lab_subnet)
        checks.append(("target in lab subnet", in_net, f"{target_ip} ∈ {lab_subnet}"))
    except ValueError as e:
        checks.append(("target in lab subnet", False, str(e)))

    try:
        atk_in_net = _in_subnet(attacker_ip, lab_subnet)
        checks.append(("attacker in lab subnet", atk_in_net, f"{attacker_ip} ∈ {lab_subnet}"))
    except ValueError as e:
        checks.append(("attacker in lab subnet", False, str(e)))

    if probe_internet:
        reachable = _internet_reachable()
        checks.append((
            "no internet route",
            not reachable,
            "public probe unreachable (good)" if not reachable
            else "REACHED public internet — segment is NOT isolated",
        ))

    ok = all(passed for _, passed, _ in checks)
    return IsolationReport(ok=ok, checks=checks)


def assert_isolated(
    lab_subnet: str,
    attacker_ip: str,
    target_ip: str,
    probe_internet: bool = True,
    strict: bool = True,
) -> IsolationReport:
    """Run checks; raise IsolationError if not isolated and strict=True."""
    report = check_isolation(lab_subnet, attacker_ip, target_ip, probe_internet)
    if not report.ok and strict:
        raise IsolationError(
            "Refusing to run attack scenarios — lab is not isolated.\n"
            + report.as_text()
        )
    return report
