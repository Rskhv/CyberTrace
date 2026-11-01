"""CyberTrace Attack Range & Threat Emulation module (Shaurya).

Public surface used by the rest of the system / by the orchestrator:
    GroundTruthLogger, load_jsonl   — the ground-truth action log (interface)
    assert_isolated                 — isolation preflight
    PacketCapture                   — per-scenario PCAP capture
"""

from .ground_truth import GroundTruthLogger, GroundTruthAction, load_jsonl
from .isolation_check import assert_isolated, check_isolation, IsolationError
from .capture import PacketCapture, CaptureError, tshark_available

__all__ = [
    "GroundTruthLogger",
    "GroundTruthAction",
    "load_jsonl",
    "assert_isolated",
    "check_isolation",
    "IsolationError",
    "PacketCapture",
    "CaptureError",
    "tshark_available",
]
