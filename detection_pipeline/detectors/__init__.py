"""CyberTrace — Stage 3 rule-based detectors (Detection Pipeline).

Three detectors, each emitting the shared NormalizedEvent into `alerts`:
  * detect_port_scans        -> PORT_SCAN / RECON
  * detect_ssh_brute_force   -> SSH_BRUTE_FORCE / CREDENTIAL_ATTACK
  * detect_exploitation      -> EXPLOITATION / EXPLOITATION (lab-specific)
"""

from .config import DetectorConfig
from .port_scan import detect_port_scans
from .ssh_brute_force import detect_ssh_brute_force
from .exploitation import detect_exploitation
from .runner import detect, run_detectors, DETECTORS

__all__ = [
    "DetectorConfig",
    "detect_port_scans",
    "detect_ssh_brute_force",
    "detect_exploitation",
    "detect",
    "run_detectors",
    "DETECTORS",
]
