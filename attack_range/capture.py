"""
CyberTrace — Attack Range module: traffic capture coordination.

Thin wrapper around `tshark` that records one PCAP per scenario to the
shared `pcap_dir`. The Attack Range starts a capture, runs the scenario,
then stops it — producing exactly the labeled PCAP files the Detection
Pipeline (Manan) consumes.

INTERFACE NOTE: the only thing the Detection Pipeline needs from capture is
the agreed file-naming convention in `pcap_dir`:
    recon.pcap, ssh_bruteforce.pcap, exploit.pcap, baseline.pcap
Nothing in this module parses the PCAPs — that is the Detection Pipeline's job.

`tshark` is a system tool (installed on the capture host), not a pip package.
If it is absent, PacketCapture raises a clear error rather than failing late.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from typing import Optional


class CaptureError(RuntimeError):
    pass


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


class PacketCapture:
    """Start/stop a tshark capture into a named PCAP.

    Use as a context manager so capture is always stopped::

        with PacketCapture(iface="eth1", pcap_dir="artifacts/run1",
                           name="recon") as cap:
            run_scenario(...)
        print(cap.pcap_path)   # artifacts/run1/recon.pcap
    """

    def __init__(
        self,
        iface: str,
        pcap_dir: str,
        name: str,
        capture_filter: str = "",
        settle_s: float = 1.0,
    ) -> None:
        self.iface = iface
        self.pcap_dir = pcap_dir
        self.name = name
        self.capture_filter = capture_filter
        self.settle_s = settle_s
        os.makedirs(pcap_dir, exist_ok=True)
        self.pcap_path = os.path.join(pcap_dir, f"{name}.pcap")
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        if not tshark_available():
            raise CaptureError(
                "tshark not found on PATH. Install Wireshark/tshark on the "
                "capture host (apt install tshark)."
            )
        cmd = ["tshark", "-i", self.iface, "-w", self.pcap_path, "-q"]
        if self.capture_filter:
            cmd += ["-f", self.capture_filter]
        # Line-buffered; tshark writes the pcap itself.
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        # Give tshark a moment to open the interface before traffic starts,
        # so the first packets of the scenario are not missed.
        time.sleep(self.settle_s)
        if self._proc.poll() is not None:
            err = (self._proc.stderr.read() or b"").decode(errors="replace")
            raise CaptureError(f"tshark exited immediately: {err.strip()}")

    def stop(self) -> str:
        if self._proc is None:
            return self.pcap_path
        # Let trailing packets flush, then signal tshark to finish cleanly.
        time.sleep(self.settle_s)
        self._proc.send_signal(signal.SIGINT)
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        self._proc = None
        return self.pcap_path

    def __enter__(self) -> "PacketCapture":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
