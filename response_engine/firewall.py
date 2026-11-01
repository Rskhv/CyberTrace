"""Lab-scoped Linux iptables adapter. Dry-run is the default."""
from __future__ import annotations
import ipaddress, json, shutil, subprocess, time

class LabIptables:
    def __init__(self, *, allowed_interfaces: set[str], lab_networks: list[str], dry_run: bool = True, binary: str = "iptables"):
        self.allowed_interfaces = set(allowed_interfaces)
        self.lab_networks = [ipaddress.ip_network(n, strict=False) for n in lab_networks]
        self.dry_run, self.binary = dry_run, binary

    def _validate(self, source_ip: str, interface: str):
        address = ipaddress.ip_address(source_ip)
        if interface not in self.allowed_interfaces: raise PermissionError("interface is not configured as isolated lab")
        if not any(address.version == net.version and address in net for net in self.lab_networks):
            raise PermissionError("source is outside configured isolated lab networks")
        if not shutil.which(self.binary): raise RuntimeError("iptables is unavailable")
        return str(address)

    def restrict(self, source_ip: str, interface: str, *, expires_at: float, incident_id: str | None = None) -> dict:
        source = self._validate(source_ip, interface)
        if expires_at <= time.time(): raise ValueError("expiry must be in the future")
        comment = "cybertrace:" + (incident_id or "temporary")
        args = [self.binary, "-C", "INPUT", "-i", interface, "-s", source, "-m", "comment", "--comment", comment, "-j", "DROP"]
        if self.dry_run: return {"result":"DRY_RUN", "command":args, "expires_at":expires_at}
        exists = subprocess.run(args, capture_output=True, check=False).returncode == 0
        if not exists:
            add = args.copy(); add[1] = "-I"
            subprocess.run(add, check=True, capture_output=True, text=True)
        return {"result":"ALREADY_PRESENT" if exists else "APPLIED", "command":args, "expires_at":expires_at}

    def remove(self, source_ip: str, interface: str, *, incident_id: str | None = None, administrator_override: bool = False) -> dict:
        source = self._validate(source_ip, interface)
        if not administrator_override: raise PermissionError("restriction removal requires administrator override")
        comment = "cybertrace:" + (incident_id or "temporary")
        args = [self.binary, "-D", "INPUT", "-i", interface, "-s", source, "-m", "comment", "--comment", comment, "-j", "DROP"]
        if self.dry_run: return {"result":"DRY_RUN", "command":args}
        result = subprocess.run(args, capture_output=True, check=False, text=True)
        return {"result":"REMOVED" if result.returncode == 0 else "NOT_PRESENT", "command":args}
