"""The three controlled scenarios, in the order the orchestrator runs them."""

from . import recon_nmap, ssh_bruteforce, exploit_metasploit

# Ordered recon -> brute-force -> exploit, which is also the multi-stage
# sequence the correlation engine is expected to reconstruct.
ALL_SCENARIOS = (recon_nmap, ssh_bruteforce, exploit_metasploit)

__all__ = ["recon_nmap", "ssh_bruteforce", "exploit_metasploit", "ALL_SCENARIOS"]
