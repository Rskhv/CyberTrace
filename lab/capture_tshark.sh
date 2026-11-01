#!/usr/bin/env bash
# Capture a named, authorized lab scenario. Run on the monitoring/Kali VM.
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <scenario> <interface> [duration-seconds]" >&2
  echo "scenario: nmap_scan | ssh_bruteforce | exploitation | benign" >&2
  exit 2
fi
scenario="$1"
iface="$2"
duration="${3:-180}"
case "$scenario" in nmap_scan|ssh_bruteforce|exploitation|benign) ;; *) echo "Invalid scenario" >&2; exit 2;; esac
if ! [[ "$duration" =~ ^[1-9][0-9]*$ ]]; then echo "Duration must be a positive integer" >&2; exit 2; fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/data/pcaps"
mkdir -p "$out"
echo "Capturing $scenario on $iface for at most $duration seconds. Stop early with Ctrl+C."
exec tshark -i "$iface" -a "duration:$duration" -w "$out/$scenario.pcapng"
