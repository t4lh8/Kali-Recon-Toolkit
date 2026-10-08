#!/usr/bin/env bash
# Kali Recon Toolkit - convenience wrapper.
# Runs host discovery, then a service scan + report. Test only what you own.
#
#   ./recon.sh 192.168.56.10
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORTS="${2:-1-1000}"

command -v nmap >/dev/null || { echo "nmap missing: sudo apt install -y nmap"; exit 1; }

echo "[*] Host discovery on ${TARGET} ..."
nmap -sn "${TARGET}" || true

echo
echo "[*] Service scan + report ..."
python3 "$(dirname "$0")/recon.py" "${TARGET}" -p "${PORTS}"
