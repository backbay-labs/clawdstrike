#!/usr/bin/env bash
set -euo pipefail

# Flash RNode firmware to a compatible LoRa device.
# Requires: rnodeconf (installed with rns)
#
# Usage: ./setup-rnode.sh [/dev/ttyUSB0]

DEVICE="${1:-/dev/ttyUSB0}"

echo "==> Detecting RNode on ${DEVICE}..."
if ! command -v rnodeconf &>/dev/null; then
    echo "ERROR: rnodeconf not found. Install with: pip install rns"
    exit 1
fi

rnodeconf "${DEVICE}" --info

echo ""
echo "==> To flash firmware, run:"
echo "    rnodeconf ${DEVICE} --autoinstall"
echo ""
echo "==> To set frequency (US ISM 915 MHz):"
echo "    rnodeconf ${DEVICE} --freq 915000000 --bw 125000 --sf 8 --cr 5 --txp 17"
