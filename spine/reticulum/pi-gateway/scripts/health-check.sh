#!/usr/bin/env bash
set -euo pipefail

# Health check for the spine-reticulum gateway container.
# Returns exit code 0 if healthy, 1 otherwise.

if spine-reticulum status >/dev/null 2>&1; then
    echo "OK"
    exit 0
else
    echo "UNHEALTHY"
    exit 1
fi
