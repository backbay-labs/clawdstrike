#!/usr/bin/env bash
set -euo pipefail

exec cargo \
  --config 'source.crates-io.replace-with="vendored-sources"' \
  "$@"
