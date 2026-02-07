#!/bin/sh
set -eu

case "$SPINE_BIN" in
  spine-checkpointer|spine-witness|spine-proofs-api)
    exec "/usr/local/bin/$SPINE_BIN" "$@"
    ;;
  *)
    echo "ERROR: Invalid SPINE_BIN='$SPINE_BIN'. Must be one of: spine-checkpointer, spine-witness, spine-proofs-api" >&2
    exit 1
    ;;
esac
