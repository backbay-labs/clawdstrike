#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT="$(cd ../../.. && pwd)"
DEST_INCLUDE_DIR="$REPO_ROOT/packages/sdk/hush-go/native/include"
DEST_LIB_DIR="$REPO_ROOT/packages/sdk/hush-go/native/lib"

mkdir -p "$DEST_INCLUDE_DIR" "$DEST_LIB_DIR"

# Build static library
cargo build --release -p hush-go-native

# Generate C header
cbindgen --config cbindgen.toml --crate hush-go-native --output "$DEST_INCLUDE_DIR/hush_go_native.h"

# Copy static library (platform-dependent name)
if [[ "$(uname)" == "Darwin" ]]; then
    cp "$REPO_ROOT/target/release/libhush_go_native.a" "$DEST_LIB_DIR/"
    cp "$REPO_ROOT/target/release/libhush_go_native.dylib" "$DEST_LIB_DIR/" 2>/dev/null || true
else
    cp "$REPO_ROOT/target/release/libhush_go_native.a" "$DEST_LIB_DIR/"
    cp "$REPO_ROOT/target/release/libhush_go_native.so" "$DEST_LIB_DIR/" 2>/dev/null || true
fi

echo "Build complete. Static library and header copied to packages/sdk/hush-go/native/"
