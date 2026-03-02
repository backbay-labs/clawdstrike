#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT="$(cd ../../.. && pwd)"

# Build static library
cargo build --release -p hush-go-native

# Generate C header
cbindgen --config cbindgen.toml --crate hush-go-native --output "$REPO_ROOT/packages/sdk/hush-go/native/include/hush_go_native.h"

# Copy static library (platform-dependent name)
if [[ "$(uname)" == "Darwin" ]]; then
    cp "$REPO_ROOT/target/release/libhush_go_native.a" "$REPO_ROOT/packages/sdk/hush-go/native/lib/"
    cp "$REPO_ROOT/target/release/libhush_go_native.dylib" "$REPO_ROOT/packages/sdk/hush-go/native/lib/" 2>/dev/null || true
else
    cp "$REPO_ROOT/target/release/libhush_go_native.a" "$REPO_ROOT/packages/sdk/hush-go/native/lib/"
    cp "$REPO_ROOT/target/release/libhush_go_native.so" "$REPO_ROOT/packages/sdk/hush-go/native/lib/" 2>/dev/null || true
fi

echo "Build complete. Static library and header copied to packages/sdk/hush-go/native/"
