#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

# Build for web (browser) target
echo "Building for web target..."
wasm-pack build --target web --out-dir pkg --release

# Build for Node.js target
echo "Building for Node.js target..."
wasm-pack build --target nodejs --out-dir pkg-node --release

# Report bundle sizes
echo ""
echo "Bundle sizes:"
ls -lh pkg/*.wasm 2>/dev/null || true
ls -lh pkg-node/*.wasm 2>/dev/null || true

# Check if under 500KB target
if [ -f pkg/hush_wasm_bg.wasm ]; then
    WASM_SIZE=$(stat -f%z pkg/hush_wasm_bg.wasm 2>/dev/null || stat -c%s pkg/hush_wasm_bg.wasm 2>/dev/null)
    if [ "$WASM_SIZE" -gt 512000 ]; then
        echo "WARNING: WASM bundle size ($WASM_SIZE bytes) exceeds 500KB target"
    else
        echo "WASM bundle size ($WASM_SIZE bytes) is under 500KB target"
    fi
fi

echo ""
echo "Build complete!"
echo "  Web package: pkg/"
echo "  Node.js package: pkg-node/"
