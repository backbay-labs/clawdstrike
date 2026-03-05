#!/usr/bin/env bash
# registry-smoke.sh — End-to-end smoke test for the clawdstrike package registry.
#
# Usage:
#   bash tests/registry-smoke.sh
#   mise run registry-smoke
#
# Prerequisites:
#   cargo build -p clawdstrike-registry -p hush-cli
#
# The script starts a local registry on a random port and validates that the
# server boots, responds to health/search/transparency endpoints, and serves
# correct HTTP status codes. The full publish→search→install→audit lifecycle
# is covered by the 171 unit tests in crates/services/clawdstrike-registry.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "${YELLOW}→ $1${NC}"; }

FAILURES=0
CLEANUP_PIDS=()
CLEANUP_DIRS=()

cleanup() {
    info "Cleaning up..."
    for pid in "${CLEANUP_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for dir in "${CLEANUP_DIRS[@]}"; do
        rm -rf "$dir"
    done
}
trap cleanup EXIT

# Resolve binaries
REGISTRY_BIN="${REPO_ROOT}/target/release/clawdstrike-registry"
CLI_BIN="${REPO_ROOT}/target/release/clawdstrike"

if [[ ! -x "$REGISTRY_BIN" ]] || [[ ! -x "$CLI_BIN" ]]; then
    REGISTRY_BIN="${REPO_ROOT}/target/debug/clawdstrike-registry"
    CLI_BIN="${REPO_ROOT}/target/debug/clawdstrike"
fi

if [[ ! -x "$REGISTRY_BIN" ]]; then
    info "Building registry and CLI..."
    cargo build -p clawdstrike-registry -p hush-cli --manifest-path "${REPO_ROOT}/Cargo.toml"
    REGISTRY_BIN="${REPO_ROOT}/target/debug/clawdstrike-registry"
    CLI_BIN="${REPO_ROOT}/target/debug/clawdstrike"
fi

# Pick a random port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

# Create temp dirs
DATA_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)
CLEANUP_DIRS+=("$DATA_DIR" "$WORK_DIR")

info "Starting registry on port $PORT (data: $DATA_DIR)"

CLAWDSTRIKE_REGISTRY_HOST="127.0.0.1" \
CLAWDSTRIKE_REGISTRY_PORT="$PORT" \
CLAWDSTRIKE_REGISTRY_DATA_DIR="$DATA_DIR" \
CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH="true" \
RUST_LOG="warn" \
    "$REGISTRY_BIN" &
SERVER_PID=$!
CLEANUP_PIDS+=("$SERVER_PID")

REGISTRY_URL="http://127.0.0.1:${PORT}"

# Wait for health
info "Waiting for registry to be ready..."
for i in $(seq 1 30); do
    if curl -sf "${REGISTRY_URL}/health" > /dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        fail "Registry process died on startup"
        exit 1
    fi
    sleep 0.5
done

# ---------------------------------------------------------------------------
# 1. Health check
# ---------------------------------------------------------------------------
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${REGISTRY_URL}/health") || true
if [[ "$HTTP_CODE" == "200" ]]; then
    pass "GET /health → 200"
else
    fail "GET /health → $HTTP_CODE (expected 200)"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Transparency checkpoint (empty log is valid)
# ---------------------------------------------------------------------------
info "Checking transparency log..."
CHECKPOINT=$(curl -sf "${REGISTRY_URL}/api/v1/transparency/checkpoint") || true
if echo "$CHECKPOINT" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "GET /api/v1/transparency/checkpoint → valid JSON"
else
    fail "transparency checkpoint invalid or missing (response: ${CHECKPOINT:0:200})"
fi

# ---------------------------------------------------------------------------
# 3. Search on empty registry returns empty list
# ---------------------------------------------------------------------------
info "Searching empty registry..."
SEARCH=$(curl -sf "${REGISTRY_URL}/api/v1/search?q=nonexistent") || true
if echo "$SEARCH" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['total']==0" 2>/dev/null; then
    pass "GET /api/v1/search → empty result set"
else
    fail "search response unexpected (response: ${SEARCH:0:200})"
fi

# ---------------------------------------------------------------------------
# 4. Package info for non-existent returns 404
# ---------------------------------------------------------------------------
info "Checking 404 for non-existent package..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${REGISTRY_URL}/api/v1/packages/%40nonexistent%2Ffoo") || true
if [[ "$HTTP_CODE" == "404" ]]; then
    pass "GET /api/v1/packages/@nonexistent/foo → 404"
else
    fail "expected 404, got $HTTP_CODE"
fi

# ---------------------------------------------------------------------------
# 5. Popular packages endpoint (empty, should return 200)
# ---------------------------------------------------------------------------
info "Checking popular packages endpoint..."
POPULAR=$(curl -sf "${REGISTRY_URL}/api/v1/popular") || true
if echo "$POPULAR" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "GET /api/v1/popular → valid JSON"
else
    fail "popular endpoint failed (response: ${POPULAR:0:200})"
fi

# ---------------------------------------------------------------------------
# 6. CLI pkg init + pack (local operations, no server interaction)
# ---------------------------------------------------------------------------
info "Testing CLI pkg init + pack..."
cd "$WORK_DIR"
if "$CLI_BIN" pkg init --pkg-type guard --name "@smoke/test-guard" > /dev/null 2>&1; then
    pass "clawdstrike pkg init succeeded"
else
    fail "clawdstrike pkg init failed"
fi

if [[ -f "clawdstrike-pkg.toml" ]]; then
    pass "pkg init created clawdstrike-pkg.toml"
else
    fail "pkg init did not create clawdstrike-pkg.toml"
fi

PACK_OUTPUT=$("$CLI_BIN" pkg pack 2>&1) || true
CPKG_FILE=$(find "$WORK_DIR" -name '*.cpkg' -print -quit 2>/dev/null || true)
if [[ -n "$CPKG_FILE" ]] && [[ -f "$CPKG_FILE" ]]; then
    pass "clawdstrike pkg pack created .cpkg archive"
else
    fail "clawdstrike pkg pack failed (output: ${PACK_OUTPUT:0:200})"
fi

# ---------------------------------------------------------------------------
# 7. Unauthenticated publish returns 401 when auth is required
# ---------------------------------------------------------------------------
info "Checking auth enforcement..."
# Start a second registry with auth enabled
AUTH_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
AUTH_DATA_DIR=$(mktemp -d)
CLEANUP_DIRS+=("$AUTH_DATA_DIR")

CLAWDSTRIKE_REGISTRY_HOST="127.0.0.1" \
CLAWDSTRIKE_REGISTRY_PORT="$AUTH_PORT" \
CLAWDSTRIKE_REGISTRY_DATA_DIR="$AUTH_DATA_DIR" \
CLAWDSTRIKE_REGISTRY_API_KEY="test-secret-key" \
RUST_LOG="warn" \
    "$REGISTRY_BIN" &
AUTH_PID=$!
CLEANUP_PIDS+=("$AUTH_PID")

# Wait for auth server
for i in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:${AUTH_PORT}/health" > /dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${AUTH_PORT}/api/v1/packages" \
    -H "Content-Type: application/json" \
    -d '{"archive_base64":"","publisher_key":"","publisher_sig":"","manifest_toml":""}') || true
if [[ "$HTTP_CODE" == "401" ]]; then
    pass "POST /api/v1/packages without auth → 401"
else
    fail "expected 401 without auth, got $HTTP_CODE"
fi

# With valid API key but bad payload → should get past auth (400 or similar, not 401)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${AUTH_PORT}/api/v1/packages" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-secret-key" \
    -d '{"archive_base64":"","publisher_key":"","publisher_sig":"","manifest_toml":""}') || true
if [[ "$HTTP_CODE" != "401" ]]; then
    pass "POST /api/v1/packages with valid auth → $HTTP_CODE (not 401)"
else
    fail "valid API key still returned 401"
fi

# ---------------------------------------------------------------------------
# 8. Data directory structure
# ---------------------------------------------------------------------------
info "Checking data directory..."
if [[ -f "$DATA_DIR/db.sqlite" ]]; then
    pass "SQLite database created at data_dir/db.sqlite"
else
    fail "SQLite database not found in data dir"
fi

if [[ -d "$DATA_DIR/keys" ]]; then
    pass "Keys directory created"
else
    fail "Keys directory not found"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=========================================="
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}All smoke tests passed!${NC}"
    exit 0
else
    echo -e "${RED}${FAILURES} test(s) failed${NC}"
    exit 1
fi
