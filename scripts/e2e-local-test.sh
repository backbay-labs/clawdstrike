#!/usr/bin/env bash
# =============================================================================
# ClawdStrike E2E Local Test — Full enrollment, policy sync, posture commands,
# and approval flow against the Compose-managed local stack.
#
# Usage:
#   ./scripts/e2e-local-test.sh              # Run all phases
#   ./scripts/e2e-local-test.sh --phase 3    # Run from phase 3 onward
#   ./scripts/e2e-local-test.sh --cleanup    # Only run cleanup
#
# Prerequisites:
#   - Docker + docker compose
#   - Rust toolchain (for e2e-posture-cmd)
#   - curl, jq, python3
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

COMPOSE_FILE="${ROOT_DIR}/infra/docker/docker-compose.services.yaml"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PG_CONTAINER="clawdstrike-e2e-pg"
PG_PORT="${CONTROL_API_POSTGRES_PORT:-5433}"
PG_USER="${CONTROL_API_POSTGRES_USER:-clawdstrike}"
PG_PASS="${CONTROL_API_POSTGRES_PASSWORD:-clawdstrike}"
PG_DB="${CONTROL_API_POSTGRES_DB:-cloud_api}"

NATS_URL="${CONTROL_API_AGENT_NATS_URL:-nats://localhost:4222}"
CONTROL_API_PORT="${CONTROL_API_PORT:-8090}"
CONTROL_API_ADDR="127.0.0.1:${CONTROL_API_PORT}"
CONTROL_API_URL="http://${CONTROL_API_ADDR}"
HUSHD_PORT="${HUSHD_PORT:-9876}"
HUSHD_URL="http://127.0.0.1:${HUSHD_PORT}"

TENANT_SLUG="${CONTROL_API_BOOTSTRAP_TENANT_SLUG:-localdev}"
TENANT_ID_DEFAULT="${CONTROL_API_BOOTSTRAP_TENANT_ID:-11111111-1111-4111-8111-111111111111}"
API_KEY="${CONTROL_API_BOOTSTRAP_API_KEY:-cs_local_dev_key}"

# Used by the direct NATS posture-command publisher in phase 5.
SEED_FILE="/tmp/clawdstrike-e2e-posture.key"

export CONTROL_API_POSTGRES_PORT="$PG_PORT"
export CONTROL_API_POSTGRES_USER="$PG_USER"
export CONTROL_API_POSTGRES_PASSWORD="$PG_PASS"
export CONTROL_API_POSTGRES_DB="$PG_DB"
export CONTROL_API_PORT
export CONTROL_API_AGENT_NATS_URL="$NATS_URL"
export CONTROL_API_BOOTSTRAP_TENANT_SLUG="$TENANT_SLUG"
export CONTROL_API_BOOTSTRAP_TENANT_ID="$TENANT_ID_DEFAULT"
export CONTROL_API_BOOTSTRAP_API_KEY="$API_KEY"
export HUSHD_PORT

# State files (written between phases)
STATE_DIR="/tmp/clawdstrike-e2e-state"
mkdir -p "$STATE_DIR"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
START_PHASE=1
CLEANUP_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --phase)   START_PHASE="$2"; shift 2 ;;
        --cleanup) CLEANUP_ONLY=true; shift ;;
        -h|--help)
            head -20 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
phase() { echo -e "\n\033[1;36m=== Phase $1: $2 ===\033[0m"; }
step()  { echo -e "\033[0;33m  → $1\033[0m"; }
ok()    { echo -e "\033[0;32m  ✓ $1\033[0m"; }
fail()  { echo -e "\033[0;31m  ✗ $1\033[0m"; return 1; }

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

wait_for_port() {
    local host=$1 port=$2 label=$3 retries=${4:-30}
    step "Waiting for ${label} on ${host}:${port}..."
    for i in $(seq 1 "$retries"); do
        if nc -z "$host" "$port" 2>/dev/null; then
            ok "${label} is up"
            return 0
        fi
        sleep 1
    done
    fail "${label} did not start within ${retries}s"
}

wait_for_url() {
    local url=$1 label=$2 retries=${3:-30}
    step "Waiting for ${label} at ${url}..."
    for _ in $(seq 1 "$retries"); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            ok "${label} is up"
            return 0
        fi
        sleep 1
    done
    fail "${label} did not become healthy within ${retries}s"
}

compose_psql() {
    compose exec -T control-api-postgres \
        env PGPASSWORD="$PG_PASS" \
        psql -U "$PG_USER" -d "$PG_DB" "$@"
}

save_state() { echo "$2" > "${STATE_DIR}/$1"; }
load_state() { cat "${STATE_DIR}/$1" 2>/dev/null || echo ""; }

ensure_posture_seed() {
    if [[ -s "$SEED_FILE" ]]; then
        return 0
    fi

    step "Generating posture signing seed..."
    python3 -c "import secrets; print(secrets.token_hex(32))" > "$SEED_FILE"
    ok "Seed written to ${SEED_FILE}"
}

resolve_tenant_id() {
    local tenant_id
    local tenant_slug_sql

    tenant_id="$(load_state tenant_id)"
    if [[ -n "$tenant_id" ]]; then
        printf '%s\n' "$tenant_id"
        return 0
    fi

    tenant_slug_sql=${TENANT_SLUG//\'/\'\'}
    tenant_id="$(
        compose_psql \
            -Atqc "SELECT id FROM tenants WHERE slug = '${tenant_slug_sql}' LIMIT 1"
    )"

    if [[ -n "$tenant_id" ]]; then
        save_state "tenant_id" "$tenant_id"
    fi

    printf '%s\n' "$tenant_id"
}

# ---------------------------------------------------------------------------
# Phase 7: Cleanup (also used at the start for idempotency)
# ---------------------------------------------------------------------------
cleanup() {
    phase 7 "Cleanup"

    step "Stopping any leftover manual control-api process..."
    if [[ -f "${STATE_DIR}/control-api.pid" ]]; then
        local pid
        pid=$(cat "${STATE_DIR}/control-api.pid")
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        rm -f "${STATE_DIR}/control-api.pid"
    fi

    step "Stopping any leftover manual Postgres container..."
    docker stop "$PG_CONTAINER" 2>/dev/null || true
    docker rm "$PG_CONTAINER" 2>/dev/null || true

    step "Stopping Compose stack..."
    compose down -v --remove-orphans 2>/dev/null || true

    step "Cleaning state files..."
    rm -rf "$STATE_DIR"
    rm -f "$SEED_FILE"

    ok "Cleanup complete"
}

if $CLEANUP_ONLY; then
    cleanup
    exit 0
fi

# ---------------------------------------------------------------------------
# Phase 1: Infrastructure
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 1 ]]; then
    phase 1 "Infrastructure"

    step "Starting Compose-managed local stack..."
    compose up -d --build nats control-api-postgres control-api hushd

    wait_for_port 127.0.0.1 4222 "NATS"
    wait_for_port 127.0.0.1 "$PG_PORT" "Postgres"
    wait_for_url "${CONTROL_API_URL}/api/v1/health/ready" "control-api" 90
    wait_for_url "${HUSHD_URL}/health" "hushd" 90

    ok "Infrastructure ready"
fi

# ---------------------------------------------------------------------------
# Phase 2: Control API
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 2 ]]; then
    phase 2 "Control API"

    ensure_posture_seed

    step "Seeding tenant + API key via Compose bootstrap job..."
    compose run --rm control-api-seed

    TENANT_ID="$(resolve_tenant_id)"
    if [[ -z "$TENANT_ID" ]]; then
        fail "Failed to resolve seeded tenant id for slug ${TENANT_SLUG}"
    fi

    ok "Tenant ${TENANT_ID} seeded for slug ${TENANT_SLUG}"
fi

# ---------------------------------------------------------------------------
# Phase 3: Enrollment
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 3 ]]; then
    phase 3 "Enrollment"
    TENANT_ID="$(resolve_tenant_id)"

    if [[ -z "$TENANT_ID" ]]; then
        fail "Missing tenant_id state; run phases 1-2 first or start the local stack before resuming"
    fi

    step "Creating enrollment token..."
    TOKEN_RESPONSE=$(curl -sf -X POST \
        "${CONTROL_API_URL}/api/v1/tenants/${TENANT_ID}/enrollment-tokens" \
        -H "x-api-key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"expires_in_hours": 24}')
    ENROLLMENT_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.enrollment_token')
    save_state "enrollment_token" "$ENROLLMENT_TOKEN"
    ok "Enrollment token: ${ENROLLMENT_TOKEN:0:20}..."

    step "Enrolling agent via control-api..."
    # Generate a throwaway Ed25519 keypair for the agent.
    # Use openssl to generate a proper Ed25519 key, or fall back to pynacl, or
    # a known test vector as last resort.
    AGENT_PUBKEY=$(openssl genpkey -algorithm ed25519 2>/dev/null | \
        openssl pkey -pubout -outform DER 2>/dev/null | \
        tail -c 32 | xxd -p -c 32 2>/dev/null || \
    python3 -c "
try:
    from nacl.signing import SigningKey
    import secrets
    sk = SigningKey(secrets.token_bytes(32))
    print(sk.verify_key.encode().hex())
except ImportError:
    # Known-good Ed25519 test vector public key (RFC 8032 test 1)
    print('d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e3')
")

    ENROLL_RESPONSE=$(curl -sf -X POST \
        "${CONTROL_API_URL}/api/v1/agents/enroll" \
        -H "Content-Type: application/json" \
        -d "{
            \"enrollment_token\": \"${ENROLLMENT_TOKEN}\",
            \"public_key\": \"${AGENT_PUBKEY}\",
            \"hostname\": \"e2e-test-host\",
            \"version\": \"0.2.4\"
        }")
    AGENT_ID=$(echo "$ENROLL_RESPONSE" | jq -r '.agent_id')
    save_state "agent_id" "$AGENT_ID"
    echo "$ENROLL_RESPONSE" | jq .
    ok "Agent enrolled: ${AGENT_ID}"
fi

# ---------------------------------------------------------------------------
# Phase 4: Policy Sync
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 4 ]]; then
    phase 4 "Policy Sync"

    step "Deploying policy via control-api..."
    DEPLOY_RESPONSE=$(curl -sf -X POST \
        "${CONTROL_API_URL}/api/v1/policies/deploy" \
        -H "x-api-key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{
            "policy_yaml": "schema_version: \"1.2.0\"\nextends: strict\nguards:\n  forbidden_path:\n    enabled: true\n",
            "description": "e2e test strict policy"
        }')
    echo "$DEPLOY_RESPONSE" | jq .
    ok "Policy deployed"

    step "Verifying active policy..."
    ACTIVE_POLICY=$(curl -sf \
        "${CONTROL_API_URL}/api/v1/policies/active" \
        -H "x-api-key: ${API_KEY}")
    echo "$ACTIVE_POLICY" | jq .
    POLICY_STATUS=$(echo "$ACTIVE_POLICY" | jq -r '.status')
    if [[ "$POLICY_STATUS" == "active" ]]; then
        ok "Active policy confirmed"
    else
        fail "Expected active policy, got status: ${POLICY_STATUS}"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 5: Posture Commands (direct NATS via e2e-posture-cmd)
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 5 ]]; then
    phase 5 "Posture Commands (direct NATS)"
    AGENT_ID=$(load_state "agent_id")

    step "Building e2e-posture-cmd..."
    cargo build -p e2e-posture-cmd --manifest-path "${ROOT_DIR}/Cargo.toml"

    POSTURE_BIN="${ROOT_DIR}/target/debug/e2e-posture-cmd"
    SUBJECT_PREFIX="tenant-localdev.clawdstrike.posture.command"

    step "Sending set_posture restricted..."
    "$POSTURE_BIN" \
        --seed-hex "$SEED_FILE" \
        --nats-url "$NATS_URL" \
        --subject "${SUBJECT_PREFIX}.${AGENT_ID}" \
        --command set-posture --posture restricted \
        --timeout-secs 3
    ok "set_posture sent"

    step "Sending request_policy_reload..."
    "$POSTURE_BIN" \
        --seed-hex "$SEED_FILE" \
        --nats-url "$NATS_URL" \
        --subject "${SUBJECT_PREFIX}.${AGENT_ID}" \
        --command request-policy-reload \
        --timeout-secs 3
    ok "request_policy_reload sent"

    step "Sending kill_switch..."
    "$POSTURE_BIN" \
        --seed-hex "$SEED_FILE" \
        --nats-url "$NATS_URL" \
        --subject "${SUBJECT_PREFIX}.${AGENT_ID}" \
        --command kill-switch --reason "e2e test" \
        --timeout-secs 3
    ok "kill_switch sent"

    echo ""
    echo "  Note: Without a running agent, posture commands are published but"
    echo "  no subscriber is present to reply. The commands are still valid"
    echo "  signed Spine envelopes. Start the agent to see live responses."
fi

# ---------------------------------------------------------------------------
# Phase 6: Approval Flow (control-api route)
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 6 ]]; then
    phase 6 "Approval Flow"
    TENANT_ID="$(resolve_tenant_id)"
    AGENT_ID=$(load_state "agent_id")

    step "Inserting a synthetic approval request into the DB..."
    APPROVAL_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
    REQUEST_ID="e2e-req-$(python3 -c "import uuid; print(uuid.uuid4().hex[:8])")"
    compose_psql -q <<SQL
INSERT INTO approvals (id, tenant_id, agent_id, request_id, event_type, event_data, status)
VALUES (
    '${APPROVAL_ID}',
    '${TENANT_ID}',
    '${AGENT_ID}',
    '${REQUEST_ID}',
    'shell_command',
    '{"action_type": "shell_command", "target": "rm -rf /tmp/test"}'::jsonb,
    'pending'
);
SQL
    save_state "approval_id" "$APPROVAL_ID"
    ok "Approval request inserted: ${APPROVAL_ID}"

    step "Listing pending approvals..."
    APPROVALS=$(curl -sf \
        "${CONTROL_API_URL}/api/v1/approvals" \
        -H "x-api-key: ${API_KEY}")
    echo "$APPROVALS" | jq .
    PENDING_COUNT=$(echo "$APPROVALS" | jq 'length')
    if [[ "$PENDING_COUNT" -ge 1 ]]; then
        ok "Found ${PENDING_COUNT} pending approval(s)"
    else
        fail "Expected at least 1 pending approval"
    fi

    step "Resolving approval..."
    RESOLVE_RESPONSE=$(curl -sf -X POST \
        "${CONTROL_API_URL}/api/v1/approvals/${APPROVAL_ID}/resolve" \
        -H "x-api-key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"resolution":"approved","resolved_by":"e2e-tester"}')
    echo "$RESOLVE_RESPONSE" | jq .
    RESOLUTION=$(echo "$RESOLVE_RESPONSE" | jq -r '.status')
    if [[ "$RESOLUTION" == "approved" ]]; then
        ok "Approval resolved as 'approved'"
    else
        fail "Expected status 'approved', got '${RESOLUTION}'"
    fi

    step "Verifying no more pending approvals..."
    REMAINING=$(curl -sf \
        "${CONTROL_API_URL}/api/v1/approvals" \
        -H "x-api-key: ${API_KEY}" | jq 'length')
    if [[ "$REMAINING" -eq 0 ]]; then
        ok "No pending approvals remaining"
    else
        echo "  (${REMAINING} pending — may include other test data)"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "\033[1;32m=== E2E Test Complete ===\033[0m"
echo ""
echo "  Tenant ID:    $(load_state tenant_id)"
echo "  Agent ID:     $(load_state agent_id)"
echo "  Approval ID:  $(load_state approval_id)"
echo "  Control API:  ${CONTROL_API_URL}"
echo "  hushd:        ${HUSHD_URL}"
echo "  NATS:         ${NATS_URL}"
echo ""
echo "  Run './scripts/e2e-local-test.sh --cleanup' when done."
echo ""
