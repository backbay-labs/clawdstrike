#!/usr/bin/env bash
# =============================================================================
# ClawdStrike E2E Local Test — Full enrollment, policy sync, posture commands,
# and approval flow against real NATS + Postgres + control-api.
#
# Usage:
#   ./scripts/e2e-local-test.sh              # Run all phases
#   ./scripts/e2e-local-test.sh --phase 3    # Run from phase 3 onward
#   ./scripts/e2e-local-test.sh --cleanup    # Only run cleanup
#
# Prerequisites:
#   - Docker (for NATS + Postgres)
#   - Rust toolchain (cargo)
#   - psql (PostgreSQL client)
#   - curl, jq, python3
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PG_CONTAINER="clawdstrike-e2e-pg"
PG_PORT=5433
PG_USER=postgres
PG_PASS=postgres
PG_DB=cloud_api
PG_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/${PG_DB}"

NATS_URL="nats://localhost:4222"
CONTROL_API_ADDR="127.0.0.1:8090"
CONTROL_API_URL="http://${CONTROL_API_ADDR}"

API_KEY="cs_local_dev_key"
SEED_FILE="/tmp/clawdstrike-e2e-approval.key"

COMPOSE_FILE="${ROOT_DIR}/infra/docker/docker-compose.services.yaml"

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

save_state() { echo "$2" > "${STATE_DIR}/$1"; }
load_state() { cat "${STATE_DIR}/$1" 2>/dev/null || echo ""; }

# ---------------------------------------------------------------------------
# Phase 7: Cleanup (also used at the start for idempotency)
# ---------------------------------------------------------------------------
cleanup() {
    phase 7 "Cleanup"

    step "Stopping control-api..."
    if [[ -f "${STATE_DIR}/control-api.pid" ]]; then
        local pid
        pid=$(cat "${STATE_DIR}/control-api.pid")
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        rm -f "${STATE_DIR}/control-api.pid"
    fi

    step "Stopping Postgres container..."
    docker stop "$PG_CONTAINER" 2>/dev/null || true
    docker rm "$PG_CONTAINER" 2>/dev/null || true

    step "Stopping NATS..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

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

    step "Starting NATS via docker compose..."
    docker compose -f "$COMPOSE_FILE" up -d nats

    step "Starting Postgres container..."
    docker rm -f "$PG_CONTAINER" 2>/dev/null || true
    docker run -d --name "$PG_CONTAINER" \
        -e POSTGRES_USER="$PG_USER" \
        -e POSTGRES_PASSWORD="$PG_PASS" \
        -e POSTGRES_DB="$PG_DB" \
        -p "${PG_PORT}:5432" \
        postgres:16-alpine

    wait_for_port 127.0.0.1 4222 "NATS"
    wait_for_port 127.0.0.1 "$PG_PORT" "Postgres"

    # Postgres needs a moment after port is open before accepting connections
    sleep 2

    step "Applying migrations..."
    for f in "${ROOT_DIR}"/crates/services/control-api/migrations/*.sql; do
        step "  $(basename "$f")"
        psql "$PG_URL" -q -f "$f"
    done

    ok "Infrastructure ready"
fi

# ---------------------------------------------------------------------------
# Phase 2: Control API
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 2 ]]; then
    phase 2 "Control API"

    step "Generating signing keypair..."
    python3 -c "import secrets; print(secrets.token_hex(32))" > "$SEED_FILE"
    ok "Keypair seed written to ${SEED_FILE}"

    step "Seeding tenant + API key..."
    TENANT_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
    # The control-api auth middleware hashes the raw API key with SHA-256
    API_KEY_HASH=$(printf '%s' "$API_KEY" | shasum -a 256 | cut -d' ' -f1)

    # On rerun, reuse the existing tenant to avoid FK violations on agents/api_keys.
    EXISTING_ID=$(psql "$PG_URL" -tAq -c "SELECT id FROM tenants WHERE slug = 'localdev' LIMIT 1")
    if [[ -n "$EXISTING_ID" ]]; then
        TENANT_ID="$EXISTING_ID"
        step "Reusing existing tenant ${TENANT_ID}"
    fi

    psql "$PG_URL" -q <<SQL
INSERT INTO tenants (id, name, slug, plan, status, agent_limit, retention_days)
VALUES ('${TENANT_ID}', 'E2E Local Dev', 'localdev', 'enterprise', 'active', 100, 30)
ON CONFLICT (slug) DO UPDATE
    SET name = EXCLUDED.name, plan = EXCLUDED.plan, status = EXCLUDED.status,
        agent_limit = EXCLUDED.agent_limit, retention_days = EXCLUDED.retention_days;

DELETE FROM api_keys WHERE tenant_id = '${TENANT_ID}' AND key_prefix = 'cs_local';
INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, scopes)
VALUES ('${TENANT_ID}', 'e2e-admin', '${API_KEY_HASH}', 'cs_local', ARRAY['admin']);
SQL
    save_state "tenant_id" "$TENANT_ID"
    ok "Tenant ${TENANT_ID} + API key seeded"

    step "Building control-api..."
    cargo build -p clawdstrike-control-api --manifest-path "${ROOT_DIR}/Cargo.toml"

    step "Starting control-api..."
    DATABASE_URL="$PG_URL" \
    NATS_URL="$NATS_URL" \
    NATS_PROVISIONING_MODE="mock" \
    NATS_ALLOW_INSECURE_MOCK_PROVISIONER="true" \
    JWT_SECRET="dev-jwt-secret-local-e2e" \
    STRIPE_SECRET_KEY="sk_test_fake" \
    STRIPE_WEBHOOK_SECRET="whsec_test_fake" \
    APPROVAL_SIGNING_ENABLED="true" \
    APPROVAL_SIGNING_KEYPAIR_PATH="$SEED_FILE" \
    APPROVAL_RESOLUTION_OUTBOX_ENABLED="true" \
    AUDIT_CONSUMER_ENABLED="false" \
    LISTEN_ADDR="$CONTROL_API_ADDR" \
    RUST_LOG="info,clawdstrike_control_api=debug" \
        "${ROOT_DIR}/target/debug/clawdstrike-control-api" &
    CONTROL_PID=$!
    save_state "control-api.pid" "$CONTROL_PID"

    wait_for_port 127.0.0.1 8090 "control-api" 30

    # Verify health
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "${CONTROL_API_URL}/api/v1/health" || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        ok "control-api healthy (HTTP ${HTTP_CODE})"
    else
        fail "control-api health check returned HTTP ${HTTP_CODE}"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 3: Enrollment
# ---------------------------------------------------------------------------
if [[ $START_PHASE -le 3 ]]; then
    phase 3 "Enrollment"
    TENANT_ID=$(load_state "tenant_id")

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
    TENANT_ID=$(load_state "tenant_id")
    AGENT_ID=$(load_state "agent_id")

    step "Inserting a synthetic approval request into the DB..."
    APPROVAL_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
    REQUEST_ID="e2e-req-$(python3 -c "import uuid; print(uuid.uuid4().hex[:8])")"
    psql "$PG_URL" -q <<SQL
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
echo "  NATS:         ${NATS_URL}"
echo ""
echo "  Run './scripts/e2e-local-test.sh --cleanup' when done."
echo ""
