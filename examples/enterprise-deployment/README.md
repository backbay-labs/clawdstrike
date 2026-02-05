# Enterprise Deployment (Example)

This example demonstrates **enterprise-style policy distribution** using:

- Signed policy bundles (`clawdstrike policy bundle build`)
- Trusted bundle verification in `hushd` (`policy_bundle_trusted_pubkeys`)
- Updating the running daemon via `PUT /api/v1/policy/bundle`

## Prerequisites

- Docker
- Rust toolchain (to run `hush`)

## Quick Start

```bash
cd examples/enterprise-deployment

# 1) Generate signing keypair for policy bundles
cargo run -p hush-cli -- keygen --output ./bundle-signing.key
export CLAWDSTRIKE_POLICY_BUNDLE_PUBKEY="$(cat ./bundle-signing.key.pub)"

# 2) Generate daemon API keys (demo only)
export CLAWDSTRIKE_API_KEY="$(openssl rand -hex 32)"
export CLAWDSTRIKE_ADMIN_KEY="$(openssl rand -hex 32)"

# 3) Start hushd
docker compose up -d --build

# 4) Build a signed bundle and publish it
cargo run -p hush-cli -- policy bundle build ./policy-next.yaml --resolve --key ./bundle-signing.key --embed-pubkey --output ./policy-next.bundle.json

curl -sS -X PUT http://localhost:8080/api/v1/policy/bundle \\
  -H "Authorization: Bearer $CLAWDSTRIKE_ADMIN_KEY" \\
  -H "Content-Type: application/json" \\
  --data-binary @./policy-next.bundle.json | jq .

# 5) Confirm the policy changed
curl -sS http://localhost:8080/api/v1/policy -H "Authorization: Bearer $CLAWDSTRIKE_API_KEY" | jq .
```

