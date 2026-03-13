# Local Docker Stack

This directory contains the canonical Docker-based local stack for ClawdStrike services.

## What it runs

Default `docker compose up -d --build` starts:

- `nats` with JetStream on `localhost:4222`
- `control-api-postgres` on `localhost:5433`
- `control-api` on `localhost:8090`
- `control-api-seed` to bootstrap a local tenant + admin API key
- `hushd` on `localhost:9876`

For the local stack, `hushd` and `control-api` build `dev` profile binaries with
`CARGO_BUILD_JOBS=1` by default. That keeps first-run memory usage manageable on
4 GiB Docker/Colima setups. Override `CLAWDSTRIKE_LOCAL_CARGO_PROFILE=release`
if you explicitly want release-profile local images.

Optional profiles:

- `spine`: `spine-checkpointer`, `spine-witness`, `spine-proofs-api`
- `registry`: `clawdstrike-registry`
- `bridges`: `tetragon-bridge`, `hubble-bridge`

## Quick start

```bash
cp infra/docker/.env.example infra/docker/.env
docker compose -f infra/docker/docker-compose.services.yaml up -d --build
docker compose -f infra/docker/docker-compose.services.yaml ps
```

Enable more of the stack:

```bash
docker compose -f infra/docker/docker-compose.services.yaml \
  --profile spine \
  --profile registry \
  up -d --build
```

Bridge services are opt-in because they require external gRPC sources:

```bash
TETRAGON_GRPC=host.docker.internal:54321 \
HUBBLE_GRPC=host.docker.internal:4245 \
docker compose -f infra/docker/docker-compose.services.yaml \
  --profile bridges \
  up -d --build
```

## Local credentials and URLs

With the default `.env.example` values:

- `hushd`: `http://localhost:9876`
- `control-api`: `http://localhost:8090`
- `NATS`: `nats://localhost:4222`
- seeded control-api tenant slug: `localdev`
- seeded control-api admin API key: `cs_local_dev_key`
- hushd check key: `clawdstrike-local-check`
- hushd admin key: `clawdstrike-local-admin`
- hushd auth pepper: `clawdstrike-local-pepper`
- local cargo profile: `dev`
- local cargo build jobs: `1`

The `control-api` container uses internal NATS connectivity (`nats://nats:4222`) while enrolled local agents receive `nats://localhost:4222`.

## Notes

- `control-api` runs its embedded migrations on startup. The `control-api-seed` job waits for the schema, then inserts or refreshes the local tenant and admin API key metadata.
- The compose stack is intentionally local-only. It uses mock NATS provisioning and development secrets.
- Kubernetes-only features such as External Secrets, ingress, RBAC, service monitors, and the `k8s-audit` bridge integration are still owned by the Helm chart in `infra/deploy/helm/clawdstrike/`.
- The older `examples/docker-compose/` directory remains a daemon-only example. Use this directory for the broader multi-service developer stack.
