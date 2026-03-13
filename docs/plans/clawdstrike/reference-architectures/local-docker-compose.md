# Local Docker Compose Stack

## Purpose

Provide a single local, source-built Docker Compose entrypoint that brings up as much of the ClawdStrike service plane as possible for users and developers without requiring Kubernetes.

## Current state

The repository already had most of the raw pieces, but not a coherent local stack:

- `infra/deploy/helm/clawdstrike/` is the canonical deployment model for the full service plane.
- `infra/docker/docker-compose.services.yaml` only covered `nats`, Spine services, optional bridge containers, and the registry.
- `Dockerfile.hushd`, `infra/docker/Dockerfile.control-api`, `infra/docker/Dockerfile.spine`, and `Dockerfile.registry` already provided the necessary container build surfaces.
- `scripts/e2e-local-test.sh` proved that a useful local control-plane loop exists, but it still booted `control-api` from `cargo` and seeded Postgres manually instead of using a first-class container workflow.
- `examples/docker-compose/` and `examples/enterprise-deployment/` remained daemon-only hushd examples, not a shared local control-plane stack.

## Target shape

The canonical local Docker stack should cover the services that are meaningfully runnable on a laptop:

### Default stack

- `nats`
- `control-api-postgres`
- `control-api`
- `control-api-seed`
- `hushd`

### Optional profiles

- `spine`: `spine-checkpointer`, `spine-witness`, `spine-proofs-api`
- `registry`: `clawdstrike-registry`
- `bridges`: `tetragon-bridge`, `hubble-bridge` when external gRPC sources exist

## Why these services fit Compose

- `hushd` is a single-process daemon with file-backed persistence.
- `control-api` already embeds its migrations and only needs Postgres + NATS.
- `NATS` and `Postgres` both have well-supported upstream images.
- Spine services are already packaged as single-purpose containers driven by `NATS_URL`.
- The package registry already had a container and persistent volume story.

## What stays Helm-first

Some workloads remain Kubernetes-shaped even if their binaries are containerized:

- `k8s-audit-bridge` needs Kubernetes audit webhook wiring and cluster auth.
- `auditd-bridge` is Linux-host specific and expects host audit surfaces.
- ingress, External Secrets, RBAC, ServiceMonitor, and PVC policy remain Helm concerns.
- public NATS exposure and SPIFFE/SPIRE integration remain cluster deployment features.

## Repository landing zones

- Canonical local stack: `infra/docker/docker-compose.services.yaml`
- Local stack operational docs: `infra/docker/README.md`
- Local bootstrap/config artifacts: `infra/docker/control-api/`, `infra/docker/hushd/`
- Runtime image packaging: `Dockerfile.hushd`, `infra/docker/Dockerfile.control-api`

## Gap statement

What now exists:

- one Compose file that can start the daemon + control plane locally
- source-built container paths for `hushd`, `control-api`, Spine, and registry
- local bootstrap for `control-api` tenant/API-key seeding

What is still missing:

- a Compose-backed e2e script that reuses the same services instead of booting `control-api` from `cargo`
- optional packaging for `k8s-audit-bridge` and `auditd-bridge` in explicitly host-bound profiles
- a packaged desktop/workbench smoke that targets the local Compose control plane by default
