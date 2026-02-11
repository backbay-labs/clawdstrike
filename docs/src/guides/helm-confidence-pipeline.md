# Helm Confidence Pipeline

This guide defines the release-confidence pipeline for the Clawdstrike Helm chart.

The pipeline has three layers:

1. Fast chart correctness checks on every commit.
2. Real-cluster smoke validation from OCI artifacts for merge-candidate pull requests.
3. Nightly resilience/security checks (restart, upgrade, rollback, and policy/OpenClaw validation).

## Pipeline Layers

### Layer 1: Fast Gate

Workflow: `.github/workflows/helm-ci.yml`

Checks:

1. `helm lint infra/deploy/helm/clawdstrike`
2. `helm template` with `infra/deploy/helm/clawdstrike/ci/test-values.yaml`
3. `scripts/release-helm-chart.sh 0.0.0-ci.<run_number>`
4. `helm show chart` against generated package
5. Upload packaged chart artifact

### Layer 2: Merge-Candidate Cluster Smoke

Workflow: `.github/workflows/helm-cluster-smoke.yml`

Trigger policy:

1. Pull request targets `main`.
2. PR must have label `merge-candidate`.
3. Fork PRs are skipped with explicit reason (no cloud/OIDC secrets).

Checks:

1. Build PR-scoped OCI chart version `0.0.0-pr.<pr>.<run>`.
2. Push to `oci://ghcr.io/backbay-labs/clawdstrike/helm-ci`.
3. Install from OCI only (no local chart path).
4. Run `scripts/helm-e2e-smoke.sh`.
5. Upload diagnostics:
  - `summary.json`
  - `summary.md`
  - `pods.txt`
  - `events.txt`
  - `describe/*`
  - `logs/*`

### Layer 3: Nightly Resilience + Security

Workflow: `.github/workflows/helm-nightly-resilience.yml`

Schedule:

1. `02:00 UTC` nightly.
2. Manual `workflow_dispatch` supported.

Checks:

1. Resolve latest stable chart version (or use manual override).
2. Install previous stable version, then upgrade to target version.
3. Restart all deployments and verify recovery.
4. Recycle NATS pod and verify recovery.
5. Execute intentional bad upgrade and verify `helm rollback`.
6. Validate no `ImagePullBackOff` / `CrashLoopBackOff`.
7. Validate rendered security context invariants.
8. Run agent security-focused Rust tests:
  - `cargo test --manifest-path apps/agent/src-tauri/Cargo.toml api_server::tests`
  - `cargo test --manifest-path apps/agent/src-tauri/Cargo.toml openclaw::manager::tests`
9. Optional macOS OpenClaw smoke (`scripts/openclaw-agent-smoke.sh`) as a separate job.

## Local Operator Entry Points

### One-command OCI Smoke

```bash
scripts/helm-e2e-smoke.sh \
  --chart-ref oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike \
  --chart-version 0.1.2 \
  --namespace "clawdstrike-smoke-$(date +%s)" \
  --values infra/deploy/helm/clawdstrike/ci/cluster-smoke-values.yaml \
  --artifact-dir dist/helm-smoke/local
```

### Nightly-style Resilience Locally

```bash
scripts/helm-resilience-security.sh \
  --chart-ref oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike \
  --chart-version 0.1.2 \
  --values infra/deploy/helm/clawdstrike/ci/resilience-values.yaml \
  --namespace "clawdstrike-resilience-$(date +%s)" \
  --artifact-dir dist/helm-resilience/local
```

## Required Secrets and Variables

### GitHub Actions Secrets

1. `AWS_OIDC_ROLE_ARN`: IAM role ARN for GitHub OIDC federation with EKS access.
2. `ARTIFACTHUB_REPOSITORY_ID`: Artifact Hub repository ID (for chart release metadata publishing).

### GitHub Actions Variables

1. `EKS_CLUSTER_NAME`: target EKS cluster name.
2. `AWS_REGION`: AWS region (`us-east-1` default if omitted).
3. `ENABLE_MACOS_OPENCLAW_SMOKE`: set to `true` to enable optional nightly macOS OpenClaw smoke job.

## Diagnostics Artifact Schema

Both smoke scripts write `summary.json` with:

1. `chart_ref`
2. `chart_version`
3. `cluster_context`
4. `namespace`
5. `helm_status`
6. `helm_test`
7. `health`
8. `timestamp`
9. `failures`

## Common Failures and Remediation

### `ImagePullBackOff`

Cause:

1. Missing GHCR pull credentials.
2. Wrong image tags vs chart app version.

Fix:

1. Set `GHCR_PULL_USERNAME` and `GHCR_PULL_TOKEN` for smoke scripts.
2. Confirm chart version references available image tags.
3. Confirm `global.imagePullSecrets` includes `ghcr-pull`.

### Pod scheduling stalls (`Pending`)

Cause:

1. Node architecture mismatch (for example, arm64-only image on x86 nodes).

Fix:

1. Set or adjust `global.nodeSelector`.
2. Ensure matching worker nodes exist in the cluster.

### `helm test` failures

Cause:

1. Service not healthy yet.
2. Startup race between pods.

Fix:

1. Inspect artifact logs and events.
2. Increase timeout via `--timeout`.
3. Re-run against a fresh namespace.

### OIDC / EKS access failures in CI

Cause:

1. Missing role trust relationship for GitHub OIDC.
2. Wrong `EKS_CLUSTER_NAME` or `AWS_REGION`.

Fix:

1. Validate IAM trust policy and permissions.
2. Validate `aws eks update-kubeconfig` manually using the same role.

## Promotion and Readiness

1. Run new workflows in non-blocking mode until three consecutive green runs.
2. Mark `Helm Cluster Smoke` as required in branch protection.
3. Keep nightly resilience enabled for two weeks with no unresolved failures.
4. Enforce production release gate only after the above are stable.
