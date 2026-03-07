# ClawdStrike Helm Chart

Production Helm chart for the ClawdStrike SDR (Swarm Detection & Response) stack.

## Architecture

![ClawdStrike Helm architecture](https://raw.githubusercontent.com/backbay-labs/clawdstrike/main/.github/assets/clawdstrike-helm-architecture.png)

## Components

| Component | Type | Default |
|-----------|------|---------|
| NATS JetStream | StatefulSet | enabled |
| spine-checkpointer | Deployment | enabled |
| spine-witness | Deployment | enabled |
| spine-proofs-api | Deployment | enabled |
| hushd | Deployment | enabled |
| tetragon-bridge | DaemonSet | disabled |
| hubble-bridge | Deployment | disabled |

## Quick Start

```bash
helm install clawdstrike ./infra/deploy/helm/clawdstrike
```

Install from OCI:

```bash
helm install clawdstrike oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike --version <version>
```

## Configuration

### Global

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imagePullPolicy` | Image pull policy | `IfNotPresent` |
| `global.imagePullSecrets` | Image pull secrets | `[]` |
| `global.nodeSelector` | Node selector applied to all workloads | `{}` |
| `global.tolerations` | Tolerations applied to all workloads | `[]` |
| `global.namespace` | Override namespace | `""` |
| `namespace.create` | Create namespace | `true` |
| `namespace.name` | Namespace name | `clawdstrike-system` |

### External Secrets

| Parameter | Description | Default |
|-----------|-------------|---------|
| `externalSecrets.enabled` | Render ExternalSecret resources for component secrets | `false` |
| `externalSecrets.secretStoreRef.kind` | External Secrets store kind | `ClusterSecretStore` |
| `externalSecrets.secretStoreRef.name` | External Secrets store name | `aws-secrets-manager` |
| `externalSecrets.secrets.spine.remoteKey` | Remote secret key for `SPINE_*` seeds | `""` |
| `externalSecrets.secrets.hushd.remoteKey` | Remote secret key for hushd auth material | `""` |
| `externalSecrets.secrets.controlApi.remoteKey` | Remote secret key for control-api secrets | `""` |
| `externalSecrets.secrets.controlApiPostgres.remoteKey` | Remote secret key for control-api Postgres auth | `""` |
| `externalSecrets.secrets.easAnchor.remoteKey` | Remote secret key for `EAS_SIGNER_PRIVATE_KEY` | `""` |

### NATS

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nats.enabled` | Deploy bundled NATS | `true` |
| `nats.external.enabled` | Use external NATS | `false` |
| `nats.external.url` | External NATS URL | `""` |
| `nats.image.repository` | NATS image | `nats` |
| `nats.image.tag` | NATS image tag | `2.10-alpine` |
| `nats.replicas` | NATS replicas | `1` |
| `nats.jetstream.enabled` | Enable JetStream | `true` |
| `nats.jetstream.storage.size` | JetStream PVC size | `10Gi` |

### Spine

| Parameter | Description | Default |
|-----------|-------------|---------|
| `spine.enabled` | Deploy Spine services | `true` |
| `spine.image.repository` | Spine image | `ghcr.io/backbay-labs/clawdstrike/spine` |
| `spine.image.tag` | Override image tag | `""` (uses appVersion) |
| `spine.checkpointer.enabled` | Deploy checkpointer | `true` |
| `spine.checkpointer.replicas` | Checkpointer replicas | `1` |
| `spine.witness.enabled` | Deploy witness | `true` |
| `spine.witness.replicas` | Witness replicas | `1` |
| `spine.proofsApi.enabled` | Deploy proofs-api | `true` |
| `spine.proofsApi.replicas` | Proofs API replicas | `1` |
| `spine.proofsApi.port` | Proofs API port | `8080` |

### hushd

| Parameter | Description | Default |
|-----------|-------------|---------|
| `hushd.enabled` | Deploy hushd | `true` |
| `hushd.image.repository` | hushd image | `ghcr.io/backbay-labs/clawdstrike/hushd` |
| `hushd.image.tag` | Override image tag | `""` (uses appVersion) |
| `hushd.replicas` | hushd replicas | `1` |
| `hushd.port` | hushd listen port | `9876` |
| `hushd.config.ruleset` | Security ruleset | `default` |
| `hushd.config.logLevel` | Log level | `info` |
| `hushd.auth.enabled` | Enable API key auth | `true` |
| `hushd.auth.existingSecret` | Existing Secret name | `""` |
| `hushd.persistence.enabled` | Enable audit DB PVC | `true` |
| `hushd.persistence.size` | PVC size | `1Gi` |

### Bridges

| Parameter | Description | Default |
|-----------|-------------|---------|
| `bridges.tetragon.enabled` | Deploy tetragon-bridge | `false` |
| `bridges.tetragon.grpcEndpoint` | Tetragon gRPC address | `http://localhost:54321` |
| `bridges.tetragon.adminPort` | Admin HTTP port for `/healthz`, `/readyz`, `/metrics` | `22112` |
| `bridges.tetragon.hostNetwork` | Run tetragon-bridge with host networking | `true` |
| `bridges.tetragon.dnsPolicy` | DNS policy for host-networked bridge | `ClusterFirstWithHostNet` |
| `bridges.tetragon.probes.enabled` | Enable admin HTTP liveness/readiness probes | `true` |
| `bridges.hubble.enabled` | Deploy hubble-bridge | `false` |
| `bridges.hubble.replicas` | Hubble bridge replica count | `1` |
| `bridges.hubble.grpcEndpoint` | Hubble gRPC address | `http://hubble-relay.kube-system.svc.cluster.local:80` |

### Security

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `podSecurityContext.runAsNonRoot` | Non-root enforcement | `true` |
| `podSecurityContext.runAsUser` | Container UID | `1000` |
| `securityContext.readOnlyRootFilesystem` | Read-only root FS | `true` |
| `networkPolicy.enabled` | Deploy NetworkPolicy | `false` |
| `serviceMonitor.enabled` | Deploy ServiceMonitor | `false` |
| `serviceMonitor.endpoints.proofsApi` | Scrape proofs-api metrics endpoint | `false` |
| `ingress.enabled` | Deploy ingress resources | `false` |
| `ingress.hushd.host` | hushd ingress host | `hushd.clawdstrike.local` |
| `ingress.proofsApi.host` | proofs-api ingress host | `proofs-api.clawdstrike.local` |

## External NATS

To use an existing NATS cluster instead of deploying one:

```bash
helm install clawdstrike ./infra/deploy/helm/clawdstrike \
  --set nats.enabled=false \
  --set nats.external.enabled=true \
  --set nats.external.url=nats://my-nats:4222
```

## Selective Installation

Deploy only specific components:

```bash
# Spine only
helm install clawdstrike ./infra/deploy/helm/clawdstrike \
  --set hushd.enabled=false

# hushd only
helm install clawdstrike ./infra/deploy/helm/clawdstrike \
  --set spine.enabled=false

# With bridges
helm install clawdstrike ./infra/deploy/helm/clawdstrike \
  --set bridges.tetragon.enabled=true \
  --set bridges.hubble.enabled=true
```

## Testing

```bash
# Lint
helm lint infra/deploy/helm/clawdstrike

# Template rendering
helm template test infra/deploy/helm/clawdstrike

# Install and test
helm install cs infra/deploy/helm/clawdstrike --wait
helm test cs
```

## Packaging

```bash
# Build chart package at dist/helm/clawdstrike-<version>.tgz
scripts/release-helm-chart.sh 0.1.0
```

## Publish to OCI (GHCR)

```bash
HELM_REGISTRY_USERNAME="$GITHUB_ACTOR" \
HELM_REGISTRY_PASSWORD="$GITHUB_TOKEN" \
scripts/release-helm-chart.sh --version 0.1.0 --push
```

Published chart reference:

```bash
oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike:0.1.0
```

Install from OCI:

```bash
helm install clawdstrike oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike --version 0.1.0
```

## Artifact Hub

Artifact Hub consumes the chart from the OCI repository. Use the following one-time setup:

1. Create an Artifact Hub Helm repository pointing to `oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike`.
2. Copy the repository ID from Artifact Hub settings.
3. Add `ARTIFACTHUB_REPOSITORY_ID` as a GitHub Actions secret in this repository.
4. Tag a release (`vX.Y.Z`) or run the Helm release workflow manually; the workflow will publish repository metadata (`artifacthub.io`) via ORAS.

## Confidence Pipeline

The Helm confidence pipeline is split into three layers:

1. **Fast gate (`Helm Chart CI`)** on chart/script changes:
  - lint + render + package
  - chart metadata inspection
  - packaged chart artifact upload
2. **Real cluster smoke (`Helm Cluster Smoke`)** for merge-candidate PRs:
  - build/push PR-scoped OCI chart to `oci://ghcr.io/backbay-labs/clawdstrike/helm-ci`
  - install from OCI only
  - run `helm test`, pod readiness checks, and health probes
  - publish diagnostics artifact bundle
3. **Nightly resilience/security (`Helm Nightly Resilience`)**:
  - restart + recovery checks
  - N-1 -> N upgrade safety
  - intentional bad upgrade + rollback validation
  - agent policy/OpenClaw Rust security tests
  - optional macOS OpenClaw smoke publishing separate results

### Local One-Command Smoke

```bash
scripts/helm-e2e-smoke.sh \
  --chart-ref oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike \
  --chart-version 0.1.2 \
  --namespace "clawdstrike-smoke-$(date +%s)" \
  --values infra/deploy/helm/clawdstrike/ci/cluster-smoke-values.yaml \
  --artifact-dir dist/helm-smoke/local
```

### All-On Preflight (Strict Gate)

```bash
scripts/helm-all-on-preflight.sh \
  --profile infra/deploy/helm/clawdstrike/profiles/all-on-dev-platform.yaml
```

### Baseline Release Verification Sequence

```bash
# 1) package and validate chart
scripts/release-helm-chart.sh 0.1.2

# 2) install from OCI tag
helm upgrade --install clawdstrike-smoke \
  oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike \
  --version 0.1.2 \
  -n clawdstrike-smoke \
  -f infra/deploy/helm/clawdstrike/ci/cluster-smoke-values.yaml \
  --wait --timeout 10m

# 3) run helm test
helm test clawdstrike-smoke -n clawdstrike-smoke --timeout 5m

# 4) verify pods
kubectl -n clawdstrike-smoke get pods

# 5) verify health endpoints
kubectl -n clawdstrike-smoke port-forward svc/clawdstrike-smoke-hushd 9876:9876 &
curl -fsS http://127.0.0.1:9876/health
kubectl -n clawdstrike-smoke port-forward svc/clawdstrike-smoke-proofs-api 8080:8080 &
curl -fsS http://127.0.0.1:8080/healthz
```

### Required CI Variables / Secrets

- `AWS_OIDC_ROLE_ARN` (secret): IAM role for GitHub OIDC -> EKS access
- `EKS_CLUSTER_NAME` (variable): target dev EKS cluster name
- `AWS_REGION` (variable, optional): defaults to `us-east-1`
- `ENABLE_MACOS_OPENCLAW_SMOKE` (variable, optional): set `true` to run optional macOS OpenClaw smoke job nightly

### Branch Protection

Enable `Helm Cluster Smoke` as a required status check after validating three consecutive successful runs.
