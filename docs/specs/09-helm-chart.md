# Spec 09: Helm Chart for Full SDR Stack

> **Status:** Draft | **Date:** 2026-02-07
> **Author:** Phase C Spec Agent
> **Effort estimate:** 8-10 engineer-days
> **Dependencies:** Docker images (already built via `.github/workflows/docker.yml`), spine crate binaries, bridge binaries, hushd binary

---

## Summary / Objective

Create a production-grade Helm chart at `deploy/helm/clawdstrike/` that deploys the full SDR stack: NATS JetStream cluster, three Spine services (checkpointer, witness, proofs-api), two bridge DaemonSets (tetragon-bridge, hubble-bridge), and the hushd enforcement daemon. The chart must support single-command installation (`helm install clawdstrike ./deploy/helm/clawdstrike`) and be publishable as an OCI artifact to GitHub Container Registry.

---

## Current State

### What exists today

**Docker images** are already built and pushed to GHCR via `.github/workflows/docker.yml`:
- `ghcr.io/backbay-labs/clawdstrike/spine:{spine-checkpointer,spine-witness,spine-proofs-api}-{latest,$SHA}`
- `ghcr.io/backbay-labs/clawdstrike/tetragon-bridge:{latest,$SHA}`
- `ghcr.io/backbay-labs/clawdstrike/hubble-bridge:{latest,$SHA}`

Three Dockerfiles exist:
- `docker/Dockerfile.spine` -- multi-binary image for all three spine services
- `docker/Dockerfile.tetragon-bridge` -- tetragon-bridge binary
- `docker/Dockerfile.hubble-bridge` -- hubble-bridge binary

**Kubernetes manifests** exist for hushd and clawdstriked:
- `deploy/kubernetes/hushd/` -- Kustomize-based: Deployment, Service, ConfigMap, Secret, PVC, Namespace
- `deploy/kubernetes/clawdstriked/` -- Kustomize-based deployment manifests for the clawdstriked enforcement daemon

**Docker Compose** exists for local development:
- `docker/docker-compose.services.yaml` -- NATS + 3 Spine services + 2 bridges (profiles)

**What is missing:**
- No Helm chart at all
- No hushd Docker image in GHCR (only `clawdstrike/hushd:dev` referenced in `deploy/kubernetes/hushd/deployment.yaml`)
- No Kubernetes manifests for Spine services or bridges
- No NATS deployment config for Kubernetes (currently uses the NATS Helm chart separately in the `aegisnet` namespace)
- No `values.yaml` for environment-specific configuration
- No chart testing or linting CI

### Referenced architecture

From `docs/research/open-source-strategy.md` (section 2.1):
> ```
> deploy/                      #   Kubernetes deployment manifests
> ├── helm/                    #   Helm chart for hushd + spine + bridges
> ├── argocd/                  #   ArgoCD Application resources
> └── tetragon-policies/       #   TracingPolicy CRDs
> ```

From `docs/research/architecture-vision.md` (section 2.2), deployed AegisNet services run in the `aegisnet` namespace on NATS JetStream (3-replica cluster, 50Gi/node). The Spine services are the open-source equivalents being consolidated from AegisNet.

From `docs/research/open-source-strategy.md` (section 4.6):
> - Helm chart: Published to OCI registry (GitHub Container Registry)

---

## Target State

A Helm chart at `deploy/helm/clawdstrike/` that:

1. Deploys all SDR components in a single `helm install` command
2. Is configurable via `values.yaml` for different environments (dev, staging, production)
3. Supports selective component installation (e.g., Spine only, hushd only, bridges only)
4. Follows Helm best practices (labels, annotations, NOTES.txt, `_helpers.tpl`)
5. Publishes to GHCR as an OCI artifact for `helm install oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike`
6. Passes `helm lint` and `helm template` validation in CI
7. Includes a `ct` (chart-testing) configuration for automated testing

---

## Implementation Plan

### Step 1: Chart scaffolding

Create the Helm chart directory structure:

```
deploy/helm/clawdstrike/
├── Chart.yaml
├── values.yaml
├── .helmignore
├── templates/
│   ├── _helpers.tpl
│   ├── NOTES.txt
│   ├── namespace.yaml
│   │
│   ├── nats/
│   │   ├── statefulset.yaml
│   │   ├── service.yaml
│   │   ├── configmap.yaml
│   │   └── pvc.yaml
│   │
│   ├── spine/
│   │   ├── checkpointer-deployment.yaml
│   │   ├── witness-deployment.yaml
│   │   ├── proofs-api-deployment.yaml
│   │   ├── proofs-api-service.yaml
│   │   └── spine-configmap.yaml
│   │
│   ├── hushd/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   ├── configmap.yaml
│   │   ├── secret.yaml
│   │   └── pvc.yaml
│   │
│   ├── bridges/
│   │   ├── tetragon-bridge-daemonset.yaml
│   │   └── hubble-bridge-daemonset.yaml
│   │
│   ├── rbac/
│   │   ├── serviceaccount.yaml
│   │   ├── role.yaml
│   │   └── rolebinding.yaml
│   │
│   └── tests/
│       └── test-connection.yaml
│
├── ci/
│   └── test-values.yaml
└── README.md
```

### Step 2: Chart.yaml

```yaml
apiVersion: v2
name: clawdstrike
description: Helm chart for ClawdStrike SDR (Swarm Detection & Response) stack
type: application
version: 0.1.0
appVersion: "0.1.0"
home: https://github.com/backbay-labs/clawdstrike
sources:
  - https://github.com/backbay-labs/clawdstrike
maintainers:
  - name: Backbay Labs
    url: https://github.com/backbay-labs
keywords:
  - security
  - ai-agent
  - sdr
  - clawdstrike
  - runtime-enforcement
dependencies:
  - name: nats
    version: "1.2.x"
    repository: "https://nats-io.github.io/k8s/helm/charts/"
    condition: nats.enabled
    alias: nats-upstream
```

**Note on NATS:** The chart supports two modes:
- **Bundled NATS** (default for development): Deploys NATS as a subchart dependency
- **External NATS** (production): Connects to an existing NATS cluster via `nats.external.url`

For the initial implementation, use a simple StatefulSet template (not the NATS subchart) to keep the chart self-contained and avoid version coupling. The subchart dependency can be added later if desired.

### Step 3: values.yaml

```yaml
# -- Global settings
global:
  # -- Image pull policy
  imagePullPolicy: IfNotPresent
  # -- Image pull secrets
  imagePullSecrets: []
  # -- Override namespace (defaults to Release.Namespace)
  namespace: ""

# -- Namespace creation
namespace:
  create: true
  name: "clawdstrike-system"

# ---------------------------------------------------------------------------
# NATS JetStream
# ---------------------------------------------------------------------------
nats:
  # -- Enable bundled NATS deployment
  enabled: true
  # -- Use an external NATS cluster instead of deploying one
  external:
    enabled: false
    url: ""
  image:
    repository: nats
    tag: "2.10-alpine"
  replicas: 1
  jetstream:
    enabled: true
    storage:
      size: 10Gi
      storageClassName: ""
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: "1"
      memory: 1Gi
  monitoring:
    enabled: true
    port: 8222

# ---------------------------------------------------------------------------
# Spine services (checkpointer, witness, proofs-api)
# ---------------------------------------------------------------------------
spine:
  enabled: true
  image:
    repository: ghcr.io/backbay-labs/clawdstrike/spine
    # -- Overrides appVersion for spine images
    tag: ""
  env:
    RUST_LOG: "info,spine=debug"

  checkpointer:
    enabled: true
    replicas: 1
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 500m
        memory: 256Mi

  witness:
    enabled: true
    replicas: 1
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 250m
        memory: 128Mi

  proofsApi:
    enabled: true
    replicas: 1
    port: 8080
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 500m
        memory: 256Mi
    service:
      type: ClusterIP
      port: 8080

# ---------------------------------------------------------------------------
# hushd (enforcement daemon)
# ---------------------------------------------------------------------------
hushd:
  enabled: true
  image:
    repository: ghcr.io/backbay-labs/clawdstrike/hushd
    tag: ""
  replicas: 1
  port: 9876
  config:
    ruleset: "default"
    logLevel: "info"
  auth:
    enabled: true
    # -- Name of existing Secret containing CLAWDSTRIKE_API_KEY and CLAWDSTRIKE_ADMIN_KEY
    existingSecret: ""
    # -- API key (only used if existingSecret is empty; stored in auto-generated Secret)
    apiKey: ""
    adminKey: ""
  persistence:
    enabled: true
    size: 1Gi
    storageClassName: ""
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 500m
      memory: 256Mi
  service:
    type: ClusterIP
    port: 9876

# ---------------------------------------------------------------------------
# Bridge DaemonSets
# ---------------------------------------------------------------------------
bridges:
  tetragon:
    enabled: false
    image:
      repository: ghcr.io/backbay-labs/clawdstrike/tetragon-bridge
      tag: ""
    grpcEndpoint: "localhost:54321"
    env:
      RUST_LOG: "info,tetragon_bridge=debug"
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 250m
        memory: 256Mi
    # -- Node selector for bridge DaemonSet
    nodeSelector: {}
    tolerations: []

  hubble:
    enabled: false
    image:
      repository: ghcr.io/backbay-labs/clawdstrike/hubble-bridge
      tag: ""
    grpcEndpoint: "localhost:4245"
    env:
      RUST_LOG: "info,hubble_bridge=debug"
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 250m
        memory: 256Mi
    nodeSelector: {}
    tolerations: []

# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------
serviceAccount:
  create: true
  name: ""
  annotations: {}

# ---------------------------------------------------------------------------
# Pod-level settings (applied to all components unless overridden)
# ---------------------------------------------------------------------------
podAnnotations: {}
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
```

### Step 4: Template helpers (`_helpers.tpl`)

Define standard helpers:

```
{{- define "clawdstrike.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "clawdstrike.fullname" -}}
{{- ... standard fullname logic ... }}
{{- end }}

{{- define "clawdstrike.namespace" -}}
{{- default .Release.Namespace .Values.global.namespace }}
{{- end }}

{{- define "clawdstrike.labels" -}}
helm.sh/chart: {{ include "clawdstrike.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: clawdstrike
{{- end }}

{{- define "clawdstrike.selectorLabels" -}}
app.kubernetes.io/name: {{ include "clawdstrike.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "clawdstrike.natsUrl" -}}
{{- if .Values.nats.external.enabled }}
{{- .Values.nats.external.url }}
{{- else }}
nats://{{ include "clawdstrike.fullname" . }}-nats:4222
{{- end }}
{{- end }}

{{- define "clawdstrike.spineImageTag" -}}
{{- default (printf "%s-%s" .component .Chart.AppVersion) .tag }}
{{- end }}
```

### Step 5: NATS StatefulSet template

Deploy a single-node NATS with JetStream by default. The template is gated on `.Values.nats.enabled && !.Values.nats.external.enabled`.

Key configuration:
- JetStream store directory mounted as PVC
- Monitoring port exposed for health checks and Prometheus scraping
- Liveness/readiness probes against `/healthz`
- ConfigMap with `nats.conf` enabling JetStream

### Step 6: Spine Deployment templates

Three separate Deployments sharing the same image but selecting the binary via the `SPINE_BIN` environment variable (matching `docker/entrypoint-spine.sh`):

- `spine-checkpointer`: `SPINE_BIN=spine-checkpointer`, `NATS_URL={{ include "clawdstrike.natsUrl" . }}`
- `spine-witness`: `SPINE_BIN=spine-witness`, `NATS_URL=...`
- `spine-proofs-api`: `SPINE_BIN=spine-proofs-api`, `NATS_URL=...`, plus a Service for HTTP access

Each Deployment uses:
- Image tag: `{{ .Values.spine.image.tag | default (printf "spine-%s-%s" $component .Chart.AppVersion) }}`
- `readOnlyRootFilesystem: true`, non-root user
- Health checks (proofs-api has HTTP `/healthz`, checkpointer/witness use exec-based NATS connectivity check)

### Step 7: hushd Deployment template

Migrates the existing `deploy/kubernetes/hushd/` Kustomize manifests into Helm templates:

- Deployment with ConfigMap-mounted `config.yaml`
- Secret for API keys (auto-generated or existing)
- PVC for audit database
- Service on port 9876
- Health probes on `/health` (matching existing `deploy/kubernetes/hushd/deployment.yaml`)

Config is rendered from values:
```yaml
listen: "0.0.0.0:{{ .Values.hushd.port }}"
ruleset: "{{ .Values.hushd.config.ruleset }}"
audit_db: "/var/lib/hushd/audit.db"
log_level: "{{ .Values.hushd.config.logLevel }}"
nats_url: "{{ include "clawdstrike.natsUrl" . }}"
```

### Step 8: Bridge DaemonSet templates

DaemonSets for tetragon-bridge and hubble-bridge, disabled by default (`bridges.tetragon.enabled: false`, `bridges.hubble.enabled: false`) since they require Tetragon/Cilium to be deployed separately.

Key settings:
- `hostNetwork: false` (bridges connect to Tetragon/Hubble via localhost gRPC within the same pod or via service endpoints)
- `NATS_URL` from helper
- `TETRAGON_GRPC` / `HUBBLE_GRPC` from values
- Node selector and tolerations for DaemonSet targeting

### Step 9: RBAC templates

- ServiceAccount per component (or shared, configurable)
- Role with minimal permissions (read Secrets for signing keys, read ConfigMaps)
- RoleBinding

### Step 10: NOTES.txt

Post-install instructions:

```
ClawdStrike SDR stack deployed to namespace {{ include "clawdstrike.namespace" . }}.

Components:
{{- if .Values.nats.enabled }}
  NATS JetStream: {{ include "clawdstrike.fullname" . }}-nats:4222
{{- end }}
{{- if .Values.spine.enabled }}
  Spine Checkpointer: running
  Spine Witness: running
  Spine Proofs API: {{ include "clawdstrike.fullname" . }}-proofs-api:{{ .Values.spine.proofsApi.port }}
{{- end }}
{{- if .Values.hushd.enabled }}
  hushd: {{ include "clawdstrike.fullname" . }}-hushd:{{ .Values.hushd.port }}
{{- end }}

To verify:
  kubectl -n {{ include "clawdstrike.namespace" . }} get pods
  kubectl -n {{ include "clawdstrike.namespace" . }} port-forward svc/{{ include "clawdstrike.fullname" . }}-hushd {{ .Values.hushd.port }}:{{ .Values.hushd.port }}
  curl http://localhost:{{ .Values.hushd.port }}/health
```

### Step 11: Test connection template

`templates/tests/test-connection.yaml` -- a Helm test pod that verifies NATS connectivity, proofs-api health, and hushd health after installation.

### Step 12: CI values for chart testing

`ci/test-values.yaml` with minimal config for CI (1 replica, small resources, no persistence):

```yaml
nats:
  jetstream:
    storage:
      size: 1Gi
hushd:
  persistence:
    enabled: false
  auth:
    enabled: false
spine:
  checkpointer:
    resources:
      requests:
        cpu: 10m
        memory: 32Mi
      limits:
        cpu: 100m
        memory: 128Mi
```

### Step 13: hushd Dockerfile

Add `docker/Dockerfile.hushd` (currently missing) and add it to the docker CI workflow. This is a prerequisite for the Helm chart to reference a real image.

```dockerfile
FROM rust:1.93-bookworm AS builder
WORKDIR /build
COPY docker/workspace-hushd.toml Cargo.toml
COPY Cargo.lock ./
COPY crates/hush-core crates/hush-core
COPY crates/clawdstrike crates/clawdstrike
COPY crates/hushd crates/hushd
COPY rulesets rulesets
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin hushd && \
    cp /build/target/release/hushd /usr/local/bin/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 tini && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 1000 hushd && useradd -u 1000 -g hushd -d /var/lib/hushd -m hushd
COPY --from=builder /usr/local/bin/hushd /usr/local/bin/
COPY rulesets /etc/clawdstrike/rulesets
USER hushd
WORKDIR /var/lib/hushd
ENTRYPOINT ["/usr/bin/tini", "--", "hushd"]
```

### Step 14: Helm chart CI workflow

Add a new job to `.github/workflows/ci.yml` or create `.github/workflows/helm.yml`:

```yaml
name: Helm Chart Lint & Test
on:
  push:
    paths:
      - "deploy/helm/**"
      - ".github/workflows/helm.yml"
  pull_request:
    paths:
      - "deploy/helm/**"
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: azure/setup-helm@v4
      - run: helm lint deploy/helm/clawdstrike
      - run: helm template test-release deploy/helm/clawdstrike -f deploy/helm/clawdstrike/ci/test-values.yaml
```

### Step 15: OCI publish workflow

Add to `.github/workflows/release.yml` (or create separate workflow):

```yaml
helm-publish:
  runs-on: ubuntu-latest
  if: startsWith(github.ref, 'refs/tags/v')
  steps:
    - uses: actions/checkout@v6
    - uses: azure/setup-helm@v4
    - name: Login to GHCR
      run: echo "${{ secrets.GITHUB_TOKEN }}" | helm registry login ghcr.io -u ${{ github.actor }} --password-stdin
    - name: Package chart
      run: helm package deploy/helm/clawdstrike --version ${{ github.ref_name }}
    - name: Push to GHCR
      run: helm push clawdstrike-*.tgz oci://ghcr.io/backbay-labs/clawdstrike/helm
```

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `deploy/helm/clawdstrike/Chart.yaml` | Create | Chart metadata |
| `deploy/helm/clawdstrike/values.yaml` | Create | Default values |
| `deploy/helm/clawdstrike/.helmignore` | Create | Ignore patterns |
| `deploy/helm/clawdstrike/README.md` | Create | Chart documentation |
| `deploy/helm/clawdstrike/templates/_helpers.tpl` | Create | Template helpers |
| `deploy/helm/clawdstrike/templates/NOTES.txt` | Create | Post-install notes |
| `deploy/helm/clawdstrike/templates/namespace.yaml` | Create | Namespace resource |
| `deploy/helm/clawdstrike/templates/nats/statefulset.yaml` | Create | NATS StatefulSet |
| `deploy/helm/clawdstrike/templates/nats/service.yaml` | Create | NATS Service |
| `deploy/helm/clawdstrike/templates/nats/configmap.yaml` | Create | NATS config |
| `deploy/helm/clawdstrike/templates/spine/checkpointer-deployment.yaml` | Create | Checkpointer Deployment |
| `deploy/helm/clawdstrike/templates/spine/witness-deployment.yaml` | Create | Witness Deployment |
| `deploy/helm/clawdstrike/templates/spine/proofs-api-deployment.yaml` | Create | Proofs API Deployment |
| `deploy/helm/clawdstrike/templates/spine/proofs-api-service.yaml` | Create | Proofs API Service |
| `deploy/helm/clawdstrike/templates/spine/spine-configmap.yaml` | Create | Spine env config |
| `deploy/helm/clawdstrike/templates/hushd/deployment.yaml` | Create | hushd Deployment |
| `deploy/helm/clawdstrike/templates/hushd/service.yaml` | Create | hushd Service |
| `deploy/helm/clawdstrike/templates/hushd/configmap.yaml` | Create | hushd config |
| `deploy/helm/clawdstrike/templates/hushd/secret.yaml` | Create | hushd auth secrets |
| `deploy/helm/clawdstrike/templates/hushd/pvc.yaml` | Create | hushd PVC |
| `deploy/helm/clawdstrike/templates/bridges/tetragon-bridge-daemonset.yaml` | Create | Tetragon bridge DaemonSet |
| `deploy/helm/clawdstrike/templates/bridges/hubble-bridge-daemonset.yaml` | Create | Hubble bridge DaemonSet |
| `deploy/helm/clawdstrike/templates/rbac/serviceaccount.yaml` | Create | ServiceAccount |
| `deploy/helm/clawdstrike/templates/rbac/role.yaml` | Create | Role |
| `deploy/helm/clawdstrike/templates/rbac/rolebinding.yaml` | Create | RoleBinding |
| `deploy/helm/clawdstrike/templates/tests/test-connection.yaml` | Create | Helm test pod |
| `deploy/helm/clawdstrike/ci/test-values.yaml` | Create | CI test values |
| `docker/Dockerfile.hushd` | Create | hushd Docker image |
| `docker/workspace-hushd.toml` | Create | Minimal Cargo workspace for hushd build |
| `.github/workflows/docker.yml` | Modify | Add hushd image build job |
| `.github/workflows/helm.yml` | Create | Helm lint/test CI |
| `.github/workflows/release.yml` | Modify | Add OCI publish step |

---

## Testing Strategy

### Unit tests (chart linting)

```bash
# Lint the chart
helm lint deploy/helm/clawdstrike

# Template rendering (all components)
helm template test deploy/helm/clawdstrike --debug

# Template rendering (spine only)
helm template test deploy/helm/clawdstrike --set hushd.enabled=false --set bridges.tetragon.enabled=false

# Template rendering with external NATS
helm template test deploy/helm/clawdstrike --set nats.enabled=false --set nats.external.enabled=true --set nats.external.url=nats://my-nats:4222
```

### Integration tests (local cluster)

```bash
# Create a kind/k3d cluster
kind create cluster --name clawdstrike-test

# Install the chart
helm install cs deploy/helm/clawdstrike -f deploy/helm/clawdstrike/ci/test-values.yaml --wait --timeout 120s

# Run Helm tests
helm test cs

# Verify pods are running
kubectl -n clawdstrike-system get pods

# Port-forward and test proofs-api health
kubectl -n clawdstrike-system port-forward svc/cs-clawdstrike-proofs-api 8080:8080
curl http://localhost:8080/healthz

# Port-forward and test hushd health
kubectl -n clawdstrike-system port-forward svc/cs-clawdstrike-hushd 9876:9876
curl http://localhost:9876/health

# Clean up
helm uninstall cs
kind delete cluster --name clawdstrike-test
```

### CI validation

The `.github/workflows/helm.yml` workflow runs:
1. `helm lint` on every PR touching `deploy/helm/`
2. `helm template` with test values to catch rendering errors
3. (Future) `ct install` with kind for full integration testing

### Smoke test: docker-compose parity

Verify that `helm template` output produces equivalent resources to the existing `docker/docker-compose.services.yaml` topology (same ports, same env vars, same image references).

---

## Rollback Plan

1. **Helm built-in rollback**: `helm rollback clawdstrike <revision>` restores previous state
2. **Full uninstall**: `helm uninstall clawdstrike -n clawdstrike-system` removes all resources
3. **Namespace cleanup**: If namespace was created by the chart, `kubectl delete ns clawdstrike-system`
4. **Fallback to Kustomize**: The existing `deploy/kubernetes/hushd/` Kustomize manifests remain functional and can be used independently: `kubectl apply -k deploy/kubernetes/hushd/`
5. **PVC retention**: PVCs use `Retain` reclaim policy by default; data is preserved across uninstall/reinstall

---

## Dependencies

| Dependency | Type | Notes |
|------------|------|-------|
| Docker images in GHCR | Build artifact | Already built for spine and bridges; hushd image needs to be added |
| NATS 2.10+ | Runtime | Bundled in chart or external |
| Tetragon (optional) | Runtime | Required only if `bridges.tetragon.enabled=true` |
| Cilium/Hubble (optional) | Runtime | Required only if `bridges.hubble.enabled=true` |
| Spec 01 (TracingPolicy CRDs) | Soft | Bridge DaemonSets work without TracingPolicies but produce no events |
| Spec 02 (CiliumNetworkPolicies) | Soft | Hubble bridge works without Cilium policies but has no flows to observe |

---

## Acceptance Criteria

- [ ] `helm lint deploy/helm/clawdstrike` passes without errors
- [ ] `helm template test deploy/helm/clawdstrike` renders valid YAML for all components
- [ ] `helm template test deploy/helm/clawdstrike --set spine.enabled=false` correctly omits Spine resources
- [ ] `helm template test deploy/helm/clawdstrike --set hushd.enabled=false` correctly omits hushd resources
- [ ] `helm template test deploy/helm/clawdstrike --set bridges.tetragon.enabled=true` includes tetragon-bridge DaemonSet
- [ ] `helm template test deploy/helm/clawdstrike --set nats.external.enabled=true --set nats.external.url=nats://ext:4222` omits NATS StatefulSet and uses external URL
- [ ] `helm install` on a kind cluster starts all pods in Running state within 60 seconds
- [ ] `helm test` passes (NATS connectivity, proofs-api healthz, hushd health)
- [ ] hushd ConfigMap matches the config structure from `deploy/kubernetes/hushd/configmap.yaml`
- [ ] All pods run as non-root (UID 1000) with read-only root filesystem
- [ ] `docker/Dockerfile.hushd` builds successfully and is added to `.github/workflows/docker.yml`
- [ ] `.github/workflows/helm.yml` runs `helm lint` and `helm template` on PRs
- [ ] Chart version in `Chart.yaml` matches workspace version `0.1.0`
- [ ] NOTES.txt displays correct post-install instructions
- [ ] Values documentation in `deploy/helm/clawdstrike/README.md` covers all configurable fields
