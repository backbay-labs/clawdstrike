# ClawdStrike Helm Chart

Production Helm chart for the ClawdStrike SDR (Swarm Detection & Response) stack.

## Components

| Component | Type | Default |
|-----------|------|---------|
| NATS JetStream | StatefulSet | enabled |
| spine-checkpointer | Deployment | enabled |
| spine-witness | Deployment | enabled |
| spine-proofs-api | Deployment | enabled |
| hushd | Deployment | enabled |
| tetragon-bridge | DaemonSet | disabled |
| hubble-bridge | DaemonSet | disabled |

## Quick Start

```bash
helm install clawdstrike ./deploy/helm/clawdstrike
```

## Configuration

### Global

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imagePullPolicy` | Image pull policy | `IfNotPresent` |
| `global.imagePullSecrets` | Image pull secrets | `[]` |
| `global.namespace` | Override namespace | `""` |
| `namespace.create` | Create namespace | `true` |
| `namespace.name` | Namespace name | `clawdstrike-system` |

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
| `bridges.tetragon.grpcEndpoint` | Tetragon gRPC address | `localhost:54321` |
| `bridges.hubble.enabled` | Deploy hubble-bridge | `false` |
| `bridges.hubble.grpcEndpoint` | Hubble gRPC address | `localhost:4245` |

### Security

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `podSecurityContext.runAsNonRoot` | Non-root enforcement | `true` |
| `podSecurityContext.runAsUser` | Container UID | `1000` |
| `securityContext.readOnlyRootFilesystem` | Read-only root FS | `true` |
| `networkPolicy.enabled` | Deploy NetworkPolicy | `false` |
| `serviceMonitor.enabled` | Deploy ServiceMonitor | `false` |
| `ingress.enabled` | Deploy Ingress | `false` |

## External NATS

To use an existing NATS cluster instead of deploying one:

```bash
helm install clawdstrike ./deploy/helm/clawdstrike \
  --set nats.enabled=false \
  --set nats.external.enabled=true \
  --set nats.external.url=nats://my-nats:4222
```

## Selective Installation

Deploy only specific components:

```bash
# Spine only
helm install clawdstrike ./deploy/helm/clawdstrike \
  --set hushd.enabled=false

# hushd only
helm install clawdstrike ./deploy/helm/clawdstrike \
  --set spine.enabled=false

# With bridges
helm install clawdstrike ./deploy/helm/clawdstrike \
  --set bridges.tetragon.enabled=true \
  --set bridges.hubble.enabled=true
```

## Testing

```bash
# Lint
helm lint deploy/helm/clawdstrike

# Template rendering
helm template test deploy/helm/clawdstrike

# Install and test
helm install cs deploy/helm/clawdstrike --wait
helm test cs
```
