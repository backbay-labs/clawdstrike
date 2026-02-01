# Self-Hosted Runners

Deploy hushclaw daemon for self-hosted infrastructure.

## Overview

Run `hushd` daemon for centralized policy enforcement across multiple agents and runners.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Infrastructure                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Agent 1  │  │ Agent 2  │  │ Runner 1 │  │ Runner 2 │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │             │             │             │           │
│       └─────────────┴──────┬──────┴─────────────┘           │
│                            │                                 │
│                    ┌───────▼───────┐                         │
│                    │    hushd      │                         │
│                    │   (daemon)    │                         │
│                    └───────┬───────┘                         │
│                            │                                 │
│                    ┌───────▼───────┐                         │
│                    │    Policy     │                         │
│                    │    Store      │                         │
│                    └───────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

## Docker Deployment

### Quick Start

```bash
docker run -d \
  --name hushd \
  -p 9090:9090 \
  -v /etc/hush:/etc/hush:ro \
  -v /var/log/hush:/var/log/hush \
  ghcr.io/hushclaw/hushd:latest
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  hushd:
    image: ghcr.io/hushclaw/hushd:latest
    container_name: hushd
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./config:/etc/hush:ro
      - ./logs:/var/log/hush
      - ./receipts:/var/lib/hush/receipts
    environment:
      - HUSH_LOG_LEVEL=info
      - HUSH_LOG_FORMAT=json

  # Optional: Prometheus metrics
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    ports:
      - "9091:9090"
```

### Configuration

```yaml
# config/hushd.yaml
server:
  address: 0.0.0.0:9090
  tls:
    enabled: true
    cert: /etc/hush/certs/server.crt
    key: /etc/hush/certs/server.key

policy:
  path: /etc/hush/policy.yaml
  hot_reload: true
  watch_interval: 30s

logging:
  level: info
  format: json
  output: /var/log/hush/hushd.log
  rotate:
    max_size_mb: 100
    max_files: 10

receipts:
  enabled: true
  path: /var/lib/hush/receipts
  sign: true
  key_path: /etc/hush/keys/signing.key

metrics:
  enabled: true
  address: 0.0.0.0:9091
```

## Kubernetes Deployment

### Helm Chart

```bash
helm repo add hushclaw https://charts.hushclaw.dev
helm install hushd hushclaw/hushd -f values.yaml
```

### Custom Deployment

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hushd
spec:
  replicas: 2
  selector:
    matchLabels:
      app: hushd
  template:
    metadata:
      labels:
        app: hushd
    spec:
      containers:
        - name: hushd
          image: ghcr.io/hushclaw/hushd:latest
          ports:
            - containerPort: 9090
          volumeMounts:
            - name: config
              mountPath: /etc/hush
              readOnly: true
            - name: logs
              mountPath: /var/log/hush
          env:
            - name: HUSH_LOG_LEVEL
              value: info
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health
              port: 9090
            initialDelaySeconds: 5
          readinessProbe:
            httpGet:
              path: /ready
              port: 9090
      volumes:
        - name: config
          configMap:
            name: hushd-config
        - name: logs
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: hushd
spec:
  selector:
    app: hushd
  ports:
    - port: 9090
      targetPort: 9090
```

### ConfigMap

```yaml
# kubernetes/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hushd-config
data:
  hushd.yaml: |
    server:
      address: 0.0.0.0:9090
    policy:
      path: /etc/hush/policy.yaml
    logging:
      level: info
      format: json

  policy.yaml: |
    version: "hushclaw-v1.0"
    extends: hushclaw:strict
    egress:
      allowed_domains:
        - "api.anthropic.com"
        - "*.internal.company.com"
```

## Client Configuration

### CLI

```bash
# Point CLI to daemon
export HUSHD_ADDRESS=https://hushd.internal:9090

hush run --policy server:default -- command
```

### SDK

```typescript
import { HushClient } from '@hushclaw/sdk';

const client = new HushClient({
  address: 'https://hushd.internal:9090',
  tls: {
    ca: '/path/to/ca.crt',
  },
});

const decision = await client.evaluate(event);
```

## High Availability

### Load Balancing

```yaml
# haproxy.cfg
frontend hushd
    bind *:9090
    default_backend hushd_servers

backend hushd_servers
    balance roundrobin
    option httpchk GET /health
    server hushd1 hushd1.internal:9090 check
    server hushd2 hushd2.internal:9090 check
    server hushd3 hushd3.internal:9090 check
```

### Policy Sync

Use shared storage for consistent policies:

```yaml
# hushd.yaml
policy:
  path: /shared/policies/current.yaml
  watch_interval: 10s
```

## Monitoring

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'hushd'
    static_configs:
      - targets: ['hushd:9091']
```

Available metrics:

| Metric | Description |
|--------|-------------|
| `hushd_evaluations_total` | Total evaluations |
| `hushd_denials_total` | Total denials |
| `hushd_evaluation_duration_seconds` | Evaluation latency |
| `hushd_policy_reloads_total` | Policy reload count |

### Grafana Dashboard

Import dashboard ID: `12345` from Grafana.com.

### Alerting

```yaml
# alertmanager rules
groups:
  - name: hushd
    rules:
      - alert: HighDenialRate
        expr: rate(hushd_denials_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High denial rate detected"
```

## Security Hardening

### TLS

```yaml
server:
  tls:
    enabled: true
    cert: /etc/hush/certs/server.crt
    key: /etc/hush/certs/server.key
    client_ca: /etc/hush/certs/ca.crt
    require_client_cert: true
```

### API Keys

```yaml
auth:
  enabled: true
  api_keys:
    - name: agent-pool-1
      key: ${API_KEY_1}
      scopes: [evaluate]
    - name: admin
      key: ${ADMIN_API_KEY}
      scopes: [evaluate, policy, admin]
```

### Network Policies (Kubernetes)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: hushd-policy
spec:
  podSelector:
    matchLabels:
      app: hushd
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: ai-agent
      ports:
        - port: 9090
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
```

## Troubleshooting

### Check daemon status

```bash
hush daemon status
curl http://localhost:9090/health
```

### View logs

```bash
docker logs hushd
kubectl logs -l app=hushd
```

### Test connectivity

```bash
hush policy test event.json --server https://hushd:9090
```
