# Kubernetes Deployment (clawdstriked)

Minimal Kustomize manifests for running `clawdstriked` in Kubernetes.

This is a **reference deployment**, not an operator.

## Apply (example)

```bash
kubectl apply -k deploy/kubernetes/clawdstriked
kubectl -n clawdstriked-system get pods
kubectl -n clawdstriked-system port-forward svc/clawdstriked 9876:9876
curl http://127.0.0.1:9876/health
curl http://127.0.0.1:9876/metrics
```

## Secrets

Edit `deploy/kubernetes/clawdstriked/secret.yaml` before applying (demo values are placeholders).
