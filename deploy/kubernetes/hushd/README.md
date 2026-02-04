# Kubernetes Deployment (hushd)

Minimal Kustomize manifests for running `hushd` in Kubernetes.

This is a **reference deployment**, not an operator.

## Apply (example)

```bash
kubectl apply -k deploy/kubernetes/hushd
kubectl -n hushd-system get pods
kubectl -n hushd-system port-forward svc/hushd 9876:9876
curl http://127.0.0.1:9876/health
curl http://127.0.0.1:9876/metrics
```

## Secrets

Edit `deploy/kubernetes/hushd/secret.yaml` before applying (demo values are placeholders).
