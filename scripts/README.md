# Scripts

Operator-facing repository scripts.

Conventions:

1. Prefer stable entrypoints here for CI/release/local orchestration.
2. Put reusable helper logic under `tools/scripts/` when it is developer-tooling specific.
3. Keep scripts idempotent and explicit about required environment variables.

Current policy/structure guardrails:

1. `scripts/path-lint.sh` - stale legacy path reference detection.
2. `scripts/move-validation.sh` - verifies moved legacy paths are no longer tracked.
3. `scripts/architecture-guardrails.sh` - verifies domain README/ownership/repo-map consistency.
4. `scripts/cleanup-legacy-paths.sh` - removes stale legacy directories from local checkouts.
5. `scripts/openclaw-agent-smoke.sh` - validates agent-owned OpenClaw flows (`health -> policy bypass toggle -> gateway connect -> request relay -> optional reconnect`).
6. `scripts/release-helm-chart.sh` - lints/templates/packages the ClawdStrike Helm chart and optionally pushes it to an OCI registry.
7. `scripts/helm-e2e-smoke.sh` - OCI install smoke check (`helm upgrade --install`, `helm test`, service health probes, diagnostics bundle).
8. `scripts/helm-resilience-security.sh` - nightly-style restart/recovery + upgrade/rollback + security checks with machine-readable summary.
9. `scripts/helm-all-on-preflight.sh` - strict preflight gate for all-on profile rollout (bridge image availability, cluster prerequisites, and render checks).
10. `scripts/openclaw-plugin-install-link-smoke.sh` - validates clean-room `plugins install --link` + `plugins enable` flow against the package entry path and emits `summary.json`.
11. `scripts/openclaw-plugin-runtime-smoke.sh` - validates OpenClaw plugin runtime loading and expected hook registrations from `plugins info ... --json`, emitting `summary.json`.
12. `scripts/openclaw-plugin-blocked-call-e2e.sh` - validates end-to-end runtime blocking for a destructive `bash` call (no target file creation), emitting `summary.json`.
13. `scripts/adaptive-openclaw-spine-e2e.sh` - combined smoke that validates OpenClaw blocked-call interception plus control-api signed Spine approval envelope emission, emitting `summary.json`.
14. `scripts/huntronomer-playwright-smoke.sh` - Huntronomer desktop shell smoke via Playwright CLI (`launch overlay -> dismiss -> Hunt Deck artifacts`), emitting `summary.json`.
