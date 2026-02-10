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
