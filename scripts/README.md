# Scripts

Operator-facing repository scripts.

Conventions:

1. Prefer stable entrypoints here for CI/release/local orchestration.
2. Put reusable helper logic under `tools/scripts/` when it is developer-tooling specific.
3. Keep scripts idempotent and explicit about required environment variables.
