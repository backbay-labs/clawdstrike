#!/usr/bin/env bash
# Validate every example policy under examples/**/*.yaml against the canonical
# Rust engine. Fails the build if any policy cannot be loaded.
#
# Skips files that are intentionally not Rust-engine policies (e.g. compose
# files, generic config). Detection is by content: a policy must have either a
# top-level `version:` line that matches a supported schema, or a top-level
# `hushspec:` line (HushSpec format that the engine accepts and compiles).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found; install Rust to run validation" >&2
  exit 1
fi

# Build the CLI once up-front so each validate call is fast.
cargo build -q -p hush-cli --bin hush 2>&1

HUSH_BIN="$REPO_ROOT/target/debug/hush"
if [[ ! -x "$HUSH_BIN" ]]; then
  echo "expected $HUSH_BIN after cargo build" >&2
  exit 1
fi

failures=0
checked=0
skipped=0

while IFS= read -r -d '' file; do
  # Skip well-known non-policy YAML shapes inside examples/.
  case "$file" in
    */docker-compose.yml|*/docker-compose.yaml)
      skipped=$((skipped + 1))
      continue ;;
    */config.yaml|*/config.yml)
      # Many examples ship a hushd/agent config alongside the policy; only
      # validate files that look like policies.
      skipped=$((skipped + 1))
      continue ;;
  esac

  if ! grep -qE '^(version|hushspec):' "$file"; then
    skipped=$((skipped + 1))
    continue
  fi

  checked=$((checked + 1))
  if "$HUSH_BIN" policy validate "$file" >/dev/null 2>&1; then
    printf '  ok   %s\n' "$file"
  else
    printf '  FAIL %s\n' "$file"
    "$HUSH_BIN" policy validate "$file" 2>&1 | sed 's/^/      /' || true
    failures=$((failures + 1)) || true
  fi
done < <(find examples -type f \( -name '*.yaml' -o -name '*.yml' \) -print0)

echo
printf 'validated %d, skipped %d, failed %d\n' "$checked" "$skipped" "$failures"

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi
