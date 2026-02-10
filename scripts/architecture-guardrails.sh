#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DOMAINS=(
  "apps"
  "crates"
  "packages"
  "integrations"
  "infra"
  "docs"
  "examples"
  "fixtures"
  "rulesets"
  "scripts"
  "tools"
  "fuzz"
)

fail=0

for domain in "${DOMAINS[@]}"; do
  if [[ ! -d "$domain" ]]; then
    echo "[architecture-guardrails] missing top-level domain directory: $domain/"
    fail=1
    continue
  fi

  if [[ ! -f "$domain/README.md" ]]; then
    echo "[architecture-guardrails] missing domain README: $domain/README.md"
    fail=1
  fi

  if ! rg --fixed-strings --quiet "| \`$domain/\` |" docs/REPO_MAP.md; then
    echo "[architecture-guardrails] docs/REPO_MAP.md missing top-level entry for: $domain/"
    fail=1
  fi

  if ! rg --quiet "^/$domain/\\*\\*\\s+@" .github/CODEOWNERS; then
    echo "[architecture-guardrails] .github/CODEOWNERS missing ownership for: /$domain/**"
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "[architecture-guardrails] FAIL"
  exit 1
fi

echo "[architecture-guardrails] OK"
