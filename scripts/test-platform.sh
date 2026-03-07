#!/usr/bin/env bash
set -euo pipefail

# Prefer Homebrew Node on macOS if available (avoids shim/toolchain mismatches).
if [[ -x "/opt/homebrew/bin/node" ]]; then
  export PATH="/opt/homebrew/bin:$PATH"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bold() { printf "\n=== %s ===\n" "$1"; }

ensure_node_modules() {
  local pkg="$1"
  if [[ ! -d "$pkg/node_modules" ]]; then
    echo "[test-platform] installing deps: $pkg"
    npm --prefix "$pkg" install
  fi
}

run_pkg() {
  local pkg="$1"
  ensure_node_modules "$pkg"
  (cd "$pkg" && npm test)
  (cd "$pkg" && npm run typecheck)
  (cd "$pkg" && npm run build)
}

bold "Path lint"
bash scripts/path-lint.sh

bold "Move validation"
bash scripts/move-validation.sh

bold "Architecture guardrails"
bash scripts/architecture-guardrails.sh

bold "Slop audit"
bash scripts/slop-audit.sh

bold "Rust workspace"
cargo test --workspace

bold "Rust Tauri crates"
cargo check --manifest-path apps/agent/src-tauri/Cargo.toml

bold "Build hush CLI (for TS e2e)"
cargo build -p hush-cli --bin hush

bold "TypeScript packages"
run_pkg packages/adapters/clawdstrike-adapter-core
run_pkg packages/policy/clawdstrike-policy
run_pkg packages/sdk/hush-ts
run_pkg packages/adapters/clawdstrike-hushd-engine
run_pkg packages/adapters/clawdstrike-langchain

ensure_node_modules packages/adapters/clawdstrike-hush-cli-engine
bold "TS e2e: hush-cli-engine (real hush binary)"
HUSH_E2E=1 HUSH_PATH="$REPO_ROOT/target/debug/hush" npm --prefix packages/adapters/clawdstrike-hush-cli-engine test
(cd packages/adapters/clawdstrike-hush-cli-engine && npm run typecheck)
(cd packages/adapters/clawdstrike-hush-cli-engine && npm run build)

run_pkg packages/adapters/clawdstrike-openai
run_pkg packages/adapters/clawdstrike-opencode
run_pkg packages/adapters/clawdstrike-claude
run_pkg packages/adapters/clawdstrike-vercel-ai
run_pkg packages/adapters/clawdstrike-openclaw

bold "TS e2e: openclaw plugin (in-process)"
npm --prefix packages/adapters/clawdstrike-openclaw run e2e

bold "Control console app"
ensure_node_modules apps/control-console
(cd apps/control-console && npm test)
(cd apps/control-console && npm run typecheck)
(cd apps/control-console && npm run build)

bold "Terminal TUI"
(cd apps/terminal && bun install --frozen-lockfile)
(cd apps/terminal && bun run typecheck)
(cd apps/terminal && bun test)
cargo test -p hush-cli tui::tests -- --nocapture

bold "Python package"
VENV_DIR="${VENV_DIR:-/tmp/hushpy-venv}"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install -U pip
fi
"$VENV_DIR/bin/python" -m pip install -e "packages/sdk/hush-py[dev]"
"$VENV_DIR/bin/python" -m pytest -q packages/sdk/hush-py

bold "Docs (mdbook)"
tools/scripts/validate-docs
mdbook build docs
mdbook test docs

bold "OK"
