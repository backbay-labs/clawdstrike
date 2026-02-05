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

bold "Rust workspace"
cargo test --workspace

bold "Rust Tauri crates"
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
cargo check --manifest-path apps/agent/src-tauri/Cargo.toml

bold "Build hush CLI (for TS e2e)"
cargo build -p hush-cli --bin hush

bold "TypeScript packages"
run_pkg packages/clawdstrike-adapter-core
run_pkg packages/clawdstrike-policy
run_pkg packages/hush-ts
run_pkg packages/clawdstrike-hushd-engine
run_pkg packages/clawdstrike-langchain

ensure_node_modules packages/clawdstrike-hush-cli-engine
bold "TS e2e: hush-cli-engine (real hush binary)"
HUSH_E2E=1 HUSH_PATH="$REPO_ROOT/target/debug/hush" npm --prefix packages/clawdstrike-hush-cli-engine test
(cd packages/clawdstrike-hush-cli-engine && npm run typecheck)
(cd packages/clawdstrike-hush-cli-engine && npm run build)

run_pkg packages/clawdstrike-codex
run_pkg packages/clawdstrike-opencode
run_pkg packages/clawdstrike-claude-code
run_pkg packages/clawdstrike-vercel-ai
run_pkg packages/clawdstrike-openclaw

bold "TS e2e: openclaw plugin (in-process)"
npm --prefix packages/clawdstrike-openclaw run e2e

bold "Python package"
VENV_DIR="${VENV_DIR:-/tmp/hushpy-venv}"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install -U pip
fi
"$VENV_DIR/bin/python" -m pip install -e "packages/hush-py[dev]"
"$VENV_DIR/bin/python" -m pytest -q packages/hush-py

bold "Docs (mdbook)"
mdbook build docs
mdbook test docs

bold "OK"
