#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.1.0"
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must be strict semver: X.Y.Z (no prerelease/build metadata)"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

python3 - "$VERSION" <<'PY'
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    raise SystemExit("python>=3.11 is required for tomllib")

import tomllib  # noqa: E402

expected = sys.argv[1]
repo_root = Path(os.environ["REPO_ROOT"])


def fail(msg: str) -> None:
    print(msg)
    raise SystemExit(1)


def read_toml(rel: str) -> dict:
    path = repo_root / rel
    return tomllib.loads(path.read_text(encoding="utf-8"))


def read_json(rel: str) -> dict:
    path = repo_root / rel
    return json.loads(path.read_text(encoding="utf-8"))


def check(label: str, actual: str | None) -> str | None:
    if actual is None:
        return f"{label}: missing version"
    if actual != expected:
        return f"{label}: expected {expected}, found {actual}"
    return None


errors: list[str] = []

cargo = read_toml("Cargo.toml")
workspace_version = cargo.get("workspace", {}).get("package", {}).get("version")
errors.append(check("Cargo.toml [workspace.package].version", workspace_version))

pyproject = read_toml("packages/sdk/hush-py/pyproject.toml")
py_version = pyproject.get("project", {}).get("version")
errors.append(check("packages/sdk/hush-py/pyproject.toml [project].version", py_version))

py_init_rel = None
for rel in ("packages/sdk/hush-py/src/clawdstrike/__init__.py", "packages/sdk/hush-py/src/hush/__init__.py"):
    if (repo_root / rel).exists():
        py_init_rel = rel
        break

if py_init_rel is None:
    errors.append("packages/sdk/hush-py __version__: missing __init__.py")
else:
    py_init = (repo_root / py_init_rel).read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', py_init, flags=re.M)
    errors.append(check(f"{py_init_rel} __version__", match.group(1) if match else None))

for pkg in [
    "packages/sdk/hush-ts/package.json",
    "packages/adapters/clawdstrike-openclaw/package.json",
    "crates/libs/hush-wasm/package.json",
]:
    errors.append(check(pkg, read_json(pkg).get("version")))

formula_rel = "infra/packaging/HomebrewFormula/hush.rb"
if not (repo_root / formula_rel).exists():
    errors.append("Homebrew formula path: expected infra/packaging/HomebrewFormula/hush.rb")
else:
    formula = (repo_root / formula_rel).read_text(encoding="utf-8")
    match = re.search(
        r'^\s*url\s+"https://github\.com/backbay-labs/clawdstrike/archive/refs/tags/v([^"]+)\.tar\.gz"\s*$',
        formula,
        flags=re.M,
    )
    errors.append(check(f"{formula_rel} url tag", match.group(1) if match else None))

errors = [e for e in errors if e is not None]
if errors:
    fail("Version preflight failed:\\n  " + "\\n  ".join(errors))

print(f"Version preflight OK: {expected}")
PY
