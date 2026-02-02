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

python - "$VERSION" <<'PY'
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

pyproject = read_toml("packages/hush-py/pyproject.toml")
py_version = pyproject.get("project", {}).get("version")
errors.append(check("packages/hush-py/pyproject.toml [project].version", py_version))

hush_init = (repo_root / "packages/hush-py/src/hush/__init__.py").read_text(encoding="utf-8")
match = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', hush_init, flags=re.M)
errors.append(check("packages/hush-py/src/hush/__init__.py __version__", match.group(1) if match else None))

for pkg in [
    "packages/hush-ts/package.json",
    "packages/clawdstrike-openclaw/package.json",
    "crates/hush-wasm/package.json",
]:
    errors.append(check(pkg, read_json(pkg).get("version")))

formula = (repo_root / "HomebrewFormula/hush.rb").read_text(encoding="utf-8")
match = re.search(
    r'^\s*url\s+"https://github\.com/clawdstrike/clawdstrike/archive/refs/tags/v([^"]+)\.tar\.gz"\s*$',
    formula,
    flags=re.M,
)
errors.append(check("HomebrewFormula/hush.rb url tag", match.group(1) if match else None))

errors = [e for e in errors if e is not None]
if errors:
    fail("Version preflight failed:\\n  " + "\\n  ".join(errors))

print(f"Version preflight OK: {expected}")
PY
