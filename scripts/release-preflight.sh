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

py_name = pyproject.get("project", {}).get("name")
if py_name != "clawdstrike":
    errors.append(
        "packages/sdk/hush-py/pyproject.toml [project].name: "
        f'expected "clawdstrike", found {py_name!r}'
    )

wheel_packages = (
    pyproject.get("tool", {})
    .get("hatch", {})
    .get("build", {})
    .get("targets", {})
    .get("wheel", {})
    .get("packages", [])
)
if "src/clawdstrike" not in wheel_packages:
    errors.append(
        "packages/sdk/hush-py/pyproject.toml [tool.hatch.build.targets.wheel].packages: "
        'expected to include "src/clawdstrike"'
    )
if "src/hush" in wheel_packages:
    errors.append(
        "packages/sdk/hush-py/pyproject.toml [tool.hatch.build.targets.wheel].packages: "
        'must not include deprecated "src/hush"'
    )

py_init_rel = "packages/sdk/hush-py/src/clawdstrike/__init__.py"
if not (repo_root / py_init_rel).exists():
    errors.append(f"{py_init_rel}: missing")
else:
    py_init = (repo_root / py_init_rel).read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', py_init, flags=re.M)
    errors.append(check(f"{py_init_rel} __version__", match.group(1) if match else None))

npm_packages = [
    ("packages/adapters/clawdstrike-adapter-core/package.json", "@clawdstrike/adapter-core"),
    ("packages/sdk/hush-ts/package.json", "@clawdstrike/sdk"),
    ("packages/sdk/clawdstrike/package.json", "clawdstrike"),
    ("packages/policy/clawdstrike-policy/package.json", "@clawdstrike/policy"),
    ("packages/adapters/clawdstrike-claude-code/package.json", "@clawdstrike/claude-code"),
    ("packages/adapters/clawdstrike-codex/package.json", "@clawdstrike/codex"),
    ("packages/adapters/clawdstrike-vercel-ai/package.json", "@clawdstrike/vercel-ai"),
    ("packages/adapters/clawdstrike-langchain/package.json", "@clawdstrike/langchain"),
    ("packages/adapters/clawdstrike-openclaw/package.json", "@clawdstrike/openclaw"),
    ("packages/adapters/clawdstrike-opencode/package.json", "@clawdstrike/opencode"),
    ("packages/adapters/clawdstrike-hush-cli-engine/package.json", "@clawdstrike/engine-local"),
    ("packages/adapters/clawdstrike-hushd-engine/package.json", "@clawdstrike/engine-remote"),
    ("crates/libs/hush-wasm/package.json", "@clawdstrike/wasm"),
]

for pkg, expected_name in npm_packages:
    data = read_json(pkg)
    errors.append(check(pkg, data.get("version")))
    actual_name = data.get("name")
    if actual_name != expected_name:
        errors.append(
            f'{pkg} name: expected "{expected_name}", found {actual_name!r}'
        )

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
