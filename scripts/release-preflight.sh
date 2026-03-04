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

native_pyproject = read_toml("packages/sdk/hush-py/hush-native/pyproject.toml")
native_py_version = native_pyproject.get("project", {}).get("version")
errors.append(
    check(
        "packages/sdk/hush-py/hush-native/pyproject.toml [project].version",
        native_py_version,
    )
)

native_pkg_name = native_pyproject.get("project", {}).get("name")
if native_pkg_name != "clawdstrike":
    errors.append(
        "packages/sdk/hush-py/hush-native/pyproject.toml [project].name: "
        f"expected clawdstrike, found {native_pkg_name}"
    )

native_cargo = read_toml("packages/sdk/hush-py/hush-native/Cargo.toml")
native_cargo_version = native_cargo.get("package", {}).get("version")
errors.append(
    check(
        "packages/sdk/hush-py/hush-native/Cargo.toml [package].version",
        native_cargo_version,
    )
)

agent_cargo = read_toml("apps/agent/src-tauri/Cargo.toml")
agent_cargo_version = agent_cargo.get("package", {}).get("version")
errors.append(
    check(
        "apps/agent/src-tauri/Cargo.toml [package].version",
        agent_cargo_version,
    )
)

agent_tauri = read_json("apps/agent/src-tauri/tauri.conf.json")
errors.append(
    check(
        "apps/agent/src-tauri/tauri.conf.json version",
        agent_tauri.get("version"),
    )
)

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

def is_package_manifest(path: Path) -> bool:
    parts = set(path.parts)
    return "node_modules" not in parts and ".turbo" not in parts


for pkg_path in sorted((repo_root / "packages").rglob("package.json")):
    if not is_package_manifest(pkg_path):
        continue
    rel = str(pkg_path.relative_to(repo_root))
    data = read_json(rel)
    errors.append(check(rel, data.get("version")))

    name = data.get("name")
    if not isinstance(name, str):
        errors.append(f"{rel} name: missing package name")
    elif name != "clawdstrike" and not name.startswith("@clawdstrike/"):
        errors.append(f"{rel} name: expected @clawdstrike/* or clawdstrike, found {name}")

errors.append(check("crates/libs/hush-wasm/package.json", read_json("crates/libs/hush-wasm/package.json").get("version")))

errors = [e for e in errors if e is not None]
if errors:
    fail("Version preflight failed:\\n  " + "\\n  ".join(errors))

print(f"Version preflight OK: {expected}")
PY
