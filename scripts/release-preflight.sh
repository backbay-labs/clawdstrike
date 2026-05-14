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


def read_text(rel: str) -> str:
    path = repo_root / rel
    return path.read_text(encoding="utf-8")


def expand_workspace_dirs(patterns: list[str]) -> list[Path]:
    results: list[Path] = []
    for pattern in patterns:
        parts = pattern.split("/")
        results.extend(expand_workspace_pattern(repo_root, parts))
    deduped = {path.resolve(): path for path in results}
    return sorted(deduped.values())


def expand_workspace_pattern(current: Path, parts: list[str]) -> list[Path]:
    if not parts:
        if (current / "package.json").exists():
            return [current]
        return []

    part = parts[0]
    if part == "*":
        paths: list[Path] = []
        for child in current.iterdir():
            if child.is_dir():
                paths.extend(expand_workspace_pattern(child, parts[1:]))
        return paths

    return expand_workspace_pattern(current / part, parts[1:])


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

for dep_name in ("clawdstrike-logos", "logos-ffi", "logos-z3"):
    dep_version = cargo.get("workspace", {}).get("dependencies", {}).get(dep_name, {}).get("version")
    errors.append(check(f"Cargo.toml [workspace.dependencies].{dep_name}.version", dep_version))

root_package = read_json("package.json")
workspace_entries = root_package.get("workspaces")
workspace_set: set[str] = set()
if not isinstance(workspace_entries, list):
    errors.append("package.json workspaces: missing or not an array")
else:
    workspace_set = {entry for entry in workspace_entries if isinstance(entry, str)}
workspace_dirs = expand_workspace_dirs(list(workspace_set))
workspace_dir_by_name: dict[str, Path] = {}
for workspace_dir in workspace_dirs:
    manifest = read_json(str(workspace_dir.relative_to(repo_root) / "package.json"))
    name = manifest.get("name")
    if isinstance(name, str):
        workspace_dir_by_name[name] = workspace_dir

root_lock = read_json("package-lock.json")
root_lock_packages = root_lock.get("packages", {})
for rel, expected_name in (
    ("crates/libs/hush-wasm", "@clawdstrike/wasm"),
    ("packages/adapters/clawdstrike-openclaw", "@clawdstrike/openclaw"),
    ("packages/sdk/hush-ts", "@clawdstrike/sdk"),
):
    lock_entry = root_lock_packages.get(rel, {})
    actual_name = lock_entry.get("name")
    if actual_name != expected_name:
        errors.append(f"package-lock.json {rel} name: expected {expected_name}, found {actual_name}")
    errors.append(check(f"package-lock.json {rel} version", lock_entry.get("version")))

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

logos_z3 = read_toml("crates/libs/logos-z3/Cargo.toml")
errors.append(check("crates/libs/logos-z3/Cargo.toml [package].version", logos_z3.get("package", {}).get("version")))
errors.append(
    check(
        "crates/libs/logos-z3/Cargo.toml [dependencies].logos-ffi.version",
        logos_z3.get("dependencies", {}).get("logos-ffi", {}).get("version"),
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

openclaw_plugin = read_json("packages/adapters/clawdstrike-openclaw/openclaw.plugin.json")
errors.append(
    check(
        "packages/adapters/clawdstrike-openclaw/openclaw.plugin.json version",
        openclaw_plugin.get("version"),
    )
)

for rel, dep_names in (
    ("infra/docker/workspace-control-api.toml", ("hush-core", "spine")),
    ("infra/docker/workspace-hushd.toml", ("hush-core", "hush-proxy", "spine", "clawdstrike", "clawdstrike-ocsf", "clawdstrike-policy-event", "hunt-scan", "hunt-query", "hush-certification")),
    ("infra/docker/workspace-registry.toml", ("hush-core", "clawdstrike", "spine", "hush-proxy")),
):
    workspace_toml = read_toml(rel)
    workspace_toml_version = workspace_toml.get("workspace", {}).get("package", {}).get("version")
    errors.append(check(f"{rel} [workspace.package].version", workspace_toml_version))
    for dep_name in dep_names:
        dep_version = workspace_toml.get("workspace", {}).get("dependencies", {}).get(dep_name, {}).get("version")
        errors.append(check(f"{rel} [workspace.dependencies].{dep_name}.version", dep_version))

formula = read_text("infra/packaging/HomebrewFormula/hush.rb")
if f"/archive/refs/tags/v{expected}.tar.gz" not in formula:
    errors.append(
        "infra/packaging/HomebrewFormula/hush.rb url: "
        f"expected archive tag v{expected}.tar.gz"
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

    publish_access = data.get("publishConfig", {}).get("access")
    if publish_access == "public":
        workspace_rel = str(pkg_path.parent.relative_to(repo_root))
        if workspace_rel not in workspace_set:
            errors.append(f"{rel}: publishable package is missing from package.json workspaces")

    lock_path = pkg_path.with_name("package-lock.json")
    if lock_path.exists():
        lock_rel = str(lock_path.relative_to(repo_root))
        lock_data = read_json(lock_rel)
        lock_root = lock_data.get("packages", {}).get("", {})
        errors.append(check(f"{lock_rel} top-level version", lock_data.get("version")))
        errors.append(check(f"{lock_rel} packages[''].version", lock_root.get("version")))
        if lock_data.get("name") != name:
            errors.append(f"{lock_rel} top-level name: expected {name}, found {lock_data.get('name')}")
        if lock_root.get("name") != name:
            errors.append(f"{lock_rel} packages[''].name: expected {name}, found {lock_root.get('name')}")
        for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            expected_deps = data.get(field)
            actual_deps = lock_root.get(field)
            if expected_deps is None and actual_deps is not None:
                errors.append(f"{lock_rel} packages[''].{field}: expected missing field")
            elif expected_deps is not None and actual_deps != expected_deps:
                errors.append(f"{lock_rel} packages[''].{field}: expected package.json to match")

        internal_deps = {
            dep_name
            for field in ("dependencies", "optionalDependencies")
            for dep_name in (data.get(field) or {}).keys()
            if dep_name in workspace_dir_by_name
        }
        for dep_name in sorted(internal_deps):
            dep_dir = workspace_dir_by_name[dep_name]
            expected_resolved = os.path.relpath(dep_dir, start=pkg_path.parent).replace(os.sep, "/")
            linked_entry = lock_data.get("packages", {}).get(f"node_modules/{dep_name}", {})
            if linked_entry.get("link") is not True:
                errors.append(f"{lock_rel} node_modules/{dep_name}: expected local link entry")
            elif linked_entry.get("resolved") != expected_resolved:
                errors.append(
                    f"{lock_rel} node_modules/{dep_name}.resolved: "
                    f"expected {expected_resolved}, found {linked_entry.get('resolved')}"
                )

            linked_package = lock_data.get("packages", {}).get(expected_resolved, {})
            if linked_package.get("name") != dep_name:
                errors.append(
                    f"{lock_rel} {expected_resolved}.name: "
                    f"expected {dep_name}, found {linked_package.get('name')}"
                )
            errors.append(check(f"{lock_rel} {expected_resolved}.version", linked_package.get("version")))

errors.append(check("crates/libs/hush-wasm/package.json", read_json("crates/libs/hush-wasm/package.json").get("version")))

errors = [e for e in errors if e is not None]
if errors:
    fail("Version preflight failed:\\n  " + "\\n  ".join(errors))

print(f"Version preflight OK: {expected}")
PY
