#!/usr/bin/env bash
set -euo pipefail

# Version bump script for clawdstrike
# Usage: ./scripts/bump-version.sh <version>
# Example: ./scripts/bump-version.sh 0.2.0

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.2.0"
    exit 1
fi

# Validate version format (strict semver, matching scripts/release-preflight.sh)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be strict semver (X.Y.Z)"
    exit 1
fi

echo "Bumping version to $VERSION..."

IS_GNU_SED=0
if sed --version 2>/dev/null | grep -q GNU; then
    IS_GNU_SED=1
fi

sed_inplace() {
    local expr="$1"
    local file="$2"
    if [[ "$IS_GNU_SED" -eq 1 ]]; then
        sed -i -e "$expr" "$file"
    else
        sed -i '' -e "$expr" "$file"
    fi
}

find_package_json_files() {
    find packages \
        \( -type d -name node_modules -o -type d -name .turbo \) -prune \
        -o -type f -name package.json -print \
        | sort
}

find_openclaw_plugin_files() {
    find packages \
        \( -type d -name node_modules -o -type d -name .turbo \) -prune \
        -o -type f -name openclaw.plugin.json -print \
        | sort
}

find_package_lock_files() {
    find packages apps \
        \( -type d -name node_modules -o -type d -name .turbo \) -prune \
        -o -type f -name package-lock.json -print \
        | sort
}

# Update root Cargo.toml workspace version
echo "  Updating Cargo.toml workspace version..."
sed_inplace "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" Cargo.toml

# Update internal workspace dependency versions used for publishing metadata.
echo "  Updating Cargo.toml internal dependency versions..."
for crate in \
    hush-core \
    hush-proxy \
    clawdstrike \
    clawdstrike-broker-protocol \
    hush-certification \
    spine \
    bridge-runtime \
    hush-multi-agent \
    hunt-scan \
    hunt-query \
    hunt-correlate \
    clawdstrike-logos \
    logos-ffi \
    logos-z3 \
    clawdstrike-ocsf \
    clawdstrike-policy-event
do
    sed_inplace "s/\\(${crate} = {[^}]*version = \\)\"[^\"]*\"/\\1\"$VERSION\"/" Cargo.toml
done

# Update package.json files across published npm packages
echo "  Updating packages/**/package.json versions..."
if command -v node &> /dev/null; then
    INTERNAL_PACKAGE_NAMES=()
    while IFS= read -r INTERNAL_PKG_JSON; do
        INTERNAL_PACKAGE_NAMES+=("$(node -p "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8')).name" "$INTERNAL_PKG_JSON")")
    done < <(find_package_json_files)

    if [[ -f "crates/libs/hush-wasm/package.json" ]]; then
        INTERNAL_PACKAGE_NAMES+=("$(node -p "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8')).name" crates/libs/hush-wasm/package.json)")
    fi

    while IFS= read -r PKG_JSON; do
        node -e "
            const fs = require('fs');
            const path = process.argv[1];
            const version = process.argv[2];
            const internalPackageNames = new Set(process.argv.slice(3));
            const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
            pkg.version = version;
            for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
                const deps = pkg[field];
                if (!deps) continue;
                for (const [name, current] of Object.entries(deps)) {
                    if (!internalPackageNames.has(name) || typeof current !== 'string') continue;
                    const match = current.match(/^([~^]?)([0-9]+\.[0-9]+\.[0-9]+)$/);
                    if (!match) continue;
                    deps[name] = match[1] + version;
                }
            }
            fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\\n');
        " "$PKG_JSON" "$VERSION" "${INTERNAL_PACKAGE_NAMES[@]}"
    done < <(find_package_json_files)

    if [[ -f "crates/libs/hush-wasm/package.json" ]]; then
        node -e "
            const fs = require('fs');
            const path = 'crates/libs/hush-wasm/package.json';
            const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
            pkg.version = process.argv[1];
            fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\\n');
        " "$VERSION"
    fi
else
    while IFS= read -r PKG_JSON; do
        sed_inplace "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$PKG_JSON"
    done < <(find_package_json_files)

    if [[ -f "crates/libs/hush-wasm/package.json" ]]; then
        sed_inplace "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" crates/libs/hush-wasm/package.json
    fi
fi

FORMULA_PATH="infra/packaging/HomebrewFormula/hush.rb"
if [[ -f "$FORMULA_PATH" ]]; then
    echo "  Updating ${FORMULA_PATH} tag URL..."
    sed_inplace "s#https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v[0-9][0-9.]*\\.tar\\.gz#https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v$VERSION.tar.gz#" "$FORMULA_PATH"
fi

# Update pyproject.toml if it exists
if [[ -f "packages/sdk/hush-py/pyproject.toml" ]]; then
    echo "  Updating packages/sdk/hush-py/pyproject.toml..."
    sed_inplace "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" packages/sdk/hush-py/pyproject.toml
fi

if [[ -f "packages/sdk/hush-py/hush-native/pyproject.toml" ]]; then
    echo "  Updating packages/sdk/hush-py/hush-native/pyproject.toml..."
    sed_inplace "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" packages/sdk/hush-py/hush-native/pyproject.toml
fi

if [[ -f "packages/sdk/hush-py/hush-native/Cargo.toml" ]]; then
    echo "  Updating packages/sdk/hush-py/hush-native/Cargo.toml..."
    sed_inplace "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" packages/sdk/hush-py/hush-native/Cargo.toml
fi

if [[ -f "apps/agent/src-tauri/Cargo.toml" ]]; then
    echo "  Updating apps/agent/src-tauri/Cargo.toml..."
    sed_inplace "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" apps/agent/src-tauri/Cargo.toml
fi

if [[ -f "apps/agent/src-tauri/tauri.conf.json" ]]; then
    echo "  Updating apps/agent/src-tauri/tauri.conf.json..."
    if command -v node &> /dev/null; then
        node -e "
            const fs = require('fs');
            const path = 'apps/agent/src-tauri/tauri.conf.json';
            const data = JSON.parse(fs.readFileSync(path, 'utf8'));
            data.version = process.argv[1];
            fs.writeFileSync(path, JSON.stringify(data, null, 2) + '\\n');
        " "$VERSION"
    else
        sed_inplace "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" apps/agent/src-tauri/tauri.conf.json
    fi
fi

PY_INIT_PATH=""
if [[ -f "packages/sdk/hush-py/src/clawdstrike/__init__.py" ]]; then
    PY_INIT_PATH="packages/sdk/hush-py/src/clawdstrike/__init__.py"
elif [[ -f "packages/sdk/hush-py/src/hush/__init__.py" ]]; then
    PY_INIT_PATH="packages/sdk/hush-py/src/hush/__init__.py"
fi

if [[ -n "$PY_INIT_PATH" ]]; then
    echo "  Updating ${PY_INIT_PATH} __version__..."
    sed_inplace "s/^__version__ = \"[^\"]*\"/__version__ = \"$VERSION\"/" "$PY_INIT_PATH"
fi

if [[ -f "crates/libs/logos-z3/Cargo.toml" ]]; then
    echo "  Updating crates/libs/logos-z3/Cargo.toml..."
    sed_inplace "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" crates/libs/logos-z3/Cargo.toml
    sed_inplace "s/\\(logos-ffi = {[^}]*version = \\)\"[^\"]*\"/\\1\"$VERSION\"/" crates/libs/logos-z3/Cargo.toml
fi

for docker_workspace in \
    infra/docker/workspace-control-api.toml \
    infra/docker/workspace-hushd.toml \
    infra/docker/workspace-registry.toml
do
    if [[ -f "$docker_workspace" ]]; then
        echo "  Updating ${docker_workspace}..."
        sed_inplace "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" "$docker_workspace"
        for crate in \
            hush-core \
            hush-proxy \
            clawdstrike \
            hush-certification \
            spine \
            hunt-scan \
            hunt-query \
            clawdstrike-ocsf \
            clawdstrike-policy-event
        do
            sed_inplace "s/\\(${crate} = {[^}]*version = \\)\"[^\"]*\"/\\1\"$VERSION\"/" "$docker_workspace"
        done
    fi
done

while IFS= read -r PLUGIN_JSON; do
    echo "  Updating ${PLUGIN_JSON}..."
    sed_inplace "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$PLUGIN_JSON"
done < <(find_openclaw_plugin_files)

if command -v npm &> /dev/null && [[ -f "package-lock.json" ]]; then
    echo "  Refreshing root package-lock.json workspace metadata..."
    npm install --package-lock-only --ignore-scripts >/dev/null
fi

if command -v npm &> /dev/null; then
    while IFS= read -r LOCK_JSON; do
        LOCK_DIR="$(dirname "$LOCK_JSON")"
        echo "  Refreshing ${LOCK_JSON} resolved dependency graph..."
        (
            cd "$LOCK_DIR"
            npm install --package-lock-only --ignore-scripts >/dev/null
        )
    done < <(find_package_lock_files)
fi

if command -v node &> /dev/null; then
    echo "  Syncing package-local lockfiles to local workspace links..."
    node scripts/sync-package-locks.mjs
fi

if command -v node &> /dev/null && [[ -f "package-lock.json" ]] && [[ -f "package.json" ]]; then
    echo "  Sanitizing root package-lock.json metadata..."
    node -e "
        const fs = require('fs');
        const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
        const lockPath = 'package-lock.json';
        const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        if (!Object.hasOwn(pkg, 'name')) {
            delete lock.name;
        }
        fs.writeFileSync(lockPath, JSON.stringify(lock, null, 2) + '\\n');
    "
fi

echo ""
echo "Version bumped to $VERSION"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit: git commit -am \"chore: bump version to \$VERSION\""
echo "  3. Tag: git tag -a v\$VERSION -m \"Release v\$VERSION\""
echo "  4. Push: git push && git push --tags"
