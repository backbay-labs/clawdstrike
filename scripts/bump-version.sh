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

# Detect sed flavor (GNU vs BSD)
if sed --version 2>/dev/null | grep -q GNU; then
    SED_INPLACE="sed -i"
else
    SED_INPLACE="sed -i ''"
fi

# Update root Cargo.toml workspace version
echo "  Updating Cargo.toml workspace version..."
$SED_INPLACE "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" Cargo.toml

# Update all crate Cargo.toml files that use workspace version inheritance
# (They inherit from workspace, so we only need to update the root)

# Update package.json files across published npm packages
echo "  Updating packages/**/package.json versions..."
if command -v node &> /dev/null; then
    while IFS= read -r PKG_JSON; do
        node -e "
            const fs = require('fs');
            const path = process.argv[1];
            const version = process.argv[2];
            const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
            pkg.version = version;
            fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\\n');
        " "$PKG_JSON" "$VERSION"
    done < <(find packages -type f -name package.json | sort)

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
        $SED_INPLACE "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$PKG_JSON"
    done < <(find packages -type f -name package.json | sort)

    if [[ -f "crates/libs/hush-wasm/package.json" ]]; then
        $SED_INPLACE "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" crates/libs/hush-wasm/package.json
    fi
fi

FORMULA_PATH="infra/packaging/HomebrewFormula/hush.rb"
if [[ -f "$FORMULA_PATH" ]]; then
    echo "  Updating ${FORMULA_PATH} tag URL..."
    $SED_INPLACE "s#https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v[0-9][0-9.]*\\.tar\\.gz#https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v$VERSION.tar.gz#" "$FORMULA_PATH"
fi

# Update pyproject.toml if it exists
if [[ -f "packages/sdk/hush-py/pyproject.toml" ]]; then
    echo "  Updating packages/sdk/hush-py/pyproject.toml..."
    $SED_INPLACE "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" packages/sdk/hush-py/pyproject.toml
fi

PY_INIT_PATH=""
if [[ -f "packages/sdk/hush-py/src/clawdstrike/__init__.py" ]]; then
    PY_INIT_PATH="packages/sdk/hush-py/src/clawdstrike/__init__.py"
elif [[ -f "packages/sdk/hush-py/src/hush/__init__.py" ]]; then
    PY_INIT_PATH="packages/sdk/hush-py/src/hush/__init__.py"
fi

if [[ -n "$PY_INIT_PATH" ]]; then
    echo "  Updating ${PY_INIT_PATH} __version__..."
    $SED_INPLACE "s/^__version__ = \"[^\"]*\"/__version__ = \"$VERSION\"/" "$PY_INIT_PATH"
fi

echo ""
echo "Version bumped to $VERSION"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit: git commit -am \"chore: bump version to \$VERSION\""
echo "  3. Tag: git tag -a v\$VERSION -m \"Release v\$VERSION\""
echo "  4. Push: git push && git push --tags"
