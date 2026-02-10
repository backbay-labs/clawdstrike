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

# Update package.json files
if [[ -f "packages/adapters/clawdstrike-openclaw/package.json" ]]; then
    echo "  Updating packages/adapters/clawdstrike-openclaw/package.json..."
    # Use node/jq if available, otherwise sed
    if command -v node &> /dev/null; then
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('packages/adapters/clawdstrike-openclaw/package.json', 'utf8'));
            pkg.version = '$VERSION';
            fs.writeFileSync('packages/adapters/clawdstrike-openclaw/package.json', JSON.stringify(pkg, null, 2) + '\n');
        "
    else
        $SED_INPLACE "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" packages/adapters/clawdstrike-openclaw/package.json
    fi
fi

if [[ -f "packages/sdk/hush-ts/package.json" ]]; then
    echo "  Updating packages/sdk/hush-ts/package.json..."
    if command -v node &> /dev/null; then
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('packages/sdk/hush-ts/package.json', 'utf8'));
            pkg.version = '$VERSION';
            fs.writeFileSync('packages/sdk/hush-ts/package.json', JSON.stringify(pkg, null, 2) + '\n');
        "
    else
        $SED_INPLACE "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" packages/sdk/hush-ts/package.json
    fi
fi

if [[ -f "crates/libs/hush-wasm/package.json" ]]; then
    echo "  Updating crates/libs/hush-wasm/package.json..."
    if command -v node &> /dev/null; then
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('crates/libs/hush-wasm/package.json', 'utf8'));
            pkg.version = '$VERSION';
            fs.writeFileSync('crates/libs/hush-wasm/package.json', JSON.stringify(pkg, null, 2) + '\n');
        "
    else
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
