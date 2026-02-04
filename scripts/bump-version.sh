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
if [[ -f "packages/clawdstrike-openclaw/package.json" ]]; then
    echo "  Updating packages/clawdstrike-openclaw/package.json..."
    # Use node/jq if available, otherwise sed
    if command -v node &> /dev/null; then
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('packages/clawdstrike-openclaw/package.json', 'utf8'));
            pkg.version = '$VERSION';
            fs.writeFileSync('packages/clawdstrike-openclaw/package.json', JSON.stringify(pkg, null, 2) + '\n');
        "
    else
        $SED_INPLACE "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" packages/clawdstrike-openclaw/package.json
    fi
fi

if [[ -f "packages/hush-ts/package.json" ]]; then
    echo "  Updating packages/hush-ts/package.json..."
    if command -v node &> /dev/null; then
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('packages/hush-ts/package.json', 'utf8'));
            pkg.version = '$VERSION';
            fs.writeFileSync('packages/hush-ts/package.json', JSON.stringify(pkg, null, 2) + '\n');
        "
    else
        $SED_INPLACE "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" packages/hush-ts/package.json
    fi
fi

if [[ -f "crates/hush-wasm/package.json" ]]; then
    echo "  Updating crates/hush-wasm/package.json..."
    if command -v node &> /dev/null; then
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('crates/hush-wasm/package.json', 'utf8'));
            pkg.version = '$VERSION';
            fs.writeFileSync('crates/hush-wasm/package.json', JSON.stringify(pkg, null, 2) + '\n');
        "
    else
        $SED_INPLACE "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" crates/hush-wasm/package.json
    fi
fi

if [[ -f "HomebrewFormula/hush.rb" ]]; then
    echo "  Updating HomebrewFormula/hush.rb tag URL..."
    $SED_INPLACE "s#https://github.com/backbay-labs/hushclaw/archive/refs/tags/v[0-9][0-9.]*\\.tar\\.gz#https://github.com/backbay-labs/hushclaw/archive/refs/tags/v$VERSION.tar.gz#" HomebrewFormula/hush.rb
fi

# Update pyproject.toml if it exists
if [[ -f "packages/hush-py/pyproject.toml" ]]; then
    echo "  Updating packages/hush-py/pyproject.toml..."
    $SED_INPLACE "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" packages/hush-py/pyproject.toml
fi

if [[ -f "packages/hush-py/src/hush/__init__.py" ]]; then
    echo "  Updating packages/hush-py/src/hush/__init__.py __version__..."
    $SED_INPLACE "s/^__version__ = \"[^\"]*\"/__version__ = \"$VERSION\"/" packages/hush-py/src/hush/__init__.py
fi

echo ""
echo "Version bumped to $VERSION"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit: git commit -am \"chore: bump version to \$VERSION\""
echo "  3. Tag: git tag -a v\$VERSION -m \"Release v\$VERSION\""
echo "  4. Push: git push && git push --tags"
