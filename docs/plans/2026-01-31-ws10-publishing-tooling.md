# WS10: Publishing & Dev Tooling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Set up publishing workflows for crates.io, npm, PyPI, and Homebrew plus development tooling for consistent code quality.

**Architecture:** We add Rust formatting/linting configs at repo root, a mise.toml for tool version management, a comprehensive GitHub Actions release workflow triggered by version tags, a Homebrew formula for CLI installation, and a version bump script to synchronize versions across all packages.

**Tech Stack:** Rust (rustfmt, clippy, cargo-deny), mise (tool versions), GitHub Actions (publishing), Homebrew (macOS installation), Bash (scripts)

---

## Task 1: Rust Formatting Configuration

**Files:**
- Create: `.rustfmt.toml`

**Step 1: Create rustfmt config file**

```toml
edition = "2021"
max_width = 100
tab_spaces = 4
use_small_heuristics = "Default"
imports_granularity = "Crate"
group_imports = "StdExternalCrate"
```

**Step 2: Verify formatting applies**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo fmt --all -- --check`
Expected: Either PASS (already formatted) or shows diff of changes needed

**Step 3: Apply formatting if needed**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo fmt --all`
Expected: All files formatted to match config

**Step 4: Commit**

```bash
git add .rustfmt.toml
git commit -m "chore: add rustfmt configuration"
```

---

## Task 2: Clippy Lint Configuration

**Files:**
- Create: `clippy.toml`
- Modify: `Cargo.toml` (add workspace lints section)

**Step 1: Create clippy.toml file**

```toml
cognitive-complexity-threshold = 30
```

**Step 2: Add workspace lints to Cargo.toml**

Add after `[profile.release]` section:

```toml
[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
```

**Step 3: Verify clippy runs with new config**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo clippy --workspace -- -D warnings 2>&1 | head -50`
Expected: Either passes or shows warnings to fix (we accept warnings for now since fixing is out of scope)

**Step 4: Commit**

```bash
git add clippy.toml Cargo.toml
git commit -m "chore: add clippy lint configuration"
```

---

## Task 3: Cargo-Deny License/Advisory Configuration

**Files:**
- Create: `deny.toml`

**Step 1: Create deny.toml file**

```toml
# cargo-deny configuration
# Run with: cargo deny check

[graph]
targets = [
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
]

[licenses]
version = 2
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "CC0-1.0",
    "Unicode-DFS-2016",
]
confidence-threshold = 0.8

[[licenses.clarify]]
name = "ring"
expression = "MIT AND ISC AND OpenSSL"
license-files = [{ path = "LICENSE", hash = 0xbd0eed23 }]

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[advisories]
version = 2
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"

[sources]
unknown-registry = "warn"
unknown-git = "warn"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**Step 2: Test deny configuration (optional - requires cargo-deny installed)**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo deny check 2>&1 || echo "cargo-deny not installed or warnings found (OK)"`
Expected: Either passes or shows cargo-deny not installed (acceptable)

**Step 3: Commit**

```bash
git add deny.toml
git commit -m "chore: add cargo-deny license and advisory configuration"
```

---

## Task 4: Mise Tool Version Management

**Files:**
- Create: `mise.toml`

**Step 1: Create mise.toml file**

```toml
[tools]
rust = "1.75"
node = "20"
python = "3.12"

[tasks.check]
description = "Run cargo check on workspace"
run = "cargo check --workspace"

[tasks.test]
description = "Run all tests"
run = "cargo test --workspace"

[tasks.lint]
description = "Run clippy with warnings as errors"
run = "cargo clippy --workspace -- -D warnings"

[tasks.fmt]
description = "Format all Rust code"
run = "cargo fmt --all"

[tasks.fmt-check]
description = "Check Rust formatting"
run = "cargo fmt --all -- --check"

[tasks.deny]
description = "Run cargo-deny checks"
run = "cargo deny check"

[tasks.doc]
description = "Build documentation"
run = "cargo doc --workspace --no-deps"

[tasks.audit]
description = "Run security audit"
run = "cargo audit"

[tasks.ci]
description = "Run all CI checks"
run = """
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
"""
```

**Step 2: Verify mise can parse the config**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cat mise.toml`
Expected: Shows the config file contents

**Step 3: Commit**

```bash
git add mise.toml
git commit -m "chore: add mise tool version management"
```

---

## Task 5: GitHub Release Notes Template

**Files:**
- Create: `.github/release.yml`

**Step 1: Create release notes template**

```yaml
# Automatically generated release notes configuration
# See: https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes

changelog:
  exclude:
    labels:
      - ignore-for-release
      - dependencies
    authors:
      - dependabot
      - dependabot[bot]
  categories:
    - title: "Breaking Changes"
      labels:
        - breaking
        - breaking-change
    - title: "Security"
      labels:
        - security
    - title: "New Features"
      labels:
        - enhancement
        - feature
    - title: "Bug Fixes"
      labels:
        - bug
        - bugfix
        - fix
    - title: "Performance"
      labels:
        - performance
        - perf
    - title: "Documentation"
      labels:
        - documentation
        - docs
    - title: "Other Changes"
      labels:
        - "*"
```

**Step 2: Commit**

```bash
git add .github/release.yml
git commit -m "chore: add GitHub release notes template"
```

---

## Task 6: Version Bump Script

**Files:**
- Create: `scripts/bump-version.sh`

**Step 1: Create scripts directory**

Run: `mkdir -p /Users/connor/Medica/clawdstrike-ws10-publish/scripts`

**Step 2: Create bump-version.sh script**

```bash
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

# Validate version format (semver)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo "Error: Version must be in semver format (e.g., 0.2.0 or 0.2.0-alpha.1)"
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

# Update pyproject.toml if it exists
if [[ -f "packages/hush-py/pyproject.toml" ]]; then
    echo "  Updating packages/hush-py/pyproject.toml..."
    $SED_INPLACE "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" packages/hush-py/pyproject.toml
fi

echo ""
echo "Version bumped to $VERSION"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit: git commit -am \"chore: bump version to $VERSION\""
echo "  3. Tag: git tag -a v$VERSION -m \"Release v$VERSION\""
echo "  4. Push: git push && git push --tags"
```

**Step 3: Make script executable**

Run: `chmod +x /Users/connor/Medica/clawdstrike-ws10-publish/scripts/bump-version.sh`

**Step 4: Test script shows usage**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && ./scripts/bump-version.sh`
Expected: Shows "Usage: ./scripts/bump-version.sh <version>"

**Step 5: Commit**

```bash
git add scripts/bump-version.sh
git commit -m "chore: add version bump script"
```

---

## Task 7: Homebrew Formula

**Files:**
- Create: `HomebrewFormula/hush.rb`

**Step 1: Create HomebrewFormula directory**

Run: `mkdir -p /Users/connor/Medica/clawdstrike-ws10-publish/HomebrewFormula`

**Step 2: Create Homebrew formula**

```ruby
# Homebrew formula for hush CLI
# Install: brew install clawdstrike/tap/hush
# Or from local: brew install --build-from-source ./HomebrewFormula/hush.rb

class Hush < Formula
  desc "CLI for clawdstrike security verification and policy enforcement"
  homepage "https://github.com/backbay-labs/clawdstrike"
  url "https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256_WILL_BE_UPDATED_ON_RELEASE"
  license "MIT"
  head "https://github.com/backbay-labs/clawdstrike.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/hush-cli")

    # Generate shell completions
    generate_completions_from_executable(bin/"hush", "completions")
  end

  test do
    assert_match "hush #{version}", shell_output("#{bin}/hush --version")

    # Test basic help
    assert_match "security verification", shell_output("#{bin}/hush --help")
  end
end
```

**Step 3: Commit**

```bash
git add HomebrewFormula/hush.rb
git commit -m "chore: add Homebrew formula for hush CLI"
```

---

## Task 8: Release Workflow - Crates.io Publishing

**Files:**
- Create: `.github/workflows/release.yml`

**Step 1: Create release workflow for crates.io**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

permissions:
  contents: write
  packages: write
  id-token: write

jobs:
  # Validate before publishing
  validate:
    name: Validate Release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-release-${{ hashFiles('**/Cargo.lock') }}

      - name: Run tests
        run: cargo test --workspace --all-features

      - name: Check formatting
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --workspace --all-features -- -D warnings

  # Publish to crates.io
  publish-crates:
    name: Publish to crates.io
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-release-${{ hashFiles('**/Cargo.lock') }}

      - name: Publish hush-core
        run: cargo publish -p hush-core --no-verify
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        continue-on-error: true

      - name: Wait for crates.io index update
        run: sleep 30

      - name: Publish hush-proxy
        run: cargo publish -p hush-proxy --no-verify
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        continue-on-error: true

      - name: Wait for crates.io index update
        run: sleep 30

      - name: Publish clawdstrike
        run: cargo publish -p clawdstrike --no-verify
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        continue-on-error: true

      - name: Wait for crates.io index update
        run: sleep 30

      - name: Publish hushd
        run: cargo publish -p hushd --no-verify
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        continue-on-error: true

      - name: Wait for crates.io index update
        run: sleep 30

      - name: Publish hush-cli
        run: cargo publish -p hush-cli --no-verify
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        continue-on-error: true

  # Build release binaries
  build-binaries:
    name: Build Binaries
    needs: validate
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
            name: hush-linux-x86_64
          - target: x86_64-apple-darwin
            os: macos-latest
            name: hush-macos-x86_64
          - target: aarch64-apple-darwin
            os: macos-latest
            name: hush-macos-aarch64
          - target: x86_64-pc-windows-msvc
            os: windows-latest
            name: hush-windows-x86_64.exe
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Build release binary
        run: cargo build --release --target ${{ matrix.target }} -p hush-cli

      - name: Prepare artifact (Unix)
        if: runner.os != 'Windows'
        run: |
          cp target/${{ matrix.target }}/release/hush ${{ matrix.name }}
          chmod +x ${{ matrix.name }}

      - name: Prepare artifact (Windows)
        if: runner.os == 'Windows'
        run: cp target/${{ matrix.target }}/release/hush.exe ${{ matrix.name }}

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.name }}
          path: ${{ matrix.name }}

  # Create GitHub release with binaries
  create-release:
    name: Create GitHub Release
    needs: build-binaries
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts

      - name: Prepare release assets
        run: |
          mkdir -p release-assets
          for dir in artifacts/*/; do
            cp "$dir"* release-assets/ || true
          done
          ls -la release-assets/

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          draft: false
          prerelease: ${{ contains(github.ref, 'alpha') || contains(github.ref, 'beta') || contains(github.ref, 'rc') }}
          generate_release_notes: true
          files: release-assets/*
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat: add release workflow for crates.io and GitHub releases"
```

---

## Task 9: Release Workflow - npm Publishing

**Files:**
- Modify: `.github/workflows/release.yml` (add npm job)

**Step 1: Add npm publishing job after create-release job**

Add to `.github/workflows/release.yml`:

```yaml
  # Publish to npm
  publish-npm:
    name: Publish to npm
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'

      - name: Install dependencies
        run: cd packages/clawdstrike-openclaw && npm ci

      - name: Build package
        run: cd packages/clawdstrike-openclaw && npm run build

      - name: Publish @clawdstrike/openclaw
        run: cd packages/clawdstrike-openclaw && npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        continue-on-error: true
```

**Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat: add npm publishing to release workflow"
```

---

## Task 10: Release Workflow - PyPI Publishing (Placeholder)

**Files:**
- Modify: `.github/workflows/release.yml` (add PyPI job)

**Step 1: Add PyPI publishing job (placeholder for when hush-py exists)**

Add to `.github/workflows/release.yml`:

```yaml
  # Publish to PyPI (when hush-py package exists)
  publish-pypi:
    name: Publish to PyPI
    needs: validate
    runs-on: ubuntu-latest
    # Only run if hush-py package exists
    if: ${{ hashFiles('packages/hush-py/pyproject.toml') != '' }}
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install build tools
        run: pip install build twine

      - name: Build package
        run: cd packages/hush-py && python -m build

      - name: Publish to PyPI
        run: twine upload packages/hush-py/dist/*
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
        continue-on-error: true
```

**Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat: add PyPI publishing to release workflow (placeholder)"
```

---

## Task 11: Update CI Workflow with cargo-deny

**Files:**
- Modify: `.github/workflows/ci.yml` (add cargo-deny check)

**Step 1: Add cargo-deny job to CI workflow**

Add to `.github/workflows/ci.yml` after security-audit job:

```yaml
  license-check:
    name: License Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cargo-deny
        uses: taiki-e/install-action@cargo-deny

      - name: Run cargo-deny
        run: cargo deny check
```

**Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "feat: add cargo-deny license check to CI"
```

---

## Task 12: Add Package Metadata to Crate Cargo.toml Files

**Files:**
- Modify: `crates/hush-core/Cargo.toml`
- Modify: `crates/hush-proxy/Cargo.toml`
- Modify: `crates/clawdstrike/Cargo.toml`
- Modify: `crates/hush-cli/Cargo.toml`
- Modify: `crates/hushd/Cargo.toml`

**Step 1: Add publishing metadata to each crate**

For each crate, ensure these fields exist in `[package]`:

```toml
[package]
name = "<crate-name>"
description = "<description>"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
keywords = ["security", "verification", "ai-agent", "clawdstrike"]
categories = ["cryptography", "command-line-utilities"]
readme = "../../README.md"
```

**Step 2: Verify dry-run publish works**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo publish -p hush-core --dry-run 2>&1 | head -20`
Expected: Shows package info without errors (or expected missing field warnings)

**Step 3: Commit**

```bash
git add crates/*/Cargo.toml
git commit -m "chore: add publishing metadata to crate Cargo.toml files"
```

---

## Task 13: Final Verification

**Files:** (no new files)

**Step 1: Run full lint check**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo fmt --all -- --check`
Expected: PASS

**Step 2: Run clippy**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo clippy --workspace 2>&1 | tail -20`
Expected: Completes (warnings OK, no errors)

**Step 3: Run tests**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && cargo test --workspace 2>&1 | tail -20`
Expected: PASS

**Step 4: Verify all files created**

Run: `cd /Users/connor/Medica/clawdstrike-ws10-publish && ls -la .rustfmt.toml clippy.toml deny.toml mise.toml && ls -la .github/release.yml .github/workflows/release.yml scripts/bump-version.sh HomebrewFormula/hush.rb`
Expected: All 8 files exist

**Step 5: Final commit if needed**

```bash
git status
# If there are uncommitted changes:
git add -A
git commit -m "chore: final WS10 publishing setup adjustments"
```

---

## Summary of Deliverables

| File | Purpose |
|------|---------|
| `.rustfmt.toml` | Rust code formatting configuration |
| `clippy.toml` | Clippy cognitive complexity threshold |
| `Cargo.toml` (modified) | Workspace lint configuration |
| `deny.toml` | cargo-deny license and advisory checks |
| `mise.toml` | Tool version management |
| `.github/release.yml` | GitHub release notes template |
| `.github/workflows/release.yml` | Publishing workflow (crates.io, npm, PyPI) |
| `scripts/bump-version.sh` | Version synchronization script |
| `HomebrewFormula/hush.rb` | Homebrew formula for CLI |

## Required Secrets for Publishing

The release workflow requires these GitHub secrets to be configured:

1. `CARGO_REGISTRY_TOKEN` - crates.io API token
2. `NPM_TOKEN` - npm access token with publish scope
3. `PYPI_TOKEN` - PyPI API token (when hush-py exists)

These should be added to the repository settings before the first release.
