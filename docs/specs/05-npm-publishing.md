# Spec 05: Publish 11 TypeScript Packages to npm Under @clawdstrike/

**Status:** Draft
**Author:** spec-writers
**Date:** 2026-02-07
**Effort:** 3 engineer-days
**Dependencies:** Spec 04 (Apache 2.0 license migration -- for correct license in published packages)

---

## Summary / Objective

Publish 11 TypeScript packages to the npm registry under the `@clawdstrike` scope. Currently, all packages use `file:` protocol dependencies for inter-package references and several are marked `"private": true`, preventing npm publication. This spec migrates inter-package dependencies to semver ranges (e.g., `"@clawdstrike/adapter-core": "^0.1.0"`) and removes the `private` flag, enabling public npm publishing.

This implements the npm publishing track from Section 4.6 of `docs/research/open-source-strategy.md`, which targets `npm publish` as `@clawdstrike/*` packages coordinated with the 0.1.0 initial public release.

---

## Current State

### Package inventory

| # | Package Dir | npm Name | Private? | file: Deps | Peer Deps |
|---|-------------|----------|----------|------------|-----------|
| 1 | `packages/hush-ts` | `@clawdstrike/sdk` | No | `@clawdstrike/adapter-core` | None |
| 2 | `packages/clawdstrike-adapter-core` | `@clawdstrike/adapter-core` | No | None | None |
| 3 | `packages/clawdstrike-policy` | `@clawdstrike/policy` | Yes | `@clawdstrike/adapter-core` | None |
| 4 | `packages/clawdstrike-claude-code` | `@clawdstrike/claude-code` | Yes | `@clawdstrike/adapter-core` | None |
| 5 | `packages/clawdstrike-codex` | `@clawdstrike/codex` | Yes | `@clawdstrike/adapter-core` | None |
| 6 | `packages/clawdstrike-vercel-ai` | `@clawdstrike/vercel-ai` | Yes | `@clawdstrike/adapter-core`, `@clawdstrike/sdk` | `ai`, `@ai-sdk/react`, `react` |
| 7 | `packages/clawdstrike-langchain` | `@clawdstrike/langchain` | Yes | `@clawdstrike/adapter-core` | `@langchain/core` |
| 8 | `packages/clawdstrike-openclaw` | `@clawdstrike/clawdstrike-security` | No | `@clawdstrike/adapter-core`, `@clawdstrike/policy` | (to verify) |
| 9 | `packages/clawdstrike-opencode` | `@clawdstrike/opencode` | Yes | `@clawdstrike/adapter-core` | (to verify) |
| 10 | `packages/clawdstrike-hush-cli-engine` | `@clawdstrike/hush-cli-engine` | (to verify) | (to verify) | (to verify) |
| 11 | `packages/clawdstrike-hushd-engine` | `@clawdstrike/hushd-engine` | (to verify) | (to verify) | (to verify) |

A potential 12th package: the desktop app may have a publishable subset, but this is out of scope. The 11 packages listed above plus any additional adapter packages found during implementation constitute the target set.

### Cross-SDK dependencies

Three packages from the `@backbay` scope (`standalone/backbay-sdk/packages/`) are identified as reusable by other specs:

| Package | Used By | Purpose |
|---------|---------|---------|
| `@backbay/notary` | Specs 10, 13 | IPFS uploads (w3up-client), EAS attestations |
| `@backbay/witness` | Specs 07, 13 | Browser-side Ed25519/Merkle verification, EAS verification |
| `@backbay/witness-react` | Spec 07 | React verification UI components (`VerificationBadge`, `VerificationDetails`) |

When publishing `@clawdstrike/*` packages, consider whether shared crypto utilities (RFC 8785 canonical JSON, SHA-256 hashing) should be extracted from `@backbay/notary` into a shared `@backbay/crypto` or `@clawdstrike/crypto` package to avoid duplicating the canonical JSON implementation across `@clawdstrike/sdk` (hush-ts) and `@backbay/notary`.

### Key issues blocking npm publish

1. **`"private": true`** -- 7 of 11 packages are marked private, preventing `npm publish`.

2. **`file:` protocol dependencies** -- 10 of 11 packages use `"@clawdstrike/adapter-core": "file:../clawdstrike-adapter-core"` (or similar) for inter-package dependencies. npm resolves `file:` references relative to the filesystem, which fails when installed from the registry.

3. **Missing `repository` field** -- Only `@clawdstrike/sdk` has a `repository` field. npm packages should include this for discoverability.

4. **Missing `homepage` and `bugs` fields** -- Standard npm metadata for public packages.

5. **No npm scope ownership** -- The `@clawdstrike` npm scope must be created and access tokens provisioned.

6. **No CI publish workflow** -- There is no GitHub Actions workflow for automated npm publishing.

### Dependency graph

```
@clawdstrike/adapter-core (leaf -- no internal deps)
    ^
    |
    +-- @clawdstrike/sdk (depends on adapter-core)
    |       ^
    |       |
    |       +-- @clawdstrike/vercel-ai (depends on adapter-core + sdk)
    |
    +-- @clawdstrike/policy (depends on adapter-core)
    +-- @clawdstrike/claude-code (depends on adapter-core)
    +-- @clawdstrike/codex (depends on adapter-core)
    +-- @clawdstrike/langchain (depends on adapter-core)
    +-- @clawdstrike/clawdstrike-security (depends on adapter-core + policy)
    +-- @clawdstrike/opencode (depends on adapter-core)
    +-- @clawdstrike/hush-cli-engine (depends on adapter-core)
    +-- @clawdstrike/hushd-engine (depends on adapter-core)
```

**Publish order** (topological sort):
1. `@clawdstrike/adapter-core` (leaf)
2. `@clawdstrike/sdk` (depends on 1)
3. All remaining packages (depend on 1, some on 2)

---

## Target State

All 11+ packages are published to npmjs.com under the `@clawdstrike` scope:
- `@clawdstrike/adapter-core@0.1.0`
- `@clawdstrike/sdk@0.1.0`
- `@clawdstrike/policy@0.1.0`
- `@clawdstrike/claude-code@0.1.0`
- `@clawdstrike/codex@0.1.0`
- `@clawdstrike/vercel-ai@0.1.0`
- `@clawdstrike/langchain@0.1.0`
- `@clawdstrike/clawdstrike-security@0.1.0`
- `@clawdstrike/opencode@0.1.0`
- `@clawdstrike/hush-cli-engine@0.1.0`
- `@clawdstrike/hushd-engine@0.1.0`

Each package:
- Has `"private"` removed (or set to `false`)
- Uses semver range for internal deps: `"@clawdstrike/adapter-core": "^0.1.0"`
- Has complete npm metadata (`repository`, `homepage`, `bugs`, `keywords`)
- Has a minimal `README.md` with installation instructions
- Builds successfully via `npm run build` (or `tsup`)
- Passes tests via `npm test`
- Has `"files"` field restricting published content to `dist/` and `README.md`

A GitHub Actions workflow automates publishing on version tag pushes.

---

## Implementation Plan

### Step 1: Register the @clawdstrike npm scope

1. Create an npm organization at https://www.npmjs.com/org/create for `clawdstrike`
2. Generate an automation token for CI use
3. Store the token as a GitHub Actions secret (`NPM_TOKEN`)

### Step 2: Remove `"private": true` from all packages

For each `packages/*/package.json`, remove the `"private": true` line:

```diff
- "private": true,
```

### Step 3: Replace `file:` deps with semver ranges

For each package, replace `file:` references with caret ranges:

```diff
  "dependencies": {
-   "@clawdstrike/adapter-core": "file:../clawdstrike-adapter-core"
+   "@clawdstrike/adapter-core": "^0.1.0"
  }
```

```diff
  "dependencies": {
-   "@clawdstrike/adapter-core": "file:../clawdstrike-adapter-core",
-   "@clawdstrike/sdk": "file:../hush-ts"
+   "@clawdstrike/adapter-core": "^0.1.0",
+   "@clawdstrike/sdk": "^0.1.0"
  }
```

**Full change list:**

| Package | Dependency | Before | After |
|---------|-----------|--------|-------|
| `@clawdstrike/sdk` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/policy` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/claude-code` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/codex` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/vercel-ai` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/vercel-ai` | `@clawdstrike/sdk` | `file:../hush-ts` | `^0.1.0` |
| `@clawdstrike/langchain` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/clawdstrike-security` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/clawdstrike-security` | `@clawdstrike/policy` | `file:../clawdstrike-policy` | `^0.1.0` |
| `@clawdstrike/opencode` | `@clawdstrike/adapter-core` | `file:../clawdstrike-adapter-core` | `^0.1.0` |
| `@clawdstrike/hush-cli-engine` | (to verify) | `file:...` | `^0.1.0` |
| `@clawdstrike/hushd-engine` | (to verify) | `file:...` | `^0.1.0` |

### Step 4: Add standard npm metadata to all packages

Add the following fields to each `package.json` that is missing them:

```json
{
  "repository": {
    "type": "git",
    "url": "https://github.com/backbay-labs/clawdstrike.git",
    "directory": "packages/<package-dir>"
  },
  "homepage": "https://github.com/backbay-labs/clawdstrike",
  "bugs": {
    "url": "https://github.com/backbay-labs/clawdstrike/issues"
  },
  "keywords": [
    "clawdstrike",
    "security",
    "ai-agent",
    "sdr"
  ]
}
```

### Step 5: Add `publishConfig` for scoped public access

npm scoped packages are private by default on the registry. Add `publishConfig` to each package:

```json
{
  "publishConfig": {
    "access": "public"
  }
}
```

### Step 6: Ensure `"files"` field is present

Verify every package has a `"files"` array limiting published content:

```json
{
  "files": [
    "dist",
    "README.md"
  ]
}
```

This excludes source files, tests, and config files from the published tarball. Most packages already have this (confirmed for `hush-ts`, `adapter-core`, `claude-code`, `vercel-ai`, `langchain`, `policy`).

### Step 7: Add/update README.md for each package

Each package needs a minimal `README.md`:

```markdown
# @clawdstrike/<package-name>

<One-line description from package.json>

## Installation

```bash
npm install @clawdstrike/<package-name>
```

## Usage

See the [ClawdStrike documentation](https://github.com/backbay-labs/clawdstrike).

## License

Apache-2.0
```

### Step 8: Create npm workspace config (optional)

If the repository uses npm workspaces for local development, add a root `package.json`:

```json
{
  "private": true,
  "workspaces": [
    "packages/*"
  ]
}
```

This allows `npm install` at the root to link all packages for development. The root `package.json` stays `"private": true` -- it is NOT published.

**Important**: This root `package.json` must not interfere with the Moon/Bun workspace setup described in the parent `backbay/CLAUDE.md`. Since ClawdStrike is a standalone repo under `standalone/`, it can have its own workspace config.

### Step 9: Verify local build and test after dep changes

After replacing `file:` deps with semver ranges, local development linking breaks. To maintain both local development and npm publish compatibility, use npm workspaces:

```bash
# At repo root
npm install       # Links workspace packages
npm run build -w  # Build all packages
npm test -w       # Run all tests
```

### Step 10: Create GitHub Actions publish workflow

Create `.github/workflows/npm-publish.yml`:

```yaml
name: Publish npm packages

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm run build -w
      - run: npm test -w

      # Publish in topological order
      - name: Publish @clawdstrike/adapter-core
        run: npm publish -w packages/clawdstrike-adapter-core --provenance
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

      - name: Publish @clawdstrike/sdk
        run: npm publish -w packages/hush-ts --provenance
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

      - name: Publish remaining packages
        run: |
          for pkg in \
            packages/clawdstrike-policy \
            packages/clawdstrike-claude-code \
            packages/clawdstrike-codex \
            packages/clawdstrike-vercel-ai \
            packages/clawdstrike-langchain \
            packages/clawdstrike-openclaw \
            packages/clawdstrike-opencode \
            packages/clawdstrike-hush-cli-engine \
            packages/clawdstrike-hushd-engine; do
            npm publish -w "$pkg" --provenance || true
          done
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

The `--provenance` flag generates SLSA provenance attestations for the published packages, which is best practice for supply chain security.

### Step 11: Manual test publish with `--dry-run`

Before the first real publish, verify each package:

```bash
cd packages/clawdstrike-adapter-core
npm pack --dry-run
# Verify: only dist/ and README.md are included
# Verify: no file: references in the packed package.json
```

Repeat for all packages.

### Step 12: Publish initial 0.1.0 release

```bash
# Tag the release
git tag v0.1.0
git push origin v0.1.0

# GitHub Actions workflow triggers and publishes all packages
```

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `packages/clawdstrike-policy/package.json` | Modify | Remove `private`, replace `file:` deps, add metadata |
| `packages/clawdstrike-claude-code/package.json` | Modify | Same |
| `packages/clawdstrike-codex/package.json` | Modify | Same |
| `packages/clawdstrike-vercel-ai/package.json` | Modify | Same |
| `packages/clawdstrike-langchain/package.json` | Modify | Same |
| `packages/clawdstrike-openclaw/package.json` | Modify | Same |
| `packages/clawdstrike-opencode/package.json` | Modify | Same |
| `packages/clawdstrike-hush-cli-engine/package.json` | Modify | Same |
| `packages/clawdstrike-hushd-engine/package.json` | Modify | Same |
| `packages/hush-ts/package.json` | Modify | Replace `file:` dep, add `publishConfig` |
| `packages/clawdstrike-adapter-core/package.json` | Modify | Add metadata, `publishConfig` |
| `package.json` (root, new) | Create | npm workspaces config (`private: true`) |
| `.github/workflows/npm-publish.yml` | Create | CI publish workflow |
| `packages/*/README.md` | Create/Update | Minimal README for each package |

Total: ~13 package.json files modified, 1 root package.json created, 1 GHA workflow created, ~11 README files created/updated.

---

## Testing Strategy

### Pre-publish validation

1. **`npm pack --dry-run`** for each package -- Verify tarball contents include only `dist/` and `README.md`, no source files or `node_modules`.

2. **Inspect packed `package.json`** -- Verify no `file:` references remain:
   ```bash
   npm pack -w packages/clawdstrike-adapter-core
   tar -xzf clawdstrike-adapter-core-0.1.0.tgz
   cat package/package.json | grep "file:"
   # Should return nothing
   ```

3. **Cross-package resolution test** -- After publishing to a local registry (verdaccio) or using `npm link`, verify that installing `@clawdstrike/sdk` in a fresh project correctly resolves `@clawdstrike/adapter-core`:
   ```bash
   mkdir /tmp/test-install
   cd /tmp/test-install
   npm init -y
   npm install @clawdstrike/sdk
   node -e "const sdk = require('@clawdstrike/sdk'); console.log('OK')"
   ```

4. **Build from clean state** -- Clone the repo fresh, `npm install`, `npm run build -w`, `npm test -w`.

### Post-publish validation

5. **npm view** -- After publishing, verify package metadata:
   ```bash
   npm view @clawdstrike/sdk
   npm view @clawdstrike/adapter-core
   ```

6. **Fresh install test** -- In a new directory, install published packages and verify they work:
   ```bash
   npm install @clawdstrike/sdk @clawdstrike/claude-code
   ```

7. **Provenance verification** -- Check that SLSA provenance is attached:
   ```bash
   npm audit signatures
   ```

### Local development test

8. **npm workspaces symlinks** -- After the changes, verify `npm install` at root still links packages correctly for local development.

---

## Rollback Plan

### Before first publish

If issues are found before publishing, simply revert the `package.json` changes:
- Restore `"private": true` flags
- Restore `file:` protocol dependencies
- Delete root `package.json` and GHA workflow

### After publish

Published npm packages cannot be unpublished after 72 hours (npm policy). However:
1. **Deprecate**: `npm deprecate @clawdstrike/sdk@0.1.0 "Withdrawn, please wait for 0.1.1"`
2. **Publish fix**: Publish a corrected 0.1.1 version
3. **Unpublish** (within 72 hours): `npm unpublish @clawdstrike/sdk@0.1.0`

### Maintaining local development

If semver deps break local development (packages pulling from registry instead of local), ensure the npm workspaces config is correct. npm workspaces override registry resolution with local symlinks when the version satisfies the semver range.

---

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| npm scope `@clawdstrike` | To be created | Requires npmjs.com organization |
| NPM_TOKEN GitHub secret | To be created | Automation token for CI publishing |
| Spec 04 (Apache 2.0 license) | Recommended | Published packages should have correct license |
| GitHub Actions | Available | Repository already on GitHub |
| Node.js >= 20.19.0 | Required | Per engines field in `@clawdstrike/sdk` |
| All packages build + test green | Required | `npm run build -w && npm test -w` must pass |

---

## npm Scope and Access

### Scope creation

The `@clawdstrike` scope must be created as an npm organization (not a personal scope) to allow multiple maintainers:

```
Organization name: clawdstrike
Plan: Free (open source)
```

### Access levels

| Role | npm Access | Who |
|------|-----------|-----|
| Owner | Publish all packages, manage members | Founding team |
| Admin | Publish all packages | Core contributors |
| Member | Read-only | Community contributors |

### Token types

| Token | Scope | Use |
|-------|-------|-----|
| Automation | `@clawdstrike:*` publish | GitHub Actions CI |
| Granular (per-maintainer) | `@clawdstrike:*` publish | Manual publishes |

---

## Acceptance Criteria

- [ ] npm scope `@clawdstrike` is registered
- [ ] All 11 packages have `"private"` removed (or absent)
- [ ] All `file:` protocol dependencies are replaced with `"^0.1.0"` semver ranges
- [ ] All packages have `"publishConfig": { "access": "public" }`
- [ ] All packages have `repository`, `homepage`, `bugs` fields
- [ ] All packages have `"files"` field restricting to `dist/` and `README.md`
- [ ] All packages have a `README.md` with installation instructions
- [ ] `npm pack --dry-run` for each package shows no `file:` references and no source files
- [ ] Root `package.json` with npm workspaces config exists (private: true)
- [ ] `npm install && npm run build -w && npm test -w` succeeds from a clean checkout
- [ ] `.github/workflows/npm-publish.yml` exists with topological publish order
- [ ] (After publish) `npm view @clawdstrike/sdk` returns valid metadata
- [ ] (After publish) Fresh `npm install @clawdstrike/sdk` in a new project resolves correctly
- [ ] (After publish) All packages show SLSA provenance attestation
