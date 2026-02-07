# Spec 04: MIT to Apache 2.0 License Migration

**Status:** Draft
**Author:** spec-writers
**Date:** 2026-02-07
**Effort:** 1 engineer-day
**Dependencies:** None (can be done at any time)

---

## Summary / Objective

Migrate the ClawdStrike project license from MIT to Apache 2.0. This aligns with the open source strategy described in Section 4.1 of `docs/research/open-source-strategy.md`, which recommends Apache 2.0 for its explicit patent grant, enterprise adoption clarity, and CNCF ecosystem alignment (Cilium, Tetragon, Falco, SPIRE, and NATS all use Apache 2.0).

The migration touches the root `LICENSE` file, `Cargo.toml` workspace license field, all crate-level `Cargo.toml` files that inherit the workspace license, and all `package.json` files in the TypeScript packages.

---

## Current State

### Root LICENSE file

From `/Users/connor/Medica/backbay/standalone/clawdstrike/LICENSE`:
```
MIT License
Copyright (c) 2026 Backbay Industries
```

### Cargo.toml workspace

From `Cargo.toml` line 31:
```toml
[workspace.package]
license = "MIT"
```

All 14 workspace member crates inherit this via `license.workspace = true` in their individual `Cargo.toml` files (confirmed in `crates/spine/Cargo.toml` line 6, `crates/tetragon-bridge/Cargo.toml` line 6, `crates/hubble-bridge/Cargo.toml` line 6).

### TypeScript packages

All 11 TypeScript packages in `packages/` specify `"license": "MIT"` in their `package.json`:
- `packages/hush-ts/package.json` line 40
- `packages/clawdstrike-adapter-core/package.json` line 29
- `packages/clawdstrike-claude-code/package.json` line 33
- `packages/clawdstrike-policy/package.json` line 40
- And 7 more adapter packages

### Python package

`packages/hush-py/` likely has a license field in its `pyproject.toml` (to be confirmed during implementation).

### Vendor directory

`vendor/` contains third-party crate sources with their own licenses (MIT, Apache 2.0, BSD, etc.). These are NOT modified -- they retain their original licenses.

### `deny.toml`

The `deny.toml` file (cargo-deny config) may have license allowlists that need updating.

---

## Target State

- Root `LICENSE` file contains the full Apache License, Version 2.0 text
- `Cargo.toml` workspace package has `license = "Apache-2.0"`
- All 14 Rust crates inherit `Apache-2.0` via `license.workspace = true`
- All 11 TypeScript packages have `"license": "Apache-2.0"` in their `package.json`
- Python package (if applicable) has `license = "Apache-2.0"` in `pyproject.toml`
- `deny.toml` license allowlist includes `Apache-2.0`
- A `NOTICE` file is created (required by Apache 2.0 Section 4d)
- Copyright header convention documented for new files

---

## Implementation Plan

### Step 1: Replace the LICENSE file

Replace the contents of `LICENSE` with the standard Apache License, Version 2.0 text from https://www.apache.org/licenses/LICENSE-2.0.txt.

The copyright notice in the `NOTICE` file (not the LICENSE file itself) will read:

```
ClawdStrike
Copyright 2026 Backbay Industries

This product includes software developed at Backbay Industries.
```

Note: Apache 2.0's LICENSE file is the standard boilerplate text and does NOT contain a copyright line (unlike MIT). Copyright attribution goes in the `NOTICE` file per Section 4(d).

### Step 2: Create NOTICE file

Create `NOTICE` at the repository root:

```
ClawdStrike
Copyright 2026 Backbay Industries

This product includes software developed at Backbay Industries
(https://backbay.industries/).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### Step 3: Update Cargo.toml workspace license

Change line 31 of `Cargo.toml`:

```toml
# Before:
license = "MIT"

# After:
license = "Apache-2.0"
```

This automatically propagates to all 14 workspace member crates that use `license.workspace = true`.

### Step 4: Update all TypeScript package.json files

For each of the 11 packages in `packages/*/package.json`, change:

```json
// Before:
"license": "MIT"

// After:
"license": "Apache-2.0"
```

Files to update:
1. `packages/hush-ts/package.json`
2. `packages/clawdstrike-adapter-core/package.json`
3. `packages/clawdstrike-claude-code/package.json`
4. `packages/clawdstrike-codex/package.json`
5. `packages/clawdstrike-hush-cli-engine/package.json`
6. `packages/clawdstrike-hushd-engine/package.json`
7. `packages/clawdstrike-langchain/package.json`
8. `packages/clawdstrike-openclaw/package.json`
9. `packages/clawdstrike-opencode/package.json`
10. `packages/clawdstrike-vercel-ai/package.json`
11. `packages/clawdstrike-policy/package.json`

### Step 5: Update Python package (if applicable)

Check `packages/hush-py/pyproject.toml` for a license field and update it. Note that pyproject.toml uses the PEP 639 table format:

```toml
# Before:
license = { text = "MIT" }

# After:
license = { text = "Apache-2.0" }
```

Also update the Python classifiers from `"License :: OSI Approved :: MIT License"` to `"License :: OSI Approved :: Apache Software License"` in the `[project]` classifiers list.

Also check for a `license` field in `packages/hush-py/hush-native/Cargo.toml` (the PyO3 native extension). **Note:** `hush-native/Cargo.toml` has `license = "MIT"` hardcoded on line 6 -- it does **not** use `license.workspace = true`. This must be manually changed to `license = "Apache-2.0"` since it will not be updated automatically by the workspace license change in Step 3.

### Step 6: Update deny.toml (if needed)

Check if `deny.toml` has a license allowlist. If Apache 2.0 is already allowed (which it likely is since many dependencies use it), no change is needed. If not, add it:

```toml
[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    # ... other allowed licenses
]
```

### Step 7: Update desktop app Tauri config (if applicable)

Check `apps/desktop/src-tauri/Cargo.toml` and `apps/desktop/src-tauri/tauri.conf.json` for license fields.

### Step 8: Update README/docs references

Search for any references to "MIT License" in markdown files and update them:

```bash
grep -r "MIT License" --include="*.md" .
grep -r '"MIT"' --include="*.json" .
grep -r "license.*MIT" --include="*.toml" .
```

### Step 9: Verify with cargo-deny

```bash
cargo deny check licenses
```

This ensures all workspace crates now report Apache-2.0 and no license conflicts exist.

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `LICENSE` | Replace | MIT text -> Apache License 2.0 full text |
| `NOTICE` | Create | Copyright attribution (required by Apache 2.0 Section 4d) |
| `Cargo.toml` | Modify | `license = "MIT"` -> `license = "Apache-2.0"` |
| `packages/hush-ts/package.json` | Modify | `"license": "MIT"` -> `"license": "Apache-2.0"` |
| `packages/clawdstrike-adapter-core/package.json` | Modify | Same |
| `packages/clawdstrike-claude-code/package.json` | Modify | Same |
| `packages/clawdstrike-codex/package.json` | Modify | Same |
| `packages/clawdstrike-hush-cli-engine/package.json` | Modify | Same |
| `packages/clawdstrike-hushd-engine/package.json` | Modify | Same |
| `packages/clawdstrike-langchain/package.json` | Modify | Same |
| `packages/clawdstrike-openclaw/package.json` | Modify | Same |
| `packages/clawdstrike-opencode/package.json` | Modify | Same |
| `packages/clawdstrike-vercel-ai/package.json` | Modify | Same |
| `packages/clawdstrike-policy/package.json` | Modify | Same |
| `packages/hush-py/pyproject.toml` | Modify | Update license field (if present) |
| `deny.toml` | Modify (if needed) | Ensure Apache-2.0 is in allowlist |

Total: ~16 files modified, 1 file created, 1 file replaced.

---

## Testing Strategy

1. **`cargo build --workspace`** -- Verifies Cargo.toml changes don't break the build.

2. **`cargo deny check licenses`** -- Verifies all crates report the correct license and no conflicts exist with dependencies.

3. **`cargo metadata --format-version 1 | jq '.packages[] | select(.source == null) | .license'`** -- Verifies all workspace crates show `"Apache-2.0"`.

4. **Manual inspection** -- Verify `LICENSE` file contains the full Apache 2.0 text (not a truncated version). The standard text is 11,556 bytes.

5. **grep for stragglers** -- Search for any remaining "MIT" license references:
   ```bash
   grep -rn '"MIT"' --include="*.json" packages/
   grep -rn 'license.*=.*"MIT"' --include="*.toml" crates/
   ```
   Should return zero results for first-party files (vendor/ excluded).

6. **NOTICE file exists** -- Verify `NOTICE` file is present at the repo root.

---

## Rollback Plan

License changes are trivially reversible:

1. Revert the `LICENSE` file to the MIT text
2. Change `Cargo.toml` back to `license = "MIT"`
3. Revert all `package.json` files
4. Delete the `NOTICE` file

Since the license is metadata (not code), reverting has zero runtime impact.

**Important**: If any releases have been published under Apache 2.0, those releases remain under Apache 2.0. License changes only apply to subsequent releases. This is not a concern at the current version (0.1.0, pre-public release).

---

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| Legal review | Recommended | Confirm all contributors consent to license change |
| No external contributors yet | Simplifies migration | No CLA/DCO needed retroactively |
| Research doc Section 4.1 | Reference | `docs/research/open-source-strategy.md` |

---

## Legal Considerations

### Contributor consent

Since ClawdStrike is currently a private repository with contributions solely from Backbay Industries employees, the copyright holder (Backbay Industries) has full authority to change the license. No external contributor consent is needed.

If there are any external contributors, their consent should be obtained before the license change. This can be done via a GitHub issue or email confirmation.

### MIT -> Apache 2.0 compatibility

MIT is permissive and one-way compatible with Apache 2.0. Code previously licensed under MIT can be relicensed under Apache 2.0 by the copyright holder. Apache 2.0 adds:
- Explicit patent grant (Section 3)
- Patent termination clause (Section 3, "if You institute patent litigation")
- Requirement to include NOTICE file (Section 4d)
- Requirement to state changes in modified files (Section 4b)

### Impact on downstream users

Users of MIT-licensed releases (0.1.0) can continue using those specific releases under MIT. New releases (0.2.0+) will be under Apache 2.0. Apache 2.0 is strictly more permissive in terms of patent rights, so this should not block any current users.

---

## Acceptance Criteria

- [ ] `LICENSE` file contains the full Apache License, Version 2.0 text (201 lines, ~11.5KB)
- [ ] `NOTICE` file exists at repository root with copyright attribution
- [ ] `Cargo.toml` workspace package has `license = "Apache-2.0"`
- [ ] All 14 Rust workspace members inherit `Apache-2.0` via `license.workspace = true`
- [ ] All 11 TypeScript packages have `"license": "Apache-2.0"` in `package.json`
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo deny check licenses` passes (if cargo-deny is configured)
- [ ] `grep -rn '"MIT"' --include="*.json" packages/` returns zero results
- [ ] `grep -rn 'license.*=.*"MIT"' --include="*.toml" crates/` returns zero results
- [ ] No references to "MIT License" remain in first-party markdown or config files
