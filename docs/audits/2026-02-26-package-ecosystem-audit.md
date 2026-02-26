# Package Ecosystem Documentation Audit — 2026-02-26

## Summary
- Files audited: 42
- Total findings: 24
- Critical (outdated/wrong): 5
- Missing (should exist but doesn't): 6
- Improvement (could be better): 13

---

## Findings

### Adapter Packages

#### 1. adapter-core README references `@clawdstrike/engine-local` import that is not a dependency
- **File:** `packages/adapters/clawdstrike-adapter-core/README.md:35-36`
- **Severity:** Critical
- **Issue:** The "Generic tool runner wrapper" code example imports `createStrikeCell` from `@clawdstrike/engine-local`, but `@clawdstrike/adapter-core` does not declare `@clawdstrike/engine-local` as a dependency or peerDependency in its `package.json`.
- **Evidence:** `packages/adapters/clawdstrike-adapter-core/package.json` has zero runtime dependencies.
- **Fix:** Add a note that `@clawdstrike/engine-local` must be installed separately, or add it to the install command at the top of the README.

#### 2. adapter-core README install section is incomplete
- **File:** `packages/adapters/clawdstrike-adapter-core/README.md:9-11`
- **Severity:** Improvement
- **Issue:** The install section only shows `npm install @clawdstrike/adapter-core`. The usage examples below require `@clawdstrike/engine-local` as well. Other adapter READMEs (langchain, claude, openai) include the engine in the install command.
- **Fix:** Add a note or separate install block for the engine dependency needed by the examples.

#### 3. openclaw README is minimal — no install command, no API examples
- **File:** `packages/adapters/clawdstrike-openclaw/README.md`
- **Severity:** Improvement
- **Issue:** The README is only 10 lines and defers everything to the getting-started guide. It lacks basic install commands (`npm install @clawdstrike/openclaw`), version information, or quick usage examples. Every other adapter README includes at least an install command and a code snippet.
- **Evidence:** Compare with `packages/adapters/clawdstrike-vercel-ai/README.md` (101 lines with full examples).
- **Fix:** Add at minimum an install command and a short usage snippet, keeping the link to the full getting-started guide.

#### 4. openclaw getting-started guide uses legacy schema `clawdstrike-v1.0` without noting canonical version
- **File:** `packages/adapters/clawdstrike-openclaw/docs/getting-started.md:41`
- **Severity:** Improvement
- **Issue:** The policy example uses `version: "clawdstrike-v1.0"`. The codebase shows this is a legacy schema that is translated to canonical `1.1.0` (see `packages/policy/clawdstrike-policy/src/policy/legacy.ts:41`). The CLAUDE.md says the schema is v1.1.0. New users should be directed to the canonical schema.
- **Evidence:** `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts:76` logs a warning: `"Loaded legacy OpenClaw policy schema (clawdstrike-v1.0); canonical 1.2.0 is preferred."`
- **Fix:** Update the getting-started guide example to use canonical schema version `1.2.0` (or at least `1.1.0`), or add a note that `clawdstrike-v1.0` is a legacy alias.

#### 5. openclaw getting-started built-in rulesets list is incomplete
- **File:** `packages/adapters/clawdstrike-openclaw/docs/getting-started.md:191-194`
- **Severity:** Improvement
- **Issue:** Lists only 2 rulesets (`clawdstrike:ai-agent-minimal` and `clawdstrike:ai-agent`). The main project CLAUDE.md lists: `permissive`, `default`, `strict`, `ai-agent`, `cicd`. The `rulesets/` directory also contains `remote-desktop`, `remote-desktop-permissive`, `remote-desktop-strict`, and `ai-agent-posture`.
- **Fix:** Either list all canonical rulesets or link to the canonical rulesets directory/docs.

#### 6. hello-secure-agent example references `npm install` but has no package.json
- **File:** `packages/adapters/clawdstrike-openclaw/examples/hello-secure-agent/README.md:12`
- **Severity:** Critical
- **Issue:** The setup instructions say `npm install` but the example directory contains only `README.md`, `openclaw.json`, `policy.yaml`, and `skills/hello/SKILL.md` -- there is no `package.json`.
- **Evidence:** `packages/adapters/clawdstrike-openclaw/examples/hello-secure-agent/` contents verified via Glob.
- **Fix:** Either add a `package.json` or remove the `npm install` step from the README.

#### 7. hello-secure-agent example testing command references non-existent test
- **File:** `packages/adapters/clawdstrike-openclaw/examples/hello-secure-agent/README.md:47`
- **Severity:** Critical
- **Issue:** The README ends with `npm test` but there are no test files in the example directory and no `package.json` to define a test script.
- **Fix:** Remove the testing section or add actual test files.

#### 8. vercel-ai README install command includes `ai` as separate install
- **File:** `packages/adapters/clawdstrike-vercel-ai/README.md:10`
- **Severity:** Improvement
- **Issue:** Install command is `npm install @clawdstrike/vercel-ai @clawdstrike/engine-local ai`. The `ai` package is listed as an optional peerDependency in `package.json:32`. The `@clawdstrike/engine-local` is not a dependency at all. This works but could confuse users since `ai` may already be installed.
- **Fix:** Minor -- note that `ai` and `@clawdstrike/engine-local` are peer/optional dependencies that must be provided by the user.

#### 9. vercel-ai README does not document the `./react` subpath export
- **File:** `packages/adapters/clawdstrike-vercel-ai/README.md`
- **Severity:** Improvement
- **Issue:** The `package.json` exports `"./react"` (`packages/adapters/clawdstrike-vercel-ai/package.json:13-16`) but the README does not mention React integration or the `@clawdstrike/vercel-ai/react` import.
- **Fix:** Add a section documenting the React subpath export.

#### 10. langchain README install lists `@clawdstrike/adapter-core` redundantly
- **File:** `packages/adapters/clawdstrike-langchain/README.md:11`
- **Severity:** Improvement
- **Issue:** Install command is `npm install @clawdstrike/langchain @clawdstrike/adapter-core @clawdstrike/engine-local`. Since `@clawdstrike/adapter-core` is already a direct dependency of `@clawdstrike/langchain` (see `package.json:22`), listing it in the install command is redundant.
- **Fix:** Simplify to `npm install @clawdstrike/langchain @clawdstrike/engine-local`.

#### 11. langchain README does not document LangGraph integration
- **File:** `packages/adapters/clawdstrike-langchain/README.md`
- **Severity:** Improvement
- **Issue:** The source exports LangGraph-specific APIs (`createSecurityCheckpoint`, `addSecurityRouting`, `sanitizeState`, `wrapToolNode` from `packages/adapters/clawdstrike-langchain/src/index.ts:13`) but the README only documents basic tool wrapping and the callback handler.
- **Fix:** Add a section documenting LangGraph integration.

#### 12. claude README install lists `@clawdstrike/adapter-core` redundantly
- **File:** `packages/adapters/clawdstrike-claude/README.md:12`
- **Severity:** Improvement
- **Issue:** Same as finding #10. `@clawdstrike/adapter-core` is already a direct dependency (`package.json:22`).
- **Fix:** Simplify to `npm install @clawdstrike/claude @clawdstrike/engine-local`.

#### 13. openai README install lists `@clawdstrike/adapter-core` redundantly
- **File:** `packages/adapters/clawdstrike-openai/README.md:12`
- **Severity:** Improvement
- **Issue:** Same pattern. `@clawdstrike/adapter-core` is a direct dependency.
- **Fix:** Simplify to `npm install @clawdstrike/openai @clawdstrike/engine-local`.

#### 14. opencode README install lists `@clawdstrike/adapter-core` redundantly
- **File:** `packages/adapters/clawdstrike-opencode/README.md:10`
- **Severity:** Improvement
- **Issue:** Same pattern.
- **Fix:** Simplify to `npm install @clawdstrike/opencode @clawdstrike/engine-local`.

---

### SDK Packages

#### 15. hush-ts README title says `@clawdstrike/sdk` but directory is `hush-ts`
- **File:** `packages/sdk/hush-ts/README.md:1`
- **Severity:** Improvement
- **Issue:** Not a bug (the npm name is `@clawdstrike/sdk`), but the discrepancy between directory name `hush-ts` and package name `@clawdstrike/sdk` could confuse contributors navigating the repo. This is a known convention but could benefit from a one-line note.
- **Fix:** Optional -- add a note like "Published as `@clawdstrike/sdk` on npm."

#### 16. hush-ts README lists only 5 guards; source exports 7
- **File:** `packages/sdk/hush-ts/README.md:18`
- **Severity:** Critical
- **Issue:** The README features list says "Security guards: ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool" (5 guards). The source (`packages/sdk/hush-ts/src/index.ts:99-102`) also exports `PromptInjectionGuard` and `JailbreakGuard`. The CLAUDE.md lists 7 built-in guards.
- **Evidence:** `packages/sdk/hush-ts/src/index.ts:99` exports `PromptInjectionGuard`; line 101 exports `JailbreakGuard`.
- **Fix:** Add `PromptInjectionGuard` and `JailbreakGuard` to the guards list and to the Guards section of the README.

#### 17. hush-ts README Guards section only shows 3 of 7 guards
- **File:** `packages/sdk/hush-ts/README.md:119-147`
- **Severity:** Critical
- **Issue:** The Guards code example and API reference only demonstrate `ForbiddenPathGuard`, `EgressAllowlistGuard`, and `SecretLeakGuard`. Missing: `PatchIntegrityGuard`, `McpToolGuard`, `PromptInjectionGuard`, `JailbreakGuard`.
- **Fix:** Add usage examples or at least API reference entries for all 7 guards.

#### 18. hush-py README pip package name may be incorrect
- **File:** `packages/sdk/hush-py/README.md:8`
- **Severity:** Improvement
- **Issue:** The install command says `pip install clawdstrike`. The `pyproject.toml` (`packages/sdk/hush-py/pyproject.toml:2`) confirms the project name is `clawdstrike`, so this is correct. However, the README title says "clawdstrike" (lowercase) while the Python module path is `src/clawdstrike` -- this is fine but worth noting the package is not yet published to PyPI (the README mentions "Experimental native bindings (not yet published)" but doesn't clarify the main package's PyPI status).
- **Fix:** Add a note about whether the package is published to PyPI or install-from-source only.

#### 19. `packages/sdk/README.md` omits the `clawdstrike` unscoped package
- **File:** `packages/sdk/README.md:5-6`
- **Severity:** Missing
- **Issue:** The SDK README lists only `hush-ts` and `hush-py` but the directory also contains `packages/sdk/clawdstrike/` (the unscoped convenience package).
- **Fix:** Add `clawdstrike` (unscoped npm package) to the list.

---

### Crate READMEs

#### 20. No individual README files for any crate under `crates/libs/` (except hush-wasm)
- **File:** `crates/libs/clawdstrike/`, `crates/libs/hush-core/`, `crates/libs/hush-proxy/`, `crates/libs/hush-certification/`, `crates/libs/hush-multi-agent/`, `crates/libs/spine/`, `crates/libs/hush-ffi/`
- **Severity:** Missing
- **Issue:** Of 8 library crates, only `hush-wasm` has its own README. The other 7 point their Cargo.toml `readme` field to `../../README.md` (the repo root README), which is standard for crates.io but means there is no crate-specific documentation within the crate directory. Key crates like `clawdstrike` (the main library) and `hush-core` (crypto primitives) would benefit from their own READMEs.
- **Fix:** At minimum, add READMEs for `clawdstrike` and `hush-core` crates, describing their public API surface and usage.

#### 21. No individual README files for any service or bridge crate
- **File:** `crates/services/hush-cli/`, `crates/services/hushd/`, `crates/services/cloud-api/`, `crates/services/eas-anchor/`, `crates/services/spine-cli/`, `crates/bridges/hubble-bridge/`, `crates/bridges/tetragon-bridge/`
- **Severity:** Missing
- **Issue:** None of the 5 service crates or 2 bridge crates have their own README files. Service crates like `hush-cli` and `hushd` are user-facing and would benefit from crate-level documentation.
- **Fix:** Add READMEs for at least `hush-cli` and `hushd`, the primary user-facing services.

#### 22. hush-wasm README npm package name `@clawdstrike/wasm` vs Cargo crate name `hush-wasm`
- **File:** `crates/libs/hush-wasm/README.md:1`
- **Severity:** Improvement
- **Issue:** The README title says `@clawdstrike/wasm` (the npm package name) but this file lives in a Rust crate directory (`crates/libs/hush-wasm`). The Cargo.toml names the crate `hush-wasm`. The README primarily documents the npm package. There is no mention of the Rust crate's API or how it relates to the npm package.
- **Fix:** Add a brief note about the Rust crate name (`hush-wasm`) and that the npm package is the WASM build artifact.

---

### App READMEs

#### 23. `apps/cloud-dashboard/` has no README
- **File:** `apps/cloud-dashboard/`
- **Severity:** Missing
- **Issue:** The `apps/README.md` lists `apps/cloud-dashboard/` as "web dashboard app" but the directory has no README. It does contain source code (`src/`, `package.json`, tests, etc.) but no documentation.
- **Evidence:** Glob found no `apps/cloud-dashboard/README.md`.
- **Fix:** Add a README describing the cloud dashboard, its purpose, setup, and dev commands.

#### 24. `packages/sdk/README.md` and category READMEs are minimal stubs
- **File:** `packages/sdk/README.md`, `packages/adapters/README.md`, `packages/policy/README.md`, `crates/libs/README.md`, `crates/services/README.md`, `crates/bridges/README.md`, `crates/tests/README.md`
- **Severity:** Missing
- **Issue:** These 7 category-level READMEs are 1-4 line stubs. While they serve as navigation markers, they do not provide useful information beyond what the directory name implies. Some are missing the full list of contents (e.g., `packages/sdk/README.md` omits the `clawdstrike` package).
- **Fix:** Expand each to include a complete list of sub-packages/crates with one-line descriptions and links.

---

## Cross-Cutting Observations

### Version Consistency
All TypeScript packages are at version `0.1.2` (matching the latest release `0b14ef4e`). The Rust workspace version is also `0.1.2`. The Python SDK is `0.1.2`. Versions are consistent across the ecosystem.

### Package Name ↔ Directory Name Mapping
Several packages have directory names that differ from their npm/crate names:
- `packages/sdk/hush-ts` → `@clawdstrike/sdk`
- `packages/adapters/clawdstrike-hush-cli-engine` → `@clawdstrike/engine-local`
- `packages/adapters/clawdstrike-hushd-engine` → `@clawdstrike/engine-remote`
- `crates/libs/spine` → crate `hush-spine`

This is a known convention but could be documented in a mapping table.

### Policy Schema Version Drift
The CLAUDE.md says the policy schema is "v1.1.0". The canonical rulesets use both `1.1.0` and `1.2.0`. The OpenClaw adapter uses legacy `clawdstrike-v1.0`. The `@clawdstrike/policy` validator accepts `1.1.0` and `1.2.0`. The CLAUDE.md should be updated to reflect that `1.2.0` is now in use.
