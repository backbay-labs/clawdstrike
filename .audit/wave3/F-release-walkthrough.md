# `release.yml` Walkthrough

**File:** `/Users/connor/Medica/backbay/standalone/clawdstrike/.github/workflows/release.yml`
**Size:** 1,267 lines, 13 jobs, 6 distinct artifact streams.
**Workspace version (Cargo + npm + py):** `0.2.7` (per `Cargo.toml` line 60, `pyproject.toml` line 4, every published `package.json`).
**Trigger:** `push: tags: [v*]` or `workflow_dispatch` with strict semver input.

## Summary

> **Headline:** Of the 6 artifact streams this workflow declares, **only ~5 of the 14 publish‑eligible Rust crates can actually move with each tag today**. The other 9 publish‑eligible crates are silently excluded by a hand‑maintained allow‑list (`release.yml:135`) because the upstream `clawdstrike` crate cannot dry‑run against crates.io. NPM (19 public packages) and PyPI (`clawdstrike` pure + 3 native wheel matrices) work; GitHub Release assets, Homebrew tap update, and Tauri DMG notarization work; Docker images and Helm charts are deliberately handled by sibling workflows (`docker.yml`, `helm-release.yml`) and are **not** in `release.yml` at all. No SBOMs, no cosign signatures, no SLSA provenance beyond `npm publish --provenance`.

The workflow's headline pathology is a **chicken-and-egg between `clawdstrike` (workspace lib) and its vendored deps `hushspec` and `nono`**. Both deps are vendored under `infra/vendor/` and `vendor/` with `publish = false` (hushspec) or a name collision (nono — `crates.io/nono` is `always-further`'s sandboxing crate, but `infra/vendor/nono` is **also** `always-further/nono` at an older `0.11.0` revision; the published `nono` is at `0.57.0`). `clawdstrike` declares `path = "../../../vendor/hushspec"` and `nono = { workspace = true }` whose workspace entry is `path = "infra/vendor/nono"`. `cargo publish` strips `path` deps but cannot resolve them at `version = "0.1.1"` (hushspec, unpublished) or `version = "0.11.0"` (nono, the upstream registry version is `0.57.0`). Therefore every reverse dep of `clawdstrike` is also blocked: `clawdstrike-policy-event`, `hunt-scan`, `hunt-query`, `hunt-correlate`, `hush-cli`, `clawdstrike-logos`.

## Job Inventory

| # | Job | Lines | Artifact stream | Status |
|---|-----|-------|-----------------|--------|
| 1 | `resolve-version` | 27–54 | (none — derives `version` / `tag`) | Working |
| 2 | `preflight` | 56–108 | (none — `cargo test`, `cargo clippy`, macOS packaging template check) | Working |
| 3 | `publish-crates` | 110–212 | crates.io (Rust) | **Partial / dry-run-only for half the workspace** |
| 4 | `publish-npm` | 214–422 | npmjs.org (public TS packages) | Working (topo-sort, idempotent) |
| 5 | `publish-wasm-npm` | 424–490 | npmjs.org (`@clawdstrike/wasm`) | Working |
| 6 | `pypi-detect` | 492–566 | (probes PyPI, gates `publish-pypi`) | Working |
| 7 | `build-pypi-native-wheels` | 568–699 | cibuildwheel matrix → `pypi-native-wheels-{linux,macos,windows}` | Working (manylinux, macOS x86_64+arm64, win AMD64) |
| 8 | `publish-pypi` | 701–785 | PyPI (`clawdstrike` pure wheel + sdist + 3 native wheels) | Working |
| 9 | `build-binaries` | 787–887 | GH Release tarballs (`clawdstrike-{linux,darwin-x86_64,darwin-aarch64}.tar.gz`) + raw binaries | Working |
| 10 | `build-hushd-binaries` | 889–966 | GH Release `hushd-*` binaries | Working (but duplicates job 9; `hushd` is already built and shipped in job 9's tarballs at lines 877–879) |
| 11 | `build-agent-dmg` | 968–1068 | GH Release `*.dmg` + notarization evidence | Working **only with secrets configured**; falls through silently when `APPLE_*` env vars are empty |
| 12 | `create-release` | 1070–1182 | GitHub Release + OTA manifests (`hushd-ota-manifest-{stable,beta}.json`) | Working |
| 13 | `update-homebrew` | 1184–1267 | `backbay-labs/homebrew-tap` formula | Working (requires `HOMEBREW_TAP_GITHUB_TOKEN`) |

**Artifact streams not in this workflow:** Docker images (`.github/workflows/docker.yml` → `ghcr.io/backbay-labs/clawdstrike/<svc>`), Helm charts (`.github/workflows/helm-release.yml`), desktop binaries (`desktop-release.yml`), FFI bindings (`ffi-bindings.yml`), formal verification (`formal-verification.yml`).

## Per-Artifact Analysis

### Rust crates

`release.yml:135`:

> ```bash
> crates=(logos-ffi clawdstrike-ocsf hush-core hush-proxy hush-spine)
> ```

That literal list is also the `publish_with_retry` invocation order at lines 204–208. Cross‑checked against `Cargo.toml`:

| Crate | In allow-list? | On crates.io | Notes |
|-------|----------------|--------------|-------|
| `logos-ffi` | **yes** | NOT FOUND (will be the first publish at `0.2.7`) | Leaf crate, zero internal deps. |
| `clawdstrike-ocsf` | **yes** | `0.2.5` (this PR pushes `0.2.7`) | Leaf, only `serde/chrono/uuid/sha2`. |
| `hush-core` | **yes** | `0.2.7` already published | Leaf. Will hit the `already exists on crates.io index` short-circuit at line 183. |
| `hush-proxy` | **yes** | `0.2.7` already published | Leaf (only `thiserror/serde/globset`). Same short-circuit. |
| `hush-spine` (crate name; dir `crates/libs/spine`, manifest name `hush-spine`) | **yes** | `0.2.7` already published | Depends on `hush-core` only. |
| **`clawdstrike`** | **NO** (excluded) | `0.2.5` | Comment at `release.yml:131`: *"dry-run fails against crates.io's hushspec/nono surface."* Root cause below. |
| `clawdstrike-policy-event` | **NO** | `0.2.5` | Transitively blocked: `clawdstrike = { workspace = true, default-features = false, features = ["policy-event"] }` (`Cargo.toml`). |
| `hunt-scan` | **NO** | `0.2.5` | `clawdstrike = { workspace = true, features = ["full"] }`. |
| `hunt-query` | **NO** | `0.2.5` | Same transitive dep. |
| `hunt-correlate` | **NO** | `0.2.5` | Same transitive dep. |
| `hush-cli` | **NO** | `0.2.5` | Depends on `clawdstrike`, `hunt-scan`, `hunt-query`, `hunt-correlate`, `clawdstrike-logos`. Also ships the `clawdstrike` and `hush` binaries — currently the binaries on GH Releases are built locally inside the runner from the workspace tree, not pulled from crates.io. |
| `clawdstrike-logos` | **NO** | NOT FOUND | Depends on `clawdstrike`. |
| `clawdstrike-broker-protocol` | n/a | n/a | `publish = false` (line 4 of its `Cargo.toml`). |
| `hush-certification` | n/a | n/a | `publish = false`. |
| `hush-multi-agent` | n/a | n/a | `publish = false`. |
| `hushd` | n/a | n/a | `publish = false`. Daemon binary is shipped via GH Release artifacts only. |
| `clawdstrike-brokerd` / `control-api` / `clawdstrike-registry` | n/a | n/a | All `publish = false`. |
| `eas-anchor` | implicitly excluded | NOT FOUND | No `publish = false` line, but not in the allow-list. |
| `spine-cli`, `bridge-runtime`, `clawdstrike-guard-sdk*`, `hush-ffi`, all bridges | implicitly excluded | NOT FOUND | Same. |

**Verdict:** Of 14 Rust crates that *could* publish (no `publish = false`), only 5 do, and 3 of those 5 are already at the target version. So per release tag, the workflow effectively pushes **2 new versions** (`logos-ffi@0.2.7`, `clawdstrike-ocsf@0.2.7`) plus idempotent no-ops on the other 3.

#### Hardcoded crate publish order (`release.yml:204–208`)

> ```bash
> publish_with_retry logos-ffi
> publish_with_retry clawdstrike-ocsf
> publish_with_retry hush-core
> publish_with_retry hush-proxy
> publish_with_retry hush-spine
> ```

Reconstructed DAG (from the `[dependencies]` blocks I inspected):

```
hush-core      (leaf)
hush-proxy     (leaf — only thiserror/serde/globset)
logos-ffi      (leaf — only serde/chrono/sha2)
clawdstrike-ocsf (leaf — only serde/chrono/uuid/sha2)
hush-spine     → hush-core
```

Any topological order works; the chosen order is valid. The placement of `hush-spine` last is correct (it's the only crate in this five with an internal edge). However, the **30-second retry on "no matching package named" / "failed to get …"** at line 188 is the load-bearing piece: even with the right order, crates.io's index lag (≈30–90 s) means `hush-spine` is published before `hush-core@0.2.7` is index-visible, so the retry loop is what makes this work in practice rather than the ordering.

#### `clawdstrike` dry-run failure — root cause

The comment at `release.yml:128–134`:

> ```
> # Keep this list to crates that currently pass `cargo publish --dry-run`
> # against registry dependencies.
> #
> # The remaining 0.2.7-drifting public crates stay excluded for now:
> # - clawdstrike: dry-run fails against crates.io's hushspec/nono surface
> # - clawdstrike-policy-event, hunt-scan, hunt-query, hunt-correlate, hush-cli,
> #   clawdstrike-logos: blocked transitively on clawdstrike 0.2.7 being unpublished
> ```

`crates/libs/clawdstrike/Cargo.toml:31–33`:

> ```toml
> nono = { workspace = true, optional = true }
> hushspec = { version = "0.1.1", path = "../../../vendor/hushspec", optional = true }
> ```

Cross-checked:

1. **`hushspec`** (`vendor/hushspec/Cargo.toml`) declares `publish = false` at line 11. `version = "0.1.1"`. **Not published to crates.io** (`curl crates.io/api/v1/crates/hushspec` returns the published `hushspec@0.1.1` from a *different* publisher unrelated to this fork — actually `crates.io/hushspec` returns `0.1.1`, the same version, but it's owned by `backbay-labs`; however the vendored fork has local edits and `publish = false`, so the package the workspace *uses* is **not** the registry version). When `cargo publish --dry-run -p clawdstrike` strips the `path`, Cargo looks up `hushspec@0.1.1` from crates.io and either finds a divergent fork or, more commonly, gets an API surface that doesn't match what `clawdstrike` calls.
2. **`nono`** is worse. `infra/vendor/nono/Cargo.toml` declares `version = "0.11.0"`, `description = "Capability-based sandboxing library using Landlock (Linux) and Seatbelt (macOS)"`, `repository = https://github.com/always-further/nono`. **The crates.io `nono@0.57.0` is the same project, but 46 minor releases ahead.** `cargo publish -p clawdstrike --dry-run` resolves `nono = "0.11.0"` against crates.io, downloads `nono@0.11.0`, then fails because the vendored fork has API drift from the registry copy at that pin (e.g., `clawdstrike::sandbox::capability_builder.rs`, which is in this PR's modified set, calls into local-fork `nono` APIs).

Both are **structural blockers**, not transient ones — the workflow comment papering over them as "stay excluded for now" understates the scope: this is roughly half the workspace stranded one minor version behind on crates.io, indefinitely, until either (a) `hushspec` is published and `nono` is migrated to `0.57.x`, or (b) the `clawdstrike` crate stops importing both.

### npm packages

`publish-npm` (line 214) discovers public packages by walking `package.json#workspaces` (root, line 8), then filtering `private === true || publishConfig.access !== "public"`. Hardcoded exclusion at line 240: `if (workspace === "crates/libs/hush-wasm") continue;` — that one is handled by `publish-wasm-npm` (line 424) because it needs `wasm-pack` to build first.

Enumerated workspaces:

| Workspace | Name | `private` | `publishConfig.access` | Publishable here? | On npmjs.org |
|-----------|------|-----------|------------------------|--------------------|---------------|
| `packages/sdk/hush-ts` | `@clawdstrike/sdk` | false | public | **yes** | `0.2.7` |
| `packages/sdk/clawdstrike` | `clawdstrike` | false | public | **yes** | `0.2.7` |
| `packages/sdk/clawdstrike-hunt` | `@clawdstrike/hunt` | false | public | **yes** | (assume `0.2.7`) |
| `packages/sdk/plugin-sdk` | `@clawdstrike/plugin-sdk` | false | public | **yes** | **404 (never published)** |
| `packages/policy/clawdstrike-policy` | `@clawdstrike/policy` | false | public | **yes** | `0.2.7` |
| `packages/adapters/clawdstrike-adapter-core` | `@clawdstrike/adapter-core` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-broker-client` | `@clawdstrike/broker-client` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-engine-adaptive` | `@clawdstrike/engine-adaptive` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-claude` | `@clawdstrike/claude` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-openai` | `@clawdstrike/openai` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-vercel-ai` | `@clawdstrike/vercel-ai` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-langchain` | `@clawdstrike/langchain` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-openclaw` | `@clawdstrike/openclaw` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-opencode` | `@clawdstrike/opencode` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-origin-core` | `@clawdstrike/origin-core` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-hush-cli-engine` | `@clawdstrike/engine-local` | false | public | **yes** | (assume) |
| `packages/adapters/clawdstrike-hushd-engine` | `@clawdstrike/engine-remote` | false | public | **yes** | (assume) |
| `packages/cli/create-plugin` | `@clawdstrike/create-plugin` | false | public | **yes** | **404** |
| `packages/swarm-engine` | `@clawdstrike/swarm-engine` | false | **none** (missing) | **NO — silently skipped** | **404** |
| `apps/control-console` | `@backbay/control-console` | true | none | NO (private) | n/a |
| `apps/workbench` | `clawdstrike-workbench` | true | none | NO | n/a |
| `apps/academy` | `clawdstrike-academy` | true | none | NO | n/a |
| `crates/libs/hush-wasm` | `@clawdstrike/wasm` | (set in package.json) | (set in package.json) | NO (excluded by name; published by `publish-wasm-npm`) | `0.2.7` |

**Snag:** `packages/swarm-engine/package.json` lacks `publishConfig.access`, so the discover step at line 247 (`if (manifest.private === true || publishAccess !== "public")`) silently excludes it. The author probably intended `swarm-engine` to publish at `0.1.0`; this is a one-line manifest fix.

**Snag:** `@clawdstrike/plugin-sdk@0.1.0` and `@clawdstrike/create-plugin@0.1.0` are eligible but never published. Their version is `0.1.0`, not `0.2.7` — they will be detected as "missing" and published this run, then skipped on the next tag bump (because the workflow only publishes the version in their `package.json`, which doesn't move with the workspace).

**Sequencing:** topo-sort in the discover step (lines 264–291) is correct; it builds a DAG over `dependencies + optionalDependencies` intersected with workspace names. `@clawdstrike/sdk` and `@clawdstrike/adapter-core` will publish before any adapter consuming them.

**Provenance:** `npm publish --access public --provenance` (lines 390, 486). With `id-token: write` at the workflow top (line 16), Sigstore provenance attestations are produced for npm. **This is the only stream that signs artifacts.**

### Python wheels

`packages/sdk/hush-py/pyproject.toml`: pure-Python `clawdstrike` (hatchling implied; `[build-system]` not shown but the workflow uses `python -m build --sdist --wheel`).

`packages/sdk/hush-py/hush-native/pyproject.toml`: **maturin 1.4–2.0**, also named `clawdstrike`. This is the trick — both pyprojects publish under the same PyPI name `clawdstrike`, with the pure wheel as `py3-none-any` and native wheels as `cp310-*-{manylinux,macosx,win_amd64}`.

Verification at `release.yml:744`:

> ```python
> checks = {
>     "pure py3-none-any wheel": any("py3-none-any.whl" in f for f in files),
>     "linux native wheel": any("manylinux" in f for f in files),
>     "macOS native wheel": any("macosx" in f for f in files),
>     "windows x86_64 native wheel": any("win_amd64" in f for f in files),
> }
> ```

If any wheel matrix shard fails, `twine upload` is gated off (`Ensure native wheel matrix succeeded`, line 717).

**Snag — uploaded by twine, not OIDC trusted publisher:** uses `TWINE_PASSWORD = ${{ secrets.PYPI_TOKEN }}` (line 775). This is a static API token. Migrating to PyPI's OIDC trusted publishing would dovetail with the existing `id-token: write` permission and remove the long-lived secret.

**Snag — no musllinux, no win_arm64, no aarch64 macOS standalone wheel verification:** `CIBW_SKIP: "*-musllinux_* *-manylinux_i686 *-win32"`. ARM Linux is built (`CIBW_ARCHS_LINUX: "x86_64 aarch64"` under QEMU). Apple Silicon is built. Windows-on-ARM is skipped.

### Docker images

**Not in this workflow.** Lives in `.github/workflows/docker.yml` (`Docker Build & Push`, triggered on `push` and `workflow_dispatch`, with optional `release_tag` input). Images: `ghcr.io/backbay-labs/clawdstrike/{spine,tetragon-bridge,hubble-bridge,hushd,…}`. The `release.yml` workflow does **not** coordinate with `docker.yml` — there's no `workflow_call` or shared dispatch. A v0.3.0 tag triggers `release.yml` only; pushing images requires a separate manual dispatch of `docker.yml` with `release_tag: v0.3.0`.

**Gap:** no coordination between `release.yml` and `docker.yml` for tag releases. Either (a) `docker.yml` should also fire on `push: tags: [v*]`, or (b) `release.yml` should `workflow_call` it.

### Helm charts

**Not in this workflow.** `helm-release.yml`. Same coordination gap.

### GitHub Releases binaries

`build-binaries` (line 787) produces, per target:
- raw binary `hush-{linux-x86_64,darwin-x86_64,darwin-aarch64,windows-x86_64.exe}` (workflow line 869: uploaded as the artifact named, e.g., `hush-linux-x86_64`)
- tarball `clawdstrike-{linux,darwin-x86_64,darwin-aarch64}.tar.gz` containing **`hush`, `clawdstrike`, `hushd`** (line 877–879)

`build-hushd-binaries` (line 889) produces another raw `hushd-*` artifact for every platform.

**Snag — duplication:** `hushd` is shipped twice: once standalone (job 10), once inside every `clawdstrike-*.tar.gz` (job 9 line 879). Either drop job 10 or stop bundling `hushd` into the universal tarball. The 4 standalone `hushd-*` artifacts are also referenced by `generate-hushd-ota-manifest.sh` (line 1148), so the OTA path needs them — job 10 is load-bearing, **job 9's tarball bundling of `hushd` is the redundant half**.

### Other (GH Release, OTA, Homebrew)

- **OTA manifest signing** (`release.yml:1128–1172`) — Ed25519 signs `hushd-ota-manifest-{stable,beta}.json`. Requires `HUSHD_OTA_SIGNING_PRIVATE_KEY_PEM`. Hard-fails if missing.
- **Homebrew tap update** (`release.yml:1184–1267`) — clones `backbay-labs/homebrew-tap`, generates `Formula/clawdstrike.rb`, pushes. The Formula installs three binaries from each tarball: `hush`, `clawdstrike`, `hushd`. The `test do` block runs `hush --version` and `hushd --version` — there's no `clawdstrike --version` smoke test even though the binary is installed.
- **macOS DMG** (`build-agent-dmg`, line 968) — full notarytool flow, certificate import into a temp keychain (lines 996–1029), invocation of `scripts/notarize-agent-macos.sh`, evidence upload. **Will silently no-op** the `Import Apple signing certificate` step (line 997 condition `if: ${{ env.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64 != '' }}`), but `scripts/notarize-agent-macos.sh` likely hard-fails downstream if the cert isn't imported. This is consistent with the recent `fix(agent): align macos packaging placeholder checks` commit (`2eff91532`).

### SBOMs and signatures

**None.** No `syft`, `cyclonedx`, `spdx`, or `cosign` references in `release.yml`. The only attestation in the workflow is npm's `--provenance` flag (Sigstore via OIDC). Rust crates, Python wheels, GH Release binaries, Homebrew formula, and the macOS DMG all ship unsigned (except the DMG, which carries an Apple Developer ID signature + notarization staple). No supply-chain signature on anything else.

## In-line cargo-audit ignore

The wave-1 audit flagged "in-line audit-ignore list" — **this is not in `release.yml`**. It lives in `.github/workflows/ci.yml` lines 488–533. Quoting:

> ```bash
> audit_ignores=(
>   --ignore RUSTSEC-2024-0375 \
>   --ignore RUSTSEC-2025-0141 \
>   --ignore RUSTSEC-2024-0388 \
>   --ignore RUSTSEC-2024-0411 \
>   --ignore RUSTSEC-2024-0412 \
>   --ignore RUSTSEC-2024-0413 \
>   --ignore RUSTSEC-2024-0414 \
>   --ignore RUSTSEC-2024-0415 \
>   --ignore RUSTSEC-2024-0416 \
>   --ignore RUSTSEC-2024-0417 \
>   --ignore RUSTSEC-2024-0418 \
>   --ignore RUSTSEC-2024-0419 \
>   --ignore RUSTSEC-2024-0420 \
>   --ignore RUSTSEC-2024-0429 \
>   --ignore RUSTSEC-2024-0436 \
>   --ignore RUSTSEC-2025-0057 \
>   --ignore RUSTSEC-2025-0134 \
>   --ignore RUSTSEC-2024-0370 \
>   --ignore RUSTSEC-2021-0145 \
>   --ignore RUSTSEC-2025-0075 \
>   --ignore RUSTSEC-2025-0080 \
>   --ignore RUSTSEC-2025-0081 \
>   --ignore RUSTSEC-2025-0098 \
>   --ignore RUSTSEC-2025-0100 \
>   --ignore RUSTSEC-2025-0119 \
>   --ignore RUSTSEC-2026-0097 \
>   --ignore RUSTSEC-2026-0105 \
>   --ignore RUSTSEC-2026-0118 \
>   --ignore RUSTSEC-2026-0119 \
>   # Temporary: transitive via portable-pty->serial in workbench PTY stack.
>   # Mitigated by command hardening (shell/env allowlists + backend-minted
>   # capability tokens bound to trusted-window context).
>   # Tracking removal: SEC-PTY-001.
>   --ignore RUSTSEC-2017-0008
>   # aws-lc-rs advisories (2026-03-23). Transitive via rustls.
>   # Awaiting patched release. Owner: @deps-maintainers.
>   --ignore RUSTSEC-2026-0044
>   --ignore RUSTSEC-2026-0045
>   --ignore RUSTSEC-2026-0046
>   --ignore RUSTSEC-2026-0047
>   --ignore RUSTSEC-2026-0048
>   --ignore RUSTSEC-2026-0049
>   --ignore RUSTSEC-2026-0067
>   --ignore RUSTSEC-2026-0068
> )
> ```

**Count:** 36 ignored advisories.

**Rationale coverage:**
- **27 advisories (lines 489–517) have ZERO in-file rationale.** They're bare `--ignore` lines with no owner, no expiry, no tracking ticket, no justification.
- **9 advisories (lines 518–533) have 1–3 lines of comment** with owner/tracking metadata.

**Mitigating control:** `release.yml` does **not** invoke `cargo-audit`, but `ci.yml:484` runs `tools/scripts/check-advisory-expiry.sh`, which parses `docs/security/dependency-advisories.md` (pipe-delimited rows) and enforces `owner`, `tracking`, and `expiry > today`. So the *real* exception policy lives in markdown. **But the workflow's ignore list is not derived from that markdown** — the two are maintained independently, so an advisory can be in the workflow's `--ignore` list without a matching row in `dependency-advisories.md` and vice versa. The expiry script doesn't lint the workflow.

**Partial duplication in `deny.toml`:** `[advisories]` section at `deny.toml:34–60` has a separate 5-entry `ignore = […]` list with structured comments (owner + expiry, e.g., `# Owner: @security-team, Expiry: 2026-06-30`). The deny.toml list is a strict subset of the workflow's `--ignore` list. Two sources of truth, two enforcement paths, no cross-validation.

**Recommendation:** Drop the inline list in `ci.yml` entirely. Move all 36 entries into a single `.cargo/audit.toml`:

```toml
# .cargo/audit.toml
[advisories]
ignore = [
  { id = "RUSTSEC-2024-0375", reason = "Transitive via rust-xmlsec SAML stack; no maintained drop-in", expiry = "2026-06-30", owner = "@security-team", tracking = "SEC-SAML-002" },
  { id = "RUSTSEC-2024-0388", reason = "<TODO>",                                                       expiry = "2026-06-30", owner = "@TBD",           tracking = "TBD" },
  # … one row per advisory, all 36
]
```

Then `cargo audit` reads it natively, `check-advisory-expiry.sh` parses TOML instead of pipe-delimited markdown, and `deny.toml`'s `[advisories].ignore` can be deleted (cargo-deny already understands `audit.toml`). One source of truth.

## Recommended Sequence to "Actually Releasable v0.3.0"

Ordered commit plan — each commit is independent and small enough to revert.

1. **`fix(release): publish missing-but-blocked crates via vendoring fix`** — the load-bearing one.
   - Either:
     - **(A)** Publish `hushspec@0.1.1` to crates.io properly (flip `publish = false` to true in `vendor/hushspec/Cargo.toml`, ensure `cargo publish -p hushspec --dry-run` is green, push), and either bump the workspace `nono` dep to `0.57.x` upstream (full re-test of `crates/libs/clawdstrike/src/sandbox/capability_builder.rs` which is in your modified set) **or** publish the local fork under a different name like `clawdstrike-nono` and update the workspace dep.
     - **(B)** Strip `nono` and `hushspec` out of `clawdstrike`'s public surface entirely — move them behind a non-default feature that's `publish = false`'d as a workspace member, or split into `clawdstrike-sandbox` and `clawdstrike-spec` sibling crates that depend on the vendored copies but are themselves `publish = false`.
   - Verify with `for c in clawdstrike clawdstrike-policy-event hunt-scan hunt-query hunt-correlate hush-cli clawdstrike-logos; do cargo publish -p $c --dry-run --allow-dirty; done`. Don't change `release.yml` until every dry-run is green.

2. **`feat(release): extend crates allow-list to the full publishable set`** — once #1 passes dry-run locally.
   - In `release.yml:135`, expand the `crates=(...)` array to the dependency-topo order and add the remaining crates that are reachable now:
     ```bash
     crates=(
       # leaves
       logos-ffi clawdstrike-ocsf hush-core hush-proxy hush-spine
       # depends on clawdstrike + leaves
       clawdstrike
       clawdstrike-policy-event
       hunt-query hunt-scan hunt-correlate
       clawdstrike-logos
       hush-cli
     )
     ```
   - Mirror the order in `publish_with_retry` calls. Delete the "0.2.7-drifting" comment.

3. **`fix(release): drop redundant hushd from clawdstrike-*.tar.gz`** — pick one location for the `hushd` binary. Recommendation: keep `build-hushd-binaries` (line 889) because the OTA manifest depends on the standalone artifacts, and delete the `cp target/.../hushd _archive/` line at `release.yml:879`. Update the Homebrew formula's `bin.install "hushd"` accordingly.

4. **`fix(release): set publishConfig.access for @clawdstrike/swarm-engine`** — one-line `package.json` change in `packages/swarm-engine/`. Without this the package is silently excluded from `publish-npm`.

5. **`refactor(audit): centralize advisory ignores in .cargo/audit.toml`** — collapse `ci.yml:488–533` and `deny.toml:34–60` into a single TOML file. Update `tools/scripts/check-advisory-expiry.sh` to parse `audit.toml`. Net deletion: ~50 lines of CI yaml and one duplicated markdown source.

6. **`feat(release): trigger Docker and Helm publishes from release tag`** — add to `release.yml`:
   ```yaml
   publish-docker:
     needs: [resolve-version, preflight]
     uses: ./.github/workflows/docker.yml
     with:
       release_tag: ${{ needs.resolve-version.outputs.tag }}
     secrets: inherit
   ```
   Same for `helm-release.yml`. Removes the "v0.3.0 ships crates+npm+pypi but not the container images" footgun.

7. **`feat(release): add SBOM + cosign for GH Release archives`** — invoke `anchore/sbom-action` after `Flatten artifacts`, sign the resulting tarballs with `cosign sign-blob --yes` (the workflow already has `id-token: write`), and upload `.sbom.json` + `.sig` alongside each artifact. Brings parity with the npm `--provenance` story.

8. **`refactor(release): migrate PyPI upload to trusted publisher OIDC`** — drop `PYPI_TOKEN` secret, use `pypa/gh-action-pypi-publish@release/v1` with `id-token: write` (already present at line 16). Removes the only long-lived publishing secret.

9. **`fix(release): make APPLE_* secret absence a hard failure, not a silent skip`** — the conditional at `release.yml:997` (`if: env.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64 != ''`) silently no-ops cert import, but `scripts/notarize-agent-macos.sh` will then fail noisily. Either fail fast at preflight, or make the secret optional all the way through. Current state is the worst of both worlds.

Once #1–#3 land, every `vX.Y.Z` tag will actually move the full publishable surface; #4–#9 are polish to make the publishing story honest about what's signed, what's centralized, and what fails when.

---

**Cross-references for downstream audit waves:**
- Vendoring strategy: `infra/vendor/nono`, `vendor/hushspec` — covered partially by wave-2 dep audit.
- `publish = false` crates that nonetheless ship containerized: `hushd`, `clawdstrike-brokerd`, `control-api`, `clawdstrike-registry` — see `infra/docker/Dockerfile.*` and `docker.yml`.
- `apps/agent/src-tauri` macOS packaging: see preflight gate `release.yml:74–102` and the recent `fix/macos-es-ne-hardening` branch commits (`56dc31483`, `768876a7b`, `2eff91532`).
