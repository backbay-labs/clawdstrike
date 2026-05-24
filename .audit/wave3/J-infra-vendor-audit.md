# `infra/vendor/` Audit

**Wave**: 3 — finding J
**Auditor**: Codebase mapper
**Date**: 2026-05-23
**Branch**: `fix/macos-es-ne-hardening`
**Targets inspected**: `infra/vendor/` (whole tree), `.cargo/config.toml`, workspace + per-app `[patch.crates-io]` blocks, `scripts/cargo-offline.sh`, `.github/workflows/ci.yml`, `git log --diff-filter=A -- infra/vendor/`.

---

## Summary

**Headline**: `infra/vendor/` is not a small set of carefully forked crates — it is a **complete 1.0 GB / ~22 k Rust file / ~2.8 M LoC `cargo vendor` mirror of the entire dependency graph (841 crates)**, used by exactly one consumer: the `offline` CI job, via `scripts/cargo-offline.sh` which injects `--config 'source.crates-io.replace-with="vendored-sources"'` at the command line. There is **no `replace-with` directive in `.cargo/config.toml`**, so regular `cargo build` does not use the vendor tree at all (apart from the two explicit path deps below). This makes the wave-1 framing slightly off: most "vendoring" here is mechanical mirror upkeep, not deliberate forks.

That said, the audit produced four genuinely interesting findings:

1. **`[patch.crates-io] async-nats = { path = "infra/vendor/async-nats" }`** is duplicated in **four `Cargo.toml`s** (workspace root + three Tauri app crates) with **zero rationale comment**. The vendored copy is a clean stock 0.40.0 — the patch carries no functional change vs crates.io. It exists solely to make the offline build resolve to the in-tree copy. This is **UNJUSTIFIED as a patch**; the offline source map already handles it.
2. **`nono`** (path dep at `infra/vendor/nono`, not a `[patch.crates-io]`) is a real **first-party fork**: optional deps were stripped from `Cargo.toml` to avoid pulling ~25 transitive crates into the vendor tree (commit `7fae1c80e`). This is a private sibling repo (`always-further/nono`) checked into a directory that implies "third-party vendored". Misfiled, but justified.
3. **`rustls-webpki`** is the only vendored crate with **upstream advisory-driven content patches** (commit `e9ab9e815`, "update rustls webpki advisory floor", ~266 lines edited across 13 files). This is an actual security backport and should be documented.
4. **98 crates appear in versioned-duplicate form** (e.g. `base64-0.13.1` alongside `base64`, `ark-ff-0.3.0` / `ark-ff-0.4.2` / `ark-ff`), totalling ~10 % of the tree. This is normal `cargo vendor` behaviour when multiple major versions coexist in the lockfile, but it does mean the vendor mirror's size is partly a symptom of dependency-graph debt elsewhere (esp. alloy + ark-* + rustls-webpki + windows-sys families).

**Cleanup ROI**: dropping the redundant `[patch.crates-io]` blocks is a 5-line zero-risk change. Adding a `infra/vendor/README.md` documenting the offline-CI contract is the single highest-value action. Trimming the mirror requires deduplicating major-version forks in the actual workspace deps, which is out-of-scope for this audit.

---

## Mechanism: how the vendor tree is actually consumed

There are **two distinct mechanisms** mixing together:

### Mechanism A — workspace path / `[patch.crates-io]` (used in every build)

`/Users/connor/Medica/backbay/standalone/clawdstrike/Cargo.toml`:

```toml
# line 182
nono = { path = "infra/vendor/nono", version = "0.11.0", default-features = false }

# lines 188-189
[patch.crates-io]
async-nats = { path = "infra/vendor/async-nats" }
```

`/Users/connor/Medica/backbay/standalone/clawdstrike/apps/agent/src-tauri/Cargo.toml`,
`/Users/connor/Medica/backbay/standalone/clawdstrike/apps/desktop/src-tauri/Cargo.toml`,
`/Users/connor/Medica/backbay/standalone/clawdstrike/apps/workbench/src-tauri/Cargo.toml` (each):

```toml
[patch.crates-io]
async-nats = { path = "../../../infra/vendor/async-nats" }
```

Only **`nono`** and **`async-nats`** are actually pulled from `infra/vendor/` in normal builds. Everything else is fetched from crates.io.

### Mechanism B — offline source replacement (used in CI `offline` job only)

`/Users/connor/Medica/backbay/standalone/clawdstrike/.cargo/config.toml` (entire file):

```toml
[source.vendored-sources]
directory = "infra/vendor"
```

Note: this **declares** a source but does **not** map crates.io to it. The mapping is injected at the CLI level by:

`/Users/connor/Medica/backbay/standalone/clawdstrike/scripts/cargo-offline.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
exec cargo \
  --config 'source.crates-io.replace-with="vendored-sources"' \
  "$@"
```

Used in `.github/workflows/ci.yml` lines 425–451:

```yaml
offline:
  name: Offline Build/Test (vendored)
  ...
  - name: Test offline
    run: scripts/cargo-offline.sh test --workspace --all-targets
    env:
      CARGO_NET_OFFLINE: "true"
```

This is why every crate the workspace transitively depends on must be present in `infra/vendor/` — without it the offline job fails. It also explains why the commit history is dominated by mechanical "re-vendor after bump" commits (`268a26517`, `6c9b9fc80`, `c186b29b8`, `41b429533`, `d3ecce751`, etc.).

### What documentation exists

`infra/vendor/` has **no `README.md`**. The only references to the directory are:

- `/Users/connor/Medica/backbay/standalone/clawdstrike/docs/REPO_MAP.md:18` — one-liner: `| infra/vendor/ | Vendored Rust dependencies for offline builds. |`
- `/Users/connor/Medica/backbay/standalone/clawdstrike/AGENTS.md:13` — `infra/vendor/: vendored Rust dependencies for offline builds (avoid hand-editing)`
- `/Users/connor/Medica/backbay/standalone/clawdstrike/docs/specs/04-apache-2-license.md:57` — license note: `contains third-party crate sources with their own licenses ... These are NOT modified -- they retain their original licenses.` **This claim is false for `nono` and `rustls-webpki`** (see below).

No ADR, no per-crate rationale, no expiry plan, no owner.

---

## Inventory at a glance

| Metric | Value |
| --- | --- |
| Total vendored directories | **841** |
| Disk size | **~1.0 GB** |
| Rust source files | **22,479** |
| Total LoC across vendored `.rs` files | **~2,806,043** |
| Crates with major-version duplicates (e.g. `base64-0.13.1` + `base64`) | **98** |
| Crates *actually* referenced by workspace `Cargo.toml` (not via offline mechanism) | **2** (`nono`, `async-nats`) |
| `[patch.crates-io]` entries across the repo | **4** (workspace root + 3 Tauri app crates), all `async-nats` |
| Per-crate rationales found (comments, READMEs, ADRs) | **0** |
| Vendored crates with confirmed local modifications | **2** (`nono`, `rustls-webpki`) |

---

## Per-Crate Table (notable entries; full mirror is mechanical)

A row-per-crate table for 841 entries is not actionable. The table below lists the crates that are interesting because they are explicitly patched, explicitly path-deped, modified, security-relevant, or were called out by name in Wave 1.

| Crate | Vendored version | Upstream "latest" reference | Local mods? | Patched in / consumed via | Rationale found? | Class | Recommended action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `async-nats` | 0.40.0 (stock, `Cargo.toml.orig` matches `Cargo.toml`) | 0.40.0 | **No** | `[patch.crates-io]` in 4 manifests (root + 3 Tauri apps) | **No** comment, no ADR; commit `b59a3c282` message is `fix(ci): resolve pr-204 review, audit, and offline failures` | **UNJUSTIFIED (patch)** / JUSTIFIED (vendor copy via offline mechanism) | **DROP the 4 `[patch.crates-io]` blocks.** Workspace deps already pin `"0.40"`; offline mode already resolves via `[source.vendored-sources]`. The patch adds no functional value, hides the bump under a CI-rename, and forces a 4-file change every time async-nats moves. |
| `nono` | 0.11.0 | First-party (`always-further/nono`), not on crates.io | **YES** — optional deps removed in `7fae1c80e` (`keyring/sigstore-verify/x509-cert/der/ignore` stripped, feature stubs added); doc-comment edits in `52ad4202f` and `28c007007` | Direct workspace path dep at `Cargo.toml:182` | Commit messages explain it (sibling-repo path didn't work in CI; deps trimmed to shrink vendor tree); not surfaced in any README | **JUSTIFIED, ACTIVE** but **misfiled** | Move to a first-party location (e.g. `crates/libs/nono/` or `infra/firstparty/`). `infra/vendor/` implies third-party untouched; this is neither. Add `nono/README.md` documenting the fork rules. |
| `rustls-webpki` | 0.103.x (see `.cargo_vcs_info.json`) | Same major | **YES** — `e9ab9e815` ("update rustls webpki advisory floor", 2026-05-19) edited 266 lines across `src/cert.rs`, `src/crl/types.rs`, `src/der.rs`, `src/subject_name/dns_name.rs`, `src/subject_name/mod.rs`, `src/trust_anchor.rs`, `src/x509.rs` | Consumed via offline source map only | **No** commentary in tree; only the commit subject. Likely a manual backport of an upstream advisory fix. | **JUSTIFIED, ACTIVE** but undocumented | Document the advisory ID and the upstream commit hash being backported; add a `LOCAL_PATCHES.md` next to the crate; pin an expiry trigger ("drop when crates.io ≥ X"). Without this, the next mechanical re-vendor will silently revert the security patch. |
| `wasmtime` | 44.0.1 | 44.0.1 | No | Workspace dep `crates/libs/clawdstrike/Cargo.toml:47` resolves from crates.io; vendor copy only used offline | Vendored in `41b429533` (`fix(ci): vendor secure wasmtime runtime`) — message implies advisory-driven choice of 44.0.1 specifically | JUSTIFIED, ACTIVE | Keep. Note the version pin rationale in vendor README. |
| `wasmtime-internal-*` (10 crates: `-core`, `-cranelift`, `-fiber`, `-jit-debug`, `-jit-icache-coherence`, `-math`, `-slab`, `-unwinder`, `-versioned-export-macros`) | 44.0.1 | Same | No (stock upstream) | Offline source map only | Same commit `41b429533`. These are the upstream-renamed crates that deduplicate the RUSTSEC-2026-0118/0119 vulnerable transitive `wasmtime-*` set. | JUSTIFIED, ACTIVE (security) | Keep; document the rename rationale next to the wasmtime entry. |
| `cranelift-*` (13 crates) | per upstream 44.0.1-compatible | Same | No | Offline source map only | Pulled in by wasmtime 44.0.1; required for offline build | JUSTIFIED, ACTIVE | Keep, no action. |
| `regorus`, `regorus-mimalloc`, `regorus-mimalloc-sys` | 0.9.1 | 0.9.1 | No | Offline source map only | Vendored for offline build of Rego policy engine consumer (used by `clawdstrike-logos`). No comment, but transitive ID is obvious from crate name. | JUSTIFIED, ACTIVE | Keep. |
| `z3`, `z3-sys` | 0.12.1 / 0.8.1 | Same | No | Offline source map only | Commit `d60f032ba` (`fix(verifier): harden inheritance checks and vendor z3 deps`). Required by `logos-z3` formal-verification crate. | JUSTIFIED, ACTIVE | Keep. Surface in vendor README. |
| `pubgrub` | 0.3.0 | 0.3.0 | No | Offline source map only | Commit `949d52dec`: "The dependency resolver uses pubgrub for version resolution. Add it to the vendor directory so the offline build CI job passes." | JUSTIFIED, ACTIVE | Keep. |
| `rcgen` (+ `yasna`, `asn1-rs`, `der-parser`, `oid-registry`, `x509-parser`) | 0.14.7 | 0.14.7 | No | Offline source map only | Commit `631a44969`: "vendor rcgen for offline build ... needed for mTLS tests" | JUSTIFIED, ACTIVE | Keep. |
| `rlimit` | 0.11.0 | 0.11.0 | No | Offline source map only | Commit `7fae1c80e` (added alongside nono trim): "vendor rlimit 0.11.0 (added by hush-cli sandbox integration)" | JUSTIFIED, ACTIVE | Keep. |
| `crossterm` | 0.29.0 | 0.29.0 | No | Offline source map only | Commit `0b01c0b67`: "Adds crossterm 0.28, crossterm_winapi, and transitive deps so the offline build/test CI job passes." Has since been bumped 0.28 → 0.29; old `crossterm-0.28.1/` directory **still present** as duplicate. | JUSTIFIED, ACTIVE (current) but **stale duplicate** (`crossterm-0.28.1/`) | Verify whether any workspace crate still resolves 0.28; if not, drop the duplicate directory and the corresponding Cargo.lock entry. |
| `wasm-streams` | 0.5.0 | 0.5.0 | No | Offline source map only | Commit `a4ccc6a22`: "add wasm-streams for offline reqwest 0.13" | JUSTIFIED, ACTIVE | Keep. |
| `bindgen` | per `d60f032ba` | Same | No | Offline source map only | Same z3-vendor commit; bindgen is z3-sys' build dep. | JUSTIFIED, ACTIVE | Keep. |
| `addr2line` | per `41b429533` | Same | No | Offline source map only | Pulled in by wasmtime 44.0.1 update; modified file count in `git status` is just `cargo vendor` rewrite, not local mods. | JUSTIFIED, ACTIVE | Keep. |
| `aws-lc-rs`, `aws-lc-sys` | per `b59a3c282` | Same | No | Offline source map only | Pulled in by rustls upgrade in async-nats 0.40 patch | JUSTIFIED, ACTIVE | Keep; track RUSTSEC-2026-0044…0049/0067/0068 (already in `cargo audit --ignore` list). |
| 98× `<crate>-<version>` versioned-duplicate dirs (e.g. `base64-0.13.1`, `ark-ff-0.3.0`/`0.4.2`, `hashbrown-0.12.3`/`0.14.5`/`0.15.5`/`0.17.1`, `windows-sys-0.45.0`/`0.48.0`/`0.52.0`/`0.59.0`/`0.60.2`, …) | Various | Various | No (stock) | Offline source map only | None | JUSTIFIED, ACTIVE (mechanical) | These are normal `cargo vendor` outputs when the lockfile resolves multiple major versions. Out-of-scope to drop here — eliminate by deduplicating the workspace dep graph upstream of vendoring. |
| Everything else (~700 crates: `tokio`, `serde`, `alloy-*`, `quinn-*`, `openssl-*`, `windows-*`, `icu_*`, etc.) | Per lockfile | Per lockfile | No | Offline source map only | None | JUSTIFIED, MECHANICAL | Keep. No per-crate rationale needed — they are present because the lockfile transitively requires them. |

---

## Justified, Active

For each: rationale, expiry trigger, owner.

### `nono` (0.11.0)
- **Rationale**: First-party sibling crate from `always-further/nono` repo. CI cannot reach a sibling path; vendor copy is the only way to build offline. Optional deps stripped to keep vendor tree small.
- **Modifications**: `Cargo.toml` trimmed (no `keyring`, `sigstore-verify`, `x509-cert`, `der`, `ignore`); feature stubs added; doc comments fixed for rustdoc.
- **Expiry trigger**: When `nono` is either (a) moved into this workspace as a first-party crate (`crates/libs/nono/`) or (b) published to crates.io.
- **Owner**: Whoever owns the sandbox stack (commit author `bb-connor` / `@deps-maintainers` per `ci.yml:524`).
- **Action**: Move out of `infra/vendor/` so directory semantics are honest. Add a stub `LOCAL_PATCHES.md` listing every removed optional dep.

### `rustls-webpki` (0.103.x)
- **Rationale**: Security advisory backport (commit `e9ab9e815`). 266 lines modified across 7 source files. Without an explicit note, the next mechanical re-vendor will revert the fix.
- **Expiry trigger**: When `cargo audit` recognises the upstream-released fix at a version this workspace can adopt.
- **Owner**: Unknown; surface via `LOCAL_PATCHES.md`.
- **Action**: Document the upstream issue / advisory ID and the commit being backported; add a guard in `scripts/cargo-offline.sh` or a `tools/scripts/check-vendor-patches.sh` that fails CI if the modified files diverge from a recorded SHA without an explicit acknowledgement.

### `wasmtime` 44.0.1 + `wasmtime-internal-*` (10 sub-crates)
- **Rationale**: Pinned 44.0.1 to pick up the upstream rename remediation for RUSTSEC-2026-0118 / 0119 (the `wasmtime-internal-*` naming makes vulnerable transitive `wasmtime-*` resolutions deduplicate).
- **Expiry trigger**: When the original `wasmtime-*` crate names ship a non-vulnerable release that `cargo audit` accepts.
- **Owner**: `@deps-maintainers` (per `ci.yml:524`).
- **Action**: Note this in vendor README; cross-link to `ci.yml:533` (which currently `--ignore`s `RUSTSEC-2026-0118` and `RUSTSEC-2026-0119`).

### Pure mechanical mirror (rest of tree)
- **Rationale**: Required by the offline-CI lockfile resolution.
- **Expiry trigger**: When the `offline` CI job is retired, the entire mirror can be deleted.
- **Owner**: CI maintainers.
- **Action**: None. Continue to refresh via `cargo vendor` after every lockfile change.

---

## Justified, Stale

None confirmed. The closest candidate is the **`crossterm-0.28.1/` duplicate directory** (the workspace was bumped to 0.29 in some path but the older vendor folder remains). Verification step:

```bash
# If this returns no rows, the duplicate vendor dir can be dropped.
grep -B0 -A1 'name = "crossterm"' /Users/connor/Medica/backbay/standalone/clawdstrike/Cargo.lock
```

---

## Unjustified

### `[patch.crates-io] async-nats = { path = "infra/vendor/async-nats" }` (4× duplicated)

**Locations (each file has the patch block at the bottom)**:
- `/Users/connor/Medica/backbay/standalone/clawdstrike/Cargo.toml:188-189`
- `/Users/connor/Medica/backbay/standalone/clawdstrike/apps/agent/src-tauri/Cargo.toml`
- `/Users/connor/Medica/backbay/standalone/clawdstrike/apps/desktop/src-tauri/Cargo.toml`
- `/Users/connor/Medica/backbay/standalone/clawdstrike/apps/workbench/src-tauri/Cargo.toml`

Each block reads, verbatim and uncommented:

```toml
[patch.crates-io]
async-nats = { path = "infra/vendor/async-nats" }            # workspace root
async-nats = { path = "../../../infra/vendor/async-nats" }   # app crates
```

**What's in there**: `infra/vendor/async-nats/Cargo.toml.orig` is byte-for-byte stock async-nats 0.40.0 from `nats-io/nats.rs@6426b96`. No source modifications. The only thing the patch achieves is forcing every transitive `async-nats = "*"` to resolve to this in-tree directory instead of crates.io.

**What would change if we used upstream**: Nothing. Every workspace `Cargo.toml` already pins `async-nats = "0.40"` (verified by grep across 16 manifests). Resolution is deterministic. The offline CI job would still find the vendored copy via `[source.vendored-sources]` because `async-nats` 0.40.0 is in the lockfile.

**Origin**: Added in commit `b59a3c282` (2026-03-23) titled `fix(ci): resolve pr-204 review, audit, and offline failures`. No accompanying rationale comment in the Cargo.toml or in any doc. The commit also bumped the vendored copy 0.39.0 → 0.40.0, which suggests the patch may have been added during a moment when async-nats 0.40 hadn't fully propagated to crates.io / `cargo audit`, but that no longer applies.

**Recommended action**: **DROP** all four blocks. This is a no-functionality-change cleanup. Adds: zero. Removes: hidden coupling that surprises every developer trying to use `cargo update -p async-nats`.

### Tree-level: 700-odd "mechanically present" crates
Strictly these are not *unjustified* — they exist because the offline CI mode requires them. But they are also not documented anywhere. The framing "841 vendored crates" reads as deliberate forking when it isn't. Audit-class: **MIS-LABELLED, not unjustified**. Fix is documentation, not deletion.

---

## Wrong Version

No vendored crate's `version` field disagrees with the lockfile resolution. Verified by spot-checking `async-nats`, `wasmtime`, `regorus`, `pubgrub`, `rcgen`, `rlimit`, `crossterm`, `wasm-streams`, `z3`. The vendor tree is kept in lockstep via the "re-vendor after bump" commit chain (`6c9b9fc80`, `268a26517`, `c186b29b8`, `41b429533`, `d3ecce751`).

The **closest near-miss** is `crossterm-0.28.1/` next to `crossterm/` (currently 0.29.0). Both *can* be in the lockfile if any transitive dep still pins 0.28 — but if the actual current lockfile only has 0.29, the duplicate is dead weight. Requires a single Cargo.lock check to confirm.

---

## Cleanup Plan

In priority order, smallest-blast-radius first.

### 1. Drop the redundant `async-nats` `[patch.crates-io]` blocks (zero-risk, 5-line PR)

Remove these four blocks:
- `/Users/connor/Medica/backbay/standalone/clawdstrike/Cargo.toml:188-189`
- `/Users/connor/Medica/backbay/standalone/clawdstrike/apps/agent/src-tauri/Cargo.toml` (last 2 lines)
- `/Users/connor/Medica/backbay/standalone/clawdstrike/apps/desktop/src-tauri/Cargo.toml` (last 2 lines)
- `/Users/connor/Medica/backbay/standalone/clawdstrike/apps/workbench/src-tauri/Cargo.toml` (last 2 lines)

Verify with:
```bash
cargo +stable check --workspace --locked
scripts/cargo-offline.sh check --workspace --locked
```

The lockfile resolution should be identical (registry 0.40.0 == vendor 0.40.0).

### 2. Write `infra/vendor/README.md` (zero-risk, single-file PR)

Capture, in one place, the truths discovered during this audit:

- The directory is a `cargo vendor` mirror, not a hand-curated fork list.
- It is consumed only by `scripts/cargo-offline.sh`, which injects `--config 'source.crates-io.replace-with="vendored-sources"'`.
- `.cargo/config.toml` declares the source but intentionally does not map it — regular `cargo build` ignores the mirror.
- Two crates have genuine local modifications: `nono` and `rustls-webpki`. Both need their own `LOCAL_PATCHES.md`.
- Refresh procedure: `cargo vendor infra/vendor` after any lockfile change. Commit verb is `chore(vendor):` (per `0b01c0b67`, `a4ccc6a22`, `268a26517` precedent).
- Disk budget: ~1 GB; if you add a top-level dep, expect 5–50 transitive crates to land here.
- Owners: `@deps-maintainers` per `.github/workflows/ci.yml:524`.

### 3. Document the two genuine forks

- `infra/vendor/nono/LOCAL_PATCHES.md`: list optional deps removed from `Cargo.toml`, doc-comment fixes, feature stubs added. Point to commits `645e92117`, `e4c8d4515`, `7fae1c80e`, `28c007007`, `52ad4202f`.
- `infra/vendor/rustls-webpki/LOCAL_PATCHES.md`: list files modified, advisory ID being backported, upstream commit being mirrored, expiry trigger ("drop when crates.io rustls-webpki ≥ X.Y.Z").

Also: **delete or rewrite** the claim in `docs/specs/04-apache-2-license.md:57` that vendored crates are "NOT modified" — it is currently false.

### 4. Move `nono` out of `infra/vendor/`

`infra/vendor/` implies "untouched third-party". `nono` is a first-party fork. Choose:
- `crates/libs/nono/` if it should be developed in this repo.
- `infra/firstparty/nono/` if you want to keep the "do not hand-edit casually" connotation.

Update `Cargo.toml:182` and `crates/libs/clawdstrike/build.rs:19` (which currently does `manifest_dir.join("../../../infra/vendor/nono/src/capability.rs")`).

### 5. Verify the `crossterm-0.28.1/` duplicate is dead

```bash
grep -A1 'name = "crossterm"' /Users/connor/Medica/backbay/standalone/clawdstrike/Cargo.lock | grep version
```

If only `0.29.x` appears, delete `infra/vendor/crossterm-0.28.1/` in the same PR as #2.

### 6. (Optional, larger) Add a CI guard against silent patch loss

Add `tools/scripts/check-vendor-patches.sh` that hashes the modified files in `nono/` and `rustls-webpki/` against a recorded SHA, and fails CI if they change without an explicit `LOCAL_PATCHES.md` update. Prevents a future `cargo vendor` refresh from silently reverting the rustls-webpki advisory backport.

### Out of scope (raise separately if needed)
- Dedup the 98 versioned-major-duplicates — requires consolidating workspace dep graph (alloy + ark-* + rustls-webpki + windows-sys families), not a vendor-tree cleanup.
- Decide whether the offline CI job is still earning its 1 GB of repo weight. If publishing to crates.io is the eventual goal, the path forward is `cargo package --offline` against a *temporary* vendor dir generated in CI rather than a committed 1 GB mirror.

---

## Appendix A — Commit chain shaping `infra/vendor/`

Chronological summary from `git log --diff-filter=A -- infra/vendor/` and pickaxes on the relevant areas:

| Commit | Date | Effect |
| --- | --- | --- |
| `4e29ed3b5` | 2026-02-02 | First introduction of `infra/vendor/` (P0/P1 launch hardening). |
| `fd6fe06ec` | 2026-02-09 | Repo-layout consolidation; vendor moved under `infra/`. |
| `9d094a7d8` | 2026-02-10 | SDR platform; large vendor add. |
| `6c9b9fc80` | 2026-02-13 | First "re-vendor after bump" (wat 1.245.1). |
| `631a44969` | 2026-02-13 | Add `rcgen` + asn1/x509 chain for mTLS tests. |
| `aeb9fb07a` | 2026-02-15 | Enterprise desktop agent hardening; vendor adds. |
| `268a26517` | 2026-02-15 | Refresh after rust-minor dependabot bump. |
| `a4ccc6a22` | 2026-02-17 | Add `wasm-streams` for offline reqwest 0.13. |
| `0b01c0b67` | 2026-02-28 | Add `crossterm` 0.28 + transitives. |
| `949d52dec` | 2026-02-28 | Add `pubgrub`. |
| `1eb25192d` | 2026-03-02 | Restore offline vendored build for darwin bridge. |
| `645e92117` | 2026-03-07 | Vendor `nono` instead of sibling path. |
| `e4c8d4515` | 2026-03-07 | Vendor nono transitive deps + platform gates. |
| `7fae1c80e` | 2026-03-07 | **Strip nono optional deps** + add `rlimit`. |
| `28c007007` | 2026-03-07 | Remove unused nono modules, fix doc links. |
| `52ad4202f` | 2026-03-07 | Escape brackets in nono doc comments. |
| `d60f032ba` | 2026-03-17 | **Vendor z3 + bindgen** for formal verification. |
| `5b8a436f8` | 2026-03-17 | Vendor logos crates (note: into `crates/libs/`, NOT `infra/vendor/`). |
| `b59a3c282` | 2026-03-23 | **Add `[patch.crates-io] async-nats`** (the wave-1 finding) + bump 0.39→0.40. |
| `c186b29b8` | (after mar-23) | Re-vendor pyo3 0.28.1 → 0.28.2 for RUSTSEC-2026-0013. |
| `4f9c8a7b9` | 2026-04-02 | AGENTS.md + package-lock chore. |
| `41b429533` | 2026-05-19 | **Vendor "secure" wasmtime runtime** (44.0.1 + wasmtime-internal-* renames). |
| `d3ecce751` | 2026-05-19 | Align offline vendored deps (rand 0.9.4 → 0.9). |
| `e9ab9e815` | 2026-05-19 | **`rustls-webpki` advisory backport** (266 LoC across 7 files). |

The pattern is unambiguous: this is a steady-state mechanical mirror with two episodes of genuine forking (`nono` trim, `rustls-webpki` security patch).

---

## Appendix B — Exact patch text inspected

For the avoidance of doubt, here are the four `[patch.crates-io]` blocks reproduced verbatim. None of them contains any comment explaining itself.

`/Users/connor/Medica/backbay/standalone/clawdstrike/Cargo.toml` (lines 184–193):

```toml
[profile.release]
lto = true
codegen-units = 1

[patch.crates-io]
async-nats = { path = "infra/vendor/async-nats" }

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
```

`/Users/connor/Medica/backbay/standalone/clawdstrike/apps/agent/src-tauri/Cargo.toml` (tail):

```toml
[patch.crates-io]
async-nats = { path = "../../../infra/vendor/async-nats" }

[lints.clippy]
unwrap_used = "deny"
```

`/Users/connor/Medica/backbay/standalone/clawdstrike/apps/desktop/src-tauri/Cargo.toml` (tail):

```toml
[patch.crates-io]
async-nats = { path = "../../../infra/vendor/async-nats" }
```

`/Users/connor/Medica/backbay/standalone/clawdstrike/apps/workbench/src-tauri/Cargo.toml` (tail):

```toml
[patch.crates-io]
async-nats = { path = "../../../infra/vendor/async-nats" }
```

No comment, no link to an upstream issue, no expiry trigger. Just the line. That is the entire rationale found in the repo.

---

*End of audit.*
