# Wave E (items 3, 4, 6) — Reviewer 2 Verdict

**Reviewer:** Agent #2
**Branch:** cleanup/waves-abce
**HEAD:** 0730ccd2e5776a900bd5cf106aa534a7b50a7202
**Verdict:** CONCUR

## Item-by-item check

### Check 1 — hushspec promotion (E3 Task 1)
**Evidence:**
- `crates/libs/hushspec/` exists with `Cargo.toml`, `LICENSE`, `README.md`, `rulesets/`, `src/`, `tests/` (`ls crates/libs/hushspec/`).
- `vendor/hushspec/` is gone — `ls vendor/hushspec/` returns "No such file or directory".
- `Cargo.toml:39` lists `"crates/libs/hushspec"` as a workspace member.
- `crates/libs/clawdstrike/Cargo.toml:33` has `hushspec = { version = "0.1.1", path = "../hushspec", optional = true }` and line 83 lists `"dep:hushspec"` under features.
- `crates/libs/hushspec/Cargo.toml` package name = `hushspec`, version = `0.1.1`, `publish = false` (consistent with a workspace-internal first-party crate).
- `cargo check -p clawdstrike` finishes with `Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.89s` — no errors, no warnings.
- Promotion commit visible at `7bc550e9f refactor(hushspec): promote vendor/hushspec to crates/libs/hushspec (first-party)`.

**Verdict:** PASS — promotion is real, path-dep resolves, downstream consumer compiles.

### Check 2 — fixtures dedup (E3 Task 2)
**Evidence:**
- `find fixtures/hushspec -type f` returns **31 files**, all under `fixtures/hushspec/fixtures/` (`core/`, `posture/`, `origins/`, `detection/`). No `rulesets/` subtree remains under `fixtures/hushspec/` (the duplicate snapshot deletion is real).
- `crates/libs/clawdstrike/tests/hushspec_conformance.rs` uses two path constants (lines 18–25): rulesets live at `concat!(env!("CARGO_MANIFEST_DIR"), "/../hushspec")` (i.e. `crates/libs/hushspec/rulesets/`, the promoted crate), while conformance fixtures live at `concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/hushspec/fixtures")` (preserved cross-spec vectors). Comments on lines 18–22 explicitly call out the split.
- `cargo test -p clawdstrike --test hushspec_conformance` ⇒ `26 passed; 0 failed; 0 ignored`. Test names include `compile_hushspec_default_ruleset`, `compile_hushspec_strict_ruleset`, `compile_hushspec_permissive_ruleset`, plus 23 fixture-driven cases — confirming both directories load and round-trip.
- Commit: `3a8655ff1 chore(fixtures): remove duplicate hushspec snapshots`.

**Verdict:** PASS — duplicate rulesets gone, conformance vectors preserved, test green.

### Check 3 — infra/vendor reduction (E3 Task 3)
**Evidence:**
- `du -sh infra/vendor/` reports `2.3M`. (Was ~1.0 GB per Wave-4 D02 N-03; ~430× reduction.)
- `ls infra/vendor/` shows exactly 3 entries: `async-nats`, `nono`, `rustls-webpki` — matches the preservation list.
- `Cargo.toml:183` `nono = { path = "infra/vendor/nono", version = "0.11.0", default-features = false }` and `Cargo.toml:189-190` `[patch.crates-io] async-nats = { path = "infra/vendor/async-nats" }` wire the first two preserved subtrees. `rustls-webpki` is present as a parked path-dep stash (Cargo.toml does not currently reference it; the `.cargo/config.toml` comment explicitly explains it's kept for an advisory backport that's currently inactive) — observation only, not a regression.
- `.cargo/config.toml` no longer points at `infra/vendor/` as a default source. It is now a 12-line comment-only file documenting that (a) the workspace builds online by default; (b) CI re-vendors at build time via `cargo vendor`; (c) the three preserved subtrees are wired via path-deps, not via this source map.
- `.gitignore:119-132` carries the exact preserved-vs-regenerated split per spec:
  ```
  119:# infra/vendor/ used to host a 1 GB `cargo vendor` mirror; that mirror is now
  ...
  126:infra/vendor/*
  127:!infra/vendor/nono
  128:!infra/vendor/nono/**
  129:!infra/vendor/async-nats
  130:!infra/vendor/async-nats/**
  131:!infra/vendor/rustls-webpki
  132:!infra/vendor/rustls-webpki/**
  ```
- `.github/workflows/ci.yml:452-462` has the required `cargo vendor` step:
  ```
  452:      - name: Vendor crates from crates.io
  ...
  457:          cargo vendor --locked --versioned-dirs infra/vendor > .cargo/config.toml
  ...
  460:        run: scripts/cargo-offline.sh test --workspace --all-targets
  ```
  Vendor step precedes the offline-test step, as required. `scripts/cargo-offline.sh` is a 4-line wrapper that injects `source.crates-io.replace-with="vendored-sources"` via `--config`, so it only honors the vendored sources after the previous step writes the config.
- Commit: `b1385f6d0 chore(infra): replace infra/vendor with CI-time cargo vendor (-1 GB)`.

**Verdict:** PASS — size, retention list, gitignore split, and CI step all match spec.

### Check 4 — docs/plans purge (E4)
**Evidence:**
- `find docs/plans -maxdepth 1 -type d | sort` lists 7 entries (1 root + 6 subdirs): `decisions/`, `editor-ide/`, `endpoint-decision-engine/`, `formal-verification/`, `macos-es-ne/`, `sentinel-swarm/`. Matches the "~6 active" target (was 18).
- `find docs/archive/plans -maxdepth 1 -type d | sort` lists 7 entries (1 root + 6 subdirs): `multi-agent/`, `origin-enclaves/`, `pact/`, `secret-broker/`, `siem-soar/`, `swarm-engine/`. Matches the "~6 archived" target (was 0).
- `docs/plans/INDEX.md` exists (commit `6038a936c docs: add docs/plans/INDEX.md as canonical surviving-plans list`). It lists each active plan in a 1-row factual table (status, scope, and where the code lives), points to `docs/archive/plans/` for the rest, documents the "stays here only while at least one phase is unshipped" rule, and explicitly directs point-in-time audit reports to `docs/audits/`. No marketing language. Last-updated stamp 2026-05-24.
- `docs/archive/plans/README.md` mirrors the active index — one bullet per archived plan, each citing where the shipped code lives (origin-enclaves → `src/origin.rs`, `enclave.rs`; siem-soar → `crates/services/hushd/src/siem/`; secret-broker → brokerd + broker-protocol; multi-agent → `hush-multi-agent`; swarm-engine → `packages/swarm-engine/`; pact = parked pre-RFC).
- `find docs/plans -name '*agent*framework*' -o -name '*agent-framework*'` returns empty. `find docs/archive/plans -name '*agent*framework*' -o -name 'autogpt*' -o -name 'crewai*' -o -name 'vercel-ai.md' -o -name 'langchain.md' -o -name 'generic-adapter*'` also returns empty. The 7 fictional agent-framework specs are gone, not archived (which is the correct disposition since they were duplicative with `docs/src/guides/`).
- `ls docs/archive/plans/` shows: `multi-agent  origin-enclaves  pact  README.md  secret-broker  siem-soar  swarm-engine` — all 6 archived plans present.
- Commits: `7a8b70c7b docs: archive non-active plans to docs/archive/plans/` and `9d17b484d docs: remove fictional and superseded plan dirs`.

**Verdict:** PASS — purge is factual, archived items reside in the archive, INDEX.md is honest and factual.

### Check 5 — Broken doc links (post-purge)
**Evidence:** Catalogued cross-doc references to deleted or relocated plan paths (excluding `.audit/` which is point-in-time and intentionally references prior state):

| Source file | Broken target | Disposition |
|---|---|---|
| `README.md` (root) | `docs/plans/certification/{README,overview,hipaa-template,pci-dss-template,soc2-template}.md` (5 link targets in one paragraph) | `docs/plans/certification/` was deleted, not archived. README still advertises a section that no longer exists. |
| `docs/src/roadmap.md:4` | `docs/plans/certification/overview.md` | Same. |
| `infra/deploy/siem-soar/README.md` | `docs/plans/siem-soar/*` | Moved to `docs/archive/plans/siem-soar/`. Path bare-string reference; renders as text not a markdown link, but still misleading. |
| `infra/deploy/siem-soar/elastic/detection-rules/README.md` | `docs/plans/siem-soar/elastic.md` | Same — moved to archive. |
| `apps/terminal/README.md` | `../../docs/plans/multi-agent/codex-swarm-playbook.md` | Moved to `docs/archive/plans/multi-agent/codex-swarm-playbook.md`. |
| `apps/terminal/docs/codex-agent-pack.md` | `../../docs/plans/multi-agent/codex-swarm-playbook.md` | Same. |
| `docs/specs/15-adaptive-sdr-architecture.md` | `../plans/clawdstrike/adaptive-sdr-research-brief.md`; `../plans/identity-access/` | Both deleted. The spec was authored against a plans-corpus that no longer exists. |
| `docs/audits/2026-02-25-openclaw-launch-readiness-index.md` | `../plans/2026-02-25-openclaw-adapter-core-alignment.md` (2 occurrences) | Deleted. Audit doc points to a vanished plan. |
| `docs/archive/plans/origin-enclaves/INDEX.md` | `docs/plans/identity-access/session-context.md` | Deleted; this is intra-archive so impact lower. |

**Count:** 9 distinct source files contain ≥1 broken link to plans deleted or relocated in E4. Two of these (README and docs/src/roadmap) are user-visible homepage paths and are the highest-priority fixes (advertise a "Certification & Compliance Specs" section that doesn't exist).

Per spec, broken doc links "note count, don't cause DISSENT unless severe." 9 broken sources is non-trivial but the README link cluster collapses into a single follow-up, so the real count is ~6 follow-up edits.

**Recommended follow-ups (non-blocking):**
1. README.md: delete the "draft certification specs" paragraph or rewrite to mention only what still ships in the repo.
2. docs/src/roadmap.md:4: drop the certification-overview link.
3. The 4 archived-plan citations (`infra/deploy/siem-soar/{,elastic/detection-rules}/README.md`, `apps/terminal/README.md`, `apps/terminal/docs/codex-agent-pack.md`) should be retargeted at `docs/archive/plans/{siem-soar,multi-agent}/` — one-line `sed` for each.
4. `docs/specs/15-adaptive-sdr-architecture.md` and `docs/audits/2026-02-25-openclaw-launch-readiness-index.md`: remove the dangling backlinks or replace with archive-located equivalents if any survive.

**Verdict:** PASS with observation — 9 broken-link sites are below the "severe" bar but should be tracked as a follow-up edit. No DISSENT.

### Check 6 — Cargo workspace coherence
**Evidence:**
- `cargo metadata --format-version=1 --no-deps` ⇒ stderr is empty (0 bytes). No warnings about missing or invalid workspace members.
- `cargo check --workspace` ⇒ final line `Finished `dev` profile [unoptimized + debuginfo] target(s) in 12.96s`. `grep -iE 'warning|error|missing'` against the full output returns empty.

**Verdict:** PASS — workspace coheres with the new `crates/libs/hushspec` member and the trimmed `infra/vendor/`.

## DISSENT log
(none)

## Concur log
- **Beyond minimum (E3 Task 1):** `crates/libs/hushspec/Cargo.toml` carries `publish = false` and a sensible feature set (`std`, `http`, `signing` gated; `default = ["std"]`). The promoted crate is also wired through the workspace members list, not just as a loose directory — i.e. it actually participates in `cargo build --workspace`, which the original spec didn't explicitly require but is the right move.
- **Beyond minimum (E3 Task 3):** The `.cargo/config.toml` comment-only file is unusually thorough for a config file — it documents both *why* the mirror was removed and *why* three subtrees were kept (first-party fork, patch crate, advisory backport stash), with file pointers (`scripts/cargo-offline.sh`, `.github/workflows/ci.yml`). Future contributors who run `git blame .cargo/config.toml` get the full rationale without needing the commit message.
- **Beyond minimum (E4):** Both `docs/plans/INDEX.md` and `docs/archive/plans/README.md` cite *where the shipped code lives* per plan (concrete file paths in `crates/`, `packages/`). This makes the archive useful as a "is this design parked or shipped?" lookup, not just a graveyard.
- **Pre-flight done right:** Commit `fe0606053 docs: update references to infra/vendor removal` was created before `b1385f6d0` actually replaced the mirror, ensuring no period where docs lied about the state on disk.

## Final verdict
CONCUR
