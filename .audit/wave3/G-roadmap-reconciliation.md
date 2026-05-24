# Roadmap Reconciliation

**Audit date:** 2026-05-23
**Auditor:** Wave 3 codebase mapper (focus: roadmaps & forward-looking planning artifacts)
**Branch sampled:** `fix/macos-es-ne-hardening`

---

## Summary

- **17 distinct roadmap documents** identified across `docs/src/`, `docs/roadmaps/`, `docs/plans/`, and `.planning/`.
- **~10,912 LOC** of explicit "roadmap" markdown (`docs/src/roadmap.md` + 16 phase/wave docs). The broader `docs/plans/` tree adds ~120,250 LOC of supporting design notes that the roadmaps cross-reference.
- **At least 7 roadmaps claim authority over overlapping subject areas** (policy schema, Spider-Sense, package manager, secret broker, sentinel swarm, workbench/IDE, EDR/endpoint).
- **5 of 17 roadmaps are stale by 8+ weeks** and at least 3 of them describe work that has *already shipped* (e.g. `roadmaps/nextgen-policy-roadmap.md` still says Spider Sense is feature-gated; `MEMORY.md` confirms first-class promotion 2026-03-03).
- **Recommended consolidation:** collapse 17 → 1 canonical `docs/src/roadmap.md` (current quarter, ≤300 lines), 1 ADR series under `docs/plans/decisions/`, and a sealed `docs/plans/decisions/archive/` for the historical drafts. **Net: delete 5 documents, archive 9, keep 3.**

---

## Roadmap Inventory

| # | Path | LOC | Last meaningful commit | Claimed status | Actual status (cross-checked) | Disposition |
|---|------|-----|------------------------|----------------|-------------------------------|-------------|
| 1 | `docs/src/roadmap.md` | 639 | 2026-03-05 `#174` | "Living document" | Mostly accurate; lists v1.2.0 schema while engine ships v1.5.0; lists 12 built-in guards while engine ships 13 (Spider Sense). | **KEEP** (rewrite ≤300 lines) |
| 2 | `docs/roadmaps/nextgen-policy-roadmap.md` | 2,496 | 2026-03-05 `#174` | DRAFT, target v1.2.0+ | **Mostly shipped.** `SUPPORTED_VERSIONS` now `["1.1.0","1.2.0","1.3.0","1.4.0","1.5.0"]`; `PathAllowlistGuard` shipped (`guards/path_allowlist.rs`); posture, observe, synth all shipped (`policy_observe.rs`, `policy_synth.rs`). | **ARCHIVE** (replace with ADR-0009 "dynamic policies & postures shipped in v1.2-1.5") |
| 3 | `docs/roadmaps/spider-sense-integration.md` | 963 | 2026-03-05 `#174` | DRAFT, target v1.2.0+ | **Shipped as first-class built-in 2026-03-03** per `MEMORY.md`. `crates/libs/clawdstrike/src/spider_sense.rs` exists, `rulesets/spider-sense.yaml` exists, `rulesets/patterns/s2bench-v1.json` exists. | **ARCHIVE** |
| 4 | `docs/roadmaps/implementation-tasks.md` | 310 | 2026-03-05 `#174` | "ACTIVE" task tracker for v1.2.0 | **All milestones shipped or superseded.** SS-1..21 implemented in `clawdstrike` crate (not a separate `clawdstrike-spider-sense` crate as planned); SC-1..6 shipped; DP-1..3 shipped; HC-1..6 shipped. | **DELETE** |
| 5 | `docs/plans/clawdstrike/formal-verification/ROADMAP.md` | 927 | 2026-03-17 `5b8a436f8` | Active, Phases 0-2 complete, Phase 3 in progress, Phase 5 CI integrated | Confirmed accurate via `MEMORY.md` + `INDEX.md`. Active. | **KEEP** as `docs/plans/formal-verification/ROADMAP.md` (drop redundant `clawdstrike/` nesting); link from canonical roadmap. |
| 6 | `docs/plans/origin-enclaves/ROADMAP.md` | 629 | 2026-03-08 `#177` | Draft v0.2, 14-week plan | **Phases 0-2 shipped** (PR #177 merged): `crates/libs/clawdstrike/src/origin.rs`, `enclave.rs`, `policy.rs` accepts `1.4.0` with `origins` block. Phases 3-7 (Slack, GitHub, enterprise adapters) not in `packages/adapters/`. | **ARCHIVE** as ADR-0010 + keep slim "post-launch" follow-up doc only if Phase 3+ is still funded. |
| 7 | `docs/plans/origin-enclaves/sdk-parity-roadmap.md` | 93 | 2026-03-09 `#181` | Draft, follow-up to PR 177 | PR #181 merged Python + Go origin parity. Roadmap is now historical. | **ARCHIVE** |
| 8 | `docs/plans/sentinel-swarm/NEXT-WAVE-ROADMAP.md` | 135 | 2026-03-14 `#190` | "Active roadmap", Phase 0 in progress | Sentinel swarm UI shipped per PR #190; `apps/workbench/src/features/missions/`, `swarm-*`, `finding-store.tsx` all present. Phases 1-4 (drivers, missions, federation) not yet in code. | **MERGE INTO canonical** as a one-paragraph "Sentinel Swarm next phase: drivers + missions" line; keep full doc under `docs/plans/sentinel-swarm/` only while phase 1 is active. |
| 9 | `docs/plans/clawdstrike/secret-broker/roadmap.md` | 518 | 2026-03-14 `#191` | Draft | Phases 0-5 effectively shipped: `crates/services/clawdstrike-brokerd/`, `crates/libs/clawdstrike-broker-protocol/`, `crates/services/hushd/src/api/broker.rs`, schema v1.5.0 broker block, DPoP support, file/env/HTTP secret backends. Phase 6 (generic HTTPS) explicit in current docs. | **ARCHIVE** (Phase 0-5 done); replace with ADR-0011. |
| 10 | `docs/plans/editor-ide/ROADMAP.md` | 229 | 2026-03-16 `#196` | Version 1.0.0-draft | PR #196 landed Phase 0-2 (multi-format editor, Sigma + OCSF). Phases 3-6 (YARA scanning, ATT&CK heatmap, file explorer, command palette, SigmaHQ import) not all in. | **KEEP** under `docs/plans/editor-ide/` while phases 3-6 are in-flight; **MERGE** when complete. |
| 11 | `docs/plans/clawdstrike/endpoint-decision-engine/roadmap.md` | 1,469 | 2026-05-19 `dc4c717ad` | Draft (newest active) | Active. `crates/libs/clawdstrike-policy-event/src/edr/` already has detection, receipt, response, sensor_state, simulation modules. Phase 0 mostly shipped per the dense status preamble. | **KEEP** under `docs/plans/endpoint-decision-engine/` (drop `clawdstrike/` nesting) — this is the **only roadmap actively being worked on this month**. |
| 12 | `docs/plans/clawdstrike/huntronomer/roadmap.md` | 156 | 2026-03-07 `6b8844552` | Draft | Stale 11 weeks. Many huntronomer git ops since but never updated this doc. Direction has shifted to workbench/editor-ide; "Huntronomer V1" branding no longer in shipping code. | **DELETE** (superseded by sentinel-swarm + editor-ide). |
| 13 | `docs/plans/clawdstrike/huntronomer/workspace-shell/roadmap.md` | 201 | 2026-03-07 `40adeb549` | Draft | **Abandoned.** Plan calls for `crates/libs/huntronomer-workspace-core/` — directory **does not exist** in the repo. Workspace UX work was instead done in `apps/workbench/` and `apps/desktop/`. | **DELETE** |
| 14 | `docs/plans/siem-soar/roadmap.md` | 494 | 2026-03-05 `#174` | "GA" scope matrix | Mostly shipped (`crates/services/hushd/src/siem/` has Splunk, Elastic, Datadog, Sumo Logic, PagerDuty, Slack/Teams, STIX/TAXII). | **ARCHIVE** as ADR-0012 ("SIEM/SOAR exporter set v1 — shipped"). |
| 15 | `docs/src/hunt/ROADMAP.md` | 1,289 | 2026-03-05 `#174` | Phase 1-3 referenced | Phase 1-3 implemented: `crates/services/hush-cli/src/hunt.rs`, `crates/libs/hunt-correlate`, `hunt-query`, `hunt-scan` all exist. E2E coverage in `hush_cli/tests/hunt_e2e.rs`. | **ARCHIVE** (move to `docs/plans/decisions/archive/` and link from `docs/src/hunt/index.md`). |
| 16 | `docs/plans/clawdstrike/reference-architectures/implementation-roadmap.md` | 231 | 2026-03-05 `#174` | Reference architecture tracker | Pure cross-cutting catalog with no work items not already on `docs/src/roadmap.md` or other plans. References `docs/plans/implementation-pad.md` which is itself a scratchpad. | **DELETE** (content fully absorbed by canonical roadmap + ADRs). |
| 17 | `.planning/ROADMAP.md` | 103 | 2026-03-21 `88f85cbe3` | "ClawdStrike Academy" (browser-based onboarding) | Live but for a **separate product** (Academy), not the core engine. Belongs in its own tree — but `.planning/` is not even on the documentation publish path. | **MOVE** to `apps/academy/ROADMAP.md` (or wherever the Academy code lives) and remove from `.planning/`. |

**Totals:** Keep 3, Archive 9, Delete 4 (entries 4, 12, 13, 16), Move 1.

---

## Cross-Roadmap Overlap Map

```
Feature / Capability                  | src/roadmap | nextgen-policy | spider-sense | impl-tasks | formal-ver | origin-enc | sentinel | secret-broker | editor-ide | endpoint-eng | hunt | siem-soar | ref-arch
--------------------------------------+-------------+----------------+--------------+------------+------------+------------+----------+---------------+------------+--------------+------+-----------+---------
Policy schema v1.2 (posture/budgets)  |   "Q2-Q3"   |   PRIMARY      |   bumps to   |  Milestone |     -      |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
Policy schema v1.4 (origins)          |     -       |       -        |      -       |      -     |     -      |  PRIMARY   |    -     |       -       |     -      |      -       |  -   |     -     |    -
Policy schema v1.5 (broker)           |     -       |       -        |      -       |      -     |     -      |     -      |    -     |     PRIMARY   |     -      |      -       |  -   |     -     |    -
Spider Sense as first-class guard     |   "beta"    |       -        |   PRIMARY    |   blocks   |     -      |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
PathAllowlistGuard                    |     -       |    mentioned   |      -       |    SC-5    |     -      |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
Observe / Synth CLI                   |     -       |    PRIMARY     |      -       |   HC-3,4   |     -      |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
SIEM exporters (Splunk/Elastic/etc.)  |   listed    |       -        |      -       |   listed   |     -      |     -      |    -     |       -       |     -      |    consumes  |  -   |  PRIMARY  |  listed
Secret broker / brokered egress       |     -       |       -        |      -       |      -     |     -      |     -      |    -     |     PRIMARY   |     -      |      -       |  -   |     -     |    -
Origin enclaves / per-origin posture  |     -       |       -        |      -       |      -     |     -      |  PRIMARY   |    -     |       -       |     -      |      -       |  -   |     -     |    -
Multi-agent delegation                |   "stable"  |    listed      |    listed    |    listed  |     -      |     -      |  ext.    |    listed     |     -      |      -       |  -   |     -     |  listed
hushd multi-policy routing            |  P0/Q2-Q3   |    PRIMARY     |      -       |      -     |     -      |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
Sentinel runtime + missions           |     -       |       -        |      -       |      -     |     -      |     -      |  PRIMARY |       -       |     -      |      -       |  -   |     -     |    -
Detection IDE / multi-format editor   |     -       |       -        |      -       |      -     |     -      |     -      |    -     |       -       |  PRIMARY   |      -       |  -   |     -     |    -
Endpoint EDR receipts                 |     -       |       -        |      -       |      -     |     -      |     -      |    -     |       -       |     -      |   PRIMARY    |  -   |   feeds   |    -
Hunt CLI (scan/query/correlate)       |    listed   |       -        |      -       |      -     |     -      |     -      |    -     |       -       |     -      |    feeds     |PRIMARY|     -    |    -
Formal verification (Z3 + Lean4)      |     -       |       -        |      -       |      -     |  PRIMARY   |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
Package manager (cpkg, WASM guards)   |   PRIMARY   |       -        |      -       |      -     |     -      |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
Compliance packs (HIPAA/PCI/SOC2)     |   PRIMARY   |       -        |      -       |      -     |     -      |     -      |    -     |       -       |     -      |      -       |  -   |     -     |    -
```

**High-conflict topics (3+ owners with disagreeing status):**

1. **Policy schema versioning**: `src/roadmap.md` says v1.2.0; `nextgen-policy-roadmap.md` says v1.2.0 is the target; `origin-enclaves/ROADMAP.md` says v1.4.0; `secret-broker/roadmap.md` says v1.5.0; **shipping code says `POLICY_SCHEMA_VERSION = "1.5.0"`**. Three roadmaps lag the implementation.
2. **Spider Sense**: `src/roadmap.md` says "beta, feature-gated"; `spider-sense-integration.md` says target v1.2.0; `implementation-tasks.md` plans a separate `clawdstrike-spider-sense` crate. **Shipping code has first-class built-in `clawdstrike::spider_sense` module, no feature gate, no separate crate.**
3. **Multi-agent**: `src/roadmap.md`, `nextgen-policy`, `spider-sense-integration`, `sentinel-swarm`, `secret-broker`, `ref-arch` all reference `hush-multi-agent` — but **none** is the authoritative roadmap for delegation token evolution.
4. **Huntronomer vs Workbench vs Sentinel Swarm**: three nested plans (`huntronomer/roadmap.md`, `huntronomer/workspace-shell/roadmap.md`, `sentinel-swarm/NEXT-WAVE-ROADMAP.md`) all govern the desktop UX shell with materially different vocabulary (Wire/Huntboard vs Mission/Finding/Intel). Code took the **sentinel-swarm** path.
5. **Endpoint decision engine vs Hunt CLI**: `endpoint-decision-engine/roadmap.md` and `hunt/ROADMAP.md` both describe local-machine threat detection, with overlapping receipt/correlation semantics. No cross-reference in either direction.

---

## Shipped-but-Listed-Planned Items

These items are described as planned/in-progress in roadmaps, but already exist in the codebase. Each one is a stale-roadmap landmine for new contributors.

| Roadmap claim | Reality | Evidence |
|---------------|---------|----------|
| `nextgen-policy-roadmap.md` SC-1: "Change strict `==` to `SUPPORTED_VERSIONS` set" | **Shipped.** | `crates/libs/clawdstrike/src/policy.rs`: `&["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"]` |
| `nextgen-policy-roadmap.md` SC-5: "`PathAllowlistGuard`" | **Shipped.** | `crates/libs/clawdstrike/src/guards/path_allowlist.rs` exported as `PathAllowlistGuard` |
| `nextgen-policy-roadmap.md` HC-3/HC-4: `hush policy observe` / `synth` | **Shipped.** | `crates/services/hush-cli/src/policy_observe.rs`, `policy_synth.rs`; CLI tests at `tests.rs:393,430` |
| `spider-sense-integration.md` (entire doc, plus `src/roadmap.md` "feature-gated") | **Shipped as default built-in.** | `crates/libs/clawdstrike/src/spider_sense.rs`, `rulesets/spider-sense.yaml`, 13 built-in guards (was 12) |
| `implementation-tasks.md` SS-1: "Create `crates/libs/clawdstrike-spider-sense/` crate" | **Not built** — built inside `clawdstrike` crate instead. | No `crates/libs/clawdstrike-spider-sense/` directory |
| `origin-enclaves/ROADMAP.md` Phase 0-2 | **Shipped** PR #177. | `crates/libs/clawdstrike/src/origin.rs`, `enclave.rs`; policy version 1.4.0 supported |
| `origin-enclaves/sdk-parity-roadmap.md` Phases 2-3 | **Shipped** PR #181. | `packages/sdk/hush-py/`, `packages/sdk/hush-go/daemon_checker.go` with origin support |
| `secret-broker/roadmap.md` Phases 0-5 | **Shipped** PR #191. | `crates/services/clawdstrike-brokerd/`, `crates/libs/clawdstrike-broker-protocol/`, `hushd/src/api/broker.rs`, schema v1.5.0 broker block, DPoP, file/env/HTTP backends |
| `editor-ide/ROADMAP.md` Phase 0-2 | **Shipped** PR #196. | `apps/workbench/src/features/editor/` |
| `siem-soar/roadmap.md` "GA" matrix | **Shipped.** | `crates/services/hushd/src/siem/` (24 files: Splunk, Elastic, Datadog, Sumo, PagerDuty, Slack/Teams, STIX/TAXII) |
| `hunt/ROADMAP.md` Phases 1-3 | **Shipped.** | `crates/services/hush-cli/src/hunt.rs`; `crates/libs/hunt-correlate`, `hunt-query`, `hunt-scan`; E2E gate at `tests/hunt_e2e.rs` |
| `src/roadmap.md`: "12 built-in guards" | **13 shipped** (Spider Sense promoted). | See `MEMORY.md`; `rulesets/spider-sense.yaml` |
| `src/roadmap.md`: schema v1.2.0 | **v1.5.0 in code.** | `POLICY_SCHEMA_VERSION = "1.5.0"` |
| `src/roadmap.md` Q3 2026: "Multi-tenant control API" | **`crates/services/control-api/` exists** with auth, models, policies, response_actions routes. | `crates/services/control-api/src/routes/` |
| `src/roadmap.md`: Package Manager Phase 0-1 (P0) | **`crates/libs/clawdstrike-guard-sdk` + `clawdstrike-guard-sdk-macros` + `clawdstrike-registry` shipped**; `hush pkg pack/install` CLI is wired (`pkg_cli.rs:228+ Trusted/Org commands present`). | `crates/libs/clawdstrike-registry/`, `crates/services/hush-cli/src/pkg_cli.rs` |

---

## Abandoned-but-Aspirational Items

Items planned that the code went a different direction on. Deletion candidates — the plans now mislead more than they inform.

| Plan | Reality | Recommendation |
|------|---------|----------------|
| `huntronomer/workspace-shell/roadmap.md` calls for `crates/libs/huntronomer-workspace-core/` | Directory does **not** exist. Workspace UX work landed in `apps/workbench/` (React) and `apps/desktop/src-tauri/`. The "thin frontend over backend-owned services" model was rejected. | **DELETE** the doc. Salvage useful contracts (PTY, fd/rg search, watcher) into ADR if any team still cares. |
| `huntronomer/roadmap.md` "Wire / Huntboard / Vault" rail vocabulary | Code uses "Sentinel / Finding / Mission / Intel" vocabulary (see `apps/workbench/src/features/missions/`, `findings/`). | **DELETE.** Sentinel-swarm replaced this. |
| `implementation-tasks.md` SS-1: separate `clawdstrike-spider-sense` crate | Spider Sense ships **inside** `clawdstrike` crate, always-on, WASM-safe. | **DELETE** the tracker; the architectural choice was made explicitly to keep WASM compatibility. |
| `nextgen-policy-roadmap.md` `Sanitize` decision variant (SC-4) | `crates/libs/clawdstrike/src/policy_event.rs` decisions are still `Allow`/`Deny`/`AskUser`. No `Sanitize` variant landed. | **DOCUMENT as deferred** in an ADR or kill outright. |
| `spider-sense-integration.md` deep-analysis async LLM judge | Shipped detection module is the embedding fast-path only; the LLM judge is "optional deep path" per docs but no Rust implementation of `SpiderSenseDeepAnalysis` async guard found in `async_guards/`. | **DOCUMENT as not-shipped** in canonical roadmap if still desired. |
| `src/roadmap.md` Reticulum/LoRa "off-grid enforcement" | No `hush-reticulum` crate in `crates/`. Spec exists at `docs/specs/12-reticulum-adapter.md` but no shipping code. | **MOVE** to a clearly-flagged "Research/Speculative" section. |
| `src/roadmap.md` "EAS On-Chain Anchoring" listed as Experimental | `crates/services/eas-anchor/` exists but `MEMORY.md` and inventory suggest it is barely used. Confirm whether to demote or delete. | **CHECK** with owner; either promote to "Stable" or drop from roadmap. |
| `ref-arch/implementation-roadmap.md` cross-cuts | All the cross-cutting items are duplicated in other plans. Nothing here is uniquely owned. | **DELETE.** |
| `.planning/ROADMAP.md` "ClawdStrike Academy" | Lives in `.planning/`, which is not in any publish path. Belongs in `apps/academy/` if that's the deployed app. | **MOVE** out of the engine repo's planning tree. |

---

## Proposed Canonical Roadmap Structure

```
docs/src/roadmap.md                        # Current quarter only, ≤300 lines, milestones tied to versions
docs/plans/decisions/
  0009-dynamic-policies-shipped.md         # Replaces nextgen-policy-roadmap
  0010-origin-enclaves-shipped.md          # Replaces origin-enclaves/ROADMAP.md
  0011-secret-broker-shipped.md            # Replaces secret-broker/roadmap.md
  0012-siem-soar-v1-shipped.md             # Replaces siem-soar/roadmap.md
  0013-spider-sense-firstclass.md          # Captures Spider Sense decision
  0014-hunt-cli-v1-shipped.md              # Replaces docs/src/hunt/ROADMAP.md
  0015-package-manager-cpkg.md             # Captures cpkg+registry direction
docs/plans/decisions/archive/              # Frozen, no-edit historical artifacts
  nextgen-policy-roadmap.md
  spider-sense-integration.md
  origin-enclaves-ROADMAP.md
  origin-enclaves-sdk-parity-roadmap.md
  secret-broker-roadmap.md
  siem-soar-roadmap.md
  hunt-ROADMAP.md
  reference-architectures-implementation-roadmap.md
  sentinel-swarm-NEXT-WAVE-ROADMAP.md         # After phases 1-4 finish
docs/plans/<feature>/                       # Only while in-flight; move to archive when shipped
  formal-verification/                      # Still active — keep
  endpoint-decision-engine/                 # Still active (newest, May 2026) — keep
  editor-ide/                               # Phases 3-6 not yet shipped — keep
```

### Section-by-section ownership

**`docs/src/roadmap.md` (rewritten, ≤300 lines, current quarter only):**

- Current shipping state (one paragraph: schema v1.5.0, 13 built-in guards, broker, enclaves, sentinel swarm UI, EDR receipts in-progress)
- This-quarter milestones (3-6 items with named owners + version targets)
- Next-quarter peek (3-6 items, headline only)
- Research/experimental list (off-grid, EAS, Reticulum — clearly flagged)
- Link block to active in-flight plans (`formal-verification/`, `endpoint-decision-engine/`, `editor-ide/`)
- Link block to ADRs for shipped decisions

**`docs/plans/decisions/` (new ADR series — see structure above):**

- ADRs 0001-0008 already exist; new ones 0009-0015 capture each shipped roadmap as a single ADR each (~100-200 lines) summarising: motivation, decision, status, link to archived historical doc.

**`docs/plans/decisions/archive/`:**

- One markdown file per archived roadmap. **Read-only.** Top-of-file banner: "Archived 2026-05-23 — superseded by ADR-####. Do not edit. Code is the source of truth."

**Per-feature `docs/plans/<feature>/`:**

- Only stays for `formal-verification/`, `endpoint-decision-engine/`, `editor-ide/`.
- Each gets a slim `INDEX.md` and a single `ROADMAP.md`. Supporting design notes stay but get archived once the feature ships.

**Out of `.planning/`:**

- `.planning/ROADMAP.md` (ClawdStrike Academy) moves to its own product tree, not this engine repo.

---

## Migration Plan

Six small, reviewable commits. Each is independent enough to revert if a stakeholder objects.

### Commit 1 — Canonical roadmap rewrite

- Replace `docs/src/roadmap.md` with a 250-300 line current-state + current-quarter version.
- Update guard count to 13, schema to v1.5.0, mark Spider Sense first-class.
- Move package-manager content from "Phase 0-1 P0" to "Shipped: cpkg + registry"; demote remaining phases to current-quarter or next-quarter as appropriate.
- Add the Research section with Reticulum + EAS clearly flagged.
- Link to ADRs (forward references; files added in commit 2).

### Commit 2 — Add ADRs 0009-0015

- One commit, 7 new ADR files under `docs/plans/decisions/`. Each ADR is short (~100 lines): context, decision, status: **Accepted/Shipped**, references to code, link to archived doc that will land in commit 3.

### Commit 3 — Archive shipped roadmaps

`git mv` (preserves history) the following into `docs/plans/decisions/archive/`:
- `docs/roadmaps/nextgen-policy-roadmap.md`
- `docs/roadmaps/spider-sense-integration.md`
- `docs/plans/origin-enclaves/ROADMAP.md` → `archive/origin-enclaves-ROADMAP.md`
- `docs/plans/origin-enclaves/sdk-parity-roadmap.md` → `archive/origin-enclaves-sdk-parity-roadmap.md`
- `docs/plans/clawdstrike/secret-broker/roadmap.md` → `archive/secret-broker-roadmap.md`
- `docs/plans/siem-soar/roadmap.md` → `archive/siem-soar-roadmap.md`
- `docs/src/hunt/ROADMAP.md` → `archive/hunt-ROADMAP.md`

Add a 3-line banner at the top of each: "Archived YYYY-MM-DD. Superseded by ADR-####. Read-only."

### Commit 4 — Delete dead roadmaps

`git rm`:
- `docs/roadmaps/implementation-tasks.md` (every task shipped or rejected)
- `docs/plans/clawdstrike/huntronomer/roadmap.md` (superseded by sentinel-swarm)
- `docs/plans/clawdstrike/huntronomer/workspace-shell/roadmap.md` (abandoned; references non-existent crate)
- `docs/plans/clawdstrike/reference-architectures/implementation-roadmap.md` (pure duplication)

If the huntronomer/workspace-shell roadmaps still have salvageable design (PTY, fd/rg search contracts), excerpt into an ADR first, then delete.

### Commit 5 — Flatten in-flight plans

`git mv` to drop redundant `clawdstrike/` nesting:
- `docs/plans/clawdstrike/formal-verification/` → `docs/plans/formal-verification/`
- `docs/plans/clawdstrike/endpoint-decision-engine/` → `docs/plans/endpoint-decision-engine/`

`editor-ide/` is already top-level under `docs/plans/`; no move needed.

Delete remaining empty `docs/plans/clawdstrike/` subtree.

Move sentinel-swarm `NEXT-WAVE-ROADMAP.md` to `docs/plans/sentinel-swarm/ROADMAP.md` (one canonical file per active plan). Archive any supporting docs that describe shipped phases; keep `SENTINEL-RUNTIME.md`, `MISSION-EVIDENCE-LOOP.md`, `FEDERATED-INTEL.md` only while those phases are active.

### Commit 6 — Update cross-links and SUMMARY.md

- mdBook `SUMMARY.md`: remove dead links, point to canonical roadmap + ADR index.
- `docs/DOCS_MAP.md`, `docs/REPO_MAP.md`, `docs/HANDOFF.md`: update any roadmap references.
- `CLAUDE.md` "Source of truth" section: explicitly say `docs/src/roadmap.md` is the only roadmap; everything else is an ADR or an in-flight plan.
- `.planning/ROADMAP.md`: either move to `apps/academy/` or delete with a banner pointing to where the Academy roadmap now lives.

### Commit 7 (optional cleanup) — Quarantine `.planning/`

`.planning/` is not on any documentation publish path and contains a roadmap for a completely different product (Academy). Either:
- Move it to that product's repo/app, or
- Delete it and add `.planning/` to `.gitignore`.

---

## Quick-Reference Decision Table

| File | Action | Reason |
|------|--------|--------|
| `docs/src/roadmap.md` | **REWRITE** (≤300 lines) | Source of truth, but currently stale and bloated |
| `docs/roadmaps/nextgen-policy-roadmap.md` | ARCHIVE → ADR-0009 | Shipped in v1.2-v1.5 |
| `docs/roadmaps/spider-sense-integration.md` | ARCHIVE → ADR-0013 | Shipped first-class 2026-03-03 |
| `docs/roadmaps/implementation-tasks.md` | DELETE | All tasks shipped/superseded |
| `docs/plans/clawdstrike/formal-verification/ROADMAP.md` | KEEP + move up | Actively in progress (Phase 3) |
| `docs/plans/origin-enclaves/ROADMAP.md` | ARCHIVE → ADR-0010 | Phases 0-2 shipped (PR #177) |
| `docs/plans/origin-enclaves/sdk-parity-roadmap.md` | ARCHIVE | Shipped (PR #181) |
| `docs/plans/sentinel-swarm/NEXT-WAVE-ROADMAP.md` | RENAME to ROADMAP.md, keep in-flight | Phase 0 in code, phases 1-4 ongoing |
| `docs/plans/clawdstrike/secret-broker/roadmap.md` | ARCHIVE → ADR-0011 | Phases 0-5 shipped (PR #191) |
| `docs/plans/editor-ide/ROADMAP.md` | KEEP | Phases 3-6 still in flight |
| `docs/plans/clawdstrike/endpoint-decision-engine/roadmap.md` | KEEP + move up | **Newest, most active (May 2026)** |
| `docs/plans/clawdstrike/huntronomer/roadmap.md` | DELETE | Superseded by sentinel-swarm |
| `docs/plans/clawdstrike/huntronomer/workspace-shell/roadmap.md` | DELETE | Abandoned (target crate never created) |
| `docs/plans/siem-soar/roadmap.md` | ARCHIVE → ADR-0012 | "GA" matrix all shipped |
| `docs/src/hunt/ROADMAP.md` | ARCHIVE → ADR-0014 | Phases 1-3 shipped with E2E gate |
| `docs/plans/clawdstrike/reference-architectures/implementation-roadmap.md` | DELETE | Pure duplication |
| `.planning/ROADMAP.md` | MOVE out of repo | Different product (Academy) |

**Net reduction:** ~10,912 LOC of roadmap content → ~1,500 LOC (canonical 300 + 7 ADRs × ~150 + 3 active plans).
