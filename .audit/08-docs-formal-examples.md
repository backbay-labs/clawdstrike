# Docs / Formal / Examples Audit

> **Auditor:** Claude (Opus 4.7, 1M ctx)
> **Date:** 2026-05-23
> **Scope:** `docs/`, `formal/`, `examples/`, planning artefacts.
> **Out of scope:** `crates/`, `packages/`, `apps/`, `infra/vendor/`.
> **Counts:** 385 markdown files under `docs/` (131 in `docs/src/`, 164 in `docs/plans/`, 14 in `docs/audits/`), ~144 files under `examples/`, ~5.5k LOC of hand-written Lean across 8 spec/proof files plus ~5k LOC of Aeneas-generated Lean.

---

## Executive Summary

A sophisticated OSS consumer landing on this repository would draw three conclusions in quick succession. **First, the public mdBook is in genuinely good shape.** `mdbook build` succeeds with no warnings, every `SUMMARY.md` entry resolves to a real file, the introduction has a working quickstart, all 15 guards have reference pages, and the rulesets/API/concepts areas are filled out. That alone puts this ahead of 90% of crypto-adjacent OSS docs. **Second, the formal verification story is the single strongest differentiator and the single most dangerous over-claim.** `lake build` succeeds (Lean 4.28.0-rc1), 155 theorems compile, and the architecture (Aeneas-translated impl + hand-written spec + bridge proofs + iterator axioms + differential tests) is intellectually honest and well-documented. But there are ~7 `sorry` admissions in load-bearing files (`MergeMonotonicity.lean:122`, four in `Impl/Merkle/Funs.lean`, plus comment-form `sorry` references in `SpecImplEquiv.lean` and `DenyMonotonicity_Impl.lean`), 145 `axiom` declarations (35 in `Impl/FunsExternal.lean`, 13 in `IteratorAxioms.lean`, etc.), and the public docs only obliquely admit this. `docs/src/formal-verification.md` says "Lean's type checker guarantees validity" without flagging the admissions, and the INDEX.md table claims "P4 partial, P7 partial" but a power user has to grep `sorry` to see that. The Aeneas-generated `Impl/Merkle/Funs.lean` literally has `sorry` in serde serializer bodies that downstream proofs depend on transitively.

**Third, the planning corpus is overgrown and aspirational.** Eighteen `docs/plans/<topic>/` directories, multiple overlapping "roadmaps" (`docs/src/roadmap.md`, `docs/plans/clawdstrike/formal-verification/ROADMAP.md`, `docs/plans/origin-enclaves/ROADMAP.md`, `docs/plans/sentinel-swarm/NEXT-WAVE-ROADMAP.md`, `docs/plans/clawdstrike/secret-broker/roadmap.md`, `docs/plans/clawdstrike/huntronomer/roadmap.md`, `docs/roadmaps/nextgen-policy-roadmap.md` at 2,496 lines, `docs/roadmaps/spider-sense-integration.md` at 963 lines, plus `docs/HANDOFF.md` from Feb 7 calling out a PR #40 that long since landed), seven "agent framework" plans (`docs/plans/agent-frameworks/{autogpt,crewai,langchain,vercel-ai,autogpt,generic-adapter,comparison}.md`) for adapters that mostly don't exist in `packages/adapters/`, a PACT "Pre-RFC" protocol doc that competes with MCP, an `editor-ide/` directory with both a `UI-POLISH-CAMPAIGN.md` and a `UI-POLISH-CAMPAIGN-R2.md`, and a `sentinel-swarm/` set whose `INDEX.md` is 768 lines and `DATA-MODEL.md` is 1,795 lines. The signal-to-noise ratio in `docs/plans/` is the most obvious "this is not a serious OSS project" tell in the repository.

**The examples are mostly fine but version-drifted.** Of 23 example directories, six policy files still use `version: "1.0.0"` (which is not in `POLICY_SUPPORTED_SCHEMA_VERSIONS = ["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"]`) and three use the legacy `version: "clawdstrike-v1.0"` string. `examples/hybrid-swarm/policy-reviewer.yaml` and `examples/red-blue-swarm/policy.yaml` use `schema_version:` (no such field — the field is `version`). The agent demos themselves (`hello-secure-agent-{ts,py,vercel}`) are clean, idiomatic, and demonstrate the right "guard-decision-then-execute" pattern. A serious cleanup of versions + deletion of stale roadmap forests + tightening of the formal-verification public messaging would move this from "ambitious solo project" to "credible open source."

---

## Inventory

| Doc area | Purpose | Currency |
|----------|---------|----------|
| `docs/src/README.md` | mdBook intro / quickstart | Fresh, accurate |
| `docs/src/SUMMARY.md` | Book TOC (170 lines, ~135 chapters) | Fresh; all entries exist |
| `docs/src/concepts/` | 11 conceptual chapters | Mostly fresh |
| `docs/src/getting-started/` | Install + 3 quickstarts + first policy | Fresh |
| `docs/src/guides/` | 21 task guides | Mostly fresh; openclaw-* dense and legacy |
| `docs/src/reference/` | Policy schema, guards (16), rulesets (10), APIs (5) | Fresh, complete, well-cross-linked |
| `docs/src/fleet-security/` | 8 chapters on fleet ops | Fresh |
| `docs/src/hunt/` | Hunt CLI docs (10 chapters) | Fresh; `report.md` honestly flagged "planned" |
| `docs/src/package-manager/` | 6 chapters | **Aspirational** — feature not shipped |
| `docs/src/plugins/` | 9 chapters + 6 contribution-point pages | **Aspirational** — plugin runtime not shipped |
| `docs/src/formal-verification.md` | Public-facing formal doc | Fresh but over-claims (see findings) |
| `docs/src/roadmap.md` (639 lines) | Public roadmap | Stale — "Last updated 2026-03-03"; many Q2/Q3 dates already passed |
| `docs/src/rfcs/0001-package-manager.md` (872 lines) | Sole RFC | Honest design doc |
| `docs/README.md`, `docs/DOCS_MAP.md`, `docs/REPO_MAP.md` | Meta-index pages | Fresh (2026-02-26) |
| `docs/HANDOFF.md` (241 lines) | One-shot Feb-7 PR-#40 handoff | **Stale — should be deleted** |
| `docs/auth.md` | Floating 2026-02-09 auth note | Orphan |
| `docs/plans/README.md` | Planning index | Stub (22 lines), points to disjoint subdirs |
| `docs/plans/implementation-pad.md` (471 lines, last touched Feb 7) | "Working scratchpad" | **Abandoned** |
| `docs/plans/monorepo-staff-organization-plan.md` | "Phase 0-5 committed" | **Completed — should be ADR** |
| `docs/plans/HANDOFF.md` cousins (`2026-02-25-openclaw-adapter-core-alignment.md`) | One-off plan | Superseded by audits |
| `docs/plans/clawdstrike/formal-verification/` (10 files, 5.5k lines) | Verification design + roadmap | Fresh, dense |
| `docs/plans/clawdstrike/huntronomer/` + `workspace-shell/` | 10 files | Fresh but huge (5k+ lines) |
| `docs/plans/clawdstrike/secret-broker/` | 5 files | Fresh |
| `docs/plans/clawdstrike/endpoint-decision-engine/` | 4 files | Fresh |
| `docs/plans/clawdstrike/macos-es-ne/` | 4 files | Fresh (current branch) |
| `docs/plans/clawdstrike/reference-architectures/` | 9 files | Aspirational; not user-facing |
| `docs/plans/clawdstrike/adaptive-sdr-{review,implementation,research-brief}.md` (~85k tokens total) | SDR research/plan trio | Should consolidate to ADR + delete two |
| `docs/plans/agent-frameworks/` | 7 files: autogpt, crewai, vercel-ai, langchain, generic-adapter, comparison, overview | **Mostly fictional** — no autogpt/crewai/langchain adapter pkgs |
| `docs/plans/custom-guards/` | 7 files | Aspirational |
| `docs/plans/policy-as-code/` | 7 files | Aspirational |
| `docs/plans/multi-agent/` | 8 files | Mix of design + active "codex-swarm-playbook" |
| `docs/plans/identity-access/` | 6 files | Aspirational |
| `docs/plans/origin-enclaves/` (~1700 lines) | 5 files | Active branch |
| `docs/plans/prompt-security/` | 8 files | Mix design / shipped |
| `docs/plans/sentinel-swarm/` (10 files, ~6800 lines) | "Sentinel-Swarm" reimagining | Aspirational megaproject |
| `docs/plans/siem-soar/` | 9 vendor-specific docs | Mostly aspirational |
| `docs/plans/swarm-engine/` (~4700 lines) | "Ported from ruflo v3" | Aspirational |
| `docs/plans/threat-intel/` | 7 files | Aspirational |
| `docs/plans/certification/` | 8 files | Aspirational |
| `docs/plans/editor-ide/` (UI-POLISH-CAMPAIGN + R2 + 5 others) | Editor concept | Aspirational + duplicated |
| `docs/plans/workbench-dev/` (7 files, ~100k chars) | Workbench refactor | Active in worktree |
| `docs/plans/pact/PROTOCOL.md` | "PACT: Provable Agent Capability Transport" Pre-RFC | Speculative |
| `docs/plans/hushspec/carve-out-plan.md` | One-off | Orphan |
| `docs/plans/decisions/0001..0008-*.md` | ADRs | Good — keep |
| `docs/specs/01..19-*.md` (20 files) | Normative specs | Mix shipped + aspirational; HANDOFF references them |
| `docs/audits/` (14 files) | Point-in-time audits | Mostly 2026-02; should age out |
| `docs/audits/2026-02-26-docs-audit-index.md` | Self-audit, 52 findings | **Many findings still open** |
| `docs/research/` (11 files) | Exploratory writing | Some superseded (architecture-vision predates current arch) |
| `docs/roadmaps/` | Yet another roadmap dir, includes `cua/deep-research-report.md` (678 lines) and `nextgen-policy-roadmap.md` (2,496 lines) | Aspirational, overlaps with `docs/plans/` |
| `docs/nono-integration/` | 8-file legacy integration plan | Orphan — not linked from anywhere |
| `docs/ops/` | 3 operational guides | Fresh, narrow |
| `docs/security/` | 1 file (dependency-advisories.md) | Fresh |
| `docs/static/` | 3 PNGs (jailbreak/adaptive intro) | Used by jailbreak guard doc |
| `docs/book/` | Pre-built mdBook HTML | **Should not be committed** |
| `formal/lean4/ClawdStrike/ClawdStrike/Core/` | 7 hand-written Lean spec files (~860 LOC) | Fresh, compiles |
| `formal/lean4/ClawdStrike/ClawdStrike/Spec/` | 2 files: Properties (707 LOC), MerkleProperties (216 LOC) | Properties.lean fully proved; MerkleProperties has axioms |
| `formal/lean4/ClawdStrike/ClawdStrike/Proofs/` | 6 files (~750 LOC) — top-level proofs | 1 `sorry` in MergeMonotonicity |
| `formal/lean4/ClawdStrike/ClawdStrike/Proofs/Impl/` | 4 files (~1k LOC) — bridge proofs | 13 axioms, structural |
| `formal/lean4/ClawdStrike/ClawdStrike/Impl/` | Aeneas-generated (~1500 LOC) | Auto-generated, marked do-not-edit |
| `formal/lean4/ClawdStrike/ClawdStrike/Impl/Merkle/Funs.lean` (1064 LOC) | Aeneas-generated Merkle | **4 `sorry`s in serde bodies** |
| `formal/tlaplus/PostureStateMachine.tla` + .cfg | TLA+ posture model | Orphan — not referenced anywhere in docs |
| `formal/scripts/` | Verification scripts | Lightly documented |
| `examples/README.md` | Top-level index | Lists 23 examples; accurate |
| `examples/hello-secure-agent-{ts,py,vercel}` | Quickstart trio | Clean, idiomatic |
| `examples/bb-edr`, `edr-pipeline`, `secure-coding-assistant`, `openclaw-plugin` | Use legacy `clawdstrike-v1.0` or `1.0.0` schema | Stale schema |
| `examples/docker-compose`, `enterprise-deployment` | Use `1.0.0` schema | Stale schema |
| `examples/hybrid-swarm`, `red-blue-swarm` | Use non-existent `schema_version:` key | **Broken** |
| `examples/policies/{project-base,extend-strict,threat-intel-*}.yaml` | Sample policies | 4 of 9 use `1.0.0` (unsupported) |
| `examples/spider-sense-threat-intel` | TS/Py/Go parity demo | Fresh |
| `examples/autonomous-sandbox`, `multi-agent-orchestration`, `delegated-pipeline` | Rust demos | Fresh |
| `examples/generic-adapter`, `output-sanitization`, `prompt-watermarking`, `jailbreak-detection`, `secure-agent-swarm` | Various feature demos | Fresh |
| `examples/rust/basic-verification`, `examples/typescript/browser-verify` | Tiny WASM demos | Fresh |

---

## Scores (1-10)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| Docs accuracy vs code | **6/10** | mdBook reference is close; policy-schema page caps at 1.4.0 while code is 1.5.0; CLAUDE.md disagrees with mdBook; six examples use unsupported schema versions; package-manager + plugins sections describe unshipped code. |
| Onboarding clarity | **8/10** | Real quickstart that works; three language entry points; clean hello-secure-agent demos. Lose a point for the maze of plans/roadmaps and another for unclear "what's shipped" signaling. |
| Examples quality | **7/10** | Most examples runnable and idiomatic, READMEs are honest. Lose points for schema-version drift, two literally invalid YAML (`schema_version` key), and `openclaw-v1.0` legacy schema lingering. |
| Formal verification rigor | **6/10** | Genuinely impressive scope (Aeneas + Lean + Z3/Logos + diff testing + CI). Lake builds cleanly. Lose substantial points for: ≥7 `sorry` admissions in load-bearing files including bridge proofs and Merkle, 145 `axiom`s including bespoke iterator axioms, public docs that under-state these gaps, and a TLA+ file nobody references. |
| Doc structure / discoverability | **5/10** | mdBook is well-organized internally, but `docs/plans/` vs `docs/specs/` vs `docs/roadmaps/` vs `docs/research/` vs `docs/audits/` vs `docs/ops/` vs `docs/reports/` vs `docs/nono-integration/` is bewildering. DOCS_MAP.md tries to disambiguate, but the existence of seven canonical roots is the problem. |
| Planning doc hygiene | **2/10** | This is the weakest area. Eight separately-named "roadmaps" with different statuses, 7 fictional agent-framework specs, multiple "Phase 7" plans for unstarted work, a `HANDOFF.md` from February still in the root, an `implementation-pad.md` last touched 2026-02-07, an editor `UI-POLISH-CAMPAIGN.md` paired with `UI-POLISH-CAMPAIGN-R2.md`, and a Pre-RFC for a competitor to MCP. |

---

## Strengths

1. **The mdBook actually builds and is internally consistent.** `mdbook build` succeeds with zero warnings; every `SUMMARY.md` entry resolves. This is uncommon and worth keeping.
2. **The hand-written Lean spec is high quality.** `formal/lean4/ClawdStrike/ClawdStrike/Spec/Properties.lean` (707 LOC) is genuinely well-structured — P1 (deny monotonicity), P2 (allow requires unanimity), P3 (severity total order), P4 (forbidden-path soundness), P4a (end-to-end), P5 (inheritance restrictiveness), and the supporting lemmas are all fully proved in 707 lines without `sorry`. That is rare for a 0.1.x project.
3. **`docs/plans/decisions/0001..0008-*.md`** are short, dated, scoped ADRs — exactly what an ADR should be. Keep this pattern; expand it; delete the rest of `docs/plans/`.
4. **`docs/src/reference/guards/`** has a page for each of 15 guards, named consistently. The reference area is the most polished part of the docs.
5. **The "honest planning" idiom is present in some places.** `docs/src/hunt/report.md` opens with "`hunt report` is a planned command and is not implemented" — that's exactly right. The pattern should be applied to plugins/ and package-manager/.
6. **`docs/audits/2026-02-26-docs-audit-index.md`** is a great artifact — 52 findings, indexed, with cross-references. Most have been fixed (schema 1.2.0 drift was repaired). The repo *has* shown it can do quality audits when motivated.
7. **The examples READMEs include explicit "dry-run" modes** (e.g., `--dry-run` in `hello-secure-agent-{ts,py}`) so users can try the demos without API keys. Thoughtful UX.
8. **`formal-diff-tests` (proptest spec vs impl)** plus CI integration (`.github/workflows/formal-verification.yml`) is the right epistemic move when bridge proofs use axioms.

---

## Findings

### [CRITICAL] Formal: Public formal-verification doc oversells what is proved

- **Where:** `docs/src/formal-verification.md:62` ("Level 2 — Lean-Proved: Core properties proved about the spec") and `docs/src/formal-verification.md:115-135` (lists P1-P13 as proved without flagging `sorry` admissions); `docs/src/formal-verification.md:217` ("A successful build means every theorem in `Spec/Properties.lean` has been verified by Lean's kernel" — true narrowly, misleading broadly).
- **What:** The public page enumerates P1-P13 as if all are proved. In reality, P4 (merge monotonicity) has a `sorry` at `formal/lean4/ClawdStrike/ClawdStrike/Proofs/MergeMonotonicity.lean:122` (`-- requires detailed list membership reasoning through filter/append`). The Aeneas-generated Merkle code (`formal/lean4/ClawdStrike/ClawdStrike/Impl/Merkle/Funs.lean:589, 632, 768, 895`) has four `sorry`s inside serde serializer bodies that any downstream Merkle inclusion claim transits. The bridge proofs in `Proofs/Impl/SpecImplEquiv.lean` and `Proofs/Impl/DenyMonotonicity_Impl.lean` rely on 13 hand-written iterator axioms in `IteratorAxioms.lean`. The public doc mentions none of this.
- **Why it matters:** Formal verification is the single biggest differentiator the project advertises. An overclaim here is reputationally catastrophic — a single Twitter thread from an academic verification person walking through the `sorry`s will end the credibility of the entire project.
- **Recommended action:** REWRITE `docs/src/formal-verification.md`. Add a "Limitations" section that says, verbatim: (a) Spec/Properties.lean is `sorry`-free for P1, P2, P3, P4 (forbidden-path), P5 (inheritance abstract); (b) MergeMonotonicity has 1 admitted sublemma; (c) Merkle properties are partial — the Aeneas-translated serde bodies contain `sorry`; (d) implementation-level bridge proofs are *modulo* 13 hand-stated axioms about Rust iterator behavior, plus the Aeneas standard library's `FunsExternal.lean` axioms (35 in this project alone). Promote `cargo test -p formal-diff-tests` (1M proptest cases vs spec) as the empirical complement.
- **Effort:** small.

### [CRITICAL] Formal: `sorry` admissions in Aeneas-generated Merkle serializer bodies

- **Where:** `formal/lean4/ClawdStrike/ClawdStrike/Impl/Merkle/Funs.lean:589, 632, 768, 895` (all `sorry` inside serde `serialize` bodies).
- **What:** The file is marked "do not edit" (Aeneas-generated), yet contains hand-injected `sorry`. Either Aeneas failed to translate these serde impls and someone manually patched them with `sorry` to make the file compile, or these were placed by hand after generation. In either case, every theorem about MerkleProof serialization is vacuously true.
- **Why it matters:** P7 ("Merkle inclusion completeness") is publicly claimed in `formal-verification.md`. The Aeneas-extracted serde path is not actually translated. This is the place a thorough reviewer will catch the project out.
- **Recommended action:** REWRITE — either complete the serde translation by hand and document the divergence from Aeneas output, or scope P7 to exclude the serde path (prove the inclusion-witness math separately, drop the "serialized envelope" claim). Update `Impl/Merkle/Funs.lean` header to note hand-patched `sorry`s. The current state ("Aeneas-generated, do not edit" + hidden `sorry`) is the worst combination.
- **Effort:** medium.

### [CRITICAL] Planning: `docs/HANDOFF.md` is a 241-line February-7 handoff still in the docs root

- **Where:** `docs/HANDOFF.md` (last touched 2026-02-26, content dated 2026-02-07, refers to PR #40).
- **What:** Reads as a fresh handoff document, includes "What's uncommitted right now" sections, marks crates "alpha" while `docs/REPO_MAP.md` and `docs/src/roadmap.md` mark the same crates "Stable." The "14 specs" referenced have all been written and the "Phase A/B/C/D" plan is abandoned in favor of newer initiatives.
- **Why it matters:** First-impression document. A new contributor lands on `docs/`, opens `HANDOFF.md`, and concludes the repo is a snapshot of one engineer's WIP rather than a maintained codebase.
- **Recommended action:** WIPE. If any reference content is still useful (the 8 "Known Issues / Gotchas" are good), migrate them to a new `docs/plans/decisions/0009-spine-conventions.md` ADR. Delete the file.
- **Effort:** trivial.

### [HIGH] Examples: Schema version drift across 9 example policies

- **Where:** `examples/bb-edr/policy.yaml:7` (`clawdstrike-v1.0`), `examples/openclaw-plugin/policy.yaml:7` (`clawdstrike-v1.0`), `examples/docker-compose/policy.yaml:2` (`1.0.0`), `examples/edr-pipeline/policy.yaml:1` (`1.0.0`), `examples/enterprise-deployment/policy-next.yaml:1` (`1.0.0`), `examples/secure-coding-assistant/policy.yaml:1` (`1.0.0`), `examples/policies/project-base.yaml:2` (`1.0.0`), `examples/policies/extend-strict.yaml` (`1.0.0`), `examples/policies/threat-intel-*.yaml` (`1.0.0`). Code: `crates/libs/clawdstrike/src/policy.rs:31` accepts only `["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"]`.
- **What:** None of these policies will load through the current Rust engine. They will fail at the `POLICY_SUPPORTED_SCHEMA_VERSIONS` check.
- **Why it matters:** A user copy-pastes `examples/docker-compose/policy.yaml` and it errors immediately. The "examples" become an anti-onboarding asset.
- **Recommended action:** REWRITE. Bulk-update all `1.0.0` to `1.5.0` (or `1.2.0` if no posture/origins/broker features used). Convert `clawdstrike-v1.0` legacy schema to `1.5.0` in the OpenClaw-plugin and bb-edr examples (or document explicitly that these are OpenClaw-engine-only fixtures with a runnable check).
- **Effort:** small.

### [HIGH] Examples: `schema_version:` key is invalid in two example policies

- **Where:** `examples/hybrid-swarm/policy-reviewer.yaml:1`, `examples/hybrid-swarm/policy-{coder,planner}.yaml` (presumably), `examples/red-blue-swarm/policy.yaml:1`.
- **What:** Uses `schema_version: "1.1.0"`. There is no `schema_version` field; the actual field name is `version` (see `examples/hello-secure-agent-ts/policy.yaml:4`). With `deny_unknown_fields` on, these policies will be rejected at parse time.
- **Why it matters:** "Hybrid swarm" and "red-blue swarm" are headline examples in the README. They're broken.
- **Recommended action:** REWRITE — rename the key and bump to `1.5.0`. Add a CI job (`scripts/validate-example-policies.sh`) that runs `hush policy verify` against every YAML under `examples/` to catch drift permanently.
- **Effort:** trivial.

### [HIGH] Docs: Policy schema version is internally inconsistent across canonical docs

- **Where:** `crates/libs/clawdstrike/src/policy.rs:29` (`POLICY_SCHEMA_VERSION = "1.5.0"`); `CLAUDE.md:81` (claims v1.5.0 backward-compatible with v1.1.0); `docs/src/reference/policy-schema.md:13-20` (claims supported versions are `1.1.0..1.4.0`, omitting 1.5.0); `docs/src/README.md:31` (sample uses `1.2.0`); `docs/src/concepts/policies.md:10` (`1.2.0`).
- **What:** The single most important versioned interface — the policy schema — has at least three different "current" versions across canonical pages. Power users will land on `policy-schema.md`, write a `1.4.0` policy, and miss the broker block that needs 1.5.0.
- **Why it matters:** Schema version mismatch will become a recurring user support footgun.
- **Recommended action:** REWRITE `docs/src/reference/policy-schema.md` to be the single source of truth on supported versions, with a table listing each version, the feature it gates, and the source-of-truth Rust constant. Add a `mdbook-linkcheck`-style script in CI that asserts the doc constant matches the code constant.
- **Effort:** small.

### [HIGH] Planning: 7 "agent framework" plans for adapters that don't exist

- **Where:** `docs/plans/agent-frameworks/{autogpt,crewai,langchain,vercel-ai,generic-adapter,comparison,overview}.md`.
- **What:** Each is a multi-thousand-line "integration plan" with version compatibility tables, architecture diagrams, and code snippets. `packages/adapters/` contains: `adapter-core`, `broker-client`, `claude`, `engine-adaptive`, `hush-cli-engine`, `hushd-engine`, `langchain`, `openai`, `openclaw`, `opencode`. Vercel AI is documented at `docs/src/guides/vercel-ai-integration.md` as "Stable" but no `clawdstrike-vercel-ai` package exists under `packages/adapters/` (search: `find packages -name "*vercel*"` returns nothing in adapters). `autogpt`, `crewai` adapters do not exist. `langchain` does exist, but `docs/plans/agent-frameworks/langchain.md` is duplicative with `docs/src/guides/langchain-integration.md`.
- **Why it matters:** Planning docs that describe non-existent packages mislead contributors looking for "what to work on" and pollute the planning surface.
- **Recommended action:** WIPE the entire `docs/plans/agent-frameworks/` directory. If `autogpt`/`crewai`/`vercel-ai` adapters are genuinely roadmap items, list them in `docs/src/roadmap.md` (one row each) and stop there. The 7 separate plan docs add nothing.
- **Effort:** trivial (deletion).

### [HIGH] Planning: `docs/plans/sentinel-swarm/` is 6,800 lines of aspirational megaproject

- **Where:** `docs/plans/sentinel-swarm/INDEX.md` (768 lines), `DATA-MODEL.md` (1,795 lines), `SPEAKEASY-INTEGRATION.md` (1,202 lines), `SIGNAL-PIPELINE.md` (981 lines), `UI-PAGE-MAP.md` (1,064 lines), `REVIEW.md` (440 lines), etc.
- **What:** "Sentinel-Swarm" is a top-to-bottom product reimagining. Status: "Design complete, phase 1 execution in progress" with branch `feat/sentinel-swarm`. There's no public-facing `docs/src/` mention of "Sentinel" as a product noun. This is 6,800 lines of plans for a not-shipped product.
- **Why it matters:** An OSS consumer reading `docs/plans/` cannot tell what is shipping vs what is daydreaming. The volume of the planning corpus implies a much larger team than exists.
- **Recommended action:** RESTRUCTURE — move under `docs/research/sentinel-swarm/` (research, not plans), or compress to a single 300-line "concept note" + delete the rest. If shipping is real, gate the docs behind branch merge: keep in branch, out of `main`.
- **Effort:** small (relocate + compress).

### [HIGH] Planning: `docs/plans/swarm-engine/` describes a 4,700-line "ported from ruflo v3" engine that doesn't live in this repo

- **Where:** `docs/plans/swarm-engine/ARCHITECTURE.md:35` says "Location: `/Users/connor/Medica/backbay/standalone/clawdstrike-swarm-engine/packages/swarm-engine/`" — that directory does not exist on this machine. `packages/swarm-engine/` does exist in this repo but contains only `package.json`, `src/`, etc., not anything matching the 4,700-line architecture spec.
- **What:** Plans that hardcode the author's local filesystem path; references to an external `clawdstrike-swarm-engine` repo that isn't checked out; design content for a package that may or may not be the same as `packages/swarm-engine/`.
- **Why it matters:** Hardcoded `/Users/connor/...` paths in committed docs is the single most "this is one person's hobby" signal possible. Even if the content is good, the path leak destroys credibility.
- **Recommended action:** REWRITE (remove the absolute paths) AND consolidate — if `packages/swarm-engine/` is the implementation, link the plan to it and prune duplicated content. If the implementation lives elsewhere, the docs should not be in this repo.
- **Effort:** small.

### [HIGH] Planning: `docs/HANDOFF.md` + `docs/plans/implementation-pad.md` + `docs/plans/monorepo-staff-organization-plan.md` are all completed work still in "active" form

- **Where:** `docs/plans/implementation-pad.md` ("execution scratchpad", last touched 2026-02-07, contents reference Tier 1/2/3 priorities from a roadmap that has since been rewritten); `docs/plans/monorepo-staff-organization-plan.md:7` ("Phase 0 and Phase 1 are committed; Phase 2 is committed; Phase 3 is committed; Phase 4 cleanup and hardening are committed; Phase 5 guardrails/policy follow-through is committed" — all phases done).
- **What:** Documents that should have been retired/converted to ADRs are still living in `docs/plans/` as if active.
- **Why it matters:** Compounds the "what's actually planned" confusion.
- **Recommended action:** WIPE `implementation-pad.md`. Convert `monorepo-staff-organization-plan.md` into a single ADR (`docs/plans/decisions/0009-monorepo-organization.md`, ~50 lines) capturing the final structure. Wipe the verbose plan.
- **Effort:** trivial.

### [HIGH] Planning: `docs/plans/clawdstrike/adaptive-sdr-{review,implementation,research-brief}.md` is 85k lines of overlapping content

- **Where:** `docs/plans/clawdstrike/adaptive-sdr-review.md` (30,034 chars), `adaptive-sdr-implementation.md` (33,352 chars), `adaptive-sdr-research-brief.md` (21,756 chars).
- **What:** Three documents covering the same Adaptive SDR work — research brief, review, implementation plan. The roadmap (`docs/src/roadmap.md:540`) marks Adaptive SDR as "Shipped." So this is a planning trio for completed work.
- **Why it matters:** Three large docs taking up cognitive real estate for shipped functionality.
- **Recommended action:** RESTRUCTURE — keep one "Adaptive SDR design" doc (consolidate to ~500 lines), move to `docs/research/adaptive-sdr-design.md`, delete the other two. Or convert to an ADR under `docs/plans/decisions/`.
- **Effort:** small (mostly deletion).

### [HIGH] Planning: `docs/plans/pact/PROTOCOL.md` is a "Pre-RFC" for a competitor to MCP

- **Where:** `docs/plans/pact/PROTOCOL.md` ("PACT: Provable Agent Capability Transport — replaces the Model Context Protocol (MCP)").
- **What:** A pre-RFC for a brand-new protocol that "replaces" MCP, sitting in `docs/plans/` with no corresponding implementation.
- **Why it matters:** Designing a new protocol to compete with an industry standard is a serious commitment. Either it's a real initiative — in which case it deserves its own RFC under `docs/src/rfcs/` with a transition story — or it's a thought experiment, in which case it should live in `docs/research/` clearly marked as such.
- **Recommended action:** Decide: promote to `docs/src/rfcs/0002-pact-protocol.md` (with explicit "non-goals", "MCP comparison", "implementation timeline" sections) OR demote to `docs/research/pact-concept.md`. The current "Pre-RFC in plans" liminal state is the worst option.
- **Effort:** small.

### [HIGH] Planning: `docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md` + `UI-POLISH-CAMPAIGN-R2.md`

- **Where:** Two campaign docs in same directory, R2 suggests R1 was abandoned/superseded.
- **What:** Round-2 of a UI polish initiative without retiring round-1.
- **Why it matters:** Documents like this betray "things were tried, abandoned, and the residue stayed." Classic AI-planning-theater signal.
- **Recommended action:** WIPE the older one (R1) or merge into R2 with a "Supersedes UI-POLISH-CAMPAIGN.md" header. Same treatment for the rest of `editor-ide/` if the desktop editor work has moved to `huntronomer/`.
- **Effort:** trivial.

### [MEDIUM] Docs: `docs/src/package-manager/` and `docs/src/plugins/` document unshipped features

- **Where:** `docs/src/SUMMARY.md:63-80` (Package Manager: 6 chapters), `:139-155` (Plugin Development: 9 chapters + 6 contribution-points).
- **What:** These chapters describe APIs (`clawdstrike pkg init/install/publish/search/verify/audit`, `clawdstrike-pkg.toml` manifest, WASM guard runtime, plugin manifest, contribution points) that are not currently shipped per `docs/src/roadmap.md:130-340` (Package Manager is "Phase 0-4" roadmap, not built). Plugin runtime similarly aspirational.
- **Why it matters:** Reference docs for unimplemented features set expectations that the CLI will then fail to meet. Users will run `clawdstrike pkg install foo` and see "unknown command."
- **Recommended action:** RESTRUCTURE — move all `package-manager/` and `plugins/` chapters under a clearly-marked "Future / Design" section in SUMMARY.md, OR add an "Implementation status" banner to each chapter that links to the relevant roadmap row. Best option: gate by feature flag in the CLI and only document the shipped subset.
- **Effort:** medium.

### [MEDIUM] Docs: `docs/src/roadmap.md` (639 lines) has dates that have already passed

- **Where:** `docs/src/roadmap.md:555-602` ("Q2 (Apr-Jun)") — date now is 2026-05-23, so Q2 is half over and the timeline is presented as future tense.
- **What:** Quarter-by-quarter Gantt-style ASCII timeline that includes work that should be in progress *now*, with no signal of whether any of it is actually being worked on.
- **Why it matters:** Stale roadmaps are worse than no roadmap. The "Q2 2026" packaging-manager work is presumably mid-flight or punted; readers cannot tell.
- **Recommended action:** REWRITE — convert the timeline to "Recently shipped / Active / Planned / Speculative" buckets without calendar dates. Add a "Last reviewed: 2026-MM-DD" header that's actually maintained. Drop the ASCII Gantt.
- **Effort:** small.

### [MEDIUM] Docs: `docs/src/roadmap.md:472-476` lists fictional community programs

- **Where:** `docs/src/roadmap.md:472-476` ("Guard Bounty Program", "Clawdstrike Champions", "Security Research Grants", "Attack Range", "Quarterly Security Report").
- **What:** Five community programs presented as roadmap items. None has a corresponding implementation, governance doc, or operating page. These read as ChatGPT-style "what would a healthy OSS project have" enumeration.
- **Why it matters:** Marketing copy in a roadmap erodes trust in the rest of the document.
- **Recommended action:** WIPE the "Community Programs" subsection. If any of these is genuinely planned, link to an issue or RFC.
- **Effort:** trivial.

### [MEDIUM] Formal: 145 axioms across the Lean project, opaque to a casual reader

- **Where:** `formal/lean4/ClawdStrike/ClawdStrike/Impl/FunsExternal.lean` (35), `Impl/FunsExternal_Template.lean` (32), `Impl/Merkle/FunsExternal_Template.lean` (31), `Proofs/Impl/IteratorAxioms.lean` (13), `Spec/MerkleProperties.lean` (10), `Core/Crypto.lean` (9), etc.
- **What:** Most are Aeneas-generated external function declarations (legit — these are unverified Rust stdlib functions). 13 in `IteratorAxioms.lean` are hand-written behavioral axioms about Rust iterators; 9 in `Core/Crypto.lean` model Ed25519 as opaque. The bridge proofs depend transitively on every one of these.
- **Why it matters:** A skeptical reader needs to know the trusted base. Right now it's spread across 8 files with no consolidated "trust boundary" doc.
- **Recommended action:** DOCUMENT — add `formal/lean4/ClawdStrike/TRUSTED-AXIOMS.md` listing all 145 axioms with a one-line justification each (or class them: "Rust stdlib", "Aeneas generated", "Hand-written iterator behavior", "Crypto primitives"). Reference it from `docs/src/formal-verification.md`.
- **Effort:** medium.

### [MEDIUM] Formal: TLA+ file is orphaned

- **Where:** `formal/tlaplus/PostureStateMachine.tla` + `PostureStateMachine.cfg`.
- **What:** A 2-file TLA+ posture state-machine model with no references from any doc (`grep -r "tlaplus\|TLA+" docs/` returns nothing). No CI runs TLC against it. No instructions for verifying it.
- **Why it matters:** Either it's a real verification asset and deserves a docs page + CI integration, or it's an experiment that should be deleted. Right now it's neither.
- **Recommended action:** Decide: DOCUMENT (add `docs/src/formal-verification.md` paragraph + CI job to run TLC) or WIPE.
- **Effort:** trivial decision; small if documenting.

### [MEDIUM] Examples: `examples/policies/synthesized-example.yaml` referenced from `docs/src/guides/observe-synth.md:39`

- **Where:** `docs/src/guides/observe-synth.md:39` references `examples/policies/synthesized-example.yaml` (file exists per `ls examples/policies/`). Was flagged in `docs/audits/2026-02-26-docs-audit-index.md:56` as "may not exist" — turns out it does. Status unclear.
- **What:** Need to verify the synthesized-example.yaml is valid against current schema and is actually a synthesized policy (not a hand-written one mislabeled).
- **Recommended action:** DOCUMENT — verify against current schema; if valid, leave alone. If `1.0.0` (likely), update.
- **Effort:** trivial.

### [MEDIUM] Docs: `docs/nono-integration/` is an 8-file integration plan disconnected from everything

- **Where:** `docs/nono-integration/01-requirements.md` ... `07-implementation-plan.md`, `INDEX.md`.
- **What:** A "Nono" integration plan in the docs root. Not linked from `DOCS_MAP.md`, not in `SUMMARY.md`, no other doc references it. "Nono" is not a documented product noun in this repo (no `crates/`, `packages/`, or `apps/` directory by that name).
- **Why it matters:** Orphan content with branded-sounding name suggests either an abandoned partnership or a vestigial private project.
- **Recommended action:** WIPE if abandoned. If real, integrate into `docs/plans/` properly and add to `DOCS_MAP.md`.
- **Effort:** trivial.

### [MEDIUM] Docs: `docs/auth.md` is a top-level orphan

- **Where:** `docs/auth.md` (Feb 2026, 4.5kb).
- **What:** A standalone auth doc in the docs root, not linked from SUMMARY.md or DOCS_MAP.md. `docs/security/` already exists for security-related docs.
- **Recommended action:** RESTRUCTURE — move to `docs/security/auth.md` or merge into `docs/src/guides/enterprise-enrollment.md`. Don't leave loose files in docs root.
- **Effort:** trivial.

### [MEDIUM] Docs: `docs/book/` (pre-built HTML) committed to the repo

- **Where:** `docs/book/` — 30+ HTML/CSS/JS files generated by `mdbook build`.
- **What:** Standard pattern is to `.gitignore` the build output. Committed `book/` directory bloats the repo and causes spurious diffs.
- **Why it matters:** Marks the repo as "doesn't follow standard Rust/mdBook hygiene."
- **Recommended action:** WIPE + add `docs/book/` to `.gitignore`. Publish via GitHub Pages / Cloudflare / GitHub Actions.
- **Effort:** trivial.

### [MEDIUM] Docs: `docs/src/roadmap.md:633` links to non-existent Discord

- **Where:** `docs/src/roadmap.md:633` — `https://discord.gg/clawdstrike`.
- **What:** Vanity Discord invite. Hard to verify without joining, but vanity URLs are usually wishful.
- **Recommended action:** Verify the invite resolves. If not, remove the contribution-channel reference or replace with GitHub Discussions.
- **Effort:** trivial.

### [LOW] Planning: `docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md` mixes operational ("here's a prompt for the agent") with planning

- **Where:** `docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md`.
- **What:** A literal prompt template intended to be pasted into an AI agent. References specific `sorry` counts ("20 remaining sorry goals") that drift as work progresses.
- **Why it matters:** Cluttering the planning surface with disposable agent prompts is exactly the AI-slop signal to avoid.
- **Recommended action:** WIPE. Keep agent prompts in `.agents/`, `.claude/`, or just in the human's head — not in canonical `docs/plans/`.
- **Effort:** trivial.

### [LOW] Planning: `docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md`

- **Where:** Same anti-pattern as the codex-handoff above.
- **Recommended action:** WIPE.
- **Effort:** trivial.

### [LOW] Planning: `docs/plans/multi-agent/codex-runtime-investigation-wave.md` + `codex-swarm-playbook.md`

- **Where:** Two more "codex" agent-orchestration docs in canonical plans.
- **What:** Operational playbooks for running parallel Codex agent worktrees. Useful for the author; weird to publish as canonical project docs.
- **Recommended action:** RESTRUCTURE — move to `.agents/playbooks/` or similar.
- **Effort:** trivial.

### [LOW] Docs: `docs/audits/` accumulates point-in-time reports without rotation

- **Where:** 14 audit files in `docs/audits/`, all dated 2026-02.
- **What:** No rotation/archival policy. After a year there will be 50+ stale audit reports.
- **Recommended action:** DOCUMENT — add `docs/audits/README.md` with a retention policy ("Audit reports older than 6 months are archived to `docs/audits/archive/`"). Track open findings in GitHub issues, not in markdown checklists.
- **Effort:** small.

### [LOW] Docs: `docs/audits/2026-02-26-docs-audit-index.md` still lists many unchecked items

- **Where:** `docs/audits/2026-02-26-docs-audit-index.md:14-72` — checklist of 52 items, all unchecked (`- [ ]`).
- **What:** Three months later, no boxes checked. Many of the listed issues (schema version drift in mdBook) actually were fixed but the checklist wasn't updated.
- **Recommended action:** Either prune to remaining open items + check off done ones, or WIPE and create a fresh audit index from this audit.
- **Effort:** small.

### [LOW] Docs: `docs/research/architecture-vision.md` predates the current architecture

- **Where:** `docs/research/architecture-vision.md` (Feb 2026).
- **What:** "Architecture vision" doc with content likely superseded by the actual REPO_MAP.md and the current `docs/src/concepts/architecture.md`.
- **Recommended action:** READ + WIPE if superseded. If retained as historical context, add a "Status: Historical" banner.
- **Effort:** trivial.

### [LOW] Examples: `examples/policies/synthesized-example.yaml` and a few siblings use legacy versions

- **Where:** `examples/policies/{project-base,project-dev,extend-strict,threat-intel-*}.yaml`.
- **What:** Several use `version: "1.0.0"` (unsupported). `examples/policies/minimal-posture.yaml` uses `1.2.0` (OK).
- **Recommended action:** REWRITE — bulk-bump to a supported version, add a CI lint.
- **Effort:** trivial.

### [LOW] Docs: Aspirational maturity labels

- **Where:** `docs/src/roadmap.md:15-31` marks `hush-core`/`clawdstrike`/`spine`/`hush-cli`/`spine-cli` as "Stable" — but `docs/REPO_MAP.md:31-46` marks all crates as "alpha". `docs/HANDOFF.md:70-78` also says "alpha". The CLAUDE.md notes "Version 0.1.x, no semver stability guarantees".
- **What:** "Stable" claims in roadmap contradict the alpha labeling in REPO_MAP and HANDOFF.
- **Recommended action:** REWRITE — pick one (alpha is honest at 0.1.x). Standardize "Stable" to mean "API frozen, semver compliant" and remove from all rows until 1.0.
- **Effort:** trivial.

### [LOW] Formal: `docs/plans/clawdstrike/formal-verification/INDEX.md` has 8 cross-references to other docs in the same directory — most useful

- **Where:** `formal-verification/INDEX.md`.
- **What:** Good — but `phase0-aeneas-feasibility.md` (Feb 2026) and `phase3-merkle-report.md` are pre-completion artefacts that should be archived now that phases are described as "Complete" in the index.
- **Recommended action:** RESTRUCTURE — move historical phase reports to `formal-verification/history/`. Keep the active ROADMAP + landscape-survey + policy-specification + INDEX as canonical.
- **Effort:** trivial.

### [LOW] Docs: `docs/specs/19-*.md` has two files numbered "19"

- **Where:** `docs/specs/19-origin-sdk-parity-api-contract.md` and `docs/specs/19-secret-broker-egress-tier.md`.
- **What:** Two specs with the same number. Will eventually conflict.
- **Recommended action:** RESTRUCTURE — renumber one to `20-secret-broker-egress-tier.md`. Add a `docs/specs/README.md` that lists the spec numbering convention.
- **Effort:** trivial.

### [LOW] Docs: 21 guide docs in `docs/src/guides/` with no organizing structure

- **Where:** `docs/src/SUMMARY.md:40-62` — flat list of 21 guides.
- **What:** Guides cover OpenClaw (4 separate guides), enterprise enrollment, audit logging, marketplace feed, threat intel, posture policy, origin enclaves, vercel-ai, langchain, generic-adapter, custom guards, etc. No grouping by purpose (integration vs operations vs policy authoring).
- **Recommended action:** RESTRUCTURE — group under `## Integration Guides`, `## Operator Guides`, `## Policy Author Guides` subsections in SUMMARY.md.
- **Effort:** trivial.

### [LOW] Docs: `docs/src/hunt/ROADMAP.md` (1,289 lines) and `docs/src/hunt/architecture.md` (1,274 lines) are very long

- **Where:** `docs/src/hunt/*`.
- **What:** Two 1k+ line chapters about a CLI subcommand suite. Architecture content overlaps with the source-of-truth implementation; ROADMAP is "planned features and historical design options".
- **Recommended action:** RESTRUCTURE — trim ROADMAP to "Shipped / Active / Future" + delete historical design options. Move architecture detail into the relevant subcommand pages.
- **Effort:** medium.

### [LOW] Examples: `examples/edr-pipeline/` and `examples/bb-edr/` overlap

- **Where:** Two EDR examples; `bb-edr/README.md:9` says "It uses `@clawdstrike/openclaw`" — same dependency as `edr-pipeline`.
- **Recommended action:** RESTRUCTURE — consolidate to one canonical EDR example; document the other as "advanced" or delete.
- **Effort:** small.

### [LOW] Docs: `docs/plans/threat-intel/`, `docs/plans/custom-guards/`, `docs/plans/policy-as-code/`, `docs/plans/identity-access/` are aspirational planning surfaces

- **Where:** Each contains 6-8 design docs.
- **What:** Multi-doc "plan" trees for feature areas that haven't yet shipped. Threat-intel does have shipped pieces (threat-intel guards exist) but the plan docs predate them and are now out of sync.
- **Recommended action:** RESTRUCTURE — for each: keep one `INDEX.md` linking to shipped components, demote the rest to research notes or delete.
- **Effort:** medium.

### [LOW] Formal: `formal/scripts/` is undocumented

- **Where:** `formal/scripts/`.
- **What:** Verification scripts with no top-level README explaining what they do or when to run them.
- **Recommended action:** DOCUMENT — add `formal/README.md` covering: how to build Lean spec, how to run diff tests, how to verify policies, how to use scripts.
- **Effort:** small.

### [LOW] Docs: `docs/static/` has 3 PNG images but no figure captions in the consuming docs

- **Where:** `docs/static/{adaptive-engine-intro,jailbreak-explain,jailbreak-intro}.png`. Referenced from `docs/src/reference/guards/jailbreak.md`.
- **What:** Hard to verify these images are still accurate without examining them. Adaptive engine UI may have changed.
- **Recommended action:** DOCUMENT — verify currency; add alt text and captions in the consuming doc.
- **Effort:** trivial.

### [LOW] Examples: `examples/rust/basic-verification/` and `examples/typescript/browser-verify/` are single-purpose demos

- **Where:** `examples/rust/`, `examples/typescript/`.
- **What:** Each directory has one subdirectory only. The flat layout (`examples/rust/`, `examples/typescript/`) suggests more languages were planned.
- **Recommended action:** RESTRUCTURE — flatten to `examples/basic-verification-rust/` and `examples/browser-verify-ts/` (matching `hello-secure-agent-{ts,py,vercel}` convention). Removes empty parent dirs.
- **Effort:** trivial.

### [LOW] Docs: `docs/specs/04-apache-2-license.md` was a migration spec for a license change presumably already done

- **Where:** `docs/specs/04-apache-2-license.md` + `LICENSE` is Apache-2.0 + `NOTICE` exists at root.
- **What:** The migration shipped. The spec is now historical.
- **Recommended action:** WIPE or move to `docs/specs/archive/`.
- **Effort:** trivial.

### [LOW] Docs: Mixed casing in plan filenames

- **Where:** `docs/plans/sentinel-swarm/SIGNAL-PIPELINE.md`, `UI-PAGE-MAP.md`, `SPEAKEASY-INTEGRATION.md` (SCREAMING-KEBAB) vs `docs/plans/multi-agent/codex-swarm-playbook.md` (kebab-case) vs `docs/plans/clawdstrike/secret-broker/README.md` (Title-case).
- **What:** Inconsistent file-naming conventions.
- **Recommended action:** RESTRUCTURE — pick one (lowercase-kebab) and rename for consistency.
- **Effort:** trivial.

---

## Action Plan

**Phase 1 — Stop the bleeding (1-2 days, mostly deletion):**

1. WIPE `docs/HANDOFF.md`, `docs/plans/implementation-pad.md`, `docs/plans/2026-02-25-openclaw-adapter-core-alignment.md`, `docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md`, `docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md`, `docs/plans/clawdstrike/adaptive-sdr-review.md`, `docs/plans/clawdstrike/adaptive-sdr-research-brief.md`, `docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md`, `docs/plans/agent-frameworks/` (whole dir), `docs/nono-integration/` (whole dir), `docs/auth.md`, `docs/book/` (and gitignore).
2. WIPE `docs/src/roadmap.md` "Community Programs" subsection.
3. FIX `examples/*/policy.yaml` schema versions; rename `schema_version` to `version`; bulk-bump to `1.5.0` or `1.2.0`.
4. ADD CI job `scripts/validate-example-policies.sh` that runs `hush policy verify` on every YAML under `examples/`.

**Phase 2 — Tell the truth about formal verification (2-3 days):**

5. REWRITE `docs/src/formal-verification.md` to add a "Limitations" section listing every `sorry`, every hand-written axiom, every Aeneas-generated axiom. Promote the differential testing as the empirical complement.
6. Either complete or scope-down the Merkle `sorry`s in `formal/lean4/.../Impl/Merkle/Funs.lean:589,632,768,895`. Update the "do not edit" header to acknowledge the patches.
7. ADD `formal/lean4/ClawdStrike/TRUSTED-AXIOMS.md` cataloguing all 145 axioms.
8. DOCUMENT or DELETE `formal/tlaplus/`.

**Phase 3 — Consolidate the planning surface (3-5 days):**

9. RESTRUCTURE `docs/plans/sentinel-swarm/` → `docs/research/sentinel-swarm/` with size compression.
10. RESTRUCTURE `docs/plans/swarm-engine/` → either delete or co-locate with `packages/swarm-engine/`. Remove hardcoded `/Users/connor/...` paths.
11. CONVERT `docs/plans/monorepo-staff-organization-plan.md` to a single ADR.
12. WIPE `docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md` (R1).
13. DECIDE: promote `docs/plans/pact/PROTOCOL.md` to `docs/src/rfcs/0002-pact.md` or demote to `docs/research/pact-concept.md`.
14. RESTRUCTURE `docs/plans/threat-intel/`, `custom-guards/`, `policy-as-code/`, `identity-access/` — keep INDEX.md, retire the rest.
15. RENUMBER duplicate spec `19-*.md` and add `docs/specs/README.md`.
16. RESTRUCTURE `docs/plans/multi-agent/codex-*.md` → move to `.agents/playbooks/`.

**Phase 4 — Reconcile schema/version drift (1 day):**

17. REWRITE `docs/src/reference/policy-schema.md` as the single source of truth on supported versions. List `1.1.0..1.5.0`.
18. REWRITE `docs/src/roadmap.md` to drop dated quarterly Gantt; use "Recently shipped / Active / Planned / Speculative" buckets.
19. Reconcile alpha/stable maturity labels across `docs/REPO_MAP.md`, `docs/src/roadmap.md`, `docs/HANDOFF.md` (now deleted), `CHANGELOG.md`.

**Phase 5 — Hygiene (ongoing):**

20. ADD `docs/audits/README.md` with retention policy.
21. ADD `formal/README.md`.
22. ADD `mdbook-linkcheck` to CI.
23. ADD `scripts/check-docs-versions.sh` asserting code constants match doc claims.

---

## Top 10 Quick Wins

1. **`rm docs/HANDOFF.md docs/auth.md docs/plans/implementation-pad.md docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md`** — 5 stale single-author files gone in one commit.
2. **`rm -rf docs/plans/agent-frameworks/ docs/nono-integration/ docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md`** — remove 3 sets of fictional/orphan content.
3. **`echo 'docs/book/' >> .gitignore && git rm -r docs/book/`** — stop committing build output.
4. **Bulk-replace** `version: "1.0.0"` → `version: "1.5.0"` and `version: "clawdstrike-v1.0"` → `version: "1.5.0"` across `examples/**/policy*.yaml`. Then rename `schema_version:` → `version:` in `examples/hybrid-swarm/` and `examples/red-blue-swarm/`.
5. **Add a 10-line "Limitations" callout** to `docs/src/formal-verification.md` listing `sorry`s and pointing to `formal/lean4/ClawdStrike/TRUSTED-AXIOMS.md` (to be created).
6. **Renumber `docs/specs/19-secret-broker-egress-tier.md` to `20-*`** to fix the spec-number collision.
7. **Delete the "Community Programs" subsection** in `docs/src/roadmap.md:467-476`.
8. **Update `docs/src/reference/policy-schema.md:13-20`** to list 1.5.0 as latest and reflect actual `POLICY_SUPPORTED_SCHEMA_VERSIONS`.
9. **Convert `docs/plans/monorepo-staff-organization-plan.md`** to a 50-line ADR (`docs/plans/decisions/0009-monorepo-organization.md`); wipe the source.
10. **Add `scripts/validate-example-policies.sh` to CI** that runs `hush policy verify` against every `examples/**/*.yaml` — will catch all schema drift forever.

---

## Things to Leave Alone

1. **`docs/src/` (the mdBook).** Structure is sound, builds cleanly, all chapters resolve. The remaining issues are content-level, not structural. Resist the urge to reorganize.
2. **`docs/plans/decisions/0001..0008-*.md`.** Short, focused, dated ADRs — exactly the pattern the rest of `docs/plans/` should converge on. Add to this directory; don't restructure it.
3. **`formal/lean4/ClawdStrike/ClawdStrike/Spec/Properties.lean` (707 lines, 0 `sorry`s).** This is the crown jewel. The proofs of P1, P2, P3, P4 (forbidden-path soundness + policy soundness), P5 are real and complete. Resist the urge to refactor.
4. **`formal/lean4/ClawdStrike/ClawdStrike/Core/`.** Hand-written spec types — clean, well-organized. Leave alone.
5. **`examples/hello-secure-agent-{ts,py,vercel}/`.** Three clean reference quickstarts in the three languages that matter. Idiomatic, runnable in `--dry-run`, faithful to the SDK.
6. **`examples/spider-sense-threat-intel/`** — TS/Py/Go cross-language parity demo, well-structured.
7. **`docs/plans/clawdstrike/formal-verification/ROADMAP.md`** and **`policy-specification.md`** — long but genuinely useful and current.
8. **`docs/plans/clawdstrike/secret-broker/{README,target-architecture,roadmap,current-state}.md`** — small, current, actively maintained.
9. **`docs/plans/clawdstrike/macos-es-ne/`** — matches current working branch (`fix/macos-es-ne-hardening`), short, focused.
10. **`docs/src/hunt/`** core subcommand pages — well-organized command reference. (Only the ROADMAP and architecture should be trimmed.)
11. **`docs/audits/2026-02-26-docs-audit-index.md`** as a *pattern* — the project clearly knows how to do these audits well; just adopt rotation/closure discipline.
12. **`CHANGELOG.md`**, **`CONTRIBUTING.md`**, **`GOVERNANCE.md`**, **`SECURITY.md`**, **`CODE_OF_CONDUCT.md`**, **`THREAT_MODEL.md`**, **`NON_GOALS.md`** at the repo root — these are good citizens (out of scope for this audit but worth noting).
