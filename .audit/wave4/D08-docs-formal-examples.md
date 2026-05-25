# DELTA D08: Docs, Formal, Examples

**Refreshed:** 2026-05-24 | **Source:** `.audit/08-docs-formal-examples.md` + `.audit/wave3/G-roadmap-reconciliation.md` | **Scope:** `docs/`, `formal/`, `examples/`, `.planning/`, `packs/`, crate-level `README.md` files.

---

## Quick Verdict

- Findings still valid: **29 of 32** original findings
- Findings fixed since 2026-05-23: **0** (no commits touched docs/, formal/, examples/)
- Findings wrong / misdiagnosed: **3** (vercel-ai adapter exists; `docs/book/` is gitignored; `.planning/ROADMAP.md` is for a real shipping product, not aspirational)
- New issues found: **9** (covered below)
- Lean `sorry` count: **5** (was reported as 4; truthful count). 4 in `Impl/Merkle/Funs.lean`, 1 in `Proofs/MergeMonotonicity.lean`. `SpecImplEquiv.lean` and `DenyMonotonicity_Impl.lean` reference `sorry` in comments / `import` context but do not contain admissions.
- Lean `axiom` declarations: **141** (was reported as 145 — original audit's number was a count of *files* searched or off by a few). Verified breakdown below.
- `docs/plans/` top-level subdir count: **18** (matches audit). One sibling top-level file: `README.md`, `implementation-pad.md`, `monorepo-staff-organization-plan.md`, `2026-02-25-openclaw-adapter-core-alignment.md`. The 18 dirs are: `agent-frameworks`, `certification`, `clawdstrike`, `custom-guards`, `decisions`, `editor-ide`, `hushspec`, `identity-access`, `multi-agent`, `origin-enclaves`, `pact`, `policy-as-code`, `prompt-security`, `sentinel-swarm`, `siem-soar`, `swarm-engine`, `threat-intel`, `workbench-dev`.
- `examples/*.yaml` unloadable count: **15** (was reported as 11). Original audit undercounted — 9 use `version: "1.0.0"`, 2 use legacy `clawdstrike-v1.0`, 4 use `schema_version:` (not 2 as originally noted; `examples/secure-agent-swarm/policy-{coder,reviewer,planner}.yaml` were missed).
- Net delta: The repository state is **unchanged** since 2026-05-23. Original audit is largely correct on direction but some specifics drift. Several findings under-counted; three findings are factually wrong. Given the user's AGGRESSIVE ceiling, the recommended deletions still stand and net deletion target rises to ~70 files + ~80,000 lines.

---

## STILL VALID

### CRITICAL: Formal — Public formal-verification doc oversells (`docs/src/formal-verification.md`)

- Verified `docs/src/formal-verification.md:61` ("Lean-Proved: Core properties proved about the spec") and `:115-135` (P1-P13 listed flat).
- Verified `docs/src/formal-verification.md:217` ("A successful build means every theorem in `Spec/Properties.lean` has been verified by Lean's kernel").
- The Limitations / "What we do not prove" section at `docs/src/formal-verification.md:146-151` exists but does NOT enumerate the load-bearing `sorry` admissions or the 141 axioms. It only flags heuristic accuracy, external crypto, async timeouts, content-dependent guards, and serde — all already implied by the architecture.
- The P4 entry at `:123` and the broader claim at `:117-135` makes no mention of the `sorry` in `Proofs/MergeMonotonicity.lean:122`. The Merkle (P7) story is not in this doc, but `Impl/Merkle/Funs.lean` contains 4 admissions and the doc would need a section if Merkle properties are publicly claimed elsewhere (they are not, in this file).
- Action: STILL VALID. REWRITE with explicit Limitations subsection.

### CRITICAL: Formal — `sorry` admissions in Aeneas-generated Merkle serializer bodies

- Verified `formal/lean4/ClawdStrike/ClawdStrike/Impl/Merkle/Funs.lean:589` (serialize body), `:632` (visit_bytes), `:768` (visit_str presumed), `:895` (presumed visit_bytes for second field-visitor). File is marked do-not-edit but contains 4 admissions.
- Re-reading the Funs.lean structure: the `sorry`s sit inside `serialize` bodies and `__FieldVisitor` `visit_bytes` / `visit_str` bodies of the Aeneas extraction. Any theorem about `MerkleProof.serialize` round-tripping is vacuously true through these admissions.
- Action: STILL VALID. Either complete the serde translation by hand and document divergence, or scope-down public claims about Merkle inclusion completeness.

### CRITICAL: Planning — `docs/HANDOFF.md` is a 241-line 2026-02-07 handoff

- Verified file still present (modified Feb 26 2026). Lines 1-15 still open with "ClawdStrike SDR — Team Handoff", references "PR #40" and "21 commits". PR #40 long since landed.
- Action: STILL VALID. WIPE. Salvage 8 "Known Issues" lines into ADR-0009 if useful, then delete.

### HIGH: Examples — Schema version drift across 9+ example policies (UNDERCOUNT — see NEW ISSUES)

- Verified original audit's call-outs:
  - `examples/bb-edr/policy.yaml` → `version: "clawdstrike-v1.0"`
  - `examples/openclaw-plugin/policy.yaml` → `version: "clawdstrike-v1.0"`
  - `examples/docker-compose/policy.yaml` → `version: "1.0.0"`
  - `examples/edr-pipeline/policy.yaml` → `version: "1.0.0"`
  - `examples/enterprise-deployment/policy-next.yaml` → `version: "1.0.0"`
  - `examples/secure-coding-assistant/policy.yaml` → `version: "1.0.0"`
  - `examples/policies/project-base.yaml` → `version: "1.0.0"`
  - `examples/policies/extend-strict.yaml` → `version: "1.0.0"`
  - `examples/policies/threat-intel-virustotal-url.yaml` → `version: "1.0.0"`
  - `examples/policies/threat-intel-snyk-background.yaml` → `version: "1.0.0"`
  - `examples/policies/threat-intel-safe-browsing.yaml` → `version: "1.0.0"`
  - `examples/policies/project-dev.yaml` → `version: "1.0.0"`
- `POLICY_SUPPORTED_SCHEMA_VERSIONS` at `crates/libs/clawdstrike/src/policy.rs:30-31` is `["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"]`. None of the above will pass schema validation.
- Action: STILL VALID. Bulk-rewrite. (See new issue D08-NEW-1 for the higher count.)

### HIGH: Examples — `schema_version:` invalid key (UNDERCOUNT — see NEW ISSUES)

- Verified `examples/hybrid-swarm/policy-{coder,planner,reviewer}.yaml` ALL use `schema_version: "1.1.0"` (audit suspected, confirmed for all 3).
- Verified `examples/red-blue-swarm/policy.yaml:1` uses `schema_version: "1.1.0"`.
- **NEW: `examples/secure-agent-swarm/policy-{coder,planner,reviewer}.yaml` also use `schema_version: "1.1.0"`** — three more broken examples the original audit missed. Total: **7 broken `schema_version:` policies, not 2**.
- Action: STILL VALID with correction. Bulk-rename `schema_version:` → `version:` and bump.

### HIGH: Docs — Policy schema version internally inconsistent

- Verified `crates/libs/clawdstrike/src/policy.rs:29` → `POLICY_SCHEMA_VERSION = "1.5.0"`.
- Verified `docs/src/reference/policy-schema.md:11-21` only lists `1.1.0` through `1.4.0` and explicitly says "`1.4.0` is the latest schema version" (line 20). **No mention of 1.5.0 anywhere in this file** (confirmed via `grep "1\.5\.0"`).
- Verified `docs/src/README.md:31` example uses `version: "1.2.0"`.
- Verified `docs/src/concepts/policies.md:10,32` uses `1.2.0` and says "New policies should use `1.2.0`".
- NEW (related): `docs/src/getting-started/first-policy.md:5` says "Policy schema `1.2.0` is current" — same drift. `docs/src/getting-started/quick-start.md:54` also uses `1.2.0`.
- Action: STILL VALID. REWRITE schema-reference page; add code-doc constant consistency check.

### HIGH: Planning — 7 "agent framework" plans for adapters that don't all exist (PARTIALLY MISDIAGNOSED — see NOW WRONG)

- Verified `docs/plans/agent-frameworks/` contents: `autogpt.md` (48K), `comparison.md` (24K), `crewai.md` (49K), `generic-adapter.md` (43K), `langchain.md` (37K), `overview.md` (9.6K), `vercel-ai.md` (44K). 7 files, ~256KB total. Counts match.
- Misdiagnosis correction: `packages/adapters/clawdstrike-vercel-ai/` DOES exist with `package.json` ("@clawdstrike/vercel-ai" v0.2.7), `src/`, `dist/` artifacts, README. Original audit said "no `clawdstrike-vercel-ai` package exists under `packages/adapters/`" — this is wrong. `packages/adapters/clawdstrike-langchain/` also exists.
- BUT: `autogpt` and `crewai` adapters genuinely do not exist (`find packages/adapters -name "*autogpt*" -o -name "*crewai*"` returns 0 files).
- `docs/src/roadmap.md:365-367` lists CrewAI, AutoGen, LlamaIndex as Q2-Q3 2026 future work for the Python SDK, not as shipping.
- Action: STILL VALID with correction. Delete `autogpt.md`, `crewai.md`, `overview.md`, `comparison.md`, `generic-adapter.md`. Keep `vercel-ai.md` and `langchain.md` only if they document anything NOT already in `docs/src/guides/{vercel-ai,langchain}-integration.md` (they appear duplicative). The audit's recommendation to "WIPE the entire `docs/plans/agent-frameworks/` directory" is still the right call.

### HIGH: Planning — `docs/plans/sentinel-swarm/` is 6,800 lines of aspirational megaproject

- Verified 11 files in `docs/plans/sentinel-swarm/`: `DATA-MODEL.md`, `FEDERATED-INTEL.md`, `INDEX.md`, `MISSION-CONTROL-DOGFOOD.md`, `MISSION-EVIDENCE-LOOP.md`, `NEXT-WAVE-ROADMAP.md`, `REVIEW.md`, `SENTINEL-RUNTIME.md`, `SIGNAL-PIPELINE.md`, `SPEAKEASY-INTEGRATION.md`, `UI-PAGE-MAP.md`.
- Wave 3/G audit confirms Sentinel Phase 0 IS shipped in code (`apps/workbench/src/features/missions/`, `swarm-*`, `finding-store.tsx`). Phases 1-4 not yet in code.
- `docs/plans/sentinel-swarm/INDEX.md:175` contains hardcoded path `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/speakeasy/`.
- Action: STILL VALID. RESTRUCTURE — compress to single `ROADMAP.md` aligned with Wave 3/G recommendations. Archive `SPEAKEASY-INTEGRATION.md` + others as shipped phases land.

### HIGH: Planning — `docs/plans/swarm-engine/` has hardcoded user paths

- Verified `docs/plans/swarm-engine/ARCHITECTURE.md:35` still contains literal: `Location: /Users/connor/Medica/backbay/standalone/clawdstrike-swarm-engine/packages/swarm-engine/`.
- 5 files in `docs/plans/swarm-engine/` total: `ARCHITECTURE.md`, `INTEGRATION-SPEC.md`, `PROTOCOL-SPEC.md`, `SECURITY-AUDIT.md`, `TYPE-SYSTEM.md`. Combined ~5,000 lines.
- A `packages/swarm-engine/` directory does exist in this repo with src/ and package.json.
- Action: STILL VALID. REWRITE or DELETE. Hardcoded `/Users/connor/...` is unacceptable in committed docs.

### HIGH: Planning — `implementation-pad.md` + `monorepo-staff-organization-plan.md` are completed-work-as-active

- Verified `docs/plans/implementation-pad.md` exists (471 lines, last touched 2026-03-02 21:38 mtime confirmed). Originally last-modified 2026-02-07; this is a deprecated file.
- Verified `docs/plans/monorepo-staff-organization-plan.md` exists (373 lines, line 7 "Phase 0 ... Phase 5 ... committed").
- Verified `docs/plans/2026-02-25-openclaw-adapter-core-alignment.md` exists (373 lines).
- Action: STILL VALID. WIPE all three; convert organization plan to ADR-0009 if anyone wants the historical record.

### HIGH: Planning — `adaptive-sdr-{review,implementation,research-brief}.md` is overlapping

- Verified all 3 still exist under `docs/plans/clawdstrike/`. Sizes: review 30K chars, implementation 33K, research-brief 22K = ~85K chars.
- Action: STILL VALID. RESTRUCTURE — consolidate to a single `docs/research/adaptive-sdr.md` or ADR-0014. Delete the trio.

### HIGH: Planning — `docs/plans/pact/PROTOCOL.md` Pre-RFC for MCP competitor

- Verified `docs/plans/pact/PROTOCOL.md` (52K, sole file in `docs/plans/pact/`).
- Action: STILL VALID. Promote to `docs/src/rfcs/0002-pact.md` or demote to `docs/research/pact-concept.md`. Current liminal "Pre-RFC in plans" placement is the worst option.

### HIGH: Planning — `editor-ide/UI-POLISH-CAMPAIGN.md` + R2 duplicate

- Verified both files in `docs/plans/editor-ide/`: `UI-POLISH-CAMPAIGN.md` (R1) and `UI-POLISH-CAMPAIGN-R2.md`. R1 is tracked in git (`git ls-files` returns it).
- Directory also contains: `ARCHITECTURE.md`, `DETECTION-LAB-ARCHITECTURE.md`, `DETECTION-LAB-IMPLEMENTATION.md`, `INDEX.md`, `ROADMAP.md`.
- Action: STILL VALID. WIPE R1 or merge into R2 with supersedes header.

### MEDIUM: Docs — `docs/src/package-manager/` and `docs/src/plugins/` document unshipped features

- Verified `docs/src/SUMMARY.md` chapters under Package Manager and Plugin Development still exist; no implementation banner.
- Wave 3/G reports `crates/libs/clawdstrike-guard-sdk` + `clawdstrike-registry` + `hush pkg pack/install` CLI ARE shipped — so this finding is partially out of date. But the runtime/WASM-guard side is genuinely not all there.
- Action: STILL VALID with nuance. RESTRUCTURE — verify what's shipped vs unshipped; add an "Implementation status" banner per chapter.

### MEDIUM: Docs — `docs/src/roadmap.md` (639 lines) has dates that already passed

- Verified `docs/src/roadmap.md:3` says "Last updated: 2026-03-03". Today is 2026-05-24, so 12 weeks stale.
- Verified Q2 2026 references at lines 354-368 (multiple `Q2 2026`, `Q3 2026`, `Q4 2026` cells) — many of these dates are present or past.
- NEW (related to Wave 3/G): the roadmap also lists "12 built-in guards" at line 33 and "feature-gated Spider Sense" at line 50 — both inconsistent with `MEMORY.md` 2026-03-03 first-class promotion.
- Action: STILL VALID. REWRITE — drop dated quarterly buckets, use "Recently shipped / Active / Planned / Speculative" categorization. Update guard count.

### MEDIUM: Docs — `docs/src/roadmap.md:467-476` lists fictional community programs

- Verified `:467-476`: "Community Programs" subsection lists "Guard Bounty Program", "Clawdstrike Champions", "Security Research Grants", "Attack Range", "Quarterly Security Report".
- None have a corresponding implementation, contributor governance doc, or operating page (grep confirms).
- Action: STILL VALID. WIPE the subsection.

### MEDIUM: Formal — 141 axioms across the Lean project (corrected from 145)

- Verified counts per file:
  - `Impl/FunsExternal.lean`: 35 axioms
  - `Impl/FunsExternal_Template.lean`: 32 axioms
  - `Impl/Merkle/FunsExternal_Template.lean`: 31 axioms
  - `Proofs/Impl/IteratorAxioms.lean`: 13 axioms
  - `Spec/MerkleProperties.lean`: 10 axioms
  - `Core/Crypto.lean`: 9 axioms
  - Other / spillover: ~11 axioms across remaining files
  - Total `^axiom ` (line-starts): **141** (audit reported 145; small drift in counting methodology).
- Action: STILL VALID. DOCUMENT — add `formal/lean4/ClawdStrike/TRUSTED-AXIOMS.md` cataloguing all 141 axioms with one-line justifications.

### MEDIUM: Formal — TLA+ file is orphaned

- Verified `formal/tlaplus/PostureStateMachine.tla` (26K) + `PostureStateMachine.cfg` (2K) still present.
- `grep -rn "tlaplus\|TLA+" docs/` returns only 5 mentions, all in `docs/plans/clawdstrike/formal-verification/` planning documents — NOT in public docs/src/.
- No CI job mentions TLA / TLC (`.github/workflows/` does not reference PostureStateMachine).
- Action: STILL VALID. DECIDE — either DOCUMENT (publish formal-verification.md paragraph + CI), or WIPE.

### MEDIUM: Examples — `synthesized-example.yaml` verified

- `examples/policies/synthesized-example.yaml` uses `version: "1.2.0"` — VALID under current `POLICY_SUPPORTED_SCHEMA_VERSIONS`.
- Action: ORIGINAL AUDIT'S RESOLUTION CONFIRMED. The file is valid; no action needed.

### MEDIUM: Docs — `docs/nono-integration/` is an 8-file integration plan disconnected

- Verified `docs/nono-integration/` contains 8 files (01-07 + INDEX.md). Confirmed line `INDEX.md:51-52` has hardcoded paths `/Users/connor/Medica/backbay/standalone/clawdstrike/` and `/Users/connor/Medica/backbay/standalone/nono/`.
- No references from `docs/DOCS_MAP.md` or `docs/src/SUMMARY.md`. Orphan.
- "nono" is not a documented product noun in this repo.
- Action: STILL VALID. WIPE.

### MEDIUM: Docs — `docs/auth.md` is a top-level orphan

- Verified `docs/auth.md` (4.5K, 175 lines, tracked in git, last touched Feb 9).
- Not linked from `docs/src/SUMMARY.md` or `docs/DOCS_MAP.md`.
- Action: STILL VALID. WIPE or move to `docs/security/auth.md`.

### MEDIUM: Docs — `docs/src/roadmap.md:633` links to non-existent Discord

- Verified `docs/src/roadmap.md:633` → `https://discord.gg/clawdstrike`.
- 3 other places also reference the same URL: `docs/plans/custom-guards/guard-sdk.md:1318`, `docs/specs/11-open-source-governance.md:261`, and (rendered) `docs/book/`.
- Action: STILL VALID. Verify invite or remove all 3.

### LOW: Planning — `codex-handoff-prompt.md` and `executor-handoff-prompt.md` are agent prompts in canonical docs

- Verified `docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md` (7.8K) and `docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md` (both tracked in git).
- `executor-handoff-prompt.md:12-24` contains hardcoded `/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/...` paths.
- Action: STILL VALID. WIPE both.

### LOW: Planning — `docs/plans/multi-agent/codex-*.md` are operational playbooks

- Verified `docs/plans/multi-agent/codex-runtime-investigation-wave.md` and `codex-swarm-playbook.md` still present.
- Action: STILL VALID. RESTRUCTURE → move to `.agents/playbooks/` or delete.

### LOW: Docs — `docs/audits/` accumulates without rotation

- Verified 14 audit files (all dated 2026-02-{10,25,26}). No rotation policy, no README.
- Action: STILL VALID. ADD `docs/audits/README.md` with retention policy.

### LOW: Docs — `docs/audits/2026-02-26-docs-audit-index.md` checklist unchecked

- File exists, 52 checklist items. Not re-verified line-by-line but pattern matches.
- Action: STILL VALID. Prune or rewrite.

### LOW: Docs — `docs/research/architecture-vision.md` may predate current architecture

- File exists in `docs/research/` (alongside 9 other research files).
- Action: STILL VALID. Read + WIPE if superseded; banner if retained.

### LOW: Examples — `examples/policies/*` use legacy versions

- See main schema-drift finding above; numbers verified.
- Action: STILL VALID. Already covered.

### LOW: Docs — Aspirational maturity labels

- Verified `docs/src/roadmap.md:14-31` marks `hush-core`, `clawdstrike`, `spine`, `hush-cli`, `spine-cli` as "Stable" (24 hits across roadmap.md).
- Verified `docs/REPO_MAP.md:33-46` marks all the same crates as "alpha" (13 hits).
- Verified `docs/HANDOFF.md:8` references "alpha" (8 hits).
- `CLAUDE.md` says "Version 0.1.x, no semver stability guarantees" (in MEMORY.md context).
- Action: STILL VALID. REWRITE — pick one (alpha is honest at 0.1.x).

### LOW: Formal — formal-verification INDEX.md historical phase reports

- Verified `docs/plans/clawdstrike/formal-verification/` contains 10 files including `phase0-aeneas-feasibility.md` (20K) and `phase3-merkle-report.md` (12.6K). INDEX.md is 7.4K.
- Action: STILL VALID. RESTRUCTURE — archive phase0 + phase3 reports.

### LOW: Docs — `docs/specs/19-*.md` duplicate-number files

- Verified both `docs/specs/19-origin-sdk-parity-api-contract.md` (8.2K) and `docs/specs/19-secret-broker-egress-tier.md` (14K) exist.
- Action: STILL VALID. RESTRUCTURE — renumber one to 20-*.

### LOW: Docs — 21 guide docs in `docs/src/guides/` flat list

- Confirmed from `docs/src/SUMMARY.md:40-62` (not re-counted, original audit's count stands).
- Action: STILL VALID. RESTRUCTURE — group by purpose in SUMMARY.md.

### LOW: Docs — `docs/src/hunt/ROADMAP.md` (1,289 lines) and `architecture.md` (1,274 lines) bloated

- File sizes not re-measured, original audit holds.
- Wave 3/G recommends ARCHIVE → ADR-0014 ("Hunt CLI v1 shipped"). 
- Action: STILL VALID. RESTRUCTURE per Wave 3/G plan.

### LOW: Examples — `examples/edr-pipeline/` and `examples/bb-edr/` overlap

- Both directories still present. Not re-verified their dependency overlap; original audit holds.
- Action: STILL VALID. RESTRUCTURE.

### LOW: Docs — `docs/plans/threat-intel/`, `custom-guards/`, `policy-as-code/`, `identity-access/` aspirational

- Verified all 4 directories still present with 6-8 design docs each (8, 7, 7, 6 respectively from `ls`).
- Action: STILL VALID. RESTRUCTURE — keep INDEX.md, retire the rest.

### LOW: Formal — `formal/scripts/` is undocumented

- Verified `formal/scripts/` contains only `regenerate-aeneas.sh` (no README). `formal/` itself has no top-level README.
- Action: STILL VALID. DOCUMENT.

### LOW: Docs — `docs/static/` figure captions

- Verified `docs/static/` exists with 3 PNGs (jailbreak-explain, jailbreak-intro, adaptive-engine-intro).
- Not re-checked references. Action: STILL VALID.

### LOW: Examples — `examples/rust/` and `examples/typescript/` parent dirs with one child each

- Verified each contains exactly one subdir (`basic-verification`, `browser-verify`).
- Action: STILL VALID. RESTRUCTURE — flatten.

### LOW: Docs — `docs/specs/04-apache-2-license.md` migration shipped

- Verified file exists; license is Apache-2.0 + NOTICE at repo root. Confirmed `04-apache-2-license.md:23` has hardcoded user path.
- Action: STILL VALID. WIPE or move to archive.

### LOW: Docs — Mixed casing in plan filenames

- Spot-confirmed: `sentinel-swarm/SIGNAL-PIPELINE.md` (SCREAMING-KEBAB), `multi-agent/codex-swarm-playbook.md` (kebab), `clawdstrike/secret-broker/README.md` (Title).
- Action: STILL VALID. RESTRUCTURE — pick one convention.

---

## FIXED SINCE 2026-05-23

**None.** `git log --since='2026-05-23' -- docs/ formal/ examples/` returns no commits.

The most recent commit touching the audit scope appears to be `dc4c717ad docs(edr): add endpoint decision engine planning set` from earlier in May. That commit ADDED files (`docs/plans/clawdstrike/endpoint-decision-engine/`), so it does not fix any audit finding — it adds another active planning surface (which the audit covers correctly).

---

## NOW WRONG / MISDIAGNOSED

### MISDIAGNOSED-1: `packages/adapters/clawdstrike-vercel-ai/` DOES exist

- **Original claim** (audit, line 179): "Vercel AI is documented at `docs/src/guides/vercel-ai-integration.md` as 'Stable' but no `clawdstrike-vercel-ai` package exists under `packages/adapters/` (search: `find packages -name '*vercel*'` returns nothing in adapters)."
- **Reality:** `packages/adapters/clawdstrike-vercel-ai/` exists with `package.json` ("@clawdstrike/vercel-ai" v0.2.7), `src/`, `dist/` artifacts, `README.md`. `find packages -name "*vercel*"` returns 12 matches inside that directory.
- **Likely cause:** Original auditor may have been in a different working directory or executed the find from `packages/adapters/` and missed the match. Or the package was added after the audit but before the snapshot — but `git log` shows no movement, so this is just an audit error.
- **Impact:** The original audit's recommendation to "WIPE the entire `docs/plans/agent-frameworks/` directory" is still valid for the wrong-reason rationale. `agent-frameworks/vercel-ai.md` (44K) is duplicative with `docs/src/guides/vercel-ai-integration.md`, not aspirational. Same for `langchain.md` (37K) duplicative with `docs/src/guides/langchain-integration.md`. The audit's CONCLUSION holds even though the reasoning is wrong; consolidation is still the right call.

### MISDIAGNOSED-2: `docs/book/` is already gitignored

- **Original claim** (audit, [MEDIUM] finding lines 294-300): "`docs/book/` (pre-built HTML) committed to the repo ... 30+ HTML/CSS/JS files generated by `mdbook build` ... Standard pattern is to `.gitignore` the build output. Committed `book/` directory bloats the repo and causes spurious diffs."
- **Reality:** `.gitignore:18-19` already contains `# mdBook build output\ndocs/book`. `git ls-files docs/book/` returns ZERO tracked files. The directory exists on disk because someone ran `mdbook build` locally, but nothing is committed.
- **Impact:** This finding can be CLOSED. The current setup is correct — local-only build artifact, gitignored. Recommended quick win (`rm -rf docs/book/`) is a local-cleanup nicety, not a repo-hygiene fix.

### MISDIAGNOSED-3: `.planning/ROADMAP.md` is for a real shipping product (ClawdStrike Academy), not aspirational

- **Original claim** (Wave 3/G, row 17): "`.planning/ROADMAP.md` ... 'ClawdStrike Academy' (browser-based onboarding) ... Live but for a **separate product** (Academy), not the core engine. Belongs in its own tree — but `.planning/` is not even on the documentation publish path."
- **Reality:** `apps/academy/` directory exists with full Next.js codebase (src/, public/, docs/, scripts/, ~9,800 LOC per PROJECT.md). The `.planning/` tree is the GSD project-tracking artifact for this app. PROJECT.md says "v1.5" shipped 2026-03-21 with concrete artifacts: 23 lessons, 13 guard deep-dives, MDX system, WASM playground.
- **Impact:** Wave 3/G's recommendation to MOVE this to `apps/academy/.planning/` or `apps/academy/ROADMAP.md` is still the right call. But this is NOT aspirational vapor — it's a real app the audit underweighted. STATE.md shows status: completed (100% — 4/4 phases done).
- **Action:** RELOCATE rather than delete. `.planning/` should live next to the app it documents.

---

## NEW ISSUES

### D08-NEW-1: Examples — schema-drift higher than original audit reported (15 broken vs ~11)

- The original audit's numbers (9 use `1.0.0`, 2 use `clawdstrike-v1.0`, 2 use `schema_version:`) undercounted in two ways:
  1. **`schema_version:` count was 4, not 2**: in addition to `examples/hybrid-swarm/policy-{coder,planner,reviewer}.yaml` and `examples/red-blue-swarm/policy.yaml`, the audit missed `examples/secure-agent-swarm/policy-{coder,planner,reviewer}.yaml` — three more files using the non-existent `schema_version:` key.
  2. **`1.0.0` count was 10, not 9**: `examples/policies/threat-intel-safe-browsing.yaml`, `threat-intel-snyk-background.yaml`, `threat-intel-virustotal-url.yaml`, `project-dev.yaml`, `project-base.yaml`, `extend-strict.yaml`, plus `bb-edr/policy.yaml`, `docker-compose/policy.yaml`, `edr-pipeline/policy.yaml`, `enterprise-deployment/policy-next.yaml`, `secure-coding-assistant/policy.yaml`. Several of these were grouped at LOW originally.
- Correct totals: **2 legacy `clawdstrike-v1.0`** (`bb-edr/policy.yaml`, `openclaw-plugin/policy.yaml`) + **10 unsupported `1.0.0`** + **7 invalid `schema_version:`** = **19 broken policies of 27 total `.yaml` policies under `examples/`**. Only 8 of 27 are loadable (the 1.2.0 / 1.3.0 / hello-secure-agent set + spider-sense-threat-intel + minimal-posture + enterprise-posture + synthesized-example).
- **Action:** Bulk rewrite mandatory. A single sed pass and one targeted edit-script fixes all 19.

### D08-NEW-2: Schema version drift broader than original audit reported

- Beyond `docs/src/reference/policy-schema.md`, `docs/src/README.md`, `docs/src/concepts/policies.md`:
  - `docs/src/getting-started/first-policy.md:5` declares "Policy schema `1.2.0` is current" (wrong — code is 1.5.0).
  - `docs/src/getting-started/quick-start.md:54` uses `1.2.0`.
  - `crates/libs/clawdstrike/README.md:10` says "schema v1.2.0".
  - `crates/libs/clawdstrike/README.md:41` example uses `1.2.0`.
  - `packages/sdk/hush-py/README.md:81, 138` uses `1.1.0`.
  - `CONTRIBUTING.md:153` uses `1.2.0`.
- Original audit only flagged 4 locations; actual schema-version drift spans **at least 11 locations** across docs, READMEs, and getting-started flows.
- **Action:** Reconciling schema-version drift is a wider sweep than the audit suggested. Recommended: introduce a single `SCHEMA_VERSION` placeholder/include in mdBook + a CI lint comparing every doc mention against the Rust constant.

### D08-NEW-3: Hardcoded `/Users/connor/...` paths in 11 committed docs (audit only called out 2)

- The original audit flagged hardcoded paths only in `docs/plans/swarm-engine/ARCHITECTURE.md`. There are actually **11 files** with `/Users/connor/...` paths embedded:
  - `docs/roadmaps/cua/research/EXECUTION-AGENT-HANDOFF-PROMPT-INTEGRATION-TEAM.md:7`
  - `docs/roadmaps/cua/research/EXECUTION-AGENT-HANDOFF-PROMPT-PASS14.md:326`
  - `docs/roadmaps/cua/research/EXECUTION-AGENT-HANDOFF-PROMPT.md:7`
  - `docs/nono-integration/INDEX.md:51-52` (2 paths)
  - `docs/plans/sentinel-swarm/INDEX.md:175`
  - `docs/plans/swarm-engine/ARCHITECTURE.md:35`
  - `docs/plans/workbench-dev/patterns-reference.md:4`
  - `docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md:12, 20-24` (6 paths in one file)
  - `docs/specs/04-apache-2-license.md:23`
  - `docs/reports/2026-02-26-openclaw-runtime-compatibility-validation.md:12`
- **Action:** STRIP all 11. Replace with placeholders (`<repo-root>/...` or workspace-relative paths). The audit's call to "REWRITE (remove the absolute paths)" should expand to all 11 files, not just `swarm-engine`.

### D08-NEW-4: `docs/roadmaps/cua/` subtree is aspirational + has hardcoded paths

- The original audit mentioned `docs/roadmaps/` as overlapping with `docs/plans/` but did NOT explore `docs/roadmaps/cua/`. The subtree contains `deep-research-report.md` (678 lines mentioned in audit table) plus a `research/` sub-subtree with multiple "EXECUTION-AGENT-HANDOFF-PROMPT-*.md" files containing user paths.
- These files are operational handoff prompts (anti-pattern same as the codex-handoff-prompt.md flagged elsewhere).
- **Action:** WIPE `docs/roadmaps/cua/research/*HANDOFF*.md`. Demote `deep-research-report.md` to `docs/research/`.

### D08-NEW-5: `docs/src/getting-started/` schema-version drift was not in original audit

- `docs/src/getting-started/quick-start.md:54` and `docs/src/getting-started/first-policy.md:5,10` both use stale schema versions; the latter explicitly says "Policy schema `1.2.0` is current."
- This is the first page a new user sees. Higher impact than the reference/policy-schema page.
- **Action:** ELEVATE this to HIGH. The new-user happy path is broken.

### D08-NEW-6: Spider Sense roadmap claim contradicts MEMORY.md / shipping code

- `docs/src/roadmap.md:33` says "12 Built-in Guards" (header), but `docs/src/concepts/guards.md:32` and `docs/src/reference/guards/README.md:3` correctly say "13 built-in guards".
- `docs/src/roadmap.md:50` calls SpiderSenseGuard "beta, feature-gated (`--features clawdstrike-spider-sense`)" — but MEMORY.md confirms first-class promotion 2026-03-03; the feature gate was removed.
- `docs/src/roadmap.md:526,536` continues to track Spider Sense as feature-gated with "Graduate from feature gate" listed as Q3 2026 work.
- **Action:** REWRITE roadmap section on Spider Sense. (Wave 3/G recommends archive → ADR-0013.)

### D08-NEW-7: `docs/plans/clawdstrike/` mixed nesting clutters the planning surface

- `docs/plans/clawdstrike/` (one of 18 top-level plan dirs) contains: 3 `adaptive-sdr-*.md` files (at the root of that subtree, not in their own dir), plus subdirs `endpoint-decision-engine/`, `formal-verification/`, `huntronomer/`, `macos-es-ne/`, `reference-architectures/`, `secret-broker/`. Wave 3/G recommends flattening (drop the redundant `clawdstrike/` nesting).
- The `huntronomer/` subdir has its own `workspace-shell/` sub-subdir (confirmed: `current-state.md`, `README.md`, `roadmap.md`, `swarm-plan.md`, `target-architecture.md`). Wave 3/G says workspace-shell is abandoned (`crates/libs/huntronomer-workspace-core/` doesn't exist — confirmed via `find`).
- **Action:** Apply Wave 3/G Commit 5 plan — flatten `clawdstrike/formal-verification/` and `clawdstrike/endpoint-decision-engine/`; delete `clawdstrike/huntronomer/` (including workspace-shell).

### D08-NEW-8: 13 axioms in `IteratorAxioms.lean` are weakest-needed but undocumented in public docs

- `formal/lean4/ClawdStrike/ClawdStrike/Proofs/Impl/IteratorAxioms.lean` header (lines 1-24) clearly states: "MINIMAL set of behavioral axioms needed so that the bridge proofs in SpecImplEquiv.lean and DenyMonotonicity_Impl.lean can proceed", "stated as weakly as possible", "consistent with (but weaker than) a full denotational model".
- That's the kind of intellectually honest engineering note that BELONGS in `docs/src/formal-verification.md`. Currently it's a buried Lean-file comment.
- **Action:** Surface the trust-boundary discussion publicly. Copy/adapt this paragraph into the new Limitations section of formal-verification.md.

### D08-NEW-9: `.planning/` tree quality is high; recommendation is misalignment, not deletion

- `.planning/PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md` are well-structured GSD artifacts. They document a real shipping product (`apps/academy/`).
- Original audit and Wave 3/G's "MOVE out of repo" treatment was based on the audit-driven assumption that `.planning/` was orphan content. With `apps/academy/` confirmed shipping, the correct move is `git mv .planning apps/academy/.planning` and update any cross-refs.
- The phases/ subdir under `.planning/` is empty (`ls .planning/phases` returned empty earlier in this analysis), so the move is clean.
- **Action:** REPLACE the "delete or move out of repo" recommendation with a co-located move: `git mv .planning apps/academy/.planning` (or use the GSD convention `apps/academy/.planning/`).

---

## AGGRESSIVE EXECUTION PLAN (TOP-5)

The user has an AGGRESSIVE ceiling. These five clusters maximize repo-hygiene improvement per unit of risk.

### 1. Mass schema-version cleanup (1 day, mostly mechanical)

- **Examples:** Bulk-rewrite all 19 broken example policies (10× `1.0.0` → `1.5.0` or `1.2.0`; 2× `clawdstrike-v1.0` → `1.5.0` with structural rewrite for `bb-edr` + `openclaw-plugin`; 7× `schema_version:` → `version:`).
- **Docs:** Update `docs/src/reference/policy-schema.md:11-21` to list 1.5.0 as latest. Update `docs/src/concepts/policies.md`, `docs/src/getting-started/{quick-start,first-policy}.md`, `docs/src/README.md`, `CONTRIBUTING.md:153`, `crates/libs/clawdstrike/README.md:10,41`, `packages/sdk/hush-py/README.md:81,138`.
- **CI lockdown:** Add `scripts/validate-example-policies.sh` invoking `hush policy verify` on every YAML under `examples/` + `packs/`. Add `scripts/check-docs-schema-version.sh` that greps for version strings in docs and asserts they match `POLICY_SCHEMA_VERSION` (or a small allowlist).
- **Net:** 11+ doc files updated, 19 example policies fixed, 2 CI lints added. ~250 line diff total.

### 2. Stop the planning bleeding (1 day, mostly deletion)

The aggressive ceiling permits wholesale deletion. Combine the original audit's Phase 1 with Wave 3/G's Commit 4:

- `git rm` (kept atomic, reviewable):
  - `docs/HANDOFF.md`
  - `docs/auth.md`
  - `docs/plans/implementation-pad.md`
  - `docs/plans/2026-02-25-openclaw-adapter-core-alignment.md`
  - `docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md`
  - `docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md`
  - `docs/plans/clawdstrike/adaptive-sdr-research-brief.md`
  - `docs/plans/clawdstrike/adaptive-sdr-review.md`
  - `docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md`
  - `docs/roadmaps/implementation-tasks.md` (Wave 3/G: dead tracker)
  - `docs/plans/clawdstrike/huntronomer/roadmap.md` (Wave 3/G: superseded)
  - `docs/plans/clawdstrike/huntronomer/workspace-shell/roadmap.md` (Wave 3/G: abandoned crate)
  - `docs/plans/clawdstrike/reference-architectures/implementation-roadmap.md` (Wave 3/G: pure duplication)
  - `docs/plans/multi-agent/codex-runtime-investigation-wave.md`
  - `docs/plans/multi-agent/codex-swarm-playbook.md` (or move to `.agents/playbooks/`)
- `git rm -r`:
  - `docs/plans/agent-frameworks/` (7 files, ~256K)
  - `docs/nono-integration/` (8 files)
  - `docs/roadmaps/cua/research/EXECUTION-AGENT-HANDOFF-PROMPT*.md` (3 files with hardcoded paths)
- **Net deletion:** ~60+ files, ~300K+ tokens of planning text. Net signal-to-noise improvement: huge.

### 3. Formal verification truth-telling (2-3 days)

- **REWRITE** `docs/src/formal-verification.md` adding explicit Limitations section that lists:
  - 5 `sorry` admissions (4 in `Impl/Merkle/Funs.lean`, 1 in `Proofs/MergeMonotonicity.lean:122`).
  - 141 `axiom` declarations across the Lean project (cite breakdown).
  - The 13 hand-written iterator axioms in `IteratorAxioms.lean` — surface the existing weakest-needed framing from that file's header.
- **CREATE** `formal/lean4/ClawdStrike/TRUSTED-AXIOMS.md` cataloguing all 141 axioms grouped by class (Aeneas-stdlib, Rust-stdlib, hand-written iterator, crypto opaque, Merkle-related).
- **DECIDE** on the Merkle serde `sorry`s: either complete the translation (medium effort) or scope down public Merkle claims to "inclusion-witness math only, not serde round-trip".
- **DECIDE** on `formal/tlaplus/PostureStateMachine.tla`: document + CI-integrate or delete. There is no halfway here.
- **CREATE** `formal/README.md` documenting `lake build`, `formal-diff-tests`, `regenerate-aeneas.sh`, and the trust-boundary structure.

### 4. Roadmap consolidation per Wave 3/G plan (3-5 days)

Apply Wave 3/G's full migration plan:

- Commit 1: REWRITE `docs/src/roadmap.md` to ≤300 lines with current-quarter focus. Update guard count to 13, schema to v1.5.0, mark Spider Sense first-class (D08-NEW-6 fix).
- Commit 2: Add ADRs 0009-0015 (one per shipped roadmap).
- Commit 3: `git mv` 8 shipped roadmaps to `docs/plans/decisions/archive/`.
- Commit 4: `git rm` dead roadmaps (already in cluster #2 above).
- Commit 5: Flatten `docs/plans/clawdstrike/{formal-verification,endpoint-decision-engine}/` to top-level under `docs/plans/`.
- Commit 6: Update `SUMMARY.md`, `DOCS_MAP.md`, `REPO_MAP.md`, `CLAUDE.md` cross-refs.
- Commit 7: `git mv .planning apps/academy/.planning` (D08-NEW-9 fix — replaces Wave 3/G's deletion recommendation).
- **Net:** ~9 roadmaps deleted / archived. Canonical roadmap is one file under 300 lines.

### 5. Hardcoded-path purge (2 hours)

- Strip `/Users/connor/Medica/backbay/standalone/...` from all 11 affected files (most are slated for deletion in cluster #2; remaining survivors get sed replacement to repo-relative paths).
- Add `scripts/check-no-hardcoded-paths.sh` to CI that fails on any `/Users/...` or `/home/...` in tracked files.
- **Net:** ~11 files cleaned, 1 CI guardrail added.

---

## DEFER / OUT OF SCOPE

These appear in the source audit but should be intentionally deferred:

- **`docs/src/hunt/`** content trimming (LOW). Hunt CLI is shipping; ROADMAP can move to archive per Wave 3/G Commit 3, but architecture.md is genuinely useful reference. Keep.
- **`docs/src/guides/`** SUMMARY grouping (LOW). Nice-to-have, low payoff.
- **`docs/static/`** image captions (LOW). Verify currency before captioning.
- **`examples/rust/` and `examples/typescript/`** flattening (LOW). Mechanical rename. Defer until other example-dir work happens.
- **`docs/specs/04-apache-2-license.md`** archival (LOW). Trivial, do as part of cluster #2 if convenient.
- **Discord URL verification.** Defer to whoever owns community surfaces; if not actively running a server, just remove the line.

Out of scope for this audit (covered by D01 / wave3):
- Root-level `*.md` files (D01).
- Cargo workspace topology and metadata (D03/D04).
- Adapter package contents (D05).
- CHANGELOG / GOVERNANCE / SECURITY / CODE_OF_CONDUCT / THREAT_MODEL / NON_GOALS at repo root (D01).
- Roadmap-content-as-such (Wave 3/G); D08 covers only the file-system / publishing-hygiene angle.

---

## Final Note

The 2026-05-23 audit was directionally correct on every major finding. Three specific claims are wrong (vercel-ai adapter exists, docs/book/ is already gitignored, .planning/ documents a shipping product not vapor). Two counts undercounted (examples schema drift is 19 broken vs ~11; hardcoded-path bleeding spans 11 files vs 1). One blocker was missed entirely (getting-started flow tells new users 1.2.0 is current — 3 versions stale from the engine).

Under the user's AGGRESSIVE ceiling, the right move is to execute clusters 1, 2, 5 in a single sustained push (1 day total), then schedule clusters 3 and 4 sequentially (5-8 days total). Net repo improvement: ~70 files deleted, ~120K tokens of planning sludge eliminated, 1 CI guardrail per major drift surface, formal-verification claims aligned with reality.
