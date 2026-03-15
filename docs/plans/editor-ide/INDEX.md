# Detection Engineering IDE — Architectural Index

> Synthesized from 13-agent codebase and competitive landscape analysis.
> Last updated: 2026-03-15

## 0. Current Status Note

This index and the original companion docs describe the baseline expansion from a policy editor into a multi-format detection IDE. Since then, the workbench has already shipped substantial parts of that plan:

- typed detection tabs and format-aware open/save
- Sigma, YARA, and OCSF editor surfaces
- mounted command palette, explorer, problems panel, and ATT&CK heatmap
- Hunt, Simulate, and Swarm Board surfaces that are now relevant to the next planning wave

**The Detection Lab implementation is now complete (2026-03-15).** All six phases (0-5) from the implementation plan have been delivered. The detection-workflow module provides 25 source files with a barrel export at `detection-workflow/index.ts` covering types, adapters (policy, sigma, yara, ocsf), stores (document identity, evidence pack, lab run, publication), services (draft generation, explainability, coverage gap discovery, evidence redaction), hooks (draft detection, evidence packs, lab execution, publication, coverage gaps, swarm launch), and swarm integration (detection nodes, session templates, receipt linking).

Reference documents:

- [`DETECTION-LAB-ARCHITECTURE.md`](./DETECTION-LAB-ARCHITECTURE.md) -- architecture
- [`DETECTION-LAB-IMPLEMENTATION.md`](./DETECTION-LAB-IMPLEMENTATION.md) -- implementation plan (complete)

Recommended reading order now:

1. this index
2. [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the original baseline assumptions
3. [`DETECTION-LAB-ARCHITECTURE.md`](./DETECTION-LAB-ARCHITECTURE.md) for the current code-grounded extension
4. [`DETECTION-LAB-IMPLEMENTATION.md`](./DETECTION-LAB-IMPLEMENTATION.md) for the execution plan and completion status

---

## 1. Executive Summary

**Goal:** Extend the ClawdStrike Workbench from a single-format policy editor into a multi-format Detection Engineering IDE supporting four detection artifact types.

**Supported Formats:**

| Format | Extension | Purpose |
|--------|-----------|---------|
| ClawdStrike Policy | `.yaml` | Agent runtime security policies |
| Sigma Rules | `.yml` | Vendor-agnostic detection rules |
| YARA Rules | `.yar` | Pattern-matching for malware/artifacts |
| OCSF Events | `.json` | Open Cybersecurity Schema Framework telemetry |

**Current State:**
- 318 source files, 155 components, 80 test files in the workbench
- CodeMirror 6 editor with visual form + YAML split view
- Tauri 2 desktop shell, React 19, Vite 6
- 13 built-in guards with Guard/AsyncGuard trait pipeline
- Production-grade `clawdstrike-ocsf` crate (4 event classes, 6 converters)
- `hunt-correlate` crate with Sigma compile + preview + test
- YARA validation only (1,311-line design spec exists; scanner engine not built)
- MCP sidecar + Claude Code plugin

**Market Opportunity:** No unified open-source detection IDE exists. Format fragmentation is the number one problem cited by detection engineers. 63% of security teams want Detection-as-Code but only 35% practice it. The gap is tooling.

---

## 2. Current Architecture

### Frontend Stack

```
React 19 + Tauri 2 + Vite 6 + CodeMirror 6
├── 155+ components
├── 15+ context stores (provider pyramid, see Risk R1)
├── 20+ routes
├── 80 test files
└── Multi-tab editor (max 10 tabs), 3-layer validation
```

### Editor Model

Historical baseline when this index was first written:
- `PolicyTab` interface in `multi-policy-store.tsx` was still the conceptual center of the editor model
- Visual form editor (left) + YAML source (right) via `split-editor.tsx`
- `yaml-editor.tsx` wrapped CodeMirror 6 with the ClawdStrike theme
- `yaml-schema.ts` provided schema-driven autocompletion
- 3-layer validation: client-side schema check, Rust Tauri command, guard evaluation

For the current shipped multi-format state and the next-wave planning assumptions, use the detection-lab docs linked above.

### Rust Backend

```
crates/libs/
├── clawdstrike/         # 13 guards, policy engine, receipts
├── clawdstrike-ocsf/    # 4 event classes, 6 converters, validation
├── hunt-correlate/      # Sigma compile/preview/test, IOC extraction
├── hush-core/           # Crypto primitives (Ed25519, SHA-256, Merkle)
└── hush-wasm/           # WASM bindings for browser-side detection

apps/workbench/src-tauri/src/commands/
└── workbench.rs         # Tauri command handlers (pattern for new commands)
```

### Backend Readiness by Format

| Format | Crate | Maturity | Missing |
|--------|-------|----------|---------|
| Policy | `clawdstrike` | Production | Nothing |
| Sigma | `hunt-correlate` | Functional | DB schema ready but not wired to editor |
| OCSF | `clawdstrike-ocsf` | Production | Editor integration only |
| YARA | (none) | Spec only | Scanner engine (`yara-x` integration) |

---

## 3. Key Design Decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | **CodeMirror 6** (not Monaco) | Lighter bundle (~150KB vs ~2MB), faster cold start, custom theme compatible, already integrated |
| D2 | **Sigma first, OCSF second, YARA third** | Ordered by backend readiness. `hunt-correlate` already compiles Sigma; OCSF crate is production-grade but needs editor wiring; YARA needs a new scanner engine |
| D3 | **`PolicyTab` becomes `DetectionTab` discriminated union** | `type DetectionTab = PolicyTab \| SigmaTab \| YaraTab \| OcsfTab` with a `kind` discriminator. Backward-compatible migration: existing `PolicyTab` fields preserved |
| D4 | **Single `CodeEditor` component with `fileType` prop** | One CodeMirror wrapper dispatches language support, completion, and linting by format. Avoids 4x component duplication |
| D5 | **YARA via `StreamLanguage` initially, Lezer grammar later** | StreamLanguage adapts a TextMate-style tokenizer to CodeMirror 6. Full Lezer grammar is a separate milestone |
| D6 | **IndexedDB-first persistence** | Breaks the 5MB localStorage wall. Optional filesystem sync via Tauri for project-mode |
| D7 | **Rust validation authoritative, client-side as fallback** | All format validation runs through Tauri commands. Client-side checks are cosmetic hints only |
| D8 | **Cherry-pick `capability.rs` + `worktree.rs` from PR #193** | These two modules provide the filesystem capability model needed for project-mode. Build remaining detection commands fresh |
| D9 | **`yara-x` (BSD, Rust-native) for YARA engine** | `yara-x` is VirusTotal's official Rust rewrite. BSD-licensed, no C dependencies, safe FFI. Classic `yara` is GPL and C-based |
| D10 | **No LSP for v1** | Static schema-driven autocomplete is sufficient for Sigma/OCSF. LSP adds complexity without proportional value at this stage |

---

## 4. Format Color System

Each detection format has a distinct color used for tab indicators, status bar badges, file tree icons, and format selector UI:

| Format | Color | Hex | Usage |
|--------|-------|-----|-------|
| Policy | Gold | `#d4a84b` | Existing brand color, carried forward |
| YARA | Amber | `#e0915c` | Warm tone, distinct from gold at small sizes |
| Sigma | Indigo | `#7c9aef` | Cool tone, high contrast against dark theme |
| OCSF | Teal | `#5cc5c4` | Complementary to indigo, reads well on both themes |

These colors pass WCAG AA contrast ratio on the workbench dark theme (`#1a1a2e` background).

---

## 5. Critical Risks

| ID | Risk | Severity | Mitigation |
|----|------|----------|------------|
| R1 | **Context provider pyramid** (13+ deep, will grow with new stores) | High | Extract to Zustand or Jotai; reduce provider nesting |
| R2 | **PolicyTab type coupling** across 9 files | High | Introduce `DetectionTab` union type behind a migration shim |
| R3 | **Tab limit of 10** hardcoded | Medium | Make configurable; consider virtual tab bar for overflow |
| R4 | **localStorage 5MB limit** | High | Migrate to IndexedDB (D6) before adding new formats |
| R5 | **Scope too large** | Critical | Phase aggressively; Sigma MVP before touching OCSF/YARA |
| R6 | **Three personas, one tool** (policy author, threat hunter, malware analyst) | Medium | Role-aware layout presets; avoid lowest-common-denominator UX |
| R7 | **No project model** (files are standalone) | Medium | Introduce workspace/project concept backed by filesystem directory |
| R8 | **YARA scanner engine not built** | High | `yara-x` integration is a prerequisite; spec exists but no code |
| R9 | **VS Code as primary competitor** | Medium | Differentiate on integrated validation, guard pipeline, and OCSF normalization — things VS Code extensions cannot do |

---

## 6. Document Index

Companion documents in this directory:

| Document | Purpose |
|----------|---------|
| `ROADMAP.md` | Phased implementation plan with milestones and deliverables |
| `ARCHITECTURE.md` | Detailed technical architecture: component tree, state flow, Tauri command surface |
| `DETECTION-LAB-ARCHITECTURE.md` | Repo-grounded architecture for the closed-loop detection workflow: hunt, replay, lab, swarm, publish, coverage, and explainability |
| `DETECTION-LAB-IMPLEMENTATION.md` | Implementation slices, storage/API contracts, merge order, and verification plan for the next-wave features |
| `UI-SPEC.md` | UI/UX specification with wireframes, interaction flows, and accessibility notes |
| `RISK-ANALYSIS.md` | Full risk register with probability, impact, and mitigation plans |
| `COMPETITIVE-LANDSCAPE.md` | Market research: existing tools, positioning, differentiation strategy |
| `FORMAT-SPECS.md` | OCSF/YARA/Sigma format reference for editor integration (schemas, examples, validation rules) |
| `PR-193-ANALYSIS.md` | PR #193 cherry-pick analysis: what to take, what to leave, merge strategy |

Recommended reading order for the current initiative:

1. `ARCHITECTURE.md`
2. `ROADMAP.md`
3. `DETECTION-LAB-ARCHITECTURE.md`
4. `DETECTION-LAB-IMPLEMENTATION.md`

---

## 7. Key Files

Files that require modification or serve as patterns for the detection IDE work.

### Frontend (apps/workbench/src/)

| File | Role | Required Change |
|------|------|-----------------|
| `lib/workbench/multi-policy-store.tsx` | Core state management, `PolicyTab` type, tab CRUD | Generalize to `DetectionTab` union; extract format-agnostic tab logic |
| `components/ui/yaml-editor.tsx` | CodeMirror 6 wrapper | Accept `fileType` prop; dispatch language support, completion, linting by format |
| `components/workbench/editor/split-editor.tsx` | Visual + source split view | Dispatch to format-specific visual panels (Sigma condition builder, OCSF field picker) |
| `lib/workbench/yaml-schema.ts` | Schema-driven autocompletion for policies | Pattern for Sigma/OCSF completion sources; extract base `SchemaCompletionSource` |
| `components/workbench/editor/policy-tab-bar.tsx` | Tab bar with policy indicators | Add format color badges; rename to `detection-tab-bar.tsx` |
| `components/desktop/status-bar.tsx` | Status bar with validation state | Add format-aware metrics (Sigma target count, YARA rule count, OCSF class) |
| `lib/workbench/types.ts` | Central type definitions | Add `DocumentKind` discriminator enum: `"policy" \| "sigma" \| "yara" \| "ocsf"` |

### Rust Backend (crates/ and src-tauri/)

| File | Role | Required Change |
|------|------|-----------------|
| `apps/workbench/src-tauri/src/commands/workbench.rs` | Tauri command handlers | Add `validate_sigma`, `compile_sigma`, `validate_yara`, `scan_yara`, `validate_ocsf` commands |
| `crates/libs/hunt-correlate/src/detection.rs` | Sigma/YARA detection backend | Expose compile/validate/test as library API consumable by Tauri commands |
| `crates/libs/clawdstrike-ocsf/src/validate.rs` | OCSF event validation | Wire to Tauri command surface for editor-side validation |
| `crates/libs/hunt-correlate/src/rules.rs` | Sigma rule parsing and compilation | Extend with editor-friendly error spans (line/column for CodeMirror diagnostics) |

---

## Appendix: Agent Analysis Contributors

This index synthesizes findings from 13 parallel analysis agents:

1. **Codebase Surveyor** — LOC counts, component inventory, dependency graph
2. **Editor Internals** — CodeMirror 6 integration, tab model, validation pipeline
3. **Sigma Backend** — `hunt-correlate` crate capabilities and gaps
4. **OCSF Backend** — `clawdstrike-ocsf` crate structure and converter coverage
5. **YARA Feasibility** — `yara-x` evaluation, language support options
6. **State Management** — Context stores, provider hierarchy, persistence layer
7. **Tauri Commands** — Command surface, IPC patterns, serialization
8. **Type System** — TypeScript types, discriminated unions, migration paths
9. **Testing Infrastructure** — Test coverage, Vitest setup, Tauri mock patterns
10. **Competitive Analysis** — VS Code extensions, Elastic SIEM, Splunk, Chronicle
11. **UX Research** — Detection engineer workflows, persona analysis
12. **Security Model** — Policy engine integration, guard pipeline for new formats
13. **Critic** — Risk analysis, scope assessment, architectural anti-patterns
