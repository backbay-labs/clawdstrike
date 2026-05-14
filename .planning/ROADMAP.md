# Roadmap: ClawdStrike Academy

## Overview

ClawdStrike Academy delivers an interactive browser-based onboarding experience for new engineers learning the ClawdStrike runtime security system. The roadmap moves from foundational infrastructure (WASM integration, MDX pipeline, theming) through shared interactive components (playground, source viewer, challenge system), into content authoring for all three learning tracks (Threat Scenarios, Guard Gallery, Policy Lab), and finishes with polish features (search, keyboard navigation). Each phase delivers a coherent, verifiable layer that the next phase builds on.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Foundation and WASM Integration** - Next.js app scaffold with working WASM engine, MDX pipeline, theming, and proof-of-concept playground
- [x] **Phase 2: Shared Components and Content Infrastructure** - Reusable interactive components (source viewer, challenge system, progress tracking) and non-WASM guard simulation layer
- [ ] **Phase 3: Threat Scenarios and Guard Gallery** - Tracks 1 and 2 content: motivational threat lessons and all 13 guard deep-dive pages with playgrounds and bypass challenges
- [x] **Phase 4: Policy Lab and Polish** - Track 3 content (policy editor, inheritance, rulesets) plus search and keyboard navigation (completed 2026-03-21)

## Phase Details

### Phase 1: Foundation and WASM Integration
**Goal**: A new engineer can open the app, see a working lesson page with syntax-highlighted code, toggle dark/light mode, and evaluate a prompt injection payload against the real WASM engine in a split-pane playground
**Depends on**: Nothing (first phase)
**Requirements**: FOUN-01, FOUN-02, FOUN-03, FOUN-04, FOUN-05, FOUN-06, DSGN-01, DSGN-05, DSGN-06
**Success Criteria** (what must be TRUE):
  1. App loads in browser with a progress indicator while the ~1.6MB WASM binary initializes, and shows an error message if WASM fails to load
  2. User can navigate a sidebar of tracks and lessons, click between them, and use Previous/Next links to move sequentially
  3. User can enter a text payload in the Guard Playground, click evaluate, and see a verdict (ALLOW/DENY), guard name, severity, and evidence from the real WASM engine
  4. Code blocks in lessons render with syntax highlighting (Shiki), support dark and light themes, and have a copy-to-clipboard button
  5. Dark/light mode toggle switches the entire app theme and persists the preference across page reloads
**Plans**: 3 plans

Plans:
- [x] 01-01-PLAN.md -- Scaffold Next.js 16 app with MDX pipeline, Shiki highlighting, dark/light theming, and shadcn/ui design system
- [x] 01-02-PLAN.md -- Content routing, sidebar navigation, Previous/Next links, and 3 stub MDX lessons
- [ ] 01-03-PLAN.md -- WASM integration layer, typed API wrappers, and Guard Playground with split-pane layout

### Phase 2: Shared Components and Content Infrastructure
**Goal**: The reusable interactive building blocks exist so that content authors can embed annotated source snippets, bypass challenges, and guard playgrounds (including non-WASM guards) into any lesson, and user progress is tracked
**Depends on**: Phase 1
**Requirements**: FOUN-07, DSGN-02, INTX-01, INTX-02, INTX-03
**Success Criteria** (what must be TRUE):
  1. User can see annotated source code from real .rs/.ts files with highlighted lines and hover/click annotations rendered by the source viewer component
  2. Source snippets displayed in lessons are extracted from the actual codebase at build time (not copy-pasted), and the build fails if tagged source regions are missing
  3. User can attempt bypass challenges by entering payloads, and the system checks whether the guard verdict matches the expected outcome (e.g., ALLOW when DENY was expected)
  4. Non-WASM guards (forbidden path, egress, secret leak, shell command, MCP, patch, CUA, remote desktop) evaluate in the playground via TypeScript simulation or extended WASM exports
  5. Completed lessons show a checkmark in the sidebar, and completion state persists across browser sessions via localStorage
**Plans**: 3 plans

Plans:
- [x] 02-01-PLAN.md -- Test framework, guard types, and all 8 non-WASM guard TS simulations with unified evaluateGuard dispatcher
- [x] 02-02-PLAN.md -- Build-time source extraction script and AnnotatedSource component with Shiki highlighting and callout annotations
- [x] 02-03-PLAN.md -- Zustand progress store with localStorage persistence, sidebar checkmarks, LessonCompleteButton, and BypassChallenge component

### Phase 3: Threat Scenarios and Guard Gallery
**Goal**: A new engineer can work through Track 1 (understanding why ClawdStrike exists) and Track 2 (deep-diving into every guard), interacting with embedded playgrounds, reading annotated source, and attempting bypass challenges along the way
**Depends on**: Phase 2
**Requirements**: THR-01, THR-02, THR-03, THR-04, THR-05, GARD-01, GARD-02, GARD-03, GARD-04, GARD-05, GARD-06, INTX-04
**Success Criteria** (what must be TRUE):
  1. Track 1 opens with a lesson showing an unprotected AI agent performing dangerous actions, followed by the same actions blocked by ClawdStrike with visible verdicts and receipts
  2. Track 1 includes interactive lessons on fail-closed design (guard error still denies) and the three enforcement tiers (in-process, sidecar, centralized), each with at least one embedded playground
  3. All 13 built-in guards have a dedicated page with threat description, configuration options, annotated source snippet from the real implementation, a live playground with pre-configured inputs, and 1-3 bypass challenges
  4. Guard pages are organized by difficulty tier (green/yellow/orange/red) with complexity zone ratings and prerequisite knowledge listed
  5. At least one security regression scenario from the actual codebase (e.g., URL spoofing, path traversal) is recreated as an interactive lesson
**Plans**: 5 plans

Plans:
- [x] 03-01-PLAN.md -- Generic guard playground dispatcher and guard gallery index page with tier-colored cards
- [ ] 03-02-PLAN.md -- @academy source markers in 15 Rust files (24 tags) and extraction manifest population
- [ ] 03-03-PLAN.md -- Track 1 threat scenario lessons (Unprotected Agent, Guarded Agent, Fail-Closed, Enforcement Tiers, URL Spoofing)
- [x] 03-04-PLAN.md -- Guard gallery green + yellow tier pages (ForbiddenPath, PathAllowlist, EgressAllowlist, SecretLeak, ShellCommand, PatchIntegrity, McpTool)
- [ ] 03-05-PLAN.md -- Guard gallery orange + red tier pages (PromptInjection, Jailbreak, ComputerUse, SpiderSense, RemoteDesktop, InputInjection)

### Phase 4: Policy Lab and Polish
**Goal**: A new engineer can write, validate, and test YAML policies in the browser, compare built-in rulesets, visualize inheritance chains, and navigate the entire app efficiently with search and keyboard shortcuts
**Depends on**: Phase 3
**Requirements**: POLI-01, POLI-02, POLI-03, POLI-04, POLI-05, POLI-06, DSGN-03, DSGN-04
**Success Criteria** (what must be TRUE):
  1. User can write YAML policies in an interactive editor that validates against the v1.5.0 schema in real-time and shows guard-level validation errors inline
  2. User can see a visual tree showing policy inheritance via extends (parent-child relationships and merge behavior)
  3. User can view all 10 built-in rulesets side-by-side with differences highlighted
  4. User can complete a guided exercise creating a custom policy for a specific scenario and testing it in the playground
  5. User can search all lesson content with Cmd+K and navigate between lessons with arrow keys
**Plans**: 4 plans

Plans:
- [x] 04-01-PLAN.md -- Install deps (ajv, cmdk, pagefind, yaml), JSON Schema for policy v1.5.0, CodeMirror lint source with Ajv validation, build-time ruleset extraction to JSON
- [ ] 04-02-PLAN.md -- Pagefind search index build script, Cmd+K search modal with cmdk, keyboard arrow navigation hook with editor focus guard
- [ ] 04-03-PLAN.md -- PolicyEditor component (CodeMirror 6 + Ajv diagnostics), InheritanceTree visualizer, RulesetComparison table, MDX registration
- [ ] 04-04-PLAN.md -- Track 3 MDX lessons: Policy Anatomy, Inheritance, Ruleset Comparison, Build Your Policy exercise, Observe-Synth-Tighten workflow

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation and WASM Integration | 2/3 | In Progress | - |
| 2. Shared Components and Content Infrastructure | 3/3 | Complete | 2026-03-20 |
| 3. Threat Scenarios and Guard Gallery | 4/5 | In Progress |  |
| 4. Policy Lab and Polish | 4/4 | Complete   | 2026-03-21 |
