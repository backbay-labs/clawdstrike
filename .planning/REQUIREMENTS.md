# Requirements: ClawdStrike Academy

**Defined:** 2026-03-20
**Core Value:** A new engineer understands why ClawdStrike exists and how it works by interacting with the real engine in their browser

## v1 Requirements

### Foundation

- [ ] **FOUN-01**: App loads hush-wasm binary (~1.6MB) with progress indicator and error recovery
- [ ] **FOUN-02**: Guard Playground component accepts YAML policy + action payload and displays verdict, severity, guard name, and evidence
- [x] **FOUN-03**: MDX content system renders lessons with sidebar navigation showing tracks and lesson titles
- [x] **FOUN-04**: Lessons display in sequential order with Previous/Next navigation links
- [x] **FOUN-05**: Code blocks render with Shiki syntax highlighting, dark/light theme support, and copy-to-clipboard button
- [ ] **FOUN-06**: WASM-exported guards (jailbreak, prompt injection, output sanitizer, spider sense, instruction hierarchy) evaluate in real-time in the playground
- [x] **FOUN-07**: Non-WASM guards (forbidden path, egress, secret leak, shell command, MCP, patch, CUA, remote desktop) have TypeScript simulation or extended WASM exports for playground evaluation

### Design

- [x] **DSGN-01**: Dark/light mode toggle persists preference across sessions
- [x] **DSGN-02**: Per-lesson completion tracking via localStorage with checkmarks visible in sidebar
- [x] **DSGN-03**: Client-side search indexes all MDX content and returns results with context snippets
- [x] **DSGN-04**: Keyboard navigation: arrow keys for prev/next lesson, Cmd+K for search
- [x] **DSGN-05**: Clean modern UI using shadcn/ui components with consistent spacing and typography
- [ ] **DSGN-06**: Responsive split-pane layout for playground (editor left, output right) on desktop viewports

### Track 1: Threat Scenarios

- [x] **THR-01**: Opening lesson demonstrates an unprotected AI agent performing dangerous actions (read secrets, exfiltrate data, execute destructive commands)
- [x] **THR-02**: Second lesson shows the same actions blocked by ClawdStrike guards with visible verdicts and receipts
- [x] **THR-03**: Lesson explains the fail-closed design principle with interactive example (guard error still denies)
- [x] **THR-04**: Lesson covers the three enforcement tiers (in-process, sidecar, centralized) with diagrams
- [x] **THR-05**: Each lesson includes at least one embedded Guard Playground for hands-on interaction

### Track 2: Guard Gallery

- [x] **GARD-01**: Each of the 13 built-in guards has a dedicated page with threat description, how it works, and configuration options
- [x] **GARD-02**: Each guard page includes an annotated source code snippet from the real Rust/TS implementation
- [x] **GARD-03**: Each guard page includes an embedded Guard Playground with pre-configured example inputs
- [x] **GARD-04**: Each guard page includes 1-3 bypass challenge scenarios where users try to craft payloads that evade detection
- [x] **GARD-05**: Guards are organized by difficulty tier (green/yellow/orange/red) with visual indicators
- [x] **GARD-06**: Guard pages display complexity zone rating and prerequisite knowledge needed

### Track 3: Policy Lab

- [x] **POLI-01**: Interactive YAML policy editor with live schema validation against v1.5.0 spec
- [x] **POLI-02**: Editor shows validation errors inline with guard-level specificity (not just "invalid YAML")
- [x] **POLI-03**: Lesson demonstrates policy inheritance via `extends` with visual tree showing parent-child relationships
- [x] **POLI-04**: Side-by-side comparison view showing differences between all 10 built-in rulesets
- [x] **POLI-05**: Guided exercise: user creates a custom policy for a specific scenario and tests it in the playground
- [x] **POLI-06**: Lesson covers the observe-synth-tighten workflow for iterative policy development

### Interactive Features

- [x] **INTX-01**: Annotated source code viewer displays real .rs/.ts files with highlighted lines and hover/click annotations
- [x] **INTX-02**: Source snippets are extracted at build time from the actual codebase (not copy-pasted snapshots)
- [x] **INTX-03**: Bypass challenges check user's payload against expected verdict (ALLOW when DENY expected, or vice versa)
- [x] **INTX-04**: Security regression scenarios recreate real bugs from security_regressions.rs as interactive lessons

## v2 Requirements

### Architecture Track

- **ARCH-01**: Interactive crate dependency graph using React Flow or D3
- **ARCH-02**: Animated "happy path" trace showing policy check flow end-to-end
- **ARCH-03**: Zoom levels from overview to module to function

### First PR Track

- **FRPR-01**: Guided exercise to write a custom guard using Guard SDK
- **FRPR-02**: Guided exercise to write and run a policy test
- **FRPR-03**: PR template walkthrough and submission guide

### Advanced

- **ADVN-01**: CTF mode with optional scoring for team events
- **ADVN-02**: Broker subsystem playground simulating capability lifecycle
- **ADVN-03**: Formal verification explorer with interactive Lean 4 proof viewer

## Out of Scope

| Feature | Reason |
|---------|--------|
| User accounts / authentication | Internal tool, localStorage sufficient, no login friction on day 1 |
| Mobile responsiveness | Onboarding happens at desk with monitor, YAML editing unusable on phone |
| Video tutorials | Go stale fast, can't be searched/diffed, disproportionate effort for audience size |
| AI chatbot assistant | Hallucination risk about codebase, content should be self-explanatory |
| Real-time collaborative editing | Screen sharing is simpler, WebSocket infra unjustified for 1-5 users |
| VS Code extension | Massive effort, web app IS the learning environment |
| Automated exercise grading | WASM verdict system IS the grader -- binary pass/fail via evaluation |
| Backend / database | Static/client-side only, WASM handles evaluation, localStorage handles state |
| Tauri desktop wrapper | Next.js web app only for v1, Tauri possible in v2 |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| FOUN-01 | Phase 1 | Pending |
| FOUN-02 | Phase 1 | Pending |
| FOUN-03 | Phase 1 | Complete |
| FOUN-04 | Phase 1 | Complete |
| FOUN-05 | Phase 1 | Complete |
| FOUN-06 | Phase 1 | Pending |
| FOUN-07 | Phase 2 | Complete |
| DSGN-01 | Phase 1 | Complete |
| DSGN-02 | Phase 2 | Complete |
| DSGN-03 | Phase 4 | Complete |
| DSGN-04 | Phase 4 | Complete |
| DSGN-05 | Phase 1 | Complete |
| DSGN-06 | Phase 1 | Pending |
| THR-01 | Phase 3 | Complete |
| THR-02 | Phase 3 | Complete |
| THR-03 | Phase 3 | Complete |
| THR-04 | Phase 3 | Complete |
| THR-05 | Phase 3 | Complete |
| GARD-01 | Phase 3 | Complete |
| GARD-02 | Phase 3 | Complete |
| GARD-03 | Phase 3 | Complete |
| GARD-04 | Phase 3 | Complete |
| GARD-05 | Phase 3 | Complete |
| GARD-06 | Phase 3 | Complete |
| POLI-01 | Phase 4 | Complete |
| POLI-02 | Phase 4 | Complete |
| POLI-03 | Phase 4 | Complete |
| POLI-04 | Phase 4 | Complete |
| POLI-05 | Phase 4 | Complete |
| POLI-06 | Phase 4 | Complete |
| INTX-01 | Phase 2 | Complete |
| INTX-02 | Phase 2 | Complete |
| INTX-03 | Phase 2 | Complete |
| INTX-04 | Phase 3 | Complete |

**Coverage:**
- v1 requirements: 34 total
- Mapped to phases: 34
- Unmapped: 0

---
*Requirements defined: 2026-03-20*
*Last updated: 2026-03-20 after 01-01 completion*
