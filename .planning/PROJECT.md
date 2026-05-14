# ClawdStrike Academy

## What This Is

An interactive Next.js 16 onboarding web app that teaches new engineers the ClawdStrike runtime security system through hands-on, in-browser experiences. New hires use the real WASM-compiled policy engine to evaluate actions, break guards, write policies, and build intuition — across 3 learning tracks with 23 lessons, 13 guard deep-dives, and 26 bypass challenges.

## Core Value

A new engineer understands *why* ClawdStrike exists and *how* it works by interacting with the real engine in their browser, compressing weeks of onboarding into days.

## Requirements

### Validated

- ✓ Interactive threat scenarios showing why AI agent security enforcement exists — v1.5
- ✓ Live WASM-powered guard playgrounds for all 13 built-in guards — v1.5
- ✓ Guard Gallery with threat descriptions, annotated source, and bypass challenges — v1.5
- ✓ Visual YAML policy editor with live validation against the real schema — v1.5
- ✓ Policy inheritance visualization (extends chains, merge strategies) — v1.5
- ✓ Built-in ruleset comparison view (all 10 rulesets side-by-side) — v1.5
- ✓ MDX content system for lesson authoring with embedded React components — v1.5
- ✓ Progress tracking (per-track, per-lesson completion) — v1.5
- ✓ Annotated source code viewer pulling real .rs/.ts files with Shiki highlighting — v1.5
- ✓ Security regression scenarios from actual bugs (URL spoofing) — v1.5
- ✓ Dark/light mode with clean modern design (shadcn/ui) — v1.5

### Active

- [ ] Architecture interactive graph (Track 4) — D3/React Flow crate dependency visualization
- [ ] "Your First PR" exercises (Track 5) — guided contribution workflow
- [ ] CTF scoring mode — optional competitive mode for team events

### Out of Scope

- User accounts/auth — internal tool, localStorage sufficient
- Mobile responsiveness — desktop-first for onboarding
- Video tutorials — go stale fast, can't be searched/diffed
- AI chatbot assistant — content should be self-explanatory
- Tauri wrapper — Next.js web app only

## Context

Shipped v1.5 with ~9,800 LOC TypeScript/TSX/MDX across `apps/academy/`.
Tech stack: Next.js 16, @next/mdx, CodeMirror 6, shadcn/ui, Tailwind v4, Shiki, Zustand, hush-wasm.
App lives at `apps/academy/` inside the clawdstrike monorepo.
3 learning tracks: Threat Scenarios (5 lessons), Guard Gallery (13 guards + index), Policy Lab (5 lessons).
9 TypeScript guard simulations + 5 WASM detection guards for in-browser evaluation.
24 `@academy` source markers in Rust guard files for build-time extraction.
Pagefind static search with Cmd+K modal across all content.

## Constraints

- **Tech stack**: Next.js 16 (App Router), MDX, shadcn/ui, Tailwind v4, Shiki, hush-wasm
- **WASM dependency**: Must load hush-wasm in browser for live guard evaluation
- **Content accuracy**: All guard descriptions and code annotations must match current codebase
- **Monorepo integration**: Lives in `apps/academy/`, excluded from default cargo workspace
- **No backend**: Static/client-side only — WASM handles all evaluation logic

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Next.js 16 over Tauri | Browser-based = easier to share, WASM runs natively, no install | ✓ Good |
| MDX for content | Write lessons as Markdown, embed interactive React components inline | ✓ Good |
| Real WASM engine, not mocks | The "wow" moment is running the actual policy engine in-browser | ✓ Good |
| Tracks 1-3 for v1.5 | Threat intro + Guard Gallery + Policy Lab covers the interactive core | ✓ Good |
| shadcn/ui + clean modern | Professional look, dark/light toggle, matches dev tooling aesthetics | ✓ Good |
| TS guard simulations for non-WASM guards | 8 pattern-matching guards ported to TypeScript, functionally equivalent | ✓ Good |
| Client-side Shiki over rehype-pretty-code | Turbopack can't serialize function references in MDX loader | ✓ Good (workaround) |
| Ajv over WasmPolicyLab for editor validation | Richer error messages, YAML position mapping, no async overhead | ✓ Good |
| Pagefind over Algolia/Flexsearch | Static index, tiny client, works with static export, no account needed | ✓ Good |

---
*Last updated: 2026-03-21 after v1.5 milestone*
