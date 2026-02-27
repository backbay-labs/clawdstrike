# Prompt Security: Implementation Notes (Rust + TS)

This repo now includes first-pass implementations of several prompt-security components:

- Rust (`crates/libs/clawdstrike`)
  - Prompt injection detection + canonicalization: `clawdstrike::hygiene`
  - Instruction hierarchy enforcement: `clawdstrike::instruction_hierarchy`
  - Output sanitization (secrets + basic PII + allow/deny lists + streaming): `clawdstrike::output_sanitizer`
    - Optional external NER hook: `EntityRecognizer`
  - Prompt watermarking (metadata, signed; RFC 8785 canonical payload bytes): `clawdstrike::watermarking`
  - Jailbreak detection (heuristics + stats + configurable linear model + optional LLM judge hook): `clawdstrike::jailbreak`
    - Session aggregation now supports TTL + half-life decay + optional persistence (`SessionStore`)
  - CLI helpers:
    - `cargo run -p clawdstrike --bin prompt_security_scan`
    - `cargo run -p clawdstrike --bin prompt_watermark`

- TypeScript (`packages/sdk/hush-ts`, `packages/adapters/clawdstrike-openclaw`)
  - Watermarking: `packages/sdk/hush-ts/src/watermarking.ts`
  - Instruction hierarchy: `packages/sdk/hush-ts/src/instruction-hierarchy.ts`
  - Jailbreak detection: `packages/sdk/hush-ts/src/jailbreak.ts`
  - Output sanitization (secrets + basic PII + allow/deny lists + streaming): `packages/sdk/hush-ts/src/output-sanitizer.ts`
    - Optional external NER hook: `EntityRecognizer`
  - Tool-output sanitization (OpenClaw hook): `packages/adapters/clawdstrike-openclaw/src/sanitizer/output-sanitizer.ts`

- Integrations (initial wiring)
  - Vercel AI SDK middleware can enable prompt-security for model calls via `config.promptSecurity`:
    - `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts`
    - `packages/adapters/clawdstrike-vercel-ai/README.md`

## Draft roadmap: Event-driven agent defense (Spider-Sense-style)

Spider-Sense (Yu et al., Feb 2026) is a good fit for this repo’s prompt-security direction:

- Roadmap: `docs/roadmaps/spider-sense-integration.md`
- Task tracker: `docs/roadmaps/implementation-tasks.md`

The key addition vs current implementations is **selective, stage-aware screening** across query/plan/action/observation, with a **fast similarity-match path** and an optional **LLM deep-analysis path** for ambiguous cases.

Known gaps remain vs the full research specs (e.g., homoglyph mapping, encoding decode before scan, robust watermark encodings, NER-based PII, and fully managed LLM judge calls). See the PR summary for details.
