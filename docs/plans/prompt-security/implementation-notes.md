# Prompt Security: Implementation Notes (Rust + TS)

This repo now includes first-pass implementations of several prompt-security components:

- Rust (`crates/clawdstrike`)
  - Prompt injection detection + canonicalization: `clawdstrike::hygiene`
  - Instruction hierarchy enforcement: `clawdstrike::instruction_hierarchy`
  - Output sanitization (secrets + basic PII): `clawdstrike::output_sanitizer`
  - Prompt watermarking (metadata, signed): `clawdstrike::watermarking`
  - Jailbreak detection (heuristics + stats + linear model + optional LLM judge hook): `clawdstrike::jailbreak`
  - CLI helpers:
    - `cargo run -p clawdstrike --bin prompt_security_scan`
    - `cargo run -p clawdstrike --bin prompt_watermark`

- TypeScript (`packages/hush-ts`, `packages/clawdstrike-openclaw`)
  - Watermarking: `packages/hush-ts/src/watermarking.ts`
  - Instruction hierarchy: `packages/hush-ts/src/instruction-hierarchy.ts`
  - Jailbreak detection: `packages/hush-ts/src/jailbreak.ts`
  - Tool-output sanitization (PII + secrets redaction in OpenClaw hook): `packages/clawdstrike-openclaw/src/sanitizer/output-sanitizer.ts`

Known gaps remain vs the full research specs (e.g., homoglyph mapping, encoding decode before scan, robust watermark encodings, NER-based PII, and fully managed LLM judge calls). See the PR summary for details.

