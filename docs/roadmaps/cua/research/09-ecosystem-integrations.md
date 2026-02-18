# 09 Ecosystem Integrations (OpenAI / Claude / OpenClaw / trycua)

## Scope

Define how Clawdstrike integrates with popular computer-use ecosystems without fragmenting policy, receipt, or verifier semantics.

Primary targets:

- OpenAI computer-use tool path.
- Claude computer-use tool path.
- Existing `@clawdstrike/openclaw` plugin path.
- `trycua/cua` as runtime/backend candidate.

## Core integration position

- Clawdstrike owns the canonical contract for policy events, outcomes, audit metadata, and receipt semantics.
- External libraries/providers are translated into that contract through adapters.
- External runtime/framework integration must not redefine trust roots, verifier order, or receipt compatibility rules.

## Pass #11 reviewer notes (2026-02-18)

- REVIEW-P11-CORRECTION: Integrate provider ecosystems as adapter layers, not as policy/verifier sources of truth.
- REVIEW-P11-GAP-FILL: Add canonical CUA action/event contract in adapter core before adding provider-specific translators.
- REVIEW-P11-CORRECTION: Require conformance fixtures across providers so equivalent CUA actions produce equivalent policy outcomes.

## Design constraints

- Fail closed on unknown provider action types, wrapper versions, and missing required fields.
- Keep baseline `SignedReceipt` compatibility and CUA metadata profile guarantees.
- Ensure event and outcome parity across provider adapters for equivalent interactions.
- Preserve deterministic reason codes and audit trails across all adapters.

## Integration tracks

### Track A: Canonical adapter-core CUA contract

- Extend adapter-core event model to support CUA-native flow surfaces:
  - `connect`, `input`, `clipboard_read`, `clipboard_write`,
  - `file_transfer_upload`, `file_transfer_download`, `session_share`,
  - `reconnect`, `disconnect`.
- Define canonical outcome normalization:
  - `accepted`, `applied`, `verified`, `denied`, `unknown` + stable reason codes.
- Bind adapter output to existing policy-event mapping and guard expectations.

### Track B: Provider translators (OpenAI + Claude)

- Implement provider-specific input/output translators into canonical contract.
- Keep provider schema drift isolated in translator modules.
- Add shared conformance fixture corpus where the same user intent yields the same canonical policy event and outcome.

### Track C: OpenClaw plugin parity

- Upgrade tool preflight/postflight mapping in `@clawdstrike/openclaw` to emit canonical CUA events where available.
- Ensure guard decisions and audit metadata align with core adapter behavior.
- Add plugin-level regression tests for parity and fail-closed handling.

### Track D: `trycua/cua` connector evaluation

- Treat `trycua/cua` as execution backend candidate.
- Validate normalization/evidence handoff against canonical contract.
- Record incompatibilities and define explicit fail-closed boundaries for unsupported fields or flows.

## Suggested experiments

- Cross-provider parity fixtures:
  - same CUA intent through OpenAI and Claude translators -> identical canonical event/outcome fields.
- Drift tests:
  - unknown provider action variants must fail closed with stable adapter error codes.
- OpenClaw parity tests:
  - same action intent through OpenClaw hook path and adapter-core path -> same decision class and reason code family.
- Connector prototype:
  - feed `trycua/cua` action stream through canonical translation and validate policy + audit outputs.

## Implementation TODO block

- [x] Add canonical CUA contract and normalization layer in adapter-core. *(Pass #13 — E1)*
- [x] Add OpenAI computer-use translator with conformance fixtures. *(Pass #15 — runtime translator path; Pass #17 — full-flow conformance fixtures)*
- [x] Add Claude computer-use translator with conformance fixtures. *(Pass #15 — runtime translator path; Pass #17 — full-flow conformance fixtures)*
- [x] Align OpenClaw hooks to canonical CUA event/outcome mapping. *(Pass #14 — E3)*
- [x] Produce `trycua/cua` connector prototype report + compatibility matrix. *(Pass #14 — E4)*

## Repo anchors

- `packages/adapters/clawdstrike-adapter-core/src/types.ts`
- `packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.ts`
- `packages/adapters/clawdstrike-openai/src/`
- `packages/adapters/clawdstrike-claude/src/`
- `packages/adapters/clawdstrike-openclaw/src/`
- `docs/roadmaps/cua/research/policy_event_mapping.yaml`
- `docs/roadmaps/cua/research/injection_outcome_schema.json`

## External references

- https://platform.openai.com/docs/guides/tools-computer-use
- https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/computer-use-tool
- https://github.com/trycua/cua
