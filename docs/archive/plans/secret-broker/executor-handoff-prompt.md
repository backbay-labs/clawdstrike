# Executor Handoff Prompt: Build Secret-Broker E2E

You are the implementation agent for the Clawdstrike secret-broker project.

Your job is to build the first end-to-end version of the brokered egress tier described in the
specs in this worktree. Do not treat this as a greenfield design exercise. The architecture,
constraints, and likely repo touchpoints are already documented. Use those docs as the source of
truth, then implement the smallest production-credible slice that proves the model end to end.

## Workspace

- Repo root: `/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/secret-broker-specs`
- Current branch: `feat/secret-broker-specs`

If you want to do the implementation on a separate branch, branch off this worktree state so the
spec docs stay available in your branch.

## Read First

1. [docs/specs/19-secret-broker-egress-tier.md](/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/secret-broker-specs/docs/specs/19-secret-broker-egress-tier.md)
2. [docs/plans/clawdstrike/secret-broker/target-architecture.md](/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/secret-broker-specs/docs/plans/clawdstrike/secret-broker/target-architecture.md)
3. [docs/plans/clawdstrike/secret-broker/roadmap.md](/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/secret-broker-specs/docs/plans/clawdstrike/secret-broker/roadmap.md)
4. [docs/plans/clawdstrike/secret-broker/current-state.md](/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/secret-broker-specs/docs/plans/clawdstrike/secret-broker/current-state.md)
5. [docs/src/concepts/enforcement-tiers.md](/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/secret-broker-specs/docs/src/concepts/enforcement-tiers.md)

## What To Build

Build v1 of the secret-broker system with these pieces working together:

1. `hushd` capability issuance API.
2. A new `clawdstrike-brokerd` service that validates a capability and executes a provider-scoped
   outbound request without exposing plaintext credentials to the caller.
3. A TypeScript broker client package for adapters.
4. Adapter-core integration that allows broker-backed execution without breaking current
   `PolicyEngineLike`.
5. A first framework/provider path through `packages/adapters/clawdstrike-openai/`.
6. Tests that prove the happy path and fail-closed behavior.

The target is not "complete platform." The target is one real end-to-end path:

- caller uses OpenAI adapter in broker mode
- adapter requests capability from `hushd`
- adapter invokes `brokerd`
- `brokerd` resolves a secret reference from a minimal local/dev backend
- `brokerd` calls the upstream provider
- evidence is sent back to `hushd`
- returned content still flows through existing output sanitization/interceptor paths

## Hard Constraints

Do not violate these:

1. Keep `hushd` as the policy authority.
2. Do not build transparent MITM proxying.
3. Do not redesign `PolicyEngineLike` unless you hit a real blocker.
4. Prefer the existing wrapper/interceptor execution model, especially `replacementResult`, for
   the first adapter path.
5. Broker-required actions must fail closed. Do not silently fall back to direct SDK execution.
6. If `brokerd` is remote, do not treat the capability as a plain bearer token. Use a
   sender-constrained approach or at minimum structure the code so sender binding is first-class.
7. Do not leak plaintext secrets via logs, error messages, traces, or client APIs.
8. For generic HTTPS work, if you touch it at all, keep redirects disabled and deny SSRF-prone
   destinations by default. But generic HTTPS is not the primary goal for this implementation.

## Likely Code Touchpoints

### Rust / policy / daemon

- `crates/services/hushd/src/api/mod.rs`
- `crates/services/hushd/src/api/check.rs`
- `crates/services/hushd/src/api/v1.rs`
- `crates/services/hushd/src/state.rs`
- `crates/services/hushd/src/config.rs`
- `crates/services/hushd/src/policy_event.rs`
- `crates/libs/clawdstrike/src/policy.rs`
- `crates/libs/clawdstrike/src/engine.rs`

### New Rust service

- `crates/services/clawdstrike-brokerd/`

### TypeScript adapters

- `packages/adapters/clawdstrike-broker-client/`
- `packages/adapters/clawdstrike-adapter-core/src/base-tool-interceptor.ts`
- `packages/adapters/clawdstrike-adapter-core/src/framework-tool-boundary.ts`
- `packages/adapters/clawdstrike-adapter-core/src/secure-tool-wrapper.ts`
- `packages/adapters/clawdstrike-adapter-core/src/adapter.ts`
- `packages/adapters/clawdstrike-adapter-core/src/interceptor.ts`
- `packages/adapters/clawdstrike-adapter-core/src/network-target.ts`
- `packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.ts`
- `packages/adapters/clawdstrike-openai/src/secure-tools.ts`
- `packages/adapters/clawdstrike-openai/src/tool-boundary.ts`

### Tests

- `packages/adapters/clawdstrike-adapter-core/tests/cross-adapter/**`
- `packages/adapters/clawdstrike-openai/src/provider-conformance-runtime.test.ts`

## Recommended Build Order

### Phase 1: Define minimal protocol and policy surface

Implement the smallest stable shapes for:

- `CredentialRef`
- `BrokerCapability`
- `BrokerExecuteRequest`
- `BrokerExecutionEvidence`
- policy schema additions for a top-level `broker:` block

Make the policy schema versioning honest. The repo currently supports policy schema versions
through `1.4.0`, so if you add `broker:`, introduce the next schema version rather than pretending
this belongs to an existing version.

### Phase 2: Add `hushd` broker API

Add capability issuance and evidence ingestion endpoints. Reuse the same identity/origin/session
context patterns as `check.rs`.

Minimum viable API surface:

- `POST /api/v1/broker/capabilities`
- `POST /api/v1/broker/evidence`

Capability requirements:

- short-lived
- destination-scoped
- exact-path-scoped for v1
- method-scoped
- secret-ref-scoped
- bound to policy hash and session identity

If you choose JWS/JWT for the envelope, pin accepted algorithms explicitly and avoid generic
library defaults.

### Phase 3: Build `clawdstrike-brokerd`

Create a new Rust service that:

- accepts one execute request
- validates capability expiry, signature, and scope
- resolves a secret from a local/dev backend
- injects auth only inside the broker
- executes the outbound request
- emits evidence back to `hushd`

Start with one typed OpenAI executor. Do not overgeneralize the provider abstraction before the
first path works.

For local/dev secret resolution, a simple in-memory or file-backed provider is fine as long as it
never returns plaintext credentials to the caller.

### Phase 4: Add TS broker client and adapter integration

Create `packages/adapters/clawdstrike-broker-client/`.

Then wire adapter-core in the least disruptive way:

- keep broker mode opt-in
- request capability from `hushd`
- invoke `brokerd`
- return broker results through the existing interceptor/wrapper path
- preserve output sanitization and existing post-execution processing

The preferred v1 move is to let the wrapper/interceptor own broker execution through
`replacementResult`. Only introduce a new explicit broker directive if that proves genuinely
necessary.

### Phase 5: OpenAI end-to-end path

Add a real broker-backed mode to:

- `packages/adapters/clawdstrike-openai/src/secure-tools.ts`
- `packages/adapters/clawdstrike-openai/src/tool-boundary.ts`

The end result should be that an OpenAI-mediated tool/provider path can be configured to run
through the broker instead of direct credential use.

## Security Requirements

These are not optional:

1. Broker-required actions deny on `hushd` failure.
2. Broker-required actions deny on `brokerd` failure.
3. No direct SDK fallback on any broker path error.
4. Remote broker calls must be sender-constrained or at least implemented behind an abstraction
   that clearly supports DPoP, mTLS, or workload-identity binding next.
5. Evidence persistence is part of the execution contract.
6. If streaming is supported in the first pass, design for explicit start/completion evidence and
   chunk ordering or event IDs to avoid reconnect ambiguity.
7. If any generic HTTPS utility code is introduced, disable redirects in v1 and deny
   private/link-local/loopback destinations unless explicitly allowed.

## Deliverables

When you are done, I expect:

1. Working Rust code for `hushd` broker endpoints.
2. A new `clawdstrike-brokerd` crate wired into the workspace.
3. A TS broker client package.
4. Adapter-core integration without unnecessary breaking changes.
5. A working OpenAI-backed broker flow.
6. Tests covering:
   - valid brokered request path
   - invalid/expired capability rejection
   - deny on missing broker authority
   - deny on broker execution failure
   - no direct-SDK fallback
   - evidence submission
7. Updated docs for any config/env vars or local dev startup needed to run the new path.

## Verification Expectations

Do not stop at code compilation. Prove the flow.

At minimum:

1. Run relevant Rust tests.
2. Run relevant TS/Vitest tests.
3. Add at least one integration-style or conformance-style test showing the full broker path.
4. Report exactly what was run and what remains untested.

## Implementation Style

- Be incremental, but carry the feature to a real e2e slice before stopping.
- Prefer existing repo patterns over inventing a parallel stack.
- Keep comments tight and only where they add real value.
- Do not revert unrelated user changes.
- If you hit an ambiguity, choose the narrower, fail-closed option and document it.

## Final Output Format

When you finish, provide:

1. A short summary of what now works end to end.
2. Key file references for the implementation.
3. Test commands run and outcomes.
4. Any remaining gaps or risks that still block production use.
