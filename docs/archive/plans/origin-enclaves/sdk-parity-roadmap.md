# Origin Enclaves SDK Parity Roadmap

> Status: Draft
> Follow-up to: PR 177 merged at `5837f4fc4`
> Scope owner: SDK parity, not core engine changes

## Goal

Bring Python and Go up to the same practical origin-enclave contract already available through Rust + hushd + TypeScript, without pretending that unsupported local backends can enforce origin policies.

## Recommended Scope Split

### Phase 1: Shared contract and fixtures

- Land the cross-SDK `OriginContext` and `origin.output_send` contract in docs and fixtures first.
- Decide canonical snake_case output and camelCase input compatibility rules once, then reuse them in Python and Go.
- Add shared fixture material under `fixtures/` only if both SDKs consume the same vectors in the same PR; otherwise keep fixtures orchestrator-owned.

### Phase 2: Python transport parity

- Add `OriginContext` public types and public helper APIs in `packages/sdk/hush-py/src/clawdstrike/`.
- Thread `origin` through `GuardContext`, `Clawdstrike.check(...)`, and `ClawdstrikeSession.check(...)`.
- Extend the native Rust binding in `packages/sdk/hush-py/hush-native/src/lib.rs` so Python native users get full engine parity with the Rust core.
- Ensure daemon-backed Python flows serialize `origin` to hushd.
- Add explicit unsupported-origin errors for the pure-Python backend when `origins` or `origin` are used.

### Phase 3: Go daemon parity

- Add public Go origin types and `GuardContext.WithOrigin(...)`.
- Extend `packages/sdk/hush-go/daemon_checker.go` so hushd requests carry `origin`.
- Add `Session.CheckWithContext(...)` so origin can change across actions within one session.
- Add explicit unsupported-origin errors for the Go local engine and v1.3-only policy loader when origin-aware features are requested.

### Phase 4: Docs and examples

- Update Python and Go READMEs with one daemon-backed origin example each.
- Add a short compatibility matrix that states:
  - Python native: supported
  - Python daemon: supported
  - Python pure backend: not yet supported
  - Go daemon: supported
  - Go local engine: not yet supported

### Phase 5: Optional local-engine parity

- Python pure-policy and Go local engine support for `version: "1.4.0"` origin policies is a separate expansion.
- Do not scope-creep this into the transport-parity PR unless the branch explicitly takes on policy parser, resolver, budget, bridge, and egress composition work in both languages.

## Merge Order

1. Shared contract docs and compatibility rules
2. Python SDK changes
3. Go SDK changes
4. Shared docs/examples cleanup

Rationale:

- The contract has to settle before either SDK encodes aliases or helper names.
- Python can reach full parity sooner because the native Rust backend already exists.
- Go has the extra session API surface and unsupported-backend guardrail work.

## Verification Matrix

Shared:

- `cargo test -p hushd --lib`
- `cargo test -p clawdstrike --lib`

Python:

- `uv run --project packages/sdk/hush-py pytest packages/sdk/hush-py/tests/test_native_engine.py`
- `uv run --project packages/sdk/hush-py pytest packages/sdk/hush-py/tests/test_session.py`
- `uv run --project packages/sdk/hush-py pytest packages/sdk/hush-py/tests/test_core.py`
- `ruff check packages/sdk/hush-py`
- `mypy --strict packages/sdk/hush-py/src`

Go:

- `cd packages/sdk/hush-go && go test ./...`

## Exit Criteria

- Python and Go can both express origin-aware requests against hushd using the same field names and action contracts as Rust/TypeScript.
- Python native-backed flows can enforce origin-aware policies through the Rust engine.
- Unsupported local backends fail loudly instead of silently ignoring origin context.
- README examples in both SDKs state which backends actually support origin enforcement.

## Risks To Keep Explicit

- Go local engine parity is materially larger than transport parity because `packages/sdk/hush-go/policy/policy.go` only understands v1.3 and the engine has no origin-enclave implementation.
- Python pure-Python backend parity is also larger than the transport work because `packages/sdk/hush-py/src/clawdstrike/policy.py` and the pure guard engine do not implement origins today.
- If the follow-up PR tries to solve transport parity and full local-engine parity together, the review and regression surface will grow sharply.
- The global `.codex/swarm/lanes.tsv` and `.codex/swarm/waves.tsv` files are currently seeded for the Huntronomer workspace-shell initiative, so this follow-up should keep its execution topology in a local plan doc unless and until execution actually moves into swarm mode.
