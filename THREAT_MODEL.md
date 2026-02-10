# Threat Model

## Scope

This threat model covers the pre-release Rust security/control plane in this repository:

- `crates/libs/clawdstrike`: guard engine, policy evaluation, async guard runtime, IRM monitors.
- `crates/services/hush-cli`: `hush run` execution wrapper, CONNECT proxy, remote policy extends.
- `crates/services/hushd`: daemon remote policy extends parity and control-plane enforcement.
- `crates/libs/hush-core`: receipt hashing/signing/verification primitives and canonicalization.
- Receipt and policy audit artifacts under `docs/audits/`.

Out of scope components are listed in `NON_GOALS.md`.

## Assets

Primary assets protected by these controls:

- Filesystem boundaries and sensitive file paths.
- Secrets in prompts, patches, and emitted data.
- Network egress boundaries (host/IP + scheme policy).
- Integrity of policy artifacts loaded via remote extends.
- Integrity and authenticity of receipts and signed attestations.

## Trust Boundaries

The primary enforcement boundary is the tool/runtime boundary.

- Policy guards evaluate tool actions and runtime events.
- `hush run` proxy and IRM checks enforce/deny at request execution boundaries.
- This is not a universal syscall mediation layer by itself.

Explicitly: tool boundary is the enforcement boundary.

## Assumptions

- Runtime has least-privilege OS permissions configured by the operator.
- DNS answers can change over time; code must pin/validate resolved endpoints where required.
- Local environment variables and CLI flags are trusted operator input.
- TLS hostname/SNI semantics follow standard client behavior.
- Private-network reachability is denied unless explicitly enabled.

## Threats Addressed

### Filesystem traversal and path escape

- Relative traversal (`..`) and mixed path forms are denied by IRM filesystem checks.
- Symlink escape behavior is covered by guard/path normalization and regression tests.

### Egress control invariants

- CONNECT policy decision is tied to the endpoint actually dialed.
- Hostname CONNECT targets are resolved once and pinned before dial.
- IP CONNECT + SNI checks enforce consistency constraints.

### Remote policy fetch constraints

- Host allowlisting is required for remote extends.
- HTTPS-only and private-IP rejection are default-safe.
- Git commit/ref tokens are validated to prevent option-like injection.

### Denial-of-service bounds

- Bounded event queue semantics with drop accounting.
- Proxy in-flight connection caps and slow-header timeouts.
- Async background guard execution bounded by in-flight caps.
- Policy extends depth limit prevents unbounded recursion.

### Receipt integrity

- Receipts/signatures rely on canonicalized content hashing and signature verification.
- Signed receipt contents are integrity artifacts; human-readable logs are not treated as signed proof.

## Mitigations Implemented

Mitigations and proofs are captured in:

- `docs/audits/2026-02-10-remediation.md`
- `docs/audits/2026-02-10-wave2-remediation.md`
- `docs/audits/2026-02-10-wave3-remediation.md`

## Residual Risk and Hardening Roadmap

Residual risks remain where controls depend on operator deployment posture:

- Misconfiguration of allowlists/safe defaults can weaken isolation.
- Dependency advisories accepted with temporary exceptions remain supply-chain risk.
- TOCTOU classes can still exist where runtime checks are separated from external state changes.

Planned hardening priorities:

- Expand parser and policy fuzz coverage.
- Continue reducing advisory exceptions and expired dependency risk.
- Increase scheduled sanitizer/Miri coverage over high-risk paths.
