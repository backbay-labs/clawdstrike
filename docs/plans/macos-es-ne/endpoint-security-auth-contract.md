# EndpointSecurity AUTH Contract

## Objective

Define the macOS enforcement contract that replaces the current Linux-only supervised-exec model.

## Why This Exists

Today, `crates/services/hush-cli/src/supervised_exec.rs` implements a Linux seccomp-notify loop that:

- intercepts `openat` and `openat2`
- evaluates the request in userspace
- injects a granted file descriptor back into the child

That is not the macOS model.

EndpointSecurity `AUTH_*` events are deadline-bound authorization requests on a kernel snapshot. They do not give ClawdStrike an equivalent "evaluate then inject fd" control surface. They can also fail open when the client misses deadlines or loses health.

The first macOS wave needs an explicit contract here so workers do not translate Linux semantics directly into an ES implementation.

## Frozen Invariants

- macOS must not claim Linux-style fd-injection semantics
- macOS supervised enforcement remains unavailable until the ES provider and attestation surfaces can prove the invariants below
- an ES authorization result is evidence about a point-in-time decision, not proof of post-open immutability
- any deadline miss, dropped-event condition, inactive provider state, missing approval, or missing Full Disk Access must degrade attestation and host health instead of being silently reported as enforced success

## Minimum Event Contract

`POLAT` freezes the contract that `ESINT` implements. The minimum acceptable file/process contract for the first wave is:

- file access authorization starts from `AUTH_OPEN`
- execution-sensitive policy must explicitly map the required exec/process events instead of assuming `AUTH_OPEN` is enough
- evidence for allowed operations must include corresponding notify-side counters or audit output where the platform model requires it
- any additional AUTH event added for create, rename, link, unlink, or process launch must be listed in the reviewed handoff, not implied

## Timeout And Fail-Open Contract

`ESINT` and `POLAT` must treat deadline handling as first-order enforcement behavior:

- every AUTH decision path records decision latency against the message deadline
- deadline misses increment explicit counters exposed to the host and receipt attestation
- any deadline miss or dropped-event condition marks the ES provider degraded
- degraded ES state prevents ClawdStrike from claiming fully enforced macOS supervised mode
- review must reject implementations that collapse "ClawdStrike asked to deny" into "the kernel definitely denied" when the observed platform outcome may have failed open

## Cache And Muting Contract

EndpointSecurity cache and muting are allowed only when the implementation can prove:

- the muted or cached scope is deterministic
- the scope is keyed to a policy/configuration identity
- policy reload or ruleset change invalidates the relevant cache or mute state
- audit output still records the effective decision model used for the run

If those conditions are not met, the first wave does not use that cache or muting path.

## TOCTOU Contract

The ES implementation must document and expose the authorization snapshot boundary:

- `AUTH_*` authorizes a request on the observed snapshot
- later file-content or file-identity drift is a separate risk
- receipts must never imply that an allow decision made the target immutable
- higher-risk flows should correlate AUTH and NOTIFY evidence rather than overstating continuous protection

## Host And Attestation Requirements

The host and receipt surface must expose at least:

- provider installed state
- provider active state
- provider healthy state
- provider degraded reasons
- deadline-miss counter
- dropped-event counter
- last-healthy timestamp
- whether enforcement was unavailable, degraded, or active during the run

## Required Verification Evidence

Before `RESINT` can clear `ESINT`, the lane must show:

- allow and deny fixtures for the frozen AUTH contract
- a synthetic deadline-miss or over-deadline path that degrades health and attestation
- a dropped-event or inactive-provider path that prevents false "enforced" claims
- a missing Full Disk Access path that surfaces degraded provider health

## Apple Sources

- Build an Endpoint Security app (WWDC20)
  https://developer.apple.com/videos/play/wwdc2020/10159/
- Monitoring system events with Endpoint Security
  https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security
- System Extensions
  https://developer.apple.com/system-extensions/
