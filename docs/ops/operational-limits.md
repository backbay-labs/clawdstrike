# Operational Limits

This document describes runtime safety limits, saturation behavior, and tuning guidance.

## Queue/Inflight/Timeout Controls

Current defaults (from `crates/services/hush-cli/src/hush_run.rs`):

- Event queue capacity: `1024` events
- Proxy max in-flight connections: `256`
- Proxy header read timeout: `5s`
- Proxy TLS/SNI peek timeout: `3s`
- Proxy DNS resolve timeout: `2s`
- Forward-to-hushd HTTP timeout: `3s`

## Saturation Semantics

### Event queue

- Queue is bounded.
- On saturation, new events are dropped (non-blocking emitter path).
- Drop count is tracked and reported at run end.

### Proxy in-flight cap

- New connections beyond cap are rejected.
- Rejected clients receive `503 Service Unavailable`.
- Rejection count is tracked and reported at run end.

### Slow headers (slowloris)

- Incomplete headers past timeout receive `408 Request Timeout` and are closed.
- Slot is released for new connections after timeout.

### Forwarding stalls

- Forwarding to hushd is best-effort and timeout-bounded.
- Stalled forward targets cannot grow queue unboundedly due bounded channel + drops.

## Behavior Under Load

Expected responses:

- `503` when proxy saturation is reached.
- `408` for header timeout.
- `403` for policy-denied network actions.

Expected observability signals:

- `droppedEventCount`
- `proxyRejectedConnections`
- warning logs on dropped events and rejected proxy connections

## Tuning Guidance

### Production

- Keep bounded queue semantics enabled.
- Keep slow-header timeout enabled and strict.
- Keep `allow_private_ips` disabled unless required.
- Alert on non-zero dropped event and rejected connection counters.

### Development

- You may reduce caps/timeouts for deterministic local stress tests.
- Keep test-only overrides scoped to dedicated test runs.

## Observability Locations

- Run-end stderr warnings from `hush run`.
- JSONL policy events output (`--events-out`).
- Receipt metadata (`droppedEventCount`, `proxyRejectedConnections`).

## Related

- `docs/ops/safe-defaults.md`
- `docs/audits/2026-02-10-wave2-remediation.md`
- `docs/audits/2026-02-10-wave3-remediation.md`
