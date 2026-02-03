# Policy Events Fixtures (v1)

This directory contains a small, representative corpus of **policy evaluation inputs** to support cross-SDK parity work (Rust + TypeScript).

## Files

- `events.jsonl`: newline-delimited JSON (`.jsonl`). Each line is one `PolicyEvent`.

## Canonical shape (M0 draft)

See `docs/plans/decisions/0003-policy-event-and-severity.md`.

Minimum required fields per event:

- `eventId` (string)
- `eventType` (string)
- `timestamp` (ISO 8601 / RFC 3339 string)
- `data` (object; must include a `type` discriminator)

Optional but recommended:

- `sessionId` (string)
- `metadata.source` (string)
- `metadata.agentId` (string)

## Validation

If present, run the lightweight validator script:

```sh
tools/scripts/validate-policy-events fixtures/policy-events/v1/events.jsonl
```

