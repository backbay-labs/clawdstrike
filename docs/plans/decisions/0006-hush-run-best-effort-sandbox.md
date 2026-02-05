# 0006 — `clawdstrike run`: best-effort process wrapper

## Status
Accepted

## Context
Users want a “single command” hardening story. Clawdstrike is not an OS sandbox, so this must be
best-effort and explicit about which enforcement layers are active.

## Decision
`clawdstrike run --policy <ref|file> -- <cmd> <args…>`:

- Generates a `sessionId`
- Writes a PolicyEvent JSONL log (`hush.events.jsonl` by default)
- Optionally uses OS tools when present (e.g., bwrap/sandbox-exec)
- Optionally uses an egress proxy to enforce `egress_allowlist`
- Produces a signed receipt over the run artifacts

Fail-closed default:
- Policy violations cause non-zero exit unless explicitly configured otherwise.

