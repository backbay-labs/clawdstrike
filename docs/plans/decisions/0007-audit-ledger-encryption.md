# 0007 — Audit ledger encryption (hushd)

## Status
Accepted

## Context
`hushd` stores audit events in SQLite. Some fields may contain sensitive data (details/metadata).
SECURITY.md calls out “audit log encryption” as planned work.

## Decision
- Keep searchable metadata plaintext (timestamp, event_type, decision, guard, severity, session_id).
- Encrypt the JSON metadata/details blob at rest when enabled by config.

Key sourcing is configurable:
- file
- env
- TPM-sealed blob (planned)

