# 0004 — Remote `extends`: integrity pinning + host allowlist

## Status
Accepted

## Context
Policies support `extends` for reuse. Local file paths and built-in rulesets are supported today.
To support distribution, we want remote `extends` while preserving fail-closed semantics.

## Decision
Remote `extends` is supported only when:

1. The reference includes an integrity pin: `#sha256=<HEX>`
2. The remote host is allowlisted (CLI flags or hushd config)

### Supported formats
- `https://…/policy.yaml#sha256=<HEX>`
- `git+https://…repo.git@<COMMIT>:<path>#sha256=<HEX>` (planned; requires `git` client)

### Caching
Remote fetches are cached by `(uri, sha256)` with size limits and max fetch bytes.

### Fail-closed rules
- Missing or mismatched `sha256` => reject
- Host not allowlisted => reject
- Fetch error => reject
- Circular dependency => reject

## Consequences
Remote resolution is implemented in `hush` / `hushd`, not inside the core policy parser, to keep
network I/O out of `clawdstrike::Policy::from_yaml_with_extends`.

