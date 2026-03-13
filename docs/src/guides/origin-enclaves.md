# Origin Enclaves Guide

This guide walks through configuring and operating origin-aware policy enforcement.

## Prerequisites

- Clawdstrike CLI installed (`cargo install --path crates/services/hush-cli`)
- A policy file with schema version `1.4.0` or later
- Familiarity with [policies](../concepts/policies.md) and [postures](../concepts/postures.md)

## SDK support

Origin-aware enforcement support depends on which SDK backend is actually evaluating the policy:

| Surface | Origin-aware status |
|--------|----------------------|
| Rust engine / `hushd` | Full support |
| TypeScript | Use Rust bridges or `hushd` |
| Python native backend | Full support |
| Python daemon backend | Full support |
| Python pure-Python backend | Fails closed for `policy.origins`, `origin`, and `origin.output_send` |
| Go daemon backend | Full support |
| Go local engine | Fails closed for `origin` and `origin.output_send` |

## Writing an Origins Policy

Add an `origins` block to your policy YAML:

```yaml
version: "1.4.0"
name: My Origin Policy
extends: clawdstrike:ai-agent

origins:
  default_behavior: deny
  profiles:
    - id: slack-internal
      match_rules:
        provider: slack
        visibility: private
      mcp:
        enabled: true
        allow: ["read_file", "search", "git_*"]
        block: ["shell_exec"]
        require_confirmation: ["file_write", "git_push"]
        default_action: block
      posture: work
      explanation: "Internal Slack — standard dev tools"

    - id: slack-public
      match_rules:
        provider: slack
        visibility: public
      mcp:
        enabled: true
        allow: ["read_file", "search"]
        default_action: block
      posture: observe
      explanation: "Public Slack — read-only"

    - id: github-issues
      match_rules:
        provider: github
        space_type: issue
      mcp:
        enabled: true
        allow: ["read_file", "search", "git_log"]
        default_action: block
      explanation: "GitHub issues — read + search"
```

### Choosing `default_behavior`

| Value | Effect | Use when |
|-------|--------|----------|
| `deny` | Reject actions with no matching profile | You want strict origin gating |
| `minimal_profile` | Apply a restrictive fallback (MCP blocked by default) | You want base guards to still run for unrecognized origins |

## CLI Commands

### Resolve an Origin

Test which profile matches a given origin:

```bash
clawdstrike origin resolve my-policy.yaml \
  --provider slack \
  --space-id C0123ABC \
  --visibility private
```

Output shows the matched profile ID, resolution path, and effective MCP config.

Add `--json` for machine-readable output:

```bash
clawdstrike origin resolve my-policy.yaml \
  --provider slack \
  --visibility public \
  --external-participants \
  --json | jq .
```

### Explain Resolution

See why a specific profile was or wasn't matched:

```bash
clawdstrike origin explain my-policy.yaml \
  --provider github \
  --space-type pull_request
```

This shows each profile's match rules alongside the origin context, highlighting which fields matched and which caused rejection.

### List Profiles

View all profiles in a policy:

```bash
clawdstrike origin list-profiles my-policy.yaml
```

## Match Rules Reference

Match rules use logical AND — all specified fields must match. Unspecified fields act as wildcards.

| Field | Type | Notes |
|-------|------|-------|
| `provider` | string | `slack`, `github`, `teams`, `jira`, `email`, `discord`, `webhook`, or custom |
| `tenant_id` | string | Org/workspace ID |
| `space_id` | string | Channel/repo/space ID — highest priority match |
| `space_type` | string | `channel`, `dm`, `thread`, `issue`, `pull_request`, etc. |
| `visibility` | string | `private`, `internal`, `public`, `external_shared` |
| `thread_id` | string | Specific conversation thread |
| `external_participants` | bool | Whether external guests are present |
| `tags` | list | All listed tags must be present in origin |
| `sensitivity` | string | Data sensitivity level |

### Resolution Priority

When multiple profiles match, the most specific wins:

1. Exact `space_id` match (always wins)
2. Highest field count among matching profiles
3. First in list order (stable tiebreaker)

## MCP Tool Surface Configuration

Each enclave profile's `mcp` block controls the tool surface:

```yaml
mcp:
  enabled: true
  allow: ["read_file", "search", "deploy_*"]  # trailing * wildcards supported
  block: ["shell_exec", "raw_file_delete"]
  require_confirmation: ["git_push"]
  default_action: block  # block | allow
```

Evaluation order:

1. `block` — blocked tools are always denied
2. `allow` — if non-empty, tools not in the list are denied
3. `require_confirmation` — matching tools return Warning (needs approval)
4. `default_action` — applies when allow list is empty

The `block` list always wins. Wildcards use trailing `*` (e.g., `deploy_*` matches `deploy_prod`).

## Cross-Origin Bridge Policies

Control what happens when an agent switches between origins mid-session:

```yaml
profiles:
  - id: slack-internal
    match_rules:
      provider: slack
      visibility: private
    bridge_policy:
      default_action: deny
      allowed_targets:
        - provider: github
        - provider: slack
          visibility: private
      require_approval_targets:
        - provider: slack
          visibility: public
```

Without a bridge policy, cross-origin transitions are denied by default.

## Integrating with Adapters

Framework adapters (OpenClaw, Vercel AI, LangChain, etc.) can pass origin context through `GuardContext`:

```rust,ignore
use clawdstrike::{GuardContext, OriginContext, OriginProvider, Visibility};

let origin = OriginContext {
    provider: OriginProvider::Slack,
    space_id: Some("C0123ABC".into()),
    visibility: Some(Visibility::Private),
    ..Default::default()
};

let context = GuardContext::new().with_origin(origin);
assert!(context.origin.is_some());
```

Pass that `context` into `engine.check_action(...)` or `engine.check_action_report(...)`
inside the adapter boundary that is already holding the action and engine instance.

In TypeScript adapters, origin data flows from the inbound message hook through the `SecurityContext`.

Python can pass either an `OriginContext` object or a mapping with canonical snake_case keys:

```python
from clawdstrike import Clawdstrike

cs = Clawdstrike.from_daemon("https://hushd.example.com", api_key="dev-token")

decision = cs.check_mcp_tool(
    "read_file",
    {"path": "/srv/runbook.md"},
    origin={
        "provider": "slack",
        "tenant_id": "T123",
        "space_id": "C456",
        "actor_role": "incident_commander",
    },
)
```

Go origin-aware requests currently go through the daemon-backed SDK:

```go
origin := guards.NewOriginContext(guards.OriginProviderSlack).
	WithTenantID("T123").
	WithSpaceID("C456")

decision := cs.CheckWithContext(
	guards.McpTool("read_file", map[string]interface{}{"path": "/srv/runbook.md"}),
	guards.NewContext().WithOrigin(origin),
)
```

## Operational Notes

### Receipt Metadata

Enclave resolution results are recorded in receipt metadata:

- `origin_provider`, `origin_space_id` — which origin was active
- `enclave_profile_id` — which profile matched
- `enclave_resolution_path` — why that profile was selected

### Session Tracking

The engine tracks origin per session. The first action with origin context establishes the session origin. Subsequent actions:

- Same origin — normal evaluation
- No origin — denied (cannot drop origin to bypass restrictions)
- Different origin — bridge policy evaluated

### Debugging

Use `RUST_LOG=clawdstrike=debug` to see enclave resolution, cross-origin checks, and MCP pre-check decisions in logs.

```bash
RUST_LOG=clawdstrike=debug clawdstrike origin resolve my-policy.yaml \
  --provider slack --visibility private
```
