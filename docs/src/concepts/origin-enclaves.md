# Origin Enclaves

Origin Enclaves provide origin-aware policy enforcement for AI agent workflows. When an agent receives messages from different sources — a Slack channel, a GitHub issue, a Teams DM — each origin can map to a distinct security profile that controls which tools the agent may use, what data it can access, and how cross-origin transitions are handled.

## Problem

Without origin awareness, a single policy applies uniformly regardless of where a message came from. An agent serving both a public Slack channel and a private internal channel uses the same tool surface and egress rules for both. This makes it impossible to enforce least-privilege by context.

## Core Concepts

### Origin Context

An `OriginContext` describes where a message came from:

| Field | Example | Purpose |
|-------|---------|---------|
| `provider` | `slack`, `github`, `teams` | Platform identity |
| `space_id` | `C0123ABC` | Specific channel/repo/space |
| `space_type` | `channel`, `dm`, `issue` | Kind of space |
| `visibility` | `private`, `public`, `external_shared` | Access scope |
| `tenant_id` | `T0123` | Org/workspace identifier |
| `thread_id` | `1234567890.123456` | Conversation thread |
| `external_participants` | `true` / `false` | Whether outsiders are present |
| `tags` | `["pii", "production"]` | Custom labels |
| `sensitivity` | `high` | Data sensitivity level |

### Enclave Profiles

An enclave profile defines the security posture for a matched origin. Profiles are declared in the policy YAML under `origins.profiles` and matched against the incoming origin context using `match_rules`.

Each profile can control:

- **MCP tool surface** — which tools are allowed, blocked, or require confirmation
- **Posture** — initial posture state (e.g., `observe`, `elevated`)
- **Egress** — network egress restrictions
- **Data policy** — external sharing, redaction, sensitive output blocking
- **Budgets** — usage limits on tool calls, egress, shell commands
- **Bridge policy** — cross-origin transition rules

### Enclave Resolution

When an origin context arrives, the engine resolves it against configured profiles using a deterministic priority scheme:

1. Exact `space_id` match (highest priority)
2. Most specific field match (more matching fields wins)
3. Provider-only match
4. Default profile (profile with empty match rules)
5. `default_behavior` fallback (`deny` or `minimal_profile`)

### Default Behavior

When no profile matches an origin, `default_behavior` controls what happens:

- **`deny`** (default) — fail-closed; the action is rejected with an `origin_required` violation.
- **`minimal_profile`** — a restrictive fallback enclave is materialized with MCP tools blocked by default. Base policy guards still run.

## Policy Configuration

### Schema Version

Origin Enclaves require policy schema version `1.4.0` or later.

### Example Policy

```yaml
version: "1.4.0"
name: Origin-Aware Policy
extends: clawdstrike:ai-agent

origins:
  default_behavior: deny

  profiles:
    - id: internal-slack
      match_rules:
        provider: slack
        visibility: private
      mcp:
        enabled: true
        allow: ["read_file", "search", "git_*"]
        block: ["shell_exec", "raw_file_delete"]
        require_confirmation: ["git_push", "file_write"]
        default_action: block
      posture: work
      explanation: "Internal Slack channels — standard tool access"

    - id: public-slack
      match_rules:
        provider: slack
        visibility: public
        external_participants: true
      mcp:
        enabled: true
        allow: ["read_file", "search"]
        default_action: block
      posture: observe
      explanation: "Public channels with external guests — read-only"

    - id: github-prs
      match_rules:
        provider: github
        space_type: pull_request
      mcp:
        enabled: true
        allow: ["read_file", "search", "git_diff", "git_log"]
        block: ["shell_exec"]
        default_action: block
      posture: work
      explanation: "GitHub PR reviews — code read + git tools"
```

### Match Rules

All specified fields in `match_rules` must match for a profile to be selected (logical AND). Unspecified fields are ignored (wildcard). Tags use set containment — all specified tags must be present in the origin.

Provider and space type comparisons use string normalization, so `Custom("slack")` matches `Slack`.

## Cross-Origin Isolation

Once a session establishes an origin (first action with origin context), subsequent actions are tracked:

- **Same origin** — proceeds normally.
- **Missing origin** — denied (fail-closed). An attacker cannot drop origin context to bypass restrictions.
- **Different origin** — cross-origin transition detected. The session enclave's `bridge_policy` determines the outcome:
  - `allow` — transition permitted for listed target providers
  - `require_approval` — blocked with Warning severity pending human approval
  - `deny` — hard block (default when no bridge policy exists)

## Enclave MCP Pre-Check

When an enclave has MCP configuration, a fast pre-check runs before the full guard pipeline:

1. **Block list** — tools matching `block` patterns are denied (supports trailing `*` wildcards)
2. **Allow list** — if non-empty, tools not matching any `allow` pattern are denied
3. **Require confirmation** — matching tools are denied with Warning severity (approval needed)
4. **Default action** — when the allow list is empty, `default_action: block` denies all remaining tools

This pre-check is separate from and runs before `McpToolGuard` in the guard pipeline. Both layers must pass for a tool to be allowed.

## Interaction with Postures

Enclave profiles can set an initial posture state via the `posture` field. When the enclave resolution produces a posture, the engine applies it as the starting state for the session. Posture transitions (escalation, de-escalation) still follow the posture model's transition rules.

## Fail-Closed Guarantees

Origin Enclaves follow Clawdstrike's fail-closed design:

- If enclave resolution fails, the action is denied.
- If an origins block exists but no origin context is provided, the action is denied (unless `minimal_profile` fallback is configured).
- If a session has an established origin and a subsequent action omits it, the action is denied.
- All deny paths record `ViolationRef` entries for complete audit provenance in receipts.
