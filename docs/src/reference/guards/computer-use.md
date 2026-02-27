# ComputerUseGuard

Controls CUA (Computer Use Agent) actions via an allowlist with configurable enforcement modes.

## Actions

- `GuardAction::Custom("remote.*", data)` -- remote session and side channel actions
- `GuardAction::Custom("input.*", data)` -- input injection actions

The guard handles any `Custom` action whose type starts with `"remote."` or `"input."`.

## Configuration

```yaml
guards:
  computer_use:
    enabled: true
    mode: guardrail       # observe | guardrail | fail_closed
    allowed_actions:
      - "remote.session.connect"
      - "remote.session.disconnect"
      - "remote.session.reconnect"
      - "input.inject"
      - "remote.clipboard"
      - "remote.file_transfer"
      - "remote.audio"
      - "remote.drive_mapping"
      - "remote.printing"
      - "remote.session_share"
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this guard. |
| `mode` | string | `guardrail` | Enforcement mode (see below). |
| `allowed_actions` | string[] | (all default CUA actions) | Action types permitted by the guard. |

### Enforcement modes

| Mode | In allowlist | Not in allowlist |
|------|-------------|------------------|
| `observe` | Allow (warn, logged) | Allow (warn, logged) |
| `guardrail` | Allow | Warn (allowed, but flagged) |
| `fail_closed` | Allow | Block (`Severity::Error`) |

## Behavior

- **observe**: Every action is allowed but emits a warning with details for audit logging. Useful during initial rollout.
- **guardrail** (default): Actions in the allowlist are silently allowed. Actions outside the allowlist are allowed with a warning.
- **fail_closed**: Actions in the allowlist are allowed. Actions outside the allowlist are blocked.

## Related

- [RemoteDesktopSideChannelGuard](./remote-desktop-side-channel.md) -- fine-grained control over individual remote desktop channels
- [InputInjectionCapabilityGuard](./input-injection-capability.md) -- input type validation and postcondition probes
- [Computer Use Gateway Guide](../../guides/computer-use-gateway.md) -- end-to-end CUA setup
