# Computer Use (CUA) Gateway

This guide explains how to set up Clawdstrike's Computer Use Agent gateway for securing AI agents that interact with remote desktops.

## Overview

The CUA Gateway is a set of three guards that work together to enforce security policies on computer use actions:

| Guard | Responsibility |
|-------|---------------|
| [ComputerUseGuard](../reference/guards/computer-use.md) | Top-level gateway: enforcement mode (observe/guardrail/fail_closed) and action allowlist |
| [RemoteDesktopSideChannelGuard](../reference/guards/remote-desktop-side-channel.md) | Fine-grained control over individual channels (clipboard, file transfer, audio, etc.) |
| [InputInjectionCapabilityGuard](../reference/guards/input-injection-capability.md) | Input type validation and optional postcondition probe requirements |

## Quick start

The easiest way to enable CUA security is to extend one of the built-in remote desktop rulesets:

```yaml
version: "1.2.0"
name: My CUA Policy
extends: clawdstrike:remote-desktop
```

## Built-in rulesets

| Ruleset | Mode | Side channels | Postcondition probe |
|---------|------|---------------|---------------------|
| `remote-desktop` | guardrail | Restricted (clipboard/file-transfer/drive-mapping/printing/session-share off) | Not required |
| `remote-desktop-permissive` | observe | All enabled | Not required |
| `remote-desktop-strict` | fail_closed | All disabled | Required |

### remote-desktop (moderate)

Extends `ai-agent`. Guardrail mode allows unknown CUA actions with a warning. Side channels are selectively disabled for a development/staging environment:

```yaml
extends: clawdstrike:remote-desktop

guards:
  computer_use:
    mode: guardrail
  remote_desktop_side_channel:
    clipboard_enabled: false
    file_transfer_enabled: false
    session_share_enabled: false
  input_injection_capability:
    allowed_input_types: ["keyboard", "mouse"]
```

### remote-desktop-permissive (development)

Extends `remote-desktop`. Observe mode logs all actions without blocking. All side channels are enabled for development and testing:

```yaml
extends: clawdstrike:remote-desktop-permissive
```

### remote-desktop-strict (production)

Extends `remote-desktop`. Fail-closed mode blocks any action not explicitly allowlisted. All side channels are disabled. Only keyboard input is allowed and postcondition probes are required:

```yaml
extends: clawdstrike:remote-desktop-strict
```

## Custom CUA policy

Override individual guard settings while inheriting defaults:

```yaml
version: "1.2.0"
name: Custom CUA Policy
extends: clawdstrike:remote-desktop

guards:
  computer_use:
    mode: fail_closed
    allowed_actions:
      - "remote.session.connect"
      - "remote.session.disconnect"
      - "input.inject"

  remote_desktop_side_channel:
    clipboard_enabled: true           # allow clipboard for this workflow
    file_transfer_enabled: false
    audio_enabled: false
    drive_mapping_enabled: false
    printing_enabled: false
    session_share_enabled: false
    max_transfer_size_bytes: 10485760  # 10MB limit if re-enabled

  input_injection_capability:
    allowed_input_types: ["keyboard"]
    require_postcondition_probe: true

settings:
  fail_fast: true
  session_timeout_secs: 1800
```

## Action flow

```text
Agent wants to inject keyboard input
  -> GuardAction::Custom("input.inject", {"input_type": "keyboard", ...})
  -> ComputerUseGuard: "input.inject" in allowlist? -> mode-dependent decision
  -> InputInjectionCapabilityGuard: "keyboard" in allowed_input_types? -> allow/block
  -> postcondition probe required? -> check for hash in data

Agent wants to copy to clipboard
  -> GuardAction::Custom("remote.clipboard", {...})
  -> ComputerUseGuard: "remote.clipboard" in allowlist? -> mode-dependent decision
  -> RemoteDesktopSideChannelGuard: clipboard_enabled? -> allow/block
```

## Recommended rollout

1. Start with `remote-desktop-permissive` to observe agent behavior in development.
2. Review audit logs to understand which actions and channels the agent uses.
3. Move to `remote-desktop` for staging with selective channel restrictions.
4. Move to `remote-desktop-strict` (or a custom fail-closed policy) for production.
