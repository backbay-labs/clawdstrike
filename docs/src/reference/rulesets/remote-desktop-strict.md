# Remote Desktop Strict

**Ruleset ID:** `remote-desktop-strict` (also accepted as `clawdstrike:remote-desktop-strict`)

**Source:** `rulesets/remote-desktop-strict.yaml`

Maximum security CUA policy for high-security remote desktop environments. Extends the `remote-desktop` ruleset with the most restrictive settings.

## What it does (high level)

- Inherits from the `remote-desktop` ruleset (`extends: remote-desktop`)
- Sets the **ComputerUse** guard to `fail_closed` mode with a minimal set of allowed actions (session connect, disconnect, and input injection only -- no reconnect, clipboard, file transfer, audio, drive mapping, printing, or session sharing)
- Disables all **RemoteDesktopSideChannel** capabilities (clipboard, file transfer, audio, drive mapping, printing, session sharing)
- Restricts **InputInjectionCapability** to keyboard only and requires postcondition probes
- Enables `fail_fast` (stop evaluating after first block)
- Sets a 30-minute session timeout

## When to use

Use this ruleset in high-security production environments where remote desktop AI agents must operate under strict constraints. All side channels are disabled and only the minimum required actions are permitted.

## Key configuration

| Setting | Value |
|---------|-------|
| `guards.computer_use.mode` | `fail_closed` |
| `guards.remote_desktop_side_channel.*` | all `false` |
| `guards.input_injection_capability.allowed_input_types` | `keyboard` only |
| `guards.input_injection_capability.require_postcondition_probe` | `true` |
| `settings.fail_fast` | `true` |
| `settings.session_timeout_secs` | `1800` (30 minutes) |

## View the exact policy

```bash
clawdstrike policy show remote-desktop-strict
```
