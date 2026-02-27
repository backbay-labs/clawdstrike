# Remote Desktop Permissive

**Ruleset ID:** `remote-desktop-permissive` (also accepted as `clawdstrike:remote-desktop-permissive`)

**Source:** `rulesets/remote-desktop-permissive.yaml`

Development-friendly CUA policy that opens all remote desktop side channels and sets enforcement to observe-only. Extends the `remote-desktop` ruleset.

## What it does (high level)

- Inherits from the `remote-desktop` ruleset (`extends: remote-desktop`)
- Sets the **ComputerUse** guard to `observe` mode (logs but does not block)
- Enables all **RemoteDesktopSideChannel** capabilities: clipboard, file transfer, audio, drive mapping, printing, and session sharing
- Adds `touch` to the **InputInjectionCapability** allowed input types (keyboard, mouse, touch)
- Enables verbose logging

## When to use

Use this ruleset during development and testing of remote desktop AI agents. It allows all side channels so you can iterate without security enforcement blocking your workflow. Do not use in production.

## Key configuration

| Setting | Value |
|---------|-------|
| `guards.computer_use.mode` | `observe` |
| `guards.remote_desktop_side_channel.clipboard_enabled` | `true` |
| `guards.remote_desktop_side_channel.file_transfer_enabled` | `true` |
| `guards.input_injection_capability.allowed_input_types` | `keyboard`, `mouse`, `touch` |
| `settings.verbose_logging` | `true` |
| `settings.session_timeout_secs` | `7200` (2 hours) |

## View the exact policy

```bash
clawdstrike policy show remote-desktop-permissive
```
