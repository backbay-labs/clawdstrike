# Remote Desktop

**Ruleset ID:** `remote-desktop` (also accepted as `clawdstrike:remote-desktop`)

**Source:** `rulesets/remote-desktop.yaml`

Base security policy for AI agents operating via remote desktop (Computer Use Agent / CUA). Extends the `ai-agent` ruleset with guards specific to remote desktop sessions.

## What it does (high level)

- Inherits all guards from the `ai-agent` ruleset (`extends: ai-agent`)
- Enables the **ComputerUse** guard in `guardrail` mode with a curated set of allowed actions (session connect/disconnect/reconnect, input injection, clipboard, file transfer, audio, drive mapping, printing, session sharing)
- Configures the **RemoteDesktopSideChannel** guard with conservative defaults: clipboard and file transfer disabled, audio allowed, drive mapping/printing/session sharing disabled, 100 MB max transfer size
- Enables the **InputInjectionCapability** guard allowing keyboard and mouse input without postcondition probes
- Sets a 2-hour session timeout

## When to use

Use this ruleset as the default starting point for remote desktop AI agent deployments. It provides a moderate security posture that blocks most side channels while allowing core remote desktop operations.

For development/testing, extend with `remote-desktop-permissive`. For high-security environments, extend with `remote-desktop-strict`.

## Key configuration

| Setting | Value |
|---------|-------|
| `guards.computer_use.mode` | `guardrail` |
| `guards.remote_desktop_side_channel.clipboard_enabled` | `false` |
| `guards.remote_desktop_side_channel.file_transfer_enabled` | `false` |
| `guards.input_injection_capability.allowed_input_types` | `keyboard`, `mouse` |
| `settings.fail_fast` | `false` |
| `settings.session_timeout_secs` | `7200` (2 hours) |

## View the exact policy

```bash
clawdstrike policy show remote-desktop
```
