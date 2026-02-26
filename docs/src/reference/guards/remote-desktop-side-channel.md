# RemoteDesktopSideChannelGuard

Controls individual remote desktop side channels: clipboard, file transfer, audio, drive mapping, printing, and session sharing.

## Actions

- `GuardAction::Custom("remote.clipboard", data)`
- `GuardAction::Custom("remote.file_transfer", data)`
- `GuardAction::Custom("remote.audio", data)`
- `GuardAction::Custom("remote.drive_mapping", data)`
- `GuardAction::Custom("remote.printing", data)`
- `GuardAction::Custom("remote.session_share", data)`

The guard handles `Custom` actions starting with `"remote."` **except** session lifecycle actions (`remote.session.connect`, `remote.session.disconnect`, `remote.session.reconnect`), which are handled by [ComputerUseGuard](./computer-use.md).

## Configuration

```yaml
guards:
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: true
    file_transfer_enabled: true
    session_share_enabled: true
    audio_enabled: true
    drive_mapping_enabled: true
    printing_enabled: true
    max_transfer_size_bytes: 104857600  # 100MB, null = unlimited
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this guard. |
| `clipboard_enabled` | bool | `true` | Allow clipboard operations. |
| `file_transfer_enabled` | bool | `true` | Allow file transfer operations. |
| `session_share_enabled` | bool | `true` | Allow session sharing. |
| `audio_enabled` | bool | `true` | Allow remote audio channel. |
| `drive_mapping_enabled` | bool | `true` | Allow remote drive mapping. |
| `printing_enabled` | bool | `true` | Allow remote printing. |
| `max_transfer_size_bytes` | u64 or null | `null` (unlimited) | Maximum file transfer size in bytes. When set, `transfer_size` must be present in the action data. |

## Behavior

Each channel can be independently enabled or disabled. When a channel is disabled, any action for that channel is blocked with `Severity::Error`.

For file transfers with `max_transfer_size_bytes` configured:

- The action data must contain a `transfer_size` (or `transferSize`) field with a `u64` value.
- Missing or non-integer `transfer_size` is denied.
- Transfers exceeding the limit are denied.

Unknown `remote.*` side channel types (not in the list above) are denied by fail-closed policy.

## Related

- [ComputerUseGuard](./computer-use.md) -- top-level CUA gateway with enforcement modes
- [InputInjectionCapabilityGuard](./input-injection-capability.md) -- input type validation
- [Computer Use Gateway Guide](../../guides/computer-use-gateway.md) -- end-to-end CUA setup
