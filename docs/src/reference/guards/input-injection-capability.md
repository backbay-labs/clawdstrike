# InputInjectionCapabilityGuard

Controls input injection capabilities by validating input types and optionally requiring postcondition probe hashes.

## Actions

- `GuardAction::Custom("input.inject", data)`

The action data must contain an `input_type` (or `inputType`) field identifying the input method.

## Configuration

```yaml
guards:
  input_injection_capability:
    enabled: true
    allowed_input_types:
      - "keyboard"
      - "mouse"
      - "touch"
    require_postcondition_probe: false
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this guard. |
| `allowed_input_types` | string[] | `["keyboard", "mouse", "touch"]` | Input types that are permitted. |
| `require_postcondition_probe` | bool | `false` | Require a `postcondition_probe_hash` field in the action data. |

## Behavior

1. **Input type validation** (fail-closed): The `input_type` field must be present in the action data and must be in the `allowed_input_types` list. Missing or unknown input types are blocked with `Severity::Error`.

2. **Postcondition probe** (optional): When `require_postcondition_probe` is `true`, the action data must contain a non-empty `postcondition_probe_hash` (or `postconditionProbeHash`) string field. This enables verification that the expected screen state was observed after a previous action.

Both snake_case and camelCase field names are accepted in the action data since the CUA pipeline may serialize using either convention.

## Notes

- In a strict security posture, restrict `allowed_input_types` to `["keyboard"]` and set `require_postcondition_probe: true` to ensure every input action is preceded by a screen verification step.
- The default configuration allows keyboard, mouse, and touch without requiring postcondition probes.

## Related

- [ComputerUseGuard](./computer-use.md) -- top-level CUA gateway with enforcement modes
- [RemoteDesktopSideChannelGuard](./remote-desktop-side-channel.md) -- remote desktop channel control
- [Computer Use Gateway Guide](../../guides/computer-use-gateway.md) -- end-to-end CUA setup
