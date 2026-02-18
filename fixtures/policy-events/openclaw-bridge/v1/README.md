# OpenClaw CUA Bridge Fixtures (v1)

Test fixtures for the OpenClaw CUA bridge handler (`@clawdstrike/openclaw`).

## Cases

| ID | Description |
|---|---|
| `openclaw_connect_event` | CUA connect from OpenClaw produces `remote.session.connect` |
| `openclaw_computer_use_action_connect` | Plain `computer_use` + `action=connect` maps to `remote.session.connect` and preserves destination metadata |
| `openclaw_input_inject_click` | CUA click from OpenClaw produces `input.inject` |
| `openclaw_clipboard_read` | Clipboard read produces `remote.clipboard` with `direction=read` |
| `openclaw_file_upload` | File upload produces `remote.file_transfer` with `direction=upload` |
| `openclaw_disconnect` | Disconnect produces `remote.session.disconnect` |
| `openclaw_unknown_cua_action_fail_closed` | Unknown action `screen_record` fails closed (`OCLAW_CUA_UNKNOWN_ACTION`) |
| `openclaw_missing_cua_metadata_fail_closed` | Missing CUA metadata fails closed (`OCLAW_CUA_MISSING_METADATA`) |
| `openclaw_adapter_core_parity` | Parity check: OpenClaw bridge and direct adapter-core produce equivalent events |
| `openclaw_reconnect_with_continuity_hash` | Reconnect preserves `continuityPrevSessionHash` in event data |

## Suite Reference

`docs/roadmaps/cua/research/openclaw_cua_bridge_suite.yaml`

## Validation

```bash
python3 docs/roadmaps/cua/research/verify_openclaw_cua_bridge.py
```
