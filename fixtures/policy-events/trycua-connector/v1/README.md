# trycua Connector Fixtures (v1)

Fixture cases for validating the trycua/cua connector against the canonical adapter-core CUA contract.

## Suite Reference

- Suite definition: `docs/roadmaps/cua/research/trycua_connector_suite.yaml`
- Canonical contract: `docs/roadmaps/cua/research/canonical_adapter_cua_contract.yaml`
- Evaluation document: `docs/roadmaps/cua/research/trycua-connector-evaluation.md`

## Cases (9 total)

| ID | Category | Expected |
|----|----------|----------|
| `trycua_click_maps_to_input_inject` | Supported flow (input) | pass |
| `trycua_type_maps_to_input_inject` | Supported flow (input) | pass |
| `trycua_vm_start_maps_to_connect` | Supported flow (connect) | pass |
| `trycua_vm_stop_maps_to_disconnect` | Supported flow (disconnect) | pass |
| `trycua_screenshot_maps_to_clipboard_read` | Supported flow (clipboard_read) | pass |
| `trycua_clipboard_sync_direction_ambiguous_fails_closed` | Fail closed (direction) | fail: TCC_DIRECTION_AMBIGUOUS |
| `trycua_file_copy_evidence_missing_fails_closed` | Fail closed (evidence) | fail: TCC_EVIDENCE_MISSING |
| `trycua_unknown_action_fails_closed` | Fail closed (unknown action) | fail: TCC_ACTION_UNKNOWN |
| `trycua_reconnect_flow_unsupported_fails_closed` | Fail closed (unsupported flow) | fail: TCC_FLOW_UNSUPPORTED |

## Coverage

The fixtures test the following connector invariants:

1. **Supported flows produce valid canonical events** -- click, type, vm_start, vm_stop, screenshot all map to correct canonical flow surfaces with correct eventType, cuaAction, and direction.
2. **Unsupported flows fail closed** -- reconnect flow produces TCC_FLOW_UNSUPPORTED.
3. **Unknown action types fail closed** -- unrecognized trycua action produces TCC_ACTION_UNKNOWN.
4. **Evidence handoff fields** -- file_copy without structured metadata (path, hash, size) produces TCC_EVIDENCE_MISSING.
5. **Direction ambiguity** -- clipboard_sync without explicit direction produces TCC_DIRECTION_AMBIGUOUS.

## Validator

Run the validator harness:

```bash
python3 docs/roadmaps/cua/research/verify_trycua_connector.py
```

Report output: `docs/roadmaps/cua/research/trycua_connector_report.json`
