# End-to-End Policy Event Mapping (B3)

Date: 2026-02-18  
Workstream: `P1` / `B3` from `EXECUTION-BACKLOG.md`

## 1. Purpose

This mapping defines deterministic preflight policy checks and post-action audit artifacts for
CUA side-effect flows:

- connect,
- input,
- clipboard,
- file transfer,
- session share,
- reconnect,
- disconnect.

Normative machine-checkable source:

- `docs/roadmaps/cua/research/policy_event_mapping.yaml`

Validation fixtures/harness:

- `fixtures/policy-events/policy-mapping/v1/cases.json`
- `docs/roadmaps/cua/research/verify_policy_event_mapping.py`

## 2. Guard model cross-reference

This mapping follows the existing Clawdstrike guard pipeline model:

- `docs/roadmaps/cua/research/08-policy-engine.md` (CUA action to guard mapping, guard stages)
- `crates/libs/clawdstrike/src/engine.rs` (stage-based evaluation and fail-closed aggregation)

The mapping is fail closed:

- unknown flow or side effect -> deny,
- missing mapping entry -> deny,
- guard evaluation error -> deny.

## 3. Flow mapping summary

| Flow | Preflight policy event | Guard checks | Post-action audit event | Required receipt artifacts |
|---|---|---|---|---|
| `connect` | `remote.session.connect` | `egress_allowlist`, `computer_use` | `audit.remote.session.connect` | `connection_id`, transport/frame hashes, decision digest |
| `input` | `input.inject` | `computer_use`, `input_injection_capability` | `audit.input.inject` | `action_id`, input/frame hashes, probe result |
| `clipboard_read` | `remote.clipboard` (+ direction=`read`) | `computer_use`, `remote_desktop_side_channel` | `audit.remote.clipboard.read` | `clipboard_payload_hash`, decision digest |
| `clipboard_write` | `remote.clipboard` (+ direction=`write`) | `computer_use`, `remote_desktop_side_channel` | `audit.remote.clipboard.write` | payload hash, redaction rule hashes, decision digest |
| `file_transfer_upload` | `remote.file_transfer` (+ direction=`upload`) | `forbidden_path`, `computer_use`, `remote_desktop_side_channel` | `audit.remote.file_transfer.upload` | transfer manifest hash, file digest, decision digest |
| `file_transfer_download` | `remote.file_transfer` (+ direction=`download`) | `egress_allowlist`, `forbidden_path`, `computer_use`, `remote_desktop_side_channel` | `audit.remote.file_transfer.download` | transfer/file/quarantine digests, decision digest |
| `session_share` | `remote.session_share` | `computer_use`, `remote_desktop_side_channel` | `audit.remote.session_share` | peer identity digest, share scope, decision digest |
| `reconnect` | `remote.session.reconnect` | `computer_use` | `audit.remote.session.reconnect` | reconnect attempt + continuity hashes |
| `disconnect` | `remote.session.disconnect` | `computer_use` | `audit.remote.session.disconnect` | disconnect reason, final session hash |

## 4. Acceptance alignment

This artifact satisfies `B3` acceptance by making every listed side effect path explicit with:

- preflight policy event,
- guard coverage,
- post-action audit artifact output.

The fixture validator enforces no undefined flow remains for required side effects.
