# trycua/cua Connector Evaluation

## Overview

This document evaluates `trycua/cua` (https://github.com/trycua/cua) as an execution backend candidate for Clawdstrike CUA policy enforcement. The evaluation maps trycua capabilities against the canonical adapter-core CUA contract defined in `canonical_adapter_cua_contract.yaml`.

**Evaluation scope:** Connector compatibility, not trust-root replacement. Clawdstrike owns the canonical contract, verifier order, and receipt semantics. trycua is evaluated strictly as an upstream execution layer whose actions must be translated into canonical policy events.

## What trycua/cua Provides

### Architecture

trycua/cua is a three-tier computer-use agent infrastructure:

1. **CuaBot** - Multi-agent computer-use sandbox CLI for orchestrating agents across sandboxed desktop environments.
2. **Cua-Agent** - AI agent framework for computer-use tasks, supporting multiple model providers (Anthropic Claude, OpenAI, custom agents).
3. **Cua-Computer** - SDK for controlling desktop environments (macOS VMs via Lume, Linux Docker, cloud providers).

### Execution Backends

| Backend | Description |
|---------|-------------|
| macOS VM | Apple Silicon virtualization via Lume |
| Linux Docker | Containerized desktop environments |
| Cloud provider | Remote sandbox execution |
| Windows | Full desktop control (limited documentation) |

### Action Types (from SDK surface)

- **UI automation:** Click, type text, mouse movement
- **Screen capture:** Screenshot functionality
- **Browser automation:** Chromium-based navigation
- **Clipboard:** Shared clipboard between host and sandbox
- **File operations:** File transfer between host and sandbox
- **Session management:** VM lifecycle (start, stop, connect, disconnect)

### Provider Support

- Anthropic Claude (`claude-sonnet-4-5-20250929`)
- OpenAI (computer-use tool path)
- OpenClaw (third-party agent integration)
- Custom agents via framework extension

### Event Model

trycua uses an async streaming model:
```python
Computer(os_type, provider_type)  # Desktop environment controller
ComputerAgent(model, computer)     # Agent framework wrapper
agent.run(messages)                # Async message-based interface
```

Actions are emitted as streaming results, not as structured policy events. There is no native policy event schema -- trycua emits raw action streams that must be translated by a connector.

## Canonical Contract Mapping

### Flow Surface Compatibility Matrix

The canonical adapter-core CUA contract defines 8 flow surfaces. The following matrix maps trycua capabilities to each.

| trycua Capability | Canonical Flow Surface | Status | Notes |
|-------------------|----------------------|--------|-------|
| VM session start | `connect` | **Partial** | trycua manages VM lifecycle but does not emit a structured connect event. Connector must synthesize `remote.session.connect` from VM start callbacks. |
| VM session stop | `disconnect` | **Partial** | VM stop/teardown exists but no structured disconnect event. Connector must map VM lifecycle hooks to `remote.session.disconnect`. |
| VM reconnect / resume | `reconnect` | **Unsupported** | No explicit reconnect primitive. VM sessions are either running or stopped. Connector must fail closed on reconnect attempts or synthesize from VM state transitions. |
| Click / type / mouse | `input` | **Compatible** | Core action types (click, type, mouse_move) map directly to `input.inject` with `cuaAction` field. Coordinate and text payloads translate cleanly. |
| Shared clipboard read | `clipboard_read` | **Partial** | Host-sandbox clipboard sharing exists but is implicit (not a discrete API call). Connector must intercept clipboard sync events and map to `remote.clipboard`. |
| Shared clipboard write | `clipboard_write` | **Partial** | Same as clipboard_read -- clipboard write is bidirectional sync, not a discrete write operation. Connector must infer direction from context. |
| File transfer (host->sandbox) | `file_transfer_upload` | **Partial** | File transfer exists in the Computer SDK but lacks structured metadata (path, size, hash). Connector must enrich events with evidence fields for `remote.file_transfer`. |
| File transfer (sandbox->host) | `file_transfer_download` | **Partial** | Same limitations as upload. Additionally, egress_allowlist guard cannot be applied without connector-provided destination metadata. |

### Status Legend

- **Compatible:** trycua capability maps cleanly to canonical flow surface with minimal translation.
- **Partial:** trycua has the capability but lacks structured event emission. Connector must synthesize/enrich canonical events.
- **Unsupported:** No trycua equivalent. Connector must fail closed.

## Fail-Closed Boundaries

The connector must enforce fail-closed semantics for:

1. **Unsupported flows:** Any trycua action that cannot be mapped to one of the 8 canonical flow surfaces must produce `ADC_FLOW_UNKNOWN` and deny the action.

2. **Missing evidence fields:** trycua does not emit structured evidence (paths, hashes, coordinates as metadata). If a guard requires evidence that the connector cannot extract from the trycua action stream, the connector must deny with `ADC_GUARD_RESULT_MALFORMED`.

3. **Unknown action types:** trycua may introduce new action types (e.g., `agent-browser`, `agent-device` for iOS/Android). Any action type not in the connector's known mapping must fail closed with `TCC_ACTION_UNKNOWN`.

4. **Reconnect flow:** trycua has no reconnect primitive. Any attempt to map a trycua event to the `reconnect` flow surface must fail closed with `TCC_FLOW_UNSUPPORTED` unless the connector can deterministically synthesize reconnect semantics from VM state transitions.

5. **Clipboard direction ambiguity:** trycua's shared clipboard is bidirectional without explicit direction. If the connector cannot determine read vs. write direction, it must fail closed with `TCC_DIRECTION_AMBIGUOUS`.

6. **Session identity:** trycua VM sessions may not carry stable session identifiers across the lifecycle. If `audit_ref` cannot be populated with a stable session ID, the connector must fail closed with `ADC_MISSING_POLICY_REF`.

## Integration Architecture

```
trycua/cua Action Stream
         |
         v
  +------------------+
  | trycua Connector  |  <-- Adapter layer (NOT trust-root)
  |                   |
  | - Action mapping  |
  | - Evidence enrich |
  | - Direction infer |
  | - Fail-closed     |
  +------------------+
         |
         v
  Canonical Policy Event
  (eventType, cuaAction, direction, evidence)
         |
         v
  +------------------+
  | Adapter Core      |  <-- Clawdstrike canonical contract
  | - Guard eval      |
  | - Policy engine   |
  | - Receipt signing |
  | - Audit pipeline  |
  +------------------+
```

The connector is a **translation layer** that:
- Receives raw trycua action streams
- Maps actions to canonical flow surfaces
- Enriches events with required evidence fields
- Infers direction where trycua is ambiguous
- Fails closed on any unmappable action or missing evidence
- Emits canonical policy events consumed by adapter-core

The connector does NOT:
- Define or modify trust roots
- Override verifier order
- Issue or modify receipts
- Bypass guard evaluation

## Incompatibilities

### Structural Incompatibilities

1. **No structured event model:** trycua emits raw action streams, not structured policy events. The entire event schema must be constructed by the connector, increasing surface area for translation errors.

2. **No native policy integration:** trycua has no concept of policy evaluation, guard checks, or receipt signing. All policy semantics are external to trycua.

3. **Implicit clipboard semantics:** Bidirectional clipboard sync without explicit read/write direction forces the connector to infer direction, which may be unreliable.

4. **No reconnect primitive:** The canonical contract requires `reconnect` as a distinct flow surface. trycua only has binary session state (running/stopped).

5. **Missing file transfer metadata:** trycua file operations lack structured metadata (source path, destination path, file hash, file size) required by `forbidden_path` and `remote_desktop_side_channel` guards.

### Provider Conformance Gaps

6. **No canonical intent mapping:** trycua does not use the provider conformance suite's intent vocabulary (click_element, type_text, navigate_url, etc.). The connector must maintain its own intent-to-action mapping.

7. **Streaming vs. request/response:** trycua's async streaming model differs from the request/response model assumed by the canonical adapter contract. The connector must buffer and correlate streaming events into discrete flow surface evaluations.

### Operational Gaps

8. **Session identity stability:** trycua VMs may not provide stable session identifiers suitable for `audit_ref` population across policy evaluations within the same logical session.

9. **Evidence handoff:** trycua does not provide evidence bundles (screenshots, DOM snapshots, input logs) in a format consumable by Clawdstrike guards. The connector must either extract evidence from the action stream or explicitly reject evidence-dependent guard evaluations.

## Connector Error Codes

| Code | Meaning |
|------|---------|
| `TCC_ACTION_UNKNOWN` | trycua action type not in connector mapping |
| `TCC_FLOW_UNSUPPORTED` | trycua has no equivalent for canonical flow surface |
| `TCC_DIRECTION_AMBIGUOUS` | Cannot determine clipboard/transfer direction |
| `TCC_EVIDENCE_MISSING` | Required evidence fields not extractable from trycua stream |
| `TCC_SESSION_ID_MISSING` | Cannot populate stable session identifier for audit_ref |

These connector-specific codes are emitted before canonical adapter-core evaluation. They are distinct from `ADC_*` codes which are emitted by the adapter-core contract itself.

## Recommendations

1. **Start with `input` flow:** This is the only fully compatible flow surface. Build and validate the connector for click/type/mouse actions first.

2. **Session lifecycle next:** Implement connect/disconnect mapping from VM lifecycle hooks. Accept the limitation that reconnect will fail closed until trycua adds explicit reconnect semantics.

3. **Clipboard requires investigation:** The bidirectional clipboard sync needs deeper analysis. Consider requiring explicit clipboard API calls rather than relying on OS-level sync detection.

4. **File transfer requires enrichment:** The connector must add metadata extraction (path, hash, size) for file operations. This is a significant implementation effort.

5. **Do not attempt evidence handoff initially:** Guards that require evidence bundles (screenshots, DOM state) should be explicitly unsupported in the connector's first iteration, failing closed.

## References

- Canonical contract: `docs/roadmaps/cua/research/canonical_adapter_cua_contract.yaml`
- Provider conformance: `docs/roadmaps/cua/research/provider_conformance_suite.yaml`
- Integration strategy: `docs/roadmaps/cua/research/09-ecosystem-integrations.md`
- Connector suite: `docs/roadmaps/cua/research/trycua_connector_suite.yaml`
- Connector fixtures: `fixtures/policy-events/trycua-connector/v1/cases.json`
- trycua/cua: https://github.com/trycua/cua
