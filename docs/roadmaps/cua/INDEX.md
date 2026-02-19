# CUA Gateway Research Index

> Computer-Use Agent Gateway — Deep Research & Implementation Reference

## Source Report
- [Deep Research Report](./deep-research-report.md) — 2026 landscape and MVP blueprint
- [Review Log](./research/REVIEW-LOG.md) — dated reviewer interventions while agents continue writing
- [Execution Backlog](./research/EXECUTION-BACKLOG.md) — execution and closure status across passes #5-#17
- [Pass #18 Execution Plan](./research/pass18-notarization-soak-rdp-plan.md) — release integrity + long soak + full RDP side-channel E2E blockers
- [Production Readiness Test Plan](../../../production-readiness-test-plan.md) — gate-by-gate criteria for release go/no-go
- [Execution Agent Handoff Prompt](./research/EXECUTION-AGENT-HANDOFF-PROMPT.md) — ready-to-run prompt for implementation pass
- [Pass #14 Handoff Prompt](./research/EXECUTION-AGENT-HANDOFF-PROMPT-PASS14.md) — E3/E4/code-review team execution prompt
- [Verifier Flow Spec](./research/verifier-flow-spec.md) — pass-seven normative verifier order and error taxonomy
- [Attestation Verifier Policy](./research/attestation_verifier_policy.yaml) — pass-seven policy source of truth
- [Signer Migration Plan](./research/signer-migration-plan.md) — pass-seven dual-sign + rollback sequencing
- [CUA Schema Package](./research/schemas/cua-metadata/schema-package.json) — pass-seven versioned metadata schema registry
- [CUA Migration Fixtures](../../../fixtures/receipts/cua-migration/cases.json) — pass-seven fixture corpus and expected outcomes
- [Pass #8 Verifier Harness](./research/verify_cua_migration_fixtures.py) — executes fixture corpus with stable `VFY_*`/`AVP_*` outcomes
- [Pass #8 Harness Report](./research/pass8-verifier-harness-report.json) — latest local run results
- [Remote Desktop Policy Matrix](./research/remote_desktop_policy_matrix.yaml) — pass-nine `B1` machine-checkable feature/mode/tier controls
- [Pass #9 Matrix Harness](./research/verify_remote_desktop_policy_matrix.py) — fixture-driven matrix validator with fail-closed codes
- [Pass #9 Matrix Report](./research/pass9-remote-desktop-matrix-report.json) — latest local run results
- [Injection Outcome Schema](./research/injection_outcome_schema.json) — pass-nine `B2` standardized injection outcome contract
- [Injection Backend Capabilities](./research/injection_backend_capabilities.yaml) — pass-nine `B2` backend feature/permission limits
- [Injection Capability Fixtures](../../../fixtures/policy-events/input-injection/v1/cases.json) — pass-nine `B2` fixture corpus
- [Pass #9 Injection Harness](./research/verify_injection_capabilities.py) — fixture-driven injection capability validator
- [Pass #9 Injection Report](./research/pass9-injection-capabilities-report.json) — latest local run results
- [Policy Event Mapping](./research/policy_event_mapping.md) — pass-nine `B3` end-to-end preflight/audit mapping
- [Policy Event Mapping Matrix](./research/policy_event_mapping.yaml) — pass-nine `B3` machine-checkable flow mapping
- [Policy Mapping Fixtures](../../../fixtures/policy-events/policy-mapping/v1/cases.json) — pass-nine `B3` fixture corpus
- [Pass #9 Policy Mapping Harness](./research/verify_policy_event_mapping.py) — fixture-driven mapping validator
- [Pass #9 Policy Mapping Report](./research/pass9-policy-event-mapping-report.json) — latest local run results
- [Post-Condition Probe Suite](./research/postcondition_probe_suite.yaml) — pass-ten `C1` deterministic click/type/scroll/key-chord probe contract
- [Post-Condition Probe Fixtures](../../../fixtures/policy-events/postcondition-probes/v1/cases.json) — pass-ten `C1` fixture corpus
- [Pass #10 Post-Condition Harness](./research/verify_postcondition_probes.py) — fixture-driven probe-state validator
- [Pass #10 Post-Condition Report](./research/pass10-postcondition-probes-report.json) — latest local run results
- [Remote Session Continuity Suite](./research/remote_session_continuity_suite.yaml) — pass-ten `C2` reconnect/packet-loss/gateway-restart continuity contract
- [Session Continuity Fixtures](../../../fixtures/policy-events/session-continuity/v1/cases.json) — pass-ten `C2` fixture corpus
- [Pass #10 Session Continuity Harness](./research/verify_remote_session_continuity.py) — fixture-driven continuity chain validator
- [Pass #10 Session Continuity Report](./research/pass10-session-continuity-report.json) — latest local run results
- [Ecosystem Integration Plan](./research/09-ecosystem-integrations.md) — pass-eleven provider/runtime integration strategy (OpenAI/Claude/OpenClaw/trycua)
- [Integration Team Handoff Prompt](./research/EXECUTION-AGENT-HANDOFF-PROMPT-INTEGRATION-TEAM.md) — team-parallel execution prompt for runtime integration
- [Envelope Semantic Equivalence Suite](./research/envelope_semantic_equivalence_suite.yaml) — pass-eleven `C3` wrapper equivalence contract
- [Envelope Equivalence Fixtures](../../../fixtures/receipts/envelope-equivalence/v1/cases.json) — pass-eleven `C3` fixture corpus
- [Pass #11 Envelope Equivalence Harness](./research/verify_envelope_semantic_equivalence.py) — fixture-driven wrapper parity validator
- [Pass #11 Envelope Equivalence Report](./research/pass11-envelope-equivalence-report.json) — latest local run results
- [Repeatable Latency Harness](./research/repeatable_latency_harness.yaml) — pass-eleven `D1` benchmark harness contract
- [Latency Benchmark Fixtures](../../../fixtures/benchmarks/remote-latency/v1/cases.json) — pass-eleven `D1` fixture corpus
- [Pass #11 Latency Harness](./research/verify_repeatable_latency_harness.py) — fixture-driven benchmark validator
- [Pass #11 Latency Report](./research/pass11-latency-harness-report.json) — latest local run results
- [Verification Bundle Format](./research/verification_bundle_format.yaml) — pass-twelve `D2` end-to-end bundle contract
- [Verification Bundle Fixtures](../../../fixtures/receipts/verification-bundle/v1/cases.json) — pass-twelve `D2` fixture corpus
- [Pass #12 Verification Bundle Harness](./research/verify_verification_bundle.py) — fixture-driven bundle validator
- [Pass #12 Verification Bundle Report](./research/pass12-verification-bundle-report.json) — latest local run results
- [Browser Action Policy Suite](./research/browser_action_policy_suite.yaml) — pass-twelve browser action policy contract
- [Browser Action Fixtures](../../../fixtures/policy-events/browser-actions/v1/cases.json) — pass-twelve browser action fixture corpus
- [Pass #12 Browser Action Harness](./research/verify_browser_action_policy.py) — fixture-driven browser action validator
- [Pass #12 Browser Action Report](./research/pass12-browser-action-policy-report.json) — latest local run results
- [Session Recording Evidence Suite](./research/session_recording_evidence_suite.yaml) — pass-twelve evidence pipeline contract
- [Session Recording Fixtures](../../../fixtures/policy-events/session-recording/v1/cases.json) — pass-twelve session recording fixture corpus
- [Pass #12 Session Recording Harness](./research/verify_session_recording_evidence.py) — fixture-driven evidence validator
- [Pass #12 Session Recording Report](./research/pass12-session-recording-evidence-report.json) — latest local run results
- [Orchestration Isolation Suite](./research/orchestration_isolation_suite.yaml) — pass-twelve container/VM isolation contract
- [Orchestration Fixtures](../../../fixtures/policy-events/orchestration/v1/cases.json) — pass-twelve orchestration fixture corpus
- [Pass #12 Orchestration Harness](./research/verify_orchestration_isolation.py) — fixture-driven isolation validator
- [Pass #12 Orchestration Report](./research/pass12-orchestration-isolation-report.json) — latest local run results
- [CUA Policy Evaluation Suite](./research/cua_policy_evaluation_suite.yaml) — pass-twelve CUA policy evaluation contract
- [Policy Evaluation Fixtures](../../../fixtures/policy-events/policy-evaluation/v1/cases.json) — pass-twelve policy evaluation fixture corpus
- [Pass #12 Policy Evaluation Harness](./research/verify_cua_policy_evaluation.py) — fixture-driven policy evaluation validator
- [Pass #12 Policy Evaluation Report](./research/pass12-cua-policy-evaluation-report.json) — latest local run results
- [CUA Remote Desktop Ruleset](../../../rulesets/remote-desktop.yaml) — pass-thirteen built-in remote-desktop ruleset (guardrail mode)
- [CUA Remote Desktop Strict Ruleset](../../../rulesets/remote-desktop-strict.yaml) — pass-thirteen strict remote-desktop ruleset (fail-closed mode)
- [CUA Remote Desktop Permissive Ruleset](../../../rulesets/remote-desktop-permissive.yaml) — pass-thirteen permissive remote-desktop ruleset (observe mode)
- [Canonical Adapter CUA Contract](./research/canonical_adapter_cua_contract.yaml) — pass-thirteen `E1` adapter-core CUA flow contract
- [Adapter Contract Fixtures](../../../fixtures/policy-events/adapter-contract/v1/cases.json) — pass-thirteen `E1` fixture corpus
- [Pass #13 Adapter Contract Harness](./research/verify_canonical_adapter_contract.py) — fixture-driven adapter contract validator
- [Pass #13 Adapter Contract Report](./research/pass13-canonical-adapter-contract-report.json) — latest local run results
- [Provider Conformance Suite](./research/provider_conformance_suite.yaml) — pass-thirteen `E2` cross-provider parity contract
- [Provider Conformance Fixtures](../../../fixtures/policy-events/provider-conformance/v1/cases.json) — pass-thirteen `E2` fixture corpus
- [Pass #13 Provider Conformance Harness](./research/verify_provider_conformance.py) — fixture-driven provider parity validator
- [Pass #13 Provider Conformance Report](./research/pass13-provider-conformance-report.json) — latest local run results
- [Pass #14 Code Review Report](./research/pass14-code-review-report.md) — thorough review of passes #11–#13 (3 critical issues fixed)
- [OpenClaw CUA Bridge Suite](./research/openclaw_cua_bridge_suite.yaml) — pass-fourteen `E3` OpenClaw CUA bridge event mapping contract
- [OpenClaw Bridge Fixtures](../../../fixtures/policy-events/openclaw-bridge/v1/cases.json) — pass-fourteen `E3` fixture corpus
- [Pass #14 OpenClaw Bridge Harness](./research/verify_openclaw_cua_bridge.py) — fixture-driven OpenClaw bridge validator
- [Pass #14 OpenClaw Bridge Report](./research/openclaw_cua_bridge_report.json) — latest local run results (10/10 pass)
- [trycua Connector Evaluation](./research/trycua-connector-evaluation.md) — pass-fourteen `E4` trycua/cua runtime connector evaluation
- [trycua Connector Suite](./research/trycua_connector_suite.yaml) — pass-fourteen `E4` connector compatibility contract
- [trycua Connector Fixtures](../../../fixtures/policy-events/trycua-connector/v1/cases.json) — pass-fourteen `E4` fixture corpus
- [Pass #14 trycua Connector Harness](./research/verify_trycua_connector.py) — fixture-driven connector compatibility validator
- [Pass #14 trycua Connector Report](./research/trycua_connector_report.json) — latest local run results (9/9 pass)

## Research Topics

### 1. Browser Automation & Instrumentation
- [Browser Automation](./research/01-browser-automation.md) — Playwright, Puppeteer, Selenium, CDP, WebDriver BiDi, chromedp
- Focus: action APIs, structured context (DOM/A11y), tracing, CDP proxy/mediation

### 2. Remote Desktop & Virtual Display
- [Remote Desktop](./research/02-remote-desktop.md) — Guacamole, noVNC, VNC, RDP, Weston, Xvfb, GNOME Remote Desktop, WebRTC, DCV
- Focus: protocol mediation, session recording, headless compositors, containment

### 3. Input Injection & Control Surfaces
- [Input Injection](./research/03-input-injection.md) — uinput, XTEST, SendInput, Quartz Events, UIA, XDG Portals
- Focus: platform-specific injection, permission models, Wayland security

### 4. Session Recording & Screen Capture
- [Session Recording](./research/04-session-recording.md) — FFmpeg, ScreenCaptureKit, Desktop Duplication API, PipeWire, CDP capture
- Focus: frame capture pipelines, artifact encoding, receipt evidence collection

### 5. Attestation, Sandboxing & Signing
- [Attestation & Signing](./research/05-attestation-signing.md) — TPM 2.0, Nitro Enclaves, SGX, SEV-SNP, TDX, Sigstore, COSE, Secure Enclave
- Focus: hardware roots of trust, keyless signing, transparency logs, receipt integrity

### 6. Orchestration & Containerization
- [Orchestration](./research/06-orchestration.md) — Docker, containerd, gVisor, Firecracker, Kata Containers, KVM, QEMU
- Focus: isolation models, microVM vs container tradeoffs, runtime lifecycle

### 7. Receipt Schema & Signing Pipeline
- [Receipt Design](./research/07-receipt-schema.md) — hash chains, COSE envelopes, evidence hashing, redaction, multi-signature
- Focus: schema design, verification flows, artifact storage, append-only ledger patterns

### 8. Policy Engine & Enforcement
- [Policy Engine](./research/08-policy-engine.md) — allowlists, redaction, approval hooks, rate limits, observe/guardrail/fail-closed modes
- Focus: policy language design, enforcement mechanics, integration with Clawdstrike guards

### 9. Ecosystem Integrations
- [Ecosystem Integrations](./research/09-ecosystem-integrations.md) — OpenAI/Claude/OpenClaw/trycua adapter strategy
- Focus: canonical contract first, provider translators, parity fixtures, fail-closed adapter drift handling

## Status

| Topic | Status | Last Updated |
|-------|--------|-------------|
| Browser Automation | Pass #12 Execution Artifacts + Harness-Validated | 2026-02-18 |
| Remote Desktop | Pass #18 Release-Gate Validation In Progress (matrix harness + restore hardening complete; long-run host validation pending) | 2026-02-19 |
| Input Injection | Pass #18 Release-Gate Validation In Progress (soak harness timeout + determinism hardening complete; 6-24h run pending) | 2026-02-19 |
| Session Recording | Pass #12 Execution Artifacts + Harness-Validated | 2026-02-18 |
| Attestation & Signing | Pass #12 Verification Bundle (`D2`) + Harness-Validated | 2026-02-18 |
| Orchestration | Pass #12 Execution Artifacts + Harness-Validated | 2026-02-18 |
| Receipt Schema | Pass #11 Envelope Equivalence (`C3`) + Harness-Validated | 2026-02-18 |
| Policy Engine | Pass #17 Runtime Hardening Complete; Pass #18 Production Gate Validation In Progress | 2026-02-19 |
| Ecosystem Integrations | Pass #17 Runtime Hardening Complete; Pass #18 Production Gate Validation In Progress | 2026-02-19 |

Program status: Pass #17 implementation remediation is complete. Pass #18 release-gate validation is now the active blocker set: signed/notarized artifact verification, sustained 6-24h soak execution, full Windows/Linux side-channel host validation evidence, and closure of remaining PR review threads.
