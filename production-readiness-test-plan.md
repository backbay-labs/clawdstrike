# CUA Production Readiness Test Plan

## Purpose
This plan defines the minimum evidence required to ship CUA protections in `clawdstrike` with confidence that policy enforcement, provider translation, remote-session controls, and verifier behavior are safe under real runtime conditions.

## Release Decision Standard
Ship only when all gates below pass on the release candidate branch and artifacts are attached to the PR.

## Test Environments
| Environment | Host | OS | Purpose |
| --- | --- | --- | --- |
| Local dev | Engineer workstation | macOS/Linux | Fast iteration and smoke checks |
| CI-equivalent | Local + CI | Ubuntu | Full deterministic regression gate |
| Staging target A | EC2 | Windows Server 2022 | Real RDP/CUA side-channel/runtime tests |
| Staging target B | EC2 | Ubuntu 24.04 + XRDP | Linux remote desktop and continuity tests |

## EC2 Testbed Provisioning
Provision/reuse staging hosts with:

```bash
./scripts/provision-cua-ec2-testbeds.sh
```

The script writes connection metadata (instance IDs, IPs, credentials, key path) to:

```text
~/.config/clawdstrike-cua/testbeds/clawdstrike-cua-testbed-<timestamp>.json
```

When pausing testing, stop instances (preserves host state and avoids compute cost):

```bash
aws ec2 stop-instances --instance-ids <linux_instance_id> <windows_instance_id>
```

When fully finished, terminate to avoid persistent storage/network costs:

```bash
aws ec2 terminate-instances --instance-ids <linux_instance_id> <windows_instance_id>
```

## Gate 0: Baseline Preconditions
1. Branch is rebased and clean.
2. `mise.toml` toolchain versions are active.
3. Secrets for provider tests are set in staging only (never committed):
   - `OPENAI_API_KEY`
   - `ANTHROPIC_API_KEY`
4. No unresolved PR review threads.

## Gate 1: Deterministic Repo Gate (must be green)
Run from repo root:

```bash
mise run ci
bash scripts/test-platform.sh
```

Run CUA fixture validators:

```bash
python3 docs/roadmaps/cua/research/verify_canonical_adapter_contract.py
python3 docs/roadmaps/cua/research/verify_policy_event_mapping.py
python3 docs/roadmaps/cua/research/verify_cua_policy_evaluation.py
python3 docs/roadmaps/cua/research/verify_cua_migration_fixtures.py
python3 docs/roadmaps/cua/research/verify_remote_desktop_policy_matrix.py
python3 docs/roadmaps/cua/research/verify_remote_desktop_ruleset_alignment.py
python3 docs/roadmaps/cua/research/verify_postcondition_probes.py
python3 docs/roadmaps/cua/research/verify_remote_session_continuity.py
python3 docs/roadmaps/cua/research/verify_envelope_semantic_equivalence.py
python3 docs/roadmaps/cua/research/verify_repeatable_latency_harness.py
python3 docs/roadmaps/cua/research/verify_provider_conformance.py
python3 docs/roadmaps/cua/research/verify_openclaw_cua_bridge.py
python3 docs/roadmaps/cua/research/verify_trycua_connector.py
```

## Gate 2: Runtime Integration Gate (must prove non-synthetic behavior)
1. Execute runtime bridge/provider tests (Rust + TS) against fixture sets.
2. Confirm OpenClaw runtime path enforces canonical CUA policy decisions, not default allow.
3. Confirm provider runtime tests cover canonical flow surface and deterministic `reason_code` emission.
4. Capture reports:
   - provider conformance runtime logs
   - openclaw bridge runtime test output
   - decision schema snapshots

## Gate 3: Staging Remote Session Gate (real networked hosts)
### Topology
1. CUA gateway/orchestrator host (local or dedicated staging runner).
2. Windows EC2 target via RDP.
3. Linux EC2 target via XRDP.

### Required test scenarios
1. `click`, `type`, `scroll`, `key_chord` post-condition probes.
2. Side-channel policy enforcement:
   - clipboard
   - file_transfer (size bounds)
   - session_share
   - audio
   - drive_mapping
   - printing
3. Session continuity chain:
   - reconnect
   - induced packet loss
   - gateway restart
4. Abuse/fail-closed checks:
   - unknown `remote.*` action denial
   - malformed transfer size payload denial
   - missing required metadata denial

### Evidence to save
1. Structured decision logs with `decision`, `reason_code`, `severity`.
2. Session transcripts and probe output JSON.
3. Screenshots/video capture for manual confirmation of block/allow UX.

## Gate 4: Provider Runtime Gate
Run identical fixture-driven scenarios through:
1. OpenAI computer-use stack (Agents SDK/tools computer-use path).
2. Claude computer-use stack.
3. OpenClaw plugin path.

Pass criteria:
1. Semantic equivalence across providers for canonical actions.
2. Policy outcomes match expected fixtures.
3. No provider-specific bypass of side-channel guardrails.

## Gate 5: Performance + Reproducibility Gate
1. Run repeatable latency harness on fixed metadata (`instance type`, region, gateway build SHA).
2. Run 3 identical repetitions per scenario.
3. Enforce max variance threshold from fixture expectations.
4. Block release on unexplained latency drift.

## Gate 6: Rollout Safety Gate
1. Verify default rulesets align with matrix expectations.
2. Dry-run production policy bundles with `hush-cli` verification path.
3. Confirm verifier error taxonomy is deterministic and machine-actionable.
4. Prepare rollback plan:
   - feature flags/toggles for CUA enforcement
   - previous known-good ruleset bundle
   - documented disable path for affected provider connector

## Required Artifacts in PR
1. Gate summary table with pass/fail by gate.
2. Links/attachments to all fixture validator outputs.
3. Runtime integration logs for OpenClaw bridge and provider conformance.
4. Staging runbook results (Windows + Linux).
5. Findings-to-fix traceability matrix.

## Go/No-Go Checklist
Release only if all are true:
1. All gates pass.
2. No critical/high unresolved findings.
3. No unresolved scope mismatch between roadmap, backlog, and runtime behavior.
4. Reviewers sign off on runtime evidence (not synthetic-only harnesses).

## Suggested Execution Order
1. Gate 1 (deterministic local/CI-equivalent).
2. Gate 2 (runtime integration).
3. Gate 3 (staging remote sessions).
4. Gate 4 (cross-provider parity).
5. Gate 5 (latency/reproducibility).
6. Gate 6 (rollout safety) and release decision.
