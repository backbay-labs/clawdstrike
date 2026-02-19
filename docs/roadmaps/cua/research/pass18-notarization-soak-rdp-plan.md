# Pass 18 Execution Plan: Notarization + Long Soak + Full RDP Side-Channel E2E

## Date
- Prepared on 2026-02-19.

## Goal
Close the two remaining production blockers:
1. Signed/notarized macOS release artifact validation.
2. 6-24h soak plus full Windows/Linux RDP side-channel end-to-end validation.

## Workstream Split (Parallel)
1. Workstream A (Release Integrity): macOS signing + notarization + stapling + Gate evidence.
2. Workstream B (Long-Run Reliability): 6-24h soak loop with reconnect/restart pressure.
3. Workstream C (RDP Side-Channel E2E): clipboard/audio/drive/printing/session-share on Windows + Linux hosts.

Run A/B/C in parallel where possible. Final release decision requires all three green.

## Prerequisites
1. Apple Developer credentials and certs available on runner.
2. Provider secrets in local `.env` only (not committed):
   - `OPENAI_API_KEY`
   - `ANTHROPIC_API_KEY`
   - `OPENCLAW_GATEWAY_TOKEN`
3. EC2 testbed metadata JSON available from provisioning script output:
   - `~/.config/clawdstrike-cua/testbeds/clawdstrike-cua-testbed-<timestamp>.json`

## Workstream A: Notarized Build (Blocking)
Use helper script:

```bash
scripts/notarize-agent-macos.sh
```

### Required env for script
- `APPLE_TEAM_ID`
- `APPLE_SIGNING_IDENTITY` (recommended explicit value)
- Either:
  - `NOTARYTOOL_PROFILE` (recommended), or
  - `APPLE_ID` + `APPLE_PASSWORD` (app-specific password)

### Expected pass evidence
1. `codesign` verification passes.
2. `spctl` accepts the app.
3. `notarytool submit --wait` returns accepted.
4. `stapler validate` passes for app and dmg.
5. Evidence files under `docs/roadmaps/cua/research/artifacts/notarization-<timestamp>/`.

## Workstream B: 6-24h Soak (Blocking)
Use helper script (default 6h):

```bash
DURATION_HOURS=6 scripts/run-cua-soak.sh
```

For 24h:

```bash
DURATION_HOURS=24 scripts/run-cua-soak.sh
```

### Expected pass evidence
1. No sustained reconnect failure.
2. Smoke iterations maintain high success rate (target 100%; investigate any failures).
3. Summary JSON emitted under `docs/roadmaps/cua/research/artifacts/soak-<timestamp>/summary.json`.
4. Per-iteration logs retained for triage.

## Workstream C: Full Windows + Linux RDP Side-Channel E2E (Blocking)
Use the latest testbed JSON and run matrix manually (or with your preferred RDP harness):

### Matrix to execute on both Windows and Linux targets
1. Clipboard allow and deny behavior.
2. Audio allow and deny behavior.
3. Drive mapping allow and deny behavior.
4. Printing allow and deny behavior.
5. Session share allow and deny behavior.

### Required outputs for each matrix case
1. Provider/tool action payload.
2. Translated policy event.
3. Runtime policy decision (`allow|warn|deny`) and `reason_code`.
4. Host-observed effect (did side channel actually occur).

### Recommended artifact path
- `docs/roadmaps/cua/research/artifacts/rdp-sidechannel-<timestamp>/`

Store one JSON result per test case plus any screenshots or recordings.

## Exit Criteria (Pass 18 complete)
1. Signed/notarized/stapled app artifact validated.
2. 6-24h soak completed with acceptable reliability and no unresolved critical failures.
3. Full side-channel matrix completed for both Windows and Linux with expected allow/deny behavior.
4. PR updated with artifact links and final go/no-go summary.

## Suggested Final Command Sequence
```bash
# A) Release integrity
scripts/notarize-agent-macos.sh

# B) Long soak
DURATION_HOURS=6 scripts/run-cua-soak.sh

# C) Full RDP side-channel matrix
# (execute matrix and collect artifacts in docs/roadmaps/cua/research/artifacts/rdp-sidechannel-<timestamp>/)
```
