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

### Notary credential discovery checklist
1. Confirm a local Developer ID signing cert exists:
```bash
security find-identity -v -p codesigning
```
Expected: at least one `Developer ID Application` identity.
2. Find Team ID:
   - Apple Developer portal -> Membership -> Team ID (10 chars).
3. Create a notarization keychain profile (recommended):
```bash
xcrun notarytool store-credentials AC_NOTARY \
  --apple-id "you@example.com" \
  --team-id "TEAMID1234" \
  --password "<app-specific-password>"
```
Alternative: use App Store Connect API key:
```bash
xcrun notarytool store-credentials AC_NOTARY \
  --key "<KEY_ID>" \
  --issuer "<ISSUER_UUID>" \
  --key-path "/path/to/AuthKey_<KEY_ID>.p8"
```
4. Export env for the release run:
```bash
export APPLE_TEAM_ID="TEAMID1234"
export NOTARYTOOL_PROFILE="AC_NOTARY"
# optional explicit cert selection:
export APPLE_SIGNING_IDENTITY="Developer ID Application: <Name> (TEAMID1234)"
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

Harness controls (added for deterministic long runs):

```bash
SOAK_ITER_TIMEOUT_SECONDS=240 DURATION_HOURS=6 scripts/run-cua-soak.sh
MAX_ITERATIONS=1 SOAK_ITER_TIMEOUT_SECONDS=240 DURATION_HOURS=6 scripts/run-cua-soak.sh
```

### Expected pass evidence
1. No sustained reconnect failure.
2. Smoke iterations maintain high success rate (target 100%; investigate any failures).
3. Summary JSON emitted under `docs/roadmaps/cua/research/artifacts/soak-<timestamp>/summary.json`.
4. Per-iteration logs retained for triage.

## Workstream C: Full Windows + Linux RDP Side-Channel E2E (Blocking)
Use the latest testbed JSON and run the fixture harness:

```bash
scripts/run-rdp-sidechannel-matrix.sh
```

Timeout controls for deterministic completion:

```bash
RDP_PROBE_TIMEOUT_SECONDS=20 REMOTE_OP_TIMEOUT_SECONDS=30 SSM_WAIT_TIMEOUT_SECONDS=120 \
  scripts/run-rdp-sidechannel-matrix.sh
```

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
SOAK_ITER_TIMEOUT_SECONDS=240 DURATION_HOURS=6 scripts/run-cua-soak.sh

# C) Full RDP side-channel matrix
RDP_PROBE_TIMEOUT_SECONDS=20 REMOTE_OP_TIMEOUT_SECONDS=30 SSM_WAIT_TIMEOUT_SECONDS=120 \
  scripts/run-rdp-sidechannel-matrix.sh
```

## Current Execution Status (2026-02-19)
1. Soak harness hardening completed:
   - Added per-iteration timeout (`SOAK_ITER_TIMEOUT_SECONDS`).
   - Added bounded iteration mode (`MAX_ITERATIONS`) for smoke validation.
   - Added structured result fields (`exit_code`, `reason`) to `results.jsonl`.
2. RDP matrix harness hardening completed:
   - Added probe timeout (`RDP_PROBE_TIMEOUT_SECONDS`).
   - Added remote op and SSM wait timeouts (`REMOTE_OP_TIMEOUT_SECONDS`, `SSM_WAIT_TIMEOUT_SECONDS`).
   - Added guaranteed restore flow with EXIT trap to avoid policy drift on test hosts.
3. Recent evidence:
   - One-hour soak pass artifact: `docs/roadmaps/cua/research/artifacts/soak-20260219-020826/summary.json`.
   - One-iteration smoke validation with real gateway token:
     `docs/roadmaps/cua/research/artifacts/soak-20260219-034325/summary.json`.
   - Full side-channel matrix completed with restore artifacts:
     `docs/roadmaps/cua/research/artifacts/rdp-sidechannel-20260219-033112/summary.json`.
4. Cost-control checkpoint:
   - EC2 Windows/Linux staging instances are currently `stopped` (not terminated) and can be restarted for resumed gate execution.
5. PR hygiene checkpoint:
   - Remaining unresolved review threads are tracked as part of Pass #18 closure criteria and are being remediated in branch updates.
