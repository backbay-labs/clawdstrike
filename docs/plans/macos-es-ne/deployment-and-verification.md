# Deployment And Verification Requirements

## Objective

Freeze the packaging path and the failure-mode verification bar for the first macOS security-software wave.

## Deployment Baseline

- containing app: `apps/agent`
- distribution baseline: Developer ID outside the Mac App Store
- privileged runtime packaging: combined system extension nested under the containing app
- install target: `/Applications` for the containing app path used by the system-extension deployment model
- Mac App Store and app-extension deployment are explicitly deferred from the first wave

This is the minimum deployment shape that `PKG` is allowed to optimize. It is not allowed to silently switch deployment models.

## Managed Deployment Artifacts

The MDM payload sources live under `apps/agent/src-tauri/macos/system-extension/profiles/`.

Render concrete profiles with:

```bash
apps/agent/src-tauri/macos/system-extension/profiles/render-mdm-profiles.sh \
  --team-id JB6682CJY9 \
  --app-bundle-id dev.clawdstrike.agent \
  --extension-bundle-id dev.clawdstrike.agent.system-extension \
  --org-identifier com.example.enterprise \
  --out-dir /tmp/clawdstrike-mdm-profiles
```

The rendered set is:

- `clawdstrike-system-extension-approval.mobileconfig`
- `clawdstrike-full-disk-access.mobileconfig`
- `clawdstrike-network-content-filter.mobileconfig`
- `manifest.txt`

Deployment order for a managed macOS host:

1. Install the rendered system-extension approval profile.
2. Install the rendered PPPC Full Disk Access profile.
3. Install the rendered NetworkExtension content-filter profile.
4. Install the notarized ClawdStrike Agent app in `/Applications`.
5. Launch the agent and let it request activation for `dev.clawdstrike.agent.system-extension`.
6. Verify `/api/v1/agent/health` reports `"pending"` during activation and `"ok"` only after ES and NE provider readouts are active and healthy.
7. Run the supervised file/network allow-deny smoke tests and archive the resulting health JSON, profile manifest, `systemextensionsctl list`, entitlements dumps, and receipts.

The source templates intentionally use render-time values for Team ID, app bundle ID, system-extension bundle ID, and organization identifier. The generated files, not the `.in` templates, are the deployment artifacts for Jamf, Kandji, Intune, or another MDM.

## TN3134 And TN3165 Constraints

`PKG` must treat TN3134 and TN3165 as gating platform documents, not optional background reading.

For the active wave that means:

- Developer ID distribution follows the system-extension deployment path
- bundle layout, entitlements, and approval flow must be reviewed against the system-extension model
- any attempt to pivot to an app-extension deployment model is a scope change that requires ORCH approval
- network-provider selection and packaging must stay aligned; do not choose a provider first and discover deployment constraints later

## Packaging Consequences

`PKG` owns the combined system-extension packaging family:

- app entitlements and bundle metadata
- system-extension entitlements, plists, and profiles
- notarization and signing workflow
- release and CI checks for missing macOS packaging artifacts

The packaging lane must also leave operator-readable evidence for:

- system extension identifier and bundle identifiers
- signer identity used for the build
- notarization result
- activation status on a real macOS signer or test host

## Required Failure-Mode Verification

The first macOS wave is not verified by "it builds." The following states are mandatory verification gates:

| State | Owner | Required evidence |
|------|-------|-------------------|
| System-extension approval denied | `HOST` + `PKG` | Host reports approval-blocked/degraded state; receipts do not claim enforcement |
| Full Disk Access missing | `ESINT` + `POLAT` | ES health degrades; attestation records provider-unavailable or degraded reason |
| Extension inactive while agent host is healthy | `HOST` + `POLAT` | Status surface shows host-up/provider-down split clearly |
| Launchd restart or host relaunch | `HOST` + `PKG` | Re-registration or degraded detection evidence after restart |
| ES deadline miss or dropped events | `ESINT` + `POLAT` | Explicit counters and degraded attestation evidence |
| NE provider unavailable | `NEINT` + `POLAT` | Host/receipt evidence that enforcement is unavailable rather than silently bypassed |
| Notarization/signing unavailable in worker env | `PKG` | Blocked release-gate handoff instead of a false verified claim |

## Review Rule

Any review lane must reject a handoff that:

- claims macOS enforcement without provider-health evidence
- treats transparent proxy as the default NE path without the documented exception
- omits denial-case or degraded-case verification because the happy path succeeded

## Apple Sources

- TN3134: Network Extension provider deployment
  https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- TN3165: Packet Filter is not API
  https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api
- System Extensions
  https://developer.apple.com/system-extensions/
