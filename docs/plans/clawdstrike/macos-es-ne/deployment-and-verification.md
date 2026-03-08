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
