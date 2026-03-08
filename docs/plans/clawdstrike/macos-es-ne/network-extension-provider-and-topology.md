# Network Extension Provider And Topology

## Objective

Freeze the macOS network-enforcement shape before `NEINT` writes code.

## Why This Exists

The current repo has a real `ProxyOnly` runtime path in `CapabilitySet`, but that is an implementation artifact of the existing nono + local proxy flow. It is not enough to justify the macOS NetworkExtension architecture.

Apple's current guidance is narrower:

- use a content filter provider when the product inspects or blocks TCP/UDP flows
- use a transparent proxy provider only when the other provider models do not fit
- system extensions can combine multiple extension points, including EndpointSecurity and NetworkExtension, inside one combined system extension

Those constraints have to drive the initial ClawdStrike shape, not the other way around.

## Frozen Decision

- `apps/agent` remains the containing app baseline for the first macOS security-software wave.
- The first macOS security-software wave targets one combined system extension nested under `apps/agent`.
- The initial NetworkExtension provider baseline is a content filter provider.
- Transparent proxy is exception-only for this initiative. It is not the default target.
- `apps/desktop` remains out of scope for the initial privileged-component rollout.

## Rationale

### Provider Choice

ClawdStrike's currently stated network requirement is policy-driven mediation of agent egress. That is much closer to "inspect or block flows" than to "preserve an existing proxy product at all costs."

That means:

- the current `ProxyOnly` runtime collapse is a legacy transport shape, not a product requirement
- `NEINT` must start from a provider-agnostic mediation contract
- content filter is the default implementation target unless we can prove it is insufficient

### Topology Choice

Apple supports combined system extensions with multiple extension points. A combined system extension gives ClawdStrike the simpler first-wave packaging and approval story:

- one containing app
- one privileged bundle family to sign and notarize
- one activation and health surface for the host to read out
- lane-specific ES and NE code under separate subtrees without pretending the top-level bundle layout is separate

## Transparent Proxy Exception Rule

`NEINT` may not implement a transparent proxy path unless ORCH records all of the following in a reviewed handoff:

1. the product requirement that content filter cannot satisfy
2. the exact provider limitation or unsupported behavior that forces transparent proxy
3. the entitlement, plist, bundle-layout, and activation changes required by the exception
4. the updated verification matrix for that exception path

Without that handoff, transparent proxy is out of scope for the active wave.

## Repo Mapping

The active implementation map uses a combined system-extension container with lane-specific subtrees:

- host control plane: `apps/agent/src-tauri/src/macos/**`
- combined system extension root: `apps/agent/src-tauri/macos/system-extension/**`
- ES subtree: `apps/agent/src-tauri/macos/system-extension/endpoint-security/**`
- NE subtree: `apps/agent/src-tauri/macos/system-extension/network-extension/**`
- entitlement and plist assets: `apps/agent/src-tauri/macos/system-extension/{entitlements,plists,profiles}/**`

## Required Review Questions

Before `NEINT` is accepted, review must answer:

- does the implemented provider still match the content-filter baseline from this document?
- if not, is there an approved transparent-proxy exception handoff?
- does the host report the provider as installed, active, healthy, and policy-synced?
- does attestation distinguish provider-unavailable and provider-degraded states from actual enforced mediation?

## Apple Sources

- TN3165: Packet Filter is not API
  https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api
- Network Extensions for the Modern Mac (WWDC19)
  https://developer.apple.com/videos/play/wwdc2019/714/
- System Extensions
  https://developer.apple.com/system-extensions/
- TN3134: Network Extension provider deployment
  https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
