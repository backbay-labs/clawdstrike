# Huntronomer Current State Review

> **Status:** Draft | **Date:** 2026-03-07
> **Reviewer:** Codex
> **Subject:** Restored `apps/desktop` tree on `feat/huntronomer`

## Executive Summary

The restored desktop app already contains enough real product material to avoid a rewrite, but it
is organized around the wrong center. Today the app behaves like a shell that hosts a collection of
security-themed modules. Huntronomer needs a tighter product loop: **signal -> hunt -> swarm ->
receipt -> publish back into the network**.

The practical conclusion is:

- keep the existing Huntronomer-branded Hunt Deck landing path as a transitional shell entry
- keep the shell/session infrastructure
- keep the OpenClaw and receipt plumbing
- keep the forensics river as the Huntboard execution core
- replace the current home, navigation, and domain model

## Strong Reusable Assets

| Asset | Current Evidence | Why It Matters |
| --- | --- | --- |
| Shell, sessions, routing, command palette | `apps/desktop/src/shell/ShellLayout.tsx`, `apps/desktop/src/shell/sessions/**`, `apps/desktop/src/shell/components/CommandPalette.tsx` | Huntronomer needs a keyboard-first desktop shell, and that foundation already exists |
| Session-first hunt lane behavior | `apps/desktop/src/shell/components/NavRail.tsx`, `apps/desktop/src/shell/dock/SessionRail.tsx` | The shell already thinks in terms of active sessions, saved commands, and rapid pivots into live operations |
| Hunt visualization substrate | `apps/desktop/src/features/forensics/ForensicsRiverView.tsx` | This is the strongest starting point for `Atlas`, `Flow`, `Timeline`, and swarm supervision views |
| Receipt / audit detail patterns | `apps/desktop/src/features/events/EventStreamView.tsx`, `apps/desktop/src/features/events/components/ReceiptPanel.tsx` | These already express policy outcomes and detailed inspection, even if the current framing is too daemon-centric |
| OpenClaw runtime control plane | `apps/desktop/src/features/openclaw/OpenClawFleetView.tsx`, `apps/desktop/src/context/OpenClawContext.tsx`, `apps/desktop/src/services/openclaw/gatewayClient.ts` | Huntronomer needs supervised swarm execution, approvals, node awareness, and runtime connectivity |
| Tauri bridge for proof/replay-adjacent commands | `apps/desktop/src/services/tauri.ts`, `apps/desktop/src-tauri/src/**` | The proof layer only works if the desktop surface can resolve receipts, replay, verification, and local runtime state |

## Code Review Findings

### 1. The current information architecture fights the product loop

**Severity:** High

`apps/desktop/src/shell/plugins/registry.tsx` defines a flat registry of semi-independent feature
views such as `Event Stream`, `Policy Tester`, `Swarm Map`, `Threat Radar`, and `Marketplace`.
That arrangement makes the app feel like a launcher for internal demos rather than a cohesive cyber
operations product. Huntronomer needs a small number of primary surfaces with subordinate views,
not a long list of peers, even though the current root already redirects into the Huntronomer-branded
`nexus` Hunt Deck.

### 2. The current feed model is audit-log-centric, not signal-centric

**Severity:** High

`apps/desktop/src/features/events/EventStreamView.tsx` is driven by daemon check/eval/violation
events normalized into `AuditEvent`. That is useful proof material, but it is not a product-grade
signal wire. Huntronomer needs first-class objects such as `Signal`, `Hunt`, `Receipt`, `Brief`,
and later `Case`, `Rule`, and `Challenge`, with structured actions and lineage.

### 3. The best Huntboard material already exists, but it is trapped inside the wrong product framing

**Severity:** High

`apps/desktop/src/features/forensics/ForensicsRiverView.tsx` already presents a serious
operator-facing execution canvas: live/replay action flow, agents, detectors, incidents, policies,
causal links, and session awareness. This is exactly the sort of surface Huntronomer needs, but it
should sit behind a `Fork Hunt` / `Assign Swarm` transition rather than acting as a top-level
"nexus" module.

### 4. Swarm supervision exists, but it is separated from signal discovery

**Severity:** Medium

`apps/desktop/src/features/openclaw/OpenClawFleetView.tsx` has gateway management, node inventory,
approval queues, and direct `system.run` invocation. That is strong runtime machinery, but it is
currently detached from any source signal or hunt context. Huntronomer has to bind that runtime
surface to a selected signal, hunt scope, and proof chain. There is also a transport caveat: the
agent-backed OpenClaw state still behaves more like a polling loop than a true push-native event
surface, so the v1 architecture should account for partial freshness and explicit stale states.

### 5. Receipt verification is stronger in the backend than in the UI

**Severity:** Medium

The desktop backend already exposes receipt verification and receipt-oriented Tauri commands, but
the current `ReceiptPanel` still frames key proof actions as unavailable or placeholder behavior.
Huntronomer should close that gap early, because proof credibility is one of the product's
defining claims.

### 6. The current visual system is inconsistent with the target premium identity

**Severity:** Medium

The restored app mixes SDR naming, demo-scene metaphors, and a newer Huntronomer launch overlay.
The product spec calls for an obsidian / graphite / muted-gold / restrained-crimson "threat
observatory" look. Huntronomer needs one coherent UI language across the shell, wire, Huntboard,
proof surfaces, and profile/case layers.

### 7. The app lacks a formal domain layer for typed network objects

**Severity:** High

The codebase currently models daemon events, OpenClaw runtime state, and view-local data, but there
is no durable `Huntronomer` domain layer that can normalize signals, hunts, receipts, briefs,
watchlists, visibility, citations, or reputation. That missing layer is the main architectural gap.

## Keep / Refactor / Retire

| Status | Areas | Notes |
| --- | --- | --- |
| Keep | `src/shell/**`, `src/services/tauri.ts`, `src/context/OpenClaw*` | Strong platform foundation |
| Keep, but rename / reframe | `src/features/forensics/**`, `src/features/events/**` | Good surfaces, wrong product framing |
| Refactor heavily | `src/shell/plugins/registry.tsx`, `src/features/cyber-nexus/**` | Current IA and branding do not match Huntronomer |
| Demote or remove | standalone demo views such as `Threat Radar`, `Swarm Map`, `Marketplace`, `Workflows` as first-class home surfaces | Some ideas may survive as secondary Huntboard or analysis modes, but not as peer top-level product identities |

## Architectural Conclusions

1. The first refactor should be structural, not cosmetic. Renaming screens alone will not produce
   Huntronomer.
2. The wire object model needs to be designed before the flagship UI is rebuilt.
3. The forensics river should be treated as the Huntboard engine, not as a branding motif.
4. Receipt verification and replay need to move closer to the operator workflow, especially the
   `Signal -> Hunt -> Receipt` path.
5. The session-first shell can remain, but it has to serve object flows and watchlists rather than
   a collection of technology demos.
6. The final IA should collapse the current plugin set into a small number of surfaces with
   consistent subordinate panels and tabs.
