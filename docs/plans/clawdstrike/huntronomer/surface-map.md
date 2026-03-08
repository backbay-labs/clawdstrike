# Huntronomer Surface Map

> **Status:** Draft | **Date:** 2026-03-07
> **Purpose:** Translate the product spec into concrete desktop surfaces and panel responsibilities

## 1. Signal Wire

The Signal Wire is the default landing experience and the growth surface for the product. It should
feel like a structured live wire, not a social feed and not a dashboard grid.

### Layout

- top command strip
- left rail
- watchlists pane
- center typed feed
- right context pane
- optional bottom pulse tape

### Top Command Strip

Contains:

- workspace selector
- live state badge
- omnibox
- time filter
- watched scope picker
- layout mode toggle
- notifications
- profile menu

Commands the omnibox must support:

- open signal / hunt / receipt / brief / case / profile
- jump to watched technique or sector
- `fork-hunt`
- `assign-swarm`
- `open-replay`
- `create-brief`

### Left Rail

Primary destinations:

- Wire
- Huntboard
- Cases
- Vault
- Rules
- Profile
- Settings

This should replace the current long plugin registry in `src/shell/plugins/registry.tsx`.

### Watchlists Pane

Tracks:

- followed users and teams
- MITRE techniques
- malware families
- sectors
- organizations
- infrastructure clusters
- saved feeds
- challenge subscriptions

This pane is what makes the wire personalized without turning the product into generic social media.

### Center Feed

v1 feed objects:

- Signal
- Hunt
- Receipt
- Brief

Each row must show:

- object type
- title
- summary
- severity and confidence
- source
- tags
- linked entities
- linked proof or swarm status where present
- object-specific actions

### Right Context Pane

Selection-aware preview for the active row. It should show enough detail to support triage and
action without forcing a full navigation.

Examples:

- selected `Signal` -> related entities, related hunts, similar receipts
- selected `Hunt` -> swarm status, last evidence, quick open to Huntboard
- selected `Receipt` -> signer, outcome, policy version, replay link

### Bottom Pulse Tape

Optional for v1, valuable if it can remain calm:

- new validations
- swarm launches
- receipt emissions
- major denials
- challenge completions

## 2. Huntboard

The Huntboard is where Huntronomer earns the operator-console identity. It should open with
preserved context after `Fork Hunt` or `Assign Swarm`.

### Required Subviews

- `Atlas`: entity and evidence topology
- `Flow`: active swarm execution and branch flow
- `Timeline`: ordered findings, denials, approvals, and pivots
- `Replay`: run playback and comparison

### Supporting Panels

- hunt queue / index
- center canvas
- right inspector
- bottom signal or proof tape

### Current Reuse Path

Current files that should seed this surface:

- `src/features/forensics/ForensicsRiverView.tsx`
- `src/features/forensics/components/**`
- `src/features/openclaw/OpenClawFleetView.tsx`

## 3. Receipt Vault / Replay Lens

This surface is the proof differentiator. It should let the operator answer:

- what happened
- under what policy
- who signed it
- what evidence exists
- what changed across runs

### Required Capabilities

- receipt list and filters
- rich receipt detail
- signer and policy lineage
- replay entry point
- compare two runs or receipts
- explicit redaction and visibility indicators

### Current Reuse Path

- `src/features/events/EventStreamView.tsx`
- `src/features/events/components/ReceiptPanel.tsx`
- `src/services/tauri.ts`

## 4. Case Room / Profile

This surface stores durable promoted work and reputation-bearing identity.

### Case Room

Must support:

- promoted hunts
- evidence and receipt bundles
- authored summaries
- citations
- validation or challenge history

### Profile

Must support:

- operator or team identity
- public / team / private work split
- lightweight reputation rollup
- followed scopes
- authored briefs, hunts, and validations

## 5. Design Notes

Visual language:

- obsidian and graphite base
- muted gold structure
- restrained crimson alerts
- premium density
- sharp hierarchy, not card sprawl

Behavioral language:

- typed objects over posts
- keyboard traversal over mouse-only browsing
- lineage visible from every important surface
- actions named `Validate`, `Challenge`, `Watch`, `Fork Hunt`, `Assign Swarm`, `Cite`, `Promote`
