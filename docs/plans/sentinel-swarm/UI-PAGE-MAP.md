# Sentinel Swarm — UI/UX Page Map

> Page-by-page design specification for the evolved Clawdstrike Workbench.
> Companion to [INDEX.md](./INDEX.md).

**Status:** Design phase
**Date:** 2026-03-12
**Branch:** `feat/sentinel-swarm`

---

## Table of Contents

1. [Route Map](#1-route-map)
2. [Overview Page](#2-overview-page)
3. [Sentinels Page](#3-sentinels-page)
4. [Findings Page](#4-findings-page)
5. [Intel Page](#5-intel-page)
6. [Swarms Page](#6-swarms-page)
7. [Speakeasy Panel](#7-speakeasy-panel)
8. [Navigation Evolution](#8-navigation-evolution)
9. [Component Reuse](#9-component-reuse)
10. [Design Tokens](#10-design-tokens)

---

## 1. Route Map

### Complete Route Table

| Route | Old Route | Status | Page | Lazy Chunk |
|-------|-----------|--------|------|------------|
| `/overview` | `/home` | **Evolve** | Sentinel-aware dashboard | `overview-page` |
| `/sentinels` | (new) | **New** | Sentinel list | `sentinel-page` |
| `/sentinels/:id` | (new) | **New** | Sentinel detail | `sentinel-detail` |
| `/sentinels/create` | (new) | **New** | Create sentinel wizard | `sentinel-create` |
| `/findings` | (new, absorbs `/hunt` investigate tab) | **New** | Findings triage list | `findings-page` |
| `/findings/:id` | (new) | **New** | Finding detail | `finding-detail` |
| `/intel` | (new, absorbs `/hunt` patterns tab) | **New** | Intel library | `intel-page` |
| `/intel/:id` | (new) | **New** | Intel detail + provenance | `intel-detail` |
| `/swarms` | (new) | **New** | Swarm list | `swarm-page` |
| `/swarms/:id` | (new) | **New** | Swarm detail + trust graph | `swarm-detail` |
| `/editor` | `/editor` | **Keep** | Policy YAML/visual editor | `policy-editor` |
| `/simulator` | `/simulator` | **Keep** | Threat Lab | `simulator-layout` |
| `/hunt` | `/hunt` | **Evolve** | Signal stream + baselines (stream/baselines tabs only) | `hunt-layout` |
| `/compare` | `/compare` | **Keep** | Side-by-side policy diffs | `compare-layout` |
| `/compliance` | `/compliance` | **Keep** | Regulatory framework coverage | `compliance-dashboard` |
| `/receipts` | `/receipts` | **Keep** | Receipt inspector | `receipt-inspector` |
| `/delegation` | `/delegation` | **Keep** (phase 2: extend with reputation edges) | Delegation graph | `delegation-page` |
| `/approvals` | `/approvals` | **Keep** (phase 2: Speakeasy integration) | Approval queue | `approval-queue` |
| `/hierarchy` | `/hierarchy` | **Keep** | Scoped policy tree | `hierarchy-page` |
| `/fleet` | `/fleet` | **Evolve** | Agent dashboard, sentinel registration column added | `fleet-dashboard` |
| `/audit` | `/audit` | **Keep** | Event log | `audit-log` |
| `/guards` | `/guards` | **Keep** | Guard reference catalog | `guards-page` |
| `/library` | `/library` | **Keep** | Policy templates + catalog | `library-gallery` |
| `/settings` | `/settings` | **Evolve** | General prefs + Speakeasy identity management | `settings-page` |

### Route Changes Summary

- **`/home` renamed to `/overview`** — reflects shift from policy-centric dashboard to sentinel-centric command center. Redirect `/home` to `/overview` for backward compatibility.
- **`/hunt` narrowed** — the Investigate tab moves to `/findings`, the Patterns tab moves to `/intel`. Hunt retains Stream and Baselines only, reframed as the raw signal viewer.
- **5 new route families** — `/sentinels`, `/findings`, `/intel`, `/swarms`, and their sub-routes.
- **All existing routes preserved** — no pages removed. Policy, Governance, and Infrastructure sections are untouched.

### Provider Stack Change

```tsx
// New provider wrapping the existing stack:
<SentinelSwarmProvider>      {/* sentinel-store + swarm-store + speakeasy-bridge */}
  <MultiPolicyProvider>
    <FleetConnectionProvider>
      {/* ... existing providers ... */}
    </FleetConnectionProvider>
  </MultiPolicyProvider>
</SentinelSwarmProvider>
```

---

## 2. Overview Page

**Route:** `/overview`
**Evolves:** `home-page.tsx` (currently `HomePage`)
**Layout:** Single-column, max-width container (`max-w-5xl`), vertically scrolling

### Wireframe

```
┌─────────────────────────────────────────────────────────┐
│  SENTINEL HEALTH RING        Policy Identity            │
│  ┌──────────┐                ClawdStrike Strict v1.2.0  │
│  │  4 / 4   │                4 active sentinels         │
│  │ sentinels│                12 findings (3 critical)   │
│  │  active  │                2 swarms connected         │
│  └──────────┘                                           │
├─────────────────────────────────────────────────────────┤
│  SENTINEL HEALTH CARDS                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Watcher  │ │ Hunter   │ │ Curator  │ │ Liaison  │  │
│  │ "Aegis"  │ │ "Prowl"  │ │ "Scribe" │ │ "Herald" │  │
│  │ ● active │ │ ● active │ │ ○ paused │ │ ● active │  │
│  │ 42 sig/h │ │ 3 hunt/d │ │ 7 find   │ │ 2 swarms │  │
│  │ [sigil]  │ │ [sigil]  │ │ [sigil]  │ │ [sigil]  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
├─────────────────────────────────────────────────────────┤
│  ACTIVE FINDINGS              SIGNAL RATE               │
│  ┌────────────────────────┐   ┌────────────────────┐   │
│  │ ● 3 critical           │   │ ▁▂▃▅▇▆▄▃▂▅▇▅▃▂▁  │   │
│  │ ● 5 high               │   │ 142 signals/hour   │   │
│  │ ● 4 medium             │   │ ↑ 12% vs baseline  │   │
│  │ → View all findings    │   │                    │   │
│  └────────────────────────┘   └────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  SWARM ACTIVITY FEED                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 2m ago  Intel received: "CVE-2026-1234 pattern" │   │
│  │ 5m ago  Sentinel "Herald" joined swarm "SecOps" │   │
│  │ 12m ago Finding promoted to intel by "Scribe"   │   │
│  │ 1h ago  New detection rule from "ACME Swarm"    │   │
│  └─────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  GUARD COVERAGE (existing matrix, unchanged)            │
│  ┌─ Filesystem ─┐ ┌─ Network ─┐ ┌─ Content ─┐        │
│  │ ...          │ │ ...       │ │ ...       │        │
│  └──────────────┘ └───────────┘ └───────────┘        │
├─────────────────────────────────────────────────────────┤
│  NAVIGATE (existing nav cards, extended)                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐               │
│  │Sentinels │ │ Findings │ │  Intel   │               │
│  │ 4 active │ │ 12 open  │ │ 8 items  │               │
│  └──────────┘ └──────────┘ └──────────┘               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐               │
│  │  Swarms  │ │  Editor  │ │  Fleet   │               │
│  │ 2 joined │ │ 3 tabs   │ │ 6 agents │               │
│  └──────────┘ └──────────┘ └──────────┘               │
└─────────────────────────────────────────────────────────┘
```

### Section Details

**Sentinel Health Ring** — Replaces the current `HealthRing` guard-count arc. New ring shows `active/total` sentinels. The guard coverage arc moves down to the Guard Coverage section. If no sentinels are configured, falls back to the existing guard health ring (graceful degradation for pre-sentinel users).

**Sentinel Health Cards** — Horizontal card row (CSS grid, `grid-cols-2 lg:grid-cols-4`). Each card shows:
- Sentinel name and mode badge (watcher/hunter/curator/liaison)
- Sigil icon derived from sentinel identity fingerprint (reuse `@backbay/speakeasy` sigil derivation)
- Status dot (green=active, amber=paused, gray=retired)
- Key metric: signals/hour for watchers, hunts/day for hunters, findings curated for curators, swarms connected for liaisons
- Click navigates to `/sentinels/:id`

**Active Findings Count** — Stacked severity bars showing open finding counts by severity. Uses the existing `SEVERITY_COLORS` palette from `investigation.tsx`. Click navigates to `/findings`.

**Signal Rate Sparkline** — 24-point SVG sparkline (one point per hour, trailing 24h). Shows current signals/hour rate and percentage change versus the rolling 7-day baseline. Reuses the sparkline rendering approach from the existing `baselines.tsx` hourly activity chart.

**Swarm Activity Feed** — Reverse-chronological list of swarm events (max 10 visible, scroll for more). Each entry: relative timestamp, event icon, one-line summary. Event types: intel received, intel published, sentinel joined/left, finding promoted, detection rule distributed, speakeasy message received. Only appears if at least one swarm is configured; otherwise this section is hidden.

**Guard Coverage** — Existing guard coverage matrix from `HomePage`, moved below the sentinel sections. No changes to the `GuardTile` component.

**Navigate** — Existing `NavCard` grid extended with Sentinels, Findings, Intel, Swarms cards. Each card shows a live count. Existing cards (Editor, Threat Lab, Compliance, Approvals, Fleet, Library) retained.

### Component Mapping

| Section | Existing Component | Action |
|---------|-------------------|--------|
| Sentinel Health Ring | `HealthRing` in `home-page.tsx` | Fork — new data source (sentinel count vs guard count) |
| Sentinel Health Cards | (none) | New — `SentinelHealthCard` |
| Active Findings | (none) | New — `FindingSeverityStack` |
| Signal Rate Sparkline | Hourly chart in `baselines.tsx` | Extract sparkline renderer as shared component |
| Swarm Activity Feed | (none) | New — `SwarmActivityFeed` |
| Guard Coverage | `GuardTile` + category grid in `home-page.tsx` | Reuse as-is |
| Navigate | `NavCard` in `home-page.tsx` | Extend with new cards |

---

## 3. Sentinels Page

### 3a. Sentinel List

**Route:** `/sentinels`
**Layout:** Full-width, header + filter bar + scrolling card grid or table

```
┌─────────────────────────────────────────────────────────┐
│  HEADER                                                 │
│  Sentinels          [+ Create Sentinel]  [⟳ Refresh]   │
│  4 active · 1 paused · 0 retired                       │
├─────────────────────────────────────────────────────────┤
│  FILTER BAR                                             │
│  [All Modes ▾] [All Status ▾] [Search...]              │
├─────────────────────────────────────────────────────────┤
│  SENTINEL CARDS (grid-cols-1 lg:grid-cols-2)            │
│  ┌────────────────────────────┐ ┌──────────────────────┐│
│  │ [sigil] Aegis              │ │ [sigil] Prowl        ││
│  │ ● Watcher · Active        │ │ ● Hunter · Active    ││
│  │ Goal: Monitor file access  │ │ Goal: Weekly recon   ││
│  │ Source: Fleet audit events │ │ Schedule: Mon 02:00  ││
│  │                            │ │                      ││
│  │ ▁▂▅▇▃▂ 142 sig/h         │ │ Last run: 2h ago     ││
│  │ 3 findings · 1 promoted   │ │ 1 finding · 0 intel  ││
│  │ Memory: 12 patterns       │ │ Memory: 4 patterns   ││
│  │                            │ │                      ││
│  │ Swarms: SecOps, ACME      │ │ Swarms: SecOps       ││
│  └────────────────────────────┘ └──────────────────────┘│
│  ┌────────────────────────────┐ ┌──────────────────────┐│
│  │ [sigil] Scribe             │ │ [sigil] Herald       ││
│  │ ○ Curator · Paused        │ │ ● Liaison · Active   ││
│  │ ...                        │ │ ...                  ││
│  └────────────────────────────┘ └──────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

**Sentinel Card contents:**
- **Header row:** Sigil (24px, colored by fingerprint) + name + edit button (icon only)
- **Status row:** Status dot + mode badge + status label
- **Goal summary:** First goal's description, truncated to one line
- **Source/Schedule:** Data source for watchers; cron schedule (human-readable) for hunters
- **Metrics row:** Mini sparkline + signals/hour (watchers), last run time (hunters), findings curated count (curators), swarms connected (liaisons)
- **Findings/Intel counts:** "N findings, M promoted to intel"
- **Memory indicator:** "N patterns in memory"
- **Swarm tags:** Pill badges for each swarm membership

**Filter bar** — Reuses the filter pattern from `approval-queue.tsx`: `FilterSelect` dropdowns for mode (watcher/hunter/curator/liaison/all) and status (active/paused/retired/all), plus a text search input.

### 3b. Create Sentinel Flow

**Route:** `/sentinels/create`
**Layout:** Centered card (max-width `max-w-2xl`), multi-step wizard

**Steps:**

1. **Mode Selection** — Four cards in a 2x2 grid, each with mode icon, name, one-line description. Click selects and highlights with gold border. Modes:
   - Watcher (icon: `IconEye`) — "Continuous monitoring and anomaly detection"
   - Hunter (icon: `IconSearch`) — "Exploratory or scheduled threat hunts"
   - Curator (icon: `IconBrain`) — "Group signals, summarize findings, promote patterns"
   - Liaison (icon: `IconUsers`) — "Participate in swarms and exchange intel"

2. **Identity & Goal** — Form fields:
   - Name (text input, required)
   - Description (text area, optional)
   - Goal definition (structured form):
     - Goal type dropdown: detect / hunt / monitor / enrich
     - Description (text)
     - Escalation threshold (slider: 0.0-1.0 confidence before auto-promoting to Finding)
   - Add Goal button for multiple goals

3. **Source Binding** — depends on mode:
   - Watcher: select data sources (fleet audit events, guard results, external feed URL)
   - Hunter: select scope (fleet agents, specific agent IDs, IP ranges) + cron schedule picker
   - Curator: select which sentinels to curate (checkboxes from existing sentinel list)
   - Liaison: select swarms to join (checkboxes from existing swarm list, or create new)

4. **Policy & Review** — Policy selection (dropdown of loaded policies or "inherit from parent"), review summary card showing all choices. Generate button creates sentinel and navigates to `/sentinels/:id`.

**Identity generation** happens automatically on step 2: the sentinel receives an Ed25519 keypair (generated via the same path as `@backbay/speakeasy` `generateIdentity()`), and the derived sigil + fingerprint are shown in the review card.

### 3c. Sentinel Detail View

**Route:** `/sentinels/:id`
**Layout:** Two-column: main content (left, 65%) + sidebar panel (right, 35%)

```
┌────────────────────────────────┬────────────────────────┐
│  SENTINEL HEADER               │  STATS SIDEBAR         │
│  [sigil] Aegis                 │                        │
│  ● Watcher · Active            │  Lifetime              │
│  Fingerprint: a3f2...8c1d      │  Created: Mar 1        │
│  [Pause] [Edit] [Retire]       │  Uptime: 11d 4h        │
│                                │  Signals: 14,231       │
│                                │  Findings: 23          │
│                                │  Intel: 5              │
│                                │                        │
│                                │  Last 24h              │
│                                │  Signals: 3,412        │
│                                │  Anomalies: 47         │
│                                │  Findings created: 2   │
│                                │                        │
│                                │  Memory                │
│                                │  Patterns: 12          │
│                                │  Baselines: 6 agents   │
│                                │  False positives: 3    │
│                                │                        │
│                                │  Swarms                │
│                                │  ● SecOps (contributor)│
│                                │  ● ACME (observer)     │
├────────────────────────────────┤                        │
│  TABS: [Signal Stream] [Goals] │                        │
│        [Memory] [Config]       │                        │
├────────────────────────────────┤                        │
│  TAB CONTENT                   │                        │
│  (see below)                   │                        │
│                                │                        │
└────────────────────────────────┴────────────────────────┘
```

**Signal Stream tab** — Filtered version of the hunt `ActivityStream` component, pre-filtered to `source.sentinelId === sentinel.id`. Shows only this sentinel's signals. Reuses the existing `ActivityStream` component with a fixed filter prop.

**Goals tab** — List of `SentinelGoal` objects. Each goal is an editable card: goal type badge, description, data sources as pills, pattern references, escalation threshold slider. Add/remove/reorder goals.

**Memory tab** — Three sections:
- Known patterns table (from `SentinelMemory.knownPatterns`): name, match count, last matched, source (local/swarm)
- Baseline profiles: mini cards per agent showing hourly activity sparklines (reuse `baselines.tsx` chart components)
- False positive hashes: simple list with remove button

**Config tab** — Policy assignment, schedule editor, swarm membership management, identity details (public key, fingerprint, sigil preview, seed phrase reveal behind confirmation).

---

## 4. Findings Page

### 4a. Findings List

**Route:** `/findings`
**Evolves:** Hunt Lab's Investigate tab (`investigation.tsx`)
**Layout:** Full-width, header + filter bar + list with optional detail drawer

```
┌─────────────────────────────────────────────────────────┐
│  HEADER                                                 │
│  Findings                                               │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
│  │Emrg 7│ │Conf 5│ │Prom 3│ │Dism 2│ │FP  1 │        │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘        │
├─────────────────────────────────────────────────────────┤
│  FILTER BAR                                             │
│  [All Status ▾] [All Severity ▾] [All Sentinels ▾]    │
│  [Search...]                           [Sort: newest ▾]│
├──────────────────────────────────┬──────────────────────┤
│  FINDINGS LIST                   │  DETAIL DRAWER       │
│  ┌──────────────────────────┐   │  (visible when a     │
│  │ ● CRIT  Emerging         │   │   finding is         │
│  │ SSH key exfiltration     │   │   selected)          │
│  │ attempt via network      │   │                      │
│  │ egress                   │   │  See §4b below       │
│  │ Sentinel: Aegis · 12 sig│   │                      │
│  │ Confidence: 0.87         │   │                      │
│  │ 2h ago                   │   │                      │
│  │ [Confirm] [Dismiss]      │   │                      │
│  ├──────────────────────────┤   │                      │
│  │ ● HIGH  Confirmed        │   │                      │
│  │ Unusual bulk file reads  │   │                      │
│  │ across /etc/...          │   │                      │
│  │ Sentinel: Prowl · 8 sig │   │                      │
│  │ [Promote to Intel] [FP] │   │                      │
│  ├──────────────────────────┤   │                      │
│  │ ...                      │   │                      │
│  └──────────────────────────┘   │                      │
└──────────────────────────────────┴──────────────────────┘
```

**Status summary badges** — Reuses `SummaryBadge` pattern from `approval-queue.tsx`. One badge per finding status: emerging (amber pulse), confirmed (gold), promoted (green), dismissed (muted), false_positive (muted). Clicking a badge filters to that status.

**Finding Card contents (list item):**
- Severity dot (uses `SEVERITY_COLORS` from `investigation.tsx`)
- Status badge (emerging/confirmed/promoted/dismissed/false_positive)
- Title (one line, truncated)
- Signal count and contributing sentinel name
- Confidence score (0.0-1.0, shown as percentage)
- Relative timestamp
- **Triage actions (inline, only for actionable states):**
  - Emerging: [Confirm] [Dismiss]
  - Confirmed: [Promote to Intel] [Mark False Positive]
  - Promoted: (no actions — read-only, shows intel link)

**Triage workflow:**
```
Emerging → Confirm → Confirmed → Promote → Promoted
                  └→ Dismiss  → Dismissed
         → False Positive
```

**Sort options:** Newest first (default), severity (critical first), confidence (highest first), signal count (most first).

**Filter bar** — Status (all / emerging / confirmed / promoted / dismissed / false_positive), Severity (all / critical / high / medium / low), Sentinel (all / per-sentinel dropdown), text search across title and annotation text.

### 4b. Finding Detail

**Route:** `/findings/:id`
**Layout:** Two-panel — main timeline (left, 60%) + enrichment sidebar (right, 40%)

```
┌────────────────────────────────┬────────────────────────┐
│  FINDING HEADER                │  ENRICHMENT SIDEBAR    │
│  SSH key exfiltration attempt  │                        │
│  ● CRIT · Emerging · 0.87     │  MITRE ATT&CK         │
│  Sentinel: Aegis               │  T1048 - Exfiltration │
│  [Confirm] [Dismiss] [FP]     │  Over Alt Protocol     │
│                                │                        │
│  SIGNAL TIMELINE               │  IOCs                  │
│  ┌──────────────────────────┐ │  ● 192.168.1.42       │
│  │ ──●── 14:32 Signal #1    │ │  ● /root/.ssh/id_rsa  │
│  │  │    file_access         │ │  ● evil.example.com   │
│  │  │    /root/.ssh/id_rsa   │ │                        │
│  │  │    anomaly: 0.92       │ │  RELATED FINDINGS     │
│  │  │                        │ │  ● Unusual network    │
│  │ ──●── 14:33 Signal #2    │ │    egress (confirmed) │
│  │  │    network_egress      │ │                        │
│  │  │    evil.example.com    │ │  PROVENANCE            │
│  │  │    anomaly: 0.88       │ │  Receipt: abc123...   │
│  │  │                        │ │  Signed by: Aegis     │
│  │ ──●── 14:34 Signal #3    │ │  Fingerprint: a3f2... │
│  │  │    ...                 │ │  [Verify] [Export]    │
│  │  │                        │ │                        │
│  │ ──●── 14:35 Finding       │ │                        │
│  │       created (auto)      │ │                        │
│  └──────────────────────────┘ │                        │
│                                │                        │
│  ANNOTATION THREAD             │                        │
│  ┌──────────────────────────┐ │                        │
│  │ [avatar] Analyst · 1h ago │ │                        │
│  │ Confirmed via manual log  │ │                        │
│  │ review. Pattern matches   │ │                        │
│  │ previous incident.        │ │                        │
│  │                            │ │                        │
│  │ [sigil] Aegis · 45m ago   │ │                        │
│  │ Correlated with 3 addtl   │ │                        │
│  │ signals from agent-07.    │ │                        │
│  │                            │ │                        │
│  │ [+ Add annotation...]     │ │                        │
│  └──────────────────────────┘ │                        │
│                                │                        │
│  PROMOTE TO INTEL              │                        │
│  [Create Intel from Finding →] │                        │
└────────────────────────────────┴────────────────────────┘
```

**Signal Timeline** — Vertical timeline with connected dots. Each signal entry shows:
- Timestamp
- Signal type badge (anomaly/detection/indicator/policy_violation/behavioral)
- Action type icon (reuse `ACTION_TYPE_ICONS` from `activity-stream.tsx`)
- Target path or domain
- Anomaly score bar (thin horizontal fill, color-coded by severity)
- Expandable detail showing full `SignalData` payload

The timeline is the evolution of the event list in `InvestigationWorkbench`. The existing `eventIds` array on `Investigation` maps directly to `signalIds` on `Finding`.

**Enrichment Sidebar** — Stacked sections:
- MITRE ATT&CK mapping (technique ID + name + tactic, clickable link)
- IOCs extracted from signal data (IPs, domains, file paths, hashes)
- Related Findings (other findings sharing signals or agents, clickable)
- Provenance (receipt ID, signing identity, fingerprint, verify/export buttons)

**Annotation Thread** — Chronological list of human and sentinel annotations. Each annotation shows: author avatar (user icon) or sigil (sentinel), author name, relative timestamp, text body. New annotation input at bottom with submit button. Reuses the annotation model from `Investigation.annotations` (same `Annotation` type, extended with `authorType: "human" | "sentinel"`).

**Promote to Intel** — Button at the bottom of the main column. Opens the Intel creation flow (see section 5) pre-populated with the finding's data.

---

## 5. Intel Page

### 5a. Intel Library

**Route:** `/intel`
**Evolves:** Hunt Lab's Patterns tab + Library gallery concept
**Layout:** Full-width, tabbed header (Local / Swarm-Sourced), filter bar, card grid

```
┌─────────────────────────────────────────────────────────┐
│  HEADER                                                 │
│  Intel Library        [+ Create Intel]  [Import...]     │
│  [Local (8)] [Swarm-Sourced (14)]                      │
├─────────────────────────────────────────────────────────┤
│  FILTER BAR                                             │
│  [All Types ▾] [All Tags ▾] [Search...]                │
├─────────────────────────────────────────────────────────┤
│  INTEL CARDS (grid-cols-1 md:grid-cols-2 lg:grid-cols-3)│
│  ┌──────────────────┐ ┌──────────────────┐              │
│  │ Detection Rule    │ │ IOC Bundle       │              │
│  │ "SSH Exfil Chain" │ │ "CVE-2026-1234"  │              │
│  │                   │ │                   │              │
│  │ Derived from: 2   │ │ Source: ACME      │              │
│  │ findings           │ │ Swarm             │              │
│  │ Confidence: 0.92  │ │ Confidence: 0.88  │              │
│  │ MITRE: T1048      │ │ Tags: cve, rce    │              │
│  │                   │ │                   │              │
│  │ ● Private         │ │ ● Swarm-shared    │              │
│  │ [sigil] Aegis     │ │ [sigil] External  │              │
│  │ Signed ✓          │ │ Verified ✓        │              │
│  └──────────────────┘ └──────────────────┘              │
└─────────────────────────────────────────────────────────┘
```

**Tabs:**
- **Local** — Intel artifacts created by the user's sentinels or manually. Full CRUD.
- **Swarm-Sourced** — Intel received from swarm peers. Read-only with import-to-local action.

**Intel Card contents:**
- Type badge (detection_rule / pattern / ioc / campaign / advisory / policy_patch) with distinct icon per type
- Title
- Source line: "Derived from N findings" (local) or "Source: Swarm Name" (swarm-sourced)
- Confidence score
- MITRE technique tags (if applicable)
- General tags as pills
- Shareability indicator: private (lock icon), swarm (group icon), public (globe icon)
- Author sigil + name
- Signature verification status (checkmark or warning)

**Filter bar:** Type dropdown, tag multi-select, text search.

### 5b. Intel Detail + Provenance

**Route:** `/intel/:id`
**Layout:** Two-column — content (left, 65%) + provenance viewer (right, 35%)

**Left column:**
- Header: type badge, title, description
- Content section (varies by type):
  - detection_rule: YAML/JSON editor (read-only for swarm-sourced, editable for local)
  - pattern: `PatternStep[]` sequence visualization (reuse pattern-mining step rendering)
  - ioc: table of indicators (type, value, first seen, last seen)
  - campaign: narrative text + linked findings timeline
  - advisory: rich text summary
  - policy_patch: diff view (reuse `CompareLayout` diff rendering)
- Derived From section: linked finding cards (clickable to `/findings/:id`)
- MITRE mapping section
- Tags (editable for local, read-only for swarm-sourced)

**Right column — Provenance Viewer:**
- Signature block: author identity (sigil + fingerprint), Ed25519 signature bytes (truncated with expand), verification status
- Receipt chain: linked `SignedReceipt` with verify button
- Source trail: if swarm-sourced, shows the chain — original author, swarm it traveled through, hop count
- Timestamps: created, last verified, received (for swarm-sourced)

### 5c. Create from Finding

Triggered from `/findings/:id` promote action. Opens `/intel/create` with pre-populated fields:

- Type auto-suggested based on finding content (pattern if finding has behavioral signals, ioc if finding has file/network indicators)
- Title pre-filled from finding title
- Derived findings pre-linked
- Confidence inherited from finding
- MITRE mappings carried over from finding enrichment

### 5d. Share to Swarm

From intel detail page, the "Share" button opens a modal:
- Select target swarms (checkboxes of joined swarms)
- Shareability level: swarm (default) or public
- Confirmation showing what will be shared (summary, not raw evidence)
- Share action signs the intel artifact with the author's key and publishes to the swarm's Gossipsub `intel` topic

### 5e. Import from Swarm

On the Swarm-Sourced tab, each card has an "Import to Local" action that:
- Copies the intel artifact to local storage
- Preserves the original signature and provenance chain
- Marks it as imported with source attribution
- Allows local editing (creates a fork, original provenance maintained)

---

## 6. Swarms Page

### 6a. Swarm List

**Route:** `/swarms`
**Layout:** Full-width, header + card list

```
┌─────────────────────────────────────────────────────────┐
│  HEADER                                                 │
│  Swarms                              [+ Create Swarm]   │
│  2 active · 1 pending invite                           │
├─────────────────────────────────────────────────────────┤
│  SWARM CARDS                                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │  ◆ SecOps Collective                 [Personal]  │   │
│  │  4 members · 12 shared detections · 3 speakeasies│   │
│  │                                                   │   │
│  │  MEMBERS        RECENT INTEL        SPEAKEASIES  │   │
│  │  [sigil] Aegis  "SSH Exfil Rule"    #incident-01 │   │
│  │  [sigil] Prowl  "CVE-2026-1234"     #campaign-q1 │   │
│  │  [sigil] alice  "Bulk Read Pattern"  #general     │   │
│  │  +1 more        +9 more                           │   │
│  │                                                   │   │
│  │  [Enter Swarm →]                                  │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  ◆ ACME Threat Intel Exchange       [Trusted]    │   │
│  │  12 members · 34 shared detections · 1 speakeasy │   │
│  │  ...                                              │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

**Swarm Card contents:**
- Swarm name + type badge (personal/trusted/federated, colored per design tokens)
- Member count, shared detection count, speakeasy count
- Preview rows: top 3 members (sigil + name), top 3 recent intel titles, speakeasy room names
- "Enter Swarm" button navigates to `/swarms/:id`

### 6b. Create Swarm Flow

**Route:** Modal overlay from `/swarms`
**Layout:** Centered dialog (`max-w-lg`)

**Steps (single-page form, not wizard):**
1. Name (text input)
2. Type selection: Personal / Trusted / Federated (radio cards with descriptions)
   - Personal: "Your own sentinels coordinating locally"
   - Trusted: "Invite team members and peers"
   - Federated: "Open to cross-organization participation"
3. Governance policies (toggles):
   - Require signatures on all shared artifacts (default: on)
   - Auto-share confirmed detections (default: off)
   - Compartmentalized by default (default: on for trusted/federated, off for personal)
   - Minimum reputation to publish (slider, 0-100, default: 0 for personal)
4. Initial members: Add sentinel IDs or invite by fingerprint
5. Create button

### 6c. Swarm Detail

**Route:** `/swarms/:id`
**Layout:** Full-width with tabbed sub-navigation

**Tabs: [Members] [Shared Detections] [Trust Graph] [Speakeasies] [Settings]**

**Members tab:**
- Table of swarm members (columns: sigil, name/fingerprint, type sentinel/operator, role admin/contributor/observer, reputation score, joined date)
- Invite button (opens modal with fingerprint input or QR code)
- Role management dropdown (admin only)
- Reuses the sortable table pattern from `fleet-dashboard.tsx` (`SortableHeader` + expandable rows)

**Shared Detections tab:**
- Feed of intel artifacts shared to this swarm, reverse-chronological
- Each item: type badge, title, author sigil + name, shared timestamp, confidence, verification status
- "Import to Local" button on each item
- "Publish Intel" button at top to share from local library

**Trust Graph tab:**
- Force-directed graph visualization showing trust relationships between swarm members
- **Reuses the `force-graph-engine.ts` layout engine and the SVG rendering from `delegation-page.tsx`**
- Node types: sentinel (sigil icon) and operator (user icon), sized by reputation score
- Edge types: trust relationship, weighted by reputation
- Edge color intensity indicates trust strength (from design tokens)
- Zoom, pan, fit controls (reuse `delegation-page.tsx` toolbar: zoom in, zoom out, fit, export SVG)
- Node click shows detail panel (member info, reputation breakdown, shared intel count)
- The graph data maps `SwarmMember` to `DelegationNode` (kind=sentinel/operator) and `TrustEdge` to `DelegationEdge`

**Speakeasies tab:**
- List of speakeasy rooms attached to this swarm
- Each room card: name, purpose badge (finding/campaign/incident/coordination/mentoring), member count, last message timestamp, classification badge (routine/sensitive/restricted)
- "Create Room" button
- Click opens the Speakeasy Panel (see section 7) inline

**Settings tab (admin only):**
- Governance policy toggles (same as creation flow, editable)
- Danger zone: leave swarm, archive swarm (admin)

---

## 7. Speakeasy Panel

### Design Decision: Slide-Over Panel (not full page)

The Speakeasy panel is a **right-side slide-over** (384px wide, `w-96`) that overlays the current page content. It can be opened from:
- Swarm detail > Speakeasies tab (click room)
- Finding detail > "Discuss in Speakeasy" action
- Overview page > Swarm activity feed (click speakeasy event)
- Global shortcut: `Cmd+Shift+E` (toggle last-opened room)

This approach keeps the user's context visible (findings, intel, swarm detail) while coordinating in the room. The panel slides in from the right edge, pushing main content slightly or overlaying with a backdrop on narrow viewports.

### Panel Layout

```
┌──────────────────────────────────────┐
│  ROOM HEADER                          │
│  ┌──┐ #incident-01          [−] [×] │
│  │◆◆│ Finding: SSH Exfil     3 mbrs │
│  └──┘ ● restricted                   │
│  ─────────────────────────────────── │
│  MEMBERS BAR                          │
│  [sigil1] [sigil2] [sigil3]  +0     │
│  ─────────────────────────────────── │
│                                       │
│  MESSAGE LIST                         │
│  ┌─────────────────────────────────┐ │
│  │ [sigil] Aegis · 14:32          │ │
│  │ ✓ Signature verified            │ │
│  │                                 │ │
│  │ Detected SSH key access from    │ │
│  │ agent-03. Anomaly score 0.92.   │ │
│  │ Pattern matches previous        │ │
│  │ incident from Feb.              │ │
│  │                                 │ │
│  │ 📎 Finding: SSH Exfil Attempt   │ │
│  ├─────────────────────────────────┤ │
│  │ [avatar] alice · 14:35         │ │
│  │ ✓ Signature verified            │ │
│  │                                 │ │
│  │ Confirmed. Let me check the     │ │
│  │ network logs.                   │ │
│  ├─────────────────────────────────┤ │
│  │ SENTINEL REQUEST · 14:37       │ │
│  │ alice → Aegis                   │ │
│  │ "Can you correlate with last    │ │
│  │  week's egress alerts?"         │ │
│  ├─────────────────────────────────┤ │
│  │ SENTINEL RESPONSE · 14:38     │ │
│  │ Aegis → alice                   │ │
│  │ "Found 3 correlated signals.    │ │
│  │  Attached as new Finding."      │ │
│  │ 📎 Finding: Correlated Egress   │ │
│  └─────────────────────────────────┘ │
│                                       │
│  MESSAGE INPUT                        │
│  ┌─────────────────────────────────┐ │
│  │ Type a message...          [↵]  │ │
│  │ [📎 Attach Finding] [🤖 Ask]   │ │
│  └─────────────────────────────────┘ │
└──────────────────────────────────────┘
```

### Room Header

- Room name (bold, `#` prefix)
- Attached-to context: if attached to a finding, shows finding title (clickable link to `/findings/:id`)
- Purpose badge: finding / campaign / incident / coordination / mentoring (color-coded per design tokens)
- Classification badge: routine (no badge) / sensitive (amber) / restricted (red)
- Member count
- Minimize button (`-`) collapses to a small tab at the right edge
- Close button (`x`) closes the panel

### Members Bar

- Horizontal row of sigils (max 5 visible + "+N" overflow)
- Each sigil: 20px circle with sigil icon, colored by fingerprint
- Hover shows name/fingerprint tooltip
- Click shows member detail popover (role, reputation, last seen)

### Message List

- Scrollable, reverse-chronological-at-bottom (chat convention: newest at bottom, auto-scroll)
- Each message shows:
  - Author sigil (sentinel) or avatar placeholder (human)
  - Author name + timestamp
  - **Signature verification badge** — green checkmark if `verifyMessage()` passes, red warning if failed, gray if unverified. Uses `@backbay/speakeasy` `verifyMessage()`.
  - Message body text
  - Finding attachment indicator: if message references a finding, shows a clickable card-style link

**Message types (from `@backbay/speakeasy`):**
- `ChatMessage` — Standard text message
- `SentinelRequest` — Human asks sentinel to investigate. Rendered with a distinct "REQUEST" header bar (gold accent)
- `SentinelResponse` — Sentinel replies to a request. Rendered with "RESPONSE" header bar (green accent). May include finding attachments.
- `PresenceMessage` — Join/leave events, shown as thin centered system messages
- `BountyCreated` / `BountyFulfilled` — Shown as system messages with distinct styling

### Sentinel Request/Response Flow

1. User clicks "Ask Sentinel" button in the message input area
2. A structured input appears: select sentinel (dropdown of sentinels in the room) + question text
3. Submitting creates a `SentinelRequest` message signed with the user's identity
4. The target sentinel processes the request asynchronously and publishes a `SentinelResponse` message signed with its identity
5. If the sentinel creates a finding during processing, the response message includes a finding attachment

### Finding Attachment Indicator

Messages can reference findings. When a finding is attached:
- A compact card appears below the message text: severity dot + finding title + status badge
- Clicking the card navigates to `/findings/:id` (the speakeasy panel remains open)

### Responsive Behavior

- **Desktop (>1280px):** Panel slides in from right, main content shrinks to accommodate
- **Tablet (768-1280px):** Panel overlays with semi-transparent backdrop, tap backdrop to close
- **Mobile (<768px):** Panel takes full width as a bottom sheet (slide up from bottom, 80% height)

---

## 8. Navigation Evolution

### Sidebar Restructure

The `DesktopSidebar` (`desktop-sidebar.tsx`) evolves from 4 sections to 5 sections. The new section structure:

```
Home (standalone link — renamed "Overview")
─────────────────
SENTINEL OPS (new section, accent: #8b5555 — warm red)
  Sentinels      /sentinels
  Findings       /findings       (badge: emerging count)
  Intel          /intel
─────────────────
SWARM (new section, accent: #55788b — teal)
  Swarms         /swarms
─────────────────
POLICY (existing, accent: #8b7355 — warm amber, unchanged)
  Editor         /editor
  Library        /library
  Guards         /guards
  Compare        /compare
─────────────────
OPS (existing, accent: #6b7b55 — sage green, evolved)
  Threat Lab     /simulator
  Signal Stream  /hunt          (renamed from "Hunt Lab")
─────────────────
GOVERNANCE (existing, accent: #7b6b8b — muted purple, unchanged)
  Compliance     /compliance
  Receipts       /receipts
  Audit          /audit
  Approvals      /approvals     (badge: pending count)
─────────────────
INFRASTRUCTURE (existing, accent: #557b8b — steel blue, unchanged)
  Delegation     /delegation
  Hierarchy      /hierarchy
  Fleet          /fleet
─────────────────
Settings (bottom standalone link)
```

### Changes from Current Sidebar

| Change | Detail |
|--------|--------|
| Home renamed to Overview | Label change, route redirect from `/home` to `/overview` |
| New "Sentinel Ops" section | Contains Sentinels, Findings, Intel — positioned at top for primacy |
| New "Swarm" section | Contains Swarms — single item for now, grows in Phase 3 |
| Hunt Lab renamed to Signal Stream | Reflects its narrowed scope (raw signal viewer, not full investigation hub) |
| Findings badge added | Shows count of emerging findings, similar to Approvals pending badge |
| Existing sections unchanged | Policy, Governance, Infrastructure sections keep all current items |

### Badge System

Two sidebar items carry live badges:
- **Findings** — count of `status === "emerging"` findings, amber pulse (mirrors the Approvals badge pattern)
- **Approvals** — unchanged, count of pending approvals

### Collapsed Sidebar Behavior

In collapsed mode (52px width), the new sections follow the existing pattern:
- Section divider is a 1px horizontal line
- Items show icon only with tooltip on hover
- Badges show as small dot on the icon (existing pattern from Approvals)

### Mobile/Responsive Considerations

The current workbench targets Tauri desktop but should be responsive-ready:
- **Sidebar:** Below 768px, sidebar collapses to an off-canvas drawer triggered by a hamburger icon in the titlebar
- **Two-column layouts** (sentinel detail, finding detail, intel detail): Stack vertically below 1024px — sidebar panel moves below main content
- **Card grids:** Use responsive columns (`grid-cols-1 md:grid-cols-2 lg:grid-cols-3`)
- **Speakeasy panel:** See section 7 responsive behavior
- **Tables** (fleet, swarm members): Horizontal scroll wrapper below 900px (existing `min-w-[900px]` pattern from fleet dashboard)

---

## 9. Component Reuse

### Reusable from Existing Codebase

| Existing Component | Location | Reuse In | Adaptation Needed |
|-------------------|----------|----------|-------------------|
| `HealthRing` | `home-page.tsx` | Overview sentinel count ring | Change data source from guard count to sentinel count |
| `NavCard` | `home-page.tsx` | Overview navigation cards | Add new card entries, no structural change |
| `GuardTile` + category grid | `home-page.tsx` | Overview guard coverage | None — reuse as-is |
| `ActivityStream` | `hunt/activity-stream.tsx` | Sentinel detail signal tab, Hunt page | Add optional `sentinelId` filter prop |
| `Baselines` chart components | `hunt/baselines.tsx` | Sentinel detail memory tab, overview sparkline | Extract sparkline as standalone `Sparkline` component |
| `InvestigationWorkbench` patterns | `hunt/investigation.tsx` | Finding detail (annotation thread, event timeline) | Restructure into Finding-specific components; reuse annotation input, severity colors, verdict options |
| `PatternMining` visualization | `hunt/pattern-mining.tsx` | Intel detail (pattern type), sentinel memory patterns tab | Extract pattern step renderer as shared component |
| Force-graph engine | `force-graph-engine.ts` | Swarm trust graph | Map `SwarmMember` → `DelegationNode`, `TrustEdge` → `DelegationEdge`; reuse layout + SVG rendering |
| SVG graph renderer + controls | `delegation-page.tsx` | Swarm trust graph tab | Extract graph viewport (zoom/pan/fit/export) as `<GraphViewport>` wrapper |
| `ApprovalCard` layout | `approval-queue.tsx` | Finding card (triage actions pattern) | Same inline-action-bar concept for Confirm/Dismiss/Promote |
| `SummaryBadge` | `approval-queue.tsx` | Findings header status counts, Overview finding counts | Reuse directly |
| `DetailDrawer` pattern | `approval-queue.tsx` | Findings list detail drawer | Same right-side drawer pattern for finding quick-view |
| `FilterSelect` | `approval-queue.tsx` | All list pages (sentinels, findings, intel, swarm members) | Reuse directly |
| `SortableHeader` | `fleet-dashboard.tsx` | Swarm members table | Reuse directly |
| `SummaryCard` | `fleet-dashboard.tsx` | Overview sentinel stats row | Reuse directly |
| `DriftBadge` / `StatusBadge` patterns | `fleet-dashboard.tsx` | Sentinel status badges, finding severity badges | Same visual pattern, different labels/colors |
| `PolicyCard` | `library/policy-card.tsx` | Intel card (similar card structure) | Fork card layout, adapt fields for intel type |
| `VerdictBadge` | `shared/verdict-badge.tsx` | Signal entries in finding timeline | Reuse directly |
| `ClaudeCodeHint` | `shared/claude-code-hint.tsx` | Overview page, sentinel create flow | New hint IDs for sentinel/swarm guidance |
| `Select` / `SelectTrigger` / `SelectContent` | `ui/select.tsx` | All form dropdowns | Reuse directly |
| `ScrollArea` | `ui/scroll-area.tsx` | All scrollable panels | Reuse directly |

### New Shared Components to Create

| Component | Purpose | Used By |
|-----------|---------|---------|
| `SigilAvatar` | Renders a Speakeasy sigil derived from a fingerprint; 8 sigil types, HSL color derivation | Sentinel cards, swarm members, speakeasy messages, overview |
| `Sparkline` | Extracted from baselines hourly chart; generic SVG sparkline with N data points | Overview signal rate, sentinel card metrics, finding signal timeline |
| `SeverityDot` | Colored circle sized by severity level | Finding cards, signal timeline entries, intel cards |
| `ConfidenceBadge` | Shows 0.0-1.0 as colored percentage bar | Finding cards, intel cards, signal entries |
| `StatusWorkflowBadge` | Shows current state in a state machine with available transitions | Finding status (emerging/confirmed/promoted), pattern status (draft/confirmed/promoted) |
| `GraphViewport` | Extracted from delegation-page.tsx; generic zoom/pan/fit/export SVG container | Swarm trust graph, delegation graph (refactored) |
| `SpeakeasyPanel` | Slide-over room panel with message list, input, verification | Global (triggered from any page) |
| `IntelCard` | Card component for intel artifact display | Intel library grid, swarm shared detections, overview |
| `FindingCard` | Card component for finding list item with triage actions | Findings list, overview, speakeasy finding attachments |
| `SentinelHealthCard` | Compact sentinel status card with mode-specific metrics | Overview, sentinel list |
| `TimelineEntry` (extended) | Extends existing approval-queue TimelineEntry with signal data | Finding detail signal timeline |

### State Architecture

New React context providers to add above the existing stack:

| Provider | Contents | Persistence |
|----------|----------|-------------|
| `SentinelProvider` | `sentinels: Sentinel[]`, CRUD dispatch, active sentinel tracking | localStorage + optional Stronghold for keys |
| `SignalProvider` | `signals: Signal[]`, pipeline state, correlation cache | In-memory (high volume, TTL-based eviction) |
| `FindingProvider` | `findings: Finding[]`, triage dispatch, enrichment cache | localStorage |
| `IntelProvider` | `intel: Intel[]`, CRUD dispatch, share queue | localStorage |
| `SwarmProvider` | `swarms: Swarm[]`, membership state, pub/sub status | localStorage + IndexedDB for received intel |
| `SpeakeasyProvider` | Wraps `@backbay/speakeasy` hooks, manages room state and panel visibility | IndexedDB (identity), in-memory (messages, max 1000 per room) |

---

## 10. Design Tokens

### Existing Palette (from Tailwind theme)

The workbench uses a consistent dark-mode palette defined inline. These values are already established across all existing components:

| Token | Hex | Usage |
|-------|-----|-------|
| `bg-primary` | `#05060a` | Page backgrounds |
| `bg-surface` | `#0b0d13` | Cards, panels, sidebars |
| `bg-elevated` | `#131721` | Active/hover states, selected items |
| `border-default` | `#2d3240` | All borders (often at 60% opacity) |
| `text-primary` | `#ece7dc` | Headings, primary text |
| `text-secondary` | `#6f7f9a` | Labels, secondary text |
| `accent-gold` | `#d4a84b` | Active states, accents, brand color |
| `verdict-allow` | `#3dbf84` | Allow/success/online |
| `verdict-deny` | `#c45c5c` | Deny/error/critical |
| `verdict-warn` | `#d4a84b` | Warn/pending/amber |
| `font-display` | Syne | Headings, brand text |
| `font-mono` | JetBrains Mono | Code, IDs, timestamps |
| `font-body` | System sans-serif | Body text, labels |

### Severity Colors

Existing in `investigation.tsx`, standardized for all sentinel-swarm pages:

| Severity | Hex | Token Name |
|----------|-----|------------|
| Critical | `#c45c5c` | `severity-critical` |
| High | `#d4784b` | `severity-high` |
| Medium | `#d4a84b` | `severity-medium` |
| Low | `#6b9b8b` | `severity-low` |
| Info | `#6f7f9a` | `severity-info` |

### Confidence Color Scale

New gradient for confidence scores (0.0-1.0):

| Range | Hex | Meaning |
|-------|-----|---------|
| 0.0-0.3 | `#6f7f9a` | Low confidence (muted) |
| 0.3-0.6 | `#d4a84b` | Medium confidence (amber) |
| 0.6-0.8 | `#d4784b` | High confidence (warm orange) |
| 0.8-1.0 | `#c45c5c` | Very high confidence (red) |

Rendered as a thin horizontal bar with CSS gradient fill.

### Sentinel Mode Colors

New color coding for the four sentinel modes:

| Mode | Hex | Rationale |
|------|-----|-----------|
| Watcher | `#5b8def` | Blue — vigilant, monitoring, passive |
| Hunter | `#d4784b` | Orange — active, exploratory, aggressive |
| Curator | `#8b7355` | Amber/brown — scholarly, organizing, warm |
| Liaison | `#7b6b8b` | Purple — diplomatic, social, connecting |

Used for: mode badge backgrounds (at 15% opacity with full-color text), sentinel card left-border accents, sidebar section accent for Sentinel Ops.

### Swarm Type Colors

New color coding for swarm types:

| Type | Hex | Rationale |
|------|-----|-----------|
| Personal | `#6f7f9a` | Muted — solo, private, default |
| Trusted | `#3dbf84` | Green — verified, safe, collaborative |
| Federated | `#5b8def` | Blue — open, broad, network |

Used for: type badges, swarm card borders, trust graph node coloring.

### Speakeasy Classification Colors

| Classification | Hex | Badge Style |
|---------------|-----|-------------|
| Routine | (no badge) | No visual indicator |
| Sensitive | `#d4a84b` | Amber outline badge |
| Restricted | `#c45c5c` | Red filled badge |

### Speakeasy Purpose Colors

| Purpose | Hex |
|---------|-----|
| Finding | `#c45c5c` (matches severity-critical) |
| Campaign | `#d4784b` |
| Incident | `#c45c5c` |
| Coordination | `#5b8def` |
| Mentoring | `#8b7355` |

### Signal Type Icons and Colors

| Signal Type | Icon | Color |
|-------------|------|-------|
| Anomaly | `IconAlertTriangle` | `#d4a84b` |
| Detection | `IconShield` | `#c45c5c` |
| Indicator | `IconFingerprint` | `#d4784b` |
| Policy Violation | `IconShieldOff` | `#c45c5c` |
| Behavioral | `IconBrain` | `#5b8def` |

### Finding Status Colors

| Status | Hex | Pulse |
|--------|-----|-------|
| Emerging | `#d4a84b` | Yes (animated) |
| Confirmed | `#d4784b` | No |
| Promoted | `#3dbf84` | No |
| Dismissed | `#6f7f9a` | No |
| False Positive | `#6f7f9a` (dimmed) | No |

### Intel Type Icons

| Type | Icon |
|------|------|
| Detection Rule | `IconShieldCheck` |
| Pattern | `IconFingerprint` |
| IOC | `IconBug` |
| Campaign | `IconTarget` |
| Advisory | `IconAlertCircle` |
| Policy Patch | `IconFileCode` |

### Shareability Icons

| Level | Icon | Color |
|-------|------|-------|
| Private | `IconLock` | `#6f7f9a` |
| Swarm | `IconUsers` | `#3dbf84` |
| Public | `IconWorld` | `#5b8def` |

---

## Appendix: Key Implementation Notes

### Lazy Loading

All new route components should be lazy-loaded following the existing pattern in `App.tsx`:

```tsx
const SentinelPage = lazy(() =>
  import("@/components/workbench/sentinels/sentinel-page").then((m) => ({
    default: m.SentinelPage,
  })),
);
```

### HashRouter Constraint

The app uses `HashRouter` for Tauri compatibility (`file://` protocol). All new routes must work with hash-based routing. Sub-routes like `/sentinels/:id` become `/#/sentinels/:id`.

### Polling Intervals

New pages should follow the established polling conventions:
- Health/status: 30s (matches fleet heartbeat polling)
- Hunt/signal stream: 30s (matches existing hunt polling)
- Approval queue: 30s (matches existing approval polling)
- Swarm intel feed: 60s (lower frequency, network-dependent)
- Speakeasy messages: real-time via Gossipsub (no polling — event-driven via `useMessages()` hook)

### Stronghold Integration

Sentinel Ed25519 keypairs should be stored in Tauri Stronghold when running as a desktop app. Falls back to IndexedDB in browser mode (same pattern as `@backbay/speakeasy` identity storage). The `secureStore` module in `secure-store.ts` already handles this dual-storage pattern.
