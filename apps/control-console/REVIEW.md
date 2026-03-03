# PR Review: feat/clawdstrike-dashboard

**Branch:** `feat/clawdstrike-dashboard`
**Date:** 2026-02-26
**Scope:** 91 files, +6,941 lines — 27 features (8 new apps, data viz, shell enhancements, settings)

---

## Verdict

**Conditional merge.** Four blocking issues must be resolved first — all are small/medium effort. Eight should-fix items are recommended before GA but need not block the PR. Seven post-merge items are tracked for follow-up.

---

## Stats

| Metric | Value |
|--------|-------|
| Files changed | 91 |
| Lines added | ~6,941 |
| Page components | 13 |
| Custom hooks | 13 |
| Test files | 17 |
| Test cases | 121 |
| Component tests | 0 |
| E2E tests | 0 |

---

## Blocking (must fix before merge)

### [B-01] Clickable rows lack keyboard accessibility

**Severity:** Blocking
**Files:** `src/pages/Events.tsx:146-152`, `src/pages/AuditLog.tsx:138-143`, `src/pages/Dashboard.tsx:263-272`
**Problem:** `<tr>` and `<div>` elements act as clickable rows (have `onClick` and `cursor: pointer`) but lack `tabIndex`, `role="button"`, and `onKeyDown` handlers. Keyboard-only users and screen reader users cannot interact with these rows. This is a WCAG 2.1 AA failure.

In Events.tsx:
```tsx
<tr
  className={isViolation ? "hover-row-violation" : "hover-row"}
  style={{ cursor: "pointer" }}
  onClick={onClick}
>
```

In AuditLog.tsx:
```tsx
<tr
  key={event.id}
  className="hover-row"
  style={{ cursor: "pointer" }}
  onClick={() => setSelectedEvent(event)}
>
```

In Dashboard.tsx:
```tsx
<div
  className={`flex items-center gap-2 ...`}
  style={{ cursor: onClick ? "pointer" : undefined }}
  onClick={onClick}
>
```

**Fix:** Add `tabIndex={0}`, `role="button"`, and an `onKeyDown` handler that triggers on Enter/Space to each clickable row element. A shared helper keeps it DRY:

```tsx
const rowA11y = (handler: () => void) => ({
  tabIndex: 0,
  role: "button" as const,
  onKeyDown: (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); handler(); }
  },
});
```

**Effort:** S

---

### [B-02] `dangerouslySetInnerHTML` from `highlightYaml` — fragile XSS defense

**Severity:** Blocking
**Files:** `src/utils/yamlHighlight.ts:6-9`, `src/components/policy/YamlEditor.tsx:63-81`, `src/pages/Policies.tsx:113-117`
**Problem:** Two components render `highlightYaml()` output via `dangerouslySetInnerHTML`. The function does HTML-escape `<`, `>`, and `&` (lines 6-9), but the sanitization is hand-rolled and has no adversarial test coverage. A future change that adds attribute-based highlighting (e.g., `style="..."`) could introduce an XSS vector without any test catching it.

Sanitization in yamlHighlight.ts:
```ts
let escaped = line
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;");
```

Usage in Policies.tsx:
```tsx
<pre dangerouslySetInnerHTML={{ __html: highlightYaml(policy.yaml) }} />
```

Usage in YamlEditor.tsx:
```tsx
<pre dangerouslySetInnerHTML={{ __html: highlighted + "\n" }} />
```

**Fix:** Add adversarial tests to `yamlHighlight.test.ts`:
- Input containing `<script>alert(1)</script>` must produce `&lt;script&gt;...`
- Input containing `" onmouseover="alert(1)"` must not produce unescaped attribute injection
- Input containing `{{constructor.constructor('alert(1)')()}}` must be inert
- Input with nested HTML entities (`&amp;lt;`) must not double-decode

Consider switching to a React-based tokenizer that returns `<span>` elements instead of raw HTML strings, eliminating `dangerouslySetInnerHTML` entirely.

**Effort:** S-M

---

### [B-03] `receiptVerify.ts` has zero tests for crypto code

**Severity:** Blocking
**Files:** `src/utils/receiptVerify.ts` (entire file, ~69 lines)
**Problem:** This module performs Ed25519 signature verification using the Web Crypto API — the only cryptographic code in the frontend. It has zero test coverage. Critical operations without tests:
- JSON parsing and validation (line 19)
- Signature/publicKey presence checks (lines 27-29)
- Canonical JSON reconstruction per RFC 8785 (line 45)
- Base64 decoding of key and signature (lines 49-50)
- `crypto.subtle.importKey()` with Ed25519 (lines 52-58)
- `crypto.subtle.verify()` (line 60)
- Error handling for unsupported Ed25519 (lines 62-68)

**Fix:** Create `src/utils/receiptVerify.test.ts` with tests for:
1. Valid receipt with known Ed25519 key pair (happy path)
2. Invalid JSON input
3. Missing signature field
4. Missing publicKey field
5. Tampered payload (valid format, wrong signature)
6. Corrupted base64 in signature
7. Corrupted base64 in publicKey
8. Canonical JSON ordering (fields in different order should produce same verification result)

Use `crypto.subtle.generateKey()` in test setup to create deterministic test fixtures.

**Effort:** M

---

### [B-04] No ErrorBoundary anywhere in the component tree

**Severity:** Blocking
**Files:** `src/App.tsx`, `src/components/shell/ClawdStrikeDesktop.tsx:85-87`
**Problem:** The entire component tree has zero ErrorBoundary components. Any unhandled error in any page component, hook, or child causes a full white-screen crash with no recovery path. The app renders 13 different page components inside windows — any one of them throwing will take down the entire desktop.

Current tree structure:
```
<SharedSSEProvider>
  <DesktopOSProvider>
    <ThemeProvider />
    <ClawdStrikeDesktop>           ← no ErrorBoundary
      <WindowContainer>            ← no ErrorBoundary
        <Suspense fallback={...}>  ← only catches loading, not errors
          <AppComponent />         ← any throw = white screen
        </Suspense>
      </WindowContainer>
    </ClawdStrikeDesktop>
  </DesktopOSProvider>
</SharedSSEProvider>
```

**Fix:** Add two ErrorBoundary layers:
1. **Root boundary** in `App.tsx` wrapping the entire tree — catches provider-level errors
2. **Per-window boundary** in `ClawdStrikeDesktop.tsx` (line 85-87) wrapping each `<AppComponent />` — isolates window crashes so other windows keep working

Use a class component (React still requires this for error boundaries) with a fallback UI showing the error message and a "Reload Window" button.

**Effort:** S

---

## Should-Fix (fix before GA)

### [S-01] AgentChat reverses 500-element array on every SSE event

**Severity:** Should-Fix
**Files:** `src/pages/AgentChat.tsx:24`
**Problem:** Every time an SSE event arrives, the `events` array reference changes, which triggers this `useMemo`:

```tsx
const chronological = useMemo(() => [...events].reverse(), [events]);
```

With up to 500 events, this copies and reverses the array on every SSE tick. Since SSE events can arrive multiple times per second, this creates unnecessary GC pressure and computation.

**Fix:** Store events in chronological order at the source (useSSE) and avoid the reversal, or use a stable reference comparison (e.g., only reverse when `events.length` changes). Alternatively, keep a `useRef` for the reversed array and only recompute when the length changes.

**Effort:** M

---

### [S-02] Module-level mutable `_nextEventId` counter in useSSE

**Severity:** Should-Fix
**Files:** `src/hooks/useSSE.ts:16`
**Problem:** A module-level `let _nextEventId = 1` is incremented inside event handlers (lines 165, 237, 260). This is shared across all component instances and persists across React strict-mode double-renders, HMR reloads, and concurrent features. It works today because the app mounts one SSE provider, but it's fragile.

```ts
let _nextEventId = 1;
```

**Fix:** Move the counter into a `useRef` inside the hook, or into the SSE provider's context state.

**Effort:** S

---

### [S-03] Empty catch blocks silently swallow errors (13 occurrences)

**Severity:** Should-Fix
**Files:**
- `src/hooks/useSSE.ts:172` — `// skip malformed payloads`
- `src/hooks/useSSE.ts:181` — `// read errors`
- `src/hooks/useSSE.ts:192` — `// ignore lock release errors`
- `src/hooks/useSSE.ts:243` — `// skip malformed`
- `src/hooks/useSSE.ts:266` — `// skip`
- `src/pages/ReplayMode.tsx:21` — `/* ignore */`
- `src/components/shell/DesktopWidgets.tsx:11` — `return {}`
- `src/hooks/useAlertRules.ts:18` — `return []`
- `src/hooks/useMultiInstance.ts:18` — `return []`
- `src/hooks/useSoundEffects.ts:10` — `// Web Audio API not available`
- `src/hooks/useBookmarks.ts:17` — `return {}`
- `src/utils/receiptVerify.ts:20` — returns `{ valid: false, error: "Invalid JSON" }`
- `src/pages/ReceiptVerifier.tsx:17` — sets error result

**Problem:** While some of these are intentional best-effort patterns (e.g., sound effects, localStorage parsing), the SSE-related catches and the ReplayMode catch suppress errors that would be valuable for debugging production issues. Zero diagnostic information is logged.

**Fix:** Add `console.warn` or `console.debug` calls in catches where the error could indicate a real problem (especially useSSE network errors and ReplayMode). Leave truly benign catches (sound effects, localStorage parse) as-is but add a brief comment explaining why.

**Effort:** S

---

### [S-04] DesktopWidgets drag handler stale closure risk

**Severity:** Should-Fix
**Files:** `src/components/shell/DesktopWidgets.tsx:51-67`
**Problem:** The `handleMouseDown` callback creates `onMove` and `onUp` closures that capture `dragRef.current` values. The callback depends on `[positions]`, but the inner closures reference `dragRef.current` properties set at mousedown time. If `positions` state changes mid-drag (e.g., from another widget update), the closure could compute incorrect deltas.

```tsx
const handleMouseDown = useCallback((id: string, e: React.MouseEvent) => {
  const pos = positions[id] || DEFAULT_POSITIONS[id];
  dragRef.current = { id, startX: e.clientX, startY: e.clientY, origX: pos.x, origY: pos.y };
  const onMove = (ev: MouseEvent) => {
    if (!dragRef.current) return;
    // ... uses dragRef.current values
  };
}, [positions]);
```

**Fix:** The `onMove` handler already uses `dragRef.current` (a ref, not a stale closure), which is actually safe. However, `handleMouseDown` reads `positions[id]` to set the drag origin — if `positions` is stale, the initial origin will be wrong. Fix by reading from the ref or from a functional state update.

**Effort:** S

---

### [S-05] Race condition in Policies.tsx ref-based state tracking

**Severity:** Should-Fix
**Files:** `src/pages/Policies.tsx:14, 41-50`
**Problem:** Two refs (`lastYamlRef`, `lastSeenEventRef`) track state across async operations. An effect watches SSE events and calls `load()` when a policy update event arrives:

```tsx
useEffect(() => {
  const policyEvent = events.find(
    (e) => e.event_type === "policy_updated" && e._id > lastSeenEventRef.current,
  );
  if (policyEvent) {
    lastSeenEventRef.current = policyEvent._id;
    load();
  }
}, [events, load]);
```

If `load()` triggers `fetchPolicy()` and a second SSE event arrives before the fetch completes, `load()` will be called again with the previous fetch still in-flight. The refs won't prevent the double-fetch because `lastSeenEventRef` is updated synchronously before the async fetch returns.

**Fix:** Add an `AbortController` to `load()` so that a new call cancels any in-flight fetch. Alternatively, use a `loadingRef` to skip re-entry.

**Effort:** S

---

### [S-06] useAlertRules fires webhook without CORS/error feedback

**Severity:** Should-Fix
**Files:** `src/hooks/useAlertRules.ts:91-105`
**Problem:** The webhook `fetch` call uses `void` to fire-and-forget with a silent `.catch(() => {})`:

```tsx
void fetch(rule.webhookUrl, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ ... }),
}).catch(() => {
  // Webhook delivery is best-effort
});
```

Users configuring webhooks get no feedback on whether delivery succeeds or fails. CORS will block most cross-origin webhook URLs from the browser. The silent catch means misconfigured URLs fail invisibly.

**Fix:** Surface webhook delivery failures via the notification system (e.g., `addNotification("Webhook delivery failed")`). Add a "Test Webhook" button in Settings that makes a test POST and shows the result. Document that browser-based webhooks are subject to CORS and recommend server-side relay for cross-origin targets.

**Effort:** M

---

### [S-07] 562KB single JS bundle — no code splitting

**Severity:** Should-Fix
**Files:** `src/state/processRegistry.tsx:2-14`
**Problem:** All 13 page components are eagerly imported at the top of processRegistry:

```tsx
import { Dashboard } from "../pages/Dashboard";
import { Events } from "../pages/Events";
import { AuditLog } from "../pages/AuditLog";
import { Policies } from "../pages/Policies";
import { Settings } from "../pages/Settings";
import { AgentExplorer } from "../pages/AgentExplorer";
import { ReceiptVerifier } from "../pages/ReceiptVerifier";
import { PolicyEditor } from "../pages/PolicyEditor";
import { GuardPlayground } from "../pages/GuardPlayground";
import { PostureMap } from "../pages/PostureMap";
import { ComplianceReport } from "../pages/ComplianceReport";
import { ReplayMode } from "../pages/ReplayMode";
import { AgentChat } from "../pages/AgentChat";
```

This means the entire application is in a single chunk. Users downloading the dashboard for the first time load every page's code even though they typically start on Dashboard.

**Fix:** Replace static imports with `React.lazy()`:

```tsx
const Dashboard = lazy(() => import("../pages/Dashboard").then(m => ({ default: m.Dashboard })));
// ... repeat for each page
```

The existing `<Suspense>` wrapper in ClawdStrikeDesktop.tsx (line 85) already provides the loading fallback.

**Effort:** S-M

---

### [S-08] Settings.tsx — extract section components to reduce 600-line file

**Severity:** Should-Fix
**Files:** `src/pages/Settings.tsx:1-595`
**Problem:** Settings.tsx is 595 lines containing 8 distinct configuration sections (connection, SIEM, webhooks, wallpaper, sound, alerts, instances, theme), each with 40-60 lines of markup and its own state/handlers. The file is difficult to navigate, test in isolation, and review in PRs.

**Fix:** Extract each section into its own component under `src/components/settings/`:
- `ConnectionSettings.tsx`
- `SiemSettings.tsx`
- `WebhookSettings.tsx`
- `WallpaperSettings.tsx`
- `SoundSettings.tsx`
- `AlertSettings.tsx`
- `InstanceSettings.tsx`
- `ThemeSettings.tsx`

Settings.tsx becomes a ~80-line coordinator that renders sections and manages navigation.

**Effort:** M

---

## Post-Merge (follow-up PRs)

### [N-01] Inline rgba values should use CSS variables (theme breakage)

**Severity:** Post-Merge
**Files:** `src/pages/AuditLog.tsx` (18 occurrences), `src/pages/Events.tsx` (10), `src/pages/AgentExplorer.tsx` (5), `src/pages/Dashboard.tsx`, `src/pages/GuardPlayground.tsx`, `src/pages/ComplianceReport.tsx`, `src/pages/AgentChat.tsx`, plus UI components — 49+ total
**Problem:** Hardcoded `rgba(...)` values are spread across the codebase instead of using CSS custom properties. Common palettes: `rgba(194,59,59,*)` (danger), `rgba(214,177,90,*)` (warning), `rgba(154,167,181,*)` (muted), `rgba(27,34,48,*)` (dark). This makes theme switching brittle — the existing `useTheme` hook sets CSS variables, but most components bypass them.
**Fix:** Define CSS variables in the theme layer (`--color-danger`, `--color-warning`, `--color-muted`, `--color-surface-dark`) and replace inline rgba values. Can be done incrementally per-page.
**Effort:** L

---

### [N-02] Repeated table header pattern across 4 pages

**Severity:** Post-Merge
**Files:** `src/pages/Events.tsx:59-78`, `src/pages/AuditLog.tsx:97-121`, `src/pages/AgentExplorer.tsx:82-89`
**Problem:** Three pages (at minimum) duplicate the same table header rendering pattern: uppercase text, 0.1em letter-spacing, rgba muted color, fontWeight 500, with linear gradient separators. Changes to the table style must be applied in multiple places.
**Fix:** Extract a `<SortableTableHeader columns={[...]} />` component.
**Effort:** M

---

### [N-03] Shared `PageLayout` wrapper for page boilerplate

**Severity:** Post-Merge
**Files:** `src/pages/Events.tsx:19`, `src/pages/AuditLog.tsx:44`, `src/pages/Policies.tsx:55`, `src/pages/AgentExplorer.tsx:24`, `src/pages/ComplianceReport.tsx:35`
**Problem:** Every page uses the same container div structure: `className="space-y-5"`, `padding: 20`, `overflow: "auto"`, `height: "100%"`. This boilerplate is copy-pasted across 5+ pages.
**Fix:** Extract a `<PageLayout>` wrapper component.
**Effort:** S

---

### [N-04] Loading skeletons instead of "Loading..." text

**Severity:** Post-Merge
**Files:** `src/pages/AuditLog.tsx:127`, `src/pages/Policies.tsx:92`, `src/pages/PolicyEditor.tsx`, `src/pages/ReplayMode.tsx`
**Problem:** Loading states render plain `"Loading..."` text in muted gray. This looks unpolished compared to skeleton loaders and provides no visual indication of the content shape that will appear.
**Fix:** Create a `<Skeleton />` component and replace text loading states.
**Effort:** M

---

### [N-05] List virtualization for long event feeds

**Severity:** Post-Merge
**Files:** `src/pages/Events.tsx:105-111`, `src/pages/AuditLog.tsx:137-188`, `src/pages/AgentExplorer.tsx:92-106`
**Problem:** Event lists render all items with `.map()` without virtualization. Events.tsx mitigates this with a `DISPLAY_LIMIT = 100` and "Show all" button, but clicking "Show all" renders the full list. No `react-window` or similar library is used.
**Fix:** Add `react-window` `FixedSizeList` for event tables with 100+ rows.
**Effort:** M

---

### [N-06] Test coverage for 5 untested hooks

**Severity:** Post-Merge
**Files:** `src/hooks/useAlertRules.ts`, `src/hooks/useMultiInstance.ts`, `src/hooks/useSoundEffects.ts`, `src/hooks/useTheme.ts`, `src/hooks/useKeyboardShortcuts.ts`
**Problem:** 5 of 13 custom hooks (38%) have zero test coverage. `useAlertRules` is the most complex — it manages localStorage, webhook calls, and notification logic. `useKeyboardShortcuts` manages global event listeners that could leak.
**Fix:** Write tests for each hook using `renderHook` from `@testing-library/react`. Priority order: useAlertRules > useKeyboardShortcuts > useMultiInstance > useTheme > useSoundEffects.
**Effort:** M

---

### [N-07] `as unknown as` type casts defeat TypeScript safety

**Severity:** Post-Merge
**Files:** `src/pages/AuditLog.tsx:68`, `src/utils/exportData.test.ts:16`
**Problem:** Two occurrences of `as unknown as` double-casts. The AuditLog usage converts `SSEEvent[]` to `Record<string, unknown>[]` for the export utility — this bypasses type checking on the export function's input.

```tsx
exportAsCSV(events as unknown as Record<string, unknown>[], "audit-events")
```

**Fix:** Make `exportAsCSV` generic or accept `SSEEvent[]` directly. The test mock cast is acceptable.
**Effort:** S

---

## Dismissed Findings (not real issues)

### [D-01] "17 useState calls → should use useReducer"
**Reasoning:** The 17 `useState` calls in Settings.tsx are partitioned across 8 independent sections. Each section manages 1-3 pieces of state. Combining them into a single reducer would create coupling between unrelated sections and add boilerplate. The current structure is correct.

### [D-02] "Magic numbers (slice limits, ID length)"
**Reasoning:** Values like `DISPLAY_LIMIT = 100`, `id.slice(0, 8)` for display truncation, and `MAX_EVENTS = 500` are intentional UX decisions, not arbitrary magic numbers. They are declared as named constants where appropriate.

### [D-03] "Inline sub-components should be extracted to separate files"
**Reasoning:** Components like `EventTableRow` in Events.tsx are single-use, tightly coupled to their parent's props/state, and benefit from colocation. Extracting them would add file indirection without improving reusability.

### [D-04] "`_props` pattern is inconsistent"
**Reasoning:** The `_props` prefix is used consistently for the unused `windowId` parameter in page components rendered by the process registry. This is intentional — it signals "received but unused" while satisfying the component signature contract.

### [D-05] "Inconsistent rounded-lg vs rounded-md on glass-panel"
**Reasoning:** The border-radius variation is intentional contextual design — panels in modals use `rounded-lg` for visual hierarchy, while inline panels use `rounded-md`. This is a design system decision, not an inconsistency.

### [D-06] "Dead code in FilterInput and Settings routing"
**Reasoning:** Verified both are live code. FilterInput is used across Events, AuditLog, and AgentExplorer pages. Settings routing sections are all reachable via the sidebar navigation.

### [D-07] "Color-only indicators (accessibility violation)"
**Reasoning:** All status indicators (allow/deny badges, severity dots, health indicators) include accompanying text labels. Color supplements the text — it is not the sole indicator. This meets WCAG 1.4.1 (Use of Color).

---

## Remediation Order

Optimized for fastest unblock — blocking items first, then batched by file proximity:

| Priority | ID | Task | Est. Effort |
|----------|----|------|-------------|
| 1 | B-04 | Add ErrorBoundary (root + per-window) | ~30 min |
| 2 | B-01 | Add keyboard accessibility to clickable rows | ~30 min |
| 3 | B-02 | Add adversarial tests to yamlHighlight | ~45 min |
| 4 | B-03 | Write receiptVerify test suite | ~1-2 hr |
| 5 | S-03 | Add logging to silent catch blocks | ~15 min |
| 6 | S-05 | Add AbortController to Policies.tsx load() | ~15 min |
| 7 | S-02 | Move _nextEventId into useRef | ~10 min |
| 8 | S-07 | Convert to React.lazy() code splitting | ~1 hr |
| 9 | S-01 | Fix AgentChat array reversal | ~30 min |
| 10 | S-04 | Fix DesktopWidgets drag closure | ~20 min |
| 11 | S-06 | Add webhook error feedback | ~45 min |
| 12 | S-08 | Extract Settings sections | ~2 hr |

---

## Test Coverage Matrix

| Module | File | Tests | Status |
|--------|------|-------|--------|
| client | `api/client.test.ts` | 17 | Pass |
| vizHelpers | `utils/vizHelpers.test.ts` | 10 | Pass |
| useSSE | `hooks/useSSE.test.ts` | 9 | Pass |
| useNotifications | `hooks/useNotifications.test.ts` | 8 | Pass |
| useBookmarks | `hooks/useBookmarks.test.ts` | 7 | Pass |
| yamlHighlight | `utils/yamlHighlight.test.ts` | 6 | Pass (needs adversarial tests — B-02) |
| useAgentSessions | `hooks/useAgentSessions.test.ts` | 6 | Pass |
| exportData | `utils/exportData.test.ts` | 6 | Pass |
| reportGenerator | `utils/reportGenerator.test.ts` | 5 | Pass |
| forceLayout | `utils/forceLayout.test.ts` | 5 | Pass |
| simpleDiff | `utils/simpleDiff.test.ts` | 5 | Pass |
| processRegistry | `state/processRegistry.test.ts` | 5 | Pass |
| useLockScreen | `hooks/useLockScreen.test.ts` | 5 | Pass |
| wallpapers | `state/wallpapers.test.ts` | 4 | Pass |
| format | `utils/format.test.ts` | 3 | Pass |
| useContextMenu | `hooks/useContextMenu.test.ts` | 3 | Pass |
| useDebouncedCallback | `hooks/useDebouncedCallback.test.ts` | 3 | Pass |
| **receiptVerify** | — | **0** | **CRITICAL — no tests (B-03)** |
| useKeyboardShortcuts | — | 0 | Missing |
| useAlertRules | — | 0 | Missing |
| useMultiInstance | — | 0 | Missing |
| useSoundEffects | — | 0 | Missing |
| useTheme | — | 0 | Missing |
| guardApi | — | 0 | Missing |
| policyApi | — | 0 | Missing |
| All page components | — | 0 | No component tests |

**Totals:** 121 tests across 17 files. 0 component tests. 0 E2E tests.
