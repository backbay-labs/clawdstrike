# Detection Engineering IDE — UI Polish Campaign Round 2

**Date:** 2026-03-14
**Status:** Planning
**Scope:** 59 findings across 4 dimensions (pixel polish, color, accessibility, redesign)

---

## 1. Executive Summary

Round 1 fixed structural issues — layout, navigation, and component wiring. Round 2 goes deeper: pixel-level polish (4 P0 + 13 P1), color refinement (2 P0 + 4 P1), a comprehensive accessibility audit (4 Critical + 8 High), and 3 bold component redesigns. The 59 findings span every editor panel and converge on a single goal: production-grade visual and interactive quality.

---

## 2. Ship-Blocking Fixes (P0 / Critical)

These must land before any release. Ordered by severity then blast radius.

| # | Issue | Root Cause | Fix | File(s) |
|---|-------|-----------|-----|---------|
| 1 | **Focus visibility broken** | `outline-none` on all inputs kills keyboard focus rings | Remove `outline-none`, use `:focus-visible` from `globals.css` | `shared-form-fields.tsx` |
| 2 | **Labels not associated with inputs** | No `htmlFor`/`id` pairing on form fields | Use `useId()` to generate stable IDs, wire `htmlFor` | `shared-form-fields.tsx` |
| 3 | **Command palette focus trap missing** | Tab key escapes behind overlay into background UI | Use `<dialog>` with `.showModal()` or implement manual focus trap | `command-palette.tsx` |
| 4 | **Color dots lack aria-label** | Format indicator dots are decorative to screen readers | Add `aria-label="Format: {name}"` or `aria-hidden="true"` with visible text fallback | 6+ files |
| 5 | **Command palette text jiggles** | Padding mismatch between active/inactive items shifts text | Apply `borderLeft: 3px solid transparent` on all items as baseline | `command-palette.tsx` |
| 6 | **console.log in production** | 3 placeholder commands log to console instead of acting | Remove `console.log` calls, wire real handlers or no-op | `command-palette.tsx` |
| 7 | **Info severity invisible** | Info color `#6f7f9a` matches muted text — zero contrast delta | Change to `#6b8ec9` (slate blue) | `problems-panel.tsx` |
| 8 | **"Low" level color inconsistent** | Sigma uses green, SigmaHQ uses teal for the same semantic | Unify to `#3dbf84` across both panels | `sigmahq-browser.tsx` |

---

## 3. Accessibility Fixes (High)

| # | Issue | Fix | File(s) |
|---|-------|-----|---------|
| A1 | Context menus missing ARIA roles | Add `role="menu"` + `role="menuitem"` + arrow-key navigation | `policy-tab-bar.tsx` |
| A2 | Tab close button too small (15x15px) | Increase hit target to min 24x24px (padding or min-size) | `policy-tab-bar.tsx` |
| A3 | `onYamlChange` fires parse on every keystroke | Debounce 150-300ms to reduce CPU churn and re-render noise | Sigma / OCSF panels |
| A4 | Section collapse has no animation | Use `grid-template-rows: 0fr / 1fr` transition technique | `shared-form-fields.tsx` |
| A5 | Select inputs lack dropdown arrow | Add chevron indicator via CSS `appearance` or custom SVG | `shared-form-fields.tsx` |
| A6 | Command palette items missing list semantics | Add `role="listbox"` on container, `role="option"` on items | `command-palette.tsx` |
| A7 | Heatmap tooltip not keyboard-accessible | Add `onFocus`/`onBlur` handlers mirroring hover behavior | `mitre-heatmap.tsx` |
| A8 | SigmaHQ grid uses viewport breakpoints | Replace `@media` with `@container` queries (desktop app context) | `sigmahq-browser.tsx` |

---

## 4. Pixel-Level Polish (P1)

| # | Issue | Fix | Scope |
|---|-------|-----|-------|
| P1 | `FieldLabel` uses `font-mono` | Remove — natural-language labels should use the default sans font | `shared-form-fields.tsx` |
| P2 | Border-radius inconsistent | Standardize: `rounded-sm` (badges), `rounded` (inputs), `rounded-lg` (cards/panels) | All panels |
| P3 | Icon sizes vary arbitrarily | Standardize: 12px inline, 14px toolbar, 16px headers, 24px empty states | All panels |
| P4 | Command palette backdrop has no transition | Add fade via `motion.div` with `opacity` animation | `command-palette.tsx` |
| P5 | Heatmap coverage threshold mismatch | 50/25 vs 60/30 used in different places — extract `coverageColor()` utility | `mitre-heatmap.tsx` |
| P6 | Tab bar format dot has extra `mr-0.5` | Remove; fix close button hover color on active tab | `policy-tab-bar.tsx` |
| P7 | SigmaHQ card hover state invisible | Lighten hover border to `#3d4250` | `sigmahq-browser.tsx` |
| P8 | Hard-coded hex colors throughout | Replace with Tailwind design tokens (M1 — cross-cutting) | All files |
| P9 | Bottom padding via spacer divs | Replace `<div className="h-6"/>` with `pb-6` on parent container | Multiple panels |

---

## 5. Color Refinement

| # | Issue | Fix |
|---|-------|-----|
| C1 | Gold brand color underrepresented in editor | Add subtle gold tint (`text-amber-500/60`) to section chevrons and active indicators |
| C2 | Alpha-based hover backgrounds unpredictable | Replace `bg-white/5` with explicit computed colors (`#2a2d35`) for deterministic rendering |
| C3 | OCSF progress bar teal-to-green too subtle | Use gold (`#d4a843`) for "complete" state to create distinct visual break |
| C4 | Sigma "informational" shares indigo with format accent | Assign a distinct color (e.g., `#8b9dc3` cool gray) to avoid semantic collision |
| C5 | Small text `#6f7f9a` borderline contrast on raised surfaces | Bump to `#7a8ba6` for WCAG AA compliance at 12-13px |

---

## 6. Bold Redesign Proposals

### 6.1 Sigma Detection: Logic Circuit Board

Transform flat selection cards into a visual boolean circuit.

**Condition bar** at the top renders the detection condition as syntax-colored tokens:
- `AND` / `OR` operators in gold
- `NOT` operator in red
- Selection references in indigo, clickable

**Logic tree** below the condition bar:
- Operator junction markers (gold `AND` / `OR` nodes) connect selection groups
- Vertical/horizontal connector lines using CSS borders
- Negated selections dimmed with red left-border accent
- Bidirectional hover linking: hovering a condition token highlights the corresponding selection node and vice versa

**Benefit:** Makes boolean logic spatially visible instead of requiring mental parsing.

### 6.2 YARA Strings: Typed Pattern Display

Replace uniform string cards with type-specific rendering:

| Type | Rendering |
|------|-----------|
| **Text** | Green text with quote delimiters, modifiers as trailing badges |
| **Hex** | Byte-aligned dump — 12 bytes/row, quad spacing, wildcards (`??`) dimmed at 40% opacity |
| **Regex** | Full syntax coloring: literals (blue), char classes (amber), escapes (red), quantifiers (gold), flags (purple) |
| **Condition** | Syntax-highlighted code block with `$variable` references cross-linked to their string definitions |

**Benefit:** Instant visual differentiation of string types without reading labels.

### 6.3 SigmaHQ Browser: Tactical Arsenal

Replace the uniform card grid with a MITRE-tactic-grouped layout:

- **Critical rules:** Full-width elevated cards with red left accent, enlarged title typography
- **Standard rules:** Compact table rows with left-border colored by severity level
- **Tactic group headers:** Sticky-positioned with rule count badge
- **Hover interaction:** "Open" button revealed on hover, hidden at rest
- **Sort order:** Severity descending within each tactic group

**Benefit:** Surfaces high-severity rules immediately; groups rules by operational context.

---

## 7. Implementation Priority

| Wave | Scope | Items | Estimate | Dependencies |
|------|-------|-------|----------|-------------|
| **R2-1** | Critical fixes | Section 2, items 1-8 | 1-2 days | None — ship-blocking |
| **R2-2** | Accessibility | Section 3, items A1-A8 | 2-3 days | R2-1 (focus fixes first) |
| **R2-3** | Pixel polish + color | Sections 4-5, items P1-P9 + C1-C5 | 2-3 days | R2-1 (tokens before polish) |
| **R2-4** | Bold redesigns | Section 6.1-6.3 | 5-7 days | R2-3 (tokens + colors settled) |

**R2-4 phasing:** Sigma detection circuit (2-3d) first, then YARA typed display (1-2d), then SigmaHQ tactical layout (2d). Each is independently shippable.

**Total estimated effort:** 10-15 days across all waves.
