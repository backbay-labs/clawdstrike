# Detection Engineering IDE — UI Polish Campaign

**Version:** 1.0.0
**Date:** 2026-03-14
**Contributing Agents:** Critique, Distill+Bold, Delight+Animate, Copy+Onboard

---

## 1. Executive Summary

The Detection Engineering IDE was built in a single sprint by AI agents. It is functional and architecturally sound, but the UI carries AI-generation artifacts: triplicated form components, monotonous layouts across format panels, passive copy, and zero motion. This campaign addresses four dimensions:

1. **Visual quality** — differentiate format panels, rationalize badges, enhance tab bar and command palette
2. **Motion design** — introduce a token-based animation system with accessibility support
3. **Information architecture** — fix labels, error messages, empty states, and progressive disclosure
4. **User guidance** — 7-touchpoint onboarding flow for first-time actions

21 work items across 4 implementation waves. Estimated total: 9-15 engineering days.

---

## 2. Critical Fixes (Ship-Blocking)

### 2.1 Broken Dynamic Tailwind Classes

Template-literal Tailwind classes in the YARA and OCSF visual panels use patterns like `` focus:border-[${ACCENT}]/50 `` that the JIT compiler cannot resolve at build time. Focus borders are silently broken — an accessibility failure.

**Fix:** Replace dynamic Tailwind classes with inline `style` props for accent-derived colors.

| File | Issue |
|------|-------|
| `apps/workbench/src/components/workbench/editor/yara-visual-panel.tsx` | Dynamic focus border classes |
| `apps/workbench/src/components/workbench/editor/ocsf-visual-panel.tsx` | Dynamic focus border classes |

### 2.2 Extract Shared Form Primitives

`Section`, `FieldLabel`, `TextInput`, `TextArea`, and `SelectInput` are duplicated across three visual panel files. Naming drift is already visible (`TextArea` vs `TextAreaField`).

**Fix:** Extract to a new file `apps/workbench/src/components/workbench/editor/shared-form-fields.tsx`. Accept accent color as a prop. Import from all three panels.

| Duplicated In |
|---------------|
| `editor/sigma-visual-panel.tsx` |
| `editor/yara-visual-panel.tsx` |
| `editor/ocsf-visual-panel.tsx` |

### 2.3 prefers-reduced-motion Support

No motion accessibility handling exists anywhere in the codebase. Every animation introduced by this campaign must respect the user's system preference.

**Fix:**
1. Add a `@media (prefers-reduced-motion: reduce)` block in `apps/workbench/src/globals.css` that sets all `--duration-*` tokens to `0ms`.
2. Create a `useMotionConfig()` hook that exposes `prefersReducedMotion: boolean` for conditional animation logic in React components.

---

## 3. Visual Design Overhaul

### 3.1 Differentiate Visual Panel Layouts

Each format panel currently looks like a color-tinted copy of the same layout. Each should have a distinctive visual signature.

| Format | File | Visual Signature |
|--------|------|-----------------|
| Sigma | `editor/sigma-visual-panel.tsx` | Detection section as visual hero. Larger condition display with selection cards and connector lines showing boolean logic. Section headers with indigo left-border accent. |
| YARA | `editor/yara-visual-panel.tsx` | Code-forward layout. Denser string rows with type-colored left bars (green = text, amber = hex, indigo = regex). Condition rendered as a syntax-highlighted code block at 13-14px. |
| OCSF | `editor/ocsf-visual-panel.tsx` | Schema-first layout. Validation summary promoted to top of panel. Class selector as visually dominant element. Teal-tinted field backgrounds. |

### 3.2 Badge Rationalization

Every badge currently uses a triple-layer treatment (border + background + text color). This is visually heavy and monotonous.

**Fix:** Establish a badge hierarchy:

| Treatment | Use Case |
|-----------|----------|
| Text-only with color | ATT&CK tags, YARA modifiers, OCSF field checklist items |
| Single-background pill | Status indicators, severity levels |
| Triple-layer (border + bg + text) | Interactive elements only (clickable filters, toggle badges) |

### 3.3 Format Sigils

Introduce typographic format codes — "SIG", "YAR", "POL", "OCSF" — rendered in each format's accent color as a dense identification system (Bloomberg Terminal style).

- 16px bold in visual panel headers
- Replace or supplement the 8px dots in tabs and the problems panel
- Consistent across tab bar, status bar, explorer tree

### 3.4 Tab Bar Enhancement

**File:** `apps/workbench/src/components/workbench/editor/policy-tab-bar.tsx`

| Element | Current | Proposed |
|---------|---------|----------|
| Active indicator | 2px bottom border | 3px top crown indicator |
| Active background | None | Format-tinted at 5% opacity |
| Dirty indicator | Separate dot | Gold ring around the format dot (combines two signals) |
| Format dot size | 8px | 10px |

### 3.5 ATT&CK Heatmap as War Room Display

**Data file:** `apps/workbench/src/lib/workbench/mitre-attack-data.ts`

| Element | Change |
|---------|--------|
| Coverage percentage | 48px, font-weight 900, hero position |
| Empty cells | Darker background (#070810) |
| Covered cells | More saturated fill |
| Tactic headers | 11px bold uppercase, gold bottom accent bar |
| Legend | Remove always-visible legend; tooltip provides the info |

### 3.6 Command Palette Premium Feel

**File:** `apps/workbench/src/components/workbench/editor/command-palette.tsx`

| Element | Current | Proposed |
|---------|---------|----------|
| Width | 500px | 560px |
| Input text | 13px | 14px |
| Gold `>` prompt | — | 15px |
| Active item indicator | Background highlight | Gold 3px left-edge bar (cursor feel) |
| Entrance animation | None | `scale(0.97)` to `scale(1)`, 150ms ease-out |
| Backdrop | `backdrop-blur-sm` | Remove (glassmorphism anti-pattern on dark themes) |

### 3.7 Problems Panel Enhancement

**File:** `apps/workbench/src/components/workbench/editor/problems-panel.tsx`

| Element | Change |
|---------|--------|
| Severity bar width | 2px to 4px |
| Grouping | Group problems by file with filename as section header |
| Error count badge | 11px with red background (notification badge style) |
| Format badge per row | Remove (dot is sufficient) |

### 3.8 SigmaHQ Browser Cleanup

**File:** `apps/workbench/src/components/workbench/library/sigmahq-browser.tsx`

| Element | Change |
|---------|--------|
| Per-card info | Reduce to: title + level indicator + product + 1-line description |
| ATT&CK tags | Move to expanded preview (progressive disclosure) |
| Critical-severity rules | Span full card width |
| Level indicator | Replace badge with 4px left-edge color bar |
| Import CTA | Hover-revealed overlay instead of always-visible button |

---

## 4. Motion Design Plan

### 4.1 Motion Tokens

Add to `apps/workbench/src/globals.css`:

```css
:root {
  --duration-instant: 100ms;
  --duration-fast: 150ms;
  --duration-normal: 250ms;
  --duration-slow: 400ms;
  --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-out-quart: cubic-bezier(0.25, 1, 0.5, 1);
}

@media (prefers-reduced-motion: reduce) {
  :root {
    --duration-instant: 0ms;
    --duration-fast: 0ms;
    --duration-normal: 0ms;
    --duration-slow: 0ms;
  }
}
```

### 4.2 High-Priority Animations

| # | Target | Technique | Duration |
|---|--------|-----------|----------|
| 1 | Tab create/close | `AnimatePresence` + layout animation for reorder, `layoutId` for sliding active indicator | `--duration-fast` |
| 2 | Command palette open/close | Scale `0.97` to `1` + opacity, reverse on close | 150ms, `--ease-out-expo` |
| 3 | Section expand/collapse | `grid-template-rows` transition (avoids height: auto issues) | 250ms, `--ease-out-quart` |
| 4 | Button press | Global `transition: transform var(--duration-instant)` on button elements | `--duration-instant` |

### 4.3 Medium-Priority Animations

| # | Target | Technique | Duration |
|---|--------|-----------|----------|
| 5 | Problems panel new items | Slide in from left, staggered | 150ms, 30ms stagger |
| 6 | Explorer tree expand | Height transition on directory, staggered fade-in on children | `--duration-normal` |
| 7 | Format dot appearance | Scale `0` to `1` spring on new tab creation | `--duration-fast` |
| 8 | ATT&CK heatmap cell hover | Opacity transition | 200ms |

### 4.4 Delight Moments

Professional, not playful. Each must respect `prefers-reduced-motion`.

| # | Trigger | Animation |
|---|---------|-----------|
| 9 | Problems panel reaches 0 issues | Checkmark icon emits a single subtle sonar ring (300ms) |
| 10 | ATT&CK coverage crosses 25/50/75/100% | Header glow pulse on milestone |
| 11 | Visual panel field edit | Brief highlight flash on the corresponding YAML source line |
| 12 | Rapid tab switching (>3 in 2s) | Shorten all animation durations (power user detection) |

### 4.5 Fix: Section Chevron Rotation

Current implementation swaps between `IconChevronRight` and `IconChevronDown` — an instant swap with no transition.

**Fix:** Use a single `IconChevronRight` with `transform: rotate(90deg)` and `transition: transform var(--duration-fast)`.

Affects all collapsible sections in:
- `editor/sigma-visual-panel.tsx`
- `editor/yara-visual-panel.tsx`
- `editor/ocsf-visual-panel.tsx`
- `editor/editor-visual-panel.tsx`

---

## 5. UX Copy Overhaul

### 5.1 Label Fixes (Top Priority)

| Current | Proposed | Location |
|---------|----------|----------|
| "Class UID" | "Event Class" | OCSF visual panel |
| "Severity ID" | "Severity" | OCSF visual panel |
| "Category UID" | "Category" | OCSF visual panel |
| "Logsource" | "Log Source" | Sigma visual panel |
| "Format" | "File type" | Explorer panel |
| "Untitled" | "Untitled sigma rule" / "Untitled yara rule" / etc. | Tab bar, format-specific |

### 5.2 Error Message Fixes

| Current | Proposed |
|---------|----------|
| `class_uid is required` | "Select an event class to continue." |
| `category_uid is required` | "Category is set automatically from the event class." |
| `JSON parse error: ...` | "The JSON in this tab isn't valid. Check for missing commas or brackets." |

All validation errors should be prefixed with a severity icon (error/warning/info).

### 5.3 Placeholder Improvements

| Current | Proposed |
|---------|----------|
| "Detects ..." | "Describe what this rule detects and why it matters." |
| "Author name" | "Your name or team" |
| "Optional service name" | "e.g. sysmon, security, powershell" |
| "Epoch milliseconds" | "e.g. 1710432000000" (plus a "Set to now" button) |
| "Select..." | Field-specific: "Choose a severity...", "Choose an activity..." |

### 5.4 Button Label Fixes

| Current | Proposed |
|---------|----------|
| "Import" | "Open in editor" |
| "Cancel" | "Keep editing" |
| "Discard" | "Discard changes" |

### 5.5 Empty State Copy

Every empty state gets three elements: headline, subtext, and an actionable CTA.

| Location | Headline | Subtext / CTA |
|----------|----------|---------------|
| Problems panel (0 issues) | "All clear -- no problems found" | File count context |
| ATT&CK heatmap (0 coverage) | "Your ATT&CK coverage starts here" | Create / browse CTAs |
| OCSF new tab | (No headline) | 4 clickable event class cards as starting points |
| Command palette (no match) | (No headline) | Show 3 suggested commands as ghost-style items |
| Explorer (no project) | "Drag a folder onto the window" | Format dot legend |

### 5.6 Status Message Humanization

| Current | Proposed |
|---------|----------|
| "No problems detected" | "All clear -- no problems found" |
| "No detection block parsed" | "No detection logic found. Add a 'detection' block in the YAML." |
| "No tags defined" | "No tags. Add ATT&CK tags to map this rule to techniques." |
| "No strings defined" | "No strings defined. Add string patterns in the source editor." |

---

## 6. Onboarding Flow

### 6.1 Progressive Discovery (7 Touchpoints)

| # | Trigger | Content | Format |
|---|---------|---------|--------|
| 1 | Home tab load (once per version) | What's New banner | Non-modal banner, dismiss button |
| 2 | First Sigma rule opened | "Changes here sync to the YAML source and back." | Inline hint in visual panel |
| 3 | First format switch | "Each color represents a detection format." | Tooltip on format dot |
| 4 | First ATT&CK view opened | "This heatmap shows your technique coverage." | Inline banner |
| 5 | First command palette open | "Type 'new' to create, 'go' to navigate" | Tip text below search input |
| 6 | First YARA rule opened | Structure hint showing meta/strings/condition | Inline hint |
| 7 | First OCSF event opened | Event class picker as onboarding step | Guided picker |

### 6.2 Implementation Rules

- All flags stored in `localStorage` under the `onboarding.*` namespace
- "Reset onboarding hints" option in settings (`editor/settings-panel.tsx`)
- Maximum one hint visible at a time; queue if multiple triggers fire simultaneously
- Every hint is under 2 sentences, dismissable, and non-blocking

---

## 7. Implementation Priority

### Wave 1: Ship-Blocking (1-2 days)

| # | Item | Section | Key Files |
|---|------|---------|-----------|
| 1 | Fix broken Tailwind dynamic classes | 2.1 | `yara-visual-panel.tsx`, `ocsf-visual-panel.tsx` |
| 2 | Extract shared form primitives | 2.2 | New: `editor/shared-form-fields.tsx` |
| 3 | Add `prefers-reduced-motion` support | 2.3 | `globals.css`, new: `useMotionConfig` hook |
| 4 | Fix section chevron rotation | 4.5 | All visual panel files |

### Wave 2: Visual Identity (3-5 days)

| # | Item | Section | Key Files |
|---|------|---------|-----------|
| 5 | Differentiate visual panel layouts | 3.1 | `sigma-visual-panel.tsx`, `yara-visual-panel.tsx`, `ocsf-visual-panel.tsx` |
| 6 | Badge rationalization | 3.2 | All panels, `sigmahq-browser.tsx` |
| 7 | Tab bar enhancement | 3.4 | `policy-tab-bar.tsx` |
| 8 | UX copy label fixes + error messages | 5.1, 5.2 | All visual panels, `problems-panel.tsx` |
| 9 | Empty state improvements | 5.5 | `problems-panel.tsx`, `command-palette.tsx`, `explorer-panel.tsx` |

### Wave 3: Motion + Delight (2-3 days)

| # | Item | Section | Key Files |
|---|------|---------|-----------|
| 10 | Motion tokens in globals.css | 4.1 | `globals.css` |
| 11 | Tab system animations | 4.2 | `policy-tab-bar.tsx` |
| 12 | Command palette entrance animation | 4.2 | `command-palette.tsx` |
| 13 | Section expand/collapse transitions | 4.2 | All visual panels |
| 14 | Button press transitions | 4.2 | `globals.css` (global rule) |

### Wave 4: Advanced Polish (3-5 days)

| # | Item | Section | Key Files |
|---|------|---------|-----------|
| 15 | ATT&CK heatmap war room treatment | 3.5 | `mitre-attack-data.ts`, heatmap component |
| 16 | Command palette premium feel | 3.6 | `command-palette.tsx` |
| 17 | Problems panel grouping + enhancement | 3.7 | `problems-panel.tsx` |
| 18 | SigmaHQ browser cleanup | 3.8 | `sigmahq-browser.tsx` |
| 19 | Format sigils | 3.3 | `policy-tab-bar.tsx`, panel headers, `problems-panel.tsx` |
| 20 | Onboarding flow | 6 | New: onboarding store + hint components |
| 21 | Delight moments | 4.4 | `problems-panel.tsx`, heatmap, `split-editor.tsx` |

---

## Appendix: Format Color Reference

From `INDEX.md` section 4. All colors pass WCAG AA on the workbench dark theme (`#1a1a2e`).

| Format | Sigil | Color | Hex |
|--------|-------|-------|-----|
| Policy | POL | Gold | `#d4a84b` |
| YARA | YAR | Amber | `#e0915c` |
| Sigma | SIG | Indigo | `#7c9aef` |
| OCSF | OCSF | Teal | `#5cc5c4` |

---

## Appendix: Key File Paths

All paths relative to `apps/workbench/src/`.

| Path | Role |
|------|------|
| `globals.css` | Motion tokens, reduced-motion media query |
| `components/workbench/editor/sigma-visual-panel.tsx` | Sigma format visual editor |
| `components/workbench/editor/yara-visual-panel.tsx` | YARA format visual editor |
| `components/workbench/editor/ocsf-visual-panel.tsx` | OCSF format visual editor |
| `components/workbench/editor/editor-visual-panel.tsx` | Policy format visual editor |
| `components/workbench/editor/policy-tab-bar.tsx` | Tab bar with format indicators |
| `components/workbench/editor/command-palette.tsx` | Command palette |
| `components/workbench/editor/problems-panel.tsx` | Diagnostics / problems panel |
| `components/workbench/editor/split-editor.tsx` | Visual + source split view |
| `components/workbench/editor/settings-panel.tsx` | Settings (onboarding reset) |
| `components/workbench/explorer/explorer-panel.tsx` | File explorer sidebar |
| `components/workbench/library/sigmahq-browser.tsx` | SigmaHQ rule browser |
| `lib/workbench/mitre-attack-data.ts` | ATT&CK matrix data |
