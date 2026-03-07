---
name: clawdstrike-tui-ui-polish
description: Use when the ClawdStrike TUI needs a visual polish pass for alignment, spacing, hierarchy, empty states, or terminal-specific layout quality without expanding the product scope.
---

# ClawdStrike TUI UI Polish

Use this skill when the interface feels janky, crowded, or unprofessional and the right move is deliberate terminal design work rather than new features.

## Outcomes

Drive toward:

- stable ANSI-safe alignment
- clear screen hierarchy
- intentional empty, offline, and degraded states
- cleaner density in headers, cards, and the status bar

## Workflow

1. Start from live evidence: screenshot, PTY capture, or both.
2. Identify whether the problem is width math, ANSI width drift, bad copy, inconsistent chrome, or weak spacing.
3. Prefer shared layout primitives and reusable components under `apps/terminal/src/tui/components`.
4. Test the changed screen at narrow, normal, and wide terminal widths.
5. Reduce noise before adding ornament. Empty space and better grouping beat more borders.
6. Recheck the screen in both healthy and degraded states if the surface supports them.

## Implementation Bias

- Fix the shell geometry first, color and copy second.
- Keep headings, badges, and footer hints consistent with the rest of the supported shell.
- Avoid one-off padding hacks when a shared helper would solve the class of bug.

## Verification

- `cd apps/terminal && bun run typecheck`
- `cd apps/terminal && bun test`
- Add or update tests when the layout logic is shared or regression-prone.
