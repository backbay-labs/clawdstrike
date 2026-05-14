# ClawdStrike Academy — Development guide

This document is for **contributors**, **maintainers**, and **automation (including AI coding agents)** working in `apps/academy`.  

**Visitors** looking for an overview of the product should read **[README.md](./README.md)** in this directory instead.

---

## UI / design (required)

All UI work in `apps/academy` **must** follow:

**[docs/design/DESIGN.md](./docs/design/DESIGN.md)**

That file is the design-system reference (colors, typography, shadows, layout, components). Read it before adding or changing pages, components, or global styles. When prompting an agent, point at that path explicitly.

**Fonts:** `DESIGN.md` references Waldenburg / Geist. The app currently uses **Cormorant Garamond** (300/600) for display and **JetBrains Mono** for code until licensed or self-hosted fonts are added (`src/app/layout.tsx`).

---

## Useful paths


| Path                    | Purpose                                                      |
| ----------------------- | ------------------------------------------------------------ |
| `src/app/`              | Next.js App Router routes and layouts                        |
| `src/components/`       | UI and layout components                                     |
| `docs/design/DESIGN.md` | Visual design contract                                       |
| `images/`               | Readme / marketing screenshots (e.g. `academy-readme-*.png`) |


---

## Workspace reference

Repo-wide conventions: **[AGENTS.md](../../AGENTS.md)** at the monorepo root (structure, Rust/TS norms, CI expectations). The Academy-specific UI rule above stays authoritative for this app’s look and feel.