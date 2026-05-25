# Plans

This directory tracks **in-flight planning** and **architecture decisions**. Plans that document shipped or parked work have been moved to `docs/archive/plans/`. The code in this repository is the source of truth for current behavior.

Last updated: 2026-05-24 (docs hygiene wave E4).

## Active plans

| Plan | Status | What it covers |
|------|--------|----------------|
| [`decisions/`](./decisions/) | ADR series (8 records) | Architecture decision records 0001-0008 (CLI surface, policy schema convergence, policy event + severity, remote extends, custom guards, sandbox, audit ledger, TPM keys). |
| [`editor-ide/`](./editor-ide/) | In flight | Detection IDE in `apps/workbench`. Phases 0-2 shipped (multi-format editor, Sigma + OCSF, detection-lab). Phases 3-6 (YARA scanning, ATT&CK heatmap polish, command-palette extensions, SigmaHQ import) tracked here. |
| [`endpoint-decision-engine/`](./endpoint-decision-engine/) | In flight (newest, May 2026) | Local runtime-integrity EDR architecture: causal evidence, policy simulation, safe response, signed endpoint receipts. Backs the `crates/libs/clawdstrike-policy-event/src/edr/` modules. |
| [`formal-verification/`](./formal-verification/) | In flight (Phase 3) | Lean 4 + Aeneas + Z3/Logos formal verification of the policy engine. Phases 0-2 complete, Phase 3 (Aeneas extraction) in progress, Phase 5 (CI) integrated. |
| [`macos-es-ne/`](./macos-es-ne/) | In flight | macOS EndpointSecurity + NetworkExtension integration under `apps/agent/src-tauri/macos/`. Frozen host and policy contracts; deployment, signing, and notarization wiring. |
| [`sentinel-swarm/`](./sentinel-swarm/) | In flight | Sentinel/Finding/Mission/Intel workbench surfaces. Phase 0 shipped (`apps/workbench/src/features/missions/`, `swarm-*`, `finding-store.tsx`). Phases 1-4 (drivers, missions, federation, dogfood) tracked here. |

## Archived plans

See [`docs/archive/plans/`](../archive/plans/) for plans that document shipped or parked features: `origin-enclaves`, `siem-soar`, `secret-broker`, `multi-agent`, `swarm-engine`, `pact`.

## Conventions

- A plan dir stays here only while at least one of its phases is unshipped. Once all phases land, the dir moves to `docs/archive/plans/` and a one-line summary is added to the archive index.
- Each plan dir has an `INDEX.md` or `README.md` describing the plan's scope, status, and active sub-documents.
- ADRs go under `decisions/` regardless of plan status.

Point-in-time audit reports live in `docs/audits/`.
