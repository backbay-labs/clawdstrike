# Codex Agent Pack

This terminal subtree ships a Codex agent pack tuned for ClawdStrike TUI dogfooding, UI polish, release hardening, and targeted multi-agent debugging.

The repo root now also includes a generic swarm/orchestration layer for parallel
worktree execution across broader initiatives. Use the TUI pack for
`apps/terminal`-specific work. Use the swarm layer when the job is lane
planning, worktree coordination, or bounded parallel execution across multiple
surfaces.

## File Layout

- `.codex/config.toml`: project-scoped Codex profiles and multi-agent role registry
- `.codex/agents/*.toml`: per-role defaults and role-specific instructions
- `.codex/swarm/lanes.tsv` and `.codex/swarm/waves.tsv`: initiative lane metadata and wave order for parallel work
- `.agents/skills/*/SKILL.md`: repo-scoped skills for TUI dogfooding, polish, hardening, and multi-agent coordination
- `apps/terminal/AGENTS.md`: terminal-subtree working agreement that tightens quality bars for supported beta screens
- `docs/plans/multi-agent/codex-swarm-playbook.md`: project-wide swarm/orchestration guide

## Two Layers

### Generic swarm layer

Use the generic swarm layer when the task needs:

- idea-to-architecture work
- repo-wide specs and roadmaps
- lane ownership and dependency graphs
- parallel worktrees
- worker/reviewer/orchestrator separation

Relevant pieces:

- profiles: `swarm-docs`, `swarm-orchestrator`, `swarm-worker`, `swarm-review`
- roles: `repo_explorer`, `architecture_planner`, `workstream_orchestrator`, `docs_researcher`, `lane_worker`, `merge_reviewer`
- skills: `$clawdstrike-idea-to-architecture`, `$clawdstrike-spec-and-roadmap`, `$clawdstrike-workstream-orchestrator`, `$clawdstrike-swarm-supervisor`, `$clawdstrike-lane-executor`, `$clawdstrike-merge-verifier`

Playbook:

- [../../docs/plans/multi-agent/codex-swarm-playbook.md](../../docs/plans/multi-agent/codex-swarm-playbook.md)

### TUI-specific layer

Use the TUI-specific layer when the task is specifically about operator-shell
behavior, PTY reproduction, layout/polish, or TUI release hardening inside
`apps/terminal`.

## Profiles

Use these from the repository root or by changing into `apps/terminal`.

### `tui-dogfood`

Use for live reproduction, PTY driving, and screen-by-screen workflow validation.

```bash
codex -C apps/terminal -p tui-dogfood
```

Good prompt:

```text
Use clawdstrike-tui-dogfood-loop. Dogfood the main, integrations, security, audit, watch, report, and history screens against the live local runtime. Return exact reproduction steps, observed footer/status text, and the highest-priority failures.
```

### `tui-polish`

Use for layout, spacing, hierarchy, empty states, and shell-density improvements.

```bash
codex exec -C apps/terminal -p tui-polish \
  "Use clawdstrike-tui-ui-polish. Polish the integrations and security screens so the offline and degraded states read cleanly at normal terminal width. Keep the change narrow and add tests if shared layout logic changes."
```

### `tui-review`

Use for read-only review of correctness, regressions, workflow breakage, and missing verification.

```bash
codex exec -C apps/terminal -p tui-review \
  "Review the current TUI operator shell. Focus on supported beta screens, workflow breakage, misleading healthy states, and missing tests. Findings first with file references."
```

### `tui-docs`

Use when the issue depends on Codex configuration, `AGENTS.md`, skills, or multi-agent behavior and you want a docs-only confirmation path.

```bash
codex exec -C apps/terminal -p tui-docs \
  "Use the openai_docs_researcher role to confirm how nested AGENTS.md files, repo skills, and multi-agent role config are discovered and applied. Return only concise guidance with links."
```

## Roles

The project role registry lives in `.codex/config.toml`.

### `tui_explorer`

Read-only code-path mapper.

Use when you need to know which files actually own a screen, runtime bridge, or release-path behavior before editing.

### `tui_dogfooder`

Live PTY reproducer.

Use when a failure needs exact key sequences, visible shell states, footer text, or runtime confirmation.

### `tui_worker`

Narrow implementation worker.

Use once the failure mode is already reproduced and ownership is clear.

### `tui_reviewer`

Read-only regression reviewer.

Use before merge or after a fix to verify supported screens did not regress.

### `openai_docs_researcher`

Official OpenAI docs specialist.

Use only when the answer depends on Codex/OpenAI documentation rather than local repo behavior.

## Multi-Agent Pattern

Use the TUI multi-agent skill when the problem spans reproduction, code tracing, docs confirmation, implementation, and review.

```bash
codex exec -C apps/terminal -p tui-polish \
  "Use clawdstrike-tui-multi-agent-debug. Start with tui_explorer and tui_dogfooder in parallel on the watch and integrations screens. If the issue depends on Codex config semantics, bring in openai_docs_researcher. Only then hand the smallest fix to tui_worker and finish with tui_reviewer."
```

Recommended split:

1. `tui_explorer`: map file ownership and likely fault domain
2. `tui_dogfooder`: reproduce live and capture exact UI/runtime behavior
3. `openai_docs_researcher`: confirm Codex semantics only when needed
4. `tui_worker`: make the smallest defensible fix
5. `tui_reviewer`: check regressions and verification coverage

## Skill Selection

### `clawdstrike-tui-dogfood-loop`

Use for live screen validation and operator workflow checks.

### `clawdstrike-tui-ui-polish`

Use for alignment, spacing, hierarchy, empty states, and terminal-specific layout quality.

### `clawdstrike-tui-release-hardening`

Use for `clawdstrike tui` bootstrap, doctor/init, packaging, local-versus-cluster state, and evidence handoff.

### `clawdstrike-tui-multi-agent-debug`

Use when the task should be split across explorer, dogfooder, worker, docs, and reviewer roles instead of handled serially.

## Verification Commands

Use the narrowest relevant set:

```bash
cargo run -q -p hush-cli --bin clawdstrike -- tui --cwd apps/terminal
cd apps/terminal && bun run typecheck
cd apps/terminal && bun test
cd apps/terminal && bun run build:tui-runtime
cargo test -p hush-cli tui::tests -- --nocapture
cargo test -p hush-cli test_tui_command_parses_with_passthrough_args -- --nocapture
```

## Notes

- Inside this checkout, prefer `cargo run -q -p hush-cli --bin clawdstrike -- tui --cwd apps/terminal`
  when validating the public wrapper path. A globally installed `clawdstrike`
  binary may lag the current branch and miss the `tui` subcommand entirely.
- Prefer `clawdstrike tui` when validating a freshly built or staged release artifact.
- Prefer `bun run cli` inside `apps/terminal` for faster local iteration.
- Use `clawdstrike tui doctor --json` to confirm the runtime resolution path:
  `CLAWDSTRIKE_TUI_DIR` override, then installed bundle, then repo source fallback.
- If Bun crashes before the TUI starts, verify whether `bun` on `PATH` is a shim
  wrapper rather than the real binary. During RC dogfooding, a `~/.proto/shims/bun`
  wrapper panic was fixed by moving the real Bun binary earlier on `PATH`.
- Supported beta screens should be held to a higher bar than experimental hunt screens.
- A graceful degraded state is acceptable. A misleading healthy state is not.

## References

- OpenAI Codex config: https://developers.openai.com/codex/config-advanced
- OpenAI Codex AGENTS.md guide: https://developers.openai.com/codex/guides/agents-md
- OpenAI Codex skills: https://developers.openai.com/codex/skills
- OpenAI Codex multi-agent: https://developers.openai.com/codex/multi-agent
