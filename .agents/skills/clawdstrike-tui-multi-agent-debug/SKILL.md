---
name: clawdstrike-tui-multi-agent-debug
description: Use when a ClawdStrike TUI issue spans live reproduction, code tracing, implementation, official Codex docs verification, and review, and should be split across focused Codex sub-agents instead of handled serially.
---

# ClawdStrike TUI Multi-Agent Debug

Use this skill when one agent would end up mixing too many jobs: reproduction, repo mapping, docs validation, implementation, and review.

## Role Split

Use the project roles in `.codex/config.toml`:

- `tui_explorer` for code-path mapping
- `tui_dogfooder` for live PTY reproduction
- `openai_docs_researcher` for Codex config, AGENTS, skills, or multi-agent questions
- `tui_worker` for the smallest fix
- `tui_reviewer` for regression and verification review

## Workflow

1. Start with explorer and dogfooder in parallel when the failure mode is unclear.
2. Add docs research only if the bug depends on Codex behavior, OpenAI docs, or configuration semantics.
3. Do not let the worker start until reproduction and ownership are concrete.
4. Hand the final diff to the reviewer before declaring the task complete.
5. Keep each sub-agent narrow and opinionated; do not let reproduction agents edit code.

## Good Fit

- a screen failure that may be runtime, wrapper, or layout related
- a Codex configuration issue involving `.codex/config.toml`, `AGENTS.md`, or skills
- a release-path bug that crosses `apps/terminal`, `hush-cli`, and local runtime behavior

## Bad Fit

- a tiny one-file change with obvious ownership
- pure docs edits with no live verification need
- a broad roadmap or brainstorming task
