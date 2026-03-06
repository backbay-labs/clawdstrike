---
name: clawdstrike-merge-verifier
description: Use when a ClawdStrike lane branch is ready for review and integration and needs verification, scope-drift checks, shared-file wiring, and merge-gate enforcement before landing.
---

# ClawdStrike Merge Verifier

Use this skill when a lane branch is complete enough to review, integrate, or merge.

## Outcomes

Drive toward:

- review findings ordered by severity
- verification command results
- shared-file integration plan for orchestrator-owned files
- merge or rework recommendation

## Workflow

1. Read the verification matrix and dependency graph first.
2. Inspect the lane diff for scope drift.
3. Run the lane's verification commands.
4. Review for ownership boundary violations and shared-file conflicts.
5. If the lane touches shared registration files, move those edits into an orchestrator integration commit instead of merging them blindly.
6. Decide whether the lane is mergeable, needs follow-up, or must be restacked.

## Required Inputs

- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`
- the initiative docs and verification plan

## Review Bias

Prioritize:

- regressions
- broken invariants
- missing verification
- ownership boundary violations
- migration conflicts

Summaries are secondary to findings.
