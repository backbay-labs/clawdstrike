# bb-edr: Triage Skill

Use this skill to turn hushclaw audit logs into an incident report and a minimal response plan.

## Inputs

- `.hush/audit.jsonl` (JSONL) — hushclaw audit events (allowed/denied, guard, reason).
- `policy.yaml` — the active security policy.

## Task

1. Read and summarize the last ~50 audit events.
2. Focus on **denied** events first:
   - Group by `guard` (e.g., `forbidden_path`, `egress`, `patch_integrity`)
   - Identify likely intent (misconfiguration vs. suspicious)
3. Produce a short incident report:
   - What happened (timeline + key indicators)
   - Impact assessment (what was attempted, what was blocked)
   - Recommended response (least-privilege)
4. If you propose any response action (writing files, changing config), **use `policy_check` first** and keep changes scoped to this project directory.

## Output

- Write `./reports/incident.md` containing the final report.

## Notes (important)

- hushclaw enforces at the **tool boundary**. It is not an OS sandbox.
- If an operation is denied, treat it as a strong indicator of suspicious behavior or incorrect policy assumptions.

