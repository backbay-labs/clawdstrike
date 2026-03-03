---
description: "Show security audit trail for the current session"
---

# ClawdStrike Audit

Display a chronological security audit trail for the current session.

## Arguments

- `$ARGUMENTS` (optional): Session ID to filter audit events. If provided, only show events for that session. If omitted, show events for the current session.

## Steps

1. Call `clawdstrike_timeline` MCP tool with the current session context (or the session ID passed as `$ARGUMENTS` if provided)
2. Format the results as a chronological table with these columns:

| Timestamp | Action | Target | Verdict | Guard | Details |
|-----------|--------|--------|---------|-------|---------|

### Column Meanings

| Column | Description |
|--------|-------------|
| **Timestamp** | ISO-8601 time when the action was evaluated |
| **Action** | The action_type that was checked (file, shell, egress, mcp_tool, prompt, computer_use) |
| **Target** | The specific resource: file path, command string, domain, tool name |
| **Verdict** | The enforcement decision: ALLOW, DENY, or AUDIT |
| **Guard** | The guard that produced the verdict (or "all" if multiple agreed) |
| **Details** | Additional context such as matched pattern, denial reason, or evidence snippet |

3. Use these verdict indicators:
   - `ALLOW` for permitted actions
   - `DENY` for blocked actions
   - `AUDIT` for logged-but-allowed actions

4. After the table, provide a summary:
   - Total actions evaluated
   - Number of allows, denies, and audits
   - Most frequently triggered guards
   - Any patterns worth noting (e.g., repeated denials on the same target)

If the session has no events yet, indicate that no actions have been evaluated in this session.

## Common Audit Queries

These are common patterns to look for when reviewing audit trails:

| Query | How to Investigate |
|-------|-------------------|
| All denied actions | Filter the table to `Verdict = DENY` rows. Look for patterns in targets. |
| Actions on a specific file | Search the Target column for the file path. Note the sequence of actions. |
| Guard-specific activity | Filter by Guard column to see all evaluations for a single guard (e.g., SecretLeakGuard). |
| Escalation attempts | Look for sequences: file reads of credentials followed by shell commands or egress. |
| High-frequency targets | Count occurrences per Target. Repeated denials on the same target suggest misconfiguration or probing. |
