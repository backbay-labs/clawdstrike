---
description: "Threat hunting and security event investigation"
---

# Threat Hunt

<trigger>
This skill activates when the user or conversation involves:
- Investigating security events or suspicious activity
- Breach investigation or incident response
- Threat hunting across audit logs or event streams
- Indicators of Compromise (IOCs) such as suspicious IPs, domains, hashes, or file paths
- Correlating security events across multiple sources
- MITRE ATT&CK technique references
- "BLOCKED by Clawdstrike" or similar denial messages appearing in conversation output
- Repeated policy denials or unexpected security enforcement behavior
</trigger>

## Investigation Workflow

Follow this structured approach when investigating security events:

### 1. Establish Timeline

Call `clawdstrike_timeline` to get a chronological view of recent events:
- Start with a broad time range, then narrow down
- Look for clusters of activity that indicate automated or coordinated actions
- Note any gaps that might indicate log tampering

### 2. Query and Filter

Use `clawdstrike_query` to drill into specific criteria:
- Filter by verdict (allow/deny/audit) to find blocked actions
- Filter by action_type (file/shell/egress/mcp_tool) to focus investigation
- Filter by guard name to see which security controls were triggered
- Search for specific paths, commands, or domains

### 3. Correlate Events

Run `clawdstrike_correlate` to detect patterns across events:
- Use built-in correlation rules to identify attack sequences
- Look for lateral movement patterns (multiple targets from one source)
- Detect privilege escalation attempts (sequence of increasingly sensitive operations)
- Identify data exfiltration patterns (sensitive file reads followed by egress)

### 4. Check IOCs

Use `clawdstrike_ioc` to check indicators against threat intelligence:
- Submit suspicious domains, IPs, file hashes, or paths
- Cross-reference with known threat actor TTPs
- Check if IOCs appear in multiple events (indicating persistence)

### 5. Generate Report

Call `clawdstrike_report` to produce a structured investigation summary:
- Include timeline of events, findings, and recommended actions
- Reference specific events by ID for traceability
- Map findings to MITRE ATT&CK techniques where applicable

## MITRE ATT&CK Quick Reference

Common techniques to look for in agent security events:

| Technique | ID | Indicators |
|-----------|------|------------|
| Command and Scripting Interpreter | T1059 | Shell commands with encoded payloads, eval/exec usage |
| File and Directory Discovery | T1083 | Enumeration of sensitive directories |
| Exfiltration Over Web Service | T1567 | Egress to uncommon domains after file reads |
| Credential Access | T1552 | Access to .env, .ssh, credential files |
| Defense Evasion | T1562 | Attempts to modify security config or disable guards |
| Persistence | T1546 | Modifications to shell profiles, cron, startup files |
| Privilege Escalation | T1548 | sudo/chmod/chown commands, setuid changes |

## MITRE Technique to MCP Tool Mapping

Use this table to select the right investigation tool for each technique:

| MITRE Technique | ID | Primary MCP Tool | Investigation Approach |
|-----------------|----|------------------|----------------------|
| Command and Scripting Interpreter | T1059 | `clawdstrike_query` | Filter by `action_type=shell`, look for encoded payloads or eval/exec |
| File and Directory Discovery | T1083 | `clawdstrike_timeline` | Broad timeline scan for sequential file reads across sensitive dirs |
| Exfiltration Over Web Service | T1567 | `clawdstrike_correlate` | Correlate file reads followed by egress to uncommon domains |
| Credential Access | T1552 | `clawdstrike_query` | Filter by `action_type=file` targeting .env, .ssh, credential paths |
| Defense Evasion | T1562 | `clawdstrike_query` | Filter for policy modification attempts or guard config changes |
| Persistence | T1546 | `clawdstrike_ioc` | Check shell profile, cron, and startup file modifications |
| Privilege Escalation | T1548 | `clawdstrike_query` | Filter by `action_type=shell` for sudo, chmod, chown, setuid |

## Incident Classification

Classify incidents using these severity levels:

| Classification | Criteria | Response |
|---------------|----------|----------|
| **P1 - Critical** | Active exploitation, data exfiltration confirmed, credential compromise | Immediate remediation, revoke credentials, isolate affected sessions |
| **P2 - High** | Blocked exploit attempt, repeated policy violations, suspicious lateral movement | Investigate within current session, tighten policy, monitor for recurrence |
| **P3 - Medium** | Single denied action matching known TTP, anomalous but unconfirmed activity | Log for review, verify policy coverage, check for related events |
| **P4 - Low** | Informational anomaly, policy audit events, benign tool misuse | Document in report, no immediate action required |

## Response Guidelines

When this skill is active:
- Present findings in order of severity and confidence
- Always provide specific event IDs and timestamps
- Recommend concrete remediation steps for each finding
- Distinguish between confirmed threats and suspicious activity requiring further investigation
