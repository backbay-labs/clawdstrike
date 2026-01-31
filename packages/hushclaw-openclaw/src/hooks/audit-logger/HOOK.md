---
name: hushclaw-audit-logger
description: "Log security events for audit trail"
metadata: {"openclaw":{"emoji":"📝","events":["tool_result_persist"]}}
---

# HushClaw Audit Logger Hook

This hook logs security-relevant events for audit and compliance purposes.
It provides a structured log of all tool executions and policy decisions.

## Features

- **Structured Logging**: JSON-formatted audit logs
- **Decision Recording**: Records allow/deny/warn decisions
- **Timestamp Tracking**: ISO 8601 timestamps for all events
- **Session Context**: Includes session ID for traceability

## Log Format

```json
{
  "timestamp": "2025-01-31T10:30:00.000Z",
  "eventType": "tool_result_persist",
  "sessionId": "session-123",
  "toolName": "exec",
  "decision": "allow",
  "guard": null,
  "reason": null,
  "redacted": false
}
```

## Configuration

Audit logging respects the plugin's logLevel configuration:

- `debug`: All events logged
- `info`: Allow/warn/deny decisions logged
- `warn`: Only warn/deny decisions logged
- `error`: Only deny decisions logged
