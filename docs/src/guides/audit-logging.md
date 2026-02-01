# Audit Logging

Configure comprehensive logging for security events.

## Overview

Hushclaw provides detailed audit logging for:

- All security decisions (Allow, Warn, Deny)
- Policy violations
- Guard evaluations
- Signed receipts for compliance

## Log Levels

| Level | What's Logged |
|-------|---------------|
| `error` | Only denials and errors |
| `warn` | Denials, warnings, and errors |
| `info` | All decisions |
| `debug` | All decisions + guard details |
| `trace` | Everything including internal state |

## Configuration

### CLI

```bash
hush run --policy policy.yaml --log-level debug -- command
```

### Environment

```bash
HUSH_LOG_LEVEL=debug hush run --policy policy.yaml -- command
```

### Config File

```yaml
# .hush/config.yaml
logging:
  level: info
  format: json
  output: file
  path: .hush/logs/audit.log
```

## Log Formats

### JSON (Recommended)

```yaml
logging:
  format: json
```

Output:

```json
{
  "timestamp": "2026-01-31T14:23:45.123Z",
  "event_id": "evt_abc123",
  "event_type": "file_read",
  "target": "~/.ssh/id_rsa",
  "decision": "deny",
  "guard": "ForbiddenPathGuard",
  "reason": "Path matches forbidden pattern",
  "severity": "critical",
  "session_id": "sess_xyz789"
}
```

### Human-Readable

```yaml
logging:
  format: human
```

Output:

```
2026-01-31 14:23:45 DENY [ForbiddenPathGuard] file_read ~/.ssh/id_rsa
  Reason: Path matches forbidden pattern
  Severity: CRITICAL
```

## Log Destinations

### File

```yaml
logging:
  output: file
  path: /var/log/hush/audit.log
  rotate:
    max_size_mb: 100
    max_files: 10
```

### Stdout

```yaml
logging:
  output: stdout
```

### Syslog

```yaml
logging:
  output: syslog
  syslog:
    facility: local0
    tag: hushclaw
```

### Multiple Outputs

```yaml
logging:
  outputs:
    - type: file
      path: .hush/logs/audit.log
    - type: stdout
      level: warn  # Only warnings to console
```

## Query Logs

### CLI

```bash
# Recent denials
hush audit query --denied --since 1h

# Specific event type
hush audit query --event-type file_read --since 24h

# By guard
hush audit query --guard ForbiddenPathGuard --since 7d

# Export to JSON
hush audit query --since 24h --format json > audit.json
```

### Output

```
2026-01-31 14:23:45 DENY file_read ~/.ssh/id_rsa
  Guard: ForbiddenPathGuard
  Reason: Path matches forbidden pattern
  Severity: CRITICAL

2026-01-31 14:20:12 DENY network_egress evil.com:443
  Guard: EgressAllowlistGuard
  Reason: Domain not in allowlist
  Severity: HIGH

Found 2 events matching query
```

## Signed Receipts

For tamper-evident audit trails:

```yaml
logging:
  receipts:
    enabled: true
    path: .hush/receipts
    sign: true
    key_path: ~/.hush/keys/audit.key
```

### Receipt Structure

```json
{
  "run_id": "run_abc123",
  "started_at": "2026-01-31T14:00:00Z",
  "ended_at": "2026-01-31T14:30:00Z",
  "events": [...],
  "event_count": 127,
  "denied_count": 2,
  "merkle_root": "0x7f3a...",
  "signature": "ed25519:abc...",
  "public_key": "ed25519:xyz..."
}
```

### Verify Receipts

```bash
hush verify .hush/receipts/run_abc123.json
```

Output:

```
Receipt Verification
────────────────────────────────────

Run ID:     run_abc123
Events:     127
Denials:    2

Signature:  VALID
Merkle:     VALID

Receipt is authentic and unmodified.
```

## Log Retention

```yaml
logging:
  retention:
    days: 90
    compress: true
    archive_path: /archive/hush-logs
```

## SIEM Integration

### Splunk

```yaml
logging:
  output: http
  http:
    url: https://splunk.company.com:8088/services/collector
    headers:
      Authorization: "Splunk ${SPLUNK_TOKEN}"
    format: json
```

### Datadog

```yaml
logging:
  output: http
  http:
    url: https://http-intake.logs.datadoghq.com/api/v2/logs
    headers:
      DD-API-KEY: "${DD_API_KEY}"
    format: json
```

### Elasticsearch

```yaml
logging:
  output: http
  http:
    url: https://elasticsearch.company.com:9200/hush-audit/_doc
    format: json
```

## Compliance Reports

Generate compliance reports:

```bash
# Daily summary
hush audit report --period day --output report.pdf

# Weekly with details
hush audit report --period week --verbose --output weekly.pdf
```

Report includes:

- Total events by type
- Denials by guard
- Severity distribution
- Top blocked paths/domains
- Trend analysis

## Best Practices

### 1. Always Log Denials

```yaml
logging:
  level: warn  # At minimum
```

### 2. Enable Receipts for Compliance

```yaml
logging:
  receipts:
    enabled: true
    sign: true
```

### 3. Rotate Logs

```yaml
logging:
  rotate:
    max_size_mb: 100
    max_files: 30
```

### 4. Protect Log Files

```bash
chmod 600 .hush/logs/audit.log
chown root:root .hush/logs/audit.log
```

### 5. Monitor for Anomalies

```yaml
alerts:
  - name: high_denial_rate
    condition: "denials_per_minute > 10"
    action: slack://alerts-channel
```

## Next Steps

- [Decisions](../concepts/decisions.md) - Understanding decision types
- [Guards Reference](../reference/guards/README.md) - What guards log
- [Receipts](../reference/api/cli.md#receipts) - CLI receipt commands
