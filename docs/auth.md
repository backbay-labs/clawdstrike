# API Authentication

Hushd supports API key authentication to protect endpoints from unauthorized access.

## Quick Start

1. Generate an API key:

```bash
hush daemon keygen --name my-app --scopes "check,read"
```

2. Add to config:

```yaml
auth:
  enabled: true
  api_keys:
    - name: "my-app"
      key: "hush_<generated-key>"
      scopes: ["check", "read"]
```

3. Use in requests:

```bash
curl -H "Authorization: Bearer hush_<key>" \
     http://localhost:9876/api/v1/check \
     -d '{"action_type": "file_access", "target": "/test"}'
```

## Scopes

| Scope | Endpoints | Description |
|-------|-----------|-------------|
| `check` | POST /api/v1/check | Check actions against policy |
| `read` | GET /api/v1/policy, /api/v1/audit, /api/v1/events | Read-only access |
| `admin` | PUT /api/v1/policy, POST /api/v1/policy/reload | Modify policy |
| `*` | All | Wildcard - grants all scopes |

## Endpoints by Auth Level

| Endpoint | Auth Required | Scope |
|----------|--------------|-------|
| GET /health | No | - |
| POST /api/v1/check | Yes | `check` or `*` |
| GET /api/v1/policy | Yes | `read` or `*` |
| PUT /api/v1/policy | Yes | `admin` |
| POST /api/v1/policy/reload | Yes | `admin` |
| GET /api/v1/audit | Yes | `read` or `*` |
| GET /api/v1/audit/stats | Yes | `read` or `*` |
| GET /api/v1/events | Yes | `read` or `*` |

## Configuration

### YAML Config

```yaml
auth:
  enabled: true
  api_keys:
    - name: "service-a"
      key: "hush_abc123..."
      scopes: ["check", "read"]
    - name: "admin"
      key: "hush_xyz789..."
      scopes: ["*"]
    - name: "temporary"
      key: "hush_temp..."
      scopes: ["check"]
      expires_at: "2024-12-31T23:59:59Z"
```

### Environment Variables

Keys can reference environment variables:

```yaml
auth:
  api_keys:
    - name: "from-env"
      key: "${HUSHD_API_KEY}"
      scopes: ["check", "read"]
```

Then set: `export HUSHD_API_KEY="hush_abc123..."`

## Security Notes

1. **Keys are hashed**: Raw keys are never stored; only SHA-256 hashes are kept in memory
2. **Use TLS**: Always use HTTPS in production to protect keys in transit
3. **Rotate keys**: Generate new keys periodically and revoke old ones
4. **Least privilege**: Grant only the scopes each client needs
5. **Expiration**: Set expiration dates for temporary access

## Disabling Auth

For development or testing, auth can be disabled:

```yaml
auth:
  enabled: false
```

**Warning**: Never disable auth in production environments.
