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
| `admin` | PUT /api/v1/policy, POST /api/v1/policy/reload, POST /api/v1/shutdown | Modify policy and daemon control |
| `*` | All | Wildcard - grants all scopes |

## Endpoints by Auth Level

| Endpoint | Auth Required | Scope |
|----------|--------------|-------|
| GET /health | No | - |
| POST /api/v1/check | Yes | `check` or `*` |
| GET /api/v1/policy | Yes | `read` or `*` |
| PUT /api/v1/policy | Yes | `admin` |
| POST /api/v1/policy/reload | Yes | `admin` |
| POST /api/v1/shutdown | Yes | `admin` |
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

1. **Keys are hashed**: Raw keys are never stored; only key digests are kept in memory (set `HUSHD_AUTH_PEPPER` to enable peppered HMAC hashing)
2. **Use TLS**: Always use HTTPS in production to protect keys in transit (terminate TLS at a reverse proxy; hushd does not implement native TLS yet)
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

## Rate Limiting

Hushd includes built-in rate limiting to protect against abuse and ensure fair usage.

### Configuration

```yaml
rate_limit:
  enabled: true           # Enable/disable rate limiting (default: true)
  requests_per_second: 100  # Refill rate (default: 100)
  burst_size: 50           # Maximum burst capacity (default: 50)
```

### How It Works

Rate limiting uses a **token bucket algorithm** with per-IP tracking:

1. Each IP address has a "bucket" that holds up to `burst_size` tokens
2. Tokens are consumed on each request (except `/health`)
3. Tokens refill at `requests_per_second` rate
4. When the bucket is empty, requests receive `429 Too Many Requests`

### Excluded Endpoints

The following endpoints are **not** rate limited:

| Endpoint | Reason |
|----------|--------|
| GET /health | Health checks should always succeed for load balancers |

### Response Headers

When rate limited, the response includes:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: <seconds>
Content-Type: text/plain

Rate limit exceeded. Please slow down.
```

### Client IP Detection

The client IP is determined in order of precedence:

1. Direct connection IP
2. If the connection IP is a trusted proxy (or `trust_xff_from_any: true`):
   - `X-Forwarded-For` header (first IP in chain)
   - `X-Real-IP` header

**Important:** If running behind a reverse proxy, ensure it sets the appropriate headers.

### Disabling Rate Limiting

For development or testing:

```yaml
rate_limit:
  enabled: false
```

### Production Recommendations

1. **Tune limits**: Adjust `requests_per_second` and `burst_size` based on expected load
2. **Monitor 429s**: Set up alerting for excessive rate limit hits
3. **Use with auth**: Combine with API key authentication for best protection
4. **Proxy configuration**: Ensure your reverse proxy passes client IPs correctly
