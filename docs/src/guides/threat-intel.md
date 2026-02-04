# Threat Intel Guards (VirusTotal, Safe Browsing, Snyk)

Threat-intel guards are configured via the canonical policy schema using `guards.custom[]` entries.

**Important:** No real external API calls should run in CI/tests. All integrations support `base_url` overrides.

## Common configuration

All threat-intel guards support the `async` block described in the [Policy Schema](../reference/policy-schema.md) (`timeout_ms`, `execution_mode`, caching, retries, etc).

Secrets are provided via placeholders:

- `${VT_API_KEY}`, `${GSB_API_KEY}`, `${SNYK_API_TOKEN}`, etc
- `${secrets.NAME}` is treated as env var `NAME` (MVP)

Missing environment variables fail policy validation (fail closed).

## VirusTotal (`clawdstrike-virustotal`)

Uses hash-only lookups for files (never uploads file contents). For URLs, uses reputation lookups.

**Applies to:**
- `file_write`: uses `data.contentHash` (preferred) or computes SHA-256 from `data.content` / `data.contentBase64`
- `network_egress`: uses `data.url` (preferred) or `https://{host}`

```yaml
version: "1.0.0"
name: Threat Intel (VT)

guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "${VT_API_KEY}"
        min_detections: 2
        # base_url: "https://www.virustotal.com/api/v3" # optional (useful for mocks)
      async:
        timeout_ms: 3000
        on_timeout: warn
        execution_mode: parallel
        cache: { enabled: true, ttl_seconds: 3600, max_size_mb: 64 }
```

## Google Safe Browsing (`clawdstrike-safe-browsing`)

**Applies to:** `network_egress` (URL reputation)

```yaml
version: "1.0.0"
name: Threat Intel (Safe Browsing)

guards:
  custom:
    - package: "clawdstrike-safe-browsing"
      enabled: true
      config:
        api_key: "${GSB_API_KEY}"
        client_id: "${GSB_CLIENT_ID}"
        # client_version: "1.0.0" # optional
        # base_url: "https://safebrowsing.googleapis.com" # optional
      async:
        timeout_ms: 3000
        on_timeout: warn
        execution_mode: parallel
        cache: { enabled: true, ttl_seconds: 3600, max_size_mb: 64 }
```

## Snyk (`clawdstrike-snyk`) — MVP scope

MVP scope is intentionally small: **`package.json` file writes only**.

**Applies to:** `file_write` when `path` ends with `package.json`

**Requires:** `data.content` / `data.contentBase64` (if missing, the guard returns a warning with a reason like `missing_content_bytes`).

Recommended default is `execution_mode: background` to avoid blocking developer workflows.

```yaml
version: "1.0.0"
name: Threat Intel (Snyk)

guards:
  custom:
    - package: "clawdstrike-snyk"
      enabled: true
      config:
        api_token: "${SNYK_API_TOKEN}"
        org_id: "${SNYK_ORG_ID}"
        # severity_threshold: high # optional (low|medium|high|critical)
        # fail_on_upgradable: true # optional
        # base_url: "https://api.snyk.io" # optional
      async:
        timeout_ms: 8000
        on_timeout: warn
        execution_mode: background
        cache: { enabled: true, ttl_seconds: 3600, max_size_mb: 64 }
```

## Privacy notes

- VirusTotal file checks are **hash-only** (no content upload).
- URL-based checks send the URL (or derived `https://{host}`) to the provider; avoid enabling in high-sensitivity environments unless approved.
- Audit events intentionally exclude secret values.

