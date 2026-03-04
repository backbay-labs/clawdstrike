# SpiderSenseGuard

**Config key:** `guards.spider_sense`

Spider-Sense is a two-stage threat-screening guard:

1. Fast path: cosine similarity against a pattern DB.
2. Deep path (optional): LLM/classifier escalation for ambiguous matches.

## Availability

- Rust core: available in `full` builds (default).
- Go SDK: available.
- Python SDK: available.
- TypeScript SDK: available.
- OpenClaw adapter: supports the `guards.spider_sense` toggle; advanced Spider-Sense runtime knobs are consumed by the SDK/engine layers.

## Minimal Policy

```yaml
version: "1.3.0"
name: spider-sense-min

guards:
  spider_sense:
    embedding_api_url: "${SPIDER_SENSE_EMBEDDING_URL}"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
    pattern_db_path: "builtin:s2bench-v1"
    pattern_db_version: "s2bench-v1"
    pattern_db_checksum: "8943003a9de9619d2f8f0bf133c9c7690ab3a582cbcbe4cb9692d44ee9643a73"
```

## Core Fields

- `enabled` (bool, default `true`)
- `similarity_threshold` (float in `[0,1]`, default `0.85`)
- `ambiguity_band` (float in `[0,1]`, default `0.10`)
- `top_k` (int `>= 1`, default `5`)
- `patterns` (inline pattern DB entries)
- `pattern_db_path` (file path or `builtin:s2bench-v1`)
- `pattern_db_version`
- `pattern_db_checksum` (SHA-256 hex)

Pattern DB source can be either:

- `patterns` (inline entries), or
- `pattern_db_path`, or
- `pattern_db_manifest_path` (manifest-driven source, see below)

## Embedding Provider Config

These fields must be provided together when provider embedding is enabled:

- `embedding_api_url`
- `embedding_api_key`
- `embedding_model`

Provider-specific request/response handling is selected from the endpoint host:

- OpenAI-compatible (default)
- Cohere (`host` contains `cohere`)
- Voyage (`host` contains `voyage`)

## Async Runtime Controls (`guards.spider_sense.async`)

```yaml
guards:
  spider_sense:
    async:
      timeout_ms: 5000
      cache:
        enabled: true
        ttl_seconds: 3600
        max_size_mb: 64
      retry:
        max_retries: 2
        initial_backoff_ms: 250
        max_backoff_ms: 2000
        multiplier: 2.0
        honor_retry_after: true
        retry_after_cap_ms: 10000
        honor_rate_limit_reset: true
        rate_limit_reset_grace_ms: 250
      circuit_breaker:
        failure_threshold: 5
        reset_timeout_ms: 30000
        success_threshold: 2
        on_open: deny
```

Notes:

- Cache keys are normalized across provider URL + model + trimmed action text.
- Retry logic honors provider rate-limit headers when enabled (`Retry-After`, `RateLimit-Reset`, `X-RateLimit-Reset`, `X-Rate-Limit-Reset`, `x-ratelimit-reset-requests`).
- `circuit_breaker.on_open` controls behavior when embedding provider circuit is open: `deny` | `warn` | `allow`.

## Pattern DB Integrity And Rotation

Spider-Sense supports two signature models:

1. Legacy pair:
   - `pattern_db_signature`
   - `pattern_db_public_key`
2. Trust-store based:
   - `pattern_db_signature`
   - `pattern_db_signature_key_id`
   - `pattern_db_trust_store_path` and/or `pattern_db_trusted_keys`

Trusted key entries support:

- `key_id` (defaults to derived ID when omitted)
- `public_key`
- `status`: `active` | `deprecated` | `revoked`
- `not_before` / `not_after` (RFC3339)

Trust-store JSON accepts either:

```json
[
  {"key_id":"ab12...", "public_key":"...", "status":"active"}
]
```

or:

```json
{
  "keys": [
    {"key_id":"ab12...", "public_key":"...", "status":"active"}
  ]
}
```

## Signed Manifest Mode

For controlled DB rotation, configure:

- `pattern_db_manifest_path`
- `pattern_db_manifest_trust_store_path` and/or `pattern_db_manifest_trusted_keys`

Manifest fields include:

- `pattern_db_path`, `pattern_db_version`, `pattern_db_checksum`
- `pattern_db_signature`, `pattern_db_signature_key_id`
- trust-store payload for DB signature verification
- `manifest_signature`, `manifest_signature_key_id`
- `not_before`, `not_after`

The manifest signature covers all fields above, including `not_before` and `not_after`.

## Ambiguity Deep Path

Deep path is enabled when LLM settings are present:

- `llm_api_url`
- `llm_api_key`
- `llm_model` (optional; provider defaults apply)
- `llm_prompt_template_id`
- `llm_prompt_template_version`
- `llm_timeout_ms` (optional; otherwise async timeout or default is used)
- `llm_fail_mode`: `warn` (default) | `deny` | `allow`

Current built-in template:

- `spider_sense.deep_path.json_classifier@1.0.0`

## Metrics Hooks

Go/Python/TypeScript Spider-Sense guards expose per-check metrics hooks with fields used for production tuning:

- decision stats: `verdict`, `top_score`, `allow_count`, `deny_count`, `ambiguous_count`, `ambiguity_rate`
- context: `db_source`, `db_version`, `trust_key_id`, `embedding_source`
- reliability: `provider_attempts`, `retry_count`, `circuit_state`, `cache_hit`
- deep path: `deep_path_used`, `deep_path_verdict`
- latency: `embedding_latency_ms`, `deep_path_latency_ms`

## Cross-SDK Conformance

Spider-Sense conformance vectors live at:

- `fixtures/spider-sense/conformance_vectors.json`
- `fixtures/spider-sense/manifest_tamper_vectors.json` (signature tamper checks across SDKs)

Run all SDK conformance checks:

```bash
bash scripts/run-sdk-conformance.sh
```

## Full Example

A full runnable example with curated threat-intel patterns, behavior profile embeddings,
signed manifest/trust-store rotation, and TS/Python/Go parity runners is available at:

- `examples/spider-sense-threat-intel/`
