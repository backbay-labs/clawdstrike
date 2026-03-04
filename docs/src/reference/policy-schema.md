# Policy Schema

Reference for canonical Clawdstrike policy files (`version`, `guards`, `settings`, `posture`, and `extends` behavior).

## Supported Versions

- `1.1.0`
- `1.2.0`
- `1.3.0`

Notes:

- `1.3.0` is the latest schema version.
- Some SDK validators still default to `1.2.0` when `version` is omitted; set `version` explicitly in production policies.

## Top-Level Fields

- `version` (string, strict semver)
- `name` (string)
- `description` (string, optional)
- `extends` (string or list of strings)
- `merge_strategy` (`replace` | `merge` | `deep_merge`)
- `guards` (object)
- `custom_guards` (array)
- `settings` (object)
- `posture` (object, `1.2.0+`)

## Remote `extends` Security

Remote `extends` is disabled by default and must be explicitly allowlisted.

- `hushd`: configure `remote_extends.allowed_hosts`
- CLI: pass `--remote-extends-allow-host` (repeatable)

Integrity pinning and resolver hardening:

- remote refs require `#sha256=<64-hex>`
- HTTPS-only by default
- private/loopback/link-local resolution blocked by default
- redirects are bounded and re-validated at each hop

## Full Example

```yaml
version: "1.3.0"
name: Example
description: Example policy with core guards, posture, and Spider-Sense
extends: clawdstrike:default
merge_strategy: deep_merge

guards:
  forbidden_path:
    patterns: ["**/.ssh/**"]

  path_allowlist:
    enabled: true
    file_access_allow: ["**/workspace/**"]
    file_write_allow: ["**/workspace/**"]
    patch_allow: ["**/workspace/**"]

  egress_allowlist:
    allow: ["api.github.com", "*.openai.com"]
    block: []
    default_action: block

  secret_leak:
    patterns:
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical

  patch_integrity:
    max_additions: 1000
    max_deletions: 500
    forbidden_patterns: ["(?i)rm\\s+-rf\\s+/"]

  shell_command:
    enabled: true
    forbidden_patterns:
      - '(?i)\brm\s+(-rf?|--recursive)\s+/\s*(?:$|\*)'
      - '(?i)\bcurl\s+[^|]*\|\s*(bash|sh|zsh)\b'
    enforce_forbidden_paths: true

  mcp_tool:
    allow: []
    block: ["shell_exec"]
    require_confirmation: ["git_push"]
    default_action: allow

  prompt_injection:
    enabled: true

  jailbreak:
    enabled: true

  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.session.connect"
      - "remote.session.disconnect"
      - "input.inject"

  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: false
    file_transfer_enabled: false
    session_share_enabled: false
    audio_enabled: true
    drive_mapping_enabled: false
    printing_enabled: false
    max_transfer_size_bytes: 104857600

  input_injection_capability:
    enabled: true
    allowed_input_types: ["keyboard", "mouse"]
    require_postcondition_probe: false

  spider_sense:
    enabled: true
    embedding_api_url: "${SPIDER_SENSE_EMBEDDING_URL}"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
    pattern_db_manifest_path: "/etc/clawdstrike/spider/manifest.json"
    pattern_db_manifest_trust_store_path: "/etc/clawdstrike/spider/manifest-roots.json"
    llm_api_url: "${SPIDER_SENSE_LLM_URL}"
    llm_api_key: "${SPIDER_SENSE_LLM_KEY}"
    llm_prompt_template_id: "spider_sense.deep_path.json_classifier"
    llm_prompt_template_version: "1.0.0"
    llm_fail_mode: warn
    async:
      timeout_ms: 5000
      cache: { enabled: true, ttl_seconds: 3600, max_size_mb: 64 }
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

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600

posture:
  initial: work
  states:
    work:
      capabilities: [file_access, file_write, egress, mcp_tool]
      budgets:
        file_writes: 100
        egress_calls: 50
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: critical_violation }
```

## `guards.spider_sense` Fields

Core screening:

- `enabled`
- `similarity_threshold`
- `ambiguity_band`
- `top_k`
- `patterns` (inline pattern entries)
- `pattern_db_path`
- `pattern_db_version`
- `pattern_db_checksum`

Embedding provider:

- `embedding_api_url`
- `embedding_api_key`
- `embedding_model`

Pattern DB signing and key rotation:

- `pattern_db_signature`
- `pattern_db_signature_key_id`
- `pattern_db_public_key` (legacy pair mode)
- `pattern_db_trust_store_path`
- `pattern_db_trusted_keys`
- `pattern_db_manifest_path`
- `pattern_db_manifest_trust_store_path`
- `pattern_db_manifest_trusted_keys`

Deep path:

- `llm_api_url`
- `llm_api_key`
- `llm_model`
- `llm_prompt_template_id`
- `llm_prompt_template_version`
- `llm_timeout_ms`
- `llm_fail_mode` (`allow` | `warn` | `deny`)

Async runtime:

- `async.timeout_ms`
- `async.cache.enabled`
- `async.cache.ttl_seconds`
- `async.cache.max_size_mb`
- `async.retry.max_retries`
- `async.retry.initial_backoff_ms`
- `async.retry.max_backoff_ms`
- `async.retry.multiplier`
- `async.retry.honor_retry_after`
- `async.retry.retry_after_cap_ms`
- `async.retry.honor_rate_limit_reset`
- `async.retry.rate_limit_reset_grace_ms`
- `async.circuit_breaker.failure_threshold`
- `async.circuit_breaker.reset_timeout_ms`
- `async.circuit_breaker.success_threshold`
- `async.circuit_breaker.on_open` (`allow` | `warn` | `deny`)

See [SpiderSenseGuard](./guards/spider-sense.md) for behavior details and operator guidance.

## Version-Gated Fields

- `version: "1.1.0"`
  - rejects `posture`
  - rejects `guards.path_allowlist`
- `version: "1.2.0"`
  - supports `posture` and `guards.path_allowlist`
  - `guards.spider_sense` accepts `1.3.0` fields with compatibility warnings in TS canonical validator
- `version: "1.3.0"`
  - includes Spider-Sense deep-path template/version and signed manifest trust-store fields

## Validation Rules (High-Level)

- unknown policy fields are rejected
- placeholders like `${VAR}` and `${secrets.NAME}` require corresponding environment variables
- patterns and regexes are validated at load time
- invalid policy documents fail closed

## Related References

- [Guards Reference](./guards/README.md)
- [SpiderSenseGuard](./guards/spider-sense.md)
- [Posture Schema](./posture-schema.md)
