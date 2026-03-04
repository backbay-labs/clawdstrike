# Spider-Sense Ruleset

**Ruleset ID:** `spider-sense` (also accepted as `clawdstrike:spider-sense`)

**Source:** `rulesets/spider-sense.yaml`

Spider-Sense preset that enables `guards.spider_sense` with:

- external embedding provider fields (`embedding_api_url`, `embedding_api_key`, `embedding_model`)
- built-in S2Bench pattern DB (`pattern_db_path: builtin:s2bench-v1`)
- pinned DB integrity metadata (`pattern_db_version` + `pattern_db_checksum`)
- default screening thresholds (`similarity_threshold: 0.85`, `ambiguity_band: 0.10`, `top_k: 5`)

## Use It

```yaml
version: "1.3.0"
name: My SpiderSense Policy
extends: clawdstrike:spider-sense
```

Set required environment variables before loading:

- `SPIDER_SENSE_EMBEDDING_URL`
- `SPIDER_SENSE_EMBEDDING_KEY`

## Typical Overrides

```yaml
version: "1.3.0"
name: My SpiderSense Policy
extends: clawdstrike:spider-sense

guards:
  spider_sense:
    pattern_db_manifest_path: /etc/clawdstrike/spider/manifest.json
    pattern_db_manifest_trust_store_path: /etc/clawdstrike/spider/manifest-roots.json
    async:
      retry:
        max_retries: 3
      circuit_breaker:
        on_open: warn
```

## Operator Notes

- Keep `pattern_db_checksum` pinned and use signatures for rotation.
- Start with `llm_fail_mode: warn` when first enabling deep path.
- Alert on `ambiguity_rate` and `provider_attempts` metrics drift.

See [SpiderSenseGuard](../guards/spider-sense.md) for full field and behavior details.
