# Spider-Sense Threat Intel + Behavior Profiles (Full Example)

This example demonstrates a production-style Spider-Sense workflow with:

1. **Threat-intel pattern DB** mapped to real public TTP sources (MITRE ATT&CK + OWASP LLM Top 10).
2. **Behavior profile embeddings** (role baselines) to detect profile drift.
3. **Dual-signal triage**:
   - Spider-Sense verdict (`allow` / `ambiguous` / `deny`)
   - profile drift state (`normal` / `elevated` / `anomalous`)
4. **Two policy tiers**:
   - `policy.baseline.yaml` (pinned checksum, local DB)
   - `policy.hardened.yaml` (signed manifest + trust stores + async resiliency knobs)
5. **Cross-SDK parity runners** in TypeScript, Python, and Go.

## Folder Layout

- `data/threat_intel_catalog.json` - curated TTP catalog + embeddings
- `data/behavior_profiles.json` - role baseline embeddings + drift thresholds
- `data/scenarios.json` - shared action scenarios used by all SDK runners
- `data/pattern_db.s2intel-v1.json` - Spider-Sense pattern DB used by policy
- `data/pattern_db.manifest.json` - signed manifest for hardened mode
- `data/pattern_db.trust-store.json` - trust store for DB signature key
- `data/manifest.trust-store.json` - trust store for manifest-signing key
- `scripts/refresh_embeddings.py` - regenerate embeddings (provider or deterministic)
- `scripts/sign_artifacts.py` - recompute checksum + signatures + trust stores
- `scripts/verify_assets.py` - verify integrity chain and validity windows
- `typescript/index.ts` - TypeScript parity runner
- `python/run_example.py` - Python parity runner
- `go/main.go` - Go parity runner
- `expected/offline_results.json` - expected baseline offline outcomes

## Runtime Model

This example is **offline runnable by default** because embeddings are committed in `data/`.

Optional live mode:

1. refresh embeddings from provider
2. re-sign assets
3. re-run runners

## First-Class Guard Note

This example uses the first-class guard config (`guards.spider_sense`) in both policy files.
It does **not** register Spider-Sense via `guards.custom`.

The runners call `check()` with a custom action payload (`custom_type = "spider_sense"`) only
to inject precomputed scenario embeddings for deterministic offline parity.
That is an action-shape choice for the demo, not a custom-guard wiring path.

## Run: TypeScript

```bash
npm --prefix examples/spider-sense-threat-intel/typescript install
npm --prefix examples/spider-sense-threat-intel/typescript start -- --policy baseline
```

JSON output:

```bash
npm --prefix examples/spider-sense-threat-intel/typescript start -- --policy baseline --json
```

## Run: Python

```bash
python examples/spider-sense-threat-intel/python/run_example.py --policy baseline
```

JSON output:

```bash
python examples/spider-sense-threat-intel/python/run_example.py --policy baseline --json
```

## Run: Go

```bash
cd examples/spider-sense-threat-intel/go
go mod tidy
go run . --policy baseline
```

JSON output:

```bash
go run . --policy baseline --json
```

## Hardened Policy Run

Use `--policy hardened` in each runner to exercise signed-manifest loading and trust-store validation.

## Filter to a Single Scenario

```bash
# TypeScript
npm --prefix examples/spider-sense-threat-intel/typescript start -- --scenario urgent_admin_override_request

# Python
python examples/spider-sense-threat-intel/python/run_example.py --scenario urgent_admin_override_request

# Go
cd examples/spider-sense-threat-intel/go && go run . --scenario urgent_admin_override_request
```

## Refresh Embeddings (Optional Live)

Provider mode (OpenAI-compatible embeddings endpoint):

```bash
export SPIDER_SENSE_EMBEDDING_URL="https://api.openai.com/v1/embeddings"
export SPIDER_SENSE_EMBEDDING_KEY="<api-key>"
export SPIDER_SENSE_EMBEDDING_MODEL="text-embedding-3-small"

python examples/spider-sense-threat-intel/scripts/refresh_embeddings.py
python examples/spider-sense-threat-intel/scripts/sign_artifacts.py
python examples/spider-sense-threat-intel/scripts/verify_assets.py
```

Deterministic mode (no API):

```bash
python examples/spider-sense-threat-intel/scripts/refresh_embeddings.py --deterministic --dims 6
python examples/spider-sense-threat-intel/scripts/sign_artifacts.py
python examples/spider-sense-threat-intel/scripts/verify_assets.py
```

## Notes for Operators

1. Keep `pattern_db_checksum` and signatures pinned in policy + manifest.
2. Track drift in:
   - `top_score`
   - `spider_verdict` distribution
   - `profile_drift_state` distribution
3. In production, wire runner output fields into SIEM/metrics pipelines.
