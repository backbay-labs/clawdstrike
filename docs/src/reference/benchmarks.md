# Performance Benchmarks

Clawdstrike is designed for minimal latency overhead at the tool boundary. This page documents our benchmark methodology and results.

## Summary

| Operation | Average Latency | Context |
|-----------|-----------------|---------|
| Individual guard check | <0.001ms | Pattern matching, allowlist lookup |
| PolicyEngine.evaluate() | ~0.04ms | Full policy evaluation |
| Jailbreak detection (heuristic+statistical) | ~0.03ms | Without ML/LLM layers |
| Combined tool boundary check | ~0.05ms | All guards + jailbreak |

**Bottom line:** Guard overhead is <0.01% of typical LLM API latency (500-2000ms).

## Running Benchmarks

### TypeScript SDK (`@clawdstrike/sdk`)

```bash
cd packages/hush-ts
npm run bench

# JSON output for CI
npm run bench:json
```

### OpenClaw Plugin (`@clawdstrike/clawdstrike-security`)

```bash
cd packages/clawdstrike-openclaw
npm run bench

# JSON output for CI
npm run bench:json
```

### Rust CLI

```bash
# After building in release mode
time (for i in {1..100}; do ./target/release/clawdstrike check --action-type file --ruleset strict /tmp/test.txt; done)
```

## Detailed Results

### Guard Latency (TypeScript)

Benchmarked on Apple M1 Pro, Node.js v20.x:

```text
======================================================================
BENCHMARK RESULTS
======================================================================
Benchmark                           Avg (ms)     Min (ms)     Max (ms)     Ops/sec
----------------------------------------------------------------------
ForbiddenPath (safe)                  0.0003       0.0000       0.0420     3125000
ForbiddenPath (blocked)               0.0003       0.0000       0.0210     3571428
SecretLeak (clean)                    0.0004       0.0000       0.0420     2500000
SecretLeak (detected)                 0.0002       0.0000       0.0210     4166666
EgressAllowlist (allowed)             0.0002       0.0000       0.0210     4545454
EgressAllowlist (blocked)             0.0003       0.0000       0.0420     3571428
Jailbreak Heuristic (safe)            0.0005       0.0000       0.0840     2000000
Jailbreak Heuristic (detected)        0.0003       0.0000       0.0420     3333333
Jailbreak Statistical (safe)          0.0089       0.0000       0.0840      112359
Jailbreak Statistical (suspicious)    0.0126       0.0000       0.0840       79365
Combined Tool Check                   0.0004       0.0000       0.0420     2380952
Jailbreak Full Pipeline               0.0067       0.0000       0.0420      149253
======================================================================
```

### PolicyEngine Latency (OpenClaw Plugin)

```text
================================================================================
POLICYENGINE BENCHMARK RESULTS
================================================================================
Benchmark                      Avg (ms)     p50 (ms)     p95 (ms)     p99 (ms)
--------------------------------------------------------------------------------
File Read (allowed)              0.0350       0.0330       0.0420       0.0830
File Read (blocked)              0.0380       0.0330       0.0420       0.1670
Network Egress (allowed)         0.0340       0.0330       0.0420       0.0420
Network Egress (blocked)         0.0360       0.0330       0.0420       0.0830
Command Exec                     0.0320       0.0330       0.0420       0.0420
Rapid Sequential (10 checks)     0.3400       0.3330       0.4170       0.4580
================================================================================

Summary:
  Average single-check overhead: 0.0350ms
  Typical LLM API latency:       500-2000ms
  Guard overhead as % of LLM:    0.0035%
  Verdict: Negligible impact on agent performance
```

## Why It's Fast

1. **No network calls** — Core detection is self-contained, no external API dependencies
2. **Pattern pre-compilation** — Regex patterns are compiled once at startup
3. **Early exit** — Fail-fast evaluation stops on first violation
4. **Minimal allocations** — Hot paths avoid heap allocations where possible
5. **Optional expensive layers** — ML and LLM-as-judge are opt-in for high-stakes decisions

## Latency Budget

For a typical agentic workflow:

| Phase | Latency |
|-------|---------|
| User input processing | 1-5ms |
| **Clawdstrike preflight check** | **<0.1ms** |
| LLM API call | 500-2000ms |
| Tool execution | 10-1000ms |
| **Clawdstrike post-action check** | **<0.1ms** |
| Response formatting | 1-5ms |

Clawdstrike adds <0.2ms to a workflow that typically takes 500-3000ms.

## CI Integration

Benchmarks can output JSON for tracking performance over time:

```bash
OUTPUT_JSON=1 npm run bench > benchmark-results.json
```

Example JSON output:

```json
{
  "timestamp": "2026-02-03T12:00:00.000Z",
  "node": "v20.10.0",
  "summary": {
    "avgOverheadMs": 0.035,
    "overheadPercent": 0.0035
  },
  "results": [
    { "name": "File Read (allowed)", "avgMs": 0.035, "p50Ms": 0.033, "p95Ms": 0.042, "p99Ms": 0.083 }
  ]
}
```

## Comparison with External Guardrails

Some guardrail solutions call external APIs for every check:

| Approach | Latency | Cost |
|----------|---------|------|
| Clawdstrike (built-in) | <0.1ms | Free |
| External model API (e.g., Gray Swan) | 100-500ms | Per-request |
| LLM-as-judge | 500-2000ms | Per-request |

Clawdstrike's multi-layer approach runs fast heuristic/statistical checks first, only invoking expensive layers when needed.
