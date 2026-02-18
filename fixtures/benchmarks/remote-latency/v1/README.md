# Remote Latency Benchmark Fixtures (v1)

Deterministic test corpus for the repeatable latency harness. Each case in
`cases.json` represents a benchmark scenario combining a host class, codec,
frame size, and cache scenario with simulated run data.

## Harness Definition

The harness YAML lives at
`docs/roadmaps/cua/research/repeatable_latency_harness.yaml` and defines
allowed host classes, codecs, frame sizes, reproducibility thresholds, and
fail-closed error codes.

## Case Structure

| Field                | Description                                          |
|----------------------|------------------------------------------------------|
| `case_id`            | Unique identifier                                    |
| `description`        | Human-readable summary                               |
| `host_class`         | One of `ci_runner`, `developer_workstation`, `production_edge` |
| `codec`              | One of `h264_sw`, `h264_hw`, `vp9_sw`, `av1_sw`     |
| `frame_size`         | One of `720p`, `1080p`, `4k`                         |
| `scenario`           | `warm_cache` or `cold_cache`                         |
| `environment`        | Required metadata (host, OS, CPU, memory, codec ver) |
| `simulated_runs`     | Array of metric samples (>= 5 per case)              |
| `expected_outcome`   | `pass` or `fail`                                     |
| `expected_error_code`| `null` for pass, `LAT_*` code for fail               |
| `tags`               | Searchable labels                                    |

## Fail-Closed Error Codes

- `LAT_HOST_UNKNOWN` -- host class not in harness definition
- `LAT_CODEC_UNKNOWN` -- codec not in harness definition
- `LAT_FRAME_UNKNOWN` -- frame size not in harness definition
- `LAT_VARIANCE_EXCEEDED` -- coefficient of variation exceeds threshold
- `LAT_ENV_INCOMPLETE` -- required environment metadata field missing

## Running the Validator

```bash
python docs/roadmaps/cua/research/verify_repeatable_latency_harness.py
```

Report is written to
`docs/roadmaps/cua/research/pass11-latency-harness-report.json`.
