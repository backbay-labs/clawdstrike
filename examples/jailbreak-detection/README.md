# Jailbreak Detection Example

Demonstrates Clawdstrike's multi-layer jailbreak detection system. The detector runs every prompt through up to four independent analysis layers, aggregates their scores, and produces a risk verdict with session-level tracking.

## Architecture

```
                         Input Prompt
                              |
                     Canonicalization
                  (NFKC, casefold, strip
                   zero-width, collapse ws)
                              |
              +-------+-------+-------+-------+
              |       |       |       |       |
          Heuristic Statistical  ML   LLM Judge
          (regex    (entropy, (linear (external
          patterns) punct,    model)  callback)
                    symbols)
              |       |       |       |
              +-------+-------+-------+
                              |
                     Risk Aggregation
                  (weighted combination,
                   0-100 risk score)
                              |
                     Decision Engine
                  (block / warn / safe)
                              |
                     Session Tracking
                  (cumulative + rolling
                   risk with decay)
```

## What It Demonstrates

- **4-layer detection pipeline** -- heuristic pattern matching, statistical anomaly detection, ML-based linear model, and an LLM judge callback
- **Canonicalization** -- NFKC normalization, case folding, zero-width character stripping, and whitespace collapsing before analysis
- **Session aggregation** -- cumulative and rolling risk scores that accumulate across messages with exponential decay
- **Custom thresholds** -- configurable block and warn thresholds for tuning sensitivity
- **Mock LLM judge** -- demonstrates the callback interface that would connect to a real model in production
- **Attack variety** -- authority confusion, DAN-style roleplay, encoding attacks, adversarial suffixes, and system prompt extraction

## Prerequisites

```bash
npm install
```

## Run

```bash
npx tsx index.ts
```

## Expected Output

```
=== Clawdstrike Jailbreak Detection Example ===

Phase 1: Per-Prompt Analysis
────────────────────────────────────────────────────────────────────────────────────────────────────────
Prompt                                              Severity    Risk  Block  Heur  Stat  ML    LLM
────────────────────────────────────────────────────────────────────────────────────────────────────────
[Benign question] What is the capital of France?    safe        3     no     0.00  0.00  0.12  0.10
  Session: msgs=1, suspicious=0, rolling_risk=3.0, cumulative=3
[Benign code help] Help me write a function to s... safe        3     no     0.00  0.00  0.12  0.10
  Session: msgs=2, suspicious=0, rolling_risk=6.0, cumulative=6
[Authority confusion 1] Ignore all previous poli... likely      63    YES    0.30  0.00  0.92  0.85
  Signals: jb_ignore_policy
  Session: msgs=3, suspicious=1, rolling_risk=69.0, cumulative=69
[Authority confusion 2] Disregard your guardrail... likely      72    YES    0.53  0.00  0.95  0.85
  Signals: jb_ignore_policy, jb_dan_unfiltered, jb_role_change
  Session: msgs=4, suspicious=2, rolling_risk=141.0, cumulative=141
...
```

(Exact scores may vary slightly across SDK versions.)
