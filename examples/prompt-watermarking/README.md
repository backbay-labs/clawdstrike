# Prompt Watermarking Example

Demonstrates Clawdstrike's cryptographic prompt watermarking system. Every prompt
sent to an AI agent is signed with an Ed25519 key, embedding provenance metadata
that can be extracted and verified later for attribution, auditing, and forensics.

## Architecture

```
                           Ed25519 Keypair
                          (auto-generated)
                                |
                                v
  Prompt -----> PromptWatermarker.watermark() -----> Watermarked Prompt
                  |  sign(canonical(payload))             |
                  |  embed as HTML comment                |
                  v                                       v
            EncodedWatermark                     WatermarkExtractor.extract()
            { payload, signature,                   |  find embedded blob
              publicKey, encodedData }               |  verify Ed25519 signature
                                                    |  check trusted-key list
                                                    v
                                              ExtractionResult
                                              { found, verified, errors }
```

## What It Demonstrates

- **Basic round-trip** -- watermark a prompt, extract, and verify the signature
- **Custom metadata** -- embed arbitrary key-value pairs (department, model, compliance tier) that survive the round-trip
- **Multi-agent attribution** -- each agent holds its own keypair; an auditor can determine which agent authored which prompt
- **Trust verification** -- restrict an extractor to a set of trusted public keys; reject or flag prompts from unknown agents
- **Fingerprint correlation** -- SHA-256 fingerprints of watermark payloads enable log correlation across a session

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
=== Clawdstrike Prompt Watermarking Example ===

Phase 1: Basic Watermark Round-Trip
----------------------------------------------------------------------
Original:     "Summarize the quarterly earnings report for Q4 2025."
Watermarked:  "<!--hushclaw.watermark:v1:..."
Public Key:   a1b2c3d4e5f6...
Signature:    0a1b2c3d4e5f...
Payload:
  Application: finance-app
  Session:     session-001
  Sequence:    0
  Metadata:    {"department":"security","environment":"production"}

Extraction:
  Found:    true
  Verified: true
  Errors:   none


Phase 2: Custom Metadata
----------------------------------------------------------------------
Embedded metadata recovered:
  department: engineering
  model: claude-opus-4-6
  compliance: SOC2
  region: us-east-1


Phase 3: Multi-Agent Attribution
----------------------------------------------------------------------
Agent             Public Key          Verified  Prompt (truncated)
----------------------------------------------------------------------
agent-planner     a1b2c3d4e5f6...    true      Create a deployment plan for the ...
agent-coder       1a2b3c4d5e6f...    true      Implement the REST API endpoint f...
agent-reviewer    f6e5d4c3b2a1...    true      Review the pull request for secur...


Phase 4: Trust Verification
----------------------------------------------------------------------
Strict extractor (only trusts agent-planner):
  agent-planner      TRUSTED    errors: none
  agent-coder        REJECTED   errors: watermark signature invalid or untrusted
  agent-reviewer     REJECTED   errors: watermark signature invalid or untrusted

Lenient extractor (allowUnverified: true):
  agent-planner      TRUSTED       found: true  errors: none
  agent-coder        UNVERIFIED    found: true  errors: none
  agent-reviewer     UNVERIFIED    found: true  errors: none


Phase 5: Fingerprint Correlation
----------------------------------------------------------------------
Seq  Fingerprint           Prompt
----------------------------------------------------------------------
0    a1b2c3d4e5f6...       Load the dataset from S3.
1    7f8e9d0c1b2a...       Clean and normalize the data.
2    3c4d5e6f7a8b...       Generate the summary report.

All fingerprints are unique but share the same session ID ("pipeline-run-42"),
enabling correlation of watermarks within a pipeline run.

=== Done ===
```

(Hex values will differ on each run since keypairs are generated randomly.)
