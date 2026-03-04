# Examples

Runnable examples for common deployment and integration scenarios.

Representative domains:

1. `examples/rust/` and `examples/typescript/` - language quickstarts.
2. `examples/docker-compose/` and `examples/enterprise-deployment/` - infra deployment patterns.
3. `examples/edr-pipeline/`, `examples/bb-edr/`, and `examples/autonomous-sandbox/` - security pipeline compositions.
4. Agent workflows:
   - `examples/hello-secure-agent-ts/` - TypeScript tool-shape demo with inline policy checks.
   - `examples/hello-secure-agent-py/` - Python + OpenAI Agents SDK with inline policy checks.
   - `examples/hello-secure-agent-vercel/` - TypeScript + Vercel AI SDK middleware pattern.
   - `examples/openclaw-plugin/` - OpenClaw plugin integration (legacy).
   - `examples/secure-coding-assistant/` and `examples/multi-agent-orchestration/` - advanced agent workflows.
5. Swarm examples (multi-agent security enforcement with hushd):
   - `examples/secure-agent-swarm/` - 3-agent swarm with different adapters (ClaudeAdapter, VercelAIAdapter, FrameworkToolBoundary) + hushd attribution.
   - `examples/red-blue-swarm/` - Red team attacks vs blue team SSE monitoring with 100% detection.
   - `examples/delegated-pipeline/` - Full crypto chain: delegation, re-delegation, signed messages, replay protection, revocation (Rust).
   - `examples/hybrid-swarm/` - Full integration: adapter interception + hushd attribution + SSE + audit queries.
6. Feature-specific examples:
   - `examples/jailbreak-detection/` - 4-layer jailbreak detection with session aggregation, LLM-judge, and layer breakdown.
   - `examples/output-sanitization/` - Secrets/PII/internal data redaction with streaming, allowlist/denylist, and category toggling.
   - `examples/prompt-watermarking/` - Signed provenance markers with multi-agent attribution, trust verification, and fingerprint correlation.
   - `examples/spider-sense-threat-intel/` - Spider-Sense threat-intel screening with behavior-profile embedding drift, signed manifest verification, and TS/Python/Go parity runners.
