# Nono Integration Documentation Index

Specification and implementation plan for incorporating [nono](../../standalone/nono/) (OS-level capability-based sandboxing) into ClawdStrike's runtime security enforcement stack.

## Problem Statement

ClawdStrike's IRM system and guards are **advisory only**. They evaluate policies, produce verdicts, log violations, and sign receipts - but nothing prevents the child process from performing the forbidden operation at the OS level. The `hush run` command has optional sandbox wrappers (`sandbox-exec` on macOS, `bwrap` on Linux), but these are basic, not integrated with guard verdicts, and not capability-based.

Nono provides kernel-level sandboxing via Landlock (Linux) and Seatbelt (macOS) with a clean Rust library API. Integrating it closes the enforcement gap: guard verdicts become structurally enforced by the kernel.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 01 | [Requirements](01-requirements.md) | Goals, non-goals, success criteria, constraints |
| 02 | [Architecture](02-architecture.md) | Integration architecture, data flow, component interactions |
| 03 | [Sandbox Replacement](03-sandbox-replacement.md) | Phase 1: Replace sandbox-exec/bwrap with nono library |
| 04 | [Policy Translation](04-policy-translation.md) | Phase 2: Translate guard policies to nono CapabilitySets |
| 05 | [Supervisor Enforcement](05-supervisor-enforcement.md) | Phase 3: Dynamic enforcement via supervisor IPC |
| 06 | [Receipt Attestation](06-receipt-attestation.md) | Sandbox state in receipts and signed attestations |
| 07 | [Implementation Plan](07-implementation-plan.md) | Phased rollout, milestones, risk mitigation |

## Key Insight

ClawdStrike and nono operate at **different layers** and are **complementary**:

```
Agent action
  |
  v
ClawdStrike guards (semantic, context-aware, advisory)
  |  - Prompt injection detection
  |  - Secret leak scanning
  |  - Shell command regex matching
  |  - MCP tool filtering
  |  - Jailbreak detection (ML)
  |  - Domain-level egress control
  v
nono kernel sandbox (structural, irrevocable, enforced)
     - Filesystem path allow-list
     - Network port/mode restriction
     - Command execution blocking
     - Signal isolation
     - File deletion prevention
```

Guards catch what the kernel cannot (content inspection, semantic analysis). The kernel prevents what guards cannot guarantee (TOCTOU-free filesystem isolation, irrevocable restrictions).

## Source Repositories

- **ClawdStrike**: `/Users/connor/Medica/backbay/standalone/clawdstrike/`
- **nono**: `/Users/connor/Medica/backbay/standalone/nono/`
