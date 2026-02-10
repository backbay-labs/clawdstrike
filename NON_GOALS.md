# Non-Goals

This document lists explicit non-goals for the current pre-release security posture.

## Adversarial ML guarantees

- We do not claim perfect jailbreak prevention.
- We do not claim complete resistance against adaptive adversarial prompt attacks.

## Host compromise classes

- We do not defend against kernel-level compromise.
- We do not defend against malicious root/admin on the host.
- We do not defend against a fully compromised dependency ecosystem.

## Filesystem edge classes not universally guaranteed

- We do not claim comprehensive defense across all mount/hardlink/junction corner cases on every platform.
- We do not claim universal elimination of check-then-open (TOCTOU) races in all external integrations.

## Platform parity limitations

- Security behavior can differ by platform/runtime features and available sandboxing primitives.
- Linux/macOS-oriented controls may not map 1:1 to Windows semantics.

## Network perimeter non-goals

- We do not claim this repository alone enforces kernel/network microsegmentation.
- Defense in depth with platform/network controls remains an operator responsibility.

## What we do instead

- Fail closed by default for ambiguous security-relevant parsing.
- Use bounded queues, inflight caps, and timeouts for DoS resistance.
- Maintain targeted regression tests, fuzzing, and scheduled memory/concurrency sensors.
