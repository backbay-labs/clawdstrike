# Clawdstrike

[![CI](https://img.shields.io/github/actions/workflow/status/backbay-labs/clawdstrike/ci.yml?branch=main&label=CI)](https://github.com/backbay-labs/clawdstrike/actions)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-orange?logo=rust)](Cargo.toml)
[![Discord](https://img.shields.io/badge/discord-join-5865F2?logo=discord&logoColor=white)](https://discord.gg/fdbCZHm8zM)

Clawdstrike is a runtime security enforcement system for AI agents and the
endpoints they run on. It sits at the tool boundary between an agent's intent
and a real-world action — file access, shell exec, network egress, MCP tool
invocation — and applies policy-driven checks with signed, non-repudiable
verdicts. Rust-first; SDKs for TypeScript, Python, Go, and WebAssembly.

**Design contract:** fail-closed. Invalid policies reject at load time;
evaluation errors deny access; ambiguity resolves to deny.

## What you get

- **A composable guard stack** — 13 built-in guards (paths, egress, secrets,
  patches, shell, MCP, prompt-injection, jailbreak, computer use, remote-desktop
  side channels, input injection, Spider-Sense) evaluated against a versioned
  YAML policy.
- **Signed receipts** — every decision produces an Ed25519-signed attestation
  serialized over RFC 8785 canonical JSON, verifiable identically from Rust,
  TypeScript, and Python.
- **A formally verified core** — the policy engine's decision logic is specified
  in Lean 4 and differentially tested against the Rust implementation.

## Install

```bash
# macOS / Linux
brew install backbay-labs/tap/clawdstrike

# Cargo (from source)
cargo install --path crates/services/hush-cli
```

SDKs:

```bash
npm install @clawdstrike/sdk
pip install clawdstrike
```

## Quick start

Check an action against a built-in ruleset:

```bash
$ clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
BLOCKED [Critical]: Access to forbidden path: ~/.ssh/id_rsa

$ clawdstrike check --action-type egress --ruleset strict api.openai.com:443
BLOCKED [Error]: Egress to api.openai.com blocked by policy
```

Wrap a real command with policy enforcement:

```bash
clawdstrike run --policy clawdstrike:strict -- python my_agent.py
```

Embed in TypeScript:

```typescript
import { Clawdstrike } from "@clawdstrike/sdk";

const cs = Clawdstrike.withDefaults("strict");
const decision = await cs.checkNetwork("api.openai.com:443");
console.log(decision.status); // "deny"
```

Embed in Python:

```python
from clawdstrike import Clawdstrike

cs = Clawdstrike.with_defaults("strict")
decision = cs.check_file("/home/user/.ssh/id_rsa")
print(decision.denied, decision.message)
```

Built-in rulesets shipped in `rulesets/`: `default`, `strict`, `ai-agent`,
`ai-agent-posture`, `cicd`, `permissive`, `remote-desktop`,
`remote-desktop-permissive`, `remote-desktop-strict`, `spider-sense`.

Policy schema version 1.5.0 (1.1.0 through 1.5.0 supported).

## Built-in guards

| Guard                            | Catches                                                          |
| -------------------------------- | ---------------------------------------------------------------- |
| `ForbiddenPathGuard`             | reads of `.ssh`, `.env`, `.aws`, credential stores               |
| `PathAllowlistGuard`             | filesystem access outside an explicit allowlist                  |
| `EgressAllowlistGuard`           | outbound network by domain (deny-by-default or allowlist)        |
| `SecretLeakGuard`                | AWS keys, GitHub tokens, private keys in file writes             |
| `PatchIntegrityGuard`            | dangerous patches: `rm -rf /`, `chmod 777`, security disablement |
| `ShellCommandGuard`              | dangerous shell commands before exec                             |
| `McpToolGuard`                   | MCP tool invocations, with confirmation gates                    |
| `PromptInjectionGuard`           | injection patterns in untrusted input                            |
| `JailbreakGuard`                 | 4-layer detection with session aggregation                       |
| `ComputerUseGuard`               | CUA action allowlist + enforcement mode                          |
| `RemoteDesktopSideChannelGuard`  | clipboard, audio, drive mapping, file transfer                   |
| `InputInjectionCapabilityGuard`  | input capability constraints in CUA environments                 |
| `SpiderSenseGuard`               | hierarchical threat screening (Yu et al. 2026)                   |

Full reference: [`docs/src/reference/guards/`](docs/src/reference/guards/README.md).

## Project status

Version 0.2.x. The CLI surface, policy schema, and SDK APIs are considered the
public contract; behavior and defaults may still change before 1.0. Not yet
hardened for fleet-scale production deployments.

- **Policy engine, CLI, Rust/TS/Python SDKs:** stable for single-host and CI/CD
  use.
- **Broker subsystem, Control API, enterprise fleet plane:** functional,
  evolving.
- **Formal verification:** properties P1–P5 fully proved in Lean 4; P6–P13 in
  progress. Differential tests (`cargo test -p formal-diff-tests`) gate every
  release.

See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/src/roadmap.md`](docs/src/roadmap.md).

## Why Clawdstrike

- **Fail-closed by construction.** Invalid policies reject at load; evaluation
  errors deny; missing config defaults restrictive. Security degradation
  requires an explicit, auditable action.
- **Proof, not logs.** Every decision is an Ed25519-signed receipt over RFC
  8785 canonical JSON. Receipts verify byte-identically across Rust, TS, and
  Python.
- **A formally specified core.** The decision logic lives in Lean 4
  (`formal/lean4/ClawdStrike/`) and is differentially tested against the Rust
  implementation under property-based fuzzing.
- **Real multi-language reach.** One policy file enforces the same contract from
  a `cargo install` binary on a laptop up through a NATS-backed fleet, across
  Rust, TypeScript, Python, Go, and WebAssembly.

## Architecture

```
agent runtime -> adapter -> canonical action event -> policy engine
                                                         |
                                                         +- guard stack
                                                         |
                                                         v
                                                 +- allow -> tool exec
                                                 +- deny  -> fail-closed
                                                 +-> Ed25519 signed receipt
                                                         |
                                              (enterprise) Spine audit trail
                                                         |
                                                       Control API
```

Deeper map: [`docs/src/concepts/architecture.md`](docs/src/concepts/architecture.md)
and [`docs/REPO_MAP.md`](docs/REPO_MAP.md).

## Documentation

- **Getting started:** [Rust](docs/src/getting-started/quick-start.md) ·
  [TypeScript](docs/src/getting-started/quick-start-typescript.md) ·
  [Python](docs/src/getting-started/quick-start-python.md)
- **Concepts:** [Design philosophy](docs/src/concepts/design-philosophy.md) ·
  [Architecture](docs/src/concepts/architecture.md) ·
  [Guards](docs/src/concepts/guards.md) ·
  [Policies](docs/src/concepts/policies.md) ·
  [Enforcement tiers](docs/src/concepts/enforcement-tiers.md)
- **Reference:** [Policy schema](docs/src/reference/policy-schema.md) ·
  [Posture schema](docs/src/reference/posture-schema.md) ·
  [Guards](docs/src/reference/guards/README.md) ·
  [Rulesets](docs/src/reference/rulesets/README.md) ·
  [CLI](docs/src/reference/api/cli.md)
- **Formal verification:** [`docs/src/formal-verification.md`](docs/src/formal-verification.md)
- **Operations:** [Observe → Synth → Tighten](docs/src/guides/observe-synth.md) ·
  [Desktop agent](docs/src/guides/desktop-agent.md) ·
  [Enterprise enrollment](docs/src/guides/enterprise-enrollment.md) ·
  [Adaptive deployment](docs/src/guides/adaptive-deployment.md)
- **Examples:** [`examples/`](examples/) — start with
  [`hello-secure-agent-py`](examples/hello-secure-agent-py/) or
  [`hello-secure-agent-ts`](examples/hello-secure-agent-ts/).

## Local development

```bash
# Format, lint, test (clippy must pass with -D warnings)
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace

# All of the above in one shot
mise run ci

# Documentation site
mdbook serve docs
```

## Security

If you discover a vulnerability, please report it privately:

- Email: [connor@backbay.io](mailto:connor@backbay.io) (48-hour response target).
- Non-sensitive issues: open a GitHub issue with the `security` label.

Disclosure policy and threat model: [`SECURITY.md`](SECURITY.md) ·
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## Contributing

Contributions welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`GOVERNANCE.md`](GOVERNANCE.md) before opening a PR. By participating you
agree to the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Project scope and
explicit non-goals are documented in [`NON_GOALS.md`](NON_GOALS.md).

## Community

- Discord: [discord.gg/fdbCZHm8zM](https://discord.gg/fdbCZHm8zM)
- Issues: [github.com/backbay-labs/clawdstrike/issues](https://github.com/backbay-labs/clawdstrike/issues)

## Citation

If you use Clawdstrike in academic work, please cite:

```bibtex
@software{clawdstrike,
  title  = {Clawdstrike: Runtime Security Enforcement for AI Agents},
  author = {Backbay Labs},
  year   = {2026},
  url    = {https://github.com/backbay-labs/clawdstrike}
}
```

The Spider-Sense guard adapts the hierarchical threat-screening pattern from
Yu et al., *Hierarchical Threat Sensing for AI Agents*, 2026
([arXiv:2602.05386](https://arxiv.org/abs/2602.05386)). Our adaptation applies
the screening hierarchy at the tool boundary rather than as an intrinsic agent
capability.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
