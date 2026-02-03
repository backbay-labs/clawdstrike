<p align="center">
  <img src=".github/assets/clawdstrike-hero.png" alt="Clawdstrike" width="900" />
</p>

<p align="center">
  <a href="https://github.com/medica/clawdstrike/actions"><img src="https://img.shields.io/github/actions/workflow/status/medica/clawdstrike/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://crates.io/crates/clawdstrike"><img src="https://img.shields.io/crates/v/clawdstrike?style=flat-square&logo=rust" alt="crates.io"></a>
  <a href="https://docs.rs/clawdstrike"><img src="https://img.shields.io/docsrs/clawdstrike?style=flat-square&logo=docs.rs" alt="docs.rs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/MSRV-1.75-orange?style=flat-square&logo=rust" alt="MSRV: 1.75">
</p>

<p align="center">
  <em>
    The claw strikes back.<br/>
    At the boundary between intent and action,<br/>
    it watches what leaves, what changes, what leaks.<br/>
    Not "visibility." Not "AI." Logs are stories—proof is a signature.<br/>
    If the tale diverges, the receipt won't sign.
  </em>
</p>

<p align="center">
  <img src=".github/assets/divider.png" alt="" width="520" />
</p>

<p align="center">
  <img src=".github/assets/sigils/claw-light.svg#gh-light-mode-only" height="42" alt="" />
  <img src=".github/assets/sigils/claw-dark.svg#gh-dark-mode-only"   height="42" alt="" />
</p>

<h1 align="center">Clawdstrike</h1>

<p align="center">
  <em>Fail closed. Sign the truth.</em>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/boundary-dark.svg"><img src=".github/assets/sigils/boundary-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Tool-boundary enforcement
   <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/seal-dark.svg"><img src=".github/assets/sigils/seal-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Signed receipts
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/plugin-dark.svg"><img src=".github/assets/sigils/plugin-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Multi-framework
</p>

<p align="center">
  <a href="docs/src/getting-started/quick-start.md">Docs</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="docs/src/getting-started/quick-start-typescript.md">TypeScript</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="docs/src/getting-started/quick-start-python.md">Python</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="examples">Examples</a>
</p>

---

## What is Clawdstrike?

Runtime security enforcement for AI agents. Composable guards, cryptographic receipts, and policy-driven access control at the tool boundary.

**Guards** — Block sensitive paths, control network egress, detect secrets, validate patches, restrict tools, catch jailbreaks

**Receipts** — Ed25519-signed attestations proving what was decided, under which policy, with what evidence

**Multi-language** — Rust, TypeScript, Python, WebAssembly

**Multi-framework** — OpenClaw, Vercel AI, LangChain, Claude Code, and more

## Quick Start

```typescript
// openclaw.config.ts
import { clawdstrike } from "@clawdstrike/openclaw";

export default {
  plugins: [
    clawdstrike({
      ruleset: "ai-agent",
      signing: { enabled: true },
    }),
  ],
};
```

Or use standalone:

```typescript
import { HushEngine, JailbreakDetector } from "@clawdstrike/sdk";

const engine = new HushEngine({ ruleset: "strict" });
const detector = new JailbreakDetector();

// Check file access
const result = await engine.checkFileAccess("~/.ssh/id_rsa", ctx);
if (!result.allowed) throw new Error("Blocked by policy");

// Detect jailbreaks
const detection = await detector.detect(userMessage, sessionId);
if (detection.blocked) return "I can't process that request.";
```

## Highlights

| Feature | Description |
|---------|-------------|
| **9 Built-in Guards** | Path, egress, secrets, patches, tools, prompt injection, jailbreak, output sanitization, watermarking |
| **4-Layer Jailbreak Detection** | Heuristic + statistical + ML + optional LLM-as-judge with session aggregation |
| **Output Sanitization** | Redact secrets, PII, internal data from LLM output with streaming support |
| **Prompt Watermarking** | Embed signed provenance markers for attribution and forensics |
| **Fail-Closed Design** | Invalid policies reject at load time; errors deny access |
| **Signed Receipts** | Tamper-evident audit trail with Ed25519 signatures |

## Documentation

- [Design Philosophy](docs/src/concepts/design-philosophy.md) — Fail-closed, defense in depth
- [Guards Reference](docs/src/reference/guards/README.md) — All 9 guards documented
- [Policy Schema](docs/src/reference/policy-schema.md) — YAML configuration
- [Framework Integrations](docs/src/concepts/multi-language.md) — OpenClaw, Vercel AI, LangChain

## Security

We take security seriously. If you discover a vulnerability:

- **For sensitive issues**: Email [connor@backbay.io](mailto:connor@backbay.io) with details. We aim to respond within 48 hours.
- **For non-sensitive issues**: Open a [GitHub issue](https://github.com/backbay-labs/clawdstrike/issues) with the `security` label.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
cargo build && cargo test && cargo clippy
```

## License

MIT License - see [LICENSE](LICENSE) for details.
