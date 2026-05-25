# Debater A: The axum/ripgrep-style README

> Persona: maintainer who reads 50 READMEs a week and writes one a year.
> Bias: every line is on probation. Soulful is fine; soulful AND useful is rare.

---

## 1. Stance

The current README is 1,126 lines because it's trying to be six things at once: tagline poster, marketing page, install guide, feature catalog, architecture whitepaper, compliance brochure. It picks none of them and does all six badly. The first 84 lines deliver three competing taglines and a broken image (`.github/assets/divider.png`, README L27) before the reader learns what the thing is. By line 200 we're deep in jailbreak SDK config; by line 800 we're in mermaid territory; by line 1080 we're reading HIPAA control mappings. A reader who lands here from Hacker News scrolls, glazes, leaves.

A README's job is the same job ripgrep, axum, tokio, and sqlx do in ~250-500 lines: **(1) tell me what the thing is in one breath, (2) get me to a working "deny" in <60 seconds, (3) point me at the deep docs and walk away.** Everything else belongs in `docs/`. The hero PNG stays because it's a real asset that frames the product in one glance. The poem dies. The "Without/With" table dies (it's a SaaS-landing-page cliche). The two mermaid diagrams in the Enterprise section die: they describe an architecture nobody installing the SDK needs to see on first contact. The compliance table dies twice.

Target: **~280 lines**, every line load-bearing. I'll defend the number in section 5.

---

## 2. What I'd keep verbatim

| Span | Why |
| --- | --- |
| `README.md:2` (hero image, `.github/assets/clawdstrike-hero.png`) | Real 2.5MB asset, frames the product. ripgrep doesn't have one; we do. Use it. |
| `README.md:6-13` (badges, minus one) | CI/npm/PyPI/Homebrew/Discord/License/MSRV. Drop Artifact Hub (L10): the badge isn't pulling reliably and adds visual weight for low signal. |
| `README.md:84` (the one-sentence definition) | "Clawdstrike is a fail-closed policy engine and cryptographic attestation runtime for AI agent systems." This is the only line in the first 100 that earns its space. It moves to L~30 in my version. |
| `README.md:156-183` (Install/Initialize/Daemon block) | The brew/init/daemon flow is exactly the "first 60 seconds" path a reader needs. Tighten copy, but keep the shape. |
| `README.md:188-208` (CLI examples with denied output) | Showing the `BLOCKED [Critical]: Access to forbidden path` output is the README's strongest sentence. It demonstrates the product in one block. Keep verbatim. |
| `README.md:1086-1094` (Design Principles) | Four short paragraphs, each load-bearing. Fail closed / Proof not logs / Same envelope any pipe / Attenuation only. This is the soul of the project. Keep, but move it earlier; it belongs in the first third. |
| `README.md:1098-1107` (Documentation table) | A README's exit ramp. Keep, trim categories to 4 rows. |
| `README.md:1109-1118` (Security + Contributing) | Standard tail. Keep. |
| `README.md:1124-1126` (License) | One line. Keep. |

That's it. About 90 lines of the current 1,126 survive as-is. The rest gets rewritten or cut.

---

## 3. What I'd kill

| Span | One-line reason |
| --- | --- |
| L17-24 | The poem. It's nice prose. It's not a README. Move to `docs/about/manifesto.md` if it must live. |
| L26-28 | Broken image reference (`divider.png` doesn't exist on disk). Audit V-09. |
| L31-33 | Decorative sigil block. No information. |
| L37-39 | Tagline #2 ("EDR for the age of the swarm. Fail closed. Sign the truth."). One tagline only; this isn't it (see §8). |
| L42-52 | The four-sigil "Kernel to chain · Tool-boundary enforcement · …" inline-style nav. Inline CSS in GitHub README never renders the way you think it does and the text is just noise. |
| L54-62 | Anchor nav directly below the icon nav. Redundant. The Documentation table at the end is enough. |
| L66-68 | `promo-reel.gif` (493KB). It's the Workbench, which is one of eight `apps/` and not what 95% of readers need. Move to the Workbench app's own README. |
| L98-104 | The "Three layers, one system" table (Guard Stack / Swarm C2 / Swarm Trace). This is marketing taxonomy invented for the README; the codebase doesn't talk like this. The crate map is the truth. |
| L108-135 | "Without Clawdstrike / With Clawdstrike" two-column table. Pure landing-page convention. AI-slop tell. Kill. |
| L143-151 | The `<kbd>Python</kbd> <kbd>TypeScript</kbd>` nav row. The reader knows what language they use; section headers suffice. |
| L242-280 | Desktop Agent block sandwiched mid-Quick-Start. It's a separate product surface; link to `apps/agent/README.md`. |
| L296-379 | TypeScript Jailbreak/OpenAI/Hunt SDK snippets: three sub-flavors of TS install, each with its own example. Pick one canonical TS example; punt the rest to the TS SDK's own README. |
| L498-541 | OpenClaw + Claude Code + Cursor plugin blocks. Three plugins, each with their own README. The main README needs one sentence: "First-class plugins for Claude Code, Cursor, and OpenClaw; see `clawdstrike-plugin/`, `cursor-plugin/`, and the OpenClaw integration guide." |
| L543-568 | Observe → Synth → Tighten. A whole workflow guide nested inside Quick Start. Move to `docs/src/guides/observe-synth.md` (which exists). |
| L569-619 | TypeScript and Python `PolicyLab` automation. Three full code blocks. Punt to language-specific docs. |
| L623-651 | Spider-Sense quick-start with embedded YAML. Punt to `docs/src/reference/guards/spider-sense.md` (exists). |
| L660-674 | "Core Capabilities" `<kbd>` nav block. Redundant with section headers. |
| L763-779 | Computer Use Gateway prose section. The CUA Gateway is a real product but the README isn't the place for a layer-by-layer breakdown; that's `docs/src/guides/computer-use-gateway.md`. |
| L786-805 | Jailbreak detection 50/50 table with image. Image is fine; the four-paragraph copy is too much for a README. Two sentences and a link. |
| L822-875 | The four-quadrant IRM/Sanitization/Receipts/Spider-Sense `<table>` block. HTML tables in markdown don't render reliably on mobile GitHub. Six paragraphs of feature copy. Punt. |
| L888-912 | "Adaptive Engine" 55/45 table with image. Same reason. |
| L916-1066 | The entire Enterprise Architecture section: two mermaid diagrams, enrollment walkthrough, Spine envelope JSON, kill-switch story, Control Console feature list. ~150 lines. **Goes wholesale to `docs/enterprise/README.md`**, with a 4-line teaser left in main README. Audit V-30. |
| L1068-1080 | Compliance Mapping table (HIPAA/PCI/SOC2). Disclaimers and aspirational mappings have no business in a README. Move to `docs/compliance/`. |

Roughly 850 lines deleted from the current README. Most of it isn't lost; it relocates to `docs/`.

---

## 4. What I'd rewrite

1. **Header block** (L1-68): collapse hero + badges + one-sentence-definition into ~25 lines. One tagline only. No poem, no divider, no sigil nav, no promo gif. The hero PNG sits, then badges, then definition, then a single `What it does` paragraph.

2. **Quick start** (L141-258): tighten to one canonical install + first deny + verify + run. Three commands, six lines of output. The Desktop Agent gets a single line + link. Language-specific snippets get a `<details>` collapsed block per language, two SDKs deep (TS, Python), four lines of code each. Go gets a footnote.

3. **Guards table** (L680-691): rewrite to list all 13 guards (currently 10, per audit V-03). Source of truth is `crates/libs/clawdstrike/src/guards/`. One line each. No bold names except the guard struct names rendered as code spans.

4. **Policy + Verify combined section**: kill the separate "Policy System" + "Formal Verification" sections (L696-758) and write one ~40-line block: "Policies are versioned YAML (1.5.0 current, 1.1.0-1.5.0 supported). Validate them. Verify them. Diff them. The verifier compiles your policy to Z3 and checks for consistency, completeness, and inheritance soundness against a Lean 4 spec." Five commands. One link to `docs/formal-verification.md`. Audit V-04 (schema version drift) gets fixed in this section.

5. **Enterprise teaser** (replacing L916-1066): 4-line paragraph + one link. "When you outgrow the SDK, Clawdstrike runs as a fleet: NATS-backed control plane, signed Spine audit chain, enrollment-token bootstrap, Control Console UI. See `docs/enterprise/`."

6. **Design Principles** (L1086-1094): move from line ~1086 to line ~120. This is the "why"; it belongs near the top, between definition and quick start. Keep the four short paragraphs verbatim.

---

## 5. Target length: ~280 lines

Why 280:

- **<200 lines** loses the hero, code examples that pull weight, and the design-principles section. ripgrep's README is 261 lines for a single binary that does one thing. We do more.
- **200-300 lines** is the sweet spot for a multi-language, multi-product OSS project. axum is 308 lines including a hand-drawn feature taxonomy. tokio's main README is ~150 lines but ships ~25 sibling READMEs under `tokio-*` crates. sqlx is 547 lines and feels long. We're in axum's neighborhood.
- **>400 lines** starts re-creating the "too many sections" problem at smaller scale.
- The current 1,126 is **4x what it should be**. Going to 280 is a 75% cut. That's the right magnitude for a "scrap and rewrite" pass.

Budget breakdown follows.

---

## 6. Section-by-section outline with line budgets

```
LINE      SECTION                                BUDGET
========================================================
1-26      Header block (hero + badges + def)     26
27-40     What it does (1 paragraph)             14
41-45     ---                                     5
46-72     Quick start: install + first deny      27
73-85     Verify a policy                        13
86-96     Run a real agent                       11
97-108    Language SDKs (TS + Python only)       12
109-115   More integrations (1 paragraph)         7
116-119   ---                                     4
120-136   Design Principles (4 paragraphs)       17
137-141   ---                                     5
142-160   Guards (table of 13)                   19
161-178   Policies (1 paragraph + 5 commands)    18
179-198   Receipts + Spine (1 para + 1 example)  20
199-216   Enterprise (1 para + link)             18
217-220   ---                                     4
221-232   Adaptive Engine teaser (1 para + img)  12
233-244   Detection (1 para + jailbreak img)     12
245-248   ---                                     4
249-264   Documentation table                    16
265-272   Security                                8
273-278   Contributing                            6
279-282   License                                 4
========================================================
TOTAL                                            ~282 lines
```

Allocation rationale:

- The first 45 lines decide whether the reader continues. They get the hero, the definition, and the elevator pitch. Nothing else.
- The next 60 lines (the Quick Start chunk) decide whether the reader installs. They get a real `BLOCKED` line in their terminal, fast.
- Design Principles at line ~120 catches the reader who's now interested and asking "but is this serious." Four short paragraphs land the punch.
- Guards / Policies / Receipts (lines 142-198) are the technical meat. Tables and commands. No prose. ~56 lines.
- Enterprise / Adaptive / Detection (199-244) is a teaser triplet: paragraph + link, paragraph + image, paragraph + image. Each one says "this is real, here's where it lives." ~46 lines.
- Documentation table is the exit ramp.

---

## 7. Concrete sample copy

### Sample A: Header + definition + quick start (lines 1-90 of new README)

```markdown
<p align="center">
  <img src=".github/assets/clawdstrike-hero.png" alt="Clawdstrike" width="900" />
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/clawdstrike/actions"><img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/clawdstrike/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI"></a>
  <a href="https://www.npmjs.com/package/@clawdstrike/sdk"><img src="https://img.shields.io/npm/v/@clawdstrike/sdk?style=flat-square&logo=npm&label=npm" alt="npm"></a>
  <a href="https://pypi.org/project/clawdstrike/"><img src="https://img.shields.io/pypi/v/clawdstrike?style=flat-square&logo=python&logoColor=white&label=PyPI" alt="PyPI"></a>
  <a href="https://github.com/backbay-labs/homebrew-tap/blob/main/Formula/clawdstrike.rb"><img src="https://img.shields.io/badge/homebrew-clawdstrike-FBB040?style=flat-square&logo=homebrew" alt="Homebrew"></a>
  <a href="https://discord.gg/fdbCZHm8zM"><img src="https://img.shields.io/badge/discord-join-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/MSRV-1.93-orange?style=flat-square&logo=rust" alt="MSRV: 1.93">
</p>

# Clawdstrike

**A fail-closed policy engine and cryptographic attestation runtime for AI agents.**

Clawdstrike sits at the tool boundary — the exact point where an agent's intent becomes a real-world action — and decides what is allowed. Every decision produces an Ed25519-signed receipt. If the action wasn't signed, it didn't happen with permission.

The same engine ships as a Rust crate, a TypeScript SDK, a Python package, a CLI, a desktop agent, and a control plane for managed fleets.

> Beta software. Public APIs are stable; defaults may still tighten before 1.0.

---

## Install

```bash
brew install backbay-labs/tap/clawdstrike
clawdstrike --version
```

Then bootstrap a project:

```bash
clawdstrike init --keygen
# writes policy.yaml, config.toml, keys/clawdstrike.key{,.pub}
```

## First deny

```bash
$ clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
BLOCKED [Critical]: Access to forbidden path: ~/.ssh/id_rsa

$ clawdstrike check --action-type egress --ruleset strict api.openai.com:443
BLOCKED [Error]: Egress to api.openai.com blocked by policy

$ clawdstrike check --action-type mcp --ruleset strict shell_exec
BLOCKED [Error]: Tool 'shell_exec' is blocked by policy
```

`strict` is one of ten built-in rulesets. List them with `clawdstrike policy list`.

## Verify a policy

```bash
$ clawdstrike verify --policy strict
Consistency:  PASS  (47 formulas, 0 conflicts)
Completeness: PASS  (4/4 action types covered)
Inheritance:  PASS  (0 weakened prohibitions)
```

The verifier compiles your policy to Z3 and checks it against a Lean 4 specification. See [Formal verification](docs/formal-verification.md).

## Run a real agent

```bash
clawdstrike run --policy clawdstrike:strict -- python my_agent.py
```

The agent runs normally; every tool call hits the engine first. Denials raise a typed error in your SDK and emit a signed receipt.
```

That's ~85 lines and the reader knows what Clawdstrike is, has installed it, has seen three denials in their terminal, has verified a policy, and has run an agent under it. Everything before this in the current README delivers strictly less.

### Sample B: Guards table (lines 142-160 of new README)

```markdown
## Guards

Each guard is a composable check at the tool boundary. Returns a verdict with evidence. Fail-fast or aggregate; configured per-policy. Source of truth: [`crates/libs/clawdstrike/src/guards/`](crates/libs/clawdstrike/src/guards/).

| Guard | Catches |
| --- | --- |
| `ForbiddenPathGuard` | Reads against `.ssh`, `.env`, `.aws`, credential stores, registry hives |
| `PathAllowlistGuard` | Inverse: allowlist-only filesystem access |
| `EgressAllowlistGuard` | Outbound network by host/port; deny-by-default or allowlist |
| `SecretLeakGuard` | AWS keys, GitHub tokens, private keys, API secrets in writes |
| `PatchIntegrityGuard` | Dangerous patches: `rm -rf /`, `chmod 777`, security disables |
| `ShellCommandGuard` | Dangerous shell commands before execution |
| `McpToolGuard` | MCP tool invocations with confirmation gates |
| `PromptInjectionGuard` | Injection attacks in untrusted input |
| `JailbreakGuard` | 4-layer detection with session aggregation (15-min half-life) |
| `ComputerUseGuard` | Top-level CUA action allowlist (`observe`/`guardrail`/`fail_closed`) |
| `RemoteDesktopSideChannelGuard` | Clipboard, audio, drive mapping, file transfer, transfer-size limits |
| `InputInjectionCapabilityGuard` | Input capability constraints + postcondition probes |
| `SpiderSenseGuard` | Hierarchical threat screening: embedding similarity + optional LLM escalation ([Yu et al., 2026](https://arxiv.org/abs/2602.05386)) |

Custom guards: write them in Rust against the `Guard` trait, or ship them as sandboxed WASM modules with declared capability sets.
```

19 lines. 13 guards. One sentence each. Single source of truth pointing back at the crate. This fixes audit V-03 (the current 10-row table) by simply listing what actually exists on disk.

### Sample C: Design Principles + Receipts (lines 120-198 of new README)

```markdown
## Design

**Fail closed.** Invalid policies reject at load time. Evaluation errors deny access. Missing config defaults to restrictive. Security degradation requires explicit, auditable action.

**Proof, not logs.** Ed25519 receipts are cryptographic attestations, not log lines someone can edit. Canonical JSON (RFC 8785) ensures signatures verify identically in Rust, TypeScript, and Python.

**Same envelope, any pipe.** A signed Spine envelope is byte-identical whether it travels over NATS at 100K msg/sec, libp2p gossipsub over residential internet, or a LoRa radio at 1,200 bps. The transport is invisible to the truth layer.

**Attenuation only.** Agents delegate subsets of their capabilities, never escalate. Delegation tokens carry cryptographic capability ceilings. Privilege escalation isn't prevented by policy; it's prevented by math.

---

## Policies

Policies are YAML, schema version `1.5.0` (supported: `1.1.0`-`1.5.0`). Inherit with `extends`; merge with `replace`, `merge`, or `deep_merge`. Remote `extends` is host-allowlisted and integrity-pinned with `#sha256=`.

Ten built-in rulesets ship with the binary: `permissive`, `default`, `strict`, `ai-agent`, `ai-agent-posture`, `cicd`, `remote-desktop`, `remote-desktop-permissive`, `remote-desktop-strict`, `spider-sense`.

The operational loop is observe-synth-tighten:

```bash
clawdstrike policy observe --out run.events.jsonl -- python my_agent.py
clawdstrike policy synth run.events.jsonl --extends clawdstrike:default --out candidate.yaml
clawdstrike policy validate candidate.yaml
clawdstrike policy simulate candidate.yaml run.events.jsonl --fail-on-deny
clawdstrike policy diff clawdstrike:default candidate.yaml
```

See [Policy schema](docs/src/reference/policy-schema.md) and [Observe → Synth → Tighten](docs/src/guides/observe-synth.md).

## Receipts

Every decision is an Ed25519-signed receipt: action, verdict, policy hash, evidence, timestamp. Receipts canonicalize via RFC 8785 so signatures verify identically across Rust, TypeScript, and Python.

In enterprise deployments, receipts become Spine envelopes — hash-chained records published to NATS JetStream:

```json
{
  "seq": 42,
  "prev_envelope_hash": "sha256:abc123...",
  "fact": { "type": "policy.eval", "decision": { "allowed": false }, ... },
  "signature": "ed25519:...",
  "envelope_hash": "sha256:def456..."
}
```

Tampering with one record breaks the chain for every subsequent record. The Control API's audit consumer verifies each envelope on ingestion.

OCSF v1.4.0 export is built in: pipe receipts straight into Splunk, Datadog, Elastic, or Sumo Logic.
```

That's ~58 lines covering design, policies, and receipts. Compare to ~280 lines in the current README spread across "Design Principles," "Policy System," "Formal Verification," "Inline Reference Monitors," "Output Sanitization," "Cryptographic Receipts," and the Spine subsection of Enterprise Architecture. Same information density, ~5x compression.

---

## 8. Three critiques I expect from other debaters, and my defense

### Critique 1 (from Debater B, "soulful long-form"): "You stripped the personality. The poem and the 'EDR for the age of the swarm' tagline are what make this README *Clawdstrike's* README and not generic Rust OSS template #47."

**Defense.** I keep the personality where it earns its place. The Design Principles section keeps "same envelope, any pipe: invisible to the truth layer." That's the soul of the project written in plain prose. The poem ("The claw strikes back. / At the boundary between intent and action…") is good writing in the wrong document. It's a manifesto, not a README. I'd be the first to commit `docs/about/manifesto.md` and link to it from the README footer. But the first 80 lines of a README are not real estate for prose-as-decoration. They're real estate for the reader's first decision: do I keep reading. Three competing taglines (poem at L17-24, "EDR for the age of the swarm" at L38-39, the actual definition at L84) is a tell that nobody made the hard cut. I'm making it: the L84 definition is the tagline. The other two go to the manifesto.

On "EDR for the age of the swarm" specifically: it's a category-positioning move (claiming EDR-class importance for AI agent security), and category positioning belongs on a blog post, not above the first command-line example. The reader either knows what EDR is and finds the analogy a stretch, or doesn't know what EDR is and finds the tagline opaque. Either way it loses.

### Critique 2 (from Debater C, "feature-list shotgun"): "You moved enterprise architecture, computer-use gateway, jailbreak detection, IRM, output sanitization, and threat intel to deep docs. Someone evaluating Clawdstrike against Lakera or Prompt Armor or any of the other vendors needs to *see* the feature surface on the README. You're hiding the product."

**Defense.** Evaluators don't read READMEs to comparison-shop feature lists. They read READMEs to figure out if the project is technically serious and operationally credible. The README that wins the evaluation is the one where every claim is testable in 60 seconds: `clawdstrike check`, `clawdstrike verify`, `clawdstrike policy diff`. Feature catalogs lose to working demos. A reader who wants the matrix view of "does this product do CUA?" / "does this product do prompt injection detection?" / "does this product do SIEM export?" gets it from the Guards table (13 entries, one line each) and the Documentation table at the end. The current README's IRM/Sanitization/Receipts/Spider-Sense quadrant table at L822-875 is six paragraphs of feature copy that says less per word than a clean 13-row Guards table.

The Enterprise section is the exception that proves the rule: 150 lines of enterprise architecture in the main README signals "we wrote this because we thought it would close enterprise deals," not "we built this." Move it to `docs/enterprise/README.md` where it can breathe: diagrams, walkthroughs, kill-switch sequence, enrollment handshake, the works. The main README gets four lines that say "the same engine runs at fleet scale; see `docs/enterprise/`." That's not hiding; that's respecting the difference between an entry point and a reference.

### Critique 3 (from Debater D, "minimalist 150-line zealot"): "If you're cutting, cut harder. tokio is 150 lines. ripgrep is 261. You're at 280 with bloat in the middle. Drop Design Principles too: that's blog content. Drop the Receipts JSON block, link to docs. Drop the Adaptive Engine teaser entirely. Get to 180."

**Defense.** Length isn't a virtue or a sin in itself; load per line is. I've ridden each of my 280 lines for what it carries. Design Principles (17 lines) is the project's intellectual identity expressed in 4 sentences. Cutting it means the reader who skims the Quick Start and the Guards table never encounters the "fail closed / proof not logs / same envelope, any pipe / attenuation only" frame. Those four ideas are what separates Clawdstrike from "we wrote a YAML linter for OpenAI tool calls." Killing them to hit a number is the wrong trade.

The Receipts JSON block (12 lines of envelope schema) is the kind of thing a reader copies, pastes, and looks at when they're deciding whether to integrate. It shows the wire format in concrete bytes. "See docs/spine-envelope.md" doesn't.

The Adaptive Engine teaser (~12 lines + image) earns its place because it tells the reader something they probably didn't know: this thing handles the network partition case. "What happens when the control plane goes down?" is one of the first questions an SRE asks, and most agent-security products answer "we don't know, file a support ticket." Showing that we have a named answer to it ("Adaptive engine: standalone, connected, degraded, fail-closed") differentiates the product in 12 lines.

The 150-line target is a Twitter-style maximalist minimalism. Going under 250 starts costing real information.

---

## 9. Trade-offs

What my approach loses compared to **"soulful long-form"** (the version that keeps the poem, the manifesto framing, the "EDR for the age of the swarm" punch, the Without/With comparison, the philosophical asides):

- Readers who arrive via a blog post or social-media share get less *vibe*. The current README has a recognizable tone-of-voice in the first 30 lines; my version has one in the first 30 lines of the Design Principles block (line 120+). That's a 90-line delay on encountering the project's personality.
- "EDR for the age of the swarm" was working as a Hacker News headline. Removing it removes a memorable phrase. The product loses some marketing power on the front door.
- The Without/With table, while a cliche, *does* teach: a reader who doesn't already know why log-based security fails learns it in 60 seconds from L108-135. My version teaches the same lesson in the Design Principles paragraphs but expects more from the reader.

What my approach loses compared to **"feature-list shotgun"** (the version that keeps every section, just tightens copy in place):

- An evaluator who wants the matrix view of every feature in one place has to navigate to `docs/` to find Compliance / Adaptive / CUA / IRM / etc. They lose the "everything is here" reassurance.
- Casual scrollers who don't read the Quick Start but do scroll to the Enterprise section feel the abrupt cut to `docs/enterprise/`. The current README's enterprise mermaid diagrams *do* communicate "this is real engineering" at a glance even without reading the prose.
- Spider-Sense, Computer Use Gateway, and Adaptive Engine each get one paragraph instead of a section. Each was probably ~6 months of work by a real engineer who would prefer their feature have its own README real estate.

What my approach **gains**:

- A reader can answer "what is this?" "how do I install it?" and "what does it do?" in three scroll-screens.
- The Guards table becomes a single source of truth that mirrors `crates/libs/clawdstrike/src/guards/`, killing the guard-count drift problem (audit V-03).
- Schema version 1.5.0 lives in one place (audit V-04).
- The broken `divider.png` reference is gone (audit V-09).
- The README stops competing with the docs site. `docs/src/` already has guides for every section I deleted; the README's job is to point at them, not duplicate them at lower quality.
- Maintenance burden drops: a 280-line README has 4x fewer places where a feature change leaks documentation drift than a 1,126-line one.

What I'd defend most strongly: **the cut to enterprise architecture**. 150 lines of mermaid + walkthroughs on the front door tells every casual reader "this is enterprise software wearing OSS clothes." Moving it to `docs/enterprise/` lets the OSS surface read like OSS and the enterprise surface read like enterprise. Both audiences get a better experience.

What I'd reconsider under cross-fire: **the promo-reel GIF**. If the Workbench is genuinely a tier-1 product surface (alongside the CLI and the SDK), it deserves screen-time on the front door. If it's one of eight apps, it doesn't. I want to see Debater B or C make that case before committing.

---

End of vision.
