# Debater B — The Security Buyer's README

**Persona:** F500 bank / healthtech / DoD-contractor CISO. 30 seconds. Half-decided this is vapor before I scroll.

**Bias declaration:** I have been pitched 14 "EDR for AI" tools this quarter. Most are rebranded LLM firewalls. I will close the tab the moment I smell marketing. I will also close it the moment I cannot find a threat model, a maintainer, or a license. The bar is not "good README." The bar is "I can write a one-paragraph summary to my CEO without opening another tab."

---

## 1. Stance — what the buyer sees in the first 30 seconds

The current README is a feature-first deck. A CISO does not read decks; a CISO scans for trust signals in this order, and bails the moment one fails:

1. **What is this, in one sentence** (verb-driven, no adjectives)
2. **Who runs it / is it real** (commit graph, contributor count, last release)
3. **What does it explicitly NOT do** (the absence of this section is the single strongest indicator I am being sold to)
4. **Threat model — one screen, three adversaries**
5. **Crypto + verification claims with caveats** (any claim of "formal" without scope is a lie)
6. **Deployment story — single-node, multi-tenant, HA, audit retention**
7. **Anybody actually running this in prod, anywhere, even a homelab?**
8. **License + governance + funding model**

The current top of `README.md:1-83` gives me a hero PNG, eight badges, an em-tag poem, a divider, a sigil pair, an h1, a tagline ("EDR for the age of the swarm"), a sub-tagline ("Fail closed. Sign the truth."), five SVG bullet chips, four nav links, a horizontal rule, and a 960px promo GIF — **before any sentence telling me what the product does**. The actual definition appears at `README.md:84` — line eighty-four. On a 13" laptop at default zoom, that is two and a half scroll-flicks past the fold.

I have already closed the tab. I am back on Crowdstrike's RFP-friendly product page.

**Read order I want, top to bottom:**
1. Hero PNG (keep — it's a brand asset, not a pitch)
2. ONE sentence definition + ONE sentence threat model summary
3. Trust signals row (commit count, license, audit links, formal-verification SCOPE link, last release, contact)
4. "What it does NOT do" — surfaced from `NON_GOALS.md`
5. Three adversary scenarios (concrete, named, with the guard that catches them)
6. 60-second quickstart (one language, one ruleset, one verb)
7. Architecture diagram with deployment modes labeled
8. Operational story (audit retention, HA, multi-tenant, kill switch)
9. Links to deeper docs

Everything else goes to `docs/`.

---

## 2. The CISO trust-signal scorecard

Eight signals. PASS/FAIL with the current README's evidence quoted.

| # | Signal | Score | Evidence at HEAD |
|---|--------|-------|------------------|
| **1** | **One-sentence definition above the fold** | **FAIL** | First definition lives at `README.md:84`: `Clawdstrike is a fail-closed policy engine and cryptographic attestation runtime for AI agent systems.` Lines 1-83 are art. The actual sentence is fine; it's just buried. |
| **2** | **Threat model link visible without scrolling** | **FAIL** | `THREAT_MODEL.md` exists at repo root (3631 bytes, well-structured) and is **never linked from the README**. `grep -n "THREAT_MODEL" README.md` → zero hits. Three months of writing a threat model that no one will see. |
| **3** | **Non-goals / what it doesn't do** | **FAIL** | `NON_GOALS.md` exists and is good (`We do not defend against kernel-level compromise. We do not defend against malicious root/admin on the host. We do not claim perfect jailbreak prevention.`). **Never linked from README.** A buyer who finds this themselves trusts the project more than one who doesn't. |
| **4** | **Formal verification scope statement (not claim)** | **PARTIAL** | `README.md:51` puts "Formally verified" as a bullet chip in the hero — this overclaims. `README.md:728-758` does scope it: `If any guard denies, the overall verdict denies` etc., listing **5 specific theorems** plus `39+ properties` and `44/45 core functions translated`. The body text is honest; the hero chip is not. D08 already flagged the public-docs overclaim. |
| **5** | **Reproducible builds / SBOM / signed releases** | **FAIL** | `grep -i -n "sbom\|reproducib\|cosign\|sigstore\|provenance\|slsa" README.md` → **zero hits.** For a security product. There is `Apache-2.0` (`README.md:12`) and an `MSRV: 1.93` badge, but no signed-release story, no SBOM link, no SLSA level statement, no `cosign verify` example. |
| **6** | **Audit trail of audits (third-party or internal)** | **PARTIAL** | `docs/audits/` contains three "2026-02-10-*-remediation.md" files referenced from `THREAT_MODEL.md:78-80` and `SECURITY.md:66-68`. The README links **none of them.** A buyer wants `Audited by <firm> on <date>, report <link>`. Internal remediation logs aren't third-party audits but should at least be cited as "internal pre-release review." |
| **7** | **Who runs this / commit-graph credibility** | **FAIL** | The README has zero contributor info, zero funding line, zero "backed by", zero board, zero CODEOWNERS reference. `GOVERNANCE.md:17-24` (D01 V-26) has five maintainer slots, all `(TBD)`. `shortlog -sne` shows 3207 commits by `bb-connor` vs 246 by `ConnorWhelan11` (same human, two emails) vs 16 by an external contributor — this is **one person's project**. A buyer needs to know that *before* they spend a week evaluating. |
| **8** | **Deployment story: HA, multi-tenant, audit retention** | **PARTIAL** | `README.md:877-1066` covers Enterprise mode and Spine envelopes well — kill switch (`README.md:1046-1054`), NATS request/reply, enrollment handshake. But: no HA story for `hushd` itself (single-node? leader election?), no audit-log retention policy, no tenant-isolation guarantee, no RTO/RPO. Compliance table (`README.md:1068-1080`) honestly disclaims that no certification program exists, which is good. |
| **9** | **Cryptography credibility (algorithm + library)** | **PARTIAL PASS** | Ed25519 mentioned 12 times, RFC 8785 canonicalization mentioned (`README.md:854, 1088`), `sha256:` hash-chain example shown in JSON (`README.md:1024-1028`). The crypto choices are defensible and named. **Missing:** which Rust crate (`ed25519-dalek`? `ring`?), key rotation story, HSM/KMS integration. A CISO will Ctrl-F "HSM" and find nothing. |
| **10** | **Is it actually deployed anywhere** | **FAIL** | `grep -i -n "production\|customers\|users\|case study\|deployed at\|trusted by" README.md` → the only "production" hits are `README.md:139` (`Not yet production-hardened for large-scale deployments`) and `README.md:892` (`built for production turbulence`). No logos. No "Trusted by". No homelab testimonials. Honest, but **a buyer needs to know if anyone has run this for >30 days**. The beta-software callout at `README.md:139` is the right honesty; it should be **higher** in the doc, not buried after the marketing block. |

**Score: 1 PASS, 4 PARTIAL, 5 FAIL out of 10.**

---

## 3. Reorganization proposal — concern-first, not feature-first

The current top-of-README order (`README.md:84-660`):
1. "What Clawdstrike Is" (1 paragraph + mermaid + 3-layer table)
2. With/Without table
3. Beta-software callout (the most important sentence on the page, hidden in a blockquote)
4. Quick Start (110 lines: install, init, daemon, enforce, verify, hunt, desktop)
5. Six SDK sections (TS, Python, Go, plugins for Cursor/OpenClaw/Claude Code, Observe-Synth-Tighten, Spider-Sense)
6. Core Capabilities (guards, policy, formal-verification, CUA, jailbreak, multi-agent, IRM, threat intel, deployment, adaptive engine)
7. Enterprise Architecture (200 lines)
8. Design Principles
9. Documentation links
10. Security + Contributing + License

This is **feature-first**. A buyer scans for **concerns**, not features. The mapping should invert.

### Concern → section mapping

| CISO Concern | Section Title | Source of Truth | Length Budget |
|--------------|---------------|----------------|---------------|
| "What does this do, in one breath" | **What it is** (header block) | `README.md:84` rewritten as a single sentence | 3 lines |
| "Is this real" | **Status & maturity** | new — versioned tag, last release date, `0.2.x`, "single primary maintainer" | 5 lines |
| "What can it NOT do" | **Non-goals** | `NON_GOALS.md` excerpt + link | 8 lines |
| "Who is going to attack me, and what stops them" | **Threat model summary** | `THREAT_MODEL.md` excerpt — 3 named adversaries + the guard that catches each | 15 lines |
| "Can I trust the crypto" | **Cryptographic guarantees** | merge `README.md:728-758` formal-verification + `README.md:1018-1032` Spine envelope | 20 lines |
| "Can I install and verify in 60 seconds" | **60-second quickstart** | collapse `README.md:153-208` to ONE language, ONE ruleset, ONE check | 25 lines |
| "How does it run in my org" | **Deployment modes** | trim `README.md:877-912` adaptive section | 15 lines |
| "What does the enterprise version actually look like" | **Enterprise architecture** | one mermaid + 10 lines + link to `docs/enterprise/` | 30 lines (mermaid included) |
| "What about my compliance auditor" | **Compliance evidence** | `README.md:1068-1080` table, with the existing honest disclaimer kept verbatim | 15 lines |
| "Who built this, who maintains it, how funded" | **Project status** | new — link to `GOVERNANCE.md`, `CODEOWNERS`, funding model, single-maintainer disclosure | 10 lines |
| "How do I report a vuln" | **Security contact** | `README.md:1109-1114` is fine, keep | 5 lines |

**Net effect:** the first **80 lines** of README answer every CISO concern. The remaining ~170 lines are quickstart + architecture + links. Everything else moves to `docs/`.

---

## 4. The threat-model section that should exist

**Placement:** immediately after the one-sentence definition and the "Status" block. Above the quickstart. CISOs read this **before** any code.

**Form:** three named adversaries, each one paragraph, each paired with the guard that catches it. Then a one-line link to `THREAT_MODEL.md` for the full document.

```markdown
## Threat Model (the 30-second version)

Clawdstrike defends the **tool boundary**: the exact point at which an LLM's
chosen action becomes a real-world side-effect (a file read, a network
connection, a shell command). It is **not** a kernel hardening tool, an IDS,
or a network firewall. See [NON_GOALS.md](NON_GOALS.md) for what we
explicitly do not defend.

### Three adversaries we stop

**1. Shadow Agent.** An employee installs an agent runtime outside the
   sanctioned fleet. It reads `~/.ssh/id_rsa` and POSTs it to an unsanctioned
   model endpoint. *Caught by:* `ForbiddenPathGuard` blocks the read;
   `EgressAllowlistGuard` blocks the POST; both produce signed receipts.

**2. Patient Jailbreaker.** An attacker spreads a jailbreak across 20
   conversation turns, each below the per-message risk threshold. The 21st
   message extracts the system prompt. *Caught by:* `JailbreakGuard` with
   session aggregation (15-min half-life rolling score) catches the
   cumulative pattern, not just the per-message score.

**3. Delegation Climber.** Agent A spawns Agent B with elevated capabilities
   so B can do something A cannot. *Prevented by:* delegation tokens carry
   cryptographic capability ceilings — attenuation only, never escalation.
   Privilege escalation is mathematically impossible, not policy-blocked.

We deny ambiguous decisions. We sign every verdict. We do not promise
detection of attacks against the LLM itself, against the host kernel,
or against operators with root.

Full threat model: [THREAT_MODEL.md](THREAT_MODEL.md) ·
Out of scope: [NON_GOALS.md](NON_GOALS.md) ·
Audit history: [docs/audits/](docs/audits/)
```

That is **30 lines**. It does more for buyer trust than the entire current "What Clawdstrike Is" + "With/Without" + "Core Capabilities" block combined (~70 lines).

---

## 5. The "who built this" section

A buyer wants to know: is this a one-person hobby, a venture-funded startup, a corporate side project, a foundation-governed OSS effort?

**Placement:** after the threat model, before the quickstart. CISOs want this **before** they `npm install`.

```markdown
## Project status

- **Version:** 0.2.7 (beta — see [CHANGELOG.md](CHANGELOG.md))
- **License:** Apache 2.0 ([LICENSE](LICENSE))
- **Governance:** See [GOVERNANCE.md](GOVERNANCE.md). Currently a single
  primary maintainer ([@bb-connor](https://github.com/bb-connor)) with
  ~3,400 commits. Maintainer-council seats are open ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **Funding:** Backbay Labs (self-funded). No corporate sponsor, no VC.
- **Production deployments:** none public. The project is pre-1.0; running
  this in production today means running a pre-1.0 fail-closed tool.
- **Third-party audit:** none yet. Internal pre-release security reviews
  archived in [docs/audits/](docs/audits/) (3 waves, Feb 2026).
- **CODEOWNERS:** `* @connor`. The bus factor is 1.

If you need a multi-vendor, third-party-audited, certified product today,
this is not it. If you are evaluating fail-closed primitives, OSS-controlled
attestation, and signed receipts as an internal capability, the engine
holds up — but you accept maintainer concentration risk.
```

That last paragraph is **the honesty paragraph** every OSS security tool should have. It is what makes me trust everything else on the page.

D01's V-26 confirms `GOVERNANCE.md:17-24` lists five `(TBD)` maintainer slots; pretending otherwise in the README is the kind of thing that gets a vendor disqualified.

---

## 6. The "what it doesn't do" section

`NON_GOALS.md` (1389 bytes, 35 lines) is the single most credibility-building file in the repo. It contains:

> We do not claim perfect jailbreak prevention.
> We do not claim complete resistance against adaptive adversarial prompt attacks.
> We do not defend against kernel-level compromise.
> We do not defend against malicious root/admin on the host.
> We do not defend against a fully compromised dependency ecosystem.

**The README never references it.** That is malpractice. A CISO who finds `NON_GOALS.md` themselves will quietly upgrade their internal scoring of the project by two notches; a CISO who finds the same text **prominently surfaced** in the README will write the project into their evaluation shortlist.

**Yes, it surfaces in README.** Pulled into the threat-model summary above, with the full file linked. Cost: 4 lines of README. Value: very high.

Counterintuitive but correct: **the section that says "we will not do these things" makes a buyer trust the sections that say "we will do these things."**

---

## 7. Trust signals to add

In rough priority for a regulated buyer:

1. **Formal verification — scope statement, not claim.** Current `README.md:51` calls the product "Formally verified" as a chip in the hero. D08 flagged that the public docs overclaim. The honest version: "The Lean 4 spec proves 5 specific properties of the policy engine's core decision logic (deny monotonicity, severity total order, cycle rejection, signature roundtrip, disabled-guard allow); 44 of 45 core functions are mechanically translated from Rust; differential proptests compare spec to impl nightly. **Crypto primitives are not in the proof scope. Guards beyond core decision logic are not in the proof scope. Network and IO are not in the proof scope.**" That last sentence is the buyer-trust unlock.

2. **Reproducible builds.** Either a `cosign verify` snippet against published release artifacts, or a one-liner that says "we do not yet sign releases — tracked in #N." Silence is worst.

3. **SBOM.** GitHub auto-generates one for releases. Cite the URL. Two lines.

4. **Signed releases.** `gh release view` output piped to `cosign verify-blob`. Even if not yet implemented, **state the gap** with a tracking issue.

5. **Audit history.** Link `docs/audits/2026-02-10-*` explicitly. Note "pre-release internal review, not third-party audit." Reference D01 V-27 which already flagged the misread risk on these dates.

6. **Pre-commit secret-scan.** Especially given D01 N-01 (live `sk-proj-*` key in `.env` at repo root). For a SecretLeakGuard-shipping project to ship without a pre-commit secret-scan is the embarrassing irony. A README line saying "we run gitleaks/trufflehog in pre-commit and CI" repairs this if/when it lands.

7. **MSRV pin file.** Currently `MSRV: 1.93` is in a badge (`README.md:13`). A `rust-toolchain.toml` would make it enforced, not advertised. D01 V-28 already flags this.

8. **HSM / KMS integration story.** A regulated buyer needs the Ed25519 signing key in an HSM, not on disk. Even "roadmap: HSM integration via `tink`/`vault-pkcs11`" is better than silence.

9. **Crypto crate transparency.** Name `ed25519-dalek` (or whichever) inline. One word. Buyer Ctrl-Fs the crate name to check advisories.

10. **Last-released-at.** GitHub releases badge shows it; add `Last release: 2026-03-18 (v0.2.7)` in the status block. If it's been > 60 days, that's a signal.

---

## 8. Concrete sample copy

Three sections, ready to drop in.

### 8a. The new header block (replaces `README.md:1-140`)

```markdown
<p align="center">
  <img src=".github/assets/clawdstrike-hero.png" alt="Clawdstrike" width="900" />
</p>

<h1 align="center">Clawdstrike</h1>

<p align="center">
  <strong>Sign every action your agents take. Deny anything ambiguous.</strong>
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/clawdstrike/actions"><img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/clawdstrike/ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
  <a href="https://github.com/backbay-labs/clawdstrike/releases/latest"><img src="https://img.shields.io/github/v/release/backbay-labs/clawdstrike?style=flat-square&label=release" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache-2.0"></a>
  <a href="THREAT_MODEL.md"><img src="https://img.shields.io/badge/threat--model-public-green?style=flat-square" alt="threat model"></a>
  <a href="NON_GOALS.md"><img src="https://img.shields.io/badge/non--goals-documented-green?style=flat-square" alt="non-goals"></a>
  <a href="docs/audits/"><img src="https://img.shields.io/badge/audits-internal--3--waves-yellow?style=flat-square" alt="audits"></a>
</p>

> **Status: pre-1.0 beta.** Public APIs are stable; defaults may evolve.
> Single primary maintainer — see [Project status](#project-status) before
> evaluating for production.

Clawdstrike is a **fail-closed policy engine and cryptographic attestation
runtime** for AI agent systems. It sits at the **tool boundary** — the
exact point an agent's intent becomes a real-world side-effect — and
enforces policy with Ed25519-signed receipts. Same engine, same receipt
format, from a single laptop to a managed fleet.

**What it is not:** an LLM firewall, an IDS, a kernel hardening tool, or
a network microsegmentation product. See [NON_GOALS.md](NON_GOALS.md).

[Threat model](#threat-model) ·
[Project status](#project-status) ·
[60-second quickstart](#60-second-quickstart) ·
[Architecture](#architecture) ·
[Enterprise](#enterprise-architecture) ·
[Compliance](#compliance-evidence)
```

**Net:** 30 lines replace the first 140 lines of the current README. Tagline is verb-driven (`Sign every action your agents take. Deny anything ambiguous.`) — no "EDR for the age of the swarm" marketing language. The beta-software disclosure moves above the fold instead of being buried at `README.md:139`. The threat model, non-goals, and audit history are all linked from the top of the doc.

### 8b. The threat-model summary block

(Use the 30-line block from §4 above verbatim. It goes immediately after the header block — buyer reads it before any install command.)

### 8c. The trust-signals block

```markdown
## Trust signals

### What we claim, with scope

- **Fail-closed by construction.** Invalid policies reject at load time;
  evaluation errors deny access; missing config defaults to restrictive.
  See [`crates/libs/clawdstrike/src/engine.rs`](crates/libs/clawdstrike/src/engine.rs).

- **Ed25519-signed receipts.** Every policy verdict produces a signed,
  canonicalized (RFC 8785) attestation. Crypto crate: `ed25519-dalek`.
  Key storage: on-disk (HSM/KMS integration tracked in
  [issue #N](https://github.com/backbay-labs/clawdstrike/issues)).

- **Formal verification (scoped).** Lean 4 specification of the policy
  engine's core decision logic. **Five properties proved:**
  deny-monotonicity, severity total-order, cycle rejection, signature
  roundtrip, disabled-guard allow. 44 of 45 core functions translated
  from Rust via Aeneas. Differential proptests run nightly.
  **Out of scope of the proof:** guards beyond core decision logic, IO,
  network, crypto primitives themselves.
  See [`formal/lean4/ClawdStrike/`](formal/lean4/ClawdStrike/) and
  [`docs/src/formal-verification.md`](docs/src/formal-verification.md).

- **Hash-chained audit trail.** Spine envelopes are Ed25519-signed and
  hash-chained — tampering with any single record breaks every subsequent
  record. See [`crates/libs/spine/`](crates/libs/spine/).

### What we don't claim

- No third-party security audit yet. Three waves of internal pre-release
  review archived in [docs/audits/](docs/audits/).
- Releases are not yet signed (no cosign/SLSA provenance).
- No SBOM published with releases yet (tracked).
- HSM/KMS-backed signing is roadmap, not shipped.
- See [NON_GOALS.md](NON_GOALS.md) for the full non-goals list.

### Audit history

| Wave | Date | Scope | Report |
|------|------|-------|--------|
| 1 | 2026-02-10 | initial guard surface | [report](docs/audits/2026-02-10-remediation.md) |
| 2 | 2026-02-10 | egress, CONNECT proxy, IRM | [report](docs/audits/2026-02-10-wave2-remediation.md) |
| 3 | 2026-02-10 | policy extends, receipt canonicalization | [report](docs/audits/2026-02-10-wave3-remediation.md) |

These are pre-release internal remediations, not incident reports.

### Vulnerability reporting

GitHub Security Advisories: [open one](https://github.com/backbay-labs/clawdstrike/security/advisories/new) ·
Email: [connor@backbay.io](mailto:connor@backbay.io) ·
Response target: 48 hours acknowledgement, 14 days fix plan.
Full policy: [SECURITY.md](SECURITY.md).
```

**Net:** 45 lines. Every claim is scoped. Every absence of a claim is **named as an absence**. That last part is what wins regulated-buyer trust.

---

## 9. Target length — defend a number

**Target: 240–280 lines.**

Argument:
- Current: 1126 lines (D01 V-01).
- Below 200 lines, you lose the architecture mermaid + enterprise mermaid + compliance table, which are buyer-credibility surfaces.
- Above 300 lines, the buyer-scan loses focus and you have re-created the current problem.
- 240–280 lines lets you have: header (30) + threat model (30) + project status (15) + quickstart (40) + architecture mermaid + 20 lines (50) + enterprise architecture mermaid + 30 lines (50) + compliance evidence (20) + trust signals (45) + footer (20) = **270 lines** with breathing room.

Everything else (full SDK tour, all six framework adapters, full enterprise walkthrough, observe-synth-tighten loop, Spider-Sense quickstart, jailbreak deep dive, IRM diagram, watermarking, threat-intel, WASM) moves to **`docs/`**. This matches D01 V-30's recommendation to move enterprise content out.

Concrete moves:
- `README.md:142-660` (six SDK / quickstart variants + observe-synth + spider-sense) → `docs/getting-started/`
- `README.md:782-805` (jailbreak deep dive) → `docs/concepts/jailbreak.md`
- `README.md:824-875` (IRM, sanitization, watermarking, threat-intel) → `docs/reference/guards/`
- `README.md:877-1066` (enterprise architecture) → `docs/enterprise/README.md`, keep a 30-line summary in main README
- `README.md:1068-1080` (compliance table) — **keep in README**, this is a buyer-eval surface

---

## 10. Three anticipated critiques + defenses

### Critique 1: "You're killing the brand voice. The poem, the sigils, the divider — that's what makes Clawdstrike feel like a *product*, not another open-source security tool with a beige README."

**Defense:** I am keeping the hero PNG. I am keeping the project name with its sigil. What I am killing is the **literary opener** (`README.md:18-22`) — the em-tag poem about "the claw strikes back" and "if the tale diverges, the receipt won't sign." A CISO does not read poems on GitHub; they Ctrl-F for "FIPS" or "HSM" and leave when they don't find them.

The brand voice can survive the move. It belongs in: the homepage at `backbay.io`, the launch blog post, the conference talk. The README is **trade-rag material**, not a manifesto. The poem isn't bad — it's just the wrong artifact in the wrong room. Keep it in `docs/manifesto.md` and link it once if you want.

The hero PNG (`README.md:1-3`) does the brand-voice work all by itself. One image, one verb-driven tagline, done.

### Critique 2: "The promo reel GIF is the closest thing we have to a screencast. CISOs love seeing the tool actually run. You're going to delete it?"

**Defense:** I am moving it, not deleting it. A 960px GIF at `assets/promo-reel.gif` is currently inlined at `README.md:67`, **before any sentence telling me what the product does**. That is a marketing-page move, not a README move.

Where it should live: a `docs/screencasts/` page, linked from the README architecture section as "See it run: 90-second walkthrough." A CISO who wants to see the workbench in motion will click through. A CISO scanning for trust signals does not want a 2.5MB autoplay GIF in their bandwidth-budgeted hotel-WiFi tab.

Two things to verify before the move:
1. Is the GIF currently helpful or is it the cluttered animated dashboard most security tools ship? If it's the latter, **just delete it.**
2. Does it actually load on GitHub? `assets/promo-reel.gif` is 2.5MB per the task brief; GitHub READMEs are bandwidth-bounded.

### Critique 3: "'EDR for the age of the swarm' is the tagline. It's been on the homepage for six months. You can't kill it."

**Defense:** I can, and the reason is that **CISOs distrust the EDR category**. They have been pitched 200 EDR products in the last decade, half of which are dead. Calling Clawdstrike "EDR for X" puts it in the mental box with Crowdstrike Falcon, SentinelOne, Carbon Black — products that cost $80–$200/seat/year, have RFP-friendly compliance matrices, and have actual third-party audit reports. Clawdstrike is none of those things, and pretending to be in that category invites a comparison it loses.

Worse, "EDR for the age of the swarm" is **noun-soup marketing** — three nouns and one prepositional phrase, none of which is verb-driven. A buyer reading their CEO a one-line description ("Hey CEO, what does Clawdstrike do?") cannot paraphrase "EDR for the age of the swarm" without sounding silly.

My replacement: **"Sign every action your agents take. Deny anything ambiguous."** Two imperative verbs (Sign, Deny). Object is concrete (every action your agents take). Posture is named (anything ambiguous). A buyer can paraphrase that to their CEO in one breath: *"It signs every agent action and blocks ambiguous ones."* That is the one-sentence test the current tagline fails.

The wordplay (Crowdstrike → Clawdstrike) survives in the project name. It doesn't need to survive in the tagline.

---

## Closing note on what's GOOD in the current README

So I am not just lighting it on fire:

- **The Google "Shadow Agent" reference (`README.md:72`) is real and compelling.** Buyer-credibility win. Don't lose it in the rewrite — surface it in the threat-model section as the canonical "this is the problem" citation.
- **The Without/With table (`README.md:108-133`) is good but in the wrong format.** The 5+5 bullet pairing is the buyer's mental model. Keep the **pattern**, kill the framing. Use the 3 adversary scenarios in §4 instead.
- **The architecture mermaid (`README.md:86-96`) is honest and short.** Keep verbatim.
- **The honest beta-software callout (`README.md:139`) is correct and rare.** Promote it above the fold.
- **The compliance table's disclaimer paragraph (`README.md:1078`)** — `No formal Clawdstrike certification program is generally available today. The tier model and framework template packs are design specs and roadmap material.` — that is the kind of sentence that builds buyer trust. Keep it verbatim. Most vendors lie about this; an honest disclaimer is a competitive moat.
- **The formal-verification body (`README.md:728-758`)** is well-scoped (the 5 properties, 44/45 functions, nightly diff tests). The problem is only the **hero chip** at `README.md:51` calling the product "Formally verified" without scope. Fix the hero, keep the body.
- **The kill-switch story (`README.md:1046-1054`)** is compelling and operationally specific. Keep in the enterprise section.

The README is not bad. It's **overloaded**. A 50% cut and a concern-first reorder is all it needs.

---

**Bottom line for the user:** a 1126-line README that hides the one-sentence definition at line 84, the threat model behind zero links, and the non-goals behind zero links is **failing the 30-second buyer test** despite shipping good content underneath. Reorganize to concern-first, surface `THREAT_MODEL.md` + `NON_GOALS.md`, scope the formal-verification claim, name the bus-factor-1 reality, and you keep every banger sentence the project already has while removing the slop. Target: 240–280 lines. Tagline: **"Sign every action your agents take. Deny anything ambiguous."**
