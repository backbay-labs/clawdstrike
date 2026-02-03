# Terminology

This page defines key terms used throughout Clawdstrike documentation.

## Core Concepts

| Term | Definition |
|------|------------|
| **Guard** | A composable security check that evaluates an action against policy rules. Examples: `ForbiddenPathGuard`, `EgressAllowlistGuard`, `JailbreakGuard`. |
| **Policy** | A YAML configuration file that defines guard behavior, patterns, and rules. Policies can inherit from rulesets via `extends`. |
| **Ruleset** | A pre-configured policy bundled with Clawdstrike. Examples: `default`, `strict`, `ai-agent`, `cicd`, `permissive`. |
| **Receipt** | An attestation record capturing tool invocations, verdicts, and provenance (policy hash, violations, timestamps). |
| **SignedReceipt** | A `Receipt` cryptographically signed with Ed25519 for tamper-evidence. Can be verified independently. |

## Actions & Verdicts

| Term | Definition |
|------|------------|
| **GuardAction** | An action being evaluated by guards. Types: `FileAccess`, `FileWrite`, `Patch`, `NetworkEgress`, `McpTool`, `Custom`. |
| **GuardContext** | Execution context passed to guards: working directory, session ID, agent ID, custom metadata. |
| **GuardResult** | The outcome of a guard evaluation: `allowed` (bool), `verdict`, `violations`, `evidence`. |
| **Verdict** | The decision for an action: `Allow`, `Warn`, or `Block`. |
| **Violation** | A specific rule that was triggered, including the guard name, pattern matched, and severity. |

## Detection & Analysis

| Term | Definition |
|------|------------|
| **Jailbreak** | An attempt to manipulate an LLM into bypassing safety alignment or operational constraints. Distinct from prompt injection. |
| **Prompt Injection** | An attempt to hijack LLM instructions via untrusted input (web pages, documents, user content). |
| **Output Sanitization** | Inspection and redaction of LLM-generated content to prevent leakage of secrets, PII, or internal information. |
| **Watermarking** | Embedding invisible markers in prompts for attribution, tracing, and forensics. |

## Cryptographic Primitives

| Term | Definition |
|------|------------|
| **Ed25519** | The elliptic curve signature scheme used for signing receipts. Fast, secure, deterministic. |
| **SHA-256** | The hash function used for content hashing and fingerprinting. |
| **Keccak-256** | An alternative hash function (Ethereum-compatible) available in `hush-core`. |
| **Merkle Tree** | A hash tree structure enabling inclusion proofs for verifiable execution chains. |
| **Canonical JSON (JCS)** | [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) serialization ensuring deterministic JSON across implementations. |

## Architecture Components

| Term | Definition |
|------|------------|
| **HushEngine** | The main entry point for Clawdstrike. Loads policy, runs guards, creates receipts. |
| **IRM (Inline Reference Monitor)** | Runtime interception layer for sandboxed modules. Types: `FilesystemIrm`, `NetworkIrm`, `ExecutionIrm`. |
| **Adapter** | A framework-specific integration that bridges Clawdstrike to agent runtimes (OpenClaw, Vercel AI, LangChain, etc.). |

## Policy Configuration

| Term | Definition |
|------|------------|
| **Pattern** | A glob or regex string used by guards to match paths, domains, or content. |
| **Exception** | A pattern that overrides a block rule, allowing specific matches. |
| **Allowlist** | A list of explicitly permitted values (domains, tools, paths). |
| **Blocklist** | A list of explicitly denied values. |
| **Default Action** | The fallback verdict when no pattern matches: `allow` or `block`. |

## Session & Context

| Term | Definition |
|------|------------|
| **Session** | A conversation or task context tracked across multiple messages for aggregated risk scoring. |
| **Session Aggregation** | Accumulating risk signals across a session to detect multi-turn attacks. |
| **Fingerprint** | A SHA-256 hash identifying content for deduplication without exposing raw data. |

## Severity Levels

| Level | Meaning |
|-------|---------|
| **safe** | No concerning signals detected. |
| **suspicious** | Weak signals present; warrants monitoring but not blocking. |
| **likely** | Strong signals suggesting malicious intent. |
| **confirmed** | Known attack pattern matched with high confidence. |
| **critical** | Highest severity; immediate blocking required. |
