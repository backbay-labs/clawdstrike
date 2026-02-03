# Summary

[Introduction](README.md)

# Getting Started

- [Installation](getting-started/installation.md)
- [Quick Start (Rust)](getting-started/quick-start.md)
- [Quick Start (TypeScript)](getting-started/quick-start-typescript.md)
- [Quick Start (Python)](getting-started/quick-start-python.md)
- [Your First Policy](getting-started/first-policy.md)

# Concepts

- [Design Philosophy](concepts/design-philosophy.md)
- [Multi-Language & Frameworks](concepts/multi-language.md)
- [Architecture](concepts/architecture.md)
- [Guards](concepts/guards.md)
- [Policies](concepts/policies.md)
- [Terminology](concepts/terminology.md)
- [Schema Governance](concepts/schema-governance.md)
- [Decisions](concepts/decisions.md)

# Guides

- [OpenClaw Integration](guides/openclaw-integration.md)
- [Vercel AI Integration](guides/vercel-ai-integration.md)
- [LangChain Integration](guides/langchain-integration.md)
- [Custom Guards](guides/custom-guards.md)
- [Policy Inheritance](guides/policy-inheritance.md)
- [Audit Logging](guides/audit-logging.md)

# Reference

- [Policy Schema](reference/policy-schema.md)
- [Guards](reference/guards/README.md)
  - [ForbiddenPathGuard](reference/guards/forbidden-path.md)
  - [EgressAllowlistGuard](reference/guards/egress.md)
  - [SecretLeakGuard](reference/guards/secret-leak.md)
  - [PatchIntegrityGuard](reference/guards/patch-integrity.md)
  - [McpToolGuard](reference/guards/mcp-tool.md)
  - [PromptInjectionGuard](reference/guards/prompt-injection.md)
  - [JailbreakGuard](reference/guards/jailbreak.md)
  - [Output Sanitizer](reference/guards/output-sanitizer.md)
  - [Watermarking](reference/guards/watermarking.md)
- [Rulesets](reference/rulesets/README.md)
  - [Default](reference/rulesets/default.md)
  - [Strict](reference/rulesets/strict.md)
  - [AI Agent](reference/rulesets/ai-agent.md)
  - [CI/CD](reference/rulesets/cicd.md)
  - [Permissive](reference/rulesets/permissive.md)
- [API](reference/api/README.md)
  - [Rust](reference/api/rust.md)
  - [TypeScript](reference/api/typescript.md)
  - [Python](reference/api/python.md)
  - [CLI](reference/api/cli.md)
- [Benchmarks](reference/benchmarks.md)

# Recipes

- [Claude Code Integration](recipes/claude-code.md)
- [GitHub Actions](recipes/github-actions.md)
- [Self-Hosted Runners](recipes/self-hosted.md)
