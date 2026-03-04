# Summary

[Introduction](README.md)

# Getting Started

- [Installation](getting-started/installation.md)
- [Package Manager Policy](getting-started/package-manager-policy.md)
- [Quick Start (Rust)](getting-started/quick-start.md)
- [Quick Start (TypeScript)](getting-started/quick-start-typescript.md)
- [Quick Start (Python)](getting-started/quick-start-python.md)
- [Your First Policy](getting-started/first-policy.md)

# Concepts

- [Design Philosophy](concepts/design-philosophy.md)
- [Multi-Language & Frameworks](concepts/multi-language.md)
- [Architecture](concepts/architecture.md)
- [Enforcement Tiers & Integration Contract](concepts/enforcement-tiers.md)
- [Guards](concepts/guards.md)
- [Policies](concepts/policies.md)
- [Schema Governance](concepts/schema-governance.md)
- [Decisions](concepts/decisions.md)
- [Postures](concepts/postures.md)
- [Terminology](concepts/terminology.md)
- [Adaptive Architecture](concepts/adaptive-architecture.md)

# Guides

- [OpenClaw Integration](guides/openclaw-integration.md)
- [Agent OpenClaw Operations](guides/agent-openclaw-operations.md)
- [Agent Attribution Model](guides/agent-attribution-model.md)
- [Helm Confidence Pipeline](guides/helm-confidence-pipeline.md)
- [Vercel AI Integration](guides/vercel-ai-integration.md)
- [LangChain Integration](guides/langchain-integration.md)
- [Generic Adapter Integration](guides/generic-adapter-integration.md)
- [Custom Guards](guides/custom-guards.md)
- [Threat Intel Guards](guides/threat-intel.md)
- [Policy Inheritance](guides/policy-inheritance.md)
- [Posture Policies](guides/posture-policy.md)
- [Observe -> Synth -> Tighten](guides/observe-synth.md)
- [Desktop Agent Deployment](guides/desktop-agent.md)
- [Adaptive Deployment](guides/adaptive-deployment.md)
- [Enterprise Enrollment](guides/enterprise-enrollment.md)
- [Audit Logging](guides/audit-logging.md)
- [Marketplace Feed](guides/marketplace-feed.md)
- [Computer Use Gateway](guides/computer-use-gateway.md)

# Package Manager

- [Overview](package-manager/index.md)
- [Package Types](package-manager/package-types.md)
- [Publishing Packages](package-manager/publishing.md)
- [Installing & Managing](package-manager/installing.md)
- [Registry Architecture](package-manager/registry-architecture.md)
- [Trust & Verification](package-manager/trust-verification.md)

# CLI

- [pkg](cli/pkg.md)
  - [init](cli/pkg-init.md)
  - [install](cli/pkg-install.md)
  - [publish](cli/pkg-publish.md)
  - [search](cli/pkg-search.md)
  - [verify](cli/pkg-verify.md)
  - [audit](cli/pkg-audit.md)

# Reference

- [Policy Schema](reference/policy-schema.md)
- [Posture Schema](reference/posture-schema.md)
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
  - [ComputerUseGuard](reference/guards/computer-use.md)
  - [ShellCommandGuard](reference/guards/shell-command.md)
  - [PathAllowlistGuard](reference/guards/path-allowlist.md)
  - [RemoteDesktopSideChannelGuard](reference/guards/remote-desktop-side-channel.md)
  - [InputInjectionCapabilityGuard](reference/guards/input-injection-capability.md)
  - [SpiderSenseGuard](reference/guards/spider-sense.md)
- [Rulesets](reference/rulesets/README.md)
  - [Default](reference/rulesets/default.md)
  - [Strict](reference/rulesets/strict.md)
  - [AI Agent](reference/rulesets/ai-agent.md)
  - [CI/CD](reference/rulesets/cicd.md)
  - [Permissive](reference/rulesets/permissive.md)
  - [Remote Desktop](reference/rulesets/remote-desktop.md)
  - [Remote Desktop Permissive](reference/rulesets/remote-desktop-permissive.md)
  - [Remote Desktop Strict](reference/rulesets/remote-desktop-strict.md)
  - [AI Agent Posture](reference/rulesets/ai-agent-posture.md)
  - [Spider-Sense](reference/rulesets/spider-sense.md)
- [API](reference/api/README.md)
  - [Rust](reference/api/rust.md)
  - [TypeScript](reference/api/typescript.md)
  - [Python](reference/api/python.md)
  - [CLI](reference/api/cli.md)
- [Benchmarks](reference/benchmarks.md)

# Hunt (Threat Hunting)

- [Overview](hunt/index.md)
  - [hunt scan](hunt/scan.md)
  - [hunt query](hunt/query.md)
  - [hunt timeline](hunt/timeline.md)
  - [hunt correlate](hunt/correlate.md)
  - [hunt watch](hunt/watch.md)
  - [hunt ioc](hunt/ioc.md)
  - [hunt testing](hunt/testing.md)
  - [hunt report (planned)](hunt/report.md)
  - [Discovery Reference](hunt/discovery-reference.md)
  - [Models Reference](hunt/models-reference.md)

# Recipes

- [Claude Integration](recipes/claude.md)
- [GitHub Actions](recipes/github-actions.md)
- [Self-Hosted Runners](recipes/self-hosted.md)

# RFCs

- [RFC-0001: Package Manager](rfcs/0001-package-manager.md)

# Roadmap

- [Implementation Roadmap](roadmap.md)
