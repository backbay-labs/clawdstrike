// ---- Policy Catalog: curated templates with rich metadata ----

export type CatalogCategory =
  | "general"
  | "ai-agent"
  | "cicd"
  | "healthcare"
  | "finance"
  | "remote-desktop"
  | "enterprise"
  | "minimal";

export type CatalogDifficulty = "beginner" | "intermediate" | "advanced";

export interface CatalogEntry {
  id: string;
  name: string;
  description: string;
  category: CatalogCategory;
  tags: string[];
  author: string;
  version: string;
  extends?: string;
  yaml: string;
  guardSummary: string[];
  useCases: string[];
  compliance: string[];
  difficulty: CatalogDifficulty;
  popularity: number;
  createdAt: string;
  updatedAt: string;
}

export const CATALOG_CATEGORIES: {
  id: CatalogCategory;
  label: string;
  color: string;
}[] = [
  { id: "general", label: "General", color: "#ece7dc" },
  { id: "ai-agent", label: "AI Agent", color: "#d4a84b" },
  { id: "cicd", label: "CI/CD", color: "#3dbf84" },
  { id: "healthcare", label: "Healthcare", color: "#5b8def" },
  { id: "finance", label: "Finance", color: "#c45c5c" },
  { id: "remote-desktop", label: "Remote Desktop", color: "#8b5cf6" },
  { id: "enterprise", label: "Enterprise", color: "#f59e0b" },
  { id: "minimal", label: "Minimal", color: "#6f7f9a" },
];

export function getCategoryColor(category: CatalogCategory): string {
  return CATALOG_CATEGORIES.find((c) => c.id === category)?.color ?? "#6f7f9a";
}

export const POLICY_CATALOG: CatalogEntry[] = [
  // ---- 1. AI Agent - Development ----
  {
    id: "ai-agent-dev",
    name: "AI Agent — Development",
    description:
      "Permissive policy for AI agent development and experimentation. Blocks obvious threats like credential theft and secret leaks while keeping network and tool access open.",
    category: "ai-agent",
    tags: ["development", "permissive", "agent", "coding-assistant"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "permissive",
    yaml: `# AI Agent — Development
# Permissive baseline for dev/test agent workflows.
# Blocks credential theft and secret exfiltration;
# leaves egress and MCP tools open for rapid iteration.
version: "1.2.0"
name: "ai-agent-dev"
description: "Permissive policy for AI agent development"
extends: "permissive"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "/etc/shadow"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "github_token"
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: "critical"
      - name: "private_key"
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: "critical"
  shell_command:
    enabled: true
  prompt_injection:
    enabled: true
    warn_at_or_above: "high"
    block_at_or_above: "critical"

settings:
  fail_fast: false
  verbose_logging: true
  session_timeout_secs: 7200`,
    guardSummary: ["forbidden_path", "secret_leak", "shell_command", "prompt_injection"],
    useCases: ["Local development", "Agent prototyping", "Coding assistants"],
    compliance: [],
    difficulty: "beginner",
    popularity: 92,
    createdAt: "2026-02-15T00:00:00Z",
    updatedAt: "2026-03-01T00:00:00Z",
  },

  // ---- 2. AI Agent - Production ----
  {
    id: "ai-agent-prod",
    name: "AI Agent — Production",
    description:
      "Maximum-security policy for production AI agents. All guards enabled with tight thresholds. Fail-closed enforcement, prompt injection blocking, jailbreak detection, and strict egress control.",
    category: "ai-agent",
    tags: ["production", "strict", "agent", "fail-closed", "all-guards"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "strict",
    yaml: `# AI Agent — Production
# Fail-closed enforcement for production agent deployments.
# Every guard enabled, tight thresholds, restricted egress,
# MCP tool allowlisting, and jailbreak detection active.
version: "1.2.0"
name: "ai-agent-prod"
description: "Maximum-security policy for production AI agents"
extends: "strict"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "**/.docker/**"
      - "**/credentials*"
      - "**/secrets*"
  path_allowlist:
    enabled: true
    file_access_allow:
      - "/workspace/**"
      - "/tmp/agent-*/**"
    file_write_allow:
      - "/workspace/src/**"
      - "/workspace/tests/**"
  egress_allowlist:
    enabled: true
    allow:
      - "api.github.com"
      - "*.anthropic.com"
      - "*.openai.com"
    default_action: "block"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "github_token"
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: "critical"
      - name: "private_key"
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: "critical"
      - name: "generic_api_key"
        pattern: "(?i)(api[_\\\\-]?key|apikey)\\\\s*[=]\\\\s*[A-Za-z0-9_\\\\-]{20,}"
        severity: "warning"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "curl.*\\\\|.*sh"
      - "wget.*\\\\|.*bash"
      - "rm\\\\s+-rf\\\\s+/"
      - "chmod\\\\s+777"
  patch_integrity:
    enabled: true
    max_additions: 500
    max_deletions: 200
    require_balance: true
    max_imbalance_ratio: 5
  mcp_tool:
    enabled: true
    default_action: "block"
    allow:
      - "read_file"
      - "list_files"
      - "search_files"
    require_confirmation:
      - "write_file"
      - "execute_command"
    block:
      - "shell_exec"
      - "eval"
      - "run_arbitrary"
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "high"
  jailbreak:
    enabled: true
    detector:
      block_threshold: 35
      warn_threshold: 15

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 1800`,
    guardSummary: [
      "forbidden_path",
      "path_allowlist",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "patch_integrity",
      "mcp_tool",
      "prompt_injection",
      "jailbreak",
    ],
    useCases: ["Production deployments", "Customer-facing agents", "SaaS AI features"],
    compliance: ["SOC2"],
    difficulty: "advanced",
    popularity: 88,
    createdAt: "2026-02-15T00:00:00Z",
    updatedAt: "2026-03-05T00:00:00Z",
  },

  // ---- 3. AI Agent - Code Review ----
  {
    id: "ai-agent-code-review",
    name: "AI Agent — Code Review",
    description:
      "Focused on code review safety. Patch integrity validation with tight limits, shell command restrictions, and secret leak prevention. Ideal for PR review bots.",
    category: "ai-agent",
    tags: ["code-review", "patch", "pull-request", "agent"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "default",
    yaml: `# AI Agent — Code Review
# Optimized for PR review and code analysis agents.
# Strong patch integrity checks, restricted shell commands,
# and secret-leak scanning on all file writes.
version: "1.2.0"
name: "ai-agent-code-review"
description: "Security policy for code review AI agents"
extends: "default"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
  path_allowlist:
    enabled: true
    file_access_allow:
      - "/workspace/**"
    file_write_allow:
      - "/workspace/src/**"
      - "/workspace/tests/**"
    patch_allow:
      - "/workspace/**"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "github_token"
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: "critical"
      - name: "private_key"
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: "critical"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "curl.*\\\\|.*sh"
      - "wget.*\\\\|.*bash"
      - "rm\\\\s+-rf"
  patch_integrity:
    enabled: true
    max_additions: 300
    max_deletions: 150
    require_balance: true
    max_imbalance_ratio: 3
    forbidden_patterns:
      - "eval\\\\("
      - "exec\\\\("
      - "__import__"
  mcp_tool:
    enabled: true
    default_action: "block"
    allow:
      - "read_file"
      - "list_files"
      - "search_files"
      - "get_diff"
      - "create_review_comment"
    block:
      - "write_file"
      - "execute_command"
      - "shell_exec"

settings:
  fail_fast: false
  verbose_logging: true
  session_timeout_secs: 3600`,
    guardSummary: [
      "forbidden_path",
      "path_allowlist",
      "secret_leak",
      "shell_command",
      "patch_integrity",
      "mcp_tool",
    ],
    useCases: ["PR review bots", "Automated code analysis", "CI code quality"],
    compliance: [],
    difficulty: "intermediate",
    popularity: 78,
    createdAt: "2026-02-20T00:00:00Z",
    updatedAt: "2026-03-01T00:00:00Z",
  },

  // ---- 4. CI/CD Pipeline ----
  {
    id: "cicd-pipeline",
    name: "CI/CD Pipeline",
    description:
      "Restricted policy for CI/CD pipelines and GitHub Actions. Shell commands locked down, egress limited to package registries and container registries, secret leak detection active.",
    category: "cicd",
    tags: ["cicd", "github-actions", "pipeline", "build", "deploy"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    yaml: `# CI/CD Pipeline
# Designed for automated build/test/deploy environments.
# Egress restricted to registries and GitHub APIs.
# Shell commands allowed but dangerous patterns blocked.
version: "1.2.0"
name: "cicd-pipeline"
description: "Security policy for CI/CD pipelines"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/id_*"
      - "**/.aws/credentials"
      - "**/.env.production"
      - "**/.git-credentials"
      - "**/.docker/config.json"
  egress_allowlist:
    enabled: true
    allow:
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
      - "docker.io"
      - "*.docker.com"
      - "ghcr.io"
      - "api.github.com"
      - "*.actions.githubusercontent.com"
      - "objects.githubusercontent.com"
    default_action: "block"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "github_token"
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: "critical"
      - name: "npm_token"
        pattern: "npm_[A-Za-z0-9]{36}"
        severity: "critical"
      - name: "docker_password"
        pattern: "dckr_pat_[A-Za-z0-9_\\\\-]+"
        severity: "critical"
    skip_paths:
      - "**/node_modules/**"
      - "**/target/**"
      - "**/.git/**"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "curl.*\\\\|.*sh"
      - "wget.*\\\\|.*bash"
      - "rm\\\\s+-rf\\\\s+/"
      - "chmod\\\\s+777"
      - "sudo\\\\s+.*"
  patch_integrity:
    enabled: true
    max_additions: 5000
    max_deletions: 2000

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 1800`,
    guardSummary: [
      "forbidden_path",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "patch_integrity",
    ],
    useCases: ["GitHub Actions", "GitLab CI", "Jenkins pipelines", "Docker builds"],
    compliance: ["SOC2"],
    difficulty: "intermediate",
    popularity: 85,
    createdAt: "2026-02-10T00:00:00Z",
    updatedAt: "2026-03-02T00:00:00Z",
  },

  // ---- 5. Healthcare (HIPAA) ----
  {
    id: "healthcare-hipaa",
    name: "Healthcare (HIPAA)",
    description:
      "HIPAA-aligned policy for healthcare environments. Strict data controls, PHI path protections, secret leak detection for medical record identifiers, and locked-down egress.",
    category: "healthcare",
    tags: ["hipaa", "healthcare", "phi", "compliance", "strict"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "strict",
    yaml: `# Healthcare (HIPAA)
# Strict data controls aligned with HIPAA requirements.
# Protects PHI paths, detects medical record identifiers,
# and restricts egress to approved healthcare APIs only.
version: "1.2.0"
name: "healthcare-hipaa"
description: "HIPAA-aligned security policy for healthcare AI agents"
extends: "strict"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/patient-data/**"
      - "**/phi/**"
      - "**/medical-records/**"
      - "**/hipaa-audit/**"
      - "/var/log/auth*"
  path_allowlist:
    enabled: true
    file_access_allow:
      - "/workspace/**"
      - "/app/data/anonymized/**"
    file_write_allow:
      - "/workspace/output/**"
      - "/app/data/processed/**"
  egress_allowlist:
    enabled: true
    allow:
      - "api.github.com"
      - "*.anthropic.com"
    default_action: "block"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "github_token"
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: "critical"
      - name: "private_key"
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: "critical"
      - name: "ssn"
        pattern: "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"
        severity: "critical"
      - name: "mrn"
        pattern: "(?i)MRN[:\\\\s]*\\\\d{6,}"
        severity: "critical"
      - name: "dea_number"
        pattern: "[A-Z]{2}\\\\d{7}"
        severity: "warning"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "curl"
      - "wget"
      - "nc\\\\s+"
      - "ncat"
  patch_integrity:
    enabled: true
    max_additions: 200
    max_deletions: 100
    require_balance: true
  mcp_tool:
    enabled: true
    default_action: "block"
    allow:
      - "read_file"
      - "list_files"
    require_confirmation:
      - "write_file"
    block:
      - "execute_command"
      - "shell_exec"
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "suspicious"
  jailbreak:
    enabled: true
    detector:
      block_threshold: 25
      warn_threshold: 10

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 900`,
    guardSummary: [
      "forbidden_path",
      "path_allowlist",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "patch_integrity",
      "mcp_tool",
      "prompt_injection",
      "jailbreak",
    ],
    useCases: ["Healthcare AI assistants", "Medical record processing", "Clinical decision support"],
    compliance: ["HIPAA"],
    difficulty: "advanced",
    popularity: 76,
    createdAt: "2026-02-18T00:00:00Z",
    updatedAt: "2026-03-04T00:00:00Z",
  },

  // ---- 6. Finance (SOC2) ----
  {
    id: "finance-soc2",
    name: "Finance (SOC2)",
    description:
      "SOC2-aligned policy for financial services. All actions audited, egress locked to approved financial APIs, MCP tools restricted, and comprehensive secret detection.",
    category: "finance",
    tags: ["soc2", "finance", "audit", "compliance", "strict"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "strict",
    yaml: `# Finance (SOC2)
# SOC2-aligned policy for financial services AI agents.
# Comprehensive audit logging, locked egress, MCP restrictions,
# and enhanced secret detection for financial identifiers.
version: "1.2.0"
name: "finance-soc2"
description: "SOC2-aligned security policy for financial services"
extends: "strict"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/trading-keys/**"
      - "**/vault/**"
      - "**/treasury/**"
  path_allowlist:
    enabled: true
    file_access_allow:
      - "/workspace/**"
      - "/app/market-data/**"
    file_write_allow:
      - "/workspace/output/**"
      - "/workspace/reports/**"
  egress_allowlist:
    enabled: true
    allow:
      - "api.github.com"
      - "*.anthropic.com"
    default_action: "block"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "github_token"
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: "critical"
      - name: "private_key"
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: "critical"
      - name: "credit_card"
        pattern: "\\\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\\\b"
        severity: "critical"
      - name: "routing_number"
        pattern: "\\\\b0[0-9]{8}\\\\b"
        severity: "warning"
      - name: "stripe_key"
        pattern: "sk_live_[A-Za-z0-9]{24,}"
        severity: "critical"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "curl"
      - "wget"
      - "nc\\\\s+"
      - "ssh\\\\s+"
      - "scp\\\\s+"
  patch_integrity:
    enabled: true
    max_additions: 300
    max_deletions: 150
    require_balance: true
    max_imbalance_ratio: 3
  mcp_tool:
    enabled: true
    default_action: "block"
    allow:
      - "read_file"
      - "list_files"
      - "search_files"
    require_confirmation:
      - "write_file"
    block:
      - "execute_command"
      - "shell_exec"
      - "eval"
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "high"
  jailbreak:
    enabled: true
    detector:
      block_threshold: 30
      warn_threshold: 10
      session_aggregation: true

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 1200`,
    guardSummary: [
      "forbidden_path",
      "path_allowlist",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "patch_integrity",
      "mcp_tool",
      "prompt_injection",
      "jailbreak",
    ],
    useCases: ["Trading platforms", "Financial advisory bots", "Compliance automation"],
    compliance: ["SOC2", "PCI-DSS"],
    difficulty: "advanced",
    popularity: 74,
    createdAt: "2026-02-18T00:00:00Z",
    updatedAt: "2026-03-04T00:00:00Z",
  },

  // ---- 7. Remote Desktop - Corporate ----
  {
    id: "remote-desktop-corporate",
    name: "Remote Desktop — Corporate",
    description:
      "Balanced CUA policy for corporate remote desktop sessions. Guardrail mode with clipboard access, restricted side channels, and mandatory postcondition probes.",
    category: "remote-desktop",
    tags: ["remote-desktop", "cua", "corporate", "guardrail"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "remote-desktop",
    yaml: `# Remote Desktop — Corporate
# Balanced CUA policy for corporate remote sessions.
# Guardrail mode allows standard interactions while
# restricting side channels and requiring postcondition probes.
version: "1.2.0"
name: "remote-desktop-corporate"
description: "Corporate remote desktop policy with balanced CUA controls"
extends: "remote-desktop"

guards:
  computer_use:
    enabled: true
    mode: "guardrail"
    allowed_actions:
      - "screenshot"
      - "mouse_click"
      - "keyboard_type"
      - "scroll"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: true
    file_transfer_enabled: false
    audio_enabled: true
    drive_mapping_enabled: false
    printing_enabled: true
    session_share_enabled: false
    max_transfer_size_bytes: 10485760
  input_injection_capability:
    enabled: true
    allowed_input_types:
      - "keyboard"
      - "mouse"
    require_postcondition_probe: true
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
  secret_leak:
    enabled: true

settings:
  fail_fast: false
  verbose_logging: true
  session_timeout_secs: 3600`,
    guardSummary: [
      "computer_use",
      "remote_desktop_side_channel",
      "input_injection_capability",
      "forbidden_path",
      "secret_leak",
    ],
    useCases: ["Corporate IT automation", "Helpdesk agents", "Admin task automation"],
    compliance: ["SOC2"],
    difficulty: "intermediate",
    popularity: 70,
    createdAt: "2026-02-22T00:00:00Z",
    updatedAt: "2026-03-01T00:00:00Z",
  },

  // ---- 8. Remote Desktop - Kiosk ----
  {
    id: "remote-desktop-kiosk",
    name: "Remote Desktop — Kiosk",
    description:
      "Maximum lockdown for public kiosk terminals. Fail-closed CUA enforcement, all side channels disabled, keyboard-only input, and mandatory postcondition probes.",
    category: "remote-desktop",
    tags: ["remote-desktop", "kiosk", "lockdown", "fail-closed", "public"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "remote-desktop-strict",
    yaml: `# Remote Desktop — Kiosk
# Maximum lockdown for public-facing kiosk terminals.
# Fail-closed mode, all side channels disabled,
# keyboard-only input injection with postcondition probes.
version: "1.2.0"
name: "remote-desktop-kiosk"
description: "Maximum lockdown policy for public kiosk terminals"
extends: "remote-desktop-strict"

guards:
  computer_use:
    enabled: true
    mode: "fail_closed"
    allowed_actions:
      - "screenshot"
      - "keyboard_type"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: false
    file_transfer_enabled: false
    audio_enabled: false
    drive_mapping_enabled: false
    printing_enabled: false
    session_share_enabled: false
    max_transfer_size_bytes: 0
  input_injection_capability:
    enabled: true
    allowed_input_types:
      - "keyboard"
    require_postcondition_probe: true
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.gnupg/**"
      - "/etc/**"
      - "/root/**"
  egress_allowlist:
    enabled: true
    allow: []
    default_action: "block"

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 600`,
    guardSummary: [
      "computer_use",
      "remote_desktop_side_channel",
      "input_injection_capability",
      "forbidden_path",
      "egress_allowlist",
    ],
    useCases: ["Public kiosks", "Shared terminals", "Digital signage"],
    compliance: [],
    difficulty: "intermediate",
    popularity: 55,
    createdAt: "2026-02-22T00:00:00Z",
    updatedAt: "2026-03-01T00:00:00Z",
  },

  // ---- 9. Minimal Sandbox ----
  {
    id: "minimal-sandbox",
    name: "Minimal Sandbox",
    description:
      "Quick-start sandbox with just two guards: forbidden path protection and shell command safety. Perfect for learning Clawdstrike or testing basic integrations.",
    category: "minimal",
    tags: ["minimal", "sandbox", "beginner", "quick-start"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    yaml: `# Minimal Sandbox
# The simplest useful policy — just forbidden paths
# and shell command guards. A great starting point
# for learning Clawdstrike policy configuration.
version: "1.2.0"
name: "minimal-sandbox"
description: "Minimal sandbox with basic protections"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "/etc/shadow"
  shell_command:
    enabled: true

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 7200`,
    guardSummary: ["forbidden_path", "shell_command"],
    useCases: ["Learning Clawdstrike", "Quick prototyping", "Basic integrations"],
    compliance: [],
    difficulty: "beginner",
    popularity: 95,
    createdAt: "2026-02-01T00:00:00Z",
    updatedAt: "2026-02-15T00:00:00Z",
  },

  // ---- 10. Enterprise SSO Agent ----
  {
    id: "enterprise-sso-agent",
    name: "Enterprise SSO Agent",
    description:
      "Origin-aware multi-tenant policy for enterprise SSO-integrated agents. Uses v1.4.0 origin profiles to enforce per-tenant boundaries, with Slack and GitHub origin matching.",
    category: "enterprise",
    tags: ["enterprise", "sso", "origin", "multi-tenant", "v1.4.0"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    yaml: `# Enterprise SSO Agent
# Origin-aware policy for multi-tenant enterprise agents.
# Uses v1.4.0 origin profiles to enforce per-tenant
# boundaries with provider-specific rules for Slack and GitHub.
version: "1.4.0"
name: "enterprise-sso-agent"
description: "Origin-aware multi-tenant policy for enterprise agents"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
  egress_allowlist:
    enabled: true
    allow:
      - "api.github.com"
      - "*.anthropic.com"
      - "*.slack.com"
    default_action: "block"
  secret_leak:
    enabled: true
  shell_command:
    enabled: true
  mcp_tool:
    enabled: true
    default_action: "block"
    allow:
      - "read_file"
      - "list_files"
      - "search_files"
    require_confirmation:
      - "write_file"
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "high"

origins:
  default_behavior: "deny"
  profiles:
    - id: "slack-internal"
      match_rules:
        provider: "slack"
        visibility: "private"
      posture: "exploring"
      mcp:
        enabled: true
        default_action: "block"
        allow:
          - "read_file"
          - "list_files"
          - "search_files"
      egress:
        enabled: true
        allow:
          - "*.anthropic.com"
          - "*.slack.com"
        default_action: "block"
      data:
        allow_external_sharing: false
        redact_before_send: true
      budgets:
        mcp_tool_calls: 50
        egress_calls: 20
      explanation: "Internal Slack channels get read-only agent access"
    - id: "github-pr"
      match_rules:
        provider: "github"
        space_type: "pull_request"
      posture: "editing"
      mcp:
        enabled: true
        default_action: "block"
        allow:
          - "read_file"
          - "list_files"
          - "search_files"
          - "write_file"
          - "create_review_comment"
      egress:
        enabled: true
        allow:
          - "api.github.com"
          - "*.anthropic.com"
        default_action: "block"
      budgets:
        mcp_tool_calls: 100
        egress_calls: 50
        shell_commands: 10
      explanation: "GitHub PRs get write access scoped to the repository"

settings:
  fail_fast: false
  verbose_logging: true
  session_timeout_secs: 3600`,
    guardSummary: [
      "forbidden_path",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "mcp_tool",
      "prompt_injection",
    ],
    useCases: ["Enterprise SaaS agents", "Multi-tenant platforms", "SSO-integrated bots"],
    compliance: ["SOC2"],
    difficulty: "advanced",
    popularity: 65,
    createdAt: "2026-03-01T00:00:00Z",
    updatedAt: "2026-03-07T00:00:00Z",
  },

  // ---- 11. Research Lab ----
  {
    id: "research-lab",
    name: "Research Lab",
    description:
      "Spider Sense + prompt injection focused policy for research environments. Hierarchical threat screening with embedding-based detection, ideal for adversarial ML research.",
    category: "general",
    tags: ["research", "spider-sense", "prompt-injection", "adversarial", "ml"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "default",
    yaml: `# Research Lab
# Spider Sense + prompt injection focused policy for
# adversarial ML research. Embedding-based threat screening
# with configurable similarity thresholds.
version: "1.2.0"
name: "research-lab"
description: "Spider Sense threat screening for research environments"
extends: "default"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
  egress_allowlist:
    enabled: true
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
      - "api.github.com"
      - "huggingface.co"
      - "*.hf.co"
    default_action: "block"
  secret_leak:
    enabled: true
  shell_command:
    enabled: true
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "high"
    max_scan_bytes: 65536
  jailbreak:
    enabled: true
    detector:
      block_threshold: 40
      warn_threshold: 15
      max_input_bytes: 65536
      session_aggregation: true
  spider_sense:
    enabled: true
    similarity_threshold: 0.80
    ambiguity_band: 0.15
    top_k: 10
    embedding_model: "text-embedding-3-small"
    pattern_db_path: "builtin:s2bench-v1"

settings:
  fail_fast: false
  verbose_logging: true
  session_timeout_secs: 7200`,
    guardSummary: [
      "forbidden_path",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "prompt_injection",
      "jailbreak",
      "spider_sense",
    ],
    useCases: ["Adversarial ML research", "Red team exercises", "Prompt injection studies"],
    compliance: [],
    difficulty: "advanced",
    popularity: 62,
    createdAt: "2026-03-03T00:00:00Z",
    updatedAt: "2026-03-07T00:00:00Z",
  },

  // ---- 12. Customer Support Bot ----
  {
    id: "customer-support-bot",
    name: "Customer Support Bot",
    description:
      "Policy for customer-facing support agents. Egress limited to approved APIs, MCP tools restricted to knowledge-base operations, prompt injection and jailbreak detection active.",
    category: "ai-agent",
    tags: ["support", "customer-facing", "chatbot", "agent"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "ai-agent",
    yaml: `# Customer Support Bot
# Policy for customer-facing support chatbots.
# Egress restricted to approved APIs, MCP tools limited
# to knowledge-base queries, prompt injection blocked.
version: "1.2.0"
name: "customer-support-bot"
description: "Security policy for customer support AI agents"
extends: "ai-agent"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/internal/**"
      - "**/admin/**"
  egress_allowlist:
    enabled: true
    allow:
      - "*.anthropic.com"
      - "*.openai.com"
      - "api.zendesk.com"
      - "api.intercom.io"
      - "api.stripe.com"
    default_action: "block"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "stripe_key"
        pattern: "sk_live_[A-Za-z0-9]{24,}"
        severity: "critical"
      - name: "credit_card"
        pattern: "\\\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\\\\b"
        severity: "critical"
  shell_command:
    enabled: true
    forbidden_patterns:
      - ".*"
  mcp_tool:
    enabled: true
    default_action: "block"
    allow:
      - "search_knowledge_base"
      - "get_article"
      - "lookup_order"
      - "get_customer_info"
    require_confirmation:
      - "create_ticket"
      - "update_ticket"
      - "issue_refund"
    block:
      - "execute_command"
      - "shell_exec"
      - "write_file"
      - "delete_file"
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "suspicious"
  jailbreak:
    enabled: true
    detector:
      block_threshold: 30
      warn_threshold: 10

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 1800`,
    guardSummary: [
      "forbidden_path",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "mcp_tool",
      "prompt_injection",
      "jailbreak",
    ],
    useCases: ["Customer support chatbots", "Helpdesk agents", "Ticket triage bots"],
    compliance: ["SOC2"],
    difficulty: "intermediate",
    popularity: 82,
    createdAt: "2026-02-25T00:00:00Z",
    updatedAt: "2026-03-05T00:00:00Z",
  },

  // ---- 13. AI Agent with Posture FSM ----
  {
    id: "ai-agent-posture-workflow",
    name: "AI Agent — Workflow Posture",
    description:
      "Advanced agent policy with a 4-state posture machine: planning, coding, testing, deploying. Each state has distinct capability budgets and guard configurations.",
    category: "ai-agent",
    tags: ["posture", "state-machine", "workflow", "agent", "advanced"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "ai-agent",
    yaml: `# AI Agent — Workflow Posture
# 4-state posture machine for structured agent workflows.
# Each state grants different capabilities and budgets.
# Transitions require explicit signals from the orchestrator.
version: "1.2.0"
name: "ai-agent-posture-workflow"
description: "Agent policy with 4-state workflow posture machine"
extends: "ai-agent"

guards:
  forbidden_path:
    enabled: true
  egress_allowlist:
    enabled: true
    allow:
      - "*.anthropic.com"
      - "*.openai.com"
      - "api.github.com"
      - "registry.npmjs.org"
    default_action: "block"
  secret_leak:
    enabled: true
  shell_command:
    enabled: true
  mcp_tool:
    enabled: true
    default_action: "block"
  prompt_injection:
    enabled: true
  jailbreak:
    enabled: true

posture:
  initial: "planning"
  states:
    planning:
      description: "Agent analyzes the task and creates a plan"
      capabilities:
        - "read_file"
        - "list_files"
        - "search_files"
      budgets:
        mcp_calls: 30
    coding:
      description: "Agent implements the plan"
      capabilities:
        - "read_file"
        - "write_file"
        - "list_files"
        - "search_files"
      budgets:
        mcp_calls: 100
        file_writes: 50
    testing:
      description: "Agent runs tests and validates"
      capabilities:
        - "read_file"
        - "execute_command"
        - "run_terminal_command"
      budgets:
        mcp_calls: 50
        shell_commands: 20
    deploying:
      description: "Agent prepares deployment artifacts"
      capabilities:
        - "read_file"
        - "write_file"
        - "execute_command"
      budgets:
        mcp_calls: 20
        shell_commands: 5
  transitions:
    - from: "planning"
      to: "coding"
      on: "plan_approved"
    - from: "coding"
      to: "testing"
      on: "code_complete"
    - from: "testing"
      to: "coding"
      on: "tests_failed"
    - from: "testing"
      to: "deploying"
      on: "tests_passed"
    - from: "deploying"
      to: "planning"
      on: "deploy_complete"

settings:
  fail_fast: false
  verbose_logging: true
  session_timeout_secs: 7200`,
    guardSummary: [
      "forbidden_path",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "mcp_tool",
      "prompt_injection",
      "jailbreak",
    ],
    useCases: ["Agentic coding workflows", "Task-driven AI agents", "Software engineering bots"],
    compliance: [],
    difficulty: "advanced",
    popularity: 72,
    createdAt: "2026-03-01T00:00:00Z",
    updatedAt: "2026-03-07T00:00:00Z",
  },

  // ---- 14. PCI-DSS Compliance ----
  {
    id: "pci-dss",
    name: "PCI-DSS Compliance",
    description:
      "PCI-DSS aligned policy for payment card data environments. Credit card and cardholder data detection, restricted network access, and comprehensive shell command blocking.",
    category: "finance",
    tags: ["pci-dss", "payments", "compliance", "credit-card"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "strict",
    yaml: `# PCI-DSS Compliance
# Payment card industry data security standard alignment.
# Detects credit card numbers, restricts cardholder data paths,
# and locks down network and shell access.
version: "1.2.0"
name: "pci-dss"
description: "PCI-DSS aligned policy for payment card environments"
extends: "strict"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/cardholder-data/**"
      - "**/payment-keys/**"
      - "**/pan-vault/**"
      - "**/hsm/**"
  path_allowlist:
    enabled: true
    file_access_allow:
      - "/workspace/**"
      - "/app/tokenized/**"
    file_write_allow:
      - "/workspace/output/**"
  egress_allowlist:
    enabled: true
    allow:
      - "api.stripe.com"
      - "api.github.com"
    default_action: "block"
  secret_leak:
    enabled: true
    patterns:
      - name: "credit_card_visa"
        pattern: "\\\\b4[0-9]{12}(?:[0-9]{3})?\\\\b"
        severity: "critical"
      - name: "credit_card_mc"
        pattern: "\\\\b5[1-5][0-9]{14}\\\\b"
        severity: "critical"
      - name: "credit_card_amex"
        pattern: "\\\\b3[47][0-9]{13}\\\\b"
        severity: "critical"
      - name: "cvv"
        pattern: "(?i)\\\\b(cvv|cvc|cvv2)[:\\\\s]*[0-9]{3,4}\\\\b"
        severity: "critical"
      - name: "stripe_key"
        pattern: "sk_live_[A-Za-z0-9]{24,}"
        severity: "critical"
      - name: "private_key"
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: "critical"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "curl"
      - "wget"
      - "nc\\\\s+"
      - "nmap"
      - "ssh\\\\s+"
  patch_integrity:
    enabled: true
    max_additions: 200
    max_deletions: 100
    require_balance: true
  mcp_tool:
    enabled: true
    default_action: "block"
    allow:
      - "read_file"
      - "list_files"
  prompt_injection:
    enabled: true
    block_at_or_above: "high"

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 900`,
    guardSummary: [
      "forbidden_path",
      "path_allowlist",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "patch_integrity",
      "mcp_tool",
      "prompt_injection",
    ],
    useCases: ["Payment processing", "E-commerce platforms", "POS systems"],
    compliance: ["PCI-DSS", "SOC2"],
    difficulty: "advanced",
    popularity: 68,
    createdAt: "2026-02-20T00:00:00Z",
    updatedAt: "2026-03-04T00:00:00Z",
  },

  // ---- 15. Data Pipeline Agent ----
  {
    id: "data-pipeline-agent",
    name: "Data Pipeline Agent",
    description:
      "Policy for AI agents orchestrating data pipelines. Balanced shell access for ETL commands, egress to data sources, and secret leak prevention for connection strings.",
    category: "cicd",
    tags: ["data-pipeline", "etl", "agent", "data-engineering"],
    author: "Clawdstrike Team",
    version: "1.0.0",
    extends: "default",
    yaml: `# Data Pipeline Agent
# Balanced policy for AI agents running data pipelines.
# Allows ETL tools and data source connections while
# blocking dangerous operations and detecting credentials.
version: "1.2.0"
name: "data-pipeline-agent"
description: "Security policy for data pipeline orchestration agents"
extends: "default"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/credentials"
      - "**/.env.production"
      - "**/.git-credentials"
  path_allowlist:
    enabled: true
    file_access_allow:
      - "/workspace/**"
      - "/data/input/**"
      - "/data/staging/**"
    file_write_allow:
      - "/data/output/**"
      - "/data/staging/**"
      - "/workspace/logs/**"
  egress_allowlist:
    enabled: true
    allow:
      - "*.amazonaws.com"
      - "*.blob.core.windows.net"
      - "*.googleapis.com"
      - "api.github.com"
      - "registry.npmjs.org"
      - "pypi.org"
    default_action: "block"
  secret_leak:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
      - name: "connection_string"
        pattern: "(?i)(postgres|mysql|mongodb|redis)://[^\\\\s]+"
        severity: "critical"
      - name: "private_key"
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: "critical"
    skip_paths:
      - "**/node_modules/**"
      - "**/target/**"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "rm\\\\s+-rf\\\\s+/"
      - "chmod\\\\s+777"
      - "curl.*\\\\|.*sh"
  patch_integrity:
    enabled: true
    max_additions: 2000
    max_deletions: 1000

settings:
  fail_fast: false
  verbose_logging: true
  session_timeout_secs: 3600`,
    guardSummary: [
      "forbidden_path",
      "path_allowlist",
      "egress_allowlist",
      "secret_leak",
      "shell_command",
      "patch_integrity",
    ],
    useCases: ["ETL pipelines", "Data lake management", "Airflow DAGs", "dbt orchestration"],
    compliance: ["SOC2"],
    difficulty: "intermediate",
    popularity: 67,
    createdAt: "2026-02-28T00:00:00Z",
    updatedAt: "2026-03-06T00:00:00Z",
  },
];
