export interface BuiltinRuleset {
  id: string;
  name: string;
  description: string;
  yaml: string;
}

export const BUILTIN_RULESETS: BuiltinRuleset[] = [
  {
    id: "default",
    name: "Default",
    description:
      "Balanced baseline policy. Blocks sensitive paths, controls egress, detects secret leaks, and limits dangerous shell commands.",
    yaml: `version: "1.2.0"
name: "default"
description: "Balanced baseline policy for AI agent security"

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
      - "/etc/passwd"
  egress_allowlist:
    enabled: true
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
      - "api.github.com"
      - "registry.npmjs.org"
      - "pypi.org"
      - "crates.io"
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
  shell_command:
    enabled: true
  patch_integrity:
    enabled: true
    max_additions: 1000
    max_deletions: 500

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600`,
  },
  {
    id: "strict",
    name: "Strict",
    description:
      "Maximum security posture. All guards enabled with tight limits. Suitable for production deployments handling sensitive data.",
    yaml: `version: "1.2.0"
name: "strict"
description: "Maximum security posture for production deployments"
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
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "**/.docker/**"
      - "**/credentials*"
  path_allowlist:
    enabled: true
    file_access_allow:
      - "/workspace/**"
    file_write_allow:
      - "/workspace/src/**"
      - "/workspace/tests/**"
  egress_allowlist:
    enabled: true
    allow:
      - "api.github.com"
      - "registry.npmjs.org"
    default_action: "block"
  secret_leak:
    enabled: true
  shell_command:
    enabled: true
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
    require_confirmation:
      - "write_file"
      - "execute_command"
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "high"
  jailbreak:
    enabled: true
    detector:
      block_threshold: 40
      warn_threshold: 15

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 1800`,
  },
  {
    id: "permissive",
    name: "Permissive",
    description:
      "Minimal restrictions. Only critical protections enabled. Suitable for development and experimentation.",
    yaml: `version: "1.2.0"
name: "permissive"
description: "Minimal restrictions for development"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/id_rsa"
      - "**/.ssh/id_ed25519"
      - "/etc/shadow"
  secret_leak:
    enabled: true
  shell_command:
    enabled: false
  egress_allowlist:
    enabled: false

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 7200`,
  },
  {
    id: "ai-agent",
    name: "AI Agent",
    description:
      "Tailored for autonomous AI agents. MCP tool control, prompt injection detection, and egress restrictions.",
    yaml: `version: "1.2.0"
name: "ai-agent"
description: "Security policy for autonomous AI agent runtimes"
extends: "default"

guards:
  forbidden_path:
    enabled: true
  egress_allowlist:
    enabled: true
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
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
    allow:
      - "read_file"
      - "list_files"
      - "search_files"
    require_confirmation:
      - "write_file"
      - "execute_command"
      - "run_terminal_command"
    block:
      - "shell_exec"
      - "eval"
  prompt_injection:
    enabled: true
    warn_at_or_above: "suspicious"
    block_at_or_above: "high"
  jailbreak:
    enabled: true
    detector:
      block_threshold: 50
      warn_threshold: 20

settings:
  fail_fast: false
  session_timeout_secs: 3600`,
  },
  {
    id: "ai-agent-posture",
    name: "AI Agent Posture",
    description:
      "AI agent policy with posture-based state machine. Capabilities change as the agent progresses through workflow stages.",
    yaml: `version: "1.2.0"
name: "ai-agent-posture"
description: "AI agent with posture state machine"
extends: "ai-agent"

guards:
  forbidden_path:
    enabled: true
  mcp_tool:
    enabled: true
    default_action: "block"
  prompt_injection:
    enabled: true
  jailbreak:
    enabled: true

posture:
  initial: "exploring"
  states:
    exploring:
      description: "Agent is reading and understanding the codebase"
      capabilities:
        - "read_file"
        - "list_files"
        - "search_files"
    editing:
      description: "Agent is making code changes"
      capabilities:
        - "read_file"
        - "write_file"
        - "list_files"
    testing:
      description: "Agent is running tests"
      capabilities:
        - "read_file"
        - "execute_command"
        - "run_terminal_command"
  transitions:
    - from: "exploring"
      to: "editing"
      on: "start_edit"
    - from: "editing"
      to: "testing"
      on: "run_tests"
    - from: "testing"
      to: "exploring"
      on: "review"

settings:
  fail_fast: false
  session_timeout_secs: 3600`,
  },
  {
    id: "cicd",
    name: "CI/CD",
    description:
      "Optimised for CI/CD pipelines. Allows build tools and registries while blocking exfiltration vectors.",
    yaml: `version: "1.2.0"
name: "cicd"
description: "Security policy for CI/CD pipelines"

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env.production"
      - "**/.git-credentials"
  egress_allowlist:
    enabled: true
    allow:
      - "registry.npmjs.org"
      - "pypi.org"
      - "crates.io"
      - "docker.io"
      - "*.docker.com"
      - "ghcr.io"
      - "api.github.com"
      - "*.actions.githubusercontent.com"
    default_action: "block"
  secret_leak:
    enabled: true
  shell_command:
    enabled: true
  patch_integrity:
    enabled: true
    max_additions: 5000
    max_deletions: 2000

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 1800`,
  },
  {
    id: "remote-desktop",
    name: "Remote Desktop",
    description:
      "Baseline CUA policy for remote desktop sessions. Controls computer-use actions and side-channel access.",
    yaml: `version: "1.2.0"
name: "remote-desktop"
description: "Baseline policy for remote desktop / CUA sessions"

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
    printing_enabled: false
  input_injection_capability:
    enabled: true
    allowed_input_types:
      - "keyboard"
      - "mouse"
    require_postcondition_probe: true

settings:
  fail_fast: false
  session_timeout_secs: 3600`,
  },
  {
    id: "remote-desktop-strict",
    name: "Remote Desktop Strict",
    description:
      "Lockdown CUA policy. Fail-closed enforcement, no side channels, mandatory postcondition probes.",
    yaml: `version: "1.2.0"
name: "remote-desktop-strict"
description: "Maximum security for remote desktop sessions"
extends: "remote-desktop"

guards:
  computer_use:
    enabled: true
    mode: "fail_closed"
    allowed_actions:
      - "screenshot"
      - "mouse_click"
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

settings:
  fail_fast: true
  session_timeout_secs: 1800`,
  },
  {
    id: "remote-desktop-permissive",
    name: "Remote Desktop Permissive",
    description:
      "Relaxed CUA policy for development. Observe mode, most side channels open.",
    yaml: `version: "1.2.0"
name: "remote-desktop-permissive"
description: "Relaxed policy for development remote desktop sessions"
extends: "remote-desktop"

guards:
  computer_use:
    enabled: true
    mode: "observe"
    allowed_actions:
      - "screenshot"
      - "mouse_click"
      - "keyboard_type"
      - "scroll"
      - "drag"
      - "double_click"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: true
    file_transfer_enabled: true
    audio_enabled: true
    drive_mapping_enabled: true
    printing_enabled: true
    session_share_enabled: true
  input_injection_capability:
    enabled: false

settings:
  fail_fast: false
  session_timeout_secs: 7200`,
  },
  {
    id: "spider-sense",
    name: "Spider Sense",
    description:
      "Hierarchical threat screening via embedding-based cosine similarity. Augments other guards with semantic detection.",
    yaml: `version: "1.2.0"
name: "spider-sense"
description: "Threat screening with embedding-based cosine similarity"
extends: "default"

guards:
  forbidden_path:
    enabled: true
  egress_allowlist:
    enabled: true
  secret_leak:
    enabled: true
  shell_command:
    enabled: true
  spider_sense:
    enabled: true
    similarity_threshold: 0.85
    ambiguity_band: 0.1
    top_k: 5
    embedding_model: "text-embedding-3-small"
    pattern_db_path: "builtin:s2bench-v1"

settings:
  fail_fast: false
  session_timeout_secs: 3600`,
  },
];
