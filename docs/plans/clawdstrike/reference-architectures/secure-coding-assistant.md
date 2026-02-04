# Secure Coding Assistant Reference Architecture

## Problem Statement

Organizations want to leverage AI coding assistants (Claude, GPT, etc.) for developer productivity while maintaining security controls. Risks include:

- Accidental exposure of credentials and secrets
- Unauthorized access to sensitive source code
- Exfiltration of proprietary code via network calls
- Malicious code generation (backdoors, vulnerabilities)
- Prompt injection attacks through code comments or file contents

## Target Persona

- **Engineering Managers** enabling AI tools for their teams
- **Security Teams** approving AI assistant deployments
- **Individual Developers** using AI assistants daily
- **DevSecOps Engineers** integrating security into workflows

## Architecture Diagram

```
+------------------------------------------------------------------+
|                     Developer Workstation                         |
|  +------------------------------------------------------------+  |
|  |                    IDE / Editor                             |  |
|  |  +------------------+  +------------------+                 |  |
|  |  | VS Code / Cursor |  | JetBrains / Vim  |                 |  |
|  |  +--------+---------+  +--------+---------+                 |  |
|  |           |                     |                           |  |
|  |           v                     v                           |  |
|  |  +------------------------------------------------+        |  |
|  |  |           AI Assistant Extension               |        |  |
|  |  |  - Claude Code / Copilot / Continue           |        |  |
|  |  +------------------------+-----------------------+        |  |
|  +---------------------------|-------------------------------+  |
|                              |                                   |
|  +---------------------------|-------------------------------+  |
|  |                    Clawdstrike Layer                       |  |
|  |  +------------------------------------------------+        |  |
|  |  |              OpenClaw Plugin                    |        |  |
|  |  |  - Policy Engine        - Secret Redaction     |        |  |
|  |  |  - Path Filtering       - Audit Logging        |        |  |
|  |  |  - Egress Control       - Tool Guards          |        |  |
|  |  +------------------------------------------------+        |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                    Network / AI API Layer                         |
|  +---------------+  +---------------+  +------------------+      |
|  | api.anthropic |  | api.openai    |  | api.github.com   |      |
|  | .com          |  | .com          |  | (Copilot)        |      |
|  +---------------+  +---------------+  +------------------+      |
+------------------------------------------------------------------+
```

## Component Breakdown

### 1. OpenClaw Plugin Configuration

```json
// openclaw.plugin.json
{
  "name": "@clawdstrike/openclaw",
  "version": "0.1.0",
  "description": "Security controls for AI coding assistants",
  "hooks": {
    "agent:bootstrap": "./dist/hooks/agent-bootstrap/handler.js",
    "tool_result_persist": "./dist/hooks/tool-guard/handler.js"
  },
  "tools": [
    {
      "name": "policy_check",
      "description": "Check if an action is allowed by security policy",
      "handler": "./dist/tools/policy-check.js"
    }
  ],
  "config": {
    "policy": "ai-agent",
    "mode": "deterministic",
    "logLevel": "info"
  }
}
```

### 2. Security Policy for Coding Assistants

```yaml
# policy.yaml - Secure Coding Assistant Policy
version: "1.0.0"
name: "Secure Coding Assistant"
description: "Security policy for AI coding assistants"
extends: "ai-agent"

guards:
  forbidden_path:
    # Inherit patterns from ai-agent base
    additional_patterns:
      # Project-specific sensitive paths
      - "**/secrets/**"
      - "**/credentials/**"
      - "**/.vault/**"
      - "**/terraform.tfstate*"
      - "**/*.pem"
      - "**/*.key"
      - "**/id_*"  # SSH keys
      # CI/CD secrets
      - "**/.github/workflows/secrets/**"
      - "**/buildspec*.yml"
    exceptions:
      # Allow reading example files
      - "**/*.example"
      - "**/*.sample"
      - "**/examples/**"
      - "**/test/fixtures/**"
      - "**/testdata/**"

  egress_allowlist:
    # AI APIs
    allow:
      - "*.anthropic.com"
      - "*.openai.com"
      - "api.together.xyz"
      - "*.fireworks.ai"
    # Code hosting
    additional_allow:
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
      - "gitlab.com"
      - "api.gitlab.com"
      - "bitbucket.org"
      # Package registries
      - "registry.npmjs.org"
      - "pypi.org"
      - "crates.io"
      - "rubygems.org"
      - "pkg.go.dev"
      # Documentation
      - "docs.rs"
      - "*.readthedocs.io"
      - "developer.mozilla.org"
      - "devdocs.io"
      # Company internal (customize)
      - "*.internal.company.com"
    block:
      - "pastebin.com"
      - "hastebin.com"
      - "gist.github.com"  # Could leak code
    default_action: block

  secret_leak:
    patterns:
      # Cloud credentials
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: aws_secret_key
        pattern: "(?i)aws[_-]?secret[_-]?access[_-]?key\\s*[=:]\\s*[A-Za-z0-9/+=]{40}"
        severity: critical
      - name: gcp_service_account
        pattern: '"type"\\s*:\\s*"service_account"'
        severity: critical
      - name: azure_subscription
        pattern: "(?i)subscription[_-]?id\\s*[=:]\\s*[a-f0-9-]{36}"
        severity: high

      # API Keys
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
      - name: github_fine_grained
        pattern: "github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"
        severity: critical
      - name: openai_key
        pattern: "sk-[A-Za-z0-9]{48}"
        severity: critical
      - name: anthropic_key
        pattern: "sk-ant-[A-Za-z0-9\\-]{95}"
        severity: critical
      - name: stripe_key
        pattern: "sk_live_[A-Za-z0-9]{24}"
        severity: critical
      - name: slack_token
        pattern: "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"
        severity: critical

      # Private keys
      - name: private_key_pem
        pattern: "-----BEGIN\\s+(RSA\\s+|EC\\s+|OPENSSH\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
      - name: private_key_base64
        pattern: "(?i)(private[_-]?key|priv[_-]?key)\\s*[=:]\\s*[A-Za-z0-9+/=]{100,}"
        severity: critical

      # Database credentials
      - name: database_url
        pattern: "(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@"
        severity: critical
      - name: connection_string
        pattern: "(?i)password\\s*=\\s*['\"][^'\"]{8,}['\"]"
        severity: high

      # Generic patterns
      - name: generic_api_key
        pattern: "(?i)(api[_-]?key|apikey|api[_-]?secret)\\s*[=:]\\s*['\"]?[A-Za-z0-9_\\-]{20,}['\"]?"
        severity: high
      - name: generic_token
        pattern: "(?i)(auth[_-]?token|access[_-]?token|bearer)\\s*[=:]\\s*['\"]?[A-Za-z0-9_\\-\\.]{20,}['\"]?"
        severity: high

    skip_paths:
      - "**/test/**"
      - "**/tests/**"
      - "**/__tests__/**"
      - "**/spec/**"
      - "**/*.test.*"
      - "**/*.spec.*"
      - "**/fixtures/**"
      - "**/mocks/**"
      - "**/testdata/**"
      - "**/node_modules/**"
      - "**/vendor/**"

  patch_integrity:
    max_additions: 5000
    max_deletions: 2000
    require_balance: false
    max_imbalance_ratio: 50.0
    forbidden_patterns:
      # Security bypasses
      - "(?i)disable[_-]?(security|auth|ssl|tls|verification)"
      - "(?i)skip[_-]?(verify|validation|check|auth)"
      - "(?i)no[_-]?verify"
      - "(?i)insecure[_-]?(skip|allow)"

      # Dangerous operations
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+777"
      - "(?i)chmod\\s+[0-7]*7[0-7]*\\s"
      - "(?i)eval\\s*\\("
      - "(?i)exec\\s*\\("
      - "(?i)subprocess\\.call.*shell\\s*=\\s*True"
      - "(?i)os\\.system\\s*\\("

      # Malicious patterns
      - "(?i)reverse[_-]?shell"
      - "(?i)bind[_-]?shell"
      - "(?i)base64[_-]?decode.*exec"
      - "(?i)curl.*\\|.*sh"
      - "(?i)wget.*\\|.*sh"

      # Backdoor indicators
      - "(?i)hidden[_-]?(user|admin|account)"
      - "(?i)backdoor"
      - "(?i)hardcoded[_-]?(password|credential)"

  mcp_tool:
    allow: []
    block:
      # Block dangerous shell operations
      - shell_exec
      - run_command
      - execute_code
    require_confirmation:
      # Require human confirmation for these
      - git_push
      - git_force_push
      - deploy
      - publish
      - npm_publish
      - pip_upload
      - cargo_publish
    default_action: allow
    max_args_size: 4194304  # 4MB

  prompt_injection:
    enabled: true
    max_scan_bytes: 1048576  # 1MB
    warn_at_or_above: low
    block_at_or_above: high

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 14400  # 4 hours

on_violation: cancel
```

### 3. TypeScript Integration

```typescript
// src/secure-assistant.ts
import { PolicyEngine, loadPolicy, generateSecurityPrompt } from '@clawdstrike/openclaw';
import type { PolicyEvent, Decision, ClawdstrikeConfig } from '@clawdstrike/openclaw';

export interface SecureAssistantConfig extends ClawdstrikeConfig {
  projectRoot: string;
  allowedWritePaths?: string[];
  additionalForbiddenPaths?: string[];
}

export class SecureCodingAssistant {
  private engine: PolicyEngine;
  private config: SecureAssistantConfig;
  private sessionId: string;

  constructor(config: SecureAssistantConfig) {
    this.config = config;
    this.sessionId = crypto.randomUUID();
    this.engine = new PolicyEngine({
      policy: config.policy ?? 'ai-agent',
      mode: config.mode ?? 'deterministic',
      guards: {
        forbidden_path: true,
        egress: true,
        secret_leak: true,
        patch_integrity: true,
        mcp_tool: true,
        ...config.guards,
      },
    });
  }

  /**
   * Generate security-aware system prompt
   */
  getSystemPrompt(): string {
    const policy = this.engine.getPolicy();
    return generateSecurityPrompt(policy);
  }

  /**
   * Check if a file read is allowed
   */
  async canReadFile(path: string): Promise<Decision> {
    return this.engine.evaluate(this.createFileEvent(path, 'read'));
  }

  /**
   * Check if a file write is allowed and validate content
   */
  async canWriteFile(path: string, content: string): Promise<Decision> {
    // First check path
    const pathDecision = await this.engine.evaluate(
      this.createFileEvent(path, 'write')
    );
    if (pathDecision.denied) {
      return pathDecision;
    }

    // Then check content for secrets
    const contentDecision = await this.engine.evaluate(
      this.createPatchEvent(path, content)
    );

    return contentDecision;
  }

  /**
   * Check if a network request is allowed
   */
  async canMakeRequest(url: string): Promise<Decision> {
    const parsed = new URL(url);
    return this.engine.evaluate({
      eventId: this.generateEventId(),
      eventType: 'network_egress',
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      data: {
        type: 'network',
        host: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) :
          (parsed.protocol === 'https:' ? 443 : 80),
        url,
      },
    });
  }

  /**
   * Check if a shell command is allowed
   */
  async canExecuteCommand(command: string, args: string[] = []): Promise<Decision> {
    return this.engine.evaluate({
      eventId: this.generateEventId(),
      eventType: 'command_exec',
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      data: {
        type: 'command',
        command,
        args,
        workingDir: this.config.projectRoot,
      },
    });
  }

  /**
   * Redact secrets from output before displaying to user
   */
  redactSecrets(content: string): string {
    return this.engine.redactSecrets(content);
  }

  /**
   * Validate a patch/diff before applying
   */
  async validatePatch(filePath: string, patchContent: string): Promise<Decision> {
    return this.engine.evaluate(this.createPatchEvent(filePath, patchContent));
  }

  private createFileEvent(path: string, operation: 'read' | 'write'): PolicyEvent {
    return {
      eventId: this.generateEventId(),
      eventType: operation === 'read' ? 'file_read' : 'file_write',
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      data: {
        type: 'file',
        path,
        operation,
      },
    };
  }

  private createPatchEvent(filePath: string, patchContent: string): PolicyEvent {
    return {
      eventId: this.generateEventId(),
      eventType: 'patch_apply',
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      data: {
        type: 'patch',
        filePath,
        patchContent,
      },
    };
  }

  private generateEventId(): string {
    return `${this.sessionId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  }
}
```

### 4. VS Code Extension Integration

```typescript
// vscode-extension/src/extension.ts
import * as vscode from 'vscode';
import { SecureCodingAssistant } from './secure-assistant';

let assistant: SecureCodingAssistant;

export function activate(context: vscode.ExtensionContext) {
  // Initialize secure assistant
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';

  assistant = new SecureCodingAssistant({
    projectRoot: workspaceRoot,
    policy: vscode.workspace.getConfiguration('clawdstrike').get('policy', 'ai-agent'),
    mode: vscode.workspace.getConfiguration('clawdstrike').get('mode', 'deterministic'),
  });

  // Register file access interceptor
  context.subscriptions.push(
    vscode.workspace.onWillCreateFiles(async (e) => {
      for (const file of e.files) {
        const decision = await assistant.canWriteFile(file.fsPath, '');
        if (decision.denied) {
          e.waitUntil(Promise.reject(new Error(
            `[Clawdstrike] Write blocked: ${decision.reason}`
          )));
          vscode.window.showErrorMessage(
            `Security policy blocked file creation: ${decision.reason}`
          );
        }
      }
    })
  );

  // Register pre-save hook for content validation
  context.subscriptions.push(
    vscode.workspace.onWillSaveTextDocument(async (e) => {
      const content = e.document.getText();
      const decision = await assistant.canWriteFile(e.document.uri.fsPath, content);

      if (decision.denied) {
        vscode.window.showErrorMessage(
          `[Clawdstrike] Save blocked: ${decision.reason}\n` +
          `Please remove sensitive content before saving.`
        );
        // Note: Can't actually prevent save in onWillSave, need pre-save hook
      } else if (decision.warn) {
        vscode.window.showWarningMessage(
          `[Clawdstrike] Warning: ${decision.message}`
        );
      }
    })
  );

  // Register command to check current file
  context.subscriptions.push(
    vscode.commands.registerCommand('clawdstrike.checkCurrentFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('No file open');
        return;
      }

      const content = editor.document.getText();
      const decision = await assistant.canWriteFile(
        editor.document.uri.fsPath,
        content
      );

      if (decision.denied) {
        vscode.window.showErrorMessage(
          `Security issue detected: ${decision.reason}`
        );
      } else if (decision.warn) {
        vscode.window.showWarningMessage(
          `Warning: ${decision.message}`
        );
      } else {
        vscode.window.showInformationMessage(
          'No security issues detected'
        );
      }
    })
  );

  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBar.text = '$(shield) Clawdstrike';
  statusBar.tooltip = 'Clawdstrike security is active';
  statusBar.command = 'clawdstrike.checkCurrentFile';
  statusBar.show();
  context.subscriptions.push(statusBar);
}

export function deactivate() {}
```

### 5. Git Pre-commit Hook

```typescript
// hooks/pre-commit.ts
#!/usr/bin/env npx tsx

import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { PolicyEngine } from '@clawdstrike/openclaw';

async function main() {
  const engine = new PolicyEngine({
    policy: 'ai-agent',
    mode: 'deterministic',
  });

  // Get staged files
  const stagedFiles = execSync('git diff --cached --name-only --diff-filter=ACMR')
    .toString()
    .trim()
    .split('\n')
    .filter(Boolean);

  let hasErrors = false;
  const errors: string[] = [];

  for (const file of stagedFiles) {
    // Check file path
    const pathDecision = await engine.evaluate({
      eventId: `pre-commit-${Date.now()}`,
      eventType: 'file_write',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: file,
        operation: 'write',
      },
    });

    if (pathDecision.denied) {
      errors.push(`${file}: ${pathDecision.reason}`);
      hasErrors = true;
      continue;
    }

    // Check file content for secrets
    try {
      const content = readFileSync(file, 'utf-8');
      const contentDecision = await engine.evaluate({
        eventId: `pre-commit-content-${Date.now()}`,
        eventType: 'patch_apply',
        timestamp: new Date().toISOString(),
        data: {
          type: 'patch',
          filePath: file,
          patchContent: content,
        },
      });

      if (contentDecision.denied) {
        errors.push(`${file}: ${contentDecision.reason}`);
        hasErrors = true;
      } else if (contentDecision.warn) {
        console.warn(`Warning in ${file}: ${contentDecision.message}`);
      }
    } catch (e) {
      // Binary file or unreadable, skip
    }
  }

  if (hasErrors) {
    console.error('\n[Clawdstrike] Commit blocked due to security violations:\n');
    errors.forEach(err => console.error(`  - ${err}`));
    console.error('\nPlease fix these issues before committing.\n');
    process.exit(1);
  }

  console.log('[Clawdstrike] Security check passed');
  process.exit(0);
}

main().catch(e => {
  console.error('[Clawdstrike] Error during security check:', e);
  process.exit(1);
});
```

### 6. CLI Tool for Manual Checks

```typescript
// cli/scan.ts
import { Command } from 'commander';
import { glob } from 'glob';
import { readFileSync } from 'fs';
import { PolicyEngine } from '@clawdstrike/openclaw';
import chalk from 'chalk';

const program = new Command();

program
  .name('clawdstrike-scan')
  .description('Scan files for security issues')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan directory for security issues')
  .argument('<path>', 'Path to scan')
  .option('-p, --policy <policy>', 'Policy to use', 'ai-agent')
  .option('--ignore <patterns...>', 'Glob patterns to ignore')
  .option('--json', 'Output as JSON')
  .action(async (path: string, options) => {
    const engine = new PolicyEngine({
      policy: options.policy,
      mode: 'deterministic',
    });

    const ignorePatterns = options.ignore ?? [
      '**/node_modules/**',
      '**/vendor/**',
      '**/.git/**',
      '**/dist/**',
      '**/build/**',
    ];

    const files = await glob(`${path}/**/*`, {
      nodir: true,
      ignore: ignorePatterns,
    });

    const results: Array<{
      file: string;
      status: 'ok' | 'warning' | 'error';
      message?: string;
    }> = [];

    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8');
        const decision = await engine.evaluate({
          eventId: `scan-${Date.now()}`,
          eventType: 'patch_apply',
          timestamp: new Date().toISOString(),
          data: {
            type: 'patch',
            filePath: file,
            patchContent: content,
          },
        });

        if (decision.denied) {
          results.push({
            file,
            status: 'error',
            message: decision.reason,
          });
        } else if (decision.warn) {
          results.push({
            file,
            status: 'warning',
            message: decision.message,
          });
        } else {
          results.push({ file, status: 'ok' });
        }
      } catch (e) {
        // Binary file, skip
      }
    }

    if (options.json) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      const errors = results.filter(r => r.status === 'error');
      const warnings = results.filter(r => r.status === 'warning');

      if (errors.length > 0) {
        console.log(chalk.red(`\n${errors.length} security error(s) found:\n`));
        errors.forEach(e => {
          console.log(chalk.red(`  ${e.file}`));
          console.log(chalk.gray(`    ${e.message}\n`));
        });
      }

      if (warnings.length > 0) {
        console.log(chalk.yellow(`\n${warnings.length} warning(s):\n`));
        warnings.forEach(w => {
          console.log(chalk.yellow(`  ${w.file}`));
          console.log(chalk.gray(`    ${w.message}\n`));
        });
      }

      const okCount = results.filter(r => r.status === 'ok').length;
      console.log(chalk.green(`\n${okCount} files passed security checks`));

      if (errors.length > 0) {
        process.exit(1);
      }
    }
  });

program.parse();
```

## Security Considerations

### 1. Secret Redaction in AI Responses

```typescript
// Automatically redact secrets from AI responses
const response = await aiClient.complete(prompt);
const safeResponse = assistant.redactSecrets(response.text);
displayToUser(safeResponse);
```

### 2. Prompt Injection Prevention

```typescript
// Wrap untrusted content before sending to AI
import { wrap_user_content } from '@clawdstrike/openclaw';

const fileContent = await readFile(userSelectedFile);
const safeContent = wrap_user_content(fileContent, 'file');

const prompt = `Analyze this code:
${safeContent}
`;
```

### 3. Audit Logging

```typescript
// Log all AI interactions for compliance
import { AuditStore } from '@clawdstrike/openclaw';

const audit = new AuditStore('./audit.db');

await audit.log({
  sessionId: assistant.sessionId,
  action: 'ai_completion',
  prompt: prompt.substring(0, 1000), // Truncate for storage
  filesAccessed: accessedFiles,
  timestamp: new Date().toISOString(),
  decision: decision.allowed ? 'allowed' : 'blocked',
});
```

## Scaling Considerations

### Per-Developer Deployment

```
Developer 1          Developer 2          Developer N
     |                    |                    |
     v                    v                    v
+----------+         +----------+         +----------+
| Local    |         | Local    |         | Local    |
| Policy   |         | Policy   |         | Policy   |
| Engine   |         | Engine   |         | Engine   |
+----------+         +----------+         +----------+
     |                    |                    |
     v                    v                    v
+--------------------------------------------------+
|              Central Audit Collector              |
+--------------------------------------------------+
```

### Team-Level Deployment

```yaml
# docker-compose.yaml for team server
version: '3.8'
services:
  clawdstrike-server:
    image: clawdstrike/server:latest
    ports:
      - "8080:8080"
    volumes:
      - ./policy.yaml:/etc/clawdstrike/policy.yaml
      - ./audit:/var/lib/clawdstrike/audit
    environment:
      - CLAWDSTRIKE_POLICY=/etc/clawdstrike/policy.yaml
      - CLAWDSTRIKE_AUTH_ENABLED=true
```

## Cost Considerations

| Component | Cost | Notes |
|-----------|------|-------|
| OpenClaw Plugin | Free | Open source |
| Audit Storage | ~$1/dev/month | SQLite local or central |
| Team Server | ~$50/month | Optional, for central policy |
| Enterprise SSO | Custom | For large deployments |

## Step-by-Step Implementation Guide

### Phase 1: Local Setup (Day 1)

1. **Install the plugin**
   ```bash
   npm install -g @clawdstrike/openclaw
   ```

2. **Create project policy**
   ```bash
   # In your project root
   cat > clawdstrike.yaml << 'EOF'
   version: "1.0.0"
   extends: "ai-agent"
   name: "my-project"
   guards:
     forbidden_path:
       additional_patterns:
         - "**/secrets/**"
   EOF
   ```

3. **Configure IDE extension**
   ```json
   // .vscode/settings.json
   {
     "clawdstrike.policy": "./clawdstrike.yaml",
     "clawdstrike.mode": "deterministic"
   }
   ```

### Phase 2: Team Rollout (Week 1)

4. **Add pre-commit hook**
   ```bash
   # Install husky
   npm install -D husky
   npx husky init

   # Add pre-commit hook
   echo 'npx tsx ./hooks/pre-commit.ts' > .husky/pre-commit
   ```

5. **Configure CI check**
   ```yaml
   # .github/workflows/security.yml
   name: Security Check
   on: [push, pull_request]
   jobs:
     clawdstrike:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-node@v4
         - run: npm install -g @clawdstrike/openclaw
         - run: clawdstrike scan . --policy ai-agent
   ```

### Phase 3: Monitoring (Week 2)

6. **Set up audit collection**
   ```typescript
   // Centralize audit logs
   const audit = new AuditStore({
     backend: 'http://audit-server.internal:8080',
     apiKey: process.env.AUDIT_API_KEY,
   });
   ```

7. **Create security dashboard**
   - Track secret detection events
   - Monitor policy violations
   - Alert on unusual patterns

## Common Pitfalls and Solutions

### Pitfall 1: Too Restrictive for Development

**Problem**: Developers can't access test fixtures containing mock secrets.

**Solution**: Use skip_paths for test directories:
```yaml
secret_leak:
  skip_paths:
    - "**/test/**"
    - "**/fixtures/**"
    - "**/__mocks__/**"
```

### Pitfall 2: False Positives on Documentation

**Problem**: Example API keys in docs trigger alerts.

**Solution**: Allow example files:
```yaml
forbidden_path:
  exceptions:
    - "**/*.example"
    - "**/docs/**"
    - "**/README.md"
```

### Pitfall 3: Slow File Operations

**Problem**: Policy checks slow down file saves.

**Solution**: Use async checks and cache decisions:
```typescript
const pathCache = new Map<string, Decision>();

async function checkWithCache(path: string): Promise<Decision> {
  const cached = pathCache.get(path);
  if (cached) return cached;

  const decision = await engine.evaluate(createFileEvent(path));
  pathCache.set(path, decision);

  // Expire cache after 5 minutes
  setTimeout(() => pathCache.delete(path), 300000);

  return decision;
}
```

### Pitfall 4: Breaking CI/CD Pipelines

**Problem**: CI fails on legitimate automation secrets.

**Solution**: Create separate CI policy:
```yaml
# ci-policy.yaml
version: "1.0.0"
extends: "ai-agent"
name: "CI Policy"
guards:
  forbidden_path:
    exceptions:
      - "**/.github/workflows/**"
      - "**/buildspec.yml"
  egress_allowlist:
    additional_allow:
      - "*.actions.githubusercontent.com"
      - "*.pkg.github.com"
```

## Troubleshooting

### Issue: Policy Not Loading

**Symptoms**: Error messages about policy file not found or invalid YAML.

**Solutions**:
1. Verify policy file path is correct and file exists
2. Validate YAML syntax using `yamllint policy.yaml`
3. Check policy schema version matches Clawdstrike version
4. Ensure `extends` references valid base policy names

### Issue: High False Positive Rate on Secret Detection

**Symptoms**: Test files or documentation triggering secret alerts.

**Solutions**:
1. Add test directories to `skip_paths` in secret_leak guard
2. Use `.example` suffix for template files with fake credentials
3. Review and tune regex patterns for your codebase
4. Consider using severity thresholds to warn vs block

### Issue: IDE Extension Performance

**Symptoms**: File operations becoming slow with extension active.

**Solutions**:
1. Implement caching for path decisions (example provided in pitfalls section)
2. Use async evaluation to avoid blocking UI
3. Reduce `max_scan_bytes` for secret detection on large files
4. Exclude binary files and large generated files from scanning

### Issue: Pre-commit Hook Blocking Valid Commits

**Symptoms**: Developers unable to commit legitimate changes.

**Solutions**:
1. Review hook output to identify which guard is triggering
2. Add appropriate exceptions to policy for valid patterns
3. Use `--no-verify` as emergency escape hatch (document when this is acceptable)
4. Consider using warning mode for new rules before enforcing

## Validation Checklist

- [ ] Policy loads without errors
- [ ] IDE extension shows active status
- [ ] File access to .ssh is blocked
- [ ] Secret patterns are detected
- [ ] Pre-commit hook catches secrets
- [ ] CI pipeline runs security checks
- [ ] Audit logs are being collected
- [ ] Team members are trained
- [ ] Escape hatch documented (how to bypass in emergencies)
- [ ] Incident response process defined
