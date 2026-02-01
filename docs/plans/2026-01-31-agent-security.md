# Agent-Aware Security Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement agent-aware security features including bootstrap hook, policy_check tool, CLI commands, and hello-world example for hushclaw OpenClaw integration.

**Architecture:** Plugin-based integration with OpenClaw using hooks for enforcement points. The `agent:bootstrap` hook injects SECURITY.md into agent context. The `policy_check` tool allows agents to introspect policy before risky operations. CLI provides developer tooling for policy management.

**Tech Stack:** TypeScript, Node.js, Vitest, Commander.js, js-yaml

---

## Task 1: Project Scaffold

**Files:**
- Create: `packages/hushclaw-openclaw/package.json`
- Create: `packages/hushclaw-openclaw/tsconfig.json`
- Create: `packages/hushclaw-openclaw/vitest.config.ts`

**Step 1: Create package.json**

```bash
mkdir -p packages/hushclaw-openclaw/src
```

Create `packages/hushclaw-openclaw/package.json`:

```json
{
  "name": "@hushclaw/openclaw",
  "version": "0.1.0",
  "description": "Hushclaw security plugin for OpenClaw",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    },
    "./cli": {
      "import": "./dist/cli/index.js",
      "types": "./dist/cli/index.d.ts"
    }
  },
  "bin": {
    "hushclaw": "./dist/cli/bin.js"
  },
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "eslint src --ext .ts",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "commander": "^12.0.0",
    "js-yaml": "^4.1.0",
    "chalk": "^5.3.0",
    "glob": "^10.3.0"
  },
  "devDependencies": {
    "@types/js-yaml": "^4.0.9",
    "@types/node": "^20.11.0",
    "typescript": "^5.3.0",
    "vitest": "^1.2.0"
  },
  "peerDependencies": {
    "openclaw": ">=0.1.0"
  },
  "peerDependenciesMeta": {
    "openclaw": {
      "optional": true
    }
  },
  "files": [
    "dist",
    "rulesets"
  ],
  "keywords": [
    "openclaw",
    "security",
    "hushclaw",
    "ai-agent"
  ],
  "license": "MIT"
}
```

**Step 2: Create tsconfig.json**

Create `packages/hushclaw-openclaw/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

**Step 3: Create vitest.config.ts**

Create `packages/hushclaw-openclaw/vitest.config.ts`:

```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
    },
  },
});
```

**Step 4: Install dependencies**

Run:
```bash
cd packages/hushclaw-openclaw && npm install
```

**Step 5: Commit**

```bash
git add packages/hushclaw-openclaw/
git commit -m "chore: scaffold hushclaw-openclaw package"
```

---

## Task 2: Policy Types and Validator

**Files:**
- Create: `packages/hushclaw-openclaw/src/policy/types.ts`
- Create: `packages/hushclaw-openclaw/src/policy/validator.ts`
- Create: `packages/hushclaw-openclaw/src/policy/validator.test.ts`

**Step 1: Create policy types**

Create `packages/hushclaw-openclaw/src/policy/types.ts`:

```typescript
export interface EgressConfig {
  mode: 'allowlist' | 'denylist' | 'open';
  allowed_domains?: string[];
  denied_domains?: string[];
}

export interface FilesystemConfig {
  allowed_write_roots?: string[];
  forbidden_paths?: string[];
}

export interface ExecutionConfig {
  mode?: 'allowlist' | 'denylist';
  allowed_commands?: string[];
  denied_patterns?: string[];
}

export interface PolicyConfig {
  version?: string;
  extends?: string;
  egress?: EgressConfig;
  filesystem?: FilesystemConfig;
  execution?: ExecutionConfig;
  on_violation?: 'cancel' | 'warn' | 'log';
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export type ActionType = 'file_read' | 'file_write' | 'network_egress' | 'command_exec' | 'tool_call';

export interface PolicyEvent {
  type: ActionType;
  resource: string;
  params?: Record<string, unknown>;
  timestamp?: number;
}

export interface PolicyDecision {
  allowed: boolean;
  denied: boolean;
  reason?: string;
  guard?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}
```

**Step 2: Write failing validator test**

Create `packages/hushclaw-openclaw/src/policy/validator.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { validatePolicy } from './validator.js';

describe('validatePolicy', () => {
  it('validates a minimal valid policy', () => {
    const policy = { version: 'hushclaw-v1.0' };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('validates a full policy', () => {
    const policy = {
      version: 'hushclaw-v1.0',
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com'],
      },
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
      on_violation: 'cancel',
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
  });

  it('rejects invalid egress mode', () => {
    const policy = {
      egress: { mode: 'invalid' },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('egress.mode');
  });

  it('rejects invalid on_violation', () => {
    const policy = {
      on_violation: 'explode',
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('on_violation');
  });

  it('warns on empty forbidden_paths', () => {
    const policy = {
      filesystem: { forbidden_paths: [] },
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.warnings[0]).toContain('empty');
  });
});
```

**Step 3: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/policy/validator.test.ts`
Expected: FAIL with "Cannot find module './validator.js'"

**Step 4: Implement validator**

Create `packages/hushclaw-openclaw/src/policy/validator.ts`:

```typescript
import type { PolicyConfig, ValidationResult } from './types.js';

const VALID_EGRESS_MODES = ['allowlist', 'denylist', 'open'];
const VALID_VIOLATION_ACTIONS = ['cancel', 'warn', 'log'];
const VALID_EXEC_MODES = ['allowlist', 'denylist'];

export function validatePolicy(policy: unknown): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (typeof policy !== 'object' || policy === null) {
    return { valid: false, errors: ['Policy must be an object'], warnings: [] };
  }

  const p = policy as PolicyConfig;

  // Validate egress
  if (p.egress) {
    if (p.egress.mode && !VALID_EGRESS_MODES.includes(p.egress.mode)) {
      errors.push(`egress.mode must be one of: ${VALID_EGRESS_MODES.join(', ')}`);
    }
    if (p.egress.allowed_domains && !Array.isArray(p.egress.allowed_domains)) {
      errors.push('egress.allowed_domains must be an array');
    }
    if (p.egress.denied_domains && !Array.isArray(p.egress.denied_domains)) {
      errors.push('egress.denied_domains must be an array');
    }
  }

  // Validate filesystem
  if (p.filesystem) {
    if (p.filesystem.forbidden_paths) {
      if (!Array.isArray(p.filesystem.forbidden_paths)) {
        errors.push('filesystem.forbidden_paths must be an array');
      } else if (p.filesystem.forbidden_paths.length === 0) {
        warnings.push('filesystem.forbidden_paths is empty - no paths will be protected');
      }
    }
    if (p.filesystem.allowed_write_roots && !Array.isArray(p.filesystem.allowed_write_roots)) {
      errors.push('filesystem.allowed_write_roots must be an array');
    }
  }

  // Validate execution
  if (p.execution) {
    if (p.execution.mode && !VALID_EXEC_MODES.includes(p.execution.mode)) {
      errors.push(`execution.mode must be one of: ${VALID_EXEC_MODES.join(', ')}`);
    }
  }

  // Validate on_violation
  if (p.on_violation && !VALID_VIOLATION_ACTIONS.includes(p.on_violation)) {
    errors.push(`on_violation must be one of: ${VALID_VIOLATION_ACTIONS.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
```

**Step 5: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/policy/validator.test.ts`
Expected: PASS

**Step 6: Commit**

```bash
git add packages/hushclaw-openclaw/src/policy/
git commit -m "feat: add policy types and validator"
```

---

## Task 3: Policy Engine

**Files:**
- Create: `packages/hushclaw-openclaw/src/policy/engine.ts`
- Create: `packages/hushclaw-openclaw/src/policy/engine.test.ts`

**Step 1: Write failing engine test**

Create `packages/hushclaw-openclaw/src/policy/engine.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { PolicyEngine } from './engine.js';
import type { PolicyConfig } from './types.js';

describe('PolicyEngine', () => {
  describe('file operations', () => {
    it('blocks forbidden paths', async () => {
      const policy: PolicyConfig = {
        filesystem: {
          forbidden_paths: ['~/.ssh', '~/.aws'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'file_read',
        resource: '~/.ssh/id_rsa',
      });
      expect(decision.denied).toBe(true);
      expect(decision.guard).toBe('ForbiddenPathGuard');
    });

    it('allows non-forbidden paths', async () => {
      const policy: PolicyConfig = {
        filesystem: {
          forbidden_paths: ['~/.ssh'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'file_read',
        resource: '/tmp/test.txt',
      });
      expect(decision.allowed).toBe(true);
    });

    it('blocks writes outside allowed roots', async () => {
      const policy: PolicyConfig = {
        filesystem: {
          allowed_write_roots: ['/tmp', '/workspace'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'file_write',
        resource: '/etc/passwd',
      });
      expect(decision.denied).toBe(true);
    });
  });

  describe('egress operations', () => {
    it('blocks non-allowlisted domains in allowlist mode', async () => {
      const policy: PolicyConfig = {
        egress: {
          mode: 'allowlist',
          allowed_domains: ['api.github.com'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'network_egress',
        resource: 'https://evil.com/data',
      });
      expect(decision.denied).toBe(true);
      expect(decision.guard).toBe('EgressAllowlistGuard');
    });

    it('allows allowlisted domains', async () => {
      const policy: PolicyConfig = {
        egress: {
          mode: 'allowlist',
          allowed_domains: ['api.github.com'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'network_egress',
        resource: 'https://api.github.com/user',
      });
      expect(decision.allowed).toBe(true);
    });

    it('supports wildcard domains', async () => {
      const policy: PolicyConfig = {
        egress: {
          mode: 'allowlist',
          allowed_domains: ['*.github.com'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'network_egress',
        resource: 'https://api.github.com/user',
      });
      expect(decision.allowed).toBe(true);
    });
  });

  describe('createEvent helper', () => {
    it('creates file_read event', () => {
      const engine = new PolicyEngine({});
      const event = engine.createEvent('file_read', '/path/to/file');
      expect(event.type).toBe('file_read');
      expect(event.resource).toBe('/path/to/file');
    });
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/policy/engine.test.ts`
Expected: FAIL

**Step 3: Implement PolicyEngine**

Create `packages/hushclaw-openclaw/src/policy/engine.ts`:

```typescript
import type { PolicyConfig, PolicyEvent, PolicyDecision, ActionType } from './types.js';

export class PolicyEngine {
  private config: PolicyConfig;

  constructor(config: PolicyConfig) {
    this.config = config;
  }

  async evaluate(event: PolicyEvent): Promise<PolicyDecision> {
    // Check filesystem guards
    if (event.type === 'file_read' || event.type === 'file_write') {
      const fsDecision = this.checkFilesystem(event);
      if (fsDecision.denied) return fsDecision;
    }

    // Check egress guards
    if (event.type === 'network_egress') {
      const egressDecision = this.checkEgress(event);
      if (egressDecision.denied) return egressDecision;
    }

    return { allowed: true, denied: false };
  }

  private checkFilesystem(event: PolicyEvent): PolicyDecision {
    const { filesystem } = this.config;
    if (!filesystem) return { allowed: true, denied: false };

    // Check forbidden paths
    if (filesystem.forbidden_paths) {
      for (const pattern of filesystem.forbidden_paths) {
        if (this.matchPath(event.resource, pattern)) {
          return {
            allowed: false,
            denied: true,
            reason: `Path matches forbidden pattern: ${pattern}`,
            guard: 'ForbiddenPathGuard',
            severity: 'critical',
          };
        }
      }
    }

    // Check allowed write roots for write operations
    if (event.type === 'file_write' && filesystem.allowed_write_roots) {
      const isAllowed = filesystem.allowed_write_roots.some(root =>
        this.matchPath(event.resource, root) || event.resource.startsWith(this.expandPath(root))
      );
      if (!isAllowed) {
        return {
          allowed: false,
          denied: true,
          reason: `Write path not in allowed roots`,
          guard: 'WriteRootGuard',
          severity: 'high',
        };
      }
    }

    return { allowed: true, denied: false };
  }

  private checkEgress(event: PolicyEvent): PolicyDecision {
    const { egress } = this.config;
    if (!egress || egress.mode === 'open') return { allowed: true, denied: false };

    const domain = this.extractDomain(event.resource);

    if (egress.mode === 'allowlist') {
      const allowed = egress.allowed_domains?.some(pattern =>
        this.matchDomain(domain, pattern)
      );
      if (!allowed) {
        return {
          allowed: false,
          denied: true,
          reason: `Domain '${domain}' not in egress allowlist`,
          guard: 'EgressAllowlistGuard',
          severity: 'high',
        };
      }
    }

    if (egress.mode === 'denylist' && egress.denied_domains) {
      const denied = egress.denied_domains.some(pattern =>
        this.matchDomain(domain, pattern)
      );
      if (denied) {
        return {
          allowed: false,
          denied: true,
          reason: `Domain '${domain}' is in deny list`,
          guard: 'EgressDenylistGuard',
          severity: 'high',
        };
      }
    }

    return { allowed: true, denied: false };
  }

  private matchPath(path: string, pattern: string): boolean {
    const expandedPattern = this.expandPath(pattern);
    const expandedPath = this.expandPath(path);

    // Simple prefix match for now
    if (expandedPath.startsWith(expandedPattern)) return true;
    if (expandedPath.includes(expandedPattern)) return true;

    return false;
  }

  private matchDomain(domain: string, pattern: string): boolean {
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1); // Remove *
      return domain.endsWith(suffix) || domain === pattern.slice(2);
    }
    return domain === pattern;
  }

  private extractDomain(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.hostname;
    } catch {
      return url;
    }
  }

  private expandPath(path: string): string {
    return path.replace(/^~/, process.env.HOME || '/home/user');
  }

  createEvent(action: ActionType, resource: string, params?: Record<string, unknown>): PolicyEvent {
    return {
      type: action,
      resource,
      params,
      timestamp: Date.now(),
    };
  }
}
```

**Step 4: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/policy/engine.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hushclaw-openclaw/src/policy/engine.ts packages/hushclaw-openclaw/src/policy/engine.test.ts
git commit -m "feat: add PolicyEngine with filesystem and egress guards"
```

---

## Task 4: Security Prompt Generator

**Files:**
- Create: `packages/hushclaw-openclaw/src/security-prompt.ts`
- Create: `packages/hushclaw-openclaw/src/security-prompt.test.ts`

**Step 1: Write failing test**

Create `packages/hushclaw-openclaw/src/security-prompt.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { generateSecurityPrompt } from './security-prompt.js';
import type { PolicyConfig } from './policy/types.js';

describe('generateSecurityPrompt', () => {
  it('generates prompt with allowlist egress info', () => {
    const config: PolicyConfig = {
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com', 'pypi.org'],
      },
    };
    const prompt = generateSecurityPrompt(config);
    expect(prompt).toContain('api.github.com');
    expect(prompt).toContain('pypi.org');
    expect(prompt).toContain('allowed');
  });

  it('includes forbidden paths', () => {
    const config: PolicyConfig = {
      filesystem: {
        forbidden_paths: ['~/.ssh', '~/.aws'],
      },
    };
    const prompt = generateSecurityPrompt(config);
    expect(prompt).toContain('~/.ssh');
    expect(prompt).toContain('~/.aws');
    expect(prompt).toContain('FORBIDDEN');
  });

  it('includes violation handling info', () => {
    const config: PolicyConfig = {
      on_violation: 'cancel',
    };
    const prompt = generateSecurityPrompt(config);
    expect(prompt).toContain('BLOCKED');
  });

  it('mentions policy_check tool', () => {
    const prompt = generateSecurityPrompt({});
    expect(prompt).toContain('policy_check');
  });

  it('handles empty config gracefully', () => {
    const prompt = generateSecurityPrompt({});
    expect(prompt).toContain('Security Policy');
    expect(typeof prompt).toBe('string');
    expect(prompt.length).toBeGreaterThan(100);
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/security-prompt.test.ts`
Expected: FAIL

**Step 3: Implement security prompt generator**

Create `packages/hushclaw-openclaw/src/security-prompt.ts`:

```typescript
import type { PolicyConfig } from './policy/types.js';

export function generateSecurityPrompt(config: PolicyConfig): string {
  const sections: string[] = [];

  sections.push(`# Security Policy

You are protected by hushclaw security enforcement. The following constraints apply:`);

  // Network Access section
  sections.push(`
## Network Access`);

  if (config.egress?.mode === 'allowlist' && config.egress.allowed_domains?.length) {
    sections.push(`- Only these domains are allowed: ${config.egress.allowed_domains.join(', ')}`);
  } else if (config.egress?.mode === 'denylist' && config.egress.denied_domains?.length) {
    sections.push(`- These domains are blocked: ${config.egress.denied_domains.join(', ')}`);
  } else {
    sections.push(`- Network access follows default policy`);
  }

  // Filesystem Access section
  sections.push(`
## Filesystem Access`);

  if (config.filesystem?.forbidden_paths?.length) {
    sections.push(`- These paths are FORBIDDEN and will be blocked:`);
    for (const path of config.filesystem.forbidden_paths) {
      sections.push(`  - ${path}`);
    }
  } else {
    sections.push(`- Default protected paths: ~/.ssh, ~/.aws, ~/.gnupg, .env files`);
  }

  if (config.filesystem?.allowed_write_roots?.length) {
    sections.push(`- Writes are only allowed in: ${config.filesystem.allowed_write_roots.join(', ')}`);
  }

  // Security Tools section
  sections.push(`
## Security Tools
You have access to the \`policy_check\` tool. Use it BEFORE attempting:
- File operations on unfamiliar paths
- Network requests to unfamiliar domains
- Execution of shell commands

Example:
\`\`\`
policy_check({ action: "file_write", resource: "/etc/passwd" })
→ { allowed: false, reason: "Path is forbidden" }
\`\`\``);

  // Violation Handling section
  const blockAction = config.on_violation === 'cancel' ? 'BLOCKED' :
                      config.on_violation === 'warn' ? 'logged with a warning' : 'logged';

  sections.push(`
## Violation Handling
When a security violation occurs:
1. The operation will be ${blockAction}
2. You will see an error message explaining why
3. Try an alternative approach that respects the policy`);

  // Tips section
  sections.push(`
## Tips
- Prefer working within /workspace or /tmp
- Use known package registries (npm, pypi, crates.io)
- Never attempt to access credentials or keys
- When unsure, use \`policy_check\` first`);

  return sections.join('\n');
}
```

**Step 4: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/security-prompt.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hushclaw-openclaw/src/security-prompt.ts packages/hushclaw-openclaw/src/security-prompt.test.ts
git commit -m "feat: add security prompt generator for agent context"
```

---

## Task 5: Agent Bootstrap Hook

**Files:**
- Create: `packages/hushclaw-openclaw/src/hooks/agent-bootstrap/handler.ts`
- Create: `packages/hushclaw-openclaw/src/hooks/agent-bootstrap/HOOK.md`
- Create: `packages/hushclaw-openclaw/src/hooks/agent-bootstrap/handler.test.ts`

**Step 1: Create HOOK.md metadata**

Create `packages/hushclaw-openclaw/src/hooks/agent-bootstrap/HOOK.md`:

```markdown
---
name: hushclaw-bootstrap
description: Inject security context into agent workspace
metadata: {"openclaw":{"emoji":"🔒","events":["agent:bootstrap"]}}
---

# Hushclaw Bootstrap Hook

Injects SECURITY.md into the agent workspace during bootstrap.
This file informs the agent about security constraints and available tools.

## Behavior

1. Loads policy from config
2. Generates security prompt using `generateSecurityPrompt()`
3. Adds SECURITY.md to bootstrap files

## Configuration

The hook reads policy from:
- `event.context.cfg.hushclaw.policy` - Policy file path
- Inline policy config in `event.context.cfg.hushclaw`
```

**Step 2: Write failing test**

Create `packages/hushclaw-openclaw/src/hooks/agent-bootstrap/handler.test.ts`:

```typescript
import { describe, it, expect, vi } from 'vitest';
import handler from './handler.js';

describe('agent:bootstrap handler', () => {
  it('ignores non-bootstrap events', async () => {
    const event = {
      type: 'other:event',
      context: { bootstrapFiles: [] },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(0);
  });

  it('injects SECURITY.md into bootstrap files', async () => {
    const event = {
      type: 'agent:bootstrap',
      context: {
        bootstrapFiles: [],
        cfg: {
          hushclaw: {
            egress: {
              mode: 'allowlist',
              allowed_domains: ['api.github.com'],
            },
          },
        },
      },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(1);
    expect(event.context.bootstrapFiles[0].path).toBe('SECURITY.md');
    expect(event.context.bootstrapFiles[0].content).toContain('Security Policy');
    expect(event.context.bootstrapFiles[0].content).toContain('api.github.com');
  });

  it('uses default policy when none provided', async () => {
    const event = {
      type: 'agent:bootstrap',
      context: {
        bootstrapFiles: [],
        cfg: {},
      },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(1);
    expect(event.context.bootstrapFiles[0].content).toContain('policy_check');
  });
});
```

**Step 3: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/hooks/agent-bootstrap/handler.test.ts`
Expected: FAIL

**Step 4: Implement handler**

Create `packages/hushclaw-openclaw/src/hooks/agent-bootstrap/handler.ts`:

```typescript
import { generateSecurityPrompt } from '../../security-prompt.js';
import type { PolicyConfig } from '../../policy/types.js';

interface BootstrapFile {
  path: string;
  content: string;
}

interface BootstrapEvent {
  type: string;
  context: {
    bootstrapFiles: BootstrapFile[];
    cfg: {
      hushclaw?: PolicyConfig;
    };
  };
}

const handler = async (event: BootstrapEvent): Promise<void> => {
  if (event.type !== 'agent:bootstrap') return;

  const config = event.context.cfg.hushclaw || {};
  const securityPrompt = generateSecurityPrompt(config);

  event.context.bootstrapFiles.push({
    path: 'SECURITY.md',
    content: securityPrompt,
  });
};

export default handler;
```

**Step 5: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/hooks/agent-bootstrap/handler.test.ts`
Expected: PASS

**Step 6: Commit**

```bash
git add packages/hushclaw-openclaw/src/hooks/
git commit -m "feat: add agent:bootstrap hook for SECURITY.md injection"
```

---

## Task 6: Policy Check Tool

**Files:**
- Create: `packages/hushclaw-openclaw/src/tools/policy-check.ts`
- Create: `packages/hushclaw-openclaw/src/tools/policy-check.test.ts`

**Step 1: Write failing test**

Create `packages/hushclaw-openclaw/src/tools/policy-check.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { policyCheckTool } from './policy-check.js';
import { PolicyEngine } from '../policy/engine.js';
import type { PolicyConfig } from '../policy/types.js';

describe('policyCheckTool', () => {
  it('has correct schema', () => {
    const engine = new PolicyEngine({});
    const tool = policyCheckTool(engine);

    expect(tool.name).toBe('policy_check');
    expect(tool.schema.properties.action).toBeDefined();
    expect(tool.schema.properties.resource).toBeDefined();
    expect(tool.schema.required).toContain('action');
    expect(tool.schema.required).toContain('resource');
  });

  it('returns allowed for permitted action', async () => {
    const policy: PolicyConfig = {
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_read',
      resource: '/tmp/test.txt',
    });

    expect(result.allowed).toBe(true);
    expect(result.denied).toBe(false);
  });

  it('returns denied for blocked action', async () => {
    const policy: PolicyConfig = {
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_read',
      resource: '~/.ssh/id_rsa',
    });

    expect(result.allowed).toBe(false);
    expect(result.denied).toBe(true);
    expect(result.guard).toBe('ForbiddenPathGuard');
  });

  it('provides suggestions for denied actions', async () => {
    const policy: PolicyConfig = {
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_write',
      resource: '~/.ssh/authorized_keys',
    });

    expect(result.suggestion).toBeDefined();
    expect(result.suggestion).toContain('SSH');
  });

  it('handles egress checks', async () => {
    const policy: PolicyConfig = {
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'network_egress',
      resource: 'https://evil.com',
    });

    expect(result.denied).toBe(true);
    expect(result.suggestion).toContain('allowed domain');
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/tools/policy-check.test.ts`
Expected: FAIL

**Step 3: Implement policy check tool**

Create `packages/hushclaw-openclaw/src/tools/policy-check.ts`:

```typescript
import type { PolicyEngine } from '../policy/engine.js';
import type { ActionType } from '../policy/types.js';

interface ToolSchema {
  type: 'object';
  properties: Record<string, unknown>;
  required: string[];
}

interface Tool {
  name: string;
  description: string;
  schema: ToolSchema;
  execute: (params: { action: string; resource: string; params?: Record<string, unknown> }) => Promise<PolicyCheckResult>;
}

interface PolicyCheckResult {
  allowed: boolean;
  denied: boolean;
  reason: string;
  guard?: string;
  severity?: string;
  suggestion?: string;
}

export function policyCheckTool(engine: PolicyEngine): Tool {
  return {
    name: 'policy_check',
    description: 'Check if an action is allowed by the security policy. Use this BEFORE attempting potentially restricted operations.',
    schema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['file_read', 'file_write', 'network_egress', 'command_exec', 'tool_call'],
          description: 'The type of action to check',
        },
        resource: {
          type: 'string',
          description: 'The resource to check (path, domain, command, or tool name)',
        },
        params: {
          type: 'object',
          description: 'Optional additional parameters',
        },
      },
      required: ['action', 'resource'],
    },
    execute: async ({ action, resource, params }) => {
      const event = engine.createEvent(action as ActionType, resource, params);
      const decision = await engine.evaluate(event);

      return {
        allowed: decision.allowed,
        denied: decision.denied,
        reason: decision.reason || (decision.allowed ? 'Action is permitted' : 'Action is not permitted'),
        guard: decision.guard,
        severity: decision.severity,
        suggestion: decision.denied ? getSuggestion(action, resource) : undefined,
      };
    },
  };
}

function getSuggestion(action: string, resource: string): string {
  if ((action === 'file_write' || action === 'file_read') && resource.includes('.ssh')) {
    return 'SSH keys are protected. Consider using a different credential storage method.';
  }
  if ((action === 'file_write' || action === 'file_read') && resource.includes('.aws')) {
    return 'AWS credentials are protected. Use environment variables or IAM roles instead.';
  }
  if (action === 'network_egress') {
    return 'Try using an allowed domain like api.github.com or pypi.org.';
  }
  if (action === 'command_exec' && resource.includes('sudo')) {
    return 'Privileged commands are restricted. Try running without sudo.';
  }
  if (action === 'command_exec' && (resource.includes('rm -rf') || resource.includes('dd if='))) {
    return 'Destructive commands are blocked. Consider safer alternatives.';
  }
  return 'Consider an alternative approach that works within the security policy.';
}
```

**Step 4: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/tools/policy-check.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hushclaw-openclaw/src/tools/
git commit -m "feat: add policy_check tool for agent policy introspection"
```

---

## Task 7: Policy Loader

**Files:**
- Create: `packages/hushclaw-openclaw/src/policy/loader.ts`
- Create: `packages/hushclaw-openclaw/src/policy/loader.test.ts`

**Step 1: Write failing test**

Create `packages/hushclaw-openclaw/src/policy/loader.test.ts`:

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadPolicy, loadPolicyFromString } from './loader.js';
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('loadPolicyFromString', () => {
  it('parses valid YAML policy', () => {
    const yaml = `
version: hushclaw-v1.0
egress:
  mode: allowlist
  allowed_domains:
    - api.github.com
`;
    const policy = loadPolicyFromString(yaml);
    expect(policy.version).toBe('hushclaw-v1.0');
    expect(policy.egress?.mode).toBe('allowlist');
    expect(policy.egress?.allowed_domains).toContain('api.github.com');
  });

  it('throws on invalid YAML', () => {
    const yaml = `{{{invalid`;
    expect(() => loadPolicyFromString(yaml)).toThrow();
  });
});

describe('loadPolicy', () => {
  const testDir = join(tmpdir(), 'hushclaw-test-' + Date.now());

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it('loads policy from file', async () => {
    const policyPath = join(testDir, 'policy.yaml');
    writeFileSync(policyPath, `
version: hushclaw-v1.0
filesystem:
  forbidden_paths:
    - ~/.ssh
`);
    const policy = await loadPolicy(policyPath);
    expect(policy.version).toBe('hushclaw-v1.0');
    expect(policy.filesystem?.forbidden_paths).toContain('~/.ssh');
  });

  it('throws on missing file', async () => {
    await expect(loadPolicy('/nonexistent/policy.yaml')).rejects.toThrow();
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/policy/loader.test.ts`
Expected: FAIL

**Step 3: Implement loader**

Create `packages/hushclaw-openclaw/src/policy/loader.ts`:

```typescript
import { load } from 'js-yaml';
import { readFile } from 'fs/promises';
import type { PolicyConfig } from './types.js';

export function loadPolicyFromString(content: string): PolicyConfig {
  const parsed = load(content);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Policy must be a YAML object');
  }
  return parsed as PolicyConfig;
}

export async function loadPolicy(path: string): Promise<PolicyConfig> {
  const content = await readFile(path, 'utf-8');
  return loadPolicyFromString(content);
}
```

**Step 4: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/policy/loader.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hushclaw-openclaw/src/policy/loader.ts packages/hushclaw-openclaw/src/policy/loader.test.ts
git commit -m "feat: add policy loader for YAML files"
```

---

## Task 8: CLI Policy Commands

**Files:**
- Create: `packages/hushclaw-openclaw/src/cli/commands/policy.ts`
- Create: `packages/hushclaw-openclaw/src/cli/commands/policy.test.ts`

**Step 1: Write failing test**

Create `packages/hushclaw-openclaw/src/cli/commands/policy.test.ts`:

```typescript
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { policyCommands } from './policy.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('policyCommands', () => {
  const testDir = join(tmpdir(), 'hushclaw-cli-test-' + Date.now());
  let consoleLog: ReturnType<typeof vi.spyOn>;
  let processExit: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
    consoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
    processExit = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
    consoleLog.mockRestore();
    processExit.mockRestore();
  });

  describe('lint', () => {
    it('validates a correct policy file', async () => {
      const policyPath = join(testDir, 'valid.yaml');
      writeFileSync(policyPath, `
version: hushclaw-v1.0
egress:
  mode: allowlist
  allowed_domains:
    - api.github.com
`);
      await policyCommands.lint(policyPath);
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('valid'));
    });

    it('reports invalid policy file', async () => {
      const policyPath = join(testDir, 'invalid.yaml');
      writeFileSync(policyPath, `
egress:
  mode: invalid_mode
`);
      await policyCommands.lint(policyPath);
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('failed'));
      expect(processExit).toHaveBeenCalledWith(1);
    });

    it('handles missing file', async () => {
      await policyCommands.lint('/nonexistent/policy.yaml');
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('Failed'));
      expect(processExit).toHaveBeenCalledWith(1);
    });
  });

  describe('test', () => {
    it('tests event against policy', async () => {
      const policyPath = join(testDir, 'policy.yaml');
      const eventPath = join(testDir, 'event.json');

      writeFileSync(policyPath, `
filesystem:
  forbidden_paths:
    - ~/.ssh
`);
      writeFileSync(eventPath, JSON.stringify({
        type: 'file_read',
        resource: '~/.ssh/id_rsa',
      }));

      await policyCommands.test(eventPath, { policy: policyPath });
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('DENIED'));
    });
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/cli/commands/policy.test.ts`
Expected: FAIL

**Step 3: Implement policy commands**

Create `packages/hushclaw-openclaw/src/cli/commands/policy.ts`:

```typescript
import { readFileSync } from 'fs';
import { loadPolicy, loadPolicyFromString } from '../../policy/loader.js';
import { validatePolicy } from '../../policy/validator.js';
import { PolicyEngine } from '../../policy/engine.js';
import type { PolicyEvent } from '../../policy/types.js';

export const policyCommands = {
  async lint(file: string): Promise<void> {
    try {
      const content = readFileSync(file, 'utf-8');
      const policy = loadPolicyFromString(content);
      const result = validatePolicy(policy);

      if (result.valid) {
        console.log('Policy is valid');
        console.log(`   Version: ${policy.version || 'unspecified'}`);
        const guards = Object.keys(policy).filter(k => !['version', 'on_violation', 'extends'].includes(k));
        console.log(`   Guards: ${guards.join(', ') || 'none'}`);

        if (result.warnings.length > 0) {
          console.log('\nWarnings:');
          result.warnings.forEach(w => console.log(`   - ${w}`));
        }
      } else {
        console.log('Policy validation failed:');
        result.errors.forEach(err => console.log(`   - ${err}`));
        process.exit(1);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to read policy file: ${message}`);
      process.exit(1);
    }
  },

  async show(options: { policy?: string } = {}): Promise<void> {
    try {
      const policyPath = options.policy || '.hush/policy.yaml';
      const policy = await loadPolicy(policyPath);
      console.log('Current policy:');
      console.log(JSON.stringify(policy, null, 2));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to load policy: ${message}`);
      process.exit(1);
    }
  },

  async test(eventFile: string, options: { policy?: string } = {}): Promise<void> {
    try {
      const policyPath = options.policy || '.hush/policy.yaml';
      const policy = await loadPolicy(policyPath);
      const event: PolicyEvent = JSON.parse(readFileSync(eventFile, 'utf-8'));

      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate(event);

      console.log('Decision:', decision.allowed ? 'ALLOWED' : 'DENIED');
      if (decision.reason) console.log('Reason:', decision.reason);
      if (decision.guard) console.log('Guard:', decision.guard);
      if (decision.severity) console.log('Severity:', decision.severity);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to test event: ${message}`);
      process.exit(1);
    }
  },

  async diff(file1: string, file2: string): Promise<void> {
    try {
      const p1 = await loadPolicy(file1);
      const p2 = await loadPolicy(file2);

      console.log('Policy Diff:');
      console.log('============');

      // Compare egress
      if (JSON.stringify(p1.egress) !== JSON.stringify(p2.egress)) {
        console.log('\nEgress:');
        console.log('  File 1:', JSON.stringify(p1.egress || {}));
        console.log('  File 2:', JSON.stringify(p2.egress || {}));
      }

      // Compare filesystem
      if (JSON.stringify(p1.filesystem) !== JSON.stringify(p2.filesystem)) {
        console.log('\nFilesystem:');
        console.log('  File 1:', JSON.stringify(p1.filesystem || {}));
        console.log('  File 2:', JSON.stringify(p2.filesystem || {}));
      }

      // Compare on_violation
      if (p1.on_violation !== p2.on_violation) {
        console.log('\nOn Violation:');
        console.log('  File 1:', p1.on_violation || 'default');
        console.log('  File 2:', p2.on_violation || 'default');
      }

      if (JSON.stringify(p1) === JSON.stringify(p2)) {
        console.log('Policies are identical');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to diff policies: ${message}`);
      process.exit(1);
    }
  },
};
```

**Step 4: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/cli/commands/policy.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hushclaw-openclaw/src/cli/
git commit -m "feat: add CLI policy commands (lint, show, test, diff)"
```

---

## Task 9: CLI Audit Commands

**Files:**
- Create: `packages/hushclaw-openclaw/src/cli/commands/audit.ts`
- Create: `packages/hushclaw-openclaw/src/cli/commands/audit.test.ts`
- Create: `packages/hushclaw-openclaw/src/audit/store.ts`

**Step 1: Create audit store**

Create `packages/hushclaw-openclaw/src/audit/store.ts`:

```typescript
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';

export interface AuditEvent {
  id: string;
  timestamp: number;
  type: string;
  resource: string;
  decision: 'allowed' | 'denied';
  guard?: string;
  reason?: string;
  runId?: string;
}

export class AuditStore {
  private path: string;
  private events: AuditEvent[] = [];

  constructor(path: string = '.hush/audit.jsonl') {
    this.path = path;
    this.load();
  }

  private load(): void {
    if (existsSync(this.path)) {
      const content = readFileSync(this.path, 'utf-8');
      this.events = content
        .split('\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line));
    }
  }

  append(event: Omit<AuditEvent, 'id' | 'timestamp'>): AuditEvent {
    const fullEvent: AuditEvent = {
      ...event,
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: Date.now(),
    };
    this.events.push(fullEvent);

    const dir = dirname(this.path);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(this.path, this.events.map(e => JSON.stringify(e)).join('\n') + '\n');

    return fullEvent;
  }

  query(options: {
    since?: number;
    guard?: string;
    denied?: boolean;
    limit?: number;
  } = {}): AuditEvent[] {
    let results = [...this.events];

    if (options.since) {
      results = results.filter(e => e.timestamp >= options.since!);
    }
    if (options.guard) {
      results = results.filter(e => e.guard === options.guard);
    }
    if (options.denied) {
      results = results.filter(e => e.decision === 'denied');
    }
    if (options.limit) {
      results = results.slice(-options.limit);
    }

    return results;
  }

  getById(id: string): AuditEvent | undefined {
    return this.events.find(e => e.id === id);
  }

  clear(): void {
    this.events = [];
    if (existsSync(this.path)) {
      writeFileSync(this.path, '');
    }
  }
}
```

**Step 2: Write failing audit commands test**

Create `packages/hushclaw-openclaw/src/cli/commands/audit.test.ts`:

```typescript
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { auditCommands } from './audit.js';
import { AuditStore } from '../../audit/store.js';
import { mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('auditCommands', () => {
  const testDir = join(tmpdir(), 'hushclaw-audit-test-' + Date.now());
  let consoleLog: ReturnType<typeof vi.spyOn>;
  let store: AuditStore;

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
    store = new AuditStore(join(testDir, 'audit.jsonl'));
    consoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
    consoleLog.mockRestore();
  });

  describe('query', () => {
    it('lists recent events', async () => {
      store.append({ type: 'file_read', resource: '/tmp/test', decision: 'allowed' });
      store.append({ type: 'file_read', resource: '~/.ssh/id_rsa', decision: 'denied', guard: 'ForbiddenPathGuard' });

      await auditCommands.query({ auditPath: join(testDir, 'audit.jsonl') });
      expect(consoleLog).toHaveBeenCalled();
    });

    it('filters by denied only', async () => {
      store.append({ type: 'file_read', resource: '/tmp/test', decision: 'allowed' });
      store.append({ type: 'file_read', resource: '~/.ssh/id_rsa', decision: 'denied', guard: 'ForbiddenPathGuard' });

      await auditCommands.query({ denied: true, auditPath: join(testDir, 'audit.jsonl') });
      // Should only show denied events
    });
  });

  describe('explain', () => {
    it('explains a specific event', async () => {
      const event = store.append({
        type: 'file_read',
        resource: '~/.ssh/id_rsa',
        decision: 'denied',
        guard: 'ForbiddenPathGuard',
        reason: 'Path matches forbidden pattern: ~/.ssh'
      });

      await auditCommands.explain(event.id, { auditPath: join(testDir, 'audit.jsonl') });
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('ForbiddenPathGuard'));
    });

    it('handles unknown event id', async () => {
      await auditCommands.explain('unknown-id', { auditPath: join(testDir, 'audit.jsonl') });
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('not found'));
    });
  });
});
```

**Step 3: Run test to verify it fails**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/cli/commands/audit.test.ts`
Expected: FAIL

**Step 4: Implement audit commands**

Create `packages/hushclaw-openclaw/src/cli/commands/audit.ts`:

```typescript
import { writeFileSync } from 'fs';
import { AuditStore } from '../../audit/store.js';

interface QueryOptions {
  since?: string;
  guard?: string;
  denied?: boolean;
  auditPath?: string;
}

interface ExplainOptions {
  auditPath?: string;
}

interface ExportOptions {
  auditPath?: string;
}

export const auditCommands = {
  async query(options: QueryOptions = {}): Promise<void> {
    const store = new AuditStore(options.auditPath || '.hush/audit.jsonl');

    const queryOptions: { since?: number; guard?: string; denied?: boolean; limit?: number } = {
      limit: 50,
    };

    if (options.since) {
      const sinceDate = new Date(options.since);
      queryOptions.since = sinceDate.getTime();
    }
    if (options.guard) {
      queryOptions.guard = options.guard;
    }
    if (options.denied) {
      queryOptions.denied = true;
    }

    const events = store.query(queryOptions);

    if (events.length === 0) {
      console.log('No audit events found');
      return;
    }

    console.log('Audit Events:');
    console.log('=============');

    for (const event of events) {
      const date = new Date(event.timestamp).toISOString();
      const status = event.decision === 'allowed' ? 'ALLOWED' : 'DENIED';
      console.log(`\n[${date}] ${event.id}`);
      console.log(`  Action: ${event.type}`);
      console.log(`  Resource: ${event.resource}`);
      console.log(`  Decision: ${status}`);
      if (event.guard) console.log(`  Guard: ${event.guard}`);
      if (event.reason) console.log(`  Reason: ${event.reason}`);
    }
  },

  async explain(eventId: string, options: ExplainOptions = {}): Promise<void> {
    const store = new AuditStore(options.auditPath || '.hush/audit.jsonl');
    const event = store.getById(eventId);

    if (!event) {
      console.log(`Event ${eventId} not found`);
      return;
    }

    console.log('Event Details');
    console.log('=============');
    console.log(`\nEvent ID:    ${event.id}`);
    console.log(`Timestamp:   ${new Date(event.timestamp).toISOString()}`);
    console.log(`Action:      ${event.type}`);
    console.log(`Resource:    ${event.resource}`);
    console.log(`Decision:    ${event.decision === 'allowed' ? 'ALLOWED' : 'DENIED'}`);

    if (event.guard) {
      console.log(`\nGuard:       ${event.guard}`);
    }
    if (event.reason) {
      console.log(`Reason:      ${event.reason}`);
    }

    if (event.decision === 'denied') {
      console.log('\nRemediation:');
      console.log('------------');
      if (event.guard === 'ForbiddenPathGuard') {
        console.log('This path is protected by the ForbiddenPathGuard.');
        console.log('To allow access, remove it from filesystem.forbidden_paths in your policy.');
      } else if (event.guard === 'EgressAllowlistGuard') {
        console.log('This domain is not in the egress allowlist.');
        console.log('To allow access, add it to egress.allowed_domains in your policy.');
      } else {
        console.log('Review your policy configuration to understand why this was blocked.');
      }
    }
  },

  async export(file: string, options: ExportOptions = {}): Promise<void> {
    const store = new AuditStore(options.auditPath || '.hush/audit.jsonl');
    const events = store.query({});

    writeFileSync(file, JSON.stringify(events, null, 2));
    console.log(`Exported ${events.length} events to ${file}`);
  },
};
```

**Step 5: Run test to verify it passes**

Run: `cd packages/hushclaw-openclaw && npx vitest run src/cli/commands/audit.test.ts`
Expected: PASS

**Step 6: Commit**

```bash
git add packages/hushclaw-openclaw/src/audit/ packages/hushclaw-openclaw/src/cli/commands/audit.ts packages/hushclaw-openclaw/src/cli/commands/audit.test.ts
git commit -m "feat: add CLI audit commands (query, explain, export)"
```

---

## Task 10: CLI Main Entry Point

**Files:**
- Create: `packages/hushclaw-openclaw/src/cli/index.ts`
- Create: `packages/hushclaw-openclaw/src/cli/bin.ts`

**Step 1: Create CLI index**

Create `packages/hushclaw-openclaw/src/cli/index.ts`:

```typescript
import { Command } from 'commander';
import { policyCommands } from './commands/policy.js';
import { auditCommands } from './commands/audit.js';

export function registerCli(program: Command): void {
  const hushclaw = program
    .command('hushclaw')
    .description('Hushclaw security management');

  // Policy commands
  const policy = hushclaw.command('policy').description('Policy management');

  policy
    .command('lint <file>')
    .description('Validate a policy file')
    .action(policyCommands.lint);

  policy
    .command('show')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Show the current effective policy')
    .action((options) => policyCommands.show(options));

  policy
    .command('test <event-file>')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Test an event against the current policy')
    .action((eventFile, options) => policyCommands.test(eventFile, options));

  policy
    .command('diff <file1> <file2>')
    .description('Compare two policy files')
    .action(policyCommands.diff);

  // Audit commands
  const audit = hushclaw.command('audit').description('Audit log management');

  audit
    .command('query')
    .option('-s, --since <time>', 'Start time (ISO format)')
    .option('-g, --guard <name>', 'Filter by guard')
    .option('-d, --denied', 'Only show denied events')
    .description('Query the audit log')
    .action((options) => auditCommands.query(options));

  audit
    .command('export <file>')
    .description('Export audit log to file')
    .action((file, options) => auditCommands.export(file, options));

  // Quick commands
  hushclaw
    .command('why <event-id>')
    .description('Explain why an event was blocked')
    .action((eventId, options) => auditCommands.explain(eventId, options));
}

export function createCli(): Command {
  const program = new Command();
  program
    .name('hushclaw')
    .description('Hushclaw security CLI')
    .version('0.1.0');

  // Register commands directly on root
  const policy = program.command('policy').description('Policy management');

  policy
    .command('lint <file>')
    .description('Validate a policy file')
    .action(policyCommands.lint);

  policy
    .command('show')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Show the current effective policy')
    .action((options) => policyCommands.show(options));

  policy
    .command('test <event-file>')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Test an event against the current policy')
    .action((eventFile, options) => policyCommands.test(eventFile, options));

  policy
    .command('diff <file1> <file2>')
    .description('Compare two policy files')
    .action(policyCommands.diff);

  const audit = program.command('audit').description('Audit log management');

  audit
    .command('query')
    .option('-s, --since <time>', 'Start time')
    .option('-g, --guard <name>', 'Filter by guard')
    .option('-d, --denied', 'Only show denied events')
    .description('Query the audit log')
    .action((options) => auditCommands.query(options));

  audit
    .command('export <file>')
    .description('Export audit log to file')
    .action((file, options) => auditCommands.export(file, options));

  program
    .command('why <event-id>')
    .description('Explain why an event was blocked')
    .action((eventId, options) => auditCommands.explain(eventId, options));

  return program;
}
```

**Step 2: Create CLI bin entry**

Create `packages/hushclaw-openclaw/src/cli/bin.ts`:

```typescript
#!/usr/bin/env node
import { createCli } from './index.js';

const program = createCli();
program.parse();
```

**Step 3: Commit**

```bash
git add packages/hushclaw-openclaw/src/cli/index.ts packages/hushclaw-openclaw/src/cli/bin.ts
git commit -m "feat: add CLI main entry point with all commands"
```

---

## Task 11: Package Index and Exports

**Files:**
- Create: `packages/hushclaw-openclaw/src/index.ts`
- Create: `packages/hushclaw-openclaw/src/policy/index.ts`

**Step 1: Create policy index**

Create `packages/hushclaw-openclaw/src/policy/index.ts`:

```typescript
export * from './types.js';
export * from './validator.js';
export * from './engine.js';
export * from './loader.js';
```

**Step 2: Create main package index**

Create `packages/hushclaw-openclaw/src/index.ts`:

```typescript
// Policy
export { PolicyEngine } from './policy/engine.js';
export { validatePolicy } from './policy/validator.js';
export { loadPolicy, loadPolicyFromString } from './policy/loader.js';
export type {
  PolicyConfig,
  PolicyEvent,
  PolicyDecision,
  ValidationResult,
  ActionType,
  EgressConfig,
  FilesystemConfig,
} from './policy/types.js';

// Security Prompt
export { generateSecurityPrompt } from './security-prompt.js';

// Tools
export { policyCheckTool } from './tools/policy-check.js';

// Hooks
export { default as agentBootstrapHandler } from './hooks/agent-bootstrap/handler.js';

// Audit
export { AuditStore, type AuditEvent } from './audit/store.js';

// CLI
export { registerCli, createCli } from './cli/index.js';
```

**Step 3: Commit**

```bash
git add packages/hushclaw-openclaw/src/index.ts packages/hushclaw-openclaw/src/policy/index.ts
git commit -m "feat: add package exports"
```

---

## Task 12: Hello World Example

**Files:**
- Create: `packages/hushclaw-openclaw/examples/hello-secure-agent/README.md`
- Create: `packages/hushclaw-openclaw/examples/hello-secure-agent/policy.yaml`
- Create: `packages/hushclaw-openclaw/examples/hello-secure-agent/openclaw.json`
- Create: `packages/hushclaw-openclaw/examples/hello-secure-agent/skills/hello/SKILL.md`

**Step 1: Create example README**

Create `packages/hushclaw-openclaw/examples/hello-secure-agent/README.md`:

```markdown
# Hello Secure Agent

A simple example demonstrating hushclaw security enforcement in OpenClaw.

## Setup

```bash
cd examples/hello-secure-agent
npm install
openclaw plugins enable @hushclaw/openclaw
openclaw start
```

## Try It

1. **Blocked operation**: Ask the agent to read `~/.ssh/id_rsa`
2. **Allowed operation**: Ask the agent to create `/tmp/hello-agent/test.txt`
3. **Policy check**: Ask the agent to check if it can access `api.github.com`

## Expected Behavior

| Request | Result | Guard |
|---------|--------|-------|
| Read ~/.ssh/id_rsa | BLOCKED | ForbiddenPathGuard |
| Write /tmp/hello-agent/test.txt | ALLOWED | - |
| Fetch api.github.com | ALLOWED | - |
| Fetch evil.com | BLOCKED | EgressAllowlistGuard |

## Policy

See `policy.yaml` for the security configuration:

- **Egress**: Only `api.github.com` and `pypi.org` allowed
- **Filesystem**: `~/.ssh`, `~/.aws`, `.env` files forbidden
- **Violation**: Cancel (block the operation)

## Testing

```bash
npm test
```
```

**Step 2: Create example policy**

Create `packages/hushclaw-openclaw/examples/hello-secure-agent/policy.yaml`:

```yaml
version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
    - "pypi.org"
  denied_domains:
    - "localhost"
    - "127.*"

filesystem:
  allowed_write_roots:
    - "/tmp/hello-agent"
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"

on_violation: cancel
```

**Step 3: Create OpenClaw config**

Create `packages/hushclaw-openclaw/examples/hello-secure-agent/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./policy.yaml",
          "mode": "deterministic",
          "logLevel": "debug"
        }
      }
    }
  }
}
```

**Step 4: Create skill file**

Create directory and file:
```bash
mkdir -p packages/hushclaw-openclaw/examples/hello-secure-agent/skills/hello
```

Create `packages/hushclaw-openclaw/examples/hello-secure-agent/skills/hello/SKILL.md`:

```markdown
---
name: hello-secure
description: A simple skill demonstrating hushclaw security
---

# Hello Secure Skill

You are a friendly assistant protected by hushclaw security.

## What You Can Do
- Create files in /tmp/hello-agent/
- Fetch data from api.github.com
- Run basic commands

## What's Blocked
- Access to ~/.ssh, ~/.aws, .env files
- Connections to unknown domains
- Dangerous commands

## Security Demo

Try these to see security in action:

1. "Read my SSH key" -> Should be blocked
2. "Create /tmp/hello-agent/test.txt" -> Should work
3. "Check if I can access evil.com" -> Use policy_check tool

Always use the `policy_check` tool when unsure!

## Example Commands

```
# Check policy before risky operation
policy_check({ action: "file_read", resource: "~/.ssh/id_rsa" })

# Safe file creation
write_file({ path: "/tmp/hello-agent/hello.txt", content: "Hello World!" })

# Safe network request
fetch({ url: "https://api.github.com/zen" })
```
```

**Step 5: Commit**

```bash
git add packages/hushclaw-openclaw/examples/
git commit -m "feat: add hello-secure-agent example"
```

---

## Task 13: E2E Tests

**Files:**
- Create: `packages/hushclaw-openclaw/tests/e2e/hello-agent.test.ts`

**Step 1: Write E2E test**

Create `packages/hushclaw-openclaw/tests/e2e/hello-agent.test.ts`:

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PolicyEngine } from '../../src/policy/engine.js';
import { loadPolicy } from '../../src/policy/loader.js';
import { policyCheckTool } from '../../src/tools/policy-check.js';
import { generateSecurityPrompt } from '../../src/security-prompt.js';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { join } from 'path';

describe('Hello Secure Agent E2E', () => {
  const exampleDir = join(__dirname, '../../examples/hello-secure-agent');
  let engine: PolicyEngine;
  let tool: ReturnType<typeof policyCheckTool>;

  beforeAll(async () => {
    const policy = await loadPolicy(join(exampleDir, 'policy.yaml'));
    engine = new PolicyEngine(policy);
    tool = policyCheckTool(engine);

    // Create test directory
    if (!existsSync('/tmp/hello-agent')) {
      mkdirSync('/tmp/hello-agent', { recursive: true });
    }
  });

  afterAll(() => {
    rmSync('/tmp/hello-agent', { recursive: true, force: true });
  });

  describe('Filesystem Guards', () => {
    it('blocks forbidden path access (~/.ssh)', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '~/.ssh/id_rsa',
      });
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('ForbiddenPathGuard');
    });

    it('blocks forbidden path access (~/.aws)', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '~/.aws/credentials',
      });
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('ForbiddenPathGuard');
    });

    it('blocks .env file access', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '/workspace/.env',
      });
      expect(result.denied).toBe(true);
    });

    it('allows writes to /tmp/hello-agent', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '/tmp/hello-agent/test.txt',
      });
      expect(result.allowed).toBe(true);
    });

    it('blocks writes outside allowed roots', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '/etc/passwd',
      });
      expect(result.denied).toBe(true);
    });
  });

  describe('Egress Guards', () => {
    it('blocks non-allowlisted domains', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://evil.com/exfiltrate',
      });
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('EgressAllowlistGuard');
    });

    it('allows api.github.com', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://api.github.com/user',
      });
      expect(result.allowed).toBe(true);
    });

    it('allows pypi.org', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://pypi.org/simple/',
      });
      expect(result.allowed).toBe(true);
    });

    it('blocks localhost', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'http://localhost:8080',
      });
      expect(result.denied).toBe(true);
    });
  });

  describe('Security Prompt', () => {
    it('generates security context for agent', async () => {
      const policy = await loadPolicy(join(exampleDir, 'policy.yaml'));
      const prompt = generateSecurityPrompt(policy);

      expect(prompt).toContain('api.github.com');
      expect(prompt).toContain('~/.ssh');
      expect(prompt).toContain('policy_check');
      expect(prompt).toContain('BLOCKED');
    });
  });

  describe('Policy Check Tool', () => {
    it('provides helpful suggestions when denied', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '~/.ssh/authorized_keys',
      });
      expect(result.suggestion).toBeDefined();
      expect(result.suggestion).toContain('SSH');
    });

    it('returns reason for denial', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://malware.com',
      });
      expect(result.reason).toContain('not in egress allowlist');
    });
  });
});
```

**Step 2: Run E2E tests**

Run: `cd packages/hushclaw-openclaw && npx vitest run tests/e2e/`
Expected: PASS

**Step 3: Commit**

```bash
git add packages/hushclaw-openclaw/tests/
git commit -m "test: add E2E tests for hello-secure-agent"
```

---

## Task 14: Getting Started Documentation

**Files:**
- Create: `packages/hushclaw-openclaw/docs/getting-started.md`

**Step 1: Write getting started guide**

Create `packages/hushclaw-openclaw/docs/getting-started.md`:

```markdown
# Getting Started with Hushclaw for OpenClaw

Hushclaw provides security enforcement for AI agents running in OpenClaw.

## Installation

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

## Quick Start

### 1. Create a Policy File

Create `.hush/policy.yaml` in your project:

```yaml
version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
    - "pypi.org"
    - "registry.npmjs.org"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - ".env"

on_violation: cancel
```

### 2. Configure OpenClaw

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./.hush/policy.yaml"
        }
      }
    }
  }
}
```

### 3. Start OpenClaw

```bash
openclaw start
```

Your agent is now protected!

## Verify It Works

Ask your agent: "Try to read ~/.ssh/id_rsa"

Expected response: Operation blocked by ForbiddenPathGuard.

## Using the CLI

### Validate Your Policy

```bash
hushclaw policy lint .hush/policy.yaml
```

### Test an Event

Create `test-event.json`:
```json
{
  "type": "file_read",
  "resource": "~/.ssh/id_rsa"
}
```

```bash
hushclaw policy test test-event.json --policy .hush/policy.yaml
```

### Query Audit Log

```bash
hushclaw audit query --denied
```

### Explain a Block

```bash
hushclaw why <event-id>
```

## Agent Tools

### policy_check

Agents can use the `policy_check` tool to check permissions before attempting operations:

```
policy_check({ action: "file_write", resource: "/etc/passwd" })
→ { allowed: false, reason: "Path is forbidden" }
```

The tool provides:
- `allowed`: Whether the action is permitted
- `denied`: Whether the action is blocked
- `reason`: Human-readable explanation
- `guard`: Which guard made the decision
- `suggestion`: Helpful alternative approaches

## Policy Reference

### Egress Control

```yaml
egress:
  mode: allowlist  # allowlist | denylist | open
  allowed_domains:
    - "api.github.com"
    - "*.amazonaws.com"  # Wildcards supported
  denied_domains:
    - "*.onion"
    - "localhost"
```

### Filesystem Protection

```yaml
filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"
  allowed_write_roots:
    - "/tmp"
    - "/workspace"
```

### Violation Handling

```yaml
on_violation: cancel  # cancel | warn | log
```

- `cancel`: Block the operation (recommended)
- `warn`: Log a warning but allow
- `log`: Silently log

## Built-in Rulesets

Use predefined rulesets by extending them:

```yaml
extends: hushclaw:ai-agent-minimal
```

Available rulesets:
- `hushclaw:ai-agent-minimal` - Basic protection
- `hushclaw:ai-agent` - Standard development
- `hushclaw:strict` - Production environments

## Next Steps

- See the [Policy Reference](./policy-reference.md) for all options
- Check the [Examples](../examples/) directory
- Read about [Advanced Configuration](./advanced.md)
```

**Step 2: Commit**

```bash
git add packages/hushclaw-openclaw/docs/
git commit -m "docs: add getting started guide"
```

---

## Task 15: Default Rulesets

**Files:**
- Create: `packages/hushclaw-openclaw/rulesets/ai-agent-minimal.yaml`
- Create: `packages/hushclaw-openclaw/rulesets/ai-agent.yaml`

**Step 1: Create minimal ruleset**

Create `packages/hushclaw-openclaw/rulesets/ai-agent-minimal.yaml`:

```yaml
# Hushclaw AI Agent Minimal Policy
# Basic protection for AI-assisted development

version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    # AI Provider APIs
    - "api.anthropic.com"
    - "api.openai.com"
    # Package Registries
    - "pypi.org"
    - "registry.npmjs.org"
    - "crates.io"
    # Source Control
    - "github.com"
    - "api.github.com"
  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - ".env"
    - "*.pem"
    - "*.key"

on_violation: cancel
```

**Step 2: Create standard ruleset**

Create `packages/hushclaw-openclaw/rulesets/ai-agent.yaml`:

```yaml
# Hushclaw AI Agent Standard Policy
# Recommended for general AI-assisted development

version: "hushclaw-v1.0"
extends: ai-agent-minimal

egress:
  mode: allowlist
  allowed_domains:
    # AI Provider APIs
    - "api.anthropic.com"
    - "api.openai.com"
    - "generativelanguage.googleapis.com"
    # Package Registries
    - "pypi.org"
    - "files.pythonhosted.org"
    - "registry.npmjs.org"
    - "crates.io"
    - "static.crates.io"
    - "rubygems.org"
    - "pkg.go.dev"
    - "proxy.golang.org"
    # Source Control
    - "github.com"
    - "api.github.com"
    - "*.githubusercontent.com"
    - "gitlab.com"
    # Documentation
    - "docs.python.org"
    - "developer.mozilla.org"
    - "docs.rs"
  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"
    - "10.*"
    - "192.168.*"
    - "172.16.*"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - "~/.config/gcloud"
    - "~/.kube"
    - "~/.docker/config.json"
    - "~/.npmrc"
    - "~/.pypirc"
    - "~/.netrc"
    - "/etc/shadow"
    - "/etc/passwd"
    - ".env"
    - ".env.*"
    - "*.pem"
    - "*.key"
    - "**/secrets/*"

execution:
  denied_patterns:
    - "rm -rf /"
    - "rm -rf /*"
    - ":(){ :|:& };:"
    - "curl.*|.*bash"
    - "wget.*|.*sh"
    - "dd if="
    - "sudo su"
    - "chmod 777"

on_violation: cancel
```

**Step 3: Commit**

```bash
git add packages/hushclaw-openclaw/rulesets/
git commit -m "feat: add default rulesets (ai-agent-minimal, ai-agent)"
```

---

## Task 16: Final Build and Test

**Step 1: Build the package**

```bash
cd packages/hushclaw-openclaw && npm run build
```

**Step 2: Run all tests**

```bash
cd packages/hushclaw-openclaw && npm test
```

Expected: All tests pass

**Step 3: Test CLI**

```bash
cd packages/hushclaw-openclaw && node dist/cli/bin.js --help
cd packages/hushclaw-openclaw && node dist/cli/bin.js policy lint rulesets/ai-agent-minimal.yaml
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: build and verify complete package"
```

---

## Summary

This plan implements:

1. **Policy Types & Validator** - Type definitions and validation for security policies
2. **Policy Engine** - Core enforcement logic with filesystem and egress guards
3. **Security Prompt Generator** - Creates SECURITY.md content for agents
4. **Agent Bootstrap Hook** - Injects security context via `agent:bootstrap` event
5. **Policy Check Tool** - Agent-callable tool for policy introspection
6. **CLI Commands** - `lint`, `show`, `test`, `diff`, `query`, `why`, `export`
7. **Hello World Example** - Complete working example with tests
8. **E2E Tests** - Integration tests validating all components work together
9. **Documentation** - Getting started guide and policy reference
10. **Default Rulesets** - Pre-built security policies for common use cases

Total: ~16 tasks, ~800 lines of TypeScript, comprehensive test coverage
