# Guard SDK: Building Custom Guards

## Document Information

| Field | Value |
|-------|-------|
| **Status** | Draft |
| **Version** | 0.1.0 |
| **Authors** | Clawdstrike Architecture Team |
| **Last Updated** | 2026-02-02 |
| **Prerequisites** | overview.md, plugin-system.md |

---

## 1. Overview

The Clawdstrike Guard SDK provides everything developers need to build, test, and publish custom security guards for the Clawdstrike ecosystem.

### 1.1 SDK Components

| Component | TypeScript | Rust | Description |
|-----------|------------|------|-------------|
| Core types | `@clawdstrike/guard-sdk` | `clawdstrike-guard-sdk` | Guard interfaces, event types |
| Testing utilities | `@clawdstrike/guard-sdk/testing` | `clawdstrike-guard-sdk-test` | Test harnesses, mocks |
| CLI tools | `@clawdstrike/cli` | `cargo-clawdstrike` | Project scaffolding, validation |
| Build tools | `@clawdstrike/build` | (built-in) | WASM compilation, bundling |

### 1.2 Features

- Type-safe guard development
- Built-in testing framework
- Hot reload during development
- WASM compilation for sandboxed execution
- Plugin manifest generation
- Marketplace publishing integration

---

## 2. Getting Started

### 2.1 Prerequisites

Before building custom guards, ensure you have:

**TypeScript Development:**
- Node.js 18.x or later (20.x recommended)
- npm 9.x or later
- TypeScript 5.0 or later

**Rust Development:**
- Rust 1.70 or later (stable)
- Cargo (included with Rust)
- wasm32-wasi target: `rustup target add wasm32-wasi`

**Optional but Recommended:**
- Visual Studio Code with Clawdstrike extension
- Docker (for sandboxed testing)

### 2.2 TypeScript Quick Start

```bash
# Install CLI globally
npm install -g @clawdstrike/cli

# Verify installation
hush --version

# Create new guard project
hush guard init my-custom-guard
cd my-custom-guard

# Project structure created:
# my-custom-guard/
# ├── package.json
# ├── clawdstrike.plugin.json
# ├── tsconfig.json
# ├── src/
# │   ├── index.ts          # Plugin entry point
# │   ├── guard.ts          # Guard implementation
# │   └── config.ts         # Configuration schema
# └── tests/
#     └── guard.test.ts     # Guard tests

# Install dependencies
npm install

# Run tests
npm test

# Build plugin
npm run build

# Validate plugin
hush guard validate

# Start development server (hot reload)
hush guard dev
```

### 2.3 Rust Quick Start

```bash
# Install Cargo subcommand
cargo install cargo-clawdstrike

# Create new guard project
cargo clawdstrike guard init my-custom-guard
cd my-custom-guard

# Project structure created:
# my-custom-guard/
# ├── Cargo.toml
# ├── clawdstrike.plugin.toml
# ├── src/
# │   ├── lib.rs            # Plugin entry point
# │   ├── guard.rs          # Guard implementation
# │   └── config.rs         # Configuration types
# └── tests/
#     └── guard_test.rs     # Guard tests

# Run tests
cargo test

# Build plugin
cargo build --release

# Build WASM target
cargo build --target wasm32-wasi --release

# Validate plugin
cargo clawdstrike guard validate
```

---

## 3. Guard Implementation

This section covers the core patterns for implementing guards in TypeScript and Rust. Both languages follow the same Guard interface contract.

### 3.1 TypeScript Guard Template

```typescript
// src/guard.ts

import {
  BaseGuard,
  Guard,
  GuardResult,
  PolicyEvent,
  Policy,
  EventType,
  Severity,
} from '@clawdstrike/guard-sdk';

import { MyGuardConfig, validateConfig } from './config';

/**
 * MyCustomGuard - [Brief description of what this guard does]
 *
 * @example
 * ```yaml
 * guards:
 *   custom:
 *     - package: "@myorg/clawdstrike-my-guard"
 *       config:
 *         option1: value1
 *         option2: value2
 * ```
 */
export class MyCustomGuard extends BaseGuard {
  private config: MyGuardConfig;

  constructor(config: Partial<MyGuardConfig> = {}) {
    super();
    this.config = validateConfig(config);
  }

  /**
   * Guard identifier - must be unique and URL-safe
   */
  name(): string {
    return 'my_custom_guard';
  }

  /**
   * Human-readable display name
   */
  displayName(): string {
    return 'My Custom Guard';
  }

  /**
   * Event types this guard handles
   * Return empty array to handle all event types
   */
  handles(): EventType[] {
    return ['file_write', 'patch_apply'];
  }

  /**
   * Optional synchronous check - preferred for performance
   * Return undefined to fall through to async check()
   */
  checkSync(event: PolicyEvent, policy: Policy): GuardResult | undefined {
    // Quick checks that don't need async
    if (this.shouldSkip(event)) {
      return this.allow();
    }

    // Return undefined to use async check()
    return undefined;
  }

  /**
   * Main check implementation
   */
  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    // Implement your security logic here
    const violation = this.detectViolation(event);

    if (violation) {
      return this.deny(violation.reason, violation.severity);
    }

    return this.allow();
  }

  /**
   * Determine if event should be skipped
   */
  private shouldSkip(event: PolicyEvent): boolean {
    // Skip if guard is disabled in config
    if (!this.config.enabled) {
      return true;
    }

    // Add other skip conditions
    return false;
  }

  /**
   * Core detection logic
   */
  private detectViolation(
    event: PolicyEvent
  ): { reason: string; severity: Severity } | null {
    // Implement your detection logic
    // Return null if no violation, or violation details

    if (event.data.type === 'file') {
      const path = event.data.path;

      // Example: Check for forbidden patterns
      for (const pattern of this.config.forbiddenPatterns) {
        if (this.matchesPattern(path, pattern)) {
          return {
            reason: `Path matches forbidden pattern: ${pattern}`,
            severity: 'high',
          };
        }
      }
    }

    return null;
  }

  private matchesPattern(path: string, pattern: string): boolean {
    // Pattern matching implementation
    const regex = new RegExp(pattern);
    return regex.test(path);
  }
}
```

### 3.2 TypeScript Configuration

```typescript
// src/config.ts

import { z } from 'zod';

/**
 * Configuration schema using Zod for validation
 */
export const MyGuardConfigSchema = z.object({
  /**
   * Whether the guard is enabled
   */
  enabled: z.boolean().default(true),

  /**
   * Patterns to forbid (regex strings)
   */
  forbiddenPatterns: z.array(z.string()).default([]),

  /**
   * Severity for violations
   */
  severity: z.enum(['low', 'medium', 'high', 'critical']).default('high'),

  /**
   * Paths to exclude from checking
   */
  excludePaths: z.array(z.string()).default([]),
});

export type MyGuardConfig = z.infer<typeof MyGuardConfigSchema>;

/**
 * Validate and apply defaults to configuration
 */
export function validateConfig(config: unknown): MyGuardConfig {
  return MyGuardConfigSchema.parse(config);
}

/**
 * Export JSON Schema for plugin manifest
 */
export function getConfigSchema(): Record<string, unknown> {
  // Convert Zod schema to JSON Schema
  // Or manually define JSON Schema:
  return {
    type: 'object',
    properties: {
      enabled: {
        type: 'boolean',
        default: true,
        description: 'Whether the guard is enabled',
      },
      forbiddenPatterns: {
        type: 'array',
        items: { type: 'string' },
        default: [],
        description: 'Regex patterns to forbid',
      },
      severity: {
        type: 'string',
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'high',
        description: 'Severity for violations',
      },
      excludePaths: {
        type: 'array',
        items: { type: 'string' },
        default: [],
        description: 'Glob patterns for paths to exclude',
      },
    },
  };
}
```

### 3.3 TypeScript Plugin Entry Point

```typescript
// src/index.ts

import { PluginDefinition } from '@clawdstrike/guard-sdk';
import { MyCustomGuard } from './guard';
import { getConfigSchema, MyGuardConfig } from './config';

/**
 * Plugin definition - default export
 */
const plugin: PluginDefinition = {
  name: '@myorg/clawdstrike-my-guard',
  version: '1.0.0',

  guards: [
    {
      name: 'my_custom_guard',
      displayName: 'My Custom Guard',
      factory: (config: MyGuardConfig) => new MyCustomGuard(config),
      configSchema: getConfigSchema(),
    },
  ],

  /**
   * Called when plugin is loaded
   */
  async onLoad(context) {
    context.logger.info('My Custom Guard plugin loaded');
  },

  /**
   * Called when plugin is unloaded
   */
  async onUnload(context) {
    context.logger.info('My Custom Guard plugin unloading');
    // Clean up resources
  },
};

export default plugin;

// Also export guard for direct usage
export { MyCustomGuard } from './guard';
export type { MyGuardConfig } from './config';
```

### 3.4 Rust Guard Template

```rust
// src/guard.rs

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};

use clawdstrike_guard_sdk::{
    Guard, GuardContext, GuardResult, GuardStatus, PolicyEvent, Policy,
    EventType, Severity,
};

use crate::config::MyGuardConfig;

/// MyCustomGuard - [Brief description]
pub struct MyCustomGuard {
    config: MyGuardConfig,
    patterns: Vec<Regex>,
}

impl MyCustomGuard {
    /// Create a new guard with configuration
    pub fn new(config: MyGuardConfig) -> Self {
        let patterns = config
            .forbidden_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        Self { config, patterns }
    }

    /// Check if path matches any forbidden pattern
    fn matches_forbidden(&self, path: &str) -> Option<&str> {
        for (pattern, regex) in self.config.forbidden_patterns.iter().zip(&self.patterns) {
            if regex.is_match(path) {
                return Some(pattern);
            }
        }
        None
    }

    /// Check if path should be excluded
    fn is_excluded(&self, path: &str) -> bool {
        self.config.exclude_paths.iter().any(|pattern| {
            glob::Pattern::new(pattern)
                .map(|p| p.matches(path))
                .unwrap_or(false)
        })
    }
}

#[async_trait]
impl Guard for MyCustomGuard {
    fn name(&self) -> &str {
        "my_custom_guard"
    }

    fn display_name(&self) -> Option<&str> {
        Some("My Custom Guard")
    }

    fn handles(&self) -> &[EventType] {
        &[EventType::FileWrite, EventType::PatchApply]
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn check_sync(&self, event: &PolicyEvent, _policy: &Policy) -> Option<GuardResult> {
        if !self.config.enabled {
            return Some(GuardResult::allow(self.name()));
        }

        // Quick synchronous checks
        match &event.data {
            EventData::File { path, .. } => {
                if self.is_excluded(path) {
                    return Some(GuardResult::allow(self.name()));
                }

                if let Some(pattern) = self.matches_forbidden(path) {
                    return Some(GuardResult::deny(
                        self.name(),
                        self.config.severity,
                        format!("Path matches forbidden pattern: {}", pattern),
                    ));
                }
            }
            _ => {}
        }

        // Fall through to async check if needed
        None
    }

    async fn check(&self, event: &PolicyEvent, policy: &Policy) -> GuardResult {
        // If sync check handled it, this won't be called
        // Add any async logic here (e.g., external service calls)

        GuardResult::allow(self.name())
    }

    async fn initialize(&mut self, context: &GuardContext) -> Result<(), GuardError> {
        context.logger.info("My Custom Guard initialized");
        Ok(())
    }

    async fn cleanup(&mut self) -> Result<(), GuardError> {
        // Clean up resources
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forbidden_pattern_match() {
        let config = MyGuardConfig {
            enabled: true,
            forbidden_patterns: vec![r".*\.secret$".to_string()],
            ..Default::default()
        };

        let guard = MyCustomGuard::new(config);

        assert!(guard.matches_forbidden("/path/to/file.secret").is_some());
        assert!(guard.matches_forbidden("/path/to/file.txt").is_none());
    }

    #[test]
    fn test_exclude_paths() {
        let config = MyGuardConfig {
            enabled: true,
            exclude_paths: vec!["**/test/**".to_string()],
            ..Default::default()
        };

        let guard = MyCustomGuard::new(config);

        assert!(guard.is_excluded("/app/test/file.txt"));
        assert!(!guard.is_excluded("/app/src/file.txt"));
    }
}
```

### 3.5 Rust Configuration

```rust
// src/config.rs

use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use clawdstrike_guard_sdk::Severity;

/// Configuration for MyCustomGuard
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MyGuardConfig {
    /// Whether the guard is enabled
    pub enabled: bool,

    /// Regex patterns for forbidden paths
    pub forbidden_patterns: Vec<String>,

    /// Severity for violations
    pub severity: Severity,

    /// Glob patterns for paths to exclude
    pub exclude_paths: Vec<String>,
}

impl Default for MyGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            forbidden_patterns: vec![],
            severity: Severity::High,
            exclude_paths: vec![],
        }
    }
}

impl MyGuardConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate regex patterns compile
        for pattern in &self.forbidden_patterns {
            if regex::Regex::new(pattern).is_err() {
                return Err(ConfigError::InvalidRegex(pattern.clone()));
            }
        }

        // Validate glob patterns
        for pattern in &self.exclude_paths {
            if glob::Pattern::new(pattern).is_err() {
                return Err(ConfigError::InvalidGlob(pattern.clone()));
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),

    #[error("Invalid glob pattern: {0}")]
    InvalidGlob(String),
}
```

### 3.6 Rust Plugin Entry Point

```rust
// src/lib.rs

use clawdstrike_guard_sdk::{
    export_plugin, Guard, GuardFactory, PluginDefinition, GuardError,
};

mod config;
mod guard;

pub use config::MyGuardConfig;
pub use guard::MyCustomGuard;

/// Plugin definition
struct MyGuardPlugin;

impl PluginDefinition for MyGuardPlugin {
    fn name(&self) -> &str {
        "clawdstrike-my-guard"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn guards(&self) -> Vec<Box<dyn GuardFactory>> {
        vec![Box::new(MyGuardFactory)]
    }

    fn on_load(&self, context: &PluginContext) {
        context.logger.info("My Custom Guard plugin loaded");
    }

    fn on_unload(&self, context: &PluginContext) {
        context.logger.info("My Custom Guard plugin unloading");
    }
}

struct MyGuardFactory;

impl GuardFactory for MyGuardFactory {
    fn name(&self) -> &str {
        "my_custom_guard"
    }

    fn display_name(&self) -> &str {
        "My Custom Guard"
    }

    fn create(&self, config: serde_json::Value) -> Result<Box<dyn Guard>, GuardError> {
        let config: MyGuardConfig = serde_json::from_value(config)
            .map_err(|e| GuardError::ConfigError(e.to_string()))?;

        config.validate()
            .map_err(|e| GuardError::ConfigError(e.to_string()))?;

        Ok(Box::new(MyCustomGuard::new(config)))
    }

    fn config_schema(&self) -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(MyGuardConfig))
            .unwrap_or_default()
    }
}

// Export plugin for dynamic loading
export_plugin!(MyGuardPlugin);
```

---

## 4. Testing Guards

### 4.1 TypeScript Testing

```typescript
// tests/guard.test.ts

import { describe, it, expect, beforeEach } from 'vitest';
import {
  GuardTestHarness,
  createTestEvent,
  fileWriteEvent,
  patchApplyEvent,
} from '@clawdstrike/guard-sdk/testing';

import { MyCustomGuard } from '../src/guard';

describe('MyCustomGuard', () => {
  let harness: GuardTestHarness;

  beforeEach(async () => {
    harness = new GuardTestHarness(
      new MyCustomGuard({
        enabled: true,
        forbiddenPatterns: ['\\.secret$', 'password'],
        severity: 'high',
        excludePaths: ['**/test/**', '**/fixtures/**'],
      })
    );
    await harness.initialize();
  });

  describe('basic functionality', () => {
    it('should allow normal files', async () => {
      const event = fileWriteEvent('/app/src/main.ts');
      await harness.expectAllow(event);
    });

    it('should deny files matching forbidden patterns', async () => {
      const event = fileWriteEvent('/app/config.secret');
      await harness.expectDeny(event, {}, {
        severity: 'high',
        reasonContains: 'forbidden pattern',
      });
    });

    it('should deny files with password in name', async () => {
      const event = fileWriteEvent('/app/password.txt');
      await harness.expectDeny(event);
    });
  });

  describe('exclusions', () => {
    it('should allow excluded paths', async () => {
      const event = fileWriteEvent('/app/test/config.secret');
      await harness.expectAllow(event);
    });

    it('should allow fixtures', async () => {
      const event = fileWriteEvent('/app/fixtures/password.txt');
      await harness.expectAllow(event);
    });
  });

  describe('configuration', () => {
    it('should skip when disabled', async () => {
      const disabledHarness = new GuardTestHarness(
        new MyCustomGuard({ enabled: false })
      );
      await disabledHarness.initialize();

      const event = fileWriteEvent('/app/config.secret');
      await disabledHarness.expectAllow(event);
    });

    it('should use configured severity', async () => {
      const criticalHarness = new GuardTestHarness(
        new MyCustomGuard({
          forbiddenPatterns: ['\\.secret$'],
          severity: 'critical',
        })
      );
      await criticalHarness.initialize();

      const event = fileWriteEvent('/app/config.secret');
      await criticalHarness.expectDeny(event, {}, { severity: 'critical' });
    });
  });

  describe('event types', () => {
    it('should handle patch events', async () => {
      const event = patchApplyEvent('/app/config.secret', '+ secret data');
      await harness.expectDeny(event);
    });

    it('should ignore unhandled event types', async () => {
      const event = createTestEvent('network_egress', {
        type: 'network',
        host: 'evil.com',
        port: 443,
      });
      await harness.expectAllow(event);
    });
  });
});
```

### 4.2 Rust Testing

```rust
// tests/guard_test.rs

use clawdstrike_guard_sdk::testing::{
    GuardTestHarness, file_write_event, patch_apply_event,
};
use clawdstrike_my_guard::{MyCustomGuard, MyGuardConfig};

#[tokio::test]
async fn test_allow_normal_files() {
    let guard = MyCustomGuard::new(MyGuardConfig {
        enabled: true,
        forbidden_patterns: vec![r"\.secret$".to_string()],
        ..Default::default()
    });

    let harness = GuardTestHarness::new(guard);
    let event = file_write_event("/app/src/main.rs");

    harness.expect_allow(&event).await;
}

#[tokio::test]
async fn test_deny_forbidden_patterns() {
    let guard = MyCustomGuard::new(MyGuardConfig {
        enabled: true,
        forbidden_patterns: vec![r"\.secret$".to_string()],
        severity: Severity::High,
        ..Default::default()
    });

    let harness = GuardTestHarness::new(guard);
    let event = file_write_event("/app/config.secret");

    harness.expect_deny(&event, |result| {
        assert_eq!(result.severity, Some(Severity::High));
        assert!(result.reason.unwrap().contains("forbidden pattern"));
    }).await;
}

#[tokio::test]
async fn test_exclude_paths() {
    let guard = MyCustomGuard::new(MyGuardConfig {
        enabled: true,
        forbidden_patterns: vec![r"\.secret$".to_string()],
        exclude_paths: vec!["**/test/**".to_string()],
        ..Default::default()
    });

    let harness = GuardTestHarness::new(guard);

    // Should be excluded
    let event = file_write_event("/app/test/config.secret");
    harness.expect_allow(&event).await;

    // Should not be excluded
    let event = file_write_event("/app/src/config.secret");
    harness.expect_deny(&event, |_| {}).await;
}

#[tokio::test]
async fn test_disabled_guard() {
    let guard = MyCustomGuard::new(MyGuardConfig {
        enabled: false,
        forbidden_patterns: vec![r"\.secret$".to_string()],
        ..Default::default()
    });

    let harness = GuardTestHarness::new(guard);
    let event = file_write_event("/app/config.secret");

    harness.expect_allow(&event).await;
}
```

### 4.3 Integration Testing

```typescript
// tests/integration.test.ts

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PolicyEngine } from '@clawdstrike/openclaw';
import { MyCustomGuard } from '../src/guard';

describe('Integration with PolicyEngine', () => {
  let engine: PolicyEngine;

  beforeAll(async () => {
    engine = new PolicyEngine({
      policy: 'ai-agent',
      customGuards: [
        {
          guard: new MyCustomGuard({
            forbiddenPatterns: ['\\.secret$'],
          }),
        },
      ],
    });
    await engine.initialize();
  });

  afterAll(async () => {
    await engine.shutdown();
  });

  it('should integrate with policy engine', async () => {
    const decision = await engine.evaluate({
      eventId: 'test-1',
      eventType: 'file_write',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/app/config.secret',
        operation: 'write',
      },
    });

    expect(decision.denied).toBe(true);
    expect(decision.guard).toBe('my_custom_guard');
  });

  it('should work with built-in guards', async () => {
    const decision = await engine.evaluate({
      eventId: 'test-2',
      eventType: 'file_write',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/home/user/.ssh/id_rsa',
        operation: 'write',
      },
    });

    // Should be blocked by built-in forbidden_path guard
    expect(decision.denied).toBe(true);
    expect(decision.guard).toBe('forbidden_path');
  });
});
```

---

## 5. CLI Tools

### 5.1 Project Scaffolding

```bash
# Create TypeScript guard project
hush guard init my-guard --language typescript

# Create Rust guard project
hush guard init my-guard --language rust

# Create from template
hush guard init my-guard --template async-guard
hush guard init my-guard --template compliance-guard

# Available templates:
# - basic (default)       Simple synchronous guard
# - async-guard           Guard with external API integration
# - compliance-guard      Guard with audit logging
# - multi-guard           Plugin with multiple guards
```

### 5.2 Validation

```bash
# Validate plugin manifest
hush guard validate

# Output:
# Validating clawdstrike.plugin.json...
# ✓ Manifest schema valid
# ✓ Guards found: my_custom_guard
# ✓ Config schema valid
# ✓ Capabilities declared
# ✓ Resource limits within bounds
#
# Validation passed.

# Validate with strict mode (for publishing)
hush guard validate --strict

# Additional checks in strict mode:
# - README.md exists
# - CHANGELOG.md exists
# - LICENSE file exists
# - Tests exist and pass
# - No unused dependencies
```

### 5.3 Development Server

```bash
# Start development server with hot reload
hush guard dev

# Output:
# Starting development server...
# Loading guard: my_custom_guard
# Watching for changes...
#
# Development server ready at http://localhost:3847
#
# Test your guard:
#   curl -X POST http://localhost:3847/check \
#     -H "Content-Type: application/json" \
#     -d '{"eventType":"file_write","data":{"type":"file","path":"/app/test.txt"}}'

# With custom port
hush guard dev --port 4000

# With specific config
hush guard dev --config ./test-config.json
```

### 5.4 WASM Build

```bash
# Build WASM target (TypeScript)
hush guard build-wasm

# Output:
# Compiling to WASM...
# - Bundling TypeScript...
# - Compiling with wasm-pack...
# - Optimizing with wasm-opt...
#
# WASM build complete: dist/guard.wasm (145 KB)

# Build with size optimization
hush guard build-wasm --optimize-size

# Build with debug symbols
hush guard build-wasm --debug
```

### 5.5 Testing Commands

```bash
# Run all tests
hush guard test

# Run with coverage
hush guard test --coverage

# Run specific test file
hush guard test tests/guard.test.ts

# Run in watch mode
hush guard test --watch

# Run security scan
hush guard security-scan
```

---

## 6. Plugin Manifest Reference

### 6.1 Full TypeScript Manifest

```json
{
  "$schema": "https://clawdstrike.dev/schemas/plugin-manifest.json",

  "version": "1.0.0",
  "name": "@myorg/clawdstrike-my-guard",
  "displayName": "My Custom Guard",
  "description": "Detects custom security patterns",

  "author": {
    "name": "My Organization",
    "email": "security@myorg.com",
    "url": "https://myorg.com"
  },

  "repository": "https://github.com/myorg/clawdstrike-my-guard",
  "homepage": "https://github.com/myorg/clawdstrike-my-guard#readme",
  "bugs": "https://github.com/myorg/clawdstrike-my-guard/issues",
  "license": "MIT",

  "keywords": ["clawdstrike", "guard", "security", "custom-patterns"],

  "clawdstrike": {
    "minVersion": "0.5.0",
    "maxVersion": "2.x"
  },

  "guards": [
    {
      "name": "my_custom_guard",
      "displayName": "My Custom Guard",
      "description": "Detects custom security patterns in files",
      "entrypoint": "./dist/guard.js",
      "handles": ["file_write", "patch_apply"],
      "configSchema": "./dist/config-schema.json",
      "async": false
    }
  ],

  "capabilities": {
    "network": false,
    "filesystem": {
      "read": false,
      "write": false
    },
    "secrets": false,
    "subprocess": false
  },

  "resources": {
    "maxMemoryMb": 64,
    "maxCpuMs": 100,
    "maxTimeoutMs": 5000
  },

  "trust": {
    "level": "community",
    "sandbox": "wasm"
  }
}
```

### 6.2 Full Rust Manifest

```toml
[plugin]
version = "1.0.0"
name = "clawdstrike-my-guard"
display_name = "My Custom Guard"
description = "Detects custom security patterns"
license = "MIT"

[author]
name = "My Organization"
email = "security@myorg.com"
url = "https://myorg.com"

[repository]
url = "https://github.com/myorg/clawdstrike-my-guard"
homepage = "https://github.com/myorg/clawdstrike-my-guard#readme"

[clawdstrike]
min_version = "0.5.0"
max_version = "2.x"

[[guards]]
name = "my_custom_guard"
display_name = "My Custom Guard"
description = "Detects custom security patterns in files"
handles = ["file_write", "patch_apply"]
async = false

[capabilities]
network = false
subprocess = false

[capabilities.filesystem]
read = false
write = false

[capabilities.secrets]
access = false

[resources]
max_memory_mb = 64
max_cpu_ms = 100
max_timeout_ms = 5000

[trust]
level = "community"
sandbox = "wasm"
```

---

## 7. Publishing Workflow

### 7.1 Pre-publish Checklist

```bash
# 1. Update version
npm version patch  # or minor, major

# 2. Update CHANGELOG.md
# Add entry for new version

# 3. Run full validation
hush guard validate --strict

# 4. Run tests with coverage
hush guard test --coverage

# 5. Run security scan
hush guard security-scan

# 6. Build WASM
hush guard build-wasm

# 7. Test in sandbox
hush guard test-sandbox

# 8. Review all files to be published
npm pack --dry-run
```

### 7.2 Publishing to npm

```bash
# Login to npm (if needed)
npm login

# Publish
npm publish --access public

# For scoped packages
npm publish --access public

# The marketplace will automatically index your package
# within 5 minutes of publishing
```

### 7.3 Publishing to crates.io

```bash
# Login to crates.io (if needed)
cargo login

# Publish
cargo publish

# The marketplace will automatically index your crate
# within 5 minutes of publishing
```

### 7.4 Requesting Verification

```bash
# After publishing, request verification
hush guard request-verification

# Requirements for verification:
# - Public source repository
# - Passing CI/CD pipeline
# - Test coverage > 80%
# - No critical security findings
# - Documentation complete

# Track verification status
hush guard verification-status
```

---

## 8. Best Practices

### 8.1 Performance

1. **Implement `checkSync` when possible** - Avoids async overhead for simple checks
2. **Short-circuit early** - Return allow/deny as soon as decision is clear
3. **Cache expensive computations** - Regex compilation, pattern matching
4. **Minimize memory allocations** - Reuse buffers, avoid cloning

### 8.2 Security

1. **Validate all configuration** - Don't trust user input
2. **Handle errors gracefully** - Never panic, always return a result
3. **Don't log sensitive data** - Redact secrets, hash file contents
4. **Declare minimum capabilities** - Only request what you need

### 8.3 User Experience

1. **Write clear denial messages** - Help users understand why action was blocked
2. **Include remediation suggestions** - Tell users how to fix the issue
3. **Document configuration options** - Use JSDoc/rustdoc comments
4. **Provide examples** - Show common configuration patterns

### 8.4 Testing

1. **Test all code paths** - Allow, deny, warn, error
2. **Test edge cases** - Empty input, unicode, very long strings
3. **Test configuration validation** - Invalid config should error clearly
4. **Test performance** - Ensure guard doesn't add significant latency

---

## 9. Troubleshooting

### 9.1 Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Guard not loading | Invalid manifest | Run `hush guard validate` |
| WASM build fails | Unsupported APIs | Check capability restrictions |
| Slow performance | Expensive sync operations | Move to async or cache results |
| Memory errors | Exceeded limits | Increase limits or optimize code |

### 9.2 Debug Mode

```bash
# Enable debug logging
DEBUG=clawdstrike:* hush guard dev

# Verbose validation
hush guard validate --verbose

# Profile guard execution
hush guard profile --event ./test-event.json
```

### 9.3 Getting Help

- Documentation: https://docs.clawdstrike.dev/sdk
- GitHub Issues: https://github.com/clawdstrike/guard-sdk/issues
- Discord: https://discord.gg/clawdstrike
- Email: sdk-support@clawdstrike.dev

---

## 10. API Reference Summary

### Core Types

| Type | Description |
|------|-------------|
| `Guard` | Main guard interface |
| `BaseGuard` | Base class with helper methods |
| `GuardResult` | Result from guard check |
| `PolicyEvent` | Event to evaluate |
| `EventType` | Event type discriminator |
| `Severity` | Violation severity level |
| `GuardContext` | Context passed to guards |
| `Policy` | Policy configuration |

### Helper Methods (BaseGuard)

| Method | Description |
|--------|-------------|
| `allow()` | Create allow result |
| `deny(reason, severity)` | Create deny result |
| `warn(reason)` | Create warn result |

### Test Utilities

| Function | Description |
|----------|-------------|
| `GuardTestHarness` | Test harness for guards |
| `createTestEvent()` | Create test event |
| `fileWriteEvent()` | Create file write event |
| `patchApplyEvent()` | Create patch event |
| `networkEgressEvent()` | Create network event |

---

*This SDK documentation is the foundation for building custom guards. See async-guards.md for external service integration and composition-dsl.md for combining guards.*
