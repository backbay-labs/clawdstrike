# Plugin System Architecture

## Document Information

| Field | Value |
|-------|-------|
| **Status** | Draft |
| **Version** | 0.1.0 |
| **Authors** | Clawdstrike Architecture Team |
| **Last Updated** | 2026-02-02 |
| **Prerequisites** | overview.md |

---

## 1. Problem Statement

### 1.1 Requirements

1. **Multi-language support**: Guards written in TypeScript or Rust
2. **Secure execution**: Untrusted code cannot escape sandbox
3. **Low overhead**: Unused guards should not impact performance
4. **Easy distribution**: Standard package managers (npm, crates.io)
5. **Consistent lifecycle**: Load, initialize, execute, cleanup

### 1.2 Constraints

- Must work in both Node.js (OpenClaw) and native (hushd) environments
- Cannot require recompilation of core for new guards
- Must support hot-reload for development
- Must audit all plugin activity

---

## 2. Architecture

### 2.1 System Overview

```
+------------------------------------------------------------------+
|                        Clawdstrike Runtime                        |
+------------------------------------------------------------------+
|                                                                    |
|  +--------------------+    +--------------------+                  |
|  |   Plugin Registry  |    |  Plugin Resolver   |                  |
|  |   (discovered pkgs)|    |  (npm/crates.io)   |                  |
|  +----------+---------+    +----------+---------+                  |
|             |                         |                            |
|             v                         v                            |
|  +----------------------------------------------------------+     |
|  |                    Plugin Loader                          |     |
|  |  +------------------+  +------------------+               |     |
|  |  | TypeScript Loader|  | Rust/WASM Loader |               |     |
|  |  | (dynamic import) |  | (wasmtime/dlopen)|               |     |
|  |  +------------------+  +------------------+               |     |
|  +----------------------------------------------------------+     |
|             |                                                      |
|             v                                                      |
|  +----------------------------------------------------------+     |
|  |                  Plugin Sandbox                           |     |
|  |  +------------------+  +------------------+               |     |
|  |  | Capability Gate  |  | Resource Limiter |               |     |
|  |  +------------------+  +------------------+               |     |
|  +----------------------------------------------------------+     |
|             |                                                      |
|             v                                                      |
|  +----------------------------------------------------------+     |
|  |               Guard Instance Manager                      |     |
|  |  - Lifecycle management (init, check, cleanup)           |     |
|  |  - Instance pooling                                       |     |
|  |  - Hot reload support                                     |     |
|  +----------------------------------------------------------+     |
|                                                                    |
+------------------------------------------------------------------+
```

### 2.2 Plugin Package Structure

#### TypeScript Plugin (npm)

```
@acme/clawdstrike-guard-example/
├── package.json
├── clawdstrike.plugin.json    # Plugin manifest
├── src/
│   ├── index.ts               # Main entry point
│   ├── guard.ts               # Guard implementation
│   └── config.ts              # Configuration schema
├── dist/
│   ├── index.js
│   ├── index.d.ts
│   └── guard.wasm             # Optional WASM build
└── tests/
    └── guard.test.ts
```

#### Rust Plugin (crates.io)

```
clawdstrike-guard-example/
├── Cargo.toml
├── clawdstrike.plugin.toml    # Plugin manifest
├── src/
│   ├── lib.rs                 # Main entry point
│   └── guard.rs               # Guard implementation
└── tests/
    └── guard_test.rs
```

### 2.3 Plugin Manifest

#### TypeScript: `clawdstrike.plugin.json`

```json
{
  "$schema": "https://clawdstrike.dev/schemas/plugin-manifest.json",
  "version": "1.0.0",
  "name": "@acme/clawdstrike-guard-example",
  "displayName": "ACME Secret Guard",
  "description": "Detects ACME-specific secret patterns",
  "author": "ACME Security Team",
  "license": "MIT",

  "clawdstrike": {
    "minVersion": "0.5.0",
    "maxVersion": "1.x"
  },

  "guards": [
    {
      "name": "acme_secret",
      "displayName": "ACME Secret Detector",
      "entrypoint": "./dist/guard.js",
      "handles": ["file_write", "patch_apply", "tool_call"],
      "configSchema": "./dist/config-schema.json"
    }
  ],

  "capabilities": {
    "network": false,
    "filesystem": {
      "read": ["**/*.config", "**/.env*"],
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
    "level": "untrusted",
    "sandbox": "wasm"
  }
}
```

#### Rust: `clawdstrike.plugin.toml`

```toml
[plugin]
version = "1.0.0"
name = "clawdstrike-guard-example"
display_name = "ACME Secret Guard"
description = "Detects ACME-specific secret patterns"
author = "ACME Security Team"
license = "MIT"

[clawdstrike]
min_version = "0.5.0"
max_version = "1.x"

[[guards]]
name = "acme_secret"
display_name = "ACME Secret Detector"
handles = ["file_write", "patch_apply", "tool_call"]

[capabilities]
network = false
subprocess = false

[capabilities.filesystem]
read = ["**/*.config", "**/.env*"]
write = false

[capabilities.secrets]
access = false

[resources]
max_memory_mb = 64
max_cpu_ms = 100
max_timeout_ms = 5000

[trust]
level = "untrusted"
sandbox = "wasm"
```

---

## 3. API Design

### 3.1 TypeScript Guard Interface

```typescript
// @clawdstrike/guard-sdk

/**
 * Core Guard interface - must be implemented by all custom guards
 */
export interface Guard {
  /**
   * Unique guard identifier (e.g., "acme_secret")
   */
  name(): string;

  /**
   * Human-readable display name
   */
  displayName?(): string;

  /**
   * Event types this guard handles (empty = all)
   */
  handles(): EventType[];

  /**
   * Synchronous check - preferred for performance
   */
  checkSync?(event: PolicyEvent, policy: Policy): GuardResult;

  /**
   * Asynchronous check - for external service calls
   */
  check(event: PolicyEvent, policy: Policy): Promise<GuardResult>;

  /**
   * Whether this guard is enabled
   */
  isEnabled(): boolean;

  /**
   * Called once when guard is loaded
   */
  initialize?(context: GuardContext): Promise<void>;

  /**
   * Called when guard is being unloaded
   */
  cleanup?(): Promise<void>;
}

/**
 * Configuration for a custom guard
 */
export interface GuardConfig {
  /**
   * JSON Schema for configuration validation
   */
  schema: JSONSchema7;

  /**
   * Default configuration values
   */
  defaults: Record<string, unknown>;

  /**
   * Validate configuration
   */
  validate(config: unknown): ValidationResult;
}

/**
 * Context provided to guard during initialization
 */
export interface GuardContext {
  /**
   * Guard configuration (validated against schema)
   */
  config: Readonly<Record<string, unknown>>;

  /**
   * Logger scoped to this guard
   */
  logger: Logger;

  /**
   * Capability-gated services
   */
  services: {
    /**
     * HTTP client (requires network capability)
     */
    http?: HttpClient;

    /**
     * Filesystem access (requires filesystem capability)
     */
    fs?: FileSystemClient;

    /**
     * Secret store access (requires secrets capability)
     */
    secrets?: SecretStore;
  };

  /**
   * Metadata about the running environment
   */
  runtime: {
    version: string;
    environment: 'development' | 'production';
    sandboxed: boolean;
  };
}

/**
 * Result from a guard check
 */
export interface GuardResult {
  /**
   * Whether the action is allowed
   */
  status: 'allow' | 'deny' | 'warn';

  /**
   * Reason for denial or warning
   */
  reason?: string;

  /**
   * Severity level
   */
  severity?: 'low' | 'medium' | 'high' | 'critical';

  /**
   * Guard name (auto-filled if not provided)
   */
  guard: string;

  /**
   * Additional structured details
   */
  details?: Record<string, unknown>;

  /**
   * Suggested remediation
   */
  remediation?: string;
}

/**
 * Policy event to evaluate
 */
export interface PolicyEvent {
  eventId: string;
  eventType: EventType;
  timestamp: string;
  sessionId?: string;
  data: EventData;
  metadata?: Record<string, unknown>;
}

export type EventType =
  | 'file_read'
  | 'file_write'
  | 'command_exec'
  | 'network_egress'
  | 'tool_call'
  | 'patch_apply'
  | 'secret_access';
```

### 3.2 Rust Guard Trait

```rust
// clawdstrike-guard-sdk

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Core Guard trait - must be implemented by all custom guards
#[async_trait]
pub trait Guard: Send + Sync {
    /// Unique guard identifier (e.g., "acme_secret")
    fn name(&self) -> &str;

    /// Human-readable display name
    fn display_name(&self) -> Option<&str> {
        None
    }

    /// Event types this guard handles (empty = all)
    fn handles(&self) -> &[EventType];

    /// Synchronous check - preferred for performance
    fn check_sync(&self, _event: &PolicyEvent, _policy: &Policy) -> Option<GuardResult> {
        None
    }

    /// Asynchronous check - for external service calls
    async fn check(&self, event: &PolicyEvent, policy: &Policy) -> GuardResult;

    /// Whether this guard is enabled
    fn is_enabled(&self) -> bool {
        true
    }

    /// Called once when guard is loaded
    async fn initialize(&mut self, _context: &GuardContext) -> Result<(), GuardError> {
        Ok(())
    }

    /// Called when guard is being unloaded
    async fn cleanup(&mut self) -> Result<(), GuardError> {
        Ok(())
    }
}

/// Configuration trait for guards with custom config
pub trait GuardConfig: Default + Serialize + for<'de> Deserialize<'de> {
    /// JSON Schema for configuration validation
    fn schema() -> Value;

    /// Validate configuration
    fn validate(&self) -> Result<(), ValidationError>;
}

/// Context provided to guard during initialization
pub struct GuardContext {
    /// Guard configuration (validated)
    pub config: Value,

    /// Logger scoped to this guard
    pub logger: Box<dyn Logger>,

    /// Capability-gated services
    pub services: GuardServices,

    /// Runtime metadata
    pub runtime: RuntimeInfo,
}

/// Capability-gated services available to guards
pub struct GuardServices {
    /// HTTP client (requires network capability)
    pub http: Option<Box<dyn HttpClient>>,

    /// Filesystem access (requires filesystem capability)
    pub fs: Option<Box<dyn FileSystemClient>>,

    /// Secret store (requires secrets capability)
    pub secrets: Option<Box<dyn SecretStore>>,
}

/// Guard check result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardResult {
    pub status: GuardStatus,
    pub reason: Option<String>,
    pub severity: Option<Severity>,
    pub guard: String,
    pub details: Option<Value>,
    pub remediation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardStatus {
    Allow,
    Deny,
    Warn,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    FileRead,
    FileWrite,
    CommandExec,
    NetworkEgress,
    ToolCall,
    PatchApply,
    SecretAccess,
}
```

### 3.3 Plugin Registration

#### TypeScript Plugin Entry Point

```typescript
// src/index.ts
import { PluginDefinition, Guard } from '@clawdstrike/guard-sdk';
import { AcmeSecretGuard } from './guard';
import { AcmeSecretConfig } from './config';

/**
 * Plugin definition - exported as default
 */
const plugin: PluginDefinition = {
  name: '@acme/clawdstrike-guard-example',
  version: '1.0.0',

  guards: [
    {
      name: 'acme_secret',
      factory: (config: AcmeSecretConfig) => new AcmeSecretGuard(config),
      configSchema: AcmeSecretConfig.schema,
    },
  ],

  // Optional: Hook into plugin lifecycle
  onLoad: async (context) => {
    context.logger.info('ACME Secret Guard plugin loaded');
  },

  onUnload: async (context) => {
    context.logger.info('ACME Secret Guard plugin unloading');
  },
};

export default plugin;
```

#### Rust Plugin Entry Point

```rust
// src/lib.rs
use clawdstrike_guard_sdk::{
    export_plugin, Guard, GuardFactory, PluginDefinition,
};

mod guard;
mod config;

use guard::AcmeSecretGuard;
use config::AcmeSecretConfig;

/// Plugin definition
struct AcmeSecretPlugin;

impl PluginDefinition for AcmeSecretPlugin {
    fn name(&self) -> &str {
        "clawdstrike-guard-example"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn guards(&self) -> Vec<Box<dyn GuardFactory>> {
        vec![Box::new(AcmeSecretGuardFactory)]
    }
}

struct AcmeSecretGuardFactory;

impl GuardFactory for AcmeSecretGuardFactory {
    fn name(&self) -> &str {
        "acme_secret"
    }

    fn create(&self, config: serde_json::Value) -> Result<Box<dyn Guard>, GuardError> {
        let config: AcmeSecretConfig = serde_json::from_value(config)?;
        Ok(Box::new(AcmeSecretGuard::new(config)))
    }

    fn config_schema(&self) -> serde_json::Value {
        AcmeSecretConfig::schema()
    }
}

// Export plugin for dynamic loading
export_plugin!(AcmeSecretPlugin);
```

---

## 4. Plugin Loading

### 4.1 Discovery Process

```
                  Policy YAML
                      │
                      v
         ┌───────────────────────┐
         │   Parse guard refs    │
         │  - built-in guards    │
         │  - custom: [packages] │
         └───────────────────────┘
                      │
          ┌───────────┴───────────┐
          v                       v
   ┌─────────────┐         ┌─────────────┐
   │ Built-in    │         │ Custom      │
   │ Guard Loader│         │ Plugin Resolver│
   └─────────────┘         └─────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              v                   v                   v
       ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
       │ Local Path  │     │ npm Package │     │ Crates.io   │
       │ ./guards/   │     │ @scope/pkg  │     │ pkg-name    │
       └─────────────┘     └─────────────┘     └─────────────┘
              │                   │                   │
              └───────────────────┴───────────────────┘
                                  │
                                  v
                    ┌───────────────────────┐
                    │   Plugin Loader       │
                    │   - Validate manifest │
                    │   - Check capabilities│
                    │   - Initialize sandbox│
                    └───────────────────────┘
                                  │
                                  v
                    ┌───────────────────────┐
                    │   Guard Instance      │
                    │   Manager             │
                    └───────────────────────┘
```

### 4.2 TypeScript Plugin Loading

```typescript
// plugin-loader.ts

import { pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';
import { PluginDefinition, PluginManifest } from './types';

export class TypeScriptPluginLoader {
  private loadedPlugins = new Map<string, PluginDefinition>();

  /**
   * Load a plugin from npm package or local path
   */
  async load(packageRef: string): Promise<PluginDefinition> {
    // Check cache
    if (this.loadedPlugins.has(packageRef)) {
      return this.loadedPlugins.get(packageRef)!;
    }

    // Resolve package location
    const packagePath = await this.resolvePackage(packageRef);

    // Load and validate manifest
    const manifest = await this.loadManifest(packagePath);
    this.validateManifest(manifest);

    // Check capabilities against policy
    await this.validateCapabilities(manifest);

    // Dynamic import
    const entrypoint = new URL(manifest.guards[0].entrypoint, pathToFileURL(packagePath + '/'));
    const module = await import(entrypoint.href);

    const plugin: PluginDefinition = module.default;

    // Validate plugin structure
    this.validatePlugin(plugin, manifest);

    // Cache and return
    this.loadedPlugins.set(packageRef, plugin);
    return plugin;
  }

  /**
   * Resolve package to filesystem path
   */
  private async resolvePackage(ref: string): Promise<string> {
    // Local path
    if (ref.startsWith('./') || ref.startsWith('/')) {
      return ref;
    }

    // npm package - use require.resolve
    try {
      const resolved = require.resolve(`${ref}/package.json`);
      return resolved.replace('/package.json', '');
    } catch {
      throw new Error(`Cannot resolve plugin package: ${ref}`);
    }
  }

  /**
   * Load plugin manifest
   */
  private async loadManifest(packagePath: string): Promise<PluginManifest> {
    const manifestPath = `${packagePath}/clawdstrike.plugin.json`;
    const content = await readFile(manifestPath, 'utf-8');
    return JSON.parse(content);
  }

  /**
   * Validate manifest against schema
   */
  private validateManifest(manifest: PluginManifest): void {
    // Version compatibility check
    const [minMajor, minMinor] = manifest.clawdstrike.minVersion.split('.').map(Number);
    const [currentMajor, currentMinor] = CLAWDSTRIKE_VERSION.split('.').map(Number);

    if (currentMajor < minMajor || (currentMajor === minMajor && currentMinor < minMinor)) {
      throw new Error(
        `Plugin requires Clawdstrike >= ${manifest.clawdstrike.minVersion}, ` +
        `but running ${CLAWDSTRIKE_VERSION}`
      );
    }

    // Validate required fields
    if (!manifest.guards || manifest.guards.length === 0) {
      throw new Error('Plugin manifest must declare at least one guard');
    }
  }

  /**
   * Validate capabilities are within allowed bounds
   */
  private async validateCapabilities(manifest: PluginManifest): Promise<void> {
    const caps = manifest.capabilities;

    // Untrusted plugins cannot have certain capabilities
    if (manifest.trust === 'untrusted') {
      if (caps.subprocess) {
        throw new Error('Untrusted plugins cannot have subprocess capability');
      }

      if (caps.filesystem?.write) {
        throw new Error('Untrusted plugins cannot have filesystem write capability');
      }
    }
  }

  /**
   * Validate plugin exports match manifest
   */
  private validatePlugin(plugin: PluginDefinition, manifest: PluginManifest): void {
    if (plugin.name !== manifest.name) {
      throw new Error(
        `Plugin name mismatch: manifest says "${manifest.name}", ` +
        `but plugin exports "${plugin.name}"`
      );
    }

    for (const guardDef of manifest.guards) {
      const found = plugin.guards.find(g => g.name === guardDef.name);
      if (!found) {
        throw new Error(
          `Manifest declares guard "${guardDef.name}" but plugin does not export it`
        );
      }
    }
  }
}
```

### 4.3 Rust Plugin Loading

```rust
// plugin_loader.rs

use std::path::Path;
use libloading::{Library, Symbol};
use wasmtime::{Engine, Module, Store};

pub struct RustPluginLoader {
    loaded_plugins: HashMap<String, LoadedPlugin>,
    wasm_engine: Engine,
}

enum LoadedPlugin {
    Native(NativePlugin),
    Wasm(WasmPlugin),
}

struct NativePlugin {
    library: Library,
    definition: Box<dyn PluginDefinition>,
}

struct WasmPlugin {
    module: Module,
    store: Store<WasmState>,
}

impl RustPluginLoader {
    pub fn new() -> Result<Self, PluginError> {
        Ok(Self {
            loaded_plugins: HashMap::new(),
            wasm_engine: Engine::default(),
        })
    }

    /// Load a plugin from crates.io package or local path
    pub async fn load(&mut self, package_ref: &str) -> Result<&dyn PluginDefinition, PluginError> {
        // Check cache
        if self.loaded_plugins.contains_key(package_ref) {
            return self.get_plugin(package_ref);
        }

        // Resolve package location
        let package_path = self.resolve_package(package_ref).await?;

        // Load and validate manifest
        let manifest = self.load_manifest(&package_path)?;
        self.validate_manifest(&manifest)?;

        // Determine loading strategy based on trust level
        let plugin = match manifest.trust.level.as_str() {
            "untrusted" | "verified" => {
                // Load as WASM for sandboxing
                self.load_wasm(&package_path, &manifest).await?
            }
            "certified" | "first-party" => {
                // Load as native for performance
                self.load_native(&package_path, &manifest)?
            }
            _ => return Err(PluginError::InvalidTrustLevel),
        };

        self.loaded_plugins.insert(package_ref.to_string(), plugin);
        self.get_plugin(package_ref)
    }

    /// Load plugin as native dynamic library
    fn load_native(
        &self,
        package_path: &Path,
        manifest: &PluginManifest,
    ) -> Result<LoadedPlugin, PluginError> {
        // Find .so/.dylib/.dll
        let lib_path = self.find_native_library(package_path)?;

        unsafe {
            let library = Library::new(&lib_path)?;

            // Get plugin definition via exported symbol
            let create_plugin: Symbol<fn() -> Box<dyn PluginDefinition>> =
                library.get(b"create_plugin")?;

            let definition = create_plugin();

            // Validate plugin matches manifest
            self.validate_plugin(&*definition, manifest)?;

            Ok(LoadedPlugin::Native(NativePlugin {
                library,
                definition,
            }))
        }
    }

    /// Load plugin as WASM module
    async fn load_wasm(
        &self,
        package_path: &Path,
        manifest: &PluginManifest,
    ) -> Result<LoadedPlugin, PluginError> {
        // Find .wasm file
        let wasm_path = package_path.join("target/wasm32-wasi/release/plugin.wasm");

        // Compile WASM module
        let module = Module::from_file(&self.wasm_engine, &wasm_path)?;

        // Create store with capability-limited state
        let state = WasmState::new(manifest.capabilities.clone());
        let store = Store::new(&self.wasm_engine, state);

        Ok(LoadedPlugin::Wasm(WasmPlugin { module, store }))
    }

    /// Load manifest from TOML file
    fn load_manifest(&self, package_path: &Path) -> Result<PluginManifest, PluginError> {
        let manifest_path = package_path.join("clawdstrike.plugin.toml");
        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PluginManifest = toml::from_str(&content)?;
        Ok(manifest)
    }
}
```

---

## 5. Sandboxing

### 5.1 WASM Sandbox Architecture

```
+------------------------------------------------------------------+
|                       Host Runtime                                |
|  +------------------------------------------------------------+  |
|  |                    WASM Sandbox                             |  |
|  |  +------------------------------------------------------+  |  |
|  |  |                 Guest Plugin                          |  |  |
|  |  |                                                       |  |  |
|  |  |  +------------+  +------------+  +------------+      |  |  |
|  |  |  | Guard Code |  | Config     |  | State      |      |  |  |
|  |  |  +------------+  +------------+  +------------+      |  |  |
|  |  |                                                       |  |  |
|  |  +------------------------+------------------------------+  |  |
|  |                           |                                 |  |
|  |  +------------------------v------------------------------+  |  |
|  |  |              Host Function Imports                     |  |  |
|  |  |  - log(level, message)                                |  |  |
|  |  |  - http_request(url, opts) [if network cap]           |  |  |
|  |  |  - read_file(path) [if fs cap]                        |  |  |
|  |  |  - get_secret(key) [if secrets cap]                   |  |  |
|  |  +--------------------------------------------------------+  |  |
|  +------------------------------------------------------------+  |
|                                                                    |
|  +------------------------------------------------------------+  |
|  |                  Resource Limiter                           |  |
|  |  - Memory: 64MB max                                        |  |
|  |  - CPU: 100ms max per check                                |  |
|  |  - Timeout: 5000ms max                                     |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### 5.2 Capability System

```typescript
// capabilities.ts

/**
 * Capabilities that can be granted to plugins
 */
export interface PluginCapabilities {
  /**
   * Network access
   */
  network: boolean | NetworkCapability;

  /**
   * Filesystem access
   */
  filesystem: boolean | FilesystemCapability;

  /**
   * Secret store access
   */
  secrets: boolean | SecretsCapability;

  /**
   * Subprocess execution (never for untrusted)
   */
  subprocess: boolean;
}

export interface NetworkCapability {
  /**
   * Allowed destination patterns
   */
  allowedHosts: string[];

  /**
   * Allowed HTTP methods
   */
  allowedMethods: ('GET' | 'POST' | 'PUT' | 'DELETE')[];

  /**
   * Maximum request body size
   */
  maxRequestSizeBytes: number;

  /**
   * Maximum response body size
   */
  maxResponseSizeBytes: number;
}

export interface FilesystemCapability {
  /**
   * Paths that can be read (glob patterns)
   */
  read: string[] | boolean;

  /**
   * Paths that can be written (glob patterns)
   */
  write: string[] | boolean;
}

export interface SecretsCapability {
  /**
   * Secret keys that can be accessed
   */
  allowedKeys: string[];
}

/**
 * Capability gate - validates access before allowing operations
 */
export class CapabilityGate {
  constructor(private capabilities: PluginCapabilities) {}

  /**
   * Check if network request is allowed
   */
  canMakeRequest(url: string, method: string): boolean {
    const cap = this.capabilities.network;

    if (cap === false) return false;
    if (cap === true) return true;

    const parsedUrl = new URL(url);
    const hostAllowed = cap.allowedHosts.some(pattern =>
      minimatch(parsedUrl.host, pattern)
    );

    const methodAllowed = cap.allowedMethods.includes(
      method.toUpperCase() as any
    );

    return hostAllowed && methodAllowed;
  }

  /**
   * Check if file read is allowed
   */
  canReadFile(path: string): boolean {
    const cap = this.capabilities.filesystem;

    if (cap === false) return false;
    if (cap === true) return true;
    if (cap.read === false) return false;
    if (cap.read === true) return true;

    return cap.read.some(pattern => minimatch(path, pattern));
  }

  /**
   * Check if file write is allowed
   */
  canWriteFile(path: string): boolean {
    const cap = this.capabilities.filesystem;

    if (cap === false) return false;
    if (cap === true) return true;
    if (cap.write === false) return false;
    if (cap.write === true) return true;

    return cap.write.some(pattern => minimatch(path, pattern));
  }

  /**
   * Check if secret access is allowed
   */
  canAccessSecret(key: string): boolean {
    const cap = this.capabilities.secrets;

    if (cap === false) return false;
    if (cap === true) return true;

    return cap.allowedKeys.includes(key);
  }
}
```

### 5.3 Resource Limits

```rust
// resource_limiter.rs

use std::time::{Duration, Instant};
use wasmtime::{ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};

/// Resource limits for plugin execution
#[derive(Clone, Debug)]
pub struct PluginResourceLimits {
    /// Maximum memory in bytes
    pub max_memory_bytes: usize,
    /// Maximum CPU time per check
    pub max_cpu_duration: Duration,
    /// Maximum wall clock time per check
    pub max_timeout: Duration,
    /// Maximum table elements
    pub max_table_elements: u32,
    /// Maximum instances
    pub max_instances: u32,
}

impl Default for PluginResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_cpu_duration: Duration::from_millis(100),
            max_timeout: Duration::from_millis(5000),
            max_table_elements: 10_000,
            max_instances: 10,
        }
    }
}

/// WASM store limiter implementation
pub struct PluginStoreLimiter {
    limits: PluginResourceLimits,
    memory_used: usize,
    start_time: Option<Instant>,
}

impl PluginStoreLimiter {
    pub fn new(limits: PluginResourceLimits) -> Self {
        Self {
            limits,
            memory_used: 0,
            start_time: None,
        }
    }

    pub fn start_execution(&mut self) {
        self.start_time = Some(Instant::now());
    }

    pub fn check_timeout(&self) -> Result<(), ResourceError> {
        if let Some(start) = self.start_time {
            if start.elapsed() > self.limits.max_timeout {
                return Err(ResourceError::Timeout);
            }
        }
        Ok(())
    }
}

impl ResourceLimiter for PluginStoreLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> bool {
        let new_total = self.memory_used.saturating_sub(current) + desired;
        if new_total > self.limits.max_memory_bytes {
            return false;
        }
        self.memory_used = new_total;
        true
    }

    fn table_growing(
        &mut self,
        _current: u32,
        desired: u32,
        _maximum: Option<u32>,
    ) -> bool {
        desired <= self.limits.max_table_elements
    }

    fn instances(&self) -> usize {
        self.limits.max_instances as usize
    }

    fn tables(&self) -> usize {
        1
    }

    fn memories(&self) -> usize {
        1
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("Plugin exceeded memory limit")]
    MemoryExceeded,

    #[error("Plugin exceeded timeout")]
    Timeout,

    #[error("Plugin exceeded CPU limit")]
    CpuExceeded,
}
```

---

## 6. Configuration Schema

### 6.1 Policy Configuration for Custom Guards

```yaml
# policy.yaml
version: "1.1.0"
name: "My Policy"

guards:
  # Built-in guards (unchanged)
  forbidden_path:
    patterns:
      - "**/.ssh/**"

  # Custom guards section
  custom:
    # npm package
    - package: "@acme/clawdstrike-secrets"
      version: "^1.0.0"
      config:
        patterns:
          - name: acme_api_key
            pattern: "ACME_[A-Z0-9]{32}"
            severity: critical

    # crates.io package
    - package: "clawdstrike-virustotal"
      registry: crates.io
      version: "~0.5"
      config:
        api_key: ${VT_API_KEY}
        timeout_ms: 30000

    # Local path (for development)
    - path: "./guards/my-custom-guard"
      config:
        enabled: true

    # Inline guard definition (simple cases)
    - inline:
        name: "block_production_writes"
        handles: [file_write]
        logic:
          if:
            path_matches: "**/production/**"
          then: deny
          reason: "Cannot write to production paths"
```

### 6.2 Configuration JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clawdstrike.dev/schemas/custom-guards.json",
  "title": "Custom Guards Configuration",
  "type": "array",
  "items": {
    "oneOf": [
      { "$ref": "#/$defs/packageGuard" },
      { "$ref": "#/$defs/pathGuard" },
      { "$ref": "#/$defs/inlineGuard" }
    ]
  },
  "$defs": {
    "packageGuard": {
      "type": "object",
      "required": ["package"],
      "properties": {
        "package": {
          "type": "string",
          "description": "npm or crates.io package name"
        },
        "registry": {
          "type": "string",
          "enum": ["npm", "crates.io"],
          "default": "npm"
        },
        "version": {
          "type": "string",
          "description": "Semver version constraint"
        },
        "config": {
          "type": "object",
          "description": "Guard-specific configuration"
        },
        "enabled": {
          "type": "boolean",
          "default": true
        }
      }
    },
    "pathGuard": {
      "type": "object",
      "required": ["path"],
      "properties": {
        "path": {
          "type": "string",
          "description": "Local path to guard package"
        },
        "config": {
          "type": "object"
        },
        "enabled": {
          "type": "boolean",
          "default": true
        }
      }
    },
    "inlineGuard": {
      "type": "object",
      "required": ["inline"],
      "properties": {
        "inline": {
          "type": "object",
          "required": ["name", "handles"],
          "properties": {
            "name": { "type": "string" },
            "handles": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": ["file_read", "file_write", "command_exec", "network_egress", "tool_call", "patch_apply", "secret_access"]
              }
            },
            "logic": { "$ref": "#/$defs/guardLogic" }
          }
        }
      }
    },
    "guardLogic": {
      "type": "object",
      "description": "Simple guard logic DSL"
    }
  }
}
```

---

## 7. Testing Framework

### 7.1 Guard Test Utilities (TypeScript)

```typescript
// @clawdstrike/guard-sdk/testing

import { Guard, PolicyEvent, Policy, GuardResult, GuardContext } from '../types';

/**
 * Test harness for custom guards
 */
export class GuardTestHarness {
  private guard: Guard;
  private mockContext: GuardContext;

  constructor(guard: Guard) {
    this.guard = guard;
    this.mockContext = this.createMockContext();
  }

  /**
   * Create a mock guard context
   */
  private createMockContext(): GuardContext {
    return {
      config: {},
      logger: {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      },
      services: {},
      runtime: {
        version: '1.0.0',
        environment: 'development',
        sandboxed: false,
      },
    };
  }

  /**
   * Set guard configuration
   */
  withConfig(config: Record<string, unknown>): this {
    this.mockContext.config = config;
    return this;
  }

  /**
   * Initialize the guard
   */
  async initialize(): Promise<this> {
    if (this.guard.initialize) {
      await this.guard.initialize(this.mockContext);
    }
    return this;
  }

  /**
   * Check an event and assert the result
   */
  async check(event: PolicyEvent, policy: Policy = {}): Promise<GuardResult> {
    return this.guard.check(event, policy);
  }

  /**
   * Assert the guard allows an event
   */
  async expectAllow(event: PolicyEvent, policy: Policy = {}): Promise<void> {
    const result = await this.check(event, policy);
    if (result.status !== 'allow') {
      throw new Error(
        `Expected allow, got ${result.status}: ${result.reason}`
      );
    }
  }

  /**
   * Assert the guard denies an event
   */
  async expectDeny(
    event: PolicyEvent,
    policy: Policy = {},
    options?: { severity?: string; reasonContains?: string }
  ): Promise<void> {
    const result = await this.check(event, policy);
    if (result.status !== 'deny') {
      throw new Error(`Expected deny, got ${result.status}`);
    }
    if (options?.severity && result.severity !== options.severity) {
      throw new Error(
        `Expected severity ${options.severity}, got ${result.severity}`
      );
    }
    if (options?.reasonContains && !result.reason?.includes(options.reasonContains)) {
      throw new Error(
        `Expected reason to contain "${options.reasonContains}", got "${result.reason}"`
      );
    }
  }

  /**
   * Assert the guard warns on an event
   */
  async expectWarn(event: PolicyEvent, policy: Policy = {}): Promise<void> {
    const result = await this.check(event, policy);
    if (result.status !== 'warn') {
      throw new Error(`Expected warn, got ${result.status}`);
    }
  }
}

/**
 * Create a test event
 */
export function createTestEvent(
  type: EventType,
  data: Partial<EventData>
): PolicyEvent {
  return {
    eventId: `test-${Date.now()}`,
    eventType: type,
    timestamp: new Date().toISOString(),
    data: data as EventData,
  };
}

/**
 * Create a file write test event
 */
export function fileWriteEvent(path: string, content?: string): PolicyEvent {
  return createTestEvent('file_write', {
    type: 'file',
    path,
    operation: 'write',
    contentHash: content ? hash(content) : undefined,
  });
}

/**
 * Create a network egress test event
 */
export function networkEgressEvent(host: string, port: number = 443): PolicyEvent {
  return createTestEvent('network_egress', {
    type: 'network',
    host,
    port,
    protocol: 'tcp',
  });
}
```

### 7.2 Guard Test Example

```typescript
// tests/acme-secret-guard.test.ts

import { describe, it, expect, beforeEach } from 'vitest';
import { GuardTestHarness, fileWriteEvent } from '@clawdstrike/guard-sdk/testing';
import { AcmeSecretGuard } from '../src/guard';

describe('AcmeSecretGuard', () => {
  let harness: GuardTestHarness;

  beforeEach(async () => {
    harness = new GuardTestHarness(new AcmeSecretGuard());
    await harness.withConfig({
      patterns: [
        { name: 'acme_key', pattern: 'ACME_[A-Z0-9]{32}', severity: 'critical' },
      ],
    }).initialize();
  });

  it('should allow files without secrets', async () => {
    const event = fileWriteEvent('/app/config.json', '{"key": "value"}');
    await harness.expectAllow(event);
  });

  it('should deny files with ACME secrets', async () => {
    const event = fileWriteEvent(
      '/app/config.json',
      'api_key = "ACME_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"'
    );
    await harness.expectDeny(event, {}, {
      severity: 'critical',
      reasonContains: 'ACME secret detected',
    });
  });

  it('should handle empty files', async () => {
    const event = fileWriteEvent('/app/empty.txt', '');
    await harness.expectAllow(event);
  });
});
```

---

## 8. Publishing Workflow

### 8.1 npm Publishing

```bash
# 1. Validate plugin manifest
npx @clawdstrike/cli plugin validate

# 2. Build the plugin
npm run build

# 3. Run guard tests
npm test

# 4. Build WASM target (optional, for sandboxed execution)
npx @clawdstrike/cli plugin build-wasm

# 5. Publish to npm
npm publish --access public

# 6. Submit for verification (optional)
npx @clawdstrike/cli plugin submit-verification
```

### 8.2 crates.io Publishing

```bash
# 1. Validate plugin manifest
cargo clawdstrike plugin validate

# 2. Build the plugin
cargo build --release

# 3. Run guard tests
cargo test

# 4. Build WASM target
cargo build --target wasm32-wasi --release

# 5. Publish to crates.io
cargo publish

# 6. Submit for verification (optional)
cargo clawdstrike plugin submit-verification
```

### 8.3 CI/CD Pipeline Example

```yaml
# .github/workflows/publish-guard.yml
name: Publish Guard

on:
  push:
    tags:
      - 'v*'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Validate manifest
        run: npx @clawdstrike/cli plugin validate

      - name: Run tests
        run: npm test

      - name: Build WASM
        run: npx @clawdstrike/cli plugin build-wasm

  security-scan:
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run security scan
        run: npx @clawdstrike/cli plugin security-scan

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: security-scan
          path: .clawdstrike/security-scan.json

  publish:
    needs: [validate, security-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'

      - name: Publish
        run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

---

## 9. Security Considerations

### 9.1 Threat Matrix

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| Malicious guard code execution | Critical | Medium | WASM sandbox, capability restrictions |
| Supply chain compromise | Critical | Low | Package signing, verification pipeline |
| Guard exfiltrates data | High | Medium | Network capability restrictions, audit logging |
| Guard causes DoS | High | Medium | Resource limits, timeouts |
| Guard bypasses policy | High | Low | Immutable results, composition validation |
| Configuration injection | Medium | Medium | Config schema validation |

### 9.2 Security Invariants

1. **No Sandbox Escape**: WASM guests cannot access host resources outside declared capabilities
2. **No Result Tampering**: Guard results are immutable after creation
3. **Full Auditability**: All guard actions are logged
4. **Fail Closed**: Plugin loading failures result in policy enforcement (not bypass)

### 9.3 Security Considerations for Untrusted Plugins

Untrusted (community) plugins pose unique security challenges. The following safeguards are mandatory:

**Execution Isolation:**
- All untrusted plugins MUST run in WASM sandbox
- No direct access to host memory, filesystem, or network
- All host interactions mediated through capability-gated imports

**Capability Restrictions for Untrusted Plugins:**
- `subprocess`: NEVER allowed (immediate rejection)
- `filesystem.write`: NEVER allowed
- `filesystem.read`: Only explicit paths, no wildcards like `**/*`
- `network`: Requires explicit allowlist of domains
- `secrets`: Limited to explicitly named keys, no enumeration

**Resource Enforcement:**
- Memory: Hard limit enforced by WASM runtime (default 64MB)
- CPU: Interrupt execution after time limit (default 100ms per check)
- Timeout: Wall-clock limit for async operations (default 5000ms)

**Monitoring Requirements:**
- All capability access attempts logged (success and denied)
- Resource usage metrics collected per-plugin
- Anomaly detection for unusual patterns (e.g., many denied requests)

### 9.4 Audit Logging

```typescript
// audit-events.ts

export interface PluginAuditEvent {
  timestamp: string;
  eventType: 'plugin_loaded' | 'plugin_check' | 'plugin_error' | 'capability_denied';
  pluginName: string;
  details: Record<string, unknown>;
}

export interface PluginLoadedEvent extends PluginAuditEvent {
  eventType: 'plugin_loaded';
  details: {
    version: string;
    trust: string;
    sandbox: string;
    capabilities: PluginCapabilities;
  };
}

export interface PluginCheckEvent extends PluginAuditEvent {
  eventType: 'plugin_check';
  details: {
    guardName: string;
    eventType: EventType;
    eventId: string;
    result: GuardResult;
    durationMs: number;
  };
}

export interface CapabilityDeniedEvent extends PluginAuditEvent {
  eventType: 'capability_denied';
  details: {
    capability: string;
    requestedResource: string;
    reason: string;
  };
}
```

---

## 10. Implementation Phases

### Phase 1: Core Plugin Interface (Weeks 1-2)

- [ ] Stabilize Guard interface (TypeScript)
- [ ] Stabilize Guard trait (Rust)
- [ ] Plugin manifest schema
- [ ] Basic plugin validation

### Phase 2: TypeScript Plugin Loader (Weeks 3-4)

- [ ] npm package resolution
- [ ] Dynamic import loading
- [ ] Configuration validation
- [ ] Guard instance management

### Phase 3: Rust Plugin Loader (Weeks 5-6)

- [ ] crates.io package resolution
- [ ] Native library loading (dlopen)
- [ ] WASM module compilation
- [ ] Cross-language interface

### Phase 4: Sandboxing (Weeks 7-9)

- [ ] WASM runtime integration (Wasmtime)
- [ ] Capability permission system
- [ ] Resource limiting
- [ ] Host function implementations

### Phase 5: Testing & Tooling (Weeks 10-11)

- [ ] Guard test framework
- [ ] Plugin CLI commands
- [ ] WASM build tooling
- [ ] CI/CD templates

### Phase 6: Documentation & Examples (Week 12)

- [ ] API documentation
- [ ] Tutorial: Building your first guard
- [ ] Example guards repository
- [ ] Security guidelines

---

## 11. Open Questions

1. **Q: Should we support hot-reload in production?**
   - Pro: Faster iteration, no downtime
   - Con: Complexity, potential for inconsistent state
   - Proposed: Support in development mode only

2. **Q: How do we handle guard state persistence?**
   - Guards may need to maintain state (e.g., rate limiting counters)
   - Options: In-memory (lost on restart), external store (Redis), or both
   - Proposed: Provide optional StateStore interface

3. **Q: Should guards be able to declare dependencies on other guards?**
   - Some guards may want to run only after another guard has checked
   - This adds complexity to the execution model
   - Proposed: Defer to composition DSL (see composition-dsl.md)

---

*Next: See marketplace.md for guard discovery and distribution.*
