# Isolation Boundaries Specification

## Problem Statement

Multi-agent systems require strong isolation between agents to prevent:

1. **Resource Interference**: Agent A consuming resources needed by Agent B
2. **Data Leakage**: Agent A accessing Agent B's memory, files, or network
3. **Privilege Escalation**: Agent A exploiting Agent B's higher privileges
4. **Fault Propagation**: Agent A crashing or hanging affects Agent B

Isolation boundaries establish clear security perimeters between agents using a combination of OS-level, container-level, and application-level mechanisms.

## Threat Model

### Attack Scenarios

#### Scenario 1: Memory Snooping

```
Agent A and Agent B share process space
                    |
                    v
Agent A reads Agent B's memory
                    |
                    v
Extracts secrets, tokens, or context
```

**Mitigation**: Process isolation - separate address spaces

#### Scenario 2: Filesystem Escape

```
Agent A writes to /workspace/../../../etc/passwd
                    |
                    v
Modifies system files outside sandbox
```

**Mitigation**: Filesystem namespacing, chroot, path validation

#### Scenario 3: Network Lateral Movement

```
Agent A compromised
                    |
                    v
Agent A connects to Agent B's local socket
                    |
                    v
Attacks Agent B via internal network
```

**Mitigation**: Network namespacing, policy-based firewalls

#### Scenario 4: Resource Exhaustion

```
Agent A allocates all available memory
                    |
                    v
Agent B OOM-killed
                    |
                    v
Denial of service
```

**Mitigation**: Resource quotas (cgroups, ulimits)

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| Compromised Agent | Full control of agent process | Escape sandbox, attack other agents |
| Prompt Injection | Influence agent behavior | Execute unauthorized actions |
| Supply Chain Attack | Malicious dependencies | Persistent access, data theft |
| Insider | Access to orchestrator | Weaken isolation boundaries |

## Architecture

### Isolation Levels

```
+------------------------------------------------------------------+
|                     Isolation Level Hierarchy                     |
+------------------------------------------------------------------+

Level 0: No Isolation (DANGEROUS - development only)
+------------------------------------------------------------------+
| All agents in single process, shared memory, shared filesystem    |
+------------------------------------------------------------------+

Level 1: Process Isolation
+------------------------------------------------------------------+
| +---------------+  +---------------+  +---------------+           |
| | Agent A       |  | Agent B       |  | Agent C       |           |
| | (Process)     |  | (Process)     |  | (Process)     |           |
| +---------------+  +---------------+  +---------------+           |
| Shared: Filesystem, Network, User namespace                       |
+------------------------------------------------------------------+

Level 2: Container Isolation
+------------------------------------------------------------------+
| +---------------+  +---------------+  +---------------+           |
| | Container A   |  | Container B   |  | Container C   |           |
| | +----------+  |  | +----------+  |  | +----------+  |           |
| | | Agent A  |  |  | | Agent B  |  |  | | Agent C  |  |           |
| | +----------+  |  | +----------+  |  | +----------+  |           |
| +---------------+  +---------------+  +---------------+           |
| Isolated: PID, Mount, Network, User namespaces                    |
| Shared: Kernel                                                    |
+------------------------------------------------------------------+

Level 3: VM Isolation (Maximum Security)
+------------------------------------------------------------------+
| +---------------+  +---------------+  +---------------+           |
| | MicroVM A     |  | MicroVM B     |  | MicroVM C     |           |
| | +-----------+ |  | +-----------+ |  | +-----------+ |           |
| | | Kernel    | |  | | Kernel    | |  | | Kernel    | |           |
| | +-----------+ |  | +-----------+ |  | +-----------+ |           |
| | | Agent A   | |  | | Agent B   | |  | | Agent C   | |           |
| | +-----------+ |  | +-----------+ |  | +-----------+ |           |
| +---------------+  +---------------+  +---------------+           |
| Isolated: Everything except hypervisor                            |
+------------------------------------------------------------------+
```

### Boundary Enforcement Points

```
+------------------------------------------------------------------+
|                    Agent Execution Environment                    |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------------------------------------------------+  |
|  |                    Clawdstrike Runtime                      |  |
|  |  +------------------+  +------------------+                 |  |
|  |  | Policy Engine    |  | Isolation        |                 |  |
|  |  |                  |  | Controller       |                 |  |
|  |  +------------------+  +------------------+                 |  |
|  +------------------------------------------------------------+  |
|                              |                                    |
|         +--------------------+--------------------+               |
|         |                    |                    |               |
|         v                    v                    v               |
|  +-------------+      +-------------+      +-------------+        |
|  | Filesystem  |      | Network     |      | Process     |        |
|  | Boundary    |      | Boundary    |      | Boundary    |        |
|  +------+------+      +------+------+      +------+------+        |
|         |                    |                    |               |
|         v                    v                    v               |
|  +-------------+      +-------------+      +-------------+        |
|  | seccomp-bpf |      | iptables/   |      | namespaces  |        |
|  | landlock    |      | nftables    |      | cgroups     |        |
|  +-------------+      +-------------+      +-------------+        |
|                                                                   |
+------------------------------------------------------------------+
```

## API Design

### TypeScript Interface

```typescript
/**
 * Isolation level configuration
 */
export type IsolationLevel = 'none' | 'process' | 'container' | 'vm';

/**
 * Isolation boundary configuration
 */
export interface IsolationConfig {
  /** Isolation level */
  level: IsolationLevel;

  /** Filesystem isolation */
  filesystem: FilesystemIsolationConfig;

  /** Network isolation */
  network: NetworkIsolationConfig;

  /** Resource limits */
  resources: ResourceLimitsConfig;

  /** Process/execution isolation */
  process: ProcessIsolationConfig;
}

/**
 * Filesystem isolation configuration
 */
export interface FilesystemIsolationConfig {
  /** Root directory for agent (chroot/pivot_root) */
  rootfs?: string;

  /** Per-agent workspace directory */
  workspaceRoot: string;

  /** Read-only bind mounts */
  readOnlyMounts?: MountSpec[];

  /** Read-write bind mounts */
  readWriteMounts?: MountSpec[];

  /** Paths that must never be accessible */
  blockedPaths?: string[];

  /** Whether to use overlay filesystem */
  useOverlay?: boolean;

  /** Overlay upper directory (for writes) */
  overlayUpperDir?: string;
}

/**
 * Mount specification
 */
export interface MountSpec {
  /** Source path on host */
  source: string;

  /** Target path in container */
  target: string;

  /** Mount options */
  options?: string[];
}

/**
 * Network isolation configuration
 */
export interface NetworkIsolationConfig {
  /** Network mode */
  mode: 'none' | 'host' | 'bridge' | 'isolated';

  /** Allowed egress destinations */
  allowedEgress?: EgressRule[];

  /** Allowed ingress sources */
  allowedIngress?: IngressRule[];

  /** DNS servers */
  dnsServers?: string[];

  /** Whether to allow inter-agent communication */
  allowInterAgent?: boolean;

  /** Inter-agent communication rules */
  interAgentRules?: InterAgentNetworkRule[];
}

/**
 * Egress rule
 */
export interface EgressRule {
  /** Destination host/CIDR */
  destination: string;

  /** Allowed ports */
  ports?: number[];

  /** Protocol (tcp, udp) */
  protocol?: 'tcp' | 'udp' | 'any';
}

/**
 * Ingress rule
 */
export interface IngressRule {
  /** Source host/CIDR */
  source: string;

  /** Allowed ports */
  ports?: number[];

  /** Protocol */
  protocol?: 'tcp' | 'udp' | 'any';
}

/**
 * Inter-agent network rule
 */
export interface InterAgentNetworkRule {
  /** Source agent pattern */
  from: string;

  /** Target agent pattern */
  to: string;

  /** Allowed ports */
  ports?: number[];

  /** Whether to allow */
  allow: boolean;
}

/**
 * Resource limits configuration
 */
export interface ResourceLimitsConfig {
  /** Memory limit in bytes */
  memoryBytes?: number;

  /** Memory + swap limit */
  memorySwapBytes?: number;

  /** CPU quota (100000 = 1 CPU) */
  cpuQuota?: number;

  /** CPU period (microseconds) */
  cpuPeriod?: number;

  /** Number of PIDs allowed */
  pidsLimit?: number;

  /** Open file descriptor limit */
  nofileLimit?: number;

  /** Maximum process size */
  asLimit?: number;

  /** Core dump size limit */
  coreLimit?: number;
}

/**
 * Process isolation configuration
 */
export interface ProcessIsolationConfig {
  /** User to run as */
  user?: string;

  /** Group to run as */
  group?: string;

  /** Linux capabilities to grant */
  capabilities?: string[];

  /** Linux capabilities to drop */
  dropCapabilities?: string[];

  /** Seccomp profile */
  seccompProfile?: SeccompProfile;

  /** AppArmor profile */
  apparmorProfile?: string;

  /** SELinux context */
  selinuxContext?: string;

  /** Whether to create new namespaces */
  namespaces?: NamespaceConfig;
}

/**
 * Namespace configuration
 */
export interface NamespaceConfig {
  /** PID namespace */
  pid?: boolean;

  /** Mount namespace */
  mount?: boolean;

  /** Network namespace */
  network?: boolean;

  /** User namespace */
  user?: boolean;

  /** UTS namespace (hostname) */
  uts?: boolean;

  /** IPC namespace */
  ipc?: boolean;

  /** Cgroup namespace */
  cgroup?: boolean;
}

/**
 * Seccomp profile
 */
export interface SeccompProfile {
  /** Default action */
  defaultAction: 'SCMP_ACT_ALLOW' | 'SCMP_ACT_ERRNO' | 'SCMP_ACT_KILL';

  /** Syscall rules */
  syscalls: SeccompSyscall[];
}

/**
 * Seccomp syscall rule
 */
export interface SeccompSyscall {
  /** Syscall names */
  names: string[];

  /** Action */
  action: 'SCMP_ACT_ALLOW' | 'SCMP_ACT_ERRNO' | 'SCMP_ACT_KILL';

  /** Arguments to match */
  args?: SeccompArg[];
}

/**
 * Seccomp argument
 */
export interface SeccompArg {
  /** Argument index */
  index: number;

  /** Value to compare */
  value: number;

  /** Comparison operator */
  op: 'SCMP_CMP_EQ' | 'SCMP_CMP_NE' | 'SCMP_CMP_LT' | 'SCMP_CMP_LE' | 'SCMP_CMP_GT' | 'SCMP_CMP_GE';
}

/**
 * Isolation controller
 */
export class IsolationController {
  private config: IsolationConfig;
  private agentSandboxes: Map<AgentId, AgentSandbox> = new Map();

  constructor(config: IsolationConfig) {
    this.config = config;
  }

  /**
   * Create an isolated sandbox for an agent
   */
  async createSandbox(
    agentId: AgentId,
    overrides?: Partial<IsolationConfig>
  ): Promise<AgentSandbox> {
    const effectiveConfig = this.mergeConfig(this.config, overrides);

    // Create sandbox based on isolation level
    let sandbox: AgentSandbox;

    switch (effectiveConfig.level) {
      case 'none':
        sandbox = new NoIsolationSandbox(agentId, effectiveConfig);
        break;
      case 'process':
        sandbox = new ProcessIsolationSandbox(agentId, effectiveConfig);
        break;
      case 'container':
        sandbox = await ContainerSandbox.create(agentId, effectiveConfig);
        break;
      case 'vm':
        sandbox = await MicroVmSandbox.create(agentId, effectiveConfig);
        break;
      default:
        throw new Error(`Unknown isolation level: ${effectiveConfig.level}`);
    }

    // Initialize sandbox
    await sandbox.initialize();

    // Store reference
    this.agentSandboxes.set(agentId, sandbox);

    return sandbox;
  }

  /**
   * Get an existing sandbox
   */
  getSandbox(agentId: AgentId): AgentSandbox | undefined {
    return this.agentSandboxes.get(agentId);
  }

  /**
   * Destroy a sandbox
   */
  async destroySandbox(agentId: AgentId): Promise<void> {
    const sandbox = this.agentSandboxes.get(agentId);
    if (sandbox) {
      await sandbox.cleanup();
      this.agentSandboxes.delete(agentId);
    }
  }

  /**
   * Destroy all sandboxes
   */
  async destroyAll(): Promise<void> {
    for (const [agentId, sandbox] of this.agentSandboxes) {
      await sandbox.cleanup();
    }
    this.agentSandboxes.clear();
  }

  private mergeConfig(
    base: IsolationConfig,
    overrides?: Partial<IsolationConfig>
  ): IsolationConfig {
    if (!overrides) return base;
    return {
      ...base,
      ...overrides,
      filesystem: { ...base.filesystem, ...overrides.filesystem },
      network: { ...base.network, ...overrides.network },
      resources: { ...base.resources, ...overrides.resources },
      process: { ...base.process, ...overrides.process },
    };
  }
}

/**
 * Agent sandbox interface
 */
export interface AgentSandbox {
  /** Agent ID */
  readonly agentId: AgentId;

  /** Isolation level */
  readonly level: IsolationLevel;

  /** Initialize the sandbox */
  initialize(): Promise<void>;

  /** Execute a command in the sandbox */
  exec(command: string, args: string[], options?: ExecOptions): Promise<ExecResult>;

  /** Read a file from the sandbox */
  readFile(path: string): Promise<Uint8Array>;

  /** Write a file to the sandbox */
  writeFile(path: string, content: Uint8Array): Promise<void>;

  /** Check if a path is accessible */
  isPathAccessible(path: string, mode: 'read' | 'write'): Promise<boolean>;

  /** Get resource usage */
  getResourceUsage(): Promise<ResourceUsage>;

  /** Cleanup the sandbox */
  cleanup(): Promise<void>;
}

/**
 * Execution options
 */
export interface ExecOptions {
  /** Working directory */
  cwd?: string;

  /** Environment variables */
  env?: Record<string, string>;

  /** Timeout in milliseconds */
  timeout?: number;

  /** Stdin content */
  stdin?: string | Uint8Array;
}

/**
 * Execution result
 */
export interface ExecResult {
  /** Exit code */
  exitCode: number;

  /** Stdout */
  stdout: string;

  /** Stderr */
  stderr: string;

  /** Whether the process timed out */
  timedOut: boolean;

  /** Resource usage */
  resourceUsage?: ResourceUsage;
}

/**
 * Resource usage
 */
export interface ResourceUsage {
  /** Memory usage in bytes */
  memoryBytes: number;

  /** CPU time in milliseconds */
  cpuTimeMs: number;

  /** Number of active processes */
  processCount: number;

  /** Open file descriptors */
  openFiles: number;
}

/**
 * No isolation sandbox (for development)
 */
class NoIsolationSandbox implements AgentSandbox {
  readonly agentId: AgentId;
  readonly level: IsolationLevel = 'none';
  private config: IsolationConfig;

  constructor(agentId: AgentId, config: IsolationConfig) {
    this.agentId = agentId;
    this.config = config;
  }

  async initialize(): Promise<void> {
    console.warn(`[SECURITY] Agent ${this.agentId} running without isolation!`);
  }

  async exec(command: string, args: string[], options?: ExecOptions): Promise<ExecResult> {
    const { execSync } = await import('child_process');
    try {
      const stdout = execSync(`${command} ${args.join(' ')}`, {
        cwd: options?.cwd,
        env: { ...process.env, ...options?.env },
        timeout: options?.timeout,
        input: options?.stdin,
        encoding: 'utf-8',
      });
      return { exitCode: 0, stdout, stderr: '', timedOut: false };
    } catch (error: any) {
      return {
        exitCode: error.status ?? 1,
        stdout: error.stdout ?? '',
        stderr: error.stderr ?? '',
        timedOut: error.killed ?? false,
      };
    }
  }

  async readFile(path: string): Promise<Uint8Array> {
    const { readFile } = await import('fs/promises');
    return readFile(path);
  }

  async writeFile(path: string, content: Uint8Array): Promise<void> {
    const { writeFile } = await import('fs/promises');
    await writeFile(path, content);
  }

  async isPathAccessible(path: string, mode: 'read' | 'write'): Promise<boolean> {
    const { access, constants } = await import('fs/promises');
    try {
      await access(path, mode === 'read' ? constants.R_OK : constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }

  async getResourceUsage(): Promise<ResourceUsage> {
    const usage = process.memoryUsage();
    return {
      memoryBytes: usage.heapUsed,
      cpuTimeMs: process.cpuUsage().user / 1000,
      processCount: 1,
      openFiles: 0,
    };
  }

  async cleanup(): Promise<void> {
    // No cleanup needed
  }
}

/**
 * Process isolation sandbox
 */
class ProcessIsolationSandbox implements AgentSandbox {
  readonly agentId: AgentId;
  readonly level: IsolationLevel = 'process';
  private config: IsolationConfig;
  private childProcess: ChildProcess | null = null;

  constructor(agentId: AgentId, config: IsolationConfig) {
    this.agentId = agentId;
    this.config = config;
  }

  async initialize(): Promise<void> {
    // Set up workspace directory
    const { mkdir } = await import('fs/promises');
    const workspaceDir = `${this.config.filesystem.workspaceRoot}/${this.agentId}`;
    await mkdir(workspaceDir, { recursive: true });
  }

  async exec(command: string, args: string[], options?: ExecOptions): Promise<ExecResult> {
    const { spawn } = await import('child_process');

    return new Promise((resolve) => {
      const child = spawn(command, args, {
        cwd: options?.cwd ?? `${this.config.filesystem.workspaceRoot}/${this.agentId}`,
        env: { ...process.env, ...options?.env },
        uid: this.config.process.user ? parseInt(this.config.process.user) : undefined,
        gid: this.config.process.group ? parseInt(this.config.process.group) : undefined,
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      child.stdout?.on('data', (data) => (stdout += data));
      child.stderr?.on('data', (data) => (stderr += data));

      if (options?.stdin) {
        child.stdin?.write(options.stdin);
        child.stdin?.end();
      }

      const timer = options?.timeout
        ? setTimeout(() => {
            timedOut = true;
            child.kill('SIGKILL');
          }, options.timeout)
        : null;

      child.on('close', (exitCode) => {
        if (timer) clearTimeout(timer);
        resolve({
          exitCode: exitCode ?? 1,
          stdout,
          stderr,
          timedOut,
        });
      });
    });
  }

  async readFile(path: string): Promise<Uint8Array> {
    // Validate path is within allowed boundaries
    const resolvedPath = this.resolvePath(path);
    const { readFile } = await import('fs/promises');
    return readFile(resolvedPath);
  }

  async writeFile(path: string, content: Uint8Array): Promise<void> {
    const resolvedPath = this.resolvePath(path);
    const { writeFile } = await import('fs/promises');
    await writeFile(resolvedPath, content);
  }

  async isPathAccessible(path: string, mode: 'read' | 'write'): Promise<boolean> {
    try {
      this.resolvePath(path);
      return true;
    } catch {
      return false;
    }
  }

  async getResourceUsage(): Promise<ResourceUsage> {
    // Would use cgroups in production
    return {
      memoryBytes: 0,
      cpuTimeMs: 0,
      processCount: 1,
      openFiles: 0,
    };
  }

  async cleanup(): Promise<void> {
    if (this.childProcess) {
      this.childProcess.kill('SIGKILL');
    }
  }

  private resolvePath(path: string): string {
    const { resolve, normalize } = require('path');
    const workspaceRoot = `${this.config.filesystem.workspaceRoot}/${this.agentId}`;
    const resolved = resolve(workspaceRoot, path);
    const normalized = normalize(resolved);

    if (!normalized.startsWith(normalize(workspaceRoot))) {
      throw new Error(`Path escape attempt: ${path}`);
    }

    // Check blocked paths
    for (const blocked of this.config.filesystem.blockedPaths ?? []) {
      if (normalized.startsWith(normalize(blocked))) {
        throw new Error(`Blocked path: ${path}`);
      }
    }

    return normalized;
  }
}

/**
 * Container sandbox (Docker/containerd)
 */
class ContainerSandbox implements AgentSandbox {
  readonly agentId: AgentId;
  readonly level: IsolationLevel = 'container';
  private config: IsolationConfig;
  private containerId: string | null = null;

  private constructor(agentId: AgentId, config: IsolationConfig) {
    this.agentId = agentId;
    this.config = config;
  }

  static async create(agentId: AgentId, config: IsolationConfig): Promise<ContainerSandbox> {
    return new ContainerSandbox(agentId, config);
  }

  async initialize(): Promise<void> {
    // Create container
    const containerConfig = this.buildContainerConfig();
    this.containerId = await this.createContainer(containerConfig);
    await this.startContainer(this.containerId);
  }

  async exec(command: string, args: string[], options?: ExecOptions): Promise<ExecResult> {
    if (!this.containerId) {
      throw new Error('Container not initialized');
    }

    // docker exec equivalent
    const execConfig = {
      Cmd: [command, ...args],
      WorkingDir: options?.cwd,
      Env: options?.env ? Object.entries(options.env).map(([k, v]) => `${k}=${v}`) : [],
    };

    // Execute in container
    return this.containerExec(this.containerId, execConfig, options?.timeout);
  }

  async readFile(path: string): Promise<Uint8Array> {
    if (!this.containerId) {
      throw new Error('Container not initialized');
    }
    return this.containerCopyFrom(this.containerId, path);
  }

  async writeFile(path: string, content: Uint8Array): Promise<void> {
    if (!this.containerId) {
      throw new Error('Container not initialized');
    }
    await this.containerCopyTo(this.containerId, path, content);
  }

  async isPathAccessible(path: string, mode: 'read' | 'write'): Promise<boolean> {
    if (!this.containerId) return false;
    try {
      await this.containerExec(this.containerId, {
        Cmd: ['test', mode === 'read' ? '-r' : '-w', path],
      });
      return true;
    } catch {
      return false;
    }
  }

  async getResourceUsage(): Promise<ResourceUsage> {
    if (!this.containerId) {
      return { memoryBytes: 0, cpuTimeMs: 0, processCount: 0, openFiles: 0 };
    }
    return this.containerStats(this.containerId);
  }

  async cleanup(): Promise<void> {
    if (this.containerId) {
      await this.stopContainer(this.containerId);
      await this.removeContainer(this.containerId);
    }
  }

  private buildContainerConfig(): ContainerCreateConfig {
    return {
      Image: 'clawdstrike/agent-runtime:latest',
      HostConfig: {
        Memory: this.config.resources.memoryBytes,
        MemorySwap: this.config.resources.memorySwapBytes,
        CpuQuota: this.config.resources.cpuQuota,
        CpuPeriod: this.config.resources.cpuPeriod,
        PidsLimit: this.config.resources.pidsLimit,
        SecurityOpt: this.buildSecurityOpts(),
        CapDrop: this.config.process.dropCapabilities ?? ['ALL'],
        CapAdd: this.config.process.capabilities ?? [],
        NetworkMode: this.mapNetworkMode(),
        Binds: this.buildMounts(),
        ReadonlyRootfs: true,
      },
      NetworkDisabled: this.config.network.mode === 'none',
    };
  }

  private buildSecurityOpts(): string[] {
    const opts: string[] = [];
    if (this.config.process.seccompProfile) {
      opts.push(`seccomp=${JSON.stringify(this.config.process.seccompProfile)}`);
    }
    if (this.config.process.apparmorProfile) {
      opts.push(`apparmor=${this.config.process.apparmorProfile}`);
    }
    opts.push('no-new-privileges');
    return opts;
  }

  private buildMounts(): string[] {
    const mounts: string[] = [];

    // Workspace
    mounts.push(
      `${this.config.filesystem.workspaceRoot}/${this.agentId}:/workspace:rw`
    );

    // Read-only mounts
    for (const mount of this.config.filesystem.readOnlyMounts ?? []) {
      mounts.push(`${mount.source}:${mount.target}:ro`);
    }

    // Read-write mounts
    for (const mount of this.config.filesystem.readWriteMounts ?? []) {
      mounts.push(`${mount.source}:${mount.target}:rw`);
    }

    return mounts;
  }

  private mapNetworkMode(): string {
    switch (this.config.network.mode) {
      case 'none':
        return 'none';
      case 'host':
        return 'host';
      case 'isolated':
        return `container:${this.agentId}-network`;
      default:
        return 'bridge';
    }
  }

  // Docker API stubs (would use dockerode or similar in production)
  private async createContainer(config: ContainerCreateConfig): Promise<string> {
    // Implementation using Docker API
    return `container-${this.agentId}`;
  }

  private async startContainer(containerId: string): Promise<void> {
    // docker start
  }

  private async stopContainer(containerId: string): Promise<void> {
    // docker stop
  }

  private async removeContainer(containerId: string): Promise<void> {
    // docker rm
  }

  private async containerExec(
    containerId: string,
    config: { Cmd: string[]; WorkingDir?: string; Env?: string[] },
    timeout?: number
  ): Promise<ExecResult> {
    // docker exec
    return { exitCode: 0, stdout: '', stderr: '', timedOut: false };
  }

  private async containerCopyFrom(containerId: string, path: string): Promise<Uint8Array> {
    // docker cp containerId:path -
    return new Uint8Array();
  }

  private async containerCopyTo(
    containerId: string,
    path: string,
    content: Uint8Array
  ): Promise<void> {
    // docker cp - containerId:path
  }

  private async containerStats(containerId: string): Promise<ResourceUsage> {
    // docker stats
    return { memoryBytes: 0, cpuTimeMs: 0, processCount: 0, openFiles: 0 };
  }
}

interface ContainerCreateConfig {
  Image: string;
  HostConfig: {
    Memory?: number;
    MemorySwap?: number;
    CpuQuota?: number;
    CpuPeriod?: number;
    PidsLimit?: number;
    SecurityOpt: string[];
    CapDrop: string[];
    CapAdd: string[];
    NetworkMode: string;
    Binds: string[];
    ReadonlyRootfs: boolean;
  };
  NetworkDisabled: boolean;
}
```

### Rust Interface

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Isolation level
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationLevel {
    None,
    Process,
    Container,
    Vm,
}

/// Isolation configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolationConfig {
    pub level: IsolationLevel,
    pub filesystem: FilesystemIsolationConfig,
    pub network: NetworkIsolationConfig,
    pub resources: ResourceLimitsConfig,
    pub process: ProcessIsolationConfig,
}

/// Filesystem isolation config
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilesystemIsolationConfig {
    pub rootfs: Option<PathBuf>,
    pub workspace_root: PathBuf,
    pub read_only_mounts: Vec<MountSpec>,
    pub read_write_mounts: Vec<MountSpec>,
    pub blocked_paths: Vec<PathBuf>,
    pub use_overlay: bool,
    pub overlay_upper_dir: Option<PathBuf>,
}

/// Mount specification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountSpec {
    pub source: PathBuf,
    pub target: PathBuf,
    pub options: Vec<String>,
}

/// Network isolation config
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkIsolationConfig {
    pub mode: NetworkMode,
    pub allowed_egress: Vec<EgressRule>,
    pub allowed_ingress: Vec<IngressRule>,
    pub dns_servers: Vec<String>,
    pub allow_inter_agent: bool,
    pub inter_agent_rules: Vec<InterAgentNetworkRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    None,
    Host,
    Bridge,
    Isolated,
}

/// Resource limits
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceLimitsConfig {
    pub memory_bytes: Option<u64>,
    pub memory_swap_bytes: Option<u64>,
    pub cpu_quota: Option<u64>,
    pub cpu_period: Option<u64>,
    pub pids_limit: Option<u64>,
    pub nofile_limit: Option<u64>,
}

/// Process isolation config
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessIsolationConfig {
    pub user: Option<String>,
    pub group: Option<String>,
    pub capabilities: Vec<String>,
    pub drop_capabilities: Vec<String>,
    pub seccomp_profile: Option<SeccompProfile>,
    pub apparmor_profile: Option<String>,
    pub namespaces: NamespaceConfig,
}

/// Namespace configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NamespaceConfig {
    pub pid: bool,
    pub mount: bool,
    pub network: bool,
    pub user: bool,
    pub uts: bool,
    pub ipc: bool,
    pub cgroup: bool,
}

/// Seccomp profile
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeccompProfile {
    pub default_action: SeccompAction,
    pub syscalls: Vec<SeccompSyscall>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SeccompAction {
    Allow,
    Errno(i32),
    Kill,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeccompSyscall {
    pub names: Vec<String>,
    pub action: SeccompAction,
    pub args: Vec<SeccompArg>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeccompArg {
    pub index: u32,
    pub value: u64,
    pub op: SeccompOp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SeccompOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Egress rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressRule {
    pub destination: String,
    pub ports: Vec<u16>,
    pub protocol: Protocol,
}

/// Ingress rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressRule {
    pub source: String,
    pub ports: Vec<u16>,
    pub protocol: Protocol,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

/// Inter-agent network rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterAgentNetworkRule {
    pub from: String,
    pub to: String,
    pub ports: Vec<u16>,
    pub allow: bool,
}

/// Agent sandbox trait
#[async_trait]
pub trait AgentSandbox: Send + Sync {
    /// Get agent ID
    fn agent_id(&self) -> &AgentId;

    /// Get isolation level
    fn level(&self) -> IsolationLevel;

    /// Initialize the sandbox
    async fn initialize(&mut self) -> Result<(), Error>;

    /// Execute a command
    async fn exec(
        &self,
        command: &str,
        args: &[String],
        options: Option<ExecOptions>,
    ) -> Result<ExecResult, Error>;

    /// Read a file
    async fn read_file(&self, path: &str) -> Result<Vec<u8>, Error>;

    /// Write a file
    async fn write_file(&self, path: &str, content: &[u8]) -> Result<(), Error>;

    /// Check path accessibility
    async fn is_path_accessible(&self, path: &str, mode: AccessMode) -> Result<bool, Error>;

    /// Get resource usage
    async fn get_resource_usage(&self) -> Result<ResourceUsage, Error>;

    /// Cleanup
    async fn cleanup(&mut self) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub enum AccessMode {
    Read,
    Write,
}

/// Execution options
#[derive(Clone, Debug, Default)]
pub struct ExecOptions {
    pub cwd: Option<String>,
    pub env: HashMap<String, String>,
    pub timeout: Option<std::time::Duration>,
    pub stdin: Option<Vec<u8>>,
}

/// Execution result
#[derive(Clone, Debug)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub resource_usage: Option<ResourceUsage>,
}

/// Resource usage
#[derive(Clone, Debug, Default)]
pub struct ResourceUsage {
    pub memory_bytes: u64,
    pub cpu_time_ms: u64,
    pub process_count: u32,
    pub open_files: u32,
}

/// Isolation controller
pub struct IsolationController {
    config: IsolationConfig,
    sandboxes: tokio::sync::RwLock<HashMap<AgentId, Arc<dyn AgentSandbox>>>,
}

impl IsolationController {
    pub fn new(config: IsolationConfig) -> Self {
        Self {
            config,
            sandboxes: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Create a sandbox for an agent
    pub async fn create_sandbox(
        &self,
        agent_id: AgentId,
        overrides: Option<IsolationConfig>,
    ) -> Result<Arc<dyn AgentSandbox>, Error> {
        let effective_config = self.merge_config(&self.config, overrides.as_ref());

        let sandbox: Arc<dyn AgentSandbox> = match effective_config.level {
            IsolationLevel::None => {
                Arc::new(NoIsolationSandbox::new(agent_id.clone(), effective_config))
            }
            IsolationLevel::Process => {
                Arc::new(ProcessIsolationSandbox::new(agent_id.clone(), effective_config).await?)
            }
            IsolationLevel::Container => {
                Arc::new(ContainerSandbox::new(agent_id.clone(), effective_config).await?)
            }
            IsolationLevel::Vm => {
                Arc::new(MicroVmSandbox::new(agent_id.clone(), effective_config).await?)
            }
        };

        let mut sandboxes = self.sandboxes.write().await;
        sandboxes.insert(agent_id, sandbox.clone());

        Ok(sandbox)
    }

    /// Get an existing sandbox
    pub async fn get_sandbox(&self, agent_id: &AgentId) -> Option<Arc<dyn AgentSandbox>> {
        let sandboxes = self.sandboxes.read().await;
        sandboxes.get(agent_id).cloned()
    }

    /// Destroy a sandbox
    pub async fn destroy_sandbox(&self, agent_id: &AgentId) -> Result<(), Error> {
        let sandbox = {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.remove(agent_id)
        };

        if let Some(sandbox) = sandbox {
            // Arc doesn't have get_mut, so we'd need interior mutability
            // In practice, use Arc<Mutex<T>> or have cleanup take &self
        }

        Ok(())
    }

    fn merge_config(&self, base: &IsolationConfig, overrides: Option<&IsolationConfig>) -> IsolationConfig {
        match overrides {
            Some(o) => IsolationConfig {
                level: o.level.clone(),
                filesystem: o.filesystem.clone(),
                network: o.network.clone(),
                resources: o.resources.clone(),
                process: o.process.clone(),
            },
            None => base.clone(),
        }
    }
}

/// No isolation sandbox
pub struct NoIsolationSandbox {
    agent_id: AgentId,
    config: IsolationConfig,
}

impl NoIsolationSandbox {
    pub fn new(agent_id: AgentId, config: IsolationConfig) -> Self {
        tracing::warn!(agent_id = %agent_id, "Creating sandbox without isolation!");
        Self { agent_id, config }
    }
}

#[async_trait]
impl AgentSandbox for NoIsolationSandbox {
    fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    fn level(&self) -> IsolationLevel {
        IsolationLevel::None
    }

    async fn initialize(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn exec(
        &self,
        command: &str,
        args: &[String],
        options: Option<ExecOptions>,
    ) -> Result<ExecResult, Error> {
        use tokio::process::Command;

        let options = options.unwrap_or_default();

        let mut cmd = Command::new(command);
        cmd.args(args);

        if let Some(cwd) = &options.cwd {
            cmd.current_dir(cwd);
        }

        for (k, v) in &options.env {
            cmd.env(k, v);
        }

        let output = cmd.output().await?;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            timed_out: false,
            resource_usage: None,
        })
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, Error> {
        Ok(tokio::fs::read(path).await?)
    }

    async fn write_file(&self, path: &str, content: &[u8]) -> Result<(), Error> {
        Ok(tokio::fs::write(path, content).await?)
    }

    async fn is_path_accessible(&self, path: &str, mode: AccessMode) -> Result<bool, Error> {
        let metadata = tokio::fs::metadata(path).await;
        Ok(metadata.is_ok())
    }

    async fn get_resource_usage(&self) -> Result<ResourceUsage, Error> {
        Ok(ResourceUsage::default())
    }

    async fn cleanup(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Process isolation sandbox using Linux namespaces
pub struct ProcessIsolationSandbox {
    agent_id: AgentId,
    config: IsolationConfig,
    workspace_dir: PathBuf,
}

impl ProcessIsolationSandbox {
    pub async fn new(agent_id: AgentId, config: IsolationConfig) -> Result<Self, Error> {
        let workspace_dir = config.filesystem.workspace_root.join(&agent_id);
        tokio::fs::create_dir_all(&workspace_dir).await?;

        Ok(Self {
            agent_id,
            config,
            workspace_dir,
        })
    }

    fn validate_path(&self, path: &str) -> Result<PathBuf, Error> {
        use std::path::Path;

        let resolved = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.workspace_dir.join(path)
        };

        let canonical = resolved.canonicalize().unwrap_or(resolved.clone());

        // Check if within workspace
        if !canonical.starts_with(&self.workspace_dir) {
            return Err(Error::PathEscape(path.to_string()));
        }

        // Check blocked paths
        for blocked in &self.config.filesystem.blocked_paths {
            if canonical.starts_with(blocked) {
                return Err(Error::BlockedPath(path.to_string()));
            }
        }

        Ok(canonical)
    }
}

#[async_trait]
impl AgentSandbox for ProcessIsolationSandbox {
    fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    fn level(&self) -> IsolationLevel {
        IsolationLevel::Process
    }

    async fn initialize(&mut self) -> Result<(), Error> {
        // Set up cgroups for resource limits
        #[cfg(target_os = "linux")]
        {
            self.setup_cgroups().await?;
        }
        Ok(())
    }

    async fn exec(
        &self,
        command: &str,
        args: &[String],
        options: Option<ExecOptions>,
    ) -> Result<ExecResult, Error> {
        use tokio::process::Command;

        let options = options.unwrap_or_default();
        let cwd = options.cwd.unwrap_or_else(|| self.workspace_dir.to_string_lossy().to_string());

        // Validate working directory
        self.validate_path(&cwd)?;

        let mut cmd = Command::new(command);
        cmd.args(args)
            .current_dir(&cwd);

        // Set resource limits via cgroups/rlimits
        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                // Drop capabilities
                // Set up seccomp
                // Enter namespaces
                Ok(())
            });
        }

        for (k, v) in &options.env {
            cmd.env(k, v);
        }

        let output = if let Some(timeout) = options.timeout {
            tokio::time::timeout(timeout, cmd.output()).await
                .map_err(|_| Error::Timeout)?
        } else {
            cmd.output().await
        }?;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            timed_out: false,
            resource_usage: None,
        })
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, Error> {
        let validated = self.validate_path(path)?;
        Ok(tokio::fs::read(validated).await?)
    }

    async fn write_file(&self, path: &str, content: &[u8]) -> Result<(), Error> {
        let validated = self.validate_path(path)?;
        Ok(tokio::fs::write(validated, content).await?)
    }

    async fn is_path_accessible(&self, path: &str, _mode: AccessMode) -> Result<bool, Error> {
        match self.validate_path(path) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn get_resource_usage(&self) -> Result<ResourceUsage, Error> {
        // Read from cgroups
        Ok(ResourceUsage::default())
    }

    async fn cleanup(&mut self) -> Result<(), Error> {
        // Remove cgroups
        // Kill any remaining processes
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl ProcessIsolationSandbox {
    async fn setup_cgroups(&self) -> Result<(), Error> {
        // Create cgroup for this agent
        // Set memory/cpu limits
        Ok(())
    }
}

/// Container sandbox (placeholder - would integrate with Docker/containerd)
pub struct ContainerSandbox {
    agent_id: AgentId,
    config: IsolationConfig,
    container_id: Option<String>,
}

impl ContainerSandbox {
    pub async fn new(agent_id: AgentId, config: IsolationConfig) -> Result<Self, Error> {
        Ok(Self {
            agent_id,
            config,
            container_id: None,
        })
    }
}

#[async_trait]
impl AgentSandbox for ContainerSandbox {
    fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    fn level(&self) -> IsolationLevel {
        IsolationLevel::Container
    }

    async fn initialize(&mut self) -> Result<(), Error> {
        // Create and start container
        self.container_id = Some(format!("clawdstrike-{}", self.agent_id));
        Ok(())
    }

    async fn exec(
        &self,
        command: &str,
        args: &[String],
        _options: Option<ExecOptions>,
    ) -> Result<ExecResult, Error> {
        // docker exec
        todo!()
    }

    async fn read_file(&self, _path: &str) -> Result<Vec<u8>, Error> {
        // docker cp from container
        todo!()
    }

    async fn write_file(&self, _path: &str, _content: &[u8]) -> Result<(), Error> {
        // docker cp to container
        todo!()
    }

    async fn is_path_accessible(&self, _path: &str, _mode: AccessMode) -> Result<bool, Error> {
        todo!()
    }

    async fn get_resource_usage(&self) -> Result<ResourceUsage, Error> {
        // docker stats
        todo!()
    }

    async fn cleanup(&mut self) -> Result<(), Error> {
        // docker stop && docker rm
        Ok(())
    }
}

/// MicroVM sandbox (placeholder - would integrate with Firecracker/gVisor)
pub struct MicroVmSandbox {
    agent_id: AgentId,
    config: IsolationConfig,
}

impl MicroVmSandbox {
    pub async fn new(agent_id: AgentId, config: IsolationConfig) -> Result<Self, Error> {
        Ok(Self { agent_id, config })
    }
}

#[async_trait]
impl AgentSandbox for MicroVmSandbox {
    fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    fn level(&self) -> IsolationLevel {
        IsolationLevel::Vm
    }

    async fn initialize(&mut self) -> Result<(), Error> {
        // Start microVM
        todo!()
    }

    async fn exec(
        &self,
        _command: &str,
        _args: &[String],
        _options: Option<ExecOptions>,
    ) -> Result<ExecResult, Error> {
        todo!()
    }

    async fn read_file(&self, _path: &str) -> Result<Vec<u8>, Error> {
        todo!()
    }

    async fn write_file(&self, _path: &str, _content: &[u8]) -> Result<(), Error> {
        todo!()
    }

    async fn is_path_accessible(&self, _path: &str, _mode: AccessMode) -> Result<bool, Error> {
        todo!()
    }

    async fn get_resource_usage(&self) -> Result<ResourceUsage, Error> {
        todo!()
    }

    async fn cleanup(&mut self) -> Result<(), Error> {
        // Stop microVM
        todo!()
    }
}

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Path escape attempt: {0}")]
    PathEscape(String),
    #[error("Blocked path: {0}")]
    BlockedPath(String),
    #[error("Timeout")]
    Timeout,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Container error: {0}")]
    Container(String),
}
```

## Configuration Examples

### Minimal Process Isolation

```yaml
isolation:
  level: process

  filesystem:
    workspace_root: /var/clawdstrike/agents
    blocked_paths:
      - /etc/shadow
      - /etc/passwd
      - /root
      - ~/.ssh

  network:
    mode: host
    allowed_egress:
      - destination: "*"
        ports: [80, 443]
        protocol: tcp

  resources:
    memory_bytes: 536870912  # 512 MB
    pids_limit: 100
```

### Full Container Isolation

```yaml
isolation:
  level: container

  filesystem:
    workspace_root: /var/clawdstrike/agents
    read_only_mounts:
      - source: /usr/share/clawdstrike/runtimes
        target: /runtimes
    blocked_paths:
      - /proc/kcore
      - /sys/firmware
    use_overlay: true

  network:
    mode: isolated
    allowed_egress:
      - destination: api.github.com
        ports: [443]
        protocol: tcp
      - destination: api.openai.com
        ports: [443]
        protocol: tcp
    allow_inter_agent: false

  resources:
    memory_bytes: 1073741824  # 1 GB
    memory_swap_bytes: 0      # No swap
    cpu_quota: 100000         # 1 CPU
    cpu_period: 100000
    pids_limit: 50
    nofile_limit: 1024

  process:
    user: "65534"  # nobody
    group: "65534"
    drop_capabilities:
      - ALL
    capabilities:
      - NET_BIND_SERVICE
    seccomp_profile:
      default_action: SCMP_ACT_ERRNO
      syscalls:
        - names: [read, write, open, close, stat, fstat, lstat, poll, lseek, mmap, mprotect, munmap, brk, rt_sigaction, rt_sigprocmask, rt_sigreturn, ioctl, access, pipe, select, sched_yield, mremap, msync, mincore, madvise, shmget, shmat, shmctl, dup, dup2, pause, nanosleep, getitimer, alarm, setitimer, getpid, sendfile, socket, connect, accept, sendto, recvfrom, sendmsg, recvmsg, shutdown, bind, listen, getsockname, getpeername, socketpair, setsockopt, getsockopt, clone, fork, vfork, execve, exit, wait4, kill, uname, semget, semop, semctl, shmdt, msgget, msgsnd, msgrcv, msgctl, fcntl, flock, fsync, fdatasync, truncate, ftruncate, getdents, getcwd, chdir, fchdir, rename, mkdir, rmdir, creat, link, unlink, symlink, readlink, chmod, fchmod, chown, fchown, lchown, umask, gettimeofday, getrlimit, getrusage, sysinfo, times, ptrace, getuid, syslog, getgid, setuid, setgid, geteuid, getegid, setpgid, getppid, getpgrp, setsid, setreuid, setregid, getgroups, setgroups, setresuid, getresuid, setresgid, getresgid, getpgid, setfsuid, setfsgid, getsid, capget, capset, rt_sigpending, rt_sigtimedwait, rt_sigqueueinfo, rt_sigsuspend, sigaltstack, utime, mknod, uselib, personality, ustat, statfs, fstatfs, sysfs, getpriority, setpriority, sched_setparam, sched_getparam, sched_setscheduler, sched_getscheduler, sched_get_priority_max, sched_get_priority_min, sched_rr_get_interval, mlock, munlock, mlockall, munlockall, vhangup, modify_ldt, pivot_root, prctl, arch_prctl, adjtimex, setrlimit, chroot, sync, acct, settimeofday, mount, umount2, swapon, swapoff, reboot, sethostname, setdomainname, iopl, ioperm, create_module, init_module, delete_module, get_kernel_syms, query_module, quotactl, nfsservctl, getpmsg, putpmsg, afs_syscall, tuxcall, security, gettid, readahead, setxattr, lsetxattr, fsetxattr, getxattr, lgetxattr, fgetxattr, listxattr, llistxattr, flistxattr, removexattr, lremovexattr, fremovexattr, tkill, time, futex, sched_setaffinity, sched_getaffinity, set_thread_area, io_setup, io_destroy, io_getevents, io_submit, io_cancel, get_thread_area, lookup_dcookie, epoll_create, epoll_ctl_old, epoll_wait_old, remap_file_pages, getdents64, set_tid_address, restart_syscall, semtimedop, fadvise64, timer_create, timer_settime, timer_gettime, timer_getoverrun, timer_delete, clock_settime, clock_gettime, clock_getres, clock_nanosleep, exit_group, epoll_wait, epoll_ctl, tgkill, utimes, vserver, mbind, set_mempolicy, get_mempolicy, mq_open, mq_unlink, mq_timedsend, mq_timedreceive, mq_notify, mq_getsetattr, kexec_load, waitid, add_key, request_key, keyctl, ioprio_set, ioprio_get, inotify_init, inotify_add_watch, inotify_rm_watch, migrate_pages, openat, mkdirat, mknodat, fchownat, futimesat, newfstatat, unlinkat, renameat, linkat, symlinkat, readlinkat, fchmodat, faccessat, pselect6, ppoll, unshare, set_robust_list, get_robust_list, splice, tee, sync_file_range, vmsplice, move_pages, utimensat, epoll_pwait, signalfd, timerfd_create, eventfd, fallocate, timerfd_settime, timerfd_gettime, accept4, signalfd4, eventfd2, epoll_create1, dup3, pipe2, inotify_init1, preadv, pwritev, rt_tgsigqueueinfo, perf_event_open, recvmmsg, fanotify_init, fanotify_mark, prlimit64, name_to_handle_at, open_by_handle_at, clock_adjtime, syncfs, sendmmsg, setns, getcpu, process_vm_readv, process_vm_writev, kcmp, finit_module, sched_setattr, sched_getattr, renameat2, seccomp, getrandom, memfd_create, kexec_file_load, bpf, execveat, userfaultfd, membarrier, mlock2, copy_file_range, preadv2, pwritev2, pkey_mprotect, pkey_alloc, pkey_free, statx, io_pgetevents, rseq]
          action: SCMP_ACT_ALLOW
    namespaces:
      pid: true
      mount: true
      network: true
      user: true
      uts: true
      ipc: true
```

## Attack Scenarios and Mitigations

### Attack 1: Container Escape via Kernel Exploit

**Attack**: Agent exploits kernel vulnerability to escape container

**Mitigation**:
- Use gVisor/kata-containers for additional isolation
- Keep kernel updated
- Use seccomp to limit syscall surface
- Consider VM-level isolation for highest security

### Attack 2: Resource Exhaustion

**Attack**: Agent allocates all memory to crash other agents

**Mitigation**:
- Strict cgroup limits
- Memory limits with OOM killer
- CPU quotas
- PID limits

### Attack 3: Filesystem Symlink Attack

**Attack**: Agent creates symlink from workspace to /etc/passwd

**Mitigation**:
- Resolve symlinks before path validation
- Mount workspace with `nosuid`, `nodev`
- Use overlayfs with proper restrictions

### Attack 4: Time-of-Check Time-of-Use (TOCTOU)

**Attack**: Agent replaces validated file between check and use

**Mitigation**:
- Open files with O_NOFOLLOW
- Use file descriptors instead of paths after validation
- Atomic operations where possible

## Implementation Phases

### Phase 1: Process Isolation
- Workspace directory isolation
- Basic path validation
- Resource limits via ulimit

### Phase 2: Linux Security Modules
- Seccomp profiles
- AppArmor/SELinux integration
- Capability dropping

### Phase 3: Container Integration
- Docker/containerd integration
- Network namespacing
- Overlay filesystem

### Phase 4: MicroVM Support
- Firecracker integration
- Kata containers
- Hardware-assisted isolation

## Trust Model and Assumptions

### Trusted
- Linux kernel (with security patches)
- Container runtime (Docker, containerd)
- Hypervisor (for VM isolation)
- Clawdstrike isolation controller

### Untrusted
- Agent code
- Agent-provided paths
- Agent-initiated network connections

### Security Invariants
1. **Path Containment**: All file operations within designated workspace
2. **Resource Bounds**: CPU, memory, PIDs within configured limits
3. **Network Isolation**: Only permitted egress destinations reachable
4. **Capability Minimization**: Only required capabilities granted
