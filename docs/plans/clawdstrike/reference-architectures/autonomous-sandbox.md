# Autonomous Agent Sandbox Reference Architecture

## Problem Statement

Organizations need to run AI agents that perform autonomous tasks (code generation, data processing, system administration) while preventing:

- Unauthorized system access
- Data exfiltration
- Resource exhaustion
- Escape from containment
- Cascading failures from agent errors

## Target Persona

- **Platform Engineers** building agent execution environments
- **ML Engineers** deploying autonomous agents
- **Security Architects** designing containment strategies
- **SRE Teams** managing agent infrastructure

## Architecture Diagram

```
+------------------------------------------------------------------+
|                    Sandbox Orchestrator                           |
|  +------------------------------------------------------------+  |
|  |  Policy Manager  |  Resource Allocator  |  Health Monitor  |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
              |                    |                    |
              v                    v                    v
+------------------------------------------------------------------+
|                    Sandbox Instances                              |
|  +-----------------+  +-----------------+  +-----------------+   |
|  | Sandbox A       |  | Sandbox B       |  | Sandbox C       |   |
|  | +-------------+ |  | +-------------+ |  | +-------------+ |   |
|  | | Agent       | |  | | Agent       | |  | | Agent       | |   |
|  | +------+------+ |  | +------+------+ |  | +------+------+ |   |
|  |        |        |  |        |        |  |        |        |   |
|  | +------v------+ |  | +------v------+ |  | +------v------+ |   |
|  | | IRM Router  | |  | | IRM Router  | |  | | IRM Router  | |   |
|  | | - FS IRM    | |  | | - FS IRM    | |  | | - FS IRM    | |   |
|  | | - Net IRM   | |  | | - Net IRM   | |  | | - Net IRM   | |   |
|  | | - Exec IRM  | |  | | - Exec IRM  | |  | | - Exec IRM  | |   |
|  | +------+------+ |  | +------+------+ |  | +------+------+ |   |
|  |        |        |  |        |        |  |        |        |   |
|  | +------v------+ |  | +------v------+ |  | +------v------+ |   |
|  | | Capability  | |  | | Capability  | |  | | Capability  | |   |
|  | | Broker      | |  | | Broker      | |  | | Broker      | |   |
|  | +-------------+ |  | +-------------+ |  | +-------------+ |   |
|  +-----------------+  +-----------------+  +-----------------+   |
+------------------------------------------------------------------+
              |                    |                    |
              v                    v                    v
+------------------------------------------------------------------+
|                    Host System (Isolated)                         |
|  +---------------+  +---------------+  +------------------+      |
|  | Filesystem    |  | Network       |  | Process          |      |
|  | (Namespaced)  |  | (Filtered)    |  | (Cgroup Limited) |      |
|  +---------------+  +---------------+  +------------------+      |
+------------------------------------------------------------------+
```

## Component Breakdown

### 1. Sandbox Core (Rust)

```rust
// sandbox-core/src/lib.rs
use clawdstrike::{
    Decision, HushEngine, IrmRouter, Policy, Sandbox as IrmSandbox,
    SandboxConfig, Monitor, HostCall, EventType,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

/// Resource limits for a sandbox
#[derive(Clone, Debug)]
pub struct ResourceLimits {
    /// Maximum memory in bytes
    pub max_memory_bytes: u64,
    /// Maximum CPU time in milliseconds
    pub max_cpu_ms: u64,
    /// Maximum number of open files
    pub max_open_files: u32,
    /// Maximum network bandwidth (bytes/sec)
    pub max_bandwidth_bps: u64,
    /// Maximum number of processes
    pub max_processes: u32,
    /// Maximum disk space in bytes
    pub max_disk_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 512 * 1024 * 1024,  // 512MB
            max_cpu_ms: 60_000,                    // 1 minute
            max_open_files: 100,
            max_bandwidth_bps: 10 * 1024 * 1024,  // 10MB/s
            max_processes: 10,
            max_disk_bytes: 1024 * 1024 * 1024,   // 1GB
        }
    }
}

/// Capability that can be granted to a sandbox
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Read from specific paths
    FileRead(Vec<String>),
    /// Write to specific paths
    FileWrite(Vec<String>),
    /// Connect to specific hosts
    NetworkEgress(Vec<String>),
    /// Execute specific commands
    ProcessExec(Vec<String>),
    /// Access environment variables
    EnvAccess(Vec<String>),
    /// Access specific MCP tools
    McpTool(Vec<String>),
}

/// Sandbox instance
pub struct AutonomousSandbox {
    /// Unique sandbox ID
    pub id: String,
    /// Security policy
    policy: Policy,
    /// IRM-based sandbox
    irm_sandbox: IrmSandbox,
    /// Granted capabilities
    capabilities: Arc<RwLock<Vec<Capability>>>,
    /// Resource limits
    limits: ResourceLimits,
    /// Resource usage tracking
    usage: Arc<RwLock<ResourceUsage>>,
    /// Concurrency limiter
    concurrency: Arc<Semaphore>,
    /// Workspace root
    workspace: String,
}

#[derive(Default)]
struct ResourceUsage {
    memory_bytes: u64,
    cpu_ms: u64,
    open_files: u32,
    bytes_sent: u64,
    bytes_received: u64,
    disk_bytes: u64,
}

impl AutonomousSandbox {
    /// Create a new sandbox with policy and limits
    pub fn new(
        policy: Policy,
        limits: ResourceLimits,
        workspace: String,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();

        let config = SandboxConfig {
            fail_fast: true,
            max_events: 10000,
            emit_telemetry: true,
        };

        let irm_sandbox = IrmSandbox::with_config(policy.clone(), config);

        Self {
            id,
            policy,
            irm_sandbox,
            capabilities: Arc::new(RwLock::new(Vec::new())),
            limits,
            usage: Arc::new(RwLock::new(ResourceUsage::default())),
            concurrency: Arc::new(Semaphore::new(10)),
            workspace,
        }
    }

    /// Initialize the sandbox
    pub async fn init(&self) -> anyhow::Result<()> {
        self.irm_sandbox.init().await?;

        // Set up workspace directory
        tokio::fs::create_dir_all(&self.workspace).await?;

        tracing::info!(
            sandbox_id = %self.id,
            workspace = %self.workspace,
            "Sandbox initialized"
        );

        Ok(())
    }

    /// Grant a capability to the sandbox
    pub async fn grant_capability(&self, cap: Capability) {
        let mut caps = self.capabilities.write().await;
        if !caps.contains(&cap) {
            caps.push(cap);
        }
    }

    /// Revoke a capability
    pub async fn revoke_capability(&self, cap: &Capability) {
        let mut caps = self.capabilities.write().await;
        caps.retain(|c| c != cap);
    }

    /// Check if sandbox has a capability
    pub async fn has_capability(&self, cap: &Capability) -> bool {
        let caps = self.capabilities.read().await;
        caps.iter().any(|c| self.capability_matches(c, cap))
    }

    fn capability_matches(&self, granted: &Capability, requested: &Capability) -> bool {
        match (granted, requested) {
            (Capability::FileRead(allowed), Capability::FileRead(requested)) => {
                requested.iter().all(|r| {
                    allowed.iter().any(|a| self.path_matches(a, r))
                })
            }
            (Capability::FileWrite(allowed), Capability::FileWrite(requested)) => {
                requested.iter().all(|r| {
                    allowed.iter().any(|a| self.path_matches(a, r))
                })
            }
            (Capability::NetworkEgress(allowed), Capability::NetworkEgress(requested)) => {
                requested.iter().all(|r| {
                    allowed.iter().any(|a| self.host_matches(a, r))
                })
            }
            _ => granted == requested,
        }
    }

    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        glob::Pattern::new(pattern)
            .map(|p| p.matches(path))
            .unwrap_or(false)
    }

    fn host_matches(&self, pattern: &str, host: &str) -> bool {
        if pattern.starts_with("*.") {
            host.ends_with(&pattern[1..])
        } else {
            pattern == host
        }
    }

    /// Check and potentially execute a file read
    pub async fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        // Check resource limits
        self.check_resources().await?;

        // Acquire concurrency permit
        let _permit = self.concurrency.acquire().await?;

        // Check capability
        if !self.has_capability(&Capability::FileRead(vec![path.to_string()])).await {
            return Err(anyhow::anyhow!(
                "Sandbox lacks FileRead capability for: {}",
                path
            ));
        }

        // Check IRM policy
        let decision = self.irm_sandbox.check_fs(path, false).await?;
        if !decision.is_allowed() {
            return Err(anyhow::anyhow!(
                "IRM denied file read: {:?}",
                decision
            ));
        }

        // Resolve to workspace-relative path
        let full_path = self.resolve_path(path)?;

        // Read file
        let content = tokio::fs::read(&full_path).await?;

        // Update usage
        {
            let mut usage = self.usage.write().await;
            usage.open_files += 1;
        }

        Ok(content)
    }

    /// Check and potentially execute a file write
    pub async fn write_file(&self, path: &str, content: &[u8]) -> anyhow::Result<()> {
        self.check_resources().await?;
        let _permit = self.concurrency.acquire().await?;

        // Check capability
        if !self.has_capability(&Capability::FileWrite(vec![path.to_string()])).await {
            return Err(anyhow::anyhow!(
                "Sandbox lacks FileWrite capability for: {}",
                path
            ));
        }

        // Check IRM policy
        let decision = self.irm_sandbox.check_fs(path, true).await?;
        if !decision.is_allowed() {
            return Err(anyhow::anyhow!(
                "IRM denied file write: {:?}",
                decision
            ));
        }

        // Check disk space
        {
            let usage = self.usage.read().await;
            if usage.disk_bytes + content.len() as u64 > self.limits.max_disk_bytes {
                return Err(anyhow::anyhow!("Disk quota exceeded"));
            }
        }

        // Resolve path and write
        let full_path = self.resolve_path(path)?;

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&full_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&full_path, content).await?;

        // Update usage
        {
            let mut usage = self.usage.write().await;
            usage.disk_bytes += content.len() as u64;
        }

        Ok(())
    }

    /// Check and potentially execute a network request
    pub async fn http_request(
        &self,
        url: &str,
        method: &str,
        body: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        self.check_resources().await?;
        let _permit = self.concurrency.acquire().await?;

        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().ok_or_else(|| anyhow::anyhow!("Invalid URL"))?;
        let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

        // Check capability
        if !self.has_capability(&Capability::NetworkEgress(vec![host.to_string()])).await {
            return Err(anyhow::anyhow!(
                "Sandbox lacks NetworkEgress capability for: {}",
                host
            ));
        }

        // Check IRM policy
        let decision = self.irm_sandbox.check_net(host, port).await?;
        if !decision.is_allowed() {
            return Err(anyhow::anyhow!(
                "IRM denied network egress: {:?}",
                decision
            ));
        }

        // Check bandwidth
        let body_len = body.map(|b| b.len()).unwrap_or(0);
        {
            let usage = self.usage.read().await;
            // Simple rate check - in production, use token bucket
            if usage.bytes_sent > self.limits.max_bandwidth_bps * 60 {
                return Err(anyhow::anyhow!("Bandwidth limit exceeded"));
            }
        }

        // Make request
        let client = reqwest::Client::new();
        let mut request = client.request(
            method.parse()?,
            url,
        );

        if let Some(body) = body {
            request = request.body(body.to_vec());
        }

        let response = request.send().await?;
        let bytes = response.bytes().await?;

        // Update usage
        {
            let mut usage = self.usage.write().await;
            usage.bytes_sent += body_len as u64;
            usage.bytes_received += bytes.len() as u64;
        }

        Ok(bytes.to_vec())
    }

    /// Execute a command within the sandbox
    pub async fn exec_command(
        &self,
        command: &str,
        args: &[String],
    ) -> anyhow::Result<String> {
        self.check_resources().await?;
        let _permit = self.concurrency.acquire().await?;

        // Check capability
        if !self.has_capability(&Capability::ProcessExec(vec![command.to_string()])).await {
            return Err(anyhow::anyhow!(
                "Sandbox lacks ProcessExec capability for: {}",
                command
            ));
        }

        // Check IRM policy
        let decision = self.irm_sandbox.check_exec(command, args).await?;
        if !decision.is_allowed() {
            return Err(anyhow::anyhow!(
                "IRM denied command execution: {:?}",
                decision
            ));
        }

        // Execute with timeout
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::process::Command::new(command)
                .args(args)
                .current_dir(&self.workspace)
                .output(),
        )
        .await??;

        // Update CPU usage estimate
        {
            let mut usage = self.usage.write().await;
            usage.cpu_ms += 1000; // Rough estimate
        }

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(anyhow::anyhow!(
                "Command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    fn resolve_path(&self, path: &str) -> anyhow::Result<String> {
        let path = std::path::Path::new(path);

        // Prevent path traversal
        if path.is_absolute() {
            return Err(anyhow::anyhow!("Absolute paths not allowed"));
        }

        let full_path = std::path::Path::new(&self.workspace).join(path);
        let canonical = full_path.canonicalize().unwrap_or(full_path.clone());

        // Ensure path is within workspace
        if !canonical.starts_with(&self.workspace) {
            return Err(anyhow::anyhow!("Path traversal detected"));
        }

        Ok(canonical.to_string_lossy().to_string())
    }

    async fn check_resources(&self) -> anyhow::Result<()> {
        let usage = self.usage.read().await;

        if usage.memory_bytes > self.limits.max_memory_bytes {
            return Err(anyhow::anyhow!("Memory limit exceeded"));
        }

        if usage.cpu_ms > self.limits.max_cpu_ms {
            return Err(anyhow::anyhow!("CPU time limit exceeded"));
        }

        Ok(())
    }

    /// Get sandbox statistics
    pub async fn stats(&self) -> SandboxStats {
        let irm_stats = self.irm_sandbox.stats().await;
        let usage = self.usage.read().await;

        SandboxStats {
            sandbox_id: self.id.clone(),
            active: irm_stats.active,
            allowed_count: irm_stats.allowed_count,
            denied_count: irm_stats.denied_count,
            memory_bytes: usage.memory_bytes,
            cpu_ms: usage.cpu_ms,
            disk_bytes: usage.disk_bytes,
            bytes_sent: usage.bytes_sent,
            bytes_received: usage.bytes_received,
        }
    }

    /// Cleanup the sandbox
    pub async fn cleanup(&self) -> anyhow::Result<()> {
        self.irm_sandbox.cleanup().await?;

        // Remove workspace
        if std::path::Path::new(&self.workspace).exists() {
            tokio::fs::remove_dir_all(&self.workspace).await?;
        }

        tracing::info!(sandbox_id = %self.id, "Sandbox cleaned up");
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SandboxStats {
    pub sandbox_id: String,
    pub active: bool,
    pub allowed_count: u64,
    pub denied_count: u64,
    pub memory_bytes: u64,
    pub cpu_ms: u64,
    pub disk_bytes: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
```

### 2. Sandbox Orchestrator

```rust
// orchestrator/src/lib.rs
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct SandboxOrchestrator {
    sandboxes: Arc<RwLock<HashMap<String, Arc<AutonomousSandbox>>>>,
    policy_manager: PolicyManager,
    resource_pool: ResourcePool,
    max_concurrent: usize,
}

impl SandboxOrchestrator {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
            policy_manager: PolicyManager::new(),
            resource_pool: ResourcePool::new(),
            max_concurrent,
        }
    }

    /// Create a new sandbox
    pub async fn create_sandbox(
        &self,
        request: CreateSandboxRequest,
    ) -> anyhow::Result<String> {
        // Check concurrent limit
        let sandboxes = self.sandboxes.read().await;
        if sandboxes.len() >= self.max_concurrent {
            return Err(anyhow::anyhow!("Maximum concurrent sandboxes reached"));
        }
        drop(sandboxes);

        // Load policy
        let policy = self.policy_manager.load_policy(&request.policy_name)?;

        // Allocate resources
        let limits = self.resource_pool.allocate(request.resource_class)?;

        // Create workspace
        let workspace = format!("/tmp/sandboxes/{}", uuid::Uuid::new_v4());

        // Create sandbox
        let sandbox = AutonomousSandbox::new(policy, limits, workspace);
        sandbox.init().await?;

        // Grant initial capabilities
        for cap in request.capabilities {
            sandbox.grant_capability(cap).await;
        }

        let sandbox_id = sandbox.id.clone();
        let sandbox = Arc::new(sandbox);

        // Register
        let mut sandboxes = self.sandboxes.write().await;
        sandboxes.insert(sandbox_id.clone(), sandbox);

        Ok(sandbox_id)
    }

    /// Get a sandbox by ID
    pub async fn get_sandbox(&self, id: &str) -> Option<Arc<AutonomousSandbox>> {
        let sandboxes = self.sandboxes.read().await;
        sandboxes.get(id).cloned()
    }

    /// Destroy a sandbox
    pub async fn destroy_sandbox(&self, id: &str) -> anyhow::Result<()> {
        let mut sandboxes = self.sandboxes.write().await;
        if let Some(sandbox) = sandboxes.remove(id) {
            sandbox.cleanup().await?;
            self.resource_pool.release(&sandbox.limits);
        }
        Ok(())
    }

    /// List all sandboxes
    pub async fn list_sandboxes(&self) -> Vec<SandboxInfo> {
        let sandboxes = self.sandboxes.read().await;
        let mut infos = Vec::new();

        for (id, sandbox) in sandboxes.iter() {
            let stats = sandbox.stats().await;
            infos.push(SandboxInfo {
                id: id.clone(),
                stats,
            });
        }

        infos
    }

    /// Health check all sandboxes
    pub async fn health_check(&self) -> HealthReport {
        let sandboxes = self.sandboxes.read().await;
        let mut unhealthy = Vec::new();

        for (id, sandbox) in sandboxes.iter() {
            let stats = sandbox.stats().await;

            // Check for issues
            if stats.denied_count > 100 {
                unhealthy.push(id.clone());
            }
            if stats.cpu_ms > 50000 {
                unhealthy.push(id.clone());
            }
        }

        HealthReport {
            total: sandboxes.len(),
            healthy: sandboxes.len() - unhealthy.len(),
            unhealthy,
        }
    }
}

#[derive(Clone)]
pub struct CreateSandboxRequest {
    pub policy_name: String,
    pub resource_class: ResourceClass,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone)]
pub enum ResourceClass {
    Small,   // 256MB, 30s CPU
    Medium,  // 512MB, 60s CPU
    Large,   // 1GB, 120s CPU
}

pub struct SandboxInfo {
    pub id: String,
    pub stats: SandboxStats,
}

pub struct HealthReport {
    pub total: usize,
    pub healthy: usize,
    pub unhealthy: Vec<String>,
}
```

### 3. HTTP API for Sandbox Management

```rust
// api/src/main.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    orchestrator: Arc<SandboxOrchestrator>,
}

#[tokio::main]
async fn main() {
    let orchestrator = Arc::new(SandboxOrchestrator::new(100));

    let state = AppState { orchestrator };

    let app = Router::new()
        .route("/sandboxes", post(create_sandbox))
        .route("/sandboxes", get(list_sandboxes))
        .route("/sandboxes/:id", get(get_sandbox))
        .route("/sandboxes/:id", delete(destroy_sandbox))
        .route("/sandboxes/:id/exec", post(exec_in_sandbox))
        .route("/sandboxes/:id/read", post(read_file_in_sandbox))
        .route("/sandboxes/:id/write", post(write_file_in_sandbox))
        .route("/health", get(health_check))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct CreateSandboxBody {
    policy: String,
    resource_class: String,
    capabilities: Vec<CapabilityBody>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum CapabilityBody {
    #[serde(rename = "file_read")]
    FileRead { paths: Vec<String> },
    #[serde(rename = "file_write")]
    FileWrite { paths: Vec<String> },
    #[serde(rename = "network")]
    Network { hosts: Vec<String> },
    #[serde(rename = "exec")]
    Exec { commands: Vec<String> },
}

async fn create_sandbox(
    State(state): State<AppState>,
    Json(body): Json<CreateSandboxBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let resource_class = match body.resource_class.as_str() {
        "small" => ResourceClass::Small,
        "medium" => ResourceClass::Medium,
        "large" => ResourceClass::Large,
        _ => return Err((StatusCode::BAD_REQUEST, "Invalid resource class".into())),
    };

    let capabilities: Vec<Capability> = body
        .capabilities
        .into_iter()
        .map(|c| match c {
            CapabilityBody::FileRead { paths } => Capability::FileRead(paths),
            CapabilityBody::FileWrite { paths } => Capability::FileWrite(paths),
            CapabilityBody::Network { hosts } => Capability::NetworkEgress(hosts),
            CapabilityBody::Exec { commands } => Capability::ProcessExec(commands),
        })
        .collect();

    let request = CreateSandboxRequest {
        policy_name: body.policy,
        resource_class,
        capabilities,
    };

    let sandbox_id = state
        .orchestrator
        .create_sandbox(request)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "sandbox_id": sandbox_id })))
}

#[derive(Deserialize)]
struct ExecBody {
    command: String,
    args: Vec<String>,
}

async fn exec_in_sandbox(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ExecBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let sandbox = state
        .orchestrator
        .get_sandbox(&id)
        .await
        .ok_or((StatusCode::NOT_FOUND, "Sandbox not found".into()))?;

    let output = sandbox
        .exec_command(&body.command, &body.args)
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;

    Ok(Json(serde_json::json!({ "output": output })))
}

async fn health_check(
    State(state): State<AppState>,
) -> Json<HealthReport> {
    Json(state.orchestrator.health_check().await)
}
```

### 4. Container-Based Isolation (Optional)

```dockerfile
# Dockerfile.sandbox
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release --bin sandbox-agent

FROM debian:bookworm-slim

# Create non-root user
RUN useradd -m -u 1000 sandbox

# Install minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /app/target/release/sandbox-agent /usr/local/bin/

# Set up workspace
RUN mkdir -p /workspace && chown sandbox:sandbox /workspace
VOLUME /workspace

# Drop privileges
USER sandbox
WORKDIR /workspace

# Resource limits via cgroups (set at runtime)
# Memory: --memory=512m
# CPU: --cpus=1
# No network by default: --network=none

ENTRYPOINT ["/usr/local/bin/sandbox-agent"]
```

```yaml
# kubernetes/sandbox-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: sandbox-${SANDBOX_ID}
  labels:
    app: clawdstrike-sandbox
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: sandbox
    image: clawdstrike/sandbox-agent:latest
    resources:
      limits:
        memory: "512Mi"
        cpu: "1000m"
      requests:
        memory: "256Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    volumeMounts:
    - name: workspace
      mountPath: /workspace
    - name: policy
      mountPath: /etc/clawdstrike
      readOnly: true

  volumes:
  - name: workspace
    emptyDir:
      sizeLimit: 1Gi
  - name: policy
    configMap:
      name: sandbox-policy

  # Network policy for egress control
  # Applied via NetworkPolicy resource

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-network-policy
spec:
  podSelector:
    matchLabels:
      app: clawdstrike-sandbox
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
    ports:
    - protocol: TCP
      port: 443
```

## Security Considerations

### 1. Defense in Depth

```
Layer 1: Capability System (Clawdstrike)
    |
    v
Layer 2: IRM Policy Enforcement
    |
    v
Layer 3: Container Isolation (Docker/K8s)
    |
    v
Layer 4: Host Security (Seccomp, AppArmor)
    |
    v
Layer 5: Network Segmentation
```

### 2. Escape Prevention

```rust
// Additional escape prevention checks
impl AutonomousSandbox {
    fn validate_no_escape(&self, path: &str) -> anyhow::Result<()> {
        // Check for symlink attacks
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(path)?;
            if !target.starts_with(&self.workspace) {
                return Err(anyhow::anyhow!("Symlink escape attempt detected"));
            }
        }

        // Check for special files
        if path.contains("/dev/") || path.contains("/proc/") || path.contains("/sys/") {
            return Err(anyhow::anyhow!("Access to special filesystems denied"));
        }

        // Check for FIFO/socket
        if metadata.file_type().is_fifo() || metadata.file_type().is_socket() {
            return Err(anyhow::anyhow!("Access to special files denied"));
        }

        Ok(())
    }
}
```

### 3. Audit Trail

```rust
// Complete audit logging
#[derive(Serialize)]
struct AuditEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    sandbox_id: String,
    operation: String,
    target: String,
    decision: String,
    reason: Option<String>,
    capabilities_used: Vec<String>,
}

impl AutonomousSandbox {
    async fn audit_log(&self, entry: AuditEntry) {
        // Write to append-only audit log
        // In production, use a secure audit backend
        tracing::info!(
            sandbox_id = %entry.sandbox_id,
            operation = %entry.operation,
            target = %entry.target,
            decision = %entry.decision,
            "Sandbox audit"
        );
    }
}
```

## Scaling Considerations

### Horizontal Scaling

```
                    Load Balancer
                          |
        +-----------------+-----------------+
        |                 |                 |
        v                 v                 v
+---------------+ +---------------+ +---------------+
| Orchestrator  | | Orchestrator  | | Orchestrator  |
| Node 1        | | Node 2        | | Node 3        |
| [50 sandboxes]| | [50 sandboxes]| | [50 sandboxes]|
+---------------+ +---------------+ +---------------+
        |                 |                 |
        v                 v                 v
+--------------------------------------------------+
|              Shared State (Redis/etcd)            |
+--------------------------------------------------+
```

### Resource Allocation

| Class | Memory | CPU | Network | Max Duration |
|-------|--------|-----|---------|--------------|
| Small | 256MB | 30s | 1MB/s | 5 minutes |
| Medium | 512MB | 60s | 10MB/s | 15 minutes |
| Large | 1GB | 120s | 50MB/s | 30 minutes |
| XLarge | 4GB | 300s | 100MB/s | 60 minutes |

## Cost Considerations

### Cloud Costs (per 1000 sandbox-hours)

| Provider | Small | Medium | Large |
|----------|-------|--------|-------|
| AWS (Fargate) | $5 | $10 | $20 |
| GCP (Cloud Run) | $4 | $8 | $16 |
| Self-hosted (K8s) | $2 | $4 | $8 |

### Optimization Tips

1. **Pool warm sandboxes** - Pre-create sandboxes for faster startup
2. **Reuse sandboxes** - Reset state instead of destroy/create
3. **Right-size resources** - Start small, scale up on demand
4. **Spot instances** - Use preemptible compute for non-critical workloads

## Step-by-Step Implementation Guide

### Phase 1: Core Sandbox (Week 1)

1. **Implement AutonomousSandbox**
   ```bash
   cargo new sandbox-core
   cd sandbox-core
   cargo add clawdstrike tokio uuid anyhow
   ```

2. **Write basic tests**
   ```rust
   #[tokio::test]
   async fn test_sandbox_file_ops() {
       let sandbox = create_test_sandbox().await;
       sandbox.grant_capability(Capability::FileWrite(vec!["**".to_string()])).await;

       sandbox.write_file("test.txt", b"hello").await.unwrap();
       let content = sandbox.read_file("test.txt").await.unwrap();
       assert_eq!(content, b"hello");
   }
   ```

### Phase 2: Orchestration (Week 2)

3. **Implement orchestrator**
   ```bash
   cargo new orchestrator
   cd orchestrator
   cargo add sandbox-core axum tokio serde
   ```

4. **Deploy API server**
   ```bash
   docker build -t sandbox-api .
   docker run -p 8080:8080 sandbox-api
   ```

### Phase 3: Production Hardening (Week 3-4)

5. **Add container isolation**
   ```bash
   kubectl apply -f kubernetes/sandbox-deployment.yaml
   kubectl apply -f kubernetes/network-policy.yaml
   ```

6. **Configure monitoring**
   ```yaml
   # prometheus/sandbox-rules.yaml
   groups:
   - name: sandbox-alerts
     rules:
     - alert: SandboxHighDenialRate
       expr: rate(sandbox_denied_total[5m]) > 10
       labels:
         severity: warning
   ```

## Common Pitfalls and Solutions

### Pitfall 1: Resource Exhaustion

**Problem**: Malicious agent consumes all available resources.

**Solution**: Strict per-sandbox limits with circuit breaker:
```rust
if usage.cpu_ms > limits.max_cpu_ms * 0.9 {
    // Warn and throttle
    self.throttle_operations().await;
}
if usage.cpu_ms > limits.max_cpu_ms {
    // Kill sandbox
    self.force_terminate().await;
}
```

### Pitfall 2: Time-of-Check-Time-of-Use (TOCTOU)

**Problem**: File changes between capability check and actual access.

**Solution**: Use atomic operations with locks:
```rust
let _lock = self.fs_lock.lock().await;
let decision = self.check_capability(path).await?;
let content = std::fs::read(path)?; // Atomic within lock
```

### Pitfall 3: Sandbox Accumulation

**Problem**: Orphaned sandboxes consume resources.

**Solution**: Implement TTL and garbage collection:
```rust
// Background task
loop {
    let sandboxes = orchestrator.list_sandboxes().await;
    for sandbox in sandboxes {
        if sandbox.stats.last_activity < Utc::now() - Duration::hours(1) {
            orchestrator.destroy_sandbox(&sandbox.id).await?;
        }
    }
    tokio::time::sleep(Duration::from_secs(60)).await;
}
```

### Pitfall 4: Capability Confusion

**Problem**: Granted capabilities are too broad.

**Solution**: Use principle of least privilege with templates:
```rust
// Pre-defined capability sets
pub fn web_scraper_capabilities() -> Vec<Capability> {
    vec![
        Capability::NetworkEgress(vec!["*.example.com".to_string()]),
        Capability::FileWrite(vec!["output/**".to_string()]),
    ]
}

pub fn code_analyzer_capabilities() -> Vec<Capability> {
    vec![
        Capability::FileRead(vec!["src/**".to_string()]),
        Capability::ProcessExec(vec!["grep".to_string(), "find".to_string()]),
    ]
}
```

## Troubleshooting

### Issue: Sandbox Initialization Failures

**Symptoms**: Sandboxes fail to start with workspace creation errors.

**Solutions**:
1. Verify `/tmp/sandboxes` base directory exists and has correct permissions
2. Check disk space availability on host system
3. Ensure container runtime has permission to create directories
4. Review IRM initialization logs for policy loading errors

### Issue: Capability Denials for Valid Operations

**Symptoms**: Agent operations blocked despite seemingly correct capabilities.

**Solutions**:
1. Use debug logging to see exact path/host being checked
2. Verify glob patterns match the intended paths (test with `glob::Pattern`)
3. Check capability order - more specific patterns should be listed first
4. Ensure capabilities are granted before operations are attempted

### Issue: Resource Limit Exceeded Prematurely

**Symptoms**: Sandboxes terminated before completing legitimate work.

**Solutions**:
1. Review resource usage patterns with `sandbox.stats()`
2. Consider using larger ResourceClass for resource-intensive workloads
3. Implement incremental checkpointing for long-running tasks
4. Check for memory leaks in agent code causing accumulation

### Issue: Sandbox Cleanup Not Completing

**Symptoms**: Orphaned workspace directories or zombie processes.

**Solutions**:
1. Ensure cleanup is called in all exit paths (use RAII patterns)
2. Add timeout to cleanup operations to prevent hangs
3. Implement background garbage collector for orphaned sandboxes
4. Check for file handles preventing directory removal

## Validation Checklist

- [ ] Sandbox cannot access files outside workspace
- [ ] Network egress is restricted to allowed hosts
- [ ] Command execution is limited to allowed commands
- [ ] Resource limits are enforced
- [ ] Audit log captures all operations
- [ ] Container isolation is verified
- [ ] Sandbox cleanup removes all resources
- [ ] Health checks detect stuck sandboxes
- [ ] Horizontal scaling works correctly
- [ ] Escape attempts are logged and blocked
