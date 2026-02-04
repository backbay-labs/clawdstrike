# Multi-Agent Orchestration Reference Architecture

## Problem Statement

Modern AI systems increasingly rely on multiple specialized agents working together. This creates unique security challenges:

- **Inter-agent trust**: How much should agents trust each other?
- **Privilege escalation**: Can a low-privilege agent manipulate a high-privilege one?
- **Information flow**: Can sensitive data leak between agents?
- **Coordination attacks**: Can agents be manipulated to coordinate maliciously?
- **Blast radius**: How do we contain failures in one agent?

## Target Persona

- **AI Platform Architects** designing multi-agent systems
- **Security Engineers** implementing zero-trust agent networks
- **ML Engineers** building agent collaboration pipelines
- **Enterprise Architects** governing AI agent deployments

## Architecture Diagram

```
+------------------------------------------------------------------------+
|                        Agent Orchestration Layer                        |
|  +------------------------------------------------------------------+  |
|  |                     Clawdstrike Control Plane                     |  |
|  |  +-------------+  +-------------+  +-------------+  +-----------+ |  |
|  |  | Policy      |  | Trust       |  | Message     |  | Audit     | |  |
|  |  | Manager     |  | Broker      |  | Router      |  | Logger    | |  |
|  |  +-------------+  +-------------+  +-------------+  +-----------+ |  |
|  +------------------------------------------------------------------+  |
+------------------------------------------------------------------------+
                                    |
         +----------------+---------+---------+----------------+
         |                |                   |                |
         v                v                   v                v
+----------------+ +----------------+ +----------------+ +----------------+
| Agent: Planner | | Agent: Coder   | | Agent: Tester  | | Agent: Deploy  |
| Trust: High    | | Trust: Medium  | | Trust: Medium  | | Trust: Low     |
| Caps: Plan     | | Caps: Code,FS  | | Caps: Exec     | | Caps: Deploy   |
+-------+--------+ +-------+--------+ +-------+--------+ +-------+--------+
        |                  |                  |                  |
        |                  |                  |                  |
        v                  v                  v                  v
+------------------------------------------------------------------------+
|                        Message Bus (NATS/Kafka)                         |
|  Topics: agent.tasks, agent.results, agent.events, agent.secrets       |
+------------------------------------------------------------------------+
                                    |
         +----------------+---------+---------+----------------+
         |                |                   |                |
         v                v                   v                v
+----------------+ +----------------+ +----------------+ +----------------+
| Sandbox A      | | Sandbox B      | | Sandbox C      | | Sandbox D      |
| (Planner)      | | (Coder)        | | (Tester)       | | (Deploy)       |
+----------------+ +----------------+ +----------------+ +----------------+
```

## Component Breakdown

### 1. Trust Model and Agent Identity

```rust
// trust/src/lib.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trust level determines what an agent can do
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Untrusted - minimal capabilities, heavy monitoring
    Untrusted = 0,
    /// Low - basic operations, no sensitive data
    Low = 1,
    /// Medium - standard operations, limited sensitive data
    Medium = 2,
    /// High - privileged operations, sensitive data access
    High = 3,
    /// System - full access, typically only for orchestrator
    System = 4,
}

/// Agent identity with cryptographic verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Unique agent ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Agent type/role
    pub role: AgentRole,
    /// Assigned trust level
    pub trust_level: TrustLevel,
    /// Public key for message signing
    pub public_key: Vec<u8>,
    /// Capabilities granted to this agent
    pub capabilities: Vec<AgentCapability>,
    /// Agent metadata
    pub metadata: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AgentRole {
    Planner,
    Coder,
    Tester,
    Reviewer,
    Deployer,
    Monitor,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentCapability {
    /// Can create tasks for other agents
    CreateTask { target_roles: Vec<AgentRole> },
    /// Can access files
    FileAccess { patterns: Vec<String>, write: bool },
    /// Can make network requests
    NetworkAccess { hosts: Vec<String> },
    /// Can execute commands
    CommandExec { commands: Vec<String> },
    /// Can access secrets
    SecretAccess { secret_names: Vec<String> },
    /// Can approve deployments
    DeployApproval,
    /// Can modify agent configuration
    AgentAdmin,
}

/// Trust broker manages agent identities and trust relationships
pub struct TrustBroker {
    agents: HashMap<String, AgentIdentity>,
    trust_relationships: HashMap<(String, String), TrustRelationship>,
    policy_engine: clawdstrike::HushEngine,
}

#[derive(Clone, Debug)]
pub struct TrustRelationship {
    /// Source agent
    pub from: String,
    /// Target agent
    pub to: String,
    /// Allowed message types
    pub allowed_messages: Vec<MessageType>,
    /// Data classification levels that can be shared
    pub data_sharing: DataClassification,
    /// Whether source can delegate tasks to target
    pub can_delegate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl TrustBroker {
    pub fn new(policy: clawdstrike::Policy) -> Self {
        Self {
            agents: HashMap::new(),
            trust_relationships: HashMap::new(),
            policy_engine: clawdstrike::HushEngine::with_policy(policy),
        }
    }

    /// Register a new agent
    pub fn register_agent(&mut self, identity: AgentIdentity) -> anyhow::Result<()> {
        // Validate agent identity
        self.validate_identity(&identity)?;

        // Store agent
        self.agents.insert(identity.id.clone(), identity);
        Ok(())
    }

    /// Establish trust relationship between agents
    pub fn establish_trust(
        &mut self,
        from: &str,
        to: &str,
        relationship: TrustRelationship,
    ) -> anyhow::Result<()> {
        let from_agent = self.agents.get(from)
            .ok_or_else(|| anyhow::anyhow!("Unknown agent: {}", from))?;
        let to_agent = self.agents.get(to)
            .ok_or_else(|| anyhow::anyhow!("Unknown agent: {}", to))?;

        // Verify trust level allows this relationship
        if relationship.can_delegate && from_agent.trust_level <= to_agent.trust_level {
            return Err(anyhow::anyhow!(
                "Cannot delegate from lower trust to higher trust"
            ));
        }

        self.trust_relationships.insert(
            (from.to_string(), to.to_string()),
            relationship,
        );

        Ok(())
    }

    /// Check if an agent can send a message to another
    pub fn can_communicate(
        &self,
        from: &str,
        to: &str,
        message_type: &MessageType,
    ) -> bool {
        if let Some(relationship) = self.trust_relationships.get(&(from.to_string(), to.to_string())) {
            relationship.allowed_messages.contains(message_type)
        } else {
            false
        }
    }

    /// Verify message signature
    pub fn verify_message(&self, message: &AgentMessage) -> anyhow::Result<bool> {
        let agent = self.agents.get(&message.from)
            .ok_or_else(|| anyhow::anyhow!("Unknown sender"))?;

        // Verify signature using agent's public key
        let signature = ed25519_dalek::Signature::from_bytes(&message.signature)?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(
            &agent.public_key.try_into().map_err(|_| anyhow::anyhow!("Invalid public key"))?
        )?;

        let payload = serde_json::to_vec(&message.payload)?;
        public_key.verify_strict(&payload, &signature)?;

        Ok(true)
    }

    fn validate_identity(&self, identity: &AgentIdentity) -> anyhow::Result<()> {
        // Ensure agent ID is unique
        if self.agents.contains_key(&identity.id) {
            return Err(anyhow::anyhow!("Agent ID already exists"));
        }

        // Validate capabilities match trust level
        for cap in &identity.capabilities {
            let required_trust = self.required_trust_for_capability(cap);
            if identity.trust_level < required_trust {
                return Err(anyhow::anyhow!(
                    "Capability {:?} requires trust level {:?}, agent has {:?}",
                    cap, required_trust, identity.trust_level
                ));
            }
        }

        Ok(())
    }

    fn required_trust_for_capability(&self, cap: &AgentCapability) -> TrustLevel {
        match cap {
            AgentCapability::CreateTask { .. } => TrustLevel::Medium,
            AgentCapability::FileAccess { write: true, .. } => TrustLevel::Medium,
            AgentCapability::FileAccess { write: false, .. } => TrustLevel::Low,
            AgentCapability::NetworkAccess { .. } => TrustLevel::Medium,
            AgentCapability::CommandExec { .. } => TrustLevel::High,
            AgentCapability::SecretAccess { .. } => TrustLevel::High,
            AgentCapability::DeployApproval => TrustLevel::High,
            AgentCapability::AgentAdmin => TrustLevel::System,
        }
    }
}
```

### 2. Secure Message Router

```rust
// router/src/lib.rs
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentMessage {
    /// Message ID
    pub id: String,
    /// Sender agent ID
    pub from: String,
    /// Recipient agent ID (or broadcast)
    pub to: MessageTarget,
    /// Message type
    pub message_type: MessageType,
    /// Message payload
    pub payload: serde_json::Value,
    /// Data classification
    pub classification: DataClassification,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Cryptographic signature
    pub signature: Vec<u8>,
    /// Message chain (for tracing delegation)
    pub chain: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageTarget {
    Agent(String),
    Role(AgentRole),
    Broadcast,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    TaskRequest,
    TaskResult,
    DataShare,
    SecretRequest,
    ApprovalRequest,
    ApprovalResponse,
    Heartbeat,
    Error,
}

pub struct MessageRouter {
    trust_broker: TrustBroker,
    agent_channels: HashMap<String, mpsc::Sender<AgentMessage>>,
    message_log: Vec<AgentMessage>,
    max_chain_length: usize,
}

impl MessageRouter {
    pub fn new(trust_broker: TrustBroker) -> Self {
        Self {
            trust_broker,
            agent_channels: HashMap::new(),
            message_log: Vec::new(),
            max_chain_length: 5,
        }
    }

    /// Register an agent's message channel
    pub fn register_channel(&mut self, agent_id: &str, channel: mpsc::Sender<AgentMessage>) {
        self.agent_channels.insert(agent_id.to_string(), channel);
    }

    /// Route a message with security checks
    pub async fn route_message(&mut self, message: AgentMessage) -> anyhow::Result<()> {
        // 1. Verify message signature
        self.trust_broker.verify_message(&message)?;

        // 2. Check chain length (prevent infinite delegation)
        if message.chain.len() > self.max_chain_length {
            return Err(anyhow::anyhow!("Message chain too long - possible delegation loop"));
        }

        // 3. Check trust relationship allows this message
        let recipients = self.resolve_target(&message.to);
        for recipient in &recipients {
            if !self.trust_broker.can_communicate(&message.from, recipient, &message.message_type) {
                tracing::warn!(
                    from = %message.from,
                    to = %recipient,
                    message_type = ?message.message_type,
                    "Blocked unauthorized inter-agent communication"
                );
                return Err(anyhow::anyhow!(
                    "Agent {} not authorized to send {:?} to {}",
                    message.from, message.message_type, recipient
                ));
            }
        }

        // 4. Validate data classification
        self.validate_data_sharing(&message)?;

        // 5. Sanitize payload based on recipient trust level
        let sanitized_messages = self.sanitize_for_recipients(&message, &recipients)?;

        // 6. Log message for audit
        self.message_log.push(message.clone());

        // 7. Deliver to recipients
        for (recipient, msg) in sanitized_messages {
            if let Some(channel) = self.agent_channels.get(&recipient) {
                channel.send(msg).await?;
            }
        }

        Ok(())
    }

    fn resolve_target(&self, target: &MessageTarget) -> Vec<String> {
        match target {
            MessageTarget::Agent(id) => vec![id.clone()],
            MessageTarget::Role(role) => {
                self.trust_broker.agents
                    .values()
                    .filter(|a| std::mem::discriminant(&a.role) == std::mem::discriminant(role))
                    .map(|a| a.id.clone())
                    .collect()
            }
            MessageTarget::Broadcast => {
                self.trust_broker.agents.keys().cloned().collect()
            }
        }
    }

    fn validate_data_sharing(&self, message: &AgentMessage) -> anyhow::Result<()> {
        let sender = self.trust_broker.agents.get(&message.from)
            .ok_or_else(|| anyhow::anyhow!("Unknown sender"))?;

        // Check if sender's trust level allows sending this classification
        let min_trust = match message.classification {
            DataClassification::Public => TrustLevel::Untrusted,
            DataClassification::Internal => TrustLevel::Low,
            DataClassification::Confidential => TrustLevel::Medium,
            DataClassification::Restricted => TrustLevel::High,
        };

        if sender.trust_level < min_trust {
            return Err(anyhow::anyhow!(
                "Agent trust level too low for data classification"
            ));
        }

        Ok(())
    }

    fn sanitize_for_recipients(
        &self,
        message: &AgentMessage,
        recipients: &[String],
    ) -> anyhow::Result<Vec<(String, AgentMessage)>> {
        let mut result = Vec::new();

        for recipient in recipients {
            let recipient_agent = self.trust_broker.agents.get(recipient)
                .ok_or_else(|| anyhow::anyhow!("Unknown recipient"))?;

            let mut sanitized = message.clone();

            // Redact fields based on recipient trust level
            if recipient_agent.trust_level < TrustLevel::High {
                // Remove sensitive fields from payload
                sanitized.payload = self.redact_sensitive_fields(&sanitized.payload);
            }

            result.push((recipient.clone(), sanitized));
        }

        Ok(result)
    }

    fn redact_sensitive_fields(&self, payload: &serde_json::Value) -> serde_json::Value {
        // Use Clawdstrike secret detection
        let payload_str = payload.to_string();
        let engine = clawdstrike::SecretLeakGuard::new();

        if engine.scan(payload_str.as_bytes()).is_empty() {
            payload.clone()
        } else {
            serde_json::json!({
                "redacted": true,
                "reason": "Contains sensitive data"
            })
        }
    }
}
```

### 3. Multi-Agent Workflow Engine

```rust
// workflow/src/lib.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Defines a multi-agent workflow
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    pub security_policy: WorkflowSecurityPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub agent_role: AgentRole,
    pub action: WorkflowAction,
    pub inputs: Vec<StepInput>,
    pub outputs: Vec<StepOutput>,
    pub requires_approval: bool,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkflowAction {
    GenerateCode { language: String, spec: String },
    ReviewCode { path: String },
    RunTests { test_command: String },
    Deploy { environment: String },
    Custom { action_type: String, params: serde_json::Value },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepInput {
    pub name: String,
    pub from_step: Option<String>,
    pub classification: DataClassification,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepOutput {
    pub name: String,
    pub classification: DataClassification,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowSecurityPolicy {
    /// Minimum trust level for workflow initiator
    pub initiator_trust: TrustLevel,
    /// Required approvals before deployment
    pub deployment_approvals: u32,
    /// Maximum workflow duration
    pub max_duration_secs: u64,
    /// Data classification ceiling
    pub max_data_classification: DataClassification,
    /// Allowed external network access
    pub allowed_egress: Vec<String>,
}

pub struct WorkflowEngine {
    router: MessageRouter,
    active_workflows: HashMap<String, WorkflowExecution>,
}

#[derive(Clone, Debug)]
pub struct WorkflowExecution {
    pub workflow: Workflow,
    pub status: WorkflowStatus,
    pub current_step: usize,
    pub step_results: HashMap<String, serde_json::Value>,
    pub approvals: Vec<Approval>,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub enum WorkflowStatus {
    Pending,
    Running,
    WaitingApproval,
    Completed,
    Failed(String),
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct Approval {
    pub step_id: String,
    pub approver_id: String,
    pub approved: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl WorkflowEngine {
    pub fn new(router: MessageRouter) -> Self {
        Self {
            router,
            active_workflows: HashMap::new(),
        }
    }

    /// Start a new workflow execution
    pub async fn start_workflow(
        &mut self,
        workflow: Workflow,
        initiator: &str,
    ) -> anyhow::Result<String> {
        // Validate initiator trust level
        let initiator_agent = self.router.trust_broker.agents.get(initiator)
            .ok_or_else(|| anyhow::anyhow!("Unknown initiator"))?;

        if initiator_agent.trust_level < workflow.security_policy.initiator_trust {
            return Err(anyhow::anyhow!(
                "Initiator trust level too low for this workflow"
            ));
        }

        let execution_id = uuid::Uuid::new_v4().to_string();

        let execution = WorkflowExecution {
            workflow: workflow.clone(),
            status: WorkflowStatus::Pending,
            current_step: 0,
            step_results: HashMap::new(),
            approvals: Vec::new(),
            started_at: chrono::Utc::now(),
        };

        self.active_workflows.insert(execution_id.clone(), execution);

        // Start first step
        self.execute_current_step(&execution_id).await?;

        Ok(execution_id)
    }

    async fn execute_current_step(&mut self, execution_id: &str) -> anyhow::Result<()> {
        let execution = self.active_workflows.get_mut(execution_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown workflow"))?;

        if execution.current_step >= execution.workflow.steps.len() {
            execution.status = WorkflowStatus::Completed;
            return Ok(());
        }

        let step = &execution.workflow.steps[execution.current_step];

        // Check if step requires approval
        if step.requires_approval {
            let approvals_needed = execution.workflow.security_policy.deployment_approvals as usize;
            let step_approvals: Vec<_> = execution.approvals.iter()
                .filter(|a| a.step_id == step.id && a.approved)
                .collect();

            if step_approvals.len() < approvals_needed {
                execution.status = WorkflowStatus::WaitingApproval;
                return Ok(());
            }
        }

        // Gather inputs from previous steps
        let mut inputs = serde_json::Map::new();
        for input in &step.inputs {
            if let Some(from_step) = &input.from_step {
                if let Some(result) = execution.step_results.get(from_step) {
                    inputs.insert(input.name.clone(), result.clone());
                }
            }
        }

        // Create task message for the agent
        let task = AgentMessage {
            id: uuid::Uuid::new_v4().to_string(),
            from: "workflow-engine".to_string(),
            to: MessageTarget::Role(step.agent_role.clone()),
            message_type: MessageType::TaskRequest,
            payload: serde_json::json!({
                "workflow_id": execution_id,
                "step_id": step.id,
                "action": step.action,
                "inputs": inputs,
            }),
            classification: execution.workflow.security_policy.max_data_classification,
            timestamp: chrono::Utc::now(),
            signature: vec![], // Sign in production
            chain: vec![],
        };

        execution.status = WorkflowStatus::Running;

        self.router.route_message(task).await?;

        Ok(())
    }

    /// Handle step completion
    pub async fn complete_step(
        &mut self,
        execution_id: &str,
        step_id: &str,
        result: serde_json::Value,
    ) -> anyhow::Result<()> {
        let execution = self.active_workflows.get_mut(execution_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown workflow"))?;

        // Verify step ID matches current step
        let current_step = &execution.workflow.steps[execution.current_step];
        if current_step.id != step_id {
            return Err(anyhow::anyhow!("Step ID mismatch"));
        }

        // Store result
        execution.step_results.insert(step_id.to_string(), result);

        // Move to next step
        execution.current_step += 1;

        // Execute next step
        self.execute_current_step(execution_id).await?;

        Ok(())
    }

    /// Add approval to a step
    pub async fn add_approval(
        &mut self,
        execution_id: &str,
        step_id: &str,
        approver_id: &str,
        approved: bool,
    ) -> anyhow::Result<()> {
        // Verify approver has approval capability
        let approver = self.router.trust_broker.agents.get(approver_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown approver"))?;

        let has_approval_cap = approver.capabilities.iter()
            .any(|c| matches!(c, AgentCapability::DeployApproval));

        if !has_approval_cap {
            return Err(anyhow::anyhow!("Agent lacks approval capability"));
        }

        let execution = self.active_workflows.get_mut(execution_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown workflow"))?;

        execution.approvals.push(Approval {
            step_id: step_id.to_string(),
            approver_id: approver_id.to_string(),
            approved,
            timestamp: chrono::Utc::now(),
        });

        // If workflow was waiting for approval, try to continue
        if matches!(execution.status, WorkflowStatus::WaitingApproval) {
            self.execute_current_step(execution_id).await?;
        }

        Ok(())
    }
}
```

### 4. Agent Implementation Example

```rust
// agents/coder/src/main.rs
use tokio::sync::mpsc;

struct CoderAgent {
    identity: AgentIdentity,
    sandbox: AutonomousSandbox,
    message_rx: mpsc::Receiver<AgentMessage>,
    router_tx: mpsc::Sender<AgentMessage>,
    signing_key: ed25519_dalek::SigningKey,
}

impl CoderAgent {
    pub async fn run(&mut self) {
        while let Some(message) = self.message_rx.recv().await {
            match self.handle_message(message).await {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "Failed to handle message");
                }
            }
        }
    }

    async fn handle_message(&mut self, message: AgentMessage) -> anyhow::Result<()> {
        match message.message_type {
            MessageType::TaskRequest => {
                self.handle_task_request(message).await?;
            }
            MessageType::SecretRequest => {
                // Coders shouldn't receive secret requests directly
                tracing::warn!("Received unexpected secret request");
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_task_request(&mut self, message: AgentMessage) -> anyhow::Result<()> {
        let action: WorkflowAction = serde_json::from_value(
            message.payload.get("action").cloned().unwrap_or_default()
        )?;

        match action {
            WorkflowAction::GenerateCode { language, spec } => {
                // Generate code using AI
                let code = self.generate_code(&language, &spec).await?;

                // Validate generated code with Clawdstrike
                let validation = self.validate_code(&code).await?;
                if !validation.passed {
                    return Err(anyhow::anyhow!("Generated code failed validation: {:?}", validation.issues));
                }

                // Write to sandbox
                let filename = format!("generated.{}", self.language_extension(&language));
                self.sandbox.write_file(&filename, code.as_bytes()).await?;

                // Send result
                let result = AgentMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    from: self.identity.id.clone(),
                    to: MessageTarget::Agent("workflow-engine".to_string()),
                    message_type: MessageType::TaskResult,
                    payload: serde_json::json!({
                        "workflow_id": message.payload.get("workflow_id"),
                        "step_id": message.payload.get("step_id"),
                        "output": {
                            "file": filename,
                            "code_hash": sha256(&code),
                        }
                    }),
                    classification: DataClassification::Internal,
                    timestamp: chrono::Utc::now(),
                    signature: self.sign_payload(&message.payload),
                    chain: {
                        let mut chain = message.chain.clone();
                        chain.push(self.identity.id.clone());
                        chain
                    },
                };

                self.router_tx.send(result).await?;
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported action for coder agent"));
            }
        }

        Ok(())
    }

    async fn validate_code(&self, code: &str) -> anyhow::Result<CodeValidation> {
        let engine = clawdstrike::HushEngine::new();
        let ctx = clawdstrike::GuardContext::new();

        // Check for dangerous patterns
        let patch_result = engine.check_patch("generated.code", code, &ctx).await?;

        let mut issues = Vec::new();
        if !patch_result.allowed {
            issues.push(patch_result.message);
        }

        // Check for secrets
        let secret_guard = clawdstrike::SecretLeakGuard::new();
        let secrets = secret_guard.scan(code.as_bytes());
        for secret in secrets {
            issues.push(format!("Detected secret: {}", secret.pattern_name));
        }

        Ok(CodeValidation {
            passed: issues.is_empty(),
            issues,
        })
    }

    fn sign_payload(&self, payload: &serde_json::Value) -> Vec<u8> {
        let bytes = serde_json::to_vec(payload).unwrap();
        let signature = self.signing_key.sign(&bytes);
        signature.to_bytes().to_vec()
    }
}

struct CodeValidation {
    passed: bool,
    issues: Vec<String>,
}
```

### 5. Coordination Attack Prevention

```rust
// prevention/src/lib.rs

/// Detects potential coordination attacks between agents
pub struct CoordinationMonitor {
    message_history: Vec<(chrono::DateTime<chrono::Utc>, AgentMessage)>,
    anomaly_thresholds: AnomalyThresholds,
}

#[derive(Clone)]
pub struct AnomalyThresholds {
    /// Max messages between same agents in window
    pub max_pair_messages: usize,
    /// Window size for rate limiting
    pub window_secs: u64,
    /// Max chain length before alert
    pub max_chain_length: usize,
    /// Max data volume between agents
    pub max_data_bytes: usize,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            max_pair_messages: 100,
            window_secs: 60,
            max_chain_length: 5,
            max_data_bytes: 10 * 1024 * 1024, // 10MB
        }
    }
}

#[derive(Debug)]
pub enum CoordinationAlert {
    RapidExchange { from: String, to: String, count: usize },
    LongDelegationChain { chain: Vec<String> },
    DataExfiltration { from: String, to: String, bytes: usize },
    UnauthorizedEscalation { from: String, attempted_action: String },
}

impl CoordinationMonitor {
    pub fn check_message(&mut self, message: &AgentMessage) -> Vec<CoordinationAlert> {
        let mut alerts = Vec::new();
        let now = chrono::Utc::now();

        // Add to history
        self.message_history.push((now, message.clone()));

        // Prune old messages
        let cutoff = now - chrono::Duration::seconds(self.anomaly_thresholds.window_secs as i64);
        self.message_history.retain(|(ts, _)| *ts > cutoff);

        // Check for rapid exchange between agents
        let pair_count = self.message_history.iter()
            .filter(|(_, m)| {
                (m.from == message.from && matches!(&message.to, MessageTarget::Agent(to) if *to == m.from.clone())) ||
                (matches!(&m.to, MessageTarget::Agent(to) if *to == message.from))
            })
            .count();

        if pair_count > self.anomaly_thresholds.max_pair_messages {
            alerts.push(CoordinationAlert::RapidExchange {
                from: message.from.clone(),
                to: format!("{:?}", message.to),
                count: pair_count,
            });
        }

        // Check chain length
        if message.chain.len() > self.anomaly_thresholds.max_chain_length {
            alerts.push(CoordinationAlert::LongDelegationChain {
                chain: message.chain.clone(),
            });
        }

        // Check data volume
        let data_bytes: usize = self.message_history.iter()
            .filter(|(_, m)| m.from == message.from)
            .map(|(_, m)| m.payload.to_string().len())
            .sum();

        if data_bytes > self.anomaly_thresholds.max_data_bytes {
            alerts.push(CoordinationAlert::DataExfiltration {
                from: message.from.clone(),
                to: format!("{:?}", message.to),
                bytes: data_bytes,
            });
        }

        alerts
    }
}
```

## Security Considerations

### 1. Zero-Trust Agent Network

```yaml
# zero-trust-policy.yaml
version: "1.0.0"
name: "Multi-Agent Zero Trust"

# No implicit trust between agents
default_trust: none

# Explicit trust relationships
trust_relationships:
  - from: planner
    to: coder
    messages: [TaskRequest]
    data_sharing: internal

  - from: coder
    to: tester
    messages: [TaskRequest, DataShare]
    data_sharing: internal

  - from: tester
    to: deployer
    messages: [TaskRequest]
    data_sharing: public
    requires_approval: true

# Global policies
policies:
  max_chain_length: 5
  message_signing: required
  audit_all_messages: true
```

### 2. Privilege Boundaries

```
              +------------------+
              |    Orchestrator  |
              |  (System Trust)  |
              +--------+---------+
                       |
        +--------------+--------------+
        |              |              |
+-------v-------+ +----v----+ +-------v-------+
|   Planner     | |  Coder  | |   Deployer    |
| (High Trust)  | | (Medium)| |  (Low Trust)  |
+---------------+ +---------+ +---------------+
        |              |              |
        v              v              v
    Can create     Can write      Can only
    tasks for      code in        trigger
    any agent      sandbox        deploy API
```

## Scaling Considerations

### Agent Pool Architecture

```
                   Load Balancer
                        |
         +--------------+--------------+
         |              |              |
+--------v--------+ +---v---+ +--------v--------+
| Agent Pool:     | |       | | Agent Pool:     |
| Coders (10)     | |  ...  | | Testers (5)     |
+-----------------+ +-------+ +-----------------+
         |              |              |
         v              v              v
+--------------------------------------------------+
|              Shared Message Bus (NATS)            |
+--------------------------------------------------+
```

## Cost Considerations

| Component | Cost Factor | Optimization |
|-----------|-------------|--------------|
| Message Bus | Per-message | Batch messages |
| Agent Compute | Per-instance | Pool and reuse |
| Storage | Per-GB audit logs | Retention policies |
| Crypto | Per-signature | Cache verifications |

## Step-by-Step Implementation Guide

### Phase 1: Trust Infrastructure (Week 1-2)

1. **Implement TrustBroker**
2. **Set up message signing**
3. **Create agent identity registry**

### Phase 2: Message Layer (Week 2-3)

4. **Deploy NATS/Kafka**
5. **Implement MessageRouter**
6. **Add coordination monitoring**

### Phase 3: Workflow Engine (Week 3-4)

7. **Define workflow schemas**
8. **Implement WorkflowEngine**
9. **Add approval workflows**

### Phase 4: Agents (Week 4-6)

10. **Implement specialized agents**
11. **Test inter-agent communication**
12. **Security testing**

## Common Pitfalls and Solutions

### Pitfall 1: Trust Transitivity

**Problem**: Agent A trusts B, B trusts C, so A accidentally trusts C.

**Solution**: Explicit relationship graph, no transitive trust:
```rust
// Trust must be explicitly granted
trust_broker.establish_trust("A", "C", relationship)?;
```

### Pitfall 2: Message Replay Attacks

**Problem**: Old messages are replayed to trigger actions.

**Solution**: Include nonce and timestamp validation:
```rust
if message.timestamp < Utc::now() - Duration::minutes(5) {
    return Err(anyhow::anyhow!("Message too old"));
}
// Also check nonce hasn't been seen
```

### Pitfall 3: Confused Deputy

**Problem**: High-trust agent tricked into acting on behalf of low-trust agent.

**Solution**: Track and validate delegation chain:
```rust
if message.chain.len() > 0 {
    let original_sender = &message.chain[0];
    // Check original sender's trust, not just immediate sender
}
```

## Troubleshooting

### Issue: Message Signature Verification Failures

**Symptoms**: Messages rejected with signature validation errors.

**Solutions**:
1. Verify agent public keys are correctly registered in TrustBroker
2. Check timestamp synchronization between agents (NTP)
3. Ensure message payload serialization is deterministic (sorted keys)
4. Verify signing key matches registered public key

### Issue: Unexpected Message Blocking

**Symptoms**: Valid inter-agent communication being denied.

**Solutions**:
1. Review trust relationship configuration for sender/receiver pair
2. Check if message type is in the allowed_messages list
3. Verify data classification level doesn't exceed relationship limits
4. Check delegation chain length hasn't exceeded max_chain_length

### Issue: Workflow Stuck in WaitingApproval

**Symptoms**: Workflows not progressing despite approvals being granted.

**Solutions**:
1. Verify approver has DeployApproval capability
2. Check if sufficient number of unique approvers have approved
3. Ensure approval step_id matches the current workflow step
4. Review workflow execution status for error conditions

### Issue: Coordination Attack False Positives

**Symptoms**: Legitimate high-volume agent communication flagged as attacks.

**Solutions**:
1. Tune AnomalyThresholds for your workload patterns
2. Add trusted agent pairs to allowlist for high-throughput channels
3. Adjust window size based on typical workflow duration
4. Implement role-based threshold overrides for orchestrator agents

## Validation Checklist

- [ ] Agent identities are cryptographically verified
- [ ] Trust relationships are explicitly defined
- [ ] Message signing is enforced
- [ ] Delegation chains are limited
- [ ] Data classification is enforced
- [ ] Coordination attacks are detected
- [ ] Approval workflows function correctly
- [ ] Audit logs capture all inter-agent communication
- [ ] Blast radius is contained per agent
- [ ] Privilege escalation is prevented
