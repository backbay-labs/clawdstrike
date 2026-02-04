# Enterprise Deployment Reference Architecture

## Problem Statement

Large organizations need to deploy AI agent security controls across multiple teams, regions, and compliance domains while maintaining:

- Centralized policy governance
- Distributed enforcement
- Compliance with regulations (SOC2, HIPAA, GDPR, FedRAMP)
- Integration with existing security infrastructure (SIEM, IAM, PAM)
- Audit trails for regulatory reporting
- Incident response capabilities

## Target Persona

- **CISOs** responsible for AI security strategy
- **Enterprise Security Architects** designing org-wide controls
- **Compliance Officers** ensuring regulatory adherence
- **SOC Managers** operationalizing AI threat detection
- **IT Directors** managing infrastructure at scale

## Architecture Diagram

```
+------------------------------------------------------------------------+
|                         Enterprise Control Plane                        |
|  +------------------------------------------------------------------+  |
|  |                    Policy Governance Layer                        |  |
|  |  +-------------+  +-------------+  +-------------+  +-----------+ |  |
|  |  | Policy      |  | Compliance  |  | Exception   |  | Audit     | |  |
|  |  | Repository  |  | Engine      |  | Manager     |  | Archive   | |  |
|  |  | (Git-based) |  | (SOC2/HIPAA)|  | (Workflow)  |  | (S3/GCS)  | |  |
|  |  +-------------+  +-------------+  +-------------+  +-----------+ |  |
|  +------------------------------------------------------------------+  |
+------------------------------------------------------------------------+
                                    |
                                    | Policy Distribution
                                    v
+------------------------------------------------------------------------+
|                    Regional Control Planes                              |
|  +---------------------+  +---------------------+  +------------------+ |
|  | US-East Region      |  | EU-West Region      |  | APAC Region      | |
|  | +---------------+   |  | +---------------+   |  | +-------------+  | |
|  | | Policy Cache  |   |  | | Policy Cache  |   |  | | Policy Cache|  | |
|  | +---------------+   |  | +---------------+   |  | +-------------+  | |
|  | | Audit         |   |  | | Audit         |   |  | | Audit       |  | |
|  | | Aggregator    |   |  | | Aggregator    |   |  | | Aggregator  |  | |
|  | +---------------+   |  | +---------------+   |  | +-------------+  | |
|  +---------------------+  +---------------------+  +------------------+ |
+------------------------------------------------------------------------+
                                    |
                                    | Enforcement
                                    v
+------------------------------------------------------------------------+
|                         Business Units                                  |
|  +---------------------+  +---------------------+  +------------------+ |
|  | Engineering         |  | Data Science        |  | Operations       | |
|  | +---------------+   |  | +---------------+   |  | +-------------+  | |
|  | | Team A        |   |  | | ML Platform   |   |  | | SRE Team    |  | |
|  | | +----------+  |   |  | | +----------+  |   |  | | +--------+  |  | |
|  | | |Clawdstrike| |   |  | | |Clawdstrike| |   |  | | |Clawdstrike|  | |
|  | | | Agents   |  |   |  | | | Agents   |  |   |  | | | Agents  |  |  | |
|  | | +----------+  |   |  | | +----------+  |   |  | | +--------+  |  | |
|  | +---------------+   |  | +---------------+   |  | +-------------+  | |
|  +---------------------+  +---------------------+  +------------------+ |
+------------------------------------------------------------------------+
                                    |
                                    | Telemetry
                                    v
+------------------------------------------------------------------------+
|                    Security Operations Center                           |
|  +---------------+  +---------------+  +---------------+               |
|  | SIEM          |  | SOAR          |  | Threat Intel  |               |
|  | (Splunk/Elastic| | (Phantom/XSOAR)| | (TIP)         |               |
|  +---------------+  +---------------+  +---------------+               |
+------------------------------------------------------------------------+
```

## Component Breakdown

### 1. Policy Governance Layer

```yaml
# policies/governance/policy-hierarchy.yaml
version: "1.0.0"
name: "Enterprise Policy Hierarchy"
description: "Defines policy inheritance and override rules"

hierarchy:
  # Level 1: Global baseline (mandatory)
  - level: global
    path: "policies/global/baseline.yaml"
    mandatory: true
    overridable: false

  # Level 2: Compliance overlays (additive)
  - level: compliance
    path: "policies/compliance/{framework}.yaml"
    mandatory: false
    overridable: false
    frameworks:
      - soc2
      - hipaa
      - gdpr
      - fedramp

  # Level 3: Regional policies
  - level: region
    path: "policies/regions/{region}.yaml"
    mandatory: true
    overridable: true
    regions:
      - us-east
      - us-west
      - eu-west
      - eu-central
      - apac

  # Level 4: Business unit policies
  - level: business_unit
    path: "policies/units/{unit}.yaml"
    mandatory: false
    overridable: true
    units:
      - engineering
      - data-science
      - operations
      - finance

  # Level 5: Team policies
  - level: team
    path: "policies/teams/{team}.yaml"
    mandatory: false
    overridable: true
    # Can only ADD restrictions, not remove

override_rules:
  # Teams can add patterns but not remove global ones
  forbidden_path:
    allow_additions: true
    allow_removals: false

  # Teams can restrict egress but not expand
  egress_allowlist:
    allow_additions: false
    allow_removals: true

  # Secret patterns are additive only
  secret_leak:
    allow_additions: true
    allow_removals: false
```

```yaml
# policies/global/baseline.yaml
version: "1.1.0"
name: "Global Security Baseline"
description: "Mandatory security controls for all AI agents"

guards:
  forbidden_path:
    patterns:
      # Critical infrastructure
      - "/etc/shadow"
      - "/etc/sudoers"
      - "/root/**"
      # Credentials
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.gcloud/**"
      - "**/.azure/**"
      # Secrets management
      - "**/.vault/**"
      - "**/secrets/**"
      - "**/*.pem"
      - "**/*.key"
      - "**/id_rsa*"
      - "**/id_ed25519*"
      # Environment files
      - "**/.env"
      - "**/.env.*"
      - "**/terraform.tfstate*"

  egress_allowlist:
    allow:
      # AI providers (approved list)
      - "*.anthropic.com"
      - "*.openai.com"
      # Internal services
      - "*.internal.company.com"
      - "*.corp.company.com"
    block:
      # Known bad destinations
      - "*.pastebin.com"
      - "*.hastebin.com"
      # Geographic restrictions
      - "*.ru"
      - "*.cn"
      - "*.ir"
    default_action: block

  secret_leak:
    patterns:
      # Cloud credentials
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: gcp_service_account
        pattern: '"type"\\s*:\\s*"service_account"'
        severity: critical
      # Internal tokens
      - name: company_api_token
        pattern: "CORP-[A-Za-z0-9]{32}"
        severity: critical

  patch_integrity:
    forbidden_patterns:
      - "(?i)disable[_-]?(security|auth|ssl|tls)"
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+777"

settings:
  fail_fast: true
  verbose_logging: false
  session_timeout_secs: 3600
```

```yaml
# policies/compliance/hipaa.yaml
version: "1.1.0"
name: "HIPAA Compliance Overlay"
extends: "global/baseline"
description: "Additional controls for HIPAA compliance"

guards:
  forbidden_path:
    additional_patterns:
      # PHI storage locations
      - "**/phi/**"
      - "**/patient-data/**"
      - "**/medical-records/**"
      - "**/*.hl7"
      - "**/*.dicom"

  secret_leak:
    patterns:
      # PHI patterns
      - name: ssn
        pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        severity: critical
      - name: medical_record_number
        pattern: "MRN[:-]?\\s*\\d{8,12}"
        severity: critical

  # Additional egress restrictions
  egress_allowlist:
    remove_allow:
      # No external AI APIs for PHI processing
      - "*.openai.com"
      - "*.anthropic.com"

settings:
  # HIPAA requires detailed logging
  verbose_logging: true
  # Shorter sessions for PHI access
  session_timeout_secs: 1800
```

### 2. Policy Distribution Service

```rust
// policy-distributor/src/lib.rs
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Policy Distribution Service
pub struct PolicyDistributor {
    /// Git repository for policies
    repo_url: String,
    /// Cached compiled policies per scope
    policy_cache: Arc<RwLock<HashMap<PolicyScope, CompiledPolicy>>>,
    /// Policy version tracker
    version_tracker: Arc<RwLock<VersionTracker>>,
    /// Regional endpoints
    regional_endpoints: HashMap<String, String>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct PolicyScope {
    pub region: String,
    pub business_unit: String,
    pub team: String,
    pub compliance_frameworks: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    pub policy: clawdstrike::Policy,
    pub version: String,
    pub compiled_at: chrono::DateTime<chrono::Utc>,
    pub source_files: Vec<String>,
    pub hash: String,
}

impl PolicyDistributor {
    pub async fn new(repo_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            repo_url: repo_url.to_string(),
            policy_cache: Arc::new(RwLock::new(HashMap::new())),
            version_tracker: Arc::new(RwLock::new(VersionTracker::new())),
            regional_endpoints: HashMap::new(),
        })
    }

    /// Compile policy for a specific scope
    pub async fn compile_policy(&self, scope: &PolicyScope) -> anyhow::Result<CompiledPolicy> {
        let mut policies = Vec::new();

        // 1. Load global baseline (mandatory)
        let baseline = self.load_policy("policies/global/baseline.yaml").await?;
        policies.push(baseline);

        // 2. Load compliance overlays
        for framework in &scope.compliance_frameworks {
            let compliance_path = format!("policies/compliance/{}.yaml", framework);
            if let Ok(policy) = self.load_policy(&compliance_path).await {
                policies.push(policy);
            }
        }

        // 3. Load regional policy
        let region_path = format!("policies/regions/{}.yaml", scope.region);
        if let Ok(policy) = self.load_policy(&region_path).await {
            policies.push(policy);
        }

        // 4. Load business unit policy
        let bu_path = format!("policies/units/{}.yaml", scope.business_unit);
        if let Ok(policy) = self.load_policy(&bu_path).await {
            policies.push(policy);
        }

        // 5. Load team policy
        let team_path = format!("policies/teams/{}.yaml", scope.team);
        if let Ok(policy) = self.load_policy(&team_path).await {
            policies.push(policy);
        }

        // Merge all policies
        let mut final_policy = policies[0].clone();
        for policy in &policies[1..] {
            final_policy = self.merge_policies(&final_policy, policy)?;
        }

        // Validate merged policy
        final_policy.validate()?;

        // Compute hash
        let policy_yaml = final_policy.to_yaml()?;
        let hash = sha256_hex(policy_yaml.as_bytes());

        Ok(CompiledPolicy {
            policy: final_policy,
            version: format!("{}:{}", chrono::Utc::now().format("%Y%m%d%H%M%S"), &hash[..8]),
            compiled_at: chrono::Utc::now(),
            source_files: vec![], // Track source files
            hash,
        })
    }

    /// Distribute policy to regional endpoints
    pub async fn distribute(&self, scope: &PolicyScope) -> anyhow::Result<()> {
        let compiled = self.compile_policy(scope).await?;

        // Cache locally
        {
            let mut cache = self.policy_cache.write().await;
            cache.insert(scope.clone(), compiled.clone());
        }

        // Push to regional endpoint
        if let Some(endpoint) = self.regional_endpoints.get(&scope.region) {
            let client = reqwest::Client::new();
            client
                .post(format!("{}/api/v1/policies", endpoint))
                .json(&compiled)
                .send()
                .await?;
        }

        // Update version tracker
        {
            let mut tracker = self.version_tracker.write().await;
            tracker.record_deployment(scope, &compiled.version);
        }

        Ok(())
    }

    fn merge_policies(
        &self,
        base: &clawdstrike::Policy,
        overlay: &clawdstrike::Policy,
    ) -> anyhow::Result<clawdstrike::Policy> {
        // Use Clawdstrike's built-in merge
        Ok(base.merge(overlay))
    }

    async fn load_policy(&self, path: &str) -> anyhow::Result<clawdstrike::Policy> {
        // In production, fetch from Git repo
        let content = tokio::fs::read_to_string(path).await?;
        clawdstrike::Policy::from_yaml(&content)
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
```

### 3. Exception Management Workflow

```rust
// exception-manager/src/lib.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Exception request for policy deviation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExceptionRequest {
    pub id: String,
    pub requestor: String,
    pub requestor_team: String,
    pub exception_type: ExceptionType,
    pub justification: String,
    pub scope: PolicyScope,
    pub requested_changes: RequestedChanges,
    pub duration: ExceptionDuration,
    pub risk_assessment: RiskAssessment,
    pub status: ExceptionStatus,
    pub approvals: Vec<Approval>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExceptionType {
    /// Temporary exception for specific project
    ProjectException,
    /// Permanent exception for business need
    PermanentException,
    /// Emergency exception (post-hoc approval)
    EmergencyException,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestedChanges {
    /// Paths to allow
    pub allow_paths: Vec<String>,
    /// Hosts to allow egress to
    pub allow_egress: Vec<String>,
    /// Commands to allow
    pub allow_commands: Vec<String>,
    /// Other policy modifications
    pub custom: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExceptionDuration {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    pub auto_renew: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk_level: RiskLevel,
    pub mitigations: Vec<String>,
    pub compensating_controls: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExceptionStatus {
    Draft,
    PendingReview,
    PendingApproval,
    Approved,
    Rejected,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
    pub role: ApproverRole,
    pub decision: ApprovalDecision,
    pub comments: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ApproverRole {
    TeamLead,
    SecurityEngineer,
    ComplianceOfficer,
    CISO,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
    RequestChanges,
}

pub struct ExceptionManager {
    exceptions: HashMap<String, ExceptionRequest>,
    approval_rules: ApprovalRules,
    policy_distributor: PolicyDistributor,
}

#[derive(Clone)]
pub struct ApprovalRules {
    /// Minimum approvals by risk level
    pub min_approvals: HashMap<RiskLevel, Vec<ApproverRole>>,
    /// Maximum duration by risk level
    pub max_duration: HashMap<RiskLevel, chrono::Duration>,
}

impl ExceptionManager {
    pub async fn submit_request(&mut self, request: ExceptionRequest) -> anyhow::Result<String> {
        // Validate request
        self.validate_request(&request)?;

        // Calculate required approvals
        let required_approvals = self.get_required_approvals(&request);

        let mut request = request;
        request.status = ExceptionStatus::PendingReview;

        let id = request.id.clone();
        self.exceptions.insert(id.clone(), request);

        // Notify approvers
        self.notify_approvers(&id, &required_approvals).await?;

        Ok(id)
    }

    pub async fn approve(
        &mut self,
        exception_id: &str,
        approval: Approval,
    ) -> anyhow::Result<ExceptionStatus> {
        let exception = self.exceptions.get_mut(exception_id)
            .ok_or_else(|| anyhow::anyhow!("Exception not found"))?;

        // Verify approver has authority
        self.verify_approver_authority(&approval, exception)?;

        exception.approvals.push(approval.clone());

        // Check if all required approvals are met
        if self.has_sufficient_approvals(exception) {
            exception.status = ExceptionStatus::Approved;

            // Apply exception to policy
            self.apply_exception(exception).await?;
        }

        Ok(exception.status.clone())
    }

    async fn apply_exception(&self, exception: &ExceptionRequest) -> anyhow::Result<()> {
        // Generate exception policy overlay
        let overlay = self.generate_exception_overlay(exception);

        // Distribute updated policy
        self.policy_distributor.distribute(&exception.scope).await?;

        tracing::info!(
            exception_id = %exception.id,
            scope = ?exception.scope,
            "Exception applied"
        );

        Ok(())
    }

    fn generate_exception_overlay(&self, exception: &ExceptionRequest) -> clawdstrike::Policy {
        let mut policy = clawdstrike::Policy::default();
        policy.name = format!("Exception: {}", exception.id);

        // Apply requested changes as policy overrides
        // This would add exceptions to the guards

        policy
    }

    fn validate_request(&self, request: &ExceptionRequest) -> anyhow::Result<()> {
        // Check duration doesn't exceed max for risk level
        if let Some(end) = request.duration.end {
            let max_duration = self.approval_rules.max_duration
                .get(&request.risk_assessment.risk_level)
                .cloned()
                .unwrap_or(chrono::Duration::days(90));

            if end - request.duration.start > max_duration {
                return Err(anyhow::anyhow!(
                    "Duration exceeds maximum for risk level {:?}",
                    request.risk_assessment.risk_level
                ));
            }
        }

        // Validate scope exists
        // Validate requested changes are sensible

        Ok(())
    }

    fn get_required_approvals(&self, request: &ExceptionRequest) -> Vec<ApproverRole> {
        self.approval_rules.min_approvals
            .get(&request.risk_assessment.risk_level)
            .cloned()
            .unwrap_or_else(|| vec![ApproverRole::SecurityEngineer, ApproverRole::CISO])
    }

    fn verify_approver_authority(
        &self,
        approval: &Approval,
        exception: &ExceptionRequest,
    ) -> anyhow::Result<()> {
        let required = self.get_required_approvals(exception);
        if !required.contains(&approval.role) {
            return Err(anyhow::anyhow!(
                "Approver role {:?} not authorized for this exception",
                approval.role
            ));
        }
        Ok(())
    }

    fn has_sufficient_approvals(&self, exception: &ExceptionRequest) -> bool {
        let required = self.get_required_approvals(exception);
        let approved: Vec<_> = exception.approvals.iter()
            .filter(|a| matches!(a.decision, ApprovalDecision::Approved))
            .collect();

        required.iter().all(|role| {
            approved.iter().any(|a| &a.role == role)
        })
    }

    async fn notify_approvers(
        &self,
        exception_id: &str,
        roles: &[ApproverRole],
    ) -> anyhow::Result<()> {
        // Send notifications via email/Slack/etc.
        tracing::info!(
            exception_id = exception_id,
            roles = ?roles,
            "Notifying approvers"
        );
        Ok(())
    }
}
```

### 4. SIEM Integration

```rust
// siem-integration/src/lib.rs
use serde::{Deserialize, Serialize};

/// SIEM event format (Splunk CIM compatible)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiemEvent {
    /// Timestamp in ISO 8601
    pub timestamp: String,
    /// Event source
    pub source: String,
    /// Event type
    pub event_type: String,
    /// Severity (1-10)
    pub severity: u8,
    /// Action taken
    pub action: String,
    /// Outcome
    pub outcome: String,

    // Agent fields
    pub agent_id: String,
    pub agent_type: String,
    pub session_id: String,

    // Target fields
    pub target_type: String,
    pub target_path: Option<String>,
    pub target_host: Option<String>,

    // Guard fields
    pub guard_name: String,
    pub policy_name: String,
    pub policy_version: String,

    // Context
    pub user: Option<String>,
    pub team: Option<String>,
    pub region: String,

    // Raw data
    pub raw_event: serde_json::Value,
}

pub struct SiemExporter {
    splunk_hec: Option<SplunkHec>,
    elastic: Option<ElasticExporter>,
    kafka: Option<KafkaExporter>,
}

impl SiemExporter {
    pub async fn export(&self, event: SiemEvent) -> anyhow::Result<()> {
        // Export to all configured backends
        if let Some(ref splunk) = self.splunk_hec {
            splunk.send(&event).await?;
        }
        if let Some(ref elastic) = self.elastic {
            elastic.send(&event).await?;
        }
        if let Some(ref kafka) = self.kafka {
            kafka.send(&event).await?;
        }
        Ok(())
    }
}

pub struct SplunkHec {
    endpoint: String,
    token: String,
    source: String,
    sourcetype: String,
}

impl SplunkHec {
    pub async fn send(&self, event: &SiemEvent) -> anyhow::Result<()> {
        let client = reqwest::Client::new();

        let payload = serde_json::json!({
            "time": chrono::Utc::now().timestamp(),
            "source": self.source,
            "sourcetype": self.sourcetype,
            "event": event,
        });

        client
            .post(&self.endpoint)
            .header("Authorization", format!("Splunk {}", self.token))
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }
}

/// Convert Clawdstrike events to SIEM format
pub fn to_siem_event(
    result: &clawdstrike::GuardResult,
    context: &EventContext,
) -> SiemEvent {
    let severity = match result.severity {
        clawdstrike::Severity::Info => 2,
        clawdstrike::Severity::Warning => 4,
        clawdstrike::Severity::Error => 6,
        clawdstrike::Severity::Critical => 9,
    };

    SiemEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: "clawdstrike".to_string(),
        event_type: if result.allowed { "action_allowed" } else { "action_blocked" }.to_string(),
        severity,
        action: context.action_type.clone(),
        outcome: if result.allowed { "success" } else { "failure" }.to_string(),
        agent_id: context.agent_id.clone(),
        agent_type: context.agent_type.clone(),
        session_id: context.session_id.clone(),
        target_type: context.target_type.clone(),
        target_path: context.target_path.clone(),
        target_host: context.target_host.clone(),
        guard_name: result.guard.clone(),
        policy_name: context.policy_name.clone(),
        policy_version: context.policy_version.clone(),
        user: context.user.clone(),
        team: context.team.clone(),
        region: context.region.clone(),
        raw_event: serde_json::to_value(result).unwrap_or_default(),
    }
}

#[derive(Clone)]
pub struct EventContext {
    pub agent_id: String,
    pub agent_type: String,
    pub session_id: String,
    pub action_type: String,
    pub target_type: String,
    pub target_path: Option<String>,
    pub target_host: Option<String>,
    pub policy_name: String,
    pub policy_version: String,
    pub user: Option<String>,
    pub team: Option<String>,
    pub region: String,
}
```

### 5. Compliance Reporting

```rust
// compliance/src/lib.rs
use serde::{Deserialize, Serialize};

/// Compliance report generator
pub struct ComplianceReporter {
    audit_store: AuditStore,
    frameworks: Vec<ComplianceFramework>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub id: String,
    pub name: String,
    pub controls: Vec<Control>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub name: String,
    pub description: String,
    pub evidence_query: String,
    pub passing_criteria: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub period: ReportPeriod,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub overall_status: ComplianceStatus,
    pub control_results: Vec<ControlResult>,
    pub exceptions: Vec<ExceptionSummary>,
    pub recommendations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportPeriod {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlResult {
    pub control_id: String,
    pub control_name: String,
    pub status: ComplianceStatus,
    pub evidence: Vec<Evidence>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: String,
    pub description: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub artifact_id: Option<String>,
}

impl ComplianceReporter {
    pub async fn generate_report(
        &self,
        framework_id: &str,
        period: ReportPeriod,
    ) -> anyhow::Result<ComplianceReport> {
        let framework = self.frameworks.iter()
            .find(|f| f.id == framework_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown framework"))?;

        let mut control_results = Vec::new();

        for control in &framework.controls {
            let result = self.evaluate_control(control, &period).await?;
            control_results.push(result);
        }

        let overall_status = self.calculate_overall_status(&control_results);

        Ok(ComplianceReport {
            framework: framework.name.clone(),
            period,
            generated_at: chrono::Utc::now(),
            overall_status,
            control_results,
            exceptions: vec![], // Load from exception manager
            recommendations: self.generate_recommendations(&control_results),
        })
    }

    async fn evaluate_control(
        &self,
        control: &Control,
        period: &ReportPeriod,
    ) -> anyhow::Result<ControlResult> {
        // Query audit store for evidence
        let events = self.audit_store.query(&control.evidence_query, period).await?;

        // Evaluate against criteria
        let (status, gaps) = self.evaluate_criteria(&control.passing_criteria, &events);

        let evidence: Vec<Evidence> = events.iter()
            .take(10)  // Include up to 10 evidence items
            .map(|e| Evidence {
                evidence_type: "audit_event".to_string(),
                description: e.summary.clone(),
                timestamp: e.timestamp,
                artifact_id: Some(e.id.clone()),
            })
            .collect();

        Ok(ControlResult {
            control_id: control.id.clone(),
            control_name: control.name.clone(),
            status,
            evidence,
            gaps,
        })
    }

    fn evaluate_criteria(
        &self,
        criteria: &str,
        events: &[AuditEvent],
    ) -> (ComplianceStatus, Vec<String>) {
        // Parse and evaluate criteria
        // This is simplified - real implementation would parse criteria DSL

        let violations: Vec<_> = events.iter()
            .filter(|e| !e.allowed)
            .collect();

        if violations.is_empty() {
            (ComplianceStatus::Compliant, vec![])
        } else if violations.len() < events.len() / 10 {
            (ComplianceStatus::PartiallyCompliant, vec![
                format!("{} violations detected", violations.len())
            ])
        } else {
            (ComplianceStatus::NonCompliant, vec![
                format!("{} violations detected (>10%)", violations.len())
            ])
        }
    }

    fn calculate_overall_status(&self, results: &[ControlResult]) -> ComplianceStatus {
        let non_compliant = results.iter()
            .filter(|r| matches!(r.status, ComplianceStatus::NonCompliant))
            .count();

        let partial = results.iter()
            .filter(|r| matches!(r.status, ComplianceStatus::PartiallyCompliant))
            .count();

        if non_compliant > 0 {
            ComplianceStatus::NonCompliant
        } else if partial > 0 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::Compliant
        }
    }

    fn generate_recommendations(&self, results: &[ControlResult]) -> Vec<String> {
        let mut recommendations = Vec::new();

        for result in results {
            if matches!(result.status, ComplianceStatus::NonCompliant | ComplianceStatus::PartiallyCompliant) {
                recommendations.push(format!(
                    "Review and remediate control {}: {}",
                    result.control_id, result.control_name
                ));
            }
        }

        recommendations
    }
}
```

## Security Considerations

### 1. Policy Signing

```rust
// All policies must be signed by authorized keys
pub struct SignedPolicy {
    pub policy: Policy,
    pub signature: Vec<u8>,
    pub signer_key_id: String,
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

pub fn verify_policy_signature(signed: &SignedPolicy, trusted_keys: &[PublicKey]) -> bool {
    // Verify signature matches policy content
    // Verify signer key is in trusted key set
}
```

### 2. Audit Immutability

```sql
-- Use append-only tables with blockchain-style chaining
CREATE TABLE audit_entries (
    id SERIAL PRIMARY KEY,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB NOT NULL
);

-- Trigger to compute and verify hash chain
CREATE TRIGGER audit_chain_trigger
BEFORE INSERT ON audit_entries
FOR EACH ROW EXECUTE FUNCTION verify_and_compute_hash();
```

### 3. Secrets Management

```yaml
# Use external secrets management
secrets:
  provider: vault  # or aws-secrets-manager, azure-keyvault
  path: "secret/clawdstrike/"
  rotation_days: 30
```

## Scaling Considerations

### Regional Distribution

```
                    Global Control Plane
                    (us-east-1, primary)
                            |
            +---------------+---------------+
            |               |               |
            v               v               v
    +---------------+ +---------------+ +---------------+
    | US Regions    | | EU Regions    | | APAC Regions  |
    | - us-east-1   | | - eu-west-1   | | - ap-south-1  |
    | - us-west-2   | | - eu-central-1| | - ap-east-1   |
    +---------------+ +---------------+ +---------------+
```

### Capacity Planning

| Scale | Agents | Events/day | Audit Storage | Control Plane |
|-------|--------|------------|---------------|---------------|
| Small | 100 | 1M | 10GB/month | 1 node |
| Medium | 1,000 | 10M | 100GB/month | 3 nodes |
| Large | 10,000 | 100M | 1TB/month | HA cluster |
| Enterprise | 100,000+ | 1B+ | 10TB+/month | Multi-region |

## Cost Considerations

### Monthly Cost Breakdown (Large Deployment)

| Component | Monthly Cost |
|-----------|--------------|
| Control Plane (HA) | $2,000 |
| Regional Nodes (3) | $3,000 |
| Audit Storage | $1,000 |
| SIEM Integration | $5,000 |
| Compliance Tooling | $2,000 |
| **Total** | **$13,000** |

## Step-by-Step Implementation Guide

### Phase 1: Foundation (Month 1)

1. Set up Git-based policy repository
2. Implement policy compilation
3. Deploy control plane infrastructure

### Phase 2: Regional Rollout (Month 2)

4. Deploy regional nodes
5. Configure policy distribution
6. Set up audit collection

### Phase 3: Integration (Month 3)

7. SIEM integration
8. IAM integration
9. Exception workflow

### Phase 4: Compliance (Month 4)

10. Compliance framework mapping
11. Automated reporting
12. Audit procedures

## Common Pitfalls and Solutions

### Pitfall 1: Policy Sprawl

**Problem**: Too many team-specific policies become unmanageable.

**Solution**: Strict hierarchy with inheritance, regular policy audits:
```yaml
# Maximum allowed policy depth
hierarchy_depth_limit: 5
# Required review for new policies
policy_review_required: true
```

### Pitfall 2: Exception Abuse

**Problem**: Teams request too many exceptions, undermining security.

**Solution**: Exception quotas and automatic expiration:
```rust
pub struct ExceptionQuota {
    pub max_active_exceptions: u32,
    pub max_duration_days: u32,
    pub cooldown_after_expiry_days: u32,
}
```

### Pitfall 3: Audit Data Explosion

**Problem**: Audit logs grow unmanageably large.

**Solution**: Tiered storage with summarization:
```yaml
audit_retention:
  hot: 7d    # Full detail in Elasticsearch
  warm: 30d  # Summarized in TimescaleDB
  cold: 365d # Compressed in S3
```

## Troubleshooting

### Issue: Policy Distribution Failures

**Symptoms**: Regional endpoints not receiving updated policies.

**Solutions**:
1. Verify network connectivity between control plane and regional nodes
2. Check authentication/authorization for policy push requests
3. Review policy compilation logs for merge conflicts
4. Ensure regional endpoint health checks are passing

### Issue: Exception Workflow Stuck

**Symptoms**: Exception requests not progressing through approval chain.

**Solutions**:
1. Verify approver notification delivery (email/Slack)
2. Check approver has correct role for the exception risk level
3. Review exception duration against max_duration limits
4. Ensure exception manager has connectivity to policy distributor

### Issue: SIEM Integration Gaps

**Symptoms**: Events missing or delayed in SIEM platform.

**Solutions**:
1. Verify HEC token validity and permissions (Splunk)
2. Check network connectivity and firewall rules to SIEM endpoint
3. Review event batching configuration for throughput issues
4. Validate event format matches expected schema (CIM compliance)

### Issue: Compliance Report Failures

**Symptoms**: Reports showing incomplete data or generation errors.

**Solutions**:
1. Verify audit store has data for the report period
2. Check control evidence queries for syntax errors
3. Ensure audit retention policy covers compliance report period
4. Review framework control definitions for missing evidence mappings

## Validation Checklist

- [ ] Policy hierarchy is documented
- [ ] Global baseline is enforced
- [ ] Regional policies are deployed
- [ ] Exception workflow functions
- [ ] SIEM receives events
- [ ] Compliance reports generate correctly
- [ ] Policy changes are audited
- [ ] Rollback procedures tested
- [ ] DR plan documented
- [ ] SOC playbooks created
