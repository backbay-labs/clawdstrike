# Blast Radius Estimation Design

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0.0-draft |
| Status | Proposal |
| Component | BlastRadiusGuard |
| Last Updated | 2026-02-02 |

---

## 1. Problem Statement

### 1.1 The Challenge

AI agents can perform destructive operations with cascading effects:

- Deleting a configuration file might bring down an entire service
- Modifying a shared library affects all dependent applications
- Writing to a package.json changes the behavior of the entire project
- Executing `rm -rf` in the wrong directory causes catastrophic data loss

Current guards only evaluate whether an action is *allowed*, not whether it is *wise*. A write to `/app/package.json` might be policy-compliant but high-risk.

### 1.2 Goals

1. **Quantify Impact**: Assign a numerical "blast radius" score to proposed actions
2. **Contextualize Risk**: Consider dependencies, reversibility, and scope
3. **Enable Informed Decisions**: Provide risk information for human oversight
4. **Prevent Catastrophe**: Block or escalate operations above risk thresholds

### 1.3 Non-Goals

- Replace human judgment for critical operations
- Achieve perfect accuracy (false negatives are acceptable; false positives are not)
- Handle business logic risk (focus on technical/operational risk)

---

## 2. Blast Radius Model

### 2.1 Core Concept

```
                            BLAST RADIUS SCORE
                                  (0-100)

    ┌─────────────────────────────────────────────────────────────┐
    │                                                             │
    │   0-25: LOW         │ Localized impact, easily reversible   │
    │   26-50: MODERATE   │ Component-level impact, recoverable   │
    │   51-75: HIGH       │ System-level impact, complex recovery │
    │   76-100: CRITICAL  │ Organization-wide impact, data loss   │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘
```

### 2.2 Scoring Components

The blast radius score is computed from multiple factors:

```
BlastRadius = w1*Scope + w2*Reversibility + w3*Dependencies + w4*Sensitivity + w5*Velocity

Where:
  - Scope: How many resources/users are affected
  - Reversibility: How easy to undo the action
  - Dependencies: How many systems depend on this resource
  - Sensitivity: Classification of the resource (public/internal/confidential/restricted)
  - Velocity: Rate of destructive operations in the session
```

### 2.3 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     BlastRadiusGuard                                 │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────────┐
│                      Action Classifier                               │
│  - Categorize action type (read/write/delete/exec)                  │
│  - Extract target resources                                          │
│  - Identify operation scope                                          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         │                      │                      │
         v                      v                      v
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ Scope Analyzer  │   │  Dependency     │   │ Reversibility   │
│                 │   │  Resolver       │   │ Assessor        │
│ - File count    │   │                 │   │                 │
│ - User impact   │   │ - Import graph  │   │ - Backup exists │
│ - Service reach │   │ - Package deps  │   │ - VCS tracked   │
│                 │   │ - Config refs   │   │ - Idempotent?   │
└────────┬────────┘   └────────┬────────┘   └────────┬────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────────┐
│                     Score Calculator                                 │
│  - Weight and combine factors                                        │
│  - Apply context modifiers                                           │
│  - Compute final blast radius                                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────────┐
│                     Decision Engine                                  │
│  - Compare against thresholds                                        │
│  - Determine action (allow/warn/block/escalate)                     │
│  - Generate explanation                                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. API Design

### 3.1 Rust Interface

```rust
//! Blast Radius Estimation for Clawdstrike
//!
//! Quantifies the potential impact of proposed actions to enable risk-aware decisions.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Blast radius score (0-100)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlastRadiusScore(pub u8);

impl BlastRadiusScore {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(100);

    pub fn new(score: u8) -> Self {
        Self(score.min(100))
    }

    pub fn category(&self) -> BlastRadiusCategory {
        match self.0 {
            0..=25 => BlastRadiusCategory::Low,
            26..=50 => BlastRadiusCategory::Moderate,
            51..=75 => BlastRadiusCategory::High,
            76..=100 => BlastRadiusCategory::Critical,
            _ => unreachable!(),
        }
    }
}

/// Blast radius category
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlastRadiusCategory {
    Low,
    Moderate,
    High,
    Critical,
}

/// Factors contributing to blast radius
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlastRadiusFactors {
    /// Number of files directly affected
    pub files_affected: u32,
    /// Estimated number of users impacted
    pub users_impacted: u32,
    /// Number of dependent systems/services
    pub dependent_systems: u32,
    /// Whether the resource is under version control
    pub version_controlled: bool,
    /// Whether a backup exists
    pub backup_exists: bool,
    /// Whether the operation is idempotent
    pub idempotent: bool,
    /// Resource sensitivity classification
    pub sensitivity: ResourceSensitivity,
    /// Operation type
    pub operation_type: OperationType,
    /// Depth in dependency tree
    pub dependency_depth: u32,
    /// Whether this is a recursive operation
    pub recursive: bool,
}

/// Resource sensitivity classification
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceSensitivity {
    #[default]
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Type of operation being performed
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationType {
    #[default]
    Read,
    Create,
    Modify,
    Delete,
    Execute,
}

/// Detailed blast radius assessment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlastRadiusAssessment {
    /// Overall blast radius score
    pub score: BlastRadiusScore,
    /// Score category
    pub category: BlastRadiusCategory,
    /// Contributing factors
    pub factors: BlastRadiusFactors,
    /// Breakdown of score components
    pub breakdown: ScoreBreakdown,
    /// Human-readable explanation
    pub explanation: String,
    /// Recommendations for risk mitigation
    pub recommendations: Vec<String>,
}

/// Breakdown of how the score was calculated
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub scope_score: f32,
    pub reversibility_score: f32,
    pub dependency_score: f32,
    pub sensitivity_score: f32,
    pub velocity_score: f32,
    pub weights: ScoreWeights,
}

/// Configurable weights for score components
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreWeights {
    pub scope: f32,
    pub reversibility: f32,
    pub dependencies: f32,
    pub sensitivity: f32,
    pub velocity: f32,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            scope: 0.25,
            reversibility: 0.25,
            dependencies: 0.20,
            sensitivity: 0.20,
            velocity: 0.10,
        }
    }
}

/// Configuration for blast radius guard
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusConfig {
    /// Whether the guard is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Score threshold for blocking (0-100)
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u8,

    /// Score threshold for warning (0-100)
    #[serde(default = "default_warn_threshold")]
    pub warn_threshold: u8,

    /// Score weights
    #[serde(default)]
    pub weights: ScoreWeights,

    /// Path patterns that always trigger high blast radius
    #[serde(default)]
    pub critical_paths: Vec<String>,

    /// Paths to exclude from blast radius calculation
    #[serde(default)]
    pub excluded_paths: Vec<String>,

    /// Enable dependency graph analysis
    #[serde(default = "default_true")]
    pub analyze_dependencies: bool,

    /// Maximum depth for dependency analysis
    #[serde(default = "default_max_depth")]
    pub max_dependency_depth: u32,

    /// Session velocity tracking
    #[serde(default)]
    pub track_velocity: bool,

    /// Time window for velocity tracking (seconds)
    #[serde(default = "default_velocity_window")]
    pub velocity_window_secs: u32,
}

fn default_enabled() -> bool { true }
fn default_block_threshold() -> u8 { 75 }
fn default_warn_threshold() -> u8 { 50 }
fn default_true() -> bool { true }
fn default_max_depth() -> u32 { 3 }
fn default_velocity_window() -> u32 { 300 }

impl Default for BlastRadiusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_threshold: 75,
            warn_threshold: 50,
            weights: ScoreWeights::default(),
            critical_paths: vec![
                "**/package.json".to_string(),
                "**/Cargo.toml".to_string(),
                "**/go.mod".to_string(),
                "**/.env*".to_string(),
                "**/docker-compose*.yml".to_string(),
                "**/Dockerfile".to_string(),
            ],
            excluded_paths: vec![
                "**/node_modules/**".to_string(),
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
            ],
            analyze_dependencies: true,
            max_dependency_depth: 3,
            track_velocity: true,
            velocity_window_secs: 300,
        }
    }
}

/// Dependency graph for impact analysis
pub trait DependencyResolver: Send + Sync {
    /// Get direct dependents of a resource
    fn get_dependents(&self, resource: &str) -> Vec<String>;

    /// Get the full dependency tree depth
    fn get_dependency_depth(&self, resource: &str) -> u32;

    /// Check if resource is in a critical path
    fn is_critical(&self, resource: &str) -> bool;
}

/// Default dependency resolver using file system heuristics
pub struct FileSystemDependencyResolver {
    /// Cache of analyzed dependencies
    cache: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl FileSystemDependencyResolver {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Analyze imports/requires in a file
    async fn analyze_file(&self, path: &Path) -> Vec<String> {
        // In a real implementation, this would parse the file and extract:
        // - JavaScript/TypeScript imports
        // - Rust use/mod statements
        // - Python imports
        // - Go imports
        // - etc.
        vec![]
    }
}

impl Default for FileSystemDependencyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyResolver for FileSystemDependencyResolver {
    fn get_dependents(&self, resource: &str) -> Vec<String> {
        // Heuristic-based dependency detection
        let path = Path::new(resource);
        let mut dependents = Vec::new();

        // Package manifests affect entire project
        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            match filename {
                "package.json" | "Cargo.toml" | "go.mod" | "requirements.txt" => {
                    dependents.push("entire_project".to_string());
                }
                "Dockerfile" | "docker-compose.yml" => {
                    dependents.push("deployment".to_string());
                }
                ".env" | ".env.local" | ".env.production" => {
                    dependents.push("runtime_config".to_string());
                }
                _ => {}
            }
        }

        dependents
    }

    fn get_dependency_depth(&self, resource: &str) -> u32 {
        let path = Path::new(resource);
        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            match filename {
                "package.json" | "Cargo.toml" | "go.mod" => 3,
                "tsconfig.json" | "webpack.config.js" => 2,
                _ => 1,
            }
        } else {
            1
        }
    }

    fn is_critical(&self, resource: &str) -> bool {
        let critical_patterns = [
            "package.json",
            "Cargo.toml",
            "go.mod",
            ".env",
            "Dockerfile",
            "docker-compose",
        ];
        critical_patterns.iter().any(|p| resource.contains(p))
    }
}

/// Session state for velocity tracking
#[derive(Default)]
struct SessionVelocity {
    destructive_ops: Vec<(chrono::DateTime<chrono::Utc>, String)>,
}

/// Blast radius guard implementation
pub struct BlastRadiusGuard {
    config: BlastRadiusConfig,
    dependency_resolver: Arc<dyn DependencyResolver>,
    sessions: Arc<RwLock<HashMap<String, SessionVelocity>>>,
    path_patterns: Vec<glob::Pattern>,
    excluded_patterns: Vec<glob::Pattern>,
}

impl BlastRadiusGuard {
    /// Create a new blast radius guard with configuration
    pub fn with_config(config: BlastRadiusConfig) -> Self {
        let path_patterns = config
            .critical_paths
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        let excluded_patterns = config
            .excluded_paths
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Self {
            config,
            dependency_resolver: Arc::new(FileSystemDependencyResolver::new()),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            path_patterns,
            excluded_patterns,
        }
    }

    /// Set a custom dependency resolver
    pub fn with_resolver(mut self, resolver: Arc<dyn DependencyResolver>) -> Self {
        self.dependency_resolver = resolver;
        self
    }

    /// Assess the blast radius of a proposed action
    pub async fn assess(&self, action: &GuardAction<'_>, context: &GuardContext) -> BlastRadiusAssessment {
        let factors = self.analyze_factors(action, context).await;
        let breakdown = self.calculate_breakdown(&factors, context).await;
        let score = self.calculate_score(&breakdown);

        let explanation = self.generate_explanation(&factors, &score);
        let recommendations = self.generate_recommendations(&factors, &score);

        BlastRadiusAssessment {
            score,
            category: score.category(),
            factors,
            breakdown,
            explanation,
            recommendations,
        }
    }

    /// Analyze factors contributing to blast radius
    async fn analyze_factors(&self, action: &GuardAction<'_>, context: &GuardContext) -> BlastRadiusFactors {
        let mut factors = BlastRadiusFactors::default();

        match action {
            GuardAction::FileWrite(path, _) | GuardAction::FileAccess(path) => {
                factors.operation_type = if matches!(action, GuardAction::FileWrite(_, _)) {
                    OperationType::Modify
                } else {
                    OperationType::Read
                };

                // Check version control
                factors.version_controlled = self.is_version_controlled(path);

                // Check dependencies
                if self.config.analyze_dependencies {
                    let dependents = self.dependency_resolver.get_dependents(path);
                    factors.dependent_systems = dependents.len() as u32;
                    factors.dependency_depth = self.dependency_resolver.get_dependency_depth(path);
                }

                // Check if critical path
                if self.is_critical_path(path) {
                    factors.sensitivity = ResourceSensitivity::Restricted;
                }

                factors.files_affected = 1;
            }
            GuardAction::ShellCommand(cmd) => {
                factors.operation_type = OperationType::Execute;

                // Analyze command for destructive patterns
                if cmd.contains("rm ") || cmd.contains("del ") {
                    factors.operation_type = OperationType::Delete;
                    if cmd.contains("-r") || cmd.contains("-rf") || cmd.contains("/s") {
                        factors.recursive = true;
                        factors.files_affected = 100; // Assume worst case
                    }
                }

                if cmd.contains("drop ") || cmd.contains("truncate ") {
                    factors.sensitivity = ResourceSensitivity::Restricted;
                    factors.users_impacted = 100;
                }
            }
            GuardAction::Patch(path, _diff) => {
                factors.operation_type = OperationType::Modify;
                factors.version_controlled = self.is_version_controlled(path);
                factors.files_affected = 1;

                if self.is_critical_path(path) {
                    factors.sensitivity = ResourceSensitivity::Restricted;
                }
            }
            _ => {}
        }

        factors
    }

    /// Calculate score breakdown
    async fn calculate_breakdown(&self, factors: &BlastRadiusFactors, context: &GuardContext) -> ScoreBreakdown {
        // Scope score (0-100)
        let scope_score = self.calculate_scope_score(factors);

        // Reversibility score (0-100, higher = less reversible = more risk)
        let reversibility_score = self.calculate_reversibility_score(factors);

        // Dependency score (0-100)
        let dependency_score = self.calculate_dependency_score(factors);

        // Sensitivity score (0-100)
        let sensitivity_score = self.calculate_sensitivity_score(factors);

        // Velocity score (0-100)
        let velocity_score = if self.config.track_velocity {
            self.calculate_velocity_score(context).await
        } else {
            0.0
        };

        ScoreBreakdown {
            scope_score,
            reversibility_score,
            dependency_score,
            sensitivity_score,
            velocity_score,
            weights: self.config.weights.clone(),
        }
    }

    fn calculate_scope_score(&self, factors: &BlastRadiusFactors) -> f32 {
        let file_score = (factors.files_affected as f32).log2().min(6.0) / 6.0 * 100.0;
        let user_score = (factors.users_impacted as f32).log2().min(7.0) / 7.0 * 100.0;
        let recursive_bonus = if factors.recursive { 30.0 } else { 0.0 };

        ((file_score + user_score) / 2.0 + recursive_bonus).min(100.0)
    }

    fn calculate_reversibility_score(&self, factors: &BlastRadiusFactors) -> f32 {
        let mut score = 50.0; // Base score

        if factors.version_controlled {
            score -= 30.0;
        }
        if factors.backup_exists {
            score -= 20.0;
        }
        if factors.idempotent {
            score -= 20.0;
        }
        if factors.operation_type == OperationType::Delete {
            score += 40.0;
        }

        score.clamp(0.0, 100.0)
    }

    fn calculate_dependency_score(&self, factors: &BlastRadiusFactors) -> f32 {
        let system_score = (factors.dependent_systems as f32).log2().min(5.0) / 5.0 * 60.0;
        let depth_score = (factors.dependency_depth as f32 / 5.0).min(1.0) * 40.0;

        (system_score + depth_score).min(100.0)
    }

    fn calculate_sensitivity_score(&self, factors: &BlastRadiusFactors) -> f32 {
        match factors.sensitivity {
            ResourceSensitivity::Public => 10.0,
            ResourceSensitivity::Internal => 30.0,
            ResourceSensitivity::Confidential => 60.0,
            ResourceSensitivity::Restricted => 90.0,
        }
    }

    async fn calculate_velocity_score(&self, context: &GuardContext) -> f32 {
        let session_id = context.session_id.as_deref().unwrap_or("unknown");
        let now = chrono::Utc::now();
        let window = chrono::Duration::seconds(self.config.velocity_window_secs as i64);

        let sessions = self.sessions.read().await;
        if let Some(state) = sessions.get(session_id) {
            let recent_count = state
                .destructive_ops
                .iter()
                .filter(|(ts, _)| now - *ts < window)
                .count();

            // More than 5 destructive ops in window = high velocity
            ((recent_count as f32 / 5.0) * 100.0).min(100.0)
        } else {
            0.0
        }
    }

    fn calculate_score(&self, breakdown: &ScoreBreakdown) -> BlastRadiusScore {
        let w = &breakdown.weights;
        let weighted_sum = breakdown.scope_score * w.scope
            + breakdown.reversibility_score * w.reversibility
            + breakdown.dependency_score * w.dependencies
            + breakdown.sensitivity_score * w.sensitivity
            + breakdown.velocity_score * w.velocity;

        BlastRadiusScore::new(weighted_sum as u8)
    }

    fn is_version_controlled(&self, path: &str) -> bool {
        // Check if .git exists in parent directories
        let path = std::path::Path::new(path);
        let mut current = path.parent();
        while let Some(dir) = current {
            if dir.join(".git").exists() {
                return true;
            }
            current = dir.parent();
        }
        false
    }

    fn is_critical_path(&self, path: &str) -> bool {
        self.path_patterns.iter().any(|p| p.matches(path))
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.excluded_patterns.iter().any(|p| p.matches(path))
    }

    fn generate_explanation(&self, factors: &BlastRadiusFactors, score: &BlastRadiusScore) -> String {
        let mut parts = Vec::new();

        if factors.files_affected > 10 {
            parts.push(format!("affects {} files", factors.files_affected));
        }
        if factors.dependent_systems > 0 {
            parts.push(format!("{} dependent systems", factors.dependent_systems));
        }
        if !factors.version_controlled {
            parts.push("not under version control".to_string());
        }
        if factors.recursive {
            parts.push("recursive operation".to_string());
        }
        if factors.sensitivity == ResourceSensitivity::Restricted {
            parts.push("critical resource".to_string());
        }

        if parts.is_empty() {
            format!("Blast radius score: {} ({:?})", score.0, score.category())
        } else {
            format!(
                "Blast radius score: {} ({:?}): {}",
                score.0,
                score.category(),
                parts.join(", ")
            )
        }
    }

    fn generate_recommendations(&self, factors: &BlastRadiusFactors, score: &BlastRadiusScore) -> Vec<String> {
        let mut recs = Vec::new();

        if !factors.version_controlled {
            recs.push("Consider putting this resource under version control".to_string());
        }
        if factors.operation_type == OperationType::Delete && !factors.backup_exists {
            recs.push("Create a backup before proceeding with deletion".to_string());
        }
        if factors.recursive {
            recs.push("Review the scope of this recursive operation carefully".to_string());
        }
        if score.category() == BlastRadiusCategory::Critical {
            recs.push("This operation requires human approval".to_string());
        }

        recs
    }

    /// Record a destructive operation for velocity tracking
    async fn record_destructive_op(&self, session_id: &str, resource: &str) {
        if !self.config.track_velocity {
            return;
        }

        let mut sessions = self.sessions.write().await;
        let state = sessions.entry(session_id.to_string()).or_default();
        state.destructive_ops.push((chrono::Utc::now(), resource.to_string()));

        // Cleanup old entries
        let window = chrono::Duration::seconds(self.config.velocity_window_secs as i64);
        let now = chrono::Utc::now();
        state.destructive_ops.retain(|(ts, _)| now - *ts < window);
    }
}

impl Default for BlastRadiusGuard {
    fn default() -> Self {
        Self::with_config(BlastRadiusConfig::default())
    }
}

#[async_trait]
impl Guard for BlastRadiusGuard {
    fn name(&self) -> &str {
        "blast_radius"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        // Only analyze potentially destructive operations
        matches!(
            action,
            GuardAction::FileWrite(_, _)
                | GuardAction::ShellCommand(_)
                | GuardAction::Patch(_, _)
        )
    }

    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
        if !self.config.enabled {
            return GuardResult::allow(self.name());
        }

        // Skip excluded paths
        if let GuardAction::FileWrite(path, _) | GuardAction::Patch(path, _) = action {
            if self.is_excluded(path) {
                return GuardResult::allow(self.name());
            }
        }

        let assessment = self.assess(action, context).await;

        // Record for velocity tracking if destructive
        if matches!(
            assessment.factors.operation_type,
            OperationType::Delete | OperationType::Modify
        ) {
            let resource = match action {
                GuardAction::FileWrite(path, _) | GuardAction::Patch(path, _) => *path,
                GuardAction::ShellCommand(cmd) => *cmd,
                _ => "unknown",
            };
            let session_id = context.session_id.as_deref().unwrap_or("unknown");
            self.record_destructive_op(session_id, resource).await;
        }

        // Determine result based on thresholds
        if assessment.score.0 >= self.config.block_threshold {
            GuardResult::block(
                self.name(),
                Severity::Critical,
                assessment.explanation,
            )
            .with_details(serde_json::to_value(&assessment).unwrap_or_default())
        } else if assessment.score.0 >= self.config.warn_threshold {
            GuardResult::warn(self.name(), assessment.explanation)
                .with_details(serde_json::to_value(&assessment).unwrap_or_default())
        } else {
            GuardResult::allow(self.name())
                .with_details(serde_json::to_value(&assessment).unwrap_or_default())
        }
    }
}
```

### 3.2 TypeScript Interface

```typescript
/**
 * @clawdstrike/openclaw - Blast Radius Guard
 *
 * Quantifies the potential impact of proposed actions.
 */

import type { Guard, GuardResult, PolicyEvent, Policy, Severity } from '../types.js';

/** Blast radius score (0-100) */
export interface BlastRadiusScore {
  value: number;
  category: BlastRadiusCategory;
}

/** Blast radius category */
export type BlastRadiusCategory = 'low' | 'moderate' | 'high' | 'critical';

/** Resource sensitivity classification */
export type ResourceSensitivity = 'public' | 'internal' | 'confidential' | 'restricted';

/** Operation type */
export type OperationType = 'read' | 'create' | 'modify' | 'delete' | 'execute';

/** Factors contributing to blast radius */
export interface BlastRadiusFactors {
  filesAffected: number;
  usersImpacted: number;
  dependentSystems: number;
  versionControlled: boolean;
  backupExists: boolean;
  idempotent: boolean;
  sensitivity: ResourceSensitivity;
  operationType: OperationType;
  dependencyDepth: number;
  recursive: boolean;
}

/** Score breakdown */
export interface ScoreBreakdown {
  scopeScore: number;
  reversibilityScore: number;
  dependencyScore: number;
  sensitivityScore: number;
  velocityScore: number;
  weights: ScoreWeights;
}

/** Configurable weights */
export interface ScoreWeights {
  scope: number;
  reversibility: number;
  dependencies: number;
  sensitivity: number;
  velocity: number;
}

/** Blast radius assessment result */
export interface BlastRadiusAssessment {
  score: BlastRadiusScore;
  factors: BlastRadiusFactors;
  breakdown: ScoreBreakdown;
  explanation: string;
  recommendations: string[];
}

/** Blast radius guard configuration */
export interface BlastRadiusConfig {
  enabled?: boolean;
  blockThreshold?: number;
  warnThreshold?: number;
  weights?: Partial<ScoreWeights>;
  criticalPaths?: string[];
  excludedPaths?: string[];
  analyzeDependencies?: boolean;
  maxDependencyDepth?: number;
  trackVelocity?: boolean;
  velocityWindowSecs?: number;
}

/** Dependency resolver interface */
export interface DependencyResolver {
  getDependents(resource: string): Promise<string[]>;
  getDependencyDepth(resource: string): Promise<number>;
  isCritical(resource: string): boolean;
}

/**
 * BlastRadiusGuard - Quantifies action impact
 */
export class BlastRadiusGuard implements Guard {
  private config: Required<BlastRadiusConfig>;
  private sessions: Map<string, Array<{ timestamp: Date; resource: string }>> = new Map();

  constructor(config: BlastRadiusConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      blockThreshold: config.blockThreshold ?? 75,
      warnThreshold: config.warnThreshold ?? 50,
      weights: {
        scope: config.weights?.scope ?? 0.25,
        reversibility: config.weights?.reversibility ?? 0.25,
        dependencies: config.weights?.dependencies ?? 0.20,
        sensitivity: config.weights?.sensitivity ?? 0.20,
        velocity: config.weights?.velocity ?? 0.10,
      },
      criticalPaths: config.criticalPaths ?? [
        '**/package.json',
        '**/Cargo.toml',
        '**/go.mod',
        '**/.env*',
      ],
      excludedPaths: config.excludedPaths ?? [
        '**/node_modules/**',
        '**/target/**',
        '**/.git/**',
      ],
      analyzeDependencies: config.analyzeDependencies ?? true,
      maxDependencyDepth: config.maxDependencyDepth ?? 3,
      trackVelocity: config.trackVelocity ?? true,
      velocityWindowSecs: config.velocityWindowSecs ?? 300,
    };
  }

  name(): string {
    return 'blast_radius';
  }

  handles(): Array<import('../types.js').EventType> {
    return ['file_write', 'command_exec', 'patch_apply'];
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  async check(event: PolicyEvent, _policy: Policy): Promise<GuardResult> {
    if (!this.config.enabled) {
      return { status: 'allow', guard: this.name() };
    }

    const assessment = await this.assess(event);

    if (assessment.score.value >= this.config.blockThreshold) {
      return {
        status: 'deny',
        reason: assessment.explanation,
        severity: 'critical',
        guard: this.name(),
      };
    }

    if (assessment.score.value >= this.config.warnThreshold) {
      return {
        status: 'warn',
        reason: assessment.explanation,
        guard: this.name(),
      };
    }

    return { status: 'allow', guard: this.name() };
  }

  /**
   * Assess the blast radius of an event
   */
  async assess(event: PolicyEvent): Promise<BlastRadiusAssessment> {
    const factors = this.analyzeFactors(event);
    const breakdown = this.calculateBreakdown(factors, event.sessionId);
    const score = this.calculateScore(breakdown);

    return {
      score,
      factors,
      breakdown,
      explanation: this.generateExplanation(factors, score),
      recommendations: this.generateRecommendations(factors, score),
    };
  }

  private analyzeFactors(event: PolicyEvent): BlastRadiusFactors {
    const factors: BlastRadiusFactors = {
      filesAffected: 1,
      usersImpacted: 0,
      dependentSystems: 0,
      versionControlled: false,
      backupExists: false,
      idempotent: false,
      sensitivity: 'public',
      operationType: 'read',
      dependencyDepth: 0,
      recursive: false,
    };

    if (event.data.type === 'file') {
      factors.operationType = event.data.operation === 'write' ? 'modify' : 'read';

      // Check if critical path
      const path = event.data.path;
      if (this.isCriticalPath(path)) {
        factors.sensitivity = 'restricted';
        factors.dependencyDepth = 3;
      }
    } else if (event.data.type === 'command') {
      factors.operationType = 'execute';
      const cmd = event.data.command;

      if (cmd.includes('rm ') || cmd.includes('del ')) {
        factors.operationType = 'delete';
        if (cmd.includes('-r') || cmd.includes('-rf')) {
          factors.recursive = true;
          factors.filesAffected = 100;
        }
      }
    }

    return factors;
  }

  private calculateBreakdown(factors: BlastRadiusFactors, sessionId?: string): ScoreBreakdown {
    return {
      scopeScore: this.calculateScopeScore(factors),
      reversibilityScore: this.calculateReversibilityScore(factors),
      dependencyScore: this.calculateDependencyScore(factors),
      sensitivityScore: this.calculateSensitivityScore(factors),
      velocityScore: this.calculateVelocityScore(sessionId),
      weights: this.config.weights as ScoreWeights,
    };
  }

  private calculateScopeScore(factors: BlastRadiusFactors): number {
    const fileScore = Math.min(Math.log2(factors.filesAffected), 6) / 6 * 100;
    const recursiveBonus = factors.recursive ? 30 : 0;
    return Math.min(fileScore + recursiveBonus, 100);
  }

  private calculateReversibilityScore(factors: BlastRadiusFactors): number {
    let score = 50;
    if (factors.versionControlled) score -= 30;
    if (factors.backupExists) score -= 20;
    if (factors.operationType === 'delete') score += 40;
    return Math.max(0, Math.min(100, score));
  }

  private calculateDependencyScore(factors: BlastRadiusFactors): number {
    return Math.min(
      (Math.log2(factors.dependentSystems + 1) / 5) * 60 +
      (factors.dependencyDepth / 5) * 40,
      100
    );
  }

  private calculateSensitivityScore(factors: BlastRadiusFactors): number {
    const scores: Record<ResourceSensitivity, number> = {
      public: 10,
      internal: 30,
      confidential: 60,
      restricted: 90,
    };
    return scores[factors.sensitivity];
  }

  private calculateVelocityScore(sessionId?: string): number {
    if (!this.config.trackVelocity || !sessionId) return 0;

    const state = this.sessions.get(sessionId);
    if (!state) return 0;

    const windowMs = this.config.velocityWindowSecs * 1000;
    const now = Date.now();
    const recentCount = state.filter(
      (op) => now - op.timestamp.getTime() < windowMs
    ).length;

    return Math.min((recentCount / 5) * 100, 100);
  }

  private calculateScore(breakdown: ScoreBreakdown): BlastRadiusScore {
    const w = breakdown.weights;
    const weighted =
      breakdown.scopeScore * w.scope +
      breakdown.reversibilityScore * w.reversibility +
      breakdown.dependencyScore * w.dependencies +
      breakdown.sensitivityScore * w.sensitivity +
      breakdown.velocityScore * w.velocity;

    const value = Math.min(Math.round(weighted), 100);
    return {
      value,
      category: this.getCategory(value),
    };
  }

  private getCategory(score: number): BlastRadiusCategory {
    if (score <= 25) return 'low';
    if (score <= 50) return 'moderate';
    if (score <= 75) return 'high';
    return 'critical';
  }

  private isCriticalPath(path: string): boolean {
    return this.config.criticalPaths.some((pattern) =>
      this.globMatch(pattern, path)
    );
  }

  private globMatch(pattern: string, path: string): boolean {
    const regex = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*');
    return new RegExp(`^${regex}$`).test(path);
  }

  private generateExplanation(
    factors: BlastRadiusFactors,
    score: BlastRadiusScore
  ): string {
    const parts: string[] = [];
    if (factors.filesAffected > 10) {
      parts.push(`affects ${factors.filesAffected} files`);
    }
    if (factors.recursive) {
      parts.push('recursive operation');
    }
    if (factors.sensitivity === 'restricted') {
      parts.push('critical resource');
    }

    const base = `Blast radius: ${score.value} (${score.category})`;
    return parts.length > 0 ? `${base}: ${parts.join(', ')}` : base;
  }

  private generateRecommendations(
    factors: BlastRadiusFactors,
    score: BlastRadiusScore
  ): string[] {
    const recs: string[] = [];
    if (!factors.versionControlled) {
      recs.push('Consider version controlling this resource');
    }
    if (factors.operationType === 'delete' && !factors.backupExists) {
      recs.push('Create a backup before deletion');
    }
    if (score.category === 'critical') {
      recs.push('Requires human approval');
    }
    return recs;
  }
}
```

---

## 4. Data Models and Schemas

### 4.1 Configuration Schema

```yaml
$schema: http://json-schema.org/draft-07/schema#
title: BlastRadiusConfig
type: object
properties:
  enabled:
    type: boolean
    default: true
  block_threshold:
    type: integer
    minimum: 0
    maximum: 100
    default: 75
  warn_threshold:
    type: integer
    minimum: 0
    maximum: 100
    default: 50
  weights:
    type: object
    properties:
      scope: { type: number, minimum: 0, maximum: 1 }
      reversibility: { type: number, minimum: 0, maximum: 1 }
      dependencies: { type: number, minimum: 0, maximum: 1 }
      sensitivity: { type: number, minimum: 0, maximum: 1 }
      velocity: { type: number, minimum: 0, maximum: 1 }
  critical_paths:
    type: array
    items: { type: string }
  excluded_paths:
    type: array
    items: { type: string }
  analyze_dependencies:
    type: boolean
    default: true
  max_dependency_depth:
    type: integer
    minimum: 1
    default: 3
  track_velocity:
    type: boolean
    default: true
  velocity_window_secs:
    type: integer
    minimum: 1
    default: 300
```

### 4.2 Assessment Result Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "BlastRadiusAssessment",
  "type": "object",
  "properties": {
    "score": {
      "type": "object",
      "properties": {
        "value": { "type": "integer", "minimum": 0, "maximum": 100 },
        "category": { "enum": ["low", "moderate", "high", "critical"] }
      },
      "required": ["value", "category"]
    },
    "factors": { "$ref": "#/definitions/BlastRadiusFactors" },
    "breakdown": { "$ref": "#/definitions/ScoreBreakdown" },
    "explanation": { "type": "string" },
    "recommendations": {
      "type": "array",
      "items": { "type": "string" }
    }
  },
  "required": ["score", "factors", "breakdown", "explanation"]
}
```

---

## 5. Integration Points

### 5.1 Policy Configuration

```yaml
version: "1.1.0"
name: "blast-radius-enabled"
guards:
  blast_radius:
    enabled: true
    block_threshold: 80
    warn_threshold: 60
    weights:
      scope: 0.30
      reversibility: 0.25
      dependencies: 0.25
      sensitivity: 0.15
      velocity: 0.05
    critical_paths:
      - "**/infrastructure/**"
      - "**/database/migrations/**"
```

### 5.2 Engine Integration

The blast radius guard integrates into the standard guard chain but returns enriched results:

```rust
let report = engine.check_action_report(&action, &context).await?;

// Access blast radius assessment if available
if let Some(details) = report.per_guard.iter()
    .find(|r| r.guard == "blast_radius")
    .and_then(|r| r.details.as_ref())
{
    let assessment: BlastRadiusAssessment = serde_json::from_value(details.clone())?;
    println!("Blast radius: {} ({:?})", assessment.score.0, assessment.score.category());
}
```

---

## 6. Performance Considerations

### 6.1 Caching Strategy

```rust
/// Cached dependency analysis
struct DependencyCache {
    /// File -> dependents mapping
    dependents: LruCache<String, Vec<String>>,
    /// File -> depth mapping
    depths: LruCache<String, u32>,
    /// TTL for cache entries
    ttl: Duration,
}

impl DependencyCache {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            dependents: LruCache::new(capacity),
            depths: LruCache::new(capacity),
            ttl,
        }
    }
}
```

### 6.2 Lazy Analysis

Dependency analysis is only performed when needed:

```rust
impl BlastRadiusGuard {
    async fn analyze_factors(&self, action: &GuardAction<'_>, context: &GuardContext) -> BlastRadiusFactors {
        let mut factors = BlastRadiusFactors::default();

        // Quick checks first (no I/O)
        factors.operation_type = self.classify_operation(action);

        // Skip expensive analysis for low-risk operations
        if factors.operation_type == OperationType::Read {
            return factors;
        }

        // Dependency analysis only if enabled and needed
        if self.config.analyze_dependencies {
            factors.dependent_systems = self.resolve_dependents(action).await;
        }

        factors
    }
}
```

### 6.3 Latency Targets

| Operation | Target | Strategy |
|-----------|--------|----------|
| Factor analysis | < 5ms | Heuristics, cached lookups |
| Score calculation | < 1ms | Pure computation |
| Dependency resolution | < 50ms | Cached graph traversal |
| Full assessment | < 60ms | Parallel analysis where possible |

---

## 7. Security Considerations

### 7.1 Gaming Prevention

Attackers might try to manipulate the blast radius score:

- **Split operations**: Break large deletes into many small ones
- **Path obfuscation**: Use symlinks or .. traversal
- **Velocity evasion**: Space out destructive operations

Mitigations:
- Track cumulative session impact
- Normalize and resolve paths before analysis
- Consider operation history in scoring

### 7.2 Fail-Safe Defaults

```rust
impl Default for BlastRadiusConfig {
    fn default() -> Self {
        Self {
            // Conservative defaults
            block_threshold: 75,  // Block high-risk by default
            warn_threshold: 50,   // Warn on moderate risk
            // ...
        }
    }
}
```

---

## 8. Implementation Phases

### Phase 1: Core Scoring (Week 1-2)
- [ ] Factor analysis for file operations
- [ ] Basic score calculation
- [ ] Guard integration

### Phase 2: Dependency Analysis (Week 2-3)
- [ ] File system dependency resolver
- [ ] Package manifest parsing
- [ ] Import/require analysis

### Phase 3: Velocity Tracking (Week 3-4)
- [ ] Session state management
- [ ] Velocity score calculation
- [ ] Threshold tuning

### Phase 4: Testing and Tuning (Week 4)
- [ ] Benchmarks for latency
- [ ] False positive analysis
- [ ] Weight optimization

---

## 9. Related Documents

- [overview.md](./overview.md) - Threat Intelligence Overview
- [honeypots.md](./honeypots.md) - Honeypot Architecture
- [cve-guards.md](./cve-guards.md) - CVE-Aware Guards
