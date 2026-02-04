# Build Your Own EDR (Endpoint Detection & Response)

## Problem Statement

Organizations deploying AI agents need real-time visibility into agent behavior with the ability to detect, investigate, and respond to security threats. Traditional EDR solutions don't understand AI-specific attack vectors like prompt injection, credential exfiltration via tool outputs, or malicious code generation.

## Target Persona

- **Security Engineers** building AI-aware threat detection
- **SOC Teams** needing AI agent telemetry in their SIEM
- **Platform Teams** responsible for agent fleet security
- **Compliance Officers** requiring audit trails for AI actions

## Architecture Diagram

```
+------------------------------------------------------------------+
|                         Agent Fleet                               |
|  +------------+  +------------+  +------------+  +------------+  |
|  | Agent 1    |  | Agent 2    |  | Agent 3    |  | Agent N    |  |
|  | Clawdstrike|  | Clawdstrike|  | Clawdstrike|  | Clawdstrike|  |
|  +-----+------+  +-----+------+  +-----+------+  +-----+------+  |
+--------|--------------|--------------|--------------|-----------+
         |              |              |              |
         v              v              v              v
+------------------------------------------------------------------+
|                    Event Collection Layer                         |
|  +-------------------------------------------------------------+ |
|  |                     Kafka / NATS / Redis Streams            | |
|  |  Topics: agent.events, agent.violations, agent.audit        | |
|  +-------------------------------------------------------------+ |
+------------------------------------------------------------------+
         |              |              |              |
         v              v              v              v
+------------------------------------------------------------------+
|                    Processing Layer                               |
|  +---------------+  +---------------+  +------------------+      |
|  | Stream        |  | Correlation   |  | ML Anomaly       |      |
|  | Processor     |  | Engine        |  | Detection        |      |
|  | (Real-time)   |  | (Sessionize)  |  | (Behavioral)     |      |
|  +---------------+  +---------------+  +------------------+      |
+------------------------------------------------------------------+
         |              |              |              |
         v              v              v              v
+------------------------------------------------------------------+
|                    Detection & Response                           |
|  +---------------+  +---------------+  +------------------+      |
|  | Rule Engine   |  | Threat Intel  |  | Response         |      |
|  | (YARA-style)  |  | Enrichment    |  | Orchestrator     |      |
|  +---------------+  +---------------+  +------------------+      |
+------------------------------------------------------------------+
         |              |              |              |
         v              v              v              v
+------------------------------------------------------------------+
|                    Storage & Visualization                        |
|  +---------------+  +---------------+  +------------------+      |
|  | TimescaleDB   |  | Elasticsearch |  | Grafana/Kibana   |      |
|  | (Metrics)     |  | (Events)      |  | (Dashboards)     |      |
|  +---------------+  +---------------+  +------------------+      |
+------------------------------------------------------------------+
```

## Component Breakdown

### 1. Agent Instrumentation Layer

Each agent runs with Clawdstrike embedded, emitting telemetry:

```rust
// agent-instrumentation/src/lib.rs
use clawdstrike::{HushEngine, Policy, GuardContext, GuardResult};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

#[derive(Clone, Serialize)]
pub struct AgentTelemetry {
    pub agent_id: String,
    pub session_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: EventType,
    pub action: ActionDetails,
    pub result: GuardResultSummary,
    pub context: serde_json::Value,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    FileAccess,
    FileWrite,
    NetworkEgress,
    ShellCommand,
    McpTool,
    PatchApply,
    PromptInjectionAttempt,
}

#[derive(Clone, Serialize)]
pub struct ActionDetails {
    pub target: String,
    pub content_hash: Option<String>,
    pub args: Option<serde_json::Value>,
}

#[derive(Clone, Serialize)]
pub struct GuardResultSummary {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
}

pub struct InstrumentedAgent {
    engine: HushEngine,
    agent_id: String,
    session_id: String,
    telemetry_tx: mpsc::Sender<AgentTelemetry>,
}

impl InstrumentedAgent {
    pub fn new(
        policy: Policy,
        agent_id: String,
        telemetry_tx: mpsc::Sender<AgentTelemetry>,
    ) -> Self {
        Self {
            engine: HushEngine::with_policy(policy).with_generated_keypair(),
            agent_id,
            session_id: uuid::Uuid::new_v4().to_string(),
            telemetry_tx,
        }
    }

    pub async fn check_file_access(&self, path: &str) -> anyhow::Result<bool> {
        let ctx = GuardContext::new()
            .with_session_id(&self.session_id)
            .with_agent_id(&self.agent_id);

        let result = self.engine.check_file_access(path, &ctx).await?;

        self.emit_telemetry(EventType::FileAccess, ActionDetails {
            target: path.to_string(),
            content_hash: None,
            args: None,
        }, &result).await;

        Ok(result.allowed)
    }

    pub async fn check_egress(&self, host: &str, port: u16) -> anyhow::Result<bool> {
        let ctx = GuardContext::new()
            .with_session_id(&self.session_id)
            .with_agent_id(&self.agent_id);

        let result = self.engine.check_egress(host, port, &ctx).await?;

        self.emit_telemetry(EventType::NetworkEgress, ActionDetails {
            target: format!("{}:{}", host, port),
            content_hash: None,
            args: None,
        }, &result).await;

        Ok(result.allowed)
    }

    async fn emit_telemetry(
        &self,
        event_type: EventType,
        action: ActionDetails,
        result: &GuardResult,
    ) {
        let telemetry = AgentTelemetry {
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            timestamp: chrono::Utc::now(),
            event_type,
            action,
            result: GuardResultSummary {
                allowed: result.allowed,
                guard: result.guard.clone(),
                severity: format!("{:?}", result.severity),
                message: result.message.clone(),
            },
            context: serde_json::json!({}),
        };

        if let Err(e) = self.telemetry_tx.send(telemetry).await {
            tracing::warn!("Failed to send telemetry: {}", e);
        }
    }
}
```

### 2. Event Collection Layer

Kafka-based event streaming for high-throughput collection:

```yaml
# kafka-config.yaml
version: '3.8'
services:
  kafka:
    image: confluentinc/cp-kafka:7.5.0
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: 'true'
    ports:
      - "9092:9092"

  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  schema-registry:
    image: confluentinc/cp-schema-registry:7.5.0
    environment:
      SCHEMA_REGISTRY_HOST_NAME: schema-registry
      SCHEMA_REGISTRY_KAFKASTORE_BOOTSTRAP_SERVERS: kafka:9092
    ports:
      - "8081:8081"
```

```rust
// event-collector/src/kafka_producer.rs
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

pub struct TelemetryProducer {
    producer: FutureProducer,
    events_topic: String,
    violations_topic: String,
}

impl TelemetryProducer {
    pub fn new(brokers: &str) -> anyhow::Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .set("compression.type", "lz4")
            .create()?;

        Ok(Self {
            producer,
            events_topic: "agent.events".to_string(),
            violations_topic: "agent.violations".to_string(),
        })
    }

    pub async fn send_event(&self, telemetry: &AgentTelemetry) -> anyhow::Result<()> {
        let payload = serde_json::to_string(telemetry)?;
        let key = format!("{}:{}", telemetry.agent_id, telemetry.session_id);

        let topic = if telemetry.result.allowed {
            &self.events_topic
        } else {
            &self.violations_topic
        };

        self.producer
            .send(
                FutureRecord::to(topic)
                    .payload(&payload)
                    .key(&key),
                Duration::from_secs(5),
            )
            .await
            .map_err(|(e, _)| anyhow::anyhow!("Kafka send error: {}", e))?;

        Ok(())
    }
}
```

### 3. Stream Processing Layer

Real-time event processing with session correlation:

```rust
// stream-processor/src/main.rs
use rdkafka::consumer::{StreamConsumer, Consumer};
use rdkafka::Message;
use std::collections::HashMap;
use tokio::time::{interval, Duration};

#[derive(Default)]
struct SessionState {
    events: Vec<AgentTelemetry>,
    violation_count: u32,
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    unique_targets: std::collections::HashSet<String>,
    risk_score: f64,
}

struct StreamProcessor {
    sessions: HashMap<String, SessionState>,
    detector: AnomalyDetector,
    rule_engine: RuleEngine,
}

impl StreamProcessor {
    pub async fn process_event(&mut self, telemetry: AgentTelemetry) -> Vec<Alert> {
        let session_key = format!("{}:{}", telemetry.agent_id, telemetry.session_id);

        let session = self.sessions
            .entry(session_key.clone())
            .or_default();

        // Update session state
        session.events.push(telemetry.clone());
        session.last_seen = Some(telemetry.timestamp);
        if session.first_seen.is_none() {
            session.first_seen = Some(telemetry.timestamp);
        }
        session.unique_targets.insert(telemetry.action.target.clone());

        if !telemetry.result.allowed {
            session.violation_count += 1;
        }

        // Calculate risk score
        session.risk_score = self.calculate_risk_score(session);

        // Run detection
        let mut alerts = Vec::new();

        // Rule-based detection
        alerts.extend(self.rule_engine.evaluate(&telemetry, session));

        // Anomaly detection
        if let Some(anomaly) = self.detector.check(&telemetry, session) {
            alerts.push(anomaly);
        }

        alerts
    }

    fn calculate_risk_score(&self, session: &SessionState) -> f64 {
        let mut score = 0.0;

        // Violations increase risk
        score += session.violation_count as f64 * 10.0;

        // Rapid target switching is suspicious
        let target_rate = session.unique_targets.len() as f64
            / session.events.len().max(1) as f64;
        if target_rate > 0.8 {
            score += 20.0;
        }

        // Long sessions are riskier
        if let (Some(first), Some(last)) = (session.first_seen, session.last_seen) {
            let duration = (last - first).num_minutes();
            if duration > 120 {
                score += 15.0;
            }
        }

        score.min(100.0)
    }
}
```

### 4. Detection Rules

YARA-inspired rule definitions for AI-specific threats:

```yaml
# rules/ai-threats.yaml
rules:
  - id: CREDENTIAL_EXFILTRATION
    name: "Credential Exfiltration Attempt"
    description: "Agent attempting to access and exfiltrate credentials"
    severity: critical
    conditions:
      - type: sequence
        window: 5m
        events:
          - event_type: file_access
            target_pattern: "**/.ssh/**|**/.aws/**|**/.env"
          - event_type: network_egress
            target_not_in:
              - "*.openai.com"
              - "*.anthropic.com"
              - "api.github.com"
    actions:
      - terminate_session
      - alert_soc
      - quarantine_agent

  - id: PROMPT_INJECTION_CHAIN
    name: "Prompt Injection Attack Chain"
    description: "Detected prompt injection followed by suspicious actions"
    severity: critical
    conditions:
      - type: sequence
        window: 10m
        events:
          - event_type: prompt_injection_attempt
            result.allowed: false
          - event_type: any
            result.allowed: false
            count: ">= 3"
    actions:
      - alert_soc
      - increase_logging

  - id: RAPID_FILE_ENUMERATION
    name: "Rapid File System Enumeration"
    description: "Agent rapidly accessing many files"
    severity: high
    conditions:
      - type: threshold
        window: 1m
        event_type: file_access
        count: "> 100"
        unique_targets: "> 50"
    actions:
      - rate_limit
      - alert

  - id: LATERAL_MOVEMENT_PREP
    name: "Lateral Movement Preparation"
    description: "Agent collecting system information typical of lateral movement"
    severity: high
    conditions:
      - type: pattern
        window: 30m
        all_of:
          - event_type: file_access
            target_pattern: "/etc/passwd|/etc/hosts|/etc/resolv.conf"
          - event_type: shell_command
            target_pattern: ".*whoami.*|.*hostname.*|.*ifconfig.*|.*ip addr.*"
          - event_type: network_egress
    actions:
      - alert_soc
      - snapshot_session
```

```rust
// rule-engine/src/lib.rs
use serde::{Deserialize, Serialize};
use regex::Regex;

#[derive(Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum Condition {
    #[serde(rename = "sequence")]
    Sequence {
        window: String,
        events: Vec<EventMatcher>,
    },
    #[serde(rename = "threshold")]
    Threshold {
        window: String,
        event_type: String,
        count: String,
        unique_targets: Option<String>,
    },
    #[serde(rename = "pattern")]
    Pattern {
        window: String,
        all_of: Vec<EventMatcher>,
    },
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    compiled_patterns: HashMap<String, Regex>,
}

impl RuleEngine {
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let config: RulesConfig = serde_yaml::from_str(yaml)?;
        let mut compiled_patterns = HashMap::new();

        for rule in &config.rules {
            for condition in &rule.conditions {
                // Pre-compile regex patterns
                Self::compile_condition_patterns(condition, &mut compiled_patterns)?;
            }
        }

        Ok(Self {
            rules: config.rules,
            compiled_patterns,
        })
    }

    pub fn evaluate(
        &self,
        event: &AgentTelemetry,
        session: &SessionState,
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if self.check_rule(rule, event, session) {
                alerts.push(Alert {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    agent_id: event.agent_id.clone(),
                    session_id: event.session_id.clone(),
                    timestamp: chrono::Utc::now(),
                    context: serde_json::json!({
                        "trigger_event": event,
                        "session_risk_score": session.risk_score,
                    }),
                    actions: rule.actions.clone(),
                });
            }
        }

        alerts
    }
}
```

### 5. Response Orchestrator

Automated response actions:

```rust
// response-orchestrator/src/lib.rs
use tokio::sync::mpsc;

#[derive(Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    TerminateSession { agent_id: String, session_id: String },
    QuarantineAgent { agent_id: String, duration_secs: u64 },
    RateLimit { agent_id: String, requests_per_minute: u32 },
    AlertSoc { alert: Alert },
    IncreaseLogging { agent_id: String, level: String },
    SnapshotSession { agent_id: String, session_id: String },
    UpdatePolicy { agent_id: String, policy_patch: serde_json::Value },
}

pub struct ResponseOrchestrator {
    action_tx: mpsc::Sender<ResponseAction>,
    soc_webhook: String,
    agent_control_api: String,
}

impl ResponseOrchestrator {
    pub async fn execute(&self, alert: Alert) -> anyhow::Result<()> {
        for action in &alert.actions {
            match action {
                Action::TerminateSession => {
                    self.terminate_session(&alert.agent_id, &alert.session_id).await?;
                }
                Action::AlertSoc => {
                    self.send_soc_alert(&alert).await?;
                }
                Action::QuarantineAgent => {
                    self.quarantine_agent(&alert.agent_id, 3600).await?;
                }
                Action::RateLimit => {
                    self.apply_rate_limit(&alert.agent_id, 10).await?;
                }
                Action::IncreaseLogging => {
                    self.increase_logging(&alert.agent_id).await?;
                }
                Action::SnapshotSession => {
                    self.snapshot_session(&alert.agent_id, &alert.session_id).await?;
                }
            }
        }
        Ok(())
    }

    async fn terminate_session(&self, agent_id: &str, session_id: &str) -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        client
            .post(format!("{}/agents/{}/sessions/{}/terminate",
                self.agent_control_api, agent_id, session_id))
            .send()
            .await?;

        tracing::warn!(
            agent_id = agent_id,
            session_id = session_id,
            "Session terminated due to security alert"
        );

        Ok(())
    }

    async fn send_soc_alert(&self, alert: &Alert) -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        client
            .post(&self.soc_webhook)
            .json(&serde_json::json!({
                "alert_id": uuid::Uuid::new_v4().to_string(),
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "agent_id": alert.agent_id,
                "timestamp": alert.timestamp,
                "context": alert.context,
            }))
            .send()
            .await?;

        Ok(())
    }
}
```

### 6. Storage and Visualization

TimescaleDB schema for time-series metrics:

```sql
-- timescaledb/schema.sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE agent_events (
    time TIMESTAMPTZ NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    target TEXT,
    allowed BOOLEAN NOT NULL,
    guard TEXT,
    severity TEXT,
    risk_score DOUBLE PRECISION,
    metadata JSONB
);

SELECT create_hypertable('agent_events', 'time');

-- Continuous aggregates for dashboards
CREATE MATERIALIZED VIEW agent_events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    agent_id,
    event_type,
    COUNT(*) AS event_count,
    COUNT(*) FILTER (WHERE NOT allowed) AS violation_count,
    AVG(risk_score) AS avg_risk_score
FROM agent_events
GROUP BY bucket, agent_id, event_type;

-- Retention policy
SELECT add_retention_policy('agent_events', INTERVAL '90 days');

-- Indexes for common queries
CREATE INDEX idx_agent_events_agent ON agent_events (agent_id, time DESC);
CREATE INDEX idx_agent_events_violations ON agent_events (time DESC)
    WHERE NOT allowed;
```

Grafana dashboard configuration:

```json
{
  "dashboard": {
    "title": "Clawdstrike EDR Dashboard",
    "panels": [
      {
        "title": "Agent Activity Overview",
        "type": "timeseries",
        "gridPos": { "x": 0, "y": 0, "w": 12, "h": 8 },
        "targets": [
          {
            "rawSql": "SELECT bucket, event_count, violation_count FROM agent_events_hourly WHERE bucket > NOW() - INTERVAL '24 hours' ORDER BY bucket"
          }
        ]
      },
      {
        "title": "Active Violations",
        "type": "table",
        "gridPos": { "x": 12, "y": 0, "w": 12, "h": 8 },
        "targets": [
          {
            "rawSql": "SELECT time, agent_id, event_type, target, guard, severity FROM agent_events WHERE NOT allowed AND time > NOW() - INTERVAL '1 hour' ORDER BY time DESC LIMIT 50"
          }
        ]
      },
      {
        "title": "Risk Score Heatmap",
        "type": "heatmap",
        "gridPos": { "x": 0, "y": 8, "w": 24, "h": 8 },
        "targets": [
          {
            "rawSql": "SELECT time, agent_id, risk_score FROM agent_events WHERE time > NOW() - INTERVAL '24 hours'"
          }
        ]
      }
    ]
  }
}
```

## Security Considerations

### 1. Telemetry Data Protection

```rust
// Encrypt sensitive fields before transmission
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;

pub fn encrypt_sensitive_fields(
    telemetry: &mut AgentTelemetry,
    key: &[u8; 32],
) -> anyhow::Result<()> {
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(b"unique nonce"); // Use random nonce in production

    // Encrypt target if it contains sensitive paths
    if telemetry.action.target.contains(".ssh")
        || telemetry.action.target.contains(".aws") {
        let encrypted = cipher.encrypt(nonce, telemetry.action.target.as_bytes())?;
        telemetry.action.target = format!("ENCRYPTED:{}", base64::encode(encrypted));
    }

    Ok(())
}
```

### 2. Anti-Tampering

```rust
// Sign telemetry to prevent tampering
use ed25519_dalek::{Keypair, Signature, Signer};

pub fn sign_telemetry(
    telemetry: &AgentTelemetry,
    keypair: &Keypair,
) -> Signature {
    let payload = serde_json::to_vec(telemetry).unwrap();
    keypair.sign(&payload)
}
```

### 3. Access Control

```yaml
# RBAC for EDR API
roles:
  soc_analyst:
    permissions:
      - read:events
      - read:alerts
      - read:sessions
      - write:alert_ack

  security_engineer:
    permissions:
      - read:*
      - write:rules
      - write:responses

  administrator:
    permissions:
      - "*"
```

## Scaling Considerations

### Horizontal Scaling

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stream-processor
  labels:
    app: stream-processor
spec:
  replicas: 3
  selector:
    matchLabels:
      app: stream-processor
  template:
    metadata:
      labels:
        app: stream-processor
    spec:
      containers:
      - name: processor
        image: clawdstrike/stream-processor:latest
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        env:
        - name: KAFKA_CONSUMER_GROUP
          value: "stream-processor"
        - name: KAFKA_PARTITION_ASSIGNMENT
          value: "cooperative-sticky"
```

### Event Throughput

| Scale | Events/sec | Kafka Partitions | Processor Replicas | TimescaleDB |
|-------|------------|------------------|-------------------|-------------|
| Small | 1,000 | 3 | 2 | Single node |
| Medium | 10,000 | 12 | 6 | 3-node cluster |
| Large | 100,000 | 48 | 24 | Multi-region |

## Cost Considerations

### Infrastructure Costs (Monthly, AWS)

| Component | Small | Medium | Large |
|-----------|-------|--------|-------|
| Kafka (MSK) | $200 | $800 | $3,000 |
| TimescaleDB | $100 | $400 | $1,500 |
| Elasticsearch | $150 | $600 | $2,400 |
| Compute (EKS) | $300 | $1,200 | $5,000 |
| **Total** | **$750** | **$3,000** | **$11,900** |

### Cost Optimization Tips

1. Use Kafka Tiered Storage for cold data
2. Implement aggressive retention policies
3. Sample low-risk events at high volumes
4. Use spot instances for stream processors

## Step-by-Step Implementation Guide

### Phase 1: Foundation (Week 1-2)

1. **Set up Kafka cluster**
   ```bash
   # Using Confluent Cloud (managed)
   confluent kafka cluster create clawdstrike-edr --cloud aws --region us-east-1
   confluent kafka topic create agent.events --partitions 6
   confluent kafka topic create agent.violations --partitions 6
   ```

2. **Deploy TimescaleDB**
   ```bash
   helm install timescaledb timescale/timescaledb-single \
     --set replicaCount=1 \
     --set persistentVolumes.data.size=100Gi
   ```

3. **Instrument first agent**
   ```rust
   let instrumented = InstrumentedAgent::new(
       Policy::from_yaml_file("policy.yaml")?,
       "agent-001".to_string(),
       telemetry_tx,
   );
   ```

### Phase 2: Processing (Week 2-3)

4. **Deploy stream processor**
   ```bash
   kubectl apply -f kubernetes/stream-processor.yaml
   ```

5. **Load detection rules**
   ```bash
   clawdstrike-edr rules load --file rules/ai-threats.yaml
   ```

6. **Configure response orchestrator**
   ```yaml
   # response-config.yaml
   soc_webhook: "https://siem.company.com/webhook/clawdstrike"
   agent_control_api: "http://agent-control.internal:8080"
   ```

### Phase 3: Visualization (Week 3-4)

7. **Deploy Grafana**
   ```bash
   helm install grafana grafana/grafana \
     --set datasources[0].name=TimescaleDB \
     --set datasources[0].type=postgres
   ```

8. **Import dashboards**
   ```bash
   curl -X POST http://grafana:3000/api/dashboards/db \
     -H "Content-Type: application/json" \
     -d @dashboards/edr-overview.json
   ```

9. **Set up alerts**
   ```yaml
   # grafana-alerts.yaml
   alertRules:
     - name: high-risk-agent
       condition: avg(risk_score) > 80
       for: 5m
       annotations:
         summary: "High-risk agent detected: {{ $labels.agent_id }}"
   ```

## Common Pitfalls and Solutions

### Pitfall 1: Event Storm During Incidents

**Problem**: A single compromised agent floods the system with events.

**Solution**: Implement per-agent rate limiting at the collector:

```rust
let limiter = RateLimiter::keyed(
    Quota::per_minute(nonzero!(1000u32)),
);

if limiter.check_key(&telemetry.agent_id).is_err() {
    // Drop event but record the drop
    metrics::counter!("events_dropped", "agent_id" => telemetry.agent_id).increment(1);
    return;
}
```

### Pitfall 2: High Cardinality Metrics

**Problem**: Too many unique agent/session combinations blow up TimescaleDB.

**Solution**: Use continuous aggregates and rollups:

```sql
-- Rollup old data to hourly granularity
SELECT compress_chunk(c)
FROM show_chunks('agent_events', older_than => INTERVAL '7 days') c;
```

### Pitfall 3: False Positives from Legitimate Automation

**Problem**: CI/CD pipelines trigger credential access alerts.

**Solution**: Implement context-aware allowlisting:

```yaml
allowlist:
  - agent_pattern: "ci-agent-*"
    event_types:
      - file_access
    target_patterns:
      - "**/.ssh/known_hosts"
      - "**/.gitconfig"
    time_window: "business_hours"
```

### Pitfall 4: Kafka Consumer Lag

**Problem**: Processors can't keep up with event volume.

**Solution**: Scale horizontally and use consumer groups:

```rust
// Use cooperative rebalancing for minimal disruption
config.set("partition.assignment.strategy", "cooperative-sticky");

// Process in batches
let batch_size = 100;
let batch = consumer.fetch(batch_size, Duration::from_secs(1))?;
processor.process_batch(batch).await?;
```

## Troubleshooting

### Issue: Events Not Appearing in Kafka

**Symptoms**: Agent telemetry is generated but not visible in Kafka topics.

**Solutions**:
1. Verify Kafka broker connectivity:
   ```bash
   kafka-broker-api-versions --bootstrap-server kafka:9092
   ```
2. Check producer configuration and ensure `bootstrap.servers` is correct
3. Verify topic exists and has correct partitions:
   ```bash
   kafka-topics --describe --topic agent.events --bootstrap-server kafka:9092
   ```

### Issue: High Consumer Lag

**Symptoms**: Stream processors falling behind event ingestion.

**Solutions**:
1. Scale processor replicas horizontally
2. Increase partition count to enable more parallelism
3. Check for slow detection rules causing backpressure
4. Enable batch processing for higher throughput

### Issue: False Positive Alerts

**Symptoms**: Detection rules triggering on legitimate activity.

**Solutions**:
1. Review and tune rule thresholds
2. Add context-aware allowlisting for known patterns
3. Implement feedback loop to refine rules based on analyst input
4. Use ML anomaly scoring to reduce rule-based false positives

### Issue: TimescaleDB Performance Degradation

**Symptoms**: Dashboard queries becoming slow over time.

**Solutions**:
1. Verify continuous aggregates are being refreshed
2. Check chunk compression is running on schedule
3. Review and optimize slow queries with `EXPLAIN ANALYZE`
4. Ensure retention policies are actively pruning old data

## Validation Checklist

- [ ] Agents emit telemetry for all action types
- [ ] Events flow through Kafka to processors
- [ ] Detection rules trigger on test scenarios
- [ ] Response actions execute successfully
- [ ] Dashboards display real-time data
- [ ] Alerts reach SOC team
- [ ] System handles 10x expected load
- [ ] Retention policies are enforced
- [ ] Access controls are verified
- [ ] Incident response runbook is documented
