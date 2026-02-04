# Cloud-Native Deployment Reference Architecture

## Problem Statement

Organizations running AI agents in cloud-native environments (Kubernetes, serverless, service mesh) need security controls that:

- Scale automatically with agent workloads
- Integrate with cloud-native observability (Prometheus, Jaeger, Grafana)
- Work with service mesh policies (Istio, Linkerd)
- Support ephemeral and stateless deployments
- Leverage cloud provider security services (IAM, KMS, Secrets Manager)

## Target Persona

- **Platform Engineers** managing Kubernetes clusters
- **DevOps Engineers** building CI/CD for AI workloads
- **SRE Teams** operating AI agent infrastructure
- **Cloud Architects** designing multi-cloud AI platforms

## Architecture Diagram

### Kubernetes Deployment

```
+------------------------------------------------------------------------+
|                         Kubernetes Cluster                              |
|  +------------------------------------------------------------------+  |
|  |                    Clawdstrike Operator                           |  |
|  |  +------------------+  +------------------+  +-----------------+  |  |
|  |  | Policy CRD       |  | Agent CRD        |  | Audit CRD       |  |  |
|  |  | Controller       |  | Controller       |  | Controller      |  |  |
|  |  +------------------+  +------------------+  +-----------------+  |  |
|  +------------------------------------------------------------------+  |
|                                                                         |
|  +------------------------------------------------------------------+  |
|  |                    Namespace: ai-agents                           |  |
|  |  +---------------+  +---------------+  +------------------+       |  |
|  |  | Agent Pod     |  | Agent Pod     |  | Agent Pod        |       |  |
|  |  | +-----------+ |  | +-----------+ |  | +-----------+    |       |  |
|  |  | | Agent     | |  | | Agent     | |  | | Agent     |    |       |  |
|  |  | | Container | |  | | Container | |  | | Container |    |       |  |
|  |  | +-----------+ |  | +-----------+ |  | +-----------+    |       |  |
|  |  | +-----------+ |  | +-----------+ |  | +-----------+    |       |  |
|  |  | | Clawdstrike| |  | | Clawdstrike| |  | | Clawdstrike|  |       |  |
|  |  | | Sidecar   | |  | | Sidecar   | |  | | Sidecar   |    |       |  |
|  |  | +-----------+ |  | +-----------+ |  | +-----------+    |       |  |
|  |  +---------------+  +---------------+  +------------------+       |  |
|  +------------------------------------------------------------------+  |
|                                                                         |
|  +------------------------------------------------------------------+  |
|  |                    Observability Stack                            |  |
|  |  +---------------+  +---------------+  +-----------------+        |  |
|  |  | Prometheus    |  | Jaeger        |  | Grafana         |        |  |
|  |  | (Metrics)     |  | (Traces)      |  | (Dashboards)    |        |  |
|  |  +---------------+  +---------------+  +-----------------+        |  |
|  +------------------------------------------------------------------+  |
+------------------------------------------------------------------------+
```

### Serverless Deployment

```
+------------------------------------------------------------------------+
|                        Serverless Architecture                          |
|                                                                         |
|  +------------------------------------------------------------------+  |
|  |                    API Gateway                                    |  |
|  |  (Route to appropriate function based on request)                 |  |
|  +-----------------------------+------------------------------------+  |
|                                |                                        |
|         +----------------------+----------------------+                 |
|         |                      |                      |                 |
|         v                      v                      v                 |
|  +---------------+      +---------------+      +---------------+       |
|  | Lambda/Cloud  |      | Lambda/Cloud  |      | Lambda/Cloud  |       |
|  | Function      |      | Function      |      | Function      |       |
|  | +-----------+ |      | +-----------+ |      | +-----------+ |       |
|  | | Agent     | |      | | Agent     | |      | | Agent     | |       |
|  | +-----------+ |      | +-----------+ |      | +-----------+ |       |
|  | +-----------+ |      | +-----------+ |      | +-----------+ |       |
|  | |Clawdstrike| |      | |Clawdstrike| |      | |Clawdstrike| |       |
|  | | Layer     | |      | | Layer     | |      | | Layer     | |       |
|  | +-----------+ |      | +-----------+ |      | +-----------+ |       |
|  +---------------+      +---------------+      +---------------+       |
|         |                      |                      |                 |
|         v                      v                      v                 |
|  +------------------------------------------------------------------+  |
|  |              Clawdstrike Central Service                          |  |
|  |  (Policy evaluation, audit aggregation)                           |  |
|  +------------------------------------------------------------------+  |
+------------------------------------------------------------------------+
```

## Component Breakdown

### 1. Kubernetes Operator

```yaml
# crds/clawdstrike-policy.yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clawdstrikepolicies.security.clawdstrike.io
spec:
  group: security.clawdstrike.io
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                version:
                  type: string
                  default: "1.0.0"
                extends:
                  type: string
                guards:
                  type: object
                  properties:
                    forbiddenPath:
                      type: object
                      properties:
                        patterns:
                          type: array
                          items:
                            type: string
                        exceptions:
                          type: array
                          items:
                            type: string
                    egressAllowlist:
                      type: object
                      properties:
                        allow:
                          type: array
                          items:
                            type: string
                        block:
                          type: array
                          items:
                            type: string
                        defaultAction:
                          type: string
                          enum: [allow, block]
                settings:
                  type: object
                  properties:
                    failFast:
                      type: boolean
                    verboseLogging:
                      type: boolean
                    sessionTimeoutSecs:
                      type: integer
      additionalPrinterColumns:
        - name: Extends
          type: string
          jsonPath: .spec.extends
        - name: Age
          type: date
          jsonPath: .metadata.creationTimestamp
  scope: Namespaced
  names:
    plural: clawdstrikepolicies
    singular: clawdstrikepolicy
    kind: ClawdstrikePolicy
    shortNames:
      - csp
      - cspolicy
```

```yaml
# crds/clawdstrike-agent.yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clawdstrikeagents.security.clawdstrike.io
spec:
  group: security.clawdstrike.io
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                policyRef:
                  type: string
                  description: "Reference to ClawdstrikePolicy"
                sidecarEnabled:
                  type: boolean
                  default: true
                capabilities:
                  type: array
                  items:
                    type: string
                resources:
                  type: object
                  properties:
                    limits:
                      type: object
                    requests:
                      type: object
            status:
              type: object
              properties:
                phase:
                  type: string
                violations:
                  type: integer
                lastUpdated:
                  type: string
  scope: Namespaced
  names:
    plural: clawdstrikeagents
    singular: clawdstrikeagent
    kind: ClawdstrikeAgent
    shortNames:
      - csa
```

```rust
// operator/src/main.rs
use kube::{Api, Client, CustomResource};
use kube_runtime::controller::{Action, Controller};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "security.clawdstrike.io",
    version = "v1",
    kind = "ClawdstrikePolicy",
    namespaced
)]
pub struct ClawdstrikePolicySpec {
    pub version: Option<String>,
    pub extends: Option<String>,
    pub guards: Option<Guards>,
    pub settings: Option<Settings>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Guards {
    pub forbidden_path: Option<ForbiddenPathConfig>,
    pub egress_allowlist: Option<EgressAllowlistConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ForbiddenPathConfig {
    pub patterns: Vec<String>,
    pub exceptions: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct EgressAllowlistConfig {
    pub allow: Vec<String>,
    pub block: Option<Vec<String>>,
    pub default_action: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Settings {
    pub fail_fast: Option<bool>,
    pub verbose_logging: Option<bool>,
    pub session_timeout_secs: Option<u64>,
}

struct PolicyReconciler {
    client: Client,
    policy_cache: Arc<tokio::sync::RwLock<std::collections::HashMap<String, clawdstrike::Policy>>>,
}

impl PolicyReconciler {
    async fn reconcile(
        &self,
        policy: Arc<ClawdstrikePolicy>,
    ) -> Result<Action, kube_runtime::controller::Error> {
        let name = policy.metadata.name.as_ref().unwrap();
        let namespace = policy.metadata.namespace.as_ref().unwrap();

        tracing::info!(name = %name, namespace = %namespace, "Reconciling policy");

        // Convert CRD to Clawdstrike policy
        let cs_policy = self.crd_to_policy(&policy)?;

        // Validate policy
        cs_policy.validate().map_err(|e| {
            tracing::error!(error = %e, "Policy validation failed");
            kube_runtime::controller::Error::ReconcilerFailed(Arc::new(e), Duration::from_secs(60))
        })?;

        // Cache the compiled policy
        {
            let mut cache = self.policy_cache.write().await;
            let key = format!("{}/{}", namespace, name);
            cache.insert(key, cs_policy);
        }

        // Update ConfigMap for sidecar injection
        self.update_policy_configmap(namespace, name, &policy).await?;

        Ok(Action::requeue(Duration::from_secs(300)))
    }

    fn crd_to_policy(&self, crd: &ClawdstrikePolicy) -> Result<clawdstrike::Policy, anyhow::Error> {
        let mut policy = clawdstrike::Policy::default();

        if let Some(version) = &crd.spec.version {
            policy.version = version.clone();
        }

        if let Some(guards) = &crd.spec.guards {
            if let Some(fp) = &guards.forbidden_path {
                policy.guards.forbidden_path = Some(clawdstrike::guards::ForbiddenPathConfig {
                    patterns: fp.patterns.clone(),
                    exceptions: fp.exceptions.clone().unwrap_or_default(),
                    ..Default::default()
                });
            }

            if let Some(ea) = &guards.egress_allowlist {
                policy.guards.egress_allowlist = Some(clawdstrike::guards::EgressAllowlistConfig {
                    allow: ea.allow.clone(),
                    block: ea.block.clone().unwrap_or_default(),
                    default_action: match ea.default_action.as_deref() {
                        Some("allow") => clawdstrike::guards::EgressDefaultAction::Allow,
                        _ => clawdstrike::guards::EgressDefaultAction::Block,
                    },
                    ..Default::default()
                });
            }
        }

        if let Some(settings) = &crd.spec.settings {
            policy.settings.fail_fast = settings.fail_fast.unwrap_or(false);
            policy.settings.verbose_logging = settings.verbose_logging.unwrap_or(false);
            policy.settings.session_timeout_secs = settings.session_timeout_secs.unwrap_or(3600);
        }

        Ok(policy)
    }

    async fn update_policy_configmap(
        &self,
        namespace: &str,
        name: &str,
        policy: &ClawdstrikePolicy,
    ) -> Result<(), kube_runtime::controller::Error> {
        let configmaps: Api<k8s_openapi::api::core::v1::ConfigMap> =
            Api::namespaced(self.client.clone(), namespace);

        let policy_yaml = serde_yaml::to_string(&policy.spec)
            .map_err(|e| kube_runtime::controller::Error::ReconcilerFailed(Arc::new(e), Duration::from_secs(60)))?;

        let cm = k8s_openapi::api::core::v1::ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("clawdstrike-policy-{}", name)),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            data: Some(std::collections::BTreeMap::from([
                ("policy.yaml".to_string(), policy_yaml),
            ])),
            ..Default::default()
        };

        configmaps
            .patch(
                &format!("clawdstrike-policy-{}", name),
                &kube::api::PatchParams::apply("clawdstrike-operator"),
                &kube::api::Patch::Apply(&cm),
            )
            .await
            .map_err(|e| kube_runtime::controller::Error::ReconcilerFailed(Arc::new(e), Duration::from_secs(60)))?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let client = Client::try_default().await?;

    let policies: Api<ClawdstrikePolicy> = Api::all(client.clone());

    let reconciler = Arc::new(PolicyReconciler {
        client: client.clone(),
        policy_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
    });

    Controller::new(policies, kube_runtime::watcher::Config::default())
        .run(
            |policy, ctx| {
                let reconciler = ctx.get_ref().clone();
                async move { reconciler.reconcile(policy).await }
            },
            |_policy, _error, _ctx| Action::requeue(Duration::from_secs(60)),
            Arc::clone(&reconciler),
        )
        .for_each(|result| async {
            match result {
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "Reconciliation failed"),
            }
        })
        .await;

    Ok(())
}
```

### 2. Sidecar Injector

```yaml
# manifests/mutating-webhook.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: clawdstrike-sidecar-injector
webhooks:
  - name: sidecar.clawdstrike.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    clientConfig:
      service:
        name: clawdstrike-injector
        namespace: clawdstrike-system
        path: /inject
      caBundle: ${CA_BUNDLE}
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    namespaceSelector:
      matchLabels:
        clawdstrike.io/inject: "enabled"
```

```rust
// sidecar-injector/src/main.rs
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use k8s_openapi::api::core::v1::{Container, Pod, Volume, VolumeMount};
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use std::sync::Arc;

struct InjectorState {
    sidecar_image: String,
    default_policy: String,
}

async fn inject_sidecar(
    State(state): State<Arc<InjectorState>>,
    Json(review): Json<AdmissionReview<Pod>>,
) -> Result<Json<AdmissionReview<Pod>>, (StatusCode, String)> {
    let request: AdmissionRequest<Pod> = review.try_into()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)))?;

    let mut response = AdmissionResponse::from(&request);

    if let Some(pod) = &request.object {
        // Check if injection is disabled
        if let Some(annotations) = &pod.metadata.annotations {
            if annotations.get("clawdstrike.io/inject") == Some(&"false".to_string()) {
                response = response.with_patch(vec![])?;
                return Ok(Json(AdmissionReview { response: Some(response), ..Default::default() }));
            }
        }

        // Get policy reference
        let policy_name = pod.metadata.annotations
            .as_ref()
            .and_then(|a| a.get("clawdstrike.io/policy"))
            .cloned()
            .unwrap_or_else(|| state.default_policy.clone());

        // Create sidecar container
        let sidecar = Container {
            name: "clawdstrike-sidecar".to_string(),
            image: Some(state.sidecar_image.clone()),
            env: Some(vec![
                k8s_openapi::api::core::v1::EnvVar {
                    name: "POLICY_NAME".to_string(),
                    value: Some(policy_name.clone()),
                    ..Default::default()
                },
                k8s_openapi::api::core::v1::EnvVar {
                    name: "POD_NAME".to_string(),
                    value_from: Some(k8s_openapi::api::core::v1::EnvVarSource {
                        field_ref: Some(k8s_openapi::api::core::v1::ObjectFieldSelector {
                            field_path: "metadata.name".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            volume_mounts: Some(vec![
                VolumeMount {
                    name: "clawdstrike-policy".to_string(),
                    mount_path: "/etc/clawdstrike".to_string(),
                    read_only: Some(true),
                    ..Default::default()
                },
                VolumeMount {
                    name: "clawdstrike-socket".to_string(),
                    mount_path: "/var/run/clawdstrike".to_string(),
                    ..Default::default()
                },
            ]),
            resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
                limits: Some(std::collections::BTreeMap::from([
                    ("memory".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("128Mi".to_string())),
                    ("cpu".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("100m".to_string())),
                ])),
                requests: Some(std::collections::BTreeMap::from([
                    ("memory".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("64Mi".to_string())),
                    ("cpu".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("50m".to_string())),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create volumes
        let policy_volume = Volume {
            name: "clawdstrike-policy".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: Some(format!("clawdstrike-policy-{}", policy_name)),
                ..Default::default()
            }),
            ..Default::default()
        };

        let socket_volume = Volume {
            name: "clawdstrike-socket".to_string(),
            empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource::default()),
            ..Default::default()
        };

        // Create JSON patches
        let patches = vec![
            json_patch::PatchOperation::Add(json_patch::AddOperation {
                path: "/spec/containers/-".to_string(),
                value: serde_json::to_value(&sidecar).unwrap(),
            }),
            json_patch::PatchOperation::Add(json_patch::AddOperation {
                path: "/spec/volumes/-".to_string(),
                value: serde_json::to_value(&policy_volume).unwrap(),
            }),
            json_patch::PatchOperation::Add(json_patch::AddOperation {
                path: "/spec/volumes/-".to_string(),
                value: serde_json::to_value(&socket_volume).unwrap(),
            }),
        ];

        response = response.with_patch(json_patch::Patch(patches))?;
    }

    Ok(Json(AdmissionReview {
        response: Some(response),
        ..Default::default()
    }))
}

#[tokio::main]
async fn main() {
    let state = Arc::new(InjectorState {
        sidecar_image: std::env::var("SIDECAR_IMAGE")
            .unwrap_or_else(|_| "clawdstrike/sidecar:latest".to_string()),
        default_policy: std::env::var("DEFAULT_POLICY")
            .unwrap_or_else(|_| "default".to_string()),
    });

    let app = Router::new()
        .route("/inject", post(inject_sidecar))
        .with_state(state);

    let addr = "0.0.0.0:8443";
    axum_server::bind_rustls(addr.parse().unwrap(), rustls_config())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

### 3. Prometheus Metrics

```rust
// metrics/src/lib.rs
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec,
    Opts, Registry,
};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // Action counters
    pub static ref ACTIONS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("clawdstrike_actions_total", "Total number of actions checked"),
        &["action_type", "guard", "result"]
    ).unwrap();

    // Violation counters
    pub static ref VIOLATIONS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("clawdstrike_violations_total", "Total number of violations"),
        &["action_type", "guard", "severity"]
    ).unwrap();

    // Latency histograms
    pub static ref CHECK_LATENCY: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new(
            "clawdstrike_check_latency_seconds",
            "Latency of policy checks"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        &["action_type"]
    ).unwrap();

    // Active sessions gauge
    pub static ref ACTIVE_SESSIONS: Gauge = Gauge::new(
        "clawdstrike_active_sessions",
        "Number of active agent sessions"
    ).unwrap();

    // Policy version info
    pub static ref POLICY_INFO: GaugeVec = GaugeVec::new(
        Opts::new("clawdstrike_policy_info", "Policy information"),
        &["name", "version", "hash"]
    ).unwrap();
}

pub fn register_metrics() {
    REGISTRY.register(Box::new(ACTIONS_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(VIOLATIONS_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(CHECK_LATENCY.clone())).unwrap();
    REGISTRY.register(Box::new(ACTIVE_SESSIONS.clone())).unwrap();
    REGISTRY.register(Box::new(POLICY_INFO.clone())).unwrap();
}

pub fn record_action(action_type: &str, guard: &str, allowed: bool) {
    let result = if allowed { "allowed" } else { "blocked" };
    ACTIONS_TOTAL
        .with_label_values(&[action_type, guard, result])
        .inc();
}

pub fn record_violation(action_type: &str, guard: &str, severity: &str) {
    VIOLATIONS_TOTAL
        .with_label_values(&[action_type, guard, severity])
        .inc();
}

pub fn observe_latency(action_type: &str, duration_secs: f64) {
    CHECK_LATENCY
        .with_label_values(&[action_type])
        .observe(duration_secs);
}
```

```yaml
# manifests/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: clawdstrike
  namespace: clawdstrike-system
spec:
  selector:
    matchLabels:
      app: clawdstrike
  endpoints:
    - port: metrics
      interval: 15s
      path: /metrics
```

### 4. Serverless (AWS Lambda) Deployment

```typescript
// lambda/handler.ts
import { APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { PolicyEngine, loadPolicy } from '@clawdstrike/openclaw';
import {
  SecretsManagerClient,
  GetSecretValueCommand
} from '@aws-sdk/client-secrets-manager';

// Initialize outside handler for connection reuse
let engine: PolicyEngine | null = null;
let policyVersion: string | null = null;

const secretsClient = new SecretsManagerClient({});

async function getPolicy(): Promise<PolicyEngine> {
  // Check if we need to refresh policy
  const currentVersion = process.env.POLICY_VERSION || 'latest';

  if (engine && policyVersion === currentVersion) {
    return engine;
  }

  // Load policy from Secrets Manager or S3
  const policyConfig = process.env.POLICY_SECRET_ARN
    ? await loadPolicyFromSecrets()
    : loadPolicy(process.env.POLICY_NAME || 'ai-agent');

  engine = new PolicyEngine({
    policy: policyConfig,
    mode: 'deterministic',
    guards: {
      forbidden_path: true,
      egress: true,
      secret_leak: true,
      patch_integrity: true,
    },
  });

  policyVersion = currentVersion;
  return engine;
}

async function loadPolicyFromSecrets(): Promise<any> {
  const response = await secretsClient.send(
    new GetSecretValueCommand({
      SecretId: process.env.POLICY_SECRET_ARN,
    })
  );

  return JSON.parse(response.SecretString || '{}');
}

export const handler: APIGatewayProxyHandler = async (event) => {
  const startTime = Date.now();

  try {
    const policyEngine = await getPolicy();
    const body = JSON.parse(event.body || '{}');

    // Create policy event from request
    const policyEvent = {
      eventId: event.requestContext.requestId,
      eventType: body.eventType,
      timestamp: new Date().toISOString(),
      sessionId: body.sessionId,
      data: body.data,
    };

    // Evaluate policy
    const decision = await policyEngine.evaluate(policyEvent);

    // Log to CloudWatch for audit
    console.log(JSON.stringify({
      type: 'policy_evaluation',
      requestId: event.requestContext.requestId,
      decision,
      latencyMs: Date.now() - startTime,
    }));

    // Publish metrics to CloudWatch
    await publishMetrics(policyEvent.eventType, decision, Date.now() - startTime);

    return {
      statusCode: 200,
      body: JSON.stringify(decision),
      headers: {
        'Content-Type': 'application/json',
        'X-Clawdstrike-Version': process.env.AWS_LAMBDA_FUNCTION_VERSION || 'unknown',
      },
    };
  } catch (error) {
    console.error('Policy evaluation error:', error);

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Policy evaluation failed',
        message: (error as Error).message,
      }),
    };
  }
};

async function publishMetrics(
  eventType: string,
  decision: any,
  latencyMs: number
): Promise<void> {
  // Use CloudWatch Embedded Metric Format
  console.log(JSON.stringify({
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [{
        Namespace: 'Clawdstrike',
        Dimensions: [['EventType', 'Decision']],
        Metrics: [
          { Name: 'Evaluations', Unit: 'Count' },
          { Name: 'Latency', Unit: 'Milliseconds' },
        ],
      }],
    },
    EventType: eventType,
    Decision: decision.allowed ? 'allowed' : 'blocked',
    Evaluations: 1,
    Latency: latencyMs,
  }));
}
```

```yaml
# serverless.yml (Serverless Framework)
service: clawdstrike-lambda

provider:
  name: aws
  runtime: nodejs20.x
  region: us-east-1
  memorySize: 256
  timeout: 10
  environment:
    POLICY_NAME: ai-agent
    POLICY_VERSION: ${opt:policy-version, 'latest'}
  iam:
    role:
      statements:
        - Effect: Allow
          Action:
            - secretsmanager:GetSecretValue
          Resource:
            - arn:aws:secretsmanager:*:*:secret:clawdstrike/*
        - Effect: Allow
          Action:
            - logs:CreateLogGroup
            - logs:CreateLogStream
            - logs:PutLogEvents
          Resource: "*"

functions:
  evaluate:
    handler: dist/handler.handler
    events:
      - http:
          path: /evaluate
          method: post
    layers:
      - arn:aws:lambda:us-east-1:${aws:accountId}:layer:clawdstrike:1

package:
  patterns:
    - '!node_modules/**'
    - 'node_modules/@clawdstrike/**'
    - 'dist/**'

layers:
  clawdstrike:
    path: layer
    compatibleRuntimes:
      - nodejs20.x
    description: Clawdstrike security layer
```

### 5. Service Mesh Integration (Istio)

```yaml
# istio/authorization-policy.yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: clawdstrike-egress-control
  namespace: ai-agents
spec:
  selector:
    matchLabels:
      app: ai-agent
  action: CUSTOM
  provider:
    name: clawdstrike-ext-authz
  rules:
    - to:
        - operation:
            hosts: ["*"]
            notHosts:
              - "*.internal.svc.cluster.local"

---
apiVersion: networking.istio.io/v1beta1
kind: EnvoyFilter
metadata:
  name: clawdstrike-ext-authz
  namespace: istio-system
spec:
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        context: SIDECAR_OUTBOUND
        listener:
          filterChain:
            filter:
              name: "envoy.filters.network.http_connection_manager"
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.ext_authz
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
            grpc_service:
              envoy_grpc:
                cluster_name: clawdstrike-ext-authz
              timeout: 0.5s
            transport_api_version: V3
```

```rust
// ext-authz/src/main.rs
use tonic::{transport::Server, Request, Response, Status};

use envoy_ext_authz::envoy::service::auth::v3::{
    authorization_server::{Authorization, AuthorizationServer},
    CheckRequest, CheckResponse,
};

pub struct ClawdstrikeAuthz {
    engine: clawdstrike::HushEngine,
}

#[tonic::async_trait]
impl Authorization for ClawdstrikeAuthz {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let req = request.into_inner();

        // Extract target from request
        let attrs = req.attributes.ok_or_else(|| Status::invalid_argument("Missing attributes"))?;
        let request_attrs = attrs.request.ok_or_else(|| Status::invalid_argument("Missing request"))?;
        let http = request_attrs.http.ok_or_else(|| Status::invalid_argument("Missing HTTP"))?;

        let host = http.host;
        let port = 443u16; // Default to HTTPS

        // Check egress policy
        let ctx = clawdstrike::GuardContext::new();
        let result = self.engine.check_egress(&host, port, &ctx).await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut response = CheckResponse::default();

        if result.allowed {
            response.status = Some(envoy_ext_authz::google::rpc::Status {
                code: 0, // OK
                message: String::new(),
                details: vec![],
            });
        } else {
            response.status = Some(envoy_ext_authz::google::rpc::Status {
                code: 7, // PERMISSION_DENIED
                message: result.message,
                details: vec![],
            });
        }

        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = clawdstrike::Policy::from_yaml_file("/etc/clawdstrike/policy.yaml")?;
    let engine = clawdstrike::HushEngine::with_policy(policy);

    let authz = ClawdstrikeAuthz { engine };

    Server::builder()
        .add_service(AuthorizationServer::new(authz))
        .serve("0.0.0.0:9001".parse()?)
        .await?;

    Ok(())
}
```

## Security Considerations

### 1. Secret Management

```yaml
# Use External Secrets Operator for secret injection
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: clawdstrike-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: clawdstrike-secrets
  data:
    - secretKey: signing-key
      remoteRef:
        key: secret/clawdstrike/signing-key
```

### 2. Network Policies

```yaml
# Restrict sidecar communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: clawdstrike-sidecar
  namespace: ai-agents
spec:
  podSelector:
    matchLabels:
      clawdstrike.io/inject: "true"
  policyTypes:
    - Egress
  egress:
    # Allow to Clawdstrike control plane
    - to:
        - namespaceSelector:
            matchLabels:
              name: clawdstrike-system
      ports:
        - protocol: TCP
          port: 8080
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
```

### 3. Pod Security

```yaml
# Pod Security Standards
apiVersion: v1
kind: Namespace
metadata:
  name: ai-agents
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## Scaling Considerations

### Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: clawdstrike-operator
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: clawdstrike-operator
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Pods
      pods:
        metric:
          name: clawdstrike_actions_per_second
        target:
          type: AverageValue
          averageValue: "1000"
```

### Resource Recommendations

| Scale | Operator | Sidecar Memory | Sidecar CPU |
|-------|----------|----------------|-------------|
| Small (<100 pods) | 2 replicas | 64Mi | 50m |
| Medium (<1000 pods) | 3 replicas | 128Mi | 100m |
| Large (<10000 pods) | 5 replicas | 256Mi | 200m |

## Cost Considerations

### Kubernetes (per month)

| Component | Resources | Cost |
|-----------|-----------|------|
| Operator (3x) | 2 vCPU, 4GB | $200 |
| Sidecars (100 pods) | 10 vCPU, 12.8GB | $400 |
| Storage (audit) | 100GB | $50 |
| **Total** | | **$650** |

### Serverless (per million invocations)

| Component | Cost |
|-----------|------|
| Lambda execution | $0.20 |
| API Gateway | $3.50 |
| CloudWatch | $0.50 |
| **Total** | **$4.20** |

## Step-by-Step Implementation Guide

### Phase 1: Operator Setup (Week 1)

1. **Deploy CRDs**
   ```bash
   kubectl apply -f crds/
   ```

2. **Deploy operator**
   ```bash
   helm install clawdstrike-operator ./charts/operator
   ```

3. **Create initial policy**
   ```yaml
   apiVersion: security.clawdstrike.io/v1
   kind: ClawdstrikePolicy
   metadata:
     name: default
   spec:
     extends: ai-agent
   ```

### Phase 2: Sidecar Injection (Week 2)

4. **Deploy webhook**
   ```bash
   kubectl apply -f manifests/mutating-webhook.yaml
   ```

5. **Label namespace**
   ```bash
   kubectl label ns ai-agents clawdstrike.io/inject=enabled
   ```

6. **Test injection**
   ```bash
   kubectl run test --image=nginx -n ai-agents
   kubectl get pod test -n ai-agents -o yaml | grep clawdstrike
   ```

### Phase 3: Observability (Week 3)

7. **Deploy ServiceMonitor**
8. **Import Grafana dashboards**
9. **Set up alerts**

### Phase 4: Production (Week 4)

10. **Enable network policies**
11. **Configure autoscaling**
12. **Document runbooks**

## Common Pitfalls and Solutions

### Pitfall 1: Webhook Timeout

**Problem**: Sidecar injection webhook times out under load.

**Solution**: Increase timeout and add caching:
```yaml
webhooks:
  - timeoutSeconds: 10
    failurePolicy: Ignore  # Don't block pod creation
```

### Pitfall 2: Policy Sync Lag

**Problem**: Policy changes don't propagate immediately.

**Solution**: Use ConfigMap with hash annotation for rolling updates:
```yaml
annotations:
  clawdstrike.io/policy-hash: "{{ sha256sum .Values.policy }}"
```

### Pitfall 3: Resource Exhaustion

**Problem**: Sidecars consume too much memory.

**Solution**: Tune resource limits and enable resource quotas:
```yaml
resources:
  limits:
    memory: "64Mi"  # Start small
  requests:
    memory: "32Mi"
```

## Troubleshooting

### Issue: CRD Validation Failures

**Symptoms**: ClawdstrikePolicy resources rejected with schema errors.

**Solutions**:
1. Verify CRD is installed with correct version: `kubectl get crd clawdstrikepolicies.security.clawdstrike.io`
2. Check policy YAML against OpenAPI schema in CRD definition
3. Use `kubectl apply --dry-run=server` to validate before applying
4. Review CRD version compatibility with operator version

### Issue: Sidecar Not Injected

**Symptoms**: Pods in labeled namespace missing Clawdstrike sidecar container.

**Solutions**:
1. Verify namespace has label `clawdstrike.io/inject: enabled`
2. Check webhook is running: `kubectl get pods -n clawdstrike-system`
3. Review webhook logs for injection errors
4. Ensure pod doesn't have `clawdstrike.io/inject: "false"` annotation
5. Check MutatingWebhookConfiguration caBundle is valid

### Issue: Metrics Not Appearing in Prometheus

**Symptoms**: Clawdstrike metrics missing from Prometheus targets.

**Solutions**:
1. Verify ServiceMonitor is in namespace Prometheus is watching
2. Check service has correct labels matching ServiceMonitor selector
3. Ensure metrics port is exposed and named correctly
4. Review Prometheus target status for scrape errors

### Issue: Lambda Cold Start Latency

**Symptoms**: First invocations taking significantly longer than subsequent ones.

**Solutions**:
1. Use provisioned concurrency for consistent latency
2. Minimize package size by excluding unnecessary dependencies
3. Initialize policy engine outside handler function
4. Consider using Lambda SnapStart (Java) or container images

### Issue: Service Mesh Authorization Failures

**Symptoms**: All egress requests being denied by ext-authz.

**Solutions**:
1. Check ext-authz service is healthy and responding
2. Verify policy is correctly loaded in ext-authz service
3. Review Envoy filter configuration for correct cluster name
4. Check timeout settings - increase if policy evaluation is slow

## Validation Checklist

- [ ] CRDs are installed and validated
- [ ] Operator reconciles policies
- [ ] Sidecar injection works
- [ ] Metrics are scraped by Prometheus
- [ ] Grafana dashboards show data
- [ ] Alerts fire correctly
- [ ] Network policies are enforced
- [ ] Pod security standards are met
- [ ] Autoscaling works under load
- [ ] DR procedures are tested
