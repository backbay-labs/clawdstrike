//! MCP (Model Context Protocol) server for Cursor/Cline integration.
//!
//! Exposes a `policy_check` tool via JSON-RPC that AI tools can call.

use crate::agent_auth::read_local_api_token;
use crate::policy::{evaluate_policy_check, PolicyCheckInput, PolicyCheckOutput};
use crate::security::auth::constant_time_eq_token;
use crate::session::SessionManager;
use crate::settings::Settings;
use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::{response::IntoResponse, routing::post, Json, Router};
use hush_core::sha256;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};

const MCP_DEVELOPER_ACTIVITY_TIMEOUT: Duration = Duration::from_millis(250);

/// MCP server for AI tool integrations.
pub struct McpServer {
    port: u16,
    settings: Arc<RwLock<Settings>>,
    session_manager: Arc<SessionManager>,
    auth_token: String,
}

impl McpServer {
    /// Create a new MCP server.
    pub fn new(
        port: u16,
        settings: Arc<RwLock<Settings>>,
        session_manager: Arc<SessionManager>,
        auth_token: String,
    ) -> Self {
        Self {
            port,
            settings,
            session_manager,
            auth_token,
        }
    }

    /// Start the MCP server.
    pub async fn start(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let state = McpState {
            settings: self.settings,
            session_manager: self.session_manager,
            http_client: reqwest::Client::new(),
            auth_token: self.auth_token,
        };

        let app = Router::new()
            .route("/", post(handle_rpc))
            .route("/rpc", post(handle_rpc))
            .route("/mcp", post(handle_rpc))
            .layer(DefaultBodyLimit::max(128 * 1024))
            .with_state(Arc::new(state));

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind MCP server to {}", addr))?;

        tracing::info!("MCP server listening on {}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
                tracing::info!("MCP server shutting down");
            })
            .await
            .with_context(|| "MCP server error")?;

        Ok(())
    }
}

/// Shared state for MCP handlers.
struct McpState {
    settings: Arc<RwLock<Settings>>,
    session_manager: Arc<SessionManager>,
    http_client: reqwest::Client,
    auth_token: String,
}

/// JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 error.
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// MCP tool definition.
#[derive(Debug, Serialize)]
struct McpTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

/// Handle JSON-RPC requests.
async fn handle_rpc(
    State(state): State<Arc<McpState>>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    if !mcp_authorized(&headers, &state.auth_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(JsonRpcResponse {
                jsonrpc: "2.0",
                result: None,
                error: Some(JsonRpcError {
                    code: -32001,
                    message: "Unauthorized".to_string(),
                    data: None,
                }),
                id: request.id,
            }),
        );
    }

    if request.jsonrpc != "2.0" {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonRpcResponse {
                jsonrpc: "2.0",
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: "Invalid Request".to_string(),
                    data: None,
                }),
                id: request.id,
            }),
        );
    }

    let response = match request.method.as_str() {
        "initialize" => handle_initialize(),
        "tools/list" => handle_list_tools(),
        "tools/call" => handle_call_tool(&state, request.params).await,
        "ping" => handle_ping(),
        _ => JsonRpcResponse {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", request.method),
                data: None,
            }),
            id: request.id.clone(),
        },
    };

    let mut response = response;
    response.id = request.id;

    (StatusCode::OK, Json(response))
}

fn mcp_authorized(headers: &HeaderMap, auth_token: &str) -> bool {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    let expected_token = match read_local_api_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Falling back to startup MCP auth token because current token could not be read"
            );
            auth_token.to_string()
        }
    };

    match token {
        Some(candidate) => constant_time_eq_token(candidate, &expected_token),
        None => false,
    }
}

fn handle_initialize() -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        result: Some(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "clawdstrike-agent",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
        error: None,
        id: None,
    }
}

fn handle_list_tools() -> JsonRpcResponse {
    let tools = vec![McpTool {
        name: "policy_check".to_string(),
        description: "Check if an action is allowed by the security policy".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "action_type": {
                    "type": "string",
                    "description": "Action type for hushd /api/v1/check (file_access, file_write, egress, shell, patch, mcp_tool).",
                    "enum": ["file_access", "file_write", "egress", "shell", "patch", "mcp_tool"]
                },
                "target": {
                    "type": "string",
                    "description": "Target of the action (file path, URL, command)"
                },
                "content": {
                    "type": "string",
                    "description": "Optional content being written or sent"
                },
                "args": {
                    "type": "object",
                    "description": "Optional args (used for mcp_tool).",
                    "additionalProperties": true
                },
                "agent_id": {
                    "type": "string",
                    "description": "Optional legacy endpoint agent ID override."
                },
                "endpoint_agent_id": {
                    "type": "string",
                    "description": "Optional canonical endpoint agent ID override."
                },
                "runtime_agent_id": {
                    "type": "string",
                    "description": "Optional AI runtime agent identifier."
                },
                "runtime_agent_kind": {
                    "type": "string",
                    "description": "Optional runtime kind (openclaw, claude_code, mcp, unknown)."
                }
            },
            "required": ["action_type", "target"]
        }),
    }];

    JsonRpcResponse {
        jsonrpc: "2.0",
        result: Some(serde_json::json!({ "tools": tools })),
        error: None,
        id: None,
    }
}

async fn handle_call_tool(state: &McpState, params: Option<serde_json::Value>) -> JsonRpcResponse {
    let params = match params {
        Some(p) => p,
        None => {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params: missing parameters".to_string(),
                    data: None,
                }),
                id: None,
            };
        }
    };

    // Extract tool name and arguments.
    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    match tool_name {
        "policy_check" => {
            let mut check_params: PolicyCheckInput = match serde_json::from_value(arguments) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse {
                        jsonrpc: "2.0",
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32602,
                            message: format!("Invalid params: {}", e),
                            data: None,
                        }),
                        id: None,
                    };
                }
            };
            if check_params.runtime_agent_kind.is_none() {
                check_params.runtime_agent_kind = Some("mcp".to_string());
            }
            if check_params.runtime_agent_id.is_none() {
                check_params.runtime_agent_id = Some("mcp-local".to_string());
            }

            let session_id = state.session_manager.session_id().await;
            let telemetry_params = check_params.clone();
            let result = evaluate_policy_check(
                state.settings.clone(),
                &state.http_client,
                check_params,
                session_id.clone(),
                None,
            )
            .await;
            publish_policy_check_developer_activity(state, &telemetry_params, session_id, &result)
                .await;

            let text = match serde_json::to_string_pretty(&result) {
                Ok(value) => value,
                Err(err) => format!("{{\"error\":\"serialize_failed\",\"message\":\"{}\"}}", err),
            };

            JsonRpcResponse {
                jsonrpc: "2.0",
                result: Some(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": text
                    }],
                    "isError": !result.allowed
                })),
                error: None,
                id: None,
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError {
                code: -32602,
                message: format!("Unknown tool: {}", tool_name),
                data: None,
            }),
            id: None,
        },
    }
}

async fn publish_policy_check_developer_activity(
    state: &McpState,
    input: &PolicyCheckInput,
    session_id: Option<String>,
    result: &PolicyCheckOutput,
) {
    let activities = developer_activities_for_policy_check(input, session_id.as_deref(), result);
    if activities.is_empty() {
        return;
    }
    let agent_api_port = state.settings.read().await.agent_api_port;
    let token = read_local_api_token().unwrap_or_else(|err| {
        tracing::warn!(
            error = %err,
            "Falling back to startup token for MCP developer-activity telemetry"
        );
        state.auth_token.clone()
    });
    let url = format!("http://127.0.0.1:{agent_api_port}/api/v1/agent/edr/developer-activity");
    let request = state
        .http_client
        .post(url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "activities": activities }));
    match tokio::time::timeout(MCP_DEVELOPER_ACTIVITY_TIMEOUT, request.send()).await {
        Ok(Ok(response)) if response.status().is_success() => {}
        Ok(Ok(response)) => {
            tracing::debug!(
                status = %response.status(),
                "MCP developer-activity telemetry was rejected"
            );
        }
        Ok(Err(err)) => {
            tracing::debug!(
                error = %err,
                "Failed to publish MCP developer-activity telemetry"
            );
        }
        Err(_) => {
            tracing::debug!("Timed out publishing MCP developer-activity telemetry");
        }
    }
}

fn developer_activities_for_policy_check(
    input: &PolicyCheckInput,
    session_id: Option<&str>,
    result: &PolicyCheckOutput,
) -> Vec<serde_json::Value> {
    let mut activities = Vec::new();
    let action_type = input.action_type.trim().to_ascii_lowercase();
    let agent_id = input
        .runtime_agent_id
        .as_deref()
        .or(input.agent_id.as_deref())
        .or(input.endpoint_agent_id.as_deref())
        .unwrap_or("mcp-local");
    let workload_id = input.runtime_agent_kind.as_deref().unwrap_or("mcp");
    let base_metadata = serde_json::json!({
        "policyAllowed": result.allowed,
        "policyGuard": result.guard,
        "policySeverity": result.severity,
        "policyActionType": input.action_type,
    });

    match action_type.as_str() {
        "mcp_tool" => {
            let mut parameters = input
                .args
                .as_ref()
                .map(|args| serde_json::to_value(args).unwrap_or_else(|_| serde_json::json!({})))
                .unwrap_or_else(|| serde_json::json!({}));
            if let serde_json::Value::Object(object) = &mut parameters {
                object
                    .entry("target".to_string())
                    .or_insert_with(|| serde_json::Value::String(input.target.clone()));
            }
            activities.push(serde_json::json!({
                "kind": "mcp_tool",
                "id": local_mcp_activity_id("mcp-tool", session_id, agent_id, &input.target),
                "sessionId": session_id,
                "agentId": agent_id,
                "workloadId": workload_id,
                "toolName": input.target,
                "parameters": parameters,
                "metadata": base_metadata,
            }));
        }
        "shell" => {
            activities.push(shell_developer_activity_for_policy_check(
                input,
                session_id,
                agent_id,
                workload_id,
                &base_metadata,
            ));
        }
        _ => {}
    }

    if let Some(secret_activity) =
        secret_developer_activity_for_policy_check(input, session_id, agent_id, workload_id)
    {
        activities.push(secret_activity);
    }

    activities
}

fn shell_developer_activity_for_policy_check(
    input: &PolicyCheckInput,
    session_id: Option<&str>,
    agent_id: &str,
    workload_id: &str,
    base_metadata: &serde_json::Value,
) -> serde_json::Value {
    let command_line = shell_command_line(input);
    let tokens = shell_tokens_for_policy_check(input, &command_line);
    let working_directory = shell_working_directory(input);
    let context = McpShellActivityContext {
        input,
        session_id,
        agent_id,
        workload_id,
        base_metadata,
        command_line: &command_line,
        working_directory: working_directory.as_deref(),
    };

    for command in normalized_shell_commands(&tokens) {
        if let Some(activity) = package_script_activity_for_shell(&context, &command) {
            return activity;
        }
        if let Some(activity) = package_registry_token_activity_for_shell(&context, &command) {
            return activity;
        }
        if let Some(activity) = cloud_cli_activity_for_shell(&context, &command) {
            return activity;
        }
    }

    serde_json::json!({
        "kind": "shell_command",
        "id": local_mcp_activity_id("mcp-shell", session_id, agent_id, &command_line),
        "sessionId": session_id,
        "agentId": agent_id,
        "workloadId": workload_id,
        "image": shell_command_image(&command_line),
        "args": [command_line],
        "metadata": base_metadata,
    })
}

struct McpShellActivityContext<'a> {
    input: &'a PolicyCheckInput,
    session_id: Option<&'a str>,
    agent_id: &'a str,
    workload_id: &'a str,
    base_metadata: &'a serde_json::Value,
    command_line: &'a str,
    working_directory: Option<&'a str>,
}

fn package_script_activity_for_shell(
    context: &McpShellActivityContext<'_>,
    command: &[String],
) -> Option<serde_json::Value> {
    let PackageCommand {
        manager,
        image,
        args,
    } = package_command(command)?;
    let (phase, package) = package_script_phase_and_package(manager, &args)?;
    Some(serde_json::json!({
        "kind": "package_script",
        "id": local_mcp_activity_id("mcp-package-script", context.session_id, context.agent_id, context.command_line),
        "sessionId": context.session_id,
        "agentId": context.agent_id,
        "workloadId": context.workload_id,
        "manager": manager,
        "package": package,
        "phase": phase,
        "script": context.command_line,
        "workingDirectory": context.working_directory,
        "image": image,
        "commandLine": context.command_line,
        "metadata": mcp_shell_activity_metadata(context.base_metadata, context.input, "package_script"),
    }))
}

fn package_registry_token_activity_for_shell(
    context: &McpShellActivityContext<'_>,
    command: &[String],
) -> Option<serde_json::Value> {
    let manager = package_registry_manager(command)?;
    let args = command.iter().skip(1).cloned().collect::<Vec<_>>();
    let command_index = first_non_option_arg_index(&args)?;
    let command_name = args.get(command_index)?.to_ascii_lowercase();
    let command_args = args
        .iter()
        .skip(command_index + 1)
        .cloned()
        .collect::<Vec<_>>();
    if !package_registry_token_command_is_sensitive(&command_name, &command_args) {
        return None;
    }

    Some(serde_json::json!({
        "kind": "repo_secret",
        "id": local_mcp_activity_id("mcp-package-registry-token", context.session_id, context.agent_id, context.command_line),
        "sessionId": context.session_id,
        "agentId": context.agent_id,
        "workloadId": context.workload_id,
        "path": format!("{manager}:token"),
        "name": format!("{manager}-token"),
        "credentialKind": "package_registry_token",
        "image": command.first().cloned(),
        "commandLine": context.command_line,
        "args": args,
        "metadata": mcp_shell_activity_metadata(context.base_metadata, context.input, "package_registry_token_command"),
    }))
}

fn cloud_cli_activity_for_shell(
    context: &McpShellActivityContext<'_>,
    command: &[String],
) -> Option<serde_json::Value> {
    let CloudCommand {
        provider,
        image,
        args,
    } = cloud_command(command)?;
    let operation_index = first_non_option_arg_index(&args)?;
    let operation = args.get(operation_index)?.clone();
    let operation_args = args
        .iter()
        .skip(operation_index + 1)
        .cloned()
        .collect::<Vec<_>>();
    let mut sensitive_args = Vec::with_capacity(operation_args.len() + 1);
    sensitive_args.push(operation.clone());
    sensitive_args.extend(operation_args.iter().cloned());
    if !cloud_cli_args_are_sensitive(&sensitive_args) {
        return None;
    }

    Some(serde_json::json!({
        "kind": "cloud_cli",
        "id": local_mcp_activity_id("mcp-cloud-cli", context.session_id, context.agent_id, context.command_line),
        "sessionId": context.session_id,
        "agentId": context.agent_id,
        "workloadId": context.workload_id,
        "provider": provider,
        "operation": operation,
        "args": operation_args,
        "image": image,
        "commandLine": context.command_line,
        "metadata": mcp_shell_activity_metadata(context.base_metadata, context.input, "cloud_cli"),
    }))
}

fn secret_developer_activity_for_policy_check(
    input: &PolicyCheckInput,
    session_id: Option<&str>,
    agent_id: &str,
    workload_id: &str,
) -> Option<serde_json::Value> {
    let target = secret_target_from_policy_check(input)?;
    let lower = target.to_ascii_lowercase();
    let (kind, credential_kind) = if lower.contains("cookie") {
        ("browser_cookie", "browser_cookie")
    } else if lower.contains("ci_token")
        || lower.contains("github_token")
        || lower.contains("gh_token")
        || lower.contains("actions")
    {
        ("ci_token", "api_token")
    } else if lower.contains("agent-local-token") || lower.contains("clawdstrike_agent_auth") {
        ("local_api_key", "api_token")
    } else if lower.contains(".aws/credentials")
        || lower.contains("gcloud")
        || lower.contains("azure")
    {
        ("repo_secret", "cloud_credential")
    } else if lower.contains(".npmrc")
        || lower.contains(".pypirc")
        || lower.contains("cargo/credentials")
    {
        ("repo_secret", "package_registry_token")
    } else if lower.contains(".ssh/") || lower.contains("id_rsa") || lower.contains("id_ed25519") {
        ("repo_secret", "ssh_key")
    } else if lower.contains("signing") || lower.contains("codesign") {
        ("repo_secret", "signing_key")
    } else {
        ("repo_secret", "api_token")
    };
    Some(serde_json::json!({
        "kind": kind,
        "id": local_mcp_activity_id("mcp-secret", session_id, agent_id, &target),
        "sessionId": session_id,
        "agentId": agent_id,
        "workloadId": workload_id,
        "path": target,
        "name": secret_name_from_target(&target),
        "credentialKind": credential_kind,
        "metadata": {
            "collectorKind": "mcp_policy_check",
            "policyActionType": input.action_type,
        },
    }))
}

fn secret_target_from_policy_check(input: &PolicyCheckInput) -> Option<String> {
    let mut candidates = Vec::new();
    if input.action_type.trim().eq_ignore_ascii_case("shell") {
        let command_line = shell_command_line(input);
        for token in shell_tokens_for_policy_check(input, &command_line) {
            if shell_token_can_be_secret_target(&token) {
                candidates.push(token);
            }
        }
    } else {
        candidates.push(input.target.clone());
    }
    if let Some(args) = input.args.as_ref() {
        for key in ["path", "file", "file_path", "target", "resource"] {
            if let Some(value) = args.get(key).and_then(serde_json::Value::as_str) {
                candidates.push(value.to_string());
            }
        }
    }
    candidates
        .into_iter()
        .map(|candidate| candidate.trim().to_string())
        .find(|candidate| target_looks_like_secret(candidate))
}

fn target_looks_like_secret(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    [
        ".env",
        ".npmrc",
        ".pypirc",
        ".aws/credentials",
        ".ssh/",
        "id_rsa",
        "id_ed25519",
        "api_key",
        "apikey",
        "secret",
        "token",
        "cookie",
        "cargo/credentials",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn shell_token_can_be_secret_target(token: &str) -> bool {
    let trimmed = token.trim_matches(['"', '\'', ',', ';']);
    trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('~')
        || trimmed.starts_with('.')
        || trimmed.contains('\\')
        || trimmed.contains("/.")
}

fn secret_name_from_target(target: &str) -> String {
    target
        .rsplit(['/', '\\'])
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("secret")
        .to_string()
}

fn shell_command_image(command: &str) -> String {
    command
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("shell")
        .to_string()
}

fn shell_command_line(input: &PolicyCheckInput) -> String {
    let target = input.target.trim();
    if !target.is_empty() {
        return target.to_string();
    }
    input
        .args
        .as_ref()
        .and_then(|args| {
            ["command", "cmd", "commandLine", "command_line"]
                .iter()
                .filter_map(|key| args.get(*key).and_then(serde_json::Value::as_str))
                .map(str::trim)
                .find(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "shell".to_string())
}

fn shell_tokens_for_policy_check(input: &PolicyCheckInput, command_line: &str) -> Vec<String> {
    let mut tokens = shell_split_best_effort(command_line);
    if tokens.len() <= 1 {
        if let Some(arg_tokens) = input.args.as_ref().and_then(shell_arg_tokens) {
            tokens.extend(arg_tokens);
        }
    }
    tokens
}

fn shell_arg_tokens(
    args: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<Vec<String>> {
    for key in ["argv", "args", "arguments"] {
        let Some(value) = args.get(key) else {
            continue;
        };
        if let Some(items) = value.as_array() {
            let tokens = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if !tokens.is_empty() {
                return Some(tokens);
            }
        }
        if let Some(value) = value.as_str() {
            let tokens = shell_split_best_effort(value);
            if !tokens.is_empty() {
                return Some(tokens);
            }
        }
    }
    None
}

fn shell_working_directory(input: &PolicyCheckInput) -> Option<String> {
    input.args.as_ref().and_then(|args| {
        ["cwd", "workingDirectory", "working_directory"]
            .iter()
            .filter_map(|key| args.get(*key).and_then(serde_json::Value::as_str))
            .map(str::trim)
            .find(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn shell_split_best_effort(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                current.push(c);
            }
            continue;
        }
        if in_double {
            match c {
                '"' => in_double = false,
                '\\' => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                }
                _ => current.push(c),
            }
            continue;
        }

        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn normalized_shell_commands(tokens: &[String]) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for segment in shell_command_segments(tokens) {
        if let Some(command) = normalize_shell_command_segment(segment) {
            commands.push(command);
        }
    }
    commands
}

fn shell_command_segments(tokens: &[String]) -> Vec<&[String]> {
    let mut segments = Vec::new();
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        if is_shell_separator(token) {
            if start < index {
                segments.push(&tokens[start..index]);
            }
            start = index + 1;
        }
    }
    if start < tokens.len() {
        segments.push(&tokens[start..]);
    }
    segments
}

fn normalize_shell_command_segment(segment: &[String]) -> Option<Vec<String>> {
    let mut index = 0;
    while index < segment.len() {
        let token = segment.get(index)?;
        let executable = executable_name(token);
        if shell_assignment(token) {
            index += 1;
            continue;
        }
        if matches!(
            executable.as_str(),
            "sudo" | "doas" | "command" | "builtin" | "nohup" | "time"
        ) {
            index += 1;
            continue;
        }
        if executable == "env" {
            index += 1;
            while index < segment.len() {
                let token = segment.get(index)?;
                if shell_assignment(token) || token.starts_with('-') {
                    index += 1;
                    continue;
                }
                break;
            }
            continue;
        }
        if matches!(executable.as_str(), "sh" | "bash" | "zsh" | "dash" | "fish") {
            if let Some(inner) = shell_c_inner_command(&segment[index + 1..]) {
                let inner_tokens = shell_split_best_effort(inner);
                return normalized_shell_commands(&inner_tokens).into_iter().next();
            }
        }
        return Some(segment[index..].to_vec());
    }
    None
}

fn shell_c_inner_command(tokens: &[String]) -> Option<&str> {
    for (index, token) in tokens.iter().enumerate() {
        if token == "-c" || (token.starts_with('-') && token.chars().skip(1).any(|c| c == 'c')) {
            return tokens.get(index + 1).map(String::as_str);
        }
    }
    None
}

fn is_shell_separator(token: &str) -> bool {
    matches!(token, "&&" | "||" | ";" | "|")
}

fn shell_assignment(token: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && !value.is_empty()
        && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
        && !name.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn executable_name(token: &str) -> String {
    let basename = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".cmd"))
        .or_else(|| basename.strip_suffix(".bat"))
        .unwrap_or(basename)
        .to_ascii_lowercase()
}

struct PackageCommand {
    manager: &'static str,
    image: String,
    args: Vec<String>,
}

fn package_command(command: &[String]) -> Option<PackageCommand> {
    let image = command.first()?.clone();
    let executable = executable_name(&image);
    if python_module_is_pip(command) {
        return Some(PackageCommand {
            manager: "pip",
            image,
            args: command.iter().skip(3).cloned().collect(),
        });
    }
    let manager = match executable.as_str() {
        "npm" => "npm",
        "pnpm" => "pnpm",
        "yarn" => "yarn",
        "pip" | "pip3" => "pip",
        "cargo" => "cargo",
        "brew" => "brew",
        "go" => "go",
        "gem" => "gem",
        _ => return None,
    };
    Some(PackageCommand {
        manager,
        image,
        args: command.iter().skip(1).cloned().collect(),
    })
}

fn python_module_is_pip(command: &[String]) -> bool {
    let Some(executable) = command.first().map(|value| executable_name(value)) else {
        return false;
    };
    matches!(
        executable.as_str(),
        "python" | "python3" | "python2" | "python.exe" | "python3.exe"
    ) && command.get(1).is_some_and(|arg| arg == "-m")
        && command
            .get(2)
            .map(|arg| executable_name(arg) == "pip")
            .unwrap_or(false)
}

fn package_script_phase_and_package(
    manager: &str,
    args: &[String],
) -> Option<(String, Option<String>)> {
    let command_index = first_non_option_arg_index(args)?;
    let command = args.get(command_index)?.to_ascii_lowercase();
    let after_command = &args[command_index + 1..];
    let phase = match manager {
        "npm" | "pnpm" => match command.as_str() {
            "install" | "i" | "ci" | "add" | "rebuild" => "install".to_string(),
            "run" | "run-script" | "exec" | "dlx" => {
                package_script_name(after_command).unwrap_or_else(|| command.clone())
            }
            _ if package_lifecycle_phase(&command) => command.clone(),
            _ => return None,
        },
        "yarn" => match command.as_str() {
            "install" | "add" | "upgrade" => "install".to_string(),
            "run" => package_script_name(after_command).unwrap_or_else(|| "run".to_string()),
            _ if package_lifecycle_phase(&command) => command.clone(),
            _ => return None,
        },
        "pip" => match command.as_str() {
            "install" => "install".to_string(),
            "wheel" => "build".to_string(),
            _ => return None,
        },
        "cargo" => match command.as_str() {
            "install" | "build" | "run" | "test" => command.clone(),
            _ => return None,
        },
        "brew" => match command.as_str() {
            "install" | "reinstall" | "upgrade" | "bundle" => "install".to_string(),
            _ => return None,
        },
        "go" => match command.as_str() {
            "install" | "get" => "install".to_string(),
            "run" | "build" | "test" => command.clone(),
            _ => return None,
        },
        "gem" => match command.as_str() {
            "install" | "build" => command.clone(),
            _ => return None,
        },
        _ => return None,
    };
    let package = package_name_from_args(after_command);
    Some((phase, package))
}

fn package_script_name(args: &[String]) -> Option<String> {
    args.iter()
        .find(|arg| !arg.starts_with('-') && !arg.contains('='))
        .map(ToString::to_string)
}

fn package_lifecycle_phase(value: &str) -> bool {
    [
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "build",
        "build.rs",
        "setup.py",
        "test",
    ]
    .iter()
    .any(|phase| value.contains(phase))
}

fn package_name_from_args(args: &[String]) -> Option<String> {
    args.iter()
        .find(|arg| {
            let value = arg.as_str();
            !value.starts_with('-')
                && !value.contains('=')
                && value != "."
                && value != "--"
                && !package_lifecycle_phase(&value.to_ascii_lowercase())
        })
        .map(ToString::to_string)
}

fn package_registry_manager(command: &[String]) -> Option<&'static str> {
    match executable_name(command.first()?).as_str() {
        "npm" => Some("npm"),
        "pnpm" => Some("pnpm"),
        "yarn" => Some("yarn"),
        _ => None,
    }
}

fn package_registry_token_command_is_sensitive(command_name: &str, args: &[String]) -> bool {
    let joined = args.join(" ").to_ascii_lowercase();
    match command_name {
        "token" => args
            .first()
            .map(|arg| {
                matches!(
                    arg.to_ascii_lowercase().as_str(),
                    "list" | "create" | "revoke" | "delete"
                )
            })
            .unwrap_or(false),
        "config" => {
            args.first()
                .map(|arg| matches!(arg.to_ascii_lowercase().as_str(), "get" | "set" | "delete"))
                .unwrap_or(false)
                && package_registry_auth_config_reference(&joined)
        }
        _ => false,
    }
}

fn package_registry_auth_config_reference(value: &str) -> bool {
    value.contains("_authtoken")
        || value.contains("node_auth_token")
        || value.contains("npm_token")
        || value.contains("npm_config_")
}

struct CloudCommand {
    provider: &'static str,
    image: String,
    args: Vec<String>,
}

fn cloud_command(command: &[String]) -> Option<CloudCommand> {
    let image = command.first()?.clone();
    let executable = executable_name(&image);
    let provider = match executable.as_str() {
        "aws" => "aws",
        "gcloud" => "gcloud",
        "az" => "az",
        "gh" => "gh",
        "vercel" => "vercel",
        "netlify" => "netlify",
        "wrangler" => "wrangler",
        "doctl" => "doctl",
        "fly" | "flyctl" => "fly",
        "op" => "op",
        "vault" => "vault",
        "doppler" => "doppler",
        "heroku" => "heroku",
        "supabase" => "supabase",
        "kubectl" => "kubectl",
        "pulumi" => "pulumi",
        "circleci" => "circleci",
        "glab" => "glab",
        "buildkite-agent" | "bk" => "buildkite",
        _ => return None,
    };
    Some(CloudCommand {
        provider,
        image,
        args: command.iter().skip(1).cloned().collect(),
    })
}

fn cloud_cli_args_are_sensitive(args: &[String]) -> bool {
    let joined = args.join(" ").to_ascii_lowercase();
    [
        "secretsmanager get-secret-value",
        "ssm get-parameter",
        "ssm get-parameters",
        "iam create-access-key",
        "iam put-user-policy",
        "iam attach-user-policy",
        "ecr get-login-password",
        "sts get-session-token",
        "sts assume-role",
        "auth print-access-token",
        "secrets versions access",
        "iam service-accounts keys create",
        "keyvault secret show",
        "keyvault secret download",
        "account get-access-token",
        "ad app credential reset",
        "secret set",
        "secret put",
        "secret bulk",
        "secret list",
        "secret delete",
        "versions secret put",
        "versions secret bulk",
        "registry docker-config",
        "registry login",
        "kubernetes cluster kubeconfig save",
        "secrets set",
        "secrets import",
        "secrets unset",
        "secrets list",
        "tokens create",
        "tokens revoke",
        "auth token",
        "variable set",
        "variable update",
        "variable delete",
        "variable get",
        "variable list",
        "variable export",
        "secret get",
        "secret create",
        "secret update",
        "env pull",
        "env add",
        "env rm",
        "env remove",
        "env ls",
        "env:get",
        "env:list",
        "env:set",
        "env:import",
        "env:unset",
        "item get",
        "document get",
        "op://",
        "kv get",
        "read secret/",
        "token create",
        "secrets download",
        "configs tokens create",
        "config:get",
        "config:set",
        "secrets pull",
        "get secret",
        "describe secret",
        "config view --raw",
        "--show-secrets",
        "context store-secret",
        "context remove-secret",
        "runner token create",
        "runner token list",
    ]
    .iter()
    .any(|needle| joined.contains(needle))
        || args.iter().any(|arg| {
            let arg = arg.to_ascii_lowercase();
            arg.contains("secret")
                || arg.contains("token")
                || arg.contains("credential")
                || arg.contains("access-key")
                || arg == "iam"
                || arg == "sts"
                || arg == "keyvault"
        })
}

fn first_non_option_arg_index(args: &[String]) -> Option<usize> {
    let mut index = 0;
    while index < args.len() {
        let arg = args.get(index)?;
        if arg == "--" {
            return (index + 1 < args.len()).then_some(index + 1);
        }
        if shell_assignment(arg) {
            index += 1;
            continue;
        }
        if arg.starts_with("--") {
            if option_takes_value(arg) && !arg.contains('=') {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            if short_option_takes_value(arg) {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        return Some(index);
    }
    None
}

fn option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "--prefix"
            | "--cwd"
            | "--directory"
            | "--project"
            | "--profile"
            | "--region"
            | "--subscription"
            | "--account"
            | "--configuration"
            | "--workspace"
    )
}

fn short_option_takes_value(arg: &str) -> bool {
    matches!(arg, "-C" | "-p" | "-r" | "-c" | "-m")
}

fn mcp_shell_activity_metadata(
    base_metadata: &serde_json::Value,
    input: &PolicyCheckInput,
    classifier: &str,
) -> serde_json::Value {
    let mut metadata = base_metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("mcp_policy_check".to_string()),
    );
    metadata.insert(
        "shellClassifier".to_string(),
        serde_json::Value::String(classifier.to_string()),
    );
    if let Some(content) = input
        .content
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        metadata.insert(
            "policyContent".to_string(),
            serde_json::Value::String(content.to_string()),
        );
    }
    serde_json::Value::Object(metadata)
}

fn local_mcp_activity_id(
    prefix: &str,
    session_id: Option<&str>,
    agent_id: &str,
    target: &str,
) -> String {
    let material = format!(
        "{prefix}\0{}\0{agent_id}\0{target}",
        session_id.unwrap_or_default()
    );
    let digest = sha256(material.as_bytes()).to_hex_prefixed();
    let fragment = digest
        .trim_start_matches("0x")
        .chars()
        .take(32)
        .collect::<String>();
    format!("{prefix}-{fragment}")
}

fn handle_ping() -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        result: Some(serde_json::json!({})),
        error: None,
        id: None,
    }
}

/// Get MCP server configuration for Claude Code/Cursor.
#[cfg(test)]
pub fn get_mcp_config(port: u16) -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            "clawdstrike": {
                "url": format!("http://127.0.0.1:{}", port),
                "tools": ["policy_check"]
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn policy_check_params_deserialize() {
        let json = r#"{"action_type":"file_access","target":"/etc/passwd"}"#;
        let params = match serde_json::from_str::<PolicyCheckInput>(json) {
            Ok(value) => value,
            Err(err) => panic!("failed to deserialize policy_check params: {}", err),
        };
        assert_eq!(params.action_type, "file_access");
        assert_eq!(params.target, "/etc/passwd");
    }

    #[test]
    fn mcp_config_generation() {
        let config = get_mcp_config(9877);
        let url = config["mcpServers"]["clawdstrike"]["url"]
            .as_str()
            .unwrap_or("");
        assert!(url.contains("9877"));
    }

    #[test]
    fn policy_check_input_accepts_args() {
        let json = serde_json::json!({
            "action_type": "mcp_tool",
            "target": "run_command",
            "args": {
                "cwd": "/tmp"
            }
        });
        let parsed = serde_json::from_value::<PolicyCheckInput>(json);
        assert!(parsed.is_ok());
        let args = parsed.ok().and_then(|p| p.args).unwrap_or_default();
        assert_eq!(
            args.get("cwd").and_then(|v| v.as_str()).unwrap_or(""),
            "/tmp"
        );
    }

    #[test]
    fn policy_check_input_without_args_deserializes() {
        let parsed = serde_json::from_value::<PolicyCheckInput>(serde_json::json!({
            "action_type": "egress",
            "target": "example.com:443"
        }));
        assert!(parsed.is_ok());
        let p = parsed.ok();
        assert_eq!(p.as_ref().map(|v| v.action_type.as_str()), Some("egress"));
    }

    #[test]
    fn can_use_hashmap_aliases_in_args() {
        let mut args: HashMap<String, serde_json::Value> = HashMap::new();
        args.insert("flag".to_string(), serde_json::json!(true));
        let input = PolicyCheckInput {
            action_type: "mcp_tool".to_string(),
            target: "run_command".to_string(),
            content: None,
            args: Some(args),
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
        };
        assert!(input.args.as_ref().is_some_and(|m| m.contains_key("flag")));
    }

    #[test]
    fn mcp_policy_check_projects_tool_and_secret_developer_activity() {
        let mut args: HashMap<String, serde_json::Value> = HashMap::new();
        args.insert("path".to_string(), serde_json::json!("/repo/.env"));
        let input = PolicyCheckInput {
            action_type: "mcp_tool".to_string(),
            target: "mcp__filesystem__read_file".to_string(),
            content: None,
            args: Some(args),
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-1"), &output);

        assert_eq!(activities.len(), 2);
        assert_eq!(activities[0]["kind"], "mcp_tool");
        assert_eq!(activities[0]["toolName"], "mcp__filesystem__read_file");
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-1");
        assert_eq!(activities[1]["kind"], "repo_secret");
        assert_eq!(activities[1]["path"], "/repo/.env");
        assert_eq!(activities[1]["credentialKind"], "api_token");
    }

    #[test]
    fn mcp_policy_check_projects_package_registry_secret_target() {
        let input = PolicyCheckInput {
            action_type: "file_access".to_string(),
            target: "/Users/alice/.npmrc".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: false,
            guard: Some("developer_secret_access".to_string()),
            severity: Some("high".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-2"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "repo_secret");
        assert_eq!(activities[0]["path"], "/Users/alice/.npmrc");
        assert_eq!(activities[0]["credentialKind"], "package_registry_token");
        assert_eq!(activities[0]["agentId"], "agent:codex");
    }

    #[test]
    fn mcp_policy_check_projects_package_manager_shell_activity() {
        let mut args: HashMap<String, serde_json::Value> = HashMap::new();
        args.insert("cwd".to_string(), serde_json::json!("/repo"));
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "npm --prefix /repo run postinstall -- --audit=false".to_string(),
            content: None,
            args: Some(args),
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: false,
            guard: Some("supply_chain".to_string()),
            severity: Some("high".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-3"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "package_script");
        assert_eq!(activities[0]["manager"], "npm");
        assert_eq!(activities[0]["phase"], "postinstall");
        assert_eq!(
            activities[0]["script"],
            "npm --prefix /repo run postinstall -- --audit=false"
        );
        assert_eq!(activities[0]["workingDirectory"], "/repo");
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-3");
        assert_eq!(
            activities[0]["metadata"]["shellClassifier"],
            "package_script"
        );
    }

    #[test]
    fn mcp_policy_check_projects_package_registry_token_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "npm token list --json".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-npm-token"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "repo_secret");
        assert_eq!(activities[0]["path"], "npm:token");
        assert_eq!(activities[0]["name"], "npm-token");
        assert_eq!(activities[0]["credentialKind"], "package_registry_token");
        assert_eq!(activities[0]["commandLine"], "npm token list --json");
        assert_eq!(
            activities[0]["metadata"]["shellClassifier"],
            "package_registry_token_command"
        );
    }

    #[test]
    fn mcp_policy_check_projects_cloud_cli_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "aws --profile prod secretsmanager get-secret-value --secret-id prod/db"
                .to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-4"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "cloud_cli");
        assert_eq!(activities[0]["provider"], "aws");
        assert_eq!(activities[0]["operation"], "secretsmanager");
        assert_eq!(activities[0]["args"][0], "get-secret-value");
        assert_eq!(activities[0]["args"][1], "--secret-id");
        assert_eq!(activities[0]["args"][2], "prod/db");
        assert_eq!(
            activities[0]["commandLine"],
            "aws --profile prod secretsmanager get-secret-value --secret-id prod/db"
        );
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-4");
        assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
    }

    #[test]
    fn mcp_policy_check_projects_github_cli_secret_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "gh secret set PROD_DB_URL --body redacted --repo acme/service".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-gh"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "cloud_cli");
        assert_eq!(activities[0]["provider"], "gh");
        assert_eq!(activities[0]["operation"], "secret");
        assert_eq!(activities[0]["args"][0], "set");
        assert_eq!(activities[0]["args"][1], "PROD_DB_URL");
        assert_eq!(
            activities[0]["commandLine"],
            "gh secret set PROD_DB_URL --body redacted --repo acme/service"
        );
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-gh");
        assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
    }

    #[test]
    fn mcp_policy_check_projects_vercel_env_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "vercel env pull .env.local --environment production".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-vercel"), &output);

        let activity = activities
            .iter()
            .find(|activity| activity["kind"] == "cloud_cli")
            .unwrap_or_else(|| panic!("missing vercel cloud CLI developer activity"));
        assert_eq!(activity["provider"], "vercel");
        assert_eq!(activity["operation"], "env");
        assert_eq!(activity["args"][0], "pull");
        assert_eq!(activity["args"][1], ".env.local");
        assert_eq!(
            activity["commandLine"],
            "vercel env pull .env.local --environment production"
        );
        assert_eq!(activity["agentId"], "agent:codex");
        assert_eq!(activity["sessionId"], "mcp-session-vercel");
        assert_eq!(activity["metadata"]["shellClassifier"], "cloud_cli");
    }

    #[test]
    fn mcp_policy_check_projects_netlify_env_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "netlify env:get API_KEY --context production".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-netlify"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "cloud_cli");
        assert_eq!(activities[0]["provider"], "netlify");
        assert_eq!(activities[0]["operation"], "env:get");
        assert_eq!(activities[0]["args"][0], "API_KEY");
        assert_eq!(
            activities[0]["commandLine"],
            "netlify env:get API_KEY --context production"
        );
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-netlify");
        assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
    }

    #[test]
    fn mcp_policy_check_projects_wrangler_secret_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "wrangler secret put API_TOKEN --env production".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-wrangler"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "cloud_cli");
        assert_eq!(activities[0]["provider"], "wrangler");
        assert_eq!(activities[0]["operation"], "secret");
        assert_eq!(activities[0]["args"][0], "put");
        assert_eq!(activities[0]["args"][1], "API_TOKEN");
        assert_eq!(
            activities[0]["commandLine"],
            "wrangler secret put API_TOKEN --env production"
        );
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-wrangler");
        assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
    }

    #[test]
    fn mcp_policy_check_projects_doctl_registry_secret_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "doctl registry docker-config example-registry --read-write".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-doctl"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "cloud_cli");
        assert_eq!(activities[0]["provider"], "doctl");
        assert_eq!(activities[0]["operation"], "registry");
        assert_eq!(activities[0]["args"][0], "docker-config");
        assert_eq!(
            activities[0]["commandLine"],
            "doctl registry docker-config example-registry --read-write"
        );
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-doctl");
        assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
    }

    #[test]
    fn mcp_policy_check_projects_fly_secret_shell_activity() {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: "fly secrets set DATABASE_URL=postgres://example --app api".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        let activities =
            developer_activities_for_policy_check(&input, Some("mcp-session-fly"), &output);

        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["kind"], "cloud_cli");
        assert_eq!(activities[0]["provider"], "fly");
        assert_eq!(activities[0]["operation"], "secrets");
        assert_eq!(activities[0]["args"][0], "set");
        assert_eq!(
            activities[0]["commandLine"],
            "fly secrets set DATABASE_URL=postgres://example --app api"
        );
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], "mcp-session-fly");
        assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
    }

    #[test]
    fn mcp_policy_check_projects_secret_platform_shell_activity() {
        let cases = [
            (
                "op item get prod/api-token",
                "mcp-session-op",
                "op",
                "item",
                &["get", "prod/api-token"][..],
            ),
            (
                "vault kv get secret/prod/api",
                "mcp-session-vault",
                "vault",
                "kv",
                &["get", "secret/prod/api"][..],
            ),
            (
                "doppler secrets download --no-file",
                "mcp-session-doppler",
                "doppler",
                "secrets",
                &["download", "--no-file"][..],
            ),
            (
                "heroku config:get DATABASE_URL --app prod-api",
                "mcp-session-heroku",
                "heroku",
                "config:get",
                &["DATABASE_URL", "--app", "prod-api"][..],
            ),
            (
                "supabase secrets list --project-ref prodref",
                "mcp-session-supabase",
                "supabase",
                "secrets",
                &["list", "--project-ref", "prodref"][..],
            ),
            (
                "kubectl get secret prod-token -o yaml",
                "mcp-session-kubectl",
                "kubectl",
                "get",
                &["secret", "prod-token", "-o", "yaml"][..],
            ),
            (
                "pulumi config get dbPassword --show-secrets",
                "mcp-session-pulumi",
                "pulumi",
                "config",
                &["get", "dbPassword", "--show-secrets"][..],
            ),
            (
                "circleci context store-secret github acme production DATABASE_URL",
                "mcp-session-circleci",
                "circleci",
                "context",
                &[
                    "store-secret",
                    "github",
                    "acme",
                    "production",
                    "DATABASE_URL",
                ][..],
            ),
            (
                "glab variable set DATABASE_URL postgres://redacted --masked",
                "mcp-session-glab",
                "glab",
                "variable",
                &["set", "DATABASE_URL", "postgres://redacted", "--masked"][..],
            ),
            (
                "buildkite-agent secret get deploy_key",
                "mcp-session-buildkite",
                "buildkite",
                "secret",
                &["get", "deploy_key"][..],
            ),
        ];
        let output = PolicyCheckOutput {
            allowed: true,
            guard: Some("allow".to_string()),
            severity: Some("info".to_string()),
            message: None,
            details: None,
        };

        for (target, session_id, provider, operation, args) in cases {
            let input = PolicyCheckInput {
                action_type: "shell".to_string(),
                target: target.to_string(),
                content: None,
                args: None,
                agent_id: None,
                endpoint_agent_id: None,
                runtime_agent_id: Some("agent:codex".to_string()),
                runtime_agent_kind: Some("mcp".to_string()),
            };

            let activities =
                developer_activities_for_policy_check(&input, Some(session_id), &output);

            assert_eq!(activities.len(), 1, "missing activity for {provider}");
            assert_eq!(activities[0]["kind"], "cloud_cli");
            assert_eq!(activities[0]["provider"], provider);
            assert_eq!(activities[0]["operation"], operation);
            for (index, expected_arg) in args.iter().enumerate() {
                assert_eq!(activities[0]["args"][index], *expected_arg);
            }
            assert_eq!(activities[0]["commandLine"], target);
            assert_eq!(activities[0]["agentId"], "agent:codex");
            assert_eq!(activities[0]["sessionId"], session_id);
            assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
        }
    }

    #[test]
    fn mcp_requires_bearer_token() {
        let expected_token = read_local_api_token().unwrap_or_else(|_| "secret-token".to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", expected_token)
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse authorization header: {err}")),
        );
        assert!(mcp_authorized(&headers, "secret-token"));
        assert!(!mcp_authorized(&HeaderMap::new(), "secret-token"));
    }
}
