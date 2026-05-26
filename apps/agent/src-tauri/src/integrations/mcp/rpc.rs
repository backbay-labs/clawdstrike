//! JSON-RPC 2.0 request/response handling for the MCP server.

use super::auth::mcp_authorized;
use super::developer_activity::developer_activities_for_policy_check;
use super::server::McpState;
use crate::agent_auth::read_local_api_token;
use crate::policy::{evaluate_policy_check, PolicyCheckInput, PolicyCheckOutput};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

const MCP_DEVELOPER_ACTIVITY_TIMEOUT: Duration = Duration::from_millis(250);

/// JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub(super) struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub(super) struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 error.
#[derive(Debug, Serialize)]
pub(super) struct JsonRpcError {
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
pub(super) async fn handle_rpc(
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

fn handle_ping() -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        result: Some(serde_json::json!({})),
        error: None,
        id: None,
    }
}
