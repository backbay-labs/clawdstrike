//! MCP (Model Context Protocol) server for Cursor/Cline integration
//!
//! Exposes a policy_check tool via JSON-RPC that AI tools can call.

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// MCP server for AI tool integrations
pub struct McpServer {
    port: u16,
    daemon_url: String,
    api_key: Option<String>,
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(port: u16, daemon_url: String, api_key: Option<String>) -> Self {
        Self {
            port,
            daemon_url,
            api_key,
        }
    }

    /// Start the MCP server
    pub async fn start(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let state = McpState {
            daemon_url: self.daemon_url.clone(),
            api_key: self.api_key.clone(),
            http_client: reqwest::Client::new(),
        };

        let app = Router::new()
            .route("/", post(handle_rpc))
            .route("/rpc", post(handle_rpc))
            .route("/mcp", post(handle_rpc))
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

/// Shared state for MCP handlers
struct McpState {
    daemon_url: String,
    api_key: Option<String>,
    http_client: reqwest::Client,
}

/// JSON-RPC 2.0 request
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 error
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// MCP tool definition
#[derive(Debug, Serialize)]
struct McpTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

/// Policy check request parameters
#[derive(Debug, Deserialize)]
struct PolicyCheckParams {
    action_type: String,
    target: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    args: Option<HashMap<String, serde_json::Value>>,
}

/// Policy check response from hushd
#[derive(Debug, Deserialize, Serialize)]
struct PolicyCheckResponse {
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    guard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

/// Handle JSON-RPC requests
async fn handle_rpc(
    State(state): State<Arc<McpState>>,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
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
                    "description": "Type of action (file_access, network, exec)",
                    "enum": ["file_access", "network", "exec"]
                },
                "target": {
                    "type": "string",
                    "description": "Target of the action (file path, URL, command)"
                },
                "content": {
                    "type": "string",
                    "description": "Optional content being written or sent"
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

async fn handle_call_tool(
    state: &McpState,
    params: Option<serde_json::Value>,
) -> JsonRpcResponse {
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

    // Extract tool name and arguments
    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));

    match tool_name {
        "policy_check" => {
            let check_params: PolicyCheckParams = match serde_json::from_value(arguments) {
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

            match call_policy_check(state, check_params).await {
                Ok(result) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    result: Some(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                        }],
                        "isError": !result.allowed
                    })),
                    error: None,
                    id: None,
                },
                Err(e) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32000,
                        message: format!("Policy check failed: {}", e),
                        data: None,
                    }),
                    id: None,
                },
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

fn handle_ping() -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        result: Some(serde_json::json!({})),
        error: None,
        id: None,
    }
}

async fn call_policy_check(
    state: &McpState,
    params: PolicyCheckParams,
) -> Result<PolicyCheckResponse> {
    let url = format!("{}/api/v1/check", state.daemon_url);

    let mut request = state.http_client.post(&url).json(&serde_json::json!({
        "action_type": params.action_type,
        "target": params.target,
        "content": params.content,
        "args": params.args
    }));

    if let Some(ref key) = state.api_key {
        request = request.header("Authorization", format!("Bearer {}", key));
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("Failed to connect to daemon at {}", url))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Daemon returned error {}: {}", status, body);
    }

    let result: PolicyCheckResponse = response
        .json()
        .await
        .with_context(|| "Failed to parse policy check response")?;

    Ok(result)
}

/// Get MCP server configuration for Claude Code/Cursor
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

    #[test]
    fn test_policy_check_params_deserialize() {
        let json = r#"{"action_type":"file_access","target":"/etc/passwd"}"#;
        let params: PolicyCheckParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.action_type, "file_access");
        assert_eq!(params.target, "/etc/passwd");
    }

    #[test]
    fn test_mcp_config_generation() {
        let config = get_mcp_config(9877);
        assert!(config["mcpServers"]["clawdstrike"]["url"]
            .as_str()
            .unwrap()
            .contains("9877"));
    }
}
