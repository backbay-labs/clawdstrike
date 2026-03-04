//! MCP (Model Context Protocol) server for Cursor/Cline integration.
//!
//! Exposes a `policy_check` tool via JSON-RPC that AI tools can call.

use crate::policy::{evaluate_policy_check, PolicyCheckInput};
use crate::security::auth::constant_time_eq_token;
use crate::session::SessionManager;
use crate::settings::Settings;
use crate::agent_auth::read_local_api_token;
use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::{response::IntoResponse, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};

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
            let result = evaluate_policy_check(
                state.settings.clone(),
                &state.http_client,
                check_params,
                session_id,
                None,
            )
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
