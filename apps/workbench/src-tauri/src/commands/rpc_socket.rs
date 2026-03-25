use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

#[cfg(windows)]
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;

pub const RPC_FRONTEND_REQUEST_EVENT: &str = "swarm:rpc_request";
const IPC_INFO_FILENAME: &str = "ipc.json";
const IPC_TOKEN_FILENAME: &str = "ipc.token";
#[cfg(unix)]
const IPC_SOCKET_FILENAME: &str = "ipc.sock";
const FRONTEND_RPC_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
pub struct RpcSocketStateInner {
    pending: Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>,
    server_task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    runtime_info: Mutex<Option<RpcRuntimeInfo>>,
    bearer_token: Mutex<Option<String>>,
}

pub type RpcSocketState = Arc<RpcSocketStateInner>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpcTransportKind {
    Unix,
    Tcp,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcRuntimeInfo {
    pub transport: RpcTransportKind,
    pub endpoint: String,
    pub token_file: String,
    pub info_file: String,
    pub socket_path: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    auth: Option<String>,
}

#[derive(Clone, Serialize)]
struct FrontendRpcRequest {
    request_id: String,
    method: String,
    params: Value,
}

#[derive(Serialize)]
struct RpcMethodDescriptor {
    name: &'static str,
    description: &'static str,
    params: &'static str,
}

const RPC_METHODS: &[RpcMethodDescriptor] = &[
    RpcMethodDescriptor {
        name: "rpc.discover",
        description: "List supported RPC methods and runtime transport details.",
        params: "{}",
    },
    RpcMethodDescriptor {
        name: "board.snapshot",
        description: "Return the current board snapshot from the active workbench view.",
        params: "{}",
    },
    RpcMethodDescriptor {
        name: "board.nodeAdd",
        description: "Create a board node. Params: { nodeType, title, position?, data?, id?, width?, height?, selected? }",
        params: "{ nodeType: string, title: string, position?: { x, y }, data?: object }",
    },
    RpcMethodDescriptor {
        name: "board.nodeRemove",
        description: "Remove a board node by id.",
        params: "{ nodeId: string }",
    },
    RpcMethodDescriptor {
        name: "board.nodeUpdate",
        description: "Patch a board node's layout and/or data.",
        params: "{ nodeId: string, data?: object, position?: { x, y }, width?: number, height?: number, selected?: boolean }",
    },
    RpcMethodDescriptor {
        name: "board.edgeAdd",
        description: "Create a board edge.",
        params: "{ source: string, target: string, id?: string, label?: string, type?: string }",
    },
    RpcMethodDescriptor {
        name: "board.edgeRemove",
        description: "Remove a board edge by id.",
        params: "{ edgeId: string }",
    },
    RpcMethodDescriptor {
        name: "board.viewportGet",
        description: "Get the active canvas viewport.",
        params: "{}",
    },
    RpcMethodDescriptor {
        name: "board.viewportSet",
        description: "Set the active canvas viewport.",
        params: "{ viewport: { x, y, zoom }, duration?: number }",
    },
    RpcMethodDescriptor {
        name: "session.spawn",
        description: "Spawn a terminal, Claude, or worktree session on the board.",
        params: "{ kind?: 'terminal'|'claude'|'worktree', ... }",
    },
    RpcMethodDescriptor {
        name: "session.kill",
        description: "Kill a session by nodeId or sessionId.",
        params: "{ nodeId?: string, sessionId?: string }",
    },
    RpcMethodDescriptor {
        name: "session.list",
        description: "List board-visible and backend-discovered sessions.",
        params: "{}",
    },
    RpcMethodDescriptor {
        name: "session.readOutput",
        description: "Read recent output lines for a session by nodeId or sessionId.",
        params: "{ nodeId?: string, sessionId?: string, lines?: number }",
    },
    RpcMethodDescriptor {
        name: "coordinator.status",
        description: "Return current coordinator connectivity and joined swarm state.",
        params: "{}",
    },
    RpcMethodDescriptor {
        name: "coordinator.publish",
        description: "Publish a coordinator message by swarmId and channel.",
        params: "{ swarmId: string, channel: 'intel'|'signal'|'detection'|'coordination', payload: unknown }",
    },
];

fn response_with_result(id: Value, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn response_with_error(id: Value, code: i32, message: impl Into<String>) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}

fn invalid_request_response(message: impl Into<String>) -> JsonRpcResponse {
    response_with_error(Value::Null, -32600, message)
}

fn parse_bearer_token(auth: Option<&str>) -> Option<&str> {
    let auth = auth?.trim();
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn is_known_method(method: &str) -> bool {
    RPC_METHODS.iter().any(|entry| entry.name == method)
}

fn rpc_root<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Failed to resolve app data dir: {error}"))?;
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("Failed to create app data dir {}: {error}", root.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
    }
    Ok(root)
}

fn write_secure_file(path: &Path, content: &[u8]) -> Result<(), String> {
    std::fs::write(path, content)
        .map_err(|error| format!("Failed to write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn generate_bearer_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom(&mut bytes).map_err(|error| format!("Failed to generate RPC bearer token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn token_file_path(root: &Path) -> PathBuf {
    root.join(IPC_TOKEN_FILENAME)
}

fn info_file_path(root: &Path) -> PathBuf {
    root.join(IPC_INFO_FILENAME)
}

#[cfg(unix)]
fn socket_file_path(root: &Path) -> PathBuf {
    root.join(IPC_SOCKET_FILENAME)
}

fn cleanup_runtime_files(runtime_info: &RpcRuntimeInfo) {
    if let Some(socket_path) = &runtime_info.socket_path {
        let _ = std::fs::remove_file(socket_path);
    }
    let _ = std::fs::remove_file(&runtime_info.info_file);
    let _ = std::fs::remove_file(&runtime_info.token_file);
}

async fn forward_frontend_request<R: Runtime>(
    app: &AppHandle<R>,
    state: &RpcSocketState,
    method: String,
    params: Value,
) -> Result<Value, String> {
    let request_id = Uuid::new_v4().to_string();
    let (sender, receiver) = oneshot::channel();
    state.pending.lock().await.insert(request_id.clone(), sender);

    let payload = FrontendRpcRequest {
        request_id: request_id.clone(),
        method,
        params,
    };

    if let Err(error) = app.emit_to("main", RPC_FRONTEND_REQUEST_EVENT, payload) {
        state.pending.lock().await.remove(&request_id);
        return Err(format!("Failed to dispatch RPC request to frontend: {error}"));
    }

    match timeout(FRONTEND_RPC_TIMEOUT, receiver).await {
        Ok(Ok(Ok(result))) => Ok(result),
        Ok(Ok(Err(error))) => Err(error),
        Ok(Err(_)) => Err("Frontend RPC bridge dropped the pending response".to_string()),
        Err(_) => {
            state.pending.lock().await.remove(&request_id);
            Err(format!(
                "Frontend RPC request timed out after {}s",
                FRONTEND_RPC_TIMEOUT.as_secs()
            ))
        }
    }
}

fn discover_payload(runtime_info: &RpcRuntimeInfo) -> Value {
    json!({
        "methods": RPC_METHODS,
        "auth": {
            "scheme": "bearer",
            "request_field": "auth",
            "format": "Bearer <token>"
        },
        "runtime": runtime_info,
    })
}

async fn handle_rpc_line<R: Runtime>(
    app: &AppHandle<R>,
    state: &RpcSocketState,
    raw: &str,
) -> JsonRpcResponse {
    let parsed_value = match serde_json::from_str::<Value>(raw) {
        Ok(value) => value,
        Err(_) => return response_with_error(Value::Null, -32700, "Parse error"),
    };

    if parsed_value.is_array() {
        return invalid_request_response("Batch requests are not supported");
    }

    let request = match serde_json::from_value::<JsonRpcRequest>(parsed_value) {
        Ok(request) => request,
        Err(_) => return invalid_request_response("Invalid request"),
    };

    if request.jsonrpc != "2.0" {
        return invalid_request_response("Invalid JSON-RPC version");
    }
    if !(request.id.is_string() || request.id.is_number()) {
        return invalid_request_response("JSON-RPC id must be a string or number");
    }
    if !is_known_method(&request.method) {
        return response_with_error(request.id, -32601, format!("Method not found: {}", request.method));
    }

    let expected_token = state.bearer_token.lock().await.clone();
    let Some(expected_token) = expected_token else {
        return response_with_error(request.id, -32010, "RPC server is not ready");
    };

    let provided_token = parse_bearer_token(request.auth.as_deref());
    if provided_token != Some(expected_token.as_str()) {
        return response_with_error(request.id, -32001, "Unauthorized");
    }

    if request.method == "rpc.discover" {
        let runtime_info = state.runtime_info.lock().await.clone();
        return match runtime_info {
            Some(runtime_info) => response_with_result(request.id, discover_payload(&runtime_info)),
            None => response_with_error(request.id, -32010, "RPC runtime info is unavailable"),
        };
    }

    match forward_frontend_request(app, state, request.method, request.params).await {
        Ok(result) => response_with_result(request.id, result),
        Err(error) => response_with_error(request.id, -32000, error),
    }
}

async fn handle_connection<R, S>(stream: S, app: AppHandle<R>, state: RpcSocketState)
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let response = handle_rpc_line(&app, &state, trimmed).await;
                match serde_json::to_vec(&response) {
                    Ok(mut bytes) => {
                        bytes.push(b'\n');
                        if writer.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let fallback = response_with_error(
                            Value::Null,
                            -32099,
                            format!("Failed to serialize response: {error}"),
                        );
                        if let Ok(mut bytes) = serde_json::to_vec(&fallback) {
                            bytes.push(b'\n');
                            if writer.write_all(&bytes).await.is_err() {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

#[cfg(unix)]
async fn run_unix_server<R: Runtime>(listener: UnixListener, app: AppHandle<R>, state: RpcSocketState) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let app = app.clone();
                let state = state.clone();
                tauri::async_runtime::spawn(async move {
                    handle_connection(stream, app, state).await;
                });
            }
            Err(error) => {
                eprintln!("[rpc-socket] unix listener accept failed: {error}");
                break;
            }
        }
    }
}

#[cfg(windows)]
async fn run_tcp_server<R: Runtime>(listener: TcpListener, app: AppHandle<R>, state: RpcSocketState) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let app = app.clone();
                let state = state.clone();
                tauri::async_runtime::spawn(async move {
                    handle_connection(stream, app, state).await;
                });
            }
            Err(error) => {
                eprintln!("[rpc-socket] tcp listener accept failed: {error}");
                break;
            }
        }
    }
}

fn create_runtime_info<R: Runtime>(app: &AppHandle<R>) -> Result<(RpcRuntimeInfo, String), String> {
    let root = rpc_root(app)?;
    let token = generate_bearer_token()?;
    let token_file = token_file_path(&root);
    let info_file = info_file_path(&root);

    #[cfg(unix)]
    {
        let socket_path = socket_file_path(&root);
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let runtime_info = RpcRuntimeInfo {
            transport: RpcTransportKind::Unix,
            endpoint: socket_path.to_string_lossy().to_string(),
            token_file: token_file.to_string_lossy().to_string(),
            info_file: info_file.to_string_lossy().to_string(),
            socket_path: Some(socket_path.to_string_lossy().to_string()),
            host: None,
            port: None,
        };
        return Ok((runtime_info, token));
    }

    #[cfg(windows)]
    {
        let runtime_info = RpcRuntimeInfo {
            transport: RpcTransportKind::Tcp,
            endpoint: String::new(),
            token_file: token_file.to_string_lossy().to_string(),
            info_file: info_file.to_string_lossy().to_string(),
            socket_path: None,
            host: Some("127.0.0.1".to_string()),
            port: None,
        };
        Ok((runtime_info, token))
    }
}

fn write_runtime_info(runtime_info: &RpcRuntimeInfo, token: &str) -> Result<(), String> {
    let token_path = Path::new(&runtime_info.token_file);
    let info_path = Path::new(&runtime_info.info_file);
    write_secure_file(token_path, token.as_bytes())?;
    let info_json = serde_json::to_vec_pretty(runtime_info)
        .map_err(|error| format!("Failed to serialize RPC runtime info: {error}"))?;
    write_secure_file(info_path, &info_json)?;
    Ok(())
}

pub async fn start_rpc_socket_server<R: Runtime>(
    app: &AppHandle<R>,
    state: &RpcSocketState,
) -> Result<(), String> {
    stop_rpc_socket_server(state).await;

    #[cfg(unix)]
    {
        let (runtime_info, token) = create_runtime_info(app)?;
        let socket_path = runtime_info
            .socket_path
            .clone()
            .ok_or_else(|| "Unix RPC socket path is missing".to_string())?;
        let listener = UnixListener::bind(&socket_path)
            .map_err(|error| format!("Failed to bind unix RPC socket {socket_path}: {error}"))?;

        write_runtime_info(&runtime_info, &token)?;
        *state.runtime_info.lock().await = Some(runtime_info);
        *state.bearer_token.lock().await = Some(token);

        let app = app.clone();
        let state_clone = state.clone();
        let task = tauri::async_runtime::spawn(async move {
            run_unix_server(listener, app, state_clone).await;
        });
        *state.server_task.lock().await = Some(task);
        return Ok(());
    }

    #[cfg(windows)]
    {
        let (mut runtime_info, token) = create_runtime_info(app)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|error| format!("Failed to bind TCP RPC listener: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("Failed to resolve TCP RPC listener address: {error}"))?;
        runtime_info.endpoint = format!("{}:{}", address.ip(), address.port());
        runtime_info.port = Some(address.port());

        write_runtime_info(&runtime_info, &token)?;
        *state.runtime_info.lock().await = Some(runtime_info);
        *state.bearer_token.lock().await = Some(token);

        let app = app.clone();
        let state_clone = state.clone();
        let task = tauri::async_runtime::spawn(async move {
            run_tcp_server(listener, app, state_clone).await;
        });
        *state.server_task.lock().await = Some(task);
        return Ok(());
    }
}

pub async fn stop_rpc_socket_server(state: &RpcSocketState) {
    if let Some(task) = state.server_task.lock().await.take() {
        task.abort();
    }

    for (_request_id, sender) in state.pending.lock().await.drain() {
        let _ = sender.send(Err("RPC server is shutting down".to_string()));
    }

    if let Some(runtime_info) = state.runtime_info.lock().await.take() {
        cleanup_runtime_files(&runtime_info);
    }
    *state.bearer_token.lock().await = None;
}

#[tauri::command]
pub async fn rpc_frontend_respond(
    state: tauri::State<'_, RpcSocketState>,
    request_id: String,
    payload: Option<Value>,
    error: Option<String>,
) -> Result<(), String> {
    let Some(sender) = state.pending.lock().await.remove(&request_id) else {
        return Err(format!("No pending frontend RPC request: {request_id}"));
    };

    sender
        .send(match error {
            Some(error) => Err(error),
            None => Ok(payload.unwrap_or(Value::Null)),
        })
        .map_err(|_| format!("Frontend RPC responder dropped request {request_id}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_known_method, parse_bearer_token, response_with_error, RpcRuntimeInfo, RpcTransportKind};
    use serde_json::Value;

    #[test]
    fn parse_bearer_token_accepts_expected_prefix() {
        assert_eq!(
            parse_bearer_token(Some("Bearer secret-token")),
            Some("secret-token")
        );
        assert_eq!(
            parse_bearer_token(Some("bearer another-token")),
            Some("another-token")
        );
    }

    #[test]
    fn parse_bearer_token_rejects_missing_or_malformed_values() {
        assert_eq!(parse_bearer_token(None), None);
        assert_eq!(parse_bearer_token(Some("")), None);
        assert_eq!(parse_bearer_token(Some("secret-token")), None);
        assert_eq!(parse_bearer_token(Some("Bearer   ")), None);
    }

    #[test]
    fn method_catalog_covers_expected_surface() {
        assert!(is_known_method("rpc.discover"));
        assert!(is_known_method("board.snapshot"));
        assert!(is_known_method("session.spawn"));
        assert!(is_known_method("coordinator.publish"));
        assert!(!is_known_method("board.fitAll"));
    }

    #[test]
    fn response_with_error_serializes_json_rpc_shape() {
        let response = response_with_error(Value::from(7), -32601, "missing");
        let serialized = serde_json::to_value(response).expect("serialize");
        assert_eq!(serialized["jsonrpc"], "2.0");
        assert_eq!(serialized["id"], 7);
        assert_eq!(serialized["error"]["code"], -32601);
        assert_eq!(serialized["error"]["message"], "missing");
    }

    #[test]
    fn runtime_info_is_serializable_for_cli_discovery() {
        let runtime = RpcRuntimeInfo {
            transport: RpcTransportKind::Unix,
            endpoint: "/tmp/ipc.sock".to_string(),
            token_file: "/tmp/ipc.token".to_string(),
            info_file: "/tmp/ipc.json".to_string(),
            socket_path: Some("/tmp/ipc.sock".to_string()),
            host: None,
            port: None,
        };
        let serialized = serde_json::to_string(&runtime).expect("serialize");
        assert!(serialized.contains("\"endpoint\":\"/tmp/ipc.sock\""));
        assert!(serialized.contains("\"token_file\":\"/tmp/ipc.token\""));
    }
}
