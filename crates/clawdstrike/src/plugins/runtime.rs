use std::path::Path;
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wasmtime::{
    Caller, Engine, ExternType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::error::{Error, Result};
use crate::guards::{GuardResult, Severity};

use super::manifest::{PluginCapabilities, PluginResourceLimits};

const WASM_GUARD_ABI_VERSION: i32 = 1;
const ACTION_PTR: usize = 1024;
const INPUT_PTR: usize = 8192;

#[derive(Clone, Debug, Default)]
pub struct WasmGuardRuntimeOptions {
    pub capabilities: PluginCapabilities,
    pub resources: PluginResourceLimits,
}

#[derive(Clone, Debug, Serialize)]
pub struct WasmRuntimeAuditRecord {
    pub kind: &'static str,
    pub guard: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct WasmGuardExecution {
    pub result: GuardResult,
    pub audit: Vec<WasmRuntimeAuditRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmGuardInputEnvelope {
    pub guard: String,
    #[serde(default)]
    pub action_type: Option<String>,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
struct WasmGuardOutput {
    allowed: bool,
    #[serde(default)]
    guard: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    details: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
struct HostState {
    capabilities: PluginCapabilities,
    output: Option<Vec<u8>>,
    capability_fault: Option<String>,
    host_fault: Option<String>,
    store_limits: StoreLimits,
}

impl HostState {
    fn new(capabilities: PluginCapabilities, max_memory_mb: u32) -> Self {
        let max_bytes = max_memory_bytes(max_memory_mb);
        let store_limits = StoreLimitsBuilder::new().memory_size(max_bytes).build();
        Self {
            capabilities,
            output: None,
            capability_fault: None,
            host_fault: None,
            store_limits,
        }
    }
}

pub fn execute_wasm_guard_module(
    wasm_path: &Path,
    envelope: &WasmGuardInputEnvelope,
    options: &WasmGuardRuntimeOptions,
) -> Result<WasmGuardExecution> {
    let wasm_bytes = std::fs::read(wasm_path).map_err(|e| {
        Error::ConfigError(format!(
            "failed to read wasm plugin module {}: {}",
            wasm_path.display(),
            e
        ))
    })?;

    execute_wasm_guard_bytes(&wasm_bytes, envelope, options)
}

pub fn validate_wasm_guard_module(wasm_path: &Path) -> Result<()> {
    let wasm_bytes = std::fs::read(wasm_path).map_err(|e| {
        Error::ConfigError(format!(
            "failed to read wasm plugin module {}: {}",
            wasm_path.display(),
            e
        ))
    })?;

    let config = wasmtime::Config::new();
    let engine = Engine::new(&config)
        .map_err(|e| Error::ConfigError(format!("failed to initialize wasm engine: {e}")))?;
    let module = Module::from_binary(&engine, &wasm_bytes)
        .map_err(|e| Error::ConfigError(format!("failed to compile wasm module: {e}")))?;

    let mut has_memory = false;
    let mut has_init = false;
    let mut has_handles = false;
    let mut has_check = false;
    for export in module.exports() {
        match (export.name(), export.ty()) {
            ("memory", ExternType::Memory(_)) => has_memory = true,
            ("clawdstrike_guard_init", ExternType::Func(_)) => has_init = true,
            ("clawdstrike_guard_handles", ExternType::Func(_)) => has_handles = true,
            ("clawdstrike_guard_check", ExternType::Func(_)) => has_check = true,
            _ => {}
        }
    }

    if !has_memory {
        return Err(Error::ConfigError(
            "wasm guard plugin must export memory".to_string(),
        ));
    }
    if !has_init {
        return Err(Error::ConfigError(
            "wasm guard plugin must export clawdstrike_guard_init".to_string(),
        ));
    }
    if !has_handles {
        return Err(Error::ConfigError(
            "wasm guard plugin must export clawdstrike_guard_handles".to_string(),
        ));
    }
    if !has_check {
        return Err(Error::ConfigError(
            "wasm guard plugin must export clawdstrike_guard_check".to_string(),
        ));
    }

    Ok(())
}

pub fn execute_wasm_guard_bytes(
    wasm_bytes: &[u8],
    envelope: &WasmGuardInputEnvelope,
    options: &WasmGuardRuntimeOptions,
) -> Result<WasmGuardExecution> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    let engine = Engine::new(&config)
        .map_err(|e| Error::ConfigError(format!("failed to initialize wasm engine: {e}")))?;

    let module = Module::from_binary(&engine, wasm_bytes)
        .map_err(|e| Error::ConfigError(format!("failed to compile wasm module: {e}")))?;

    enforce_memory_limit(&module, options.resources.max_memory_mb, &envelope.guard)?;

    let mut linker = Linker::new(&engine);
    linker
        .func_wrap(
            "clawdstrike_host",
            "set_output",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                    caller.data_mut().host_fault =
                        Some("wasm module did not export memory".to_string());
                    return -1;
                };

                if ptr < 0 || len < 0 {
                    caller.data_mut().host_fault =
                        Some("plugin returned negative output pointer/length".to_string());
                    return -1;
                }

                let start = ptr as usize;
                let len = len as usize;
                let end = match start.checked_add(len) {
                    Some(v) => v,
                    None => {
                        caller.data_mut().host_fault =
                            Some("plugin output pointer overflow".to_string());
                        return -1;
                    }
                };

                let data = memory.data(&caller);
                if end > data.len() {
                    caller.data_mut().host_fault = Some(format!(
                        "plugin output range [{start}, {end}) exceeds memory size {}",
                        data.len()
                    ));
                    return -1;
                }

                caller.data_mut().output = Some(data[start..end].to_vec());
                0
            },
        )
        .map_err(|e| Error::ConfigError(format!("failed to bind set_output hostcall: {e}")))?;

    linker
        .func_wrap(
            "clawdstrike_host",
            "request_capability",
            |mut caller: Caller<'_, HostState>, cap_kind: i32| -> i32 {
                if capability_allowed(cap_kind, &caller.data().capabilities) {
                    0
                } else {
                    caller.data_mut().capability_fault =
                        Some(capability_kind_name(cap_kind).to_string());
                    -1
                }
            },
        )
        .map_err(|e| {
            Error::ConfigError(format!("failed to bind request_capability hostcall: {e}"))
        })?;

    let mut store = Store::new(
        &engine,
        HostState::new(
            options.capabilities.clone(),
            options.resources.max_memory_mb,
        ),
    );
    store.limiter(|state| &mut state.store_limits);
    let fuel = u64::from(options.resources.max_cpu_ms).saturating_mul(100_000);
    store
        .set_fuel(fuel)
        .map_err(|e| Error::ConfigError(format!("failed to set wasm fuel limit: {e}")))?;
    store.set_epoch_deadline(1);

    let instance = linker.instantiate(&mut store, &module).map_err(|e| {
        Error::ConfigError(format!(
            "failed to instantiate wasm guard plugin module: {e}"
        ))
    })?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| Error::ConfigError("wasm guard plugin must export memory".to_string()))?;

    let init = instance
        .get_typed_func::<(), i32>(&mut store, "clawdstrike_guard_init")
        .map_err(|e| {
            Error::ConfigError(format!(
                "missing required export clawdstrike_guard_init: {e}"
            ))
        })?;
    let handles = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "clawdstrike_guard_handles")
        .map_err(|e| {
            Error::ConfigError(format!(
                "missing required export clawdstrike_guard_handles: {e}"
            ))
        })?;
    let check = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "clawdstrike_guard_check")
        .map_err(|e| {
            Error::ConfigError(format!(
                "missing required export clawdstrike_guard_check: {e}"
            ))
        })?;

    let abi = init.call(&mut store, ()).map_err(|e| {
        Error::ConfigError(format!(
            "failed to call clawdstrike_guard_init for guard {}: {}",
            envelope.guard, e
        ))
    })?;
    if abi != WASM_GUARD_ABI_VERSION {
        return Ok(deny_execution(
            &envelope.guard,
            "abi_mismatch",
            format!(
                "plugin ABI mismatch: expected {}, got {}",
                WASM_GUARD_ABI_VERSION, abi
            ),
        ));
    }

    let action_type = envelope
        .action_type
        .as_deref()
        .unwrap_or("custom")
        .as_bytes()
        .to_vec();
    write_into_memory(&memory, &mut store, ACTION_PTR, &action_type)?;
    let action_len = i32::try_from(action_type.len()).map_err(|_| {
        Error::ConfigError("action type is too large for wasm guard ABI".to_string())
    })?;

    let handles_result = handles.call(
        &mut store,
        (
            i32::try_from(ACTION_PTR).map_err(|_| {
                Error::ConfigError("internal ABI pointer overflow (action)".to_string())
            })?,
            action_len,
        ),
    );
    let handles_ok = match handles_result {
        Ok(v) => v != 0,
        Err(e) => {
            return Ok(deny_execution(
                &envelope.guard,
                "sandbox_fault",
                format!("guard handles() trapped: {e}"),
            ))
        }
    };
    if !handles_ok {
        return Ok(WasmGuardExecution {
            result: GuardResult::allow(envelope.guard.clone()),
            audit: Vec::new(),
        });
    }

    let input_json = serde_json::to_vec(envelope).map_err(|e| {
        Error::ConfigError(format!(
            "failed to serialize wasm guard input envelope: {}",
            e
        ))
    })?;
    write_into_memory(&memory, &mut store, INPUT_PTR, &input_json)?;
    let input_len = i32::try_from(input_json.len())
        .map_err(|_| Error::ConfigError("wasm guard input exceeds ABI limit".to_string()))?;

    let timeout_fired = Arc::new(AtomicBool::new(false));
    let timeout_fired_for_thread = Arc::clone(&timeout_fired);
    let timeout_duration = Duration::from_millis(u64::from(options.resources.max_timeout_ms));
    let engine_for_thread = engine.clone();
    let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
    let timeout_thread = std::thread::spawn(move || {
        if cancel_rx.recv_timeout(timeout_duration).is_err() {
            timeout_fired_for_thread.store(true, Ordering::SeqCst);
            engine_for_thread.increment_epoch();
        }
    });

    let check_result = check.call(
        &mut store,
        (
            i32::try_from(INPUT_PTR).map_err(|_| {
                Error::ConfigError("internal ABI pointer overflow (input)".to_string())
            })?,
            input_len,
        ),
    );
    let _ = cancel_tx.send(());
    let _ = timeout_thread.join();

    if let Some(cap) = store.data().capability_fault.as_deref() {
        return Ok(deny_execution(
            &envelope.guard,
            "capability_denied",
            format!("wasm guard requested disallowed capability: {cap}"),
        ));
    }
    if let Some(host_fault) = store.data().host_fault.as_deref() {
        return Ok(deny_execution(
            &envelope.guard,
            "sandbox_fault",
            format!("hostcall processing failed: {host_fault}"),
        ));
    }

    let status = match check_result {
        Ok(status) => status,
        Err(e) => {
            if timeout_fired.load(Ordering::SeqCst) {
                return Ok(deny_execution(
                    &envelope.guard,
                    "timeout",
                    format!(
                        "wasm guard timed out after {}ms",
                        options.resources.max_timeout_ms
                    ),
                ));
            }

            let text = e.to_string();
            if text.contains("all fuel consumed") || text.contains("interrupt") {
                return Ok(deny_execution(
                    &envelope.guard,
                    "timeout",
                    format!(
                        "wasm guard exceeded CPU budget ({}ms)",
                        options.resources.max_cpu_ms
                    ),
                ));
            }

            return Ok(deny_execution(
                &envelope.guard,
                "sandbox_fault",
                format!("wasm guard trapped: {text}"),
            ));
        }
    };

    if status != 0 {
        return Ok(deny_execution(
            &envelope.guard,
            "sandbox_fault",
            format!("wasm guard returned non-zero status: {status}"),
        ));
    }

    let output = store.data().output.as_ref().ok_or_else(|| {
        Error::ConfigError(format!(
            "wasm guard {} returned success without emitting output",
            envelope.guard
        ))
    })?;
    let output_str = std::str::from_utf8(output).map_err(|e| {
        Error::ConfigError(format!(
            "wasm guard {} emitted non-UTF8 output: {}",
            envelope.guard, e
        ))
    })?;
    let parsed: WasmGuardOutput = serde_json::from_str(output_str).map_err(|e| {
        Error::ConfigError(format!(
            "wasm guard {} emitted invalid output JSON: {}",
            envelope.guard, e
        ))
    })?;

    let severity = parse_severity(parsed.severity.as_deref(), parsed.allowed);
    let message = parsed.message.unwrap_or_else(|| {
        if parsed.allowed {
            "Allowed".to_string()
        } else {
            "Denied".to_string()
        }
    });
    let guard = parsed.guard.unwrap_or_else(|| envelope.guard.clone());

    Ok(WasmGuardExecution {
        result: GuardResult {
            allowed: parsed.allowed,
            guard,
            severity,
            message,
            details: parsed.details,
        },
        audit: Vec::new(),
    })
}

fn enforce_memory_limit(module: &Module, max_memory_mb: u32, guard: &str) -> Result<()> {
    let max_bytes = max_memory_bytes_u64(max_memory_mb);
    for export in module.exports() {
        if let ExternType::Memory(memory) = export.ty() {
            let page_size = memory.page_size();
            let declared_min_bytes = memory.minimum().saturating_mul(page_size);
            if declared_min_bytes > max_bytes {
                return Err(Error::ConfigError(format!(
                    "wasm guard {} declares {} bytes of minimum linear memory, exceeding max_memory_mb={}",
                    guard, declared_min_bytes, max_memory_mb
                )));
            }

            if let Some(declared_max_pages) = memory.maximum() {
                let declared_max_bytes = declared_max_pages.saturating_mul(page_size);
                if declared_max_bytes > max_bytes {
                    return Err(Error::ConfigError(format!(
                        "wasm guard {} declares {} bytes of maximum linear memory, exceeding max_memory_mb={}",
                        guard, declared_max_bytes, max_memory_mb
                    )));
                }
            }
        }
    }

    Ok(())
}

fn max_memory_bytes_u64(max_memory_mb: u32) -> u64 {
    u64::from(max_memory_mb).saturating_mul(1024 * 1024)
}

fn max_memory_bytes(max_memory_mb: u32) -> usize {
    usize::try_from(max_memory_bytes_u64(max_memory_mb)).unwrap_or(usize::MAX)
}

fn write_into_memory(
    memory: &wasmtime::Memory,
    store: &mut Store<HostState>,
    ptr: usize,
    bytes: &[u8],
) -> Result<()> {
    let end = ptr
        .checked_add(bytes.len())
        .ok_or_else(|| Error::ConfigError("wasm memory pointer overflow".to_string()))?;
    let data = memory.data_mut(store);
    if end > data.len() {
        return Err(Error::ConfigError(format!(
            "wasm ABI write out of bounds: range [{ptr}, {end}) exceeds memory size {}",
            data.len()
        )));
    }
    data[ptr..end].copy_from_slice(bytes);
    Ok(())
}

fn parse_severity(raw: Option<&str>, allowed: bool) -> Severity {
    match raw.map(|s| s.trim().to_ascii_lowercase()) {
        Some(v) if v == "critical" => Severity::Critical,
        Some(v) if v == "high" || v == "error" => Severity::Error,
        Some(v) if v == "medium" || v == "warning" || v == "warn" => Severity::Warning,
        Some(v) if v == "low" || v == "info" => Severity::Info,
        Some(_) | None => {
            if allowed {
                Severity::Info
            } else {
                Severity::Error
            }
        }
    }
}

fn deny_execution(guard: &str, kind: &'static str, message: String) -> WasmGuardExecution {
    WasmGuardExecution {
        result: GuardResult {
            allowed: false,
            guard: guard.to_string(),
            severity: Severity::Error,
            message: message.clone(),
            details: Some(serde_json::json!({
                "runtime_fault": kind,
            })),
        },
        audit: vec![WasmRuntimeAuditRecord {
            kind,
            guard: guard.to_string(),
            message,
        }],
    }
}

fn capability_allowed(cap_kind: i32, caps: &PluginCapabilities) -> bool {
    match cap_kind {
        0 => caps.network,
        1 => caps.subprocess,
        2 => !caps.filesystem.read.is_empty(),
        3 => caps.filesystem.write,
        4 => caps.secrets.access,
        _ => false,
    }
}

fn capability_kind_name(cap_kind: i32) -> &'static str {
    match cap_kind {
        0 => "network",
        1 => "subprocess",
        2 => "filesystem.read",
        3 => "filesystem.write",
        4 => "secrets.access",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> WasmGuardInputEnvelope {
        WasmGuardInputEnvelope {
            guard: "acme.guard".to_string(),
            action_type: Some("tool_call".to_string()),
            payload: serde_json::json!({
                "eventType": "tool_call",
                "data": { "type": "tool", "toolName": "demo", "parameters": {} }
            }),
            config: serde_json::json!({}),
        }
    }

    #[test]
    fn executes_wasm_guard_successfully() {
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":false,\"severity\":\"high\",\"message\":\"Denied by wasm\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 64
                  i32.const 62
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let exec =
            execute_wasm_guard_bytes(&wasm, &envelope(), &WasmGuardRuntimeOptions::default())
                .expect("execute");
        assert!(!exec.result.allowed);
        assert_eq!(exec.result.guard, "acme.guard");
        assert_eq!(exec.result.severity, Severity::Error);
        assert!(exec.result.message.contains("Denied"));
        assert!(exec.audit.is_empty());
    }

    #[test]
    fn denies_disallowed_capability_requests() {
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":true,\"severity\":\"low\",\"message\":\"ok\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 1
                  call $cap
                  drop
                  i32.const 64
                  i32.const 48
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let exec =
            execute_wasm_guard_bytes(&wasm, &envelope(), &WasmGuardRuntimeOptions::default())
                .expect("execute");
        assert!(!exec.result.allowed);
        assert_eq!(
            exec.audit.first().map(|a| a.kind),
            Some("capability_denied")
        );
    }

    #[test]
    fn enforces_declared_maximum_memory_limit() {
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1 200)
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let mut options = WasmGuardRuntimeOptions::default();
        options.resources.max_memory_mb = 1;
        let err = execute_wasm_guard_bytes(&wasm, &envelope(), &options).expect_err("must fail");
        match err {
            Error::ConfigError(msg) => assert!(
                msg.contains("maximum linear memory"),
                "unexpected error message: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn enforces_runtime_memory_growth_limit() {
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":false,\"severity\":\"high\",\"message\":\"memory growth denied\"}")
                (data (i32.const 160) "{\"allowed\":true,\"severity\":\"low\",\"message\":\"memory growth allowed\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 100
                  memory.grow
                  i32.const -1
                  i32.eq
                  if
                    i32.const 64
                    i32.const 68
                    call $set_output
                    drop
                  else
                    i32.const 160
                    i32.const 67
                    call $set_output
                    drop
                  end
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let mut options = WasmGuardRuntimeOptions::default();
        options.resources.max_memory_mb = 1;

        let exec = execute_wasm_guard_bytes(&wasm, &envelope(), &options).expect("execute");
        assert!(
            !exec.result.allowed,
            "memory growth should have been denied"
        );
        assert!(
            exec.result.message.contains("memory growth denied"),
            "unexpected message: {}",
            exec.result.message
        );
    }

    #[test]
    fn times_out_for_non_terminating_plugins() {
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  (loop
                    br 0)
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let mut options = WasmGuardRuntimeOptions::default();
        options.resources.max_cpu_ms = 1;
        options.resources.max_timeout_ms = 10;

        let exec = execute_wasm_guard_bytes(&wasm, &envelope(), &options).expect("execute");
        assert!(!exec.result.allowed);
        let kind = exec.audit.first().map(|a| a.kind).unwrap_or("none");
        assert!(kind == "timeout" || kind == "sandbox_fault");
    }

    #[test]
    fn fast_guard_call_does_not_wait_for_timeout_window() {
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":true,\"severity\":\"low\",\"message\":\"ok\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 64
                  i32.const 48
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let mut options = WasmGuardRuntimeOptions::default();
        options.resources.max_timeout_ms = 4000;

        let start = std::time::Instant::now();
        let exec = execute_wasm_guard_bytes(&wasm, &envelope(), &options).expect("execute");
        let elapsed = start.elapsed();

        assert!(exec.result.allowed, "expected allowed guard result");
        assert!(
            elapsed < Duration::from_millis(2500),
            "fast guard call took {:?}, expected to complete well before timeout window",
            elapsed
        );
    }
}
