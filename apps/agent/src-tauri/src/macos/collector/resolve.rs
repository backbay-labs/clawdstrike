//! Tool resolution: locate the macOS status helpers via env-var overrides,
//! Tauri resource bundles, or the local Swift package build outputs.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager, Runtime};

use super::tool::{
    ToolInvocation, ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV, ALLOW_SWIFT_RUN_STATUS_TOOLS_ENV,
};

pub(super) fn resolve_status_tool<R: Runtime>(
    app: &AppHandle<R>,
    env_var: &str,
    relative_package_path: &str,
    executable: &'static str,
) -> Option<ToolInvocation> {
    let allow_swift_run = swift_run_status_tools_enabled();

    if let Some(tool) = resolve_direct_tool_from_env(env_var) {
        return Some(tool);
    }

    if let Some(resource_package) = resolve_resource_package_path(app, relative_package_path) {
        if let Some(tool) =
            resolve_package_status_tool(&resource_package, executable, allow_swift_run)
        {
            return Some(tool);
        }
    }

    let source_package = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_package_path);
    if let Some(tool) = resolve_package_status_tool(&source_package, executable, allow_swift_run) {
        return Some(tool);
    }

    None
}

fn swift_run_status_tools_enabled() -> bool {
    std::env::var(ALLOW_SWIFT_RUN_STATUS_TOOLS_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn direct_status_tool_overrides_enabled() -> bool {
    std::env::var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub(super) fn resolve_direct_tool_from_env(env_var: &str) -> Option<ToolInvocation> {
    let path = std::env::var_os(env_var)?;
    if !direct_status_tool_overrides_enabled() {
        tracing::warn!(
            env = env_var,
            "ignoring macOS status helper override because direct helper overrides are disabled"
        );
        return None;
    }
    let program = PathBuf::from(path);
    if !program.is_absolute() {
        tracing::warn!(
            path = %program.display(),
            env = env_var,
            "ignoring macOS status helper override because the path is not absolute"
        );
        return None;
    }
    if !program.is_file() {
        tracing::warn!(
            path = %program.display(),
            env = env_var,
            "ignoring macOS status helper override because the path does not exist"
        );
        return None;
    }
    Some(ToolInvocation::Direct {
        program,
        args: vec![OsString::from("live")],
    })
}

fn resolve_resource_package_path<R: Runtime>(
    app: &AppHandle<R>,
    relative_package_path: &str,
) -> Option<PathBuf> {
    app.path()
        .resolve(relative_package_path, BaseDirectory::Resource)
        .ok()
        .filter(|path| path.exists())
}

fn resolve_direct_built_tool(
    package_path: &Path,
    executable: &'static str,
) -> Option<ToolInvocation> {
    for candidate in direct_built_tool_candidates(package_path, executable) {
        if candidate.is_file() {
            return Some(ToolInvocation::Direct {
                program: candidate,
                args: vec![OsString::from("live")],
            });
        }
    }
    None
}

fn direct_built_tool_candidates(package_path: &Path, executable: &'static str) -> Vec<PathBuf> {
    let mut candidates = vec![package_path.join("bin").join(executable)];
    for profile in ["release", "debug"] {
        candidates.push(package_path.join(".build").join(profile).join(executable));
    }
    let build_dir = package_path.join(".build");
    if let Ok(entries) = std::fs::read_dir(&build_dir) {
        let mut platform_dirs = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        platform_dirs.sort();
        for platform_dir in platform_dirs {
            for profile in ["release", "debug"] {
                candidates.push(platform_dir.join(profile).join(executable));
            }
        }
    }
    candidates
}

pub(super) fn resolve_package_status_tool(
    package_path: &Path,
    executable: &'static str,
    allow_swift_run: bool,
) -> Option<ToolInvocation> {
    resolve_package_status_tool_with_swift_availability(
        package_path,
        executable,
        allow_swift_run,
        which::which("swift").is_ok(),
    )
}

pub(super) fn resolve_package_status_tool_with_swift_availability(
    package_path: &Path,
    executable: &'static str,
    allow_swift_run: bool,
    swift_available: bool,
) -> Option<ToolInvocation> {
    if let Some(tool) = resolve_direct_built_tool(package_path, executable) {
        return Some(tool);
    }
    if allow_swift_run && swift_available && package_path.join("Package.swift").is_file() {
        return Some(ToolInvocation::SwiftRun {
            package_path: package_path.to_path_buf(),
            executable,
        });
    }
    None
}
