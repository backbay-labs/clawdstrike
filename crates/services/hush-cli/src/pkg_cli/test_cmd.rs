//! `pkg test` — run guard test fixtures against a WASM guard plugin.
//!
//! The runner itself requires the `wasm-plugin-runtime` feature; without it,
//! `cmd_pkg_test` is a stub that reports the missing feature.

use std::io::Write;
use std::path::Path;
#[cfg(feature = "wasm-plugin-runtime")]
use std::path::PathBuf;

#[cfg(feature = "wasm-plugin-runtime")]
use super::scaffold::sanitize_cargo_package_name;
#[cfg(feature = "wasm-plugin-runtime")]
use super::PLUGIN_MANIFEST_FILENAME;
use crate::ExitCode;

#[cfg(feature = "wasm-plugin-runtime")]
pub(super) fn cmd_pkg_test(
    path: Option<&Path>,
    filter: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    use clawdstrike::pkg::test_runner::{parse_guard_test_file, run_guard_tests};

    let pkg_dir = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
                return ExitCode::RuntimeError;
            }
        },
    };

    // Discover test fixture files
    let tests_dir = pkg_dir.join("tests");
    if !tests_dir.is_dir() {
        let _ = writeln!(
            stderr,
            "Error: no tests/ directory found in {}",
            pkg_dir.display()
        );
        return ExitCode::ConfigError;
    }

    let fixture_files: Vec<PathBuf> = match std::fs::read_dir(&tests_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect(),
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read tests/ directory: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if fixture_files.is_empty() {
        let _ = writeln!(
            stderr,
            "Error: no .yaml/.yml fixture files found in {}",
            tests_dir.display()
        );
        return ExitCode::ConfigError;
    }

    // Find the WASM file: check plugin manifest entrypoint first, then fall
    // back to conventional target output locations.
    let wasm_path = find_wasm_binary(&pkg_dir, stderr);
    let wasm_path = match wasm_path {
        Some(p) => p,
        None => return ExitCode::ConfigError,
    };

    let wasm_bytes = match std::fs::read(&wasm_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "Error: cannot read WASM file {}: {e}",
                wasm_path.display()
            );
            return ExitCode::RuntimeError;
        }
    };

    // Load runtime options from plugin manifest if available.
    let options = load_runtime_options(&pkg_dir);

    let _ = writeln!(stdout, "Running guard tests...");
    let _ = writeln!(stdout, "WASM: {}", wasm_path.display());
    let _ = writeln!(stdout);

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut total_error = 0usize;

    for fixture_path in &fixture_files {
        let suite = match parse_guard_test_file(fixture_path) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "Error: failed to parse {}: {e}",
                    fixture_path.display()
                );
                total_error += 1;
                continue;
            }
        };

        let file_name = fixture_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let _ = writeln!(stdout, "--- {} ({})", suite.suite, file_name);

        let results = run_guard_tests(&wasm_bytes, &suite, &options, filter);

        for result in &results {
            if result.passed {
                total_pass += 1;
                let _ = writeln!(
                    stdout,
                    "  PASS  {} ({:.1}ms)",
                    result.name,
                    result.duration.as_secs_f64() * 1000.0
                );
            } else if let Some(ref err) = result.error {
                total_error += 1;
                let _ = writeln!(stdout, "  ERROR {} -- {}", result.name, err);
            } else {
                total_fail += 1;
                let _ = writeln!(
                    stdout,
                    "  FAIL  {} ({:.1}ms)",
                    result.name,
                    result.duration.as_secs_f64() * 1000.0
                );
                for mismatch in &result.mismatches {
                    let _ = writeln!(
                        stdout,
                        "         {}: expected '{}', got '{}'",
                        mismatch.field, mismatch.expected, mismatch.actual
                    );
                }
            }
        }

        let _ = writeln!(stdout);
    }

    let _ = writeln!(
        stdout,
        "Results: {} passed, {} failed, {} errors",
        total_pass, total_fail, total_error
    );

    if total_fail > 0 || total_error > 0 {
        ExitCode::Fail
    } else {
        ExitCode::Ok
    }
}

#[cfg(not(feature = "wasm-plugin-runtime"))]
pub(super) fn cmd_pkg_test(
    _path: Option<&Path>,
    _filter: Option<&str>,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let _ = writeln!(
        stderr,
        "Error: `pkg test` requires the `wasm-plugin-runtime` feature.\n\
         Rebuild with: cargo build --features wasm-plugin-runtime"
    );
    ExitCode::ConfigError
}

#[cfg(feature = "wasm-plugin-runtime")]
fn load_plugin_manifest_from_package(
    pkg_dir: &Path,
) -> Option<(std::path::PathBuf, clawdstrike::plugins::PluginManifest)> {
    use clawdstrike::plugins::parse_plugin_manifest_toml;

    let manifest_path = pkg_dir.join(PLUGIN_MANIFEST_FILENAME);
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(_) => return None,
    };
    if let Ok(manifest) = parse_plugin_manifest_toml(&content) {
        return Some((manifest_path, manifest));
    }

    None
}

#[cfg(feature = "wasm-plugin-runtime")]
fn find_wasm_binary(pkg_dir: &Path, stderr: &mut dyn Write) -> Option<PathBuf> {
    // Try plugin manifest entrypoint first.
    if let Some((_manifest_path, manifest)) = load_plugin_manifest_from_package(pkg_dir) {
        if let Some(entrypoint) = manifest
            .guards
            .first()
            .and_then(|g| g.entrypoint.as_deref())
        {
            let candidate = pkg_dir.join(entrypoint);
            if candidate.exists() {
                return Some(candidate);
            }
        }

        // Fall back to conventional artifact naming from plugin name.
        let fallback_pkg_name = sanitize_cargo_package_name(&manifest.plugin.name);
        let wasm_name = format!("{}.wasm", fallback_pkg_name.replace('-', "_"));
        for profile in &["release", "debug"] {
            let candidate = pkg_dir
                .join("target/wasm32-unknown-unknown")
                .join(profile)
                .join(&wasm_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // Fall back: try to read Cargo.toml for [package].name
    let cargo_path = pkg_dir.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_path) {
        if let Ok(table) = content.parse::<toml::Table>() {
            if let Some(pkg_name) = table
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
            {
                let wasm_name = format!("{}.wasm", pkg_name.replace('-', "_"));
                for profile in &["release", "debug"] {
                    let candidate = pkg_dir
                        .join("target/wasm32-unknown-unknown")
                        .join(profile)
                        .join(&wasm_name);
                    if candidate.exists() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    // Last resort: find any .wasm file in the target dirs
    for profile in &["release", "debug"] {
        let dir = pkg_dir.join("target/wasm32-unknown-unknown").join(profile);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|ext| ext == "wasm") {
                    return Some(p);
                }
            }
        }
    }

    let _ = writeln!(
        stderr,
        "Error: no .wasm file found. Build your guard first:\n  \
         cargo build --target wasm32-unknown-unknown --release"
    );
    None
}

#[cfg(feature = "wasm-plugin-runtime")]
fn load_runtime_options(pkg_dir: &Path) -> clawdstrike::plugins::WasmGuardRuntimeOptions {
    use clawdstrike::plugins::WasmGuardRuntimeOptions;

    if let Some((_manifest_path, manifest)) = load_plugin_manifest_from_package(pkg_dir) {
        return WasmGuardRuntimeOptions {
            capabilities: manifest.capabilities,
            resources: manifest.resources,
        };
    }

    WasmGuardRuntimeOptions::default()
}
