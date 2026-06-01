//! `pkg pack` — build a `.cpkg` archive from a package directory, with
//! pre-pack content validation and embedded-archive exclusion.

use std::io::Write;
use std::path::Path;

use hush_core::Hash;

use clawdstrike::pkg::archive;
use clawdstrike::pkg::manifest::{parse_pkg_manifest_toml, PkgManifest, PkgType};

use super::tempdir_for_download;
use crate::ExitCode;

pub(super) fn archive_file_name(name: &str, version: &str) -> String {
    format!(
        "{}-{}.cpkg",
        name.replace('/', "-").replace('@', ""),
        version
    )
}

fn copy_dir_recursive_excluding_cpkg(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry_type.is_dir() {
            copy_dir_recursive_excluding_cpkg(&src_path, &dst_path)?;
        } else if entry_type.is_file() {
            if src_path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("cpkg"))
            {
                continue;
            }
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

pub(super) fn pack_source_dir_without_embedded_archives(
    source_dir: &Path,
    output_path: &Path,
) -> Result<Hash, String> {
    let staging_root =
        tempdir_for_download().map_err(|e| format!("cannot create pack staging dir: {e}"))?;
    let staged_source = staging_root.join("source");
    let staged_archive = staging_root.join("package.cpkg");

    let result = (|| {
        copy_dir_recursive_excluding_cpkg(source_dir, &staged_source)
            .map_err(|e| format!("failed to stage package contents: {e}"))?;
        let hash = archive::pack(&staged_source, &staged_archive)
            .map_err(|e| format!("pack failed: {e}"))?;
        std::fs::copy(&staged_archive, output_path)
            .map_err(|e| format!("cannot write archive output {}: {e}", output_path.display()))?;
        Ok(hash)
    })();

    let _ = std::fs::remove_dir_all(staging_root);
    result
}

pub(super) fn cmd_pkg_pack(
    path: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let source_dir = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
                return ExitCode::RuntimeError;
            }
        },
    };

    // Read and validate manifest
    let manifest_path = source_dir.join("clawdstrike-pkg.toml");
    let manifest_str = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read clawdstrike-pkg.toml: {e}");
            return ExitCode::ConfigError;
        }
    };

    let manifest: PkgManifest = match parse_pkg_manifest_toml(&manifest_str) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid manifest: {e}");
            return ExitCode::ConfigError;
        }
    };

    // Pre-pack validation based on package type
    if let Err(msg) = validate_pack_contents(&source_dir, &manifest) {
        let _ = writeln!(stderr, "Error: {msg}");
        return ExitCode::ConfigError;
    }

    // Warn on missing README.md
    if !source_dir.join("README.md").exists() {
        let _ = writeln!(stderr, "Warning: README.md not found; consider adding one");
    }

    // Build archive name
    let archive_name = archive_file_name(&manifest.package.name, &manifest.package.version);
    let output_path = source_dir.join(&archive_name);

    // Pack
    let hash = match pack_source_dir_without_embedded_archives(&source_dir, &output_path) {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(stdout, "Packed: {}", output_path.display());
    let _ = writeln!(stdout, "Hash:   {}", hash.to_hex());
    ExitCode::Ok
}

/// Validate that a package directory contains the expected contents for its type.
pub(super) fn validate_pack_contents(
    source_dir: &Path,
    manifest: &PkgManifest,
) -> Result<(), String> {
    match manifest.package.pkg_type {
        PkgType::PolicyPack => {
            let policies_dir = source_dir.join("policies");
            if !policies_dir.is_dir() {
                return Err("policy-pack must contain a policies/ directory".to_string());
            }
            let has_yaml = std::fs::read_dir(&policies_dir)
                .map(|entries| {
                    entries.filter_map(|e| e.ok()).any(|e| {
                        e.path()
                            .extension()
                            .is_some_and(|ext| ext == "yaml" || ext == "yml")
                    })
                })
                .unwrap_or(false);
            if !has_yaml {
                return Err(
                    "policy-pack policies/ directory must contain at least one .yaml file"
                        .to_string(),
                );
            }
        }
        PkgType::Guard if !source_dir.join("src/lib.rs").exists() => {
            return Err("guard package must contain src/lib.rs (or a WASM entrypoint)".to_string());
        }
        PkgType::Guard => {}
        PkgType::Bundle if manifest.dependencies.is_empty() => {
            return Err(
                "bundle package must have at least one entry in [dependencies]".to_string(),
            );
        }
        PkgType::Bundle => {}
        _ => {}
    }
    Ok(())
}
