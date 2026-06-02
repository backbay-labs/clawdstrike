//! Package scaffolding: template-file writers and content generators used by
//! `pkg init` to lay down a new package skeleton.

use std::path::Path;

use clawdstrike::pkg::manifest::PkgType;

use super::PLUGIN_MANIFEST_FILENAME;

/// Write a template file into the given directory, creating parent dirs as needed.
fn write_template_file(dir: &Path, filename: &str, content: &str) -> std::io::Result<()> {
    let path = dir.join(filename);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)
}

pub(super) fn scaffold_package(dir: &Path, pkg_type: &PkgType, name: &str) -> std::io::Result<()> {
    // Create type-specific directories
    match pkg_type {
        PkgType::Guard => {
            std::fs::create_dir_all(dir.join("src"))?;
            std::fs::create_dir_all(dir.join("tests"))?;
            std::fs::create_dir_all(dir.join(".cargo"))?;
        }
        PkgType::PolicyPack => {
            std::fs::create_dir_all(dir.join("policies"))?;
            std::fs::create_dir_all(dir.join("data"))?;
            std::fs::create_dir_all(dir.join("tests"))?;
        }
        PkgType::Adapter => {
            std::fs::create_dir_all(dir.join("src"))?;
        }
        PkgType::Engine => {
            std::fs::create_dir_all(dir.join("src"))?;
        }
        PkgType::Template => {
            std::fs::create_dir_all(dir.join("template"))?;
        }
        PkgType::Bundle => {
            // No extra directories needed
        }
    }

    // Write the package manifest
    let manifest_toml = generate_manifest_toml(name, pkg_type);
    write_template_file(dir, "clawdstrike-pkg.toml", &manifest_toml)?;

    // Type-specific template files
    match pkg_type {
        PkgType::Guard => scaffold_guard_templates(dir, name)?,
        PkgType::PolicyPack => scaffold_policy_pack_templates(dir, name)?,
        PkgType::Bundle => scaffold_bundle_templates(dir, name)?,
        _ => {}
    }

    Ok(())
}

fn scaffold_guard_templates(dir: &Path, name: &str) -> std::io::Result<()> {
    let cargo_package_name = sanitize_cargo_package_name(name);
    let wasm_entrypoint = default_guard_wasm_entrypoint(&cargo_package_name);

    // Derive a safe Rust identifier from the guard name for struct names
    let struct_name = name
        .replace('@', "")
        .replace(['/', '-'], "_")
        .split('_')
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<String>()
        + "Guard";

    // src/lib.rs
    std::fs::write(
        dir.join("src/lib.rs"),
        generate_guard_lib_rs(name, &struct_name),
    )?;

    // Cargo.toml for the guard project
    std::fs::write(
        dir.join("Cargo.toml"),
        generate_guard_cargo_toml(&cargo_package_name),
    )?;

    // Canonical runtime plugin manifest.
    let plugin_manifest = generate_guard_plugin_manifest(name, &wasm_entrypoint);
    std::fs::write(dir.join(PLUGIN_MANIFEST_FILENAME), &plugin_manifest)?;

    // tests/basic.yaml
    std::fs::write(
        dir.join("tests/basic.yaml"),
        generate_guard_test_fixture(name),
    )?;

    // .cargo/config.toml
    std::fs::write(
        dir.join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
    )?;

    Ok(())
}

pub(super) fn sanitize_cargo_package_name(name: &str) -> String {
    let without_scope = name.trim_start_matches('@').replace('/', "-");
    let mut out = String::with_capacity(without_scope.len());
    let mut prev_sep = false;

    for ch in without_scope.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        let is_sep = mapped == '-' || mapped == '_';
        if is_sep && prev_sep {
            continue;
        }
        out.push(mapped);
        prev_sep = is_sep;
    }

    let trimmed = out.trim_matches(|c| c == '-' || c == '_').to_string();
    if trimmed.is_empty() {
        return "guard-plugin".to_string();
    }
    if !trimmed
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
    {
        return format!("guard-{trimmed}");
    }
    trimmed
}

fn default_guard_wasm_entrypoint(cargo_package_name: &str) -> String {
    format!(
        "target/wasm32-unknown-unknown/release/{}.wasm",
        cargo_package_name.replace('-', "_")
    )
}

fn scaffold_policy_pack_templates(dir: &Path, name: &str) -> std::io::Result<()> {
    // policies/default.yaml
    write_template_file(
        dir,
        "policies/default.yaml",
        &generate_policy_pack_default_yaml(name),
    )?;

    // tests/policy-test.yaml
    write_template_file(
        dir,
        "tests/policy-test.yaml",
        &generate_policy_pack_test(name),
    )?;

    // README.md
    write_template_file(dir, "README.md", &generate_policy_pack_readme(name))?;

    Ok(())
}

fn scaffold_bundle_templates(dir: &Path, name: &str) -> std::io::Result<()> {
    // README.md
    write_template_file(dir, "README.md", &generate_bundle_readme(name))?;

    Ok(())
}

fn generate_policy_pack_default_yaml(name: &str) -> String {
    format!(
        r#"# {name} — Default Policy
version: "1.2.0"
name: {name}
description: Default policy for {name}
extends: clawdstrike:default

guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "/etc/shadow"
      - "/etc/passwd"
    exceptions: []

  secret_leak:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{{16}}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
    skip_paths:
      - "**/test/**"
      - "**/tests/**"

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600
"#
    )
}

fn generate_policy_pack_test(name: &str) -> String {
    format!(
        r#"# Test suite for {name} policy pack
suite: "{name} policy tests"
tests:
  - name: "blocks access to .ssh directory"
    action:
      type: "file_access"
      path: "/home/user/.ssh/id_rsa"
    policy: "policies/default.yaml"
    expect:
      allowed: false

  - name: "allows access to safe path"
    action:
      type: "file_access"
      path: "/tmp/safe-file.txt"
    policy: "policies/default.yaml"
    expect:
      allowed: true
"#
    )
}

fn generate_policy_pack_readme(name: &str) -> String {
    format!(
        r#"# {name}

A Clawdstrike policy pack.

## Policies

| Policy | Description |
|--------|-------------|
| `policies/default.yaml` | Default policy configuration |

## Usage

```yaml
extends: "{name}/policies/default"
```

```bash
clawdstrike pkg install {name}
clawdstrike check --ruleset {name}/policies/default --action-type file /path/to/check
```

## Compliance Mapping

| Requirement | Control | Guard |
|---|---|---|
| *Add your compliance mapping here* | | |
"#
    )
}

fn generate_bundle_readme(name: &str) -> String {
    format!(
        r#"# {name}

A Clawdstrike bundle package that combines guards and policy packs.

## Dependencies

This bundle includes the following packages (see `[dependencies]` in `clawdstrike-pkg.toml`):

| Package | Version | Description |
|---------|---------|-------------|
| *Add dependencies to clawdstrike-pkg.toml* | | |

## Usage

```bash
clawdstrike pkg install {name}
```

All bundled guards and policies are installed together as a single unit.
"#
    )
}

fn generate_guard_lib_rs(name: &str, struct_name: &str) -> String {
    format!(
        r#"//! {name} -- a Clawdstrike WASM guard plugin.
//!
//! This guard is compiled to `wasm32-unknown-unknown` and loaded by
//! the Clawdstrike runtime at evaluation time.

use clawdstrike_guard_sdk::prelude::*;

/// {struct_name} implements a custom security guard.
#[clawdstrike_guard]
#[derive(Default)]
pub struct {struct_name};

impl Guard for {struct_name} {{
    fn name(&self) -> &str {{
        "{name}"
    }}

    fn handles(&self, action_type: &str) -> bool {{
        // Return true for the action types this guard should evaluate.
        // Examples: "file_access", "mcp_tool", "shell_command", "network"
        matches!(action_type, "file_access" | "mcp_tool")
    }}

    fn check(&self, input: GuardInput) -> GuardOutput {{
        // Implement your security logic here.
        //
        // `input.payload` contains the action details as a JSON value.
        // `input.config` contains per-invocation configuration.
        //
        // Return `GuardOutput::allow()` or `GuardOutput::deny(severity, message)`.

        GuardOutput::allow()
    }}
}}
"#
    )
}

fn generate_guard_cargo_toml(cargo_package_name: &str) -> String {
    format!(
        r#"[package]
name = "{cargo_package_name}"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
clawdstrike-guard-sdk = {{ version = "0.1" }}

[profile.release]
opt-level = "s"
lto = true
strip = true
"#
    )
}

fn generate_guard_plugin_manifest(name: &str, entrypoint: &str) -> String {
    format!(
        r#"[plugin]
name = "{name}"
version = "0.1.0"
description = "A custom Clawdstrike guard plugin"

[[guards]]
name = "{name}"
entrypoint = "{entrypoint}"
handles = ["file_access", "mcp_tool"]

[capabilities]

[resources]
max_memory_mb = 16
max_cpu_ms = 50
max_timeout_ms = 5000

[trust]
level = "untrusted"
sandbox = "wasm"
"#
    )
}

fn generate_guard_test_fixture(name: &str) -> String {
    format!(
        r#"suite: "{name} Tests"
guard: "{name}"
fixtures:
  - name: "allows safe action"
    action:
      type: "file_access"
      path: "/tmp/safe-file.txt"
    expect:
      allowed: true

  - name: "evaluates tool call"
    action:
      type: "mcp_tool"
      tool: "read_file"
      args:
        path: "/tmp/test.txt"
    expect:
      allowed: true
"#
    )
}

fn generate_manifest_toml(name: &str, pkg_type: &PkgType) -> String {
    let deps = if *pkg_type == PkgType::Bundle {
        r#"[dependencies]
# "@clawdstrike/example-guard" = "^0.1"
# "@clawdstrike/example-policy" = "^0.1"
"#
    } else {
        "[dependencies]\n"
    };

    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
pkg_type = "{pkg_type}"
description = ""
authors = []
license = "Apache-2.0"

[clawdstrike]
min_version = "{clawdstrike_version}"

[trust]
level = "untrusted"
sandbox = "wasm"

{deps}"#,
        clawdstrike_version = env!("CARGO_PKG_VERSION"),
    )
}
