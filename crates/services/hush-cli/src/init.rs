use std::io::Write;
use std::path::{Path, PathBuf};

use crate::ui;
use crate::ExitCode;

const RULESETS: &[(&str, &str)] = &[
    ("default", "Balanced security defaults for general use"),
    (
        "strict",
        "Maximum security — blocks most operations by default",
    ),
    (
        "ai-agent",
        "Tuned for AI agent runtimes (Claude, GPT, etc.)",
    ),
    (
        "ai-agent-posture",
        "AI agent with posture-based state machine",
    ),
    ("permissive", "Minimal restrictions — audit-only mode"),
    ("cicd", "Designed for CI/CD pipeline environments"),
    (
        "remote-desktop",
        "Controls for remote desktop / CUA sessions",
    ),
    (
        "remote-desktop-permissive",
        "Permissive remote desktop — audit-only mode",
    ),
    (
        "remote-desktop-strict",
        "Strict remote desktop — maximum restrictions",
    ),
];

pub struct InitArgs {
    pub non_interactive: bool,
    pub ruleset: Option<String>,
    pub keygen: bool,
    pub dir: Option<PathBuf>,
}

pub fn cmd_init(args: InitArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    let base_dir = args
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let cs_dir = base_dir.join(".clawdstrike");

    // Detect existing config
    if cs_dir.exists() {
        if args.non_interactive {
            let _ = writeln!(
                stderr,
                "Warning: .clawdstrike/ already exists. Reinitializing."
            );
        } else {
            let confirm = dialoguer::Confirm::new()
                .with_prompt(".clawdstrike/ already exists. Reinitialize?")
                .default(false)
                .interact();
            match confirm {
                Ok(true) => {}
                Ok(false) => {
                    let _ = writeln!(stdout, "Aborted.");
                    return ExitCode::Ok;
                }
                Err(_) => {
                    let _ = writeln!(stderr, "Error: failed to read confirmation");
                    return ExitCode::RuntimeError;
                }
            }
        }
    }

    // Choose ruleset
    let ruleset = if let Some(ref rs) = args.ruleset {
        if !RULESETS.iter().any(|(id, _)| id == rs) {
            let _ = writeln!(stderr, "Error: unknown ruleset {:?}", rs);
            let _ = writeln!(
                stderr,
                "Available: {}",
                RULESETS
                    .iter()
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return ExitCode::InvalidArgs;
        }
        rs.clone()
    } else if args.non_interactive {
        "default".to_string()
    } else {
        let items: Vec<String> = RULESETS
            .iter()
            .map(|(id, desc)| format!("{:<22} {}", id, desc))
            .collect();

        let selection = dialoguer::Select::new()
            .with_prompt("Choose a base ruleset")
            .items(&items)
            .default(0)
            .interact();

        match selection {
            Ok(idx) => RULESETS[idx].0.to_string(),
            Err(_) => {
                let _ = writeln!(stderr, "Error: failed to read selection");
                return ExitCode::RuntimeError;
            }
        }
    };

    // Keypair decision
    let do_keygen = if args.keygen {
        true
    } else if args.non_interactive {
        false
    } else {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Generate an Ed25519 signing keypair?")
            .default(true)
            .interact();
        match confirm {
            Ok(v) => v,
            Err(_) => {
                let _ = writeln!(stderr, "Error: failed to read confirmation");
                return ExitCode::RuntimeError;
            }
        }
    };

    // Scaffold directory
    if let Err(e) = std::fs::create_dir_all(&cs_dir) {
        let _ = writeln!(stderr, "Error: failed to create .clawdstrike/: {}", e);
        return ExitCode::RuntimeError;
    }

    // Write policy.yaml
    let policy_path = cs_dir.join("policy.yaml");
    if let Err(e) = write_policy_yaml(&policy_path, &ruleset) {
        let _ = writeln!(stderr, "Error: failed to write policy.yaml: {}", e);
        return ExitCode::RuntimeError;
    }

    // Write config.toml
    let config_path = cs_dir.join("config.toml");
    if let Err(e) = write_config_toml(&config_path) {
        let _ = writeln!(stderr, "Error: failed to write config.toml: {}", e);
        return ExitCode::RuntimeError;
    }

    // Generate keypair
    if do_keygen {
        let keys_dir = cs_dir.join("keys");
        if let Err(e) = generate_keypair(&keys_dir) {
            let _ = writeln!(stderr, "Error: failed to generate keypair: {}", e);
            return ExitCode::RuntimeError;
        }
    }

    // Update .gitignore
    if let Err(e) = update_gitignore(&base_dir) {
        let _ = writeln!(stderr, "Warning: failed to update .gitignore: {}", e);
        // Non-fatal — continue
    }

    // Success output
    let mut lines = vec![
        format!("  {} policy.yaml (extends: clawdstrike:{})", "✓", ruleset),
        format!("  {} config.toml", "✓"),
    ];
    if do_keygen {
        lines.push(format!("  {} keys/hush.key", "✓"));
        lines.push(format!("  {} keys/hush.pub", "✓"));
    }
    lines.push(String::new());
    lines.push("Next steps:".to_string());
    lines.push("  hush check --action-type file /tmp/test.txt".to_string());
    lines.push("  hush policy lint .clawdstrike/policy.yaml".to_string());

    ui::render_box("Clawdstrike Initialized", &lines, stdout);

    ExitCode::Ok
}

fn write_policy_yaml(path: &Path, ruleset: &str) -> std::io::Result<()> {
    let content = format!(
        r#"version: "1.2.0"
name: "project policy"
description: "Auto-generated by hush init"
extends: "clawdstrike:{ruleset}"
"#
    );
    std::fs::write(path, content)
}

fn write_config_toml(path: &Path) -> std::io::Result<()> {
    let content = r#"# Clawdstrike configuration
# See: https://docs.clawdstrike.dev/configuration

# [daemon]
# url = "http://127.0.0.1:9876"
# token_env = "CLAWDSTRIKE_API_KEY"

# [defaults]
# ruleset = "default"
# signing_key = ".clawdstrike/keys/hush.key"

# [registry]
# url = "https://registry.clawdstrike.dev"
"#;
    std::fs::write(path, content)
}

fn generate_keypair(keys_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(keys_dir)?;

    let keypair = hush_core::Keypair::generate();
    let private_hex = keypair.to_hex();
    let public_hex = keypair.public_key().to_hex();

    let key_path = keys_dir.join("hush.key");
    let pub_path = keys_dir.join("hush.pub");

    // Reuse the shared write_secret_file helper for restricted-permission writes.
    crate::write_secret_file(&key_path.to_string_lossy(), &private_hex)?;

    std::fs::write(&pub_path, &public_hex)?;

    Ok(())
}

fn update_gitignore(base_dir: &Path) -> std::io::Result<()> {
    let gitignore_path = base_dir.join(".gitignore");
    let entries = [".clawdstrike/keys/*.key", ".clawdstrike/credentials.toml"];

    let existing = if gitignore_path.exists() {
        std::fs::read_to_string(&gitignore_path)?
    } else {
        String::new()
    };

    let mut to_add = Vec::new();
    for entry in &entries {
        if !existing.lines().any(|line| line.trim() == *entry) {
            to_add.push(*entry);
        }
    }

    if to_add.is_empty() {
        return Ok(());
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gitignore_path)?;

    // Add newline before our entries if the file doesn't end with one
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file)?;
    }

    writeln!(file, "\n# Clawdstrike secrets")?;
    for entry in &to_add {
        writeln!(file, "{}", entry)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_non_interactive_scaffolds_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = cmd_init(
            InitArgs {
                non_interactive: true,
                ruleset: None,
                keygen: false,
                dir: Some(tmp.path().to_path_buf()),
            },
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::Ok);

        let cs_dir = tmp.path().join(".clawdstrike");
        assert!(cs_dir.join("policy.yaml").exists());
        assert!(cs_dir.join("config.toml").exists());
        assert!(!cs_dir.join("keys").exists()); // no keygen

        let policy = std::fs::read_to_string(cs_dir.join("policy.yaml")).unwrap();
        assert!(policy.contains("extends: \"clawdstrike:default\""));
        assert!(policy.contains("version: \"1.2.0\""));
    }

    #[test]
    fn init_non_interactive_with_keygen() {
        let tmp = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = cmd_init(
            InitArgs {
                non_interactive: true,
                ruleset: Some("strict".to_string()),
                keygen: true,
                dir: Some(tmp.path().to_path_buf()),
            },
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::Ok);

        let cs_dir = tmp.path().join(".clawdstrike");
        assert!(cs_dir.join("keys/hush.key").exists());
        assert!(cs_dir.join("keys/hush.pub").exists());

        let policy = std::fs::read_to_string(cs_dir.join("policy.yaml")).unwrap();
        assert!(policy.contains("extends: \"clawdstrike:strict\""));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(cs_dir.join("keys/hush.key")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn init_updates_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = cmd_init(
            InitArgs {
                non_interactive: true,
                ruleset: None,
                keygen: false,
                dir: Some(tmp.path().to_path_buf()),
            },
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::Ok);

        let gitignore = std::fs::read_to_string(tmp.path().join(".gitignore")).unwrap();
        assert!(gitignore.contains(".clawdstrike/keys/*.key"));
        assert!(gitignore.contains(".clawdstrike/credentials.toml"));
    }

    #[test]
    fn init_unknown_ruleset_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = cmd_init(
            InitArgs {
                non_interactive: true,
                ruleset: Some("nonexistent".to_string()),
                keygen: false,
                dir: Some(tmp.path().to_path_buf()),
            },
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::InvalidArgs);
    }

    #[test]
    fn init_reinit_non_interactive() {
        let tmp = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        // First init
        let _ = cmd_init(
            InitArgs {
                non_interactive: true,
                ruleset: None,
                keygen: false,
                dir: Some(tmp.path().to_path_buf()),
            },
            &mut stdout,
            &mut stderr,
        );

        // Second init should succeed with warning
        stdout.clear();
        stderr.clear();
        let code = cmd_init(
            InitArgs {
                non_interactive: true,
                ruleset: Some("strict".to_string()),
                keygen: false,
                dir: Some(tmp.path().to_path_buf()),
            },
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::Ok);
        let policy = std::fs::read_to_string(tmp.path().join(".clawdstrike/policy.yaml")).unwrap();
        assert!(policy.contains("clawdstrike:strict"));
    }

    #[test]
    fn gitignore_deduplication() {
        let tmp = tempfile::tempdir().unwrap();

        // Write a gitignore that already has one of our entries
        std::fs::write(
            tmp.path().join(".gitignore"),
            "node_modules/\n.clawdstrike/keys/*.key\n",
        )
        .unwrap();

        update_gitignore(tmp.path()).unwrap();

        let content = std::fs::read_to_string(tmp.path().join(".gitignore")).unwrap();
        let key_count = content
            .lines()
            .filter(|l| l.trim() == ".clawdstrike/keys/*.key")
            .count();
        assert_eq!(key_count, 1); // should not duplicate
        assert!(content.contains(".clawdstrike/credentials.toml")); // should add missing
    }
}
