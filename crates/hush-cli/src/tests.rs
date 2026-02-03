//! CLI unit tests for hush command-line interface
//!
//! Tests cover:
//! - Command parsing for all subcommands
//! - Argument validation and defaults
//! - Help and version flags
//! - Invalid command handling
//! - Shell completion generation

#[cfg(test)]
mod cli_parsing {
    use clap::Parser;

    use crate::{Cli, Commands, DaemonCommands, MerkleCommands, PolicyCommands};

    #[test]
    fn test_check_command_parses_with_required_args() {
        let cli = Cli::parse_from(["hush", "check", "--action-type", "file", "/path/to/file"]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                json,
                policy,
                ruleset,
            } => {
                assert_eq!(action_type, "file");
                assert_eq!(target, "/path/to/file");
                assert!(!json);
                assert!(policy.is_none());
                assert!(ruleset.is_none()); // defaults to "default" at runtime
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_check_command_with_custom_ruleset() {
        let cli = Cli::parse_from([
            "hush",
            "check",
            "--action-type",
            "egress",
            "--ruleset",
            "strict",
            "api.example.com:443",
        ]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                json,
                ruleset,
                policy,
            } => {
                assert_eq!(action_type, "egress");
                assert_eq!(target, "api.example.com:443");
                assert!(!json);
                assert!(policy.is_none());
                assert_eq!(ruleset, Some("strict".to_string()));
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_check_command_mcp_action_type() {
        let cli = Cli::parse_from(["hush", "check", "-a", "mcp", "filesystem_read"]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                policy,
                ..
            } => {
                assert_eq!(action_type, "mcp");
                assert_eq!(target, "filesystem_read");
                assert!(policy.is_none());
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_check_command_with_policy_file() {
        let cli = Cli::parse_from([
            "hush",
            "check",
            "--action-type",
            "file",
            "--policy",
            "policy.yaml",
            "/path/to/file",
        ]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                json,
                policy,
                ruleset,
            } => {
                assert_eq!(action_type, "file");
                assert_eq!(target, "/path/to/file");
                assert!(!json);
                assert_eq!(policy, Some("policy.yaml".to_string()));
                assert!(ruleset.is_none());
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_verify_command_parses() {
        let cli = Cli::parse_from(["hush", "verify", "receipt.json", "--pubkey", "key.pub"]);

        match cli.command {
            Commands::Verify {
                receipt,
                json,
                pubkey,
            } => {
                assert_eq!(receipt, "receipt.json");
                assert!(!json);
                assert_eq!(pubkey, "key.pub");
            }
            _ => panic!("Expected Verify command"),
        }
    }

    #[test]
    fn test_keygen_command_default_output() {
        let cli = Cli::parse_from(["hush", "keygen"]);

        match cli.command {
            Commands::Keygen { output } => {
                assert_eq!(output, "hush.key"); // default
            }
            _ => panic!("Expected Keygen command"),
        }
    }

    #[test]
    fn test_keygen_command_custom_output() {
        let cli = Cli::parse_from(["hush", "keygen", "--output", "/custom/path/my.key"]);

        match cli.command {
            Commands::Keygen { output } => {
                assert_eq!(output, "/custom/path/my.key");
            }
            _ => panic!("Expected Keygen command"),
        }
    }

    #[test]
    fn test_policy_show_default_ruleset() {
        let cli = Cli::parse_from(["hush", "policy", "show"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Show { ruleset, merged } => {
                    assert_eq!(ruleset, "default");
                    assert!(!merged);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_show_custom_ruleset() {
        let cli = Cli::parse_from(["hush", "policy", "show", "strict"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Show { ruleset, merged } => {
                    assert_eq!(ruleset, "strict");
                    assert!(!merged);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_show_with_merged_flag() {
        let cli = Cli::parse_from(["hush", "policy", "show", "--merged", "strict"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Show { ruleset, merged } => {
                    assert_eq!(ruleset, "strict");
                    assert!(merged);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_validate() {
        let cli = Cli::parse_from(["hush", "policy", "validate", "policy.yaml"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Validate { file, resolve } => {
                    assert_eq!(file, "policy.yaml");
                    assert!(!resolve);
                }
                _ => panic!("Expected Validate subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_validate_with_resolve_flag() {
        let cli = Cli::parse_from(["hush", "policy", "validate", "--resolve", "policy.yaml"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Validate { file, resolve } => {
                    assert_eq!(file, "policy.yaml");
                    assert!(resolve);
                }
                _ => panic!("Expected Validate subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_list() {
        let cli = Cli::parse_from(["hush", "policy", "list"]);

        match cli.command {
            Commands::Policy { command } => {
                assert!(matches!(command, PolicyCommands::List));
            }
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_eval_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "eval",
            "--resolve",
            "--json",
            "default",
            "event.json",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Eval {
                    policy_ref,
                    event,
                    resolve,
                    json,
                } => {
                    assert_eq!(policy_ref, "default");
                    assert_eq!(event, "event.json");
                    assert!(resolve);
                    assert!(json);
                }
                _ => panic!("Expected Eval subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_simulate_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "simulate",
            "default",
            "events.jsonl",
            "--json",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Simulate {
                    policy_ref,
                    events,
                    resolve,
                    json,
                } => {
                    assert_eq!(policy_ref, "default");
                    assert_eq!(events, "events.jsonl");
                    assert!(!resolve);
                    assert!(json);
                }
                _ => panic!("Expected Simulate subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_diff_parses() {
        let cli = Cli::parse_from(["hush", "policy", "diff", "clawdstrike:default", "policy.yaml"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Diff {
                    left,
                    right,
                    resolve,
                    json,
                } => {
                    assert_eq!(left, "clawdstrike:default");
                    assert_eq!(right, "policy.yaml");
                    assert!(!resolve);
                    assert!(!json);
                }
                _ => panic!("Expected Diff subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_diff_parses_with_flags() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "diff",
            "--resolve",
            "--json",
            "left.yaml",
            "clawdstrike:strict",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Diff {
                    left,
                    right,
                    resolve,
                    json,
                } => {
                    assert_eq!(left, "left.yaml");
                    assert_eq!(right, "clawdstrike:strict");
                    assert!(resolve);
                    assert!(json);
                }
                _ => panic!("Expected Diff subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_daemon_start_defaults() {
        let cli = Cli::parse_from(["hush", "daemon", "start"]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Start { config, bind, port } => {
                    assert!(config.is_none());
                    assert_eq!(bind, "127.0.0.1");
                    assert_eq!(port, 9876);
                }
                _ => panic!("Expected Start subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_daemon_start_with_options() {
        let cli = Cli::parse_from([
            "hush",
            "daemon",
            "start",
            "--config",
            "/etc/hush/config.yaml",
            "--bind",
            "0.0.0.0",
            "--port",
            "8080",
        ]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Start { config, bind, port } => {
                    assert_eq!(config, Some("/etc/hush/config.yaml".to_string()));
                    assert_eq!(bind, "0.0.0.0");
                    assert_eq!(port, 8080);
                }
                _ => panic!("Expected Start subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_daemon_status_default_url() {
        let cli = Cli::parse_from(["hush", "daemon", "status"]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Status { url } => {
                    assert_eq!(url, "http://127.0.0.1:9876");
                }
                _ => panic!("Expected Status subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_daemon_reload() {
        let cli = Cli::parse_from(["hush", "daemon", "reload", "http://localhost:9999"]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Reload { url } => {
                    assert_eq!(url, "http://localhost:9999");
                }
                _ => panic!("Expected Reload subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_completions_bash() {
        let cli = Cli::parse_from(["hush", "completions", "bash"]);

        match cli.command {
            Commands::Completions { shell } => {
                assert_eq!(shell, clap_complete::Shell::Bash);
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_completions_zsh() {
        let cli = Cli::parse_from(["hush", "completions", "zsh"]);

        match cli.command {
            Commands::Completions { shell } => {
                assert_eq!(shell, clap_complete::Shell::Zsh);
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_completions_fish() {
        let cli = Cli::parse_from(["hush", "completions", "fish"]);

        match cli.command {
            Commands::Completions { shell } => {
                assert_eq!(shell, clap_complete::Shell::Fish);
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_version_flag() {
        let result = Cli::try_parse_from(["hush", "--version"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn test_help_flag() {
        let result = Cli::try_parse_from(["hush", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_invalid_command_fails() {
        let result = Cli::try_parse_from(["hush", "nonexistent-command"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verbose_flag_counts() {
        let cli = Cli::parse_from(["hush", "-vvv", "policy", "list"]);
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn test_hash_command_default_algorithm() {
        let cli = Cli::parse_from(["hush", "hash", "file.txt"]);

        match cli.command {
            Commands::Hash {
                file,
                algorithm,
                format,
            } => {
                assert_eq!(file, "file.txt");
                assert_eq!(algorithm, "sha256");
                assert_eq!(format, "hex");
            }
            _ => panic!("Expected Hash command"),
        }
    }

    #[test]
    fn test_hash_command_keccak256() {
        let cli = Cli::parse_from(["hush", "hash", "--algorithm", "keccak256", "data.bin"]);

        match cli.command {
            Commands::Hash {
                algorithm, file, ..
            } => {
                assert_eq!(algorithm, "keccak256");
                assert_eq!(file, "data.bin");
            }
            _ => panic!("Expected Hash command"),
        }
    }

    #[test]
    fn test_hash_command_base64_format() {
        let cli = Cli::parse_from(["hush", "hash", "--format", "base64", "file.txt"]);

        match cli.command {
            Commands::Hash { format, .. } => {
                assert_eq!(format, "base64");
            }
            _ => panic!("Expected Hash command"),
        }
    }

    #[test]
    fn test_hash_command_stdin() {
        let cli = Cli::parse_from(["hush", "hash", "-"]);

        match cli.command {
            Commands::Hash { file, .. } => {
                assert_eq!(file, "-");
            }
            _ => panic!("Expected Hash command"),
        }
    }

    #[test]
    fn test_sign_command_basic() {
        let cli = Cli::parse_from(["hush", "sign", "--key", "hush.key", "document.txt"]);

        match cli.command {
            Commands::Sign {
                key,
                file,
                verify,
                output,
            } => {
                assert_eq!(key, "hush.key");
                assert_eq!(file, "document.txt");
                assert!(!verify);
                assert!(output.is_none());
            }
            _ => panic!("Expected Sign command"),
        }
    }

    #[test]
    fn test_sign_command_with_verify() {
        let cli = Cli::parse_from(["hush", "sign", "--key", "my.key", "--verify", "message.txt"]);

        match cli.command {
            Commands::Sign { verify, .. } => {
                assert!(verify);
            }
            _ => panic!("Expected Sign command"),
        }
    }

    #[test]
    fn test_sign_command_with_output() {
        let cli = Cli::parse_from([
            "hush",
            "sign",
            "--key",
            "hush.key",
            "--output",
            "doc.sig",
            "document.txt",
        ]);

        match cli.command {
            Commands::Sign { output, .. } => {
                assert_eq!(output, Some("doc.sig".to_string()));
            }
            _ => panic!("Expected Sign command"),
        }
    }

    #[test]
    fn test_merkle_root_command() {
        let cli = Cli::parse_from([
            "hush",
            "merkle",
            "root",
            "file1.txt",
            "file2.txt",
            "file3.txt",
        ]);

        match cli.command {
            Commands::Merkle { command } => match command {
                MerkleCommands::Root { files } => {
                    assert_eq!(files.len(), 3);
                    assert_eq!(files[0], "file1.txt");
                    assert_eq!(files[1], "file2.txt");
                    assert_eq!(files[2], "file3.txt");
                }
                _ => panic!("Expected Root subcommand"),
            },
            _ => panic!("Expected Merkle command"),
        }
    }

    #[test]
    fn test_merkle_proof_command() {
        let cli = Cli::parse_from([
            "hush",
            "merkle",
            "proof",
            "--index",
            "1",
            "file1.txt",
            "file2.txt",
            "file3.txt",
        ]);

        match cli.command {
            Commands::Merkle { command } => match command {
                MerkleCommands::Proof { index, files } => {
                    assert_eq!(index, 1);
                    assert_eq!(files.len(), 3);
                }
                _ => panic!("Expected Proof subcommand"),
            },
            _ => panic!("Expected Merkle command"),
        }
    }

    #[test]
    fn test_merkle_verify_command() {
        let cli = Cli::parse_from([
            "hush",
            "merkle",
            "verify",
            "--root",
            "abc123",
            "--leaf",
            "file2.txt",
            "--proof",
            "proof.json",
        ]);

        match cli.command {
            Commands::Merkle { command } => match command {
                MerkleCommands::Verify { root, leaf, proof } => {
                    assert_eq!(root, "abc123");
                    assert_eq!(leaf, "file2.txt");
                    assert_eq!(proof, "proof.json");
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Merkle command"),
        }
    }
}

#[cfg(test)]
mod completions {
    use clap::CommandFactory;
    use clap_complete::{generate, Shell};

    use crate::Cli;

    #[test]
    fn test_bash_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Bash, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(script.contains("_hush"), "Should contain bash function");
        assert!(script.contains("check"), "Should contain check subcommand");
        assert!(
            script.contains("completions"),
            "Should contain completions subcommand"
        );
    }

    #[test]
    fn test_zsh_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Zsh, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(
            script.contains("#compdef hush"),
            "Should have zsh compdef header"
        );
        assert!(script.contains("check"), "Should contain check subcommand");
    }

    #[test]
    fn test_fish_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Fish, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(
            script.contains("complete -c hush"),
            "Should have fish complete command"
        );
    }
}

#[cfg(test)]
mod functional_tests {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use hush_core::{keccak256, sha256, Keypair, MerkleProof, MerkleTree};

    #[test]
    fn test_hash_sha256_known_vector() {
        // "hello" -> known SHA-256 hash
        let hash = sha256(b"hello");
        assert_eq!(
            hash.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hash_keccak256_known_vector() {
        // "hello" -> known Keccak-256 hash
        let hash = keccak256(b"hello");
        assert_eq!(
            hash.to_hex(),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_hash_base64_format() {
        let hash = sha256(b"hello");
        let b64 = BASE64.encode(hash.as_bytes());
        // Base64 of the SHA-256 hash bytes
        assert!(!b64.is_empty());
        // Verify roundtrip
        let decoded = BASE64.decode(&b64).expect("valid base64");
        assert_eq!(decoded.as_slice(), hash.as_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate();
        let message = b"test message for signing";

        let signature = keypair.sign(message);
        let public_key = keypair.public_key();

        assert!(public_key.verify(message, &signature));
        assert!(!public_key.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec(), b"leaf3".to_vec()];

        let tree1 = MerkleTree::from_leaves(&leaves).expect("valid tree");
        let tree2 = MerkleTree::from_leaves(&leaves).expect("valid tree");

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_proof_verify() {
        let leaves = vec![b"file1".to_vec(), b"file2".to_vec(), b"file3".to_vec()];
        let tree = MerkleTree::from_leaves(&leaves).expect("valid tree");
        let root = tree.root();

        // Generate proof for leaf at index 1
        let proof = tree.inclusion_proof(1).expect("valid proof");

        // Serialize and deserialize (simulates file I/O)
        let json = serde_json::to_string(&proof).expect("serialize");
        let restored: MerkleProof = serde_json::from_str(&json).expect("deserialize");

        // Verify the proof
        assert!(restored.verify(&leaves[1], &root));

        // Wrong leaf should fail
        assert!(!restored.verify(&leaves[0], &root));
    }
}

#[cfg(test)]
mod cli_contract {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use hush_core::{sha256, Keypair, Receipt, SignedReceipt, Verdict};

    use crate::{cmd_check, cmd_verify, ExitCode};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("hush_cli_{name}_{nanos}"))
    }

    #[tokio::test]
    async fn check_json_allowed_exit_code_ok() {
        let mut out = Vec::new();
        let mut err = Vec::new();

        let code = cmd_check(
            "file".to_string(),
            "/app/src/main.rs".to_string(),
            true,
            None,
            Some("default".to_string()),
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Ok);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("command").and_then(|v| v.as_str()), Some("check"));
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(0));
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("allowed"));
        assert_eq!(
            v.get("result")
                .and_then(|r| r.get("allowed"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn check_json_blocked_exit_code_fail() {
        let mut out = Vec::new();
        let mut err = Vec::new();

        let code = cmd_check(
            "file".to_string(),
            "/home/user/.ssh/id_rsa".to_string(),
            true,
            None,
            Some("default".to_string()),
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Fail);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(2));
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("blocked"));
        assert_eq!(
            v.get("result")
                .and_then(|r| r.get("allowed"))
                .and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[tokio::test]
    async fn check_json_warn_exit_code_warn() {
        let policy_path = temp_path("policy.yaml");
        std::fs::write(
            &policy_path,
            r#"
version: "1.0.0"
name: "warn-policy"
guards:
  egress_allowlist:
    default_action: log
"#,
        )
        .expect("write policy");

        let mut out = Vec::new();
        let mut err = Vec::new();

        let code = cmd_check(
            "egress".to_string(),
            "evil.example:443".to_string(),
            true,
            Some(policy_path.to_string_lossy().to_string()),
            None,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Warn);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(1));
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("warn"));
        assert_eq!(
            v.get("result")
                .and_then(|r| r.get("allowed"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn verify_json_pass_exit_code_ok() {
        let receipt_path = temp_path("receipt.json");
        let pubkey_path = temp_path("pubkey.hex");

        let keypair = Keypair::generate();
        let receipt = Receipt::new(sha256(b"content"), Verdict::pass());
        let signed = SignedReceipt::sign(receipt, &keypair).expect("sign");

        std::fs::write(&receipt_path, signed.to_json().expect("receipt json")).expect("write");
        std::fs::write(&pubkey_path, keypair.public_key().to_hex()).expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();

        let code = cmd_verify(
            receipt_path.to_string_lossy().to_string(),
            pubkey_path.to_string_lossy().to_string(),
            true,
            &mut out,
            &mut err,
        );

        assert_eq!(code, ExitCode::Ok);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("command").and_then(|v| v.as_str()), Some("verify"));
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("pass"));
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(0));
        assert_eq!(
            v.get("signature")
                .and_then(|s| s.get("valid"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            v.get("receipt_summary")
                .and_then(|s| s.get("verdict_passed"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn verify_json_fail_verdict_exit_code_fail() {
        let receipt_path = temp_path("receipt_fail.json");
        let pubkey_path = temp_path("pubkey_fail.hex");

        let keypair = Keypair::generate();
        let receipt = Receipt::new(sha256(b"content"), Verdict::fail());
        let signed = SignedReceipt::sign(receipt, &keypair).expect("sign");

        std::fs::write(&receipt_path, signed.to_json().expect("receipt json")).expect("write");
        std::fs::write(&pubkey_path, keypair.public_key().to_hex()).expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();

        let code = cmd_verify(
            receipt_path.to_string_lossy().to_string(),
            pubkey_path.to_string_lossy().to_string(),
            true,
            &mut out,
            &mut err,
        );

        assert_eq!(code, ExitCode::Fail);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("fail"));
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(2));
        assert_eq!(
            v.get("signature")
                .and_then(|s| s.get("valid"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            v.get("receipt_summary")
                .and_then(|s| s.get("verdict_passed"))
                .and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn verify_json_invalid_signature_exit_code_fail() {
        let receipt_path = temp_path("receipt_invalid.json");
        let pubkey_path = temp_path("pubkey_invalid.hex");

        let keypair = Keypair::generate();
        let receipt = Receipt::new(sha256(b"content"), Verdict::pass());
        let signed = SignedReceipt::sign(receipt, &keypair).expect("sign");

        std::fs::write(&receipt_path, signed.to_json().expect("receipt json")).expect("write");
        std::fs::write(&pubkey_path, Keypair::generate().public_key().to_hex()).expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();

        let code = cmd_verify(
            receipt_path.to_string_lossy().to_string(),
            pubkey_path.to_string_lossy().to_string(),
            true,
            &mut out,
            &mut err,
        );

        assert_eq!(code, ExitCode::Fail);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("invalid"));
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(2));
        assert_eq!(
            v.get("signature")
                .and_then(|s| s.get("valid"))
                .and_then(|v| v.as_bool()),
            Some(false)
        );
    }
}

#[cfg(test)]
mod policy_event_contract {
    use crate::policy_event::{map_policy_event, MappedGuardAction, PolicyEvent};

    #[test]
    fn policy_event_accepts_snake_case_aliases_and_normalizes_to_camel_case() {
        let input = serde_json::json!({
            "event_id": "evt-123",
            "event_type": "patch_apply",
            "timestamp": "2026-02-03T00:00:00Z",
            "session_id": "sess-123",
            "data": {
                "type": "patch",
                "file_path": "src/lib.rs",
                "patch_content": "+ hello",
                "patch_hash": "sha256:deadbeef"
            },
            "metadata": {
                "agent_id": "agent-123",
                "tool_kind": "mcp"
            }
        });

        let event: PolicyEvent = serde_json::from_value(input).expect("parse PolicyEvent");
        let normalized = serde_json::to_value(&event).expect("serialize normalized");

        assert_eq!(normalized.get("eventId").and_then(|v| v.as_str()), Some("evt-123"));
        assert_eq!(
            normalized.get("eventType").and_then(|v| v.as_str()),
            Some("patch_apply")
        );
        assert_eq!(
            normalized.get("sessionId").and_then(|v| v.as_str()),
            Some("sess-123")
        );

        let data = normalized.get("data").expect("data");
        assert_eq!(data.get("type").and_then(|v| v.as_str()), Some("patch"));
        assert_eq!(
            data.get("filePath").and_then(|v| v.as_str()),
            Some("src/lib.rs")
        );
        assert_eq!(
            data.get("patchContent").and_then(|v| v.as_str()),
            Some("+ hello")
        );
        assert_eq!(
            data.get("patchHash").and_then(|v| v.as_str()),
            Some("sha256:deadbeef")
        );
    }

    #[test]
    fn custom_event_requires_data_custom_type() {
        let input = serde_json::json!({
            "eventId": "evt-1",
            "eventType": "custom",
            "timestamp": "2026-02-03T00:00:00Z",
            "data": { "type": "custom" }
        });

        let err = serde_json::from_value::<PolicyEvent>(input).unwrap_err();
        assert!(
            err.to_string().contains("customType"),
            "error should mention customType"
        );
    }

    #[test]
    fn tool_call_maps_to_mcp_tool_when_metadata_declares_mcp() {
        let input = serde_json::json!({
            "eventId": "evt-mcp",
            "eventType": "tool_call",
            "timestamp": "2026-02-03T00:00:00Z",
            "data": {
                "type": "tool",
                "toolName": "read_file",
                "parameters": { "path": "/tmp/x" }
            },
            "metadata": { "toolKind": "mcp" }
        });

        let event: PolicyEvent = serde_json::from_value(input).expect("parse");
        let mapped = map_policy_event(&event).expect("map");
        assert!(matches!(mapped.action, MappedGuardAction::McpTool { .. }));
    }

    #[test]
    fn tool_call_maps_to_mcp_tool_when_tool_name_has_mcp_prefix() {
        let input = serde_json::json!({
            "eventId": "evt-mcp2",
            "eventType": "tool_call",
            "timestamp": "2026-02-03T00:00:00Z",
            "data": {
                "type": "tool",
                "toolName": "mcp__blender__execute_blender_code",
                "parameters": { "code": "print('hi')" }
            }
        });

        let event: PolicyEvent = serde_json::from_value(input).expect("parse");
        let mapped = map_policy_event(&event).expect("map");
        assert!(matches!(mapped.action, MappedGuardAction::McpTool { .. }));
    }

    #[test]
    fn tool_call_maps_to_custom_when_not_mcp() {
        let input = serde_json::json!({
            "eventId": "evt-custom",
            "eventType": "tool_call",
            "timestamp": "2026-02-03T00:00:00Z",
            "data": {
                "type": "tool",
                "toolName": "shell_exec",
                "parameters": { "command": "echo hi" }
            },
            "metadata": { "toolKind": "other" }
        });

        let event: PolicyEvent = serde_json::from_value(input).expect("parse");
        let mapped = map_policy_event(&event).expect("map");
        assert!(matches!(
            mapped.action,
            MappedGuardAction::Custom { ref custom_type, .. } if custom_type == "tool_call"
        ));
    }
}

#[cfg(test)]
mod policy_pac_contract {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::policy_pac::{cmd_policy_eval, cmd_policy_simulate};
    use crate::ExitCode;

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("hush_cli_{name}_{nanos}"))
    }

    #[tokio::test]
    async fn policy_eval_json_includes_decision_schema_fields() {
        let event_path = temp_path("policy_event.json");
        std::fs::write(
            &event_path,
            r#"{"eventId":"evt-allow","eventType":"file_read","timestamp":"2026-02-03T00:00:00Z","data":{"type":"file","path":"/app/src/main.rs","operation":"read"}}"#,
        )
        .expect("write event");

        let mut out = Vec::new();
        let mut err = Vec::new();

        let code = cmd_policy_eval(
            "default".to_string(),
            event_path.to_string_lossy().to_string(),
            false,
            true,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Ok);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(
            v.get("command").and_then(|v| v.as_str()),
            Some("policy_eval")
        );
        let decision = v.get("decision").expect("decision");
        for key in ["allowed", "denied", "warn", "guard", "severity", "message", "reason"] {
            assert!(decision.get(key).is_some(), "missing decision.{key}");
        }
        assert!(v.get("report").is_some(), "missing report");
    }

    #[tokio::test]
    async fn policy_simulate_json_includes_results_and_event_ids_from_fixtures() {
        let mut out = Vec::new();
        let mut err = Vec::new();

        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/policy-events/v1/events.jsonl");

        let code = cmd_policy_simulate(
            "default".to_string(),
            fixtures_path.to_string_lossy().to_string(),
            false,
            true,
            &mut out,
            &mut err,
        )
        .await;

        assert!(
            matches!(code, ExitCode::Ok | ExitCode::Warn | ExitCode::Fail),
            "unexpected exit code"
        );
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(
            v.get("command").and_then(|v| v.as_str()),
            Some("policy_simulate")
        );

        let results = v
            .get("results")
            .and_then(|v| v.as_array())
            .expect("results array");
        assert_eq!(results.len(), 6, "expected one result per fixture line");

        let ids: std::collections::BTreeSet<String> = results
            .iter()
            .filter_map(|r| r.get("eventId").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();

        for id in [
            "evt-0001",
            "evt-0002",
            "evt-0003",
            "evt-0004",
            "evt-0005",
            "evt-0006",
        ] {
            assert!(ids.contains(id), "missing eventId {id}");
        }

        let first = &results[0];
        let decision = first.get("decision").expect("decision");
        for key in ["allowed", "denied", "warn", "guard", "severity", "message", "reason"] {
            assert!(decision.get(key).is_some(), "missing decision.{key}");
        }
        assert!(first.get("report").is_some(), "missing report");
    }
}
