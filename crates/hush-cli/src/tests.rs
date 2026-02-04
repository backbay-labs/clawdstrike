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
            Commands::Keygen { output, tpm_seal } => {
                assert_eq!(output, "hush.key"); // default
                assert!(!tpm_seal);
            }
            _ => panic!("Expected Keygen command"),
        }
    }

    #[test]
    fn test_keygen_command_custom_output() {
        let cli = Cli::parse_from(["hush", "keygen", "--output", "/custom/path/my.key"]);

        match cli.command {
            Commands::Keygen { output, tpm_seal } => {
                assert_eq!(output, "/custom/path/my.key");
                assert!(!tpm_seal);
            }
            _ => panic!("Expected Keygen command"),
        }
    }

    #[test]
    fn test_keygen_command_tpm_seal_parses() {
        let cli = Cli::parse_from(["hush", "keygen", "--tpm-seal", "--out", "hush.keyblob"]);

        match cli.command {
            Commands::Keygen { output, tpm_seal } => {
                assert_eq!(output, "hush.keyblob");
                assert!(tpm_seal);
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
                    jsonl,
                    summary,
                    fail_on_deny,
                    no_fail_on_deny,
                    benchmark,
                } => {
                    assert_eq!(policy_ref, "default");
                    assert_eq!(events, Some("events.jsonl".to_string()));
                    assert!(!resolve);
                    assert!(json);
                    assert!(!jsonl);
                    assert!(!summary);
                    assert!(!fail_on_deny);
                    assert!(!no_fail_on_deny);
                    assert!(!benchmark);
                }
                _ => panic!("Expected Simulate subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_diff_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "diff",
            "clawdstrike:default",
            "policy.yaml",
        ]);

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
                DaemonCommands::Reload { url, token } => {
                    assert_eq!(url, "http://localhost:9999");
                    assert!(token.is_none());
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

    #[test]
    fn test_policy_lint_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "lint",
            "--resolve",
            "--strict",
            "--json",
            "default",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Lint {
                    policy_ref,
                    resolve,
                    strict,
                    json,
                } => {
                    assert_eq!(policy_ref, "default");
                    assert!(resolve);
                    assert!(strict);
                    assert!(json);
                }
                _ => panic!("Expected Lint subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_test_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "test",
            "--resolve",
            "--json",
            "--coverage",
            "tests/policy.test.yaml",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Test {
                    test_file,
                    resolve,
                    json,
                    coverage,
                } => {
                    assert_eq!(test_file, "tests/policy.test.yaml");
                    assert!(resolve);
                    assert!(json);
                    assert!(coverage);
                }
                _ => panic!("Expected Test subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_impact_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "impact",
            "default",
            "strict",
            "events.jsonl",
            "--resolve",
            "--json",
            "--fail-on-breaking",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Impact {
                    old_policy,
                    new_policy,
                    events,
                    resolve,
                    json,
                    fail_on_breaking,
                } => {
                    assert_eq!(old_policy, "default");
                    assert_eq!(new_policy, "strict");
                    assert_eq!(events, "events.jsonl");
                    assert!(resolve);
                    assert!(json);
                    assert!(fail_on_breaking);
                }
                _ => panic!("Expected Impact subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_version_parses() {
        let cli = Cli::parse_from(["hush", "policy", "version", "--json", "default"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Version {
                    policy_ref,
                    resolve,
                    json,
                } => {
                    assert_eq!(policy_ref, "default");
                    assert!(!resolve);
                    assert!(json);
                }
                _ => panic!("Expected Version subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_simulate_jsonl_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "simulate",
            "default",
            "events.jsonl",
            "--jsonl",
            "--no-fail-on-deny",
            "--benchmark",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Simulate {
                    policy_ref,
                    events,
                    json,
                    jsonl,
                    summary,
                    fail_on_deny,
                    no_fail_on_deny,
                    benchmark,
                    ..
                } => {
                    assert_eq!(policy_ref, "default");
                    assert_eq!(events, Some("events.jsonl".to_string()));
                    assert!(!json);
                    assert!(jsonl);
                    assert!(!summary);
                    assert!(!fail_on_deny);
                    assert!(no_fail_on_deny);
                    assert!(benchmark);
                }
                _ => panic!("Expected Simulate subcommand"),
            },
            _ => panic!("Expected Policy command"),
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

    use crate::remote_extends::RemoteExtendsConfig;
    use crate::{cmd_check, cmd_verify, CheckArgs, ExitCode};

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
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_check(
            CheckArgs {
                action_type: "file".to_string(),
                target: "/app/src/main.rs".to_string(),
                json: true,
                policy: None,
                ruleset: Some("default".to_string()),
            },
            &remote,
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
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_check(
            CheckArgs {
                action_type: "file".to_string(),
                target: "/home/user/.ssh/id_rsa".to_string(),
                json: true,
                policy: None,
                ruleset: Some("default".to_string()),
            },
            &remote,
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
version: "1.1.0"
name: "warn-policy"
guards:
  egress_allowlist:
    default_action: log
"#,
        )
        .expect("write policy");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_check(
            CheckArgs {
                action_type: "egress".to_string(),
                target: "evil.example:443".to_string(),
                json: true,
                policy: Some(policy_path.to_string_lossy().to_string()),
                ruleset: None,
            },
            &remote,
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

        assert_eq!(
            normalized.get("eventId").and_then(|v| v.as_str()),
            Some("evt-123")
        );
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
    fn policy_event_rejects_invalid_rfc3339_timestamp() {
        let input = serde_json::json!({
            "eventId": "evt-1",
            "eventType": "file_read",
            "timestamp": "not-a-timestamp",
            "data": { "type": "file", "path": "/tmp/x", "operation": "read" }
        });

        assert!(serde_json::from_value::<PolicyEvent>(input).is_err());
    }

    #[test]
    fn policy_event_accepts_unknown_event_type_but_mapping_fails_closed() {
        let input = serde_json::json!({
            "eventId": "evt-future",
            "eventType": "future_event",
            "timestamp": "2026-02-03T00:00:00Z",
            "data": { "type": "file", "path": "/tmp/x", "operation": "read" }
        });

        let event: PolicyEvent = serde_json::from_value(input).expect("parse");
        let err = map_policy_event(&event).unwrap_err();
        assert!(
            err.to_string().contains("unsupported eventType"),
            "mapping should fail with unsupported eventType"
        );
    }

    #[test]
    fn command_exec_mapping_uses_posix_quoting_for_args() {
        let input = serde_json::json!({
            "eventId": "evt-cmd",
            "eventType": "command_exec",
            "timestamp": "2026-02-03T00:00:00Z",
            "data": {
                "type": "command",
                "command": "echo",
                "args": ["hello world", "O'Reilly"]
            }
        });

        let event: PolicyEvent = serde_json::from_value(input).expect("parse");
        let mapped = map_policy_event(&event).expect("map");
        match mapped.action {
            MappedGuardAction::ShellCommand { commandline } => {
                assert_eq!(commandline, "echo 'hello world' 'O'\"'\"'Reilly'");
            }
            other => panic!("expected ShellCommand, got {:?}", other),
        }
    }

    #[test]
    fn context_is_forwarded_into_guard_context_metadata_but_not_emitted_in_normalized_event() {
        let input = serde_json::json!({
            "eventId": "evt-ctx",
            "eventType": "file_read",
            "timestamp": "2026-02-03T00:00:00Z",
            "data": { "type": "file", "path": "/tmp/x", "operation": "read" },
            "metadata": { "agentId": "agent-1", "source": "cli" },
            "context": { "user": { "id": "u1" } }
        });

        let event: PolicyEvent = serde_json::from_value(input).expect("parse");
        let normalized = serde_json::to_value(&event).expect("serialize normalized");
        assert!(
            normalized.get("context").is_none(),
            "normalized event should not include context"
        );

        let ctx = event.to_guard_context();
        let meta = ctx.metadata.expect("metadata present");
        assert_eq!(
            meta.get("agentId").and_then(|v| v.as_str()),
            Some("agent-1")
        );
        assert!(
            meta.get("context").is_some(),
            "metadata should include context"
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
    use crate::remote_extends::RemoteExtendsConfig;
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
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_policy_eval(
            "default".to_string(),
            event_path.to_string_lossy().to_string(),
            false,
            &remote,
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
        for key in [
            "allowed", "denied", "warn", "guard", "severity", "message", "reason",
        ] {
            assert!(decision.get(key).is_some(), "missing decision.{key}");
        }
        let report = v.get("report").expect("missing report");
        let report_obj = report.as_object().expect("report must be object");
        let report_keys: std::collections::BTreeSet<&str> =
            report_obj.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            report_keys,
            std::collections::BTreeSet::from(["overall", "per_guard"]),
            "report keys must be stable"
        );

        let overall = report.get("overall").expect("report.overall");
        let overall_obj = overall.as_object().expect("report.overall must be object");
        let allowed_overall_keys: std::collections::BTreeSet<&str> =
            std::collections::BTreeSet::from([
                "allowed", "guard", "severity", "message", "details",
            ]);
        for k in overall_obj.keys() {
            assert!(
                allowed_overall_keys.contains(k.as_str()),
                "unexpected report.overall field {k}"
            );
        }
        for required in ["allowed", "guard", "severity", "message"] {
            assert!(
                overall.get(required).is_some(),
                "missing report.overall.{required}"
            );
        }

        let per_guard = report.get("per_guard").expect("report.per_guard");
        assert!(per_guard.is_array(), "report.per_guard must be array");
    }

    #[tokio::test]
    async fn policy_simulate_json_includes_results_and_event_ids_from_fixtures() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/policy-events/v1/events.jsonl");

        let code = cmd_policy_simulate(
            "default".to_string(),
            Some(fixtures_path.to_string_lossy().to_string()),
            crate::policy_pac::PolicySimulateOptions {
                resolve: false,
                remote_extends: &remote,
                json: true,
                jsonl: false,
                summary: false,
                fail_on_deny: true,
                benchmark: false,
            },
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
            .filter_map(|r| {
                r.get("eventId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();

        for id in [
            "evt-0001", "evt-0002", "evt-0003", "evt-0004", "evt-0005", "evt-0006",
        ] {
            assert!(ids.contains(id), "missing eventId {id}");
        }

        let first = &results[0];
        let decision = first.get("decision").expect("decision");
        for key in [
            "allowed", "denied", "warn", "guard", "severity", "message", "reason",
        ] {
            assert!(decision.get(key).is_some(), "missing decision.{key}");
        }
        assert!(first.get("report").is_some(), "missing report");
    }

    #[tokio::test]
    async fn policy_simulate_jsonl_streams_one_json_object_per_event() {
        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/policy-events/v1/events.jsonl");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_policy_simulate(
            "default".to_string(),
            Some(fixtures_path.to_string_lossy().to_string()),
            crate::policy_pac::PolicySimulateOptions {
                resolve: false,
                remote_extends: &remote,
                json: false,
                jsonl: true,
                summary: false,
                fail_on_deny: true,
                benchmark: false,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Fail, "fixtures include a blocked event");

        let stdout = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 6, "expected one JSON line per event");

        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
            assert!(v.get("eventId").is_some());
            assert!(v.get("decision").is_some());
            assert!(v.get("report").is_some());
        }
    }

    #[tokio::test]
    async fn policy_simulate_json_summary_only_omits_results_but_preserves_counts() {
        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/policy-events/v1/events.jsonl");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_policy_simulate(
            "default".to_string(),
            Some(fixtures_path.to_string_lossy().to_string()),
            crate::policy_pac::PolicySimulateOptions {
                resolve: false,
                remote_extends: &remote,
                json: true,
                jsonl: false,
                summary: true,
                fail_on_deny: true,
                benchmark: false,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Fail);

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(
            v.get("summary")
                .and_then(|v| v.get("total"))
                .and_then(|v| v.as_i64()),
            Some(6)
        );
        assert_eq!(
            v.get("results").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(0)
        );
    }

    #[tokio::test]
    async fn policy_simulate_no_fail_on_deny_exit_code_ok() {
        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/policy-events/v1/events.jsonl");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_policy_simulate(
            "default".to_string(),
            Some(fixtures_path.to_string_lossy().to_string()),
            crate::policy_pac::PolicySimulateOptions {
                resolve: false,
                remote_extends: &remote,
                json: true,
                jsonl: false,
                summary: true,
                fail_on_deny: false,
                benchmark: false,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Ok);
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(0));
        assert_eq!(
            v.get("summary")
                .and_then(|v| v.get("blocked"))
                .and_then(|v| v.as_i64()),
            Some(2)
        );
    }

    #[tokio::test]
    async fn policy_simulate_matches_expected_decisions_fixture_default_ruleset() {
        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/policy-events/v1/events.jsonl");
        let expected_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/policy-events/v1/expected/default.decisions.json");

        let expected_raw =
            std::fs::read_to_string(&expected_path).expect("read default.decisions.json");
        let expected_json: serde_json::Value =
            serde_json::from_str(&expected_raw).expect("expected decisions json");
        let expected_results = expected_json
            .get("results")
            .and_then(|v| v.as_array())
            .expect("expected.results array");
        let expected_by_id: std::collections::BTreeMap<String, serde_json::Value> =
            expected_results
                .iter()
                .filter_map(|r| {
                    let id = r.get("eventId")?.as_str()?.to_string();
                    let decision = r.get("decision")?.clone();
                    Some((id, decision))
                })
                .collect();

        assert_eq!(expected_by_id.len(), 6, "expected one decision per fixture");

        let mut out = Vec::new();
        let mut err = Vec::new();

        let remote_extends = crate::remote_extends::RemoteExtendsConfig::disabled();

        let code = cmd_policy_simulate(
            "default".to_string(),
            Some(fixtures_path.to_string_lossy().to_string()),
            crate::policy_pac::PolicySimulateOptions {
                resolve: false,
                remote_extends: &remote_extends,
                json: true,
                jsonl: false,
                summary: false,
                fail_on_deny: false,
                benchmark: false,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Ok);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        let results = v
            .get("results")
            .and_then(|v| v.as_array())
            .expect("results array");
        assert_eq!(results.len(), 6, "expected one result per fixture line");

        for r in results {
            let id = r
                .get("eventId")
                .and_then(|v| v.as_str())
                .expect("result.eventId")
                .to_string();
            let decision = r.get("decision").expect("result.decision");

            let expected = expected_by_id
                .get(&id)
                .unwrap_or_else(|| panic!("missing expected decision for {}", id));
            assert_eq!(decision, expected, "decision mismatch for {}", id);
        }
    }
}

#[cfg(test)]
mod policy_test_runner_contract {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::policy_test::cmd_policy_test;
    use crate::remote_extends::RemoteExtendsConfig;
    use crate::ExitCode;

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("hush_cli_{name}_{nanos}"))
    }

    #[tokio::test]
    async fn policy_test_runner_executes_basic_suite() {
        let test_path = temp_path("policy_test.yaml");
        std::fs::write(
            &test_path,
            r#"
name: "Basic Policy Tests"
policy: "clawdstrike:default"
suites:
  - name: "Forbidden Path Guard"
    tests:
      - name: "blocks ssh key reads"
        input:
          eventType: file_read
          data:
            type: file
            path: /home/user/.ssh/id_rsa
            operation: read
        expect:
          denied: true
          guard: forbidden_path
          severity: critical
      - name: "allows normal reads"
        input:
          eventType: file_read
          data:
            type: file
            path: /app/src/main.rs
            operation: read
        expect:
          allowed: true
"#,
        )
        .expect("write test file");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_policy_test(
            test_path.to_string_lossy().to_string(),
            false,
            &remote,
            true,
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
            Some("policy_test")
        );
        assert_eq!(v.get("failed").and_then(|v| v.as_i64()), Some(0));
        assert_eq!(v.get("passed").and_then(|v| v.as_i64()), Some(2));
        assert!(
            v.get("coverage").is_some(),
            "expected coverage when enabled"
        );
    }
}

#[cfg(test)]
mod remote_extends_contract {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use clawdstrike::Policy;
    use hush_core::sha256;

    use crate::remote_extends::{RemoteExtendsConfig, RemotePolicyResolver};

    struct TestHttpServer {
        base_url: String,
        shutdown: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpServer {
        fn spawn(routes: HashMap<String, Vec<u8>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            let base_url = format!("http://{}", addr);

            listener.set_nonblocking(true).expect("set_nonblocking");

            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown2 = shutdown.clone();

            let handle = std::thread::spawn(move || {
                while !shutdown2.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = handle_connection(&mut stream, &routes);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                base_url,
                shutdown,
                handle: Some(handle),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}/{}", self.base_url, path.trim_start_matches('/'))
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            // Best-effort wake accept loop.
            let _ = TcpStream::connect_timeout(
                &self.base_url["http://".len()..]
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
                Duration::from_millis(50),
            );
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn handle_connection(
        stream: &mut TcpStream,
        routes: &HashMap<String, Vec<u8>>,
    ) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_millis(200)))?;
        stream.set_write_timeout(Some(Duration::from_millis(200)))?;

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf)?;
        let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
        let mut lines = req.lines();
        let first = lines.next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        if method != "GET" {
            stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }

        let body = routes.get(path).cloned().unwrap_or_default();
        if body.is_empty() {
            stream.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }

        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        Ok(())
    }

    fn resolver_for_localhost() -> RemotePolicyResolver {
        let cfg = RemoteExtendsConfig::new(["127.0.0.1".to_string()]);
        RemotePolicyResolver::new(cfg).expect("resolver")
    }

    #[test]
    fn remote_extends_requires_sha256_pin() {
        let base = br#"
version: "1.1.0"
name: base
settings:
  fail_fast: true
"#
        .to_vec();

        let mut routes = HashMap::new();
        routes.insert("/base.yaml".to_string(), base);
        let server = TestHttpServer::spawn(routes);

        let child = format!(
            r#"
version: "1.1.0"
name: child
extends: {}
"#,
            server.url("/base.yaml")
        );

        let resolver = resolver_for_localhost();
        let err = Policy::from_yaml_with_extends_resolver(&child, None, &resolver)
            .expect_err("missing pin should fail");
        let msg = err.to_string();
        assert!(msg.contains("sha256"), "unexpected error: {msg}");
    }

    #[test]
    fn remote_extends_wrong_sha_fails_closed() {
        let base = br#"
version: "1.1.0"
name: base
settings:
  fail_fast: true
"#
        .to_vec();

        let base_sha = sha256(&base).to_hex();
        let mut wrong = base_sha.clone();
        wrong.replace_range(0..1, if &wrong[0..1] == "a" { "b" } else { "a" });

        let mut routes = HashMap::new();
        routes.insert("/base.yaml".to_string(), base);
        let server = TestHttpServer::spawn(routes);

        let child = format!(
            r#"
version: "1.1.0"
name: child
extends: {}#sha256={}
"#,
            server.url("/base.yaml"),
            wrong
        );

        let resolver = resolver_for_localhost();
        let err = Policy::from_yaml_with_extends_resolver(&child, None, &resolver)
            .expect_err("wrong sha should fail");
        let msg = err.to_string();
        assert!(msg.contains("mismatch"), "unexpected error: {msg}");
    }

    #[test]
    fn remote_extends_requires_allowlisted_host() {
        let base = br#"
version: "1.1.0"
name: base
settings:
  fail_fast: true
"#
        .to_vec();
        let base_sha = sha256(&base).to_hex();

        let mut routes = HashMap::new();
        routes.insert("/base.yaml".to_string(), base);
        let server = TestHttpServer::spawn(routes);

        let child = format!(
            r#"
version: "1.1.0"
name: child
extends: {}#sha256={}
"#,
            server.url("/base.yaml"),
            base_sha
        );

        let cfg = RemoteExtendsConfig::disabled();
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let err = Policy::from_yaml_with_extends_resolver(&child, None, &resolver)
            .expect_err("disallowed host should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("allowlisted") || msg.contains("disabled"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn remote_extends_resolves_relative_urls() {
        let nested = br#"
version: "1.1.0"
name: nested
settings:
  fail_fast: true
"#
        .to_vec();
        let nested_sha = sha256(&nested).to_hex();

        let base = format!(
            r#"
version: "1.1.0"
name: base
extends: nested.yaml#sha256={}
settings:
  verbose_logging: true
"#,
            nested_sha
        )
        .into_bytes();
        let base_sha = sha256(&base).to_hex();

        let mut routes = HashMap::new();
        routes.insert("/policies/base.yaml".to_string(), base);
        routes.insert("/policies/nested.yaml".to_string(), nested);
        let server = TestHttpServer::spawn(routes);

        let top = format!(
            r#"
version: "1.1.0"
name: top
extends: {}#sha256={}
settings:
  session_timeout_secs: 120
"#,
            server.url("/policies/base.yaml"),
            base_sha
        );

        let resolver = resolver_for_localhost();
        let policy = Policy::from_yaml_with_extends_resolver(&top, None, &resolver)
            .expect("remote chain should resolve");
        assert!(
            policy.settings.effective_fail_fast(),
            "nested setting preserved"
        );
        assert!(
            policy.settings.effective_verbose_logging(),
            "base setting preserved"
        );
        assert_eq!(policy.settings.effective_session_timeout_secs(), 120);
    }
}

#[cfg(test)]
mod canonical_commandline_contract {
    use crate::canonical_commandline::{canonical_shell_commandline, canonical_shell_word};

    #[test]
    fn canonical_shell_word_leaves_safe_set_unquoted() {
        assert_eq!(
            canonical_shell_word("abcXYZ0123_@%+=:,./-"),
            "abcXYZ0123_@%+=:,./-"
        );
    }

    #[test]
    fn canonical_shell_word_quotes_spaces() {
        assert_eq!(canonical_shell_word("hello world"), "'hello world'");
    }

    #[test]
    fn canonical_shell_word_escapes_single_quotes() {
        assert_eq!(canonical_shell_word("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn canonical_shell_commandline_joins_tokens() {
        let args = vec!["hi".to_string(), "there world".to_string()];
        assert_eq!(
            canonical_shell_commandline("echo", &args),
            "echo hi 'there world'"
        );
    }
}
