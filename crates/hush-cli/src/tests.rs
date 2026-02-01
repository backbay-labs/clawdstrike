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
        let cli = Cli::parse_from([
            "hush",
            "check",
            "--action-type",
            "file",
            "/path/to/file",
        ]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                ruleset,
            } => {
                assert_eq!(action_type, "file");
                assert_eq!(target, "/path/to/file");
                assert_eq!(ruleset, "default"); // default value
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
                ruleset,
            } => {
                assert_eq!(action_type, "egress");
                assert_eq!(target, "api.example.com:443");
                assert_eq!(ruleset, "strict");
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_check_command_mcp_action_type() {
        let cli = Cli::parse_from([
            "hush",
            "check",
            "-a",
            "mcp",
            "filesystem_read",
        ]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                ..
            } => {
                assert_eq!(action_type, "mcp");
                assert_eq!(target, "filesystem_read");
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_verify_command_parses() {
        let cli = Cli::parse_from([
            "hush",
            "verify",
            "receipt.json",
            "--pubkey",
            "key.pub",
        ]);

        match cli.command {
            Commands::Verify { receipt, pubkey } => {
                assert_eq!(receipt, "receipt.json");
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
        let cli = Cli::parse_from([
            "hush",
            "keygen",
            "--output",
            "/custom/path/my.key",
        ]);

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
        let cli = Cli::parse_from([
            "hush",
            "daemon",
            "reload",
            "http://localhost:9999",
        ]);

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
        let cli = Cli::parse_from([
            "hush", "sign", "--key", "my.key", "--verify", "message.txt",
        ]);

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
            "hush", "sign", "--key", "hush.key", "--output", "doc.sig", "document.txt",
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
            "hush", "merkle", "root", "file1.txt", "file2.txt", "file3.txt",
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
            "hush", "merkle", "proof", "--index", "1", "file1.txt", "file2.txt", "file3.txt",
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
        assert!(script.contains("completions"), "Should contain completions subcommand");
    }

    #[test]
    fn test_zsh_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Zsh, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(script.contains("#compdef hush"), "Should have zsh compdef header");
        assert!(script.contains("check"), "Should contain check subcommand");
    }

    #[test]
    fn test_fish_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Fish, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(script.contains("complete -c hush"), "Should have fish complete command");
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
