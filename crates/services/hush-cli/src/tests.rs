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

    use crate::{
        Cli, Commands, DaemonCommands, GuardCommands, MerkleCommands, PolicyBundleCommands,
        PolicyCommands, PolicyTestCommands, RegoCommands,
    };

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
                assert_eq!(output, "clawdstrike.key"); // default
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
                PolicyCommands::Validate {
                    file,
                    resolve,
                    check_env,
                } => {
                    assert_eq!(file, "policy.yaml");
                    assert!(!resolve);
                    assert!(!check_env);
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
                PolicyCommands::Validate {
                    file,
                    resolve,
                    check_env,
                } => {
                    assert_eq!(file, "policy.yaml");
                    assert!(resolve);
                    assert!(!check_env);
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
                    track_posture,
                    ocsf_out,
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
                    assert!(!track_posture);
                    assert!(ocsf_out.is_none());
                }
                _ => panic!("Expected Simulate subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_simulate_track_posture_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "simulate",
            "default",
            "events.jsonl",
            "--track-posture",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Simulate { track_posture, .. } => {
                    assert!(track_posture);
                }
                _ => panic!("Expected Simulate subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_observe_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "observe",
            "--policy",
            "clawdstrike:permissive",
            "--out",
            "events.jsonl",
            "--",
            "echo",
            "hello",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Observe {
                    policy,
                    out,
                    hushd_url,
                    session,
                    command,
                    ..
                } => {
                    assert_eq!(policy, "clawdstrike:permissive");
                    assert_eq!(out, "events.jsonl");
                    assert!(hushd_url.is_none());
                    assert!(session.is_none());
                    assert_eq!(command, vec!["echo".to_string(), "hello".to_string()]);
                }
                _ => panic!("Expected Observe subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_synth_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "synth",
            "events.jsonl",
            "--extends",
            "default",
            "--out",
            "candidate.yaml",
            "--diff-out",
            "candidate.diff.json",
            "--risk-out",
            "candidate.risks.md",
            "--with-posture",
            "--json",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Synth {
                    events,
                    extends,
                    out,
                    diff_out,
                    risk_out,
                    with_posture,
                    json,
                } => {
                    assert_eq!(events, "events.jsonl");
                    assert_eq!(extends, Some("default".to_string()));
                    assert_eq!(out, "candidate.yaml");
                    assert_eq!(diff_out, Some("candidate.diff.json".to_string()));
                    assert_eq!(risk_out, "candidate.risks.md");
                    assert!(with_posture);
                    assert!(json);
                }
                _ => panic!("Expected Synth subcommand"),
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
                    sarif,
                } => {
                    assert_eq!(policy_ref, "default");
                    assert!(resolve);
                    assert!(strict);
                    assert!(json);
                    assert!(!sarif);
                }
                _ => panic!("Expected Lint subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_lint_sarif_parses() {
        let cli = Cli::parse_from(["hush", "policy", "lint", "--sarif", "default"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Lint {
                    policy_ref,
                    resolve,
                    strict,
                    json,
                    sarif,
                } => {
                    assert_eq!(policy_ref, "default");
                    assert!(!resolve);
                    assert!(!strict);
                    assert!(!json);
                    assert!(sarif);
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
                    command,
                    test_file,
                    resolve,
                    json,
                    coverage,
                    by_guard,
                    min_coverage,
                    format,
                    output,
                    snapshots,
                    update_snapshots,
                    mutation,
                } => {
                    assert!(command.is_none());
                    assert_eq!(test_file.as_deref(), Some("tests/policy.test.yaml"));
                    assert!(resolve);
                    assert!(json);
                    assert!(coverage);
                    assert!(!by_guard);
                    assert!(min_coverage.is_none());
                    assert_eq!(format, crate::PolicyTestOutputFormat::Text);
                    assert!(output.is_none());
                    assert!(!snapshots);
                    assert!(!update_snapshots);
                    assert!(!mutation);
                }
                _ => panic!("Expected Test subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_test_generate_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "test",
            "generate",
            "default",
            "--events",
            "fixtures/policy-events/v1/events.jsonl",
            "--output",
            "generated.policy-test.yaml",
            "--json",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Test {
                    command, test_file, ..
                } => {
                    assert!(test_file.is_none());
                    match command {
                        Some(PolicyTestCommands::Generate {
                            policy_ref,
                            events,
                            output,
                            json,
                        }) => {
                            assert_eq!(policy_ref, "default");
                            assert_eq!(
                                events.as_deref(),
                                Some("fixtures/policy-events/v1/events.jsonl")
                            );
                            assert_eq!(output.as_deref(), Some("generated.policy-test.yaml"));
                            assert!(json);
                        }
                        _ => panic!("Expected policy test generate subcommand"),
                    }
                }
                _ => panic!("Expected Test subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_guard_inspect_parses() {
        let cli = Cli::parse_from(["hush", "guard", "inspect", "--json", "./plugin"]);

        match cli.command {
            Commands::Guard { command } => match command {
                GuardCommands::Inspect { plugin_ref, json } => {
                    assert_eq!(plugin_ref, "./plugin");
                    assert!(json);
                }
                _ => panic!("Expected guard inspect subcommand"),
            },
            _ => panic!("Expected Guard command"),
        }
    }

    #[test]
    fn test_guard_validate_parses() {
        let cli = Cli::parse_from(["hush", "guard", "validate", "--strict", "./plugin"]);

        match cli.command {
            Commands::Guard { command } => match command {
                GuardCommands::Validate {
                    plugin_ref,
                    strict,
                    json,
                } => {
                    assert_eq!(plugin_ref, "./plugin");
                    assert!(strict);
                    assert!(!json);
                }
                _ => panic!("Expected guard validate subcommand"),
            },
            _ => panic!("Expected Guard command"),
        }
    }

    #[test]
    fn test_policy_rego_compile_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "rego",
            "compile",
            "policy.rego",
            "--entrypoint",
            "data.example.allow",
            "--json",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Rego { command } => match command {
                    RegoCommands::Compile {
                        file,
                        entrypoint,
                        json,
                    } => {
                        assert_eq!(file, "policy.rego");
                        assert_eq!(entrypoint, Some("data.example.allow".to_string()));
                        assert!(json);
                    }
                    _ => panic!("Expected Rego compile"),
                },
                _ => panic!("Expected policy rego command"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_rego_eval_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "rego",
            "eval",
            "policy.rego",
            "-",
            "--entrypoint",
            "data.example.allow",
            "--trace",
            "--json",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Rego { command } => match command {
                    RegoCommands::Eval {
                        file,
                        input,
                        entrypoint,
                        trace,
                        json,
                    } => {
                        assert_eq!(file, "policy.rego");
                        assert_eq!(input, "-");
                        assert_eq!(entrypoint, Some("data.example.allow".to_string()));
                        assert!(trace);
                        assert!(json);
                    }
                    _ => panic!("Expected Rego eval"),
                },
                _ => panic!("Expected policy rego command"),
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
    fn test_policy_migrate_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "migrate",
            "policy.yaml",
            "--to",
            "1.1.0",
            "--from",
            "1.0.0",
            "--output",
            "policy.migrated.yaml",
            "--json",
            "--dry-run",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Migrate {
                    input,
                    to,
                    from,
                    legacy_openclaw,
                    output,
                    in_place,
                    json,
                    dry_run,
                } => {
                    assert_eq!(input, "policy.yaml");
                    assert_eq!(to, "1.1.0");
                    assert_eq!(from, Some("1.0.0".to_string()));
                    assert!(!legacy_openclaw);
                    assert_eq!(output, Some("policy.migrated.yaml".to_string()));
                    assert!(!in_place);
                    assert!(json);
                    assert!(dry_run);
                }
                _ => panic!("Expected Migrate subcommand"),
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

    #[test]
    fn test_policy_bundle_build_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "bundle",
            "build",
            "ai-agent",
            "--resolve",
            "--key",
            "bundle.key",
            "--embed-pubkey",
            "--output",
            "policy.bundle.json",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Bundle { command } => match command {
                    PolicyBundleCommands::Build {
                        policy_ref,
                        resolve,
                        key,
                        output,
                        embed_pubkey,
                        json,
                        ..
                    } => {
                        assert_eq!(policy_ref, "ai-agent");
                        assert!(resolve);
                        assert_eq!(key, "bundle.key");
                        assert_eq!(output, "policy.bundle.json");
                        assert!(embed_pubkey);
                        assert!(!json);
                    }
                    _ => panic!("Expected Bundle Build subcommand"),
                },
                _ => panic!("Expected Bundle subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_bundle_verify_parses() {
        let cli = Cli::parse_from([
            "hush",
            "policy",
            "bundle",
            "verify",
            "./policy.bundle.json",
            "--pubkey",
            "./bundle.key.pub",
        ]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Bundle { command } => match command {
                    PolicyBundleCommands::Verify {
                        bundle,
                        pubkey,
                        json,
                    } => {
                        assert_eq!(bundle, "./policy.bundle.json");
                        assert_eq!(pubkey, Some("./bundle.key.pub".to_string()));
                        assert!(!json);
                    }
                    _ => panic!("Expected Bundle Verify subcommand"),
                },
                _ => panic!("Expected Bundle subcommand"),
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
        assert_eq!(
            v.get("signature")
                .and_then(|s| s.get("error_codes"))
                .and_then(|codes| codes.as_array())
                .and_then(|codes| codes.first())
                .and_then(|code| code.as_str()),
            Some("VFY_SIGNATURE_INVALID")
        );
    }

    #[test]
    fn verify_json_invalid_receipt_json_emits_vfy_parse_invalid_json() {
        let receipt_path = temp_path("receipt_parse_invalid.json");
        let pubkey_path = temp_path("pubkey_parse_invalid.hex");

        std::fs::write(&receipt_path, "not-json").expect("write");
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

        assert_eq!(code, ExitCode::ConfigError);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("error"));
        assert_eq!(
            v.get("error")
                .and_then(|e| e.get("error_code"))
                .and_then(|c| c.as_str()),
            Some("VFY_PARSE_INVALID_JSON")
        );
    }

    #[test]
    fn verify_json_invalid_signed_receipt_shape_emits_vfy_shape_invalid() {
        let receipt_path = temp_path("receipt_shape_invalid.json");
        let pubkey_path = temp_path("pubkey_shape_invalid.hex");

        std::fs::write(&receipt_path, r#"{"hello":"world"}"#).expect("write");
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

        assert_eq!(code, ExitCode::ConfigError);
        assert!(err.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("outcome").and_then(|v| v.as_str()), Some("error"));
        assert_eq!(
            v.get("error")
                .and_then(|e| e.get("error_code"))
                .and_then(|c| c.as_str()),
            Some("VFY_SIGNED_RECEIPT_SHAPE_INVALID")
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
    use std::collections::BTreeSet;
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

    fn fixture_events_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/policy-events/v1/events.jsonl")
    }

    fn fixture_event_ids(path: &PathBuf) -> BTreeSet<String> {
        std::fs::read_to_string(path)
            .expect("read fixture events")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let v: serde_json::Value =
                    serde_json::from_str(line).expect("valid fixture event JSON");
                v.get("eventId")
                    .and_then(|x| x.as_str())
                    .expect("fixture eventId")
                    .to_string()
            })
            .collect()
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
            "allowed",
            "denied",
            "warn",
            "reason_code",
            "guard",
            "severity",
            "message",
            "reason",
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

        let fixtures_path = fixture_events_path();
        let expected_ids = fixture_event_ids(&fixtures_path);

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
                track_posture: false,
                ocsf_out: None,
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
        assert_eq!(
            results.len(),
            expected_ids.len(),
            "expected one result per fixture line"
        );

        let ids: BTreeSet<String> = results
            .iter()
            .filter_map(|r| {
                r.get("eventId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();

        for id in expected_ids {
            assert!(ids.contains(&id), "missing eventId {id}");
        }

        let first = &results[0];
        let decision = first.get("decision").expect("decision");
        for key in [
            "allowed",
            "denied",
            "warn",
            "reason_code",
            "guard",
            "severity",
            "message",
            "reason",
        ] {
            assert!(decision.get(key).is_some(), "missing decision.{key}");
        }
        assert!(first.get("report").is_some(), "missing report");
    }

    #[tokio::test]
    async fn policy_simulate_jsonl_streams_one_json_object_per_event() {
        let fixtures_path = fixture_events_path();
        let expected_count = fixture_event_ids(&fixtures_path).len();

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
                track_posture: false,
                ocsf_out: None,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Fail, "fixtures include a blocked event");

        let stdout = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            lines.len(),
            expected_count,
            "expected one JSON line per event"
        );

        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
            assert!(v.get("eventId").is_some());
            assert!(v.get("decision").is_some());
            assert!(v.get("report").is_some());
        }
    }

    #[tokio::test]
    async fn policy_simulate_json_summary_only_omits_results_but_preserves_counts() {
        let fixtures_path = fixture_events_path();
        let expected_count = fixture_event_ids(&fixtures_path).len();

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
                track_posture: false,
                ocsf_out: None,
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
            Some(expected_count as i64)
        );
        assert_eq!(
            v.get("results").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(0)
        );
    }

    #[tokio::test]
    async fn policy_simulate_no_fail_on_deny_exit_code_ok() {
        let fixtures_path = fixture_events_path();

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
                track_posture: false,
                ocsf_out: None,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Ok);
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(v.get("exit_code").and_then(|v| v.as_i64()), Some(0));
        let blocked = v
            .get("summary")
            .and_then(|v| v.get("blocked"))
            .and_then(|v| v.as_i64())
            .expect("summary.blocked");
        assert!(
            blocked > 0,
            "fixture corpus should include blocked decisions"
        );
    }

    #[tokio::test]
    async fn policy_simulate_matches_expected_decisions_fixture_default_ruleset() {
        let fixtures_path = fixture_events_path();
        let expected_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/policy-events/v1/expected/default.decisions.json");

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

        assert!(
            !expected_by_id.is_empty(),
            "expected one decision per fixture"
        );

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
                track_posture: false,
                ocsf_out: None,
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
        assert_eq!(
            results.len(),
            expected_by_id.len(),
            "expected one result per fixture line"
        );

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

    use crate::policy_test::{
        cmd_policy_test, cmd_policy_test_generate, PolicyTestGenerateOptions, PolicyTestRunOptions,
    };
    use crate::remote_extends::RemoteExtendsConfig;
    use crate::{ExitCode, PolicyTestOutputFormat};

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
            PolicyTestRunOptions {
                json: true,
                coverage: true,
                min_coverage: None,
                format: PolicyTestOutputFormat::Json,
                output: None,
                snapshots: false,
                update_snapshots: false,
                mutation: false,
            },
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

    #[tokio::test]
    async fn policy_test_runner_enforces_min_coverage_threshold() {
        let test_path = temp_path("policy_test_min_coverage.yaml");
        std::fs::write(
            &test_path,
            r#"
name: "Min Coverage"
policy: "clawdstrike:default"
suites:
  - name: "Single Guard"
    tests:
      - name: "only forbidden path"
        input:
          eventType: file_read
          data:
            type: file
            path: /home/user/.ssh/id_rsa
            operation: read
        expect:
          denied: true
          guard: forbidden_path
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
            PolicyTestRunOptions {
                json: true,
                coverage: true,
                min_coverage: Some(100.0),
                format: PolicyTestOutputFormat::Json,
                output: None,
                snapshots: false,
                update_snapshots: false,
                mutation: false,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Fail);
        assert!(err.is_empty());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        let failures = v
            .get("failures")
            .and_then(|f| f.as_array())
            .expect("failures array");
        assert!(failures
            .iter()
            .any(|f| f.get("test").and_then(|t| t.as_str()) == Some("min_coverage")));
    }

    #[tokio::test]
    async fn policy_test_runner_min_coverage_implies_coverage() {
        let test_path = temp_path("policy_test_min_coverage_implies_coverage.yaml");
        std::fs::write(
            &test_path,
            r#"
name: "Min Coverage Implies Coverage"
policy: "clawdstrike:default"
suites:
  - name: "Single Guard"
    tests:
      - name: "only forbidden path"
        input:
          eventType: file_read
          data:
            type: file
            path: /home/user/.ssh/id_rsa
            operation: read
        expect:
          denied: true
          guard: forbidden_path
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
            PolicyTestRunOptions {
                json: true,
                coverage: false,
                min_coverage: Some(100.0),
                format: PolicyTestOutputFormat::Json,
                output: None,
                snapshots: false,
                update_snapshots: false,
                mutation: false,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Fail);
        assert!(err.is_empty());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert!(
            v.get("coverage_percent")
                .and_then(|value| value.as_f64())
                .is_some(),
            "coverage percent should be computed when min_coverage is set"
        );
        let failures = v
            .get("failures")
            .and_then(|f| f.as_array())
            .expect("failures array");
        assert!(failures
            .iter()
            .any(|f| f.get("test").and_then(|t| t.as_str()) == Some("min_coverage")));
    }

    #[tokio::test]
    async fn policy_test_runner_writes_html_and_junit_reports() {
        let test_path = temp_path("policy_test_reports.yaml");
        std::fs::write(
            &test_path,
            r#"
name: "Report Formats"
policy: "clawdstrike:default"
suites:
  - name: "Allow"
    tests:
      - name: "allows normal path"
        input:
          eventType: file_read
          data:
            type: file
            path: /workspace/src/main.rs
            operation: read
        expect:
          allowed: true
"#,
        )
        .expect("write test file");

        let remote = RemoteExtendsConfig::disabled();

        let html_path = temp_path("report.html");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let html_code = cmd_policy_test(
            test_path.to_string_lossy().to_string(),
            false,
            &remote,
            PolicyTestRunOptions {
                json: false,
                coverage: true,
                min_coverage: None,
                format: PolicyTestOutputFormat::Html,
                output: Some(html_path.to_string_lossy().to_string()),
                snapshots: false,
                update_snapshots: false,
                mutation: false,
            },
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(html_code, ExitCode::Ok);
        assert!(err.is_empty());
        let html = std::fs::read_to_string(&html_path).expect("html report");
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("Policy Test Report"));

        let junit_path = temp_path("report.xml");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let junit_code = cmd_policy_test(
            test_path.to_string_lossy().to_string(),
            false,
            &remote,
            PolicyTestRunOptions {
                json: false,
                coverage: false,
                min_coverage: None,
                format: PolicyTestOutputFormat::Junit,
                output: Some(junit_path.to_string_lossy().to_string()),
                snapshots: false,
                update_snapshots: false,
                mutation: false,
            },
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(junit_code, ExitCode::Ok);
        assert!(err.is_empty());
        let xml = std::fs::read_to_string(&junit_path).expect("junit report");
        assert!(xml.contains("<testsuite"));
    }

    #[tokio::test]
    async fn policy_test_runner_supports_snapshots_and_mutation_mode() {
        let test_path = temp_path("policy_test_snapshots.yaml");
        std::fs::write(
            &test_path,
            r#"
name: "Snapshots"
policy: "clawdstrike:default"
suites:
  - name: "Simple"
    tests:
      - name: "allow write"
        input:
          eventType: file_write
          data:
            type: file
            path: ./output/report.txt
            operation: write
        expect:
          allowed: true
"#,
        )
        .expect("write test file");
        let snapshot_path = PathBuf::from(format!("{}.snapshot.json", test_path.to_string_lossy()));

        let remote = RemoteExtendsConfig::disabled();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let missing_snapshot_code = cmd_policy_test(
            test_path.to_string_lossy().to_string(),
            false,
            &remote,
            PolicyTestRunOptions {
                json: true,
                coverage: false,
                min_coverage: None,
                format: PolicyTestOutputFormat::Json,
                output: None,
                snapshots: true,
                update_snapshots: false,
                mutation: false,
            },
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(missing_snapshot_code, ExitCode::Fail);
        assert!(err.is_empty());

        let mut out = Vec::new();
        let mut err = Vec::new();
        let update_snapshot_code = cmd_policy_test(
            test_path.to_string_lossy().to_string(),
            false,
            &remote,
            PolicyTestRunOptions {
                json: true,
                coverage: false,
                min_coverage: None,
                format: PolicyTestOutputFormat::Json,
                output: None,
                snapshots: true,
                update_snapshots: true,
                mutation: false,
            },
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(update_snapshot_code, ExitCode::Ok);
        assert!(snapshot_path.exists());

        let mut out = Vec::new();
        let mut err = Vec::new();
        let mutation_code = cmd_policy_test(
            test_path.to_string_lossy().to_string(),
            false,
            &remote,
            PolicyTestRunOptions {
                json: true,
                coverage: false,
                min_coverage: None,
                format: PolicyTestOutputFormat::Json,
                output: None,
                snapshots: false,
                update_snapshots: false,
                mutation: true,
            },
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(mutation_code, ExitCode::Fail);
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        let failures = v
            .get("failures")
            .and_then(|f| f.as_array())
            .expect("failures array");
        assert!(failures
            .iter()
            .any(|f| f.get("suite").and_then(|s| s.as_str()) == Some("<mutation>")));
    }

    #[tokio::test]
    async fn policy_test_generate_writes_suite_from_policy_and_events() {
        let output_path = temp_path("generated_suite.yaml");
        let events = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/policy-events/v1/events.jsonl");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = cmd_policy_test_generate(
            "default".to_string(),
            false,
            &remote,
            PolicyTestGenerateOptions {
                events: Some(events.to_string_lossy().to_string()),
                output: Some(output_path.to_string_lossy().to_string()),
                json: false,
            },
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::Ok);
        assert!(err.is_empty());
        let generated = std::fs::read_to_string(&output_path).expect("generated file");
        assert!(generated.contains("Generated Baseline Cases"));
        assert!(generated.contains("Observed Event Cases"));
        assert!(generated.contains("policy: default"));
    }
}

#[cfg(all(test, feature = "rego-runtime"))]
mod rego_contract {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::policy_rego::cmd_policy_rego;
    use crate::{ExitCode, RegoCommands};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("hush_cli_rego_{name}_{nanos}"))
    }

    #[test]
    fn rego_compile_and_eval_commands_work() {
        let rego_path = temp_path("policy.rego");
        std::fs::write(
            &rego_path,
            r#"
package example

allow if {
  input.user == "admin"
}
"#,
        )
        .expect("write rego");

        let input_path = temp_path("input.json");
        std::fs::write(&input_path, r#"{"user":"admin"}"#).expect("write input");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let compile_code = cmd_policy_rego(
            RegoCommands::Compile {
                file: rego_path.to_string_lossy().to_string(),
                entrypoint: Some("data.example.allow".to_string()),
                json: true,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(compile_code, ExitCode::Ok);
        assert!(err.is_empty());

        let mut out = Vec::new();
        let mut err = Vec::new();
        let eval_code = cmd_policy_rego(
            RegoCommands::Eval {
                file: rego_path.to_string_lossy().to_string(),
                input: input_path.to_string_lossy().to_string(),
                entrypoint: Some("data.example.allow".to_string()),
                trace: true,
                json: true,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(eval_code, ExitCode::Ok);
        assert!(err.is_empty());

        let json: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(
            json.get("command").and_then(|v| v.as_str()),
            Some("policy_rego_eval")
        );
        let result = json.get("result").expect("result field");
        assert!(result.get("result").is_some());
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

    use clawdstrike::policy::{PolicyLocation, PolicyResolver};
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
                        Err(_) => {
                            // Keep the harness alive through transient accept errors so
                            // chained fetches in the same test don't fail spuriously.
                            std::thread::sleep(Duration::from_millis(10));
                        }
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
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;

        // Read until the request headers are complete. Under heavy
        // instrumentation, a single read is not always sufficient.
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() >= 64 * 1024 {
                        break;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if buf.is_empty() {
                        return Err(e);
                    }
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        let req = std::str::from_utf8(&buf).unwrap_or("");
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
        let cfg = RemoteExtendsConfig::new(["127.0.0.1".to_string()])
            .with_https_only(false)
            .with_allow_private_ips(true);
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
    fn remote_extends_git_scp_host_must_be_allowlisted() {
        let cfg = RemoteExtendsConfig::new(["github.com".to_string()]);
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let reference = format!(
            "git+git@evil.example:org/repo.git@deadbeef:policy.yaml#sha256={}",
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("SCP-style disallowed host should be rejected before fetch");
        assert!(
            err.to_string().contains("allowlisted"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn remote_extends_git_userless_scp_host_must_be_allowlisted() {
        let cfg = RemoteExtendsConfig::new(["github.com".to_string()]);
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let reference = format!(
            "git+evil.example:org/repo.git@deadbeef:policy.yaml#sha256={}",
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("userless SCP-style disallowed host should be rejected before fetch");
        let msg = err.to_string();
        assert!(
            msg.contains("allowlisted"),
            "unexpected error for userless SCP remote: {msg}"
        );
    }

    #[test]
    fn remote_extends_git_file_scheme_is_rejected() {
        let cfg = RemoteExtendsConfig::new(["github.com".to_string()]);
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let reference = format!(
            "git+file:///tmp/repo.git@deadbeef:policy.yaml#sha256={}",
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("file:// git remote should be rejected");
        assert!(
            err.to_string()
                .contains("Unsupported git remote scheme for remote extends"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn remote_extends_rejects_dash_prefixed_commit_ref() {
        let cfg = RemoteExtendsConfig::new(["github.com".to_string()]);
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let reference = format!(
            "git+https://github.com/backbay-labs/clawdstrike.git@-not-a-ref:policy.yaml#sha256={}",
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("dash-prefixed commit/ref must be rejected before any git invocation");
        assert!(
            err.to_string().contains("must not start with '-'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn remote_extends_git_private_ip_blocked_when_disallowed() {
        let cfg = RemoteExtendsConfig::new(["127.0.0.1".to_string()])
            .with_https_only(false)
            .with_allow_private_ips(false);
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let reference = format!(
            "git+ssh://127.0.0.1/repo.git@deadbeef:policy.yaml#sha256={}",
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("private IP git remote should be rejected");
        assert!(
            err.to_string().contains("non-public IPs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn remote_extends_git_ipv4_mapped_ipv6_private_ip_blocked_when_disallowed() {
        let cfg = RemoteExtendsConfig::new(["::ffff:7f00:1".to_string()])
            .with_https_only(false)
            .with_allow_private_ips(false);
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let reference = format!(
            "git+ssh://[::ffff:127.0.0.1]/repo.git@deadbeef:policy.yaml#sha256={}",
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("ipv4-mapped loopback git remote should be rejected");
        assert!(
            err.to_string().contains("non-public IPs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn remote_extends_git_cache_hit_does_not_require_dns_resolution() {
        let cache_dir = std::env::temp_dir().join(format!(
            "hush-cli-remote-extends-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        let repo = "https://offline-cache.example.invalid/org/repo.git";
        let commit = "deadbeef";
        let path = "policy.yaml";
        let yaml_bytes = br#"
version: "1.1.0"
name: cached
settings:
  fail_fast: true
"#;
        let expected_sha = sha256(yaml_bytes).to_hex();
        let key = format!("git:{}@{}:{}#sha256={}", repo, commit, path, expected_sha);
        let digest = sha256(key.as_bytes()).to_hex();
        let cache_path = cache_dir.join(format!("{}.yaml", digest));
        std::fs::write(&cache_path, yaml_bytes).expect("write cached bytes");

        let cfg = RemoteExtendsConfig::new(["offline-cache.example.invalid".to_string()])
            .with_cache_dir(&cache_dir)
            .with_allow_private_ips(false);
        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
        let reference = format!("git+{}@{}:{}#sha256={}", repo, commit, path, expected_sha);

        let resolved = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect("cached git policy should resolve without DNS");
        assert!(
            resolved.yaml.contains("name: cached"),
            "expected cached YAML payload"
        );

        let _ = std::fs::remove_dir_all(&cache_dir);
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
mod policy_migrate_contract {
    use crate::policy_migrate::{migrate_policy_yaml, PolicyMigrateMode, PolicyMigrateOptions};

    #[test]
    fn migrates_policy_version_1_0_0_to_1_1_0_and_validates() {
        let input = r#"
version: "1.0.0"
name: "Example policy"
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
"#;

        let res = migrate_policy_yaml(
            input,
            &PolicyMigrateOptions {
                from: Some("1.0.0".to_string()),
                to: "1.1.0".to_string(),
                legacy_openclaw: false,
            },
        )
        .expect("migration succeeds");

        assert_eq!(res.mode, PolicyMigrateMode::VersionBump);

        let policy = clawdstrike::Policy::from_yaml(&res.migrated_yaml).expect("output loads");
        assert_eq!(policy.version, "1.1.0");
        assert_eq!(policy.name, "Example policy");
    }

    #[test]
    fn migrates_legacy_openclaw_policy_to_canonical_and_validates() {
        let input = r#"
version: clawdstrike-v1.0
name: "Legacy"
extends: "default"

filesystem:
  forbidden_paths:
    - "**/.ssh/**"

egress:
  mode: allowlist
  allowed_domains:
    - "*.example.com"
  denied_domains:
    - "bad.example.com"

tools:
  allowed:
    - "filesystem_read"
"#;

        let res = migrate_policy_yaml(
            input,
            &PolicyMigrateOptions {
                from: None,
                to: "1.1.0".to_string(),
                legacy_openclaw: true,
            },
        )
        .expect("migration succeeds");

        assert_eq!(res.mode, PolicyMigrateMode::LegacyOpenclaw);

        let policy = clawdstrike::Policy::from_yaml(&res.migrated_yaml).expect("output loads");
        assert_eq!(policy.version, "1.1.0");
        assert_eq!(policy.name, "Legacy");
        assert_eq!(policy.extends, Some("default".to_string()));

        let fp = policy
            .guards
            .forbidden_path
            .as_ref()
            .expect("forbidden_path mapped");
        assert_eq!(
            fp.patterns.as_ref().expect("patterns set"),
            &vec!["**/.ssh/**".to_string()]
        );

        let egress = policy
            .guards
            .egress_allowlist
            .as_ref()
            .expect("egress_allowlist mapped");
        assert_eq!(egress.allow, vec!["*.example.com".to_string()]);
        assert_eq!(egress.block, vec!["bad.example.com".to_string()]);

        let mcp = policy.guards.mcp_tool.as_ref().expect("mcp_tool mapped");
        assert_eq!(mcp.allow, vec!["filesystem_read".to_string()]);
    }

    #[test]
    fn migrates_policy_version_1_1_0_to_1_2_0_and_validates() {
        let input = r#"
version: "1.1.0"
name: "Schema bump"
extends: clawdstrike:default
"#;

        let res = migrate_policy_yaml(
            input,
            &PolicyMigrateOptions {
                from: Some("1.1.0".to_string()),
                to: "1.2.0".to_string(),
                legacy_openclaw: false,
            },
        )
        .expect("migration succeeds");

        assert_eq!(res.mode, PolicyMigrateMode::VersionBump);
        let policy = clawdstrike::Policy::from_yaml(&res.migrated_yaml).expect("output loads");
        assert_eq!(policy.version, "1.2.0");
        assert_eq!(policy.name, "Schema bump");
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

#[cfg(all(test, unix))]
mod keygen_file_permissions {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn write_secret_file_tightens_existing_file_permissions_to_0600() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hush-write-secret-file-{}-{}",
            std::process::id(),
            nonce
        ));

        std::fs::write(&path, "old").expect("seed file");
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).expect("set broad mode");

        crate::write_secret_file(path.to_str().expect("utf8 path"), "secret")
            .expect("write_secret_file");

        let mode = std::fs::metadata(&path)
            .expect("metadata after write")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(path);
    }
}

// ---------------------------------------------------------------------------
// Hunt Correlate / Watch / IOC CLI tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod hunt_cli_parsing {
    use clap::Parser;

    use crate::{Cli, Commands, HuntCommands};

    #[test]
    fn hunt_watch_parses_with_defaults() {
        let cli = Cli::parse_from(["hush", "hunt", "watch", "--rules", "rule.yaml"]);

        match cli.command {
            Commands::Hunt { command } => match command {
                HuntCommands::Watch {
                    rules,
                    nats_url,
                    nats_creds,
                    max_window,
                    json,
                    no_color,
                } => {
                    assert_eq!(rules, vec!["rule.yaml"]);
                    assert_eq!(nats_url, "nats://localhost:4222");
                    assert!(nats_creds.is_none());
                    assert_eq!(max_window, "5m");
                    assert!(!json);
                    assert!(!no_color);
                }
                _ => panic!("Expected Watch command"),
            },
            _ => panic!("Expected Hunt command"),
        }
    }

    #[test]
    fn hunt_watch_parses_multiple_rules() {
        let cli = Cli::parse_from([
            "hush",
            "hunt",
            "watch",
            "--rules",
            "r1.yaml",
            "--rules",
            "r2.yaml",
            "--json",
            "--no-color",
            "--max-window",
            "10m",
        ]);

        match cli.command {
            Commands::Hunt { command } => match command {
                HuntCommands::Watch {
                    rules,
                    max_window,
                    json,
                    no_color,
                    ..
                } => {
                    assert_eq!(rules, vec!["r1.yaml", "r2.yaml"]);
                    assert_eq!(max_window, "10m");
                    assert!(json);
                    assert!(no_color);
                }
                _ => panic!("Expected Watch command"),
            },
            _ => panic!("Expected Hunt command"),
        }
    }

    #[test]
    fn hunt_correlate_parses_with_query_flags() {
        let cli = Cli::parse_from([
            "hush",
            "hunt",
            "correlate",
            "--rules",
            "exfil.yaml",
            "--source",
            "receipt",
            "--verdict",
            "allow",
            "--start",
            "2025-01-01T00:00:00Z",
            "--limit",
            "500",
            "--offline",
            "--json",
        ]);

        match cli.command {
            Commands::Hunt { command } => match command {
                HuntCommands::Correlate {
                    rules,
                    source,
                    verdict,
                    start,
                    limit,
                    offline,
                    json,
                    ..
                } => {
                    assert_eq!(rules, vec!["exfil.yaml"]);
                    assert_eq!(source, Some(vec!["receipt".to_string()]));
                    assert_eq!(verdict, Some("allow".to_string()));
                    assert_eq!(start, Some("2025-01-01T00:00:00Z".to_string()));
                    assert_eq!(limit, 500);
                    assert!(offline);
                    assert!(json);
                }
                _ => panic!("Expected Correlate command"),
            },
            _ => panic!("Expected Hunt command"),
        }
    }

    #[test]
    fn hunt_correlate_defaults() {
        let cli = Cli::parse_from(["hush", "hunt", "correlate", "--rules", "r.yaml"]);

        match cli.command {
            Commands::Hunt { command } => match command {
                HuntCommands::Correlate {
                    rules,
                    source,
                    verdict,
                    start,
                    end,
                    limit,
                    offline,
                    json,
                    jsonl,
                    no_color,
                    ..
                } => {
                    assert_eq!(rules, vec!["r.yaml"]);
                    assert!(source.is_none());
                    assert!(verdict.is_none());
                    assert!(start.is_none());
                    assert!(end.is_none());
                    assert_eq!(limit, 100);
                    assert!(!offline);
                    assert!(!json);
                    assert!(!jsonl);
                    assert!(!no_color);
                }
                _ => panic!("Expected Correlate command"),
            },
            _ => panic!("Expected Hunt command"),
        }
    }

    #[test]
    fn hunt_ioc_parses_feed_and_stix() {
        let cli = Cli::parse_from([
            "hush",
            "hunt",
            "ioc",
            "--feed",
            "iocs.txt",
            "--feed",
            "iocs.csv",
            "--stix",
            "bundle.json",
            "--offline",
            "--json",
        ]);

        match cli.command {
            Commands::Hunt { command } => match command {
                HuntCommands::Ioc {
                    feed,
                    stix,
                    offline,
                    json,
                    ..
                } => {
                    assert_eq!(
                        feed,
                        Some(vec!["iocs.txt".to_string(), "iocs.csv".to_string()])
                    );
                    assert_eq!(stix, Some(vec!["bundle.json".to_string()]));
                    assert!(offline);
                    assert!(json);
                }
                _ => panic!("Expected Ioc command"),
            },
            _ => panic!("Expected Hunt command"),
        }
    }

    #[test]
    fn hunt_ioc_defaults() {
        let cli = Cli::parse_from(["hush", "hunt", "ioc", "--feed", "iocs.txt"]);

        match cli.command {
            Commands::Hunt { command } => match command {
                HuntCommands::Ioc {
                    feed,
                    stix,
                    source,
                    start,
                    end,
                    limit,
                    offline,
                    json,
                    no_color,
                    ..
                } => {
                    assert_eq!(feed, Some(vec!["iocs.txt".to_string()]));
                    assert!(stix.is_none());
                    assert!(source.is_none());
                    assert!(start.is_none());
                    assert!(end.is_none());
                    assert_eq!(limit, 100);
                    assert!(!offline);
                    assert!(!json);
                    assert!(!no_color);
                }
                _ => panic!("Expected Ioc command"),
            },
            _ => panic!("Expected Hunt command"),
        }
    }
}

#[cfg(test)]
mod hunt_contract {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::remote_extends::RemoteExtendsConfig;
    use crate::{ExitCode, HuntCommands};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("hush_hunt_{name}_{nanos}"))
    }

    #[tokio::test]
    async fn correlate_no_rules_returns_invalid_args() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Correlate {
                rules: vec![],
                source: None,
                verdict: None,
                start: None,
                end: None,
                action_type: None,
                process: None,
                namespace: None,
                pod: None,
                limit: 100,
                nl: None,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: None,
                verify: false,
                json: true,
                jsonl: false,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::InvalidArgs.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["command"].as_str(), Some("hunt correlate"));
        assert_eq!(
            v["exit_code"].as_i64(),
            Some(ExitCode::InvalidArgs.as_i32() as i64)
        );
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("No correlation rule files"));
    }

    #[tokio::test]
    async fn correlate_with_rules_offline_empty_events_returns_ok() {
        let rule_path = temp_path("rule.yaml");
        std::fs::write(
            &rule_path,
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "Test Rule"
severity: low
description: "test"
window: 5m
conditions:
  - source: receipt
    action_type: file
    verdict: deny
    bind: evt
output:
  title: "test alert"
  evidence:
    - evt
"#,
        )
        .expect("write rule");

        // Create empty local dir for offline mode
        let local_dir = temp_path("events_dir");
        std::fs::create_dir_all(&local_dir).expect("create events dir");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Correlate {
                rules: vec![rule_path.to_string_lossy().to_string()],
                source: None,
                verdict: None,
                start: None,
                end: None,
                action_type: None,
                process: None,
                namespace: None,
                pod: None,
                limit: 100,
                nl: None,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: Some(vec![local_dir.to_string_lossy().to_string()]),
                verify: false,
                json: true,
                jsonl: false,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        let _ = std::fs::remove_file(&rule_path);
        let _ = std::fs::remove_dir_all(&local_dir);

        assert_eq!(code, ExitCode::Ok.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["version"].as_u64(), Some(1));
        assert_eq!(v["command"].as_str(), Some("hunt correlate"));
        assert_eq!(v["exit_code"].as_i64(), Some(0));
        assert!(v["error"].is_null());

        let data = &v["data"];
        assert!(data["alerts"].as_array().unwrap().is_empty());
        assert_eq!(data["summary"]["events_processed"].as_u64(), Some(0));
        assert_eq!(data["summary"]["alerts_generated"].as_u64(), Some(0));
        assert_eq!(data["summary"]["rules_loaded"].as_u64(), Some(1));
    }

    #[tokio::test]
    async fn correlate_bad_rule_path_returns_config_error() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Correlate {
                rules: vec!["/nonexistent/rule.yaml".to_string()],
                source: None,
                verdict: None,
                start: None,
                end: None,
                action_type: None,
                process: None,
                namespace: None,
                pod: None,
                limit: 100,
                nl: None,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: None,
                verify: false,
                json: true,
                jsonl: false,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::ConfigError.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["command"].as_str(), Some("hunt correlate"));
        assert_eq!(
            v["exit_code"].as_i64(),
            Some(ExitCode::ConfigError.as_i32() as i64)
        );
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Failed to load rules"));
    }

    #[tokio::test]
    async fn ioc_no_feeds_returns_invalid_args() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Ioc {
                feed: None,
                stix: None,
                source: None,
                start: None,
                end: None,
                limit: 100,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: None,
                verify: false,
                json: true,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::InvalidArgs.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["command"].as_str(), Some("hunt ioc"));
        assert_eq!(
            v["exit_code"].as_i64(),
            Some(ExitCode::InvalidArgs.as_i32() as i64)
        );
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("No IOC feeds specified"));
    }

    #[tokio::test]
    async fn ioc_with_feed_offline_empty_events_returns_ok() {
        // Create a simple text IOC feed
        let feed_path = temp_path("iocs.txt");
        std::fs::write(&feed_path, "# IOC feed\nevil.com\n10.0.0.99\n").expect("write feed");

        // Create empty local dir for offline mode
        let local_dir = temp_path("ioc_events_dir");
        std::fs::create_dir_all(&local_dir).expect("create events dir");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Ioc {
                feed: Some(vec![feed_path.to_string_lossy().to_string()]),
                stix: None,
                source: None,
                start: None,
                end: None,
                limit: 100,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: Some(vec![local_dir.to_string_lossy().to_string()]),
                verify: false,
                json: true,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        let _ = std::fs::remove_file(&feed_path);
        let _ = std::fs::remove_dir_all(&local_dir);

        assert_eq!(code, ExitCode::Ok.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["version"].as_u64(), Some(1));
        assert_eq!(v["command"].as_str(), Some("hunt ioc"));
        assert_eq!(v["exit_code"].as_i64(), Some(0));
        assert!(v["error"].is_null());

        let data = &v["data"];
        assert!(data["matches"].as_array().unwrap().is_empty());
        assert_eq!(data["summary"]["events_scanned"].as_u64(), Some(0));
        assert_eq!(data["summary"]["iocs_loaded"].as_u64(), Some(2));
        assert_eq!(data["summary"]["matches_found"].as_u64(), Some(0));
    }

    #[tokio::test]
    async fn ioc_bad_feed_path_returns_config_error() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Ioc {
                feed: Some(vec!["/nonexistent/iocs.txt".to_string()]),
                stix: None,
                source: None,
                start: None,
                end: None,
                limit: 100,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: None,
                verify: false,
                json: true,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::ConfigError.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["command"].as_str(), Some("hunt ioc"));
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Failed to load IOC feed"));
    }

    #[tokio::test]
    async fn ioc_stix_bundle_offline_returns_ok() {
        let sha = "a".repeat(64);
        let bundle = serde_json::json!({
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Bad hash",
                    "pattern": format!("[file:hashes.SHA-256 = '{}']", sha),
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z"
                }
            ]
        });
        let stix_path = temp_path("stix.json");
        std::fs::write(&stix_path, serde_json::to_string(&bundle).unwrap()).expect("write stix");

        let local_dir = temp_path("stix_events_dir");
        std::fs::create_dir_all(&local_dir).expect("create events dir");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Ioc {
                feed: None,
                stix: Some(vec![stix_path.to_string_lossy().to_string()]),
                source: None,
                start: None,
                end: None,
                limit: 100,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: Some(vec![local_dir.to_string_lossy().to_string()]),
                verify: false,
                json: true,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        let _ = std::fs::remove_file(&stix_path);
        let _ = std::fs::remove_dir_all(&local_dir);

        assert_eq!(code, ExitCode::Ok.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["command"].as_str(), Some("hunt ioc"));
        assert_eq!(v["data"]["summary"]["iocs_loaded"].as_u64(), Some(1));
    }

    #[tokio::test]
    async fn watch_no_rules_returns_invalid_args() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Watch {
                rules: vec![],
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                max_window: "5m".to_string(),
                json: true,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::InvalidArgs.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["command"].as_str(), Some("hunt watch"));
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("No correlation rule files"));
    }

    #[tokio::test]
    async fn watch_bad_max_window_returns_invalid_args() {
        let rule_path = temp_path("watch_rule.yaml");
        std::fs::write(
            &rule_path,
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "Test"
severity: low
description: "test"
window: 1m
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"#,
        )
        .expect("write rule");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Watch {
                rules: vec![rule_path.to_string_lossy().to_string()],
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                max_window: "invalid".to_string(),
                json: true,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        let _ = std::fs::remove_file(&rule_path);

        assert_eq!(code, ExitCode::InvalidArgs.as_i32());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON output");
        assert_eq!(v["command"].as_str(), Some("hunt watch"));
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Invalid --max-window"));
    }

    #[tokio::test]
    async fn correlate_text_output_no_rules() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let remote = RemoteExtendsConfig::disabled();

        let code = crate::hunt::cmd_hunt(
            HuntCommands::Correlate {
                rules: vec![],
                source: None,
                verdict: None,
                start: None,
                end: None,
                action_type: None,
                process: None,
                namespace: None,
                pod: None,
                limit: 100,
                nl: None,
                nats_url: "nats://localhost:4222".to_string(),
                nats_creds: None,
                offline: true,
                local_dir: None,
                verify: false,
                json: false,
                jsonl: false,
                no_color: true,
            },
            &remote,
            false,
            &mut out,
            &mut err,
        )
        .await;

        assert_eq!(code, ExitCode::InvalidArgs.as_i32());
        let stderr_str = String::from_utf8(err).unwrap();
        assert!(stderr_str.contains("No correlation rule files"));
    }
}
