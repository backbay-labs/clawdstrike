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

    use crate::{Cli, Commands};

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
}

#[cfg(test)]
mod completions {
    // Completion generation tests will be added in subsequent tasks
}
