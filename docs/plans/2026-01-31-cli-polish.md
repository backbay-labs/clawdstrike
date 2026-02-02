# CLI Polish Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add shell completions (bash/zsh/fish) and 10+ CLI unit tests to hush-cli for v0.1.0 release readiness.

**Architecture:** Add `clap_complete` for shell completion generation via new `completions` subcommand. Create dedicated test module with clap parsing tests covering all commands, subcommands, flags, and error cases. Update docs and Homebrew formula.

**Tech Stack:** Rust, clap 4.4, clap_complete 4.4, cargo test

---

## Task 1: Add clap_complete Dependency

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/Cargo.toml`

**Step 1: Add clap_complete to dependencies**

Edit `crates/hush-cli/Cargo.toml` to add clap_complete:

```toml
[dependencies]
hush-core.workspace = true
clawdstrike.workspace = true
clap.workspace = true
clap_complete = "4.4"
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
serde_json.workspace = true
anyhow.workspace = true
reqwest = { workspace = true, features = ["blocking"] }
```

**Step 2: Verify compilation**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo check -p hush-cli`
Expected: Compiles without errors

**Step 3: Commit**

```bash
git add crates/hush-cli/Cargo.toml
git commit -m "chore(hush-cli): add clap_complete dependency for shell completions"
```

---

## Task 2: Add Completions Subcommand to CLI

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/main.rs`

**Step 1: Add the Completions variant to Commands enum**

Find the `Commands` enum (around line 29) and add a new variant after `Daemon`:

```rust
#[derive(Subcommand)]
enum Commands {
    /// Check an action against policy
    Check {
        /// Action type (file, egress, mcp)
        #[arg(short, long)]
        action_type: String,

        /// Target (path, host, tool name)
        target: String,

        /// Ruleset to use
        #[arg(short, long, default_value = "default")]
        ruleset: String,
    },

    /// Verify a signed receipt
    Verify {
        /// Path to receipt JSON file
        receipt: String,

        /// Path to public key file
        #[arg(short, long)]
        pubkey: String,
    },

    /// Generate a signing keypair
    Keygen {
        /// Output path for private key
        #[arg(short, long, default_value = "hush.key")]
        output: String,
    },

    /// Policy commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Daemon management commands
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}
```

**Step 2: Add clap_complete import at the top**

Add to imports section:

```rust
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
```

**Step 3: Add match arm for Completions in main()**

Find the main match statement and add before the closing `Ok(())`:

```rust
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "hush", &mut std::io::stdout());
        }
```

**Step 4: Verify compilation**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo check -p hush-cli`
Expected: Compiles without errors

**Step 5: Test completions output**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo run -p hush-cli -- completions bash | head -20`
Expected: Bash completion script output starting with `_hush()`

**Step 6: Commit**

```bash
git add crates/hush-cli/src/main.rs
git commit -m "feat(hush-cli): add completions subcommand for shell completion generation"
```

---

## Task 3: Create Test Module Structure

**Files:**
- Create: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/tests.rs`
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/main.rs`

**Step 1: Create tests.rs with module structure**

Create `crates/hush-cli/src/tests.rs`:

```rust
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

    use crate::Cli;

    // Tests will be added in subsequent tasks
}

#[cfg(test)]
mod completions {
    // Completion generation tests will be added in subsequent tasks
}
```

**Step 2: Add tests module to main.rs**

Add at the end of `main.rs` (before the closing brace if any, otherwise at the very end):

```rust
#[cfg(test)]
mod tests;
```

**Step 3: Verify compilation**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli --no-run`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add crates/hush-cli/src/tests.rs crates/hush-cli/src/main.rs
git commit -m "test(hush-cli): add test module structure"
```

---

## Task 4: Test Check Command Parsing

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/tests.rs`

**Step 1: Write failing test for Check command**

Replace the `cli_parsing` module in `tests.rs`:

```rust
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
```

**Step 2: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli cli_parsing -- --nocapture`
Expected: All 3 tests pass

**Step 3: Commit**

```bash
git add crates/hush-cli/src/tests.rs
git commit -m "test(hush-cli): add Check command parsing tests"
```

---

## Task 5: Test Verify and Keygen Commands

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/tests.rs`

**Step 1: Add tests for Verify and Keygen**

Add these tests inside the `cli_parsing` module (after the existing tests):

```rust
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
```

**Step 2: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli cli_parsing -- --nocapture`
Expected: All 6 tests pass

**Step 3: Commit**

```bash
git add crates/hush-cli/src/tests.rs
git commit -m "test(hush-cli): add Verify and Keygen command parsing tests"
```

---

## Task 6: Test Policy Subcommands

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/tests.rs`

**Step 1: Add tests for Policy subcommands**

Add these tests inside the `cli_parsing` module, also importing `PolicyCommands`:

First, update the use statement at the top of the module:

```rust
    use crate::{Cli, Commands, PolicyCommands};
```

Then add the tests:

```rust
    #[test]
    fn test_policy_show_default_ruleset() {
        let cli = Cli::parse_from(["hush", "policy", "show"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Show { ruleset } => {
                    assert_eq!(ruleset, "default");
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
                PolicyCommands::Show { ruleset } => {
                    assert_eq!(ruleset, "strict");
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
                PolicyCommands::Validate { file } => {
                    assert_eq!(file, "policy.yaml");
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
```

**Step 2: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli cli_parsing -- --nocapture`
Expected: All 10 tests pass

**Step 3: Commit**

```bash
git add crates/hush-cli/src/tests.rs
git commit -m "test(hush-cli): add Policy subcommand parsing tests"
```

---

## Task 7: Test Daemon Subcommands

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/tests.rs`

**Step 1: Add tests for Daemon subcommands**

Update the use statement to include `DaemonCommands`:

```rust
    use crate::{Cli, Commands, DaemonCommands, PolicyCommands};
```

Add these tests:

```rust
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
```

**Step 2: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli cli_parsing -- --nocapture`
Expected: All 14 tests pass

**Step 3: Commit**

```bash
git add crates/hush-cli/src/tests.rs
git commit -m "test(hush-cli): add Daemon subcommand parsing tests"
```

---

## Task 8: Test Completions Command and Error Cases

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/tests.rs`

**Step 1: Add tests for Completions and error handling**

Add these tests to the `cli_parsing` module:

```rust
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
```

**Step 2: Run all tests**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli cli_parsing -- --nocapture`
Expected: All 21 tests pass

**Step 3: Commit**

```bash
git add crates/hush-cli/src/tests.rs
git commit -m "test(hush-cli): add Completions and error handling tests"
```

---

## Task 9: Test Shell Completion Generation

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/crates/hush-cli/src/tests.rs`

**Step 1: Add completion generation tests**

Replace the `completions` module:

```rust
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
```

**Step 2: Run completion tests**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli completions -- --nocapture`
Expected: All 3 tests pass

**Step 3: Commit**

```bash
git add crates/hush-cli/src/tests.rs
git commit -m "test(hush-cli): add shell completion generation tests"
```

---

## Task 10: Update CLI Documentation

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/docs/src/reference/api/cli.md`

**Step 1: Update shell completion section**

The current docs reference `hush completion` but our implementation uses `hush completions`. Update the "Shell Completion" section (around line 318-329) to match actual implementation:

Find and replace:

```markdown
## Shell Completion

```bash
# Bash
hush completion bash > /etc/bash_completion.d/hush

# Zsh
hush completion zsh > ~/.zsh/completions/_hush

# Fish
hush completion fish > ~/.config/fish/completions/hush.fish
```
```

With:

```markdown
## Shell Completions

Generate shell completions for your preferred shell:

```bash
# Bash - system-wide
sudo hush completions bash > /etc/bash_completion.d/hush

# Bash - user-local
hush completions bash > ~/.local/share/bash-completion/completions/hush

# Zsh - add to fpath
hush completions zsh > ~/.zfunc/_hush
# Then add to ~/.zshrc: fpath=(~/.zfunc $fpath)

# Fish
hush completions fish > ~/.config/fish/completions/hush.fish

# PowerShell
hush completions powershell > $PROFILE.CurrentUserAllHosts

# Elvish
hush completions elvish > ~/.elvish/lib/hush.elv
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`
```

**Step 2: Verify markdown renders correctly**

Run: `head -50 /Users/connor/Medica/clawdstrike-ws11-cli-polish/docs/src/reference/api/cli.md && tail -30 /Users/connor/Medica/clawdstrike-ws11-cli-polish/docs/src/reference/api/cli.md`
Expected: Clean markdown without syntax errors

**Step 3: Commit**

```bash
git add docs/src/reference/api/cli.md
git commit -m "docs(cli): update shell completions documentation"
```

---

## Task 11: Verify Homebrew Formula

**Files:**
- Modify: `/Users/connor/Medica/clawdstrike-ws11-cli-polish/HomebrewFormula/hush.rb` (if needed)

**Step 1: Verify formula already has completions**

The formula already contains:
```ruby
generate_completions_from_executable(bin/"hush", "completions")
```

This is correct - Homebrew's `generate_completions_from_executable` will call `hush completions bash`, `hush completions zsh`, etc.

**Step 2: Run all tests one final time**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli -- --nocapture`
Expected: All 24 tests pass (21 parsing + 3 completions)

**Step 3: Verify completions work manually**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo run -p hush-cli -- completions zsh | head -5`
Expected: Zsh completion script output

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo run -p hush-cli -- completions fish | head -5`
Expected: Fish completion script output

**Step 4: No commit needed if formula unchanged**

---

## Task 12: Final Verification and Summary

**Step 1: Run full test suite**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo test -p hush-cli 2>&1`
Expected: 24+ tests pass

**Step 2: Verify help text for all commands**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo run -p hush-cli -- --help`
Expected: Help text shows all commands including `completions`

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo run -p hush-cli -- completions --help`
Expected: Help text explains shell argument

**Step 3: Run clippy**

Run: `cd /Users/connor/Medica/clawdstrike-ws11-cli-polish && cargo clippy -p hush-cli -- -D warnings 2>&1 | tail -20`
Expected: No warnings (or only pre-existing ones from workspace)

**Step 4: Create summary commit (if any uncommitted changes)**

```bash
git status
# If there are changes:
git add -A
git commit -m "chore(hush-cli): finalize CLI polish for v0.1.0"
```

---

## Acceptance Criteria Checklist

After completing all tasks, verify:

- [ ] `hush completions bash` outputs valid bash completions
- [ ] `hush completions zsh` outputs valid zsh completions
- [ ] `hush completions fish` outputs valid fish completions
- [ ] `hush completions powershell` outputs valid PowerShell completions
- [ ] `hush completions elvish` outputs valid Elvish completions
- [ ] `cargo test -p hush-cli` runs 10+ tests (target: 24)
- [ ] All commands have proper help text via `--help`
- [ ] Documentation updated with completion instructions
- [ ] Homebrew formula installs completions
- [ ] No clippy warnings introduced

---

## Summary

| Task | Description | Tests Added |
|------|-------------|-------------|
| 1 | Add clap_complete dependency | 0 |
| 2 | Add Completions subcommand | 0 |
| 3 | Create test module structure | 0 |
| 4 | Test Check command | 3 |
| 5 | Test Verify and Keygen | 3 |
| 6 | Test Policy subcommands | 4 |
| 7 | Test Daemon subcommands | 4 |
| 8 | Test Completions and errors | 7 |
| 9 | Test completion generation | 3 |
| 10 | Update documentation | 0 |
| 11 | Verify Homebrew formula | 0 |
| 12 | Final verification | 0 |

**Total: 24 tests** (exceeds 10+ requirement)
