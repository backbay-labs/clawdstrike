//! Claude Code integration via hooks.
//!
//! Auto-installs pre-tool hooks to ~/.claude/hooks/ for policy checking.

mod hook_script;
mod installer;

pub use installer::ClaudeCodeIntegration;

#[cfg(test)]
mod tests;
