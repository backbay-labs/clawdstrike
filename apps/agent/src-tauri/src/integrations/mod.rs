//! AI tool integrations
//!
//! This module contains integrations for various AI coding tools.

pub mod claude_code;
pub mod mcp;
pub mod openclaw_plugin;

pub use claude_code::ClaudeCodeIntegration;
pub use mcp::McpServer;
pub use openclaw_plugin::OpenClawPluginIntegration;
