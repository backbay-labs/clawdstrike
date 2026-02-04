//! AI tool integrations
//!
//! This module contains integrations for various AI coding tools.

pub mod claude_code;
pub mod mcp_server;

pub use claude_code::ClaudeCodeIntegration;
pub use mcp_server::McpServer;
