//! MCP (Model Context Protocol) server for Cursor/Cline integration.
//!
//! Exposes a `policy_check` tool via JSON-RPC that AI tools can call.

mod auth;
mod developer_activity;
mod rpc;
mod server;

#[cfg(test)]
mod tests;

pub use server::McpServer;
