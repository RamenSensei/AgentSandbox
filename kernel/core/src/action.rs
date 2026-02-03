//! Structured actions: what an agent asks the kernel to execute.

use crate::budget::ResourceBudget;
use crate::ids::LeaseId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The action taxonomy. Every variant is a *semantic* request; the kernel —
/// not the agent — decides which isolation backend executes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ActionKind {
    /// Run a shell command inside the branch workspace.
    Shell { command: String, #[serde(default)] cwd: Option<String>, #[serde(default)] env: BTreeMap<String, String> },
    /// Read a file from the branch workspace.
    ReadFile { path: String },
    /// Write a file into the branch workspace.
    WriteFile { path: String, contents_b64: String },
    /// Delete a path in the branch workspace.
    DeletePath { path: String },
    /// Read-only HTTP fetch through the egress proxy.
    HttpRead { url: String },
    /// Invoke an MCP tool through the gateway.
    McpInvoke { server: String, tool: String, arguments: serde_json::Value },
    /// A typed connector operation that may produce an external effect
    /// (e.g. `github.create_pull_request`). Never executed inline: the kernel
    /// turns it into a proposed effect.
    ConnectorOp { connector: String, operation: String, params: serde_json::Value },
    /// Query the causal ledger (`trace.query`).
    TraceQuery { query: String },
    /// Ask for a semantic diff of a branch since a state.
    BranchDiff { since: crate::ids::StateId },
}

impl ActionKind {
    /// The capability operation this action requires.
    pub fn required_operation(&self) -> crate::capability::Operation {
        use crate::capability::Operation;
        match self {
            ActionKind::Shell { .. } => Operation::new("proc.shell"),
            ActionKind::ReadFile { .. } => Operation::new("fs.read"),
            ActionKind::WriteFile { .. } => Operation::new("fs.write"),
            ActionKind::DeletePath { .. } => Operation::new("fs.delete"),
            ActionKind::HttpRead { .. } => Operation::new("net.http_read"),
            ActionKind::McpInvoke { .. } => Operation::new("mcp.invoke"),
            ActionKind::ConnectorOp { connector, operation, .. } => {
                Operation::new(format!("{connector}.{operation}"))
            }
            ActionKind::TraceQuery { .. } => Operation::new("trace.query"),
            ActionKind::BranchDiff { .. } => Operation::new("state.diff"),
        }
    }

    /// Canonical parameters used for constraint checking.
    pub fn params(&self) -> serde_json::Value {
        match self {
            ActionKind::Shell { command, cwd, .. } => serde_json::json!({"command": command, "cwd": cwd}),
            ActionKind::ReadFile { path } | ActionKind::DeletePath { path } => serde_json::json!({"path": path}),
            ActionKind::WriteFile { path, .. } => serde_json::json!({"path": path}),
            ActionKind::HttpRead { url } => serde_json::json!({"url": url}),
            ActionKind::McpInvoke { server, tool, arguments } => {
                serde_json::json!({"server": server, "tool": tool, "arguments": arguments})
            }
            ActionKind::ConnectorOp { params, .. } => params.clone(),
            ActionKind::TraceQuery { query } => serde_json::json!({"query": query}),
            ActionKind::BranchDiff { since } => serde_json::json!({"since": since}),
        }
    }
}
