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
