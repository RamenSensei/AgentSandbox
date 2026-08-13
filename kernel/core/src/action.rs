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
    Shell {
        command: String,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    /// Read a file from the branch workspace.
    ReadFile { path: String },
    /// Write a file into the branch workspace.
    WriteFile { path: String, contents_b64: String },
    /// Delete a path in the branch workspace.
    DeletePath { path: String },
    /// Start a **persistent** process in the branch workspace (dev server,
    /// REPL, database, watcher, …). Unlike [`ActionKind::Shell`] the process
    /// outlives the step: the returned handle can be written to, observed
    /// incrementally and signalled by later steps. The process belongs to the
    /// branch and is killed when the branch is discarded. It does NOT survive
    /// a fork (forks get the files, not the live processes).
    ProcessStart {
        command: String,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        /// Optional human-readable name for status listings.
        #[serde(default)]
        name: Option<String>,
    },
    /// Write bytes to a running process's stdin (optionally closing it).
    ProcessStdin {
        process: String,
        data_b64: String,
        #[serde(default)]
        close: bool,
    },
    /// Read combined stdout/stderr of a process from a byte offset. The
    /// response reports `next_offset` so an agent can tail a long-running
    /// process incrementally instead of waiting for it to finish.
    ProcessLogs {
        process: String,
        #[serde(default)]
        from_offset: u64,
        #[serde(default)]
        max_bytes: Option<u64>,
    },
    /// Send a signal to a running process: `"int"`, `"term"` or `"kill"`.
    ProcessSignal { process: String, signal: String },
    /// Report whether a process is running, its exit code, and log totals.
    /// An empty `process` lists every live process on the branch.
    ProcessStatus {
        #[serde(default)]
        process: String,
    },
    /// Read-only HTTP fetch through the egress proxy.
    HttpRead { url: String },
    /// Invoke an MCP tool through the gateway.
    McpInvoke {
        server: String,
        tool: String,
        arguments: serde_json::Value,
    },
    /// A typed connector operation that may produce an external effect
    /// (e.g. `github.create_pull_request`). Never executed inline: the kernel
    /// turns it into a proposed effect.
    ConnectorOp {
        connector: String,
        operation: String,
        params: serde_json::Value,
    },
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
            ActionKind::ProcessStart { .. } => Operation::new("proc.start"),
            ActionKind::ProcessStdin { .. } => Operation::new("proc.stdin"),
            ActionKind::ProcessLogs { .. } => Operation::new("proc.logs"),
            ActionKind::ProcessSignal { .. } => Operation::new("proc.signal"),
            ActionKind::ProcessStatus { .. } => Operation::new("proc.status"),
            ActionKind::HttpRead { .. } => Operation::new("net.http_read"),
            ActionKind::McpInvoke { .. } => Operation::new("mcp.invoke"),
            ActionKind::ConnectorOp {
                connector,
                operation,
                ..
            } => Operation::new(format!("{connector}.{operation}")),
            ActionKind::TraceQuery { .. } => Operation::new("trace.query"),
            ActionKind::BranchDiff { .. } => Operation::new("state.diff"),
        }
    }

    /// Canonical parameters used for constraint checking.
    pub fn params(&self) -> serde_json::Value {
        match self {
            ActionKind::Shell { command, cwd, .. } => {
                serde_json::json!({"command": command, "cwd": cwd})
            }
            ActionKind::ReadFile { path } | ActionKind::DeletePath { path } => {
                serde_json::json!({"path": path})
            }
            ActionKind::WriteFile { path, .. } => serde_json::json!({"path": path}),
            ActionKind::ProcessStart { command, cwd, .. } => {
                serde_json::json!({"command": command, "cwd": cwd})
            }
            ActionKind::ProcessStdin { process, .. }
            | ActionKind::ProcessLogs { process, .. }
            | ActionKind::ProcessStatus { process } => {
                serde_json::json!({"process": process})
            }
            ActionKind::ProcessSignal { process, signal } => {
                serde_json::json!({"process": process, "signal": signal})
            }
            ActionKind::HttpRead { url } => serde_json::json!({"url": url}),
            ActionKind::McpInvoke {
                server,
                tool,
                arguments,
            } => {
                serde_json::json!({"server": server, "tool": tool, "arguments": arguments})
            }
            ActionKind::ConnectorOp { params, .. } => params.clone(),
            ActionKind::TraceQuery { query } => serde_json::json!({"query": query}),
            ActionKind::BranchDiff { since } => serde_json::json!({"since": since}),
        }
    }
}

/// A fully-specified execution request from a principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub kind: ActionKind,
    /// Lease presented as authority for this action.
    pub lease: LeaseId,
    /// Free-text intent hint. Used ONLY for scheduling (prewarming, backend
    /// selection) and audit narration — never as an authorization input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_hint: Option<String>,
    /// Budget the caller is willing to spend on this action.
    pub budget: ResourceBudget,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_ops_map_to_namespaced_operations() {
        let a = ActionKind::ConnectorOp {
            connector: "github".into(),
            operation: "create_pull_request".into(),
            params: serde_json::json!({}),
        };
        assert_eq!(a.required_operation().0, "github.create_pull_request");
        assert_eq!(a.required_operation().namespace(), "github");
    }
}
