//! # ak-connector-mcp
//!
//! An MCP (Model Context Protocol) **gateway** connector: it speaks JSON-RPC
//! 2.0 over stdio (newline-delimited) to a child MCP server process and
//! surfaces its tools as kernel effect operations named `<server>.<tool>`.
//!
//! ## Trust model
//!
//! - Every MCP tool defaults to [`EffectClass::OpaqueExternal`]: the kernel
//!   has no idea what an arbitrary tool does, so it is treated as
//!   irreversible and maximally restricted (explicit approval required).
//! - A **signed manifest** ([`SignedManifest`], YAML, Ed25519-signed) may
//!   declare a per-tool effect class and parameter constraints. Constraints
//!   are enforced in [`Connector::canonicalize`] *before* anything is
//!   forwarded to the server.
//! - **Per-server principal identity:** each MCP server should be registered
//!   in the kernel as its own tool [`ak_core::Principal`] (kind `Tool`, low
//!   trust), so that leases, budgets and receipts attribute effects to the
//!   specific server binary — never to the agent that happens to call it.
//!   Use a distinct [`McpGateway`] (with a distinct `server_name`) per
//!   server process; never multiplex two servers behind one principal.
