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

use ak_core::effect::{EffectClass, EffectContract};
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelError, KernelResult};
use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument};

fn conn_err(msg: impl std::fmt::Display) -> KernelError {
    KernelError::Connector(msg.to_string())
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Constraint on a single tool parameter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    /// Must the parameter be present?
    #[serde(default)]
    pub required: bool,
    /// Required JSON type: `string` | `number` | `boolean` | `object` | `array`.
    #[serde(default)]
    pub r#type: Option<String>,
    /// Closed set of allowed values.
    #[serde(default)]
    pub one_of: Option<Vec<Value>>,
    /// Maximum length for string values.
    #[serde(default)]
    pub max_len: Option<usize>,
}

/// Declared semantics of one tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    /// The declared effect class the manifest signer vouches for.
    pub class: EffectClass,
    /// Per-parameter constraints. Parameters not listed here are rejected
    /// unless `allow_extra_params` is set.
    #[serde(default)]
    pub params: BTreeMap<String, ParamSpec>,
    #[serde(default)]
    pub allow_extra_params: bool,
}

/// A manifest mapping tool names to declared semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub tools: BTreeMap<String, ToolSpec>,
}

/// A YAML manifest plus an Ed25519 signature over the exact YAML bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The manifest document, verbatim (signature covers these bytes).
    pub manifest_yaml: String,
    /// Hex-encoded Ed25519 signature.
    pub signature: String,
    /// Identifier of the signing key (informational).
    pub key_id: String,
}

impl SignedManifest {
    /// Verify the signature against `public_key` (32-byte hex) and parse the
    /// manifest. Verification failure or YAML errors refuse the manifest.
    pub fn verify_and_parse(&self, public_key_hex: &str) -> KernelResult<Manifest> {
        let key_bytes: [u8; 32] = hex::decode(public_key_hex)
            .map_err(|e| conn_err(format!("bad manifest public key hex: {e}")))?
            .try_into()
            .map_err(|_| conn_err("manifest public key must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| conn_err(format!("bad manifest public key: {e}")))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|e| conn_err(format!("bad manifest signature hex: {e}")))?
            .try_into()
            .map_err(|_| conn_err("manifest signature must be 64 bytes"))?;
        key.verify(self.manifest_yaml.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| conn_err("manifest signature verification failed"))?;
        serde_yaml::from_str(&self.manifest_yaml)
            .map_err(|e| conn_err(format!("manifest yaml invalid: {e}")))
    }
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl ToolSpec {
    /// Enforce the parameter constraints against `args`.
    pub fn enforce(&self, tool: &str, args: &Value) -> KernelResult<()> {
        let obj = args
            .as_object()
            .ok_or_else(|| conn_err(format!("tool `{tool}`: arguments must be an object")))?;
        for (key, value) in obj {
            let Some(spec) = self.params.get(key) else {
                if self.allow_extra_params {
                    continue;
                }
                return Err(conn_err(format!(
                    "tool `{tool}`: parameter `{key}` is not declared in the manifest"
                )));
            };
            if let Some(t) = &spec.r#type {
                if json_type_name(value) != t {
                    return Err(conn_err(format!(
                        "tool `{tool}`: parameter `{key}` must be of type {t}"
                    )));
                }
            }
            if let Some(allowed) = &spec.one_of {
                if !allowed.contains(value) {
                    return Err(conn_err(format!(
                        "tool `{tool}`: parameter `{key}` value is not in the allowed set"
                    )));
                }
            }
            if let (Some(max), Some(s)) = (spec.max_len, value.as_str()) {
                if s.len() > max {
                    return Err(conn_err(format!(
                        "tool `{tool}`: parameter `{key}` exceeds max length {max}"
                    )));
                }
            }
        }
        for (key, spec) in &self.params {
            if spec.required && !obj.contains_key(key) {
                return Err(conn_err(format!(
                    "tool `{tool}`: required parameter `{key}` is missing"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC transport
// ---------------------------------------------------------------------------

struct Transport {
    reader: BufReader<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    next_id: u64,
    /// Keeps the child process alive (and killed on drop) when spawned.
    _child: Option<tokio::process::Child>,
}

impl Transport {
    async fn call(&mut self, method: &str, params: Value) -> KernelResult<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut line = serde_json::to_string(&request)?;
        line.push('\n');
        debug!(method, id, "mcp request");
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        loop {
            let mut buf = String::new();
            let n = self.reader.read_line(&mut buf).await?;
            if n == 0 {
                return Err(conn_err("mcp server closed the stream"));
            }
            let trimmed = buf.trim();
            if trimmed.is_empty() {
                continue;
            }
            let msg: Value = serde_json::from_str(trimmed)?;
            // Skip notifications / unrelated ids.
            if msg.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = msg.get("error") {
                return Err(conn_err(format!("mcp server error: {err}")));
            }
            return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

/// A gateway to one MCP server process. Implements [`Connector`] with
/// operations named `<server_name>.<tool>`.
pub struct McpGateway {
    server_name: String,
    manifest: Option<Manifest>,
    transport: Mutex<Transport>,
}

impl std::fmt::Debug for McpGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpGateway").field("server", &self.server_name).finish_non_exhaustive()
    }
}

impl McpGateway {
    /// Spawn `command args…` as a child MCP server speaking newline-delimited
    /// JSON-RPC on its stdio. If `manifest` is provided it must verify
    /// against `manifest_public_key_hex`.
    #[instrument(skip(manifest))]
    pub fn spawn(
        server_name: &str,
        command: &str,
        args: &[&str],
        manifest: Option<(&SignedManifest, &str)>,
    ) -> KernelResult<Self> {
        let manifest = Self::check_manifest(manifest)?;
        let mut child = tokio::process::Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| conn_err("child stdin unavailable"))?;
        let stdout = child.stdout.take().ok_or_else(|| conn_err("child stdout unavailable"))?;
        info!(server = server_name, command, "spawned mcp server");
        Ok(Self {
            server_name: server_name.to_string(),
            manifest,
            transport: Mutex::new(Transport {
                reader: BufReader::new(Box::new(stdout)),
                writer: Box::new(stdin),
                next_id: 0,
                _child: Some(child),
            }),
        })
    }

    /// Build a gateway over arbitrary streams (tests: `tokio::io::duplex`).
    pub fn from_streams(
        server_name: &str,
        reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
        manifest: Option<(&SignedManifest, &str)>,
    ) -> KernelResult<Self> {
        let manifest = Self::check_manifest(manifest)?;
        Ok(Self {
            server_name: server_name.to_string(),
            manifest,
            transport: Mutex::new(Transport {
                reader: BufReader::new(Box::new(reader)),
                writer: Box::new(writer),
                next_id: 0,
                _child: None,
            }),
        })
    }

    fn check_manifest(
        manifest: Option<(&SignedManifest, &str)>,
    ) -> KernelResult<Option<Manifest>> {
        manifest.map(|(m, key)| m.verify_and_parse(key)).transpose()
    }

    /// The declared effect class of `tool`: from the verified manifest, else
    /// the [`EffectClass::OpaqueExternal`] default.
    pub fn effect_class(&self, tool: &str) -> EffectClass {
        self.manifest
            .as_ref()
            .and_then(|m| m.tools.get(tool))
            .map(|t| t.class)
            .unwrap_or(EffectClass::OpaqueExternal)
    }

    fn tool_of(&self, operation: &str) -> KernelResult<String> {
        operation
            .strip_prefix(&format!("{}.", self.server_name))
            .map(str::to_string)
            .ok_or_else(|| {
                conn_err(format!(
                    "operation `{operation}` does not belong to mcp server `{}`",
                    self.server_name
                ))
            })
    }

    /// `tools/list` against the live server.
    pub async fn list_tools(&self) -> KernelResult<Vec<Value>> {
        let mut t = self.transport.lock().await;
        let result = t.call("tools/list", json!({})).await?;
        Ok(result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// `tools/call` against the live server.
    async fn call_tool(&self, tool: &str, arguments: &Value) -> KernelResult<Value> {
        let mut t = self.transport.lock().await;
        t.call("tools/call", json!({ "name": tool, "arguments": arguments })).await
    }
}

#[async_trait]
impl Connector for McpGateway {
    fn name(&self) -> &str {
        &self.server_name
    }

    /// Only manifest-declared tools are advertised with their vouched class.
    /// Undeclared tools remain callable but always classify as
    /// `OpaqueExternal`.
    fn operations(&self) -> Vec<(String, EffectClass)> {
        self.manifest
            .as_ref()
            .map(|m| {
                m.tools
                    .iter()
                    .map(|(tool, spec)| (format!("{}.{}", self.server_name, tool), spec.class))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Enforces manifest parameter constraints *before* anything reaches the
    /// server process.
    #[instrument(skip(self, args))]
    fn canonicalize(&self, operation: &str, args: &Value) -> KernelResult<Value> {
        let tool = self.tool_of(operation)?;
        if !args.is_object() {
            return Err(conn_err("arguments must be a JSON object"));
        }
        if let Some(manifest) = &self.manifest {
            if let Some(spec) = manifest.tools.get(&tool) {
                spec.enforce(&tool, args)?;
            }
        }
        // serde_json objects are BTreeMaps: re-encoding is key-sorted.
        Ok(args.clone())
    }

    /// Dry-run: confirm the tool exists via `tools/list`; no `tools/call` is
    /// issued (an MCP call may side-effect, so prepare never forwards one).
    #[instrument(skip(self, contract), fields(operation = %contract.operation))]
    async fn prepare(&self, contract: &EffectContract) -> KernelResult<PreparedEffect> {
        let tool = self.tool_of(&contract.operation)?;
        let tools = self.list_tools().await?;
        let listed = tools
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some(tool.as_str()));
        if !listed {
            return Err(conn_err(format!("mcp server does not expose tool `{tool}`")));
        }
        let class = self.effect_class(&tool);
        Ok(PreparedEffect {
            preview: json!({
                "server": self.server_name,
                "tool": tool,
                "arguments": contract.arguments,
                "declared_class": class,
                "manifest_backed": self.manifest.as_ref().map(|m| m.tools.contains_key(&tool)).unwrap_or(false),
            }),
            observed_preconditions: json!({ "tool_listed": true }),
        })
    }

    #[instrument(skip(self, contract), fields(operation = %contract.operation))]
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        let tool = self.tool_of(&contract.operation)?;
        // Re-enforce constraints at the boundary, even if canonicalize was
        // bypassed upstream.
        if let Some(spec) = self.manifest.as_ref().and_then(|m| m.tools.get(&tool)) {
            spec.enforce(&tool, &contract.arguments)?;
        }
        let response = self.call_tool(&tool, &contract.arguments).await?;
        Ok(CommitResult { response })
    }
}

#[cfg(test)]
mod tests;
