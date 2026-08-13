//! `agent-kernel-server`: serve the AgentKernel JSON API over HTTP.

use ak_api::auth::AuthConfig;
use ak_api::{http, Kernel, KernelConfig};
use clap::Parser;
use std::sync::Arc;

/// The AgentKernel API server.
#[derive(Parser, Debug)]
#[command(name = "agent-kernel-server", version)]
struct Args {
    /// Path to a YAML kernel config (`data_dir`, `policy_file`,
    /// `workspace_root`, …). When omitted, `./agent-kernel-data` is used.
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:7466")]
    listen: String,

    /// Path to a YAML auth config (`enabled`, `tokens: [{token_sha256,
    /// principal, roles}]`). Required for non-loopback listen addresses.
    #[arg(long)]
    auth_config: Option<std::path::PathBuf>,

    /// Explicitly allow serving without authentication on a loopback
    /// address (local development only).
    #[arg(long)]
    insecure_no_auth: bool,

    /// Enable the built-in HTTP observation plane with these read-safe
    /// domains (repeatable; `*`-globs allowed, e.g. `--http-read-safe
    /// docs.rs --http-read-safe '*.wikipedia.org'`). GETs to these domains
    /// execute inline; every other target requires the effect approval path.
    /// Merged with any `http` block in the config file.
    #[arg(long = "http-read-safe")]
    http_read_safe: Vec<String>,

    /// Spawn a confined MCP server at startup and register it as a
    /// connector (repeatable). Format: `name=command [args…]`
    /// (whitespace-split; use the config file's `mcp` block for env,
    /// manifest and advanced options). Servers run inside the verified OS
    /// sandbox with a scrubbed environment and no network; hosts without a
    /// verified sandbox refuse to start them.
    #[arg(long = "mcp-server")]
    mcp_server: Vec<String>,

    /// Register a remote isolation backend (repeatable). Format:
    /// `kind=endpoint` with kind one of `gvisor`, `forkd`, `cube` (use the
    /// config file's `backends` block for kubernetes, which requires an
    /// operator-declared isolation strength). Auth tokens come from
    /// `GVISOR_API_TOKEN` / `FORKD_API_TOKEN` / `CUBE_API_TOKEN`.
    #[arg(long = "backend")]
    backend: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let mut config: KernelConfig = match &args.config {
        Some(path) => serde_yaml::from_str(&std::fs::read_to_string(path)?)?,
        None => KernelConfig::new("agent-kernel-data"),
    };
    if !args.http_read_safe.is_empty() {
        let http = config.http.get_or_insert_with(Default::default);
        http.read_safe_domains
            .extend(args.http_read_safe.iter().cloned());
    }
    for spec in &args.mcp_server {
        let Some((name, cmdline)) = spec.split_once('=') else {
            anyhow::bail!("--mcp-server expects `name=command [args…]`, got `{spec}`");
        };
        let mut parts = cmdline.split_whitespace();
        let Some(command) = parts.next() else {
            anyhow::bail!("--mcp-server {name}: empty command");
        };
        config.mcp.push(ak_api::McpServerSetup {
            name: name.trim().to_string(),
            command: command.to_string(),
            args: parts.map(str::to_string).collect(),
            manifest_file: None,
            manifest_public_key_hex: None,
            env: Default::default(),
            dangerously_allow_unsandboxed: false,
        });
    }
    for spec in &args.backend {
        let Some((kind, endpoint)) = spec.split_once('=') else {
            anyhow::bail!("--backend expects `kind=endpoint`, got `{spec}`");
        };
        let endpoint = endpoint.trim().to_string();
        config.backends.push(match kind.trim() {
            "gvisor" => ak_api::BackendSetup::Gvisor {
                endpoint,
                image: None,
            },
            "forkd" => ak_api::BackendSetup::Forkd { endpoint },
            "cube" => ak_api::BackendSetup::Cube { endpoint },
            other => anyhow::bail!(
                "--backend kind `{other}` is not supported on the CLI; use the config \
                 file's `backends` block (kinds: gvisor, forkd, cube, kubernetes)"
            ),
        });
    }
    let auth = match &args.auth_config {
        Some(path) => AuthConfig::from_yaml_file(path).map_err(|e| anyhow::anyhow!("{e}"))?,
        None => AuthConfig::disabled(),
    };
    let addr: std::net::SocketAddr = args.listen.parse()?;
    if !auth.enabled {
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "refusing to listen on non-loopback {} without --auth-config; unauthenticated mode is loopback-only",
                args.listen
            );
        }
        if !args.insecure_no_auth {
            anyhow::bail!(
                "no --auth-config given; pass --insecure-no-auth to explicitly accept an unauthenticated loopback control plane"
            );
        }
        tracing::warn!("serving WITHOUT authentication (loopback only)");
    }
    let kernel = Arc::new(Kernel::open(config)?);
    let app = http::router_with_auth(kernel, auth);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(listen = %args.listen, "agent-kernel-server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received, draining connections");
        })
        .await?;
    Ok(())
}
