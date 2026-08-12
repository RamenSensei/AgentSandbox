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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let config: KernelConfig = match &args.config {
        Some(path) => serde_yaml::from_str(&std::fs::read_to_string(path)?)?,
        None => KernelConfig::new("agent-kernel-data"),
    };
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
