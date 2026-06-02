//! `agent-kernel-server`: serve the AgentKernel JSON API over HTTP.

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let config: KernelConfig = match &args.config {
        Some(path) => serde_yaml::from_str(&std::fs::read_to_string(path)?)?,
        None => KernelConfig::new("agent-kernel-data"),
    };
    let kernel = Arc::new(Kernel::open(config)?);
    let app = http::router(kernel);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(listen = %args.listen, "agent-kernel-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
