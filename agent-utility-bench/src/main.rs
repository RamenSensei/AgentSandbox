//! CLI: run every enablement scenario, print a table, optionally write a
//! JSON report, and exit non-zero when any scenario fails its criterion.

use ak_agent_utility_bench::run_all;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ak-agent-utility-bench",
    about = "AgentKernel agent-enablement (utility) benchmark"
)]
struct Args {
    /// Write the JSON report (per-scenario metrics + summary) here.
    #[arg(long)]
    report: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let report = run_all().await?;

    println!("agent-kernel utility (enablement) benchmark");
    println!("===========================================");
    for s in &report.scenarios {
        let mark = if s.skipped {
            "SKIP"
        } else if s.success {
            "PASS"
        } else {
            "FAIL"
        };
        println!("[{mark}] {:<24} {}", s.scenario, s.note);
        if !s.metrics.is_null() {
            println!("       metrics: {}", s.metrics);
        }
    }
    println!("-------------------------------------------");
    println!(
        "overall_success={} autonomous_recovery_rate={:.2} total_wall_ms={}",
        report.summary.overall_success,
        report.summary.autonomous_recovery_rate,
        report.summary.total_wall_ms
    );

    if let Some(path) = &args.report {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
        println!("report written to {}", path.display());
    }

    if !report.summary.overall_success {
        std::process::exit(1);
    }
    Ok(())
}
