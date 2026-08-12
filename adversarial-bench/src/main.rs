//! CLI: run every adversarial scenario, print a summary, optionally write a
//! JSON report, exit non-zero when any scenario fails.

use ak_adversarial_bench::run_all_scenarios;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ak-adversarial-bench",
    about = "AgentKernel security/abuse scenario benchmark"
)]
struct Args {
    /// Write the JSON report ([{scenario, passed, detail}, ...]) here.
    #[arg(long)]
    report: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let results = run_all_scenarios().await?;

    println!("agent-kernel adversarial benchmark");
    println!("==================================");
    for r in &results {
        let mark = if r.passed { "PASS" } else { "FAIL" };
        println!("[{mark}] {:<38} {}", r.scenario, r.detail);
    }
    let failed = results.iter().filter(|r| !r.passed).count();
    println!(
        "----------------------------------\n{}/{} scenarios passed",
        results.len() - failed,
        results.len()
    );

    if let Some(path) = &args.report {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(&results)?)?;
        println!("report written to {}", path.display());
    }

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}
