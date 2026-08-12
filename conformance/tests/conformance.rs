//! Runs every YAML case in `conformance/cases/` against the kernel façade.

use ak_conformance::{load_cases, run_case};

#[tokio::test]
async fn all_conformance_cases_pass() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("cases");
    let cases = load_cases(&dir).expect("cases load");
    assert!(
        cases.len() >= 15,
        "expected at least 15 cases, found {}",
        cases.len()
    );
    let mut failures = Vec::new();
    for case in &cases {
        match run_case(case).await {
            Ok(()) => println!("PASS  {}", case.name),
            Err(e) => {
                println!("FAIL  {} — {e}", case.name);
                failures.push(format!("{}: {e}", case.name));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "conformance failures:\n{}",
        failures.join("\n")
    );
}
