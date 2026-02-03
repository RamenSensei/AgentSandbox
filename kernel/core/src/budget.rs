//! Unified resource accounting: CPU, memory, network, tokens, money and risk
//! share one budget model, charged at step boundaries.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// CPU milliseconds.
    pub cpu_ms: u64,
    /// Peak resident memory, bytes.
    pub memory_bytes: u64,
    /// Network egress, bytes.
    pub network_bytes: u64,
    /// LLM tokens (context budget is a sandbox resource too).
    pub tokens: u64,
    /// Money, micro-USD.
    pub cost_micro_usd: u64,
    /// Abstract risk units consumed by high-risk operations.
    pub risk_units: u32,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self { cpu_ms: 0, memory_bytes: 0, network_bytes: 0, tokens: 0, cost_micro_usd: 0, risk_units: 0 }
    }
}
