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

impl ResourceBudget {
    pub const fn zero() -> Self {
        Self { cpu_ms: 0, memory_bytes: 0, network_bytes: 0, tokens: 0, cost_micro_usd: 0, risk_units: 0 }
    }

    /// A generous default envelope for a single local step.
    pub fn step_default() -> Self {
        Self {
            cpu_ms: 60_000,
            memory_bytes: 2 << 30,
            network_bytes: 256 << 20,
            tokens: 200_000,
            cost_micro_usd: 0,
            risk_units: 10,
        }
    }

    /// True when `self` is dimension-wise `<=` `outer` (attenuation check).
    pub fn fits_within(&self, outer: &ResourceBudget) -> bool {
        self.cpu_ms <= outer.cpu_ms
            && self.memory_bytes <= outer.memory_bytes
            && self.network_bytes <= outer.network_bytes
            && self.tokens <= outer.tokens
            && self.cost_micro_usd <= outer.cost_micro_usd
            && self.risk_units <= outer.risk_units
    }

    /// Subtract `usage`, saturating; returns the dimensions that were
    /// exhausted (empty when the charge fit).
    pub fn charge(&mut self, usage: &ResourceBudget) -> Vec<&'static str> {
        let mut exhausted = Vec::new();
        macro_rules! dim {
            ($field:ident, $name:literal) => {
                if usage.$field > self.$field {
                    exhausted.push($name);
                    self.$field = 0;
                } else {
                    self.$field -= usage.$field;
                }
            };
        }
        dim!(cpu_ms, "cpu_ms");
        dim!(memory_bytes, "memory_bytes");
        dim!(network_bytes, "network_bytes");
        dim!(tokens, "tokens");
        dim!(cost_micro_usd, "cost_micro_usd");
        dim!(risk_units, "risk_units");
        exhausted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_reports_exhausted_dimensions() {
        let mut b = ResourceBudget { cpu_ms: 100, tokens: 10, ..ResourceBudget::zero() };
        let over = ResourceBudget { cpu_ms: 50, tokens: 20, ..ResourceBudget::zero() };
        assert_eq!(b.charge(&over), vec!["tokens"]);
        assert_eq!(b.cpu_ms, 50);
        assert_eq!(b.tokens, 0);
    }

    #[test]
    fn fits_within_is_dimension_wise() {
        let outer = ResourceBudget::step_default();
        let mut inner = ResourceBudget::zero();
        assert!(inner.fits_within(&outer));
        inner.risk_units = 11;
        assert!(!inner.fits_within(&outer));
    }
}
