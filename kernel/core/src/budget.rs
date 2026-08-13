//! Unified resource accounting: CPU, memory, network, tokens, money and risk
//! share one budget model, charged at step boundaries.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

    /// Names of the dimensions where `self` exceeds `outer` (empty when
    /// [`ResourceBudget::fits_within`] holds). Used to produce precise,
    /// machine-readable budget denials.
    pub fn exceeding_dimensions(&self, outer: &ResourceBudget) -> Vec<&'static str> {
        let mut over = Vec::new();
        macro_rules! dim {
            ($field:ident, $name:literal) => {
                if self.$field > outer.$field {
                    over.push($name);
                }
            };
        }
        dim!(cpu_ms, "cpu_ms");
        dim!(memory_bytes, "memory_bytes");
        dim!(network_bytes, "network_bytes");
        dim!(tokens, "tokens");
        dim!(cost_micro_usd, "cost_micro_usd");
        dim!(risk_units, "risk_units");
        over
    }

    /// Dimension-wise saturating subtraction (`self - other`, floored at 0).
    pub fn saturating_sub(&self, other: &ResourceBudget) -> ResourceBudget {
        ResourceBudget {
            cpu_ms: self.cpu_ms.saturating_sub(other.cpu_ms),
            memory_bytes: self.memory_bytes.saturating_sub(other.memory_bytes),
            network_bytes: self.network_bytes.saturating_sub(other.network_bytes),
            tokens: self.tokens.saturating_sub(other.tokens),
            cost_micro_usd: self.cost_micro_usd.saturating_sub(other.cost_micro_usd),
            risk_units: self.risk_units.saturating_sub(other.risk_units),
        }
    }

    /// Dimension-wise saturating addition.
    pub fn saturating_add(&self, other: &ResourceBudget) -> ResourceBudget {
        ResourceBudget {
            cpu_ms: self.cpu_ms.saturating_add(other.cpu_ms),
            memory_bytes: self.memory_bytes.saturating_add(other.memory_bytes),
            network_bytes: self.network_bytes.saturating_add(other.network_bytes),
            tokens: self.tokens.saturating_add(other.tokens),
            cost_micro_usd: self.cost_micro_usd.saturating_add(other.cost_micro_usd),
            risk_units: self.risk_units.saturating_add(other.risk_units),
        }
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
        assert_eq!(inner.exceeding_dimensions(&outer), vec!["risk_units"]);
    }

    #[test]
    fn saturating_arithmetic_never_wraps() {
        let a = ResourceBudget { cpu_ms: 10, tokens: 5, ..ResourceBudget::zero() };
        let b = ResourceBudget { cpu_ms: 25, tokens: 2, ..ResourceBudget::zero() };
        let diff = a.saturating_sub(&b);
        assert_eq!(diff.cpu_ms, 0);
        assert_eq!(diff.tokens, 3);
        let sum = a.saturating_add(&b);
        assert_eq!(sum.cpu_ms, 35);
        assert_eq!(sum.tokens, 7);
        let max = ResourceBudget { cpu_ms: u64::MAX, ..ResourceBudget::zero() };
        assert_eq!(max.saturating_add(&max).cpu_ms, u64::MAX);
    }
}
