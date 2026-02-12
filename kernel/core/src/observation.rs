//! Structured observations returned to the agent after each step.
//!
//! Observations are budget-aware: raw logs stay in the ledger; the agent gets
//! a distilled, queryable summary that preserves its effective context window.

use crate::denial::Denial;
use crate::hash::ContentHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Observation {
    /// Successful execution with distilled output.
    Success {
        summary: String,
        /// Structured payload (e.g. parsed test results).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
        /// First `stdout_head_bytes` of stdout, if textual.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout_head: Option<String>,
        exit_code: i32,
        /// Full output is addressable in the ledger via this hash.
        full_output: ContentHash,
        truncated: bool,
    },
    /// Execution ran but failed; includes a causal hint when derivable.
    Failure {
        summary: String,
        exit_code: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_causal_failure: Option<String>,
        full_output: ContentHash,
    },
    /// The kernel refused the action. Always machine-readable.
    Denied { denial: Denial },
    /// An external effect was proposed and now awaits prepare/approval.
    EffectPending {
        effect: crate::ids::EffectId,
        contract_hash: ContentHash,
        class: crate::effect::EffectClass,
    },
    /// An external effect committed; the receipt is the proof.
    EffectCommitted { receipt: crate::ids::ReceiptId },
}

impl Observation {
    pub fn is_denial(&self) -> bool {
        matches!(self, Observation::Denied { .. })
    }
}

/// Distill raw process output into a bounded head + hash reference.
pub fn distill_output(raw: &[u8], head_limit: usize) -> (Option<String>, ContentHash, bool) {
    let hash = crate::hash::hash_bytes(raw);
    let truncated = raw.len() > head_limit;
    let head = String::from_utf8_lossy(&raw[..raw.len().min(head_limit)]).into_owned();
    (Some(head), hash, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distill_bounds_output_and_keeps_full_hash() {
        let raw = vec![b'x'; 10_000];
        let (head, hash, truncated) = distill_output(&raw, 512);
        assert_eq!(head.unwrap().len(), 512);
        assert!(truncated);
        assert_eq!(hash, crate::hash::hash_bytes(&raw));
    }
}
