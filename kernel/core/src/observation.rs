//! Structured observations returned to the agent after each step.
//!
//! Observations are budget-aware: raw logs stay in the ledger; the agent gets
//! a distilled, queryable summary that preserves its effective context window.
//! Distillation keeps the **head and the tail** of the output: compiler
//! errors, test summaries and package-manager hints usually live at the end,
//! not the beginning. The full blob is always addressable by content hash
//! (`GET /v1/raw/{hash}` in the HTTP protocol).

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
        /// Leading bytes of the output, if textual.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout_head: Option<String>,
        /// Trailing bytes of the output (only present when the middle was
        /// elided; test summaries and final errors live here).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout_tail: Option<String>,
        exit_code: i32,
        /// Full output is addressable in the ledger via this hash.
        full_output: ContentHash,
        truncated: bool,
    },
    /// Execution ran but failed; includes a causal hint when derivable.
    Failure {
        summary: String,
        exit_code: i32,
        /// Best-effort root-cause line extracted from stderr (error/panic/
        /// traceback markers scanned across the whole stream, not just the
        /// first line).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_causal_failure: Option<String>,
        /// Trailing bytes of combined output — where compilers and test
        /// runners put their summaries.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_tail: Option<String>,
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

    /// Exit code of an executed observation (None for denials/effects).
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Observation::Success { exit_code, .. } | Observation::Failure { exit_code, .. } => {
                Some(*exit_code)
            }
            _ => None,
        }
    }
}

/// Head + tail distillation of raw process output.
#[derive(Debug, Clone, PartialEq)]
pub struct DistilledOutput {
    /// Leading `head_limit` bytes (lossy UTF-8). `None` when the output is
    /// empty.
    pub head: Option<String>,
    /// Trailing `tail_limit` bytes, present only when the middle was elided.
    pub tail: Option<String>,
    pub hash: ContentHash,
    pub truncated: bool,
}

/// Distill raw output into bounded head + tail + full-content hash. When the
/// output fits within `head_limit` there is no tail; otherwise the head keeps
/// the first `head_limit` bytes and the tail the last `tail_limit` bytes.
pub fn distill_output(raw: &[u8], head_limit: usize, tail_limit: usize) -> DistilledOutput {
    let hash = crate::hash::hash_bytes(raw);
    if raw.is_empty() {
        return DistilledOutput {
            head: None,
            tail: None,
            hash,
            truncated: false,
        };
    }
    let truncated = raw.len() > head_limit;
    let head = String::from_utf8_lossy(&raw[..raw.len().min(head_limit)]).into_owned();
    let tail = if truncated && tail_limit > 0 {
        let start = raw.len().saturating_sub(tail_limit).max(head_limit);
        (start < raw.len()).then(|| String::from_utf8_lossy(&raw[start..]).into_owned())
    } else {
        None
    };
    DistilledOutput {
        head: Some(head),
        tail,
        hash,
        truncated,
    }
}

/// Line-prefix / substring markers that usually indicate the *causal* failure
/// line in tool output, ordered by specificity.
const CAUSAL_MARKERS: &[&str] = &[
    "panicked at",
    "error[",
    "error:",
    "Error:",
    "ERROR",
    "fatal:",
    "FAILED",
    "Traceback",
    "Exception",
    "assertion failed",
    "Segmentation fault",
    "command not found",
    "No such file or directory",
    "permission denied",
    "Permission denied",
];

/// Extract the most likely root-cause line from a failure stream. Scans the
/// whole stream for known failure markers (a compiler error can sit in the
/// middle, a test summary at the end); falls back to the first non-empty
/// line. Returned lines are trimmed and capped at 400 bytes.
pub fn extract_causal_failure(stream: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stream);
    let cap = |s: &str| {
        let t = s.trim();
        let mut end = t.len().min(400);
        while end > 0 && !t.is_char_boundary(end) {
            end -= 1;
        }
        t[..end].to_string()
    };
    for marker in CAUSAL_MARKERS {
        if let Some(line) = text.lines().find(|l| l.contains(marker)) {
            return Some(cap(line));
        }
    }
    text.lines().find(|l| !l.trim().is_empty()).map(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distill_bounds_output_and_keeps_full_hash() {
        let raw = vec![b'x'; 10_000];
        let d = distill_output(&raw, 512, 256);
        assert_eq!(d.head.unwrap().len(), 512);
        assert_eq!(d.tail.unwrap().len(), 256);
        assert!(d.truncated);
        assert_eq!(d.hash, crate::hash::hash_bytes(&raw));
    }

    #[test]
    fn distill_small_output_has_no_tail() {
        let d = distill_output(b"hello", 512, 256);
        assert_eq!(d.head.as_deref(), Some("hello"));
        assert!(d.tail.is_none());
        assert!(!d.truncated);
    }

    #[test]
    fn distill_empty_output() {
        let d = distill_output(b"", 512, 256);
        assert!(d.head.is_none());
        assert!(d.tail.is_none());
        assert!(!d.truncated);
    }

    #[test]
    fn distill_head_and_tail_never_overlap() {
        // 600 bytes, head 512, tail 256: tail must start at 512, not 344.
        let raw: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let d = distill_output(&raw, 512, 256);
        assert_eq!(d.tail.unwrap().len(), 88);
    }

    #[test]
    fn causal_failure_finds_mid_stream_errors() {
        let out = b"Compiling foo v0.1.0\nwarning: unused import\nerror[E0308]: mismatched types\n --> src/main.rs:3:5\nsome trailing noise";
        assert_eq!(
            extract_causal_failure(out).unwrap(),
            "error[E0308]: mismatched types"
        );
    }

    #[test]
    fn causal_failure_falls_back_to_first_nonempty_line() {
        assert_eq!(
            extract_causal_failure(b"\n\nsomething odd happened\nmore").unwrap(),
            "something odd happened"
        );
        assert!(extract_causal_failure(b"").is_none());
        assert!(extract_causal_failure(b"\n \n").is_none());
    }

    #[test]
    fn causal_failure_caps_long_lines_on_char_boundary() {
        let mut line = "error: ".to_string();
        line.push_str(&"é".repeat(400));
        let got = extract_causal_failure(line.as_bytes()).unwrap();
        assert!(got.len() <= 400);
        assert!(got.starts_with("error: "));
    }
}
