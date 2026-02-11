//! Strongly-typed identifiers for every object in the world-state DAG.
//!
//! All IDs are newtype wrappers over UUID-or-content-hash strings so that they
//! cannot be confused with one another at compile time and serialize as plain
//! strings on the wire.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// Create a new random identifier with the canonical prefix.
            pub fn generate() -> Self {
                Self(format!("{}-{}", $prefix, uuid::Uuid::new_v4()))
            }

            /// Wrap an existing identifier string, validating its prefix.
            pub fn parse(s: &str) -> Result<Self, crate::error::KernelError> {
                if s.starts_with(concat!($prefix, "-")) {
                    Ok(Self(s.to_string()))
                } else {
                    Err(crate::error::KernelError::InvalidId {
                        expected_prefix: $prefix,
                        got: s.to_string(),
                    })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(
    /// A long-running task: the root of a state DAG.
    EpisodeId, "ep"
);
id_type!(
    /// One decision-and-execution unit inside an episode.
    StepId, "step"
);
id_type!(
    /// A speculative world branch forked from a state node.
    BranchId, "br"
);
id_type!(
    /// A content-addressed, immutable world-state node.
    StateId, "st"
);
id_type!(
    /// An agent, sub-agent, tool or human identity.
    PrincipalId, "pr"
);
id_type!(
    /// A capability lease grant.
    LeaseId, "lease"
);
id_type!(
    /// A proposed-but-uncommitted external effect.
    EffectId, "fx"
);
id_type!(
    /// A signed receipt for a committed external effect.
    ReceiptId, "rcpt"
);

pub use self::{EffectId as PendingEffectId, ReceiptId as CommittedReceiptId};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_round_trip_and_validate_prefix() {
        let ep = EpisodeId::generate();
        assert!(ep.as_str().starts_with("ep-"));
        assert_eq!(EpisodeId::parse(ep.as_str()).unwrap(), ep);
        assert!(EpisodeId::parse("st-123").is_err());
    }
}
