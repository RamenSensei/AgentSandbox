//! The deterministic [`PolicyEngine`].

use crate::compiler::{compile_grant, CompiledGrant};
use crate::document::{PolicyDocument, RuleEffect};
use ak_core::capability::{glob_match, Operation};
use ak_core::denial::{Denial, DenialCode, RequestableScope};
use ak_core::ids::BranchId;
use ak_core::principal::Principal;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum Decision {
    /// The operation is allowed. Carries the compiled lease + confinement,
    /// ready for the scheduler.
    Allow {
        /// Id of the rule that granted.
        rule_id: String,
        /// Compiled grant (lease + backend confinement).
        grant: CompiledGrant,
    },
    /// The operation is allowed only with out-of-band approval. The caller
    /// should surface the sketch to an approver, then call
    /// [`crate::compile_grant`] with the approved rule.
    RequireApproval {
        /// Id of the rule that requires approval.
        rule_id: String,
        /// The operation awaiting approval.
        operation: Operation,
        /// The constraint sketch the approver is signing off on.
        constraints: serde_json::Value,
        /// Policy epoch at evaluation time; approvals are pinned to it.
        policy_epoch: u64,
    },
    /// The operation is denied. The [`Denial`] is already redacted for the
    /// requesting principal's trust level.
    Deny {
        /// Machine-readable, trust-redacted denial.
        denial: Denial,
    },
}

/// Deterministic policy evaluation over a [`PolicyDocument`].
///
/// # Determinism invariant
///
/// `evaluate` takes exactly five inputs: the principal, the canonical
/// operation, the canonical parameters, the branch, and the clock. **LLM
/// intent hints ([`ak_core::action::Action::intent_hint`]) are deliberately
/// not an input** — free text can steer scheduling and audit narration, but
/// it must never change an authorization outcome. Given the same document and
/// the same five inputs, `evaluate` always returns the same [`Decision`].
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    doc: PolicyDocument,
}

impl PolicyEngine {
    /// Build an engine over a policy document.
    pub fn new(doc: PolicyDocument) -> Self {
        Self { doc }
    }

    /// The document this engine evaluates against.
    pub fn document(&self) -> &PolicyDocument {
        &self.doc
    }

    /// Mutable access to the document (mutations bump its epoch through the
    /// document's own setters).
    pub fn document_mut(&mut self) -> &mut PolicyDocument {
        &mut self.doc
    }

    /// Evaluate whether `principal` may invoke `operation` with `params` on
    /// `branch` at time `now`.
    ///
    /// Rules are scanned in document order; the first rule whose principal
    /// selector and operation glob match decides:
    ///
    /// - [`RuleEffect::Deny`] → [`Decision::Deny`] with
    ///   [`DenialCode::PolicyForbidden`];
    /// - [`RuleEffect::RequireApproval`] → [`Decision::RequireApproval`];
    /// - [`RuleEffect::Allow`] → the rule's constraints are checked against
    ///   `params`; a violation yields [`DenialCode::ConstraintViolated`],
    ///   otherwise the grant is compiled and allowed.
    ///
    /// No matching rule denies with [`DenialCode::PolicyForbidden`]
    /// (default-deny). Denials are redacted via [`Denial::redact_for`] using
    /// the principal's trust, and never contain host paths or the policy map —
    /// only the attempted operation, safe alternatives the principal already
    /// has, and (for sufficiently trusted principals) requestable scopes.
    pub fn evaluate(
        &self,
        principal: &Principal,
        operation: &Operation,
        params: &serde_json::Value,
        branch: Option<&BranchId>,
        now: DateTime<Utc>,
    ) -> Decision {
        for rule in &self.doc.rules {
            if !rule.principals.matches(principal) || !rule.matches_operation(&operation.0) {
                continue;
            }
            match rule.effect {
                RuleEffect::Deny => {
                    return self.deny(
                        principal,
                        operation,
                        DenialCode::PolicyForbidden,
                        "this operation is explicitly forbidden for this principal".into(),
                    );
                }
                RuleEffect::RequireApproval => {
                    return Decision::RequireApproval {
                        rule_id: rule.id.clone(),
                        operation: operation.clone(),
                        constraints: serde_json::to_value(&rule.constraints)
                            .unwrap_or(serde_json::Value::Null),
                        policy_epoch: self.doc.policy_epoch,
                    };
                }
                RuleEffect::Allow => {
                    for (param, constraint) in &rule.constraints {
                        if !constraint.allows(params.get(param)) {
                            return self.deny(
                                principal,
                                operation,
                                DenialCode::ConstraintViolated,
                                format!(
                                    "parameter `{param}` violates the constraint on this operation"
                                ),
                            );
                        }
                    }
                    match compile_grant(
                        &self.doc,
                        principal,
                        operation,
                        rule,
                        &IndexMap::new(),
                        branch.cloned(),
                        now,
                    ) {
                        Ok(grant) => {
                            return Decision::Allow { rule_id: rule.id.clone(), grant }
                        }
                        Err(_) => {
                            // A rule that matched but failed to compile is a
                            // policy bug; fail closed.
                            return self.deny(
                                principal,
                                operation,
                                DenialCode::PolicyForbidden,
                                "the matching grant could not be compiled".into(),
                            );
                        }
                    }
                }
            }
        }
        self.deny(
            principal,
            operation,
            DenialCode::CapabilityDenied,
            "no policy rule grants this operation to this principal".into(),
        )
    }

    /// Build a redacted, machine-readable denial.
    fn deny(
        &self,
        principal: &Principal,
        operation: &Operation,
        code: DenialCode,
        reason: String,
    ) -> Decision {
        let denial = Denial {
            code,
            attempted_operation: operation.clone(),
            reason,
            safe_alternatives: self.safe_alternatives(principal, operation),
            requestable_scopes: self.requestable_scopes(operation),
            escalation_allowed: self.doc.escalation.allow_requests,
        };
        Decision::Deny { denial: denial.redact_for(principal.trust) }
    }

    /// Operations (from *allow* rules matching this principal) the principal
    /// could use instead of `attempted`. Glob patterns are reported verbatim
    /// as operations — they leak only what the principal is already granted.
    fn safe_alternatives(&self, principal: &Principal, attempted: &Operation) -> Vec<Operation> {
        let mut out = Vec::new();
        for rule in &self.doc.rules {
            if rule.effect != RuleEffect::Allow || !rule.principals.matches(principal) {
                continue;
            }
            for glob in &rule.operations {
                let op = Operation::new(glob.clone());
                if glob != &attempted.0 && !out.contains(&op) {
                    out.push(op);
                }
            }
        }
        out
    }

    /// Escalation scopes relevant to `attempted` (falling back to all
    /// requestable scopes when none match directly).
    fn requestable_scopes(&self, attempted: &Operation) -> Vec<RequestableScope> {
        if !self.doc.escalation.allow_requests {
            return Vec::new();
        }
        let to_scope = |spec: &crate::document::RequestableScopeSpec| RequestableScope {
            operation: Operation::new(spec.operation.clone()),
            constraints: spec.constraints.clone(),
            requires_human: spec.requires_human,
        };
        let matching: Vec<RequestableScope> = self
            .doc
            .escalation
            .requestable
            .iter()
            .filter(|s| glob_match(&s.operation, &attempted.0) || glob_match(&attempted.0, &s.operation))
            .map(to_scope)
            .collect();
        if matching.is_empty() {
            self.doc.escalation.requestable.iter().map(to_scope).collect()
        } else {
            matching
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{
        EscalationPolicy, PathPolicy, PolicyRule, PrincipalSelector, RequestableScopeSpec,
    };
    use ak_core::capability::Constraint;
    use ak_core::principal::TrustLevel;
    use serde_json::json;

    fn engine() -> PolicyEngine {
        let mut doc = PolicyDocument::default();
        doc.set_paths(PathPolicy {
            readable_prefixes: vec!["".into()],
            writable_prefixes: vec!["src/".into()],
        });
        doc.set_egress_domains(vec!["api.github.com".into()]);
        doc.set_escalation(EscalationPolicy {
            allow_requests: true,
            requestable: vec![RequestableScopeSpec {
                operation: "net.http_read".into(),
                constraints: json!({"domain": "api.github.com"}),
                requires_human: false,
            }],
        });
        doc.add_rule(PolicyRule {
            id: "deny-shell-for-tools".into(),
            principals: PrincipalSelector {
                kinds: vec![ak_core::principal::PrincipalKind::Tool],
                ..Default::default()
            },
            operations: vec!["proc.shell".into()],
            effect: RuleEffect::Deny,
            constraints: IndexMap::new(),
            max_uses: 1,
            ttl_seconds: 60,
            budget: None,
            risk_weight: 0,
            note: None,
        })
        .unwrap();
        doc.add_rule(PolicyRule {
            id: "allow-write-src".into(),
            principals: PrincipalSelector::default(),
            operations: vec!["fs.write".into()],
            effect: RuleEffect::Allow,
            constraints: {
                let mut c = IndexMap::new();
                c.insert("path".into(), Constraint::Prefix { prefix: "src/".into() });
                c
            },
            max_uses: 20,
            ttl_seconds: 600,
            budget: None,
            risk_weight: 1,
            note: None,
        })
        .unwrap();
        doc.add_rule(PolicyRule {
            id: "approve-pr".into(),
            principals: PrincipalSelector::default(),
            operations: vec!["github.*".into()],
            effect: RuleEffect::RequireApproval,
            constraints: IndexMap::new(),
            max_uses: 1,
            ttl_seconds: 600,
            budget: None,
            risk_weight: 5,
            note: None,
        })
        .unwrap();
        PolicyEngine::new(doc)
    }
    #[test]
    fn allow_path_compiles_a_grant() {
        let e = engine();
        let p = Principal::new_agent("agent");
        let now = Utc::now();
        let d = e.evaluate(
            &p,
            &Operation::new("fs.write"),
            &json!({"path": "src/main.rs"}),
            None,
            now,
        );
        match d {
            Decision::Allow { rule_id, grant } => {
                assert_eq!(rule_id, "allow-write-src");
                assert_eq!(grant.lease.remaining_uses, 20);
                assert!(grant
                    .lease
                    .check(&p.id, &Operation::new("fs.write"), &json!({"path": "src/x"}), None, now)
                    .is_ok());
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn constraint_violation_denies_with_correct_code() {
        let e = engine();
        let p = Principal::new_agent("agent");
        let d = e.evaluate(
            &p,
            &Operation::new("fs.write"),
            &json!({"path": "/etc/passwd"}),
            None,
            Utc::now(),
        );
        match d {
            Decision::Deny { denial } => {
                assert_eq!(denial.code, DenialCode::ConstraintViolated);
                // No host paths leak in the reason.
                assert!(!denial.reason.contains("/etc"));
                assert!(!denial.reason.contains("src/"));
                assert!(denial.escalation_allowed);
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn unmatched_operation_default_denies_with_alternatives_and_scopes() {
        let e = engine();
        let p = Principal::new_agent("agent");
        let d = e.evaluate(&p, &Operation::new("net.raw_socket"), &json!({}), None, Utc::now());
        match d {
            Decision::Deny { denial } => {
                assert_eq!(denial.code, DenialCode::CapabilityDenied);
                assert!(denial.safe_alternatives.contains(&Operation::new("fs.write")));
                assert_eq!(denial.requestable_scopes.len(), 1);
                assert_eq!(denial.requestable_scopes[0].operation.0, "net.http_read");
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn explicit_deny_rule_wins_and_approval_path_carries_epoch() {
        let e = engine();
        let mut tool = Principal::new_agent("tool");
        tool.kind = ak_core::principal::PrincipalKind::Tool;
        let d = e.evaluate(&tool, &Operation::new("proc.shell"), &json!({}), None, Utc::now());
        assert!(matches!(
            d,
            Decision::Deny { denial: Denial { code: DenialCode::PolicyForbidden, .. } }
        ));

        let agent = Principal::new_agent("agent");
        let d = e.evaluate(
            &agent,
            &Operation::new("github.create_pull_request"),
            &json!({}),
            None,
            Utc::now(),
        );
        match d {
            Decision::RequireApproval { rule_id, policy_epoch, .. } => {
                assert_eq!(rule_id, "approve-pr");
                assert_eq!(policy_epoch, e.document().policy_epoch);
            }
            other => panic!("expected approval, got {other:?}"),
        }
    }

    #[test]
    fn denials_are_redacted_by_trust() {
        let e = engine();
        let mut quarantined = Principal::new_agent("skill");
        quarantined.trust = TrustLevel::Quarantined;
        let d = e.evaluate(
            &quarantined,
            &Operation::new("net.raw_socket"),
            &json!({}),
            None,
            Utc::now(),
        );
        match d {
            Decision::Deny { denial } => {
                assert!(denial.requestable_scopes.is_empty());
                assert!(!denial.escalation_allowed);
                assert_eq!(denial.reason, "operation not permitted for this principal");
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }
}
