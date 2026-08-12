//! The [`EffectBroker`]: registry of connectors, durable store of pending
//! effects and receipts, and enforcer of the commit-time revalidation rules.

use ak_core::effect::{EffectContract, EffectPhase, PendingEffect, Receipt, ReceiptBody};
use ak_core::hash::{canonical_json, hash_canonical, ContentHash};
use ak_core::ids::{BranchId, EffectId, LeaseId, PrincipalId, ReceiptId, StepId};
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{EffectClass, KernelError, KernelResult};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{info, instrument, warn};

/// Signs the canonical JSON of a [`ReceiptBody`]. Implemented by the
/// kernel-identity crate's Ed25519 keypair (or a test signer) without this
/// crate depending on it.
pub trait ReceiptSigner: Send + Sync {
    /// Sign `message`, returning `(signature_hex, key_id)`.
    fn sign(&self, message: &[u8]) -> (String, String);
}

impl<F> ReceiptSigner for F
where
    F: Fn(&[u8]) -> (String, String) + Send + Sync,
{
    fn sign(&self, message: &[u8]) -> (String, String) {
        self(message)
    }
}

/// Approval record stored alongside an effect; hashed into the receipt as the
/// `authorization_witness`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ApprovalRecord {
    approver: PrincipalId,
    approved_at: chrono::DateTime<chrono::Utc>,
    policy_epoch: u64,
    /// Contract hash the approver saw. Commit refuses if the effect's hash
    /// has changed since.
    contract_hash: ContentHash,
}

/// The transactional effect broker. See the crate-level docs for the
/// lifecycle it enforces.
pub struct EffectBroker {
    connectors: Mutex<HashMap<String, Arc<dyn Connector>>>,
    store: Mutex<Connection>,
    signer: Box<dyn ReceiptSigner>,
}

impl std::fmt::Debug for EffectBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectBroker").finish_non_exhaustive()
    }
}

fn storage_err(e: rusqlite::Error) -> KernelError {
    KernelError::Storage(e.to_string())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS effects (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    json TEXT NOT NULL,
    observed_preconditions TEXT,
    approval TEXT
);
CREATE INDEX IF NOT EXISTS idx_effects_idem ON effects(idempotency_key);
CREATE TABLE IF NOT EXISTS receipts (
    id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    compensating INTEGER NOT NULL DEFAULT 0,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipts_idem ON receipts(idempotency_key);
";

impl EffectBroker {
    /// Broker over an in-memory SQLite store (tests, ephemeral kernels).
    pub fn in_memory(signer: Box<dyn ReceiptSigner>) -> KernelResult<Self> {
        let conn = Connection::open_in_memory().map_err(storage_err)?;
        Self::with_connection(conn, signer)
    }

    /// Broker over a file-backed SQLite store.
    pub fn open(path: &std::path::Path, signer: Box<dyn ReceiptSigner>) -> KernelResult<Self> {
        let conn = Connection::open(path).map_err(storage_err)?;
        Self::with_connection(conn, signer)
    }

    fn with_connection(conn: Connection, signer: Box<dyn ReceiptSigner>) -> KernelResult<Self> {
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        Ok(Self {
            connectors: Mutex::new(HashMap::new()),
            store: Mutex::new(conn),
            signer,
        })
    }

    /// Register a connector under its [`Connector::name`]. Operations are
    /// routed by the prefix before the first `.` (e.g. `github.create_branch`
    /// routes to the `github` connector).
    pub fn register_connector(&self, connector: Arc<dyn Connector>) {
        let name = connector.name().to_string();
        info!(connector = %name, "registering connector");
        if let Ok(mut map) = self.connectors.lock() {
            map.insert(name, connector);
        }
    }

    fn connector_for(&self, operation: &str) -> KernelResult<Arc<dyn Connector>> {
        let prefix = operation.split('.').next().unwrap_or(operation);
        let map = self
            .connectors
            .lock()
            .map_err(|_| KernelError::Storage("connector registry poisoned".into()))?;
        map.get(prefix).cloned().ok_or_else(|| KernelError::NotFound {
            kind: "connector",
            id: prefix.to_string(),
        })
    }

    fn with_store<T>(&self, f: impl FnOnce(&Connection) -> KernelResult<T>) -> KernelResult<T> {
        let conn = self
            .store
            .lock()
            .map_err(|_| KernelError::Storage("effect store poisoned".into()))?;
        f(&conn)
    }

    fn load_effect(&self, id: &EffectId) -> KernelResult<PendingEffect> {
        self.with_store(|conn| {
            let json: Option<String> = conn
                .query_row("SELECT json FROM effects WHERE id = ?1", params![id.as_str()], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(storage_err)?;
            let json = json.ok_or_else(|| KernelError::NotFound {
                kind: "effect",
                id: id.to_string(),
            })?;
            Ok(serde_json::from_str(&json)?)
        })
    }

    fn save_effect(&self, effect: &PendingEffect) -> KernelResult<()> {
        let json = serde_json::to_string(effect)?;
        self.with_store(|conn| {
            conn.execute(
                "UPDATE effects SET json = ?2 WHERE id = ?1",
                params![effect.id.as_str(), json],
            )
            .map_err(storage_err)?;
            Ok(())
        })
    }

    fn load_column(&self, id: &EffectId, column: &str) -> KernelResult<Option<String>> {
        let sql = format!("SELECT {column} FROM effects WHERE id = ?1");
        self.with_store(|conn| {
            conn.query_row(&sql, params![id.as_str()], |r| r.get::<_, Option<String>>(0))
                .optional()
                .map_err(storage_err)?
                .ok_or_else(|| KernelError::NotFound { kind: "effect", id: id.to_string() })
        })
    }

    fn set_column(&self, id: &EffectId, column: &str, value: Option<&str>) -> KernelResult<()> {
        let sql = format!("UPDATE effects SET {column} = ?2 WHERE id = ?1");
        self.with_store(|conn| {
            conn.execute(&sql, params![id.as_str(), value]).map_err(storage_err)?;
            Ok(())
        })
    }

    fn committed_receipt_for_key(&self, key: &str) -> KernelResult<Option<String>> {
        self.with_store(|conn| {
            conn.query_row(
                "SELECT id FROM receipts WHERE idempotency_key = ?1 AND compensating = 0",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage_err)
        })
    }

    /// Fetch a receipt by id.
    pub fn receipt(&self, id: &ReceiptId) -> KernelResult<Receipt> {
        self.with_store(|conn| {
            let json: Option<String> = conn
                .query_row("SELECT json FROM receipts WHERE id = ?1", params![id.as_str()], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(storage_err)?;
            let json = json.ok_or_else(|| KernelError::NotFound {
                kind: "receipt",
                id: id.to_string(),
            })?;
            Ok(serde_json::from_str(&json)?)
        })
    }

    /// Fetch a pending effect by id.
    pub fn effect(&self, id: &EffectId) -> KernelResult<PendingEffect> {
        self.load_effect(id)
    }

    /// List stored effects, newest proposal first, optionally filtered by
    /// phase name (`proposed`, `prepared`, `approved`, `committed`,
    /// `aborted`, `compensated`).
    pub fn list_effects(&self, phase: Option<&str>) -> KernelResult<Vec<PendingEffect>> {
        let rows: Vec<String> = self.with_store(|conn| {
            let mut stmt =
                conn.prepare("SELECT json FROM effects ORDER BY rowid DESC").map_err(storage_err)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(storage_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_err)?;
            Ok(rows)
        })?;
        let mut out = Vec::with_capacity(rows.len());
        for json in rows {
            let effect: PendingEffect = serde_json::from_str(&json)?;
            if let Some(want) = phase {
                if !phase_name(&effect.phase).eq_ignore_ascii_case(want) {
                    continue;
                }
            }
            out.push(effect);
        }
        Ok(out)
    }

    /// Propose an effect: canonicalize its arguments through the owning
    /// connector, deduplicate on the idempotency key, and persist it in
    /// phase `Proposed`.
    ///
    /// Returns [`KernelError::DuplicateCommit`] if the idempotency key has
    /// already produced a committed receipt.
    #[instrument(skip(self, contract), fields(operation = %contract.operation))]
    pub fn propose(
        &self,
        mut contract: EffectContract,
        proposer: PrincipalId,
        branch: BranchId,
        step: StepId,
        lease: LeaseId,
    ) -> KernelResult<PendingEffect> {
        let connector = self.connector_for(&contract.operation)?;
        contract.arguments = connector.canonicalize(&contract.operation, &contract.arguments)?;

        if let Some(receipt) = self.committed_receipt_for_key(&contract.idempotency_key)? {
            return Err(KernelError::DuplicateCommit {
                key: contract.idempotency_key.clone(),
                receipt,
            });
        }

        let effect = PendingEffect::new(contract, proposer, branch, step, lease, Utc::now());
        let json = serde_json::to_string(&effect)?;
        self.with_store(|conn| {
            conn.execute(
                "INSERT INTO effects (id, idempotency_key, json) VALUES (?1, ?2, ?3)",
                params![effect.id.as_str(), effect.contract.idempotency_key, json],
            )
            .map_err(storage_err)?;
            Ok(())
        })?;
        info!(effect = %effect.id, "effect proposed");
        Ok(effect)
    }

    /// Dry-run the effect against the live external system, recording the
    /// observed preconditions and moving to phase `Prepared`.
    #[instrument(skip(self))]
    pub async fn prepare(&self, effect_id: &EffectId) -> KernelResult<PreparedEffect> {
        let mut effect = self.load_effect(effect_id)?;
        if !matches!(effect.phase, EffectPhase::Proposed) {
            return Err(wrong_phase(&effect, "proposed"));
        }
        let connector = self.connector_for(&effect.contract.operation)?;
        let prepared = connector.prepare(&effect.contract).await?;

        effect.phase = EffectPhase::Prepared { preview: prepared.preview.clone() };
        self.save_effect(&effect)?;
        self.set_column(
            effect_id,
            "observed_preconditions",
            Some(&serde_json::to_string(&prepared.observed_preconditions)?),
        )?;
        info!(effect = %effect_id, "effect prepared");
        Ok(prepared)
    }

    /// Record an explicit approval, bound to the contract hash and the policy
    /// epoch under which the approval was granted.
    #[instrument(skip(self))]
    pub fn approve(
        &self,
        effect_id: &EffectId,
        approver: PrincipalId,
        policy_epoch: u64,
    ) -> KernelResult<()> {
        let mut effect = self.load_effect(effect_id)?;
        if !matches!(effect.phase, EffectPhase::Prepared { .. }) {
            return Err(wrong_phase(&effect, "prepared"));
        }
        let record = ApprovalRecord {
            approver: approver.clone(),
            approved_at: Utc::now(),
            policy_epoch,
            contract_hash: effect.contract_hash.clone(),
        };
        self.set_column(effect_id, "approval", Some(&serde_json::to_string(&record)?))?;
        effect.phase = EffectPhase::Approved {
            approver,
            approved_at: record.approved_at,
            policy_epoch,
        };
        self.save_effect(&effect)?;
        info!(effect = %effect_id, "effect approved");
        Ok(())
    }

    /// Commit the effect after full revalidation. Any failed check aborts the
    /// effect and returns [`KernelError::StaleAuthorization`].
    ///
    /// Revalidation, in order:
    /// 1. the contract hash is unchanged since approval;
    /// 2. the policy epoch is unchanged since approval;
    /// 3. the capability lease is still valid (`lease_check`);
    /// 4. the connector's `prepare` is re-run and every declared precondition
    ///    plus every prepare-time observation still holds;
    /// 5. the idempotency key has not been committed elsewhere.
    #[instrument(skip(self, lease_check))]
    pub async fn commit(
        &self,
        effect_id: &EffectId,
        current_policy_epoch: u64,
        lease_check: impl Fn(&LeaseId) -> bool,
    ) -> KernelResult<Receipt> {
        let effect = self.load_effect(effect_id)?;

        // Irreversible / opaque effects can only be committed from an
        // explicit approval; reversible ones may commit straight from
        // `Prepared`.
        let approval: Option<ApprovalRecord> = match &effect.phase {
            EffectPhase::Approved { .. } => {
                let raw = self.load_column(effect_id, "approval")?.ok_or_else(|| {
                    KernelError::Storage("approved effect missing approval record".into())
                })?;
                Some(serde_json::from_str(&raw)?)
            }
            EffectPhase::Prepared { .. } => {
                if matches!(
                    effect.contract.class,
                    EffectClass::Irreversible | EffectClass::OpaqueExternal
                ) {
                    return Err(wrong_phase(&effect, "approved"));
                }
                None
            }
            _ => return Err(wrong_phase(&effect, "approved")),
        };

        // 1. Contract must hash to exactly what was proposed (and approved).
        let live_hash = effect.contract.contract_hash();
        if live_hash != effect.contract_hash {
            return self.stale(effect_id, "contract content no longer matches its recorded hash").await;
        }
        if let Some(a) = &approval {
            if a.contract_hash != live_hash {
                return self
                    .stale(effect_id, "contract hash changed since approval")
                    .await;
            }
            // 2. Policy epoch unchanged since approval.
            if a.policy_epoch != current_policy_epoch {
                return self
                    .stale(
                        effect_id,
                        &format!(
                            "policy epoch advanced from {} to {} since approval",
                            a.policy_epoch, current_policy_epoch
                        ),
                    )
                    .await;
            }
        }

        // 3. Lease still valid.
        if !lease_check(&effect.lease) {
            return self
                .stale(effect_id, &format!("lease `{}` is no longer valid", effect.lease))
                .await;
        }

        // 4. Re-observe the world and compare preconditions.
        let connector = self.connector_for(&effect.contract.operation)?;
        let reprepared = connector.prepare(&effect.contract).await?;
        if let Err(reason) =
            preconditions_hold(&effect.contract.preconditions, &reprepared.observed_preconditions)
        {
            return self.stale(effect_id, &reason).await;
        }
        if let Some(raw) = self.load_column(effect_id, "observed_preconditions")? {
            let prepared_obs: serde_json::Value = serde_json::from_str(&raw)?;
            if let Err(reason) = preconditions_hold(&prepared_obs, &reprepared.observed_preconditions)
            {
                return self.stale(effect_id, &reason).await;
            }
        }

        // 5. Exactly-once.
        if let Some(receipt) = self.committed_receipt_for_key(&effect.contract.idempotency_key)? {
            return Err(KernelError::DuplicateCommit {
                key: effect.contract.idempotency_key.clone(),
                receipt,
            });
        }

        // All checks passed: perform the effect.
        let result = connector.commit(&effect.contract).await?;
        let witness_source = match &approval {
            Some(a) => serde_json::to_value(a)?,
            None => serde_json::json!({
                "auto_commit": true,
                "contract_hash": effect.contract_hash,
            }),
        };
        let body = ReceiptBody {
            effect: effect.id.clone(),
            who: effect.proposer.clone(),
            operation: effect.contract.operation.clone(),
            resource: effect.contract.resource.clone(),
            contract_hash: effect.contract_hash.clone(),
            branch: effect.branch.clone(),
            step: effect.step.clone(),
            policy_epoch: current_policy_epoch,
            authorization_witness: hash_canonical(&witness_source),
            external_response_digest: hash_canonical(&result.response),
            committed_at: Utc::now(),
        };
        let receipt = self.sign_and_store(&effect, body, false)?;

        let mut effect = effect;
        effect.phase = EffectPhase::Committed { receipt: receipt.id.clone() };
        self.save_effect(&effect)?;
        info!(effect = %effect_id, receipt = %receipt.id, "effect committed");
        Ok(receipt)
    }

    fn sign_and_store(
        &self,
        effect: &PendingEffect,
        body: ReceiptBody,
        compensating: bool,
    ) -> KernelResult<Receipt> {
        let (signature, key_id) = self.signer.sign(canonical_json(&body).as_bytes());
        let receipt = Receipt { id: ReceiptId::generate(), body, signature, key_id };
        let json = serde_json::to_string(&receipt)?;
        self.with_store(|conn| {
            conn.execute(
                "INSERT INTO receipts (id, effect_id, idempotency_key, compensating, json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    receipt.id.as_str(),
                    effect.id.as_str(),
                    effect.contract.idempotency_key,
                    compensating as i64,
                    json
                ],
            )
            .map_err(storage_err)?;
            Ok(())
        })?;
        Ok(receipt)
    }

    async fn stale(&self, effect_id: &EffectId, reason: &str) -> KernelResult<Receipt> {
        warn!(effect = %effect_id, reason, "commit-time revalidation failed; aborting");
        self.abort(effect_id, reason)?;
        Err(KernelError::StaleAuthorization { reason: reason.to_string() })
    }

    /// Abort a not-yet-committed effect with a human-readable reason.
    #[instrument(skip(self))]
    pub fn abort(&self, effect_id: &EffectId, reason: &str) -> KernelResult<()> {
        let mut effect = self.load_effect(effect_id)?;
        match effect.phase {
            EffectPhase::Committed { .. } | EffectPhase::Compensated { .. } => {
                return Err(wrong_phase(&effect, "proposed|prepared|approved"));
            }
            _ => {}
        }
        effect.phase = EffectPhase::Aborted { reason: reason.to_string() };
        self.save_effect(&effect)?;
        Ok(())
    }

    /// Run the connector's compensating action for a committed effect and
    /// record a compensating receipt.
    #[instrument(skip(self))]
    pub async fn compensate(&self, effect_id: &EffectId) -> KernelResult<Receipt> {
        let effect = self.load_effect(effect_id)?;
        if !matches!(effect.phase, EffectPhase::Committed { .. }) {
            return Err(wrong_phase(&effect, "committed"));
        }
        let connector = self.connector_for(&effect.contract.operation)?;
        let result = connector.compensate(&effect.contract).await?;
        let body = ReceiptBody {
            effect: effect.id.clone(),
            who: effect.proposer.clone(),
            operation: format!("{}.compensate", effect.contract.operation),
            resource: effect.contract.resource.clone(),
            contract_hash: effect.contract_hash.clone(),
            branch: effect.branch.clone(),
            step: effect.step.clone(),
            policy_epoch: 0,
            authorization_witness: hash_canonical(&serde_json::json!({
                "compensation_for": effect.id,
            })),
            external_response_digest: hash_canonical(&result.response),
            committed_at: Utc::now(),
        };
        let receipt = self.sign_and_store(&effect, body, true)?;
        let mut effect = effect;
        effect.phase = EffectPhase::Compensated { compensating_receipt: receipt.id.clone() };
        self.save_effect(&effect)?;
        info!(effect = %effect_id, receipt = %receipt.id, "effect compensated");
        Ok(receipt)
    }
}

fn phase_name(phase: &EffectPhase) -> &'static str {
    match phase {
        EffectPhase::Proposed => "proposed",
        EffectPhase::Prepared { .. } => "prepared",
        EffectPhase::Approved { .. } => "approved",
        EffectPhase::Committed { .. } => "committed",
        EffectPhase::Aborted { .. } => "aborted",
        EffectPhase::Compensated { .. } => "compensated",
    }
}

fn wrong_phase(effect: &PendingEffect, expected: &'static str) -> KernelError {
    KernelError::WrongEffectPhase {
        effect: effect.id.to_string(),
        phase: phase_name(&effect.phase).to_string(),
        expected,
    }
}

/// Check that every key/value in `expected` matches `observed`. Returns a
/// precise reason on the first mismatch.
fn preconditions_hold(expected: &serde_json::Value, observed: &serde_json::Value) -> Result<(), String> {
    let Some(map) = expected.as_object() else { return Ok(()) };
    for (k, v) in map {
        match observed.get(k) {
            Some(o) if o == v => {}
            Some(o) => {
                return Err(format!(
                    "precondition `{k}` drifted: expected {v}, observed {o}"
                ))
            }
            None => return Err(format!("precondition `{k}` is no longer observable")),
        }
    }
    Ok(())
}

// The unused import lint would fire for CommitResult in some cfgs; it is part
// of the public flow via the Connector trait.
#[allow(unused)]
fn _assert_commit_result_used(_r: CommitResult) {}

#[cfg(test)]
mod tests {
    use super::*;
    use ak_core::traits::PreparedEffect;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A connector over a fake external world whose observable state (a
    /// "head sha") can be mutated between broker calls.
    struct MockConnector {
        world_sha: Mutex<String>,
        commits: AtomicU64,
        compensations: AtomicU64,
        /// A secret only the connector may see, used to prove no secret
        /// bytes leak into serialized broker artifacts.
        vault: Arc<crate::secrets::SecretVault>,
    }

    impl MockConnector {
        fn new(vault: Arc<crate::secrets::SecretVault>) -> Self {
            Self {
                world_sha: Mutex::new("sha-1".into()),
                commits: AtomicU64::new(0),
                compensations: AtomicU64::new(0),
                vault,
            }
        }
    }

    #[async_trait]
    impl Connector for MockConnector {
        fn name(&self) -> &str {
            "mock"
        }
        fn operations(&self) -> Vec<(String, EffectClass)> {
            vec![
                ("mock.push".into(), EffectClass::Compensatable),
                ("mock.email".into(), EffectClass::Irreversible),
            ]
        }
        fn canonicalize(
            &self,
            _operation: &str,
            args: &serde_json::Value,
        ) -> KernelResult<serde_json::Value> {
            Ok(args.clone())
        }
        async fn prepare(&self, _contract: &EffectContract) -> KernelResult<PreparedEffect> {
            let sha = self
                .world_sha
                .lock()
                .map_err(|_| KernelError::Other("poisoned".into()))?
                .clone();
            Ok(PreparedEffect {
                preview: json!({"will": "push"}),
                observed_preconditions: json!({"head_sha": sha}),
            })
        }
        async fn commit(&self, _contract: &EffectContract) -> KernelResult<CommitResult> {
            // Prove the connector-only credential path works; the secret must
            // never appear in any broker artifact.
            let auth = self.vault.with_secret("api_token", |s| format!("Bearer {s}"))?;
            assert!(auth.contains("s3cr3t"));
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(CommitResult { response: json!({"status": "ok", "id": 42}) })
        }
        async fn compensate(&self, _contract: &EffectContract) -> KernelResult<CommitResult> {
            self.compensations.fetch_add(1, Ordering::SeqCst);
            Ok(CommitResult { response: json!({"status": "reverted"}) })
        }
    }

    fn test_signer() -> Box<dyn ReceiptSigner> {
        Box::new(|msg: &[u8]| {
            (ak_core::hash::hash_bytes(msg).0, "test-key".to_string())
        })
    }

    fn contract(class: EffectClass, key: &str) -> EffectContract {
        EffectContract {
            operation: "mock.push".into(),
            resource: "org/repo".into(),
            arguments: json!({"branch": "main"}),
            preconditions: json!({"head_sha": "sha-1"}),
            idempotency_key: key.into(),
            class,
        }
    }

    struct Rig {
        broker: EffectBroker,
        connector: Arc<MockConnector>,
        vault: Arc<crate::secrets::SecretVault>,
    }

    fn rig() -> Rig {
        let vault = Arc::new(crate::secrets::SecretVault::in_memory());
        vault.insert("api_token", "s3cr3t-hunter2").expect("insert");
        let broker = EffectBroker::in_memory(test_signer()).expect("broker");
        let connector = Arc::new(MockConnector::new(vault.clone()));
        broker.register_connector(connector.clone());
        Rig { broker, connector, vault }
    }

    fn propose(r: &Rig, c: EffectContract) -> PendingEffect {
        r.broker
            .propose(
                c,
                PrincipalId::generate(),
                BranchId::generate(),
                StepId::generate(),
                LeaseId::generate(),
            )
            .expect("propose")
    }

    #[tokio::test]
    async fn happy_path_lifecycle() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-1"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        r.broker
            .approve(&fx.id, PrincipalId::generate(), 7)
            .expect("approve");
        let receipt = r.broker.commit(&fx.id, 7, |_| true).await.expect("commit");
        assert_eq!(receipt.body.operation, "mock.push");
        assert_eq!(receipt.body.contract_hash, fx.contract_hash);
        assert_eq!(receipt.body.policy_epoch, 7);
        assert_eq!(receipt.key_id, "test-key");
        assert_eq!(r.connector.commits.load(Ordering::SeqCst), 1);
        // Phase is Committed and receipt is durable.
        let stored = r.broker.effect(&fx.id).expect("effect");
        assert!(matches!(stored.phase, EffectPhase::Committed { .. }));
        assert_eq!(r.broker.receipt(&receipt.id).expect("receipt").body, receipt.body);
        // Compensation produces a second, compensating receipt.
        let comp = r.broker.compensate(&fx.id).await.expect("compensate");
        assert_eq!(comp.body.operation, "mock.push.compensate");
        assert_eq!(r.connector.compensations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_precondition_aborts_commit() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-2"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        r.broker.approve(&fx.id, PrincipalId::generate(), 1).expect("approve");
        // The world moves under us.
        *r.connector.world_sha.lock().expect("lock") = "sha-2".into();
        let err = r.broker.commit(&fx.id, 1, |_| true).await.expect_err("must abort");
        match err {
            KernelError::StaleAuthorization { reason } => {
                assert!(reason.contains("head_sha"), "reason: {reason}")
            }
            other => panic!("expected StaleAuthorization, got {other:?}"),
        }
        assert_eq!(r.connector.commits.load(Ordering::SeqCst), 0);
        assert!(matches!(
            r.broker.effect(&fx.id).expect("effect").phase,
            EffectPhase::Aborted { .. }
        ));
    }

    #[tokio::test]
    async fn changed_contract_aborts_commit() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-3"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        r.broker.approve(&fx.id, PrincipalId::generate(), 1).expect("approve");
        // Simulate tampering: swap the stored contract arguments so the
        // content no longer matches the hash the approver saw.
        let mut stored = r.broker.effect(&fx.id).expect("effect");
        stored.contract.arguments = json!({"branch": "release"});
        r.broker.save_effect(&stored).expect("save");
        let err = r.broker.commit(&fx.id, 1, |_| true).await.expect_err("must abort");
        assert!(matches!(err, KernelError::StaleAuthorization { .. }), "{err:?}");
        assert_eq!(r.connector.commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_epoch_change_aborts_commit() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-4"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        r.broker.approve(&fx.id, PrincipalId::generate(), 3).expect("approve");
        let err = r.broker.commit(&fx.id, 4, |_| true).await.expect_err("must abort");
        match err {
            KernelError::StaleAuthorization { reason } => {
                assert!(reason.contains("policy epoch"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_lease_aborts_commit() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-5"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        r.broker.approve(&fx.id, PrincipalId::generate(), 1).expect("approve");
        let err = r.broker.commit(&fx.id, 1, |_| false).await.expect_err("must abort");
        match err {
            KernelError::StaleAuthorization { reason } => assert!(reason.contains("lease")),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn duplicate_idempotency_key_is_rejected() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-6"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        r.broker.approve(&fx.id, PrincipalId::generate(), 1).expect("approve");
        r.broker.commit(&fx.id, 1, |_| true).await.expect("commit");
        // A new proposal with the same key must be refused up front.
        let err = r
            .broker
            .propose(
                contract(EffectClass::Compensatable, "k-6"),
                PrincipalId::generate(),
                BranchId::generate(),
                StepId::generate(),
                LeaseId::generate(),
            )
            .expect_err("duplicate");
        assert!(matches!(err, KernelError::DuplicateCommit { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn irreversible_requires_explicit_approval() {
        let r = rig();
        let mut c = contract(EffectClass::Irreversible, "k-7");
        c.operation = "mock.email".into();
        let fx = propose(&r, c);
        r.broker.prepare(&fx.id).await.expect("prepare");
        // Committing straight from Prepared must be refused for irreversible
        // effects.
        let err = r.broker.commit(&fx.id, 1, |_| true).await.expect_err("needs approval");
        assert!(matches!(err, KernelError::WrongEffectPhase { expected: "approved", .. }), "{err:?}");
        assert_eq!(r.connector.commits.load(Ordering::SeqCst), 0);
        // With approval, it commits.
        r.broker.approve(&fx.id, PrincipalId::generate(), 1).expect("approve");
        r.broker.commit(&fx.id, 1, |_| true).await.expect("commit");
    }

    #[tokio::test]
    async fn reversible_may_commit_from_prepared() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-8"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        let receipt = r.broker.commit(&fx.id, 9, |_| true).await.expect("commit");
        assert_eq!(receipt.body.policy_epoch, 9);
    }

    #[tokio::test]
    async fn no_secret_bytes_in_serialized_artifacts() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-9"));
        r.broker.prepare(&fx.id).await.expect("prepare");
        r.broker.approve(&fx.id, PrincipalId::generate(), 1).expect("approve");
        let receipt = r.broker.commit(&fx.id, 1, |_| true).await.expect("commit");

        let effect_json = serde_json::to_string(&r.broker.effect(&fx.id).expect("fx")).expect("ser");
        let receipt_json = serde_json::to_string(&receipt).expect("ser");
        for leak in ["s3cr3t", "hunter2"] {
            assert!(!effect_json.contains(leak), "secret leaked into PendingEffect");
            assert!(!receipt_json.contains(leak), "secret leaked into Receipt");
        }
        // The vault's Debug output is redacted too.
        assert!(!format!("{:?}", r.vault).contains("s3cr3t"));
    }

    #[tokio::test]
    async fn abort_and_wrong_phase_transitions() {
        let r = rig();
        let fx = propose(&r, contract(EffectClass::Compensatable, "k-10"));
        // prepare twice fails
        r.broker.prepare(&fx.id).await.expect("prepare");
        assert!(r.broker.prepare(&fx.id).await.is_err());
        r.broker.abort(&fx.id, "operator cancelled").expect("abort");
        assert!(matches!(
            r.broker.effect(&fx.id).expect("fx").phase,
            EffectPhase::Aborted { .. }
        ));
        // committed effects cannot be aborted
        let fx2 = propose(&r, contract(EffectClass::Compensatable, "k-11"));
        r.broker.prepare(&fx2.id).await.expect("prepare");
        r.broker.commit(&fx2.id, 1, |_| true).await.expect("commit");
        assert!(r.broker.abort(&fx2.id, "nope").is_err());
    }
}
