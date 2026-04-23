//! Unit tests against an in-process mock GitHub server (axum).

use super::*;
use axum::extract::{Path, State};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use std::sync::Mutex;

#[derive(Default)]
struct MockState {
    /// Head sha reported for every branch ref (mutable to simulate drift).
    sha: Mutex<String>,
    created_refs: Mutex<Vec<Value>>,
    comments: Mutex<Vec<Value>>,
    pr_state: Mutex<String>,
    auth_headers: Mutex<Vec<String>>,
}

type S = Arc<MockState>;

async fn spawn_mock() -> (String, S) {
    let state: S = Arc::new(MockState {
        sha: Mutex::new("sha-live-1".into()),
        pr_state: Mutex::new("open".into()),
        ..Default::default()
    });

    async fn record_auth(state: &S, headers: &axum::http::HeaderMap) {
        if let Some(a) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            state.auth_headers.lock().unwrap().push(a.to_string());
        }
    }

    let app = Router::new()
        .route(
            "/repos/:owner/:repo",
            get(|headers: axum::http::HeaderMap, State(s): State<S>| async move {
                record_auth(&s, &headers).await;
                Json(json!({"full_name": "acme/widgets", "default_branch": "main", "private": false}))
            }),
        )
        .route(
            "/repos/:owner/:repo/git/ref/heads/:branch",
            get(|State(s): State<S>| async move {
                let sha = s.sha.lock().unwrap().clone();
                Json(json!({"ref": "refs/heads/main", "object": {"sha": sha}}))
            }),
        )
        .route(
            "/repos/:owner/:repo/git/refs",
            post(|headers: axum::http::HeaderMap, State(s): State<S>, Json(body): Json<Value>| async move {
                record_auth(&s, &headers).await;
                s.created_refs.lock().unwrap().push(body.clone());
                Json(json!({"ref": body["ref"]}))
            }),
        )
        .route(
            "/repos/:owner/:repo/git/refs/heads/:branch",
            delete(|Path((_, _, branch)): Path<(String, String, String)>, State(s): State<S>| async move {
                s.created_refs
                    .lock()
                    .unwrap()
                    .retain(|r| r["ref"] != format!("refs/heads/{branch}"));
                Json(json!({}))
            }),
        )
        .route(
            "/repos/:owner/:repo/issues/:n",
            get(|| async { Json(json!({"state": "open", "number": 12})) }),
        )
        .route(
            "/repos/:owner/:repo/issues/:n/comments",
            post(|State(s): State<S>, Json(body): Json<Value>| async move {
                s.comments.lock().unwrap().push(body);
                Json(json!({"id": 9001}))
            }),
        )
        .route(
            "/repos/:owner/:repo/pulls",
            get(|State(s): State<S>| async move {
                let st = s.pr_state.lock().unwrap().clone();
                if st == "open" {
                    Json(json!([{"number": 7, "state": "open"}]))
                } else {
                    Json(json!([]))
                }
            })
            .post(|| async {
                Json(json!({"number": 7, "html_url": "http://mock/pull/7", "state": "open"}))
            }),
        )
        .route(
            "/repos/:owner/:repo/pulls/:n",
            patch(|State(s): State<S>, Json(body): Json<Value>| async move {
                let mut st = s.pr_state.lock().unwrap();
                *st = body["state"].as_str().unwrap_or("open").to_string();
                Json(json!({"number": 7, "state": *st}))
            }),
        )
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), state)
}

fn connector(base: &str) -> GithubConnector {
    GithubConnector::new(base, Arc::new(StaticTokenSource("test-token".into())))
}

fn contract(op: &str, args: Value, class: EffectClass) -> EffectContract {
    EffectContract {
        operation: op.into(),
        resource: "acme/widgets".into(),
        arguments: args,
        preconditions: json!({}),
        idempotency_key: "k".into(),
        class,
    }
}

#[test]
fn canonicalize_rejects_unknown_and_missing_fields() {
    let gh = connector("http://unused");
    // unknown field
    let err = gh
        .canonicalize(OP_CREATE_BRANCH, &json!({"owner": "a", "repo": "r", "branch": "b", "from_branch": "main", "force": true}))
        .unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    // missing field
    assert!(gh.canonicalize(OP_CREATE_BRANCH, &json!({"owner": "a"})).is_err());
    // unsupported (and forbidden) operations do not exist
    assert!(gh.canonicalize("github.merge_pull_request", &json!({})).is_err());
    assert!(gh.canonicalize("github.delete_repository", &json!({})).is_err());
    // valid
    let ok = gh
        .canonicalize(OP_READ_REPO, &json!({"repo": "r", "owner": "a"}))
        .unwrap();
    assert_eq!(ok, json!({"owner": "a", "repo": "r"}));
}

#[test]
fn only_declared_operations_exist() {
    let gh = connector("http://unused");
    let ops: Vec<String> = gh.operations().into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        ops,
        vec![OP_READ_REPO, OP_CREATE_BRANCH, OP_CREATE_DRAFT_PR, OP_COMMENT_ISSUE]
    );
    for (_, class) in gh.operations() {
        assert!(class <= EffectClass::Irreversible);
    }
}

#[tokio::test]
async fn create_branch_prepare_captures_precondition_and_commit_creates_ref() {
    let (base, state) = spawn_mock().await;
    let gh = connector(&base);
    let c = contract(
        OP_CREATE_BRANCH,
        json!({"owner": "acme", "repo": "widgets", "branch": "feature-x", "from_branch": "main"}),
        EffectClass::Compensatable,
    );
    let prepared = gh.prepare(&c).await.unwrap();
    assert_eq!(prepared.observed_preconditions, json!({"base_head_sha": "sha-live-1"}));
    assert!(prepared.preview["action"].as_str().unwrap().contains("feature-x"));
    // No side effect from prepare.
    assert!(state.created_refs.lock().unwrap().is_empty());

    let result = gh.commit(&c).await.unwrap();
    assert_eq!(result.response["ref"], "refs/heads/feature-x");
    assert_eq!(state.created_refs.lock().unwrap().len(), 1);
    // Auth header used the token source.
    assert!(state.auth_headers.lock().unwrap().iter().any(|h| h == "Bearer test-token"));

    // Compensation deletes the ref.
    let comp = gh.compensate(&c).await.unwrap();
    assert_eq!(comp.response["deleted_ref"], "refs/heads/feature-x");
    assert!(state.created_refs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn precondition_drift_is_visible_between_prepares() {
    let (base, state) = spawn_mock().await;
    let gh = connector(&base);
    let c = contract(
        OP_CREATE_BRANCH,
        json!({"owner": "acme", "repo": "widgets", "branch": "b", "from_branch": "main"}),
        EffectClass::Compensatable,
    );
    let p1 = gh.prepare(&c).await.unwrap();
    *state.sha.lock().unwrap() = "sha-live-2".into();
    let p2 = gh.prepare(&c).await.unwrap();
    assert_ne!(p1.observed_preconditions, p2.observed_preconditions);
}

#[tokio::test]
async fn draft_pr_commit_and_compensate_closes_pr() {
    let (base, state) = spawn_mock().await;
    let gh = connector(&base);
    let c = contract(
        OP_CREATE_DRAFT_PR,
        json!({"owner": "acme", "repo": "widgets", "title": "Fix", "head": "feature-x", "base": "main", "body": "hi"}),
        EffectClass::Compensatable,
    );
    let prepared = gh.prepare(&c).await.unwrap();
    assert_eq!(prepared.observed_preconditions["base_head_sha"], "sha-live-1");
    assert_eq!(prepared.preview["draft"], true);

    let result = gh.commit(&c).await.unwrap();
    assert_eq!(result.response["number"], 7);
    assert_eq!(result.response["draft"], true);

    let comp = gh.compensate(&c).await.unwrap();
    assert_eq!(comp.response["closed_pr"], 7);
    assert_eq!(*state.pr_state.lock().unwrap(), "closed");
}

#[tokio::test]
async fn comment_on_issue_is_irreversible_and_uncompensatable() {
    let (base, state) = spawn_mock().await;
    let gh = connector(&base);
    let c = contract(
        OP_COMMENT_ISSUE,
        json!({"owner": "acme", "repo": "widgets", "issue_number": 12, "body": "done"}),
        EffectClass::Irreversible,
    );
    let prepared = gh.prepare(&c).await.unwrap();
    assert_eq!(prepared.observed_preconditions, json!({"issue_state": "open"}));
    let result = gh.commit(&c).await.unwrap();
    assert_eq!(result.response["id"], 9001);
    assert_eq!(state.comments.lock().unwrap().len(), 1);
    assert!(gh.compensate(&c).await.is_err());
}

#[tokio::test]
async fn read_repository_is_pure_round_trip() {
    let (base, _state) = spawn_mock().await;
    let gh = connector(&base);
    let c = contract(
        OP_READ_REPO,
        json!({"owner": "acme", "repo": "widgets"}),
        EffectClass::Pure,
    );
    let prepared = gh.prepare(&c).await.unwrap();
    assert_eq!(prepared.preview["full_name"], "acme/widgets");
    let result = gh.commit(&c).await.unwrap();
    assert_eq!(result.response["default_branch"], "main");
}
