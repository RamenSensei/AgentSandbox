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
