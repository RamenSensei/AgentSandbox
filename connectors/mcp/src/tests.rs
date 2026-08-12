//! Tests for the MCP gateway, driven by a tiny in-test MCP server speaking
//! newline-delimited JSON-RPC over `tokio::io::duplex` streams (a stand-in
//! for a child process's stdio).

use super::*;
use ed25519_dalek::{Signer, SigningKey};

/// Spawn the in-test MCP server; returns the client-side streams.
fn spawn_test_server() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    // client writes -> server reads; server writes -> client reads
    let (client_w, server_r) = tokio::io::duplex(64 * 1024);
    let (server_w, client_r) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut reader = BufReader::new(server_r);
        let mut writer = server_w;
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            let Ok(req) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            let id = req["id"].clone();
            let result = match req["method"].as_str() {
                Some("tools/list") => json!({
                    "tools": [
                        {"name": "echo", "description": "echo text back"},
                        {"name": "delete_everything", "description": "dangerous"},
                    ]
                }),
                Some("tools/call") => {
                    let name = req["params"]["name"].as_str().unwrap_or("");
                    if name == "echo" {
                        json!({"content": [{"type": "text", "text": req["params"]["arguments"]["text"]}]})
                    } else {
                        json!({"content": [{"type": "text", "text": format!("ran {name}")}]})
                    }
                }
                _ => {
                    let resp = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unknown method"}});
                    let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                    continue;
                }
            };
            let resp = json!({"jsonrpc": "2.0", "id": id, "result": result});
            if writer
                .write_all(format!("{resp}\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
        }
    });
    (client_r, client_w)
}

const MANIFEST_YAML: &str = r#"
tools:
  echo:
    class: pure
    params:
      text:
        required: true
        type: string
        max_len: 100
      mode:
        one_of: ["plain", "loud"]
"#;

fn signed_manifest() -> (SignedManifest, String) {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let signature = key.sign(MANIFEST_YAML.as_bytes());
    (
        SignedManifest {
            manifest_yaml: MANIFEST_YAML.to_string(),
            signature: hex::encode(signature.to_bytes()),
            key_id: "manifest-key-1".into(),
        },
        hex::encode(key.verifying_key().to_bytes()),
    )
}

fn gateway(with_manifest: bool) -> McpGateway {
    let (r, w) = spawn_test_server();
    if with_manifest {
        let (m, pubkey) = signed_manifest();
        McpGateway::from_streams("notes", r, w, Some((&m, &pubkey))).expect("gateway")
    } else {
        McpGateway::from_streams("notes", r, w, None).expect("gateway")
    }
}

fn contract(op: &str, args: Value, class: EffectClass) -> EffectContract {
    EffectContract {
        operation: op.into(),
        resource: "mcp://notes".into(),
        arguments: args,
        preconditions: json!({}),
        idempotency_key: "k".into(),
        class,
    }
}

#[tokio::test]
async fn tools_list_and_call_round_trip() {
    let g = gateway(true);
    let tools = g.list_tools().await.expect("list");
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "echo");

    let c = contract("notes.echo", json!({"text": "hi"}), EffectClass::Pure);
    let prepared = g.prepare(&c).await.expect("prepare");
    assert_eq!(
        prepared.observed_preconditions,
        json!({"tool_listed": true})
    );
    assert_eq!(prepared.preview["declared_class"], "pure");
    assert_eq!(prepared.preview["manifest_backed"], true);

    let result = g.commit(&c).await.expect("commit");
    assert_eq!(result.response["content"][0]["text"], "hi");
}

#[tokio::test]
async fn undeclared_tools_default_to_opaque_external() {
    let g = gateway(true);
    assert_eq!(
        g.effect_class("delete_everything"),
        EffectClass::OpaqueExternal
    );
    assert_eq!(g.effect_class("echo"), EffectClass::Pure);
    // Without any manifest, everything is opaque and nothing is advertised.
    let g2 = gateway(false);
    assert_eq!(g2.effect_class("echo"), EffectClass::OpaqueExternal);
    assert!(g2.operations().is_empty());
    // Advertised ops carry the manifest classes.
    let ops = g.operations();
    assert_eq!(ops, vec![("notes.echo".to_string(), EffectClass::Pure)]);
}

#[tokio::test]
async fn manifest_constraints_are_enforced_before_forwarding() {
    let g = gateway(true);
    // missing required param
    assert!(g.canonicalize("notes.echo", &json!({})).is_err());
    // wrong type
    assert!(g.canonicalize("notes.echo", &json!({"text": 5})).is_err());
    // undeclared param
    assert!(g
        .canonicalize("notes.echo", &json!({"text": "hi", "evil": true}))
        .is_err());
    // value outside one_of
    assert!(g
        .canonicalize("notes.echo", &json!({"text": "hi", "mode": "shout"}))
        .is_err());
    // over max_len
    assert!(g
        .canonicalize("notes.echo", &json!({"text": "x".repeat(200)}))
        .is_err());
    // ok
    assert!(g
        .canonicalize("notes.echo", &json!({"text": "hi", "mode": "loud"}))
        .is_ok());
    // commit re-enforces even if canonicalize was bypassed
    let bad = contract(
        "notes.echo",
        json!({"evil": true, "text": "hi"}),
        EffectClass::Pure,
    );
    assert!(g.commit(&bad).await.is_err());
}

#[tokio::test]
async fn prepare_refuses_unlisted_tools_and_foreign_operations() {
    let g = gateway(true);
    let c = contract("notes.nonexistent", json!({}), EffectClass::OpaqueExternal);
    assert!(g.prepare(&c).await.is_err());
    let foreign = contract(
        "github.create_branch",
        json!({}),
        EffectClass::Compensatable,
    );
    assert!(g.prepare(&foreign).await.is_err());
    assert!(g.canonicalize("github.create_branch", &json!({})).is_err());
}

#[test]
fn manifest_signature_is_verified() {
    let (m, pubkey) = signed_manifest();
    assert!(m.verify_and_parse(&pubkey).is_ok());
    // Tampered manifest fails.
    let mut tampered = m.clone();
    tampered.manifest_yaml = tampered.manifest_yaml.replace("pure", "irreversible");
    assert!(tampered.verify_and_parse(&pubkey).is_err());
    // Wrong key fails.
    let other = SigningKey::generate(&mut rand::rngs::OsRng);
    let other_pub = hex::encode(other.verifying_key().to_bytes());
    assert!(m.verify_and_parse(&other_pub).is_err());
    // Gateway construction refuses a bad manifest.
    let (r, w) = spawn_test_server_sync();
    assert!(McpGateway::from_streams("notes", r, w, Some((&tampered, &pubkey))).is_err());
}

/// Non-async wrapper (the streams don't need a live server for this test).
fn spawn_test_server_sync() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    let (_a, b) = tokio::io::duplex(1024);
    let (c, _d) = tokio::io::duplex(1024);
    (b, c)
}
