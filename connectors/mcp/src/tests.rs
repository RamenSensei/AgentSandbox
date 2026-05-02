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
            let Ok(req) = serde_json::from_str::<Value>(line.trim()) else { continue };
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
            if writer.write_all(format!("{resp}\n").as_bytes()).await.is_err() {
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
