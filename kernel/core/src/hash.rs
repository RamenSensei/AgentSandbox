//! Canonical hashing utilities.
//!
//! Every artifact that participates in authorization (effect contracts, policy
//! documents, receipts) is hashed over a *canonical JSON* encoding: object keys
//! sorted lexicographically, no insignificant whitespace, UTF-8. Commit-time
//! revalidation compares these hashes, so canonicalization must be stable.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// A lowercase hex-encoded SHA-256 digest, prefixed with the algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, Serialize)]
#[serde(transparent)]
pub struct ContentHash(pub String);

impl ContentHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Hash raw bytes.
pub fn hash_bytes(bytes: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    ContentHash(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Hash any serializable value over its canonical JSON encoding.
pub fn hash_canonical<T: Serialize>(value: &T) -> ContentHash {
    hash_bytes(canonical_json(value).as_bytes())
}

/// Produce canonical JSON: keys sorted, compact separators.
pub fn canonical_json<T: Serialize>(value: &T) -> String {
    let v = serde_json::to_value(value).expect("canonical_json: value must serialize");
    let mut out = String::new();
    write_canonical(&v, &mut out);
    out
}

fn write_canonical(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn canonicalization_sorts_keys_recursively() {
        let a = json!({"b": 1, "a": {"z": true, "y": [1, {"q": 2, "p": 3}]}});
        assert_eq!(
            canonical_json(&a),
            r#"{"a":{"y":[1,{"p":3,"q":2}],"z":true},"b":1}"#
        );
    }

    #[test]
    fn key_order_does_not_change_hash() {
        let a = json!({"x": 1, "y": 2});
        let b = json!({"y": 2, "x": 1});
        assert_eq!(hash_canonical(&a), hash_canonical(&b));
    }
}
