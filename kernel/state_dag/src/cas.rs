//! Content-addressed blob store (CAS).
//!
//! Blobs are stored on disk under a root directory, fanned out by the first
//! two hex characters of their SHA-256 digest:
//!
//! ```text
//! <root>/ab/ab34…ef
//! ```
//!
//! The store is immutable and idempotent: writing the same bytes twice is a
//! no-op, and a blob's path is a pure function of its content hash.

use ak_core::hash::{hash_bytes, ContentHash};
use ak_core::{KernelError, KernelResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counter making temp-file names unique across threads within a
/// process (the PID alone distinguishes processes).
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A content-addressed store rooted at a directory.
#[derive(Debug, Clone)]
pub struct Cas {
    root: PathBuf,
}

/// Extract the raw hex digest from a `sha256:<hex>` [`ContentHash`].
pub(crate) fn hex_of(hash: &ContentHash) -> KernelResult<&str> {
    hash.as_str()
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| KernelError::Storage(format!("malformed content hash `{hash}`")))
}

impl Cas {
    /// Open (creating if necessary) a CAS rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> KernelResult<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The root directory of this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, hash: &ContentHash) -> KernelResult<PathBuf> {
        let hex = hex_of(hash)?;
        Ok(self.root.join(&hex[..2]).join(hex))
    }

    /// Store raw bytes, returning their content hash. Idempotent.
    #[tracing::instrument(level = "debug", skip_all, fields(len = bytes.len()))]
    pub fn put(&self, bytes: &[u8]) -> KernelResult<ContentHash> {
        let hash = hash_bytes(bytes);
        let path = self.blob_path(&hash)?;
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            // Write via a unique temp file then rename, so concurrent writers
            // and crashes never leave a truncated blob at the final path.
            let tmp = path.with_extension(format!(
                "tmp-{}-{}",
                std::process::id(),
                TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::write(&tmp, bytes)?;
            fs::rename(&tmp, &path)?;
        }
        Ok(hash)
    }

    /// Load the blob for `hash`, verifying its content hash on the way out.
    /// A mismatch (on-disk tampering or corruption) is a storage error.
    #[tracing::instrument(level = "debug", skip(self), fields(hash = %hash))]
    pub fn get(&self, hash: &ContentHash) -> KernelResult<Vec<u8>> {
        let path = self.blob_path(hash)?;
        let bytes = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KernelError::NotFound {
                    kind: "blob",
                    id: hash.to_string(),
                }
            } else {
                KernelError::Io(e)
            }
        })?;
        let actual = hash_bytes(&bytes);
        if &actual != hash {
            return Err(KernelError::Storage(format!(
                "corrupt CAS blob: expected {hash}, content hashes to {actual}"
            )));
        }
        Ok(bytes)
    }

    /// Whether a blob exists in the store.
    pub fn contains(&self, hash: &ContentHash) -> KernelResult<bool> {
        Ok(self.blob_path(hash)?.exists())
    }

    /// Delete a blob (used by garbage collection). Missing blobs are ignored.
    pub fn remove(&self, hash: &ContentHash) -> KernelResult<()> {
        let path = self.blob_path(hash)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KernelError::Io(e)),
        }
    }

    /// Enumerate every blob currently stored.
    pub fn list(&self) -> KernelResult<Vec<ContentHash>> {
        let mut out = Vec::new();
        for shard in fs::read_dir(&self.root)? {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            for entry in fs::read_dir(shard.path())? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                    out.push(ContentHash(format!("sha256:{name}")));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_idempotent_put() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let h1 = cas.put(b"hello world").unwrap();
        let h2 = cas.put(b"hello world").unwrap();
        assert_eq!(h1, h2);
        assert!(cas.contains(&h1).unwrap());
        assert_eq!(cas.get(&h1).unwrap(), b"hello world");
        assert_eq!(cas.list().unwrap(), vec![h1.clone()]);
        cas.remove(&h1).unwrap();
        assert!(!cas.contains(&h1).unwrap());
        assert!(matches!(cas.get(&h1), Err(KernelError::NotFound { .. })));
    }

    #[test]
    fn malformed_hash_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        assert!(cas.get(&ContentHash("md5:abcd".into())).is_err());
        assert!(cas.get(&ContentHash("sha256:zz".into())).is_err());
    }

    #[test]
    fn tampered_blob_fails_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let h = cas.put(b"pristine").unwrap();
        let path = cas.blob_path(&h).unwrap();
        fs::write(&path, b"tampered").unwrap();
        match cas.get(&h) {
            Err(KernelError::Storage(msg)) => assert!(msg.contains("corrupt CAS blob")),
            other => panic!("expected corruption error, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_writes_of_different_blobs_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let cas = cas.clone();
                std::thread::spawn(move || {
                    let bytes = vec![i; 1024];
                    (cas.put(&bytes).unwrap(), bytes)
                })
            })
            .collect();
        for h in handles {
            let (hash, bytes) = h.join().unwrap();
            assert_eq!(cas.get(&hash).unwrap(), bytes);
        }
        assert_eq!(cas.list().unwrap().len(), 8);
    }
}
