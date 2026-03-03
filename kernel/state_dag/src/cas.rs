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

/// A content-addressed store rooted at a directory.
#[derive(Debug, Clone)]
pub struct Cas {
    root: PathBuf,
}
