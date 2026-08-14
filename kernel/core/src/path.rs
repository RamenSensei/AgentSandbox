//! Workspace-relative path semantics, shared by every component that
//! confines paths: the local sandbox, remote state sync, and the kernel's
//! validation of remote-returned deltas. One definition, one behavior.

use std::path::{Component, Path, PathBuf};

/// Normalize a workspace-relative path: reject absolute paths, `..`
/// components, and empty paths. `.` components are dropped, so `"."`
/// normalizes to the empty path (the workspace root) — callers that need a
/// file path must reject an empty result themselves. Returns the normalized
/// relative [`PathBuf`] or a human-readable refusal reason.
pub fn normalize_relative(raw: &str) -> Result<PathBuf, String> {
    let p = Path::new(raw);
    if p.as_os_str().is_empty() {
        return Err("empty path".into());
    }
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => return Err(format!("path `{raw}` contains `..`")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "path `{raw}` is absolute; only workspace-relative paths are allowed"
                ))
            }
        }
    }
    Ok(out)
}

/// Check a normalized relative path against allowed prefixes. An empty prefix
/// list means the whole workspace is allowed; an empty-string prefix likewise.
pub fn matches_prefixes(rel: &Path, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    prefixes.iter().any(|p| {
        let p = p.trim_start_matches("./").trim_end_matches('/');
        if p.is_empty() {
            return true;
        }
        rel.starts_with(p)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_rejects() {
        assert_eq!(normalize_relative("a/b.txt").unwrap(), Path::new("a/b.txt"));
        assert_eq!(normalize_relative("./a/./b").unwrap(), Path::new("a/b"));
        assert_eq!(normalize_relative(".").unwrap(), Path::new(""));
        assert!(normalize_relative("").is_err());
        assert!(normalize_relative("a/../b").is_err());
        assert!(normalize_relative("/etc/passwd").is_err());
    }

    #[test]
    fn prefix_matching() {
        let rel = Path::new("src/main.rs");
        assert!(matches_prefixes(rel, &[]));
        assert!(matches_prefixes(rel, &["".into()]));
        assert!(matches_prefixes(rel, &["./src/".into()]));
        assert!(matches_prefixes(rel, &["docs".into(), "src".into()]));
        assert!(!matches_prefixes(rel, &["docs".into()]));
        // Prefixes are path components, not string prefixes.
        assert!(!matches_prefixes(Path::new("srcx/f.rs"), &["src".into()]));
    }
}
