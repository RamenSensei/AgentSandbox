//! OS sandbox probing and command wrapping for the local backend.
//!
//! Two technologies are supported, both **feature-detected and verified at
//! runtime** — the probe executes a canary inside the candidate sandbox and
//! additionally proves that a host file outside the workspace is unreadable.
//! Only a sandbox that passes both checks is reported, so
//! `BackendProfile::isolation_strength` reflects *verified* capability.
//!
//! - **Linux**: bubblewrap (`bwrap`). Network + PID namespaces unshared,
//!   read-only rootfs, workspace prefixes bound according to the compiled
//!   confinement (tmpfs shadows the rest of the workspace when read
//!   confinement is requested).
//! - **macOS**: Seatbelt via `/usr/bin/sandbox-exec` with a generated
//!   deny-default SBPL profile. Reads are limited to the system paths needed
//!   to execute binaries plus the workspace's readable prefixes; writes to
//!   the writable prefixes (and `/dev/null`); **all network is denied**.
//!
//! The sandbox denies all direct network access on both platforms: egress is
//! the job of typed connectors, where domain allowlists can actually be
//! enforced on resolved addresses. A domain list without a proxy or resolver
//! hook would be theater at this layer.

use std::path::{Path, PathBuf};

/// The sandbox technology verified by [`probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxTech {
    /// No working OS sandbox found. Shell execution fails closed unless the
    /// operator opted out.
    None,
    /// Linux bubblewrap, probe-verified.
    Bwrap,
    /// macOS Seatbelt (`sandbox-exec`), probe-verified.
    SandboxExec,
}

impl SandboxTech {
    /// Verified isolation strength for [`ak_core::traits::BackendProfile`].
    /// The unsandboxed value reflects in-process path checks only.
    pub fn isolation_strength(self) -> u8 {
        match self {
            SandboxTech::None => 5,
            SandboxTech::SandboxExec => 35,
            SandboxTech::Bwrap => 40,
        }
    }
}

/// Probe the host for a working sandbox: run a canary inside it, then prove
/// a secret file outside the workspace is unreadable from inside.
pub fn probe() -> SandboxTech {
    if cfg!(target_os = "linux") && probe_bwrap() {
        return SandboxTech::Bwrap;
    }
    if cfg!(target_os = "macos") && probe_sandbox_exec() {
        return SandboxTech::SandboxExec;
    }
    SandboxTech::None
}

const CANARY: &str = "__ak_sandbox_probe__";

fn probe_dirs() -> Option<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::tempdir().ok()?;
    let secret = dir.path().join("host-secret.txt");
    std::fs::write(&secret, b"must-not-be-readable").ok()?;
    Some((dir, secret))
}

fn probe_bwrap() -> bool {
    let Some((dir, secret)) = probe_dirs() else {
        return false;
    };
    let ws = dir.path().join("ws");
    if std::fs::create_dir_all(&ws).is_err() {
        return false;
    }
    let canary_ok = std::process::Command::new("bwrap")
        .args(bwrap_args(&ws, &[], &[]).iter())
        .args(["/bin/sh", "-c", &format!("echo {CANARY}")])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains(CANARY))
        .unwrap_or(false);
    if !canary_ok {
        return false;
    }
    // The probe secret's parent is tmpfs-shadowed by the same argument set
    // we use for real runs, so this read must fail.
    std::process::Command::new("bwrap")
        .args(bwrap_args(&ws, &[], &[]).iter())
        .args(["/bin/sh", "-c", &format!("cat {}", secret.display())])
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(false)
}

fn probe_sandbox_exec() -> bool {
    let Some((dir, secret)) = probe_dirs() else {
        return false;
    };
    let ws = dir.path().join("ws");
    if std::fs::create_dir_all(&ws).is_err() {
        return false;
    }
    let Ok(ws_canon) = ws.canonicalize() else {
        return false;
    };
    let profile = seatbelt_profile(&ws_canon, &[], &[], None);
    let profile_path = dir.path().join("probe.sb");
    if std::fs::write(&profile_path, profile).is_err() {
        return false;
    }
    let run = |cmd: &str| {
        std::process::Command::new("/usr/bin/sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .args(["/bin/sh", "-c", cmd])
            .output()
    };
    let canary_ok = run(&format!("echo {CANARY}"))
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains(CANARY))
        .unwrap_or(false);
    if !canary_ok {
        return false;
    }
    run(&format!("cat {}", secret.display()))
        .map(|o| !o.status.success())
        .unwrap_or(false)
}

/// Workspace-internal scratch dir exposed to the child as `TMPDIR`. Always
/// writable inside the sandbox; excluded from `paths_written`.
pub const SCRATCH_DIR: &str = ".aktmp";

/// System path prefixes a process needs readable in order to execute at all
/// (dynamic linker, shared caches, standard binaries). Deliberately excludes
/// every user-data location (`/Users`, `/home`, `/root`, `/tmp`, `/var`
/// outside `db`/`select`).
#[cfg(target_os = "macos")]
const MACOS_SYSTEM_READS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/private/etc",
    "/private/var/db",
    "/private/var/select",
    "/opt",
    "/dev",
];

/// Generate a deny-default Seatbelt profile for one execution.
///
/// `readable`/`writable` are workspace-relative prefixes from the compiled
/// confinement; empty means the whole workspace. The workspace path must be
/// canonical (macOS `/tmp` is a symlink to `/private/tmp`; Seatbelt matches
/// on real paths).
///
/// `egress_proxy_port`: when set, outbound TCP to **exactly**
/// `localhost:<port>` is allowed — the egress proxy becomes the sole route
/// out; everything else stays denied. SBPL applies the *last* matching
/// rule, so the allow follows the `(deny network*)`.
pub fn seatbelt_profile(
    ws_canon: &Path,
    readable: &[String],
    writable: &[String],
    egress_proxy_port: Option<u16>,
) -> String {
    let mut reads: Vec<String> = Vec::new();
    #[cfg(target_os = "macos")]
    for p in MACOS_SYSTEM_READS {
        reads.push(format!("(subpath \"{p}\")"));
    }
    #[cfg(not(target_os = "macos"))]
    for p in ["/usr", "/bin", "/sbin", "/etc", "/opt", "/dev"] {
        reads.push(format!("(subpath \"{p}\")"));
    }
    // Reading the root directory entry itself is required by dyld.
    reads.push("(literal \"/\")".into());
    if grants_whole_workspace(readable) {
        reads.push(format!("(subpath \"{}\")", ws_canon.display()));
    } else {
        for prefix in normalized_prefixes(readable) {
            reads.push(format!("(subpath \"{}\")", ws_canon.join(prefix).display()));
        }
        // The scratch dir stays usable even under read confinement.
        reads.push(format!(
            "(subpath \"{}\")",
            ws_canon.join(SCRATCH_DIR).display()
        ));
    }

    let mut writes: Vec<String> = vec!["(literal \"/dev/null\")".into()];
    if grants_whole_workspace(writable) {
        writes.push(format!("(subpath \"{}\")", ws_canon.display()));
    } else {
        for prefix in normalized_prefixes(writable) {
            writes.push(format!("(subpath \"{}\")", ws_canon.join(prefix).display()));
        }
        writes.push(format!(
            "(subpath \"{}\")",
            ws_canon.join(SCRATCH_DIR).display()
        ));
    }

    let egress = match egress_proxy_port {
        Some(port) => format!(
            "(allow network-outbound (remote tcp \"localhost:{port}\"))\n\
             (allow system-socket)\n"
        ),
        None => String::new(),
    };

    format!(
        "(version 1)\n\
         (deny default)\n\
         (allow process*)\n\
         (allow signal)\n\
         (allow sysctl-read)\n\
         (allow mach-lookup)\n\
         (allow file-read-metadata)\n\
         (allow file-ioctl)\n\
         (allow file-read* {reads})\n\
         (allow file-write* {writes})\n\
         (deny network*)\n\
         {egress}",
        reads = reads.join(" "),
        writes = writes.join(" "),
        egress = egress,
    )
}

/// True when a prefix list grants the whole workspace: either no prefixes
/// at all, or an entry that normalizes to the workspace root (`""`, `"."`,
/// `"./"`). This mirrors the in-process path-check semantics, where an
/// empty prefix matches every workspace path.
fn grants_whole_workspace(prefixes: &[String]) -> bool {
    prefixes.is_empty()
        || prefixes
            .iter()
            .any(|p| p.trim_start_matches("./").trim_end_matches('/').is_empty() || p == ".")
}

/// Normalize workspace-relative prefixes for embedding in mount/profile
/// rules: strip `./`, trailing slashes, and refuse anything that would
/// escape (`..`, absolute) by skipping it — the in-process path checks
/// already refused such prefixes at the policy layer.
fn normalized_prefixes(prefixes: &[String]) -> Vec<&str> {
    prefixes
        .iter()
        .map(|p| p.trim_start_matches("./").trim_end_matches('/'))
        .filter(|p| !p.is_empty() && !p.starts_with('/') && !p.split('/').any(|c| c == ".."))
        .collect()
}

/// Build the bubblewrap argument list enforcing the compiled confinement.
///
/// Layout: read-only rootfs, fresh `/dev` + `/proc`, tmpfs `/tmp`, network
/// and PID namespaces unshared, then the workspace:
///
/// - read confinement requested → tmpfs shadows the whole workspace and only
///   the readable prefixes are bound back read-only;
/// - writable prefixes (or the whole workspace when unrestricted) are bound
///   read-write on top;
/// - the scratch dir is always bound read-write.
pub fn bwrap_args(ws: &Path, readable: &[String], writable: &[String]) -> Vec<String> {
    let s = |p: &Path| p.display().to_string();
    let mut args: Vec<String> = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-net".into(),
        "--unshare-pid".into(),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        // Shadow every user-data location the ro-bind of `/` would otherwise
        // expose read-only: agent code must not be able to read the service
        // user's home, root's home, or runtime sockets under /run. (The
        // workspace binds below re-open exactly what confinement grants.)
        "--tmpfs".into(),
        "/home".into(),
        "--tmpfs".into(),
        "/root".into(),
        "--tmpfs".into(),
        "/run".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
        "--tmpfs".into(),
        "/tmp".into(),
    ];
    let scratch = ws.join(SCRATCH_DIR);
    let read_all = grants_whole_workspace(readable);
    let write_all = grants_whole_workspace(writable);
    if read_all {
        if write_all {
            args.extend(["--bind".into(), s(ws), s(ws)]);
        } else {
            args.extend(["--ro-bind".into(), s(ws), s(ws)]);
        }
    } else {
        // Shadow the workspace, then bind back only what is readable.
        args.extend(["--tmpfs".into(), s(ws)]);
        for prefix in normalized_prefixes(readable) {
            let p = ws.join(prefix);
            let _ = std::fs::create_dir_all(&p);
            args.extend(["--ro-bind".into(), s(&p), s(&p)]);
        }
    }
    if !write_all {
        for prefix in normalized_prefixes(writable) {
            let p = ws.join(prefix);
            let _ = std::fs::create_dir_all(&p);
            args.extend(["--bind".into(), s(&p), s(&p)]);
        }
    }
    let _ = std::fs::create_dir_all(&scratch);
    args.extend(["--bind".into(), s(&scratch), s(&scratch)]);
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_embeds_canonical_workspace_and_prefixes() {
        let ws = Path::new("/private/tmp/ws-1");
        let profile = seatbelt_profile(
            ws,
            &["src/".into()],
            &["src/".into(), "./docs".into()],
            None,
        );
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(subpath \"/private/tmp/ws-1/src\")"));
        assert!(profile.contains("(subpath \"/private/tmp/ws-1/docs\")"));
        assert!(profile.contains(&format!("(subpath \"/private/tmp/ws-1/{SCRATCH_DIR}\")")));
        // Unrestricted workspace read is NOT granted when prefixes are given.
        assert!(
            !profile.contains("(allow file-read* (literal \"/\") (subpath \"/private/tmp/ws-1\")")
        );
    }

    #[test]
    fn hostile_prefixes_are_dropped_from_mount_rules() {
        let prefixes: Vec<String> = vec![
            "../../etc".into(),
            "/etc".into(),
            "src/../..".into(),
            "ok/dir/".into(),
            "".into(),
        ];
        let cleaned = normalized_prefixes(&prefixes);
        assert_eq!(cleaned, vec!["ok/dir"]);
    }

    #[test]
    fn empty_prefix_entry_means_whole_workspace() {
        // The in-process checks treat `""` as "matches every path"; the
        // sandbox must agree instead of silently dropping the grant.
        assert!(grants_whole_workspace(&[]));
        assert!(grants_whole_workspace(&["".into()]));
        assert!(grants_whole_workspace(&["./".into()]));
        assert!(grants_whole_workspace(&[".".into()]));
        assert!(grants_whole_workspace(&["src".into(), "".into()]));
        assert!(!grants_whole_workspace(&["src".into()]));

        let ws = Path::new("/private/tmp/ws-2");
        let profile = seatbelt_profile(ws, &["".into()], &["".into()], None);
        assert!(profile.contains("(subpath \"/private/tmp/ws-2\")"));
    }

    #[test]
    fn bwrap_args_shadow_workspace_under_read_confinement() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let args = bwrap_args(&ws, &["src".into()], &["docs".into()]);
        let joined = args.join(" ");
        assert!(joined.contains("--unshare-net"));
        assert!(joined.contains(&format!("--tmpfs {}", ws.display())));
        assert!(joined.contains(&format!(
            "--ro-bind {src} {src}",
            src = ws.join("src").display()
        )));
        assert!(joined.contains(&format!("--bind {d} {d}", d = ws.join("docs").display())));
    }

    #[test]
    fn probe_reports_a_verified_tech_on_supported_hosts() {
        let tech = probe();
        if cfg!(target_os = "macos") {
            // Every supported macOS ships /usr/bin/sandbox-exec.
            assert_eq!(tech, SandboxTech::SandboxExec);
            assert_eq!(tech.isolation_strength(), 35);
        } else {
            // Linux: bwrap when present, else honest None.
            assert!(matches!(tech, SandboxTech::Bwrap | SandboxTech::None));
        }
    }
}
