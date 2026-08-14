//! Tests for the `ak-egress-fwd` in-namespace forwarder: standalone bridge
//! behavior on any Unix host (loopback is already up outside a fresh
//! netns), and — where a verified bwrap + probe-passing host allows — the
//! full sandboxed egress path in `egress_sandbox.rs`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

const FWD: &str = env!("CARGO_BIN_EXE_ak-egress-fwd");
static FORWARDER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn serial_forwarder_test() -> MutexGuard<'static, ()> {
    FORWARDER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Host side of the probe hand-shake: echo the pong for each connection.
fn spawn_unix_pong(path: &std::path::Path) {
    let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let mut reader = BufReader::new(conn);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() && line.trim() == "AK_EGRESS_PROBE" {
                let mut conn = reader.into_inner();
                let _ = conn.write_all(b"AK_EGRESS_PONG\n");
            }
        }
    });
}

#[test]
fn probe_mode_round_trips_through_the_unix_socket() {
    let _serial = serial_forwarder_test();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("probe.sock");
    spawn_unix_pong(&sock);
    let out = Command::new(FWD)
        .args(["--listen", "127.0.0.1:0"])
        .arg("--unix")
        .arg(&sock)
        .arg("--probe")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("probe-ok"));
}

#[test]
fn probe_fails_loudly_when_the_socket_answers_wrong() {
    let _serial = serial_forwarder_test();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("mute.sock");
    // A listener that accepts and closes without answering.
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || for _conn in listener.incoming().flatten() {});
    let out = Command::new(FWD)
        .args(["--listen", "127.0.0.1:0"])
        .arg("--unix")
        .arg(&sock)
        .arg("--probe")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("probe"));
}

#[test]
fn wrapped_command_exit_code_is_propagated() {
    let _serial = serial_forwarder_test();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("x.sock");
    spawn_unix_pong(&sock);
    let status = Command::new(FWD)
        .args(["--listen", "127.0.0.1:0"])
        .arg("--unix")
        .arg(&sock)
        .args(["--", "/bin/sh", "-c", "exit 7"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(7));
}

/// The forwarder bridges arbitrary bytes, not just the probe line: a raw
/// TCP client through the listener reaches the Unix side verbatim. Uses a
/// dynamically selected host port (the production netns uses a fixed port,
/// but its fresh namespace guarantees exclusivity).
#[test]
fn bridges_raw_bytes_between_tcp_and_unix() {
    // This test must not race the `:0` probe processes above between
    // releasing its reserved port and the child binding that same port.
    let _serial = serial_forwarder_test();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bridge.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut conn = conn;
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let Ok(mut child) = Command::new(FWD)
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .arg("--unix")
        .arg(&sock)
        .args(["--", "/bin/sh", "-c", "sleep 5"])
        .spawn()
    else {
        return;
    };
    // Wait for the listener, then echo through it.
    let mut conn = None;
    for _ in 0..50 {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    let Some(mut conn) = conn else {
        let _ = child.kill();
        panic!("forwarder listener never came up");
    };
    conn.write_all(b"raw-bridge-bytes").unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"raw-bridge-bytes");
    let _ = child.kill();
    let _ = child.wait();
}
