//! `ak-egress-fwd` — the in-namespace egress forwarder for bubblewrap
//! sandboxes.
//!
//! bwrap unshares the network namespace, so the host-loopback egress proxy
//! is unreachable from inside — the honest options are "no egress" or a
//! bridge whose only reachable endpoint is the proxy. This binary is that
//! bridge. It runs **inside** the sandbox as PID-1-adjacent wrapper of the
//! confined command:
//!
//! 1. brings the namespace's loopback interface up (requires
//!    `CAP_NET_ADMIN` over the fresh netns; the backend probes for the
//!    bwrap flags that grant it),
//! 2. listens on a fixed in-namespace TCP address (the sandbox's
//!    `http_proxy`),
//! 3. forwards each accepted connection byte-for-byte into a Unix socket
//!    bind-mounted from the host, where the real egress proxy enforces
//!    token auth, the domain allowlist, SSRF guards and byte caps,
//! 4. execs the confined command and exits with its status.
//!
//! The forwarder adds **no authority**: the Unix socket is the proxy's own
//! listener, every connection still authenticates with the per-step token,
//! and nothing else exists in the namespace to talk to. With `--probe` it
//! instead performs a self-test (connect to its own listener, round-trip
//! one line through the Unix socket) and exits 0/1 — the backend's
//! construction-time probe runs exactly this inside a scratch sandbox
//! before ever advertising egress capability.
//!
//! Deliberately `std`-only (plus `libc` for the loopback ioctl): it must
//! be a small, dependency-free binary that works on any glibc/musl rootfs.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::exit;

fn fail(msg: &str) -> ! {
    eprintln!("ak-egress-fwd: {msg}");
    exit(3);
}

struct Args {
    listen: String,
    unix: PathBuf,
    probe: bool,
    command: Vec<String>,
}

fn parse_args() -> Args {
    let mut listen = None;
    let mut unix = None;
    let mut probe = false;
    let mut command = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => listen = it.next(),
            "--unix" => unix = it.next().map(PathBuf::from),
            "--probe" => probe = true,
            "--" => {
                command = it.collect();
                break;
            }
            other => fail(&format!("unknown argument `{other}`")),
        }
    }
    let (Some(listen), Some(unix)) = (listen, unix) else {
        fail("usage: ak-egress-fwd --listen ADDR --unix PATH (--probe | -- CMD ...)");
    };
    if !probe && command.is_empty() {
        fail("no command given (and not --probe)");
    }
    Args {
        listen,
        unix,
        probe,
        command,
    }
}

/// Bring `lo` up in this network namespace. Loopback starts DOWN in a
/// fresh netns; without this, nothing can connect to the listener.
#[cfg(target_os = "linux")]
fn up_loopback() -> std::io::Result<()> {
    // SAFETY: standard SIOCGIFFLAGS/SIOCSIFFLAGS ioctl sequence over a
    // throwaway datagram socket, with a zeroed, properly-sized ifreq.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        // Standalone probe/bridge tests (and operational diagnostics) run
        // in the host namespace, whose loopback is already up. Avoid a
        // needless privileged SIOCSIFFLAGS there; a fresh bwrap netns still
        // reaches the write below and therefore still requires CAP_NET_ADMIN.
        if ifr.ifr_ifru.ifru_flags & libc::IFF_UP as libc::c_short != 0 {
            libc::close(fd);
            return Ok(());
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        libc::close(fd);
    }
    Ok(())
}

/// Outside Linux there is no netns; the host loopback is already up.
#[cfg(not(target_os = "linux"))]
fn up_loopback() -> std::io::Result<()> {
    Ok(())
}

/// Copy one direction until EOF/error, then propagate the shutdown.
fn pump(mut from: impl Read, to: impl ShutdownWrite) -> std::io::Result<()> {
    let mut to = to;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            let _ = to.shutdown_write();
            return Ok(());
        }
        to.write_all(&buf[..n])?;
    }
}

trait ShutdownWrite: Write {
    fn shutdown_write(&mut self) -> std::io::Result<()>;
}
impl ShutdownWrite for TcpStream {
    fn shutdown_write(&mut self) -> std::io::Result<()> {
        TcpStream::shutdown(self, std::net::Shutdown::Write)
    }
}
impl ShutdownWrite for UnixStream {
    fn shutdown_write(&mut self) -> std::io::Result<()> {
        UnixStream::shutdown(self, std::net::Shutdown::Write)
    }
}

fn bridge(conn: TcpStream, unix_path: PathBuf) {
    let Ok(upstream) = UnixStream::connect(&unix_path) else {
        return; // proxy gone; the connection just fails
    };
    let conn_r = match conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let up_w = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    let t = std::thread::spawn(move || {
        let _ = pump(conn_r, up_w);
    });
    let _ = pump(upstream, conn);
    let _ = t.join();
}

fn main() {
    let args = parse_args();
    if let Err(e) = up_loopback() {
        fail(&format!(
            "cannot bring loopback up in this namespace: {e} \
             (the sandbox needs CAP_NET_ADMIN over its fresh netns)"
        ));
    }
    let listener = match TcpListener::bind(&args.listen) {
        Ok(l) => l,
        Err(e) => fail(&format!("cannot bind {}: {e}", args.listen)),
    };
    let local = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => fail(&format!("no local addr: {e}")),
    };
    let unix_path = args.unix.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let path = unix_path.clone();
            std::thread::spawn(move || bridge(conn, path));
        }
    });

    if args.probe {
        // Self-test: TCP into our own listener, expect the host side of the
        // Unix socket to echo one probe line back through the bridge.
        let mut conn = match TcpStream::connect(local) {
            Ok(c) => c,
            Err(e) => fail(&format!("probe connect failed: {e}")),
        };
        conn.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        if conn.write_all(b"AK_EGRESS_PROBE\n").is_err() {
            fail("probe write failed");
        }
        let mut reply = [0u8; 64];
        let n = conn.read(&mut reply).unwrap_or(0);
        if &reply[..n] == b"AK_EGRESS_PONG\n" {
            println!("probe-ok");
            exit(0);
        }
        fail("probe round trip did not return AK_EGRESS_PONG");
    }

    let status = std::process::Command::new(&args.command[0])
        .args(&args.command[1..])
        .status();
    match status {
        Ok(s) => exit(s.code().unwrap_or(-1)),
        Err(e) => fail(&format!("exec {:?} failed: {e}", args.command[0])),
    }
}
