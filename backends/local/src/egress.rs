//! Transparent egress proxy: controlled network for sandboxed workloads.
//!
//! The sandbox denies all direct network. When a step's compiled confinement
//! grants egress domains, the backend hands the workload standard
//! `HTTP_PROXY`/`HTTPS_PROXY` and `ALL_PROXY` environment variables pointing
//! at this loopback proxy with a **per-step bearer token** — so HTTP-native
//! package managers as well as SOCKS-aware SSH/database clients work without
//! sandbox-specific adapters, while policy is enforced at the one place a
//! domain allowlist can actually be enforced: the egress hop.
//!
//! Per connection the proxy enforces:
//!
//! - **token auth** (`Proxy-Authorization: Basic <token:>`): a connection
//!   without a valid session token gets `407` and reaches nothing;
//! - **domain allowlist** (`*`-globs) from the step's confinement;
//! - **SSRF guards**: literal-IP targets refused, names resolved and every
//!   address checked against [`ak_core::net::is_forbidden_ip`], the
//!   connection **pinned** to the vetted address (no second lookup);
//! - **port allowlist** (default 80/443);
//! - **byte caps** counted over both directions and charged to the step's
//!   `network_bytes` budget dimension.
//!
//! HTTP `CONNECT` tunneling (TLS passes through end-to-end; the proxy never
//! terminates TLS), absolute-URI plain HTTP and authenticated SOCKS5 CONNECT
//! are supported on the same listener and share the same policy/session.
//!
//! Sandbox reachability: on macOS the generated Seatbelt profile opens
//! **only** `localhost:<proxy port>` outbound; everything else stays
//! denied, so the proxy is the sole route out. On Linux bubblewrap
//! unshares the network namespace entirely — host loopback is unreachable
//! from inside, so the proxy also serves a **Unix socket**
//! ([`EgressProxy::serve_unix`]) that is bind-mounted into the sandbox,
//! where the `ak-egress-fwd` forwarder (probe-verified at backend
//! construction, see [`crate::sandbox::probe_netns_egress`]) bridges an
//! in-namespace loopback listener to it. The namespace has no other
//! interface and the socket leads only to this proxy, so the token +
//! allowlist + SSRF guards below stay the sole route out. Hosts where the
//! probe fails keep egress off (honest fail-closed, not silent bypass).

use ak_core::capability::glob_match;
use ak_core::net::is_forbidden_ip;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Configuration for the egress proxy.
#[derive(Debug, Clone)]
pub struct EgressConfig {
    /// Master switch. When off (or when no egress domains are granted) the
    /// workload gets no proxy environment and no network.
    pub enabled: bool,
    /// Destination ports a workload may reach. Empty = any port.
    pub allowed_ports: Vec<u16>,
    /// **Tests only.** Allow loopback destinations (and any port), so a
    /// mock server can stand in for the internet.
    pub danger_allow_loopback: bool,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_ports: vec![80, 443],
            danger_allow_loopback: false,
        }
    }
}

/// One active egress session (== one shell step or process session).
#[derive(Clone)]
struct Session {
    domains: Vec<String>,
    used: Arc<AtomicU64>,
    revoked: Arc<AtomicBool>,
    cap: u64,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

/// Owns every proxy listener task and Unix socket path. Grants share this
/// owner, so a long-lived process grant keeps its route alive even if the
/// proxy handle moves; dropping the last owner aborts listeners and unlinks
/// sockets instead of leaking backend-scoped tasks.
#[derive(Default)]
struct ListenerRegistry {
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    unix_paths: Mutex<Vec<std::path::PathBuf>>,
}

impl ListenerRegistry {
    fn add_task(&self, task: &tokio::task::JoinHandle<()>) {
        self.tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(task.abort_handle());
    }

    fn add_unix_path(&self, path: &std::path::Path) {
        self.unix_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.to_path_buf());
    }
}

impl Drop for ListenerRegistry {
    fn drop(&mut self) {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            task.abort();
        }
        for path in self
            .unix_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A live grant to use the proxy: carries the token-bearing proxy URL for
/// the workload's environment and the live byte counter. Dropping the grant
/// revokes the token: no new connection can authenticate and existing
/// tunnels stop at their next buffer boundary.
pub struct EgressGrant {
    token: String,
    port: u16,
    used: Arc<AtomicU64>,
    revoked: Arc<AtomicBool>,
    sessions: Sessions,
    listeners: Arc<ListenerRegistry>,
}

impl EgressGrant {
    /// `http://<token>@127.0.0.1:<port>` — standard proxy-URL shape every
    /// mainstream tool turns into `Proxy-Authorization: Basic`.
    pub fn proxy_url(&self) -> String {
        self.proxy_url_via(self.port)
    }

    /// The proxy URL through a different local port — used under bwrap,
    /// where the sandbox reaches the proxy via the in-namespace forwarder
    /// port instead of the host listener. Same token, same session.
    pub fn proxy_url_via(&self, port: u16) -> String {
        format!("http://{}:@127.0.0.1:{}", self.token, port)
    }

    /// `socks5h://ak:<token>@127.0.0.1:<port>` — the `h` keeps DNS at the
    /// policy-enforcing proxy rather than letting the workload resolve and
    /// substitute an address locally.
    pub fn socks_proxy_url(&self) -> String {
        self.socks_proxy_url_via(self.port)
    }

    /// SOCKS5 URL through a different local port (the bwrap netns route).
    pub fn socks_proxy_url_via(&self, port: u16) -> String {
        format!("socks5h://ak:{}@127.0.0.1:{}", self.token, port)
    }

    /// Loopback port the sandbox must open.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Additionally serve the proxy on a Unix socket at `path` (replacing
    /// any stale socket file). This is the bwrap route: the socket is
    /// bind-mounted into the sandbox and the in-namespace forwarder
    /// bridges to it; sessions, auth and guards are identical to TCP.
    #[cfg(unix)]
    pub async fn serve_unix(
        &self,
        path: &std::path::Path,
        config: EgressConfig,
    ) -> std::io::Result<()> {
        serve_unix_listener(
            path,
            config,
            Arc::clone(&self.sessions),
            Arc::clone(&self.listeners),
        )
        .await
    }

    /// Bytes transferred so far (both directions, all connections).
    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }
}

impl Drop for EgressGrant {
    fn drop(&mut self) {
        self.revoked.store(true, Ordering::Release);
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.token);
    }
}

/// The proxy: one per backend, sessions registered per step.
pub struct EgressProxy {
    port: u16,
    sessions: Sessions,
    listeners: Arc<ListenerRegistry>,
}

impl EgressProxy {
    /// Bind `127.0.0.1:0` and start serving. Must run inside a tokio
    /// runtime.
    pub async fn start(config: EgressConfig) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        let listeners = Arc::new(ListenerRegistry::default());
        let accept_sessions = Arc::clone(&sessions);
        let task = tokio::spawn(async move {
            loop {
                let Ok((conn, _peer)) = listener.accept().await else {
                    break;
                };
                let sessions = Arc::clone(&accept_sessions);
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(conn, sessions, config).await;
                });
            }
        });
        listeners.add_task(&task);
        tracing::info!(port, "egress proxy listening on loopback");
        Ok(Self {
            port,
            sessions,
            listeners,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Additionally serve the proxy on a Unix socket at `path` (replacing
    /// any stale socket file). This is the bwrap route: the socket is
    /// bind-mounted into the sandbox and the in-namespace forwarder
    /// bridges to it; sessions, auth and guards are identical to TCP.
    #[cfg(unix)]
    pub async fn serve_unix(
        &self,
        path: &std::path::Path,
        config: EgressConfig,
    ) -> std::io::Result<()> {
        serve_unix_listener(
            path,
            config,
            Arc::clone(&self.sessions),
            Arc::clone(&self.listeners),
        )
        .await
    }

    /// Register a session: `domains` are `*`-glob patterns, `cap` the byte
    /// budget across both directions.
    pub fn grant(&self, domains: Vec<String>, cap: u64) -> EgressGrant {
        let token = format!("eg-{}", uuid::Uuid::new_v4().simple());
        let used = Arc::new(AtomicU64::new(0));
        let revoked = Arc::new(AtomicBool::new(false));
        let domains = domains
            .into_iter()
            .map(|domain| {
                domain
                    .to_ascii_lowercase()
                    .trim_end_matches('.')
                    .to_string()
            })
            .collect();
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                token.clone(),
                Session {
                    domains,
                    used: Arc::clone(&used),
                    revoked: Arc::clone(&revoked),
                    cap,
                },
            );
        EgressGrant {
            token,
            port: self.port,
            used,
            revoked,
            sessions: Arc::clone(&self.sessions),
            listeners: Arc::clone(&self.listeners),
        }
    }
}

#[cfg(unix)]
async fn serve_unix_listener(
    path: &std::path::Path,
    config: EgressConfig,
    sessions: Sessions,
    listeners: Arc<ListenerRegistry>,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((conn, _peer)) = listener.accept().await else {
                break;
            };
            let sessions = Arc::clone(&sessions);
            let config = config.clone();
            tokio::spawn(async move {
                let _ = handle_connection(conn, sessions, config).await;
            });
        }
    });
    listeners.add_task(&task);
    listeners.add_unix_path(path);
    tracing::info!(path = %path.display(), "egress proxy listening on unix socket");
    Ok(())
}

const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Client-side stream the proxy serves: TCP on loopback (Seatbelt route)
/// or a Unix socket (bwrap netns-forwarder route).
pub trait ClientStream: AsyncReadExt + AsyncWriteExt + Unpin + Send {}
impl<S: AsyncReadExt + AsyncWriteExt + Unpin + Send> ClientStream for S {}

async fn respond(conn: &mut impl ClientStream, status: &str, extra: &str) {
    let body =
        format!("HTTP/1.1 {status}\r\n{extra}content-length: 0\r\nconnection: close\r\n\r\n");
    let _ = conn.write_all(body.as_bytes()).await;
}

async fn read_head_from(
    conn: &mut impl ClientStream,
    mut head: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let mut byte = [0u8; 1];
    while head.len() < MAX_HEAD_BYTES {
        let n = conn.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "request head too large or truncated",
    ))
}

/// Read a complete HTTP head when no protocol-dispatch byte was consumed.
#[cfg(test)]
async fn read_head(conn: &mut impl ClientStream) -> std::io::Result<Vec<u8>> {
    read_head_from(conn, Vec::with_capacity(1024)).await
}

/// Read an HTTP request head after `first` was consumed to distinguish HTTP
/// from SOCKS5.
async fn read_http_head(conn: &mut impl ClientStream, first: u8) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    head.push(first);
    read_head_from(conn, head).await
}

struct RequestHead {
    method: String,
    target: String,
    version: String,
    /// Lowercased-name header lines, in order.
    headers: Vec<(String, String)>,
}

fn parse_head(head: &[u8]) -> Option<RequestHead> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Some(RequestHead {
        method,
        target,
        version,
        headers,
    })
}

fn bearer_token(req: &RequestHead) -> Option<String> {
    let value = req
        .headers
        .iter()
        .find(|(name, _)| name == "proxy-authorization")
        .map(|(_, v)| v.as_str())?;
    let b64 = value
        .strip_prefix("Basic ")
        .or(value.strip_prefix("basic "))?;
    let decoded = base64_decode(b64.trim())?;
    let creds = String::from_utf8(decoded).ok()?;
    Some(creds.split(':').next().unwrap_or("").to_string())
}

/// Minimal standard-alphabet base64 decoder (no dependency juggling).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|&a| a == c)? as u32;
        buf = (buf << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Split `host[:port]` (CONNECT authority-form), handling bracketed IPv6.
fn split_authority(target: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match target.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((target.to_string(), default_port)),
    }
}

enum TargetError {
    Denied(&'static str),
    Unresolvable,
}

/// Full guard set on a destination; returns the pinned address to connect.
async fn validate_target(
    host: &str,
    port: u16,
    session: &Session,
    config: &EgressConfig,
) -> Result<SocketAddr, TargetError> {
    let host = host.to_ascii_lowercase().trim_end_matches('.').to_string();
    if host.is_empty() || port == 0 {
        return Err(TargetError::Denied("empty host or zero destination port"));
    }
    let port_allowed = config.allowed_ports.is_empty() || config.allowed_ports.contains(&port);
    if !port_allowed && !config.danger_allow_loopback {
        return Err(TargetError::Denied("destination port not allowed"));
    }
    if !session.domains.iter().any(|g| glob_match(g, &host)) {
        return Err(TargetError::Denied(
            "destination host is not covered by this step's egress domains",
        ));
    }
    // Literal IPs: refused, except loopback in test mode. Guests name their
    // targets; the proxy does the resolving.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if config.danger_allow_loopback && ip.is_loopback() {
            return Ok(SocketAddr::new(ip, port));
        }
        if !port_allowed {
            return Err(TargetError::Denied("destination port not allowed"));
        }
        return Err(TargetError::Denied("literal ip targets are refused"));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| TargetError::Unresolvable)?
        .collect();
    if addrs.is_empty() {
        return Err(TargetError::Unresolvable);
    }
    for addr in &addrs {
        if config.danger_allow_loopback && addr.ip().is_loopback() {
            continue;
        }
        if is_forbidden_ip(&addr.ip()) {
            return Err(TargetError::Denied(
                "destination resolves into a private/loopback/metadata range",
            ));
        }
    }
    let selected = addrs[0];
    if !(port_allowed || config.danger_allow_loopback && selected.ip().is_loopback()) {
        return Err(TargetError::Denied("destination port not allowed"));
    }
    Ok(selected)
}

/// A cancellation-safe reservation against the shared byte cap. Bytes are
/// committed only after `AsyncWrite` reports them written; any remainder is
/// atomically refunded on error or future cancellation.
struct ByteReservation<'a> {
    used: &'a AtomicU64,
    uncommitted: u64,
}

impl ByteReservation<'_> {
    fn len(&self) -> usize {
        self.uncommitted as usize
    }

    fn commit(&mut self, written: usize) {
        let written = written as u64;
        debug_assert!(written <= self.uncommitted);
        self.uncommitted -= written;
    }
}

impl Drop for ByteReservation<'_> {
    fn drop(&mut self) {
        if self.uncommitted > 0 {
            self.used.fetch_sub(self.uncommitted, Ordering::AcqRel);
        }
    }
}

/// Atomically reserve up to `wanted` bytes without ever moving the shared
/// counter above `cap`. Both tunnel directions race on the same counter.
fn reserve_up_to(used: &AtomicU64, cap: u64, wanted: usize) -> Option<ByteReservation<'_>> {
    let mut current = used.load(Ordering::Acquire);
    loop {
        let granted = (cap.saturating_sub(current)).min(wanted as u64);
        if granted == 0 {
            return None;
        }
        match used.compare_exchange_weak(
            current,
            current + granted,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(ByteReservation {
                    used,
                    uncommitted: granted,
                })
            }
            Err(actual) => current = actual,
        }
    }
}

/// Reserve an indivisible control write (the rewritten origin request).
/// A partial HTTP request must never be sent upstream.
fn reserve_exact(used: &AtomicU64, cap: u64, wanted: usize) -> Option<ByteReservation<'_>> {
    let wanted = u64::try_from(wanted).ok()?;
    let mut current = used.load(Ordering::Acquire);
    loop {
        if cap.saturating_sub(current) < wanted {
            return None;
        }
        match used.compare_exchange_weak(
            current,
            current + wanted,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(ByteReservation {
                    used,
                    uncommitted: wanted,
                })
            }
            Err(actual) => current = actual,
        }
    }
}

/// Copy both directions with a shared byte counter; stop when the session
/// cap is exhausted.
async fn tunnel(
    client: impl ClientStream,
    mut upstream: TcpStream,
    used: Arc<AtomicU64>,
    revoked: Arc<AtomicBool>,
    cap: u64,
) {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let up = copy_counted(&mut client_read, &mut upstream_write, &used, &revoked, cap);
    let down = copy_counted(&mut upstream_read, &mut client_write, &used, &revoked, cap);
    // Either side closing (or the cap firing) ends the tunnel.
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

async fn copy_counted<R, W>(
    reader: &mut R,
    writer: &mut W,
    used: &AtomicU64,
    revoked: &AtomicBool,
    cap: u64,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    while !revoked.load(Ordering::Acquire) {
        let Ok(n) = reader.read(&mut buf).await else {
            break;
        };
        if n == 0 {
            let _ = writer.shutdown().await;
            break;
        }
        if revoked.load(Ordering::Acquire) {
            let _ = writer.shutdown().await;
            break;
        }
        let Some(mut reservation) = reserve_up_to(used, cap, n) else {
            tracing::warn!(cap, "egress byte cap exhausted; closing tunnel");
            let _ = writer.shutdown().await;
            break;
        };
        let granted = reservation.len();
        let mut written = 0;
        while written < granted {
            match writer.write(&buf[written..granted]).await {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    written += count;
                    reservation.commit(count);
                }
            }
        }
        // Dropping refunds anything reserved but not reported written. This
        // is also what happens if tokio::select cancels this direction.
        drop(reservation);
        if written < n {
            tracing::warn!(cap, "egress byte cap exhausted; closing tunnel");
            let _ = writer.shutdown().await;
            break;
        }
    }
}

async fn handle_connection(
    mut conn: impl ClientStream,
    sessions: Sessions,
    config: EgressConfig,
) -> std::io::Result<()> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        conn.read_exact(&mut first),
    )
    .await
    {
        Ok(Ok(_)) => {}
        _ => return Ok(()),
    }
    if first[0] == 5 {
        return handle_socks5(conn, sessions, config).await;
    }

    let head = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_http_head(&mut conn, first[0]),
    )
    .await
    {
        Ok(Ok(head)) => head,
        _ => return Ok(()),
    };
    let Some(req) = parse_head(&head) else {
        respond(&mut conn, "400 Bad Request", "").await;
        return Ok(());
    };
    let session = bearer_token(&req).and_then(|token| {
        sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&token)
            .cloned()
    });
    let Some(session) = session else {
        respond(
            &mut conn,
            "407 Proxy Authentication Required",
            "proxy-authenticate: Basic realm=\"agent-kernel egress\"\r\n",
        )
        .await;
        return Ok(());
    };
    if session.revoked.load(Ordering::Acquire) {
        respond(&mut conn, "407 Proxy Authentication Required", "").await;
        return Ok(());
    }
    if session.used.load(Ordering::Relaxed) >= session.cap {
        respond(&mut conn, "403 Forbidden", "").await;
        return Ok(());
    }

    if req.method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_authority(&req.target, 443) else {
            respond(&mut conn, "400 Bad Request", "").await;
            return Ok(());
        };
        let addr = match validate_target(&host, port, &session, &config).await {
            Ok(a) => a,
            Err(TargetError::Denied(reason)) => {
                tracing::warn!(host, port, reason, "egress CONNECT denied");
                respond(&mut conn, "403 Forbidden", "").await;
                return Ok(());
            }
            Err(TargetError::Unresolvable) => {
                respond(&mut conn, "502 Bad Gateway", "").await;
                return Ok(());
            }
        };
        if session.revoked.load(Ordering::Acquire) {
            return Ok(());
        }
        let Ok(upstream) = TcpStream::connect(addr).await else {
            respond(&mut conn, "502 Bad Gateway", "").await;
            return Ok(());
        };
        if session.revoked.load(Ordering::Acquire) {
            return Ok(());
        }
        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        tracing::debug!(host, port, "egress CONNECT tunnel open");
        tunnel(conn, upstream, session.used, session.revoked, session.cap).await;
        return Ok(());
    }

    // Absolute-URI plain HTTP: http://host[:port]/path...
    let Some(rest) = req.target.strip_prefix("http://") else {
        respond(&mut conn, "400 Bad Request", "").await;
        return Ok(());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let Some((host, port)) = split_authority(authority, 80) else {
        respond(&mut conn, "400 Bad Request", "").await;
        return Ok(());
    };
    let addr = match validate_target(&host, port, &session, &config).await {
        Ok(a) => a,
        Err(TargetError::Denied(reason)) => {
            tracing::warn!(host, port, reason, "egress request denied");
            respond(&mut conn, "403 Forbidden", "").await;
            return Ok(());
        }
        Err(TargetError::Unresolvable) => {
            respond(&mut conn, "502 Bad Gateway", "").await;
            return Ok(());
        }
    };
    // Rewrite to origin-form, strip proxy-* headers, force close semantics
    // (keep-alive across a byte-counting proxy buys nothing but stuck
    // connections).
    let mut out = format!("{} {} {}\r\n", req.method, path, req.version);
    for (name, value) in &req.headers {
        if name.starts_with("proxy-") || name == "connection" {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("connection: close\r\n\r\n");
    let Some(mut reservation) = reserve_exact(&session.used, session.cap, out.len()) else {
        respond(&mut conn, "403 Forbidden", "").await;
        return Ok(());
    };
    if session.revoked.load(Ordering::Acquire) {
        return Ok(());
    }
    let Ok(mut upstream) = TcpStream::connect(addr).await else {
        // No byte crossed the egress boundary; dropping refunds the full
        // reservation.
        respond(&mut conn, "502 Bad Gateway", "").await;
        return Ok(());
    };
    let mut written = 0;
    while written < out.len() && !session.revoked.load(Ordering::Acquire) {
        match upstream.write(&out.as_bytes()[written..]).await {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                written += count;
                reservation.commit(count);
            }
        }
    }
    drop(reservation);
    if written != out.len() {
        return Ok(());
    }
    tracing::debug!(host, port, path, "egress plain-http forwarded");
    tunnel(conn, upstream, session.used, session.revoked, session.cap).await;
    Ok(())
}

/// RFC 1928/1929 handshake result. Only username/password authentication and
/// CONNECT are accepted: `ak` is the stable username and the per-step token
/// is the password. This keeps the authority secret out of the destination
/// fields and gives every protocol the same revocable session lookup.
async fn socks5_handshake(
    conn: &mut impl ClientStream,
    sessions: &Sessions,
) -> std::io::Result<Option<(Session, String, u16)>> {
    let mut nmethods = [0u8; 1];
    conn.read_exact(&mut nmethods).await?;
    if nmethods[0] == 0 {
        conn.write_all(&[5, 0xff]).await?;
        return Ok(None);
    }
    let mut methods = vec![0u8; nmethods[0] as usize];
    conn.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        conn.write_all(&[5, 0xff]).await?;
        return Ok(None);
    }
    conn.write_all(&[5, 2]).await?;

    let mut auth_head = [0u8; 2];
    conn.read_exact(&mut auth_head).await?;
    if auth_head[0] != 1 || auth_head[1] == 0 {
        conn.write_all(&[1, 1]).await?;
        return Ok(None);
    }
    let mut username = vec![0u8; auth_head[1] as usize];
    conn.read_exact(&mut username).await?;
    let mut password_len = [0u8; 1];
    conn.read_exact(&mut password_len).await?;
    if password_len[0] == 0 {
        conn.write_all(&[1, 1]).await?;
        return Ok(None);
    }
    let mut password = vec![0u8; password_len[0] as usize];
    conn.read_exact(&mut password).await?;
    let session = if username == b"ak" {
        std::str::from_utf8(&password).ok().and_then(|token| {
            sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(token)
                .cloned()
        })
    } else {
        None
    };
    let Some(session) = session.filter(|s| !s.revoked.load(Ordering::Acquire)) else {
        conn.write_all(&[1, 1]).await?;
        return Ok(None);
    };
    conn.write_all(&[1, 0]).await?;

    let mut request = [0u8; 4];
    conn.read_exact(&mut request).await?;
    if request[0] != 5 || request[1] != 1 || request[2] != 0 {
        send_socks5_reply(conn, 7).await?;
        return Ok(None);
    }
    let host = match request[3] {
        1 => {
            let mut octets = [0u8; 4];
            conn.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            if len[0] == 0 {
                send_socks5_reply(conn, 8).await?;
                return Ok(None);
            }
            let mut domain = vec![0u8; len[0] as usize];
            conn.read_exact(&mut domain).await?;
            let Ok(domain) = String::from_utf8(domain) else {
                send_socks5_reply(conn, 8).await?;
                return Ok(None);
            };
            domain
        }
        4 => {
            let mut octets = [0u8; 16];
            conn.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        _ => {
            send_socks5_reply(conn, 8).await?;
            return Ok(None);
        }
    };
    let mut port = [0u8; 2];
    conn.read_exact(&mut port).await?;
    Ok(Some((session, host, u16::from_be_bytes(port))))
}

/// A fixed IPv4 `0.0.0.0:0` bind address is valid for both success and
/// failure replies; callers do not use BIND and therefore gain no authority
/// from exposing the proxy's local ephemeral address.
async fn send_socks5_reply(conn: &mut impl ClientStream, reply: u8) -> std::io::Result<()> {
    conn.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn handle_socks5(
    mut conn: impl ClientStream,
    sessions: Sessions,
    config: EgressConfig,
) -> std::io::Result<()> {
    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        socks5_handshake(&mut conn, &sessions),
    )
    .await;
    let Some((session, host, port)) = (match handshake {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    }) else {
        return Ok(());
    };
    if session.used.load(Ordering::Relaxed) >= session.cap {
        send_socks5_reply(&mut conn, 2).await?;
        return Ok(());
    }
    let addr = match validate_target(&host, port, &session, &config).await {
        Ok(addr) => addr,
        Err(TargetError::Denied(reason)) => {
            tracing::warn!(host, port, reason, "egress SOCKS5 CONNECT denied");
            send_socks5_reply(&mut conn, 2).await?;
            return Ok(());
        }
        Err(TargetError::Unresolvable) => {
            send_socks5_reply(&mut conn, 4).await?;
            return Ok(());
        }
    };
    if session.revoked.load(Ordering::Acquire) {
        return Ok(());
    }
    let Ok(upstream) = TcpStream::connect(addr).await else {
        send_socks5_reply(&mut conn, 5).await?;
        return Ok(());
    };
    if session.revoked.load(Ordering::Acquire) {
        return Ok(());
    }
    send_socks5_reply(&mut conn, 0).await?;
    tracing::debug!(host, port, "egress SOCKS5 tunnel open");
    tunnel(conn, upstream, session.used, session.revoked, session.cap).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinished_byte_reservations_refund_exactly() {
        let used = AtomicU64::new(0);
        let mut reservation = reserve_up_to(&used, 10, 8).unwrap();
        assert_eq!(used.load(Ordering::Acquire), 8);
        reservation.commit(3);
        drop(reservation);
        assert_eq!(
            used.load(Ordering::Acquire),
            3,
            "only bytes reported written remain charged"
        );
        let reservation = reserve_exact(&used, 10, 7).unwrap();
        drop(reservation);
        assert_eq!(used.load(Ordering::Acquire), 3);
    }

    /// The Unix-socket listener (the bwrap forwarder route) serves the
    /// same sessions with the same auth: a tokened CONNECT tunnels, a
    /// tokenless one gets 407. Cross-platform — no sandbox involved.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_listener_serves_tokened_connect_and_rejects_tokenless() {
        let echo = echo_server().await;
        let config = EgressConfig {
            enabled: true,
            allowed_ports: Vec::new(),
            danger_allow_loopback: true,
        };
        let proxy = EgressProxy::start(config.clone()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("egress.sock");
        proxy.serve_unix(&sock, config).await.unwrap();
        let grant = proxy.grant(vec!["127.0.0.1".into()], 1 << 20);

        let mut conn = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let token = grant
            .proxy_url()
            .split("//")
            .nth(1)
            .unwrap()
            .split(':')
            .next()
            .unwrap()
            .to_string();
        let auth = ak_core::b64::encode(format!("{token}:").as_bytes());
        conn.write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nproxy-authorization: Basic {auth}\r\n\r\n",
                echo.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = vec![0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("200 Connection Established"),
            "got: {}",
            String::from_utf8_lossy(&buf[..n])
        );
        conn.write_all(b"ping-through-unix").await.unwrap();
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping-through-unix");
        assert!(grant.used_bytes() > 0, "unix route must meter bytes");

        // Tokenless: 407, reaches nothing.
        let mut conn = tokio::net::UnixStream::connect(&sock).await.unwrap();
        conn.write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let n = conn.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("407"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_proxy_unlinks_its_unix_listener() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("owned.sock");
        {
            let proxy = EgressProxy::start(test_config()).await.unwrap();
            proxy.serve_unix(&sock, test_config()).await.unwrap();
            assert!(sock.exists());
        }
        assert!(!sock.exists(), "backend-scoped Unix sockets must not leak");
    }

    async fn echo_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        spawn_echo_server(listener).await
    }

    async fn localhost_echo_server() -> SocketAddr {
        let ip = tokio::net::lookup_host(("localhost", 1))
            .await
            .unwrap()
            .next()
            .unwrap()
            .ip();
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0))
            .await
            .unwrap();
        spawn_echo_server(listener).await
    }

    async fn spawn_echo_server(listener: tokio::net::TcpListener) -> SocketAddr {
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if conn.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn socks5_auth(conn: &mut TcpStream, token: &str) -> [u8; 2] {
        conn.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0u8; 2];
        conn.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);

        let token = token.as_bytes();
        assert!(token.len() <= u8::MAX as usize);
        let mut auth = vec![1, 2, b'a', b'k', token.len() as u8];
        auth.extend_from_slice(token);
        conn.write_all(&auth).await.unwrap();
        let mut status = [0u8; 2];
        conn.read_exact(&mut status).await.unwrap();
        status
    }

    async fn socks5_domain_connect(
        proxy_port: u16,
        token: &str,
        command: u8,
        host: &str,
        port: u16,
    ) -> (TcpStream, [u8; 10]) {
        let mut conn = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        assert_eq!(socks5_auth(&mut conn, token).await, [1, 0]);
        assert!(!host.is_empty() && host.len() <= u8::MAX as usize);
        let mut request = vec![5, command, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        conn.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        conn.read_exact(&mut reply).await.unwrap();
        (conn, reply)
    }

    /// Minimal HTTP/1.1 server answering every request with a body.
    async fn http_server(body: &'static str) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ = conn.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = conn.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    fn test_config() -> EgressConfig {
        EgressConfig {
            enabled: true,
            allowed_ports: Vec::new(),
            danger_allow_loopback: true,
        }
    }

    /// The session token a workload would extract from the grant's proxy URL.
    fn token_of(grant: &EgressGrant) -> String {
        grant.token.clone()
    }

    fn basic_auth(token: &str) -> String {
        // Standard alphabet encode of "token:".
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let input = format!("{token}:");
        let bytes = input.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    async fn send_and_read(proxy_port: u16, request: &str) -> String {
        let mut conn = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        conn.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_to_end(&mut out),
        )
        .await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn unauthenticated_connections_get_407_and_reach_nothing() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let resp = send_and_read(
            proxy.port(),
            "CONNECT 127.0.0.1:1 HTTP/1.1\r\nhost: x\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
        // A bogus token is refused identically.
        let resp = send_and_read(
            proxy.port(),
            &format!(
                "CONNECT 127.0.0.1:1 HTTP/1.1\r\nproxy-authorization: Basic {}\r\n\r\n",
                basic_auth("eg-not-real")
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
    }

    #[tokio::test]
    async fn connect_tunnels_bytes_and_counts_them() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let target = echo_server().await;
        let grant = proxy.grant(vec!["127.0.0.1".into()], 1 << 20);

        let mut conn = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .unwrap();
        let req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nproxy-authorization: Basic {}\r\n\r\n",
            target.port(),
            basic_auth(&token_of(&grant))
        );
        conn.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        let established = String::from_utf8_lossy(&buf[..n]);
        assert!(
            established.starts_with("HTTP/1.1 200"),
            "got: {established}"
        );

        conn.write_all(b"ping-through-tunnel").await.unwrap();
        let mut echo = [0u8; 64];
        let n = conn.read(&mut echo).await.unwrap();
        assert_eq!(&echo[..n], b"ping-through-tunnel");
        assert!(grant.used_bytes() >= 2 * b"ping-through-tunnel".len() as u64);
    }

    #[tokio::test]
    async fn socks5_domain_connect_tunnels_and_counts_bytes() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let target = localhost_echo_server().await;
        let grant = proxy.grant(vec!["localhost.".into()], 1 << 20);
        let (mut conn, reply) = socks5_domain_connect(
            proxy.port(),
            &token_of(&grant),
            1,
            "LOCALHOST.",
            target.port(),
        )
        .await;
        assert_eq!(reply[0..2], [5, 0]);

        conn.write_all(b"ping-through-socks5").await.unwrap();
        let mut echo = [0u8; 64];
        let n = conn.read(&mut echo).await.unwrap();
        assert_eq!(&echo[..n], b"ping-through-socks5");
        assert!(grant.used_bytes() >= 2 * b"ping-through-socks5".len() as u64);
    }

    #[tokio::test]
    async fn socks5_requires_token_auth_and_connect_command() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();

        // Anonymous SOCKS is never accepted.
        let mut conn = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .unwrap();
        conn.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        conn.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0xff]);

        // A syntactically valid but unknown per-step token fails auth.
        let mut conn = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .unwrap();
        assert_eq!(socks5_auth(&mut conn, "eg-not-real").await, [1, 1]);

        // Revocation removes the same per-step authority from SOCKS auth.
        let revoked = proxy.grant(vec!["localhost".into()], 1 << 20);
        let revoked_token = token_of(&revoked);
        drop(revoked);
        let mut conn = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .unwrap();
        assert_eq!(socks5_auth(&mut conn, &revoked_token).await, [1, 1]);

        // BIND/UDP do not become an accidental second authority surface.
        let grant = proxy.grant(vec!["localhost".into()], 1 << 20);
        let (_, reply) =
            socks5_domain_connect(proxy.port(), &token_of(&grant), 3, "localhost", 443).await;
        assert_eq!(reply[0..2], [5, 7]);

        // Unknown address kinds and an empty domain fail before resolution
        // or any upstream connection.
        for request in [vec![5, 1, 0, 9], vec![5, 1, 0, 3, 0]] {
            let mut conn = TcpStream::connect(("127.0.0.1", proxy.port()))
                .await
                .unwrap();
            assert_eq!(socks5_auth(&mut conn, &token_of(&grant)).await, [1, 0]);
            conn.write_all(&request).await.unwrap();
            let mut reply = [0u8; 10];
            conn.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0..2], [5, 8]);
        }
    }

    #[tokio::test]
    async fn socks5_reuses_domain_port_ssrf_and_cap_guards() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let grant = proxy.grant(vec!["docs.example".into()], 1 << 20);
        let (_, reply) =
            socks5_domain_connect(proxy.port(), &token_of(&grant), 1, "other.example", 443).await;
        assert_eq!(reply[0..2], [5, 2], "ungranted domain must be denied");

        let zero_cap = proxy.grant(vec!["localhost".into()], 0);
        let (_, reply) =
            socks5_domain_connect(proxy.port(), &token_of(&zero_cap), 1, "localhost", 443).await;
        assert_eq!(reply[0..2], [5, 2], "spent cap must be denied");

        let zero_port = proxy.grant(vec!["localhost".into()], 1 << 20);
        let (_, reply) =
            socks5_domain_connect(proxy.port(), &token_of(&zero_port), 1, "localhost", 0).await;
        assert_eq!(reply[0..2], [5, 2], "port zero must be denied");

        let strict = EgressProxy::start(EgressConfig {
            enabled: true,
            allowed_ports: vec![443],
            danger_allow_loopback: false,
        })
        .await
        .unwrap();
        let strict_grant = strict.grant(vec!["*".into()], 1 << 20);
        let (_, reply) = socks5_domain_connect(
            strict.port(),
            &token_of(&strict_grant),
            1,
            "docs.example",
            6379,
        )
        .await;
        assert_eq!(reply[0..2], [5, 2], "ungranted port must be denied");

        let mut conn = TcpStream::connect(("127.0.0.1", strict.port()))
            .await
            .unwrap();
        assert_eq!(
            socks5_auth(&mut conn, &token_of(&strict_grant)).await,
            [1, 0]
        );
        conn.write_all(&[5, 1, 0, 1, 169, 254, 169, 254, 1, 187])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0..2], [5, 2], "literal metadata IP must be denied");
    }

    #[tokio::test]
    async fn disallowed_domains_and_forbidden_targets_get_403() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let grant = proxy.grant(vec!["docs.example".into()], 1 << 20);
        let token = token_of(&grant);
        // Host not in the session's domain globs.
        let resp = send_and_read(
            proxy.port(),
            &format!(
                "CONNECT other.example:443 HTTP/1.1\r\nproxy-authorization: Basic {}\r\n\r\n",
                basic_auth(&token)
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");

        // Literal-IP target in production mode (no loopback danger flag).
        let strict = EgressProxy::start(EgressConfig {
            danger_allow_loopback: false,
            allowed_ports: vec![443],
            enabled: true,
        })
        .await
        .unwrap();
        let g2 = strict.grant(vec!["*".into()], 1 << 20);
        let token2 = token_of(&g2);
        let resp = send_and_read(
            strict.port(),
            &format!(
                "CONNECT 169.254.169.254:443 HTTP/1.1\r\nproxy-authorization: Basic {}\r\n\r\n",
                basic_auth(&token2)
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 403"), "metadata ip: {resp}");
        // Disallowed port.
        let resp = send_and_read(
            strict.port(),
            &format!(
                "CONNECT any.example:6379 HTTP/1.1\r\nproxy-authorization: Basic {}\r\n\r\n",
                basic_auth(&token2)
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 403"), "port: {resp}");
    }

    #[tokio::test]
    async fn absolute_uri_http_is_forwarded() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let target = http_server("hello-from-origin").await;
        let grant = proxy.grant(vec!["127.0.0.1.".into()], 1 << 20);
        let token = token_of(&grant);
        let resp = send_and_read(
            proxy.port(),
            &format!(
                "GET http://127.0.0.1:{}/hello HTTP/1.1\r\nhost: 127.0.0.1\r\nproxy-authorization: Basic {}\r\n\r\n",
                target.port(),
                basic_auth(&token)
            ),
        )
        .await;
        assert!(resp.contains("hello-from-origin"), "got: {resp}");
    }

    #[tokio::test]
    async fn an_origin_request_must_fit_the_remaining_cap_atomically() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let target = http_server("must-not-arrive").await;
        let grant = proxy.grant(vec!["127.0.0.1".into()], 8);
        let resp = send_and_read(
            proxy.port(),
            &format!(
                "GET http://127.0.0.1:{}/x HTTP/1.1\r\nhost: x\r\nproxy-authorization: Basic {}\r\n\r\n",
                target.port(),
                basic_auth(&token_of(&grant))
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert_eq!(grant.used_bytes(), 0, "a partial request was never sent");
    }

    #[tokio::test]
    async fn byte_cap_cuts_the_tunnel() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let big: &'static str = Box::leak("z".repeat(64 * 1024).into_boxed_str());
        let target = http_server(big).await;
        let grant = proxy.grant(vec!["127.0.0.1".into()], 512);
        let token = token_of(&grant);
        let resp = send_and_read(
            proxy.port(),
            &format!(
                "GET http://127.0.0.1:{}/big HTTP/1.1\r\nhost: x\r\nproxy-authorization: Basic {}\r\n\r\n",
                target.port(),
                basic_auth(&token)
            ),
        )
        .await;
        assert!(
            (resp.len() as u64) < 64 * 1024,
            "cap must cut the transfer, got {} bytes",
            resp.len()
        );
        assert!(
            grant.used_bytes() <= 512,
            "the shared counter must never overshoot its cap"
        );

        // Once the cap is spent, new connections are refused outright.
        let resp = send_and_read(
            proxy.port(),
            &format!(
                "GET http://127.0.0.1:{}/more HTTP/1.1\r\nhost: x\r\nproxy-authorization: Basic {}\r\n\r\n",
                target.port(),
                basic_auth(&token)
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
    }

    #[tokio::test]
    async fn dropping_the_grant_revokes_the_token() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let target = http_server("x").await;
        let grant = proxy.grant(vec!["127.0.0.1".into()], 1 << 20);
        let token = token_of(&grant);
        drop(grant);
        let resp = send_and_read(
            proxy.port(),
            &format!(
                "GET http://127.0.0.1:{}/x HTTP/1.1\r\nhost: x\r\nproxy-authorization: Basic {}\r\n\r\n",
                target.port(),
                basic_auth(&token)
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
    }

    #[tokio::test]
    async fn dropping_the_grant_cuts_an_authenticated_tunnel() {
        let proxy = EgressProxy::start(test_config()).await.unwrap();
        let target = echo_server().await;
        let grant = proxy.grant(vec!["127.0.0.1".into()], 1 << 20);
        let used = Arc::clone(&grant.used);
        let mut conn = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .unwrap();
        conn.write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nproxy-authorization: Basic {}\r\n\r\n",
                target.port(),
                basic_auth(&token_of(&grant))
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let head = read_head(&mut conn).await.unwrap();
        assert!(String::from_utf8_lossy(&head).contains("200 Connection Established"));

        drop(grant);
        let _ = conn.write_all(b"must-not-cross-after-revoke").await;
        let mut buf = [0u8; 64];
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), conn.read(&mut buf))
            .await
            .expect("revoked tunnel must close promptly");
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "revoked tunnel leaked data"
        );
        assert_eq!(
            used.load(Ordering::Acquire),
            0,
            "discarded post-revocation bytes must not be charged or forwarded"
        );
    }
}
