//! Transparent egress proxy: controlled network for sandboxed workloads.
//!
//! The sandbox denies all direct network. When a step's compiled confinement
//! grants egress domains, the backend hands the workload standard
//! `HTTP_PROXY`/`HTTPS_PROXY` environment variables pointing at this
//! loopback proxy with a **per-step bearer token** — so `pip install`,
//! `cargo fetch`, `npm install`, `git fetch` and `curl` work unmodified,
//! while the policy is enforced at the one place a domain allowlist can
//! actually be enforced: the egress hop.
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
//! Both `CONNECT` tunneling (TLS passes through end-to-end; the proxy never
//! terminates TLS) and absolute-URI plain HTTP are supported.
//!
//! Sandbox reachability: on macOS the generated Seatbelt profile opens
//! **only** `localhost:<proxy port>` outbound; everything else stays denied,
//! so the proxy is the sole route out. On Linux bubblewrap unshares the
//! network namespace entirely — host loopback is unreachable from inside,
//! so egress stays off there until an in-namespace forwarder lands (honest
//! fail-closed, not silent bypass).

use ak_core::capability::glob_match;
use ak_core::net::is_forbidden_ip;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
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
    cap: u64,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

/// A live grant to use the proxy: carries the token-bearing proxy URL for
/// the workload's environment and the live byte counter. Dropping the grant
/// revokes the token — in-flight connections are cut off from new reads at
/// the next buffer boundary only by their byte cap, but no *new* connection
/// can authenticate.
pub struct EgressGrant {
    token: String,
    port: u16,
    used: Arc<AtomicU64>,
    sessions: Sessions,
}

impl EgressGrant {
    /// `http://<token>@127.0.0.1:<port>` — standard proxy-URL shape every
    /// mainstream tool turns into `Proxy-Authorization: Basic`.
    pub fn proxy_url(&self) -> String {
        format!("http://{}:@127.0.0.1:{}", self.token, self.port)
    }

    /// Loopback port the sandbox must open.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Bytes transferred so far (both directions, all connections).
    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }
}

impl Drop for EgressGrant {
    fn drop(&mut self) {
        if let Ok(mut map) = self.sessions.lock() {
            map.remove(&self.token);
        }
    }
}

/// The proxy: one per backend, sessions registered per step.
pub struct EgressProxy {
    port: u16,
    sessions: Sessions,
}

impl EgressProxy {
    /// Bind `127.0.0.1:0` and start serving. Must run inside a tokio
    /// runtime.
    pub async fn start(config: EgressConfig) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        let accept_sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
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
        tracing::info!(port, "egress proxy listening on loopback");
        Ok(Self { port, sessions })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Register a session: `domains` are `*`-glob patterns, `cap` the byte
    /// budget across both directions.
    pub fn grant(&self, domains: Vec<String>, cap: u64) -> EgressGrant {
        let token = format!("eg-{}", uuid::Uuid::new_v4().simple());
        let used = Arc::new(AtomicU64::new(0));
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                token.clone(),
                Session {
                    domains,
                    used: Arc::clone(&used),
                    cap,
                },
            );
        EgressGrant {
            token,
            port: self.port,
            used,
            sessions: Arc::clone(&self.sessions),
        }
    }
}

const MAX_HEAD_BYTES: usize = 16 * 1024;

async fn respond(conn: &mut TcpStream, status: &str, extra: &str) {
    let body =
        format!("HTTP/1.1 {status}\r\n{extra}content-length: 0\r\nconnection: close\r\n\r\n");
    let _ = conn.write_all(body.as_bytes()).await;
}

/// Read the request head (up to the blank line), bounded.
async fn read_head(conn: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
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
    let host = host.to_ascii_lowercase();
    if !config.danger_allow_loopback
        && !config.allowed_ports.is_empty()
        && !config.allowed_ports.contains(&port)
    {
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
    Ok(addrs[0])
}

/// Copy both directions with a shared byte counter; stop when the session
/// cap is exhausted.
async fn tunnel(mut client: TcpStream, mut upstream: TcpStream, used: Arc<AtomicU64>, cap: u64) {
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let up = copy_counted(&mut client_read, &mut upstream_write, &used, cap);
    let down = copy_counted(&mut upstream_read, &mut client_write, &used, cap);
    // Either side closing (or the cap firing) ends the tunnel.
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

async fn copy_counted<R, W>(reader: &mut R, writer: &mut W, used: &AtomicU64, cap: u64)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 {
            let _ = writer.shutdown().await;
            break;
        }
        let total = used.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
        if total > cap {
            tracing::warn!(cap, "egress byte cap exhausted; closing tunnel");
            let _ = writer.shutdown().await;
            break;
        }
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

async fn handle_connection(
    mut conn: TcpStream,
    sessions: Sessions,
    config: EgressConfig,
) -> std::io::Result<()> {
    let head = match tokio::time::timeout(std::time::Duration::from_secs(30), read_head(&mut conn))
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
        let Ok(upstream) = TcpStream::connect(addr).await else {
            respond(&mut conn, "502 Bad Gateway", "").await;
            return Ok(());
        };
        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        tracing::debug!(host, port, "egress CONNECT tunnel open");
        tunnel(conn, upstream, session.used, session.cap).await;
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
    let Ok(mut upstream) = TcpStream::connect(addr).await else {
        respond(&mut conn, "502 Bad Gateway", "").await;
        return Ok(());
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
    session.used.fetch_add(out.len() as u64, Ordering::Relaxed);
    upstream.write_all(out.as_bytes()).await?;
    tracing::debug!(host, port, path, "egress plain-http forwarded");
    tunnel(conn, upstream, session.used, session.cap).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
        let grant = proxy.grant(vec!["127.0.0.1".into()], 1 << 20);
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
}
