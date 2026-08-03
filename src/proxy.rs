//! The ephemeral loopback proxy.
//!
//! Two paths, chosen by sniffing the first request line:
//!
//! * `CONNECT host:port` — answered with `200 Connection Established`, then the two sockets
//!   are spliced together with [`tokio::io::copy_bidirectional`]. TLS is never terminated, so
//!   there are no certificates to install and no per-byte crypto cost; the counters see exactly
//!   the ciphertext that crosses the wire.
//! * anything else (absolute-form HTTP, i.e. `GET http://host/path`) — served by hyper and
//!   forwarded with a pooled client whose connector wraps each upstream socket in a counter.
//!   Counting on the *upstream* socket rather than the client socket is deliberate: it measures
//!   what actually left the machine, not what the child handed to the proxy.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tower_service::Service;

use crate::io::{ConnLog, Counting, Rewind, Side};
use crate::socks;
use crate::stats::{EndpointStats, OpenGuard, Registry};

/// Largest request head the proxy will buffer before giving up on a connection.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Hop-by-hop headers that must not be forwarded upstream.
const HOP_BY_HOP: [HeaderName; 3] = [
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("proxy-authorization"),
    HeaderName::from_static("keep-alive"),
];

type CountedBody = BoxBody<Bytes, hyper::Error>;

/// Shared state handed to every connection task.
#[derive(Debug)]
struct Shared {
    registry: Arc<Registry>,
    verbose: bool,
}

impl Shared {
    /// Creates a verbose logger for a new connection, or `None` when not in verbose mode.
    fn conn_log(&self, target: &str) -> Option<Arc<ConnLog>> {
        self.verbose
            .then(|| Arc::new(ConnLog::new(self.registry.next_conn_id(), target)))
    }
}

/// A running proxy server bound to an OS-assigned loopback port.
///
/// Dropping the `Proxy` stops the accept loop; connections already in flight are not killed,
/// so the caller can drain them before reporting.
#[derive(Debug)]
pub struct Proxy {
    addr: SocketAddr,
    accept_loop: JoinHandle<()>,
}

impl Proxy {
    /// Binds to `127.0.0.1:0` and starts accepting connections immediately.
    ///
    /// # Errors
    ///
    /// Returns an error if the loopback listener cannot be bound.
    pub async fn bind(registry: Arc<Registry>, verbose: bool) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared { registry, verbose });
        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    continue;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let guard = shared.registry.track_open();
                    if let Err(err) = handle_connection(stream, Arc::clone(&shared)).await
                        && shared.verbose
                    {
                        eprintln!("[wiretally] connection error: {err}");
                    }
                    drop(guard);
                });
            }
        });
        Ok(Self { addr, accept_loop })
    }

    /// Address the child process should be pointed at.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Proxy URL in the form expected by `HTTP_PROXY` and `HTTPS_PROXY`.
    pub fn http_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Proxy URL in the form expected by `ALL_PROXY`.
    ///
    /// The `socks5h` scheme (rather than `socks5`) asks the client to send hostnames to the
    /// proxy instead of resolving them itself, which keeps endpoints named in the report.
    pub fn socks_url(&self) -> String {
        format!("socks5h://{}", self.addr)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

/// Sniffs the first byte and dispatches to the SOCKS5, tunnel, or HTTP path.
///
/// One byte is enough to separate the protocols: a SOCKS5 greeting starts with its version
/// (`0x05`), while every HTTP request starts with an ASCII method name. Peeking rather than
/// reading keeps the HTTP paths unchanged.
async fn handle_connection(mut stream: TcpStream, shared: Arc<Shared>) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    let mut first = [0u8; 1];
    if stream.peek(&mut first).await? == 0 {
        return Ok(());
    }
    if first[0] == socks::GREETING_BYTE {
        return serve_socks(stream, shared).await;
    }

    let head = read_head(&mut stream).await?;
    let Some((method, target)) = request_line(&head) else {
        anyhow::bail!("malformed request head");
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        let leftover = head_body(&head);
        let (host, port) = split_authority(target, 443);
        connect_and_splice(stream, host, port, leftover, shared, Handshake::Http).await
    } else {
        serve_http(Rewind::new(head, stream), shared).await
    }
}

/// Completes a SOCKS5 handshake and splices the resulting tunnel.
async fn serve_socks(mut client: TcpStream, shared: Arc<Shared>) -> anyhow::Result<()> {
    let request = match socks::accept(&mut client).await {
        Ok(request) => request,
        Err(err) => {
            let _ = socks::reply(&mut client, err.reply_code()).await;
            if err.is_udp_associate() {
                // Always warn: unlike other handshake failures, this one means real traffic is
                // about to happen over UDP that no proxy can see or count.
                eprintln!("[wiretally] warning: {err}");
            } else if shared.verbose {
                eprintln!("[wiretally] socks5: {err}");
            }
            return Err(err.into());
        }
    };
    connect_and_splice(
        client,
        request.host,
        request.port,
        Vec::new(),
        shared,
        Handshake::Socks,
    )
    .await
}

/// Which protocol's success/failure replies to send to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handshake {
    /// `HTTP/1.1 200 Connection Established` / `502 Bad Gateway`.
    Http,
    /// A SOCKS5 reply record.
    Socks,
}

impl Handshake {
    /// Tells the client the tunnel is open.
    async fn accept(self, client: &mut TcpStream) -> io::Result<()> {
        match self {
            Self::Http => {
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
            }
            Self::Socks => socks::reply(client, socks::REP_SUCCESS).await,
        }
    }

    /// Tells the client the upstream connection failed.
    async fn refuse(self, client: &mut TcpStream) -> io::Result<()> {
        match self {
            Self::Http => {
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await
            }
            Self::Socks => socks::reply(client, socks::REP_CONNECTION_REFUSED).await,
        }
    }
}

/// Reads until the end of the request head (`\r\n\r\n`), returning everything read.
async fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return if buf.is_empty() {
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            } else {
                Ok(buf)
            };
        }
        buf.extend_from_slice(&chunk[..n]);
        if find_head_end(&buf).is_some() {
            return Ok(buf);
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Bytes read past the end of the head, which belong to the tunnel payload.
fn head_body(head: &[u8]) -> Vec<u8> {
    find_head_end(head).map_or_else(Vec::new, |end| head[end..].to_vec())
}

/// Splits `METHOD target` out of a request head.
fn request_line(head: &[u8]) -> Option<(&str, &str)> {
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    (!method.is_empty() && !target.is_empty()).then_some((method, target))
}

/// Splits an authority into a `(host, port)` pair, defaulting the port and unwrapping the
/// brackets of an IPv6 literal.
///
/// ```
/// use wiretally::proxy::split_authority;
///
/// assert_eq!(split_authority("example.com:8080", 443), ("example.com".into(), 8080));
/// assert_eq!(split_authority("example.com", 443), ("example.com".into(), 443));
/// assert_eq!(split_authority("[::1]:80", 443), ("::1".into(), 80));
/// ```
pub fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').unwrap_or((rest, ""));
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (host.to_ascii_lowercase(), port);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => match port.parse() {
            Ok(port) => (host.to_ascii_lowercase(), port),
            Err(_) => (authority.to_ascii_lowercase(), default_port),
        },
        None => (authority.to_ascii_lowercase(), default_port),
    }
}

/// Opens the upstream connection, answers the client's handshake, and counts the tunnel.
///
/// Shared by the `CONNECT` and SOCKS5 paths: once either handshake names a host and port, the
/// rest is protocol-agnostic byte shuffling, which is exactly why this tool can measure gRPC,
/// Postgres, or any other TCP protocol the client chooses to tunnel.
async fn connect_and_splice(
    mut client: TcpStream,
    host: String,
    port: u16,
    leftover: Vec<u8>,
    shared: Arc<Shared>,
    handshake: Handshake,
) -> anyhow::Result<()> {
    let stats = shared.registry.endpoint(&host);
    let log = shared.conn_log(&format!("{host}:{port}"));

    let upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(upstream) => upstream,
        Err(err) => {
            let _ = handshake.refuse(&mut client).await;
            return Err(err.into());
        }
    };
    upstream.set_nodelay(true)?;
    if let Ok(peer) = upstream.peer_addr() {
        stats.observe_ip(peer.ip());
        if let Some(log) = &log {
            log.event(format!("OPEN  -> {host}:{port} ({})", peer.ip()));
        }
    }
    stats.add_connection();

    handshake.accept(&mut client).await?;

    // The counter sits on the client side here so the handshake itself — proxy overhead that
    // never reaches the remote host — stays out of the totals, while any bytes the client
    // pipelined behind it still get counted via `Rewind`.
    let mut counted = Counting::new(
        Rewind::new(leftover, client),
        Arc::clone(&stats),
        Side::Client,
        log.clone(),
    );
    let mut upstream = upstream;
    let result = tokio::io::copy_bidirectional(&mut counted, &mut upstream).await;

    if let Some(log) = &log {
        log.event(format!(
            "CLOSE -> Total Rx: {} bytes | Total Tx: {} bytes",
            stats.ingress(),
            stats.egress()
        ));
    }
    result?;
    Ok(())
}

/// Serves absolute-form HTTP requests off a single client connection.
async fn serve_http(stream: Rewind<TcpStream>, shared: Arc<Shared>) -> anyhow::Result<()> {
    let client: Client<CountingConnector, Incoming> =
        Client::builder(TokioExecutor::new()).build(CountingConnector {
            shared: Arc::clone(&shared),
        });
    let service = service_fn(move |req| {
        let client = client.clone();
        async move { forward(req, client).await }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

/// Forwards one proxied request upstream, converting failures into `502`s.
async fn forward(
    mut req: Request<Incoming>,
    client: Client<CountingConnector, Incoming>,
) -> Result<Response<CountedBody>, Infallible> {
    for header in HOP_BY_HOP {
        req.headers_mut().remove(header);
    }
    if req.uri().authority().is_none()
        && let Err(err) = absolutize(&mut req)
    {
        return Ok(error_response(StatusCode::BAD_REQUEST, err));
    }

    match client.request(req).await {
        Ok(resp) => Ok(resp.map(|body| body.boxed())),
        Err(err) => Ok(error_response(
            StatusCode::BAD_GATEWAY,
            format!("upstream request failed: {err}"),
        )),
    }
}

/// Rebuilds an origin-form request URI into absolute form using the `Host` header.
///
/// Well-behaved clients always send absolute form to a proxy; this covers the ones that don't.
fn absolutize(req: &mut Request<Incoming>) -> Result<(), String> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or("request has neither an absolute URI nor a Host header")?
        .to_owned();
    let path = req
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_owned();
    *req.uri_mut() = format!("http://{host}{path}")
        .parse::<Uri>()
        .map_err(|err| format!("cannot build absolute URI: {err}"))?;
    Ok(())
}

fn error_response(status: StatusCode, message: impl Into<Bytes>) -> Response<CountedBody> {
    let body = Full::new(message.into())
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    resp
}

/// Connector that opens plain TCP connections and counts every byte on them.
#[derive(Debug, Clone)]
struct CountingConnector {
    shared: Arc<Shared>,
}

impl Service<Uri> for CountingConnector {
    type Response = CountedStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            let authority = uri
                .authority()
                .map(|a| a.as_str().to_owned())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing authority"))?;
            let default_port = if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            };
            let (host, port) = split_authority(&authority, default_port);
            let stats = shared.registry.endpoint(&host);
            let log = shared.conn_log(&format!("{host}:{port}"));

            let stream = TcpStream::connect((host.as_str(), port)).await?;
            stream.set_nodelay(true)?;
            if let Ok(peer) = stream.peer_addr() {
                stats.observe_ip(peer.ip());
                if let Some(log) = &log {
                    log.event(format!("OPEN  -> {host}:{port} ({})", peer.ip()));
                }
            }
            stats.add_connection();

            Ok(CountedStream {
                io: TokioIo::new(Counting::new(
                    stream,
                    Arc::clone(&stats),
                    Side::Upstream,
                    log.clone(),
                )),
                _guard: shared.registry.track_open(),
                close_log: log.map(|log| CloseLog { log, stats }),
            })
        })
    }
}

/// Logs a `CLOSE` line with connection totals when the upstream socket is dropped.
#[derive(Debug)]
struct CloseLog {
    log: Arc<ConnLog>,
    stats: Arc<EndpointStats>,
}

impl Drop for CloseLog {
    fn drop(&mut self) {
        self.log.event(format!(
            "CLOSE -> Total Rx: {} bytes | Total Tx: {} bytes",
            self.stats.ingress(),
            self.stats.egress()
        ));
    }
}

/// Upstream socket as hyper's client wants it: counted, pooled, and tied to a drain guard.
#[derive(Debug)]
struct CountedStream {
    io: TokioIo<Counting<TcpStream>>,
    _guard: OpenGuard,
    close_log: Option<CloseLog>,
}

impl Connection for CountedStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for CountedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for CountedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Keep the close line ordered after the last byte, not after pool eviction.
        let poll = Pin::new(&mut self.io).poll_shutdown(cx);
        if poll.is_ready() {
            self.close_log = None;
        }
        poll
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_extracts_method_and_target() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            request_line(head),
            Some(("CONNECT", "example.com:443")),
            "CONNECT target should come through verbatim"
        );
        let head = b"GET http://example.com/x HTTP/1.1\r\n\r\n";
        assert_eq!(request_line(head), Some(("GET", "http://example.com/x")));
        assert_eq!(request_line(b"garbage"), None);
    }

    #[test]
    fn head_body_returns_pipelined_bytes() {
        let head = b"CONNECT a:443 HTTP/1.1\r\n\r\nEXTRA".to_vec();
        assert_eq!(head_body(&head), b"EXTRA");
        let head = b"CONNECT a:443 HTTP/1.1\r\n\r\n".to_vec();
        assert!(head_body(&head).is_empty());
    }

    #[test]
    fn authority_split_handles_ipv6_and_missing_ports() {
        assert_eq!(
            split_authority("Example.COM:8443", 80),
            ("example.com".into(), 8443)
        );
        assert_eq!(
            split_authority("example.com", 80),
            ("example.com".into(), 80)
        );
        assert_eq!(
            split_authority("[2001:db8::1]:443", 80),
            ("2001:db8::1".into(), 443)
        );
        assert_eq!(
            split_authority("[2001:db8::1]", 80),
            ("2001:db8::1".into(), 80)
        );
    }
}
