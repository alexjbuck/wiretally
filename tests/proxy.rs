//! Byte-accuracy tests for the proxy.
//!
//! Each test puts a raw TCP origin server behind the proxy and has that server count exactly
//! what crossed its own socket. The proxy's counters must agree with those numbers exactly —
//! that is the accuracy claim, and it is checked without touching the network.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use net_counter::proxy::Proxy;
use net_counter::stats::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Byte counts observed by the origin server itself.
#[derive(Debug, Default)]
struct OriginCounts {
    read: AtomicU64,
    written: AtomicU64,
}

/// Starts an origin server that echoes everything it receives, counting both directions.
async fn echo_origin() -> (SocketAddr, Arc<OriginCounts>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counts = Arc::new(OriginCounts::default());
    let server_counts = Arc::clone(&counts);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counts = Arc::clone(&server_counts);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    counts.read.fetch_add(n as u64, Ordering::SeqCst);
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    counts.written.fetch_add(n as u64, Ordering::SeqCst);
                }
            });
        }
    });
    (addr, counts)
}

/// Starts an origin server that answers any HTTP request with `body`, counting both directions.
async fn http_origin(body: &'static str) -> (SocketAddr, Arc<OriginCounts>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counts = Arc::new(OriginCounts::default());
    let server_counts = Arc::clone(&counts);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counts = Arc::clone(&server_counts);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                counts.read.fetch_add(n as u64, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                if stream.write_all(response.as_bytes()).await.is_ok() {
                    counts
                        .written
                        .fetch_add(response.len() as u64, Ordering::SeqCst);
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, counts)
}

/// Reads from `stream` until the end of an HTTP head, returning the head bytes.
async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read_exact(&mut byte).await.is_ok() {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    head
}

#[tokio::test]
async fn connect_tunnel_counts_exact_wire_bytes() {
    let (origin, origin_counts) = echo_origin().await;
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut client).await;
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
        "expected a tunnel to be established, got {:?}",
        String::from_utf8_lossy(&head)
    );

    // Large enough to span many read/write chunks in both directions. Reading concurrently
    // with writing is required: 300 KB will not fit in the socket buffers along the path.
    let payload = vec![0xABu8; 300_000];
    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let reader = tokio::spawn(async move {
        let mut echoed = vec![0u8; 300_000];
        client_rx.read_exact(&mut echoed).await.unwrap();
        echoed
    });
    client_tx.write_all(&payload).await.unwrap();
    let echoed = reader.await.unwrap();
    assert_eq!(echoed, payload, "tunnel must be byte-transparent");

    let stats = registry.endpoint("127.0.0.1");
    assert_eq!(
        stats.egress(),
        origin_counts.read.load(Ordering::SeqCst),
        "egress must equal what the origin actually received"
    );
    assert_eq!(
        stats.ingress(),
        origin_counts.written.load(Ordering::SeqCst),
        "ingress must equal what the origin actually sent"
    );
    assert_eq!(stats.egress(), payload.len() as u64);
    assert_eq!(stats.connections(), 1);
    assert_eq!(
        stats.ip().map(|ip| ip.to_string()),
        Some("127.0.0.1".to_owned())
    );
    // The CONNECT handshake itself is proxy overhead and must not inflate the totals.
    assert_eq!(stats.egress(), payload.len() as u64);
}

#[tokio::test]
async fn plain_http_counts_exact_upstream_bytes() {
    let body = "hello from the origin";
    let (origin, origin_counts) = http_origin(body).await;
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/data HTTP/1.1\r\nHost: {origin}\r\nProxy-Connection: keep-alive\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_head(&mut client).await;
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "got {head}");
    let mut received = String::new();
    client.read_to_string(&mut received).await.unwrap();
    assert!(
        received.ends_with(body),
        "body must pass through: {received}"
    );

    let stats = registry.endpoint("127.0.0.1");
    assert_eq!(
        stats.egress(),
        origin_counts.read.load(Ordering::SeqCst),
        "egress must equal the request bytes the origin received"
    );
    assert_eq!(
        stats.ingress(),
        origin_counts.written.load(Ordering::SeqCst),
        "ingress must equal the response bytes the origin sent"
    );
    assert_eq!(stats.connections(), 1);
}

#[tokio::test]
async fn unreachable_connect_target_returns_bad_gateway() {
    // Bind and immediately drop a listener to get an address nothing is listening on.
    let dead = {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        listener.local_addr().unwrap()
    };
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(format!("CONNECT {dead} HTTP/1.1\r\nHost: {dead}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = String::from_utf8_lossy(&read_head(&mut client).await).into_owned();
    assert!(head.starts_with("HTTP/1.1 502"), "got {head}");
    assert_eq!(registry.endpoint("127.0.0.1").connections(), 0);
}

#[tokio::test]
async fn multiple_connections_to_one_host_aggregate() {
    let (origin, _) = echo_origin().await;
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    for _ in 0..3 {
        let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
        client
            .write_all(format!("CONNECT {origin} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let _ = read_head(&mut client).await;
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
    }

    let stats = registry.endpoint("127.0.0.1");
    assert_eq!(stats.connections(), 3);
    assert_eq!(stats.egress(), 12);
    assert_eq!(stats.ingress(), 12);
    assert_eq!(registry.snapshot(None).len(), 1, "one host, one row");
}
