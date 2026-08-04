//! Byte-accuracy tests for the proxy.
//!
//! Each test puts a raw TCP origin server behind the proxy and has that server count exactly
//! what crossed its own socket. The proxy's counters must agree with those numbers exactly —
//! that is the accuracy claim, and it is checked without touching the network.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiretally::proxy::Proxy;
use wiretally::stats::Registry;

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

/// Sends a SOCKS5 no-auth greeting and a CONNECT request for `host:port`, returning the reply.
async fn socks_connect(client: &mut TcpStream, host: &str, port: u16) -> Vec<u8> {
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut selection = [0u8; 2];
    client.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [0x05, 0x00], "no-auth should be selected");

    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = vec![0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    reply
}

#[tokio::test]
async fn socks5_tunnels_arbitrary_tcp_and_counts_it() {
    // The origin here speaks no HTTP at all — it is a plain byte echo, standing in for gRPC,
    // Postgres, or any other TCP protocol a client might tunnel.
    let (origin, origin_counts) = echo_origin().await;
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let reply = socks_connect(&mut client, "localhost", origin.port()).await;
    assert_eq!(reply[0..2], [0x05, 0x00], "expected a success reply");

    let payload = b"\x00\x01binary-not-http\xff".repeat(500);
    let mut echoed = vec![0u8; payload.len()];
    client.write_all(&payload).await.unwrap();
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "socks tunnel must be byte-transparent");

    // socks5h sends the hostname, so the endpoint is named rather than an address.
    let stats = registry.endpoint("localhost");
    assert_eq!(
        stats.egress(),
        origin_counts.read.load(Ordering::SeqCst),
        "egress must equal what the origin received"
    );
    assert_eq!(stats.egress(), payload.len() as u64);
    assert_eq!(stats.ingress(), payload.len() as u64);
    assert_eq!(stats.connections(), 1);
    // The SOCKS handshake is proxy overhead and must not appear in the totals.
    assert_eq!(stats.egress(), payload.len() as u64);
}

/// Binds a UDP echo server, standing in for a DNS resolver or any other datagram service.
async fn udp_echo_origin() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], from).await;
        }
    });
    addr
}

#[tokio::test]
async fn socks5_udp_associate_relays_datagrams_and_counts_them() {
    let destination = udp_echo_origin().await;
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    // Control connection: ask for a UDP association and learn where to send datagrams.
    let mut control = TcpStream::connect(proxy.local_addr()).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut selection = [0u8; 2];
    control.read_exact(&mut selection).await.unwrap();
    let mut request = vec![0x05, 0x03, 0x00, 0x01];
    request.extend_from_slice(&[0, 0, 0, 0]);
    request.extend_from_slice(&0u16.to_be_bytes());
    control.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "association should be granted, not refused");
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();
    assert_ne!(relay_port, 0, "reply must advertise a real relay port");

    // Datagram path: header names the true destination, payload is relayed verbatim.
    let client = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let payload = b"datagram payload";
    let mut wrapped = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    wrapped.extend_from_slice(&destination.port().to_be_bytes());
    wrapped.extend_from_slice(payload);
    client.send_to(&wrapped, relay).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (len, _) = client.recv_from(&mut buf).await.unwrap();
    assert_eq!(
        &buf[len - payload.len()..len],
        payload,
        "relayed reply must carry the payload back"
    );

    let stats = registry.endpoint("127.0.0.1");
    assert_eq!(stats.egress(), payload.len() as u64, "UDP out is counted");
    assert_eq!(stats.ingress(), payload.len() as u64, "UDP in is counted");
    assert_eq!(stats.connections(), 1);

    // Closing the control connection ends the association.
    drop(control);
}

#[tokio::test]
async fn socks5_and_http_share_one_port() {
    let (origin, _) = echo_origin().await;
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut socks_client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let reply = socks_connect(&mut socks_client, "127.0.0.1", origin.port()).await;
    assert_eq!(reply[1], 0x00);
    socks_client.write_all(b"abc").await.unwrap();
    let mut echoed = [0u8; 3];
    socks_client.read_exact(&mut echoed).await.unwrap();

    let mut http_client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    http_client
        .write_all(format!("CONNECT {origin} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = String::from_utf8_lossy(&read_head(&mut http_client).await).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "got {head}");
    http_client.write_all(b"de").await.unwrap();
    let mut echoed = [0u8; 2];
    http_client.read_exact(&mut echoed).await.unwrap();

    let stats = registry.endpoint("127.0.0.1");
    assert_eq!(stats.connections(), 2, "both protocols hit the same host");
    assert_eq!(stats.egress(), 5);
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
async fn origin_form_requests_are_rebuilt_from_the_host_header() {
    // A well-behaved client sends `GET http://host/path` to a proxy. Some don't, and send the
    // origin form they would send to the server itself; the proxy reconstructs the absolute URI
    // from the Host header rather than failing the request.
    let body = "rebuilt";
    let (origin, origin_counts) = http_origin(body).await;
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(format!("GET /data HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = String::from_utf8_lossy(&read_head(&mut client).await).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "got {head}");

    let stats = registry.endpoint("127.0.0.1");
    assert_eq!(
        stats.egress(),
        origin_counts.read.load(Ordering::SeqCst),
        "a rebuilt request is counted like any other"
    );
    assert_eq!(stats.connections(), 1);
}

#[tokio::test]
async fn an_origin_form_request_with_no_host_is_a_bad_request() {
    // HTTP/1.0 permits omitting Host, which leaves the proxy with no way to know where the
    // request was meant to go. It must say so rather than guess or hang.
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(b"GET /data HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let head = String::from_utf8_lossy(&read_head(&mut client).await).into_owned();
    // The status line echoes the request's version, so this answer is HTTP/1.0.
    assert!(head.starts_with("HTTP/1.0 400"), "got {head}");
    assert!(
        head.contains("text/plain"),
        "the error body should be readable: {head}"
    );
    assert!(
        registry.snapshot(None).is_empty(),
        "nothing left the machine, so nothing is counted"
    );
}

#[tokio::test]
async fn an_unreachable_origin_becomes_a_bad_gateway() {
    // The forwarded-HTTP counterpart of the CONNECT 502 test: here the failure happens inside
    // the counting connector rather than before the handshake.
    let dead = {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        listener.local_addr().unwrap()
    };
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(format!("GET http://{dead}/data HTTP/1.1\r\nHost: {dead}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = String::from_utf8_lossy(&read_head(&mut client).await).into_owned();
    assert!(head.starts_with("HTTP/1.1 502"), "got {head}");
    assert_eq!(registry.endpoint("127.0.0.1").connections(), 0);
}

#[tokio::test]
async fn an_oversized_request_head_is_refused_rather_than_buffered() {
    // `read_head` buffers until it sees the end of the head, so an endless header stream is the
    // one way a client could make the proxy allocate without bound. It must be cut off.
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    // 96 KiB of header line with no terminating blank line, past the 64 KiB limit.
    let filler = format!("X-Pad: {}\r\n", "p".repeat(1000));
    let mut written = 0;
    while written < 96 * 1024 {
        if client.write_all(filler.as_bytes()).await.is_err() {
            break; // The proxy hung up mid-write, which is the behaviour under test.
        }
        written += filler.len();
    }

    // Dropping the socket with unread data still queued makes the OS send an RST, so the read
    // may fail outright instead of returning a clean EOF. Either way the client got no answer,
    // which is the point.
    let mut response = Vec::new();
    match client.read_to_end(&mut response).await {
        Ok(_) => assert!(
            response.is_empty(),
            "the connection should be dropped, not answered: {:?}",
            String::from_utf8_lossy(&response)
        ),
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset, "{err}"),
    }
    assert!(registry.snapshot(None).is_empty(), "nothing was forwarded");
}

#[tokio::test]
async fn a_malformed_request_line_closes_the_connection() {
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), false).await.unwrap();

    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client.write_all(b"nonsense\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(
        response.is_empty(),
        "an unparseable head has no target to answer for: {:?}",
        String::from_utf8_lossy(&response)
    );
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
