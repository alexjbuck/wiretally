//! SOCKS5 UDP relay ([RFC 1928 §7](https://www.rfc-editor.org/rfc/rfc1928#section-7)).
//!
//! A client that asks for `UDP ASSOCIATE` stops sending datagrams to the destination and starts
//! sending them here instead, wrapped in a small header naming the real destination. That makes
//! the relay the only place UDP bytes are visible to this tool — so it forwards them and counts
//! them, rather than refusing and risking breaking a client that would otherwise have worked.
//!
//! Two sockets are involved: one facing the client (whose address is advertised in the
//! handshake reply) and one facing the internet. Payload bytes are counted; the relay header is
//! proxy overhead and excluded, matching how the TCP paths treat their handshakes.
//!
//! Only what the client routes through here can be counted. A client that sends QUIC straight
//! to a destination never asks for a relay and stays invisible.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::{UdpSocket, lookup_host};

use crate::io::ConnLog;
use crate::socks;
use crate::stats::{EndpointStats, Registry};

/// Maximum datagram this relay will handle, header included.
const MAX_DATAGRAM: usize = 65_535;

/// A live UDP association for one SOCKS5 control connection.
///
/// The association lives as long as its control connection: dropping the relay closes both
/// sockets, which is what RFC 1928 requires.
#[derive(Debug)]
pub struct Relay {
    client_side: UdpSocket,
    upstream: UdpSocket,
    registry: Arc<Registry>,
    log: Option<Arc<ConnLog>>,
    /// Counters per destination host, cached so the hot path never locks the registry.
    endpoints: HashMap<String, Arc<EndpointStats>>,
    /// Resolved destinations, cached so names are resolved once per association.
    resolved: HashMap<(String, u16), SocketAddr>,
    /// Maps a reply's source address back to the host name the client used for it.
    names: HashMap<IpAddr, String>,
    /// Where to send replies; learned from the first datagram the client sends.
    client_addr: Option<SocketAddr>,
}

impl Relay {
    /// Binds the relay's sockets, both on loopback-reachable addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if either socket cannot be bound.
    pub async fn bind(registry: Arc<Registry>, log: Option<Arc<ConnLog>>) -> io::Result<Self> {
        Ok(Self {
            client_side: UdpSocket::bind(("127.0.0.1", 0)).await?,
            upstream: UdpSocket::bind(("0.0.0.0", 0)).await?,
            registry,
            log,
            endpoints: HashMap::new(),
            resolved: HashMap::new(),
            names: HashMap::new(),
            client_addr: None,
        })
    }

    /// Address the client should send its datagrams to.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket's local address cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.client_side.local_addr()
    }

    /// Relays datagrams in both directions until the relay is dropped.
    ///
    /// Individual datagram failures are logged (in verbose mode) and skipped rather than
    /// aborting the association: UDP is lossy by definition, and one undeliverable datagram
    /// says nothing about the next.
    pub async fn run(mut self) {
        let mut from_client = vec![0u8; MAX_DATAGRAM];
        let mut from_upstream = vec![0u8; MAX_DATAGRAM];
        let mut scratch = Vec::with_capacity(MAX_DATAGRAM);

        loop {
            // The event is extracted before handling so the borrows taken by the two futures
            // are released before the handlers touch `self` mutably.
            let event = tokio::select! {
                result = self.client_side.recv_from(&mut from_client) => match result {
                    Ok((len, addr)) => Event::FromClient { len, addr },
                    Err(_) => return,
                },
                result = self.upstream.recv_from(&mut from_upstream) => match result {
                    Ok((len, addr)) => Event::FromUpstream { len, addr },
                    Err(_) => return,
                },
            };

            match event {
                Event::FromClient { len, addr } => {
                    self.client_addr = Some(addr);
                    self.forward_out(&from_client[..len]).await;
                }
                Event::FromUpstream { len, addr } => {
                    self.forward_back(addr, &from_upstream[..len], &mut scratch)
                        .await;
                }
            }
        }
    }

    /// Unwraps a client datagram and sends its payload to the real destination.
    async fn forward_out(&mut self, raw: &[u8]) {
        let datagram = match socks::parse_datagram(raw) {
            Ok(datagram) => datagram,
            Err(err) => {
                self.note(format!("UDP   -- dropped datagram: {err}"));
                return;
            }
        };
        let Some(target) = self.resolve(&datagram.host, datagram.port).await else {
            return;
        };

        let stats = self.endpoint(&datagram.host);
        match self.upstream.send_to(datagram.payload, target).await {
            Ok(sent) => {
                stats.add_egress(sent as u64);
                stats.observe_ip(target.ip());
                self.names.insert(target.ip(), datagram.host.clone());
                if let Some(log) = &self.log {
                    log.event(format!(
                        "UDP   -> {sent} bytes {}:{}",
                        datagram.host, datagram.port
                    ));
                }
            }
            Err(err) => self.note(format!("UDP   -- send to {target} failed: {err}")),
        }
    }

    /// Wraps a reply from the internet and hands it back to the client.
    async fn forward_back(&mut self, from: SocketAddr, payload: &[u8], scratch: &mut Vec<u8>) {
        let Some(client_addr) = self.client_addr else {
            // Nothing has told us where the client lives yet, so there is nowhere to reply to.
            return;
        };
        let host = self
            .names
            .get(&from.ip())
            .cloned()
            .unwrap_or_else(|| from.ip().to_string());
        let stats = self.endpoint(&host);

        socks::encode_datagram(from, payload, scratch);
        match self.client_side.send_to(scratch, client_addr).await {
            Ok(_) => {
                stats.add_ingress(payload.len() as u64);
                if let Some(log) = &self.log {
                    log.event(format!("UDP   <- {} bytes {host}", payload.len()));
                }
            }
            Err(err) => self.note(format!("UDP   -- reply to client failed: {err}")),
        }
    }

    /// Returns cached counters for `host`, counting a new destination as a new connection.
    fn endpoint(&mut self, host: &str) -> Arc<EndpointStats> {
        if let Some(stats) = self.endpoints.get(host) {
            return Arc::clone(stats);
        }
        let stats = self.registry.endpoint(host);
        // One "connection" per destination host in this association: UDP has none of its own,
        // and this keeps the CONNS column meaningful next to the TCP rows.
        stats.add_connection();
        self.endpoints.insert(host.to_owned(), Arc::clone(&stats));
        stats
    }

    /// Resolves and caches a destination, returning `None` if it cannot be resolved.
    async fn resolve(&mut self, host: &str, port: u16) -> Option<SocketAddr> {
        let key = (host.to_owned(), port);
        if let Some(addr) = self.resolved.get(&key) {
            return Some(*addr);
        }
        let addr = match lookup_host((host, port)).await {
            Ok(mut addrs) => addrs.next(),
            Err(err) => {
                self.note(format!("UDP   -- cannot resolve {host}:{port}: {err}"));
                None
            }
        }?;
        self.resolved.insert(key, addr);
        Some(addr)
    }

    /// Logs a relay-level note, in verbose mode only.
    fn note(&self, message: String) {
        if let Some(log) = &self.log {
            log.event(message);
        }
    }
}

/// Which socket produced a datagram.
#[derive(Debug, Clone, Copy)]
enum Event {
    /// The client sent a datagram to relay outward.
    FromClient { len: usize, addr: SocketAddr },
    /// A destination replied.
    FromUpstream { len: usize, addr: SocketAddr },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Binds a UDP echo server that returns every payload it receives.
    async fn udp_echo() -> SocketAddr {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..len], from).await;
            }
        });
        addr
    }

    /// Wraps `payload` in a client-side relay header for `dest`.
    fn wrap(dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x00, 0x00, 0x00, 0x01];
        match dest.ip() {
            IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
            IpAddr::V6(_) => unreachable!("test uses ipv4"),
        }
        out.extend_from_slice(&dest.port().to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn relayed_datagrams_are_delivered_and_counted_both_ways() {
        let destination = udp_echo().await;
        let registry = Arc::new(Registry::new());
        let relay = Relay::bind(Arc::clone(&registry), None).await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let payload = b"query bytes";
        client
            .send_to(&wrap(destination, payload), relay_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        let echoed = socks::parse_datagram(&buf[..len]).unwrap();
        assert_eq!(echoed.payload, payload, "relay must be byte-transparent");
        assert_eq!(echoed.port, destination.port(), "reply names its source");

        let stats = registry.endpoint("127.0.0.1");
        assert_eq!(stats.egress(), payload.len() as u64);
        assert_eq!(stats.ingress(), payload.len() as u64);
        assert_eq!(stats.connections(), 1);
    }

    #[tokio::test]
    async fn many_datagrams_accumulate_under_one_endpoint() {
        let destination = udp_echo().await;
        let registry = Arc::new(Registry::new());
        let relay = Relay::bind(Arc::clone(&registry), None).await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let payload = [0xEEu8; 512];
        let mut buf = vec![0u8; 2048];
        for _ in 0..5 {
            client
                .send_to(&wrap(destination, &payload), relay_addr)
                .await
                .unwrap();
            client.recv_from(&mut buf).await.unwrap();
        }

        let stats = registry.endpoint("127.0.0.1");
        assert_eq!(stats.egress(), 5 * 512);
        assert_eq!(stats.ingress(), 5 * 512);
        assert_eq!(
            stats.connections(),
            1,
            "one destination is one row, however many datagrams"
        );
    }

    #[tokio::test]
    async fn malformed_datagrams_are_dropped_without_killing_the_relay() {
        let destination = udp_echo().await;
        let registry = Arc::new(Registry::new());
        let relay = Relay::bind(Arc::clone(&registry), None).await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        // Fragmented, then truncated, then valid: only the last should be relayed.
        client
            .send_to(&[0x00, 0x00, 0x07, 0x01, 1, 2, 3, 4, 0, 53], relay_addr)
            .await
            .unwrap();
        client.send_to(&[0x00, 0x00], relay_addr).await.unwrap();
        client
            .send_to(&wrap(destination, b"ok"), relay_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(socks::parse_datagram(&buf[..len]).unwrap().payload, b"ok");
        assert_eq!(registry.endpoint("127.0.0.1").egress(), 2);
    }
}
