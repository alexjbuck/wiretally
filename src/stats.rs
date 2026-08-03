//! Per-endpoint byte counters.
//!
//! Counters live behind [`Arc`] and are updated with relaxed atomic adds, so the cost on the
//! data path is a single uncontended `fetch_add` per chunk — no locking, no allocation. The
//! registry map is only locked when a *new* endpoint is first seen or when the final snapshot
//! is taken.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

/// Live counters for a single remote endpoint (one host, all its connections).
#[derive(Debug, Default)]
pub struct EndpointStats {
    ingress: AtomicU64,
    egress: AtomicU64,
    connections: AtomicU64,
    /// First remote address observed for this host, if any.
    ip: Mutex<Option<IpAddr>>,
}

impl EndpointStats {
    /// Records `n` bytes received from the remote endpoint.
    #[inline]
    pub fn add_ingress(&self, n: u64) {
        self.ingress.fetch_add(n, Ordering::Relaxed);
    }

    /// Records `n` bytes sent to the remote endpoint.
    #[inline]
    pub fn add_egress(&self, n: u64) {
        self.egress.fetch_add(n, Ordering::Relaxed);
    }

    /// Records that one more connection was opened to this endpoint.
    #[inline]
    pub fn add_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Remembers the resolved address of this endpoint; the first address observed wins.
    pub fn observe_ip(&self, addr: IpAddr) {
        let mut slot = self.ip.lock().expect("stats mutex poisoned");
        slot.get_or_insert(addr);
    }

    /// Bytes received from this endpoint so far.
    pub fn ingress(&self) -> u64 {
        self.ingress.load(Ordering::Relaxed)
    }

    /// Bytes sent to this endpoint so far.
    pub fn egress(&self) -> u64 {
        self.egress.load(Ordering::Relaxed)
    }

    /// Connections opened to this endpoint so far.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Resolved address of this endpoint, if one was observed.
    pub fn ip(&self) -> Option<IpAddr> {
        *self.ip.lock().expect("stats mutex poisoned")
    }
}

/// Immutable point-in-time view of one endpoint's counters, as reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    /// Hostname from the `CONNECT` target or request URI, or a reverse-resolved name.
    pub domain: String,
    /// Remote address the connections actually went to.
    pub ip_address: Option<IpAddr>,
    /// Bytes received from this endpoint.
    pub ingress_bytes: u64,
    /// Bytes sent to this endpoint.
    pub egress_bytes: u64,
    /// Connections opened to this endpoint.
    pub connections: u64,
    /// Whether this endpoint satisfies the `--domain-prefix` filter (always `true` when no
    /// filter was given).
    pub matches_filter: bool,
}

/// All endpoints seen during a run, keyed by hostname.
///
/// Cloning the `Arc` is the intended way to share this with connection tasks.
#[derive(Debug, Default)]
pub struct Registry {
    endpoints: Mutex<HashMap<String, Arc<EndpointStats>>>,
    open_connections: AtomicU64,
    next_conn_id: AtomicU64,
}

impl Registry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the counters for `host`, creating them on first sight.
    ///
    /// The returned handle should be held for the lifetime of a connection so the hot path
    /// never touches the map again.
    pub fn endpoint(&self, host: &str) -> Arc<EndpointStats> {
        let mut map = self.endpoints.lock().expect("registry mutex poisoned");
        Arc::clone(map.entry(host.to_owned()).or_default())
    }

    /// Allocates a monotonically increasing connection id for verbose logging.
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Marks a connection as in flight; the returned guard decrements on drop.
    pub fn track_open(self: &Arc<Self>) -> OpenGuard {
        self.open_connections.fetch_add(1, Ordering::SeqCst);
        OpenGuard {
            registry: Arc::clone(self),
        }
    }

    /// Number of connections currently in flight. Used to drain tunnels after the child exits.
    pub fn open_connections(&self) -> u64 {
        self.open_connections.load(Ordering::SeqCst)
    }

    /// Renames an endpoint recorded under a bare IP address to a reverse-resolved hostname,
    /// merging into an existing entry for that hostname if one exists.
    pub fn rename(&self, from: &str, to: &str) {
        if from == to {
            return;
        }
        let mut map = self.endpoints.lock().expect("registry mutex poisoned");
        let Some(stats) = map.remove(from) else {
            return;
        };
        match map.get(to) {
            Some(existing) => {
                existing.add_ingress(stats.ingress());
                existing.add_egress(stats.egress());
                for _ in 0..stats.connections() {
                    existing.add_connection();
                }
                if let Some(ip) = stats.ip() {
                    existing.observe_ip(ip);
                }
            }
            None => {
                map.insert(to.to_owned(), stats);
            }
        }
    }

    /// Hosts recorded so far, paired with their counters.
    pub fn hosts(&self) -> Vec<(String, Arc<EndpointStats>)> {
        let map = self.endpoints.lock().expect("registry mutex poisoned");
        map.iter()
            .map(|(host, stats)| (host.clone(), Arc::clone(stats)))
            .collect()
    }

    /// Snapshots every endpoint, marking filter matches and sorting by ingress (descending).
    ///
    /// `filter` is matched as a domain suffix: `amazonaws.com` matches both
    /// `amazonaws.com` and `s3.us-east-1.amazonaws.com`, but not `notamazonaws.com`.
    pub fn snapshot(&self, filter: Option<&str>) -> Vec<Endpoint> {
        let mut out: Vec<Endpoint> = self
            .hosts()
            .into_iter()
            .map(|(domain, stats)| Endpoint {
                matches_filter: matches_domain(&domain, filter),
                ip_address: stats.ip(),
                ingress_bytes: stats.ingress(),
                egress_bytes: stats.egress(),
                connections: stats.connections(),
                domain,
            })
            .collect();
        out.sort_by(|a, b| {
            b.ingress_bytes
                .cmp(&a.ingress_bytes)
                .then_with(|| b.egress_bytes.cmp(&a.egress_bytes))
                .then_with(|| a.domain.cmp(&b.domain))
        });
        out
    }
}

/// Decrements the registry's in-flight connection count when dropped.
#[derive(Debug)]
pub struct OpenGuard {
    registry: Arc<Registry>,
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.registry
            .open_connections
            .fetch_sub(1, Ordering::SeqCst);
    }
}

/// Returns whether `domain` falls under `filter`, treated as a domain suffix.
///
/// A `None` filter matches everything, which is what makes "no filter" and "filter that
/// matches all" behave identically in the report.
///
/// ```
/// use wiretally::stats::matches_domain;
///
/// assert!(matches_domain("s3.amazonaws.com", Some("amazonaws.com")));
/// assert!(matches_domain("amazonaws.com", Some("amazonaws.com")));
/// assert!(!matches_domain("notamazonaws.com", Some("amazonaws.com")));
/// assert!(matches_domain("anything.dev", None));
/// ```
pub fn matches_domain(domain: &str, filter: Option<&str>) -> bool {
    let Some(filter) = filter else { return true };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let filter = filter
        .trim_start_matches("*.")
        .trim_matches('.')
        .to_ascii_lowercase();
    if filter.is_empty() {
        return true;
    }
    domain == filter || domain.ends_with(&format!(".{filter}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_match_respects_label_boundaries() {
        assert!(matches_domain("a.b.example.com", Some("example.com")));
        assert!(!matches_domain("badexample.com", Some("example.com")));
        assert!(matches_domain("EXAMPLE.com", Some("example.com")));
        assert!(matches_domain("x.example.com.", Some(".example.com")));
        assert!(matches_domain("x.example.com", Some("*.example.com")));
    }

    #[test]
    fn endpoint_handles_are_shared_per_host() {
        let registry = Registry::new();
        registry.endpoint("a.example").add_ingress(10);
        registry.endpoint("a.example").add_egress(4);
        registry.endpoint("a.example").add_connection();
        let snap = registry.snapshot(Some("example"));
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ingress_bytes, 10);
        assert_eq!(snap[0].egress_bytes, 4);
        assert_eq!(snap[0].connections, 1);
        assert!(snap[0].matches_filter);
    }

    #[test]
    fn rename_merges_into_existing_host() {
        let registry = Registry::new();
        let ip = registry.endpoint("1.2.3.4");
        ip.add_ingress(100);
        ip.add_connection();
        let named = registry.endpoint("host.example");
        named.add_ingress(1);
        named.add_connection();

        registry.rename("1.2.3.4", "host.example");

        let snap = registry.snapshot(None);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].domain, "host.example");
        assert_eq!(snap[0].ingress_bytes, 101);
        assert_eq!(snap[0].connections, 2);
    }

    #[test]
    fn snapshot_sorts_by_ingress_descending() {
        let registry = Registry::new();
        registry.endpoint("small").add_ingress(1);
        registry.endpoint("big").add_ingress(1_000);
        let snap = registry.snapshot(None);
        assert_eq!(snap[0].domain, "big");
    }
}
