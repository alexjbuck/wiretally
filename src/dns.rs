//! Reverse DNS for endpoints that were only ever seen as bare IP addresses.
//!
//! Most endpoints need no lookup at all: the `CONNECT` target or request URI already carries
//! the hostname the child asked for, which is more informative than a PTR record (PTR for an
//! S3 address is something like `s3-1-w.amazonaws.com`, not the bucket's regional endpoint).
//! Lookups therefore only happen for endpoints whose key parses as an IP address, and results
//! are cached so repeated addresses cost nothing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{Name, RData};

/// Cached reverse resolver.
///
/// Construction never fails hard: if the system resolver configuration cannot be read, the
/// resolver is simply disabled and every lookup returns `None`, leaving IP-keyed endpoints in
/// the report as addresses.
#[derive(Debug)]
pub struct ReverseResolver {
    resolver: Option<TokioResolver>,
    cache: Mutex<HashMap<IpAddr, Option<String>>>,
}

impl ReverseResolver {
    /// Builds a resolver from the system configuration, falling back to a disabled resolver.
    pub fn from_system() -> Self {
        let resolver = TokioResolver::builder_tokio()
            .and_then(|builder| builder.build())
            .ok();
        Self {
            resolver,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a resolver that performs no lookups.
    pub fn disabled() -> Self {
        Self {
            resolver: None,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the PTR hostname for `ip`, or `None` if there is none (or lookups are disabled).
    ///
    /// The trailing dot of the PTR record is stripped so results compare equal to hostnames
    /// taken from request targets.
    pub async fn hostname(&self, ip: IpAddr) -> Option<String> {
        if let Some(hit) = self
            .cache
            .lock()
            .expect("dns cache mutex poisoned")
            .get(&ip)
            .cloned()
        {
            return hit;
        }
        let resolved = match &self.resolver {
            Some(resolver) => resolver
                .reverse_lookup(Name::from(ip))
                .await
                .ok()
                .and_then(|lookup| {
                    lookup
                        .answers()
                        .iter()
                        .find_map(|record| match &record.data {
                            RData::PTR(ptr) => {
                                Some(ptr.0.to_string().trim_end_matches('.').to_ascii_lowercase())
                            }
                            _ => None,
                        })
                })
                .filter(|name| !name.is_empty()),
            None => None,
        };
        self.cache
            .lock()
            .expect("dns cache mutex poisoned")
            .insert(ip, resolved.clone());
        resolved
    }
}

impl Default for ReverseResolver {
    fn default() -> Self {
        Self::from_system()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_resolver_returns_none() {
        let resolver = ReverseResolver::disabled();
        assert_eq!(resolver.hostname("127.0.0.1".parse().unwrap()).await, None);
    }
}
