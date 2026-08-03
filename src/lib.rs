//! Byte-accurate network accounting for an arbitrary child process.
//!
//! [`proxy::Proxy`] runs an ephemeral HTTP/HTTPS-`CONNECT` proxy on loopback. Any process
//! configured to use it (via the standard `HTTP_PROXY`/`HTTPS_PROXY` environment variables)
//! has every byte it sends and receives counted per remote endpoint, without TLS
//! interception: `CONNECT` requests become raw TCP tunnels, so the byte totals are exact
//! wire counts rather than decoded payload sizes.
//!
//! ```no_run
//! use net_counter::{proxy::Proxy, stats::Registry};
//! use std::sync::Arc;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let registry = Arc::new(Registry::new());
//! let proxy = Proxy::bind(Arc::clone(&registry), false).await?;
//! // Point a child process at `proxy.local_addr()`, then read `registry.snapshot()`.
//! # Ok(())
//! # }
//! ```

pub mod dns;
pub mod io;
pub mod proxy;
pub mod report;
pub mod stats;
