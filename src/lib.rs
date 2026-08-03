//! Byte-accurate network accounting for an arbitrary child process.
//!
//! [`proxy::Proxy`] runs an ephemeral proxy on loopback that speaks three protocols on one
//! port — HTTP, HTTP `CONNECT`, and SOCKS5 — so a child process configured through the
//! standard `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` variables has every byte it sends and
//! receives counted per remote endpoint.
//!
//! Tunnelled traffic is never decrypted or even parsed: `CONNECT` and SOCKS5 both become raw
//! TCP splices, so the totals are exact wire counts for any TCP protocol the client chooses to
//! tunnel, and there is no certificate to install. A client that asks for SOCKS5 UDP relay gets
//! one, counted the same way ([`udp::Relay`]) — but UDP sent straight to a destination, which is
//! what QUIC and HTTP/3 normally do, never reaches the proxy and cannot be seen at all.
//!
//! ```no_run
//! use wiretally::{proxy::Proxy, stats::Registry};
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
pub mod socks;
pub mod stats;
pub mod udp;
