//! Stream adapters used on the data path.
//!
//! [`Counting`] is the only thing standing between the two sockets of a tunnel, so it does the
//! minimum possible work: one atomic add per successful read or write, plus an optional
//! branch for verbose logging. No buffering, no copying — the caller's buffer is passed
//! straight through to the inner stream.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::stats::EndpointStats;

/// Which end of the proxy a [`Counting`] stream is attached to.
///
/// The direction labels are always relative to the *child process*: egress is what the child
/// sends, ingress is what it receives. Reading from the client socket is therefore egress,
/// while reading from the upstream socket is ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Socket facing the child process.
    Client,
    /// Socket facing the remote host.
    Upstream,
}

/// Verbose per-connection wire logger, writing to stderr.
#[derive(Debug)]
pub struct ConnLog {
    id: u64,
    target: String,
}

impl ConnLog {
    /// Creates a logger for connection `id` to `target` (`host:port`).
    pub fn new(id: u64, target: impl Into<String>) -> Self {
        Self {
            id,
            target: target.into(),
        }
    }

    /// Logs an arbitrary event line, e.g. `OPEN  -> host:443 (1.2.3.4)`.
    pub fn event(&self, body: impl AsRef<str>) {
        eprintln!(
            "[{}] [CONN #{}] {}",
            chrono::Local::now().format("%H:%M:%S%.3f"),
            self.id,
            body.as_ref()
        );
    }

    /// Logs bytes sent by the child process.
    pub fn tx(&self, n: usize) {
        self.event(format!("TX    -> {} bytes {}", n, self.target));
    }

    /// Logs bytes received by the child process.
    pub fn rx(&self, n: usize) {
        self.event(format!("RX    <- {} bytes {}", n, self.target));
    }
}

/// Wraps a stream and attributes every byte crossing it to an [`EndpointStats`].
#[derive(Debug)]
pub struct Counting<S> {
    inner: S,
    stats: Arc<EndpointStats>,
    side: Side,
    log: Option<Arc<ConnLog>>,
}

impl<S> Counting<S> {
    /// Wraps `inner`, attributing traffic to `stats` from the perspective of `side`.
    pub fn new(inner: S, stats: Arc<EndpointStats>, side: Side, log: Option<Arc<ConnLog>>) -> Self {
        Self {
            inner,
            stats,
            side,
            log,
        }
    }

    /// Borrows the wrapped stream.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Unwraps back to the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }

    #[inline]
    fn on_read(&self, n: usize) {
        if n == 0 {
            return;
        }
        match self.side {
            Side::Client => {
                self.stats.add_egress(n as u64);
                if let Some(log) = &self.log {
                    log.tx(n);
                }
            }
            Side::Upstream => {
                self.stats.add_ingress(n as u64);
                if let Some(log) = &self.log {
                    log.rx(n);
                }
            }
        }
    }

    #[inline]
    fn on_write(&self, n: usize) {
        if n == 0 {
            return;
        }
        match self.side {
            Side::Client => {
                self.stats.add_ingress(n as u64);
                if let Some(log) = &self.log {
                    log.rx(n);
                }
            }
            Side::Upstream => {
                self.stats.add_egress(n as u64);
                if let Some(log) = &self.log {
                    log.tx(n);
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let read = buf.filled().len() - before;
            self.on_read(read);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.on_write(*n);
        }
        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &poll {
            self.on_write(*n);
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A stream that replays a prefix of already-read bytes before continuing with the real stream.
///
/// The proxy has to sniff the first request line to decide between `CONNECT` tunnelling and
/// plain-HTTP forwarding. Those bytes are already consumed by then, so the HTTP path needs
/// them handed back before hyper takes over the connection.
#[derive(Debug)]
pub struct Rewind<S> {
    prefix: Option<Vec<u8>>,
    offset: usize,
    inner: S,
}

impl<S> Rewind<S> {
    /// Creates a stream that yields `prefix` first, then whatever `inner` produces.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: (!prefix.is_empty()).then_some(prefix),
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Self {
            prefix,
            offset,
            inner,
        } = &mut *self;
        if let Some(bytes) = prefix {
            let remaining = &bytes[*offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            *offset += n;
            if *offset == bytes.len() {
                *prefix = None;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counting_client_side_maps_read_to_egress() {
        let stats = Arc::new(EndpointStats::default());
        let mut stream = Counting::new(
            std::io::Cursor::new(b"hello".to_vec()),
            Arc::clone(&stats),
            Side::Client,
            None,
        );
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(stats.egress(), 5);
        assert_eq!(stats.ingress(), 0);
    }

    #[tokio::test]
    async fn counting_upstream_side_maps_write_to_egress() {
        let stats = Arc::new(EndpointStats::default());
        let mut stream = Counting::new(Vec::new(), Arc::clone(&stats), Side::Upstream, None);
        stream.write_all(b"abcd").await.unwrap();
        assert_eq!(stats.egress(), 4);
        assert_eq!(stats.ingress(), 0);
    }

    #[tokio::test]
    async fn rewind_replays_prefix_then_stream() {
        let mut stream = Rewind::new(b"head".to_vec(), std::io::Cursor::new(b"tail".to_vec()));
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"headtail");
    }
}
