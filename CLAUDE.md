# wiretally

Counts a child process's network bytes per domain via an ephemeral loopback proxy
(HTTP, HTTP CONNECT, SOCKS5 CONNECT + UDP ASSOCIATE, all on one port, dispatched by first byte).

## Gotchas

- hickory-resolver 0.26: `TokioResolver::builder_tokio()` **and** `.build()` both return `Result`;
  `Record.data` is a field, not a method; read PTR via `RData::PTR(ptr) => ptr.0`;
  `Name::from(ip)` builds the `in-addr.arpa` name for `reverse_lookup`.
- Reverse DNS of `127.0.0.1` is machine-specific (a local `/etc/hosts` name). Tests must assert on
  `ip_address`, never on `domain`, for loopback endpoints.
- A test that writes >64 KB through a tunnel must read concurrently (`tokio::io::split` + spawn),
  or it deadlocks on socket buffers — looks like a hang, not a failure.
- In `tokio::select!`, resolve branches into an event enum and handle it *after* the macro; branch
  bodies can't take `&mut self` while another branch holds an immutable borrow.

## Invariants (breaking these silently corrupts the numbers)

- Proxy handshake bytes (CONNECT, SOCKS, UDP relay headers) are **excluded** from totals — local
  overhead that never reaches the remote host.
- Count on the *upstream* socket for forwarded HTTP; on the *client* socket for tunnels.
- Scope is cooperative clients only (they must honour the proxy env vars). Never claim coverage of
  traffic that bypasses the proxy.

## Testing

- Byte accuracy is proven by making the origin server count its own socket, then asserting the
  proxy's counters match **exactly**. No network access in tests.
- Live smoke checks: `cargo run -q -- -v -- curl -s -o /dev/null https://example.com/`, and force
  the SOCKS path with `-- sh -c 'curl -s --proxy "$ALL_PROXY" https://example.com/'`.
