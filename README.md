# wiretally

Run any command behind an ephemeral counting proxy and get a per-domain byte report when it
exits.

```bash
wiretally --domain-prefix amazonaws.com -- mcap info s3://my-bucket/dataset.mcap
```

```text
================================================================================
                          NET-COUNTER TRAFFIC SUMMARY
================================================================================
Command:          curl -s -o /dev/null https://example.com/
Target Filter:    *.example.com (Prefix Match)
Execution Time:   0.09s
Exit Code:        0

DOMAIN / ENDPOINT SUMMARY:
--------------------------------------------------------------------------------
ENDPOINT / DOMAIN                   INGRESS (Rx)      EGRESS (Tx)   CONNS
--------------------------------------------------------------------------------
example.com                              4.71 KB            585 B       1
--------------------------------------------------------------------------------
TOTAL (Matching Filter):                 4.71 KB            585 B       1
TOTAL (All Destinations):                4.71 KB            585 B       1
================================================================================
```

## Usage

```text
wiretally [OPTIONS] -- <COMMAND> [ARGS...]

  -d, --domain-prefix <STRING>  Domain suffix filter, e.g. "amazonaws.com"
  -v, --verbose                 Per-connection wire log on stderr
  -j, --json                    Emit the summary as JSON instead of a table
```

The child's stdout and stderr are inherited directly, and `wiretally` exits with the child's
exit code (`128 + signal` if it was killed), so it drops into pipelines and CI without changing
behaviour. With `--json`, the report is a single JSON document on stdout:

```bash
wiretally -j -d amazonaws.com -- mcap info s3://bucket/file.mcap \
  | jq '.endpoints[] | select(.matches_filter) | {domain, ingress_bytes}'
```

## How it works

1. A proxy binds an OS-assigned port on `127.0.0.1` and speaks three protocols on it, chosen by
   the first byte of each connection: SOCKS5 (`0x05`), HTTP `CONNECT`, and plain HTTP.
2. The child's environment — and only the child's — gets `HTTP_PROXY`/`HTTPS_PROXY` (plus
   lowercase) pointing at `http://127.0.0.1:PORT`, and `ALL_PROXY`/`all_proxy` pointing at
   `socks5h://127.0.0.1:PORT`. Nothing global is touched.
3. `CONNECT` and SOCKS5 connections are spliced as raw TCP. TLS is never terminated: no
   certificate to install, no crypto on the data path, and the counters see exactly the
   ciphertext that crossed the wire. Because the splice is protocol-agnostic, anything the
   client tunnels is measured — HTTP/2, gRPC, WebSockets, Postgres, plain TLS. Plain HTTP is
   forwarded by hyper, with the counters on the *upstream* socket so the numbers reflect what
   left the machine rather than what the child handed to the proxy.
4. Counting is one relaxed `fetch_add` per read or write on an otherwise untouched buffer, so
   the per-chunk overhead is a few nanoseconds and nothing is buffered in memory.
5. After the child exits, in-flight connections are given up to two seconds to drain, endpoints
   that were only ever seen as bare IPs get a reverse-DNS name, and the report is printed.

`socks5h` rather than `socks5` matters: it makes the client send hostnames to the proxy instead
of resolving them first, so endpoints stay named in the report instead of collapsing to IPs.

### What gets counted

| Traffic | Counted | Via |
|---|---|---|
| HTTPS, HTTP/2 over TLS | yes | `CONNECT` tunnel |
| Plain HTTP | yes | forwarded by hyper |
| gRPC, Postgres, Redis, arbitrary TCP | yes, if the client honours `ALL_PROXY` | SOCKS5 |
| QUIC, HTTP/3, DNS, any UDP | **no** | impossible via a proxy — see below |
| Anything from a client that ignores proxy env vars | **no** | — |

Endpoint names come from the `CONNECT` target or request URI when available, because that is
what the child asked for; a PTR record for an S3 address (`s3-1-w.amazonaws.com`) says much less
than the regional endpoint the SDK used. Reverse DNS is therefore a fallback, not the default.

`--domain-prefix` matches on label boundaries: `amazonaws.com` covers `amazonaws.com` and
`s3.us-east-1.amazonaws.com`, but not `notamazonaws.com`. Non-matching endpoints are dropped
from the table but still counted in the `TOTAL (All Destinations)` row, so a filter can never
hide traffic completely.

## Limitations

Everything here follows from being a proxy rather than a packet capture:

- **UDP is invisible, in both directions.** A proxy only sees bytes a client deliberately hands
  it over a TCP connection, so QUIC, HTTP/3, DNS, and QUIC-based gRPC transports are not counted
  — not under-counted, not counted at all. When a client asks for SOCKS5 `UDP ASSOCIATE`,
  wiretally refuses with `command not supported` and prints a warning, which both makes the gap
  visible and pushes most clients to fall back to TCP where they *can* be measured. Counting UDP
  would require OS-level capture (a TUN device, eBPF, or pcap) rather than a proxy.
- Clients that ignore the proxy environment variables are not measured: raw sockets, anything
  with `NO_PROXY` set for the host, and SDKs that only honour their own config keys.
- The `CONNECT`/SOCKS handshake between child and proxy is excluded from the totals — it is
  local overhead that never reaches the remote host.
- Per-endpoint totals aggregate by hostname, so two hostnames on the same IP stay separate rows
  (which is usually what you want) and one hostname across many IPs collapses into one row.

## Development

```bash
cargo test          # unit, doc, and integration tests
cargo clippy --all-targets
```

The integration tests put a raw TCP origin server behind the proxy and make that server count
what crossed its own socket; the proxy's counters must match those numbers exactly. No network
access is required for them.
