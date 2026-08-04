//! SOCKS5 ([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)) handshake, no authentication.
//!
//! SOCKS5 is what makes this a general TCP meter rather than an HTTP one: a client pointed at
//! `ALL_PROXY=socks5h://…` tunnels *any* TCP protocol through it — gRPC, Postgres, Redis, plain
//! TLS — and the `socks5h` form sends the hostname rather than a pre-resolved address, so
//! endpoints still get named instead of showing up as bare IPs.
//!
//! `CONNECT` and `UDP ASSOCIATE` are both supported, so a client that asks for UDP relay gets
//! working UDP *and* has it counted. Note this covers only clients that ask: QUIC or HTTP/3
//! sent straight to a destination never touches the proxy and cannot be seen at all.
//!
//! There is deliberately no third option. Refusing `UDP ASSOCIATE` can break a client that
//! would otherwise have gone direct, and accepting it without relaying is worse — the client
//! stops sending to the destination and its datagrams disappear into the proxy with no error.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS protocol version this module speaks.
pub const VERSION: u8 = 0x05;

/// First byte of a SOCKS5 greeting, used to tell SOCKS clients from HTTP ones.
pub const GREETING_BYTE: u8 = VERSION;

const METHOD_NONE: u8 = 0x00;
const METHOD_UNACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Size of the fixed part of a UDP request header: `RSV(2) FRAG(1) ATYP(1)`.
const UDP_HEADER_PREFIX: usize = 4;

/// Reply code for a successful `CONNECT`.
pub const REP_SUCCESS: u8 = 0x00;
/// Reply code for an unspecified failure.
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// Reply code for a refused upstream connection.
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
/// Reply code for an unsupported command, e.g. `UDP ASSOCIATE`.
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
/// Reply code for an unsupported address type.
pub const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

/// A destination requested by a SOCKS5 client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Destination host: a domain name (with `socks5h`) or an address literal.
    pub host: String,
    /// Destination port.
    pub port: u16,
}

/// What a client asked the proxy to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Tunnel a TCP connection to the given destination.
    Connect(Request),
    /// Relay UDP datagrams. The address is what the client said it will send from, which is
    /// commonly `0.0.0.0:0` ("I don't know yet") and so cannot be relied on.
    UdpAssociate(Request),
}

/// Why a SOCKS5 handshake could not be completed.
#[derive(Debug)]
pub enum Error {
    /// The connection failed while reading or writing the handshake.
    Io(std::io::Error),
    /// The client asked for a SOCKS version this module does not speak.
    UnsupportedVersion(u8),
    /// The client offered no authentication method the proxy accepts.
    NoAcceptableMethod,
    /// The client asked for a command other than `CONNECT`.
    UnsupportedCommand(u8),
    /// The client used an address type other than IPv4, IPv6, or domain name.
    UnsupportedAddressType(u8),
}

impl Error {
    /// SOCKS5 reply code to send back for this error.
    pub fn reply_code(&self) -> u8 {
        match self {
            Self::UnsupportedCommand(_) => REP_COMMAND_NOT_SUPPORTED,
            Self::UnsupportedAddressType(_) => REP_ADDRESS_NOT_SUPPORTED,
            _ => REP_GENERAL_FAILURE,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "socks5 handshake io error: {err}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported socks version {v:#04x}"),
            Self::NoAcceptableMethod => {
                write!(f, "client offered no acceptable authentication method")
            }
            Self::UnsupportedCommand(c) => write!(f, "unsupported socks command {c:#04x}"),
            Self::UnsupportedAddressType(a) => write!(f, "unsupported address type {a:#04x}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Performs the greeting and reads the client's request, leaving the reply to the caller.
///
/// The reply is deliberately not sent here: the proxy has to try the upstream connection (or
/// bind the relay socket) first so it can report failure accurately, and a client must not
/// start sending payload until it sees a success reply.
///
/// # Errors
///
/// Returns [`Error`] for malformed, unsupported, or truncated handshakes. Send
/// [`Error::reply_code`] back with [`reply`] before closing the connection.
pub async fn accept<S>(stream: &mut S) -> Result<Command, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION {
        return Err(Error::UnsupportedVersion(greeting[0]));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NONE) {
        stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await?;
        return Err(Error::NoAcceptableMethod);
    }
    stream.write_all(&[VERSION, METHOD_NONE]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Err(Error::UnsupportedVersion(header[0]));
    }
    let (command, address_type) = (header[1], header[3]);

    // Drain the whole request before rejecting anything, so the reply lands on a clean stream.
    let host = match address_type {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain)
                .trim_end_matches('.')
                .to_ascii_lowercase()
        }
        other => return Err(Error::UnsupportedAddressType(other)),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let request = Request {
        host,
        port: u16::from_be_bytes(port),
    };

    match command {
        CMD_CONNECT => Ok(Command::Connect(request)),
        CMD_UDP_ASSOCIATE => Ok(Command::UdpAssociate(request)),
        other => Err(Error::UnsupportedCommand(other)),
    }
}

/// A datagram received from a SOCKS5 client, with its relay header stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// Destination host the client wants this payload delivered to.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// The payload to relay, excluding the SOCKS header.
    pub payload: &'a [u8],
}

/// Why a relayed datagram could not be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramError {
    /// The datagram was shorter than its own header claims.
    Truncated,
    /// The client used an address type other than IPv4, IPv6, or domain name.
    UnsupportedAddressType(u8),
    /// The datagram is part of a fragmented message, which this relay does not reassemble.
    Fragmented(u8),
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated udp relay header"),
            Self::UnsupportedAddressType(a) => write!(f, "unsupported address type {a:#04x}"),
            Self::Fragmented(frag) => {
                write!(f, "fragmented datagram (FRAG {frag:#04x}) is not supported")
            }
        }
    }
}

impl std::error::Error for DatagramError {}

/// Parses a client datagram: `RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA`.
///
/// # Errors
///
/// Returns [`DatagramError`] if the header is truncated, fragmented, or uses an address type
/// this relay cannot forward. Callers should drop such datagrams, as UDP has no way to report
/// the failure back.
///
/// ```
/// use wiretally::socks::parse_datagram;
///
/// let mut buf = vec![0, 0, 0, 0x01, 10, 0, 0, 7];
/// buf.extend_from_slice(&53u16.to_be_bytes());
/// buf.extend_from_slice(b"payload");
/// let datagram = parse_datagram(&buf)?;
/// assert_eq!((datagram.host.as_str(), datagram.port), ("10.0.0.7", 53));
/// assert_eq!(datagram.payload, b"payload");
/// # Ok::<(), wiretally::socks::DatagramError>(())
/// ```
pub fn parse_datagram(buf: &[u8]) -> Result<Datagram<'_>, DatagramError> {
    if buf.len() < UDP_HEADER_PREFIX {
        return Err(DatagramError::Truncated);
    }
    if buf[2] != 0 {
        return Err(DatagramError::Fragmented(buf[2]));
    }
    let mut cursor = UDP_HEADER_PREFIX;
    let host = match buf[3] {
        ATYP_IPV4 => {
            let octets: [u8; 4] = read_slice(buf, &mut cursor)?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = read_slice(buf, &mut cursor)?;
            Ipv6Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let [len]: [u8; 1] = read_slice(buf, &mut cursor)?;
            let end = cursor + len as usize;
            let domain = buf.get(cursor..end).ok_or(DatagramError::Truncated)?;
            cursor = end;
            String::from_utf8_lossy(domain)
                .trim_end_matches('.')
                .to_ascii_lowercase()
        }
        other => return Err(DatagramError::UnsupportedAddressType(other)),
    };
    let port: [u8; 2] = read_slice(buf, &mut cursor)?;
    Ok(Datagram {
        host,
        port: u16::from_be_bytes(port),
        payload: &buf[cursor..],
    })
}

/// Reads a fixed-size field, advancing `cursor`.
fn read_slice<const N: usize>(buf: &[u8], cursor: &mut usize) -> Result<[u8; N], DatagramError> {
    let end = *cursor + N;
    let bytes: [u8; N] = buf
        .get(*cursor..end)
        .ok_or(DatagramError::Truncated)?
        .try_into()
        .map_err(|_| DatagramError::Truncated)?;
    *cursor = end;
    Ok(bytes)
}

/// Wraps `payload` in a relay header naming `from` as its source, ready to send to the client.
///
/// The buffer is cleared and reused rather than allocated per datagram, which keeps the relay
/// allocation-free once it is warm.
pub fn encode_datagram(from: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    match from.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&from.port().to_be_bytes());
    out.extend_from_slice(payload);
}

/// Sends a SOCKS5 reply with the given code and an all-zero bound address.
///
/// Fine for `CONNECT`, where the bound address is informational and ignored by every client
/// this targets. `UDP ASSOCIATE` must use [`reply_bound`] instead, because there the address is
/// where the client is expected to send its datagrams.
///
/// # Errors
///
/// Returns an error if the reply cannot be written.
pub async fn reply<S>(stream: &mut S, code: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

/// Sends a SOCKS5 reply advertising `bound` as the address the client should talk to.
///
/// # Errors
///
/// Returns an error if the reply cannot be written.
pub async fn reply_bound<S>(stream: &mut S, code: u8, bound: SocketAddr) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(22);
    out.extend_from_slice(&[VERSION, code, 0x00]);
    match bound.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&out).await
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use tokio::io::duplex;

    /// Drives a handshake against `accept`, returning its result and the bytes sent to the client.
    async fn handshake(client_bytes: &[u8]) -> (Result<Command, Error>, Vec<u8>) {
        let (mut client, mut server) = duplex(1024);
        client.write_all(client_bytes).await.unwrap();
        let result = accept(&mut server).await;
        drop(server);
        let mut sent = Vec::new();
        client.read_to_end(&mut sent).await.unwrap();
        (result, sent)
    }

    #[tokio::test]
    async fn domain_request_preserves_the_hostname() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, 11];
        bytes.extend_from_slice(b"Example.COM");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let (result, sent) = handshake(&bytes).await;
        assert_eq!(
            result.unwrap(),
            Command::Connect(Request {
                host: "example.com".to_owned(),
                port: 443
            })
        );
        assert_eq!(sent, vec![0x05, METHOD_NONE], "method selection only");
    }

    /// Destination of a `CONNECT`, for tests that only care about the address parsing.
    fn connect_target(command: Command) -> Request {
        match command {
            Command::Connect(request) => request,
            other => panic!("expected CONNECT, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ipv4_and_ipv6_literals_are_accepted() {
        let mut v4 = vec![0x05, 0x01, 0x00, 0x05, CMD_CONNECT, 0x00, ATYP_IPV4];
        v4.extend_from_slice(&[10, 0, 0, 7]);
        v4.extend_from_slice(&80u16.to_be_bytes());
        let target = connect_target(handshake(&v4).await.0.unwrap());
        assert_eq!(target.host, "10.0.0.7");

        let mut v6 = vec![0x05, 0x01, 0x00, 0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        let target = connect_target(handshake(&v6).await.0.unwrap());
        assert_eq!(target.host, "::1");
    }

    #[tokio::test]
    async fn udp_associate_is_accepted_as_its_own_command() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4];
        bytes.extend_from_slice(&[127, 0, 0, 1]);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            handshake(&bytes).await.0.unwrap(),
            Command::UdpAssociate(_)
        ));
    }

    #[tokio::test]
    async fn bind_is_still_unsupported() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x02, 0x00, ATYP_IPV4];
        bytes.extend_from_slice(&[127, 0, 0, 1]);
        bytes.extend_from_slice(&80u16.to_be_bytes());
        let err = handshake(&bytes).await.0.unwrap_err();
        assert_eq!(err.reply_code(), REP_COMMAND_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn datagram_round_trip_preserves_payload_and_source() {
        let mut encoded = Vec::new();
        let from: SocketAddr = "203.0.113.9:53".parse().unwrap();
        encode_datagram(from, b"answer", &mut encoded);
        let parsed = parse_datagram(&encoded).unwrap();
        assert_eq!(parsed.host, "203.0.113.9");
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload, b"answer");
    }

    #[test]
    fn datagram_parse_rejects_fragments_and_truncation() {
        assert_eq!(
            parse_datagram(&[0x00, 0x00, 0x01, ATYP_IPV4, 1, 2, 3, 4, 0, 53]),
            Err(DatagramError::Fragmented(1))
        );
        assert_eq!(parse_datagram(&[0x00, 0x00]), Err(DatagramError::Truncated));
        assert_eq!(
            parse_datagram(&[0x00, 0x00, 0x00, ATYP_IPV4, 1, 2]),
            Err(DatagramError::Truncated)
        );
        assert_eq!(
            parse_datagram(&[0x00, 0x00, 0x00, 0x09, 1, 2]),
            Err(DatagramError::UnsupportedAddressType(0x09))
        );
    }

    #[test]
    fn datagram_parse_accepts_domain_destinations() {
        let mut buf = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 11];
        buf.extend_from_slice(b"Example.COM");
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(b"body");
        let parsed = parse_datagram(&buf).unwrap();
        assert_eq!(parsed.host, "example.com", "names are normalised");
        assert_eq!(parsed.payload, b"body");
    }

    #[tokio::test]
    async fn udp_reply_advertises_the_relay_address() {
        let (mut client, mut server) = duplex(64);
        let bound: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        reply_bound(&mut server, REP_SUCCESS, bound).await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[3], ATYP_IPV4);
        assert_eq!(&buf[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([buf[8], buf[9]]), 40_000);
    }

    #[tokio::test]
    async fn authentication_requirement_is_rejected() {
        let (result, sent) = handshake(&[0x05, 0x01, 0x02]).await;
        assert!(matches!(result, Err(Error::NoAcceptableMethod)));
        assert_eq!(sent, vec![0x05, METHOD_UNACCEPTABLE]);
    }

    #[tokio::test]
    async fn wrong_version_is_rejected() {
        let (result, _) = handshake(&[0x04, 0x01, 0x00]).await;
        assert!(matches!(result, Err(Error::UnsupportedVersion(0x04))));
    }

    #[tokio::test]
    async fn success_reply_is_ten_bytes() {
        let (mut client, mut server) = duplex(64);
        reply(&mut server, REP_SUCCESS).await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn unsupported_address_type_is_rejected_with_its_own_code() {
        // Greeting is fine; the request then names an address family this proxy cannot forward.
        let bytes = vec![0x05, 0x01, 0x00, 0x05, CMD_CONNECT, 0x00, 0x09];
        let (result, sent) = handshake(&bytes).await;
        let err = result.unwrap_err();
        assert!(matches!(err, Error::UnsupportedAddressType(0x09)));
        assert_eq!(err.reply_code(), REP_ADDRESS_NOT_SUPPORTED);
        assert_eq!(
            sent,
            vec![0x05, METHOD_NONE],
            "the greeting is answered before the request is rejected"
        );
    }

    #[tokio::test]
    async fn version_is_rechecked_on_the_request_after_the_greeting() {
        // A client can speak 0x05 in its greeting and then send a mismatched request header;
        // accepting that would mean parsing the rest of the record under the wrong layout.
        let bytes = vec![0x05, 0x01, 0x00, 0x04, CMD_CONNECT, 0x00, ATYP_IPV4];
        let (result, _) = handshake(&bytes).await;
        assert!(matches!(result, Err(Error::UnsupportedVersion(0x04))));
    }

    #[tokio::test]
    async fn a_truncated_handshake_surfaces_as_an_io_error() {
        // Half a greeting, then EOF: `read_exact` fails and the error must carry its source
        // through, since that is what the caller logs. The client half has to be dropped for the
        // read to see EOF rather than block waiting for the second byte, so this cannot use the
        // shared `handshake` helper.
        let (mut client, mut server) = duplex(1024);
        client.write_all(&[0x05]).await.unwrap();
        drop(client);

        let err = accept(&mut server).await.unwrap_err();
        assert!(matches!(err, Error::Io(_)));
        assert!(std::error::Error::source(&err).is_some());
        assert_eq!(
            err.reply_code(),
            REP_GENERAL_FAILURE,
            "errors with no specific code fall back to a general failure"
        );
    }

    #[test]
    fn every_error_describes_itself() {
        // The proxy only ever shows these to a human in verbose mode, so the requirement is that
        // each variant says something distinct rather than any exact wording.
        let errors = [
            Error::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Error::UnsupportedVersion(0x04),
            Error::NoAcceptableMethod,
            Error::UnsupportedCommand(0x02),
            Error::UnsupportedAddressType(0x09),
        ];
        let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        assert_eq!(
            rendered
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            rendered.len(),
            "variants must not render identically: {rendered:?}"
        );
        assert_eq!(
            Error::NoAcceptableMethod.reply_code(),
            REP_GENERAL_FAILURE,
            "no code of its own"
        );
        assert!(
            std::error::Error::source(&Error::NoAcceptableMethod).is_none(),
            "only the io variant wraps another error"
        );

        let datagram_errors = [
            DatagramError::Truncated,
            DatagramError::UnsupportedAddressType(0x09),
            DatagramError::Fragmented(0x01),
        ];
        let rendered: Vec<String> = datagram_errors.iter().map(ToString::to_string).collect();
        assert_eq!(
            rendered
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            rendered.len(),
            "variants must not render identically: {rendered:?}"
        );
    }

    #[test]
    fn io_errors_convert_into_handshake_errors() {
        let err: Error = std::io::Error::from(std::io::ErrorKind::ConnectionReset).into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn ipv6_datagrams_round_trip() {
        // The v6 arms of both the encoder and the parser are otherwise only reachable on a v6
        // host, which is exactly the configuration least likely to be tested by hand.
        let from: SocketAddr = "[2001:db8::1]:9000".parse().unwrap();
        let mut encoded = Vec::new();
        encode_datagram(from, b"v6 payload", &mut encoded);
        assert_eq!(encoded[3], ATYP_IPV6);

        let parsed = parse_datagram(&encoded).unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 9000);
        assert_eq!(parsed.payload, b"v6 payload");
    }

    #[tokio::test]
    async fn udp_reply_can_advertise_an_ipv6_relay() {
        let (mut client, mut server) = duplex(64);
        let bound: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        reply_bound(&mut server, REP_SUCCESS, bound).await.unwrap();
        let mut buf = [0u8; 22];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[3], ATYP_IPV6);
        assert_eq!(
            &buf[4..20],
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()
        );
        assert_eq!(u16::from_be_bytes([buf[20], buf[21]]), 40_000);
    }

    proptest::proptest! {
        /// Anything the encoder produces must be readable by the parser, unchanged.
        ///
        /// These two sit on opposite ends of the relay — the encoder writes replies to the
        /// client, the parser reads what the client sends — so a disagreement between them
        /// would show up as silently misrouted datagrams rather than an error.
        #[test]
        fn encoded_datagrams_parse_back_identically(
            octets in proptest::array::uniform16(proptest::num::u8::ANY),
            v4 in proptest::bool::ANY,
            port in proptest::num::u16::ANY,
            payload in proptest::collection::vec(proptest::num::u8::ANY, 0..512),
        ) {
            let ip = if v4 {
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
            } else {
                IpAddr::V6(Ipv6Addr::from(octets))
            };
            let from = SocketAddr::new(ip, port);

            let mut encoded = Vec::new();
            encode_datagram(from, &payload, &mut encoded);
            let parsed = parse_datagram(&encoded).unwrap();

            proptest::prop_assert_eq!(parsed.host, ip.to_string());
            proptest::prop_assert_eq!(parsed.port, port);
            proptest::prop_assert_eq!(parsed.payload, payload.as_slice());
        }

        /// The parser reads attacker-shaped input off the wire, so it must never panic.
        ///
        /// Every length in the header comes from the datagram itself; the property that matters
        /// is that no combination of them indexes out of bounds or overflows.
        #[test]
        fn parsing_arbitrary_bytes_never_panics(
            raw in proptest::collection::vec(proptest::num::u8::ANY, 0..600),
        ) {
            if let Ok(datagram) = parse_datagram(&raw) {
                proptest::prop_assert!(
                    datagram.payload.len() <= raw.len(),
                    "the payload is a slice of the input, so it cannot grow"
                );
            }
        }

        /// A datagram cut short at any point is rejected, never parsed as something smaller.
        #[test]
        fn truncating_a_valid_datagram_is_always_an_error(
            cut in 0usize..13,
        ) {
            let from: SocketAddr = "198.51.100.4:53".parse().unwrap();
            let mut encoded = Vec::new();
            encode_datagram(from, b"", &mut encoded);
            // A v4 datagram with an empty payload is exactly 10 bytes, so every prefix shorter
            // than that is truncated; longer cuts leave it intact.
            let prefix = &encoded[..cut.min(encoded.len())];
            proptest::prop_assert_eq!(parse_datagram(prefix).is_err(), cut < encoded.len());
        }
    }
}
