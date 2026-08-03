//! SOCKS5 ([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)) handshake, no authentication.
//!
//! SOCKS5 is what makes this a general TCP meter rather than an HTTP one: a client pointed at
//! `ALL_PROXY=socks5h://…` tunnels *any* TCP protocol through it — gRPC, Postgres, Redis, plain
//! TLS — and the `socks5h` form sends the hostname rather than a pre-resolved address, so
//! endpoints still get named instead of showing up as bare IPs.
//!
//! Only `CONNECT` is supported. `UDP ASSOCIATE` is refused, which is the honest answer for
//! QUIC and HTTP/3: this tool cannot carry them, and pretending otherwise would silently
//! under-count.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

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

    /// Whether this was a `UDP ASSOCIATE` request, i.e. most likely QUIC or HTTP/3.
    ///
    /// Worth reporting separately: it is the one failure mode that means traffic happened and
    /// went uncounted, rather than a client simply misbehaving.
    pub fn is_udp_associate(&self) -> bool {
        matches!(self, Self::UnsupportedCommand(CMD_UDP_ASSOCIATE))
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
            Self::UnsupportedCommand(CMD_UDP_ASSOCIATE) => write!(
                f,
                "client requested UDP ASSOCIATE (QUIC/HTTP3), which cannot be proxied or counted"
            ),
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

/// Performs the greeting and reads the `CONNECT` request, leaving the reply to the caller.
///
/// The reply is deliberately not sent here: the proxy has to try the upstream connection first
/// so it can report refusal accurately, and a client must not start sending payload until it
/// sees a success reply.
///
/// # Errors
///
/// Returns [`Error`] for malformed, unsupported, or truncated handshakes. Send
/// [`Error::reply_code`] back with [`reply`] before closing the connection.
pub async fn accept<S>(stream: &mut S) -> Result<Request, Error>
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

    if command != CMD_CONNECT {
        return Err(Error::UnsupportedCommand(command));
    }
    Ok(Request {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Sends a SOCKS5 reply with the given code and an all-zero bound address.
///
/// The bound address is informational and ignored by every client this targets, so the
/// unspecified IPv4 address is used rather than exposing the proxy's own port.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Drives a handshake against `accept`, returning its result and the bytes sent to the client.
    async fn handshake(client_bytes: &[u8]) -> (Result<Request, Error>, Vec<u8>) {
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
            Request {
                host: "example.com".to_owned(),
                port: 443
            }
        );
        assert_eq!(sent, vec![0x05, METHOD_NONE], "method selection only");
    }

    #[tokio::test]
    async fn ipv4_and_ipv6_literals_are_accepted() {
        let mut v4 = vec![0x05, 0x01, 0x00, 0x05, CMD_CONNECT, 0x00, ATYP_IPV4];
        v4.extend_from_slice(&[10, 0, 0, 7]);
        v4.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(handshake(&v4).await.0.unwrap().host, "10.0.0.7");

        let mut v6 = vec![0x05, 0x01, 0x00, 0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(handshake(&v6).await.0.unwrap().host, "::1");
    }

    #[tokio::test]
    async fn udp_associate_is_refused_and_flagged() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4];
        bytes.extend_from_slice(&[127, 0, 0, 1]);
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let err = handshake(&bytes).await.0.unwrap_err();
        assert!(err.is_udp_associate(), "got {err}");
        assert_eq!(err.reply_code(), REP_COMMAND_NOT_SUPPORTED);
        assert!(err.to_string().contains("QUIC"));
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
}
