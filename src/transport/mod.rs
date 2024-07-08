//! [STUN]/[TURN] transport definitions.
//!
//! [STUN]: https://en.wikipedia.org/wiki/STUN
//! [TURN]: https://en.wikipedia.org/wiki/TURN

mod tcp;

use std::io;

use std::net::SocketAddr;

use async_trait::async_trait;
use bytecodec::DecodeExt;
use derive_more::{Display, Error as StdError, From};
use stun_codec::{Message, MessageDecoder};
use tokio::net::{self, ToSocketAddrs};

use crate::{
    attr::{Attribute, PROTO_UDP},
    chandata,
    chandata::ChannelData,
    server::INBOUND_MTU,
};

pub use tokio::net::UdpSocket;

pub use self::tcp::Server as TcpServer;

/// Parsed ingress [STUN]/[TURN] message.
///
/// [STUN]: https://en.wikipedia.org/wiki/STUN
/// [TURN]: https://en.wikipedia.org/wiki/TURN
#[derive(Debug)]
pub enum Request {
    /// [STUN Message].
    ///
    /// [STUN Message]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
    Message(Message<Attribute>),

    /// [TURN ChannelData Message][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    ChannelData(ChannelData),
}

/// Abstraction of [STUN]/[TURN] transport implementation.
///
/// [STUN]: https://en.wikipedia.org/wiki/STUN
/// [TURN]: https://en.wikipedia.org/wiki/TURN
#[async_trait]
pub trait Transport {
    /// Receives a [`Request`] datagram message.
    ///
    /// # Errors
    ///
    /// See the [`Error`] for details.
    async fn recv_from(&self) -> Result<(Request, SocketAddr), Error>;

    /// Sends `data` to the provided [`SocketAddr`].
    ///
    /// # Errors
    ///
    /// See the [`Error`] for details.
    async fn send_to(
        &self,
        data: Vec<u8>,
        target: SocketAddr,
    ) -> Result<(), Error>;

    /// Returns the local [`SocketAddr`] of this [`Transport`].
    fn local_addr(&self) -> SocketAddr;

    /// Returns the protocol number of this [`Transport`] according to [IANA].
    ///
    /// [IANA]: https://tinyurl.com/iana-protocol-numbers
    fn proto(&self) -> u8;
}

#[async_trait]
impl Transport for UdpSocket {
    async fn recv_from(&self) -> Result<(Request, SocketAddr), Error> {
        let mut buf = vec![0u8; INBOUND_MTU];
        let (n, addr) = self.recv_from(&mut buf).await?;

        let msg = if ChannelData::is_channel_data(&buf[0..n]) {
            buf.truncate(n);
            let data = ChannelData::decode(buf)?;

            Request::ChannelData(data)
        } else {
            let msg = MessageDecoder::<Attribute>::new()
                .decode_from_bytes(&buf[0..n])
                .map_err(|e| Error::Decode(*e.kind()))?
                .map_err(|e| Error::Decode(*e.error().kind()))?;

            Request::Message(msg)
        };

        Ok((msg, addr))
    }

    async fn send_to(
        &self,
        data: Vec<u8>,
        target: SocketAddr,
    ) -> Result<(), Error> {
        Ok(self.send_to(&data, target).await.map(|_| ())?)
    }

    fn local_addr(&self) -> SocketAddr {
        // PANIC: Unwrapping is OK here, as this function is intended to be
        //        called on the bound `UdpSocket` only.
        #[allow(clippy::unwrap_used)] // intentional
        self.local_addr().unwrap()
    }

    fn proto(&self) -> u8 {
        PROTO_UDP
    }
}

/// Performs a DNS resolution of the provided `host`.
///
/// # Errors
///
/// If the provided `host` cannot be resolved to IP address.
pub(crate) async fn lookup_host(
    use_ipv4: bool,
    host: impl ToSocketAddrs,
) -> Result<SocketAddr, Error> {
    for remote_addr in net::lookup_host(host).await? {
        if (use_ipv4 && remote_addr.is_ipv4())
            || (!use_ipv4 && remote_addr.is_ipv6())
        {
            return Ok(remote_addr);
        }
    }

    Err(io::Error::other(format!(
        "No available {} IP address found!",
        if use_ipv4 { "ipv4" } else { "ipv6" },
    ))
    .into())
}

/// Possible errors of a [`Transport`].
#[derive(Debug, Display, From, Eq, PartialEq, StdError)]
#[allow(variant_size_differences)]
pub enum Error {
    /// Tried to use a dead [`Transport`].
    #[display("Underlying TCP/UDP transport is dead")]
    TransportIsDead,

    /// Failed to decode message.
    #[display("Failed to decode STUN/TURN message: {_0:?}")]
    Decode(#[error(not(source))] bytecodec::ErrorKind),

    /// [TURN ChannelData][1] format error.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    #[from(chandata::FormatError)]
    ChannelData(chandata::FormatError),

    /// I/O error of the [`Transport`].
    #[display("I/O error: {_0}")]
    #[from(io::Error, IoError)]
    Io(IoError),
}

/// [`io::Error`] implementing [`Eq`] and [`PartialEq`] by its [`kind`].
///
/// [`kind`]: io::Error::kind()
#[derive(Debug, Display, From, StdError)]
pub struct IoError(pub io::Error);

impl Eq for IoError {}

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

#[cfg(test)]
mod lookup_host_spec {
    use super::lookup_host;

    #[tokio::test]
    async fn considers_ip_version() {
        let stun_serv_addr = "stun1.l.google.com:19302";

        if let Ok(ipv4_addr) = lookup_host(true, stun_serv_addr).await {
            assert!(
                ipv4_addr.is_ipv4(),
                "expected ipv4 but got ipv6: {ipv4_addr}",
            );
        }

        if let Ok(ipv6_addr) = lookup_host(false, stun_serv_addr).await {
            assert!(
                ipv6_addr.is_ipv6(),
                "expected ipv6 but got ipv4: {ipv6_addr}",
            );
        }
    }

    #[tokio::test]
    async fn resolves_localhost() {
        let udp_addr = lookup_host(true, "localhost:1234").await.unwrap();

        assert_eq!(udp_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(udp_addr.port(), 1234);

        let res = lookup_host(false, "127.0.0.1:1234").await;

        assert!(res.is_err(), "expected error, got: {res:?}");
    }
}
