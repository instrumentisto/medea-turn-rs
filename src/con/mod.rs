//! Main STUN/TURN transport implementation.

mod tcp;

use std::io;

use std::net::SocketAddr;

use async_trait::async_trait;
use bytecodec::DecodeExt;
use stun_codec::{Message, MessageDecoder};
use thiserror::Error;
use tokio::net::{self, ToSocketAddrs, UdpSocket};

use crate::{
    attr::{Attribute, PROTO_UDP},
    chandata,
    chandata::ChannelData,
    server::INBOUND_MTU,
};

pub use tcp::TcpServer;

/// Transport-related error.
#[derive(Debug, Error, PartialEq)]
#[allow(variant_size_differences)]
pub enum Error {
    /// Tried to use dead transport.
    #[error("Underlying TCP/UDP transport is dead")]
    TransportIsDead,

    /// Failed to decode message.
    #[error("Failed to decode STUN/TURN message: {0:?}")]
    Decode(bytecodec::ErrorKind),

    /// TURN [ChannelData][1] format error.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    #[error("{0}")]
    ChannelData(#[from] chandata::Error),

    /// Error for transport.
    #[error("{0}")]
    Io(#[from] IoError),
}

/// [`io::Error`] wrapper.
#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(IoError(e))
    }
}

/// Parsed ingress STUN or TURN message.
#[derive(Debug)]
pub enum Request {
    /// [STUN Message].
    ///
    /// [STUN Message]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
    Message(Message<Attribute>),

    /// [TURN ChannelData][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    ChannelData(ChannelData),
}

/// Abstracting over transport implementation.
#[async_trait]
pub trait Conn {
    async fn recv_from(&self) -> Result<(Request, SocketAddr), Error>;

    async fn send_to(
        &self,
        buf: Vec<u8>,
        target: SocketAddr,
    ) -> Result<(), Error>;

    /// Returns the local transport address.
    fn local_addr(&self) -> SocketAddr;

    /// Return the transport protocol according to [IANA].
    ///
    /// [IANA]: https://tinyurl.com/iana-protocol-numbers
    fn proto(&self) -> u8;

    /// Closes the underlying transport.
    async fn close(&self);
}

/// Performs a DNS resolution.
pub(crate) async fn lookup_host<T>(
    use_ipv4: bool,
    host: T,
) -> Result<SocketAddr, Error>
where
    T: ToSocketAddrs,
{
    for remote_addr in net::lookup_host(host).await? {
        if (use_ipv4 && remote_addr.is_ipv4())
            || (!use_ipv4 && remote_addr.is_ipv6())
        {
            return Ok(remote_addr);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "No available {} IP address found!",
            if use_ipv4 { "ipv4" } else { "ipv6" },
        ),
    )
    .into())
}

#[async_trait]
impl Conn for UdpSocket {
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
        #[allow(clippy::unwrap_used)]
        self.local_addr().unwrap()
    }

    fn proto(&self) -> u8 {
        PROTO_UDP
    }

    async fn close(&self) {}
}

#[cfg(test)]
mod conn_test {
    use super::*;

    #[tokio::test]
    async fn test_conn_lookup_host() {
        let stun_serv_addr = "stun1.l.google.com:19302";

        if let Ok(ipv4_addr) = lookup_host(true, stun_serv_addr).await {
            assert!(
                ipv4_addr.is_ipv4(),
                "expected ipv4 but got ipv6: {ipv4_addr}"
            );
        }

        if let Ok(ipv6_addr) = lookup_host(false, stun_serv_addr).await {
            assert!(
                ipv6_addr.is_ipv6(),
                "expected ipv6 but got ipv4: {ipv6_addr}"
            );
        }
    }
}

#[cfg(test)]
mod net_test {
    use super::*;

    #[tokio::test]
    async fn test_net_native_resolve_addr() {
        let udp_addr = lookup_host(true, "localhost:1234").await.unwrap();
        assert_eq!(udp_addr.ip().to_string(), "127.0.0.1", "should match");
        assert_eq!(udp_addr.port(), 1234, "should match");

        let result = lookup_host(false, "127.0.0.1:1234").await;
        assert!(result.is_err(), "should not match");
    }
}
