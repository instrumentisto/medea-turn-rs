//! Main STUN/TURN transport implementation.

mod tcp;

use std::io;

use std::net::SocketAddr;

use async_trait::async_trait;

use tokio::{
    net,
    net::{ToSocketAddrs, UdpSocket},
};

use crate::{attr::PROTO_UDP, server::INBOUND_MTU, Error};

pub use tcp::TcpServer;

/// Abstracting over transport implementation.
#[async_trait]
pub trait Conn {
    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), Error>;
    async fn send_to(
        &self,
        buf: Vec<u8>,
        target: SocketAddr,
    ) -> Result<usize, Error>;

    /// Returns the local transport address.
    fn local_addr(&self) -> SocketAddr;

    /// Return the transport protocol according to [IANA].
    ///
    /// [IANA]: https://tinyurl.com/iana-protocol-numbers
    fn proto(&self) -> u8;

    /// Closes the underlying transport.
    async fn close(&self) -> Result<(), Error>;
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
    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), Error> {
        let mut buf = vec![0u8; INBOUND_MTU];
        let (len, addr) = self.recv_from(&mut buf).await?;
        buf.truncate(len);

        Ok((buf, addr))
    }

    async fn send_to(
        &self,
        data: Vec<u8>,
        target: SocketAddr,
    ) -> Result<usize, Error> {
        Ok(self.send_to(&data, target).await?)
    }

    fn local_addr(&self) -> SocketAddr {
        #[allow(clippy::unwrap_used)]
        self.local_addr().unwrap()
    }

    fn proto(&self) -> u8 {
        PROTO_UDP
    }

    async fn close(&self) -> Result<(), Error> {
        Ok(())
    }
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
