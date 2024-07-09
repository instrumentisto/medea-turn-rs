//! Relay definitions.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;

use crate::{transport, Error};

/// Generator of relay addresses when creating an [allocation].
///
/// [allocation]: https://tools.ietf.org/html/rfc5766#section-5
#[derive(Clone, Debug)]
pub struct Allocator {
    /// [`IpAddr`] returned to the user when a relay is created.
    pub relay_address: IpAddr,

    /// Minimum (inclusive) port to allocate.
    pub min_port: u16,

    /// Maximum (inclusive) port to allocate.
    pub max_port: u16,

    /// Amount of tries to allocate a random port in the allowed range.
    pub max_retries: u16,

    /// Address passed when creating a relay.
    pub address: String,
}

impl Allocator {
    /// Allocates a new relay connection.
    ///
    /// # Errors
    ///
    /// - With an [`Error::MaxRetriesExceeded`] if the requested port is `0` and
    /// failed to find a free port in the specified [`max_retries`].
    /// - With an [`Error::Transport`] if failed to bind to the specified port.
    ///
    /// [`max_retries`]: Allocator::max_retries
    pub async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested_port: u16,
    ) -> Result<(Arc<UdpSocket>, SocketAddr), Error> {
        let max_retries =
            if self.max_retries == 0 { 10 } else { self.max_retries };

        if requested_port == 0 {
            for _ in 0..max_retries {
                let port = self.min_port
                    + rand::random::<u16>()
                        % (self.max_port - self.min_port + 1);
                let addr = transport::lookup_host(
                    use_ipv4,
                    &format!("{}:{port}", self.address),
                )
                .await?;
                let Ok(conn) = UdpSocket::bind(addr).await else {
                    continue;
                };

                let mut relay_addr =
                    conn.local_addr().map_err(transport::Error::from)?;
                relay_addr.set_ip(self.relay_address);
                return Ok((Arc::new(conn), relay_addr));
            }

            Err(Error::MaxRetriesExceeded)
        } else {
            let addr = transport::lookup_host(
                use_ipv4,
                &format!("{}:{requested_port}", self.address),
            )
            .await?;
            let conn = Arc::new(
                UdpSocket::bind(addr).await.map_err(transport::Error::from)?,
            );
            let mut relay_addr =
                conn.local_addr().map_err(transport::Error::from)?;
            relay_addr.set_ip(self.relay_address);

            Ok((conn, relay_addr))
        }
    }
}
