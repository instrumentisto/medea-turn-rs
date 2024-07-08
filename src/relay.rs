//! [`RelayAllocator`] is used to create relay transports wit the given
//! configuration.

#![allow(clippy::module_name_repetitions)]

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;

use crate::{transport, Error};

/// [`RelayAllocator`] is used to generate a Relay Address when creating an
/// allocation.
#[derive(Clone, Debug)]
pub struct RelayAllocator {
    /// `relay_address` is the IP returned to the user when the relay is
    /// created.
    pub relay_address: IpAddr,

    /// `min_port` the minimum port to allocate.
    pub min_port: u16,

    /// `max_port` the maximum (inclusive) port to allocate.
    pub max_port: u16,

    /// `max_retries` the amount of tries to allocate a random port in the
    /// defined range.
    pub max_retries: u16,

    /// `address` is passed to Listen/ListenPacket when creating the Relay.
    pub address: String,
}

impl RelayAllocator {
    /// Allocates a new relay connection.
    ///
    /// # Errors
    ///
    /// With [`Error::MaxRetriesExceeded`] if the requested port is `0` and
    /// failed to find a free port in the specified maximum retries.
    ///
    /// With [`Error::Transport`] if failed to bind to the specified port.
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
                    &format!("{}:{}", self.address, port),
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
                &format!("{}:{}", self.address, requested_port),
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
