//! [Channel] definitions.
//!
//! [Channel]: https://tools.ietf.org/html/rfc5766#section-2.5

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    sync::{Mutex, mpsc},
    time::{Instant, sleep},
};

/// Representation of a [channel].
///
/// [channel]: https://tools.ietf.org/html/rfc5766#section-2.5
#[derive(Clone, Debug)]
pub(crate) struct ChannelBind {
    /// Transport address of the peer behind this [`ChannelBind`].
    peer: SocketAddr,

    /// Number of this [`ChannelBind`].
    number: u16,

    /// [`mpsc::Sender`] to the internal loop of this [`ChannelBind`], used to
    /// update its lifetime or stop it.
    reset_tx: mpsc::Sender<Duration>,
}

impl ChannelBind {
    /// Creates a new [`ChannelBind`] and [`spawn`]s a loop watching its
    /// lifetime.
    ///
    /// [`spawn`]: tokio::spawn()
    pub(crate) fn new(
        number: u16,
        peer: SocketAddr,
        bindings: Arc<Mutex<HashMap<u16, Self>>>,
        lifetime: Duration,
    ) -> Self {
        let (reset_tx, mut reset_rx) = mpsc::channel(1);
        drop(tokio::spawn(async move {
            let timer = sleep(lifetime);
            tokio::pin!(timer);

            loop {
                tokio::select! {
                    () = &mut timer => {
                        if bindings.lock().await.remove(&number).is_none() {
                            log::error!(
                                "Failed to remove \
                                 `ChannelBind(number: {number})`",
                            );
                        }
                        break;
                    },
                    result = reset_rx.recv() => {
                        if let Some(d) = result {
                            timer.as_mut().reset(Instant::now() + d);
                        } else {
                            break;
                        }
                    },
                }
            }
        }));

        Self { peer, number, reset_tx }
    }
    /// Returns the [`SocketAddr`] of the peer behind this [`ChannelBind`].
    pub(crate) const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the number of this [`ChannelBind`].
    pub(crate) const fn num(&self) -> u16 {
        self.number
    }

    /// Updates the `lifetime` of this [`ChannelBind`].
    pub(crate) async fn refresh(&self, lifetime: Duration) {
        _ = self.reset_tx.send(lifetime).await;
    }
}

#[cfg(test)]
mod allocation_spec {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use tokio::net::UdpSocket;

    #[cfg(doc)]
    use super::ChannelBind;
    use crate::{
        Allocation, Error, FiveTuple,
        attr::{ChannelNumber, Username},
        server::DEFAULT_LIFETIME,
    };

    /// Creates an [`Allocation`] with a bound [`ChannelBind`] for testing
    /// purposes.
    async fn create_channel_bind_allocation(
        lifetime: Duration,
    ) -> Result<Allocation, Error> {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let relay_socket = Arc::clone(&turn_socket);
        let relay_addr = relay_socket.local_addr().unwrap();
        let a = Allocation::new(
            turn_socket,
            relay_socket,
            relay_addr,
            FiveTuple::default(),
            DEFAULT_LIFETIME,
            Username::new(String::from("user")).unwrap(),
            None,
        );

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0);

        a.add_channel_bind(ChannelNumber::MIN, addr, lifetime).await?;

        Ok(a)
    }

    #[tokio::test]
    async fn channel_bind_is_present() {
        let a = create_channel_bind_allocation(Duration::from_millis(20))
            .await
            .unwrap();

        let result = a.get_channel_addr(&ChannelNumber::MIN).await;
        if let Some(addr) = result {
            assert_eq!(addr.ip().to_string(), "0.0.0.0", "wrong IP address");
        } else {
            panic!("expected some, but got none");
        }
    }
}
