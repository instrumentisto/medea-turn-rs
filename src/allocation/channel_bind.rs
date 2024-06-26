//! TURN [`Channel`].
//!
//! [`Channel`]: https://tools.ietf.org/html/rfc5766#section-2.5

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::{
    sync::{mpsc, Mutex},
    time::{sleep, Duration, Instant},
};

/// TURN [`Channel`].
///
/// [`Channel`]: https://tools.ietf.org/html/rfc5766#section-2.5
#[derive(Clone)]
pub(crate) struct ChannelBind {
    /// Transport address of the peer.
    peer: SocketAddr,

    /// Channel number.
    number: u16,

    /// Channel to the internal loop used to update lifetime or drop channel
    /// binding.
    reset_tx: Option<mpsc::Sender<Duration>>,
}

impl ChannelBind {
    /// Creates a new [`ChannelBind`]
    pub(crate) const fn new(number: u16, peer: SocketAddr) -> Self {
        Self { number, peer, reset_tx: None }
    }

    /// Starts [`ChannelBind`]'s internal lifetime watching loop.
    pub(crate) fn start(
        &mut self,
        bindings: Arc<Mutex<HashMap<u16, Self>>>,
        lifetime: Duration,
    ) {
        let (reset_tx, mut reset_rx) = mpsc::channel(1);
        self.reset_tx = Some(reset_tx);

        let number = self.number;

        drop(tokio::spawn(async move {
            let timer = sleep(lifetime);
            tokio::pin!(timer);

            loop {
                tokio::select! {
                    () = &mut timer => {
                        if bindings.lock().await.remove(&number).is_none() {
                            log::error!(
                                "Failed to remove ChannelBind for {number}"
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
    }

    /// Returns transport address of the peer.
    pub(crate) const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns channel number.
    pub(crate) const fn num(&self) -> u16 {
        self.number
    }

    /// Updates [`ChannelBind`]'s lifetime.
    pub(crate) async fn refresh(&self, lifetime: Duration) {
        if let Some(tx) = &self.reset_tx {
            _ = tx.send(lifetime).await;
        }
    }
}

#[cfg(test)]
mod channel_bind_test {
    use std::net::Ipv4Addr;

    use tokio::net::UdpSocket;

    use crate::{
        allocation::Allocation,
        attr::{ChannelNumber, Username},
        con, Error, FiveTuple,
    };

    use super::*;

    async fn create_channel_bind(
        lifetime: Duration,
    ) -> Result<Allocation, Error> {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let relay_socket = Arc::clone(&turn_socket);
        let relay_addr = relay_socket.local_addr().unwrap();
        let a = Allocation::new(
            turn_socket,
            relay_socket,
            relay_addr,
            FiveTuple::default(),
            Username::new(String::from("user")).unwrap(),
            None,
        );

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0);

        a.add_channel_bind(ChannelNumber::MIN, addr, lifetime).await?;

        Ok(a)
    }

    #[tokio::test]
    async fn test_channel_bind() {
        let a = create_channel_bind(Duration::from_millis(20)).await.unwrap();

        let result = a.get_channel_addr(&ChannelNumber::MIN).await;
        if let Some(addr) = result {
            assert_eq!(addr.ip().to_string(), "0.0.0.0");
        } else {
            panic!("expected some, but got none");
        }
    }
}
