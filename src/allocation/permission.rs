//! TURN [Allocation] [Permission].
//!
//! [Allocation]: https://datatracker.ietf.org/doc/html/rfc5766#section-2.2
//! [Permission]: https://datatracker.ietf.org/doc/html/rfc5766#section-8

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use tokio::{
    sync::{mpsc, Mutex},
    time::{sleep, Duration, Instant},
};

/// The Permission Lifetime MUST be 300 seconds (= 5 minutes)[1].
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-8
pub(crate) const PERMISSION_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// TURN [Allocation] [Permission].
///
/// [Allocation]: https://datatracker.ietf.org/doc/html/rfc5766#section-2.2
/// [Permission]: https://datatracker.ietf.org/doc/html/rfc5766#section-8
pub(crate) struct Permission {
    /// [`IpAddr`] of this permission that is matched with the source IP
    /// address of the datagram received.
    ip: IpAddr,

    /// Channel to the inner lifetime watching loop.
    reset_tx: Option<mpsc::Sender<Duration>>,
}

impl Permission {
    /// Creates a new [`Permission`].
    pub(crate) const fn new(ip: IpAddr) -> Self {
        Self { ip, reset_tx: None }
    }

    /// Starts [`Permission`]'s internal lifetime watching loop.
    pub(crate) fn start(
        &mut self,
        permissions: Arc<Mutex<HashMap<IpAddr, Self>>>,
        lifetime: Duration,
    ) {
        let (reset_tx, mut reset_rx) = mpsc::channel(1);
        self.reset_tx = Some(reset_tx);

        let ip = self.ip;

        drop(tokio::spawn(async move {
            let timer = sleep(lifetime);
            tokio::pin!(timer);

            loop {
                tokio::select! {
                    () = &mut timer => {
                        drop(permissions.lock().await.remove(&ip));
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

    /// Returns [`IpAddr`] of this [`Permission`].
    pub(crate) const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Updates [`Permission`]'s lifetime.
    pub(crate) async fn refresh(&self, lifetime: Duration) {
        if let Some(tx) = &self.reset_tx {
            _ = tx.send(lifetime).await;
        }
    }
}
