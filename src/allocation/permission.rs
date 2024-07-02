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
    reset_tx: mpsc::Sender<Duration>,
}

impl Permission {
    /// Creates a new [`Permission`].
    pub(crate) fn new(
        ip: IpAddr,
        permissions: Arc<Mutex<HashMap<IpAddr, Self>>>,
        lifetime: Duration,
    ) -> Self {
        let (reset_tx, mut reset_rx) = mpsc::channel(1);

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

        Self { ip, reset_tx }
    }

    /// Returns [`IpAddr`] of this [`Permission`].
    pub(crate) const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Updates [`Permission`]'s lifetime.
    pub(crate) async fn refresh(&self, lifetime: Duration) {
        _ = self.reset_tx.send(lifetime).await;
    }
}
