//! [STUN]/[TURN] server implementation.
//!
//! [STUN]: https://en.wikipedia.org/wiki/STUN
//! [TURN]: https://en.wikipedia.org/wiki/TURN

mod request;

use std::{collections::HashMap, sync::Arc};

use derive_more::Debug;
use tokio::{
    sync::{
        broadcast::{
            error::RecvError,
            {self},
        },
        mpsc, oneshot,
    },
    time::Duration,
};

#[cfg(doc)]
use crate::allocation::Allocation;
use crate::{
    allocation::{FiveTuple, Info, Manager, ManagerConfig},
    relay,
    transport::Transport,
    AuthHandler, Error,
};

/// Default lifetime of an [allocation][1] (10 minutes) as defined in
/// [RFC 5766 Section 2.2][1].
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-2.2
pub(crate) const DEFAULT_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// [MTU] of UDP connections.
///
/// [MTU]: https://en.wikipedia.org/wiki/Maximum_transmission_unit
pub(crate) const INBOUND_MTU: usize = 1500;

/// Configuration of a [`Server`].
#[derive(Debug)]
pub struct Config<A> {
    /// List of all [STUN]/[TURN] connections listeners.
    ///
    /// Each listener may have a custom behavior around the creation of
    /// [`relay`]s.
    ///
    /// [STUN]: https://en.wikipedia.org/wiki/STUN
    /// [TURN]: https://en.wikipedia.org/wiki/TURN
    #[debug("{:?}", connections.iter()
        .map(|c| (c.local_addr(), c.proto()))
        .collect::<Vec<_>>())]
    pub connections: Vec<Arc<dyn Transport + Send + Sync>>,

    /// [`Allocator`] of [`relay`] connections.
    ///
    /// [`Allocator`]: relay::Allocator
    pub relay_addr_generator: relay::Allocator,

    /// [Realm][1] of the [`Server`].
    ///
    /// > A string used to describe the server or a context within the server.
    /// > The realm tells the client which username and password combination to
    /// > use to authenticate requests.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-3
    pub realm: String,

    /// Callback for handling incoming authentication requests, allowing users
    /// to customize it with custom behavior.
    pub auth_handler: Arc<A>,

    /// Lifetime of a [channel bindings][1].
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-2.5
    pub channel_bind_lifetime: Duration,

    /// [`mpsc::Sender`] receiving notify on [allocation][1] close event, along
    /// with metrics data.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-2.2
    pub alloc_close_notify: Option<mpsc::Sender<Info>>,
}

/// Instance of a [STUN]/[TURN] server.
///
/// [STUN]: https://en.wikipedia.org/wiki/STUN
/// [TURN]: https://en.wikipedia.org/wiki/TURN
#[derive(Debug)]
pub struct Server {
    /// [`broadcast::Sender`] to this [`Server`]'s internal loop.
    command_tx: broadcast::Sender<Command>,
}

impl Server {
    /// Creates a new [`Server`] according to the provided [`Config`], and
    /// [`spawn`]s its internal loop.
    ///
    /// [`spawn`]: tokio::spawn()
    #[must_use]
    pub fn new<A>(config: Config<A>) -> Self
    where
        A: AuthHandler + Send + Sync + 'static,
    {
        let (command_tx, _) = broadcast::channel(16);
        let this = Self { command_tx: command_tx.clone() };
        let channel_bind_lifetime =
            if config.channel_bind_lifetime == Duration::from_secs(0) {
                DEFAULT_LIFETIME
            } else {
                config.channel_bind_lifetime
            };

        for conn in config.connections {
            let auth_handler = Arc::clone(&config.auth_handler);
            let realm = config.realm.clone();
            let mut nonces = HashMap::new();
            let mut handle_rx = command_tx.subscribe();
            let mut allocation_manager = Manager::new(ManagerConfig {
                relay_addr_generator: config.relay_addr_generator.clone(),
                alloc_close_notify: config.alloc_close_notify.clone(),
            });

            let (mut close_tx, mut close_rx) = oneshot::channel::<()>();
            drop(tokio::spawn(async move {
                let local_con_addr = conn.local_addr();
                let protocol = conn.proto();

                loop {
                    let (msg, src_addr) = tokio::select! {
                        cmd = handle_rx.recv() => {
                            match cmd {
                                Ok(Command::DeleteAllocations(
                                    name,
                                    completion,
                                )) => {
                                    allocation_manager
                                        .delete_allocations_by_username(
                                            &name,
                                        );
                                    drop(completion);
                                }
                                Ok(Command::GetAllocationsInfo(
                                    five_tuples,
                                    tx,
                                )) => {
                                    let infos = allocation_manager
                                        .get_allocations_info(&five_tuples);
                                    drop(tx.send(infos).await);
                                }
                                Err(RecvError::Closed) => {
                                    close_rx.close();
                                    break;
                                }
                                Err(RecvError::Lagged(n)) => {
                                    log::warn!(
                                        "`Server` has lagged by {n} messages",
                                    );
                                }
                            }
                            continue;
                        },
                        v = conn.recv_from() => {
                            match v {
                                Ok(v) => v,
                                Err(e) => {
                                    log::debug!("Exit read loop on error: {e}");
                                    break;
                                }
                            }
                        },
                        () = close_tx.closed() => break
                    };

                    let handle = request::handle(
                        msg,
                        &conn,
                        FiveTuple {
                            src_addr,
                            dst_addr: local_con_addr,
                            protocol,
                        },
                        &realm,
                        channel_bind_lifetime,
                        &mut allocation_manager,
                        &mut nonces,
                        &auth_handler,
                    );
                    if let Err(e) = handle.await {
                        log::warn!("Error when handling `Request`: {e}");
                    }
                }
            }));
        }

        this
    }

    /// Deletes all existing [allocations][1] with the provided `username`.
    ///
    /// # Errors
    ///
    /// With an [`Error::Closed`] if the [`Server`] was closed already.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-2.2
    pub async fn delete_allocations_by_username(
        &self,
        username: String,
    ) -> Result<(), Error> {
        let (closed_tx, closed_rx) = mpsc::channel(1);
        #[allow(clippy::map_err_ignore)] // intentional
        let _: usize = self
            .command_tx
            .send(Command::DeleteAllocations(username, Arc::new(closed_rx)))
            .map_err(|_| Error::Closed)?;

        closed_tx.closed().await;

        Ok(())
    }

    /// Returns [`Info`]s for the provided [`FiveTuple`]s.
    ///
    /// If `five_tuples` is:
    /// - [`None`]:               It returns information about the all
    ///   allocations.
    /// - [`Some`] and not empty: It returns information about the allocations
    ///   associated with the specified [`FiveTuple`]s.
    /// - [`Some`], but empty:    It returns an empty [`HashMap`].
    ///
    /// # Errors
    ///
    /// With an [`Error::Closed`] if the [`Server`] was closed already.
    pub async fn get_allocations_info(
        &self,
        five_tuples: Option<Vec<FiveTuple>>,
    ) -> Result<HashMap<FiveTuple, Info>, Error> {
        if let Some(five_tuples) = &five_tuples {
            if five_tuples.is_empty() {
                return Ok(HashMap::new());
            }
        }

        let (infos_tx, mut infos_rx) = mpsc::channel(1);

        #[allow(clippy::map_err_ignore)] // intentional
        let _: usize = self
            .command_tx
            .send(Command::GetAllocationsInfo(five_tuples, infos_tx))
            .map_err(|_| Error::Closed)?;

        let mut info: HashMap<FiveTuple, Info> = HashMap::new();
        for _ in 0..self.command_tx.receiver_count() {
            info.extend(infos_rx.recv().await.ok_or(Error::Closed)?);
        }
        Ok(info)
    }
}

/// Commands for communication between [`Server`]'s public methods and the tasks
/// spawned in its inner loop.
#[derive(Clone)]
enum Command {
    /// Delete [`Allocation`] by the provided `username`.
    DeleteAllocations(String, Arc<mpsc::Receiver<()>>),

    /// Return information about [`Allocation`] for the provided [`FiveTuple`]s.
    GetAllocationsInfo(
        Option<Vec<FiveTuple>>,
        mpsc::Sender<HashMap<FiveTuple, Info>>,
    ),
}
