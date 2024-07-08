//! TURN server implementation.

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

use crate::{
    allocation::{FiveTuple, Info, Manager, ManagerConfig},
    relay,
    transport::Transport,
    AuthHandler, Error,
};

/// `DEFAULT_LIFETIME` in RFC 5766 is 10 minutes.
///
/// [RFC 5766 Section 2.2](https://www.rfc-editor.org/rfc/rfc5766#section-2.2)
pub(crate) const DEFAULT_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// MTU used for UDP connections.
pub(crate) const INBOUND_MTU: usize = 1500;

/// [`Config`] configures the TURN Server.
#[derive(Debug)]
pub struct Config<A> {
    /// `conn_configs` are a list of all the turn listeners.
    /// Each listener can have custom behavior around the creation of Relays.
    #[debug("{:?}", connections.iter()
        .map(|c| (c.local_addr(), c.proto()))
        .collect::<Vec<_>>())]
    pub connections: Vec<Arc<dyn Transport + Send + Sync>>,

    /// Relay connections allocator.
    pub relay_addr_generator: relay::Allocator,

    /// `realm` sets the realm for this server
    pub realm: String,

    /// `auth_handler` is a callback used to handle incoming auth requests,
    /// allowing users to customize Pion TURN with custom behavior.
    pub auth_handler: Arc<A>,

    /// Sets the lifetime of channel binding.
    pub channel_bind_lifetime: Duration,

    /// To receive notify on allocation close event, with metrics data.
    pub alloc_close_notify: Option<mpsc::Sender<Info>>,
}

/// Server is an instance of the TURN Server
#[derive(Debug)]
pub struct Server {
    /// Channel to [`Server`]'s internal loop.
    command_tx: broadcast::Sender<Command>,
}

impl Server {
    /// creates a new TURN server
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
                                        "Turn server has lagged by {n} \
                                        messages",
                                    );
                                }
                            }
                            continue;
                        },
                        v = conn.recv_from() => {
                            match v {
                                Ok(v) => v,
                                Err(err) => {
                                    log::debug!(
                                        "exit read loop on error: {err}"
                                    );
                                    break;
                                }
                            }
                        },
                        () = close_tx.closed() => break
                    };

                    let handle = request::handle_message(
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

                    if let Err(err) = handle.await {
                        log::warn!("Error when handling STUN request: {err}");
                    }
                }
            }));
        }

        this
    }

    /// Deletes all existing allocations by the provided `username`.
    ///
    /// # Errors
    ///
    /// With [`Error::Closed`] if the [`Server`] was closed already.
    pub async fn delete_allocations_by_username(
        &self,
        username: String,
    ) -> Result<(), Error> {
        let (closed_tx, closed_rx) = mpsc::channel(1);
        #[allow(clippy::map_err_ignore)]
        let _: usize = self
            .command_tx
            .send(Command::DeleteAllocations(username, Arc::new(closed_rx)))
            .map_err(|_| Error::Closed)?;

        closed_tx.closed().await;

        Ok(())
    }

    /// Returns [`Info`]s by specified [`FiveTuple`]s.
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
    /// With [`Error::Closed`] if the [`Server`] was closed already.
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

        #[allow(clippy::map_err_ignore)]
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

/// The protocol to communicate between the [`Server`]'s public methods
/// and the tasks spawned in inner loop.
#[derive(Clone)]
enum Command {
    /// Command to delete [`Allocation`][`Allocation`] by provided `username`.
    ///
    /// [`Allocation`]: `crate::allocation::Allocation`
    DeleteAllocations(String, Arc<mpsc::Receiver<()>>),

    /// Command to get information of [`Allocation`][`Allocation`]s by provided
    /// [`FiveTuple`]s.
    ///
    /// [`Allocation`]: `crate::allocation::Allocation`
    GetAllocationsInfo(
        Option<Vec<FiveTuple>>,
        mpsc::Sender<HashMap<FiveTuple, Info>>,
    ),
}
