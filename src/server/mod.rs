//! TURN server implementation.

mod config;
mod request;

use std::{collections::HashMap, sync::Arc};

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
    allocation::{AllocInfo, FiveTuple, Manager, ManagerConfig},
    AuthHandler, Error,
};

pub use self::config::Config;

/// `DEFAULT_LIFETIME` in RFC 5766 is 10 minutes.
///
/// [RFC 5766 Section 2.2](https://www.rfc-editor.org/rfc/rfc5766#section-2.2)
pub(crate) const DEFAULT_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// MTU used for UDP connections.
pub(crate) const INBOUND_MTU: usize = 1500;

/// Server is an instance of the TURN Server
#[derive(Debug)]
pub struct Server {
    /// Channel to [`Server`]'s internal loop.
    command_tx: Option<broadcast::Sender<Command>>,
}

impl Server {
    /// creates a new TURN server
    #[must_use]
    pub fn new<A>(config: Config<A>) -> Self
    where
        A: AuthHandler + Send + Sync + 'static,
    {
        let (command_tx, _) = broadcast::channel(16);
        let this = Self { command_tx: Some(command_tx.clone()) };
        let channel_bind_lifetime =
            if config.channel_bind_lifetime == Duration::from_secs(0) {
                DEFAULT_LIFETIME
            } else {
                config.channel_bind_lifetime
            };

        for conn in config.connections {
            let mut nonces = HashMap::new();
            let auth_handler = Arc::clone(&config.auth_handler);
            let realm = config.realm.clone();
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
                                            name.as_str(),
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
                                Ok(Command::Close(completion)) => {
                                    close_rx.close();
                                    drop(completion);
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
                        realm.as_str(),
                        channel_bind_lifetime,
                        &mut allocation_manager,
                        &mut nonces,
                        &auth_handler,
                    );

                    if let Err(err) = handle.await {
                        log::error!("error when handling datagram: {err}");
                    }
                }

                conn.close().await;
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
        #[allow(clippy::map_err_ignore)]
        if let Some(tx) = &self.command_tx {
            let (closed_tx, closed_rx) = mpsc::channel(1);
            _ = tx
                .send(Command::DeleteAllocations(username, Arc::new(closed_rx)))
                .map_err(|_| Error::Closed)?;

            closed_tx.closed().await;

            Ok(())
        } else {
            Err(Error::Closed)
        }
    }

    /// Returns [`AllocInfo`]s by specified [`FiveTuple`]s.
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
    ) -> Result<HashMap<FiveTuple, AllocInfo>, Error> {
        if let Some(five_tuples) = &five_tuples {
            if five_tuples.is_empty() {
                return Ok(HashMap::new());
            }
        }

        #[allow(clippy::map_err_ignore)]
        if let Some(tx) = &self.command_tx {
            let (infos_tx, mut infos_rx) = mpsc::channel(1);

            _ = tx
                .send(Command::GetAllocationsInfo(five_tuples, infos_tx))
                .map_err(|_| Error::Closed)?;

            let mut info: HashMap<FiveTuple, AllocInfo> = HashMap::new();

            for _ in 0..tx.receiver_count() {
                info.extend(infos_rx.recv().await.ok_or(Error::Closed)?);
            }

            Ok(info)
        } else {
            Err(Error::Closed)
        }
    }

    /// Close stops the TURN Server. It cleans up any associated state and
    /// closes all connections it is managing.
    pub async fn close(&self) {
        if let Some(tx) = &self.command_tx {
            if tx.receiver_count() == 0 {
                return;
            }

            let (closed_tx, closed_rx) = mpsc::channel(1);
            drop(tx.send(Command::Close(Arc::new(closed_rx))));
            closed_tx.closed().await;
        }
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
        mpsc::Sender<HashMap<FiveTuple, AllocInfo>>,
    ),

    /// Command to close the [`Server`].
    Close(Arc<mpsc::Receiver<()>>),
}
