//! TURN server configuration.

#![allow(clippy::module_name_repetitions)]

use std::{fmt, sync::Arc};

use tokio::{sync::mpsc, time::Duration};

use crate::{allocation::AllocInfo, con::Conn, relay::RelayAllocator};

/// [`Config`] configures the TURN Server.
pub struct Config<A> {
    /// `conn_configs` are a list of all the turn listeners.
    /// Each listener can have custom behavior around the creation of Relays.
    pub connections: Vec<Arc<dyn Conn + Send + Sync>>,

    /// Relay connections allocator.
    pub relay_addr_generator: RelayAllocator,

    /// `realm` sets the realm for this server
    pub realm: String,

    /// `auth_handler` is a callback used to handle incoming auth requests,
    /// allowing users to customize Pion TURN with custom behavior.
    pub auth_handler: Arc<A>,

    /// Sets the lifetime of channel binding.
    pub channel_bind_lifetime: Duration,

    /// To receive notify on allocation close event, with metrics data.
    pub alloc_close_notify: Option<mpsc::Sender<AllocInfo>>,
}

impl<A> fmt::Debug for Config<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field(
                "connections",
                &self
                    .connections
                    .iter()
                    .map(|c| (c.local_addr(), c.proto()))
                    .collect::<Vec<_>>(),
            )
            .field("relay_addr_generator", &self.relay_addr_generator)
            .field("realm", &self.realm)
            .field("auth_handler", &"AuthHandler")
            .field("channel_bind_lifetime", &self.channel_bind_lifetime)
            .field("alloc_close_notify", &self.alloc_close_notify)
            .finish()
    }
}
