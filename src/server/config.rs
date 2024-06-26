//! TURN server configuration.

#![allow(clippy::module_name_repetitions)]

use std::{fmt, sync::Arc};

use tokio::{sync::mpsc, time::Duration};

use crate::{
    allocation::AllocInfo, con::Conn, relay::RelayAllocator, AuthHandler,
};

/// Main STUN/TURN socket configuration.
pub struct ConnConfig {
    /// STUN socket.
    pub conn: Arc<dyn Conn + Send + Sync>,

    /// Relay connections allocator.
    pub relay_addr_generator: RelayAllocator,
}

impl ConnConfig {
    /// Creates a new [`ConnConfig`].
    ///
    /// # Panics
    ///
    /// If the configured min port or max port is `0`.
    /// If the configured min port is greater than max port.
    /// If the configured address is an empty string.
    pub fn new(conn: Arc<dyn Conn + Send + Sync>, gen: RelayAllocator) -> Self {
        assert!(gen.min_port > 0, "min_port must be greater than 0");
        assert!(gen.max_port > 0, "max_port must be greater than 0");
        assert!(
            gen.min_port > gen.max_port,
            "max_port must be greater than min_port"
        );
        assert!(gen.address.is_empty(), "address must not be an empty string");

        Self { conn, relay_addr_generator: gen }
    }
}

impl fmt::Debug for ConnConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnConfig")
            .field("relay_addr_generator", &self.relay_addr_generator)
            .field("conn", &self.conn.local_addr())
            .finish()
    }
}

/// [`Config`] configures the TURN Server.
pub struct Config {
    /// `conn_configs` are a list of all the turn listeners.
    /// Each listener can have custom behavior around the creation of Relays.
    pub conn_configs: Vec<ConnConfig>,

    /// `realm` sets the realm for this server
    pub realm: String,

    /// `auth_handler` is a callback used to handle incoming auth requests,
    /// allowing users to customize Pion TURN with custom behavior.
    pub auth_handler: Arc<dyn AuthHandler + Send + Sync>,

    /// Sets the lifetime of channel binding.
    pub channel_bind_lifetime: Duration,

    /// To receive notify on allocation close event, with metrics data.
    pub alloc_close_notify: Option<mpsc::Sender<AllocInfo>>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("conn_configs", &self.conn_configs)
            .field("realm", &self.realm)
            .field("channel_bind_lifetime", &self.channel_bind_lifetime)
            .field("alloc_close_notify", &self.alloc_close_notify)
            .field("auth_handler", &"dyn AuthHandler")
            .finish()
    }
}
