//! [Allocation] definitions.
//!
//! [Allocation]: https://tools.ietf.org/html/rfc5766#section-5

mod channel_bind;
mod manager;
mod permission;

use std::{
    collections::HashMap,
    marker::{Send, Sync},
    mem,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use bytecodec::EncodeExt as _;
use derive_more::with_trait::Display;
use rand::random;
use stun_codec::{
    rfc5766::methods::DATA, Message, MessageClass, MessageEncoder,
    TransactionId,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    time::{sleep, Duration, Instant},
};

use crate::{
    allocation::permission::PERMISSION_LIFETIME,
    attr::{Attribute, Data, Username, XorPeerAddress},
    chandata::ChannelData,
    server::INBOUND_MTU,
    transport, Error, Transport,
};

use self::{channel_bind::ChannelBind, permission::Permission};

pub(crate) use self::manager::{Config as ManagerConfig, Manager};

/// Shortcut for a [`Transport`] trait object.
type DynTransport = Arc<dyn Transport + Send + Sync>;

/// 5-tuple uniquely identifying a UDP/TCP session.
///
/// Consists of:
/// 1. source IP address
/// 2. source port
/// 3. destination IP address
/// 4. destination port
/// 5. transport protocol
#[derive(Clone, Copy, Debug, Display, Eq, Hash, PartialEq)]
#[display("{protocol}_{src_addr}_{dst_addr}")]
pub struct FiveTuple {
    /// Number of the transport protocol according to [IANA].
    ///
    /// [IANA]: https://tinyurl.com/iana-protocol-numbers
    pub protocol: u8,

    /// Source address.
    pub src_addr: SocketAddr,

    /// Destination address.
    pub dst_addr: SocketAddr,
}

/// Information about an [allocation].
///
/// [allocation]: https://tools.ietf.org/html/rfc5766#section-5
#[derive(Clone, Debug)]
pub struct Info {
    /// [`FiveTuple`] of the [allocation].
    ///
    /// [allocation]: https://tools.ietf.org/html/rfc5766#section-5
    pub five_tuple: FiveTuple,

    /// [`Username`] of the [allocation].
    ///
    /// [allocation]: https://tools.ietf.org/html/rfc5766#section-5
    pub username: Username,

    /// Relayed bytes through the [allocation].
    ///
    /// [allocation]: https://tools.ietf.org/html/rfc5766#section-5
    pub relayed_bytes: usize,
}

impl Info {
    /// Creates a new [`Info`] out of the provided parameters.
    #[must_use]
    pub const fn new(
        five_tuple: FiveTuple,
        username: Username,
        relayed_bytes: usize,
    ) -> Self {
        Self { five_tuple, username, relayed_bytes }
    }
}

/// Representation of an [allocation].
///
/// [allocation]: https://tools.ietf.org/html/rfc5766#section-5
#[derive(Debug)]
pub(crate) struct Allocation {
    /// Relay [`SocketAddr`].
    relay_addr: SocketAddr,

    /// Allocated relay [`UdpSocket`].
    relay_socket: Arc<UdpSocket>,

    /// [`FiveTuple`] this [`Allocation`] is created for.
    five_tuple: FiveTuple,

    /// [`Username`] of the remote [ICE] user.
    ///
    /// [ICE]: https://webrtcglossary.com/ice
    username: Username,

    /// List of [`Permission`]s for this [`Allocation`].
    permissions: Arc<Mutex<HashMap<IpAddr, Permission>>>,

    /// [`ChannelBind`]s of this [`Allocation`].
    channel_bindings: Arc<Mutex<HashMap<u16, ChannelBind>>>,

    /// [`mpsc::Sender`] to the internal loop of this [`Allocation`], used to
    /// update its lifetime or stop it.
    refresh_tx: mpsc::Sender<Duration>,

    /// Total number of relayed bytes through this [`Allocation`].
    relayed_bytes: AtomicUsize,

    /// [`mpsc::Sender`] for notifying when this [`Allocation`] is closed.
    alloc_close_notify: Option<mpsc::Sender<Info>>,
}

impl Allocation {
    /// Creates a new [`Allocation`] out of the provided parameters.
    pub(crate) fn new(
        turn_socket: Arc<dyn Transport + Send + Sync>,
        relay_socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        five_tuple: FiveTuple,
        lifetime: Duration,
        username: Username,
        alloc_close_notify: Option<mpsc::Sender<Info>>,
    ) -> Self {
        let (refresh_tx, refresh_rx) = mpsc::channel(1);

        let this = Self {
            relay_addr,
            relay_socket,
            five_tuple,
            username,
            permissions: Arc::new(Mutex::new(HashMap::new())),
            channel_bindings: Arc::new(Mutex::new(HashMap::new())),
            refresh_tx,
            relayed_bytes: AtomicUsize::default(),
            alloc_close_notify,
        };

        this.spawn_relay_handler(refresh_rx, lifetime, turn_socket);

        this
    }

    /// Indicates whether the underlying relay socket and transmission loop is
    /// alive.
    pub(crate) fn is_alive(&self) -> bool {
        !self.refresh_tx.is_closed()
    }

    /// Send the provided `data` via the associated relay socket.
    ///
    /// # Errors
    ///
    /// - With an [`Error::NoAllocationFound`] if this [`Allocation`] is dead.
    /// - With a [`transport::Error`] if failed to send the `data`.
    pub(crate) async fn relay(
        &self,
        data: &[u8],
        to: SocketAddr,
    ) -> Result<(), Error> {
        if !self.is_alive() {
            return Err(Error::NoAllocationFound);
        }

        let n = self
            .relay_socket
            .send_to(data, to)
            .await
            .map_err(transport::Error::from)?;
        _ = self.relayed_bytes.fetch_add(n, Ordering::AcqRel);
        Ok(())
    }

    /// Returns [`SocketAddr`] of the associated relay socket.
    pub(crate) const fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Checks the [`Permission`] for the provided [`SocketAddr`].
    pub(crate) async fn has_permission(&self, addr: &SocketAddr) -> bool {
        if !self.is_alive() {
            return false;
        }

        self.permissions.lock().await.get(&addr.ip()).is_some()
    }

    /// Adds a new [`Permission`] to this [`Allocation`].
    pub(crate) async fn add_permission(&self, ip: IpAddr) {
        if !self.is_alive() {
            return;
        }

        let mut permissions = self.permissions.lock().await;

        if let Some(existed_permission) = permissions.get(&ip) {
            existed_permission.refresh(PERMISSION_LIFETIME).await;
        } else {
            let p = Permission::new(
                ip,
                Arc::clone(&self.permissions),
                PERMISSION_LIFETIME,
            );
            drop(permissions.insert(p.ip(), p));
        }
    }

    /// Adds a new [`ChannelBind`] to this [`Allocation`], also updating the
    /// [`Permission`]s needed for this [`ChannelBind`].
    pub(crate) async fn add_channel_bind(
        &self,
        number: u16,
        peer_addr: SocketAddr,
        lifetime: Duration,
    ) -> Result<(), Error> {
        if !self.is_alive() {
            return Err(Error::NoAllocationFound);
        }

        // The `ChannelNumber` is not currently bound to a different transport
        // address (same transport address is OK).
        if let Some(addr) = self.get_channel_addr(&number).await {
            if addr != peer_addr {
                return Err(Error::SameChannelDifferentPeer);
            }
        }

        // The transport address is not currently bound to a different
        // `ChannelNumber`.
        if let Some(n) = self.get_channel_number(&peer_addr).await {
            if number != n {
                return Err(Error::SamePeerDifferentChannel);
            }
        }

        let mut channel_bindings = self.channel_bindings.lock().await;
        if let Some(cb) = channel_bindings.get(&number).cloned() {
            drop(channel_bindings);

            cb.refresh(lifetime).await;

            // `ChannelBind`s also refresh `Permission`s.
            self.add_permission(cb.peer().ip()).await;
        } else {
            let bind = ChannelBind::new(
                number,
                peer_addr,
                Arc::clone(&self.channel_bindings),
                lifetime,
            );

            drop(channel_bindings.insert(number, bind));
            drop(channel_bindings);

            // `ChannelBind`s also refresh `Permission`s.
            self.add_permission(peer_addr.ip()).await;
        }
        Ok(())
    }

    /// Returns the [`ChannelBind`]'s address by the provided `number`.
    pub(crate) async fn get_channel_addr(
        &self,
        number: &u16,
    ) -> Option<SocketAddr> {
        if !self.is_alive() {
            return None;
        }

        self.channel_bindings.lock().await.get(number).map(ChannelBind::peer)
    }

    /// Returns the [`ChannelBind`]'s number from this [`Allocation`] by its
    /// `addr`ess.
    pub(crate) async fn get_channel_number(
        &self,
        addr: &SocketAddr,
    ) -> Option<u16> {
        if !self.is_alive() {
            return None;
        }
        self.channel_bindings
            .lock()
            .await
            .values()
            .find_map(|b| (b.peer() == *addr).then_some(b.num()))
    }

    /// Updates the `lifetime` of this [`Allocation`].
    pub(crate) async fn refresh(&self, lifetime: Duration) {
        _ = self.refresh_tx.send(lifetime).await;
    }

    /// [`spawn`]s a relay handler of this [`Allocation`].
    ///
    /// See [Section 10.3][1]:
    /// > When the server receives a UDP datagram at a currently allocated
    /// > relayed transport address, the server looks up the allocation
    /// > associated with the relayed transport address.  The server then
    /// > checks to see whether the set of permissions for the allocation allow
    /// > the relaying of the UDP datagram as described in [Section 8].
    /// >
    /// > If relaying is permitted, then the server checks if there is a
    /// > channel bound to the peer that sent the UDP datagram (see
    /// > [Section 11]).  If a channel is bound, then processing proceeds as
    /// > described in [Section 11.7][2].
    /// >
    /// > If relaying is permitted but no channel is bound to the peer, then
    /// > the server forms and sends a Data indication.  The Data indication
    /// > MUST contain both an XOR-PEER-ADDRESS and a DATA attribute.  The DATA
    /// > attribute is set to the value of the 'data octets' field from the
    /// > datagram, and the XOR-PEER-ADDRESS attribute is set to the source
    /// > transport address of the received UDP datagram.  The Data indication
    /// > is then sent on the 5-tuple associated with the allocation.
    ///
    /// [`spawn`]: tokio::spawn()
    /// [1]: https://tools.ietf.org/html/rfc5766#section-10.3
    /// [2]: https://tools.ietf.org/html/rfc5766#section-11.7
    /// [Section 8]: https://tools.ietf.org/html/rfc5766#section-8
    /// [Section 11]: https://tools.ietf.org/html/rfc5766#section-11
    // TODO: Refactor to satisfy `clippy::too_many_lines` lint.
    #[expect(clippy::too_many_lines, reason = "needs refactoring")]
    fn spawn_relay_handler(
        &self,
        mut refresh_rx: mpsc::Receiver<Duration>,
        lifetime: Duration,
        turn_socket: Arc<dyn Transport + Send + Sync>,
    ) {
        let five_tuple = self.five_tuple;
        let relay_addr = self.relay_addr;
        let relay_socket = Arc::clone(&self.relay_socket);
        let channel_bindings = Arc::clone(&self.channel_bindings);
        let permissions = Arc::clone(&self.permissions);

        drop(tokio::spawn(async move {
            log::trace!("Listening on relay addr: {relay_addr}");

            let expired = sleep(lifetime);
            tokio::pin!(expired);
            let mut buffer = vec![0u8; INBOUND_MTU];

            loop {
                let (data, src_addr) = tokio::select! {
                    result = relay_socket.recv_from(&mut buffer) => {
                        if let Ok((n, src_addr)) = result {
                            (&buffer[..n], src_addr)
                        } else {
                            break;
                        }
                    }
                    () = &mut expired => {
                        break;
                    },
                    refresh = refresh_rx.recv() => {
                        match refresh {
                            Some(lf) => {
                                if lf == Duration::ZERO {
                                    break;
                                }
                                expired.as_mut().reset(Instant::now() + lf);
                                continue;
                            }
                            None => {
                                break;
                            }
                        }
                    },
                };

                let cb_number = channel_bindings
                    .lock()
                    .await
                    .iter()
                    .find(|(_, cb)| cb.peer() == src_addr)
                    .map(|(cn, _)| *cn);

                if let Some(number) = cb_number {
                    match ChannelData::encode(data, number) {
                        Ok(data) => {
                            if let Err(e) = turn_socket
                                .send_to(data, five_tuple.src_addr)
                                .await
                            {
                                match e {
                                    transport::Error::TransportIsDead => {
                                        break;
                                    }
                                    transport::Error::Decode(..)
                                    | transport::Error::ChannelData(..)
                                    | transport::Error::Io(..) => {
                                        log::warn!(
                                            "Failed to send `ChannelData` from \
                                             `Allocation(scr: {src_addr}`: {e}",
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "Failed to send `ChannelData` from \
                                 `Allocation(src: {src_addr})`: {e}",
                            );
                        }
                    };
                } else {
                    let has_permission =
                        permissions.lock().await.contains_key(&src_addr.ip());

                    if has_permission {
                        log::trace!(
                            "Relaying message from {src_addr} to client at {}",
                            five_tuple.src_addr,
                        );

                        let mut msg: Message<Attribute> = Message::new(
                            MessageClass::Indication,
                            DATA,
                            TransactionId::new(random()),
                        );
                        msg.add_attribute(XorPeerAddress::new(src_addr));
                        let Ok(data) = Data::new(data.to_vec()) else {
                            log::error!("`DataIndication` is too long");
                            continue;
                        };
                        msg.add_attribute(data);

                        match MessageEncoder::new().encode_into_bytes(msg) {
                            Ok(encoded) => {
                                if let Err(e) = turn_socket
                                    .send_to(encoded, five_tuple.src_addr)
                                    .await
                                {
                                    log::error!(
                                        "Failed to send `DataIndication` from \
                                         `Allocation(src: {src_addr})`: {e}",
                                    );
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "`DataIndication` encoding failed: {e}",
                                );
                            }
                        }
                    } else {
                        log::info!(
                            "No `Permission` or `ChannelBind` exists for \
                             `{src_addr}` on `Allocation(relay: {relay_addr})`",
                        );
                    }
                }
            }
            drop(mem::take(&mut *channel_bindings.lock().await));
            drop(mem::take(&mut *permissions.lock().await));

            log::trace!(
                "`Allocation(five_tuple: {five_tuple})` stopped, stop \
                 `relay_handler`",
            );
        }));
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if let Some(notify_tx) = self.alloc_close_notify.take() {
            let info = Info {
                five_tuple: self.five_tuple,
                username: self.username.clone(),
                relayed_bytes: self.relayed_bytes.load(Ordering::Acquire),
            };

            drop(tokio::spawn(async move {
                drop(notify_tx.send(info).await);
            }));
        }
    }
}

#[cfg(test)]
mod spec {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        str::FromStr,
        sync::Arc,
    };

    use tokio::net::UdpSocket;

    use crate::{
        attr::{ChannelNumber, Username, PROTO_UDP},
        server::DEFAULT_LIFETIME,
    };

    use super::{Allocation, FiveTuple};

    impl Default for FiveTuple {
        fn default() -> Self {
            FiveTuple {
                protocol: PROTO_UDP,
                src_addr: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
                dst_addr: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
            }
        }
    }

    #[tokio::test]
    async fn has_permission() {
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

        let addr1 = SocketAddr::from_str("127.0.0.1:3478").unwrap();
        let addr2 = SocketAddr::from_str("127.0.0.1:3479").unwrap();
        let addr3 = SocketAddr::from_str("127.0.0.2:3478").unwrap();

        a.add_permission(addr1.ip()).await;
        a.add_permission(addr2.ip()).await;
        a.add_permission(addr3.ip()).await;

        let found_p1 = a.has_permission(&addr1).await;
        assert!(found_p1, "should keep the first one");

        let found_p2 = a.has_permission(&addr2).await;
        assert!(found_p2, "second one should be ignored");

        let found_p3 = a.has_permission(&addr3).await;
        assert!(found_p3, "`Permission` with another IP should be found");
    }

    #[tokio::test]
    async fn add_permission() {
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

        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();
        a.add_permission(addr.ip()).await;

        let found_p = a.has_permission(&addr).await;
        assert!(found_p, "should keep the first one");
    }

    #[tokio::test]
    async fn get_channel_by_number() {
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

        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();

        a.add_channel_bind(ChannelNumber::MIN, addr, DEFAULT_LIFETIME)
            .await
            .unwrap();

        let exist_channel_addr =
            a.get_channel_addr(&ChannelNumber::MIN).await.unwrap();
        assert_eq!(addr, exist_channel_addr);

        let not_exist_channel =
            a.get_channel_addr(&(ChannelNumber::MIN + 1)).await;
        assert!(not_exist_channel.is_none(), "found, but shouldn't");
    }

    #[tokio::test]
    async fn get_channel_by_addr() {
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

        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();
        let addr2 = SocketAddr::from_str("127.0.0.1:3479").unwrap();

        a.add_channel_bind(ChannelNumber::MIN, addr, DEFAULT_LIFETIME)
            .await
            .unwrap();

        let exist_channel_number = a.get_channel_number(&addr).await.unwrap();
        assert_eq!(ChannelNumber::MIN, exist_channel_number);

        let not_exist_channel = a.get_channel_number(&addr2).await;
        assert!(not_exist_channel.is_none(), "found, but shouldn't");
    }

    #[tokio::test]
    async fn closing() {
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

        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();
        a.add_channel_bind(ChannelNumber::MIN, addr, DEFAULT_LIFETIME)
            .await
            .unwrap();
        a.add_permission(addr.ip()).await;
    }
}

#[cfg(test)]
mod five_tuple_spec {
    use std::net::SocketAddr;

    use crate::{
        attr::{PROTO_TCP, PROTO_UDP},
        FiveTuple,
    };

    #[test]
    fn equality() {
        let src_addr1: SocketAddr =
            "0.0.0.0:3478".parse::<SocketAddr>().unwrap();
        let src_addr2: SocketAddr =
            "0.0.0.0:3479".parse::<SocketAddr>().unwrap();

        let dst_addr1: SocketAddr =
            "0.0.0.0:3480".parse::<SocketAddr>().unwrap();
        let dst_addr2: SocketAddr =
            "0.0.0.0:3481".parse::<SocketAddr>().unwrap();

        let tests = [
            (
                "Equal",
                true,
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
            ),
            (
                "DifferentProtocol",
                false,
                FiveTuple {
                    protocol: PROTO_TCP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
            ),
            (
                "DifferentSrcAddr",
                false,
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr2,
                    dst_addr: dst_addr1,
                },
            ),
            (
                "DifferentDstAddr",
                false,
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr2,
                },
            ),
        ];
        for (name, expect, a, b) in tests {
            let fact = a == b;
            assert_eq!(
                expect, fact,
                "{name}: {a}, {b} equal check should be {expect}, but {fact}",
            );
        }
    }
}
