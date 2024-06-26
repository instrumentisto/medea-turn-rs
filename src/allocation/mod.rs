//! TURN server [Allocation].
//!
//! [Allocation]:https://datatracker.ietf.org/doc/html/rfc5766#section-5

mod allocation_manager;
mod channel_bind;
mod permission;

use std::{
    collections::HashMap,
    fmt,
    marker::{Send, Sync},
    mem,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex as SyncMutex,
    },
};

use bytecodec::EncodeExt;
use rand::random;
use stun_codec::{
    rfc5766::methods::DATA, Message, MessageClass, MessageEncoder,
    TransactionId,
};
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc,
        oneshot::{self, Sender},
        Mutex,
    },
    time::{sleep, Duration, Instant},
};

use crate::{
    allocation::permission::PERMISSION_LIFETIME,
    attr::{Attribute, Data, Username, XorPeerAddress},
    chandata::ChannelData,
    con::Conn,
    server::INBOUND_MTU,
    Error,
};

use self::{channel_bind::ChannelBind, permission::Permission};

pub(crate) use allocation_manager::{Manager, ManagerConfig};

/// [`Allocation`]s storage.
pub(crate) type AllocationMap =
    Arc<SyncMutex<HashMap<FiveTuple, Arc<Allocation>>>>;

/// Information about an allocation.
#[derive(Debug, Clone)]
pub struct AllocInfo {
    /// [`FiveTuple`] of this allocation.
    pub five_tuple: FiveTuple,

    /// Username of this allocation.
    pub username: String,

    /// Relayed bytes with this allocation.
    pub relayed_bytes: usize,
}

impl AllocInfo {
    /// Creates a new [`AllocInfo`].
    #[must_use]
    pub const fn new(
        five_tuple: FiveTuple,
        username: String,
        relayed_bytes: usize,
    ) -> Self {
        Self {
            five_tuple,
            username,
            relayed_bytes,
        }
    }
}

/// The tuple (source IP address, source port, destination IP
/// address, destination port, transport protocol).  A 5-tuple
/// uniquely identifies a UDP/TCP session.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct FiveTuple {
    /// Transport protocol according to [IANA] protocol numbers.
    ///
    /// [IANA]: https://tinyurl.com/iana-protocol-numbers
    pub protocol: u8,

    /// Packet source address.
    pub src_addr: SocketAddr,

    /// Packet target address.
    pub dst_addr: SocketAddr,
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}_{}", self.protocol, self.src_addr, self.dst_addr)
    }
}

/// TURN server [Allocation].
///
/// [Allocation]:https://datatracker.ietf.org/doc/html/rfc5766#section-5
pub(crate) struct Allocation {
    /// [`Conn`] used to create this [`Allocation`].
    turn_socket: Arc<dyn Conn + Send + Sync>,

    /// Relay socket address.
    relay_addr: SocketAddr,

    /// Allocated relay socket.
    relay_socket: Arc<UdpSocket>,

    /// [`FiveTuple`] this allocation is created with.
    five_tuple: FiveTuple,

    /// Remote user ICE [`Username`].
    username: Username,

    /// List of [`Permission`]s for this [`Allocation`]
    permissions: Arc<Mutex<HashMap<IpAddr, Permission>>>,

    /// This [`Allocation`] [`ChannelBind`]ings.
    channel_bindings: Arc<Mutex<HashMap<u16, ChannelBind>>>,

    /// All [`Allocation`]s storage.
    allocations: Option<AllocationMap>,

    /// Channel to the internal loop used to update lifetime or drop
    /// allocation.
    reset_tx: SyncMutex<Option<mpsc::Sender<Duration>>>,

    /// Total number of relayed bytes.
    relayed_bytes: AtomicUsize,

    /// Channel to the packet handler loop used to stop it.
    drop_tx: Option<Sender<u32>>,

    /// Injected into allocations to notify when allocation is closed.
    alloc_close_notify: Option<mpsc::Sender<AllocInfo>>,
}

impl Allocation {
    /// Creates a new [`Allocation`].
    pub(crate) fn new(
        turn_socket: Arc<dyn Conn + Send + Sync>,
        relay_socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        five_tuple: FiveTuple,
        username: Username,
        alloc_close_notify: Option<mpsc::Sender<AllocInfo>>,
    ) -> Self {
        Self {
            turn_socket,
            relay_addr,
            relay_socket,
            five_tuple,
            username,
            permissions: Arc::new(Mutex::new(HashMap::new())),
            channel_bindings: Arc::new(Mutex::new(HashMap::new())),
            allocations: None,
            reset_tx: SyncMutex::new(None),
            relayed_bytes: AtomicUsize::default(),
            drop_tx: None,
            alloc_close_notify,
        }
    }

    /// Send the given data via associated relay socket.
    pub(crate) async fn relay(
        &self,
        data: &[u8],
        to: SocketAddr,
    ) -> Result<(), Error> {
        match self.relay_socket.send_to(data, to).await {
            Ok(n) => {
                _ = self.relayed_bytes.fetch_add(n, Ordering::AcqRel);

                Ok(())
            }
            Err(err) => Err(Error::from(err)),
        }
    }

    /// Returns [`SocketAddr`] of the associated relay socket.
    pub(crate) const fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Checks the Permission for the `addr`.
    pub(crate) async fn has_permission(&self, addr: &SocketAddr) -> bool {
        self.permissions.lock().await.get(&addr.ip()).is_some()
    }

    /// Adds a new [`Permission`] to this [`Allocation`].
    pub(crate) async fn add_permission(&self, ip: IpAddr) {
        let mut permissions = self.permissions.lock().await;

        if let Some(existed_permission) = permissions.get(&ip) {
            existed_permission.refresh(PERMISSION_LIFETIME).await;
        } else {
            let mut p = Permission::new(ip);
            p.start(Arc::clone(&self.permissions), PERMISSION_LIFETIME);
            drop(permissions.insert(p.ip(), p));
        }
    }

    /// Adds a new [`ChannelBind`] to this [`Allocation`], it also updates the
    /// permissions needed for this [`ChannelBind`].
    #[allow(clippy::significant_drop_tightening)] // false-positive
    pub(crate) async fn add_channel_bind(
        &self,
        number: u16,
        peer_addr: SocketAddr,
        lifetime: Duration,
    ) -> Result<(), Error> {
        // The channel number is not currently bound to a different transport
        // address (same transport address is OK);
        if let Some(addr) = self.get_channel_addr(&number).await {
            if addr != peer_addr {
                return Err(Error::SameChannelDifferentPeer);
            }
        }

        // The transport address is not currently bound to a different
        // channel number.
        if let Some(n) = self.get_channel_number(&peer_addr).await {
            if number != n {
                return Err(Error::SamePeerDifferentChannel);
            }
        }

        let mut channel_bindings = self.channel_bindings.lock().await;
        if let Some(cb) = channel_bindings.get(&number).cloned() {
            drop(channel_bindings);

            cb.refresh(lifetime).await;

            // Channel binds also refresh permissions.
            self.add_permission(cb.peer().ip()).await;
        } else {
            let mut bind = ChannelBind::new(number, peer_addr);
            bind.start(Arc::clone(&self.channel_bindings), lifetime);

            drop(channel_bindings.insert(number, bind));

            // Channel binds also refresh permissions.
            self.add_permission(peer_addr.ip()).await;
        }
        Ok(())
    }

    /// Gets the [`ChannelBind`]'s address by `number`.
    pub(crate) async fn get_channel_addr(
        &self,
        number: &u16,
    ) -> Option<SocketAddr> {
        self.channel_bindings
            .lock()
            .await
            .get(number)
            .map(ChannelBind::peer)
    }

    /// Gets the [`ChannelBind`]'s number from this [`Allocation`] by `addr`.
    pub(crate) async fn get_channel_number(
        &self,
        addr: &SocketAddr,
    ) -> Option<u16> {
        self.channel_bindings
            .lock()
            .await
            .values()
            .find_map(|b| (b.peer() == *addr).then_some(b.num()))
    }

    /// Closes the [`Allocation`].
    pub(crate) async fn close(&self) -> Result<(), Error> {
        #[allow(clippy::unwrap_used)]
        if self.reset_tx.lock().unwrap().take().is_none() {
            return Err(Error::Closed);
        }

        drop(mem::take(&mut *self.permissions.lock().await));
        drop(mem::take(&mut *self.channel_bindings.lock().await));

        log::trace!("allocation with {} closed!", self.five_tuple);

        drop(self.relay_socket.close().await);

        if let Some(notify_tx) = &self.alloc_close_notify {
            drop(
                notify_tx
                    .send(AllocInfo {
                        five_tuple: self.five_tuple,
                        username: self.username.name().to_owned(),
                        relayed_bytes: self
                            .relayed_bytes
                            .load(Ordering::Acquire),
                    })
                    .await,
            );
        }

        Ok(())
    }

    /// Starts the internal lifetime watching loop.
    pub(crate) fn start(&self, lifetime: Duration) {
        let (reset_tx, mut reset_rx) = mpsc::channel(1);
        #[allow(clippy::unwrap_used)]
        drop(self.reset_tx.lock().unwrap().replace(reset_tx));

        let allocations = self.allocations.clone();
        let five_tuple = self.five_tuple;

        drop(tokio::spawn(async move {
            let timer = sleep(lifetime);
            tokio::pin!(timer);

            loop {
                tokio::select! {
                    () = &mut timer => {
                        if let Some(allocs) = &allocations{
                            #[allow(clippy::unwrap_used)]
                            let alloc = allocs
                                .lock()
                                .unwrap()
                                .remove(&five_tuple);

                            if let Some(a) = alloc {
                                drop(a.close().await);
                            }
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

    /// Updates the allocations lifetime.
    pub(crate) async fn refresh(&self, lifetime: Duration) {
        #[allow(clippy::unwrap_used)]
        let reset_tx = self.reset_tx.lock().unwrap().clone();

        if let Some(tx) = reset_tx {
            _ = tx.send(lifetime).await;
        }
    }

    ///  When the server receives a UDP datagram at a currently allocated
    ///  relayed transport address, the server looks up the allocation
    ///  associated with the relayed transport address.  The server then
    ///  checks to see whether the set of permissions for the allocation allow
    ///  the relaying of the UDP datagram as described in Section 8.
    ///
    ///  If relaying is permitted, then the server checks if there is a
    ///  channel bound to the peer that sent the UDP datagram (see
    ///  Section 11).  If a channel is bound, then processing proceeds as
    ///  described in Section 11.7.
    ///
    ///  If relaying is permitted but no channel is bound to the peer, then
    ///  the server forms and sends a Data indication.  The Data indication
    ///  MUST contain both an XOR-PEER-ADDRESS and a DATA attribute.  The DATA
    ///  attribute is set to the value of the 'data octets' field from the
    ///  datagram, and the XOR-PEER-ADDRESS attribute is set to the source
    ///  transport address of the received UDP datagram.  The Data indication
    ///  is then sent on the 5-tuple associated with the allocation.
    #[allow(clippy::too_many_lines)]
    fn packet_handler(&mut self) {
        let five_tuple = self.five_tuple;
        let relay_addr = self.relay_addr;
        let relay_socket = Arc::clone(&self.relay_socket);
        let turn_socket = Arc::clone(&self.turn_socket);
        let allocations = self.allocations.clone();
        let channel_bindings = Arc::clone(&self.channel_bindings);
        let permissions = Arc::clone(&self.permissions);
        let (drop_tx, drop_rx) = oneshot::channel::<u32>();
        self.drop_tx = Some(drop_tx);

        drop(tokio::spawn(async move {
            let mut buffer = vec![0u8; INBOUND_MTU];

            tokio::pin!(drop_rx);
            loop {
                let (n, src_addr) = tokio::select! {
                    result = relay_socket.recv_from(&mut buffer) => {
                        if let Ok((data, src_addr)) = result {
                            (data, src_addr)
                        } else {
                            if let Some(allocs) = &allocations {
                                #[allow(clippy::unwrap_used)]
                                drop(
                                    allocs.lock().unwrap().remove(&five_tuple)
                                );
                            }
                            break;
                        }
                    }
                    _ = drop_rx.as_mut() => {
                        log::trace!("allocation has stopped, \
                            stop packet_handler. five_tuple: {:?}",
                            five_tuple);
                        break;
                    }
                };

                let cb_number = {
                    let mut cb_number = None;
                    #[allow(
                        clippy::iter_over_hash_type,
                        clippy::significant_drop_in_scrutinee
                    )]
                    for cb in channel_bindings.lock().await.values() {
                        if cb.peer() == src_addr {
                            cb_number = Some(cb.num());
                            break;
                        }
                    }
                    cb_number
                };

                if let Some(number) = cb_number {
                    match ChannelData::encode(buffer[..n].to_vec(), number) {
                        Ok(data) => {
                            if let Err(err) = turn_socket
                                .send_to(data, five_tuple.src_addr)
                                .await
                            {
                                log::error!(
                                    "Failed to send ChannelData from \
                                    allocation {src_addr}: {err}",
                                );
                            }
                        }
                        Err(err) => {
                            log::error!(
                                "Failed to send ChannelData from allocation \
                                {src_addr}: {err}"
                            );
                        }
                    };
                } else {
                    let exist =
                        permissions.lock().await.get(&src_addr.ip()).is_some();

                    if exist {
                        log::trace!(
                            "relaying message from {} to client at {}",
                            src_addr,
                            five_tuple.src_addr
                        );

                        let mut msg: Message<Attribute> = Message::new(
                            MessageClass::Indication,
                            DATA,
                            TransactionId::new(random()),
                        );
                        msg.add_attribute(XorPeerAddress::new(src_addr));
                        let Ok(data) = Data::new(buffer[..n].to_vec()) else {
                            log::error!("DataIndication is too long");
                            continue;
                        };
                        msg.add_attribute(data);

                        match MessageEncoder::new().encode_into_bytes(msg) {
                            Ok(encoded) => {
                                if let Err(err) = turn_socket
                                    .send_to(encoded, five_tuple.src_addr)
                                    .await
                                {
                                    log::error!(
                                        "Failed to send DataIndication from \
                                        allocation {} {}",
                                        src_addr,
                                        err
                                    );
                                }
                            }
                            Err(e) => {
                                log::error!("DataIndication encode err: {e}");
                            }
                        }
                    } else {
                        log::info!(
                            "No Permission or Channel exists for {} on \
                                allocation {}",
                            src_addr,
                            relay_addr
                        );
                    }
                }
            }
        }));
    }
}

#[cfg(test)]
mod allocation_test {
    use std::{net::Ipv4Addr, str::FromStr};

    use tokio::net::UdpSocket;

    use super::*;

    use crate::{
        attr::{ChannelNumber, PROTO_UDP},
        server::DEFAULT_LIFETIME,
    };

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
    async fn test_has_permission() {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
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

        let addr1 = SocketAddr::from_str("127.0.0.1:3478").unwrap();
        let addr2 = SocketAddr::from_str("127.0.0.1:3479").unwrap();
        let addr3 = SocketAddr::from_str("127.0.0.2:3478").unwrap();

        a.add_permission(addr1.ip()).await;
        a.add_permission(addr2.ip()).await;
        a.add_permission(addr3.ip()).await;

        let found_p1 = a.has_permission(&addr1).await;
        assert!(found_p1, "Should keep the first one.");

        let found_p2 = a.has_permission(&addr2).await;
        assert!(found_p2, "Second one should be ignored.");

        let found_p3 = a.has_permission(&addr3).await;
        assert!(found_p3, "Permission with another IP should be found");
    }

    #[tokio::test]
    async fn test_add_permission() {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
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

        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();
        a.add_permission(addr.ip()).await;

        let found_p = a.has_permission(&addr).await;
        assert!(found_p, "Should keep the first one.");
    }

    #[tokio::test]
    async fn test_get_channel_by_number() {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
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

        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();

        a.add_channel_bind(ChannelNumber::MIN, addr, DEFAULT_LIFETIME)
            .await
            .unwrap();

        let exist_channel_addr =
            a.get_channel_addr(&ChannelNumber::MIN).await.unwrap();
        assert_eq!(addr, exist_channel_addr);

        let not_exist_channel =
            a.get_channel_addr(&(ChannelNumber::MIN + 1)).await;
        assert!(
            not_exist_channel.is_none(),
            "should be nil for not existed channel."
        );
    }

    #[tokio::test]
    async fn test_get_channel_by_addr() {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
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

        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();
        let addr2 = SocketAddr::from_str("127.0.0.1:3479").unwrap();

        a.add_channel_bind(ChannelNumber::MIN, addr, DEFAULT_LIFETIME)
            .await
            .unwrap();

        let exist_channel_number = a.get_channel_number(&addr).await.unwrap();
        assert_eq!(ChannelNumber::MIN, exist_channel_number);

        let not_exist_channel = a.get_channel_number(&addr2).await;
        assert!(
            not_exist_channel.is_none(),
            "should be nil for not existed channel."
        );
    }

    #[tokio::test]
    async fn test_allocation_close() {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
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

        // add mock lifetimeTimer
        a.start(DEFAULT_LIFETIME);

        // add channel
        let addr = SocketAddr::from_str("127.0.0.1:3478").unwrap();

        a.add_channel_bind(ChannelNumber::MIN, addr, DEFAULT_LIFETIME)
            .await
            .unwrap();

        // add permission
        a.add_permission(addr.ip()).await;

        a.close().await.unwrap();
    }
}

#[cfg(test)]
mod five_tuple_test {
    use std::net::SocketAddr;

    use crate::{
        attr::{PROTO_TCP, PROTO_UDP},
        FiveTuple,
    };

    #[test]
    fn test_five_tuple_equal() {
        let src_addr1: SocketAddr =
            "0.0.0.0:3478".parse::<SocketAddr>().unwrap();
        let src_addr2: SocketAddr =
            "0.0.0.0:3479".parse::<SocketAddr>().unwrap();

        let dst_addr1: SocketAddr =
            "0.0.0.0:3480".parse::<SocketAddr>().unwrap();
        let dst_addr2: SocketAddr =
            "0.0.0.0:3481".parse::<SocketAddr>().unwrap();

        let tests = vec![
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
                "{name}: {a}, {b} equal check should be {expect}, but {fact}"
            );
        }
    }
}
