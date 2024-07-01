//! [Allocation]s storage.
//!
//! [Allocation]: https://datatracker.ietf.org/doc/html/rfc5766#section-5

use std::{
    collections::HashMap,
    mem,
    sync::{atomic::Ordering, Arc, Mutex as SyncMutex},
    time::Duration,
};

use futures::future;
use tokio::{
    sync::{mpsc, Mutex},
    time::sleep,
};

use crate::{
    allocation::{Allocation, AllocationMap},
    attr::Username,
    con::Conn,
    relay::RelayAllocator,
    AllocInfo, Error, FiveTuple,
};

/// `ManagerConfig` a bag of config params for [`Manager`].
pub(crate) struct ManagerConfig {
    /// Relay connections allocator.
    pub(crate) relay_addr_generator: RelayAllocator,

    /// Injected into allocations to notify when allocation is closed.
    pub(crate) alloc_close_notify: Option<mpsc::Sender<AllocInfo>>,
}

/// [`Manager`] is used to hold active allocations.
pub(crate) struct Manager {
    /// [`Allocation`]s storage.
    allocations: AllocationMap,

    /// [Reservation][1]s storage.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-14.9
    reservations: Arc<Mutex<HashMap<u64, u16>>>,

    /// Relay connections allocator.
    relay_allocator: RelayAllocator,

    /// Injected into allocations to notify when allocation is closed.
    alloc_close_notify: Option<mpsc::Sender<AllocInfo>>,
}

impl Manager {
    /// Creates a new [`Manager`].
    pub(crate) fn new(config: ManagerConfig) -> Self {
        Self {
            allocations: Arc::new(SyncMutex::new(HashMap::new())),
            reservations: Arc::new(Mutex::new(HashMap::new())),
            relay_allocator: config.relay_addr_generator,
            alloc_close_notify: config.alloc_close_notify,
        }
    }

    /// Returns the information about the all [`Allocation`]s associated with
    /// the specified [`FiveTuple`]s.
    pub(crate) fn get_allocations_info(
        &self,
        five_tuples: &Option<Vec<FiveTuple>>,
    ) -> HashMap<FiveTuple, AllocInfo> {
        let mut infos = HashMap::new();

        #[allow(
            clippy::unwrap_used,
            clippy::iter_over_hash_type,
            clippy::significant_drop_in_scrutinee
        )]
        for (five_tuple, alloc) in self.allocations.lock().unwrap().iter() {
            #[allow(clippy::unwrap_used)]
            if five_tuples.is_none()
                || five_tuples.as_ref().unwrap().contains(five_tuple)
            {
                drop(infos.insert(
                    *five_tuple,
                    AllocInfo::new(
                        *five_tuple,
                        alloc.username.name().to_owned(),
                        alloc.relayed_bytes.load(Ordering::Acquire),
                    ),
                ));
            }
        }

        infos
    }

    /// Fetches the [`Allocation`] matching the passed [`FiveTuple`].
    pub(crate) fn has_alloc(&self, five_tuple: &FiveTuple) -> bool {
        #[allow(clippy::unwrap_used)]
        self.allocations.lock().unwrap().get(five_tuple).is_some()
    }

    /// Fetches the [`Allocation`] matching the passed [`FiveTuple`].
    #[allow(clippy::unwrap_in_result)]
    pub(crate) fn get_alloc(
        &self,
        five_tuple: &FiveTuple,
    ) -> Option<Arc<Allocation>> {
        #[allow(clippy::unwrap_used)]
        self.allocations.lock().unwrap().get(five_tuple).cloned()
    }

    /// Creates a new [`Allocation`] and starts relaying.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_allocation(
        &self,
        five_tuple: FiveTuple,
        turn_socket: Arc<dyn Conn + Send + Sync>,
        requested_port: u16,
        lifetime: Duration,
        username: Username,
        use_ipv4: bool,
    ) -> Result<Arc<Allocation>, Error> {
        if lifetime == Duration::from_secs(0) {
            return Err(Error::LifetimeZero);
        }

        if self.has_alloc(&five_tuple) {
            return Err(Error::DupeFiveTuple);
        }

        let (relay_socket, relay_addr) = self
            .relay_allocator
            .allocate_conn(use_ipv4, requested_port)
            .await?;
        let alloc = Arc::new(Allocation::new(
            turn_socket,
            relay_socket,
            relay_addr,
            five_tuple,
            lifetime,
            Arc::clone(&self.allocations),
            username,
            self.alloc_close_notify.clone(),
        ));

        #[allow(clippy::unwrap_used)]
        drop(
            self.allocations
                .lock()
                .unwrap()
                .insert(five_tuple, Arc::clone(&alloc)),
        );

        Ok(alloc)
    }

    /// Removes an [`Allocation`].
    pub(crate) async fn delete_allocation(&self, five_tuple: &FiveTuple) {
        #[allow(clippy::unwrap_used)]
        let allocation = self.allocations.lock().unwrap().remove(five_tuple);

        if let Some(a) = allocation {
            if let Err(err) = a.close().await {
                log::error!("Failed to close allocation: {}", err);
            }
        }
    }

    /// Deletes the [`Allocation`]s according to the specified username `name`.
    pub(crate) async fn delete_allocations_by_username(&self, name: &str) {
        let to_delete = {
            #[allow(clippy::unwrap_used)]
            let mut allocations = self.allocations.lock().unwrap();

            let mut to_delete = Vec::new();

            // TODO(logist322): Use `.drain_filter()` once stabilized.
            allocations.retain(|_, allocation| {
                let match_name = allocation.username.name() == name;

                if match_name {
                    to_delete.push(Arc::clone(allocation));
                }

                !match_name
            });

            to_delete
        };

        drop(
            future::join_all(to_delete.iter().map(|a| async move {
                if let Err(err) = a.close().await {
                    log::error!("Failed to close allocation: {}", err);
                }
            }))
            .await,
        );
    }

    /// Stores the reservation for the token+port.
    pub(crate) async fn create_reservation(&self, token: u64, port: u16) {
        let reservations = Arc::clone(&self.reservations);

        drop(tokio::spawn(async move {
            let liftime = sleep(Duration::from_secs(30));
            tokio::pin!(liftime);

            tokio::select! {
                () = &mut liftime => {
                    _ = reservations.lock().await.remove(&token);
                },
            }
        }));

        _ = self.reservations.lock().await.insert(token, port);
    }

    /// Returns a random un-allocated udp4 port.
    pub(crate) async fn get_random_even_port(&self) -> Result<u16, Error> {
        let (_, addr) = self.relay_allocator.allocate_conn(true, 0).await?;
        Ok(addr.port())
    }

    /// Closes this [`Manager`] and closes all [`Allocation`]s it manages.
    pub(crate) async fn close(&self) -> Result<(), Error> {
        #[allow(clippy::unwrap_used)]
        let allocations = mem::take(&mut *self.allocations.lock().unwrap());

        #[allow(clippy::iter_over_hash_type)]
        for a in allocations.values() {
            a.close().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod allocation_manager_test {
    use bytecodec::DecodeExt;
    use rand::random;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };
    use stun_codec::MessageDecoder;
    use tokio::net::UdpSocket;

    use crate::{
        attr::{Attribute, ChannelNumber, Data},
        chandata::ChannelData,
        server::DEFAULT_LIFETIME,
    };

    use super::*;

    fn new_test_manager() -> Manager {
        let config = ManagerConfig {
            relay_addr_generator: RelayAllocator {
                relay_address: IpAddr::from([127, 0, 0, 1]),
                min_port: 49152,
                max_port: 65535,
                max_retries: 10,
                address: String::from("127.0.0.1"),
            },
            alloc_close_notify: None,
        };
        Manager::new(config)
    }

    fn random_five_tuple() -> FiveTuple {
        FiveTuple {
            src_addr: SocketAddr::new(
                Ipv4Addr::new(0, 0, 0, 0).into(),
                random(),
            ),
            dst_addr: SocketAddr::new(
                Ipv4Addr::new(0, 0, 0, 0).into(),
                random(),
            ),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_packet_handler() {
        // turn server initialization
        let turn_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // client listener initialization
        let client_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src_addr = client_listener.local_addr().unwrap();
        let (data_ch_tx, mut data_ch_rx) = mpsc::channel(1);
        // client listener read data
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 1500];
            loop {
                let n = match client_listener.recv_from(&mut buffer).await {
                    Ok((n, _)) => n,
                    Err(_) => break,
                };

                let _ = data_ch_tx.send(buffer[..n].to_vec()).await;
            }
        });

        let m = new_test_manager();
        let a = m
            .create_allocation(
                FiveTuple {
                    src_addr,
                    dst_addr: turn_socket.local_addr().unwrap(),
                    ..Default::default()
                },
                Arc::new(turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();

        let peer_listener1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_listener2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let port = {
            // add permission with peer1 address
            a.add_permission(peer_listener1.local_addr().unwrap().ip()).await;
            // add channel with min channel number and peer2 address
            a.add_channel_bind(
                ChannelNumber::MIN,
                peer_listener2.local_addr().unwrap(),
                DEFAULT_LIFETIME,
            )
            .await
            .unwrap();

            a.relay_socket.local_addr().unwrap().port()
        };

        let relay_addr_with_host_str = format!("127.0.0.1:{port}");
        let relay_addr_with_host =
            SocketAddr::from_str(&relay_addr_with_host_str).unwrap();

        // test for permission and data message
        let target_text = "permission";
        let _ = peer_listener1
            .send_to(target_text.as_bytes(), relay_addr_with_host)
            .await
            .unwrap();
        let data = data_ch_rx.recv().await.unwrap();

        let msg = MessageDecoder::<Attribute>::new()
            .decode_from_bytes(&data)
            .unwrap()
            .unwrap();

        let msg_data = msg.get_attribute::<Data>().unwrap().data().to_vec();
        assert_eq!(
            target_text.as_bytes(),
            &msg_data,
            "get message doesn't equal the target text"
        );

        // test for channel bind and channel data
        let target_text2 = "channel bind";
        let _ = peer_listener2
            .send_to(target_text2.as_bytes(), relay_addr_with_host)
            .await
            .unwrap();
        let data = data_ch_rx.recv().await.unwrap();

        // resolve channel data
        assert!(ChannelData::is_channel_data(&data), "should be channel data");

        let channel_data = ChannelData::decode(data).unwrap();
        assert_eq!(
            ChannelNumber::MIN,
            channel_data.num(),
            "get channel data's number is invalid"
        );
        assert_eq!(
            target_text2.as_bytes(),
            &channel_data.data(),
            "get data doesn't equal the target text."
        );

        // listeners close
        m.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_create_allocation_duplicate_five_tuple() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let five_tuple = random_five_tuple();

        let _ = m
            .create_allocation(
                five_tuple,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();

        let result = m
            .create_allocation(
                five_tuple,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await;
        assert!(result.is_err(), "expected error, but got ok");
    }

    #[tokio::test]
    async fn test_delete_allocation() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let five_tuple = random_five_tuple();

        let _ = m
            .create_allocation(
                five_tuple,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();

        assert!(
            m.has_alloc(&five_tuple),
            "Failed to get allocation right after creation"
        );

        m.delete_allocation(&five_tuple).await;

        assert!(
            !m.has_alloc(&five_tuple),
            "Get allocation with {five_tuple} should be nil after delete"
        );
    }

    #[tokio::test]
    async fn test_allocation_timeout() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let mut allocations = vec![];
        let lifetime = Duration::from_millis(100);

        for _ in 0..5 {
            let five_tuple = random_five_tuple();

            let a = m
                .create_allocation(
                    five_tuple,
                    Arc::clone(&turn_socket),
                    0,
                    lifetime,
                    Username::new(String::from("user")).unwrap(),
                    true,
                )
                .await
                .unwrap();

            allocations.push(a);
        }

        let mut count = 0;

        'outer: loop {
            count += 1;

            if count >= 10 {
                panic!("Allocations didn't timeout");
            }

            sleep(lifetime + Duration::from_millis(100)).await;

            let any_outstanding = false;

            for a in &allocations {
                if a.close().await.is_ok() {
                    continue 'outer;
                }
            }

            if !any_outstanding {
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_manager_close() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let mut allocations = vec![];

        let a1 = m
            .create_allocation(
                random_five_tuple(),
                Arc::clone(&turn_socket),
                0,
                Duration::from_millis(100),
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();
        allocations.push(a1);

        let a2 = m
            .create_allocation(
                random_five_tuple(),
                Arc::clone(&turn_socket),
                0,
                Duration::from_millis(200),
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();
        allocations.push(a2);

        sleep(Duration::from_millis(150)).await;

        log::trace!("Mgr is going to be closed...");

        m.close().await.unwrap();

        for a in allocations {
            assert!(
                a.close().await.is_err(),
                "Allocation should be closed if lifetime timeout"
            );
        }
    }

    #[tokio::test]
    async fn test_delete_allocation_by_username() {
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let five_tuple1 = random_five_tuple();
        let five_tuple2 = random_five_tuple();
        let five_tuple3 = random_five_tuple();

        let _ = m
            .create_allocation(
                five_tuple1,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();
        let _ = m
            .create_allocation(
                five_tuple2,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();
        let _ = m
            .create_allocation(
                five_tuple3,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user2")).unwrap(),
                true,
            )
            .await
            .unwrap();

        assert_eq!(m.allocations.lock().unwrap().len(), 3);

        m.delete_allocations_by_username("user").await;

        assert_eq!(m.allocations.lock().unwrap().len(), 1);

        assert!(
            m.get_alloc(&five_tuple1).is_none()
                && m.get_alloc(&five_tuple2).is_none()
                && m.get_alloc(&five_tuple3).is_some()
        );
    }
}
