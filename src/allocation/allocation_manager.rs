//! [Allocation]s storage.
//!
//! [Allocation]: https://datatracker.ietf.org/doc/html/rfc5766#section-5

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use tokio::sync::mpsc;

use crate::{
    allocation::Allocation, attr::Username, con::Conn, relay::RelayAllocator,
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
    allocations: HashMap<FiveTuple, Allocation>,

    /// Relay connections allocator.
    relay_allocator: RelayAllocator,

    /// Injected into allocations to notify when allocation is closed.
    alloc_close_notify: Option<mpsc::Sender<AllocInfo>>,
}

impl Manager {
    /// Creates a new [`Manager`].
    pub(crate) fn new(config: ManagerConfig) -> Self {
        Self {
            allocations: HashMap::default(),
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

        #[allow(clippy::iter_over_hash_type)]
        for (five_tuple, alloc) in &self.allocations {
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

    /// Creates a new [`Allocation`] and starts relaying.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_allocation(
        &mut self,
        five_tuple: FiveTuple,
        turn_socket: Arc<dyn Conn + Send + Sync>,
        requested_port: u16,
        lifetime: Duration,
        username: Username,
        use_ipv4: bool,
    ) -> Result<SocketAddr, Error> {
        if lifetime == Duration::from_secs(0) {
            return Err(Error::LifetimeZero);
        }

        self.allocations.retain(|_, v| v.alive());

        if self.get_alloc(&five_tuple).is_some() {
            return Err(Error::DupeFiveTuple);
        }

        let (relay_socket, relay_addr) = self
            .relay_allocator
            .allocate_conn(use_ipv4, requested_port)
            .await?;
        let alloc = Allocation::new(
            turn_socket,
            relay_socket,
            relay_addr,
            five_tuple,
            lifetime,
            username,
            self.alloc_close_notify.clone(),
        );

        drop(self.allocations.insert(five_tuple, alloc));

        Ok(relay_addr)
    }

    /// Fetches the [`Allocation`] matching the passed [`FiveTuple`].
    pub(crate) fn get_alloc(
        &mut self,
        five_tuple: &FiveTuple,
    ) -> Option<&Allocation> {
        self.allocations.get(five_tuple).and_then(|a| a.alive().then_some(a))
    }

    /// Removes an [`Allocation`].
    pub(crate) fn delete_allocation(&mut self, five_tuple: &FiveTuple) {
        drop(self.allocations.remove(five_tuple));
    }

    /// Deletes the [`Allocation`]s according to the specified username `name`.
    pub(crate) fn delete_allocations_by_username(&mut self, name: &str) {
        self.allocations
            .retain(|_, allocation| allocation.username.name() != name);
    }

    /// Returns a random un-allocated udp4 port.
    pub(crate) async fn get_random_even_port(&self) -> Result<u16, Error> {
        let (_, addr) = self.relay_allocator.allocate_conn(true, 0).await?;
        Ok(addr.port())
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
    use tokio::{net::UdpSocket, time::sleep};

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
        drop(tokio::spawn(async move {
            let mut buffer = vec![0u8; 1500];
            loop {
                let n = match client_listener.recv_from(&mut buffer).await {
                    Ok((n, _)) => n,
                    Err(_) => break,
                };

                drop(data_ch_tx.send(buffer[..n].to_vec()).await);
            }
        }));

        let five_tuple = FiveTuple {
            src_addr,
            dst_addr: turn_socket.local_addr().unwrap(),
            ..Default::default()
        };
        let mut m = new_test_manager();
        _ = m
            .create_allocation(
                five_tuple,
                Arc::new(turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();
        let a = m.get_alloc(&five_tuple).unwrap();

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
    }

    #[tokio::test]
    async fn test_create_allocation_duplicate_five_tuple() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut m = new_test_manager();

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

        let mut m = new_test_manager();

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
            m.get_alloc(&five_tuple).is_some(),
            "Failed to get allocation right after creation"
        );

        m.delete_allocation(&five_tuple);

        assert!(
            !m.get_alloc(&five_tuple).is_some(),
            "Get allocation with {five_tuple} should be nil after delete"
        );
    }

    #[tokio::test]
    async fn test_allocation_timeout() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut m = new_test_manager();

        let mut allocations = vec![];
        let lifetime = Duration::from_millis(100);

        for _ in 0..5 {
            let five_tuple = random_five_tuple();

            _ = m
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

            allocations.push(five_tuple);
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
                if m.get_alloc(a).is_some() {
                    continue 'outer;
                }
            }

            if !any_outstanding {
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_delete_allocation_by_username() {
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut m = new_test_manager();

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

        assert_eq!(m.allocations.len(), 3);

        m.delete_allocations_by_username("user");

        assert_eq!(m.allocations.len(), 1);

        assert!(m.get_alloc(&five_tuple1).is_none());
        assert!(m.get_alloc(&five_tuple2).is_none());
        assert!(m.get_alloc(&five_tuple3).is_some());
    }
}
