//! Storage of [allocation]s.
//!
//! [allocation]: https://tools.ietf.org/html/rfc5766#section-5

use std::{
    collections::HashMap, net::SocketAddr, sync::atomic::Ordering,
    time::Duration,
};

use tokio::sync::mpsc;

use crate::{attr::Username, relay, Error};

use super::{Allocation, DynTransport, FiveTuple, Info};

/// Configuration parameters of a [`Manager`].
#[derive(Debug)]
pub(crate) struct Config {
    /// [`relay::Allocator`] of connections.
    pub(crate) relay_addr_generator: relay::Allocator,

    /// [`mpsc::Sender`] for notifying when an [`Allocation`] is closed.
    pub(crate) alloc_close_notify: Option<mpsc::Sender<Info>>,
}

/// [`Manager`] holding active [`Allocation`]s.
#[derive(Debug)]
pub(crate) struct Manager {
    /// Stored [`Allocation`]s.
    allocations: HashMap<FiveTuple, Allocation>,

    /// [`relay::Allocator`] of connections.
    relay_allocator: relay::Allocator,

    /// [`mpsc::Sender`] for notifying when an [`Allocation`] is closed.
    alloc_close_notify: Option<mpsc::Sender<Info>>,
}

impl Manager {
    /// Creates a new [`Manager`] out of the provided [`Config`].
    pub(crate) fn new(config: Config) -> Self {
        Self {
            allocations: HashMap::default(),
            relay_allocator: config.relay_addr_generator,
            alloc_close_notify: config.alloc_close_notify,
        }
    }

    /// Returns information about all the [`Allocation`]s associated with the
    /// provided [`FiveTuple`]s.
    pub(crate) fn get_allocations_info(
        &self,
        five_tuples: &Option<Vec<FiveTuple>>,
    ) -> HashMap<FiveTuple, Info> {
        let mut infos = HashMap::new();

        #[expect( // order doesn't matter here
            clippy::iter_over_hash_type,
            reason = "order doesn't matter here",
        )]
        for (five_tuple, alloc) in &self.allocations {
            if five_tuples.as_ref().map_or(true, |f| f.contains(five_tuple)) {
                drop(infos.insert(
                    *five_tuple,
                    Info::new(
                        *five_tuple,
                        alloc.username.clone(),
                        alloc.relayed_bytes.load(Ordering::Acquire),
                    ),
                ));
            }
        }

        infos
    }

    /// Creates a new [`Allocation`] with provided parameters and starts
    /// relaying it.
    pub(crate) async fn create_allocation(
        &mut self,
        five_tuple: FiveTuple,
        turn_socket: DynTransport,
        requested_port: u16,
        lifetime: Duration,
        username: Username,
        use_ipv4: bool,
    ) -> Result<SocketAddr, Error> {
        if lifetime == Duration::from_secs(0) {
            return Err(Error::LifetimeZero);
        }

        self.allocations.retain(|_, v| v.is_alive());

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

    /// Returns the [`Allocation`] matching the provided [`FiveTuple`], if any.
    pub(crate) fn get_alloc(
        &self,
        five_tuple: &FiveTuple,
    ) -> Option<&Allocation> {
        self.allocations.get(five_tuple).and_then(|a| a.is_alive().then_some(a))
    }

    /// Removes the [`Allocation`] matching the provided [`FiveTuple`], if any.
    pub(crate) fn delete_allocation(&mut self, five_tuple: &FiveTuple) {
        drop(self.allocations.remove(five_tuple));
    }

    /// Removes all the [`Allocation`]s with the provided `username`, if any.
    pub(crate) fn delete_allocations_by_username(
        &mut self,
        username: impl AsRef<str>,
    ) {
        let username = username.as_ref();
        self.allocations
            .retain(|_, allocation| allocation.username.name() != username);
    }

    /// Returns a random non-allocated UDP port.
    ///
    /// # Errors
    ///
    /// If new port fails to be allocated. See the [`Error`] for details
    pub(crate) async fn get_random_even_port(&self) -> Result<u16, Error> {
        self.relay_allocator
            .allocate_conn(true, 0)
            .await
            .map(|(_, addr)| addr.port())
    }
}

#[cfg(test)]
mod spec {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
        sync::Arc,
        time::Duration,
    };

    use bytecodec::DecodeExt;
    use rand::random;
    use stun_codec::MessageDecoder;
    use tokio::{net::UdpSocket, sync::mpsc, time::sleep};

    use crate::{
        attr::{Attribute, ChannelNumber, Data, Username},
        chandata::ChannelData,
        relay,
        server::DEFAULT_LIFETIME,
        Error, FiveTuple,
    };

    use super::{Config, DynTransport, Manager};

    /// Creates a new [`Manager`] for testing purposes.
    fn create_manager() -> Manager {
        let config = Config {
            relay_addr_generator: relay::Allocator {
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

    /// Generates a new random [`FiveTuple`] for testing purposes.
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
    async fn packet_handler_works() {
        let turn_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let client_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src_addr = client_listener.local_addr().unwrap();
        let (data_ch_tx, mut data_ch_rx) = mpsc::channel(1);
        // `client_listener` read data
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
        let mut m = create_manager();
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
            a.add_permission(peer_listener1.local_addr().unwrap().ip()).await;
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
            "get message doesn't equal target text",
        );

        let target_text2 = "channel bind";
        let _ = peer_listener2
            .send_to(target_text2.as_bytes(), relay_addr_with_host)
            .await
            .unwrap();
        let data = data_ch_rx.recv().await.unwrap();

        assert!(ChannelData::is_channel_data(&data), "should be channel data");

        let channel_data = ChannelData::decode(data).unwrap();

        assert_eq!(
            ChannelNumber::MIN,
            channel_data.num(),
            "get channel data's number is invalid",
        );
        assert_eq!(
            target_text2.as_bytes(),
            &channel_data.data(),
            "get data doesn't equal target text",
        );
    }

    #[tokio::test]
    async fn errors_on_duplicate_five_tuple() {
        let turn_socket: DynTransport =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut m = create_manager();
        let five_tuple = random_five_tuple();
        _ = m
            .create_allocation(
                five_tuple,
                DynTransport::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();

        let res = m
            .create_allocation(
                five_tuple,
                DynTransport::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await;

        assert_eq!(res, Err(Error::DupeFiveTuple));
    }

    #[tokio::test]
    async fn deletes_allocation() {
        let turn_socket: DynTransport =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut m = create_manager();
        let five_tuple = random_five_tuple();
        _ = m
            .create_allocation(
                five_tuple,
                DynTransport::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();

        assert!(
            m.get_alloc(&five_tuple).is_some(),
            "cannot to get `Allocation` right after creation",
        );

        m.delete_allocation(&five_tuple);

        assert!(
            !m.get_alloc(&five_tuple).is_some(),
            "`Allocation` of `{five_tuple}` was not deleted",
        );
    }

    #[tokio::test]
    async fn allocations_timeout() {
        let turn_socket: DynTransport =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut m = create_manager();
        let mut allocations = vec![];
        let lifetime = Duration::from_millis(100);
        for _ in 0..5 {
            let five_tuple = random_five_tuple();

            _ = m
                .create_allocation(
                    five_tuple,
                    DynTransport::clone(&turn_socket),
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
                panic!("`Allocation`s didn't timeout");
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
    async fn deletes_allocation_by_username() {
        let turn_socket: DynTransport =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut m = create_manager();
        let five_tuple1 = random_five_tuple();
        let five_tuple2 = random_five_tuple();
        let five_tuple3 = random_five_tuple();
        _ = m
            .create_allocation(
                five_tuple1,
                DynTransport::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();
        _ = m
            .create_allocation(
                five_tuple2,
                DynTransport::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();
        _ = m
            .create_allocation(
                five_tuple3,
                DynTransport::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                Username::new(String::from("user2")).unwrap(),
                true,
            )
            .await
            .unwrap();

        assert_eq!(
            m.allocations.len(),
            3,
            "wrong number of created `Allocation`s",
        );

        m.delete_allocations_by_username("user");

        assert_eq!(
            m.allocations.len(),
            1,
            "wrong number of left `Allocation`s",
        );

        assert!(
            m.get_alloc(&five_tuple1).is_none(),
            "first allocation is not deleted",
        );
        assert!(
            m.get_alloc(&five_tuple2).is_none(),
            "second allocation is not deleted",
        );
        assert!(
            m.get_alloc(&five_tuple3).is_some(),
            "third allocation is deleted",
        );
    }
}
