//! Relay definitions.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use tokio::net::UdpSocket;

use crate::{Error, transport};

/// Generator of relay addresses when creating an [allocation].
///
/// [allocation]: https://tools.ietf.org/html/rfc5766#section-5
#[derive(Clone, Debug)]
pub struct Allocator {
    /// [`IpAddr`] returned to the user when a relay is created.
    relay_address: IpAddr,

    /// Address passed when binding relay sockets.
    address: String,

    /// Amount of tries to allocate a random port in the allowed range.
    max_retries: u16,

    /// Available ports.
    pool: PortPool,
}

impl Allocator {
    /// Creates a new [`Allocator`].
    #[must_use]
    pub fn new(
        relay_address: IpAddr,
        address: String,
        min_port: u16,
        max_port: u16,
        max_retries: u16,
    ) -> Self {
        Self {
            relay_address,
            address,
            max_retries,
            pool: PortPool::new(min_port, max_port),
        }
    }

    /// Picks a random available port from the pool, binds a [`UdpSocket`] to
    /// it, and returns the socket, its relay [`SocketAddr`], and a
    /// [`PortGuard`].
    ///
    ///
    /// # Errors
    ///
    /// - [`Error::PortsExhausted`] if no port is available in the pool.
    /// - [`Error::MaxRetriesExceeded`] if the configured attempt budget is
    ///   exhausted before finding a bindable port.
    /// - [`Error::Transport`] if a non-bind transport error occurred.
    pub(crate) async fn allocate_conn(
        &self,
        use_ipv4: bool,
    ) -> Result<(Arc<UdpSocket>, SocketAddr, PortGuard), Error> {
        #[expect( // guards are not intended to be read, only exist
            clippy::collection_is_never_read,
            reason = "guards are not intended to be read, only exist"
        )]
        let mut failed_guards = Vec::new();

        // Start from `0` to always make at least one attempt.
        for attempt in 0..=self.max_retries {
            let port = self.pool.acquire().ok_or(Error::PortsExhausted)?;

            let guard = PortGuard { port, pool: self.pool.clone() };

            let addr = transport::lookup_host(
                use_ipv4,
                &format!("{}:{port}", self.address),
            )
            .await?;

            match UdpSocket::bind(addr).await {
                Ok(socket) => {
                    let socket = Arc::new(socket);
                    let mut relay_addr =
                        socket.local_addr().map_err(transport::Error::from)?;
                    relay_addr.set_ip(self.relay_address);

                    return Ok((socket, relay_addr, guard));
                }
                Err(e) => {
                    log::warn!(
                        "Failed to bind relay socket on port {port}: {e}. \
                         Attempt #{attempt}/{}",
                        self.max_retries,
                    );
                    // Keep failed ports out of the pool for the duration of
                    // this call, to not keep retrying the same busy port.
                    failed_guards.push(guard);
                }
            }
        }

        Err(Error::MaxRetriesExceeded)
    }
}

/// Shared pool of available relay ports.
#[derive(Clone, Debug)]
pub(crate) struct PortPool {
    /// Bit-vector of available ports, relative to `min_port`.
    bits: Arc<Mutex<Vec<u64>>>,

    /// Lowest port number covered by this [`PortPool`].
    ///
    /// Acts as an offset when accessing bitvec.
    min_port: u16,
}

impl PortPool {
    /// Creates a pool with every port in `min_port..=max_port` available.
    fn new(min_port: u16, max_port: u16) -> Self {
        assert!(min_port <= max_port, "min_port must be <= max_port");

        let range = usize::from(max_port) - usize::from(min_port) + 1;
        let num_words = range.div_ceil(64);
        let mut bits = vec![0u64; num_words];
        for i in 0..range {
            bits[i / 64] |= 1u64 << (i % 64);
        }
        Self { bits: Arc::new(Mutex::new(bits)), min_port }
    }

    /// Claims and returns a random available port, or [`None`] if all ports are
    /// currently in use.
    fn acquire(&self) -> Option<u16> {
        #[expect(clippy::unwrap_used, reason = "locking")]
        let mut bits = self.bits.lock().unwrap();
        let len = bits.len();
        if len == 0 {
            return None;
        }
        let start = usize::from(rand::random::<u16>()) % len;
        for i in 0..len {
            let word_idx = (start + i) % len;
            let word = bits[word_idx];
            if word == 0 {
                continue;
            }

            let bit = word.trailing_zeros();
            bits[word_idx] &= !(1u64 << bit);
            drop(bits);

            // `word_idx * 64 <= 65472` and `bit <= 63`, so neither `try_from`
            // conversion fails.
            #[expect(clippy::unwrap_used, reason = "bounded by pool size")]
            let offset = u16::try_from(word_idx * 64).unwrap()
                + u16::try_from(bit).unwrap();

            let port = self.min_port + offset;

            return Some(port);
        }
        None
    }

    /// Returns a previously acquired port back to the pool.
    pub(crate) fn release(&self, port: u16) {
        let port = usize::from(port);
        let base = usize::from(self.min_port);
        let Some(i) = port.checked_sub(base) else { return };
        #[expect(clippy::unwrap_used, reason = "locking")]
        if let Some(word) = self.bits.lock().unwrap().get_mut(i / 64) {
            *word |= 1u64 << (i % 64);
        }
    }
}

/// Guard returning a relay port to its [`PortPool`] once dropped.
///
/// Obtained via [`Allocator::allocate_conn()`].
#[derive(Debug)]
pub(crate) struct PortGuard {
    /// Port being held.
    port: u16,

    /// Pool this port belongs to.
    pool: PortPool,
}

impl Drop for PortGuard {
    fn drop(&mut self) {
        self.pool.release(self.port);
    }
}

#[cfg(test)]
mod port_pool_spec {
    use std::{
        collections::HashSet,
        sync::{Arc, Mutex},
        thread,
    };

    use super::{PortGuard, PortPool};

    impl PortPool {
        /// Creates an empty pool (no ports available).
        pub(crate) fn dummy() -> Self {
            Self { bits: Arc::new(Mutex::new(vec![])), min_port: 0 }
        }
    }

    impl PortGuard {
        pub(crate) fn dummy() -> Self {
            Self { port: 0, pool: PortPool::dummy() }
        }
    }

    #[test]
    fn acquire_exhausts_range() {
        let pool = PortPool::new(20_000, 20_004);
        let mut seen = HashSet::new();

        for _ in 0..5 {
            let p = pool.acquire().expect("expected available port");

            assert!((20_000..=20_004).contains(&p));
            assert!(seen.insert(p), "duplicate port {p}");
        }
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn release_allows_reacquire() {
        let pool = PortPool::new(30_000, 30_000);

        assert_eq!(pool.acquire(), Some(30_000));
        assert!(pool.acquire().is_none());

        pool.release(30_000);

        assert_eq!(pool.acquire(), Some(30_000));
        assert!(pool.acquire().is_none());
    }

    #[tokio::test]
    async fn single_port() {
        let pool = PortPool::new(1, 1);

        assert_eq!(pool.acquire(), Some(1));
        assert_eq!(pool.acquire(), None);

        pool.release(1);

        assert_eq!(pool.acquire(), Some(1));
    }

    #[test]
    fn single_port_boundary_max() {
        let pool = PortPool::new(u16::MAX, u16::MAX);

        assert_eq!(pool.acquire(), Some(u16::MAX));
        assert!(pool.acquire().is_none());

        pool.release(u16::MAX);

        assert_eq!(pool.acquire(), Some(u16::MAX));
    }

    #[test]
    #[should_panic(expected = "min_port must be <= max_port")]
    fn new_panics_when_min_greater_than_max() {
        drop(PortPool::new(100, 99));
    }

    #[test]
    fn acquired_ports_stay_in_range() {
        let pool = PortPool::new(1000, 1063);
        let mut seen = HashSet::new();

        while let Some(p) = pool.acquire() {
            assert!((1000..=1063).contains(&p), "port {p} out of range");
            assert!(seen.insert(p), "duplicate port {p}");
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn multiple_release_and_reacquire() {
        let pool = PortPool::new(5000, 5002);

        let p0 = pool.acquire().unwrap();
        let p1 = pool.acquire().unwrap();
        let p2 = pool.acquire().unwrap();

        assert!(pool.acquire().is_none());

        pool.release(p1);
        pool.release(p0);
        pool.release(p2);

        let mut reclaimed = HashSet::new();
        for _ in 0..3 {
            reclaimed.insert(pool.acquire().expect("port should be available"));
        }

        assert_eq!(reclaimed, HashSet::from([p0, p1, p2]));
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn concurrent_acquire_no_duplicates() {
        let pool = Arc::new(PortPool::new(10_000, 10_063));
        let acquired: Arc<Mutex<HashSet<u16>>> =
            Arc::new(Mutex::new(HashSet::new()));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let acquired = Arc::clone(&acquired);
                thread::spawn(move || {
                    // Each thread grabs ports until none are left.
                    while let Some(p) = pool.acquire() {
                        let mut set = acquired.lock().unwrap();

                        assert!(set.insert(p), "duplicate port {p}");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(acquired.lock().unwrap().len(), 64);
    }
}

#[cfg(test)]
mod port_guard_spec {
    use super::{PortGuard, PortPool};

    #[test]
    fn releases_on_drop() {
        let pool = PortPool::new(7000, 7000);

        assert_eq!(pool.acquire(), Some(7000));
        assert!(pool.acquire().is_none());

        let guard = PortGuard { port: 7000, pool: pool.clone() };
        drop(guard);

        assert_eq!(pool.acquire(), Some(7000));
    }
}

#[cfg(test)]
mod allocator_spec {
    use std::{net::IpAddr, thread, time::Duration};

    use tokio::net::UdpSocket;

    use super::Allocator;
    use crate::Error;

    #[tokio::test]
    async fn skips_busy_ports() {
        let busy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        let allocator = Allocator::new(
            IpAddr::from([127, 0, 0, 1]),
            String::from("127.0.0.1"),
            busy_port,
            busy_port + 1,
            2,
        );

        let (_socket, relay_addr, _guard) =
            allocator.allocate_conn(true).await.unwrap();

        assert_eq!(relay_addr.ip(), IpAddr::from([127, 0, 0, 1]));
        assert_eq!(relay_addr.port(), busy_port + 1);

        assert_eq!(
            allocator.allocate_conn(true).await.unwrap_err(),
            Error::PortsExhausted,
        );
    }

    #[tokio::test]
    async fn normal_usage() {
        let allocator = Allocator::new(
            IpAddr::from([127, 0, 0, 1]),
            String::from("127.0.0.1"),
            49152,
            49154,
            1,
        );
        let mut ports = Vec::new();
        let (socket1, _relay_addr1, guard1) =
            allocator.allocate_conn(true).await.unwrap();
        ports.push(guard1.port);
        let (_socket2, _relay_addr2, guard2) =
            allocator.allocate_conn(true).await.unwrap();
        ports.push(guard2.port);
        let (_socket3, _relay_addr3, guard3) =
            allocator.allocate_conn(true).await.unwrap();
        ports.push(guard3.port);

        // No more ports at this point.
        assert_eq!(
            allocator.allocate_conn(true).await.unwrap_err(),
            Error::PortsExhausted,
        );

        ports.sort();

        assert_eq!(ports, [49152, 49153, 49154]);

        // Now drop guard but not socket.
        drop(guard1);

        // Socket is alive, so allocation attempt fails.
        assert!(allocator.allocate_conn(true).await.is_err());

        // Drop socket and wait a bit for system to properly kill it.
        drop(socket1);
        thread::sleep(Duration::from_millis(500));

        // It can be properly reused now.
        assert_eq!(allocator.allocate_conn(true).await.unwrap().2.port, 49152);
    }
}
