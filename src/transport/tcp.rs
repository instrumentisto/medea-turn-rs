//! [STUN]/[TURN] TCP-based [`Transport`] implementation.
//!
//! [STUN]: https://en.wikipedia.org/wiki/STUN
//! [TURN]: https://en.wikipedia.org/wiki/TURN

use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use bytecodec::DecodeExt;
use bytes::BytesMut;
use futures::StreamExt;
use stun_codec::MessageDecoder;
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, TcpStream},
    sync::{mpsc, mpsc::error::TrySendError, oneshot, Mutex},
};
use tokio_util::codec::{Decoder, FramedRead};

use crate::{
    attr::{Attribute, PROTO_TCP},
    chandata::{nearest_padded_value_length, ChannelData},
};

use super::{Error, Request, Transport};

/// Shortcut for a [`HashMap`] of active TCP sessions.
type TcpWritersMap = Arc<
    Mutex<
        HashMap<
            SocketAddr,
            mpsc::Sender<(Vec<u8>, oneshot::Sender<Result<(), Error>>)>,
        >,
    >,
>;

/// Server implementing [STUN]/[TURN] TCP-based [`Transport`].
///
/// [STUN]: https://en.wikipedia.org/wiki/STUN
/// [TURN]: https://en.wikipedia.org/wiki/TURN
#[derive(Debug)]
pub struct Server {
    /// [`mpsc::Receiver`] of [`Request`]s.
    ingress_rx: Mutex<mpsc::Receiver<(Request, SocketAddr)>>,

    /// Local [`SocketAddr`] of the [`TcpListener`].
    local_addr: SocketAddr,

    /// Active TCP sessions.
    writers: TcpWritersMap,
}

#[async_trait]
impl Transport for Server {
    async fn recv_from(&self) -> Result<(Request, SocketAddr), Error> {
        if let Some((data, addr)) = self.ingress_rx.lock().await.recv().await {
            Ok((data, addr))
        } else {
            Err(Error::TransportIsDead)
        }
    }

    async fn send_to(
        &self,
        data: Vec<u8>,
        target: SocketAddr,
    ) -> Result<(), Error> {
        let mut writers = self.writers.lock().await;
        #[allow(clippy::significant_drop_in_scrutinee)] // intentional
        match writers.entry(target) {
            Entry::Occupied(mut e) => {
                let (res_tx, res_rx) = oneshot::channel();
                if e.get_mut().send((data, res_tx)).await.is_err() {
                    // Underlying TCP stream is dead.
                    drop(e.remove_entry());

                    Err(Error::TransportIsDead)
                } else {
                    #[allow(clippy::map_err_ignore)] // intentional
                    res_rx.await.map_err(|_| Error::TransportIsDead)?
                }
            }
            Entry::Vacant(_) => Err(Error::TransportIsDead),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn proto(&self) -> u8 {
        PROTO_TCP
    }
}

impl Server {
    /// Creates and [`spawn`]s a new [`Server`] on the provided [`TcpListener`].
    ///
    /// # Errors
    ///
    /// If fails to receive the local [`SocketAddr`] of the provided
    /// [`TcpListener`].
    ///
    /// [`spawn`]: tokio::spawn()
    pub fn new(listener: TcpListener) -> Result<Self, Error> {
        let local_addr = listener.local_addr()?;
        let (ingress_tx, ingress_rx) = mpsc::channel(256);
        let writers = Arc::new(Mutex::new(HashMap::new()));

        drop(tokio::spawn({
            let writers = Arc::clone(&writers);
            async move {
                loop {
                    tokio::select! {
                        stream = listener.accept() => {
                            match stream {
                                Ok((stream, remote)) => {
                                    Self::spawn_stream_handler(
                                        stream,
                                        local_addr,
                                        remote,
                                        ingress_tx.clone(),
                                        Arc::clone(&writers),
                                    );
                                },
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                        () = ingress_tx.closed() => {
                            break;
                        }
                    }
                }
                log::debug!("Closing `TcpListener` at {local_addr}");
            }
        }));

        Ok(Self { ingress_rx: Mutex::new(ingress_rx), local_addr, writers })
    }

    /// [`spawn`]s a handler for the provided [`TcpStream`].
    ///
    /// [`spawn`]: tokio::spawn()
    fn spawn_stream_handler(
        mut stream: TcpStream,
        local: SocketAddr,
        remote: SocketAddr,
        ingress_tx: mpsc::Sender<(Request, SocketAddr)>,
        writers: TcpWritersMap,
    ) {
        drop(tokio::spawn(async move {
            let (egress_tx, mut egress_rx) = mpsc::channel::<(
                Vec<u8>,
                oneshot::Sender<Result<(), Error>>,
            )>(256);
            drop(writers.lock().await.insert(remote, egress_tx));

            let (reader, mut writer) = stream.split();
            let mut reader = FramedRead::new(reader, Codec::default());
            loop {
                tokio::select! {
                    msg = egress_rx.recv() => {
                        if let Some((msg, tx)) = msg {
                            let res =
                                writer.write_all(msg.as_slice()).await
                                    .map_err(Error::from);

                            drop(tx.send(res));
                        } else {
                            log::debug!("Closing TCP {local} <=> {remote}");
                            break;
                        }
                    },
                    msg = reader.next() => {
                        match msg {
                            Some(Ok(msg)) => {
                                match ingress_tx.try_send((msg, remote)) {
                                    Ok(()) => {},
                                    Err(TrySendError::Full(_)) => {
                                        log::debug!(
                                            "Dropped ingress message from TCP \
                                             {local} <=> {remote}",
                                        );
                                    }
                                    Err(TrySendError::Closed(_)) =>
                                    {
                                        log::debug!(
                                            "Closing TCP {local} <=> {remote}",
                                        );
                                        break;
                                    }
                                }
                            }
                            Some(Err(_)) => {},
                            None => {
                                log::debug!("Closing TCP {local} <=> {remote}");
                                break;
                            }
                        }
                    },
                }
            }
        }));
    }
}

/// Kind of a [`Request`] message.
#[derive(Clone, Copy, Debug)]
enum RequestKind {
    /// [STUN Message].
    ///
    /// ```ascii
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |0 0|     STUN Message Type     |         Message Length        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Magic Cookie                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// |                     Transaction ID (96 bits)                  |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// [STUN Message]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
    Message(usize),

    /// [TURN ChannelData Message][1].
    ///
    /// ```ascii
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Channel Number        |            Length             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// /                       Application Data                        |
    /// /                                                               |
    /// |                                                               |
    /// |                               +-------------------------------+
    /// |                               |
    /// +-------------------------------+
    /// ```
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    ChannelData(usize),
}

impl RequestKind {
    /// Detects a [`RequestKind`] from the provided first 4 bytes of a
    /// [`Request`].
    fn detect_kind(first_4_bytes: [u8; 4]) -> Self {
        let size = usize::from(u16::from_be_bytes([
            first_4_bytes[2],
            first_4_bytes[3],
        ]));

        // If the first two bits are zeroes, then this is a STUN method.
        if first_4_bytes[0] & 0b1100_0000 == 0 {
            Self::Message(nearest_padded_value_length(size + 20))
        } else {
            Self::ChannelData(nearest_padded_value_length(size + 4))
        }
    }

    /// Returns the expected length of the [`Request`] message.
    const fn length(&self) -> usize {
        *match self {
            Self::Message(l) | Self::ChannelData(l) => l,
        }
    }
}

/// [`Decoder`] splitting a [STUN]/[TURN] stream into frames.
///
/// [STUN]: https://en.wikipedia.org/wiki/STUN
/// [TURN]: https://en.wikipedia.org/wiki/TURN
#[derive(Default)]
struct Codec {
    /// Current [`RequestKind`].
    current: Option<RequestKind>,

    /// [STUN Message] decoder.
    ///
    /// [STUN Message]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
    msg_decoder: MessageDecoder<Attribute>,
}

impl Decoder for Codec {
    type Item = Request;
    type Error = Error;

    fn decode(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        // PANIC: Indexing is OK below, since we guard it with `if` condition.
        #![allow(clippy::missing_asserts_for_indexing)] // false positive

        if self.current.is_none() && buf.len() >= 4 {
            self.current = Some(RequestKind::detect_kind([
                buf[0], buf[1], buf[2], buf[3],
            ]));
        }

        if let Some(current) = self.current {
            if buf.len() >= current.length() {
                _ = self.current.take();

                let raw = buf.split_to(current.length());
                let msg = match current {
                    RequestKind::Message(_) => {
                        let msg = self
                            .msg_decoder
                            .decode_from_bytes(&raw)
                            .map_err(|e| Error::Decode(*e.kind()))?
                            .map_err(|e| Error::Decode(*e.error().kind()))?;

                        Request::Message(msg)
                    }
                    RequestKind::ChannelData(_) => {
                        Request::ChannelData(ChannelData::decode(raw.to_vec())?)
                    }
                };
                return Ok(Some(msg));
            }
        }

        Ok(None)
    }
}
