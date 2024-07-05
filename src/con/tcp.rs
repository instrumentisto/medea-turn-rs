//! STUN/TURN TCP server connection implementation.

#![allow(clippy::module_name_repetitions)]

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
    con::{Conn, Request, TransportError},
};

/// Channels to the active TCP sessions.
type TcpWritersMap = Arc<
    Mutex<
        HashMap<
            SocketAddr,
            mpsc::Sender<(
                Vec<u8>,
                oneshot::Sender<Result<(), TransportError>>,
            )>,
        >,
    >,
>;

/// TURN TCP transport.
#[derive(Debug)]
pub struct TcpServer {
    /// Ingress messages receiver.
    ingress_rx: Mutex<mpsc::Receiver<(Request, SocketAddr)>>,

    /// Local [`TcpListener`] address.
    local_addr: SocketAddr,

    /// Channels to all active TCP sessions.
    writers: TcpWritersMap,
}

#[async_trait]
impl Conn for TcpServer {
    async fn recv_from(&self) -> Result<(Request, SocketAddr), TransportError> {
        if let Some((data, addr)) = self.ingress_rx.lock().await.recv().await {
            Ok((data, addr))
        } else {
            Err(TransportError::TransportIsDead)
        }
    }

    #[allow(clippy::significant_drop_in_scrutinee)]
    async fn send_to(
        &self,
        data: Vec<u8>,
        target: SocketAddr,
    ) -> Result<(), TransportError> {
        let mut writers = self.writers.lock().await;
        match writers.entry(target) {
            Entry::Occupied(mut e) => {
                let (res_tx, res_rx) = oneshot::channel();
                if e.get_mut().send((data, res_tx)).await.is_err() {
                    // Underlying TCP stream is dead.
                    drop(e.remove_entry());

                    Err(TransportError::TransportIsDead)
                } else {
                    #[allow(clippy::map_err_ignore)]
                    res_rx.await.map_err(|_| TransportError::TransportIsDead)?
                }
            }
            Entry::Vacant(_) => Err(TransportError::TransportIsDead),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn proto(&self) -> u8 {
        PROTO_TCP
    }
}

impl TcpServer {
    /// Creates a new [`TcpServer`].
    ///
    /// # Errors
    ///
    /// With [`TransportError`] if failed to receive local [`SocketAddr`] for
    /// the provided [`TcpListener`].
    pub fn new(listener: TcpListener) -> Result<Self, TransportError> {
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
                log::debug!("Closing TCP listener at {local_addr}");
            }
        }));

        Ok(Self { ingress_rx: Mutex::new(ingress_rx), local_addr, writers })
    }

    /// Spawns a handler task for the given [`TcpStream`]
    fn spawn_stream_handler(
        mut stream: TcpStream,
        local_addr: SocketAddr,
        remote: SocketAddr,
        ingress_tx: mpsc::Sender<(Request, SocketAddr)>,
        writers: TcpWritersMap,
    ) {
        drop(tokio::spawn(async move {
            let (egress_tx, mut egress_rx) = mpsc::channel::<(
                Vec<u8>,
                oneshot::Sender<Result<(), TransportError>>,
            )>(256);
            drop(writers.lock().await.insert(remote, egress_tx));

            let (reader, mut writer) = stream.split();
            let mut reader = FramedRead::new(reader, StunTcpCodec::default());
            loop {
                tokio::select! {
                    msg = egress_rx.recv() => {
                        if let Some((msg, tx)) = msg {
                            let res =
                                writer.write_all(msg.as_slice()).await
                                    .map_err(TransportError::from);

                            drop(tx.send(res));
                        } else {
                            log::debug!(
                                "Closing TCP {local_addr} <=> {remote}"
                            );

                            break;
                        }
                    },
                    msg = reader.next() => {
                        match msg {
                            Some(Ok(msg)) => {
                                match ingress_tx.try_send((msg, remote)) {
                                    Ok(()) => {},
                                    Err(TrySendError::Full(_)) => {
                                        log::debug!("Dropped ingress message \
                                        from TCP {local_addr} <=> {remote}");
                                    }
                                    Err(TrySendError::Closed(_)) =>
                                    {
                                        log::debug!("Closing TCP \
                                            {local_addr} <=> {remote}");

                                        break;
                                    }
                                }
                            }
                            Some(Err(_)) => {},
                            None => {
                                log::debug!("Closing TCP {local_addr} <=> \
                                    {remote}");

                                break;
                            }
                        }
                    },
                }
            }
        }));
    }
}

#[derive(Debug, Clone, Copy)]
enum StunMessageKind {
    /// [STUN Message].
    ///
    ///
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
    ///
    /// [STUN Message]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
    Message(usize),

    /// TURN [ChannelData][1].
    ///
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
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    ChannelData(usize),
}

impl StunMessageKind {
    /// Detects [`StunMessageKind`] from the given 4 bytes.
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

    /// Returns the expected length of the message.
    const fn length(&self) -> usize {
        *match self {
            Self::Message(l) | Self::ChannelData(l) => l,
        }
    }
}

/// [`Decoder`] that splits STUN/TURN stream into frames.
#[derive(Default)]
struct StunTcpCodec {
    /// Current message kind.
    current: Option<StunMessageKind>,

    /// [STUN Message] decoder.
    ///
    /// [STUN Message]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
    msg_decoder: MessageDecoder<Attribute>,
}

impl Decoder for StunTcpCodec {
    type Item = Request;
    type Error = TransportError;

    #[allow(clippy::unwrap_in_result, clippy::missing_asserts_for_indexing)]
    fn decode(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if self.current.is_none() && buf.len() >= 4 {
            self.current = Some(StunMessageKind::detect_kind([
                buf[0], buf[1], buf[2], buf[3],
            ]));
        }

        if let Some(pending) = self.current {
            if buf.len() >= pending.length() {
                #[allow(clippy::unwrap_used)]
                let current = self.current.take().unwrap();
                let raw = buf.split_to(current.length());

                let msg = match current {
                    StunMessageKind::Message(_) => {
                        let msg = self
                            .msg_decoder
                            .decode_from_bytes(&raw)
                            .map_err(|e| TransportError::Decode(*e.kind()))?
                            .map_err(|e| {
                                TransportError::Decode(*e.error().kind())
                            })?;

                        Request::Message(msg)
                    }
                    StunMessageKind::ChannelData(_) => {
                        Request::ChannelData(ChannelData::decode(raw.to_vec())?)
                    }
                };

                return Ok(Some(msg));
            }
        }

        Ok(None)
    }
}
