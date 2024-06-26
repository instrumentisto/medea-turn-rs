//! Ingress STUN/TURN messages handlers.

use bytecodec::{DecodeExt, EncodeExt};
use std::{
    collections::HashMap,
    marker::{Send, Sync},
    mem,
    net::SocketAddr,
    sync::Arc,
};

use rand::{distributions::Alphanumeric, random, Rng};
use stun_codec::{
    rfc5389::{
        errors::{BadRequest, StaleNonce, Unauthorized, UnknownAttribute},
        methods::BINDING,
    },
    rfc5766::{
        errors::{
            AllocationMismatch, InsufficientCapacity,
            UnsupportedTransportProtocol,
        },
        methods::{ALLOCATE, CHANNEL_BIND, CREATE_PERMISSION, REFRESH, SEND},
    },
    rfc8656::errors::{AddressFamilyNotSupported, PeerAddressFamilyMismatch},
    Attribute as _, Message, MessageClass, MessageDecoder, MessageEncoder,
    TransactionId,
};
use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{
    allocation::{FiveTuple, Manager},
    attr::{
        AddressFamily, Attribute, ChannelNumber, Data, DontFragment, ErrorCode,
        EvenPort, Fingerprint, Lifetime, MessageIntegrity, Nonce, Realm,
        RequestedAddressFamily, RequestedTransport, ReservationToken,
        UnknownAttributes, Username, XorMappedAddress, XorPeerAddress,
        XorRelayAddress, PROTO_UDP,
    },
    chandata::ChannelData,
    con::Conn,
    server::DEFAULT_LIFETIME,
    AuthHandler, Error,
};

/// It is RECOMMENDED that the server use a maximum allowed lifetime value of no
/// more than 3600 seconds (1 hour).
const MAXIMUM_ALLOCATION_LIFETIME: Duration = Duration::from_secs(3600);

/// Lifetime of the NONCE sent by server.
const NONCE_LIFETIME: Duration = Duration::from_secs(3600);

/// Handles the given STUN/TURN message according to [spec].
///
/// [spec]: https://datatracker.ietf.org/doc/html/rfc5389#section-7.3
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_message(
    mut raw: Vec<u8>,
    conn: &Arc<dyn Conn + Send + Sync>,
    five_tuple: FiveTuple,
    server_realm: &str,
    channel_bind_lifetime: Duration,
    allocs: &Arc<Manager>,
    nonces: &Arc<Mutex<HashMap<String, Instant>>>,
    auth_handler: &Arc<dyn AuthHandler + Send + Sync>,
) -> Result<(), Error> {
    if ChannelData::is_channel_data(&raw) {
        let data = ChannelData::decode(mem::take(&mut raw))?;

        handle_data_packet(data, five_tuple, allocs).await
    } else {
        use stun_codec::MessageClass::{Indication, Request};

        let msg = MessageDecoder::<Attribute>::new()
            .decode_from_bytes(&raw)
            .map_err(|e| Error::Decode(*e.kind()))?
            .map_err(|e| Error::Decode(*e.error().kind()))?;

        let auth = match (msg.method(), msg.class()) {
            (
                ALLOCATE | REFRESH | CREATE_PERMISSION | CHANNEL_BIND,
                Request,
            ) => {
                authenticate_request(
                    &msg,
                    auth_handler,
                    conn,
                    nonces,
                    five_tuple,
                    server_realm,
                )
                .await?
            }
            _ => None,
        };

        match (msg.method(), msg.class()) {
            (ALLOCATE, Request) => {
                if let Some((uname, realm, pass)) = auth {
                    handle_allocate_request(
                        msg, conn, allocs, five_tuple, uname, realm, pass,
                    )
                    .await
                } else {
                    Ok(())
                }
            }
            (REFRESH, Request) => {
                if let Some((uname, realm, pass)) = auth {
                    handle_refresh_request(
                        msg, conn, allocs, five_tuple, uname, realm, pass,
                    )
                    .await
                } else {
                    Ok(())
                }
            }
            (CREATE_PERMISSION, Request) => {
                if let Some((uname, realm, pass)) = auth {
                    handle_create_permission_request(
                        msg, conn, allocs, five_tuple, uname, realm, pass,
                    )
                    .await
                } else {
                    Ok(())
                }
            }
            (CHANNEL_BIND, Request) => {
                if let Some((uname, realm, pass)) = auth {
                    handle_channel_bind_request(
                        msg,
                        conn,
                        allocs,
                        five_tuple,
                        channel_bind_lifetime,
                        uname,
                        realm,
                        pass,
                    )
                    .await
                } else {
                    Ok(())
                }
            }
            (BINDING, Request) => {
                handle_binding_request(conn, five_tuple).await
            }
            (SEND, Indication) => {
                handle_send_indication(msg, allocs, five_tuple).await
            }
            (_, _) => Err(Error::UnexpectedClass),
        }
    }
}

/// Relays the given [`ChannelData`].
async fn handle_data_packet(
    data: ChannelData,
    five_tuple: FiveTuple,
    allocs: &Arc<Manager>,
) -> Result<(), Error> {
    if let Some(alloc) = allocs.get_alloc(&five_tuple) {
        let channel = alloc.get_channel_addr(&data.num()).await;
        if let Some(peer) = channel {
            alloc.relay(&data.data(), peer).await?;

            Ok(())
        } else {
            Err(Error::NoSuchChannelBind)
        }
    } else {
        Err(Error::NoAllocationFound)
    }
}

/// Handles the given STUN [`Message`] as an [AllocateRequest].
///
/// [AllocateRequest]: https://datatracker.ietf.org/doc/html/rfc5766#section-6.2
#[allow(clippy::too_many_lines)]
async fn handle_allocate_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Conn + Send + Sync>,
    allocs: &Arc<Manager>,
    five_tuple: FiveTuple,
    uname: Username,
    realm: Realm,
    pass: Box<str>,
) -> Result<(), Error> {
    // 1. The server MUST require that the request be authenticated.  This
    //    authentication MUST be done using the long-term credential
    //    mechanism of [https://tools.ietf.org/html/rfc5389#section-10.2.2]
    //    unless the client and server agree to use another mechanism through
    //    some procedure outside the scope of this document.

    let mut requested_port = 0;
    let mut reservation_token: Option<u64> = None;
    let mut use_ipv4 = true;

    // 2. The server checks if the 5-tuple is currently in use by an existing
    //    allocation.  If yes, the server rejects the request with a 437
    //    (Allocation Mismatch) error.
    if allocs.has_alloc(&five_tuple) {
        let mut msg = Message::new(
            MessageClass::ErrorResponse,
            ALLOCATE,
            msg.transaction_id(),
        );
        msg.add_attribute(ErrorCode::from(AllocationMismatch));

        answer_with_err(conn, five_tuple.src_addr, msg).await?;

        return Err(Error::RelayAlreadyAllocatedForFiveTuple);
    }

    // 3. The server checks if the request contains a REQUESTED-TRANSPORT
    //    attribute. If the REQUESTED-TRANSPORT attribute is not included or is
    //    malformed, the server rejects the request with a 400 (Bad Request)
    //    error.  Otherwise, if the attribute is included but specifies a
    //    protocol other that UDP, the server rejects the request with a 442
    //    (Unsupported Transport Protocol) error.
    let Some(requested_proto) = msg
        .get_attribute::<RequestedTransport>()
        .map(RequestedTransport::protocol)
    else {
        let mut msg = Message::new(
            MessageClass::ErrorResponse,
            ALLOCATE,
            msg.transaction_id(),
        );
        msg.add_attribute(ErrorCode::from(BadRequest));

        answer_with_err(conn, five_tuple.src_addr, msg).await?;

        return Err(Error::AttributeNotFound);
    };

    if requested_proto != PROTO_UDP {
        let mut msg = Message::new(
            MessageClass::ErrorResponse,
            ALLOCATE,
            msg.transaction_id(),
        );
        msg.add_attribute(ErrorCode::from(UnsupportedTransportProtocol));

        answer_with_err(conn, five_tuple.src_addr, msg).await?;

        return Err(Error::UnsupportedRelayProto);
    }

    // 4. The request may contain a DONT-FRAGMENT attribute.  If it does, but
    //    the server does not support sending UDP datagrams with the DF bit set
    //    to 1 (see Section 12), then the server treats the DONT- FRAGMENT
    //    attribute in the Allocate request as an unknown comprehension-required
    //    attribute.
    if msg.get_attribute::<DontFragment>().is_some() {
        let mut msg = Message::new(
            MessageClass::ErrorResponse,
            ALLOCATE,
            msg.transaction_id(),
        );
        msg.add_attribute(ErrorCode::from(UnknownAttribute));
        msg.add_attribute(UnknownAttributes::new(
            vec![DontFragment.get_type()],
        ));

        answer_with_err(conn, five_tuple.src_addr, msg).await?;

        return Err(Error::NoDontFragmentSupport);
    }

    // 5. The server checks if the request contains a RESERVATION-TOKEN
    //    attribute. If yes, and the request also contains an EVEN-PORT
    //    attribute, then the server rejects the request with a 400 (Bad
    //    Request) error.  Otherwise, it checks to see if the token is valid
    //    (i.e., the token is in range and has not expired and the corresponding
    //    relayed transport address is still available).  If the token is not
    //    valid for some reason, the server rejects the request with a 508
    //    (Insufficient Capacity) error.
    let has_reservation_token =
        msg.get_attribute::<ReservationToken>().is_some();
    let even_port = msg.get_attribute::<EvenPort>();

    if has_reservation_token && even_port.is_some() {
        let mut msg = Message::new(
            MessageClass::ErrorResponse,
            ALLOCATE,
            msg.transaction_id(),
        );
        msg.add_attribute(ErrorCode::from(BadRequest));

        answer_with_err(conn, five_tuple.src_addr, msg).await?;

        return Err(Error::RequestWithReservationTokenAndEvenPort);
    }

    // RFC 6156, Section 4.2:
    //
    // If it contains both a RESERVATION-TOKEN and a
    // REQUESTED-ADDRESS-FAMILY, the server replies with a 400
    // (Bad Request) Allocate error response.
    //
    // 4.2.1.  Unsupported Address Family
    // This document defines the following new error response code:
    // 440 (Address Family not Supported):  The server does not support the
    // address family requested by the client.
    if let Some(req_family) = msg
        .get_attribute::<RequestedAddressFamily>()
        .map(RequestedAddressFamily::address_family)
    {
        if has_reservation_token {
            let mut msg = Message::new(
                MessageClass::ErrorResponse,
                ALLOCATE,
                msg.transaction_id(),
            );
            msg.add_attribute(ErrorCode::from(AddressFamilyNotSupported));

            answer_with_err(conn, five_tuple.src_addr, msg).await?;

            return Err(Error::RequestWithReservationTokenAndReqAddressFamily);
        }

        if req_family == AddressFamily::V6 {
            use_ipv4 = false;
        }
    }

    // 6. The server checks if the request contains an EVEN-PORT attribute. If
    //    yes, then the server checks that it can satisfy the request (i.e., can
    //    allocate a relayed transport address as described below).  If the
    //    server cannot satisfy the request, then the server rejects the request
    //    with a 508 (Insufficient Capacity) error.
    if even_port.is_some() {
        let mut random_port = 1;

        while random_port % 2 != 0 {
            random_port = match allocs.get_random_even_port().await {
                Ok(port) => port,
                Err(err) => {
                    let mut msg = Message::new(
                        MessageClass::ErrorResponse,
                        ALLOCATE,
                        msg.transaction_id(),
                    );
                    msg.add_attribute(ErrorCode::from(InsufficientCapacity));

                    answer_with_err(conn, five_tuple.src_addr, msg).await?;

                    return Err(err);
                }
            };
        }

        requested_port = random_port;
        reservation_token = Some(random());
    }

    // 7. At any point, the server MAY choose to reject the request with a 486
    //    (Allocation Quota Reached) error if it feels the client is trying to
    //    exceed some locally defined allocation quota.  The server is free to
    //    define this allocation quota any way it wishes, but SHOULD define it
    //    based on the username used to authenticate the request, and not on the
    //    client's transport address.

    // 8. Also at any point, the server MAY choose to reject the request with a
    //    300 (Try Alternate) error if it wishes to redirect the client to a
    //    different server.  The use of this error code and attribute follow the
    //    specification in [RFC5389].
    let lifetime_duration = get_lifetime(&msg);
    let a = match allocs
        .create_allocation(
            five_tuple,
            Arc::clone(conn),
            requested_port,
            lifetime_duration,
            uname.clone(),
            use_ipv4,
        )
        .await
    {
        Ok(a) => a,
        Err(err) => {
            let mut msg = Message::new(
                MessageClass::ErrorResponse,
                ALLOCATE,
                msg.transaction_id(),
            );
            msg.add_attribute(ErrorCode::from(InsufficientCapacity));

            answer_with_err(conn, five_tuple.src_addr, msg).await?;

            return Err(err);
        }
    };

    // Once the allocation is created, the server replies with a success
    // response.  The success response contains:
    //   * An XOR-RELAYED-ADDRESS attribute containing the relayed transport
    //     address.
    //   * A LIFETIME attribute containing the current value of the time-to-
    //     expiry timer.
    //   * A RESERVATION-TOKEN attribute (if a second relayed transport address
    //     was reserved).
    //   * An XOR-MAPPED-ADDRESS attribute containing the client's IP address
    //     and port (from the 5-tuple).

    let msg = {
        if let Some(token) = reservation_token {
            allocs.create_reservation(token, a.relay_addr().port()).await;
        }

        let mut msg = Message::new(
            MessageClass::SuccessResponse,
            ALLOCATE,
            msg.transaction_id(),
        );

        msg.add_attribute(XorRelayAddress::new(a.relay_addr()));
        msg.add_attribute(
            Lifetime::new(lifetime_duration)
                .map_err(|e| Error::Encode(*e.kind()))?,
        );
        msg.add_attribute(XorMappedAddress::new(five_tuple.src_addr));

        if let Some(token) = reservation_token {
            msg.add_attribute(ReservationToken::new(token));
        }

        let integrity = MessageIntegrity::new_long_term_credential(
            &msg, &uname, &realm, &pass,
        )
        .map_err(|e| Error::Encode(*e.kind()))?;
        msg.add_attribute(integrity);

        msg
    };

    build_and_send(conn, five_tuple.src_addr, msg).await
}

/// Authenticates the given [`Message`].
async fn authenticate_request(
    msg: &Message<Attribute>,
    auth_handler: &Arc<dyn AuthHandler + Send + Sync>,
    conn: &Arc<dyn Conn + Send + Sync>,
    nonces: &Arc<Mutex<HashMap<String, Instant>>>,
    five_tuple: FiveTuple,
    realm: &str,
) -> Result<Option<(Username, Realm, Box<str>)>, Error> {
    let Some(integrity) = msg.get_attribute::<MessageIntegrity>() else {
        respond_with_nonce(
            msg,
            ErrorCode::from(Unauthorized),
            conn,
            realm,
            five_tuple,
            nonces,
        )
        .await?;
        return Ok(None);
    };

    let mut bad_request_msg = Message::new(
        MessageClass::ErrorResponse,
        msg.method(),
        msg.transaction_id(),
    );
    bad_request_msg.add_attribute(ErrorCode::from(BadRequest));

    let Some(nonce_attr) = &msg.get_attribute::<Nonce>() else {
        answer_with_err(conn, five_tuple.src_addr, bad_request_msg).await?;
        return Err(Error::AttributeNotFound);
    };

    let to_be_deleted = {
        // Assert Nonce exists and is not expired
        let mut nonces = nonces.lock().await;

        let to_be_deleted = nonces.get(nonce_attr.value()).map_or(
            true,
            |nonce_creation_time| {
                Instant::now()
                    .checked_duration_since(*nonce_creation_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    >= NONCE_LIFETIME
            },
        );

        if to_be_deleted {
            _ = nonces.remove(nonce_attr.value());
        }
        to_be_deleted
    };

    if to_be_deleted {
        respond_with_nonce(
            msg,
            ErrorCode::from(StaleNonce),
            conn,
            realm,
            five_tuple,
            nonces,
        )
        .await?;
        return Ok(None);
    }

    let Some(uname_attr) = msg.get_attribute::<Username>() else {
        answer_with_err(conn, five_tuple.src_addr, bad_request_msg).await?;
        return Err(Error::AttributeNotFound);
    };
    let Some(realm_attr) = msg.get_attribute::<Realm>() else {
        answer_with_err(conn, five_tuple.src_addr, bad_request_msg).await?;
        return Err(Error::AttributeNotFound);
    };

    let Ok(pass) = auth_handler.auth_handle(
        uname_attr.name(),
        realm_attr.text(),
        five_tuple.src_addr,
    ) else {
        answer_with_err(conn, five_tuple.src_addr, bad_request_msg).await?;
        return Err(Error::NoSuchUser);
    };

    if let Err(err) =
        integrity.check_long_term_credential(uname_attr, realm_attr, &pass)
    {
        let mut unauthorized_msg = Message::new(
            MessageClass::ErrorResponse,
            msg.method(),
            msg.transaction_id(),
        );
        unauthorized_msg.add_attribute(err);

        answer_with_err(conn, five_tuple.src_addr, unauthorized_msg).await?;

        Err(Error::IntegrityMismatch)
    } else {
        Ok(Some((uname_attr.clone(), realm_attr.clone(), pass)))
    }
}

/// Sends a [`MessageClass::SuccessResponse`] message with a
/// [`XorMappedAddress`] attribute to the given [`Conn`].
async fn handle_binding_request(
    conn: &Arc<dyn Conn + Send + Sync>,
    five_tuple: FiveTuple,
) -> Result<(), Error> {
    log::trace!("received BindingRequest from {}", five_tuple.src_addr);

    let mut msg = Message::new(
        MessageClass::SuccessResponse,
        BINDING,
        TransactionId::new(random()),
    );
    msg.add_attribute(XorMappedAddress::new(five_tuple.src_addr));
    let fingerprint =
        Fingerprint::new(&msg).map_err(|e| Error::Encode(*e.kind()))?;
    msg.add_attribute(fingerprint);

    build_and_send(conn, five_tuple.src_addr, msg).await
}

/// Handle the given [`Message`] as [Refresh Request].
///
/// [Refresh Request]: https://datatracker.ietf.org/doc/html/rfc5766#section-7.2
async fn handle_refresh_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Conn + Send + Sync>,
    allocs: &Arc<Manager>,
    five_tuple: FiveTuple,
    uname: Username,
    realm: Realm,
    pass: Box<str>,
) -> Result<(), Error> {
    log::trace!("received RefreshRequest from {}", five_tuple.src_addr);

    let lifetime_duration = get_lifetime(&msg);
    if lifetime_duration == Duration::from_secs(0) {
        allocs.delete_allocation(&five_tuple).await;
    } else if let Some(a) = allocs.get_alloc(&five_tuple) {
        // If a server receives a Refresh Request with a
        // REQUESTED-ADDRESS-FAMILY attribute, and the
        // attribute's value doesn't match the address
        // family of the allocation, the server MUST reply with a 443
        // (Peer Address Family Mismatch) Refresh error
        // response. [RFC 6156, Section 5.2]
        if let Some(family) = msg
            .get_attribute::<RequestedAddressFamily>()
            .map(RequestedAddressFamily::address_family)
        {
            if (family == AddressFamily::V6 && !a.relay_addr().is_ipv6())
                || (family == AddressFamily::V4 && !a.relay_addr().is_ipv4())
            {
                let mut msg = Message::new(
                    MessageClass::ErrorResponse,
                    REFRESH,
                    msg.transaction_id(),
                );
                msg.add_attribute(ErrorCode::from(PeerAddressFamilyMismatch));

                answer_with_err(conn, five_tuple.src_addr, msg).await?;

                return Err(Error::PeerAddressFamilyMismatch);
            }
        }
        a.refresh(lifetime_duration).await;
    } else {
        return Err(Error::NoAllocationFound);
    }

    let mut msg = Message::new(
        MessageClass::SuccessResponse,
        REFRESH,
        msg.transaction_id(),
    );
    msg.add_attribute(
        Lifetime::new(lifetime_duration)
            .map_err(|e| Error::Encode(*e.kind()))?,
    );
    let integrity =
        MessageIntegrity::new_long_term_credential(&msg, &uname, &realm, &pass)
            .map_err(|e| Error::Encode(*e.kind()))?;
    msg.add_attribute(integrity);

    build_and_send(conn, five_tuple.src_addr, msg).await
}

/// Handles the given [`Message`] as a [CreatePermission Request][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-9.2
async fn handle_create_permission_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Conn + Send + Sync>,
    allocs: &Arc<Manager>,
    five_tuple: FiveTuple,
    uname: Username,
    realm: Realm,
    pass: Box<str>,
) -> Result<(), Error> {
    log::trace!("received CreatePermission from {}", five_tuple.src_addr);

    let Some(alloc) = allocs.get_alloc(&five_tuple) else {
        return Err(Error::NoAllocationFound);
    };

    let mut add_count = 0;

    for attr in msg.attributes() {
        let Attribute::XorPeerAddress(attr) = attr else {
            continue;
        };
        let addr = attr.address();

        // If an XOR-PEER-ADDRESS attribute contains an address of an
        // address family different than that of the relayed transport
        // address for the allocation, the server MUST generate an error
        // response with the 443 (Peer Address Family Mismatch) response
        // code. [RFC 6156, Section 6.2]
        if (addr.is_ipv4() && !alloc.relay_addr().is_ipv4())
            || (addr.is_ipv6() && !alloc.relay_addr().is_ipv6())
        {
            let mut msg = Message::new(
                MessageClass::ErrorResponse,
                CREATE_PERMISSION,
                msg.transaction_id(),
            );
            msg.add_attribute(ErrorCode::from(PeerAddressFamilyMismatch));

            answer_with_err(conn, five_tuple.src_addr, msg).await?;

            return Err(Error::PeerAddressFamilyMismatch);
        }

        log::trace!("adding permission for {}", addr);

        alloc.add_permission(addr.ip()).await;
        add_count += 1;
    }

    let resp_class = if add_count > 0 {
        MessageClass::SuccessResponse
    } else {
        MessageClass::ErrorResponse
    };

    let msg = {
        let mut msg =
            Message::new(resp_class, CREATE_PERMISSION, msg.transaction_id());
        let integrity = MessageIntegrity::new_long_term_credential(
            &msg, &uname, &realm, &pass,
        )
        .map_err(|e| Error::Encode(*e.kind()))?;
        msg.add_attribute(integrity);

        msg
    };

    build_and_send(conn, five_tuple.src_addr, msg).await
}

/// Handles the given [`Message`] as a [Send Indication][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-10.2
async fn handle_send_indication(
    msg: Message<Attribute>,
    allocs: &Arc<Manager>,
    five_tuple: FiveTuple,
) -> Result<(), Error> {
    log::trace!("received SendIndication from {}", five_tuple.src_addr);

    let Some(a) = allocs.get_alloc(&five_tuple) else {
        return Err(Error::NoAllocationFound);
    };

    let data_attr =
        msg.get_attribute::<Data>().ok_or(Error::AttributeNotFound)?;
    let peer_address = msg
        .get_attribute::<XorPeerAddress>()
        .map(XorPeerAddress::address)
        .ok_or(Error::AttributeNotFound)?;

    let has_perm = a.has_permission(&peer_address).await;
    if !has_perm {
        return Err(Error::NoPermission);
    }

    // TODO: dont clone
    a.relay(data_attr.data(), peer_address).await.map_err(Into::into)
}

/// Handles the given [`Message`] as a [ChannelBind Request][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.2
#[allow(clippy::too_many_arguments)]
async fn handle_channel_bind_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Conn + Send + Sync>,
    allocs: &Arc<Manager>,
    five_tuple: FiveTuple,
    channel_bind_lifetime: Duration,
    uname: Username,
    realm: Realm,
    pass: Box<str>,
) -> Result<(), Error> {
    if let Some(alloc) = allocs.get_alloc(&five_tuple) {
        let mut bad_request_msg = Message::new(
            MessageClass::ErrorResponse,
            CHANNEL_BIND,
            msg.transaction_id(),
        );
        bad_request_msg.add_attribute(ErrorCode::from(BadRequest));

        let Some(ch_num) =
            msg.get_attribute::<ChannelNumber>().map(|a| a.value())
        else {
            answer_with_err(conn, five_tuple.src_addr, bad_request_msg).await?;

            return Err(Error::AttributeNotFound);
        };
        let Some(peer_addr) =
            msg.get_attribute::<XorPeerAddress>().map(XorPeerAddress::address)
        else {
            answer_with_err(conn, five_tuple.src_addr, bad_request_msg).await?;

            return Err(Error::AttributeNotFound);
        };

        // If the XOR-PEER-ADDRESS attribute contains an address of
        // an address family different than that
        // of the relayed transport address for the
        // allocation, the server MUST generate an error response
        // with the 443 (Peer Address Family
        // Mismatch) response code. [RFC 6156, Section 7.2]
        if (peer_addr.is_ipv4() && !alloc.relay_addr().is_ipv4())
            || (peer_addr.is_ipv6() && !alloc.relay_addr().is_ipv6())
        {
            let mut peer_address_family_mismatch_msg = Message::new(
                MessageClass::ErrorResponse,
                CHANNEL_BIND,
                msg.transaction_id(),
            );
            peer_address_family_mismatch_msg
                .add_attribute(ErrorCode::from(PeerAddressFamilyMismatch));

            answer_with_err(
                conn,
                five_tuple.src_addr,
                peer_address_family_mismatch_msg,
            )
            .await?;

            return Err(Error::PeerAddressFamilyMismatch);
        }

        log::trace!("binding channel {ch_num} to {peer_addr}",);

        if let Err(err) = alloc
            .add_channel_bind(ch_num, peer_addr, channel_bind_lifetime)
            .await
        {
            answer_with_err(conn, five_tuple.src_addr, bad_request_msg).await?;

            return Err(err);
        }

        let mut msg = Message::new(
            MessageClass::SuccessResponse,
            CHANNEL_BIND,
            msg.transaction_id(),
        );

        let integrity = MessageIntegrity::new_long_term_credential(
            &msg, &uname, &realm, &pass,
        )
        .map_err(|e| Error::Encode(*e.kind()))?;
        msg.add_attribute(integrity);

        build_and_send(conn, five_tuple.src_addr, msg).await
    } else {
        Err(Error::NoAllocationFound)
    }
}

/// Responds the given [`Message`] with a [`MessageClass::ErrorResponse`] with
/// a new random nonce.
async fn respond_with_nonce(
    msg: &Message<Attribute>,
    response_code: ErrorCode,
    conn: &Arc<dyn Conn + Send + Sync>,
    realm: &str,
    five_tuple: FiveTuple,
    nonces: &Arc<Mutex<HashMap<String, Instant>>>,
) -> Result<(), Error> {
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    {
        // Nonce has already been taken
        let mut nonces = nonces.lock().await;
        if nonces.contains_key(&nonce) {
            return Err(Error::RequestReplay);
        }
        _ = nonces.insert(nonce.clone(), Instant::now());
    }

    let mut msg = Message::new(
        MessageClass::ErrorResponse,
        msg.method(),
        msg.transaction_id(),
    );
    msg.add_attribute(response_code);
    msg.add_attribute(Nonce::new(nonce).map_err(|e| Error::Encode(*e.kind()))?);
    msg.add_attribute(
        Realm::new(realm.to_owned()).map_err(|e| Error::Encode(*e.kind()))?,
    );

    build_and_send(conn, five_tuple.src_addr, msg).await
}

/// Encodes and sends the provided [`Message`] to the given [`SocketAddr`]
/// via given [`Conn`].
async fn build_and_send(
    conn: &Arc<dyn Conn + Send + Sync>,
    dst: SocketAddr,
    msg: Message<Attribute>,
) -> Result<(), Error> {
    let bytes = MessageEncoder::new()
        .encode_into_bytes(msg)
        .map_err(|e| Error::Encode(*e.kind()))?;

    _ = conn.send_to(bytes, dst).await?;
    Ok(())
}

/// Send a STUN packet and return the original error to the caller
async fn answer_with_err(
    conn: &Arc<dyn Conn + Send + Sync>,
    dst: SocketAddr,
    msg: Message<Attribute>,
) -> Result<(), Error> {
    build_and_send(conn, dst, msg).await?;

    Ok(())
}

/// Calculates a [`Lifetime`] fetching it from the given [`Message`] and
/// ensuring that it is not greater than configured
/// [`MAXIMUM_ALLOCATION_LIFETIME`].
fn get_lifetime(m: &Message<Attribute>) -> Duration {
    m.get_attribute::<Lifetime>().map(Lifetime::lifetime).map_or(
        DEFAULT_LIFETIME,
        |lifetime| {
            if lifetime > MAXIMUM_ALLOCATION_LIFETIME {
                DEFAULT_LIFETIME
            } else {
                lifetime
            }
        },
    )
}

#[cfg(test)]
mod request_test {
    use std::{net::IpAddr, str::FromStr};

    use tokio::{
        net::UdpSocket,
        time::{Duration, Instant},
    };

    use crate::{allocation::ManagerConfig, relay::RelayAllocator};

    use super::*;

    const STATIC_KEY: &str = "ABC";

    #[tokio::test]
    async fn test_allocation_lifetime_parsing() {
        let lifetime = Lifetime::new(Duration::from_secs(5)).unwrap();

        let mut m = Message::new(
            MessageClass::Request,
            ALLOCATE,
            TransactionId::new(random()),
        );
        let lifetime_duration = get_lifetime(&m);

        assert_eq!(
            lifetime_duration, DEFAULT_LIFETIME,
            "Allocation lifetime should be default time duration"
        );

        m.add_attribute(lifetime.clone());

        let lifetime_duration = get_lifetime(&m);
        assert_eq!(
            lifetime_duration,
            lifetime.lifetime(),
            "Expect lifetime_duration is {lifetime:?}, but \
            {lifetime_duration:?}"
        );
    }

    #[tokio::test]
    async fn test_allocation_lifetime_overflow() {
        let lifetime = Lifetime::new(MAXIMUM_ALLOCATION_LIFETIME * 2).unwrap();

        let mut m2 = Message::new(
            MessageClass::Request,
            ALLOCATE,
            TransactionId::new(random()),
        );
        m2.add_attribute(lifetime);

        let lifetime_duration = get_lifetime(&m2);
        assert_eq!(
            lifetime_duration, DEFAULT_LIFETIME,
            "Expect lifetime_duration is {DEFAULT_LIFETIME:?}, \
                but {lifetime_duration:?}"
        );
    }

    struct TestAuthHandler;
    impl AuthHandler for TestAuthHandler {
        fn auth_handle(
            &self,
            _username: &str,
            _realm: &str,
            _src_addr: SocketAddr,
        ) -> Result<Box<str>, Error> {
            Ok(STATIC_KEY.to_owned().into())
        }
    }

    #[tokio::test]
    async fn test_allocation_lifetime_deletion_zero_lifetime() {
        let conn: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let allocation_manager = Arc::new(Manager::new(ManagerConfig {
            relay_addr_generator: RelayAllocator {
                relay_address: IpAddr::from([127, 0, 0, 1]),
                min_port: 49152,
                max_port: 65535,
                max_retries: 10,
                address: String::from("127.0.0.1"),
            },
            alloc_close_notify: None,
        }));

        let socket =
            SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 5000);
        let five_tuple = FiveTuple {
            src_addr: socket,
            dst_addr: conn.local_addr(),
            protocol: conn.proto(),
        };
        let nonces = Arc::new(Mutex::new(HashMap::new()));

        nonces.lock().await.insert(STATIC_KEY.to_owned(), Instant::now());

        allocation_manager
            .create_allocation(
                five_tuple,
                Arc::clone(&conn),
                0,
                Duration::from_secs(3600),
                Username::new(String::from("user")).unwrap(),
                true,
            )
            .await
            .unwrap();

        assert!(allocation_manager.get_alloc(&five_tuple).is_some());

        let mut m: Message<Attribute> = Message::new(
            MessageClass::Request,
            REFRESH,
            TransactionId::new(random()),
        );
        m.add_attribute(Lifetime::new(Duration::default()).unwrap());
        m.add_attribute(Nonce::new(STATIC_KEY.to_owned()).unwrap());
        m.add_attribute(Realm::new(STATIC_KEY.to_owned()).unwrap());
        m.add_attribute(Username::new(STATIC_KEY.to_owned()).unwrap());
        let integrity = MessageIntegrity::new_long_term_credential(
            &m,
            &Username::new(STATIC_KEY.to_owned()).unwrap(),
            &Realm::new(STATIC_KEY.to_owned()).unwrap(),
            STATIC_KEY,
        )
        .unwrap();
        m.add_attribute(integrity);

        let bytes = MessageEncoder::new().encode_into_bytes(m).unwrap();

        let auth: Arc<dyn AuthHandler + Send + Sync> =
            Arc::new(TestAuthHandler {});
        handle_message(
            bytes,
            &conn,
            five_tuple,
            STATIC_KEY,
            Duration::from_secs(60),
            &allocation_manager,
            &nonces,
            &auth,
        )
        .await
        .unwrap();

        assert!(allocation_manager.get_alloc(&five_tuple).is_none());
    }
}
