//! Ingress [`Request`] handling.

use std::{
    collections::HashMap,
    marker::{Send, Sync},
    net::SocketAddr,
    sync::Arc,
};

use rand::{RngExt as _, distr::Alphanumeric};
use secrecy::{ExposeSecret as _, SecretString};
use stun_codec::{
    Attribute as _, Message, MessageClass,
    rfc5389::{
        errors::{BadRequest, StaleNonce, Unauthorized, UnknownAttribute},
        methods::BINDING,
    },
    rfc5766::{
        errors::{
            AllocationMismatch, InsufficientCapacity,
            UnsupportedTransportProtocol, WrongCredentials,
        },
        methods::{ALLOCATE, CHANNEL_BIND, CREATE_PERMISSION, REFRESH, SEND},
    },
    rfc8656::errors::{AddressFamilyNotSupported, PeerAddressFamilyMismatch},
};
use tokio::time::{Duration, Instant};

use crate::{
    AuthHandler, Error, TurnConfig,
    allocation::{Allocation, FiveTuple, Manager, ManagerConfig},
    attr::{
        AddressFamily, Attribute, ChannelNumber, Data, DontFragment, ErrorCode,
        EvenPort, Fingerprint, Lifetime, MessageIntegrity, Nonce, PROTO_UDP,
        Realm, RequestedAddressFamily, RequestedTransport, ReservationToken,
        UnknownAttributes, Username, XorMappedAddress, XorPeerAddress,
        XorRelayAddress,
    },
    chandata::ChannelData,
    server::{DEFAULT_ALLOC_LIFETIME, MAX_ALLOC_LIFETIME},
    transport::{Request, Transport},
};

/// Lifetime of a [`Nonce`] sent by a server.
const NONCE_LIFETIME: Duration = Duration::from_secs(3600);

/// Handles the provided [`Request`] according to [RFC 5389 Section 7.3][1].
///
/// # Errors
///
/// See the [`Error`] for details.
///
/// [1]: https://tools.ietf.org/html/rfc5389#section-7.3
pub(crate) async fn handle<Auth: AuthHandler>(
    req: Request,
    conn: &Arc<dyn Transport + Send + Sync>,
    five_tuple: FiveTuple,
    turn: &mut Option<TurnCtx<Auth>>,
) -> Result<(), Error> {
    match req {
        Request::ChannelData(data) => {
            if let Some(turn) = turn {
                handle_channel_data(data, five_tuple, &turn.alloc).await
            } else {
                log::warn!(
                    "Received a `ChannelData` message, but TURN is disabled",
                );
                Ok(())
            }
        }
        Request::Message(msg) => {
            use stun_codec::MessageClass::{Indication, Request};

            // This is the only STUN(rfc5389) message, it doesn't need TURN to
            // be enabled.
            if (msg.method(), msg.class()) == (BINDING, Request) {
                return handle_binding_request(msg, conn, five_tuple).await;
            }

            let Some(turn) = turn else {
                log::warn!("Received a TURN message, but TURN is disabled");
                return Ok(());
            };

            // This is the only TURN request that does not need to be
            // authenticated (it requires a previously authorized allocation)
            if (msg.method(), msg.class()) == (SEND, Indication) {
                return handle_send_indication(msg, &turn.alloc, five_tuple)
                    .await;
            }

            // All other TURN messages must be authorized.
            let Some(creds) =
                authenticate_request(&msg, conn, five_tuple, turn).await?
            else {
                return Ok(());
            };

            match (msg.method(), msg.class()) {
                (ALLOCATE, Request) => {
                    handle_allocate_request(
                        msg,
                        conn,
                        &mut turn.alloc,
                        five_tuple,
                        creds,
                    )
                    .await
                }
                (REFRESH, Request) => {
                    handle_refresh_request(
                        msg,
                        conn,
                        &mut turn.alloc,
                        five_tuple,
                        creds,
                    )
                    .await
                }
                (CREATE_PERMISSION, Request) => {
                    handle_create_permission_request(
                        msg,
                        conn,
                        &turn.alloc,
                        five_tuple,
                        creds,
                    )
                    .await
                }
                (CHANNEL_BIND, Request) => {
                    handle_channel_bind_request(
                        msg,
                        conn,
                        &turn.alloc,
                        five_tuple,
                        turn.conf.channel_bind_lifetime,
                        creds,
                    )
                    .await
                }
                (_, _) => Err(Error::UnexpectedClass),
            }
        }
    }
}

/// Relays the provided [`ChannelData`].
///
/// # Errors
///
/// - With an [`Error::NoAllocationFound`] if there is no [`Allocation`] found
///   for the provided [`FiveTuple`].
/// - Or if fails to relay the provided `data`.
async fn handle_channel_data(
    data: ChannelData,
    five_tuple: FiveTuple,
    allocs: &Manager,
) -> Result<(), Error> {
    log::trace!("Received `ChannelData` for {five_tuple}");

    // For all TURN messages (including ChannelData) EXCEPT an Allocate request,
    // if the 5-tuple does not identify an existing allocation, then the
    // message MUST either be rejected with a 437 Allocation Mismatch error
    // (if it is a request) or silently ignored (if it is an indication or a
    // ChannelData message).
    let Some(alloc) = allocs.get_alloc(&five_tuple) else {
        log::trace!("Could not find `Allocation` for {five_tuple}");
        return Ok(());
    };

    let Some(peer) = alloc.get_channel_addr(&data.num()).await else {
        // If the ChannelData message is received on a channel that is not bound
        // to any peer, then the message is silently discarded.
        log::trace!("`ChannelData` not bound to any peer");
        return Ok(());
    };

    alloc.relay(&data.data(), peer).await
}

/// Handles the provided [STUN] [`Message`] as an [Allocate request][1].
///
/// # Errors
///
/// See the [`Error`] for details.
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-6.2
/// [STUN]: https://en.wikipedia.org/wiki/STUN
// TODO: Refactor to satisfy `clippy::too_many_lines` lint.
#[expect(clippy::too_many_lines, reason = "needs refactoring")]
async fn handle_allocate_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Transport + Send + Sync>,
    allocs: &mut Manager,
    five_tuple: FiveTuple,
    creds: LongTermCredentials,
) -> Result<(), Error> {
    // 1. The server MUST require that the request be authenticated.  This
    //    authentication MUST be done using the long-term credential
    //    mechanism of [https://tools.ietf.org/html/rfc5389#section-10.2.2]
    //    unless the client and server agree to use another mechanism through
    //    some procedure outside the scope of this document.

    let mut requested_port = 0;
    let mut use_ipv4 = true;

    // 2. The server checks if the 5-tuple is currently in use by an existing
    //    allocation.  If yes, the server rejects the request with a 437
    //    (Allocation Mismatch) error.
    if allocs.get_alloc(&five_tuple).is_some() {
        respond_with_err(&msg, AllocationMismatch, conn, five_tuple.src_addr)
            .await;

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
        respond_with_err(&msg, BadRequest, conn, five_tuple.src_addr).await;

        return Err(Error::AttributeNotFound);
    };

    if requested_proto != PROTO_UDP {
        respond_with_err(
            &msg,
            UnsupportedTransportProtocol,
            conn,
            five_tuple.src_addr,
        )
        .await;

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
        let err_code = ErrorCode::from(UnknownAttribute);

        log::trace!(
            "Sending error response to {}: method={:?} transaction_id={:?} \
             code={} reason={}",
            five_tuple.src_addr,
            msg.method(),
            msg.transaction_id(),
            err_code.code(),
            err_code.reason_phrase(),
        );

        msg.add_attribute(err_code);
        msg.add_attribute(UnknownAttributes::new(vec![
            DontFragment.get_type(),
        ]));

        drop(conn.send_msg_to(msg, five_tuple.src_addr).await);

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
        respond_with_err(&msg, BadRequest, conn, five_tuple.src_addr).await;

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
            respond_with_err(
                &msg,
                AddressFamilyNotSupported,
                conn,
                five_tuple.src_addr,
            )
            .await;

            return Err(Error::RequestWithReservationTokenAndReqAddressFamily);
        }

        if req_family == AddressFamily::V6 {
            use_ipv4 = false;
        }
    }

    // 6. The server checks if the request contains an EVEN-PORT attribute. If
    //    yes, then the server checks that it can satisfy the request (i.e., can
    //    allocate a relayed transport address as described below). If the
    //    server cannot satisfy the request, then the server rejects the request
    //    with a 508 (Insufficient Capacity) error.
    if even_port.is_some() {
        let mut random_port = 1;

        while random_port % 2 != 0 {
            random_port = match allocs.get_random_even_port().await {
                Ok(port) => port,
                Err(err) => {
                    respond_with_err(
                        &msg,
                        InsufficientCapacity,
                        conn,
                        five_tuple.src_addr,
                    )
                    .await;

                    return Err(err);
                }
            };
        }

        requested_port = random_port;
    }

    // If the request contains a LIFETIME attribute, then the
    // server computes the minimum of the client's proposed lifetime and the
    // server's maximum allowed lifetime. If this computed value is greater
    // than the default lifetime, then the server uses the computed lifetime
    // as the initial value of the time-to-expiry field. Otherwise, the
    // server uses the default lifetime. It is RECOMMENDED that the server
    // use a maximum allowed lifetime value of no more than 3600 seconds (1
    // hour).
    let lifetime = msg
        .get_attribute::<Lifetime>()
        .map_or(DEFAULT_ALLOC_LIFETIME, Lifetime::lifetime)
        .min(MAX_ALLOC_LIFETIME)
        .max(DEFAULT_ALLOC_LIFETIME);
    let relay_addr = match allocs
        .create_allocation(
            five_tuple,
            Arc::clone(conn),
            requested_port,
            lifetime,
            creds.uname.clone(),
            use_ipv4,
        )
        .await
    {
        Ok(a) => a,
        Err(err) => {
            let stun_err = if matches!(err, Error::DupeFiveTuple) {
                ErrorCode::from(AllocationMismatch)
            } else {
                ErrorCode::from(InsufficientCapacity)
            };

            respond_with_err(&msg, stun_err, conn, five_tuple.src_addr).await;

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
        let mut msg = Message::new(
            MessageClass::SuccessResponse,
            ALLOCATE,
            msg.transaction_id(),
        );

        msg.add_attribute(XorRelayAddress::new(relay_addr));
        msg.add_attribute(
            Lifetime::new(lifetime).map_err(|e| Error::Encode(*e.kind()))?,
        );
        msg.add_attribute(XorMappedAddress::new(five_tuple.src_addr));
        msg.add_attribute(creds.integrity(&msg)?);

        msg
    };

    Ok(conn.send_msg_to(msg, five_tuple.src_addr).await?)
}

/// [TURN] [Long-Term Credential][0].
///
/// [TURN]: https://en.wikipedia.org/wiki/TURN
/// [0]: https://datatracker.ietf.org/doc/html/rfc5389#section-10.2
struct LongTermCredentials {
    /// String used to describe the server or a context within the server.
    ///
    /// The realm tells the client which username and password combination to
    /// use to authenticate requests.
    realm: Realm,

    /// [Long-Term Credential][0] username.
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc5389#section-10.2
    uname: Username,

    /// [Long-Term Credential][0] password.
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc5389#section-10.2
    upass: SecretString,
}

impl LongTermCredentials {
    /// Creates a [`MessageIntegrity`] for the provided [`Message`].
    fn integrity(
        &self,
        msg: &Message<Attribute>,
    ) -> Result<MessageIntegrity, Error> {
        MessageIntegrity::new_long_term_credential(
            msg,
            &self.uname,
            &self.realm,
            self.upass.expose_secret(),
        )
        .map_err(|e| Error::Encode(*e.kind()))
    }
}

/// Authenticates the provided [`Message`].
///
/// # Errors
///
/// See the [`Error`] for details.
async fn authenticate_request<Auth: AuthHandler>(
    msg: &Message<Attribute>,
    conn: &Arc<dyn Transport + Send + Sync>,
    five_tuple: FiveTuple,
    turn_ctx: &mut TurnCtx<Auth>,
) -> Result<Option<LongTermCredentials>, Error> {
    let Some(integrity) = msg.get_attribute::<MessageIntegrity>() else {
        respond_with_err_with_nonce(
            msg,
            ErrorCode::from(Unauthorized),
            conn,
            &turn_ctx.conf.realm,
            five_tuple,
            &mut turn_ctx.nonces,
        )
        .await?;
        return Ok(None);
    };

    let Some(nonce_attr) = &msg.get_attribute::<Nonce>() else {
        respond_with_err(msg, BadRequest, conn, five_tuple.src_addr).await;
        return Err(Error::AttributeNotFound);
    };

    let stale_nonce = {
        // Assert that the nonce exists and is not yet expired.
        let stale_nonce = turn_ctx.nonces.get(nonce_attr.value()).is_none_or(
            |nonce_creation_time| {
                Instant::now()
                    .checked_duration_since(*nonce_creation_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    >= NONCE_LIFETIME
            },
        );

        if stale_nonce {
            _ = turn_ctx.nonces.remove(nonce_attr.value());
        }
        stale_nonce
    };

    if stale_nonce {
        respond_with_err_with_nonce(
            msg,
            ErrorCode::from(StaleNonce),
            conn,
            &turn_ctx.conf.realm,
            five_tuple,
            &mut turn_ctx.nonces,
        )
        .await?;
        return Ok(None);
    }

    let Some(uname_attr) = msg.get_attribute::<Username>() else {
        respond_with_err(msg, BadRequest, conn, five_tuple.src_addr).await;
        return Err(Error::AttributeNotFound);
    };
    let Some(realm_attr) = msg.get_attribute::<Realm>() else {
        respond_with_err(msg, BadRequest, conn, five_tuple.src_addr).await;
        return Err(Error::AttributeNotFound);
    };

    let Ok(pass) = turn_ctx.conf.auth_handler.auth_handle(
        uname_attr.name(),
        realm_attr.text(),
        five_tuple.src_addr,
    ) else {
        respond_with_err(msg, BadRequest, conn, five_tuple.src_addr).await;
        return Err(Error::NoSuchUser);
    };

    if let Err(e) = integrity.check_long_term_credential(
        uname_attr,
        realm_attr,
        pass.expose_secret(),
    ) {
        respond_with_err(msg, e, conn, five_tuple.src_addr).await;
        Err(Error::IntegrityMismatch)
    } else {
        Ok(Some(LongTermCredentials {
            uname: uname_attr.clone(),
            realm: realm_attr.clone(),
            upass: pass,
        }))
    }
}

/// Sends a [`MessageClass::SuccessResponse`] message with a
/// [`XorMappedAddress`] attribute to the provided [`Transport`].
///
/// # Errors
///
/// See the [`Error`] for details.
async fn handle_binding_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Transport + Send + Sync>,
    five_tuple: FiveTuple,
) -> Result<(), Error> {
    log::trace!("Received `BindingRequest` for {five_tuple}");

    let mut msg = Message::new(
        MessageClass::SuccessResponse,
        BINDING,
        msg.transaction_id(),
    );
    msg.add_attribute(XorMappedAddress::new(five_tuple.src_addr));
    let fingerprint =
        Fingerprint::new(&msg).map_err(|e| Error::Encode(*e.kind()))?;
    msg.add_attribute(fingerprint);

    Ok(conn.send_msg_to(msg, five_tuple.src_addr).await?)
}

/// Handles the provided [`Message`] as a [Refresh Request][1].
///
/// # Errors
///
/// See the [`Error`] for details.
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-7.2
async fn handle_refresh_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Transport + Send + Sync>,
    allocs: &mut Manager,
    five_tuple: FiveTuple,
    creds: LongTermCredentials,
) -> Result<(), Error> {
    log::trace!("Received `RefreshRequest` for {five_tuple}");

    let alloc =
        get_alloc_for_uname(&msg, conn, allocs, five_tuple, &creds).await?;

    // The server computes a value called the "desired lifetime" as follows:
    // if the request contains a LIFETIME attribute and the attribute value
    // is 0, then the "desired lifetime" is 0. Otherwise, if the request
    // contains a LIFETIME attribute, then the server computes the minimum of
    // the client's requested lifetime and the server's maximum allowed
    // lifetime. If this computed value is greater than the default lifetime,
    // then the "desired lifetime" is the computed value. Otherwise, the
    // "desired lifetime" is the default lifetime.
    let lifetime = match msg.get_attribute::<Lifetime>().map(Lifetime::lifetime)
    {
        None => Some(DEFAULT_ALLOC_LIFETIME),
        Some(l) if l.is_zero() => None,
        Some(l) => Some(l.min(MAX_ALLOC_LIFETIME).max(DEFAULT_ALLOC_LIFETIME)),
    };

    // Subsequent processing depends on the "desired lifetime" value:
    //
    // o  If the "desired lifetime" is 0, then the request succeeds and the
    //    allocation is deleted.
    // o  If the "desired lifetime" is non-zero, then the request succeeds
    //    and the allocation's time-to-expiry is set to the "desired
    //    lifetime".
    if let Some(lifetime) = lifetime {
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
            if (family == AddressFamily::V6 && !alloc.relay_addr().is_ipv6())
                || (family == AddressFamily::V4
                    && !alloc.relay_addr().is_ipv4())
            {
                respond_with_err(
                    &msg,
                    PeerAddressFamilyMismatch,
                    conn,
                    five_tuple.src_addr,
                )
                .await;

                return Err(Error::PeerAddressFamilyMismatch);
            }
        }
        alloc.refresh(lifetime).await;
    } else {
        allocs.delete_allocation(&five_tuple);
    }

    let mut msg = Message::new(
        MessageClass::SuccessResponse,
        REFRESH,
        msg.transaction_id(),
    );
    msg.add_attribute(
        Lifetime::new(lifetime.unwrap_or(Duration::ZERO))
            .map_err(|e| Error::Encode(*e.kind()))?,
    );
    msg.add_attribute(creds.integrity(&msg)?);

    Ok(conn.send_msg_to(msg, five_tuple.src_addr).await?)
}

/// Handles the provided [`Message`] as a [CreatePermission Request][1].
///
/// # Errors
///
/// See the [`Error`] for details.
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-9.2
async fn handle_create_permission_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Transport + Send + Sync>,
    allocs: &Manager,
    five_tuple: FiveTuple,
    creds: LongTermCredentials,
) -> Result<(), Error> {
    log::trace!("Received `CreatePermission` for {five_tuple}");

    let alloc =
        get_alloc_for_uname(&msg, conn, allocs, five_tuple, &creds).await?;

    let mut add_count = 0;

    for attr in msg.attributes() {
        let Attribute::XorPeerAddress(attr) = attr else {
            continue;
        };
        let addr = attr.address();

        // If an XOR-PEER-ADDRESS attribute contains an address of an address
        // family different than that of the relayed transport address for the
        // allocation, the server MUST generate an error response with the 443
        // (Peer Address Family Mismatch) response code. [RFC 6156, Section 6.2]
        if (addr.is_ipv4() && !alloc.relay_addr().is_ipv4())
            || (addr.is_ipv6() && !alloc.relay_addr().is_ipv6())
        {
            respond_with_err(
                &msg,
                PeerAddressFamilyMismatch,
                conn,
                five_tuple.src_addr,
            )
            .await;

            return Err(Error::PeerAddressFamilyMismatch);
        }

        log::trace!("Adding permission for {addr}");

        alloc.add_permission(addr.ip()).await;
        add_count += 1;
    }

    // The CreatePermission request MUST contain at least one XOR-PEER-ADDRESS
    // attribute and MAY contain multiple such attributes. If no such attribute
    // exists, or if any of these attributes are invalid, then a 400
    // (Bad Request) error is returned.
    if add_count == 0 {
        respond_with_err(&msg, BadRequest, conn, five_tuple.src_addr).await;
        return Err(Error::AttributeNotFound);
    }

    let mut msg = Message::new(
        MessageClass::SuccessResponse,
        CREATE_PERMISSION,
        msg.transaction_id(),
    );
    msg.add_attribute(creds.integrity(&msg)?);

    Ok(conn.send_msg_to(msg, five_tuple.src_addr).await?)
}

/// Handles the provided [`Message`] as a [Send Indication][1].
///
/// # Errors
///
/// See the [`Error`] for details.
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-10.2
async fn handle_send_indication(
    msg: Message<Attribute>,
    allocs: &Manager,
    five_tuple: FiveTuple,
) -> Result<(), Error> {
    log::trace!("Received `SendIndication` for {five_tuple}");

    // For all TURN messages (including ChannelData) EXCEPT an Allocate request,
    // if the 5-tuple does not identify an existing allocation, then the
    // message MUST either be rejected with a 437 Allocation Mismatch error
    // (if it is a request) or silently ignored (if it is an indication or a
    // ChannelData message).
    let Some(a) = allocs.get_alloc(&five_tuple) else {
        log::trace!("Could not find `Allocation` for `SendIndication`");
        return Ok(());
    };

    // The Send indication MUST contain both an XOR-PEER-ADDRESS attribute and
    // a DATA attribute. If one of these attributes is missing or invalid, then
    // the message is discarded. Note that the DATA attribute is allowed to
    // contain zero bytes of data.
    let Some(data_attr) = msg.get_attribute::<Data>() else {
        log::trace!("`SendIndication` has no data");
        return Ok(());
    };
    let Some(peer_address) =
        msg.get_attribute::<XorPeerAddress>().map(XorPeerAddress::address)
    else {
        log::trace!("`SendIndication` has no `XorPeerAddress`");
        return Ok(());
    };

    // The server also checks that there is a permission installed for the IP
    // address contained in the XOR-PEER-ADDRESS attribute. If no such
    // permission exists, the message is discarded.
    if !a.has_permission(&peer_address).await {
        log::trace!("`SendIndication` has permission for {peer_address}");
        return Ok(());
    }

    a.relay(data_attr.data(), peer_address).await
}

/// Returns the [`Allocation`] matching the provided [`FiveTuple`] and
/// [`LongTermCredentials`] [`Username`].
///
/// Sends [`AllocationMismatch`] [`MessageClass::ErrorResponse`] if failed
/// to find [`Allocation`] with the given [`FiveTuple`].
///
/// Sends [`WrongCredentials`] [`MessageClass::ErrorResponse`] on [`Username`]
/// mismatch.
async fn get_alloc_for_uname<'a>(
    msg: &Message<Attribute>,
    conn: &Arc<dyn Transport + Send + Sync>,
    allocs: &'a Manager,
    five_tuple: FiveTuple,
    creds: &LongTermCredentials,
) -> Result<&'a Allocation, Error> {
    // When a TURN message arrives at the server from the client, the server
    // uses the 5-tuple in the message to identify the associated allocation.
    // For all TURN messages (including ChannelData) EXCEPT an Allocate request,
    // if the 5-tuple does not identify an existing allocation, then the
    // message MUST either be rejected with a 437 Allocation Mismatch error
    // (if it is a request) or silently ignored (if it is an indication or
    // a ChannelData message).
    let Some(alloc) = allocs.get_alloc(&five_tuple) else {
        respond_with_err(msg, AllocationMismatch, conn, five_tuple.src_addr)
            .await;

        return Err(Error::NoAllocationFound);
    };

    // if the 5-tuple identifies an existing allocation, but the request does
    // not use the same username as used to create the allocation, then the
    // request MUST be rejected with a 441 (Wrong Credentials) error.
    if creds.uname.name() != alloc.username().name() {
        respond_with_err(msg, WrongCredentials, conn, five_tuple.src_addr)
            .await;

        return Err(Error::WrongCredentials);
    }

    Ok(alloc)
}

/// Handles the provided [`Message`] as a [ChannelBind Request][1].
///
/// # Errors
///
/// See the [`Error`] for details.
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-11.2
async fn handle_channel_bind_request(
    msg: Message<Attribute>,
    conn: &Arc<dyn Transport + Send + Sync>,
    allocs: &Manager,
    five_tuple: FiveTuple,
    channel_bind_lifetime: Duration,
    creds: LongTermCredentials,
) -> Result<(), Error> {
    let alloc =
        get_alloc_for_uname(&msg, conn, allocs, five_tuple, &creds).await?;

    let Some(ch_num) = msg.get_attribute::<ChannelNumber>().map(|a| a.value())
    else {
        respond_with_err(&msg, BadRequest, conn, five_tuple.src_addr).await;

        return Err(Error::AttributeNotFound);
    };
    let Some(peer_addr) =
        msg.get_attribute::<XorPeerAddress>().map(XorPeerAddress::address)
    else {
        respond_with_err(&msg, BadRequest, conn, five_tuple.src_addr).await;

        return Err(Error::AttributeNotFound);
    };

    // Port 0 is not meaningful so reject it explicitly.
    if peer_addr.port() == 0 {
        respond_with_err(&msg, BadRequest, conn, five_tuple.src_addr).await;

        return Err(Error::AttributeNotFound);
    }

    // If the XOR-PEER-ADDRESS attribute contains an address of an address
    // family different than that of the relayed transport address for the
    // allocation, the server MUST generate an error response with the 443
    // (Peer Address Family Mismatch) response code. [RFC 6156, Section 7.2]
    if (peer_addr.is_ipv4() && !alloc.relay_addr().is_ipv4())
        || (peer_addr.is_ipv6() && !alloc.relay_addr().is_ipv6())
    {
        respond_with_err(
            &msg,
            PeerAddressFamilyMismatch,
            conn,
            five_tuple.src_addr,
        )
        .await;

        return Err(Error::PeerAddressFamilyMismatch);
    }

    log::trace!("Binding channel {ch_num} to {peer_addr}");

    if let Err(e) =
        alloc.add_channel_bind(ch_num, peer_addr, channel_bind_lifetime).await
    {
        respond_with_err(&msg, BadRequest, conn, five_tuple.src_addr).await;
        return Err(e);
    }

    let mut msg = Message::new(
        MessageClass::SuccessResponse,
        CHANNEL_BIND,
        msg.transaction_id(),
    );
    msg.add_attribute(creds.integrity(&msg)?);

    Ok(conn.send_msg_to(msg, five_tuple.src_addr).await?)
}

/// Responds to the provided [`Message`] with a [`MessageClass::ErrorResponse`]
/// with a new random nonce.
///
/// # Errors
///
/// See the [`Error`] for details.
async fn respond_with_err_with_nonce(
    msg: &Message<Attribute>,
    response_code: ErrorCode,
    conn: &Arc<dyn Transport + Send + Sync>,
    realm: &str,
    five_tuple: FiveTuple,
    nonces: &mut HashMap<String, Instant>,
) -> Result<(), Error> {
    let nonce: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    _ = nonces.insert(nonce.clone(), Instant::now());

    log::trace!(
        "Sending error response (with nonce) to {}: method={:?} \
         transaction_id={:?} code={} reason={}",
        five_tuple.src_addr,
        msg.method(),
        msg.transaction_id(),
        response_code.code(),
        response_code.reason_phrase(),
    );

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

    Ok(conn.send_msg_to(msg, five_tuple.src_addr).await?)
}

/// Sends a [`MessageClass::ErrorResponse`] to the client and returns the
/// original error to the caller.
///
/// # Errors
///
/// See the [`Error`] for details.
async fn respond_with_err(
    req: &Message<Attribute>,
    err: impl Into<ErrorCode>,
    conn: &Arc<dyn Transport + Send + Sync>,
    dst: SocketAddr,
) {
    let code = err.into();
    log::trace!(
        "Sending error response to {dst}: method={:?} \
         code={} reason={}",
        req.method(),
        code.code(),
        code.reason_phrase(),
    );
    let mut err_msg = Message::new(
        MessageClass::ErrorResponse,
        req.method(),
        req.transaction_id(),
    );
    err_msg.add_attribute(code);

    drop(conn.send_msg_to(err_msg, dst).await);
}

/// [TURN] server context.
///
/// [TURN]: https://en.wikipedia.org/wiki/TURN
pub(crate) struct TurnCtx<Auth> {
    /// [TURN] server configuration provided via external API.
    ///
    /// [TURN]: https://en.wikipedia.org/wiki/TURN
    pub conf: TurnConfig<Auth>,

    /// [Allocation] [`Manager`].
    ///
    /// [Allocation]: https://datatracker.ietf.org/doc/html/rfc5766#section-5
    pub alloc: Manager,

    /// [Nonce]s storage.
    ///
    /// [Nonce] is a string chosen at random by the server and included in the
    /// message-digest for preventing reply attacks.
    ///
    /// [Nonce]: https://en.wikipedia.org/wiki/Cryptographic_nonce
    pub nonces: HashMap<String, Instant>,
}

impl<A> From<TurnConfig<A>> for TurnCtx<A> {
    fn from(mut conf: TurnConfig<A>) -> Self {
        if conf.channel_bind_lifetime == Duration::from_secs(0) {
            conf.channel_bind_lifetime = DEFAULT_ALLOC_LIFETIME;
        }

        Self {
            alloc: Manager::new(ManagerConfig {
                relay_addr_generator: conf.relay_addr_generator.clone(),
                alloc_close_notify: conf.alloc_close_notify.clone(),
            }),
            conf,
            nonces: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod handle_spec {
    use std::{
        collections::HashMap,
        net::{IpAddr, SocketAddr},
        str::FromStr,
        sync::Arc,
    };

    use rand::random;
    use secrecy::SecretString;
    use stun_codec::{
        Message, MessageClass, TransactionId, rfc5766::methods::REFRESH,
    };
    use tokio::{
        net::UdpSocket,
        time::{Duration, Instant},
    };

    use super::{TurnCtx, handle};
    use crate::{
        AuthHandler, Error, FiveTuple, Transport, TurnConfig, allocation,
        attr::{Attribute, Lifetime, MessageIntegrity, Nonce, Realm, Username},
        relay,
        relay::Allocator,
        transport::Request,
    };

    const STATIC_KEY: &str = "ABC";

    struct TestAuthHandler;

    impl AuthHandler for TestAuthHandler {
        fn auth_handle(
            &self,
            _username: &str,
            _realm: &str,
            _src_addr: SocketAddr,
        ) -> Result<SecretString, Error> {
            Ok(STATIC_KEY.to_owned().into())
        }
    }

    #[tokio::test]
    async fn lifetime_deletion_zero_lifetime() {
        let conn: Arc<dyn Transport + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let mut allocation_manager =
            allocation::Manager::new(allocation::ManagerConfig {
                relay_addr_generator: relay::Allocator {
                    relay_address: IpAddr::from([127, 0, 0, 1]),
                    min_port: 49152,
                    max_port: 65535,
                    max_retries: 10,
                    address: String::from("127.0.0.1"),
                },
                alloc_close_notify: None,
            });

        let socket =
            SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 5000);
        let five_tuple = FiveTuple {
            src_addr: socket,
            dst_addr: conn.local_addr(),
            protocol: conn.proto(),
        };
        let mut nonces = HashMap::new();

        _ = nonces.insert(STATIC_KEY.to_owned(), Instant::now());

        _ = allocation_manager
            .create_allocation(
                five_tuple,
                Arc::clone(&conn),
                0,
                Duration::from_secs(3600),
                Username::new(STATIC_KEY.to_owned()).unwrap(),
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
        m.add_attribute(Lifetime::new(Duration::ZERO).unwrap());
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

        let mut turn = Some(TurnCtx {
            conf: TurnConfig {
                relay_addr_generator: Allocator {
                    relay_address: IpAddr::from([127, 0, 0, 1]),
                    min_port: 0,
                    max_port: 0,
                    max_retries: 0,
                    address: "".to_string(),
                },
                realm: STATIC_KEY.to_owned(),
                auth_handler: Arc::new(TestAuthHandler {}),
                channel_bind_lifetime: Duration::from_secs(60),
                alloc_close_notify: None,
            },
            alloc: allocation_manager,
            nonces,
        });
        assert!(turn.as_ref().unwrap().alloc.get_alloc(&five_tuple).is_some());
        handle(Request::Message(m), &conn, five_tuple, &mut turn)
            .await
            .unwrap();

        assert!(turn.as_ref().unwrap().alloc.get_alloc(&five_tuple).is_none());
    }
}
