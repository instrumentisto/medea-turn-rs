//! [STUN] and [TURN] attributes used by a [`Server`].
//!
//! [`Server`]: crate::Server
//! [STUN]: https://en.wikipedia.org/wiki/STUN
//! [TURN]: https://en.wikipedia.org/wiki/TURN

use stun_codec::define_attribute_enums;

pub(crate) use stun_codec::{
    rfc5389::attributes::{
        AlternateServer, ErrorCode, Fingerprint, MappedAddress,
        MessageIntegrity, Nonce, Realm, Software, UnknownAttributes, Username,
        XorMappedAddress,
    },
    rfc5766::attributes::{
        ChannelNumber, Data, DontFragment, EvenPort, Lifetime,
        RequestedTransport, ReservationToken, XorPeerAddress, XorRelayAddress,
    },
    rfc8656::attributes::{AddressFamily, RequestedAddressFamily},
};

/// UDP protocol number according to [IANA].
///
/// [IANA]: https://tinyurl.com/iana-protocol-numbers
pub(crate) const PROTO_UDP: u8 = 17;

/// TCP protocol number according to [IANA].
///
/// [IANA]: https://tinyurl.com/iana-protocol-numbers
pub(crate) const PROTO_TCP: u8 = 6;

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [
        // RFC 5389
        MappedAddress,
        Username,
        MessageIntegrity,
        ErrorCode,
        UnknownAttributes,
        Realm,
        Nonce,
        XorMappedAddress,
        Software,
        AlternateServer,
        Fingerprint,
        // RFC 5766
        ChannelNumber,
        Lifetime,
        XorPeerAddress,
        Data,
        XorRelayAddress,
        EvenPort,
        RequestedTransport,
        DontFragment,
        ReservationToken,
        // RFC 8656
        RequestedAddressFamily
    ]
);
