//! A pure Rust implementation of TURN.

#![deny(
    macro_use_extern_crate,
    nonstandard_style,
    rust_2018_idioms,
    rustdoc::all,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code
)]
#![forbid(non_ascii_idents)]
#![warn(
    clippy::absolute_paths,
    clippy::as_conversions,
    clippy::as_ptr_cast_mut,
    clippy::assertions_on_result_states,
    clippy::branches_sharing_code,
    clippy::clear_with_drain,
    clippy::clone_on_ref_ptr,
    clippy::collection_is_never_read,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::decimal_literal_representation,
    clippy::default_union_representation,
    clippy::derive_partial_eq_without_eq,
    clippy::else_if_without_else,
    clippy::empty_drop,
    clippy::empty_line_after_outer_attr,
    clippy::empty_structs_with_brackets,
    clippy::equatable_if_let,
    clippy::empty_enum_variants_with_brackets,
    clippy::exit,
    clippy::expect_used,
    clippy::fallible_impl_from,
    clippy::filetype_is_file,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast,
    clippy::fn_to_numeric_cast_any,
    clippy::format_push_string,
    clippy::get_unwrap,
    clippy::if_then_some_else_none,
    clippy::imprecise_flops,
    clippy::index_refutable_slice,
    clippy::infinite_loop,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::iter_over_hash_type,
    clippy::iter_with_drain,
    clippy::large_include_file,
    clippy::large_stack_frames,
    clippy::let_underscore_untyped,
    clippy::lossy_float_literal,
    clippy::manual_c_str_literals,
    clippy::manual_clamp,
    clippy::map_err_ignore,
    clippy::mem_forget,
    clippy::missing_assert_message,
    clippy::missing_asserts_for_indexing,
    clippy::missing_const_for_fn,
    clippy::missing_docs_in_private_items,
    clippy::multiple_inherent_impl,
    clippy::multiple_unsafe_ops_per_block,
    clippy::mutex_atomic,
    clippy::mutex_integer,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_raw_strings,
    clippy::nonstandard_macro_braces,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::panic_in_result_fn,
    clippy::partial_pub_fields,
    clippy::pedantic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::pub_without_shorthand,
    clippy::ref_as_ptr,
    clippy::rc_buffer,
    clippy::rc_mutex,
    clippy::read_zero_byte_vec,
    clippy::readonly_write_lock,
    clippy::redundant_clone,
    clippy::redundant_type_annotations,
    clippy::ref_patterns,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_name_method,
    clippy::semicolon_inside_block,
    clippy::shadow_unrelated,
    clippy::significant_drop_in_scrutinee,
    clippy::significant_drop_tightening,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_lit_as_bytes,
    clippy::string_lit_chars_any,
    clippy::string_slice,
    clippy::string_to_string,
    clippy::suboptimal_flops,
    clippy::suspicious_operation_groupings,
    clippy::suspicious_xor_used_as_pow,
    clippy::tests_outside_test_module,
    clippy::todo,
    clippy::trailing_empty_array,
    clippy::transmute_undefined_repr,
    clippy::trivial_regex,
    clippy::try_err,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::uninhabited_references,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc,
    clippy::unnecessary_self_imports,
    clippy::unnecessary_struct_initialization,
    clippy::unneeded_field_pattern,
    clippy::unused_peekable,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    clippy::use_debug,
    clippy::use_self,
    clippy::useless_let_if_seq,
    clippy::verbose_file_reads,
    clippy::wildcard_enum_match_arm,
    explicit_outlives_requirements,
    future_incompatible,
    let_underscore_drop,
    meta_variable_misuse,
    missing_abi,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    semicolon_in_expressions_from_macros,
    single_use_lifetimes,
    unit_bindings,
    unreachable_pub,
    unsafe_op_in_unsafe_fn,
    unstable_features,
    unused_crate_dependencies,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_macro_rules,
    unused_qualifications,
    unused_results,
    variant_size_differences
)]
#![cfg_attr(test, allow(unused_crate_dependencies, unused_lifetimes))]

mod allocation;
mod attr;
mod chandata;
mod con;
mod relay;
mod server;

use std::{io, net::SocketAddr};

use thiserror::Error;

pub use self::{
    allocation::{AllocInfo, FiveTuple},
    con::TcpServer,
    relay::RelayAllocator,
    server::{Config, ConnConfig, Server},
};

/// External authentication handler.
pub trait AuthHandler {
    /// Perform authentication of the given user data returning ICE password
    /// on success.
    ///
    /// # Errors
    ///
    /// If authentication fails.
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
    ) -> Result<Box<str>, Error>;
}

/// TURN server errors.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
#[allow(variant_size_differences)]
pub enum Error {
    /// Failed to allocate new relay connection sine maximum retires count
    /// exceeded.
    #[error("turn: max retries exceeded")]
    MaxRetriesExceeded,

    /// Failed to handle channel data since channel number is incorrect.
    #[error("channel number not in [0x4000, 0x7FFF]")]
    InvalidChannelNumber,

    /// Failed to handle channel data cause of incorrect message length.
    #[error("channelData length != len(Data)")]
    BadChannelDataLength,

    /// Failed to handle message since it's shorter than expected.
    #[error("unexpected EOF")]
    UnexpectedEof,

    /// A peer address is part of a different address family than that of the
    /// relayed transport address of the allocation.
    #[error("error code 443: peer address family mismatch")]
    PeerAddressFamilyMismatch,

    /// Error when trying to perform action after closing server.
    #[error("use of closed network connection")]
    Closed,

    /// Channel binding request failed since channel number is currently bound
    /// to a different transport address.
    #[error("you cannot use the same channel number with different peer")]
    SameChannelDifferentPeer,

    /// Channel binding request failed since the transport address is currently
    /// bound to a different channel number.
    #[error("you cannot use the same peer number with different channel")]
    SamePeerDifferentChannel,

    /// Cannot create allocation with zero lifetime.
    #[error("allocations must not be created with a lifetime of 0")]
    LifetimeZero,

    /// Cannot create allocation for the same five-tuple.
    #[error("allocation attempt created with duplicate FiveTuple")]
    DupeFiveTuple,

    /// The given nonce is wrong or already been used.
    #[error("duplicated Nonce generated, discarding request")]
    RequestReplay,

    /// Authentication error.
    #[error("no such user exists")]
    NoSuchUser,

    /// Unsupported request class.
    #[error("unexpected class")]
    UnexpectedClass,

    /// Allocate request failed since allocation already exists for the given
    /// five-tuple.
    #[error("relay already allocated for 5-TUPLE")]
    RelayAlreadyAllocatedForFiveTuple,

    /// STUN message does not have a required attribute.
    #[error("requested attribute not found")]
    AttributeNotFound,

    /// STUN message contains wrong message integrity.
    #[error("message integrity mismatch")]
    IntegrityMismatch,

    /// [DONT-FRAGMENT][1] attribute is not supported.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-14.8
    #[error("no support for DONT-FRAGMENT")]
    NoDontFragmentSupport,

    /// Allocate request cannot have both [RESERVATION-TOKEN][1] and
    /// [EVEN-PORT].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-14.9
    /// [EVEN-PORT]: https://datatracker.ietf.org/doc/html/rfc5766#section-14.6
    #[error("Request must not contain RESERVATION-TOKEN and EVEN-PORT")]
    RequestWithReservationTokenAndEvenPort,

    /// Allocation request cannot contain both [RESERVATION-TOKEN][1] and
    /// [REQUESTED-ADDRESS-FAMILY][2].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-14.9
    /// [2]: https://www.rfc-editor.org/rfc/rfc6156#section-4.1.1
    #[error(
        "Request must not contain RESERVATION-TOKEN \
            and REQUESTED-ADDRESS-FAMILY"
    )]
    RequestWithReservationTokenAndReqAddressFamily,

    /// No allocation for the given five-tuple.
    #[error("no allocation found")]
    NoAllocationFound,

    /// The specified protocol is not supported.
    #[error("allocation requested unsupported proto")]
    UnsupportedRelayProto,

    /// Failed to handle send indication since there is no permission for the
    /// given address.
    #[error("unable to handle send-indication, no permission added")]
    NoPermission,

    /// Failed to handle channel data since ther is no binding for the given
    /// channel.
    #[error("no such channel bind")]
    NoSuchChannelBind,

    /// Failed to decode message.
    #[error("Failed to decode STUN/TURN message: {0:?}")]
    Decode(bytecodec::ErrorKind),

    /// Failed to encode message.
    #[error("Failed to encode STUN/TURN message: {0:?}")]
    Encode(bytecodec::ErrorKind),

    /// Tried to use dead transport.
    #[error("Underlying TCP/UDP transport is dead")]
    TransportIsDead,

    /// Error for transport.
    #[error("{0}")]
    Io(#[source] IoError),
}

/// [`io::Error`] wrapper.
#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(IoError(e))
    }
}
