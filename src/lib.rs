#![cfg_attr(any(doc, test), doc = include_str!("../README.md"))]
#![cfg_attr(not(any(doc, test)), doc = env!("CARGO_PKG_NAME"))]
#![deny(nonstandard_style, rustdoc::all, trivial_casts, trivial_numeric_casts)]
#![forbid(non_ascii_idents, unsafe_code)]
#![warn(
    clippy::absolute_paths,
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::as_conversions,
    clippy::as_pointer_underscore,
    clippy::as_ptr_cast_mut,
    clippy::assertions_on_result_states,
    clippy::branches_sharing_code,
    clippy::cfg_not_test,
    clippy::clear_with_drain,
    clippy::clone_on_ref_ptr,
    clippy::coerce_container_to_any,
    clippy::collection_is_never_read,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::decimal_literal_representation,
    clippy::default_union_representation,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_include_without_cfg,
    clippy::empty_drop,
    clippy::empty_structs_with_brackets,
    clippy::equatable_if_let,
    clippy::empty_enum_variants_with_brackets,
    clippy::exit,
    clippy::expect_used,
    clippy::fallible_impl_from,
    clippy::filetype_is_file,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::get_unwrap,
    clippy::if_then_some_else_none,
    clippy::imprecise_flops,
    clippy::infinite_loop,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::iter_over_hash_type,
    clippy::iter_with_drain,
    clippy::large_include_file,
    clippy::large_stack_frames,
    clippy::let_underscore_untyped,
    clippy::literal_string_with_formatting_args,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::map_with_unused_argument_over_ranges,
    clippy::mem_forget,
    clippy::missing_assert_message,
    clippy::missing_asserts_for_indexing,
    clippy::missing_const_for_fn,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::multiple_inherent_impl,
    clippy::multiple_unsafe_ops_per_block,
    clippy::mutex_atomic,
    clippy::mutex_integer,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_raw_strings,
    clippy::non_zero_suggestions,
    clippy::nonstandard_macro_braces,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::panic_in_result_fn,
    clippy::partial_pub_fields,
    clippy::pathbuf_init_then_push,
    clippy::pedantic,
    clippy::precedence_bits,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::pub_without_shorthand,
    clippy::rc_buffer,
    clippy::rc_mutex,
    clippy::read_zero_byte_vec,
    clippy::redundant_clone,
    clippy::redundant_test_prefix,
    clippy::redundant_type_annotations,
    clippy::renamed_function_params,
    clippy::ref_patterns,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::return_and_then,
    clippy::same_name_method,
    clippy::semicolon_inside_block,
    clippy::set_contains_or_insert,
    clippy::shadow_unrelated,
    clippy::significant_drop_in_scrutinee,
    clippy::significant_drop_tightening,
    clippy::single_option_map,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_lit_as_bytes,
    clippy::string_lit_chars_any,
    clippy::string_slice,
    clippy::suboptimal_flops,
    clippy::suspicious_operation_groupings,
    clippy::suspicious_xor_used_as_pow,
    clippy::tests_outside_test_module,
    clippy::todo,
    clippy::too_long_first_doc_paragraph,
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
    clippy::unused_peekable,
    clippy::unused_result_ok,
    clippy::unused_trait_names,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    clippy::use_debug,
    clippy::use_self,
    clippy::useless_let_if_seq,
    clippy::verbose_file_reads,
    clippy::while_float,
    clippy::wildcard_enum_match_arm,
    ambiguous_negative_literals,
    closure_returning_async_block,
    future_incompatible,
    impl_trait_redundant_captures,
    let_underscore_drop,
    macro_use_extern_crate,
    meta_variable_misuse,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    redundant_lifetimes,
    rust_2018_idioms,
    single_use_lifetimes,
    unit_bindings,
    unnameable_types,
    unreachable_pub,
    unstable_features,
    unused,
    variant_size_differences
)]

mod allocation;
pub mod attr;
pub mod chandata;
pub mod relay;
mod server;
pub mod transport;

use std::{net::SocketAddr, sync::Arc};

use derive_more::with_trait::{Display, Error as StdError, From};
use secrecy::SecretString;

#[cfg(test)]
pub(crate) use self::allocation::Allocation;
pub(crate) use self::transport::Transport;
pub use self::{
    allocation::{FiveTuple, Info as AllocationInfo},
    chandata::ChannelData,
    server::{Config as ServerConfig, Server, TurnConfig},
};

// TODO: Try remove once `bytecodec` is updated to new major version.
/// Not really used, for surviving `minimal-versions` check only.
mod minimal_versions {
    use byteorder1 as _;
    use trackable1 as _;
}

/// Authentication handler.
pub trait AuthHandler {
    /// Performs authentication of the specified user, returning its ICE
    /// password on success.
    ///
    /// # Errors
    ///
    /// If authentication fails.
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
    ) -> Result<SecretString, Error>;
}

impl<T: ?Sized + AuthHandler> AuthHandler for Arc<T> {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
    ) -> Result<SecretString, Error> {
        (**self).auth_handle(username, realm, src_addr)
    }
}

/// [`AuthHandler`] always returning an [`Error`].
///
/// Can be used in type signatures when [TURN] is disabled.
///
/// [TURN]: https://en.wikipedia.org/wiki/TURN
#[derive(Clone, Copy, Debug)]
pub struct NoneAuthHandler;

impl AuthHandler for NoneAuthHandler {
    fn auth_handle(
        &self,
        _: &str,
        _: &str,
        _: SocketAddr,
    ) -> Result<SecretString, Error> {
        Err(Error::NoSuchUser)
    }
}

/// Possible errors of a [STUN]/[TURN] [`Server`].
///
/// [STUN]: https://en.wikipedia.org/wiki/STUN
/// [TURN]: https://en.wikipedia.org/wiki/TURN
#[derive(Debug, Display, Eq, From, PartialEq, StdError)]
#[non_exhaustive]
pub enum Error {
    /// Failed to allocate new relay connection, since maximum retires count
    /// exceeded.
    #[display("turn: max retries exceeded")]
    MaxRetriesExceeded,

    /// {eer address is part of a different address family than that of the
    /// relayed transport address of the allocation.
    #[display("error code 443: peer address family mismatch")]
    PeerAddressFamilyMismatch,

    /// Error when trying to perform action after closing server.
    #[display("use of closed network connection")]
    Closed,

    /// Channel binding request failed, since channel number is currently bound
    /// to a different transport address.
    #[display("cannot use the same channel number with different peer")]
    SameChannelDifferentPeer,

    /// Channel binding request failed, since the transport address is currently
    /// bound to a different channel number.
    #[display("cannot use the same peer number with different channel")]
    SamePeerDifferentChannel,

    /// Cannot create allocation with zero lifetime.
    #[display("allocations must not be created with a lifetime of 0")]
    LifetimeZero,

    /// Cannot create allocation for the same five-tuple.
    #[display("allocation attempt created with duplicate 5-TUPLE")]
    DupeFiveTuple,

    /// Authentication error.
    #[display("no such user exists")]
    NoSuchUser,

    /// Unsupported request class.
    #[display("unexpected class")]
    UnexpectedClass,

    /// Allocation request failed, since allocation already exists for the
    /// provided [`FiveTuple`].
    #[display("relay already allocated for 5-TUPLE")]
    RelayAlreadyAllocatedForFiveTuple,

    /// [STUN] message doesn't have a required attribute.
    ///
    /// [STUN]: https://en.wikipedia.org/wiki/STUN
    #[display("requested attribute not found")]
    AttributeNotFound,

    /// [STUN] message contains wrong [`MessageIntegrity`].
    ///
    /// [`MessageIntegrity`]: attr::MessageIntegrity
    /// [STUN]: https://en.wikipedia.org/wiki/STUN
    #[display("message integrity mismatch")]
    IntegrityMismatch,

    /// [DONT-FRAGMENT][1] attribute is not supported.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-14.8
    #[display("no support for DONT-FRAGMENT")]
    NoDontFragmentSupport,

    /// Allocation request cannot have both [RESERVATION-TOKEN][1] and
    /// [EVEN-PORT][2].
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-14.9
    /// [2]: https://tools.ietf.org/html/rfc5766#section-14.6
    #[display("Request must not contain RESERVATION-TOKEN and EVEN-PORT")]
    RequestWithReservationTokenAndEvenPort,

    /// Allocation request cannot contain both [RESERVATION-TOKEN][1] and
    /// [REQUESTED-ADDRESS-FAMILY][2].
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-14.9
    /// [2]: https://tools.ietf.org/html/rfc6156#section-4.1.1
    #[display(
        "Request must not contain RESERVATION-TOKEN \
            and REQUESTED-ADDRESS-FAMILY"
    )]
    RequestWithReservationTokenAndReqAddressFamily,

    /// No allocation for the provided [`FiveTuple`].
    #[display("no allocation found")]
    NoAllocationFound,

    /// The specified protocol is not supported.
    #[display("allocation requested unsupported proto")]
    UnsupportedRelayProto,

    /// Failed to handle [Send Indication][1], since there is no permission for
    /// the provided address.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-10.2
    #[display("unable to handle send-indication, no permission added")]
    NoPermission,

    /// Failed to handle channel data, since there is no binding for the
    /// provided channel.
    #[display("no such channel bind")]
    NoSuchChannelBind,

    /// Failed to encode message.
    #[display("Failed to encode STUN/TURN message: {_0:?}")]
    #[from(ignore)]
    Encode(#[error(not(source))] bytecodec::ErrorKind),

    /// Failed to send message.
    #[display("Transport error: {_0}")]
    Transport(transport::Error),
}
