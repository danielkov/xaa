//! Sender constraining with DPoP (RFC 9449) and the `jwt-dpop` grant
//! (draft-parecki-oauth-jwt-dpop-grant). See RFC-007.
//!
//! An ID-JAG bound to a key is useless to anyone who copies it without the
//! key (draft §9.11). The binding is made at the IdP during the token
//! exchange and checked at the Resource AS during the access token request.
//!
//! - Client: [`DpopKey`] holds the key and builds proofs; [`DpopRequest`]
//!   asks a token call to use it.
//! - Servers: [`validate_dpop_proof`] runs the RFC 9449 §4.3 checks,
//!   [`ValidatedDpopProof::consume`] records the proof `jti` last, and
//!   [`DpopNonce`] supplies server nonces.
//! - Both: [`IdpBinding`] and [`ResourceAsBinding`] are the decision tables
//!   of RFC-007 §4, covering certificate binding ([`crate::mtls`]) as well.

mod binding;
mod key;
mod validate;

pub use binding::{
    AccessTokenBinding, AssertionGrantType, BindingPreference, BindingRejection,
    DpopToNonSupportingAs, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_JWT_DPOP, IdpBinding,
    ResourceAsBinding, require_sender_constraint,
};
pub use key::{DpopKey, DpopRequest};
pub use validate::{
    DEFAULT_MAX_AGE, DPOP_HEADER, DPOP_NONCE_HEADER, DpopError, DpopNonce, DpopValidation,
    ValidatedDpopProof, default_dpop_algorithms, has_dpop_header, validate_dpop_proof,
};
