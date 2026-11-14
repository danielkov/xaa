//! The typed ID-JAG claim set and the value types it is built from.
//! See RFC-002 §6 and draft §3.1.
//!
//! Shape rules are applied when claims are parsed, each with its own
//! [`Error`](crate::Error) variant. Values that the protocol compares are kept
//! byte-for-byte: issuers, audiences, and resource identifiers are compared
//! by simple string comparison and never normalized (draft §4.3, RFC 3986
//! §6.2.1).

mod id_jag;
mod types;

pub use id_jag::{Actor, IdJagClaims};
pub use types::{
    Audience, AuthorizationDetail, AuthorizationDetails, Confirmation, Issuer, NumericDate,
    Resources, SamlNameId, Scope, SubjectIdentifier,
};

#[cfg(any(test, feature = "idp"))]
pub(crate) use types::NAMEID_FORMAT_TRANSIENT;
