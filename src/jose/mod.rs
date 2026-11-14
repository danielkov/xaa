//! A deliberately small JOSE subset: compact JWS with asymmetric signatures,
//! JWK / JWK Set public keys, and RFC 7638 thumbprints. See RFC-002.
//!
//! Everything the ID-JAG profile does not need is rejected at parse time:
//! `alg: none`, symmetric algorithms, JWE, `crit`, and JSON serialization.

mod alg;
mod jwk;
mod jws;
mod key;

pub use alg::{AlgorithmPolicy, SignatureAlgorithm};
pub use jwk::{Jwk, JwkSet};
pub use jws::{
    ExpectedTyp, JoseHeader, ParseLimits, UnverifiedJws, Verified, peek_typ, verify,
    verify_with_key,
};
pub use key::{JwsSigner, PrivateKey, SignFuture};

pub(crate) use jws::{parse_object_rejecting_duplicates, sign_jws};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// base64url without padding (RFC 7515 §2).
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url without padding: padding, whitespace, non-alphabet bytes,
/// and non-canonical trailing bits all fail.
pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.as_bytes()).ok()
}
