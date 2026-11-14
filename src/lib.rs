//! `xaa` — stateless Cross App Access (XAA) toolkit.
//!
//! Implements the Identity Assertion JWT Authorization Grant
//! (`draft-ietf-oauth-identity-assertion-authz-grant`, "ID-JAG"), the
//! protocol behind [Cross App Access](https://xaa.dev/).
//!
//! # Components
//!
//! Named after the draft's roles (§2.1).
//!
//! - **Client** (`client` feature) — the requesting app. Exchanges an
//!   IdP-issued subject token (ID Token, SAML assertion, or refresh token)
//!   for an ID-JAG (§4.3 Token Exchange), then presents the ID-JAG to the
//!   Resource Authorization Server (§4.4 Access Token Request).
//! - **Resource AS** (`resource-as` feature) — the Resource Authorization
//!   Server. Validates a presented ID-JAG (`typ`, signature, issuer trust,
//!   audience, `client_id` binding, lifetime, `jti` replay) and hands the
//!   caller a verified grant to mint its own access token from.
//! - **IdP** (`idp` feature, off by default) — the IdP Authorization
//!   Server. Issues ID-JAGs at the token-exchange endpoint. Exists so the
//!   client and Resource AS can be proven against each other without
//!   third-party software in the loop.

pub mod claims;
pub mod client_auth;
pub mod dpop;
pub mod error;
mod form;
pub mod http;
pub mod jose;
pub mod metadata;
pub mod mtls;
pub mod oauth_error;
pub mod replay;
pub mod secret;

pub use error::Error;

#[cfg(test)]
mod test_support;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "idp")]
pub mod idp;
#[cfg(feature = "resource-as")]
pub mod resource_as;

/// Thin shims into otherwise `pub(crate)` parsing entry points for the
/// `cargo-fuzz` harnesses under `fuzz/`. Compiled only under
/// `--cfg fuzzing`; invisible to regular builds, docs, and downstream
/// callers.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod __fuzz {
    use serde_json::{Map, Value};

    use crate::claims::IdJagClaims;
    use crate::jose::{ParseLimits, UnverifiedJws};

    /// Compact-JWS structure checks, then ID-JAG claim-shape rules on the
    /// (unverified) payload: everything that runs on attacker-supplied
    /// `assertion` bytes apart from the signature check itself.
    pub fn id_jag_decode(data: &[u8]) {
        let Ok(token) = std::str::from_utf8(data) else {
            return;
        };
        let Ok(jws) = UnverifiedJws::parse(token, &ParseLimits::default()) else {
            return;
        };
        if let Ok(object) = serde_json::from_slice::<Map<String, Value>>(jws.payload_unverified())
            && let Ok(claims) = IdJagClaims::from_object(object)
        {
            // Whatever parses must serialize to something that parses again.
            // (Not necessarily to an equal value: a fractional NumericDate is
            // emitted as an integer.)
            assert!(IdJagClaims::from_object(claims.to_object()).is_ok());
        }
    }
}
