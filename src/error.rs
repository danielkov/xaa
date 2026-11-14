//! The library error. See RFC-001 §7.
//!
//! One variant per rule, so a caller (and a log line) can tell exactly which
//! check failed. Server components wrap these in protocol errors that carry
//! the OAuth error code to return; this type never goes on the wire.

use crate::http::BoxError;

/// Errors raised by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // ----- JOSE: parse (RFC-002 §2) -------------------------------------------------
    /// The token is longer than the configured limit. Checked before decoding.
    #[error("token is {len} bytes, over the {max} byte limit")]
    TokenTooLong { len: usize, max: usize },
    /// Not a three-segment compact JWS, or a segment is not strict base64url.
    #[error("malformed JWS: {reason}")]
    MalformedJws { reason: &'static str },
    /// Five segments: a JWE. Encrypted JWTs are not supported (RFC-002 §12).
    #[error("encrypted JWT (JWE) is not supported")]
    EncryptedJwtUnsupported,
    /// The header `alg` is missing, is `none`, or names an unsupported algorithm.
    #[error("unsupported JWS algorithm: {alg}")]
    UnsupportedAlgorithm { alg: String },
    /// The header carries `crit`. No critical extension is understood.
    #[error("JWS header carries a crit parameter")]
    CriticalHeader,

    // ----- JOSE: verify (RFC-002 §3–§5) ---------------------------------------------
    /// The header `typ` is missing or is not the type required here.
    #[error("wrong JWT typ: expected {expected}, got {got:?}")]
    WrongTyp {
        expected: &'static str,
        got: Option<String>,
    },
    /// The header `alg` is not on the allow-list for this issuer.
    #[error("algorithm {alg} is not allowed")]
    DisallowedAlgorithm { alg: &'static str },
    /// The header names a `kid` that is not in the key set.
    #[error("no key with kid {kid:?}")]
    UnknownKeyId { kid: String },
    /// No `kid` in the header and the key set has zero or several usable keys.
    #[error("no kid in header and {candidates} keys are compatible with the algorithm")]
    AmbiguousKey { candidates: usize },
    /// The selected key cannot be used with the header `alg` (type, `alg`,
    /// `use`, or `key_ops` mismatch).
    #[error("key cannot be used here: {reason}")]
    KeyMismatch { reason: &'static str },
    /// An RSA key shorter than 2048 bits.
    #[error("RSA key is {bits} bits; at least 2048 are required")]
    WeakKey { bits: usize },
    /// The signature does not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// Signing failed.
    #[error("signing failed: {0}")]
    Signing(#[source] BoxError),

    // ----- JWK (RFC-002 §8) ---------------------------------------------------------
    /// A JWK or JWK Set is not well-formed.
    #[error("malformed JWK: {reason}")]
    MalformedJwk { reason: &'static str },
    /// A JWK carries private key members.
    #[error("JWK contains private key material")]
    PrivateKeyMaterial,
    /// A private key could not be imported.
    #[error("invalid private key: {reason}")]
    InvalidPrivateKey { reason: &'static str },

    // ----- Claims (RFC-002 §6) ------------------------------------------------------
    /// The payload is not a JSON object of the expected shape.
    #[error("malformed claims: {0}")]
    MalformedClaims(String),
    /// A required claim is absent.
    #[error("missing claim: {name}")]
    MissingClaim { name: &'static str },
    /// A claim is present but its value breaks a shape rule.
    #[error("invalid claim {name}: {reason}")]
    InvalidClaim {
        name: &'static str,
        reason: &'static str,
    },
    /// A `saml-nameid` subject identifier with the transient NameID format
    /// (draft §3.2.2).
    #[error("saml-nameid subject identifier uses the transient NameID format")]
    TransientNameId,

    // ----- Time (RFC-001 §8) --------------------------------------------------------
    /// The token's `exp` has passed.
    #[error("token has expired")]
    Expired,
    /// The token's `nbf` or `iat` is in the future.
    #[error("token is not yet valid")]
    NotYetValid,
    /// A time computation overflowed.
    #[error("time value out of range")]
    TimeOutOfRange,

    // ----- Client assertions (RFC-002 §9) -------------------------------------------
    /// A client assertion breaks one of the RFC 10070 rules.
    #[error("invalid client assertion: {reason}")]
    InvalidClientAssertion { reason: &'static str },
    /// An identifier was presented twice.
    #[error("replayed {what}")]
    Replayed { what: &'static str },
    /// The replay store returned an error. Fails closed.
    #[error("replay store error: {0}")]
    ReplayStore(#[source] BoxError),

    // ----- Configuration and caller bugs --------------------------------------------
    /// A configuration value is unusable.
    #[error("invalid configuration: {reason}")]
    InvalidConfiguration { reason: &'static str },

    // ----- Sender constraining (RFC-007) --------------------------------------------
    /// A DPoP proof breaks one of the RFC 9449 §4.3 rules.
    #[error("invalid DPoP proof: {reason}")]
    InvalidDpopProof { reason: &'static str },
    /// The server requires a DPoP nonce and the proof has none or a stale one.
    #[error("DPoP nonce required")]
    DpopNonceRequired,

    // ----- Metadata (RFC-006) -------------------------------------------------------
    /// A metadata document is not well-formed or lacks a required member.
    #[error("invalid metadata: {reason}")]
    InvalidMetadata { reason: &'static str },
    /// The metadata `issuer` is not identical to the issuer it was fetched for
    /// (draft §9.5, RFC 8414 §3.3). The document MUST NOT be used.
    #[error("metadata issuer mismatch: expected {expected}, got {got}")]
    MetadataIssuerMismatch { expected: String, got: String },
    /// The Protected Resource Metadata `resource` is not identical to the
    /// resource it was fetched for (draft §9.6, RFC 9728 §3.3).
    #[error("protected resource metadata resource mismatch: expected {expected}, got {got}")]
    PrmResourceMismatch { expected: String, got: String },
    /// An endpoint or identifier that must be `https` is not.
    #[error("insecure URL for {what}")]
    InsecureEndpoint { what: &'static str },
    /// A fetch returned an unexpected status or body.
    #[error("unexpected response fetching {what}: status {status}")]
    UnexpectedResponse { what: &'static str, status: u16 },

    // ----- Client (RFC-003) ---------------------------------------------------------
    /// A request cannot be built from the given inputs.
    #[error("invalid request: {reason}")]
    InvalidRequest { reason: &'static str },
    /// A token-endpoint success response breaks a response rule.
    #[error("invalid token response: {reason}")]
    InvalidTokenResponse { reason: &'static str },
    /// The issued ID-JAG is not a compact JWS typed `oauth-id-jag+jwt`.
    #[error("issued ID-JAG is malformed: {reason}")]
    MalformedIdJag { reason: &'static str },
    /// The issued ID-JAG's `aud` is not the Resource AS issuer.
    #[error("issued ID-JAG audience does not match the Resource AS")]
    IdJagAudienceMismatch,
    /// The issued ID-JAG's `client_id` is not the client's ID at the Resource AS.
    #[error("issued ID-JAG client_id does not match the client's registration at the Resource AS")]
    IdJagClientIdMismatch,
    /// The issued ID-JAG carries a `resource` that was not requested as sent.
    /// Resource identifiers are not secrets, so both sides are reported: the
    /// usual cause is an IdP that rewrote the identifier (a trailing slash,
    /// letter case) instead of echoing it byte for byte (draft §4.3.3).
    #[error(
        "issued ID-JAG carries resource {got:?}, which is not one of the requested {requested:?}"
    )]
    IdJagResourceAltered { got: String, requested: Vec<String> },
    /// A binding was requested and the ID-JAG is unbound or bound to another key.
    #[error("issued ID-JAG is not bound to the presented key")]
    BindingDowngrade,
    /// An unauthenticated request would carry an unbound ID-JAG.
    #[error("an unauthenticated access token request requires a sender-constrained ID-JAG")]
    UnauthenticatedUnboundGrant,
    /// A `cnf.jkt` ID-JAG without the matching DPoP key.
    #[error("the ID-JAG is DPoP-bound; the matching DPoP key is required")]
    DpopKeyRequired,
    /// DPoP binding for a Resource AS that does not support `jwt-dpop`.
    #[error("the Resource AS does not support the jwt-dpop grant")]
    ResourceAsLacksJwtDpop,
    /// The requested scope is not a subset of the ID-JAG's scope.
    #[error("requested scope is not a subset of the ID-JAG scope")]
    ScopeNotSubset,
    /// A token-exchange response whose `issued_token_type` is not the type
    /// that was requested (RFC 8693 §2.2.1, draft §4.3.4).
    #[error("unexpected issued_token_type: {got:?}")]
    UnexpectedIssuedTokenType { got: Option<String> },
    /// An access token response whose `token_type` is neither `Bearer` nor
    /// `DPoP`.
    #[error("unsupported access token type: {got}")]
    UnsupportedTokenType { got: String },
    /// A token endpoint answered with an OAuth error (RFC 6749 §5.2).
    #[cfg(feature = "client")]
    #[error("{0}")]
    TokenEndpoint(Box<crate::client::TokenEndpointError>),

    // ----- Grant invariants (RFC-004 §6, RFC-005 §5.3) ------------------------------
    /// Caller policy granted more than the ID-JAG carries.
    #[error("grant exceeds the ID-JAG: {what}")]
    GrantExceedsIdJag { what: &'static str },
    /// Caller policy granted more than the client requested.
    #[error("grant exceeds the request: {what}")]
    GrantExceedsRequest { what: &'static str },
    /// A `sub_id` for a Resource AS that did not ask for one (draft §9.9).
    #[error("sub_id supplied for a Resource AS that does not want one")]
    UnwantedSubId,

    // ----- Transport ----------------------------------------------------------------
    /// The caller's [`HttpClient`](crate::http::HttpClient) failed.
    #[error("HTTP transport error: {0}")]
    Http(#[source] BoxError),
}
