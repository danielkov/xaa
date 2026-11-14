//! The token endpoint's protocol error. See RFC-004 §7 and RFC-001 §7.

use crate::client_auth::ClientCredentials;
use crate::dpop::{BindingRejection, DpopError};
use crate::error::Error;
use crate::http::HttpResponse;
use crate::oauth_error::{ErrorResponseExtras, OAuthErrorCode, error_response};

/// The exact rule a token request failed. For the caller's logs only: it
/// never goes on the wire (draft §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RejectReason {
    // ----- Request parsing (RFC-004 §2) ---------------------------------------------
    /// No `grant_type` parameter.
    #[error("grant_type is missing")]
    MissingGrantType,
    /// A grant other than jwt-bearer and jwt-dpop.
    #[error("grant_type is neither jwt-bearer nor jwt-dpop")]
    UnsupportedGrantType,
    /// No `assertion` parameter.
    #[error("assertion is missing")]
    MissingAssertion,
    /// A parameter that may appear once appeared more often (RFC 6749 §3.2).
    #[error("parameter {name} is repeated")]
    RepeatedParameter { name: &'static str },
    /// The `scope` parameter is not a list of RFC 6749 §3.3 scope tokens.
    #[error("scope parameter is malformed")]
    MalformedScope,
    /// More than one `DPoP` header (RFC 9449 §4.3 check 1).
    #[error("more than one DPoP header")]
    MultipleDpopProofs,
    /// More than one client authentication method (RFC 6749 §2.3).
    #[error("more than one client authentication method")]
    MultipleClientAuthMethods,
    /// Client credentials are present but unusable.
    #[error("client credentials are malformed")]
    MalformedClientCredentials,
    /// The TLS client certificate handed in by the caller is not DER.
    #[error("the TLS client certificate is not DER")]
    InvalidClientCertificate,

    // ----- Preconditions (RFC-004 §3, §8) -------------------------------------------
    /// An unauthenticated client, and the server does not accept those.
    #[error("unauthenticated clients are not accepted")]
    UnauthenticatedClientNotAllowed,
    /// [`JtiPolicy::SingleUse`](super::JtiPolicy::SingleUse) without a
    /// replay store: a deployment error.
    #[error("single-use ID-JAGs need a replay store and none was given")]
    ReplayStoreMissing,
    /// `now` and `clock_skew` do not add up to a representable time.
    #[error("time value out of range")]
    TimeOutOfRange,

    // ----- §4 rule 1 ----------------------------------------------------------------
    /// `jwt-dpop` without a DPoP proof (jwt-dpop-grant §5 step 1).
    #[error("the jwt-dpop grant requires a DPoP proof")]
    DpopProofMissing,
    /// The DPoP proof breaks an RFC 9449 §4.3 rule.
    #[error("the DPoP proof is invalid")]
    DpopProofInvalid,
    /// A DPoP nonce is required and the proof has none or a stale one.
    #[error("a DPoP nonce is required")]
    DpopNonceRequired,

    // ----- §4 rules 2–8 -------------------------------------------------------------
    /// Rule 2: the assertion is not a compact JWS within limits.
    #[error("the assertion is not a well-formed compact JWS")]
    MalformedAssertion,
    /// Rule 3: header `typ` is not `oauth-id-jag+jwt`.
    #[error("the assertion typ is not oauth-id-jag+jwt")]
    WrongTyp,
    /// Rule 4: `iss` is unreadable or names no trusted issuer.
    #[error("the assertion issuer is not trusted")]
    UntrustedIssuer,
    /// Rule 5: `iss` is this server's own issuer (draft §9.4).
    #[error("the assertion was issued by this server")]
    SelfIssued,
    /// Rule 6: the caller has no JWK Set for the issuer.
    #[error("no keys are available for the issuer")]
    NoKeysForIssuer,
    /// Rule 6: the header `alg` is not on the issuer's allow-list.
    #[error("the signature algorithm is not allowed for the issuer")]
    DisallowedAlgorithm,
    /// Rule 6: the header `kid` is not in the issuer's key set. Refresh the
    /// JWKS and retry once.
    #[error("the key ID is not in the issuer's key set")]
    UnknownKeyId,
    /// Rule 6: no key in the set can be used for this signature.
    #[error("no usable verification key")]
    NoUsableKey,
    /// Rule 6: the signature does not verify.
    #[error("the signature does not verify")]
    InvalidSignature,
    /// Rule 7: the payload is not a JSON object.
    #[error("the claims are not a JSON object")]
    MalformedClaims,
    /// Rule 7: a required claim is absent.
    #[error("required claim {name} is missing")]
    MissingClaim { name: &'static str },
    /// Rule 7: a claim breaks a shape rule.
    #[error("claim {name} is invalid")]
    InvalidClaim { name: &'static str },
    /// Rule 8: `aud` is not exactly this server's issuer identifier.
    #[error("aud is not this server's issuer identifier as the sole value")]
    AudienceMismatch,

    // ----- §4 rule 9 ----------------------------------------------------------------
    /// `exp` has passed.
    #[error("the ID-JAG has expired")]
    Expired,
    /// `iat` or `nbf` is in the future.
    #[error("the ID-JAG is not yet valid")]
    NotYetValid,
    /// `exp` is before `iat`.
    #[error("exp is before iat")]
    ExpiresBeforeIssued,
    /// `exp - iat` is over the configured maximum (draft §4.4.4).
    #[error("the ID-JAG lifetime exceeds the maximum")]
    LifetimeTooLong,

    // ----- §4 rule 10 ---------------------------------------------------------------
    /// A multi-tenant issuer's ID-JAG has no `tenant`.
    #[error("tenant is missing for a multi-tenant issuer")]
    MissingTenant,
    /// The issuer tenant is not trusted.
    #[error("the issuer tenant is not trusted")]
    UntrustedTenant,
    /// The issuer tenant maps to more than one recipient tenant.
    #[error("the recipient tenant is ambiguous")]
    AmbiguousTenant,

    // ----- §4 rule 11 ---------------------------------------------------------------
    /// The `client_id` claim is not the client making the request.
    #[error("client_id does not match the requesting client")]
    ClientIdMismatch,
    /// The client is not registered in the recipient tenant (draft §6.2).
    #[error("the client does not belong to the recipient tenant")]
    ClientNotInTenant,
    /// An unauthenticated client presented an ID-JAG without `cnf`.
    #[error("an unauthenticated client presented an unbound ID-JAG")]
    UnauthenticatedUnboundGrant,

    // ----- §4 rule 12, §6 -----------------------------------------------------------
    /// The sender-constraint decision table rejected the request (RFC-007 §4.2).
    #[error("sender constraint: {0}")]
    SenderConstraint(BindingRejection),

    // ----- §4 rule 13 ---------------------------------------------------------------
    /// `sub_id` is not a well-formed Subject Identifier.
    #[error("sub_id is malformed")]
    MalformedSubjectIdentifier,
    /// `sub_id` uses a format other than `saml-nameid`.
    #[error("the sub_id format is not supported")]
    UnsupportedSubjectIdentifier,
    /// `sub_id.issuer` is not associated with the ID-JAG issuer (draft §9.8).
    #[error("the sub_id SAML issuer is not authorized for the ID-JAG issuer")]
    UntrustedSamlIssuer,
    /// The issuer requires a `saml-nameid` subject and the ID-JAG has none.
    #[error("a saml-nameid sub_id is required")]
    SamlSubjectRequired,

    // ----- §4 rules 14–16 -----------------------------------------------------------
    /// `resource` is absent and the server requires it.
    #[error("the resource claim is required")]
    MissingResource,
    /// A `resource` value is not governed by this server for the tenant.
    #[error("a resource is not governed by this server")]
    ResourceNotGoverned,
    /// `authorization_details` is not an RFC 9396 array.
    #[error("authorization_details is malformed")]
    InvalidAuthorizationDetails,
    /// The DPoP proof's `jti` was seen before (RFC 9449 §11.1).
    #[error("the DPoP proof was replayed")]
    DpopProofReplayed,
    /// The ID-JAG's `jti` was seen before.
    #[error("the ID-JAG was replayed")]
    Replayed,
    /// The replay store failed. Fails closed.
    #[error("the replay store is unavailable")]
    ReplayStoreUnavailable,

    // ----- Decision (RFC-004 §6) ----------------------------------------------------
    /// The ID-JAG names resources and policy granted none of them.
    #[error("no resource was granted")]
    NoResourceGranted,
    /// Caller policy refused the grant.
    #[error("denied by policy")]
    DeniedByPolicy,
    /// Caller policy granted more than the ID-JAG carries: a caller bug.
    /// [`TokenError::error`] holds the [`Error::GrantExceedsIdJag`].
    #[error("policy granted more than the ID-JAG allows")]
    GrantExceedsIdJag,
}

/// A rejected token request: the OAuth error code for the wire and the
/// precise [`RejectReason`] for logs.
#[derive(Debug)]
pub struct TokenError {
    code: OAuthErrorCode,
    reason: Option<RejectReason>,
    source: Option<Box<Error>>,
    dpop_nonce: Option<String>,
    basic_challenge: bool,
}

impl TokenError {
    fn new(code: OAuthErrorCode, reason: Option<RejectReason>) -> Self {
        Self {
            code,
            reason,
            source: None,
            dpop_nonce: None,
            basic_challenge: false,
        }
    }

    pub(super) fn rejected(code: OAuthErrorCode, reason: RejectReason) -> Self {
        Self::new(code, Some(reason))
    }

    pub(super) fn invalid_grant(reason: RejectReason) -> Self {
        Self::rejected(OAuthErrorCode::InvalidGrant, reason)
    }

    pub(super) fn invalid_request(reason: RejectReason) -> Self {
        Self::rejected(OAuthErrorCode::InvalidRequest, reason)
    }

    pub(super) fn server_error(reason: RejectReason) -> Self {
        Self::rejected(OAuthErrorCode::ServerError, reason)
    }

    pub(super) fn with_source(mut self, source: Error) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// A caller-policy violation of a decision-builder invariant.
    pub(super) fn grant_exceeds_id_jag(what: &'static str) -> Self {
        Self::server_error(RejectReason::GrantExceedsIdJag)
            .with_source(Error::GrantExceedsIdJag { what })
    }

    /// Map a DPoP validation or replay failure (RFC-007 §3).
    pub(super) fn from_dpop(error: DpopError) -> Self {
        let code = error.code();
        match error {
            DpopError::UseNonce { nonce } => {
                let mut rejected = Self::rejected(code, RejectReason::DpopNonceRequired);
                rejected.dpop_nonce = Some(nonce);
                rejected
            }
            DpopError::InvalidProof(source) => {
                let reason = match source {
                    Error::Replayed { .. } => RejectReason::DpopProofReplayed,
                    _ => RejectReason::DpopProofInvalid,
                };
                Self::rejected(code, reason).with_source(source)
            }
            DpopError::Internal(source) => {
                let reason = match source {
                    Error::ReplayStore(_) => RejectReason::ReplayStoreUnavailable,
                    _ => RejectReason::TimeOutOfRange,
                };
                Self::rejected(code, reason).with_source(source)
            }
        }
    }

    /// Client authentication failed (RFC 6749 §5.2). The caller returns this
    /// itself, without calling
    /// [`ResourceAs::validate`](super::ResourceAs::validate).
    pub fn invalid_client() -> Self {
        Self::new(OAuthErrorCode::InvalidClient, None)
    }

    /// Client authentication failed for these credentials. After a failed
    /// `Authorization: Basic` attempt the response is 401 with
    /// `WWW-Authenticate: Basic` (RFC 6749 §5.2).
    pub fn invalid_client_for(credentials: &ClientCredentials) -> Self {
        let mut error = Self::invalid_client();
        error.basic_challenge = matches!(credentials, ClientCredentials::Basic { .. });
        error
    }

    /// The request's `scope` is not acceptable (RFC 6749 §5.2). For callers
    /// that refuse a requested scope outside the ID-JAG's instead of
    /// granting the intersection (RFC-004 §6).
    pub fn invalid_scope() -> Self {
        Self::new(OAuthErrorCode::InvalidScope, None)
    }

    /// The OAuth error code that goes on the wire.
    pub fn code(&self) -> &OAuthErrorCode {
        &self.code
    }

    /// The exact rule that failed. For logs only. `None` for errors the
    /// caller constructed.
    pub fn reason(&self) -> Option<&RejectReason> {
        self.reason.as_ref()
    }

    /// The library error behind the rejection, when there is one. For logs
    /// only. For a decision-builder violation this is
    /// [`Error::GrantExceedsIdJag`]: a bug in the caller's policy.
    pub fn error(&self) -> Option<&Error> {
        self.source.as_deref()
    }

    /// The RFC 6749 §5.2 response: `{"error", "error_description"}` with a
    /// fixed per-code description (draft §10), `Cache-Control: no-store`,
    /// and a `DPoP-Nonce` header for `use_dpop_nonce` (RFC 9449 §8).
    ///
    /// Status is 400, except 401 for `invalid_client` after a Basic attempt
    /// and 500 for `server_error`.
    pub fn to_response(&self) -> HttpResponse {
        let mut response = error_response(
            &self.code,
            &ErrorResponseExtras {
                dpop_nonce: self.dpop_nonce.clone(),
                basic_challenge: self.basic_challenge,
                ..ErrorResponseExtras::default()
            },
        );
        if self.code == OAuthErrorCode::ServerError {
            response.status = 500;
        }
        response
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            Some(reason) => write!(f, "{}: {reason}", self.code),
            None => write!(f, "{}", self.code),
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}
