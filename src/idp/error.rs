//! The token-exchange protocol error. See RFC-001 §7 and RFC-005 §9.

use crate::dpop::DpopError;
use crate::error::Error;
use crate::http::HttpResponse;
use crate::oauth_error::{ErrorResponseExtras, OAuthErrorBody, OAuthErrorCode, error_response};

/// The fixed `error_description` of the RFC-005 §6.1 refusal.
const AUDIENCE_LACKS_JWT_DPOP_DESCRIPTION: &str = "The audience does not accept DPoP-bound grants.";

/// The exact rule a token exchange failed. For the caller's logs and the
/// [`ExchangeRecord`](super::ExchangeRecord) only: it never goes on the wire
/// (draft §10).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RejectReason {
    // ----- Request parsing (RFC-005 §2) ---------------------------------------------
    /// `grant_type` is not the token-exchange grant (RFC 8693 §2.1).
    #[error("grant_type is not token-exchange")]
    UnsupportedGrantType,
    /// A parameter that may appear once appeared twice (RFC 6749 §3.2),
    /// including a second `audience` (draft §4.3.3).
    #[error("parameter {name} is repeated")]
    RepeatedParameter { name: &'static str },
    /// A required parameter is absent or empty (draft §4.3).
    #[error("parameter {name} is missing")]
    MissingParameter { name: &'static str },
    /// `requested_token_type` is neither the ID-JAG type nor the refresh
    /// token type (draft §4.3, §4.5).
    #[error("requested_token_type is not supported")]
    UnsupportedRequestedTokenType,
    /// `subject_token_type` is not `id_token`, `saml2`, or `refresh_token`
    /// (draft §4.3).
    #[error("subject_token_type is not supported")]
    UnsupportedSubjectTokenType,
    /// `actor_token` without `actor_token_type`, or the reverse
    /// (RFC 8693 §2.1).
    #[error("actor_token and actor_token_type must appear together")]
    ActorTokenTypeMismatch,
    /// `authorization_details` is not a JSON array of objects with a string
    /// `type` (RFC 9396 §2).
    #[error("authorization_details is malformed")]
    MalformedAuthorizationDetails,
    /// `scope` is not a list of RFC 6749 §3.3 scope tokens.
    #[error("scope is malformed")]
    MalformedScope,
    /// A `saml2` subject token is neither base64url nor standard base64, or
    /// mixes both alphabets (RFC-005 §2).
    #[error("saml2 subject_token is not base64url or base64")]
    MalformedSamlEncoding,
    /// More than one client authentication method (RFC 6749 §2.3).
    #[error("more than one client authentication method")]
    MultipleClientAuthMethods,
    /// Client credentials are present but unusable.
    #[error("client credentials are malformed")]
    MalformedClientCredentials,
    /// The TLS client certificate handed to `parse` is not DER. A caller bug.
    #[error("the TLS client certificate is not DER")]
    InvalidClientCertificate,

    // ----- Client authentication (RFC-005 §3) ---------------------------------------
    /// The client did not authenticate (draft §4.3.3 MUST).
    #[error("the client is not authenticated")]
    ClientNotAuthenticated,
    /// The caller's verification of the client's credentials failed.
    #[error("client authentication failed")]
    ClientAuthenticationFailed,

    // ----- Subject token (RFC-005 §4) -----------------------------------------------
    /// A JWT subject token carries a `typ` that is neither `JWT` nor
    /// allow-listed (draft §4.3.3 MUST).
    #[error("subject_token carries the typ of another token type")]
    SubjectTokenTypNotAllowed,
    /// The [`SubjectTokenVerifier`](super::SubjectTokenVerifier) rejected the
    /// token.
    #[error("the subject token is not valid")]
    SubjectTokenRejected,
    /// The verifier or the policy asked for stronger or fresher user
    /// authentication (draft §9.3).
    #[error("step-up authentication is required")]
    StepUpRequired,
    /// An ID Token or Refresh Token that was not issued to the authenticated
    /// client (draft §4.3.3 MUST).
    #[error("the subject token was not issued to the authenticated client")]
    SubjectTokenNotIssuedToClient,
    /// A SAML assertion whose `Audience` does not map to the authenticated
    /// client (draft §4.5 MUST).
    #[error("the SAML audience does not map to the authenticated client")]
    SamlAudienceNotMapped,
    /// A multi-tenant issuer and a verified subject without a tenant
    /// (draft §6.1). A caller bug.
    #[error("the verified subject has no issuer tenant")]
    MissingIssuerTenant,

    // ----- Audience, resource, scope (RFC-005 §5) -----------------------------------
    /// The directory does not know the `audience` (draft §4.3.3 MUST).
    #[error("the audience is not a known Resource Authorization Server")]
    UnknownAudience,
    /// A requested `resource` is not governed by the Resource AS
    /// (draft §4.3.3, §9.5).
    #[error("a requested resource is not governed by the audience")]
    ResourceNotGoverned,
    /// The Resource AS requires a `resource` and none was requested
    /// (RFC 8707 §2).
    #[error("the audience requires a resource parameter")]
    ResourceRequired,
    /// Resources were requested and policy granted none (draft §4.3.3 MUST).
    #[error("none of the requested resources was granted")]
    NoResourceGranted,
    /// Policy denied the exchange (draft §4.3.4.3).
    #[error("policy denied the exchange")]
    PolicyDenied,
    /// Policy refused the target.
    #[error("policy refused the audience or resource")]
    PolicyInvalidTarget,
    /// Policy refused the requested scope.
    #[error("policy refused the requested scope")]
    PolicyInvalidScope,
    /// The policy's grant breaks an RFC-005 §5.3 invariant. A caller bug;
    /// [`ExchangeError::library_error`] names the invariant.
    #[error("the policy's grant violates an invariant")]
    GrantInvariantViolated,

    // ----- Sender constraining (RFC-005 §6) -----------------------------------------
    /// The DPoP proof is invalid or was replayed (RFC 9449 §5).
    #[error("the DPoP proof is invalid")]
    InvalidDpopProof,
    /// A DPoP nonce is required (RFC 9449 §8).
    #[error("a DPoP nonce is required")]
    DpopNonceRequired,
    /// A valid DPoP proof for a Resource AS that is not known to support
    /// `jwt-dpop` (jwt-dpop-grant §7.1, RFC-005 §6.1).
    #[error("the audience does not accept DPoP-bound grants")]
    AudienceLacksJwtDpop,

    // ----- SAML → Refresh Token (RFC-005 §8) ----------------------------------------
    /// A refresh token was requested and the draft §4.5 exchange is off.
    #[error("the SAML to refresh token exchange is not enabled")]
    RefreshExchangeDisabled,
    /// A refresh token was requested with a subject token that is not a SAML
    /// assertion (draft §4.5).
    #[error("a refresh token can only be requested with a saml2 subject token")]
    RefreshExchangeRequiresSaml,
    /// The request's `requested_token_type` belongs to the other exchange
    /// method.
    #[error("the request asks for a token type this method does not issue")]
    WrongRequestedTokenType,

    // ----- Internal -----------------------------------------------------------------
    /// Signing, the replay store, or a time computation failed. Fails closed.
    #[error("internal failure")]
    Internal,
}

impl RejectReason {
    /// The OAuth error code this rule maps to.
    pub fn code(&self) -> OAuthErrorCode {
        match self {
            Self::UnsupportedGrantType => OAuthErrorCode::UnsupportedGrantType,
            Self::RepeatedParameter { .. }
            | Self::MissingParameter { .. }
            | Self::UnsupportedRequestedTokenType
            | Self::UnsupportedSubjectTokenType
            | Self::ActorTokenTypeMismatch
            | Self::MalformedAuthorizationDetails
            | Self::MalformedSamlEncoding
            | Self::MultipleClientAuthMethods
            | Self::SubjectTokenTypNotAllowed
            | Self::SubjectTokenRejected
            | Self::SubjectTokenNotIssuedToClient
            | Self::SamlAudienceNotMapped
            | Self::RefreshExchangeDisabled
            | Self::RefreshExchangeRequiresSaml
            | Self::WrongRequestedTokenType => OAuthErrorCode::InvalidRequest,
            Self::MalformedScope | Self::PolicyInvalidScope => OAuthErrorCode::InvalidScope,
            Self::MalformedClientCredentials
            | Self::ClientNotAuthenticated
            | Self::ClientAuthenticationFailed => OAuthErrorCode::InvalidClient,
            Self::StepUpRequired => OAuthErrorCode::InsufficientUserAuthentication,
            Self::UnknownAudience
            | Self::ResourceNotGoverned
            | Self::ResourceRequired
            | Self::NoResourceGranted
            | Self::PolicyInvalidTarget
            | Self::AudienceLacksJwtDpop => OAuthErrorCode::InvalidTarget,
            Self::PolicyDenied => OAuthErrorCode::AccessDenied,
            Self::InvalidDpopProof => OAuthErrorCode::InvalidDpopProof,
            Self::DpopNonceRequired => OAuthErrorCode::UseDpopNonce,
            Self::InvalidClientCertificate
            | Self::MissingIssuerTenant
            | Self::GrantInvariantViolated
            | Self::Internal => OAuthErrorCode::ServerError,
        }
    }
}

/// A refused token exchange: the OAuth error code to return, and the exact
/// reason for the caller's logs (RFC-001 §7).
#[derive(Debug, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct ExchangeError {
    code: OAuthErrorCode,
    reason: RejectReason,
    // Boxed to keep `Result<_, ExchangeError>` small.
    #[source]
    source: Option<Box<Error>>,
    extras: Box<ErrorResponseExtras>,
}

impl ExchangeError {
    pub(crate) fn new(reason: RejectReason) -> Self {
        Self {
            code: reason.code(),
            reason,
            source: None,
            extras: Box::default(),
        }
    }

    /// A refusal caused by a library error: a caller bug, or a failed
    /// collaborator.
    pub(crate) fn with_source(reason: RejectReason, source: Error) -> Self {
        Self {
            source: Some(Box::new(source)),
            ..Self::new(reason)
        }
    }

    pub(crate) fn step_up(max_age: Option<u64>, acr_values: Option<String>) -> Self {
        let mut error = Self::new(RejectReason::StepUpRequired);
        error.extras.max_age = max_age;
        error.extras.acr_values = acr_values;
        error
    }

    pub(crate) fn from_dpop(error: DpopError) -> Self {
        match error {
            DpopError::InvalidProof(source) => {
                Self::with_source(RejectReason::InvalidDpopProof, source)
            }
            DpopError::UseNonce { nonce } => {
                let mut error = Self::new(RejectReason::DpopNonceRequired);
                error.extras.dpop_nonce = Some(nonce);
                error
            }
            DpopError::Internal(source) => Self::with_source(RejectReason::Internal, source),
        }
    }

    /// `invalid_client`, for a caller whose verification of the client's
    /// credentials failed (draft §4.3.3). After a failed `Basic` attempt use
    /// [`TokenExchangeRequest::invalid_client`](super::TokenExchangeRequest::invalid_client),
    /// which adds the 401 challenge.
    pub fn invalid_client() -> Self {
        Self::new(RejectReason::ClientAuthenticationFailed)
    }

    /// Answer `invalid_client` with status 401 and `WWW-Authenticate: Basic`
    /// (RFC 6749 §5.2). Has no effect on other codes.
    pub fn with_basic_challenge(mut self, challenge: bool) -> Self {
        self.extras.basic_challenge = challenge;
        self
    }

    /// The OAuth error code to return.
    pub fn code(&self) -> &OAuthErrorCode {
        &self.code
    }

    /// The exact rule that failed. For logs only.
    pub fn reason(&self) -> &RejectReason {
        &self.reason
    }

    /// The library error behind the refusal, if there is one: the violated
    /// grant invariant ([`Error::GrantExceedsRequest`],
    /// [`Error::TransientNameId`], [`Error::UnwantedSubId`]), the DPoP rule,
    /// or the failed collaborator. For logs only.
    pub fn library_error(&self) -> Option<&Error> {
        self.source.as_deref()
    }

    /// The RFC 6749 §5.2 response: JSON with a fixed per-code
    /// `error_description` (draft §10), `Cache-Control: no-store`, status
    /// 400, or 401 for `invalid_client` after `Basic`, or 500 for
    /// `server_error`. `insufficient_user_authentication` carries `max_age`
    /// and `acr_values` (draft §9.3); `use_dpop_nonce` carries a
    /// `DPoP-Nonce` header (RFC 9449 §8).
    pub fn to_response(&self) -> HttpResponse {
        let mut response = error_response(&self.code, &self.extras);
        if self.code == OAuthErrorCode::ServerError {
            response.status = 500;
        }
        if self.reason == RejectReason::AudienceLacksJwtDpop {
            let body = OAuthErrorBody {
                error: self.code.as_str().to_owned(),
                error_description: Some(AUDIENCE_LACKS_JWT_DPOP_DESCRIPTION.to_owned()),
                error_uri: None,
                max_age: None,
                acr_values: None,
            };
            if let Ok(bytes) = serde_json::to_vec(&body) {
                response.body = bytes;
            }
        }
        response
    }
}

impl From<RejectReason> for ExchangeError {
    fn from(reason: RejectReason) -> Self {
        Self::new(reason)
    }
}
