//! Token-endpoint errors and what to do about them. See RFC-003 §8.

use crate::dpop::DPOP_NONCE_HEADER;
use crate::error::Error;
use crate::http::HttpResponse;
use crate::oauth_error::{OAuthErrorBody, OAuthErrorCode};

/// Which token endpoint answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// The IdP: the §4.3 Token Exchange or the §4.5 SAML exchange.
    Idp,
    /// The Resource AS: the §4.4 Access Token Request.
    ResourceAs,
}

impl Endpoint {
    fn what(self) -> &'static str {
        match self {
            Self::Idp => "IdP token endpoint",
            Self::ResourceAs => "Resource AS token endpoint",
        }
    }
}

/// A non-200 answer from a token endpoint, parsed from its RFC 6749 §5.2
/// body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEndpointError {
    pub endpoint: Endpoint,
    pub status: u16,
    pub code: OAuthErrorCode,
    pub description: Option<String>,
    pub uri: Option<String>,
    /// From `insufficient_user_authentication` (draft §9.3, RFC 9470).
    pub max_age: Option<u64>,
    /// From `insufficient_user_authentication` (draft §9.3, RFC 9470).
    pub acr_values: Option<String>,
    /// From the `DPoP-Nonce` response header (RFC 9449 §8).
    pub dpop_nonce: Option<String>,
}

/// The next step after a [`TokenEndpointError`]. The library never takes it
/// on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Remediation {
    /// `use_dpop_nonce`: repeat the request with a proof that carries
    /// [`TokenEndpointError::dpop_nonce`] (RFC 9449 §8).
    RetryWithDpopNonce,
    /// The IdP refused the subject token (draft §4.3.4.3): get a new one,
    /// or re-authenticate the user.
    ObtainNewSubjectToken,
    /// IdP `insufficient_user_authentication` (draft §9.3): re-authenticate
    /// the user to the returned `acr_values` / `max_age`.
    StepUpAuthentication,
    /// IdP `invalid_target`: the audience, resource, or binding asked for
    /// is not acceptable. This includes a DPoP proof for a Resource AS
    /// without `jwt-dpop`.
    ChangeRequest,
    /// Resource AS `invalid_grant` on an ID-JAG that was presented before:
    /// request a new ID-JAG with the original subject token (draft §4.4.4).
    ObtainNewIdJag,
    /// `invalid_client`, `unauthorized_client`, `invalid_dpop_proof`: the
    /// client's registration or credentials are wrong.
    FixClientConfiguration,
    /// `access_denied` at either server, or `invalid_grant` on a fresh
    /// ID-JAG. Stop: another ID-JAG "will not resolve the error" (draft
    /// §4.4.4), and a denial takes an administrative process on the
    /// server's side (draft §4.3.4.3, §4.4.3).
    NotRemediableByClient,
    Unknown,
}

impl TokenEndpointError {
    /// Parse a non-200 token-endpoint response.
    ///
    /// The result is always an error: [`Error::TokenEndpoint`] when the body
    /// is an RFC 6749 §5.2 error object, [`Error::UnexpectedResponse`]
    /// otherwise.
    pub(super) fn from_response(endpoint: Endpoint, response: &HttpResponse) -> Error {
        let Ok(body) = serde_json::from_slice::<OAuthErrorBody>(&response.body) else {
            return Error::UnexpectedResponse {
                what: endpoint.what(),
                status: response.status,
            };
        };
        Error::TokenEndpoint(Box::new(Self {
            endpoint,
            status: response.status,
            code: OAuthErrorCode::parse(&body.error),
            description: body.error_description,
            uri: body.error_uri,
            max_age: body.max_age,
            acr_values: body.acr_values,
            dpop_nonce: response.header(DPOP_NONCE_HEADER).map(str::to_owned),
        }))
    }

    /// The next step for this error (draft §4.4.4).
    ///
    /// `id_jag_was_fresh` is [`IssuedIdJag::fresh`] as it was when the
    /// failed access token request was built: whether that was the first
    /// time the ID-JAG was presented. It is ignored for IdP errors.
    ///
    /// [`IssuedIdJag::fresh`]: super::IssuedIdJag::fresh
    pub fn remediation(&self, id_jag_was_fresh: bool) -> Remediation {
        match (&self.code, self.endpoint) {
            (OAuthErrorCode::UseDpopNonce, _) => Remediation::RetryWithDpopNonce,
            (
                OAuthErrorCode::InvalidClient
                | OAuthErrorCode::UnauthorizedClient
                | OAuthErrorCode::InvalidDpopProof,
                _,
            ) => Remediation::FixClientConfiguration,
            (OAuthErrorCode::AccessDenied, _) => Remediation::NotRemediableByClient,
            // RFC 8693 §2.2.2 names `invalid_request` for a bad subject
            // token; `invalid_grant` is RFC 6749 §5.2's code for an expired
            // or revoked grant, which at the IdP is the subject token too.
            (OAuthErrorCode::InvalidRequest | OAuthErrorCode::InvalidGrant, Endpoint::Idp) => {
                Remediation::ObtainNewSubjectToken
            }
            (OAuthErrorCode::InsufficientUserAuthentication, Endpoint::Idp) => {
                Remediation::StepUpAuthentication
            }
            (OAuthErrorCode::InvalidTarget, Endpoint::Idp) => Remediation::ChangeRequest,
            (OAuthErrorCode::InvalidGrant, Endpoint::ResourceAs) => {
                if id_jag_was_fresh {
                    Remediation::NotRemediableByClient
                } else {
                    Remediation::ObtainNewIdJag
                }
            }
            _ => Remediation::Unknown,
        }
    }
}

impl std::fmt::Display for TokenEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} answered {} (status {})",
            self.endpoint.what(),
            self.code,
            self.status
        )
    }
}

impl std::error::Error for TokenEndpointError {}
