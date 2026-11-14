//! OAuth error codes and token-endpoint error bodies (RFC 6749 §5.2).
//!
//! Shared by the server components, which emit these bodies, and the client,
//! which parses them back.

use serde::{Deserialize, Serialize};

use crate::http::HttpResponse;

/// The OAuth `error` codes this profile uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    /// RFC 8707 §2, RFC 8693 §2.2.2.
    InvalidTarget,
    /// Draft §4.3.4.3, §4.4.3.
    AccessDenied,
    /// RFC 9470 §3, draft §9.3.
    InsufficientUserAuthentication,
    /// RFC 9449 §5.
    InvalidDpopProof,
    /// RFC 9449 §8.
    UseDpopNonce,
    /// RFC 9396 §5.
    InvalidAuthorizationDetails,
    ServerError,
    TemporarilyUnavailable,
    /// A code this crate does not model. Only produced when parsing.
    Other(String),
}

impl OAuthErrorCode {
    /// The wire value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::AccessDenied => "access_denied",
            Self::InsufficientUserAuthentication => "insufficient_user_authentication",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
            Self::InvalidAuthorizationDetails => "invalid_authorization_details",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::Other(code) => code,
        }
    }

    /// Parse a wire value. Unknown codes become [`OAuthErrorCode::Other`].
    pub fn parse(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "invalid_client" => Self::InvalidClient,
            "invalid_grant" => Self::InvalidGrant,
            "unauthorized_client" => Self::UnauthorizedClient,
            "unsupported_grant_type" => Self::UnsupportedGrantType,
            "invalid_scope" => Self::InvalidScope,
            "invalid_target" => Self::InvalidTarget,
            "access_denied" => Self::AccessDenied,
            "insufficient_user_authentication" => Self::InsufficientUserAuthentication,
            "invalid_dpop_proof" => Self::InvalidDpopProof,
            "use_dpop_nonce" => Self::UseDpopNonce,
            "invalid_authorization_details" => Self::InvalidAuthorizationDetails,
            "server_error" => Self::ServerError,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            other => Self::Other(other.to_owned()),
        }
    }

    /// A fixed, non-sensitive description for this code. Server components
    /// never put request-derived detail in `error_description` (draft §10):
    /// the precise reason goes to the caller's logs instead.
    pub fn default_description(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "The request is missing a parameter or is otherwise malformed.",
            Self::InvalidClient => "Client authentication failed.",
            Self::InvalidGrant => "The provided authorization grant is invalid.",
            Self::UnauthorizedClient => "The client is not authorized to use this grant.",
            Self::UnsupportedGrantType => "The grant type is not supported.",
            Self::InvalidScope => "The requested scope is invalid or exceeds the grant.",
            Self::InvalidTarget => "The requested audience or resource is not acceptable.",
            Self::AccessDenied => "The request was denied by policy.",
            Self::InsufficientUserAuthentication => {
                "The user authentication does not meet the requirements."
            }
            Self::InvalidDpopProof => "The DPoP proof is missing or invalid.",
            Self::UseDpopNonce => "A DPoP nonce is required.",
            Self::InvalidAuthorizationDetails => "The authorization details are invalid.",
            Self::ServerError => "The server encountered an error.",
            Self::TemporarilyUnavailable => "The server is temporarily unavailable.",
            Self::Other(_) => "The request failed.",
        }
    }
}

impl std::fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RFC 6749 §5.2 error body, with the RFC 9470 members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthErrorBody {
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
    /// RFC 9470 §3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    /// RFC 9470 §3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,
}

/// Extra members and headers for an error response.
#[derive(Debug, Clone, Default)]
pub struct ErrorResponseExtras {
    /// `max_age` for `insufficient_user_authentication` (RFC 9470).
    pub max_age: Option<u64>,
    /// `acr_values` for `insufficient_user_authentication` (RFC 9470).
    pub acr_values: Option<String>,
    /// A fresh nonce for the `DPoP-Nonce` header (RFC 9449 §8).
    pub dpop_nonce: Option<String>,
    /// Emit `WWW-Authenticate: Basic` with status 401 for `invalid_client`
    /// (RFC 6749 §5.2), when the client authenticated through the
    /// `Authorization` header.
    pub basic_challenge: bool,
}

/// Build a token-endpoint error response: RFC 6749 §5.2 JSON, a fixed
/// description, and `Cache-Control: no-store`.
pub fn error_response(code: &OAuthErrorCode, extras: &ErrorResponseExtras) -> HttpResponse {
    let body = OAuthErrorBody {
        error: code.as_str().to_owned(),
        error_description: Some(code.default_description().to_owned()),
        error_uri: None,
        max_age: extras.max_age,
        acr_values: extras.acr_values.clone(),
    };
    let unauthorized = extras.basic_challenge && *code == OAuthErrorCode::InvalidClient;
    let mut headers = json_no_store_headers();
    if unauthorized {
        headers.push(("WWW-Authenticate".to_owned(), "Basic".to_owned()));
    }
    if let Some(nonce) = &extras.dpop_nonce {
        headers.push(("DPoP-Nonce".to_owned(), nonce.clone()));
    }
    HttpResponse {
        status: if unauthorized { 401 } else { 400 },
        headers,
        // Serializing a struct of strings and integers cannot fail; fall back
        // to a constant body rather than panic.
        body: serde_json::to_vec(&body)
            .unwrap_or_else(|_infallible| br#"{"error":"server_error"}"#.to_vec()),
    }
}

/// Headers for a token-endpoint JSON response (RFC 6749 §5.1).
pub(crate) fn json_no_store_headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Cache-Control".to_owned(), "no-store".to_owned()),
        ("Pragma".to_owned(), "no-cache".to_owned()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for code in [
            OAuthErrorCode::InvalidRequest,
            OAuthErrorCode::InvalidClient,
            OAuthErrorCode::InvalidGrant,
            OAuthErrorCode::UnauthorizedClient,
            OAuthErrorCode::UnsupportedGrantType,
            OAuthErrorCode::InvalidScope,
            OAuthErrorCode::InvalidTarget,
            OAuthErrorCode::AccessDenied,
            OAuthErrorCode::InsufficientUserAuthentication,
            OAuthErrorCode::InvalidDpopProof,
            OAuthErrorCode::UseDpopNonce,
            OAuthErrorCode::InvalidAuthorizationDetails,
            OAuthErrorCode::ServerError,
            OAuthErrorCode::TemporarilyUnavailable,
        ] {
            assert_eq!(OAuthErrorCode::parse(code.as_str()), code);
        }
        assert_eq!(
            OAuthErrorCode::parse("vendor_error"),
            OAuthErrorCode::Other("vendor_error".to_owned())
        );
    }

    #[test]
    fn error_response_is_no_store_json_with_fixed_description() {
        let response = error_response(
            &OAuthErrorCode::InvalidGrant,
            &ErrorResponseExtras::default(),
        );
        assert_eq!(response.status, 400);
        assert_eq!(response.header("cache-control"), Some("no-store"));
        assert_eq!(response.header("content-type"), Some("application/json"));
        let body: OAuthErrorBody = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error, "invalid_grant");
        assert_eq!(
            body.error_description.as_deref(),
            Some(OAuthErrorCode::InvalidGrant.default_description())
        );
    }

    #[test]
    fn invalid_client_with_basic_is_401_with_challenge() {
        let response = error_response(
            &OAuthErrorCode::InvalidClient,
            &ErrorResponseExtras {
                basic_challenge: true,
                ..ErrorResponseExtras::default()
            },
        );
        assert_eq!(response.status, 401);
        assert_eq!(response.header("www-authenticate"), Some("Basic"));
    }

    #[test]
    fn dpop_nonce_and_step_up_members_are_emitted() {
        let response = error_response(
            &OAuthErrorCode::UseDpopNonce,
            &ErrorResponseExtras {
                dpop_nonce: Some("n-1".to_owned()),
                ..ErrorResponseExtras::default()
            },
        );
        assert_eq!(response.header("dpop-nonce"), Some("n-1"));

        let response = error_response(
            &OAuthErrorCode::InsufficientUserAuthentication,
            &ErrorResponseExtras {
                max_age: Some(300),
                acr_values: Some("urn:example:mfa".to_owned()),
                ..ErrorResponseExtras::default()
            },
        );
        let body: OAuthErrorBody = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.max_age, Some(300));
        assert_eq!(body.acr_values.as_deref(), Some("urn:example:mfa"));
    }
}
