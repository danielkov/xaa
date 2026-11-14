//! Token-endpoint plumbing shared by the three round trips: the request
//! envelope and the response members.

use std::time::Duration;

use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::claims::{AuthorizationDetails, Scope};
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::jose::parse_object_rejecting_duplicates;

use super::token_error::{Endpoint, TokenEndpointError};

/// A form parameter list. Token and secret values go in here and never in
/// the URL (draft §9.2).
pub(super) type Form = Vec<(String, String)>;

pub(super) fn push(form: &mut Form, name: &str, value: &str) {
    form.push((name.to_owned(), value.to_owned()));
}

/// The headers every token request starts with.
pub(super) fn token_request_headers() -> Vec<(String, String)> {
    vec![
        (
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ),
        ("Accept".to_owned(), "application/json".to_owned()),
    ]
}

/// A `POST` of `form` to `token_endpoint`. The URL is the configured
/// endpoint, untouched.
pub(super) fn token_request(
    token_endpoint: &Url,
    mut form: Form,
    headers: Vec<(String, String)>,
) -> HttpRequest {
    let body = crate::form::encode(&form);
    for (_name, value) in &mut form {
        zeroize::Zeroize::zeroize(value);
    }
    HttpRequest {
        method: http::Method::POST,
        url: token_endpoint.clone(),
        headers,
        body,
    }
}

pub(super) async fn send<C: HttpClient>(
    http: &C,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    http.send(request).await.map_err(Error::Http)
}

/// The members of a success response: status 200 and a JSON object with
/// unique member names. Any other status is an OAuth error (RFC-003 §8).
pub(super) fn success_members(
    endpoint: Endpoint,
    response: &HttpResponse,
) -> Result<Map<String, Value>, Error> {
    if response.status != 200 {
        return Err(TokenEndpointError::from_response(endpoint, response));
    }
    parse_object_rejecting_duplicates(&response.body).map_err(|_reason| {
        Error::InvalidTokenResponse {
            reason: "body is not a JSON object with unique member names",
        }
    })
}

/// Remove a string member. JSON `null` counts as absent; any other
/// non-string value fails with `wrong_type`.
pub(super) fn take_string(
    members: &mut Map<String, Value>,
    name: &str,
    wrong_type: &'static str,
) -> Result<Option<String>, Error> {
    match members.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(Error::InvalidTokenResponse { reason: wrong_type }),
    }
}

/// Remove a required, non-empty token member.
pub(super) fn take_token(
    members: &mut Map<String, Value>,
    name: &str,
    missing: &'static str,
) -> Result<Zeroizing<String>, Error> {
    let token = take_string(members, name, missing)?.map(Zeroizing::new);
    match token {
        Some(token) if !token.is_empty() => Ok(token),
        _ => Err(Error::InvalidTokenResponse { reason: missing }),
    }
}

/// What a success response says about scope.
pub(super) enum ReportedScope {
    /// No `scope` member: the grant is what was requested (RFC 6749 §5.1).
    Absent,
    /// A `scope` member that is empty or blank: the server granted no scope.
    /// This is not the same as [`Absent`](Self::Absent), and must not fall
    /// back to what was requested.
    Empty,
    Granted(Scope),
}

impl ReportedScope {
    /// The scope the token carries: what the server reported, or `requested`
    /// when it reported nothing.
    pub(super) fn or_requested(self, requested: impl FnOnce() -> Option<Scope>) -> Option<Scope> {
        match self {
            Self::Absent => requested(),
            Self::Empty => None,
            Self::Granted(scope) => Some(scope),
        }
    }
}

/// The `scope` member of a success response.
///
/// Whitespace is read leniently: leading, trailing, or repeated spaces are
/// ignored, and an empty or blank string is [`ReportedScope::Empty`].
/// RFC 6749 §3.3 allows neither, but servers emit both (the xaa.dev Resource
/// AS answers `"scope": ""` when the request named no scope, see
/// `docs/interop.md`). Each token must still be a valid scope token.
pub(super) fn take_scope(members: &mut Map<String, Value>) -> Result<ReportedScope, Error> {
    let Some(scope) = take_string(members, "scope", "scope is not a string")? else {
        return Ok(ReportedScope::Absent);
    };
    let tokens: Vec<&str> = scope.split_ascii_whitespace().collect();
    if tokens.is_empty() {
        return Ok(ReportedScope::Empty);
    }
    Scope::parse(tokens.join(" "))
        .map(ReportedScope::Granted)
        .map_err(|_source| Error::InvalidTokenResponse {
            reason: "scope is not a space-separated list of scope tokens",
        })
}

/// The `expires_in` member, if present: a non-negative number of seconds
/// (RFC 6749 §5.1).
pub(super) fn take_expires_in(members: &mut Map<String, Value>) -> Result<Option<Duration>, Error> {
    match members.remove("expires_in") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(|seconds| Some(Duration::from_secs(seconds)))
            .ok_or(Error::InvalidTokenResponse {
                reason: "expires_in is not a non-negative integer",
            }),
    }
}

/// The `authorization_details` member, if present (RFC 9396 §7).
pub(super) fn take_authorization_details(
    members: &mut Map<String, Value>,
) -> Result<Option<AuthorizationDetails>, Error> {
    match members.remove("authorization_details") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            serde_json::from_value(value)
                .map(Some)
                .map_err(|_source| Error::InvalidTokenResponse {
                    reason: "authorization_details is not an array of objects with a string type",
                })
        }
    }
}

/// The RFC 8693 §2.2.1 envelope of a token-exchange response: the issued
/// token, after checking `issued_token_type` and `token_type`.
///
/// A `refresh_token` member, which draft §4.3.4 says SHOULD NOT be used, is
/// removed and zeroized.
pub(super) fn take_exchanged_token(
    members: &mut Map<String, Value>,
    expected_issued_token_type: &str,
) -> Result<Zeroizing<String>, Error> {
    if let Some(Value::String(refresh_token)) = members.remove("refresh_token") {
        drop(Zeroizing::new(refresh_token));
    }
    let issued = take_string(
        members,
        "issued_token_type",
        "issued_token_type is not a string",
    )?;
    if issued.as_deref() != Some(expected_issued_token_type) {
        return Err(Error::UnexpectedIssuedTokenType { got: issued });
    }
    let token_type = take_string(members, "token_type", "token_type is not a string")?.ok_or(
        Error::InvalidTokenResponse {
            reason: "token_type is missing",
        },
    )?;
    // RFC 6749 §7.1: the token type is case-insensitive.
    if !token_type.eq_ignore_ascii_case("N_A") {
        return Err(Error::InvalidTokenResponse {
            reason: "token_type is not N_A",
        });
    }
    take_token(members, "access_token", "access_token is missing or empty")
}
