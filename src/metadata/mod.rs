//! Metadata and discovery: Authorization Server Metadata (RFC 8414, with the
//! OIDC Discovery fallback), Protected Resource Metadata (RFC 9728), JWK Set
//! retrieval, and client metadata (RFC 7591). See RFC-006.
//!
//! Every fetch exists in two forms: sans-IO (build an
//! [`HttpRequest`], then parse the [`HttpResponse`]) and an async wrapper over
//! the caller's [`HttpClient`]. Nothing is cached.
//!
//! The [`HttpClient`] MUST NOT follow redirects for these fetches. The
//! identity checks (`issuer`, draft §9.5; `resource`, draft §9.6) bind a
//! document to the URL it was *requested* from, and a followed redirect
//! would let another origin answer for it. A redirect status is treated like
//! any other non-200 response.

mod authorization_server;
mod client;
mod jwks;
mod protected_resource;

use std::time::Duration;

use serde_json::{Map, Value};
use url::{Host, Url};

use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::jose::parse_object_rejecting_duplicates;

pub use authorization_server::{
    AuthorizationServerMetadata, IdpMetadataBuilder, MetadataLocation, ResourceAsMetadataBuilder,
    Support, authorization_server_metadata_request, authorization_server_metadata_url,
    fetch_authorization_server_metadata, parse_authorization_server_metadata_response,
};
pub use client::{ClientMetadata, ClientMetadataBuilder};
pub use jwks::{FetchedJwks, fetch_jwks, jwks_request, parse_jwks_response};
pub use protected_resource::{
    PrmOrigin, ProtectedResourceMetadata, ValidatedPrm, fetch_protected_resource_metadata,
    parse_protected_resource_metadata_response, parse_www_authenticate_resource_metadata,
    protected_resource_metadata_request, protected_resource_metadata_url,
};

// ---------------------------------------------------------------------------
// Protocol constants (RFC-001 §4)
// ---------------------------------------------------------------------------

/// The token-exchange grant type (RFC 8693 §2.1).
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// The JWT-bearer grant type (RFC 7523 §2.1).
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The JWT-DPoP grant type (jwt-dpop-grant §9.1).
pub const GRANT_TYPE_JWT_DPOP: &str = "urn:ietf:params:oauth:grant-type:jwt-dpop";
/// The ID-JAG token type (draft §11.2).
pub const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// The ID-JAG authorization grant profile (draft §11.2).
pub const GRANT_PROFILE_ID_JAG: &str = "urn:ietf:params:oauth:grant-profile:id-jag";

/// Default cap on a metadata or JWK Set response body: 64 KiB (RFC-006 §3, §5).
pub const DEFAULT_MAX_BODY_BYTES: usize = 65_536;

// ---------------------------------------------------------------------------
// FetchOptions
// ---------------------------------------------------------------------------

/// Options for metadata and JWK Set fetches (RFC-006 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOptions {
    /// Accept `http` for `localhost`, `127.0.0.1`, and `[::1]` wherever
    /// `https` is otherwise required. For tests and examples only; off by
    /// default.
    pub allow_http_loopback: bool,
    /// After a non-200 response from the RFC 8414 §3.1 location, try OIDC
    /// Discovery's `/.well-known/openid-configuration` (draft §7.1 MAY,
    /// RFC 8414 §5). On by default: real IdPs serve only that document
    /// (`docs/interop.md`).
    pub oidc_discovery_fallback: bool,
    /// Largest response body accepted, in bytes. The check runs on the body
    /// the [`HttpClient`] returned, so a client that talks to untrusted
    /// servers should also cap what it reads.
    pub max_body_bytes: usize,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            allow_http_loopback: false,
            oidc_discovery_fallback: true,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

// ---------------------------------------------------------------------------
// URL rules
// ---------------------------------------------------------------------------

/// Require `https`, or `http` to a loopback host when `allow_http_loopback`
/// is set (RFC 8414 §2, RFC 9728 §2, RFC-006 §3).
pub(crate) fn require_secure(
    url: &Url,
    what: &'static str,
    allow_http_loopback: bool,
) -> Result<(), Error> {
    let loopback = || match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address == std::net::Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(address)) => address == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_http_loopback && loopback() => Ok(()),
        _ => Err(Error::InsecureEndpoint { what }),
    }
}

/// The static texts for one kind of identifier, so errors name it.
pub(crate) struct IdentifierRules {
    pub(crate) what: &'static str,
    pub(crate) not_a_url: &'static str,
    pub(crate) has_userinfo: &'static str,
    pub(crate) has_query: &'static str,
    pub(crate) has_fragment: &'static str,
    /// RFC 8414 §2 forbids a query in an issuer; RFC 9728 §1.2 only
    /// discourages one in a resource identifier.
    pub(crate) allow_query: bool,
}

/// Parse an issuer or resource identifier as a URL and apply the shape
/// rules: `https`, no userinfo, no fragment, and (for issuers) no query.
///
/// The parsed URL is only used to build a request URL. Identity comparisons
/// always use the original string.
pub(crate) fn parse_identifier(
    identifier: &str,
    rules: &IdentifierRules,
    allow_http_loopback: bool,
) -> Result<Url, Error> {
    let url = Url::parse(identifier).map_err(|_source| Error::InvalidMetadata {
        reason: rules.not_a_url,
    })?;
    require_secure(&url, rules.what, allow_http_loopback)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidMetadata {
            reason: rules.has_userinfo,
        });
    }
    if url.fragment().is_some() {
        return Err(Error::InvalidMetadata {
            reason: rules.has_fragment,
        });
    }
    if !rules.allow_query && url.query().is_some() {
        return Err(Error::InvalidMetadata {
            reason: rules.has_query,
        });
    }
    Ok(url)
}

/// The identifier's path with one terminating `/` removed (RFC 8414 §3.1,
/// RFC 9728 §3.1). A bare `/` becomes empty.
pub(crate) fn path_without_terminating_slash(url: &Url) -> String {
    let path = url.path();
    path.strip_suffix('/').unwrap_or(path).to_owned()
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

/// A `GET` for a JSON document. No credentials, no body.
pub(crate) fn json_get(url: Url) -> HttpRequest {
    HttpRequest {
        method: http::Method::GET,
        url,
        headers: vec![("accept".to_owned(), "application/json".to_owned())],
        body: Vec::new(),
    }
}

pub(crate) async fn send<C: HttpClient>(
    http: &C,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    http.send(request).await.map_err(Error::Http)
}

/// Status 200 and a body under the size cap (RFC 8414 §3.2, RFC 9728 §3.2).
/// Returns the body.
pub(crate) fn successful_body<'a>(
    response: &'a HttpResponse,
    what: &'static str,
    too_large: Error,
    opts: &FetchOptions,
) -> Result<&'a [u8], Error> {
    if response.status != 200 {
        return Err(Error::UnexpectedResponse {
            what,
            status: response.status,
        });
    }
    if response.body.len() > opts.max_body_bytes {
        return Err(too_large);
    }
    Ok(&response.body)
}

/// `max-age` from a `Cache-Control` header value (RFC 9111 §5.2.2.1).
pub(crate) fn cache_control_max_age(header: &str) -> Option<Duration> {
    header.split(',').find_map(|directive| {
        let (name, value) = directive.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("max-age") {
            return None;
        }
        let seconds: u64 = value.trim().trim_matches('"').parse().ok()?;
        Some(Duration::from_secs(seconds))
    })
}

// ---------------------------------------------------------------------------
// JSON member access
// ---------------------------------------------------------------------------

/// Parse a metadata document: a JSON object. Duplicate member names fail,
/// because two parsers could otherwise disagree about which `issuer` or
/// `resource` the document declares.
pub(crate) fn parse_document(bytes: &[u8]) -> Result<Map<String, Value>, Error> {
    parse_object_rejecting_duplicates(bytes).map_err(|_reason| Error::InvalidMetadata {
        reason: "document is not a JSON object with unique member names",
    })
}

/// Remove member `name`. JSON `null` counts as absent.
fn take(members: &mut Map<String, Value>, name: &str) -> Option<Value> {
    members.remove(name).filter(|value| !value.is_null())
}

pub(crate) fn take_string(
    members: &mut Map<String, Value>,
    name: &str,
    wrong_type: &'static str,
) -> Result<Option<String>, Error> {
    match take(members, name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(Error::InvalidMetadata { reason: wrong_type }),
    }
}

pub(crate) fn take_bool(
    members: &mut Map<String, Value>,
    name: &str,
    wrong_type: &'static str,
) -> Result<Option<bool>, Error> {
    match take(members, name) {
        None => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(flag)),
        Some(_) => Err(Error::InvalidMetadata { reason: wrong_type }),
    }
}

pub(crate) fn take_strings(
    members: &mut Map<String, Value>,
    name: &str,
    wrong_type: &'static str,
) -> Result<Option<Vec<String>>, Error> {
    let Some(value) = take(members, name) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(Error::InvalidMetadata { reason: wrong_type });
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::String(text) => Ok(text),
            _ => Err(Error::InvalidMetadata { reason: wrong_type }),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

pub(crate) fn take_url(
    members: &mut Map<String, Value>,
    name: &str,
    not_a_url: &'static str,
) -> Result<Option<Url>, Error> {
    let Some(text) = take_string(members, name, not_a_url)? else {
        return Ok(None);
    };
    Url::parse(&text)
        .map(Some)
        .map_err(|_source| Error::InvalidMetadata { reason: not_a_url })
}

/// Insert `name` when `value` is present.
pub(crate) fn put<T: Into<Value>>(object: &mut Map<String, Value>, name: &str, value: Option<T>) {
    if let Some(value) = value {
        object.insert(name.to_owned(), value.into());
    }
}

/// Append `value` unless the list already has it.
pub(crate) fn push_unique(list: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !list.contains(&value) {
        list.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn https_is_always_accepted() {
        require_secure(&url("https://as.example/token"), "token_endpoint", false).unwrap();
    }

    #[test]
    fn http_is_rejected_by_default_even_on_loopback() {
        for target in [
            "http://as.example/token",
            "http://localhost:8080/token",
            "http://127.0.0.1/token",
            "http://[::1]/token",
        ] {
            assert!(matches!(
                require_secure(&url(target), "token_endpoint", false),
                Err(Error::InsecureEndpoint {
                    what: "token_endpoint"
                })
            ));
        }
    }

    #[test]
    fn loopback_relaxation_covers_only_the_three_loopback_hosts() {
        for target in [
            "http://localhost:8080/token",
            "http://LOCALHOST/token",
            "http://127.0.0.1:9000/token",
            "http://[::1]:9000/token",
        ] {
            require_secure(&url(target), "token_endpoint", true).unwrap();
        }
        for target in [
            "http://as.example/token",
            "http://localhost.evil.example/token",
            "http://127.0.0.2/token",
            "http://10.0.0.1/token",
            "ftp://localhost/token",
        ] {
            assert!(matches!(
                require_secure(&url(target), "token_endpoint", true),
                Err(Error::InsecureEndpoint { .. })
            ));
        }
    }

    #[test]
    fn max_age_is_read_from_cache_control() {
        assert_eq!(
            cache_control_max_age("public, max-age=300, must-revalidate"),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            cache_control_max_age("Max-Age=\"60\""),
            Some(Duration::from_secs(60))
        );
        assert_eq!(cache_control_max_age("no-store"), None);
        assert_eq!(cache_control_max_age("max-age=soon"), None);
        assert_eq!(cache_control_max_age("s-maxage=10"), None);
    }

    #[test]
    fn null_members_count_as_absent() {
        let mut members = parse_document(br#"{"a":null,"b":"x"}"#).unwrap();
        assert_eq!(take_string(&mut members, "a", "a").unwrap(), None);
        assert_eq!(
            take_string(&mut members, "b", "b").unwrap(),
            Some("x".to_owned())
        );
    }

    #[test]
    fn documents_with_duplicate_members_or_other_shapes_fail() {
        for body in [
            &br#"{"issuer":"https://a","issuer":"https://b"}"#[..],
            b"[]",
            b"\"text\"",
            b"<html>",
            b"",
        ] {
            assert!(matches!(
                parse_document(body),
                Err(Error::InvalidMetadata { .. })
            ));
        }
    }
}
