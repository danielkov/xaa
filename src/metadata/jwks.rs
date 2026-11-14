//! JWK Set retrieval: the keys the Resource AS verifies an issuer's ID-JAGs
//! with (draft §4.4.1, §7.1). See RFC-006 §5.

use std::time::Duration;

use url::Url;

use super::{FetchOptions, cache_control_max_age, json_get, require_secure, send, successful_body};
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::jose::JwkSet;

const WHAT: &str = "JWK Set";

/// A JWK Set as fetched, with the server's caching hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedJwks {
    pub keys: JwkSet,
    /// `Cache-Control: max-age`, if present. A hint only: the library holds
    /// no cache.
    pub max_age: Option<Duration>,
}

/// Sans-IO: the `GET` request for the JWK Set at `jwks_uri`.
///
/// Take `jwks_uri` from the issuer's validated metadata
/// ([`AuthorizationServerMetadata::jwks_uri`](super::AuthorizationServerMetadata)),
/// or from configuration. It must be `https`.
pub fn jwks_request(jwks_uri: &Url, opts: &FetchOptions) -> Result<HttpRequest, Error> {
    require_secure(jwks_uri, "jwks_uri", opts.allow_http_loopback)?;
    Ok(json_get(jwks_uri.clone()))
}

/// Sans-IO: parse the response to a [`jwks_request`].
///
/// Requires status 200 and a body within `opts.max_body_bytes`. Keys of an
/// unsupported type are skipped; a key with private members fails the whole
/// set ([`JwkSet::from_json`]).
pub fn parse_jwks_response(
    response: &HttpResponse,
    opts: &FetchOptions,
) -> Result<FetchedJwks, Error> {
    let body = successful_body(
        response,
        WHAT,
        Error::MalformedJwk {
            reason: "JWK Set exceeds the size limit",
        },
        opts,
    )?;
    Ok(FetchedJwks {
        keys: JwkSet::from_json(body)?,
        max_age: response
            .header("cache-control")
            .and_then(cache_control_max_age),
    })
}

/// Fetch the JWK Set at `jwks_uri` (RFC-006 §5).
///
/// Nothing is cached here. A Resource AS should cache per issuer and refetch
/// on [`Error::UnknownKeyId`], but rate-limit those refetches (for example
/// once per 60 s per issuer): otherwise anyone who can send assertions with
/// random `kid` values can make it hammer the IdP's JWKS endpoint.
///
/// `http` MUST NOT follow redirects (see the module documentation).
pub async fn fetch_jwks<C: HttpClient>(
    http: &C,
    jwks_uri: &Url,
    opts: &FetchOptions,
) -> Result<FetchedJwks, Error> {
    let request = jwks_request(jwks_uri, opts)?;
    let response = send(http, request).await?;
    parse_jwks_response(&response, opts)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support::{MockHttpClient, json_response, jwks_of, p256_key, rsa_key};

    const JWKS_URL: &str = "https://idp.xaa.dev/jwks";

    fn opts() -> FetchOptions {
        FetchOptions::default()
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn published() -> JwkSet {
        jwks_of(&[&rsa_key(), &p256_key()])
    }

    #[test]
    fn request_is_a_bare_get_for_json() {
        let request = jwks_request(&url(JWKS_URL), &opts()).unwrap();
        assert_eq!(request.method, http::Method::GET);
        assert_eq!(request.url.as_str(), JWKS_URL);
        assert_eq!(request.body, Vec::<u8>::new());
        assert_eq!(
            request.headers,
            vec![("accept".to_owned(), "application/json".to_owned())]
        );
    }

    #[test]
    fn http_jwks_uri_is_refused_except_loopback_when_allowed() {
        assert!(matches!(
            jwks_request(&url("http://idp.xaa.dev/jwks"), &opts()),
            Err(Error::InsecureEndpoint { what: "jwks_uri" })
        ));
        assert!(matches!(
            jwks_request(&url("http://localhost:8080/jwks"), &opts()),
            Err(Error::InsecureEndpoint { what: "jwks_uri" })
        ));
        let relaxed = FetchOptions {
            allow_http_loopback: true,
            ..FetchOptions::default()
        };
        jwks_request(&url("http://localhost:8080/jwks"), &relaxed).unwrap();
        assert!(matches!(
            jwks_request(&url("http://idp.xaa.dev/jwks"), &relaxed),
            Err(Error::InsecureEndpoint { what: "jwks_uri" })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_returns_the_keys_and_the_max_age_hint() {
        let mut response = json_response(200, &published().to_value());
        response.headers.push((
            "Cache-Control".to_owned(),
            "public, max-age=3600".to_owned(),
        ));
        let http = MockHttpClient::new().respond(JWKS_URL, response);
        let fetched = fetch_jwks(&http, &url(JWKS_URL), &opts()).await.unwrap();
        assert_eq!(fetched.keys, published());
        assert_eq!(fetched.keys.keys().len(), 2);
        assert_eq!(fetched.max_age, Some(Duration::from_secs(3600)));
        assert_eq!(http.requested_urls(), vec![JWKS_URL.to_owned()]);
    }

    #[test]
    fn max_age_is_absent_without_the_header() {
        let fetched =
            parse_jwks_response(&json_response(200, &published().to_value()), &opts()).unwrap();
        assert_eq!(fetched.max_age, None);
    }

    #[test]
    fn unsupported_keys_are_skipped() {
        let mut document = published().to_value();
        document
            .get_mut("keys")
            .and_then(|keys| keys.as_array_mut())
            .unwrap()
            .push(json!({ "kty": "OKP", "crv": "Ed25519", "x": "AAAA" }));
        let fetched = parse_jwks_response(&json_response(200, &document), &opts()).unwrap();
        assert_eq!(fetched.keys.keys().len(), 2);
    }

    #[test]
    fn non_200_fails() {
        for status in [204, 302, 404, 500] {
            assert!(matches!(
                parse_jwks_response(&json_response(status, &published().to_value()), &opts()),
                Err(Error::UnexpectedResponse { what: WHAT, status: got }) if got == status
            ));
        }
    }

    #[test]
    fn malformed_bodies_fail() {
        let mut not_json = json_response(200, &json!({}));
        not_json.body = b"<html>".to_vec();
        assert!(matches!(
            parse_jwks_response(&not_json, &opts()),
            Err(Error::MalformedJwk { .. })
        ));
        assert!(matches!(
            parse_jwks_response(&json_response(200, &json!({ "keyz": [] })), &opts()),
            Err(Error::MalformedJwk { .. })
        ));
    }

    #[test]
    fn private_key_material_fails_the_set() {
        let mut document = published().to_value();
        document
            .get_mut("keys")
            .and_then(|keys| keys.get_mut(0))
            .and_then(|key| key.as_object_mut())
            .unwrap()
            .insert("d".to_owned(), json!("AAAA"));
        assert!(matches!(
            parse_jwks_response(&json_response(200, &document), &opts()),
            Err(Error::PrivateKeyMaterial)
        ));
    }

    #[test]
    fn oversized_body_fails() {
        let mut document = published().to_value();
        document
            .as_object_mut()
            .unwrap()
            .insert("padding".to_owned(), json!("x".repeat(70_000)));
        let response = json_response(200, &document);
        assert!(matches!(
            parse_jwks_response(&response, &opts()),
            Err(Error::MalformedJwk {
                reason: "JWK Set exceeds the size limit"
            })
        ));
        let roomy = FetchOptions {
            max_body_bytes: 100_000,
            ..FetchOptions::default()
        };
        parse_jwks_response(&response, &roomy).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_failures_surface() {
        let http = MockHttpClient::new();
        assert!(matches!(
            fetch_jwks(&http, &url(JWKS_URL), &opts()).await,
            Err(Error::UnexpectedResponse { status: 404, .. })
        ));

        let http = MockHttpClient::new().fail(JWKS_URL, "tls handshake failed");
        assert!(matches!(
            fetch_jwks(&http, &url(JWKS_URL), &opts()).await,
            Err(Error::Http(_))
        ));

        let http = MockHttpClient::new();
        assert!(matches!(
            fetch_jwks(&http, &url("http://idp.xaa.dev/jwks"), &opts()).await,
            Err(Error::InsecureEndpoint { what: "jwks_uri" })
        ));
        assert_eq!(http.requests().len(), 0);
    }
}
