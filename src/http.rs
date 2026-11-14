//! Bring-your-own HTTP: the transport seam for the client's token calls and
//! for metadata and JWKS fetches. See RFC-001 §6.
//!
//! Server components never use this trait. They take parsed requests and
//! return [`HttpResponse`] values for the caller's web framework to send.

use std::future::Future;

use url::Url;

/// The HTTP method type used by [`HttpRequest`] and by DPoP proofs,
/// re-exported so callers need no direct dependency on the `http` crate.
pub use http::Method;

/// Boxed error type used at the crate's caller-extension seams.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An HTTP client supplied by the caller.
///
/// Implementations own TLS, timeouts, proxies, and — for mutual-TLS client
/// authentication or certificate-bound tokens (RFC 8705) — the client
/// certificate. They MUST NOT follow redirects for token-endpoint requests:
/// a redirect would replay credentials to another origin.
pub trait HttpClient: Send + Sync {
    /// Send `request` and return the response, whatever its status.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, BoxError>> + Send;
}

/// An outbound HTTP request built by this crate.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    /// Never carries a token or secret (draft §9.2).
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// An HTTP response: one received by the client components, or one built by
/// the server components for the caller to send.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// First value of header `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[cfg(feature = "reqwest-client")]
mod reqwest_impl {
    use super::{BoxError, HttpClient, HttpRequest, HttpResponse};

    /// [`HttpClient`] backed by `reqwest`.
    ///
    /// The wrapped client is public so a caller that already holds a
    /// configured one (proxies, TLS settings, a client certificate for
    /// RFC 8705) can hand it in: `ReqwestClient(client)`. Such a client MUST
    /// be built with redirects disabled; [`ReqwestClient::new`] does that.
    #[derive(Debug, Clone)]
    pub struct ReqwestClient(pub reqwest::Client);

    /// Largest response body [`ReqwestClient`] reads: 1 MiB. Token and
    /// metadata responses are far smaller; the peer may be an untrusted
    /// server named by a `WWW-Authenticate` challenge.
    const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

    impl ReqwestClient {
        /// A client that never follows redirects, gives up on a request
        /// after 30 seconds, and reads at most 1 MiB of a response. A redirect from a token endpoint would replay
        /// credentials to another origin.
        pub fn new() -> Result<Self, BoxError> {
            Ok(Self(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(std::time::Duration::from_secs(10))
                    .timeout(std::time::Duration::from_secs(30))
                    .build()?,
            ))
        }
    }

    impl HttpClient for ReqwestClient {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BoxError> {
            let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())?;
            let mut outbound = self.0.request(method, request.url).body(request.body);
            for (name, value) in &request.headers {
                outbound = outbound.header(name, value);
            }
            let mut response = outbound.send().await?;
            let status = response.status().as_u16();
            let mut headers = Vec::with_capacity(response.headers().len());
            for (name, value) in response.headers() {
                // A header value that is not visible ASCII cannot be one this
                // crate reads (`DPoP-Nonce`, `Cache-Control`, `Content-Type`).
                if let Ok(value) = value.to_str() {
                    headers.push((name.as_str().to_owned(), value.to_owned()));
                }
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err("the response body is larger than 1 MiB".into());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }
    }
}

#[cfg(feature = "reqwest-client")]
pub use reqwest_impl::ReqwestClient;
