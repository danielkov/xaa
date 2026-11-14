//! Shared fixtures for unit tests.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::http::{BoxError, HttpClient, HttpRequest, HttpResponse};
use crate::jose::{JwkSet, JwsSigner, PrivateKey, SignatureAlgorithm, sign_jws};

pub(crate) const RSA_2048_PEM: &str = include_str!("../tests/fixtures/rsa2048.pem");
pub(crate) const RSA_2048_B_PEM: &str = include_str!("../tests/fixtures/rsa2048_b.pem");
pub(crate) const RSA_1024_PEM: &str = include_str!("../tests/fixtures/rsa1024.pem");
pub(crate) const P256_PEM: &str = include_str!("../tests/fixtures/p256.pem");
pub(crate) const P384_PEM: &str = include_str!("../tests/fixtures/p384.pem");

/// 2026-11-14T12:00:00Z.
pub(crate) const NOW_SECS: u64 = 1_794_657_600;

pub(crate) fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(NOW_SECS))
        .unwrap()
}

pub(crate) fn rsa_key() -> PrivateKey {
    PrivateKey::from_pkcs8_pem(RSA_2048_PEM)
        .unwrap()
        .with_key_id("rsa-1")
}

pub(crate) fn other_rsa_key() -> PrivateKey {
    PrivateKey::from_pkcs8_pem(RSA_2048_B_PEM)
        .unwrap()
        .with_key_id("rsa-2")
}

pub(crate) fn p256_key() -> PrivateKey {
    PrivateKey::from_pkcs8_pem(P256_PEM)
        .unwrap()
        .with_key_id("p256-1")
}

pub(crate) fn p384_key() -> PrivateKey {
    PrivateKey::from_pkcs8_pem(P384_PEM)
        .unwrap()
        .with_key_id("p384-1")
}

/// A key for `alg`, with a `kid`.
pub(crate) fn key_for(alg: SignatureAlgorithm) -> PrivateKey {
    match alg {
        SignatureAlgorithm::Es256 => p256_key(),
        SignatureAlgorithm::Es384 => p384_key(),
        rsa => rsa_key().with_algorithm(rsa).unwrap(),
    }
}

pub(crate) fn jwks_of(keys: &[&PrivateKey]) -> JwkSet {
    JwkSet::from_keys(keys.iter().map(|key| key.public_jwk()).collect())
}

/// Sign `claims` with `key`.
pub(crate) async fn sign(
    key: &dyn JwsSigner,
    typ: Option<&str>,
    claims: &impl Serialize,
) -> String {
    sign_jws(key, typ, BTreeMap::new(), claims).await.unwrap()
}

/// Assemble a compact JWS from a raw header and payload, signed with `key`
/// over exactly those bytes. For tests that need headers the signer never
/// emits.
pub(crate) async fn sign_raw(key: &dyn JwsSigner, header_json: &str, payload_json: &str) -> String {
    let mut token = crate::jose::b64url_encode(header_json.as_bytes());
    token.push('.');
    token.push_str(&crate::jose::b64url_encode(payload_json.as_bytes()));
    let signature = key.sign(token.as_bytes()).await.unwrap();
    token.push('.');
    token.push_str(&crate::jose::b64url_encode(&signature));
    token
}

/// A response with `status`, a JSON content type, and `body` serialized.
pub(crate) fn json_response(status: u16, body: &impl Serialize) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(body).unwrap(),
    }
}

/// An [`HttpClient`] that answers from canned responses keyed by exact URL
/// (any method) and records every request.
///
/// - A URL with no route gets an empty 404.
/// - Several outcomes queued for one URL are served in order; the last one
///   repeats. That covers retry flows such as a DPoP nonce challenge.
/// - It never follows redirects: a 3xx is returned as queued.
#[derive(Default)]
pub(crate) struct MockHttpClient {
    routes: Mutex<BTreeMap<String, VecDeque<Result<HttpResponse, String>>>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl MockHttpClient {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Queue `response` for requests to `url`.
    pub(crate) fn respond(self, url: &str, response: HttpResponse) -> Self {
        self.push(url, Ok(response));
        self
    }

    /// Queue a transport error for requests to `url`.
    pub(crate) fn fail(self, url: &str, message: &str) -> Self {
        self.push(url, Err(message.to_owned()));
        self
    }

    fn push(&self, url: &str, outcome: Result<HttpResponse, String>) {
        self.routes
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .push_back(outcome);
    }

    /// Every request sent so far, in order.
    pub(crate) fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// The URL of every request sent so far, in order.
    pub(crate) fn requested_urls(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| request.url.to_string())
            .collect()
    }
}

impl HttpClient for MockHttpClient {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, BoxError>> + Send {
        let outcome = {
            let mut routes = self.routes.lock().unwrap();
            match routes.get_mut(request.url.as_str()) {
                Some(queue) if queue.len() > 1 => queue.pop_front(),
                Some(queue) => queue.front().cloned(),
                None => None,
            }
        };
        self.requests.lock().unwrap().push(request);
        std::future::ready(match outcome {
            Some(Ok(response)) => Ok(response),
            Some(Err(message)) => Err(message.into()),
            None => Ok(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }),
        })
    }
}
