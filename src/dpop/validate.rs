//! Server side: DPoP proof validation, nonces, and proof replay.
//! See RFC-007 §3.

use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};
use url::Url;

use crate::claims::NumericDate;
use crate::error::Error;
use crate::form::header_values;
use crate::jose::{
    AlgorithmPolicy, ExpectedTyp, Jwk, ParseLimits, SignatureAlgorithm, UnverifiedJws,
    verify_with_key,
};
use crate::oauth_error::OAuthErrorCode;
use crate::replay::{ReplayNamespace, ReplayOutcome, ReplayStore};

/// The request header that carries the proof (RFC 9449 §4.1).
pub const DPOP_HEADER: &str = "DPoP";
/// The response header that carries a server nonce (RFC 9449 §8).
pub const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";
/// Default acceptance window for a proof's `iat`.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60);

/// Server-chosen DPoP nonces (RFC 9449 §8).
///
/// Nonces are the caller's. A stateless implementation, such as a
/// time-bucketed MAC that accepts the current and the previous bucket, works
/// and needs no storage.
pub trait DpopNonce: Send + Sync {
    /// The nonce to hand out now, in a `DPoP-Nonce` header.
    fn current(&self, now: SystemTime) -> String;
    /// Whether a proof carrying `nonce` is acceptable now.
    fn accept(&self, nonce: &str, now: SystemTime) -> bool;
}

/// Why a DPoP proof was not accepted, and what to answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DpopError {
    /// The proof breaks an RFC 9449 §4.3 rule, or its `jti` was replayed.
    /// Answer `invalid_dpop_proof`. The inner error names the exact rule and
    /// is for logs only.
    #[error("invalid DPoP proof: {0}")]
    InvalidProof(#[source] Error),
    /// A nonce is required and the proof has none or a stale one. Answer
    /// `use_dpop_nonce` and send `nonce` in the `DPoP-Nonce` header
    /// (RFC 9449 §8). Nothing has been consumed; the client retries.
    #[error("DPoP nonce required")]
    UseNonce {
        /// A fresh nonce for the `DPoP-Nonce` response header.
        nonce: String,
    },
    /// The proof could not be judged: the replay store failed or a time
    /// computation overflowed. Fails closed; answer `server_error`.
    #[error("DPoP proof could not be checked: {0}")]
    Internal(#[source] Error),
}

impl DpopError {
    /// The OAuth error code to return (RFC 9449 §5, §8).
    pub fn code(&self) -> OAuthErrorCode {
        match self {
            Self::InvalidProof(_) => OAuthErrorCode::InvalidDpopProof,
            Self::UseNonce { .. } => OAuthErrorCode::UseDpopNonce,
            Self::Internal(_) => OAuthErrorCode::ServerError,
        }
    }

    /// The nonce to send in the `DPoP-Nonce` header of the error response,
    /// if this is a `use_dpop_nonce` rejection.
    pub fn dpop_nonce(&self) -> Option<&str> {
        match self {
            Self::UseNonce { nonce } => Some(nonce),
            Self::InvalidProof(_) | Self::Internal(_) => None,
        }
    }
}

impl From<DpopError> for Error {
    /// The library error behind the rejection. A nonce rejection becomes
    /// [`Error::DpopNonceRequired`] and loses the fresh nonce.
    fn from(error: DpopError) -> Self {
        match error {
            DpopError::InvalidProof(source) | DpopError::Internal(source) => source,
            DpopError::UseNonce { .. } => Self::DpopNonceRequired,
        }
    }
}

fn invalid(reason: &'static str) -> DpopError {
    DpopError::InvalidProof(Error::InvalidDpopProof { reason })
}

/// What a server expects of a DPoP proof on one request.
#[derive(Clone, Copy)]
pub struct DpopValidation<'a> {
    /// The HTTP method of the request: `POST` at a token endpoint.
    pub expected_htm: &'a str,
    /// The URL of the request: the server's own token endpoint, as the
    /// client sees it. Query and fragment are ignored.
    pub expected_htu: &'a Url,
    /// The proof algorithms this server accepts
    /// (`dpop_signing_alg_values_supported`).
    pub algorithms: &'a AlgorithmPolicy,
    /// Set to require a server nonce in every proof (RFC 9449 §8).
    pub nonce: Option<&'a dyn DpopNonce>,
    /// How old a proof's `iat` may be. Default [`DEFAULT_MAX_AGE`].
    pub max_age: Duration,
    pub now: SystemTime,
    /// Tolerance applied to both ends of the `iat` window.
    pub clock_skew: Duration,
}

impl<'a> DpopValidation<'a> {
    /// Expectations for a token endpoint: `POST`, no nonce requirement, and
    /// the default `max_age`. Set the public fields to change them.
    pub fn token_endpoint(
        token_endpoint: &'a Url,
        algorithms: &'a AlgorithmPolicy,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Self {
        Self {
            expected_htm: "POST",
            expected_htu: token_endpoint,
            algorithms,
            nonce: None,
            max_age: DEFAULT_MAX_AGE,
            now,
            clock_skew,
        }
    }
}

impl std::fmt::Debug for DpopValidation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopValidation")
            .field("expected_htm", &self.expected_htm)
            .field("expected_htu", &self.expected_htu.as_str())
            .field("algorithms", &self.algorithms)
            .field("nonce_required", &self.nonce.is_some())
            .field("max_age", &self.max_age)
            .field("now", &self.now)
            .field("clock_skew", &self.clock_skew)
            .finish()
    }
}

/// The asymmetric algorithms a server may accept for DPoP proofs when it has
/// no narrower policy: `ES256`, `ES384`, `RS256`, `PS256`, the ones
/// [`DpopKey::generate`](super::DpopKey::generate) produces.
pub fn default_dpop_algorithms() -> AlgorithmPolicy {
    AlgorithmPolicy::only(&[
        SignatureAlgorithm::Es256,
        SignatureAlgorithm::Es384,
        SignatureAlgorithm::Rs256,
        SignatureAlgorithm::Ps256,
    ])
}

/// Whether the request carries a `DPoP` header at all. Lets a server tell
/// "no proof" from "a bad proof" where the grant does not require one
/// (RFC-007 §4.2).
pub fn has_dpop_header(headers: &[(String, String)]) -> bool {
    !header_values(headers, DPOP_HEADER).is_empty()
}

/// A DPoP proof that passed every RFC 9449 §4.3 check.
///
/// Its `jti` has not been recorded yet: call [`consume`](Self::consume) after
/// the component's own checks pass.
#[derive(Debug, Clone)]
pub struct ValidatedDpopProof {
    jkt: String,
    jti: String,
    iat: NumericDate,
    jwk: Jwk,
    ath: Option<String>,
    replay_until: SystemTime,
}

impl ValidatedDpopProof {
    /// The proof's `ath` claim, if it has one: base64url of the SHA-256 hash
    /// of the access token the proof was made for (RFC 9449 §4.2).
    pub fn ath(&self) -> Option<&str> {
        self.ath.as_deref()
    }

    /// Whether the proof was made for `access_token`: its `ath` is present
    /// and matches. A resource server MUST check this for a DPoP-bound
    /// access token (RFC 9449 §4.3, check 10), together with the key
    /// ([`jkt`](Self::jkt)) the token is bound to. Token endpoints never
    /// call it: proofs sent there have no `ath`.
    pub fn is_for_access_token(&self, access_token: &crate::secret::AccessToken) -> bool {
        use subtle::ConstantTimeEq as _;
        let expected = super::key::access_token_hash(access_token);
        self.ath
            .as_deref()
            .is_some_and(|ath| ath.as_bytes().ct_eq(expected.as_bytes()).into())
    }

    /// The RFC 7638 SHA-256 thumbprint of the proof key: what `cnf.jkt` is
    /// set to or compared with (RFC 9449 §6.1).
    pub fn jkt(&self) -> &str {
        &self.jkt
    }

    /// The proof's unique identifier.
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// When the proof was created.
    pub fn iat(&self) -> NumericDate {
        self.iat
    }

    /// The proof key: the header `jwk`, which verified the signature.
    pub fn public_jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// Record the proof's `jti` and fail if it was seen before
    /// (RFC 9449 §11.1).
    ///
    /// Run this last, after every other check on the request, so a request
    /// rejected for another reason does not burn the `jti`
    /// (jwt-dpop-grant §5.1). The entry lives in
    /// [`ReplayNamespace::DpopProof`] until `iat + max_age + clock_skew`,
    /// after which the proof no longer validates anyway.
    pub async fn consume(
        &self,
        replay: &dyn ReplayStore,
        now: SystemTime,
    ) -> Result<(), DpopError> {
        let namespace = ReplayNamespace::DpopProof { jkt: &self.jkt };
        match replay
            .check_and_insert(namespace, &self.jti, self.replay_until, now)
            .await
        {
            Ok(ReplayOutcome::Fresh) => Ok(()),
            Ok(ReplayOutcome::Replayed) => Err(DpopError::InvalidProof(Error::Replayed {
                what: "DPoP proof jti",
            })),
            Err(source) => Err(DpopError::Internal(Error::ReplayStore(source))),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(jkt: &str) -> Self {
        let key = crate::test_support::p256_key().public_jwk();
        Self {
            jkt: jkt.to_owned(),
            jti: "test-jti".to_owned(),
            iat: NumericDate::from_secs(crate::test_support::NOW_SECS).unwrap(),
            jwk: key,
            ath: None,
            replay_until: crate::test_support::now(),
        }
    }
}

/// Validate the DPoP proof of a request (RFC 9449 §4.3).
///
/// `headers` are the request headers. The checks run in this order, and the
/// first failure ends validation:
///
/// 1. exactly one `DPoP` header;
/// 2. a well-formed compact JWS within the default [`ParseLimits`], whose
///    `alg` is an implemented asymmetric algorithm (never `none` or `HS*`);
/// 3. `typ` is `dpop+jwt`;
/// 4. `alg` is in `v.algorithms`;
/// 5. the header `jwk` is present and is a supported public key with no
///    private members;
/// 6. the key suits `alg`, an RSA key has at least 2048 bits, and the
///    signature verifies with it;
/// 7. `jti`, `htm`, `htu`, and `iat` are present;
/// 8. `htm` equals `v.expected_htm`;
/// 9. `htu` equals `v.expected_htu`, ignoring query and fragment, after
///    RFC 3986 §6.2.2 / §6.2.3 normalization;
/// 10. if `v.nonce` is set, the proof's `nonce` is present and accepted;
///     otherwise [`DpopError::UseNonce`] with a fresh nonce;
/// 11. `iat` is no later than `now + clock_skew` and no earlier than
///     `now - max_age - clock_skew`.
///
/// `ath` is not examined: token-endpoint proofs have none. A Resource
/// Server validating a proof for a resource request sets `expected_htm` /
/// `expected_htu` for that request and then calls
/// [`ValidatedDpopProof::is_for_access_token`] (RFC-007 §6).
pub fn validate_dpop_proof(
    headers: &[(String, String)],
    v: &DpopValidation<'_>,
) -> Result<ValidatedDpopProof, DpopError> {
    // 1. Exactly one header.
    let proof = match header_values(headers, DPOP_HEADER).as_slice() {
        [] => return Err(invalid("no DPoP header")),
        [proof] => *proof,
        _ => return Err(invalid("more than one DPoP header")),
    };

    // 2. A compact JWS. `alg: none` and symmetric algorithms fail to parse.
    let jws =
        UnverifiedJws::parse(proof, &ParseLimits::default()).map_err(DpopError::InvalidProof)?;
    let header = jws.header();

    // 3. `typ`.
    ExpectedTyp::DpopProof
        .check(header)
        .map_err(DpopError::InvalidProof)?;

    // 4. `alg` allow-list.
    let alg = header.algorithm();
    if !v.algorithms.allows(alg) {
        return Err(DpopError::InvalidProof(Error::DisallowedAlgorithm {
            alg: alg.as_str(),
        }));
    }

    // 5. A public key in the header.
    let jwk = header
        .member("jwk")
        .ok_or_else(|| invalid("no jwk header"))?;
    let jwk = Jwk::from_value(jwk)
        .map_err(DpopError::InvalidProof)?
        .ok_or_else(|| invalid("jwk is of an unsupported key type"))?;

    // 6. Key constraints and signature. This is the one place a header key is trusted
    // (RFC-002 §2 rule 7): the proof is self-signed by design.
    let verified =
        verify_with_key::<Map<String, Value>>(&jws, ExpectedTyp::DpopProof, &jwk, v.algorithms)
            .map_err(DpopError::InvalidProof)?;
    let claims = verified.claims();

    // 7. Required claims.
    let jti = required_string(claims, "jti")?;
    let htm = required_string(claims, "htm")?;
    let htu = required_string(claims, "htu")?;
    let iat = match claims.get("iat") {
        None => return Err(missing("iat")),
        Some(value) => {
            NumericDate::from_json(value).ok_or(DpopError::InvalidProof(Error::InvalidClaim {
                name: "iat",
                reason: "not a NumericDate",
            }))?
        }
    };

    // 8. `htm`. Method names are case-sensitive (RFC 9110 §9.1).
    if htm != v.expected_htm {
        return Err(invalid("htm does not match the request method"));
    }

    // 9. `htu`.
    let htu = Url::parse(htu).map_err(|_source| invalid("htu is not an absolute URL"))?;
    if normalized_htu(&htu) != normalized_htu(v.expected_htu) {
        return Err(invalid("htu does not match the request URL"));
    }

    // 10. Nonce. Before the `iat` window: a client whose clock is off can
    // still learn the nonce, and RFC 9449 §8 lets the nonce carry freshness.
    if let Some(nonces) = v.nonce {
        let accepted = match claims.get("nonce") {
            Some(Value::String(nonce)) => nonces.accept(nonce, v.now),
            _ => false,
        };
        if !accepted {
            return Err(DpopError::UseNonce {
                nonce: nonces.current(v.now),
            });
        }
    }

    // 11. `iat` window.
    let created = iat.to_system_time().map_err(DpopError::Internal)?;
    let latest = v
        .now
        .checked_add(v.clock_skew)
        .ok_or(DpopError::Internal(Error::TimeOutOfRange))?;
    if created > latest {
        return Err(invalid("iat is in the future"));
    }
    let replay_until = created
        .checked_add(v.max_age)
        .and_then(|until| until.checked_add(v.clock_skew))
        .ok_or(DpopError::Internal(Error::TimeOutOfRange))?;
    if replay_until < v.now {
        return Err(invalid("iat is too old"));
    }

    Ok(ValidatedDpopProof {
        jkt: verified.key_thumbprint().to_owned(),
        jti: jti.to_owned(),
        iat,
        jwk,
        ath: claims.get("ath").and_then(Value::as_str).map(str::to_owned),
        replay_until,
    })
}

fn missing(name: &'static str) -> DpopError {
    DpopError::InvalidProof(Error::MissingClaim { name })
}

/// A claim that must be a non-empty string.
fn required_string<'c>(
    claims: &'c Map<String, Value>,
    name: &'static str,
) -> Result<&'c str, DpopError> {
    match claims.get(name) {
        None => Err(missing(name)),
        Some(Value::String(text)) if !text.is_empty() => Ok(text),
        Some(_) => Err(DpopError::InvalidProof(Error::InvalidClaim {
            name,
            reason: "not a non-empty string",
        })),
    }
}

/// The parts of a URL that `htu` comparison looks at (RFC 9449 §4.3 check
/// 9): everything but query and fragment.
///
/// [`Url`] already applies most of RFC 3986 §6.2.2 and §6.2.3: lowercase
/// scheme and host, dot-segment removal, an empty path as `/`. The default
/// port is made explicit here and the path's percent-encoding is normalized
/// by [`normalize_percent_encoding`].
#[derive(Debug, PartialEq, Eq)]
struct NormalizedHtu<'u> {
    scheme: &'u str,
    username: &'u str,
    password: Option<&'u str>,
    host: Option<&'u str>,
    port: Option<u16>,
    path: String,
}

fn normalized_htu(url: &Url) -> NormalizedHtu<'_> {
    NormalizedHtu {
        scheme: url.scheme(),
        username: url.username(),
        password: url.password(),
        host: url.host_str(),
        port: url.port_or_known_default(),
        path: normalize_percent_encoding(url.path()),
    }
}

/// RFC 3986 §6.2.2.1 and §6.2.2.2: uppercase the hex digits of
/// percent-encoded octets, and decode those that encode unreserved
/// characters.
fn normalize_percent_encoding(path: &str) -> String {
    let mut normalized = String::with_capacity(path.len());
    let mut chars = path.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            normalized.push(c);
            continue;
        }
        let mut ahead = chars.clone();
        let octet = ahead
            .next()
            .zip(ahead.next())
            .and_then(|(high, low)| Some((high.to_digit(16)?, low.to_digit(16)?)))
            .and_then(|(high, low)| u8::try_from(high.checked_mul(16)?.checked_add(low)?).ok());
        let Some(octet) = octet else {
            // A stray `%`: keep it as it is.
            normalized.push(c);
            continue;
        };
        chars = ahead;
        if octet.is_ascii_alphanumeric() || matches!(octet, b'-' | b'.' | b'_' | b'~') {
            normalized.push(char::from(octet));
        } else {
            normalized.push('%');
            for digit in [octet / 16, octet % 16] {
                let digit = char::from_digit(u32::from(digit), 16).unwrap_or('0');
                normalized.push(digit.to_ascii_uppercase());
            }
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpop::{DpopKey, DpopRequest};
    use crate::jose::{JwsSigner, PrivateKey, b64url_encode};
    use crate::replay::{InMemoryReplayStore, ReplayFuture};
    use crate::test_support::{
        NOW_SECS, RSA_1024_PEM, now, other_rsa_key, p256_key, rsa_key, sign_raw,
    };
    use serde_json::json;
    use std::sync::Arc;

    const TOKEN_ENDPOINT: &str = "https://as.example/token";
    const SKEW: Duration = Duration::from_secs(30);

    fn endpoint() -> Url {
        Url::parse(TOKEN_ENDPOINT).unwrap()
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))
            .unwrap()
    }

    fn headers(proof: &str) -> Vec<(String, String)> {
        vec![
            (
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("DPoP".to_owned(), proof.to_owned()),
        ]
    }

    /// Validate `proof` against the token endpoint with default settings.
    fn check(proof: &str) -> Result<ValidatedDpopProof, DpopError> {
        let endpoint = endpoint();
        let algorithms = default_dpop_algorithms();
        let v = DpopValidation::token_endpoint(&endpoint, &algorithms, now(), SKEW);
        validate_dpop_proof(&headers(proof), &v)
    }

    /// The library error behind an `invalid_dpop_proof` rejection.
    fn invalid_reason(result: Result<ValidatedDpopProof, DpopError>) -> Error {
        let err = result.unwrap_err();
        assert_eq!(err.code(), OAuthErrorCode::InvalidDpopProof, "{err}");
        assert_eq!(err.dpop_nonce(), None);
        match err {
            DpopError::InvalidProof(source) => source,
            other => panic!("expected an invalid proof, got {other:?}"),
        }
    }

    fn default_claims() -> Value {
        json!({"jti": "jti-1", "htm": "POST", "htu": TOKEN_ENDPOINT, "iat": NOW_SECS})
    }

    fn header_for(key: &PrivateKey) -> Value {
        json!({
            "typ": "dpop+jwt",
            "alg": key.algorithm().as_str(),
            "jwk": key.public_jwk().to_value(),
        })
    }

    /// A proof signed by the P-256 fixture, with `claims` and a header
    /// edited by `edit_header`.
    async fn proof_with(claims: &Value, edit_header: impl FnOnce(&mut Value)) -> String {
        let key = p256_key();
        let mut header = header_for(&key);
        edit_header(&mut header);
        sign_raw(&key, &header.to_string(), &claims.to_string()).await
    }

    async fn proof_with_claims(claims: &Value) -> String {
        proof_with(claims, |_| {}).await
    }

    /// The default claims with `name` set to `value`, or removed for `null`.
    fn claims_with(name: &str, value: Value) -> Value {
        let mut claims = default_claims();
        let object = claims.as_object_mut().unwrap();
        if value.is_null() {
            object.remove(name);
        } else {
            object.insert(name.to_owned(), value);
        }
        claims
    }

    struct FixedNonce;

    impl DpopNonce for FixedNonce {
        fn current(&self, _now: SystemTime) -> String {
            "nonce-current".to_owned()
        }

        fn accept(&self, nonce: &str, _now: SystemTime) -> bool {
            nonce == "nonce-current" || nonce == "nonce-previous"
        }
    }

    // ----- Positive ---------------------------------------------------------

    #[tokio::test]
    async fn created_proof_validates_for_every_generated_algorithm() {
        let rsa = rsa_key();
        let pss = rsa_key().with_algorithm(SignatureAlgorithm::Ps256).unwrap();
        let keys = [
            DpopKey::generate(SignatureAlgorithm::Es256).unwrap(),
            DpopKey::generate(SignatureAlgorithm::Es384).unwrap(),
            DpopKey::from_signer(Arc::new(rsa_key()), rsa.public_jwk()).unwrap(),
            DpopKey::from_signer(Arc::new(pss), rsa.public_jwk()).unwrap(),
        ];
        for key in keys {
            let request = DpopRequest {
                key: &key,
                nonce: None,
            };
            let proof = request
                .token_endpoint_proof(&endpoint(), now())
                .await
                .unwrap();
            let validated = check(&proof).unwrap();
            assert_eq!(validated.jkt(), key.thumbprint());
            assert_eq!(validated.public_jwk().thumbprint_sha256(), key.thumbprint());
            assert_eq!(validated.iat().as_secs(), NOW_SECS);
            assert_eq!(validated.jti().len(), 22);
        }
    }

    #[test]
    fn rfc_9449_examples_verify() {
        // RFC 9449 §4.2 Figure 2 / §5 Figure 4: a token-endpoint proof.
        const TOKEN_PROOF: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik\
            VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR\
            nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE\
            QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj\
            oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia\
            WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg\
            4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";
        // RFC 9449 §7.1 Figure 13: a resource-request proof with `ath`.
        const RESOURCE_PROOF: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik\
            VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR\
            nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE\
            QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj\
            oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z\
            WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF\
            c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E\
            OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";
        // RFC 9449 §6.1 Figure 8: the thumbprint of the example key.
        const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

        let algorithms = AlgorithmPolicy::only(&[SignatureAlgorithm::Es256]);
        let cases = [
            (
                TOKEN_PROOF,
                "POST",
                "https://server.example.com/token",
                1_562_262_616,
                "-BwC3ESc6acc2lTc",
            ),
            (
                RESOURCE_PROOF,
                "GET",
                "https://resource.example.org/protectedresource",
                1_562_262_618,
                "e1j3V_bKic8-LAEB",
            ),
        ];
        for (proof, htm, htu, iat, jti) in cases {
            let htu = Url::parse(htu).unwrap();
            let mut v = DpopValidation::token_endpoint(&htu, &algorithms, at(iat), Duration::ZERO);
            v.expected_htm = htm;
            let validated = validate_dpop_proof(&headers(proof), &v).unwrap();
            assert_eq!(validated.jkt(), JKT);
            assert_eq!(validated.jti(), jti);
            assert_eq!(validated.iat().as_secs(), iat);

            // RFC 9449 §7.1: the access token the Figure 13 proof is for.
            let token =
                crate::secret::AccessToken::new("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU");
            let other = crate::secret::AccessToken::new("another-token");
            if htm == "GET" {
                assert_eq!(
                    validated.ath(),
                    Some("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo")
                );
                assert!(validated.is_for_access_token(&token));
                assert!(!validated.is_for_access_token(&other));
            } else {
                // A token-endpoint proof has no `ath` and is for no token.
                assert_eq!(validated.ath(), None);
                assert!(!validated.is_for_access_token(&token));
            }
        }
    }

    // ----- Row 1: exactly one DPoP header -----------------------------------

    #[tokio::test]
    async fn row_1_no_header_or_several() {
        let endpoint = endpoint();
        let algorithms = default_dpop_algorithms();
        let v = DpopValidation::token_endpoint(&endpoint, &algorithms, now(), SKEW);
        let proof = proof_with_claims(&default_claims()).await;

        let none = vec![("Accept".to_owned(), "*/*".to_owned())];
        assert!(!has_dpop_header(&none));
        assert!(matches!(
            invalid_reason(validate_dpop_proof(&none, &v)),
            Error::InvalidDpopProof {
                reason: "no DPoP header"
            }
        ));

        // Header names are case-insensitive, so these are two DPoP headers.
        let two = vec![
            ("DPoP".to_owned(), proof.clone()),
            ("dpop".to_owned(), proof.clone()),
        ];
        assert!(has_dpop_header(&two));
        assert!(matches!(
            invalid_reason(validate_dpop_proof(&two, &v)),
            Error::InvalidDpopProof {
                reason: "more than one DPoP header"
            }
        ));

        // Two proofs folded into one field value do not parse as one JWS.
        let folded = headers(&format!("{proof}, {proof}"));
        invalid_reason(validate_dpop_proof(&folded, &v));

        let one = vec![("dpop".to_owned(), proof)];
        validate_dpop_proof(&one, &v).unwrap();
    }

    // ----- Row 2: a well-formed compact JWS within limits -------------------

    #[tokio::test]
    async fn row_2_malformed_or_oversized_jws() {
        assert!(matches!(
            invalid_reason(check("not-a-jws")),
            Error::MalformedJws { .. }
        ));
        assert!(matches!(
            invalid_reason(check("")),
            Error::MalformedJws { .. }
        ));
        let proof = proof_with_claims(&default_claims()).await;
        assert!(matches!(
            invalid_reason(check(&format!("{proof}.x.y"))),
            Error::EncryptedJwtUnsupported
        ));
        let huge = claims_with("pad", Value::from("x".repeat(20_000)));
        assert!(matches!(
            invalid_reason(check(&proof_with_claims(&huge).await)),
            Error::TokenTooLong { .. }
        ));
        let critical = proof_with(&default_claims(), |header| {
            header["crit"] = json!(["b64"]);
        })
        .await;
        assert!(matches!(
            invalid_reason(check(&critical)),
            Error::CriticalHeader
        ));
    }

    // ----- Row 3: typ -------------------------------------------------------

    #[tokio::test]
    async fn row_3_wrong_or_missing_typ() {
        for typ in [
            json!("JWT"),
            json!("oauth-id-jag+jwt"),
            json!("at+jwt"),
            Value::Null,
        ] {
            let proof = proof_with(&default_claims(), |header| {
                if typ.is_null() {
                    header.as_object_mut().unwrap().remove("typ");
                } else {
                    header["typ"] = typ.clone();
                }
            })
            .await;
            assert!(
                matches!(invalid_reason(check(&proof)), Error::WrongTyp { .. }),
                "{typ}"
            );
        }
    }

    // ----- Row 4: alg -------------------------------------------------------

    #[tokio::test]
    async fn row_4_alg_outside_the_policy_none_or_symmetric() {
        // A valid ES256 proof for a server that accepts only RS256.
        let proof = proof_with_claims(&default_claims()).await;
        let endpoint = endpoint();
        let algorithms = AlgorithmPolicy::only(&[SignatureAlgorithm::Rs256]);
        let v = DpopValidation::token_endpoint(&endpoint, &algorithms, now(), SKEW);
        assert!(matches!(
            invalid_reason(validate_dpop_proof(&headers(&proof), &v)),
            Error::DisallowedAlgorithm { alg: "ES256" }
        ));

        // RS512 is implemented but not in the default DPoP policy.
        let rs512 = rsa_key().with_algorithm(SignatureAlgorithm::Rs512).unwrap();
        let proof = sign_raw(
            &rs512,
            &header_for(&rs512).to_string(),
            &default_claims().to_string(),
        )
        .await;
        assert!(matches!(
            invalid_reason(check(&proof)),
            Error::DisallowedAlgorithm { alg: "RS512" }
        ));

        // `none` and symmetric algorithms never get past parsing, whatever
        // the policy says.
        for alg in ["none", "HS256", "HS512"] {
            let proof = proof_with(&default_claims(), |header| {
                header["alg"] = json!(alg);
            })
            .await;
            assert!(
                matches!(
                    invalid_reason(check(&proof)),
                    Error::UnsupportedAlgorithm { .. }
                ),
                "{alg}"
            );
        }
    }

    // ----- Row 5: jwk -------------------------------------------------------

    #[tokio::test]
    async fn row_5_jwk_missing_private_or_unsupported() {
        let missing = proof_with(&default_claims(), |header| {
            header.as_object_mut().unwrap().remove("jwk");
        })
        .await;
        assert!(matches!(
            invalid_reason(check(&missing)),
            Error::InvalidDpopProof {
                reason: "no jwk header"
            }
        ));

        // A private key in the header, even the right one.
        let private = proof_with(&default_claims(), |header| {
            header["jwk"]["d"] = json!("c2VjcmV0");
        })
        .await;
        assert!(matches!(
            invalid_reason(check(&private)),
            Error::PrivateKeyMaterial
        ));

        // A symmetric key.
        let symmetric = proof_with(&default_claims(), |header| {
            header["jwk"] = json!({"kty": "oct", "k": "c2VjcmV0"});
        })
        .await;
        assert!(matches!(
            invalid_reason(check(&symmetric)),
            Error::PrivateKeyMaterial
        ));

        let unsupported = proof_with(&default_claims(), |header| {
            header["jwk"] = json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"});
        })
        .await;
        assert!(matches!(
            invalid_reason(check(&unsupported)),
            Error::InvalidDpopProof {
                reason: "jwk is of an unsupported key type"
            }
        ));

        for not_a_key in [json!("jwk"), json!({"kty": "EC", "crv": "P-256"})] {
            let proof = proof_with(&default_claims(), |header| {
                header["jwk"] = not_a_key.clone();
            })
            .await;
            assert!(
                matches!(invalid_reason(check(&proof)), Error::MalformedJwk { .. }),
                "{not_a_key}"
            );
        }
    }

    #[tokio::test]
    async fn row_5_rsa_key_under_2048_bits() {
        use pkcs8::DecodePrivateKey as _;
        use rsa::signature::{SignatureEncoding as _, Signer as _};
        use rsa::traits::PublicKeyParts as _;
        let weak = rsa::PrivateKey::from_pkcs8_pem(RSA_1024_PEM).unwrap();
        let header = json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {
                "kty": "RSA",
                "n": b64url_encode(&weak.n_bytes()),
                "e": b64url_encode(&weak.e_bytes()),
            },
        });
        let mut proof = b64url_encode(header.to_string().as_bytes());
        proof.push('.');
        proof.push_str(&b64url_encode(default_claims().to_string().as_bytes()));
        let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(weak)
            .try_sign(proof.as_bytes())
            .unwrap();
        proof.push('.');
        proof.push_str(&b64url_encode(&signature.to_bytes()));
        assert!(matches!(
            invalid_reason(check(&proof)),
            Error::WeakKey { bits: 1024 }
        ));
    }

    // ----- Row 6: signature -------------------------------------------------

    #[tokio::test]
    async fn row_6_signature_does_not_verify_with_the_header_key() {
        // Signed by one RSA key, claiming another in the header.
        let signer = rsa_key();
        let claimed = other_rsa_key();
        let proof = sign_raw(
            &signer,
            &header_for(&claimed).to_string(),
            &default_claims().to_string(),
        )
        .await;
        assert!(matches!(invalid_reason(check(&proof)), Error::BadSignature));

        // A payload changed after signing.
        let proof = proof_with_claims(&default_claims()).await;
        let mut segments: Vec<&str> = proof.split('.').collect();
        let forged = b64url_encode(
            claims_with("htu", json!("https://evil.example/token"))
                .to_string()
                .as_bytes(),
        );
        segments[1] = &forged;
        assert!(matches!(
            invalid_reason(check(&segments.join("."))),
            Error::BadSignature
        ));

        // A header key of another type than the algorithm.
        let mismatched = proof_with(&default_claims(), |header| {
            header["jwk"] = rsa_key().public_jwk().to_value();
        })
        .await;
        assert!(matches!(
            invalid_reason(check(&mismatched)),
            Error::KeyMismatch { .. }
        ));
    }

    // ----- Row 7: required claims -------------------------------------------

    #[tokio::test]
    async fn row_7_required_claims() {
        for name in ["jti", "htm", "htu", "iat"] {
            let proof = proof_with_claims(&claims_with(name, Value::Null)).await;
            match invalid_reason(check(&proof)) {
                Error::MissingClaim { name: missing } => assert_eq!(missing, name),
                other => panic!("{name}: {other:?}"),
            }
        }
        for (name, value) in [
            ("jti", json!(7)),
            ("jti", json!("")),
            ("htm", json!(["POST"])),
            ("htu", json!({})),
            ("iat", json!("now")),
            ("iat", json!(-1)),
        ] {
            let proof = proof_with_claims(&claims_with(name, value.clone())).await;
            match invalid_reason(check(&proof)) {
                Error::InvalidClaim { name: invalid, .. } => assert_eq!(invalid, name),
                other => panic!("{name}={value}: {other:?}"),
            }
        }
        // A payload that is not a JSON object.
        let key = p256_key();
        let proof = sign_raw(&key, &header_for(&key).to_string(), "[]").await;
        assert!(matches!(
            invalid_reason(check(&proof)),
            Error::MalformedClaims(_)
        ));
    }

    // ----- Row 8: htm -------------------------------------------------------

    #[tokio::test]
    async fn row_8_htm_mismatch() {
        for htm in ["GET", "post", "PUT"] {
            let proof = proof_with_claims(&claims_with("htm", json!(htm))).await;
            assert!(
                matches!(
                    invalid_reason(check(&proof)),
                    Error::InvalidDpopProof {
                        reason: "htm does not match the request method"
                    }
                ),
                "{htm}"
            );
        }
    }

    // ----- Row 9: htu -------------------------------------------------------

    #[tokio::test]
    async fn row_9_htu_mismatch() {
        for htu in [
            "https://as.example/token2",
            "https://as.example/token/",
            "https://as.example/Token",
            "https://as.example/",
            "https://other.example/token",
            "https://as.example.evil.example/token",
            "http://as.example/token",
            "https://as.example:8443/token",
            "https://user@as.example/token",
        ] {
            let proof = proof_with_claims(&claims_with("htu", json!(htu))).await;
            assert!(
                matches!(
                    invalid_reason(check(&proof)),
                    Error::InvalidDpopProof {
                        reason: "htu does not match the request URL"
                    }
                ),
                "{htu}"
            );
        }
        for htu in ["/token", "as.example/token", "not a url"] {
            let proof = proof_with_claims(&claims_with("htu", json!(htu))).await;
            assert!(
                matches!(
                    invalid_reason(check(&proof)),
                    Error::InvalidDpopProof {
                        reason: "htu is not an absolute URL"
                    }
                ),
                "{htu}"
            );
        }
    }

    #[tokio::test]
    async fn row_9_htu_ignores_query_and_fragment_and_normalizes() {
        for htu in [
            // Query and fragment are ignored (RFC 9449 §4.3 check 9).
            "https://as.example/token?tenant=a",
            "https://as.example/token#frag",
            "https://as.example/token?a=b#frag",
            // RFC 3986 §6.2.2.1: case of scheme, host, and hex digits.
            "HTTPS://AS.EXAMPLE/token",
            "https://as.example/%74oken",
            "https://as.example/tok%65n",
            // §6.2.2.3: dot segments.
            "https://as.example/a/../token",
            "https://as.example/./token",
            // §6.2.3: the default port.
            "https://as.example:443/token",
        ] {
            let proof = proof_with_claims(&claims_with("htu", json!(htu))).await;
            check(&proof).unwrap_or_else(|err| panic!("{htu}: {err:?}"));
        }

        // The server's own URL is normalized the same way, and its query is
        // ignored too.
        let expected = Url::parse("https://as.example:443/a%2fb/%7Etoken?x=1").unwrap();
        let algorithms = default_dpop_algorithms();
        let v = DpopValidation::token_endpoint(&expected, &algorithms, now(), SKEW);
        let same = proof_with_claims(&claims_with(
            "htu",
            json!("https://as.example/a%2Fb/~token"),
        ))
        .await;
        validate_dpop_proof(&headers(&same), &v).unwrap();
        // An encoded reserved character is not the character itself.
        let different =
            proof_with_claims(&claims_with("htu", json!("https://as.example/a/b/~token"))).await;
        invalid_reason(validate_dpop_proof(&headers(&different), &v));
    }

    #[test]
    fn percent_encoding_normalization() {
        for (input, expected) in [
            ("/token", "/token"),
            ("/%7e%41%2d%2E%5f", "/~A-._"),
            ("/a%2fb%3a", "/a%2Fb%3A"),
            ("/%", "/%"),
            ("/%4", "/%4"),
            ("/%zz%41", "/%zzA"),
            ("/%c3%a9", "/%C3%A9"),
        ] {
            assert_eq!(normalize_percent_encoding(input), expected, "{input}");
        }
    }

    // ----- Row 10: nonce ----------------------------------------------------

    #[tokio::test]
    async fn row_10_nonce_missing_or_stale_gets_a_fresh_one() {
        let endpoint = endpoint();
        let algorithms = default_dpop_algorithms();
        let mut v = DpopValidation::token_endpoint(&endpoint, &algorithms, now(), SKEW);
        v.nonce = Some(&FixedNonce);

        for nonce in [Value::Null, json!("nonce-ancient"), json!(""), json!(7)] {
            let proof = proof_with_claims(&claims_with("nonce", nonce.clone())).await;
            let err = validate_dpop_proof(&headers(&proof), &v).unwrap_err();
            assert_eq!(err.code(), OAuthErrorCode::UseDpopNonce, "{nonce}");
            assert_eq!(err.dpop_nonce(), Some("nonce-current"), "{nonce}");
            assert!(matches!(Error::from(err), Error::DpopNonceRequired));
        }
        for nonce in ["nonce-current", "nonce-previous"] {
            let proof = proof_with_claims(&claims_with("nonce", json!(nonce))).await;
            validate_dpop_proof(&headers(&proof), &v).unwrap();
        }

        // Without a nonce requirement, a nonce in the proof is ignored.
        let proof = proof_with_claims(&claims_with("nonce", json!("anything"))).await;
        check(&proof).unwrap();
    }

    #[tokio::test]
    async fn row_10_runs_after_the_proof_checks_and_before_iat() {
        let endpoint = endpoint();
        let algorithms = default_dpop_algorithms();
        let mut v = DpopValidation::token_endpoint(&endpoint, &algorithms, now(), SKEW);
        v.nonce = Some(&FixedNonce);

        // A proof for another URL is invalid, not a nonce prompt: a nonce is
        // only handed to a proof that is otherwise well-formed.
        let wrong_htu =
            proof_with_claims(&claims_with("htu", json!("https://as.example/other"))).await;
        invalid_reason(validate_dpop_proof(&headers(&wrong_htu), &v));

        // A stale proof without a nonce is asked for the nonce first.
        let stale = proof_with_claims(&claims_with("iat", json!(NOW_SECS - 3600))).await;
        let err = validate_dpop_proof(&headers(&stale), &v).unwrap_err();
        assert_eq!(err.code(), OAuthErrorCode::UseDpopNonce);

        // With the nonce, the stale `iat` is what fails.
        let mut claims = claims_with("iat", json!(NOW_SECS - 3600));
        claims["nonce"] = json!("nonce-current");
        let stale = proof_with_claims(&claims).await;
        assert!(matches!(
            invalid_reason(validate_dpop_proof(&headers(&stale), &v)),
            Error::InvalidDpopProof {
                reason: "iat is too old"
            }
        ));
    }

    #[tokio::test]
    async fn nonce_rejection_consumes_nothing_and_the_retry_succeeds() {
        let endpoint = endpoint();
        let algorithms = default_dpop_algorithms();
        let mut v = DpopValidation::token_endpoint(&endpoint, &algorithms, now(), SKEW);
        v.nonce = Some(&FixedNonce);
        let replay = InMemoryReplayStore::new(16);
        let key = DpopKey::generate(SignatureAlgorithm::Es256).unwrap();

        let first = DpopRequest {
            key: &key,
            nonce: None,
        };
        let proof = first.token_endpoint_proof(&endpoint, now()).await.unwrap();
        let err = validate_dpop_proof(&headers(&proof), &v).unwrap_err();
        let nonce = err.dpop_nonce().unwrap().to_owned();

        let retry = DpopRequest {
            key: &key,
            nonce: Some(&nonce),
        };
        let proof = retry.token_endpoint_proof(&endpoint, now()).await.unwrap();
        let validated = validate_dpop_proof(&headers(&proof), &v).unwrap();
        assert_eq!(validated.jkt(), key.thumbprint());
        validated.consume(&replay, now()).await.unwrap();
    }

    // ----- Row 11: iat ------------------------------------------------------

    #[tokio::test]
    async fn row_11_iat_window() {
        // max_age 60 s, skew 30 s: accepted from now - 90 s to now + 30 s.
        for iat in [NOW_SECS - 90, NOW_SECS - 60, NOW_SECS, NOW_SECS + 30] {
            let proof = proof_with_claims(&claims_with("iat", json!(iat))).await;
            check(&proof).unwrap_or_else(|err| panic!("{iat}: {err:?}"));
        }
        for iat in [NOW_SECS - 91, NOW_SECS - 3600, 0] {
            let proof = proof_with_claims(&claims_with("iat", json!(iat))).await;
            assert!(
                matches!(
                    invalid_reason(check(&proof)),
                    Error::InvalidDpopProof {
                        reason: "iat is too old"
                    }
                ),
                "{iat}"
            );
        }
        for iat in [NOW_SECS + 31, NOW_SECS + 3600] {
            let proof = proof_with_claims(&claims_with("iat", json!(iat))).await;
            assert!(
                matches!(
                    invalid_reason(check(&proof)),
                    Error::InvalidDpopProof {
                        reason: "iat is in the future"
                    }
                ),
                "{iat}"
            );
        }

        // `max_age` and `clock_skew` are the caller's.
        let endpoint = endpoint();
        let algorithms = default_dpop_algorithms();
        let mut v = DpopValidation::token_endpoint(&endpoint, &algorithms, now(), Duration::ZERO);
        v.max_age = Duration::from_secs(5);
        let proof = proof_with_claims(&claims_with("iat", json!(NOW_SECS - 5))).await;
        validate_dpop_proof(&headers(&proof), &v).unwrap();
        let proof = proof_with_claims(&claims_with("iat", json!(NOW_SECS - 6))).await;
        invalid_reason(validate_dpop_proof(&headers(&proof), &v));
        let proof = proof_with_claims(&claims_with("iat", json!(NOW_SECS + 1))).await;
        invalid_reason(validate_dpop_proof(&headers(&proof), &v));
    }

    // ----- Replay -----------------------------------------------------------

    #[tokio::test]
    async fn replayed_jti_is_rejected_per_key() {
        let replay = InMemoryReplayStore::new(16);
        let proof = proof_with_claims(&default_claims()).await;
        let validated = check(&proof).unwrap();
        validated.consume(&replay, now()).await.unwrap();

        // The same proof again validates but is not fresh.
        let again = check(&proof).unwrap();
        let err = again.consume(&replay, now()).await.unwrap_err();
        assert_eq!(err.code(), OAuthErrorCode::InvalidDpopProof);
        assert!(matches!(
            err,
            DpopError::InvalidProof(Error::Replayed {
                what: "DPoP proof jti"
            })
        ));

        // The same jti under another key is a different proof.
        let other = rsa_key();
        let proof = sign_raw(
            &other,
            &header_for(&other).to_string(),
            &default_claims().to_string(),
        )
        .await;
        check(&proof)
            .unwrap()
            .consume(&replay, now())
            .await
            .unwrap();

        // Another jti under the first key is fresh.
        let proof = proof_with_claims(&claims_with("jti", json!("jti-2"))).await;
        check(&proof)
            .unwrap()
            .consume(&replay, now())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn replay_entry_lives_until_the_proof_stops_validating() {
        struct Recorder(std::sync::Mutex<Vec<(String, String, SystemTime)>>);

        impl ReplayStore for Recorder {
            fn check_and_insert<'a>(
                &'a self,
                ns: ReplayNamespace<'a>,
                id: &'a str,
                expires_at: SystemTime,
                _now: SystemTime,
            ) -> ReplayFuture<'a> {
                self.0
                    .lock()
                    .unwrap()
                    .push((format!("{ns:?}"), id.to_owned(), expires_at));
                Box::pin(std::future::ready(Ok(ReplayOutcome::Fresh)))
            }
        }

        let recorder = Recorder(std::sync::Mutex::new(Vec::new()));
        let proof = proof_with_claims(&claims_with("iat", json!(NOW_SECS - 10))).await;
        let validated = check(&proof).unwrap();
        validated.consume(&recorder, now()).await.unwrap();

        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (namespace, id, expires_at) = &calls[0];
        let expected_namespace = ReplayNamespace::DpopProof {
            jkt: validated.jkt(),
        };
        assert_eq!(namespace, &format!("{expected_namespace:?}"));
        assert_eq!(id, "jti-1");
        // iat + max_age (60 s) + skew (30 s).
        assert_eq!(*expires_at, at(NOW_SECS - 10 + 60 + 30));
    }

    #[tokio::test]
    async fn replay_store_failure_fails_closed() {
        struct Broken;

        impl ReplayStore for Broken {
            fn check_and_insert<'a>(
                &'a self,
                _ns: ReplayNamespace<'a>,
                _id: &'a str,
                _expires_at: SystemTime,
                _now: SystemTime,
            ) -> ReplayFuture<'a> {
                Box::pin(std::future::ready(Err("store is down".into())))
            }
        }

        let proof = proof_with_claims(&default_claims()).await;
        let err = check(&proof)
            .unwrap()
            .consume(&Broken, now())
            .await
            .unwrap_err();
        assert_eq!(err.code(), OAuthErrorCode::ServerError);
        assert!(matches!(err, DpopError::Internal(Error::ReplayStore(_))));
        assert!(matches!(Error::from(err), Error::ReplayStore(_)));
    }
}
