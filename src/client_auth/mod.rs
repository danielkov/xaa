//! Client authentication at a token endpoint: how the client presents
//! credentials, how a server extracts them, and `private_key_jwt` client
//! assertions (RFC 7523 as updated by RFC 10070). See RFC-002 §9,
//! RFC-003 §1, and RFC-004 §2–§3.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(any(test, feature = "client", feature = "resource-as", feature = "idp"))]
use base64::Engine as _;
#[cfg(any(test, feature = "client", feature = "resource-as", feature = "idp"))]
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};

use crate::claims::{Audience, Issuer, NumericDate};
use crate::error::Error;
#[cfg(any(test, feature = "resource-as", feature = "idp"))]
use crate::form::{Form, header_values};
use crate::jose::{
    AlgorithmPolicy, ExpectedTyp, JwkSet, JwsSigner, ParseLimits, UnverifiedJws, sign_jws, verify,
};
use crate::replay::{ReplayNamespace, ReplayOutcome, ReplayStore};
use crate::secret::{ClientAssertion, ClientSecret};

/// `client_assertion_type` for JWT client assertions (RFC 7523 §2.2).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How long a client assertion built by this crate is valid.
const CLIENT_ASSERTION_LIFETIME: Duration = Duration::from_secs(60);

/// 128 random bits from the thread RNG (seeded from the OS), base64url.
pub(crate) fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    crate::jose::b64url_encode(&bytes)
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// The client's credentials at one authorization server (RFC-003 §1).
#[derive(Clone)]
pub enum ClientAuth {
    /// `client_secret_basic` (RFC 6749 §2.3.1).
    ClientSecretBasic {
        client_id: String,
        secret: ClientSecret,
    },
    /// `client_secret_post` (RFC 6749 §2.3.1).
    ClientSecretPost {
        client_id: String,
        secret: ClientSecret,
    },
    /// `private_key_jwt` (RFC 7523 §2.2, RFC 10070).
    PrivateKeyJwt {
        client_id: String,
        signer: Arc<dyn JwsSigner>,
    },
    /// `tls_client_auth` / `self_signed_tls_client_auth` (RFC 8705 §2). The
    /// TLS client certificate is the caller's
    /// [`HttpClient`](crate::http::HttpClient)'s job; the library sends
    /// `client_id`.
    TlsClientAuth { client_id: String },
}

impl ClientAuth {
    /// The client identifier at this server.
    pub fn client_id(&self) -> &str {
        match self {
            Self::ClientSecretBasic { client_id, .. }
            | Self::ClientSecretPost { client_id, .. }
            | Self::PrivateKeyJwt { client_id, .. }
            | Self::TlsClientAuth { client_id } => client_id,
        }
    }

    #[cfg(any(test, feature = "client"))]
    /// Add the credentials to a token request. `server` is the issuer
    /// identifier of the authorization server being called; it becomes the
    /// sole `aud` of a client assertion.
    pub(crate) async fn apply(
        &self,
        server: &Issuer,
        form: &mut Vec<(String, String)>,
        headers: &mut Vec<(String, String)>,
        now: SystemTime,
    ) -> Result<(), Error> {
        match self {
            Self::ClientSecretBasic { client_id, secret } => {
                // RFC 6749 §2.3.1: both parts are form-urlencoded first.
                let encode = |part: &str| -> String {
                    url::form_urlencoded::byte_serialize(part.as_bytes()).collect()
                };
                let credentials =
                    format!("{}:{}", encode(client_id), encode(secret.expose_secret()));
                headers.push((
                    "Authorization".to_owned(),
                    format!("Basic {}", STANDARD.encode(credentials.as_bytes())),
                ));
            }
            Self::ClientSecretPost { client_id, secret } => {
                form.push(("client_id".to_owned(), client_id.clone()));
                form.push((
                    "client_secret".to_owned(),
                    secret.expose_secret().to_owned(),
                ));
            }
            Self::PrivateKeyJwt { client_id, signer } => {
                let assertion =
                    build_client_assertion(signer.as_ref(), client_id, server, now).await?;
                form.push((
                    "client_assertion_type".to_owned(),
                    CLIENT_ASSERTION_TYPE_JWT_BEARER.to_owned(),
                ));
                form.push((
                    "client_assertion".to_owned(),
                    assertion.expose_secret().to_owned(),
                ));
            }
            Self::TlsClientAuth { client_id } => {
                form.push(("client_id".to_owned(), client_id.clone()));
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let method = match self {
            Self::ClientSecretBasic { .. } => "ClientSecretBasic",
            Self::ClientSecretPost { .. } => "ClientSecretPost",
            Self::PrivateKeyJwt { .. } => "PrivateKeyJwt",
            Self::TlsClientAuth { .. } => "TlsClientAuth",
        };
        f.debug_struct(method)
            .field("client_id", &self.client_id())
            .finish_non_exhaustive()
    }
}

/// Build a `private_key_jwt` client assertion (RFC-002 §9).
///
/// `iss` = `sub` = `client_id`; `aud` is the server's issuer identifier as
/// the sole value (RFC 10070: the token endpoint URL MUST NOT be used); the
/// header `typ` is `client-authentication+jwt`; `jti` is 128 random bits;
/// the assertion is valid for 60 seconds.
pub async fn build_client_assertion(
    signer: &dyn JwsSigner,
    client_id: &str,
    server: &Issuer,
    now: SystemTime,
) -> Result<ClientAssertion, Error> {
    let iat = NumericDate::from_system_time(now)?;
    let exp = NumericDate::from_system_time(
        now.checked_add(CLIENT_ASSERTION_LIFETIME)
            .ok_or(Error::TimeOutOfRange)?,
    )?;
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": server.as_str(),
        "jti": random_id(),
        "iat": iat,
        "exp": exp,
    });
    let token = sign_jws(
        signer,
        Some("client-authentication+jwt"),
        std::collections::BTreeMap::new(),
        &claims,
    )
    .await?;
    Ok(ClientAssertion::new(token))
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// A client authentication method (RFC 7591 `token_endpoint_auth_method`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
    TlsClientAuth,
}

impl ClientAuthMethod {
    /// The registered method name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::TlsClientAuth => "tls_client_auth",
        }
    }
}

/// Client credentials as presented on a token request: extracted, not
/// verified. Secrets live in the caller's store, so the caller verifies them
/// and reports the result as a [`ClientIdentity`].
#[derive(Debug, Clone)]
pub enum ClientCredentials {
    /// `Authorization: Basic`.
    Basic {
        client_id: String,
        secret: ClientSecret,
    },
    /// `client_id` and `client_secret` in the form.
    Post {
        client_id: String,
        secret: ClientSecret,
    },
    /// A JWT client assertion. Verify it with [`verify_client_assertion`].
    Assertion { assertion: ClientAssertion },
    /// A `client_id` together with a TLS client certificate (RFC 8705 §2).
    /// Whether that certificate authenticates this client is the caller's
    /// check against the client's registered certificate metadata.
    TlsClientAuth { client_id: String },
    /// No credentials.
    None { client_id: Option<String> },
}

impl ClientCredentials {
    /// The method the credentials use, or `None` if there are none.
    pub fn method(&self) -> Option<ClientAuthMethod> {
        match self {
            Self::Basic { .. } => Some(ClientAuthMethod::ClientSecretBasic),
            Self::Post { .. } => Some(ClientAuthMethod::ClientSecretPost),
            Self::Assertion { .. } => Some(ClientAuthMethod::PrivateKeyJwt),
            Self::TlsClientAuth { .. } => Some(ClientAuthMethod::TlsClientAuth),
            Self::None { .. } => None,
        }
    }
}

#[cfg(any(test, feature = "resource-as", feature = "idp"))]
/// Why credentials could not be extracted from a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialsError {
    /// More than one authentication method (RFC 6749 §2.3).
    MultipleMethods,
    /// A credential parameter appeared twice.
    Repeated,
    /// Credentials are present but unusable.
    Malformed,
}

#[cfg(any(test, feature = "resource-as", feature = "idp"))]
impl ClientCredentials {
    pub(crate) fn extract(
        form: &Form,
        headers: &[(String, String)],
        tls_client_cert_presented: bool,
    ) -> Result<Self, CredentialsError> {
        let one = |name: &'static str| {
            form.one(name)
                .map_err(|_repeated| CredentialsError::Repeated)
        };
        let client_id = one("client_id")?;
        let client_secret = one("client_secret")?;
        let assertion = one("client_assertion")?;
        let assertion_type = one("client_assertion_type")?;

        let authorization = header_values(headers, "authorization");
        let basic = match authorization.as_slice() {
            [] => None,
            [value] => parse_basic(value)?,
            _ => return Err(CredentialsError::Malformed),
        };

        let methods = [
            basic.is_some(),
            client_secret.is_some(),
            assertion.is_some() || assertion_type.is_some(),
        ]
        .iter()
        .filter(|present| **present)
        .count();
        if methods > 1 {
            return Err(CredentialsError::MultipleMethods);
        }

        if let Some((basic_id, secret)) = basic {
            // A client_id in the body alongside Basic must name the same client.
            if client_id.is_some_and(|form_id| form_id != basic_id) {
                return Err(CredentialsError::Malformed);
            }
            return Ok(Self::Basic {
                client_id: basic_id,
                secret,
            });
        }
        if let Some(secret) = client_secret {
            let client_id = client_id.ok_or(CredentialsError::Malformed)?;
            return Ok(Self::Post {
                client_id: client_id.to_owned(),
                secret: ClientSecret::new(secret),
            });
        }
        if assertion.is_some() || assertion_type.is_some() {
            let (Some(assertion), Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)) =
                (assertion, assertion_type)
            else {
                return Err(CredentialsError::Malformed);
            };
            return Ok(Self::Assertion {
                assertion: ClientAssertion::new(assertion),
            });
        }
        match client_id {
            Some(client_id) if tls_client_cert_presented => Ok(Self::TlsClientAuth {
                client_id: client_id.to_owned(),
            }),
            other => Ok(Self::None {
                client_id: other.map(str::to_owned),
            }),
        }
    }
}

#[cfg(any(test, feature = "resource-as", feature = "idp"))]
/// Parse an `Authorization` header. `Ok(None)` for a scheme other than Basic.
fn parse_basic(value: &str) -> Result<Option<(String, ClientSecret)>, CredentialsError> {
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let decoded = STANDARD
        .decode(encoded.trim().as_bytes())
        .map_err(|_source| CredentialsError::Malformed)?;
    let decoded = String::from_utf8(decoded).map_err(|_source| CredentialsError::Malformed)?;
    let (client_id, secret) = decoded.split_once(':').ok_or(CredentialsError::Malformed)?;
    // RFC 6749 §2.3.1: each part is form-urlencoded.
    let decode = |part: &str| -> Option<String> {
        url::form_urlencoded::parse(part.as_bytes())
            .next()
            .map(|(name, _)| name.into_owned())
    };
    let client_id = decode(client_id).ok_or(CredentialsError::Malformed)?;
    let secret = decode(secret).unwrap_or_default();
    Ok(Some((client_id, ClientSecret::new(secret))))
}

/// Who is calling the token endpoint, as established by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdentity {
    /// The client authenticated with `method`.
    Authenticated {
        client_id: String,
        method: ClientAuthMethod,
    },
    /// The client did not authenticate. `client_id` is whatever the request
    /// claimed; it proves nothing.
    Unauthenticated { client_id: Option<String> },
}

impl ClientIdentity {
    /// The authenticated client's identifier, if the client authenticated.
    pub fn authenticated_client_id(&self) -> Option<&str> {
        match self {
            Self::Authenticated { client_id, .. } => Some(client_id),
            Self::Unauthenticated { .. } => None,
        }
    }
}

/// Server-side limits on client assertions.
#[derive(Debug, Clone)]
pub struct ClientAssertionPolicy {
    /// Upper bound on `exp - iat`, and on how far ahead `exp` may be when
    /// there is no `iat`. Default 5 minutes.
    pub max_lifetime: Duration,
    /// Profile-defined `typ` values accepted in addition to
    /// `client-authentication+jwt` and no `typ` at all.
    pub also_accept_typ: Vec<String>,
}

impl Default for ClientAssertionPolicy {
    fn default() -> Self {
        Self {
            max_lifetime: Duration::from_mins(5),
            also_accept_typ: Vec::new(),
        }
    }
}

/// The `iss` of a client assertion, read without verifying anything.
///
/// A server needs the claimed client identifier before it can look up that
/// client's keys. The value is untrusted until [`verify_client_assertion`]
/// succeeds for it.
pub fn client_assertion_issuer_unverified(assertion: &ClientAssertion) -> Result<String, Error> {
    let jws = UnverifiedJws::parse(assertion.expose_secret(), &ParseLimits::default())?;
    let claims: Map<String, Value> = serde_json::from_slice(jws.payload_unverified())
        .map_err(|source| Error::MalformedClaims(source.to_string()))?;
    match claims.get("iss") {
        Some(Value::String(iss)) => Ok(iss.clone()),
        _ => Err(Error::MissingClaim { name: "iss" }),
    }
}

/// What a client assertion is verified against.
#[derive(Debug, Clone, Copy)]
pub struct ClientAssertionContext<'a> {
    /// The client the assertion must authenticate.
    pub client_id: &'a str,
    /// This server's own issuer identifier: the only accepted `aud`.
    pub server: &'a Issuer,
    /// The client's registered JWK Set.
    pub keys: &'a JwkSet,
    pub algorithms: &'a AlgorithmPolicy,
    pub policy: &'a ClientAssertionPolicy,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// Verify a `private_key_jwt` client assertion (RFC-002 §9).
///
/// Checks, in order: `typ`, signature against the client's keys,
/// `iss` = `sub` = `client_id`, `aud` is this server's issuer identifier as
/// the sole value (RFC 10070; a token endpoint URL is rejected), the time
/// window, and finally `jti` replay.
pub async fn verify_client_assertion(
    assertion: &ClientAssertion,
    context: ClientAssertionContext<'_>,
    replay: &dyn ReplayStore,
) -> Result<(), Error> {
    let ClientAssertionContext {
        client_id,
        server,
        keys,
        algorithms,
        policy,
        now,
        clock_skew,
    } = context;
    let invalid = |reason: &'static str| Error::InvalidClientAssertion { reason };

    let jws = UnverifiedJws::parse(assertion.expose_secret(), &ParseLimits::default())?;
    let verified = verify::<Map<String, Value>>(
        &jws,
        ExpectedTyp::ClientAssertion {
            also_accept: &policy.also_accept_typ,
        },
        keys,
        algorithms,
    )?;
    let claims = verified.claims();

    let string_claim = |name: &str| claims.get(name).and_then(Value::as_str);
    if string_claim("iss") != Some(client_id) || string_claim("sub") != Some(client_id) {
        return Err(invalid("iss and sub must both be the client_id"));
    }
    let audience = claims
        .get("aud")
        .cloned()
        .and_then(|aud| serde_json::from_value::<Audience>(aud).ok())
        .ok_or(invalid("aud is missing or malformed"))?;
    if audience.sole() != Some(server.as_str()) {
        return Err(invalid(
            "aud must be the authorization server issuer identifier as its sole value",
        ));
    }

    let exp = claims
        .get("exp")
        .and_then(NumericDate::from_json)
        .ok_or(invalid("exp is missing or malformed"))?
        .to_system_time()?;
    let earliest = now.checked_sub(clock_skew).ok_or(Error::TimeOutOfRange)?;
    let latest = now.checked_add(clock_skew).ok_or(Error::TimeOutOfRange)?;
    if exp <= earliest {
        return Err(Error::Expired);
    }
    let lifetime_start = match claims.get("iat") {
        None => now,
        Some(iat) => {
            let iat = NumericDate::from_json(iat)
                .ok_or(invalid("iat is malformed"))?
                .to_system_time()?;
            if iat > latest {
                return Err(Error::NotYetValid);
            }
            iat
        }
    };
    if let Some(nbf) = claims.get("nbf") {
        let nbf = NumericDate::from_json(nbf)
            .ok_or(invalid("nbf is malformed"))?
            .to_system_time()?;
        if nbf > latest {
            return Err(Error::NotYetValid);
        }
    }
    let longest = lifetime_start
        .checked_add(policy.max_lifetime)
        .and_then(|end| end.checked_add(clock_skew))
        .ok_or(Error::TimeOutOfRange)?;
    if exp > longest {
        return Err(invalid("lifetime exceeds the maximum"));
    }

    // Last, so a forged or stale assertion never reaches the store.
    let jti = string_claim("jti").ok_or(invalid("jti is missing"))?;
    let keep_until = exp.checked_add(clock_skew).ok_or(Error::TimeOutOfRange)?;
    match replay
        .check_and_insert(
            ReplayNamespace::ClientAssertion { client_id },
            jti,
            keep_until,
            now,
        )
        .await
        .map_err(Error::ReplayStore)?
    {
        ReplayOutcome::Fresh => Ok(()),
        ReplayOutcome::Replayed => Err(Error::Replayed {
            what: "client assertion",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::SignatureAlgorithm;
    use crate::replay::InMemoryReplayStore;
    use crate::test_support::{jwks_of, now, other_rsa_key, p256_key, rsa_key, sign};

    const CLIENT: &str = "client-1";

    fn server() -> Issuer {
        Issuer::new("https://as.example")
    }

    struct Fixture {
        keys: JwkSet,
        algorithms: AlgorithmPolicy,
        policy: ClientAssertionPolicy,
        server: Issuer,
        replay: InMemoryReplayStore,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                keys: jwks_of(&[&p256_key()]),
                algorithms: AlgorithmPolicy::only(&[SignatureAlgorithm::Es256]),
                policy: ClientAssertionPolicy::default(),
                server: server(),
                replay: InMemoryReplayStore::new(64),
            }
        }

        async fn verify(&self, assertion: &str) -> Result<(), Error> {
            self.verify_at(assertion, now()).await
        }

        async fn verify_at(&self, assertion: &str, at: SystemTime) -> Result<(), Error> {
            verify_client_assertion(
                &ClientAssertion::new(assertion),
                ClientAssertionContext {
                    client_id: CLIENT,
                    server: &self.server,
                    keys: &self.keys,
                    algorithms: &self.algorithms,
                    policy: &self.policy,
                    now: at,
                    clock_skew: Duration::from_secs(30),
                },
                &self.replay,
            )
            .await
        }
    }

    fn claims(overrides: Value) -> Value {
        let secs = crate::test_support::NOW_SECS;
        let mut base = json!({
            "iss": CLIENT,
            "sub": CLIENT,
            "aud": "https://as.example",
            "jti": random_id(),
            "iat": secs,
            "exp": secs + 60,
        });
        for (name, value) in overrides.as_object().unwrap() {
            if value.is_null() {
                base.as_object_mut().unwrap().remove(name);
            } else {
                base.as_object_mut()
                    .unwrap()
                    .insert(name.clone(), value.clone());
            }
        }
        base
    }

    async fn signed(overrides: Value) -> String {
        sign(
            &p256_key(),
            Some("client-authentication+jwt"),
            &claims(overrides),
        )
        .await
    }

    #[tokio::test]
    async fn built_assertion_verifies_and_has_the_rfc10070_shape() {
        let fixture = Fixture::new();
        let key = p256_key();
        let assertion = build_client_assertion(&key, CLIENT, &server(), now())
            .await
            .unwrap();
        assert_eq!(
            crate::jose::peek_typ(assertion.expose_secret()).as_deref(),
            Some("client-authentication+jwt")
        );
        assert_eq!(
            client_assertion_issuer_unverified(&assertion).unwrap(),
            CLIENT
        );
        fixture.verify(assertion.expose_secret()).await.unwrap();

        let jws = UnverifiedJws::parse(assertion.expose_secret(), &ParseLimits::default()).unwrap();
        let payload: Value = serde_json::from_slice(jws.payload_unverified()).unwrap();
        assert_eq!(payload["aud"], "https://as.example", "aud is a sole string");
        assert_eq!(payload["iss"], payload["sub"]);
        assert_eq!(
            payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(),
            60
        );
        assert_eq!(
            crate::jose::b64url_decode(payload["jti"].as_str().unwrap())
                .unwrap()
                .len(),
            16
        );
    }

    #[tokio::test]
    async fn replayed_assertion_is_rejected() {
        let fixture = Fixture::new();
        let assertion = signed(json!({})).await;
        fixture.verify(&assertion).await.unwrap();
        assert!(matches!(
            fixture.verify(&assertion).await.unwrap_err(),
            Error::Replayed { .. }
        ));
    }

    #[tokio::test]
    async fn token_endpoint_url_is_not_an_acceptable_audience() {
        let fixture = Fixture::new();
        for aud in [
            json!("https://as.example/token"),
            json!(["https://as.example", "https://as.example/token"]),
            json!("https://as.example/"),
            json!([]),
            json!(7),
        ] {
            let err = fixture
                .verify(&signed(json!({ "aud": aud })).await)
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::InvalidClientAssertion { .. }),
                "{err:?}"
            );
        }
        // A one-element array of the issuer is still a sole value.
        fixture
            .verify(&signed(json!({"aud": ["https://as.example"]})).await)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn iss_and_sub_must_be_the_client() {
        let fixture = Fixture::new();
        for overrides in [
            json!({"iss": "other"}),
            json!({"sub": "other"}),
            json!({"iss": null}),
            json!({"sub": null}),
        ] {
            assert!(matches!(
                fixture.verify(&signed(overrides).await).await.unwrap_err(),
                Error::InvalidClientAssertion { .. }
            ));
        }
    }

    #[tokio::test]
    async fn time_window_rules() {
        let fixture = Fixture::new();
        let secs = crate::test_support::NOW_SECS;
        let expired = signed(json!({"iat": secs - 200, "exp": secs - 31})).await;
        assert!(matches!(
            fixture.verify(&expired).await.unwrap_err(),
            Error::Expired
        ));
        // Inside the skew.
        fixture
            .verify(&signed(json!({"iat": secs - 80, "exp": secs - 20})).await)
            .await
            .unwrap();
        let future = signed(json!({"iat": secs + 31, "exp": secs + 90})).await;
        assert!(matches!(
            fixture.verify(&future).await.unwrap_err(),
            Error::NotYetValid
        ));
        let nbf = signed(json!({"nbf": secs + 31})).await;
        assert!(matches!(
            fixture.verify(&nbf).await.unwrap_err(),
            Error::NotYetValid
        ));
        let long = signed(json!({"exp": secs + 600})).await;
        assert!(matches!(
            fixture.verify(&long).await.unwrap_err(),
            Error::InvalidClientAssertion { .. }
        ));
        // No iat: exp is bounded from now.
        fixture
            .verify(&signed(json!({"iat": null, "exp": secs + 200})).await)
            .await
            .unwrap();
        let unbounded = signed(json!({"iat": null, "exp": secs + 900})).await;
        fixture.verify(&unbounded).await.unwrap_err();
        let no_exp = signed(json!({"exp": null})).await;
        fixture.verify(&no_exp).await.unwrap_err();
    }

    #[tokio::test]
    async fn jti_is_required_and_failures_do_not_burn_it() {
        let fixture = Fixture::new();
        assert!(
            fixture
                .verify(&signed(json!({"jti": null})).await)
                .await
                .is_err()
        );

        // A rejected assertion must not consume its jti.
        let claims = claims(json!({"jti": "fixed", "aud": "https://wrong.example"}));
        let bad = sign(&p256_key(), None, &claims).await;
        fixture.verify(&bad).await.unwrap_err();
        let good = signed(json!({"jti": "fixed"})).await;
        fixture.verify(&good).await.unwrap();
    }

    #[tokio::test]
    async fn signature_and_typ_are_checked() {
        let fixture = Fixture::new();
        let wrong_key = sign(
            &rsa_key(),
            Some("client-authentication+jwt"),
            &claims(json!({})),
        )
        .await;
        fixture.verify(&wrong_key).await.unwrap_err();
        let _ = other_rsa_key();
        let id_jag_typed = sign(&p256_key(), Some("oauth-id-jag+jwt"), &claims(json!({}))).await;
        assert!(matches!(
            fixture.verify(&id_jag_typed).await.unwrap_err(),
            Error::WrongTyp { .. }
        ));
        let untyped = sign(&p256_key(), None, &claims(json!({}))).await;
        fixture.verify(&untyped).await.unwrap();
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[tokio::test]
    async fn applied_credentials_extract_back() {
        let server = server();
        let basic = ClientAuth::ClientSecretBasic {
            client_id: "id:with colon".to_owned(),
            secret: ClientSecret::new("p@ss word+/="),
        };
        let (mut form, mut hdrs) = (Vec::new(), Vec::new());
        basic
            .apply(&server, &mut form, &mut hdrs, now())
            .await
            .unwrap();
        assert_eq!(form, Vec::new());
        let extracted =
            ClientCredentials::extract(&Form::parse(&crate::form::encode(&form)), &hdrs, false)
                .unwrap();
        let ClientCredentials::Basic { client_id, secret } = extracted else {
            panic!("expected Basic");
        };
        assert_eq!(client_id, "id:with colon");
        assert_eq!(secret.expose_secret(), "p@ss word+/=");

        let post = ClientAuth::ClientSecretPost {
            client_id: "c".to_owned(),
            secret: ClientSecret::new("s"),
        };
        let (mut form, mut hdrs) = (Vec::new(), Vec::new());
        post.apply(&server, &mut form, &mut hdrs, now())
            .await
            .unwrap();
        let extracted =
            ClientCredentials::extract(&Form::parse(&crate::form::encode(&form)), &hdrs, false)
                .unwrap();
        assert_eq!(extracted.method(), Some(ClientAuthMethod::ClientSecretPost));

        let jwt = ClientAuth::PrivateKeyJwt {
            client_id: CLIENT.to_owned(),
            signer: Arc::new(p256_key()),
        };
        let (mut form, mut hdrs) = (Vec::new(), Vec::new());
        jwt.apply(&server, &mut form, &mut hdrs, now())
            .await
            .unwrap();
        let extracted =
            ClientCredentials::extract(&Form::parse(&crate::form::encode(&form)), &hdrs, false)
                .unwrap();
        let ClientCredentials::Assertion { assertion } = extracted else {
            panic!("expected Assertion");
        };
        Fixture::new()
            .verify(assertion.expose_secret())
            .await
            .unwrap();

        let tls = ClientAuth::TlsClientAuth {
            client_id: "c".to_owned(),
        };
        let (mut form, mut hdrs) = (Vec::new(), Vec::new());
        tls.apply(&server, &mut form, &mut hdrs, now())
            .await
            .unwrap();
        let body = crate::form::encode(&form);
        assert!(matches!(
            ClientCredentials::extract(&Form::parse(&body), &hdrs, true).unwrap(),
            ClientCredentials::TlsClientAuth { .. }
        ));
        assert!(matches!(
            ClientCredentials::extract(&Form::parse(&body), &hdrs, false).unwrap(),
            ClientCredentials::None { client_id: Some(_) }
        ));
    }

    #[test]
    fn extraction_rejects_multiple_methods_and_malformed_input() {
        let basic = headers(&[("Authorization", "Basic Yzpz")]);
        assert_eq!(
            ClientCredentials::extract(&Form::parse(b"client_id=c&client_secret=s"), &basic, false)
                .unwrap_err(),
            CredentialsError::MultipleMethods
        );
        assert_eq!(
            ClientCredentials::extract(
                &Form::parse(b"client_secret=s&client_assertion=a&client_assertion_type=x"),
                &[],
                false
            )
            .unwrap_err(),
            CredentialsError::MultipleMethods
        );
        assert_eq!(
            ClientCredentials::extract(&Form::parse(b"client_id=other"), &basic, false)
                .unwrap_err(),
            CredentialsError::Malformed
        );
        assert_eq!(
            ClientCredentials::extract(&Form::parse(b"client_secret=s"), &[], false).unwrap_err(),
            CredentialsError::Malformed
        );
        assert_eq!(
            ClientCredentials::extract(
                &Form::parse(b"client_assertion=a&client_assertion_type=urn:wrong"),
                &[],
                false
            )
            .unwrap_err(),
            CredentialsError::Malformed
        );
        assert_eq!(
            ClientCredentials::extract(&Form::parse(b"client_id=a&client_id=b"), &[], false)
                .unwrap_err(),
            CredentialsError::Repeated
        );
        assert_eq!(
            ClientCredentials::extract(
                &Form::parse(b""),
                &headers(&[("Authorization", "Basic !!!")]),
                false
            )
            .unwrap_err(),
            CredentialsError::Malformed
        );
        // A non-Basic Authorization header (e.g. DPoP) is not client credentials.
        assert!(matches!(
            ClientCredentials::extract(
                &Form::parse(b""),
                &headers(&[("Authorization", "Bearer abc")]),
                false
            )
            .unwrap(),
            ClientCredentials::None { client_id: None }
        ));
    }

    #[test]
    fn debug_does_not_print_secrets() {
        let auth = ClientAuth::ClientSecretPost {
            client_id: "c".to_owned(),
            secret: ClientSecret::new("hunter2"),
        };
        assert!(!format!("{auth:?}").contains("hunter2"));
    }
}
