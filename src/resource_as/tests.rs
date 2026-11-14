//! Unit tests for the Resource AS: request parsing (§2), every validation
//! rule and its order (§4), the decision-builder invariants (§6), responses
//! (§7), `JtiPolicy` (§8), and metadata (§10).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use serde_json::{Value, json};
use url::Url;

use super::*;
use crate::claims::{AuthorizationDetails, Confirmation, Issuer, Scope};
use crate::dpop::{DpopKey, DpopNonce};
use crate::error::Error;
use crate::form::encode;
use crate::jose::{JwkSet, PrivateKey, SignatureAlgorithm};
use crate::metadata::Support;
use crate::mtls::certificate_thumbprint;
use crate::oauth_error::OAuthErrorCode;
use crate::replay::{InMemoryReplayStore, ReplayFuture, ReplayNamespace, ReplayStore};
use crate::secret::AccessToken;
use crate::test_support::{
    NOW_SECS, jwks_of, now, other_rsa_key, p256_key, p384_key, rsa_key, sign, sign_raw,
};

const AS: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const IDP: &str = "https://idp.example";
const CLIENT: &str = "client-at-as";
const API: &str = "https://api.example/";
const FILES: &str = "https://files.example/";
const TENANT: &str = "tenant-a";
const TYP: &str = "oauth-id-jag+jwt";
const BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const DPOP: &str = "urn:ietf:params:oauth:grant-type:jwt-dpop";
const SKEW: Duration = Duration::from_secs(30);
const EXP: u64 = NOW_SECS + 300;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct Registry {
    governed: Vec<&'static str>,
    constrained: Vec<&'static str>,
    foreign_clients: Vec<&'static str>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            governed: vec![API, FILES],
            constrained: Vec::new(),
            foreign_clients: Vec::new(),
        }
    }
}

impl ResourceRegistry for Registry {
    fn governs(&self, resource: &str, tenant: &RecipientTenant) -> bool {
        tenant.as_str() == TENANT && self.governed.contains(&resource)
    }

    fn requires_sender_constraint(&self, resource: &str, _tenant: &RecipientTenant) -> bool {
        self.constrained.contains(&resource)
    }

    fn client_belongs_to_tenant(&self, client_id: &str, _tenant: &RecipientTenant) -> bool {
        !self.foreign_clients.contains(&client_id)
    }
}

/// Counts every call and delegates to an in-memory store.
struct CountingStore {
    calls: AtomicUsize,
    inner: InMemoryReplayStore,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            inner: InMemoryReplayStore::new(64),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ReplayStore for CountingStore {
    fn check_and_insert<'a>(
        &'a self,
        ns: ReplayNamespace<'a>,
        id: &'a str,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> ReplayFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.check_and_insert(ns, id, expires_at, now)
    }
}

struct BrokenStore;

impl ReplayStore for BrokenStore {
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

struct FixedNonce;

impl DpopNonce for FixedNonce {
    fn current(&self, _now: SystemTime) -> String {
        "nonce-2".to_owned()
    }

    fn accept(&self, nonce: &str, _now: SystemTime) -> bool {
        nonce == "nonce-2"
    }
}

/// Maps `iss` + `tenant` to a recipient tenant and records `aud_tenant`.
struct Resolver;

impl TenantResolver for Resolver {
    fn resolve(&self, issuer: &Issuer, tenant: &str, aud_tenant: Option<&str>) -> TenantDecision {
        assert_eq!(issuer.as_str(), IDP);
        match (tenant, aud_tenant) {
            ("acme", None | Some("a")) => TenantDecision::Trusted(RecipientTenant::new(TENANT)),
            ("acme", Some(other)) => TenantDecision::Trusted(RecipientTenant::new(other)),
            ("shared", _) => TenantDecision::Ambiguous,
            _ => TenantDecision::Untrusted,
        }
    }
}

fn url() -> Url {
    Url::parse(TOKEN_ENDPOINT).unwrap()
}

fn config(jti_policy: JtiPolicy) -> ResourceAsConfig {
    let mut config = ResourceAsConfig::new(Issuer::new(AS), url(), jti_policy);
    config.trusted_issuers = vec![TrustedIssuer::single_tenant(
        Issuer::new(IDP),
        RecipientTenant::new(TENANT),
    )];
    config
}

fn claims() -> Value {
    json!({
        "iss": IDP,
        "sub": "user-1",
        "aud": AS,
        "client_id": CLIENT,
        "jti": "jti-1",
        "exp": EXP,
        "iat": NOW_SECS,
        "resource": API,
        "scope": "read write"
    })
}

fn with(mut claims: Value, name: &str, value: Value) -> Value {
    claims
        .as_object_mut()
        .unwrap()
        .insert(name.to_owned(), value);
    claims
}

fn without(mut claims: Value, name: &str) -> Value {
    claims.as_object_mut().unwrap().remove(name);
    claims
}

fn authenticated() -> ClientIdentity {
    ClientIdentity::Authenticated {
        client_id: CLIENT.to_owned(),
        method: ClientAuthMethod::ClientSecretPost,
    }
}

fn unauthenticated() -> ClientIdentity {
    ClientIdentity::Unauthenticated { client_id: None }
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    encode(&pairs)
}

fn dpop_header(proof: String) -> Vec<(String, String)> {
    vec![("DPoP".to_owned(), proof)]
}

async fn proof(key: &DpopKey, nonce: Option<&str>) -> Vec<(String, String)> {
    dpop_header(
        key.proof(&http::Method::POST, &url(), nonce, now())
            .await
            .unwrap(),
    )
}

fn dpop_key() -> DpopKey {
    DpopKey::generate(SignatureAlgorithm::Es256).unwrap()
}

fn certificate() -> Vec<u8> {
    vec![0x30, 0x03, 0x01, 0x02, 0x03]
}

/// One token request against one configuration.
struct Case {
    config: ResourceAsConfig,
    claims: Value,
    /// A ready-made assertion, instead of signing `claims`.
    assertion: Option<String>,
    signer: PrivateKey,
    grant_type: &'static str,
    scope: Option<&'static str>,
    client: ClientIdentity,
    headers: Vec<(String, String)>,
    certificate: Option<Vec<u8>>,
    registry: Registry,
    keys: HashMap<Issuer, JwkSet>,
}

impl Case {
    fn new() -> Self {
        Self {
            config: config(JtiPolicy::AllowReuse),
            claims: claims(),
            assertion: None,
            signer: p256_key(),
            grant_type: BEARER,
            scope: None,
            client: authenticated(),
            headers: Vec::new(),
            certificate: None,
            registry: Registry::default(),
            keys: HashMap::from([(Issuer::new(IDP), jwks_of(&[&p256_key()]))]),
        }
    }

    fn claims(claims: Value) -> Self {
        Self {
            claims,
            ..Self::new()
        }
    }

    async fn request(&self) -> TokenRequest {
        let assertion = match &self.assertion {
            Some(assertion) => assertion.clone(),
            None => sign(&self.signer, Some(TYP), &self.claims).await,
        };
        let mut pairs = vec![
            ("grant_type", self.grant_type),
            ("assertion", assertion.as_str()),
        ];
        if let Some(scope) = self.scope {
            pairs.push(("scope", scope));
        }
        TokenRequest::parse(&form(&pairs), &self.headers, self.certificate.as_deref()).unwrap()
    }

    async fn run_with(
        &self,
        replay: Option<&dyn ReplayStore>,
    ) -> Result<VerifiedGrant, TokenError> {
        let request = self.request().await;
        ResourceAs::new(self.config.clone())
            .unwrap()
            .validate(
                &request,
                &self.client,
                &self.keys,
                &self.registry,
                replay,
                now(),
                SKEW,
            )
            .await
    }

    async fn run(&self) -> Result<VerifiedGrant, TokenError> {
        self.run_with(None).await
    }

    async fn accept(&self) -> VerifiedGrant {
        self.run().await.unwrap()
    }

    /// The request is rejected for exactly `reason`, with `code` on the wire.
    async fn rejects(&self, code: OAuthErrorCode, reason: RejectReason) -> TokenError {
        let error = self.run().await.unwrap_err();
        assert_rejected(&error, &code, reason);
        error
    }

    async fn invalid_grant(&self, reason: RejectReason) -> TokenError {
        self.rejects(OAuthErrorCode::InvalidGrant, reason).await
    }
}

fn body(response: &crate::http::HttpResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

fn assert_rejected(error: &TokenError, code: &OAuthErrorCode, reason: RejectReason) {
    assert_eq!(error.reason(), Some(&reason), "{error}");
    assert_eq!(error.code(), code, "{error}");
    let response = error.to_response();
    let body = body(&response);
    assert_eq!(body["error"], code.as_str());
    // The wire never says more than the code does (draft §10).
    assert_eq!(body["error_description"], code.default_description());
    assert_eq!(body.as_object().unwrap().len(), 2);
}

fn parse_error(
    pairs: &[(&str, &str)],
    headers: &[(String, String)],
    certificate: Option<&[u8]>,
) -> TokenError {
    TokenRequest::parse(&form(pairs), headers, certificate).unwrap_err()
}

// ---------------------------------------------------------------------------
// §2 Request parsing
// ---------------------------------------------------------------------------

#[test]
fn parses_a_jwt_bearer_request() {
    let request = TokenRequest::parse(
        &form(&[
            ("grant_type", BEARER),
            ("assertion", "a.b.c"),
            ("scope", "read write"),
            ("client_id", CLIENT),
            ("client_secret", "s3cret"),
        ]),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(request.grant_type(), AssertionGrantType::JwtBearer);
    assert_eq!(request.requested_scope().unwrap().as_str(), "read write");
    assert!(!request.has_dpop_proof());
    assert_eq!(request.certificate_thumbprint(), None);
    match request.client_credentials() {
        ClientCredentials::Post { client_id, secret } => {
            assert_eq!(client_id, CLIENT);
            assert_eq!(secret.expose_secret(), "s3cret");
        }
        other => panic!("unexpected credentials: {other:?}"),
    }
    // The assertion is a secret: Debug never prints it.
    assert!(!format!("{request:?}").contains("a.b.c"));
}

#[test]
fn parses_a_jwt_dpop_request_with_proof_and_certificate() {
    let request = TokenRequest::parse(
        &form(&[
            ("grant_type", DPOP),
            ("assertion", "a.b.c"),
            ("client_id", CLIENT),
        ]),
        &dpop_header("proof".to_owned()),
        Some(&certificate()),
    )
    .unwrap();
    assert_eq!(request.grant_type(), AssertionGrantType::JwtDpop);
    assert!(request.has_dpop_proof());
    assert_eq!(
        request.certificate_thumbprint(),
        Some(certificate_thumbprint(&certificate()).unwrap().as_str())
    );
    assert!(matches!(
        request.client_credentials(),
        ClientCredentials::TlsClientAuth { client_id } if client_id == CLIENT
    ));
    assert_eq!(request.requested_scope(), None);
}

#[test]
fn extracts_basic_credentials_without_verifying_them() {
    // "client-at-as:s3cret"
    let headers = vec![(
        "Authorization".to_owned(),
        "Basic Y2xpZW50LWF0LWFzOnMzY3JldA==".to_owned(),
    )];
    let request = TokenRequest::parse(
        &form(&[("grant_type", BEARER), ("assertion", "a.b.c")]),
        &headers,
        None,
    )
    .unwrap();
    assert!(matches!(
        request.client_credentials(),
        ClientCredentials::Basic { client_id, .. } if client_id == CLIENT
    ));
}

#[test]
fn other_grant_types_are_unsupported_grant_type() {
    for grant_type in [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ] {
        let error = parse_error(
            &[("grant_type", grant_type), ("assertion", "a.b.c")],
            &[],
            None,
        );
        assert_rejected(
            &error,
            &OAuthErrorCode::UnsupportedGrantType,
            RejectReason::UnsupportedGrantType,
        );
    }
}

#[test]
fn missing_and_repeated_parameters_are_invalid_request() {
    let cases: [(&[(&str, &str)], RejectReason); 6] = [
        (&[("assertion", "a.b.c")], RejectReason::MissingGrantType),
        (&[("grant_type", BEARER)], RejectReason::MissingAssertion),
        (
            &[("grant_type", BEARER), ("assertion", "")],
            RejectReason::MissingAssertion,
        ),
        (
            &[
                ("grant_type", BEARER),
                ("assertion", "a.b.c"),
                ("assertion", "d.e.f"),
            ],
            RejectReason::RepeatedParameter { name: "assertion" },
        ),
        (
            &[
                ("grant_type", BEARER),
                ("grant_type", DPOP),
                ("assertion", "a.b.c"),
            ],
            RejectReason::RepeatedParameter { name: "grant_type" },
        ),
        (
            &[
                ("grant_type", BEARER),
                ("assertion", "a.b.c"),
                ("scope", "read"),
                ("scope", "write"),
            ],
            RejectReason::RepeatedParameter { name: "scope" },
        ),
    ];
    for (pairs, reason) in cases {
        let error = parse_error(pairs, &[], None);
        assert_rejected(&error, &OAuthErrorCode::InvalidRequest, reason);
        assert_eq!(error.to_response().status, 400);
    }
}

#[test]
fn a_malformed_scope_is_invalid_scope_and_an_empty_one_is_absent() {
    let error = parse_error(
        &[
            ("grant_type", BEARER),
            ("assertion", "a.b.c"),
            ("scope", "read  write"),
        ],
        &[],
        None,
    );
    assert_rejected(
        &error,
        &OAuthErrorCode::InvalidScope,
        RejectReason::MalformedScope,
    );

    let request = TokenRequest::parse(
        &form(&[
            ("grant_type", BEARER),
            ("assertion", "a.b.c"),
            ("scope", ""),
        ]),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(request.requested_scope(), None);
}

#[test]
fn more_than_one_dpop_header_is_invalid_dpop_proof() {
    let headers = vec![
        ("DPoP".to_owned(), "one".to_owned()),
        ("dpop".to_owned(), "two".to_owned()),
    ];
    let error = parse_error(
        &[("grant_type", DPOP), ("assertion", "a.b.c")],
        &headers,
        None,
    );
    assert_rejected(
        &error,
        &OAuthErrorCode::InvalidDpopProof,
        RejectReason::MultipleDpopProofs,
    );
}

#[test]
fn more_than_one_client_authentication_method_is_invalid_request() {
    let headers = vec![(
        "Authorization".to_owned(),
        "Basic Y2xpZW50LWF0LWFzOnMzY3JldA==".to_owned(),
    )];
    let error = parse_error(
        &[
            ("grant_type", BEARER),
            ("assertion", "a.b.c"),
            ("client_id", CLIENT),
            ("client_secret", "s3cret"),
        ],
        &headers,
        None,
    );
    assert_rejected(
        &error,
        &OAuthErrorCode::InvalidRequest,
        RejectReason::MultipleClientAuthMethods,
    );

    let error = parse_error(
        &[
            ("grant_type", BEARER),
            ("assertion", "a.b.c"),
            ("client_secret", "one"),
            ("client_secret", "two"),
        ],
        &[],
        None,
    );
    assert_eq!(error.code(), &OAuthErrorCode::InvalidRequest);

    let error = parse_error(
        &[
            ("grant_type", BEARER),
            ("assertion", "a.b.c"),
            ("client_secret", "orphan"),
        ],
        &[],
        None,
    );
    assert_rejected(
        &error,
        &OAuthErrorCode::InvalidRequest,
        RejectReason::MalformedClientCredentials,
    );
}

#[test]
fn a_certificate_that_is_not_der_is_a_server_error() {
    let error = parse_error(
        &[("grant_type", BEARER), ("assertion", "a.b.c")],
        &[],
        Some(b"-----BEGIN CERTIFICATE-----"),
    );
    assert_rejected(
        &error,
        &OAuthErrorCode::ServerError,
        RejectReason::InvalidClientCertificate,
    );
    assert_eq!(error.to_response().status, 500);
}

// ---------------------------------------------------------------------------
// Happy paths, one per binding mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bearer_grant_with_an_authenticated_client() {
    let mut case = Case::new();
    case.scope = Some("read");
    let grant = case.accept().await;
    assert_eq!(grant.claims().sub, "user-1");
    assert_eq!(grant.claims().iss.as_str(), IDP);
    assert_eq!(grant.header().typ(), Some(TYP));
    assert_eq!(grant.recipient_tenant().as_str(), TENANT);
    assert_eq!(grant.client(), &authenticated());
    assert_eq!(grant.binding(), None);
    assert_eq!(grant.requested_scope().unwrap().as_str(), "read");
    assert_eq!(grant.saml_subject_key(), None);

    let decision = grant.decide(&case.registry).build().unwrap();
    assert_eq!(decision.token_type(), "Bearer");
    assert_eq!(decision.resources(), [API]);
}

#[tokio::test]
async fn rs256_grants_verify_too() {
    let mut case = Case::new();
    case.signer = rsa_key();
    case.keys = HashMap::from([(Issuer::new(IDP), jwks_of(&[&rsa_key(), &p256_key()]))]);
    case.accept().await;
}

#[tokio::test]
async fn dpop_bound_grant_with_jwt_dpop() {
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    let grant = case.accept().await;
    assert_eq!(
        grant.binding(),
        Some(&AccessTokenBinding::Dpop {
            jkt: key.thumbprint().to_owned()
        })
    );
    let decision = grant.decide(&case.registry).build().unwrap();
    assert_eq!(decision.token_type(), "DPoP");
    assert_eq!(
        decision.binding().unwrap().confirmation(),
        Confirmation::Jkt(key.thumbprint().to_owned())
    );
}

#[tokio::test]
async fn certificate_bound_grant() {
    let thumbprint = certificate_thumbprint(&certificate()).unwrap();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "x5t#S256": thumbprint })));
    case.certificate = Some(certificate());
    let grant = case.accept().await;
    assert_eq!(
        grant.binding(),
        Some(&AccessTokenBinding::Mtls {
            x5t_s256: thumbprint
        })
    );
    // A certificate-bound token is still `Bearer` (RFC 8705 §3).
    assert_eq!(
        grant.decide(&case.registry).build().unwrap().token_type(),
        "Bearer"
    );
}

#[tokio::test]
async fn unauthenticated_client_with_a_sender_constrained_grant() {
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.config.allow_unauthenticated_sender_constrained = true;
    case.client = ClientIdentity::Unauthenticated {
        client_id: Some(CLIENT.to_owned()),
    };
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    let grant = case.accept().await;
    assert!(matches!(
        grant.binding(),
        Some(AccessTokenBinding::Dpop { .. })
    ));
    assert_eq!(grant.client().authenticated_client_id(), None);

    // The certificate-bound variant.
    let thumbprint = certificate_thumbprint(&certificate()).unwrap();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "x5t#S256": thumbprint })));
    case.config.allow_unauthenticated_sender_constrained = true;
    case.client = unauthenticated();
    case.certificate = Some(certificate());
    let grant = case.accept().await;
    assert!(matches!(
        grant.binding(),
        Some(AccessTokenBinding::Mtls { .. })
    ));
}

#[tokio::test]
async fn unbound_grant_with_a_proof_binds_the_access_token_to_the_proof_key() {
    let key = dpop_key();
    let mut case = Case::new();
    case.headers = proof(&key, None).await;
    let grant = case.accept().await;
    assert_eq!(
        grant.binding(),
        Some(&AccessTokenBinding::Dpop {
            jkt: key.thumbprint().to_owned()
        })
    );

    // With a certificate as well, the configured preference picks one.
    case.certificate = Some(certificate());
    case.headers = proof(&key, None).await;
    assert!(matches!(
        case.accept().await.binding(),
        Some(AccessTokenBinding::Dpop { .. })
    ));
    case.config.binding_preference = BindingPreference::Mtls;
    case.headers = proof(&key, None).await;
    assert!(matches!(
        case.accept().await.binding(),
        Some(AccessTokenBinding::Mtls { .. })
    ));
}

// ---------------------------------------------------------------------------
// Preconditions (§3, §8)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_clients_are_refused_unless_allowed() {
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.client = unauthenticated();
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    case.rejects(
        OAuthErrorCode::InvalidClient,
        RejectReason::UnauthenticatedClientNotAllowed,
    )
    .await;
}

// ---------------------------------------------------------------------------
// §4 rule 1: the DPoP proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_1_jwt_dpop_without_a_proof() {
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.grant_type = DPOP;
    case.rejects(
        OAuthErrorCode::InvalidDpopProof,
        RejectReason::DpopProofMissing,
    )
    .await;
}

#[tokio::test]
async fn rule_1_an_invalid_proof() {
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.grant_type = DPOP;

    // Wrong `htu`.
    let elsewhere = Url::parse("https://as.example/other").unwrap();
    case.headers = dpop_header(
        key.proof(&http::Method::POST, &elsewhere, None, now())
            .await
            .unwrap(),
    );
    let error = case
        .rejects(
            OAuthErrorCode::InvalidDpopProof,
            RejectReason::DpopProofInvalid,
        )
        .await;
    assert!(matches!(
        error.error(),
        Some(Error::InvalidDpopProof { .. })
    ));

    // Wrong `htm`.
    case.headers = dpop_header(
        key.proof(&http::Method::GET, &url(), None, now())
            .await
            .unwrap(),
    );
    case.rejects(
        OAuthErrorCode::InvalidDpopProof,
        RejectReason::DpopProofInvalid,
    )
    .await;

    // Not a proof at all. Under jwt-bearer a presented proof must be valid too.
    case.headers = dpop_header("garbage".to_owned());
    case.rejects(
        OAuthErrorCode::InvalidDpopProof,
        RejectReason::DpopProofInvalid,
    )
    .await;
    let mut bearer = Case::new();
    bearer.headers = dpop_header("garbage".to_owned());
    bearer
        .rejects(
            OAuthErrorCode::InvalidDpopProof,
            RejectReason::DpopProofInvalid,
        )
        .await;
}

#[tokio::test]
async fn rule_1_a_missing_or_stale_nonce_is_use_dpop_nonce() {
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.grant_type = DPOP;
    case.config.dpop_nonce = Some(Arc::new(FixedNonce));
    for nonce in [None, Some("nonce-1")] {
        case.headers = proof(&key, nonce).await;
        let error = case
            .rejects(
                OAuthErrorCode::UseDpopNonce,
                RejectReason::DpopNonceRequired,
            )
            .await;
        let response = error.to_response();
        assert_eq!(response.status, 400);
        assert_eq!(response.header("DPoP-Nonce"), Some("nonce-2"));
    }
    case.headers = proof(&key, Some("nonce-2")).await;
    case.accept().await;
}

#[tokio::test]
async fn rule_1_runs_before_the_assertion_is_read() {
    let mut case = Case::new();
    case.assertion = Some("not-a-jws".to_owned());
    case.grant_type = DPOP;
    case.rejects(
        OAuthErrorCode::InvalidDpopProof,
        RejectReason::DpopProofMissing,
    )
    .await;
}

// ---------------------------------------------------------------------------
// §4 rules 2–3: structure and typ
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_2_the_assertion_is_not_a_compact_jws() {
    let mut case = Case::new();
    for assertion in ["not-a-jws", "a.b", "a.b.c.d.e", "!!!.e30.sig"] {
        case.assertion = Some(assertion.to_owned());
        case.invalid_grant(RejectReason::MalformedAssertion).await;
    }

    // Over the size limit.
    let mut case = Case::new();
    case.config.parse_limits.max_len = 64;
    let error = case.invalid_grant(RejectReason::MalformedAssertion).await;
    assert!(matches!(error.error(), Some(Error::TokenTooLong { .. })));
}

#[tokio::test]
async fn rule_3_wrong_or_missing_typ() {
    let mut case = Case::new();
    for typ in [Some("JWT"), Some("at+jwt"), Some("dpop+jwt"), None] {
        case.assertion = Some(sign(&p256_key(), typ, &claims()).await);
        case.invalid_grant(RejectReason::WrongTyp).await;
    }
}

// ---------------------------------------------------------------------------
// §4 rules 4–6: issuer trust and signature
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_4_untrusted_or_unreadable_issuer() {
    for iss in [
        json!("https://evil.example"),
        json!("https://idp.example/"),
        json!(7),
    ] {
        Case::claims(with(claims(), "iss", iss))
            .invalid_grant(RejectReason::UntrustedIssuer)
            .await;
    }
    Case::claims(without(claims(), "iss"))
        .invalid_grant(RejectReason::UntrustedIssuer)
        .await;

    let mut case = Case::new();
    case.assertion = Some(
        sign_raw(
            &p256_key(),
            r#"{"alg":"ES256","typ":"oauth-id-jag+jwt","kid":"p256-1"}"#,
            "[1,2,3]",
        )
        .await,
    );
    case.invalid_grant(RejectReason::UntrustedIssuer).await;
}

#[tokio::test]
async fn rule_4_keys_of_another_trusted_issuer_do_not_verify() {
    // Two trusted issuers. A grant naming one, signed by the other, fails.
    let mut case = Case::new();
    case.config
        .trusted_issuers
        .push(TrustedIssuer::single_tenant(
            Issuer::new("https://idp-b.example"),
            RecipientTenant::new("tenant-b"),
        ));
    case.keys.insert(
        Issuer::new("https://idp-b.example"),
        jwks_of(&[&p384_key(), &rsa_key()]),
    );
    case.signer = rsa_key();
    case.rejects(OAuthErrorCode::InvalidGrant, RejectReason::UnknownKeyId)
        .await;
}

#[tokio::test]
async fn rule_5_self_issued_grants() {
    let mut case = Case::claims(with(claims(), "iss", json!(AS)));
    case.config
        .trusted_issuers
        .push(TrustedIssuer::single_tenant(
            Issuer::new(AS),
            RecipientTenant::new(TENANT),
        ));
    case.keys.insert(Issuer::new(AS), jwks_of(&[&p256_key()]));
    case.invalid_grant(RejectReason::SelfIssued).await;

    case.config.allow_self_issued = true;
    case.accept().await;
}

#[tokio::test]
async fn rule_6_signature() {
    // Another key under the same `kid`.
    let mut case = Case::new();
    case.signer = PrivateKey::generate_p256().with_key_id("p256-1");
    let error = case.invalid_grant(RejectReason::InvalidSignature).await;
    assert!(matches!(error.error(), Some(Error::BadSignature)));

    // A tampered payload under the original signature.
    let mut case = Case::new();
    let token = sign(&p256_key(), Some(TYP), &claims()).await;
    let mut segments = token.split('.');
    let (header, signature) = (segments.next().unwrap(), segments.nth(1).unwrap());
    let payload = crate::jose::b64url_encode(
        serde_json::to_string(&with(claims(), "sub", json!("admin")))
            .unwrap()
            .as_bytes(),
    );
    case.assertion = Some(format!("{header}.{payload}.{signature}"));
    case.invalid_grant(RejectReason::InvalidSignature).await;
}

#[tokio::test]
async fn rule_6_unknown_kid_is_reported_for_a_jwks_refresh() {
    let mut case = Case::new();
    case.signer = other_rsa_key();
    let error = case.invalid_grant(RejectReason::UnknownKeyId).await;
    assert!(matches!(error.error(), Some(Error::UnknownKeyId { kid }) if kid == "rsa-2"));

    // After the refresh the same request verifies.
    case.keys = HashMap::from([(Issuer::new(IDP), jwks_of(&[&p256_key(), &other_rsa_key()]))]);
    case.accept().await;
}

#[tokio::test]
async fn rule_6_algorithm_allow_list_and_missing_keys() {
    // ES384 is not on the default per-issuer allow-list.
    let mut case = Case::new();
    case.signer = p384_key();
    case.keys = HashMap::from([(Issuer::new(IDP), jwks_of(&[&p384_key()]))]);
    case.invalid_grant(RejectReason::DisallowedAlgorithm).await;

    let mut case = Case::new();
    case.keys = HashMap::new();
    case.invalid_grant(RejectReason::NoKeysForIssuer).await;

    // No `kid`, and two keys that could have signed.
    let mut case = Case::new();
    case.keys = HashMap::from([(
        Issuer::new(IDP),
        jwks_of(&[
            &p256_key(),
            &PrivateKey::generate_p256().with_key_id("p256-2"),
        ]),
    )]);
    case.assertion = Some(
        sign_raw(
            &p256_key(),
            r#"{"alg":"ES256","typ":"oauth-id-jag+jwt"}"#,
            &claims().to_string(),
        )
        .await,
    );
    let error = case.invalid_grant(RejectReason::NoUsableKey).await;
    assert!(matches!(error.error(), Some(Error::AmbiguousKey { .. })));
}

// ---------------------------------------------------------------------------
// §4 rules 7–9: claims, audience, time
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_7_required_claims() {
    for name in ["sub", "aud", "client_id", "jti", "exp", "iat"] {
        Case::claims(without(claims(), name))
            .invalid_grant(RejectReason::MissingClaim { name })
            .await;
    }
}

#[tokio::test]
async fn rule_7_claim_shapes() {
    let cases = [
        ("sub", json!(42)),
        ("aud", json!({ "not": "an audience" })),
        ("exp", json!("tomorrow")),
        ("iat", json!(-5)),
        ("scope", json!("read  write")),
        ("resource", json!([])),
        ("cnf", json!("jkt")),
        ("cnf", json!({ "jkt": "a", "x5t#S256": "b" })),
        ("amr", json!("pwd")),
    ];
    for (name, value) in cases {
        let error = Case::claims(with(claims(), name, value))
            .invalid_grant(RejectReason::InvalidClaim { name })
            .await;
        assert!(matches!(error.error(), Some(Error::InvalidClaim { .. })));
    }
}

#[tokio::test]
async fn rule_8_audience() {
    let rejected = [
        // identity-chaining §2.4.2 allows the token endpoint; this profile does not.
        json!(TOKEN_ENDPOINT),
        json!("https://as.example/"),
        json!("https://AS.example"),
        json!("https://other-as.example"),
        json!([AS, "https://other-as.example"]),
        json!([AS, AS]),
        json!([]),
    ];
    for aud in rejected {
        Case::claims(with(claims(), "aud", aud))
            .invalid_grant(RejectReason::AudienceMismatch)
            .await;
    }
    // A one-element array is the sole value.
    Case::claims(with(claims(), "aud", json!([AS])))
        .accept()
        .await;
}

#[tokio::test]
async fn rule_9_time() {
    const EXPIRED: u64 = NOW_SECS - 30;
    const JUST_VALID: u64 = NOW_SECS - 29;
    const ISSUED: u64 = NOW_SECS - 200;
    const FUTURE: u64 = NOW_SECS + 31;
    const EDGE: u64 = NOW_SECS + 30;
    const TOO_LONG: u64 = NOW_SECS + 601;
    const LONGEST: u64 = NOW_SECS + 600;

    // `exp` must be after `now - skew`.
    let old = with(claims(), "iat", json!(ISSUED));
    Case::claims(with(old.clone(), "exp", json!(EXPIRED)))
        .invalid_grant(RejectReason::Expired)
        .await;
    Case::claims(with(old, "exp", json!(JUST_VALID)))
        .accept()
        .await;

    // `iat` and `nbf` may be at most `skew` ahead.
    Case::claims(with(claims(), "iat", json!(FUTURE)))
        .invalid_grant(RejectReason::NotYetValid)
        .await;
    Case::claims(with(claims(), "iat", json!(EDGE)))
        .accept()
        .await;
    Case::claims(with(claims(), "nbf", json!(FUTURE)))
        .invalid_grant(RejectReason::NotYetValid)
        .await;
    Case::claims(with(claims(), "nbf", json!(EDGE)))
        .accept()
        .await;

    // `exp - iat` is bounded (draft §4.4.4).
    Case::claims(with(claims(), "exp", json!(TOO_LONG)))
        .invalid_grant(RejectReason::LifetimeTooLong)
        .await;
    Case::claims(with(claims(), "exp", json!(LONGEST)))
        .accept()
        .await;
    let mut case = Case::new();
    case.config.max_id_jag_lifetime = Duration::from_mins(4);
    case.invalid_grant(RejectReason::LifetimeTooLong).await;

    // `exp` before `iat`, both inside the skew window.
    Case::claims(with(
        with(claims(), "iat", json!(EDGE)),
        "exp",
        json!(NOW_SECS),
    ))
    .invalid_grant(RejectReason::ExpiresBeforeIssued)
    .await;
}

// ---------------------------------------------------------------------------
// §4 rule 10: tenancy
// ---------------------------------------------------------------------------

fn multi_tenant_case(claims: Value) -> Case {
    let mut case = Case::claims(claims);
    case.config.trusted_issuers = vec![TrustedIssuer::multi_tenant(
        Issuer::new(IDP),
        Arc::new(Resolver),
    )];
    case
}

#[tokio::test]
async fn rule_10_single_tenant_uses_the_configured_recipient_tenant() {
    // A `tenant` claim from a single-tenant issuer changes nothing.
    let grant = Case::claims(with(claims(), "tenant", json!("whatever")))
        .accept()
        .await;
    assert_eq!(grant.recipient_tenant(), &RecipientTenant::new(TENANT));
}

#[tokio::test]
async fn rule_10_multi_tenant() {
    let grant = multi_tenant_case(with(claims(), "tenant", json!("acme")))
        .accept()
        .await;
    assert_eq!(grant.recipient_tenant().as_str(), TENANT);
    assert_eq!(grant.claims().tenant.as_deref(), Some("acme"));

    // `aud_tenant` reaches the resolver.
    let both = with(
        with(claims(), "tenant", json!("acme")),
        "aud_tenant",
        json!("a"),
    );
    assert_eq!(
        multi_tenant_case(both)
            .accept()
            .await
            .recipient_tenant()
            .as_str(),
        TENANT
    );

    multi_tenant_case(claims())
        .invalid_grant(RejectReason::MissingTenant)
        .await;
    multi_tenant_case(with(claims(), "tenant", json!("globex")))
        .invalid_grant(RejectReason::UntrustedTenant)
        .await;
    multi_tenant_case(with(claims(), "tenant", json!("shared")))
        .invalid_grant(RejectReason::AmbiguousTenant)
        .await;
}

#[tokio::test]
async fn rule_10_the_recipient_tenant_scopes_the_resource_check() {
    // The resolver sends this grant to a tenant where the API is not governed.
    let other = with(
        with(claims(), "tenant", json!("acme")),
        "aud_tenant",
        json!("tenant-z"),
    );
    multi_tenant_case(other)
        .invalid_grant(RejectReason::ResourceNotGoverned)
        .await;
}

// ---------------------------------------------------------------------------
// §4 rule 11: client binding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_11_client_id_must_be_the_authenticated_client() {
    Case::claims(with(claims(), "client_id", json!("another-client")))
        .invalid_grant(RejectReason::ClientIdMismatch)
        .await;
    let mut case = Case::new();
    case.client = ClientIdentity::Authenticated {
        client_id: "Client-At-As".to_owned(),
        method: ClientAuthMethod::PrivateKeyJwt,
    };
    case.invalid_grant(RejectReason::ClientIdMismatch).await;
}

#[tokio::test]
async fn rule_11_tenant_scoped_client_ids() {
    let mut case = Case::new();
    case.registry.foreign_clients = vec![CLIENT];
    case.invalid_grant(RejectReason::ClientNotInTenant).await;
}

#[tokio::test]
async fn rule_11_unauthenticated_clients_need_cnf() {
    let mut case = Case::new();
    case.config.allow_unauthenticated_sender_constrained = true;
    case.client = unauthenticated();
    let error = case
        .rejects(
            OAuthErrorCode::InvalidClient,
            RejectReason::UnauthenticatedUnboundGrant,
        )
        .await;
    assert_eq!(error.to_response().status, 400);

    // A proof alone does not make an unbound grant acceptable.
    case.headers = proof(&dpop_key(), None).await;
    case.rejects(
        OAuthErrorCode::InvalidClient,
        RejectReason::UnauthenticatedUnboundGrant,
    )
    .await;

    // A claimed client_id that contradicts the grant.
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.config.allow_unauthenticated_sender_constrained = true;
    case.client = ClientIdentity::Unauthenticated {
        client_id: Some("another-client".to_owned()),
    };
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    case.invalid_grant(RejectReason::ClientIdMismatch).await;
}

// ---------------------------------------------------------------------------
// §4 rule 12: sender constraint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_12_a_dpop_bound_grant_under_jwt_bearer_is_rejected() {
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    let reason = RejectReason::SenderConstraint(BindingRejection::DpopBoundGrantAsBearer);
    case.invalid_grant(reason).await;
    // Even with a valid proof for the right key.
    case.headers = proof(&key, None).await;
    case.invalid_grant(reason).await;
}

#[tokio::test]
async fn rule_12_proof_key_must_match_cnf_jkt() {
    let mut case = Case::claims(with(
        claims(),
        "cnf",
        json!({ "jkt": dpop_key().thumbprint() }),
    ));
    case.grant_type = DPOP;
    case.headers = proof(&dpop_key(), None).await;
    case.invalid_grant(RejectReason::SenderConstraint(
        BindingRejection::DpopKeyMismatch,
    ))
    .await;
}

#[tokio::test]
async fn rule_12_jwt_dpop_needs_cnf_jkt() {
    let reason = RejectReason::SenderConstraint(BindingRejection::JwtDpopRequiresJkt);
    let mut case = Case::new();
    case.grant_type = DPOP;
    case.headers = proof(&dpop_key(), None).await;
    case.invalid_grant(reason).await;

    let thumbprint = certificate_thumbprint(&certificate()).unwrap();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "x5t#S256": thumbprint })));
    case.grant_type = DPOP;
    case.certificate = Some(certificate());
    case.headers = proof(&dpop_key(), None).await;
    case.invalid_grant(reason).await;
}

#[tokio::test]
async fn rule_12_certificate_binding() {
    let thumbprint = certificate_thumbprint(&certificate()).unwrap();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "x5t#S256": thumbprint })));
    case.invalid_grant(RejectReason::SenderConstraint(
        BindingRejection::CertificateRequired,
    ))
    .await;
    case.certificate = Some(vec![0x30, 0x03, 0x09, 0x09, 0x09]);
    case.invalid_grant(RejectReason::SenderConstraint(
        BindingRejection::CertificateMismatch,
    ))
    .await;
}

#[tokio::test]
async fn rule_12_an_unsupported_cnf_is_never_treated_as_unbound() {
    for cnf in [
        json!({ "jwk": { "kty": "EC" } }),
        json!({ "jkt": "abc", "extra": true }),
        json!({}),
    ] {
        Case::claims(with(claims(), "cnf", cnf))
            .invalid_grant(RejectReason::SenderConstraint(
                BindingRejection::UnsupportedConfirmation,
            ))
            .await;
    }
}

// ---------------------------------------------------------------------------
// §4 rule 13: sub_id
// ---------------------------------------------------------------------------

const SAML_ISSUER: &str = "https://saml.idp.example/metadata";

fn nameid() -> Value {
    json!({
        "format": "saml-nameid",
        "issuer": SAML_ISSUER,
        "nameid": "alice@example.com",
        "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "name_qualifier": "nq",
        "sp_name_qualifier": "spnq",
        "sp_provided_id": "sp-id"
    })
}

fn saml_case(sub_id: Value, subject_key: SamlSubjectKey) -> Case {
    let mut case = Case::claims(with(claims(), "sub_id", sub_id));
    case.config.trusted_issuers[0].saml_issuers = vec![SamlIssuerTrust {
        saml_issuer: SAML_ISSUER.to_owned(),
        subject_key,
    }];
    case
}

#[tokio::test]
async fn rule_13_saml_subject_key_uses_the_configured_members() {
    let format = Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_owned());
    let expectations = [
        (
            SamlSubjectKey::Qualified,
            (
                format.clone(),
                Some("nq".to_owned()),
                Some("spnq".to_owned()),
            ),
        ),
        (SamlSubjectKey::NameIdAndFormat, (format, None, None)),
        (SamlSubjectKey::NameIdOnly, (None, None, None)),
    ];
    for (subject_key, (nameid_format, name_qualifier, sp_name_qualifier)) in expectations {
        let grant = saml_case(nameid(), subject_key).accept().await;
        assert_eq!(
            grant.saml_subject_key(),
            Some(&SamlSubjectKeyValue {
                saml_issuer: SAML_ISSUER.to_owned(),
                nameid: "alice@example.com".to_owned(),
                nameid_format,
                name_qualifier,
                sp_name_qualifier,
            })
        );
        assert!(grant.claims().sub_id.is_some());
    }
}

#[tokio::test]
async fn rule_13_sub_id_issuer_never_establishes_trust_by_itself() {
    // No SAML issuer is associated with the IdP.
    Case::claims(with(claims(), "sub_id", nameid()))
        .invalid_grant(RejectReason::UntrustedSamlIssuer)
        .await;
    // Another SAML issuer than the associated one.
    let mut other = nameid();
    other["issuer"] = json!("https://saml.evil.example/metadata");
    saml_case(other, SamlSubjectKey::Qualified)
        .invalid_grant(RejectReason::UntrustedSamlIssuer)
        .await;
    // The association belongs to a different trusted IdP.
    let mut case = Case::claims(with(claims(), "sub_id", nameid()));
    let mut idp_b = TrustedIssuer::single_tenant(
        Issuer::new("https://idp-b.example"),
        RecipientTenant::new(TENANT),
    );
    idp_b.saml_issuers = vec![SamlIssuerTrust {
        saml_issuer: SAML_ISSUER.to_owned(),
        subject_key: SamlSubjectKey::Qualified,
    }];
    case.config.trusted_issuers.push(idp_b);
    case.invalid_grant(RejectReason::UntrustedSamlIssuer).await;
}

#[tokio::test]
async fn rule_13_unsupported_and_malformed_sub_id() {
    for sub_id in [
        json!({ "format": "email", "email": "alice@example.com" }),
        json!({ "format": "iss_sub", "iss": IDP, "sub": "user-1" }),
        json!({ "format": "opaque", "id": "x" }),
        json!({ "format": "did", "url": "did:example:1" }),
    ] {
        saml_case(sub_id, SamlSubjectKey::Qualified)
            .invalid_grant(RejectReason::UnsupportedSubjectIdentifier)
            .await;
    }

    let mut transient = nameid();
    transient["nameid_format"] = json!("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
    let error = saml_case(transient, SamlSubjectKey::Qualified)
        .invalid_grant(RejectReason::MalformedSubjectIdentifier)
        .await;
    assert!(matches!(error.error(), Some(Error::TransientNameId)));

    for sub_id in [
        json!("alice"),
        json!({ "issuer": SAML_ISSUER }),
        json!({ "format": "saml-nameid", "issuer": SAML_ISSUER }),
    ] {
        saml_case(sub_id, SamlSubjectKey::Qualified)
            .invalid_grant(RejectReason::MalformedSubjectIdentifier)
            .await;
    }
}

#[tokio::test]
async fn rule_13_required_saml_subject() {
    let mut case = Case::new();
    case.config.trusted_issuers[0].require_saml_subject = true;
    case.invalid_grant(RejectReason::SamlSubjectRequired).await;

    let mut case = saml_case(nameid(), SamlSubjectKey::NameIdOnly);
    case.config.trusted_issuers[0].require_saml_subject = true;
    case.accept().await;
}

// ---------------------------------------------------------------------------
// §4 rules 14–15: resource and authorization_details
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_14_every_resource_must_be_governed() {
    for resource in [
        json!("https://elsewhere.example/"),
        // Simple string comparison: no normalization.
        json!("https://api.example"),
        json!("https://API.example/"),
        json!([API, "https://elsewhere.example/"]),
    ] {
        Case::claims(with(claims(), "resource", resource))
            .invalid_grant(RejectReason::ResourceNotGoverned)
            .await;
    }
    Case::claims(with(claims(), "resource", json!([API, FILES])))
        .accept()
        .await;
}

#[tokio::test]
async fn rule_14_a_missing_resource_rejects_only_when_required() {
    let grant = Case::claims(without(claims(), "resource")).accept().await;
    assert_eq!(grant.claims().resource, None);

    let mut case = Case::claims(without(claims(), "resource"));
    case.config.require_resource_claim = true;
    case.invalid_grant(RejectReason::MissingResource).await;
}

#[tokio::test]
async fn rule_15_authorization_details() {
    for details in [
        json!("not an array"),
        json!({ "type": "payment" }),
        json!([{ "actions": ["read"] }]),
        json!([{ "type": 7 }]),
    ] {
        Case::claims(with(claims(), "authorization_details", details))
            .invalid_grant(RejectReason::InvalidAuthorizationDetails)
            .await;
    }

    let details = json!([{ "type": "files", "locations": [API], "actions": ["read"] }]);
    let grant = Case::claims(with(claims(), "authorization_details", details.clone()))
        .accept()
        .await;
    assert_eq!(
        serde_json::to_value(grant.claims().authorization_details.as_ref().unwrap()).unwrap(),
        details
    );
}

// ---------------------------------------------------------------------------
// §4 rule 16 and §8: replay and JtiPolicy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_use_accepts_each_id_jag_once() {
    let store = InMemoryReplayStore::new(16);
    let mut case = Case::new();
    case.config.jti_policy = JtiPolicy::SingleUse;
    case.run_with(Some(&store)).await.unwrap();
    let error = case.run_with(Some(&store)).await.unwrap_err();
    assert_rejected(
        &error,
        &OAuthErrorCode::InvalidGrant,
        RejectReason::Replayed,
    );

    // Another `jti` from the same issuer is fresh.
    case.claims = with(claims(), "jti", json!("jti-2"));
    case.run_with(Some(&store)).await.unwrap();
}

#[tokio::test]
async fn allow_reuse_accepts_re_presentation_until_exp() {
    let case = Case::new();
    case.accept().await;
    case.accept().await;

    // A store, when given, is not consulted for the ID-JAG.
    let store = CountingStore::new();
    case.run_with(Some(&store)).await.unwrap();
    case.run_with(Some(&store)).await.unwrap();
    assert_eq!(store.calls(), 0);
}

#[tokio::test]
async fn single_use_without_a_store_fails_closed() {
    let mut case = Case::new();
    case.config.jti_policy = JtiPolicy::SingleUse;
    let error = case
        .rejects(
            OAuthErrorCode::ServerError,
            RejectReason::ReplayStoreMissing,
        )
        .await;
    assert_eq!(error.to_response().status, 500);
}

#[tokio::test]
async fn a_replay_store_error_fails_closed() {
    let mut case = Case::new();
    case.config.jti_policy = JtiPolicy::SingleUse;
    let error = case.run_with(Some(&BrokenStore)).await.unwrap_err();
    // A server fault, not a bad grant: the client may retry.
    assert_rejected(
        &error,
        &OAuthErrorCode::ServerError,
        RejectReason::ReplayStoreUnavailable,
    );
    assert!(matches!(error.error(), Some(Error::ReplayStore(_))));
}

#[tokio::test]
async fn a_replayed_dpop_proof_is_rejected_without_burning_the_grant() {
    let key = dpop_key();
    let store = CountingStore::new();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.config.jti_policy = JtiPolicy::SingleUse;
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    case.run_with(Some(&store)).await.unwrap();
    // Proof `jti`, then ID-JAG `jti`.
    assert_eq!(store.calls(), 2);

    // The same proof with a fresh grant: the proof is the replay, and the
    // fresh grant's `jti` is not recorded.
    case.claims = with(case.claims.clone(), "jti", json!("jti-2"));
    let error = case.run_with(Some(&store)).await.unwrap_err();
    assert_rejected(
        &error,
        &OAuthErrorCode::InvalidDpopProof,
        RejectReason::DpopProofReplayed,
    );
    assert_eq!(store.calls(), 3);
    case.headers = proof(&key, None).await;
    case.run_with(Some(&store)).await.unwrap();
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_stale_dpop_nonce_does_not_burn_either_jti() {
    let key = dpop_key();
    let store = CountingStore::new();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.config.jti_policy = JtiPolicy::SingleUse;
    case.config.dpop_nonce = Some(Arc::new(FixedNonce));
    case.grant_type = DPOP;

    let stale = proof(&key, Some("nonce-1")).await;
    case.headers = stale.clone();
    let error = case.run_with(Some(&store)).await.unwrap_err();
    assert_rejected(
        &error,
        &OAuthErrorCode::UseDpopNonce,
        RejectReason::DpopNonceRequired,
    );
    assert_eq!(store.calls(), 0);

    // The retry with the nonce from the challenge succeeds with the same ID-JAG.
    let nonce = error.to_response().header("DPoP-Nonce").unwrap().to_owned();
    case.headers = proof(&key, Some(&nonce)).await;
    case.run_with(Some(&store)).await.unwrap();
    assert_eq!(store.calls(), 2);
}

#[tokio::test]
async fn a_rejected_request_never_reaches_the_replay_store() {
    let store = CountingStore::new();
    let key = dpop_key();

    // A forged ID-JAG.
    let mut forged = Case::new();
    forged.config.jti_policy = JtiPolicy::SingleUse;
    forged.signer = PrivateKey::generate_p256().with_key_id("p256-1");
    forged.headers = proof(&key, None).await;
    let error = forged.run_with(Some(&store)).await.unwrap_err();
    assert_eq!(error.reason(), Some(&RejectReason::InvalidSignature));

    // Failures of the last rules before replay, with a valid proof attached.
    let late_failures = [
        (
            with(claims(), "resource", json!("https://elsewhere.example/")),
            RejectReason::ResourceNotGoverned,
        ),
        (
            with(claims(), "authorization_details", json!("nope")),
            RejectReason::InvalidAuthorizationDetails,
        ),
        (
            with(claims(), "client_id", json!("another-client")),
            RejectReason::ClientIdMismatch,
        ),
    ];
    for (claims, reason) in late_failures {
        let mut case = Case::claims(claims);
        case.config.jti_policy = JtiPolicy::SingleUse;
        case.headers = proof(&key, None).await;
        let error = case.run_with(Some(&store)).await.unwrap_err();
        assert_eq!(error.reason(), Some(&reason));
    }
    assert_eq!(store.calls(), 0);

    // A bearer grant whose every resource requires a sender-constrained
    // token can only be refused, so it is refused before replay too.
    let mut bearer_only = Case::claims(with(claims(), "resource", json!([FILES])));
    bearer_only.config.jti_policy = JtiPolicy::SingleUse;
    bearer_only.registry.constrained = vec![FILES];
    let error = bearer_only.run_with(Some(&store)).await.unwrap_err();
    assert_eq!(
        error.reason(),
        Some(&RejectReason::SenderConstraint(
            BindingRejection::SenderConstraintRequired
        ))
    );
    assert_eq!(error.code(), &OAuthErrorCode::InvalidGrant);
    assert_eq!(store.calls(), 0);
    // With one unconstrained resource the grant is still usable for that
    // resource; the decision builder draws the line (RFC-004 §6).
    let mut mixed = Case::claims(with(claims(), "resource", json!([API, FILES])));
    mixed.registry.constrained = vec![FILES];
    mixed.run().await.unwrap();

    // The same `jti` is still usable afterwards.
    let mut case = Case::new();
    case.config.jti_policy = JtiPolicy::SingleUse;
    case.run_with(Some(&store)).await.unwrap();
}

/// Each case breaks two rules; the earlier one in the §4 table is reported.
#[tokio::test]
async fn rules_are_checked_in_table_order() {
    let break_aud = |claims: Value| with(claims, "aud", json!(TOKEN_ENDPOINT));
    let break_time = |claims: Value| with(claims, "exp", json!(NOW_SECS - 100));
    let break_client = |claims: Value| with(claims, "client_id", json!("another-client"));
    let break_cnf = |claims: Value| with(claims, "cnf", json!({ "jwk": {} }));
    let break_sub_id = |claims: Value| with(claims, "sub_id", json!("malformed"));
    let break_resource =
        |claims: Value| with(claims, "resource", json!("https://elsewhere.example/"));
    let break_details = |claims: Value| with(claims, "authorization_details", json!(1));
    let cnf_rejection = RejectReason::SenderConstraint(BindingRejection::UnsupportedConfirmation);

    // 3 before 4.
    let mut case = Case::new();
    case.assertion = Some(
        sign(
            &p256_key(),
            Some("JWT"),
            &with(claims(), "iss", json!("https://evil.example")),
        )
        .await,
    );
    case.invalid_grant(RejectReason::WrongTyp).await;

    // 4 before 6: an untrusted issuer is refused before any key is tried.
    let mut case = Case::claims(with(claims(), "iss", json!("https://evil.example")));
    case.signer = PrivateKey::generate_p256().with_key_id("p256-1");
    case.invalid_grant(RejectReason::UntrustedIssuer).await;

    // 6 before 7 and everything after: nothing is judged before the signature.
    let mut case = Case::claims(break_sub_id(break_aud(without(claims(), "sub"))));
    case.signer = PrivateKey::generate_p256().with_key_id("p256-1");
    case.invalid_grant(RejectReason::InvalidSignature).await;

    // 7 before 8.
    Case::claims(break_aud(without(claims(), "jti")))
        .invalid_grant(RejectReason::MissingClaim { name: "jti" })
        .await;
    // 8 before 9.
    Case::claims(break_time(break_aud(claims())))
        .invalid_grant(RejectReason::AudienceMismatch)
        .await;
    // 9 before 10.
    multi_tenant_case(break_time(claims()))
        .invalid_grant(RejectReason::Expired)
        .await;
    // 10 before 11.
    multi_tenant_case(break_client(claims()))
        .invalid_grant(RejectReason::MissingTenant)
        .await;
    // 11 before 12.
    Case::claims(break_cnf(break_client(claims())))
        .invalid_grant(RejectReason::ClientIdMismatch)
        .await;
    // 12 before 13.
    Case::claims(break_sub_id(break_cnf(claims())))
        .invalid_grant(cnf_rejection)
        .await;
    // 13 before 14.
    Case::claims(break_resource(break_sub_id(claims())))
        .invalid_grant(RejectReason::MalformedSubjectIdentifier)
        .await;
    // 14 before 15.
    Case::claims(break_details(break_resource(claims())))
        .invalid_grant(RejectReason::ResourceNotGoverned)
        .await;
    // 15 before 16.
    let store = CountingStore::new();
    let mut case = Case::claims(break_details(claims()));
    case.config.jti_policy = JtiPolicy::SingleUse;
    let error = case.run_with(Some(&store)).await.unwrap_err();
    assert_eq!(
        error.reason(),
        Some(&RejectReason::InvalidAuthorizationDetails)
    );
    assert_eq!(store.calls(), 0);
}

// ---------------------------------------------------------------------------
// A claim set in the shape of the draft's §4.3.4 examples
// ---------------------------------------------------------------------------

#[tokio::test]
async fn draft_shaped_claim_sets_pass_and_each_mutation_fails() {
    let key = dpop_key();
    let plain = json!({
        "jti": "9e43f81b64a33f20116179",
        "iss": IDP,
        "sub": "U019488227",
        "aud": AS,
        "client_id": CLIENT,
        "exp": EXP,
        "iat": NOW_SECS,
        "resource": API,
        "scope": "chat.read chat.history",
        "auth_time": NOW_SECS,
        "amr": ["mfa", "phrh"],
        "email": "alice@example.com"
    });
    let bound = with(plain.clone(), "cnf", json!({ "jkt": key.thumbprint() }));

    let grant = Case::claims(plain.clone()).accept().await;
    assert_eq!(
        grant.subject_hints(),
        UnverifiedSubjectHints {
            email: Some("alice@example.com"),
            aud_sub: None
        }
    );
    assert_eq!(grant.claims().amr.as_deref().unwrap(), ["mfa", "phrh"]);
    let mut case = Case::claims(bound.clone());
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    case.accept().await;

    let mutations = [
        ("iss", json!("https://other.idp.example")),
        ("aud", json!("https://other.as.example")),
        ("client_id", json!("someone-else")),
        ("exp", json!(NOW_SECS - 3600)),
        ("iat", json!(NOW_SECS + 3600)),
        ("resource", json!("https://other.api.example/")),
    ];
    for (name, value) in &mutations {
        let error = Case::claims(with(plain.clone(), name, value.clone()))
            .run()
            .await
            .unwrap_err();
        assert_eq!(error.code(), &OAuthErrorCode::InvalidGrant, "{name}");
    }
    for name in ["jti", "iss", "sub", "aud", "client_id", "exp", "iat"] {
        let error = Case::claims(without(plain.clone(), name))
            .run()
            .await
            .unwrap_err();
        assert_eq!(error.code(), &OAuthErrorCode::InvalidGrant, "{name}");
    }
    // The bound example with another key's thumbprint.
    let mut case = Case::claims(with(
        bound,
        "cnf",
        json!({ "jkt": dpop_key().thumbprint() }),
    ));
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    case.invalid_grant(RejectReason::SenderConstraint(
        BindingRejection::DpopKeyMismatch,
    ))
    .await;
}

// ---------------------------------------------------------------------------
// §6 Decision builder
// ---------------------------------------------------------------------------

fn scope(text: &str) -> Scope {
    Scope::parse(text).unwrap()
}

fn details(value: Value) -> AuthorizationDetails {
    AuthorizationDetails::from_json_str(&value.to_string()).unwrap()
}

/// The error is a caller bug: `Error::GrantExceedsIdJag`, `server_error` on
/// the wire.
fn assert_exceeds(error: &TokenError) {
    assert_rejected(
        error,
        &OAuthErrorCode::ServerError,
        RejectReason::GrantExceedsIdJag,
    );
    assert!(matches!(
        error.error(),
        Some(Error::GrantExceedsIdJag { .. })
    ));
    assert_eq!(error.to_response().status, 500);
}

#[tokio::test]
async fn decision_defaults_to_the_claimed_resources_and_no_scope() {
    let case = Case::claims(with(claims(), "resource", json!([API, FILES])));
    let grant = case.accept().await;
    let decision = grant.decide(&case.registry).build().unwrap();
    assert_eq!(decision.resources(), [API, FILES]);
    assert_eq!(decision.scope(), None);
    assert_eq!(decision.authorization_details(), None);
    assert_eq!(decision.binding(), None);
}

#[tokio::test]
async fn decision_resources_must_be_within_the_resource_claim() {
    let case = Case::claims(with(claims(), "resource", json!([API, FILES])));
    let grant = case.accept().await;
    let decide = || grant.decide(&case.registry);

    let narrowed = decide()
        .resources(vec![FILES.to_owned(), FILES.to_owned()])
        .build()
        .unwrap();
    assert_eq!(narrowed.resources(), [FILES]);

    // Governed by this server, but not in the ID-JAG.
    let mut registry = Registry::default();
    registry.governed.push("https://admin.example/");
    let error = grant
        .decide(&registry)
        .resources(vec![API.to_owned(), "https://admin.example/".to_owned()])
        .build()
        .unwrap_err();
    assert_exceeds(&error);
    assert_exceeds(
        &decide()
            .resources(vec!["https://api.example".to_owned()])
            .build()
            .unwrap_err(),
    );

    // Granting none of them is a denial, not a token without an audience.
    let error = decide().resources(Vec::new()).build().unwrap_err();
    assert_rejected(
        &error,
        &OAuthErrorCode::AccessDenied,
        RejectReason::NoResourceGranted,
    );
}

#[tokio::test]
async fn decision_default_resources_must_be_governed() {
    let case = Case::claims(without(claims(), "resource"));
    let grant = case.accept().await;
    let decide = || grant.decide(&case.registry);

    assert_eq!(decide().build().unwrap().resources(), [] as [&str; 0]);
    assert_eq!(
        decide()
            .resources(vec![FILES.to_owned()])
            .build()
            .unwrap()
            .resources(),
        [FILES]
    );
    assert_exceeds(
        &decide()
            .resources(vec![
                FILES.to_owned(),
                "https://elsewhere.example/".to_owned(),
            ])
            .build()
            .unwrap_err(),
    );
}

#[tokio::test]
async fn decision_scope_must_be_within_the_id_jag_and_the_request() {
    // No `scope` parameter: the ID-JAG's scope is the ceiling.
    let case = Case::new();
    let grant = case.accept().await;
    let decide = || grant.decide(&case.registry);
    assert_eq!(
        decide().scope(scope("write read")).build().unwrap().scope(),
        Some(&scope("write read"))
    );
    assert_eq!(
        decide().scope(scope("read")).build().unwrap().scope(),
        Some(&scope("read"))
    );
    assert_exceeds(&decide().scope(scope("read admin")).build().unwrap_err());

    // With a `scope` parameter: the intersection.
    let mut case = Case::new();
    case.scope = Some("read admin");
    let grant = case.accept().await;
    let decide = || grant.decide(&case.registry);
    decide().scope(scope("read")).build().unwrap();
    // In the ID-JAG but not requested.
    assert_exceeds(&decide().scope(scope("read write")).build().unwrap_err());
    // Requested but not in the ID-JAG.
    assert_exceeds(&decide().scope(scope("admin")).build().unwrap_err());

    // An ID-JAG without `scope` carries none to grant.
    let case = Case::claims(without(claims(), "scope"));
    let grant = case.accept().await;
    grant.decide(&case.registry).build().unwrap();
    assert_exceeds(
        &grant
            .decide(&case.registry)
            .scope(scope("read"))
            .build()
            .unwrap_err(),
    );
}

#[tokio::test]
async fn decision_authorization_details_must_come_from_the_id_jag() {
    let read = json!({ "type": "files", "locations": [API], "actions": ["read"] });
    let write = json!({ "type": "files", "locations": [FILES], "actions": ["write"] });
    let case = Case::claims(with(
        with(claims(), "resource", json!([API, FILES])),
        "authorization_details",
        json!([read, write]),
    ));
    let grant = case.accept().await;
    let decide = || grant.decide(&case.registry);

    let decision = decide()
        .authorization_details(details(json!([read])))
        .build()
        .unwrap();
    assert_eq!(
        decision.authorization_details(),
        Some(&details(json!([read])))
    );

    // An object that is not in the claim, even a "narrower" one.
    let invented = json!([{ "type": "files", "locations": [API], "actions": ["delete"] }]);
    assert_exceeds(
        &decide()
            .authorization_details(details(invented))
            .build()
            .unwrap_err(),
    );

    // The ID-JAG carries none.
    let case = Case::new();
    let grant = case.accept().await;
    assert_exceeds(
        &grant
            .decide(&case.registry)
            .authorization_details(details(json!([read])))
            .build()
            .unwrap_err(),
    );
}

#[tokio::test]
async fn decision_authorization_details_locations_must_be_claimed_resources() {
    // The IdP put a location in authorization_details that is not in `resource`.
    let stray = json!([{ "type": "files", "locations": [API, FILES] }]);
    let case = Case::claims(with(claims(), "authorization_details", stray.clone()));
    let grant = case.accept().await;
    assert_exceeds(
        &grant
            .decide(&case.registry)
            .authorization_details(details(stray.clone()))
            .build()
            .unwrap_err(),
    );

    // Without a `resource` claim, locations must be governed.
    let case = Case::claims(with(
        without(claims(), "resource"),
        "authorization_details",
        stray.clone(),
    ));
    let grant = case.accept().await;
    grant
        .decide(&case.registry)
        .authorization_details(details(stray.clone()))
        .build()
        .unwrap();
    let registry = Registry {
        governed: vec![API],
        ..Registry::default()
    };
    assert_exceeds(
        &grant
            .decide(&registry)
            .authorization_details(details(stray))
            .build()
            .unwrap_err(),
    );
}

#[tokio::test]
async fn decision_enforces_required_sender_constraints() {
    let reason = RejectReason::SenderConstraint(BindingRejection::SenderConstraintRequired);
    let mut case = Case::claims(with(claims(), "resource", json!([API, FILES])));
    case.registry.constrained = vec![FILES];

    // Bearer: only the unconstrained resource can be granted.
    let grant = case.accept().await;
    let error = grant.decide(&case.registry).build().unwrap_err();
    assert_rejected(&error, &OAuthErrorCode::InvalidGrant, reason);
    grant
        .decide(&case.registry)
        .resources(vec![API.to_owned()])
        .build()
        .unwrap();

    // A proven binding satisfies the requirement.
    case.headers = proof(&dpop_key(), None).await;
    let grant = case.accept().await;
    let decision = grant.decide(&case.registry).build().unwrap();
    assert!(matches!(
        decision.binding(),
        Some(AccessTokenBinding::Dpop { .. })
    ));

    // A constrained location in authorization_details counts too.
    let located = json!([{ "type": "files", "locations": [FILES] }]);
    let mut case = Case::claims(with(
        with(claims(), "resource", json!([API, FILES])),
        "authorization_details",
        located.clone(),
    ));
    case.registry.constrained = vec![FILES];
    let grant = case.accept().await;
    let error = grant
        .decide(&case.registry)
        .resources(vec![API.to_owned()])
        .authorization_details(details(located))
        .build()
        .unwrap_err();
    assert_rejected(&error, &OAuthErrorCode::InvalidGrant, reason);
}

#[tokio::test]
async fn deny_is_access_denied() {
    let case = Case::new();
    let grant = case.accept().await;
    let error = grant.decide(&case.registry).deny();
    assert_rejected(
        &error,
        &OAuthErrorCode::AccessDenied,
        RejectReason::DeniedByPolicy,
    );
    assert_eq!(error.to_response().status, 400);
}

fn tokens(pool: &'static [&'static str]) -> impl Strategy<Value = Vec<&'static str>> {
    proptest::sample::subsequence(pool, 0..=pool.len())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Whatever policy asks for, a built decision is inside the ID-JAG (and
    /// the request), and anything else is an error.
    #[test]
    fn decisions_never_exceed_the_id_jag(
        claimed_scope in tokens(&["a", "b", "c", "d"]),
        requested_scope in proptest::option::of(tokens(&["a", "b", "c", "d", "e"])),
        granted_scope in tokens(&["a", "b", "c", "d", "e", "f"]),
        claimed_resources in tokens(&[API, FILES]),
        granted_resources in proptest::option::of(tokens(&[API, FILES, "https://elsewhere.example/"])),
    ) {
        let join = |tokens: &[&str]| (!tokens.is_empty()).then(|| tokens.join(" "));
        let mut claims = without(without(claims(), "scope"), "resource");
        if let Some(text) = join(&claimed_scope) {
            claims = with(claims, "scope", json!(text));
        }
        if !claimed_resources.is_empty() {
            claims = with(claims, "resource", json!(claimed_resources));
        }
        let mut case = Case::claims(claims);
        let requested = requested_scope.as_deref().and_then(join);
        // `Case::scope` wants a `'static` string; leak the handful of bytes.
        case.scope = requested.clone().map(|text| &*text.leak());

        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let grant = runtime.block_on(case.accept());

        let mut builder = grant.decide(&case.registry);
        if let Some(text) = join(&granted_scope) {
            builder = builder.scope(scope(&text));
        }
        if let Some(resources) = &granted_resources {
            builder = builder.resources(resources.iter().map(|r| (*r).to_owned()).collect());
        }
        match builder.build() {
            Ok(decision) => {
                if let Some(granted) = decision.scope() {
                    prop_assert!(granted.tokens().all(|token| claimed_scope.contains(&token)));
                    // An empty selection sends no `scope` parameter at all, so it
                    // is "no downscoping request", not "request nothing".
                    if let Some(requested) = requested_scope.as_ref().filter(|r| !r.is_empty()) {
                        prop_assert!(granted.tokens().all(|token| requested.contains(&token)));
                    }
                }
                for resource in decision.resources() {
                    prop_assert!(case.registry.governs(resource, grant.recipient_tenant()));
                    if !claimed_resources.is_empty() {
                        prop_assert!(claimed_resources.contains(&resource.as_str()));
                    }
                }
                if !claimed_resources.is_empty() {
                    prop_assert!(!decision.resources().is_empty());
                }
            }
            Err(error) => {
                let scope_exceeds = granted_scope.iter().any(|token| {
                    !claimed_scope.contains(token)
                        || requested_scope.as_ref().is_some_and(|requested| !requested.contains(token))
                });
                let resources_exceed = granted_resources.as_ref().is_some_and(|granted| {
                    granted.iter().any(|resource| {
                        if claimed_resources.is_empty() {
                            *resource != API && *resource != FILES
                        } else {
                            !claimed_resources.contains(resource)
                        }
                    })
                });
                let none_granted = !claimed_resources.is_empty()
                    && granted_resources.as_ref().is_some_and(Vec::is_empty);
                match error.reason() {
                    Some(RejectReason::GrantExceedsIdJag) => {
                        prop_assert!(scope_exceeds || resources_exceed);
                    }
                    Some(RejectReason::NoResourceGranted) => prop_assert!(none_granted),
                    other => prop_assert!(false, "unexpected rejection: {other:?}"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// §7 Responses
// ---------------------------------------------------------------------------

fn assert_token_endpoint_headers(response: &crate::http::HttpResponse) {
    assert_eq!(response.header("Content-Type"), Some("application/json"));
    assert_eq!(response.header("Cache-Control"), Some("no-store"));
    assert_eq!(response.header("Pragma"), Some("no-cache"));
}

#[tokio::test]
async fn token_response_for_a_bearer_grant() {
    let read = json!([{ "type": "files", "locations": [API], "actions": ["read"] }]);
    let case = Case::claims(with(claims(), "authorization_details", read.clone()));
    let grant = case.accept().await;
    let decision = grant
        .decide(&case.registry)
        .scope(scope("read"))
        .authorization_details(details(read.clone()))
        .build()
        .unwrap();
    let response = decision.token_response(AccessToken::new("at-123"), Duration::from_hours(2));
    assert_eq!(response.status, 200);
    assert_token_endpoint_headers(&response);
    assert_eq!(
        body(&response),
        json!({
            "access_token": "at-123",
            "token_type": "Bearer",
            "expires_in": 7200,
            "scope": "read",
            "authorization_details": read
        })
    );
}

#[tokio::test]
async fn token_response_omits_what_was_not_granted_and_never_has_a_refresh_token() {
    let case = Case::new();
    let grant = case.accept().await;
    let decision = grant.decide(&case.registry).build().unwrap();
    let response = decision.token_response(AccessToken::new("at-123"), Duration::from_secs(60));
    assert_eq!(
        body(&response),
        json!({ "access_token": "at-123", "token_type": "Bearer", "expires_in": 60 })
    );
    assert!(
        !String::from_utf8(response.body)
            .unwrap()
            .contains("refresh_token")
    );
}

#[tokio::test]
async fn token_type_follows_the_binding() {
    // DPoP-bound.
    let key = dpop_key();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "jkt": key.thumbprint() })));
    case.grant_type = DPOP;
    case.headers = proof(&key, None).await;
    let grant = case.accept().await;
    let decision = grant.decide(&case.registry).build().unwrap();
    let response = decision.token_response(AccessToken::new("at"), Duration::from_secs(60));
    assert_eq!(body(&response)["token_type"], "DPoP");

    // Certificate-bound.
    let thumbprint = certificate_thumbprint(&certificate()).unwrap();
    let mut case = Case::claims(with(claims(), "cnf", json!({ "x5t#S256": thumbprint })));
    case.certificate = Some(certificate());
    let grant = case.accept().await;
    let decision = grant.decide(&case.registry).build().unwrap();
    let response = decision.token_response(AccessToken::new("at"), Duration::from_secs(60));
    assert_eq!(body(&response)["token_type"], "Bearer");
    assert_eq!(
        decision.binding().unwrap().confirmation(),
        Confirmation::X5tS256(thumbprint)
    );
}

#[test]
fn caller_built_errors() {
    let error = TokenError::invalid_client();
    assert_eq!(error.code(), &OAuthErrorCode::InvalidClient);
    assert_eq!(error.reason(), None);
    let response = error.to_response();
    assert_eq!(response.status, 400);
    assert_eq!(response.header("WWW-Authenticate"), None);
    assert_token_endpoint_headers(&response);
    assert_eq!(
        body(&response),
        json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed."
        })
    );

    // After a failed Basic attempt: 401 with a challenge (RFC 6749 §5.2).
    let basic = ClientCredentials::Basic {
        client_id: CLIENT.to_owned(),
        secret: crate::secret::ClientSecret::new("wrong"),
    };
    let response = TokenError::invalid_client_for(&basic).to_response();
    assert_eq!(response.status, 401);
    assert_eq!(response.header("WWW-Authenticate"), Some("Basic"));
    let post = ClientCredentials::Post {
        client_id: CLIENT.to_owned(),
        secret: crate::secret::ClientSecret::new("wrong"),
    };
    assert_eq!(
        TokenError::invalid_client_for(&post).to_response().status,
        400
    );

    let response = TokenError::invalid_scope().to_response();
    assert_eq!(response.status, 400);
    assert_eq!(body(&response)["error"], "invalid_scope");
}

#[tokio::test]
async fn error_responses_do_not_carry_the_reason() {
    let error = Case::claims(with(claims(), "client_id", json!("another-client")))
        .invalid_grant(RejectReason::ClientIdMismatch)
        .await;
    let response = error.to_response();
    assert_eq!(response.status, 400);
    assert_token_endpoint_headers(&response);
    assert_eq!(
        body(&response),
        json!({
            "error": "invalid_grant",
            "error_description": "The provided authorization grant is invalid."
        })
    );
    // The reason is for logs.
    assert_eq!(
        error.to_string(),
        "invalid_grant: client_id does not match the requesting client"
    );
}

// ---------------------------------------------------------------------------
// §1, §10 Configuration and metadata
// ---------------------------------------------------------------------------

#[test]
fn configuration_is_checked_at_construction() {
    ResourceAs::new(config(JtiPolicy::SingleUse)).unwrap();

    let mut duplicate = config(JtiPolicy::AllowReuse);
    duplicate.trusted_issuers.push(TrustedIssuer::single_tenant(
        Issuer::new(IDP),
        RecipientTenant::new("tenant-b"),
    ));
    let mut zero = config(JtiPolicy::AllowReuse);
    zero.max_id_jag_lifetime = Duration::ZERO;
    let empty = ResourceAsConfig::new(Issuer::new(""), url(), JtiPolicy::AllowReuse);
    for invalid in [duplicate, zero, empty] {
        assert!(matches!(
            ResourceAs::new(invalid).unwrap_err(),
            Error::InvalidConfiguration { .. }
        ));
    }
}

#[test]
fn configuration_defaults() {
    let config = ResourceAsConfig::new(Issuer::new(AS), url(), JtiPolicy::SingleUse);
    assert_eq!(config.max_id_jag_lifetime, Duration::from_mins(10));
    assert!(!config.require_resource_claim);
    assert!(!config.allow_unauthenticated_sender_constrained);
    assert!(!config.allow_self_issued);
    assert!(config.dpop_nonce.is_none());
    assert_eq!(config.trusted_issuers.len(), 0);

    let trusted = TrustedIssuer::single_tenant(Issuer::new(IDP), RecipientTenant::new(TENANT));
    assert!(trusted.algorithms.allows(SignatureAlgorithm::Rs256));
    assert!(trusted.algorithms.allows(SignatureAlgorithm::Es256));
    assert_eq!(trusted.algorithms.algorithms().len(), 2);
    assert!(!trusted.require_saml_subject);
}

#[test]
fn metadata_advertises_the_profile_and_never_the_trusted_issuers() {
    let metadata = ResourceAs::new(config(JtiPolicy::SingleUse))
        .unwrap()
        .metadata()
        .build()
        .unwrap();
    assert_eq!(metadata.accepts_id_jag_profile(), Support::Advertised);
    assert_eq!(metadata.accepts_jwt_dpop(), Support::Advertised);
    let document = metadata.to_value();
    assert_eq!(document["issuer"], AS);
    assert_eq!(document["token_endpoint"], TOKEN_ENDPOINT);
    assert_eq!(document["grant_types_supported"], json!([BEARER, DPOP]));
    assert_eq!(
        document["authorization_grant_profiles_supported"],
        json!(["urn:ietf:params:oauth:grant-profile:id-jag"])
    );
    assert_eq!(
        document["dpop_signing_alg_values_supported"],
        json!(["ES256", "ES384", "RS256", "PS256"])
    );
    assert!(!document.to_string().contains("idp.example"));
}

/// Web frameworks spawn handlers: the validation future must be `Send`.
#[tokio::test]
async fn the_validation_future_is_send() {
    fn assert_send<T: Send>(value: T) -> T {
        value
    }
    let case = Case::new();
    let request = case.request().await;
    let resource_as = ResourceAs::new(case.config.clone()).unwrap();
    assert_send(resource_as.validate(
        &request,
        &case.client,
        &case.keys,
        &case.registry,
        None,
        now(),
        SKEW,
    ))
    .await
    .unwrap();
}

/// Draft §6.1: `aud_tenant` names the recipient tenant when present. A
/// single-tenant issuer's trust relationship does not override it.
#[tokio::test]
async fn single_tenant_issuer_aud_tenant_must_name_the_recipient_tenant() {
    let claims = with(claims(), "aud_tenant", json!("workspace-b"));

    Case::claims(claims.clone())
        .invalid_grant(RejectReason::UntrustedTenant)
        .await;

    let mut other = Case::claims(claims.clone());
    for issuer in &mut other.config.trusted_issuers {
        issuer.aud_tenant = Some("workspace-a".to_owned());
    }
    other.invalid_grant(RejectReason::UntrustedTenant).await;

    let mut same = Case::claims(claims);
    for issuer in &mut same.config.trusted_issuers {
        issuer.aud_tenant = Some("workspace-b".to_owned());
    }
    same.run().await.unwrap();
}
