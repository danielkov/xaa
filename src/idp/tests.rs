//! Unit tests for the IdP component: one per row of the RFC-005 rule tables.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use url::Url;

use super::*;
use crate::claims::{
    AuthorizationDetails, Confirmation, IdJagClaims, NumericDate, SamlNameId, Scope,
    SubjectIdentifier,
};
use crate::client_auth::{ClientAuthMethod, ClientCredentials, ClientIdentity};
use crate::dpop::DpopKey;
use crate::jose::{
    ExpectedTyp, ParseLimits, PrivateKey, SignatureAlgorithm, UnverifiedJws, b64url_decode, verify,
};
use crate::mtls::tests::{RFC_8705_THUMBPRINT, rfc_8705_certificate_der};
use crate::oauth_error::{OAuthErrorBody, OAuthErrorCode};
use crate::replay::InMemoryReplayStore;
use crate::secret::{IdToken, RefreshToken};
use crate::test_support::{NOW_SECS, jwks_of, now, other_rsa_key, p256_key, rsa_key, sign};

const ISSUER: &str = "https://idp.example";
const TOKEN_ENDPOINT: &str = "https://idp.example/token";
const RAS: &str = "https://as.resource.example";
const RAS_ALIAS: &str = "urn:example:resource-as";
const RESOURCE: &str = "https://api.resource.example/";
const RESOURCE_2: &str = "https://files.resource.example/v1";
const CLIENT: &str = "client-at-idp";
const RAS_CLIENT: &str = "client-at-ras";
const RAS_SUB: &str = "ras-user-1";
const SP_ENTITY_ID: &str = "https://client.example/saml/sp";
const SAML_XML: &[u8] = b"\xfb\xff\xfe<saml:Assertion>alice</saml:Assertion>";
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

// ----- fixtures ---------------------------------------------------------------------

fn config() -> IdpConfig {
    IdpConfig::new(
        Issuer::new(ISSUER),
        Url::parse(TOKEN_ENDPOINT).unwrap(),
        Arc::new(rsa_key()),
    )
}

fn idp() -> Idp {
    Idp::new(config()).unwrap()
}

fn idp_with(edit: impl FnOnce(&mut IdpConfig)) -> Idp {
    let mut config = config();
    edit(&mut config);
    Idp::new(config).unwrap()
}

fn saml_map() -> Arc<dyn SamlAudienceMap> {
    Arc::new(HashMap::from([(
        SP_ENTITY_ID.to_owned(),
        CLIENT.to_owned(),
    )]))
}

struct Directory {
    entry: ResourceAsEntry,
    governed: Vec<&'static str>,
    seen_tenants: Mutex<Vec<Option<String>>>,
}

impl ResourceAsDirectory for Directory {
    fn resolve_audience(
        &self,
        audience: &str,
        issuer_tenant: Option<&str>,
    ) -> Option<ResourceAsEntry> {
        self.seen_tenants
            .lock()
            .unwrap()
            .push(issuer_tenant.map(str::to_owned));
        (audience == RAS || audience == RAS_ALIAS).then(|| self.entry.clone())
    }

    fn governs(&self, ras: &ResourceAsEntry, resource: &str) -> bool {
        ras.issuer.as_str() == RAS && self.governed.contains(&resource)
    }
}

fn directory() -> Directory {
    directory_with(|_| {})
}

fn directory_with(edit: impl FnOnce(&mut ResourceAsEntry)) -> Directory {
    let mut entry = ResourceAsEntry::new(Issuer::new(RAS));
    edit(&mut entry);
    Directory {
        entry,
        governed: vec![RESOURCE, RESOURCE_2],
        seen_tenants: Mutex::new(Vec::new()),
    }
}

/// A verifier that answers the same thing for every token.
struct Subjects(Result<VerifiedSubject, SubjectRejection>);

impl SubjectTokenVerifier for Subjects {
    fn verify(
        &self,
        _token: &SubjectTokenInput<'_>,
        _client: &AuthenticatedClient,
        _now: SystemTime,
    ) -> impl Future<Output = Result<VerifiedSubject, SubjectRejection>> + Send {
        std::future::ready(self.0.clone())
    }
}

/// A subject whose token was issued to [`CLIENT`], as an ID Token or a
/// Refresh Token would be.
fn subject() -> VerifiedSubject {
    VerifiedSubject {
        issued_to_client: Some(CLIENT.to_owned()),
        ..VerifiedSubject::new(SubjectRef::new("user-1"))
    }
}

fn saml_subject() -> VerifiedSubject {
    VerifiedSubject {
        saml_audience: Some(SP_ENTITY_ID.to_owned()),
        ..VerifiedSubject::new(SubjectRef::new("user-1"))
    }
}

fn ok_subjects() -> Subjects {
    Subjects(Ok(subject()))
}

/// Grants exactly what was requested.
struct Echo;

fn echo_grant(ctx: &ExchangeContext<'_>) -> ExchangeGrant {
    let mut grant = ExchangeGrant::new(RAS_CLIENT, RAS_SUB);
    grant.resources = ctx.resources.to_vec();
    grant.scope = ctx.scope.cloned();
    grant.authorization_details = ctx.authorization_details.cloned();
    grant
}

impl ExchangePolicy for Echo {
    fn evaluate(
        &self,
        ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send {
        std::future::ready(Ok(echo_grant(ctx)))
    }
}

/// Answers the same thing whatever was requested.
struct Fixed(Result<ExchangeGrant, ExchangeDenial>);

impl ExchangePolicy for Fixed {
    fn evaluate(
        &self,
        _ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send {
        std::future::ready(self.0.clone())
    }
}

fn grant() -> ExchangeGrant {
    ExchangeGrant::new(RAS_CLIENT, RAS_SUB)
}

fn grant_with(edit: impl FnOnce(&mut ExchangeGrant)) -> Fixed {
    let mut grant = grant();
    edit(&mut grant);
    Fixed(Ok(grant))
}

type Pairs = Vec<(&'static str, String)>;

/// A complete ID-JAG request with an opaque refresh token as the subject and
/// `client_secret_post` credentials.
fn pairs() -> Pairs {
    vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE.to_owned()),
        ("requested_token_type", TOKEN_TYPE_ID_JAG.to_owned()),
        ("audience", RAS.to_owned()),
        ("subject_token", "opaque-refresh-token".to_owned()),
        ("subject_token_type", TOKEN_TYPE_REFRESH_TOKEN.to_owned()),
        ("client_id", CLIENT.to_owned()),
        ("client_secret", "s3cret".to_owned()),
    ]
}

fn set(mut pairs: Pairs, name: &'static str, value: &str) -> Pairs {
    pairs.retain(|(key, _)| *key != name);
    pairs.push((name, value.to_owned()));
    pairs
}

fn add(mut pairs: Pairs, name: &'static str, value: &str) -> Pairs {
    pairs.push((name, value.to_owned()));
    pairs
}

fn without(mut pairs: Pairs, name: &'static str) -> Pairs {
    pairs.retain(|(key, _)| *key != name);
    pairs
}

fn with_subject(pairs: Pairs, token_type: &str, token: &str) -> Pairs {
    set(
        set(pairs, "subject_token", token),
        "subject_token_type",
        token_type,
    )
}

fn saml_pairs() -> Pairs {
    with_subject(pairs(), TOKEN_TYPE_SAML2, &URL_SAFE_NO_PAD.encode(SAML_XML))
}

fn refresh_exchange_pairs() -> Pairs {
    set(
        without(saml_pairs(), "audience"),
        "requested_token_type",
        TOKEN_TYPE_REFRESH_TOKEN,
    )
}

fn body(pairs: &Pairs) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish().into_bytes()
}

fn parse(pairs: &Pairs) -> Result<TokenExchangeRequest, ExchangeError> {
    TokenExchangeRequest::parse(&body(pairs), &[], None)
}

fn request(pairs: &Pairs) -> TokenExchangeRequest {
    parse(pairs).unwrap()
}

fn request_with(
    pairs: &Pairs,
    headers: &[(String, String)],
    certificate: Option<&[u8]>,
) -> TokenExchangeRequest {
    TokenExchangeRequest::parse(&body(pairs), headers, certificate).unwrap()
}

fn client() -> ClientIdentity {
    ClientIdentity::Authenticated {
        client_id: CLIENT.to_owned(),
        method: ClientAuthMethod::ClientSecretPost,
    }
}

fn authenticated_client() -> AuthenticatedClient {
    AuthenticatedClient {
        client_id: CLIENT.to_owned(),
        method: ClientAuthMethod::ClientSecretPost,
    }
}

type Outcome = (Result<IssuedIdJag, ExchangeError>, ExchangeRecord);

/// Exchange with an accepting verifier, the default directory, and [`Echo`].
async fn run(idp: &Idp, request: &TokenExchangeRequest) -> Outcome {
    idp.exchange(
        request,
        &client(),
        &ok_subjects(),
        &directory(),
        &Echo,
        now(),
    )
    .await
}

async fn run_policy(request: &TokenExchangeRequest, policy: &impl ExchangePolicy) -> Outcome {
    idp()
        .exchange(
            request,
            &client(),
            &ok_subjects(),
            &directory(),
            policy,
            now(),
        )
        .await
}

async fn run_subjects(idp: &Idp, request: &TokenExchangeRequest, subjects: &Subjects) -> Outcome {
    idp.exchange(request, &client(), subjects, &directory(), &Echo, now())
        .await
}

async fn run_directory(idp: &Idp, request: &TokenExchangeRequest, dir: &Directory) -> Outcome {
    idp.exchange(request, &client(), &ok_subjects(), dir, &Echo, now())
        .await
}

/// Assert a refusal: the error's reason and code, and the same in the record.
fn rejected<T: std::fmt::Debug>(
    outcome: (Result<T, ExchangeError>, ExchangeRecord),
    reason: &RejectReason,
    code: &OAuthErrorCode,
) -> ExchangeError {
    let (result, record) = outcome;
    let error = result.unwrap_err();
    assert_eq!(error.reason(), reason);
    assert_eq!(error.code(), code);
    assert_eq!(
        record.outcome,
        ExchangeOutcome::Rejected {
            code: code.clone(),
            reason: reason.clone(),
        }
    );
    assert_eq!(record.at, now());
    error
}

/// Assert a caller-bug refusal: `server_error`, and the library error.
fn grant_bug(outcome: Outcome) -> ExchangeError {
    let error = rejected(
        outcome,
        &RejectReason::GrantInvariantViolated,
        &OAuthErrorCode::ServerError,
    );
    assert_eq!(error.to_response().status, 500);
    error
}

fn parse_error(pairs: &Pairs, reason: &RejectReason, code: &OAuthErrorCode) -> ExchangeError {
    let error = parse(pairs).unwrap_err();
    assert_eq!(error.reason(), reason);
    assert_eq!(error.code(), code);
    error
}

fn invalid_request(pairs: &Pairs, reason: &RejectReason) {
    parse_error(pairs, reason, &OAuthErrorCode::InvalidRequest);
}

fn error_body(error: &ExchangeError) -> OAuthErrorBody {
    serde_json::from_slice(&error.to_response().body).unwrap()
}

/// The header and payload of an issued ID-JAG.
fn decode(issued: &IssuedIdJag) -> (Value, Value) {
    let mut segments = issued.id_jag().expose_secret().split('.');
    let mut next = || {
        let bytes = b64url_decode(segments.next().unwrap()).unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    };
    (next(), next())
}

fn payload(outcome: Outcome) -> Value {
    decode(&outcome.0.unwrap()).1
}

fn id_token_claims() -> Value {
    json!({
        "iss": ISSUER,
        "sub": "idp-user-1",
        "aud": CLIENT,
        "exp": NOW_SECS + 300,
        "iat": NOW_SECS - 10,
    })
}

fn claims_with(name: &str, value: Value) -> Value {
    let mut claims = id_token_claims();
    claims[name] = value;
    claims
}

fn claims_without(name: &str) -> Value {
    let mut claims = id_token_claims();
    claims.as_object_mut().unwrap().remove(name);
    claims
}

fn map_subject(claims: &IdTokenClaims) -> Option<IdTokenSubject> {
    (claims.sub == "idp-user-1").then(|| IdTokenSubject {
        subject: SubjectRef::new("user-1"),
        issuer_tenant: claims
            .claims
            .get("tenant")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

type Mapper = fn(&IdTokenClaims) -> Option<IdTokenSubject>;

fn id_token_verifier() -> IdTokenVerifier<Mapper> {
    IdTokenVerifier::new(
        Issuer::new(ISSUER),
        jwks_of(&[&rsa_key()]),
        AlgorithmPolicy::only(&[SignatureAlgorithm::Rs256]),
        Duration::from_secs(30),
        map_subject as Mapper,
    )
}

async fn verify_id_token(token: &str) -> Result<VerifiedSubject, SubjectRejection> {
    let token = IdToken::new(token);
    id_token_verifier()
        .verify(
            &SubjectTokenInput::IdToken(&token),
            &authenticated_client(),
            now(),
        )
        .await
}

async fn id_token_invalid(key: &PrivateKey, claims: &Value) {
    let token = sign(key, None, claims).await;
    assert_eq!(
        verify_id_token(&token).await.unwrap_err(),
        SubjectRejection::Invalid
    );
}

async fn dpop_headers(key: &DpopKey, nonce: Option<&str>) -> Vec<(String, String)> {
    let proof = key
        .proof(
            &http::Method::POST,
            &Url::parse(TOKEN_ENDPOINT).unwrap(),
            nonce,
            now(),
        )
        .await
        .unwrap();
    vec![("DPoP".to_owned(), proof)]
}

fn dpop_key() -> DpopKey {
    DpopKey::generate(SignatureAlgorithm::Es256).unwrap()
}

fn dpop_idp() -> Idp {
    idp_with(|config| config.dpop = true)
}

fn supports_jwt_dpop() -> Directory {
    directory_with(|entry| entry.supports_jwt_dpop = true)
}

// ----- §2 request parsing -----------------------------------------------------------

#[test]
fn parse_reads_every_parameter() {
    let details = r#"[{"type":"todo","actions":["read"]}]"#;
    let pairs = add(
        add(
            add(
                add(
                    add(add(pairs(), "resource", RESOURCE), "resource", RESOURCE_2),
                    "scope",
                    "todos.read todos.write",
                ),
                "authorization_details",
                details,
            ),
            "actor_token",
            "actor",
        ),
        "actor_token_type",
        TOKEN_TYPE_ID_TOKEN,
    );
    let request = request(&pairs);
    assert_eq!(request.requested_token_type(), RequestedTokenType::IdJag);
    assert_eq!(request.audience(), Some(RAS));
    assert_eq!(request.resources(), [RESOURCE, RESOURCE_2]);
    assert_eq!(request.scope().unwrap().as_str(), "todos.read todos.write");
    assert_eq!(request.subject_token_type(), SubjectTokenType::RefreshToken);
    assert!(matches!(
        request.subject_token(),
        SubjectTokenInput::RefreshToken(token) if token.expose_secret() == "opaque-refresh-token"
    ));
    assert_eq!(
        request.authorization_details(),
        Some(&AuthorizationDetails::from_json_str(details).unwrap())
    );
    assert!(request.has_actor_token());
    assert!(matches!(
        request.client_credentials(),
        ClientCredentials::Post { client_id, .. } if client_id == CLIENT
    ));
    assert!(!request.has_dpop_proof());
    assert_eq!(request.certificate_thumbprint(), None);
    // Secrets never reach Debug output.
    let printed = format!("{request:?}");
    assert!(!printed.contains("opaque-refresh-token"));
    assert!(!printed.contains("s3cret"));
}

#[test]
fn grant_type_other_than_token_exchange_is_unsupported() {
    for pairs in [
        set(pairs(), "grant_type", "authorization_code"),
        set(
            pairs(),
            "grant_type",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ),
        without(pairs(), "grant_type"),
    ] {
        parse_error(
            &pairs,
            &RejectReason::UnsupportedGrantType,
            &OAuthErrorCode::UnsupportedGrantType,
        );
    }
}

#[test]
fn requested_token_type_must_be_id_jag_or_refresh_token() {
    for unsupported in [
        "urn:ietf:params:oauth:token-type:access_token",
        TOKEN_TYPE_ID_TOKEN,
        "urn:ietf:params:oauth:token-type:jwt",
    ] {
        invalid_request(
            &set(pairs(), "requested_token_type", unsupported),
            &RejectReason::UnsupportedRequestedTokenType,
        );
    }
    invalid_request(
        &without(pairs(), "requested_token_type"),
        &RejectReason::MissingParameter {
            name: "requested_token_type",
        },
    );
    // The refresh token type parses; whether it is enabled is the IdP's call.
    let request = request(&refresh_exchange_pairs());
    assert_eq!(
        request.requested_token_type(),
        RequestedTokenType::RefreshToken
    );
    assert_eq!(request.audience(), None);
}

#[test]
fn audience_is_required_for_an_id_jag() {
    for pairs in [without(pairs(), "audience"), set(pairs(), "audience", "")] {
        invalid_request(&pairs, &RejectReason::MissingParameter { name: "audience" });
    }
}

#[test]
fn more_than_one_audience_is_refused() {
    invalid_request(
        &add(pairs(), "audience", "https://other.example"),
        &RejectReason::RepeatedParameter { name: "audience" },
    );
}

#[test]
fn subject_token_and_its_type_are_required() {
    for name in ["subject_token", "subject_token_type"] {
        invalid_request(
            &without(pairs(), name),
            &RejectReason::MissingParameter { name },
        );
    }
}

#[test]
fn subject_token_type_must_be_id_token_saml2_or_refresh_token() {
    for unsupported in [
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:jwt",
        "urn:ietf:params:oauth:token-type:saml1",
        TOKEN_TYPE_ID_JAG,
    ] {
        invalid_request(
            &set(pairs(), "subject_token_type", unsupported),
            &RejectReason::UnsupportedSubjectTokenType,
        );
    }
    for (token_type, expected) in [
        (TOKEN_TYPE_ID_TOKEN, SubjectTokenType::IdToken),
        (TOKEN_TYPE_REFRESH_TOKEN, SubjectTokenType::RefreshToken),
        (TOKEN_TYPE_SAML2, SubjectTokenType::Saml2),
    ] {
        let request = request(&with_subject(pairs(), token_type, "YWJj"));
        assert_eq!(request.subject_token_type(), expected);
        assert_eq!(expected.as_str(), token_type);
    }
}

#[test]
fn actor_token_and_its_type_come_together() {
    invalid_request(
        &add(pairs(), "actor_token", "actor"),
        &RejectReason::ActorTokenTypeMismatch,
    );
    invalid_request(
        &add(pairs(), "actor_token_type", TOKEN_TYPE_ID_TOKEN),
        &RejectReason::ActorTokenTypeMismatch,
    );
    assert!(!request(&pairs()).has_actor_token());
}

#[test]
fn authorization_details_must_be_an_array_of_typed_objects() {
    for malformed in [
        "not json",
        r#"{"type":"todo"}"#,
        r#"["todo"]"#,
        r#"[{"actions":["read"]}]"#,
        r#"[{"type":7}]"#,
    ] {
        invalid_request(
            &add(pairs(), "authorization_details", malformed),
            &RejectReason::MalformedAuthorizationDetails,
        );
    }
}

#[test]
fn a_repeated_non_repeatable_parameter_is_refused() {
    for name in [
        "grant_type",
        "requested_token_type",
        "subject_token",
        "subject_token_type",
        "scope",
        "authorization_details",
        "actor_token",
        "actor_token_type",
    ] {
        invalid_request(
            &add(add(pairs(), name, "a"), name, "b"),
            &RejectReason::RepeatedParameter { name },
        );
    }
    // Credential parameters too.
    invalid_request(
        &add(pairs(), "client_id", "another"),
        &RejectReason::RepeatedParameter {
            name: "client credentials",
        },
    );
}

#[test]
fn resource_may_repeat_and_is_kept_in_order_byte_for_byte() {
    let values = [
        "https://API.resource.example/%7Euser/?q=a+b&c",
        RESOURCE,
        "https://api.resource.example",
    ];
    let mut pairs = pairs();
    for value in values {
        pairs = add(pairs, "resource", value);
    }
    assert_eq!(request(&pairs).resources(), values);
    // A parameter sent without a value is omitted (RFC 6749 §3.2).
    assert_eq!(
        request(&add(self::pairs(), "resource", ""))
            .resources()
            .len(),
        0
    );
}

#[test]
fn saml2_tokens_are_accepted_as_base64url_or_base64() {
    // The fixture has bytes that encode to `-_` / `+/` and needs padding.
    let standard = STANDARD.encode(SAML_XML);
    assert!(standard.contains('+') && standard.contains('/') && standard.ends_with('='));
    for encoded in [
        URL_SAFE_NO_PAD.encode(SAML_XML),
        URL_SAFE.encode(SAML_XML),
        standard,
        STANDARD_NO_PAD.encode(SAML_XML),
        // No alphabet-specific character at all.
        STANDARD.encode(b"<Assertion/>"),
    ] {
        let request = request(&with_subject(pairs(), TOKEN_TYPE_SAML2, &encoded));
        let SubjectTokenInput::Saml2(assertion) = request.subject_token() else {
            panic!("not a SAML subject token");
        };
        assert!(
            assertion.expose_secret() == SAML_XML || assertion.expose_secret() == b"<Assertion/>"
        );
    }
}

#[test]
fn saml2_tokens_mixing_alphabets_or_not_base64_are_refused() {
    let url_safe = URL_SAFE_NO_PAD.encode(SAML_XML);
    let mixed = url_safe.replacen('-', "+", 1);
    assert!(mixed.contains('+') && mixed.contains('_'));
    for malformed in [
        mixed.as_str(),
        "<saml:Assertion/>",
        "YWJj YWJj",
        "YWJj\nYWJj",
        "====",
    ] {
        invalid_request(
            &with_subject(pairs(), TOKEN_TYPE_SAML2, malformed),
            &RejectReason::MalformedSamlEncoding,
        );
    }
}

#[test]
fn malformed_scope_is_invalid_scope() {
    for malformed in ["a  b", " a", "a\"b", "a\\b"] {
        parse_error(
            &add(pairs(), "scope", malformed),
            &RejectReason::MalformedScope,
            &OAuthErrorCode::InvalidScope,
        );
    }
}

#[test]
fn two_client_authentication_methods_are_refused() {
    let pairs = add(
        add(pairs(), "client_assertion", "a.b.c"),
        "client_assertion_type",
        crate::client_auth::CLIENT_ASSERTION_TYPE_JWT_BEARER,
    );
    invalid_request(&pairs, &RejectReason::MultipleClientAuthMethods);
}

#[test]
fn unusable_client_credentials_are_invalid_client() {
    // A secret without a client_id.
    let error = parse_error(
        &without(pairs(), "client_id"),
        &RejectReason::MalformedClientCredentials,
        &OAuthErrorCode::InvalidClient,
    );
    assert_eq!(error.to_response().status, 400);

    // A broken Basic header: 401 with the challenge (RFC 6749 §5.2).
    let pairs = without(without(pairs(), "client_id"), "client_secret");
    let headers = vec![("Authorization".to_owned(), "Basic !!!".to_owned())];
    let error = TokenExchangeRequest::parse(&body(&pairs), &headers, None).unwrap_err();
    assert_eq!(error.reason(), &RejectReason::MalformedClientCredentials);
    let response = error.to_response();
    assert_eq!(response.status, 401);
    assert_eq!(response.header("www-authenticate"), Some("Basic"));
}

#[test]
fn a_certificate_that_is_not_der_is_a_caller_bug() {
    let error =
        TokenExchangeRequest::parse(&body(&pairs()), &[], Some(b"-----BEGIN CERTIFICATE-----"))
            .unwrap_err();
    assert_eq!(error.reason(), &RejectReason::InvalidClientCertificate);
    assert_eq!(error.code(), &OAuthErrorCode::ServerError);
    assert!(matches!(
        error.library_error(),
        Some(Error::InvalidConfiguration { .. })
    ));
}

#[test]
fn credentials_are_extracted_by_method() {
    let no_secret = without(pairs(), "client_secret");
    assert!(matches!(
        request(&no_secret).client_credentials(),
        ClientCredentials::None { client_id: Some(id) } if id == CLIENT
    ));
    let der = rfc_8705_certificate_der();
    let request = request_with(&no_secret, &[], Some(&der));
    assert!(matches!(
        request.client_credentials(),
        ClientCredentials::TlsClientAuth { client_id } if client_id == CLIENT
    ));
    assert_eq!(request.certificate_thumbprint(), Some(RFC_8705_THUMBPRINT));
}

// ----- §3 client authentication -----------------------------------------------------

#[tokio::test]
async fn an_unauthenticated_client_is_always_invalid_client() {
    // Even with a DPoP proof and a certificate: there is no
    // sender-constrained exception at the IdP.
    let idp = idp_with(|config| {
        config.dpop = true;
        config.mtls_binding = true;
    });
    let der = rfc_8705_certificate_der();
    let headers = dpop_headers(&dpop_key(), None).await;
    let request = request_with(&without(pairs(), "client_secret"), &headers, Some(&der));
    let unauthenticated = ClientIdentity::Unauthenticated {
        client_id: Some(CLIENT.to_owned()),
    };
    let outcome = idp
        .exchange(
            &request,
            &unauthenticated,
            &ok_subjects(),
            &supports_jwt_dpop(),
            &Echo,
            now(),
        )
        .await;
    let record = outcome.1.clone();
    let error = rejected(
        outcome,
        &RejectReason::ClientNotAuthenticated,
        &OAuthErrorCode::InvalidClient,
    );
    assert_eq!(error.to_response().status, 400);
    assert_eq!(record.client_id.as_deref(), Some(CLIENT));
    assert_eq!(record.audience.as_deref(), Some(RAS));
    assert_eq!(record.resolved_issuer, None);
}

#[tokio::test]
async fn invalid_client_after_basic_is_401_with_a_challenge() {
    let pairs = without(without(pairs(), "client_id"), "client_secret");
    let credentials = STANDARD.encode(format!("{CLIENT}:wrong"));
    let headers = vec![("authorization".to_owned(), format!("Basic {credentials}"))];
    let request = request_with(&pairs, &headers, None);
    assert!(matches!(
        request.client_credentials(),
        ClientCredentials::Basic { .. }
    ));

    // The caller's own refusal.
    let response = request.invalid_client().to_response();
    assert_eq!(response.status, 401);
    assert_eq!(response.header("www-authenticate"), Some("Basic"));

    // The library's refusal of an unauthenticated identity.
    let unauthenticated = ClientIdentity::Unauthenticated { client_id: None };
    let (result, record) = idp()
        .exchange(
            &request,
            &unauthenticated,
            &ok_subjects(),
            &directory(),
            &Echo,
            now(),
        )
        .await;
    let response = result.unwrap_err().to_response();
    assert_eq!(response.status, 401);
    assert_eq!(response.header("www-authenticate"), Some("Basic"));
    assert_eq!(record.client_id, None);

    // Without Basic it is a plain 400.
    let error = ExchangeError::invalid_client();
    assert_eq!(error.reason(), &RejectReason::ClientAuthenticationFailed);
    assert_eq!(error.code(), &OAuthErrorCode::InvalidClient);
    assert_eq!(error.to_response().status, 400);
    assert_eq!(
        self::request(&self::pairs())
            .invalid_client()
            .to_response()
            .status,
        400
    );
}

// ----- §4 subject tokens: happy paths -----------------------------------------------

#[tokio::test]
async fn an_id_token_is_exchanged_through_the_built_in_verifier() {
    let claims = json!({
        "iss": ISSUER,
        "sub": "idp-user-1",
        "aud": CLIENT,
        "exp": NOW_SECS + 300,
        "iat": NOW_SECS - 10,
        "auth_time": NOW_SECS - 600,
        "acr": "urn:example:mfa",
        "amr": ["pwd", "otp"],
    });
    let token = sign(&rsa_key(), None, &claims).await;
    let request = request(&add(
        with_subject(pairs(), TOKEN_TYPE_ID_TOKEN, &token),
        "resource",
        RESOURCE,
    ));
    let (result, record) = idp()
        .exchange(
            &request,
            &client(),
            &id_token_verifier(),
            &directory(),
            &Echo,
            now(),
        )
        .await;
    let issued = result.unwrap();
    let (_, payload) = decode(&issued);
    assert_eq!(payload["sub"], RAS_SUB);
    assert_eq!(payload["client_id"], RAS_CLIENT);
    assert_eq!(payload["auth_time"], NOW_SECS - 600);
    assert_eq!(payload["acr"], "urn:example:mfa");
    assert_eq!(payload["amr"], json!(["pwd", "otp"]));
    assert_eq!(payload["resource"], RESOURCE);
    assert!(matches!(record.outcome, ExchangeOutcome::Issued { .. }));
}

#[tokio::test]
async fn a_refresh_token_is_exchanged_through_the_callers_verifier() {
    let (result, record) = run(&idp(), &request(&pairs())).await;
    let issued = result.unwrap();
    assert_eq!(issued.claims().sub, RAS_SUB);
    assert_eq!(record.client_id.as_deref(), Some(CLIENT));
}

/// Records the assertion bytes it was handed.
struct SamlVerifier(Mutex<Vec<u8>>);

impl SubjectTokenVerifier for SamlVerifier {
    fn verify(
        &self,
        token: &SubjectTokenInput<'_>,
        _client: &AuthenticatedClient,
        _now: SystemTime,
    ) -> impl Future<Output = Result<VerifiedSubject, SubjectRejection>> + Send {
        let result = match token {
            SubjectTokenInput::Saml2(assertion) => {
                *self.0.lock().unwrap() = assertion.expose_secret().to_vec();
                Ok(saml_subject())
            }
            _ => Err(SubjectRejection::Invalid),
        };
        std::future::ready(result)
    }
}

#[tokio::test]
async fn a_saml_assertion_is_exchanged_through_the_callers_verifier() {
    let idp = idp_with(|config| config.saml_audiences = Some(saml_map()));
    // Standard base64, as in the draft §4.5 example.
    let pairs = with_subject(pairs(), TOKEN_TYPE_SAML2, &STANDARD.encode(SAML_XML));
    let verifier = SamlVerifier(Mutex::new(Vec::new()));
    let (result, _) = idp
        .exchange(
            &request(&pairs),
            &client(),
            &verifier,
            &directory(),
            &Echo,
            now(),
        )
        .await;
    assert_eq!(result.unwrap().claims().sub, RAS_SUB);
    // The verifier got the decoded XML.
    assert_eq!(*verifier.0.lock().unwrap(), SAML_XML);
}

// ----- §4.2 library-enforced subject checks -----------------------------------------

#[tokio::test]
async fn a_subject_token_typed_as_another_token_is_refused_whatever_the_verifier_says() {
    for typ in [
        "at+jwt",
        "oauth-id-jag+jwt",
        "dpop+jwt",
        "application/at+jwt",
        "AT+JWT",
        "client-authentication+jwt",
        "id_token",
    ] {
        let token = sign(&rsa_key(), Some(typ), &id_token_claims()).await;
        for token_type in [TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_REFRESH_TOKEN] {
            let request = request(&with_subject(pairs(), token_type, &token));
            // The verifier accepts everything.
            rejected(
                run(&idp(), &request).await,
                &RejectReason::SubjectTokenTypNotAllowed,
                &OAuthErrorCode::InvalidRequest,
            );
        }
    }
}

#[tokio::test]
async fn jwt_absent_and_allow_listed_typ_values_pass() {
    for typ in [None, Some("JWT"), Some("jwt"), Some("application/jwt")] {
        let token = sign(&rsa_key(), typ, &id_token_claims()).await;
        let request = request(&with_subject(pairs(), TOKEN_TYPE_ID_TOKEN, &token));
        run(&idp(), &request).await.0.unwrap();
    }
    let idp = idp_with(|config| config.id_token_typ_allow = vec!["id+jwt".to_owned()]);
    for typ in ["id+jwt", "ID+JWT", "application/id+jwt"] {
        let token = sign(&rsa_key(), Some(typ), &id_token_claims()).await;
        let request = request(&with_subject(pairs(), TOKEN_TYPE_ID_TOKEN, &token));
        run(&idp, &request).await.0.unwrap();
    }
}

#[tokio::test]
async fn an_id_token_issued_to_another_client_is_refused() {
    let token = sign(&rsa_key(), None, &id_token_claims()).await;
    let request = request(&with_subject(pairs(), TOKEN_TYPE_ID_TOKEN, &token));
    for issued_to in [Some("another-client".to_owned()), None] {
        let subjects = Subjects(Ok(VerifiedSubject {
            issued_to_client: issued_to,
            ..subject()
        }));
        rejected(
            run_subjects(&idp(), &request, &subjects).await,
            &RejectReason::SubjectTokenNotIssuedToClient,
            &OAuthErrorCode::InvalidRequest,
        );
    }
    // Through the built-in verifier too: `aud` names another client.
    let token = sign(
        &rsa_key(),
        None,
        &claims_with("aud", json!("another-client")),
    )
    .await;
    let request = self::request(&with_subject(pairs(), TOKEN_TYPE_ID_TOKEN, &token));
    let outcome = idp()
        .exchange(
            &request,
            &client(),
            &id_token_verifier(),
            &directory(),
            &Echo,
            now(),
        )
        .await;
    rejected(
        outcome,
        &RejectReason::SubjectTokenNotIssuedToClient,
        &OAuthErrorCode::InvalidRequest,
    );
}

#[tokio::test]
async fn a_refresh_token_bound_to_another_client_is_refused() {
    for issued_to in [Some("another-client".to_owned()), None] {
        let subjects = Subjects(Ok(VerifiedSubject {
            issued_to_client: issued_to,
            // A SAML audience does not stand in for the client binding.
            saml_audience: Some(SP_ENTITY_ID.to_owned()),
            ..subject()
        }));
        let idp = idp_with(|config| config.saml_audiences = Some(saml_map()));
        rejected(
            run_subjects(&idp, &request(&pairs()), &subjects).await,
            &RejectReason::SubjectTokenNotIssuedToClient,
            &OAuthErrorCode::InvalidRequest,
        );
    }
}

#[tokio::test]
async fn a_saml_assertion_whose_audience_does_not_map_to_the_client_is_refused() {
    let mapped = idp_with(|config| config.saml_audiences = Some(saml_map()));
    let request = request(&saml_pairs());
    for subject in [
        // Another SP's assertion.
        VerifiedSubject {
            saml_audience: Some("https://other.example/sp".to_owned()),
            ..saml_subject()
        },
        // No audience reported; an OAuth client binding does not replace it.
        VerifiedSubject {
            saml_audience: None,
            issued_to_client: Some(CLIENT.to_owned()),
            ..saml_subject()
        },
    ] {
        rejected(
            run_subjects(&mapped, &request, &Subjects(Ok(subject))).await,
            &RejectReason::SamlAudienceNotMapped,
            &OAuthErrorCode::InvalidRequest,
        );
    }
    // The SP maps to a different client.
    let other: Arc<dyn SamlAudienceMap> = Arc::new(std::collections::BTreeMap::from([(
        SP_ENTITY_ID.to_owned(),
        "another-client".to_owned(),
    )]));
    let idp = idp_with(|config| config.saml_audiences = Some(other));
    rejected(
        run_subjects(&idp, &request, &Subjects(Ok(saml_subject()))).await,
        &RejectReason::SamlAudienceNotMapped,
        &OAuthErrorCode::InvalidRequest,
    );
    // No map configured: fails closed.
    rejected(
        run_subjects(&self::idp(), &request, &Subjects(Ok(saml_subject()))).await,
        &RejectReason::SamlAudienceNotMapped,
        &OAuthErrorCode::InvalidRequest,
    );
    // The mapped pair passes.
    run_subjects(&mapped, &request, &Subjects(Ok(saml_subject())))
        .await
        .0
        .unwrap();
}

#[tokio::test]
async fn a_multi_tenant_issuer_needs_the_subjects_tenant() {
    let idp = idp_with(|config| config.tenancy = IdpTenancy::Multi);
    let error = rejected(
        run(&idp, &request(&pairs())).await,
        &RejectReason::MissingIssuerTenant,
        &OAuthErrorCode::ServerError,
    );
    assert!(matches!(
        error.library_error(),
        Some(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(error.to_response().status, 500);

    // With a tenant: it reaches the directory and becomes the `tenant` claim.
    let subjects = Subjects(Ok(VerifiedSubject {
        issuer_tenant: Some("tenant-a".to_owned()),
        ..subject()
    }));
    let directory = directory();
    let (result, _) = idp
        .exchange(
            &request(&pairs()),
            &client(),
            &subjects,
            &directory,
            &Echo,
            now(),
        )
        .await;
    assert_eq!(decode(&result.unwrap()).1["tenant"], "tenant-a");
    assert_eq!(
        *directory.seen_tenants.lock().unwrap(),
        [Some("tenant-a".to_owned())]
    );
}

#[tokio::test]
async fn a_token_the_verifier_rejects_is_invalid_request() {
    rejected(
        run_subjects(
            &idp(),
            &request(&pairs()),
            &Subjects(Err(SubjectRejection::Invalid)),
        )
        .await,
        &RejectReason::SubjectTokenRejected,
        &OAuthErrorCode::InvalidRequest,
    );
}

#[tokio::test]
async fn a_verifier_can_ask_for_step_up() {
    let subjects = Subjects(Err(SubjectRejection::StepUpRequired {
        max_age: Some(300),
        acr_values: Some("urn:example:mfa".to_owned()),
    }));
    let error = rejected(
        run_subjects(&idp(), &request(&pairs()), &subjects).await,
        &RejectReason::StepUpRequired,
        &OAuthErrorCode::InsufficientUserAuthentication,
    );
    let body = error_body(&error);
    assert_eq!(body.error, "insufficient_user_authentication");
    assert_eq!(body.max_age, Some(300));
    assert_eq!(body.acr_values.as_deref(), Some("urn:example:mfa"));
}

// ----- §4.3 built-in ID Token verifier ----------------------------------------------

#[tokio::test]
async fn id_token_verifier_accepts_a_valid_token() {
    let claims = json!({
        "iss": ISSUER,
        "sub": "idp-user-1",
        "aud": [CLIENT],
        "exp": NOW_SECS + 1,
        "iat": NOW_SECS,
        "nbf": NOW_SECS,
        "auth_time": NOW_SECS - 60,
        "acr": "urn:example:mfa",
        "amr": ["pwd"],
        "tenant": "tenant-a",
        "nonce": "ignored",
        "at_hash": "ignored",
    });
    let token = sign(&rsa_key(), None, &claims).await;
    let subject = verify_id_token(&token).await.unwrap();
    assert_eq!(
        subject,
        VerifiedSubject {
            subject: SubjectRef::new("user-1"),
            issued_to_client: Some(CLIENT.to_owned()),
            saml_audience: None,
            issuer_tenant: Some("tenant-a".to_owned()),
            auth_time: Some(NumericDate::from_secs(NOW_SECS - 60).unwrap()),
            acr: Some("urn:example:mfa".to_owned()),
            amr: Some(vec!["pwd".to_owned()]),
        }
    );
    assert_eq!(subject.subject.as_str(), "user-1");
}

#[tokio::test]
async fn id_token_verifier_requires_a_jws_signed_with_the_idps_own_key() {
    // Another key, under the same and under another `kid`.
    id_token_invalid(&other_rsa_key(), &id_token_claims()).await;
    id_token_invalid(&other_rsa_key().with_key_id("rsa-1"), &id_token_claims()).await;
    // An algorithm outside the policy.
    let es256 = IdTokenVerifier::new(
        Issuer::new(ISSUER),
        jwks_of(&[&p256_key()]),
        AlgorithmPolicy::only(&[SignatureAlgorithm::Rs256]),
        Duration::ZERO,
        map_subject as Mapper,
    );
    let token = IdToken::new(sign(&p256_key(), None, &id_token_claims()).await);
    assert_eq!(
        es256
            .verify(
                &SubjectTokenInput::IdToken(&token),
                &authenticated_client(),
                now()
            )
            .await
            .unwrap_err(),
        SubjectRejection::Invalid
    );
    // Not a JWS at all; a tampered payload.
    for token in ["opaque", "a.b.c", ""] {
        assert_eq!(
            verify_id_token(token).await.unwrap_err(),
            SubjectRejection::Invalid
        );
    }
    let good = sign(&rsa_key(), None, &id_token_claims()).await;
    let forged = sign(&other_rsa_key(), None, &claims_with("sub", json!("admin"))).await;
    let mut good_parts = good.split('.');
    let mut forged_parts = forged.split('.');
    let spliced = format!(
        "{}.{}.{}",
        good_parts.next().unwrap(),
        forged_parts.nth(1).unwrap(),
        good_parts.nth(1).unwrap()
    );
    assert_eq!(
        verify_id_token(&spliced).await.unwrap_err(),
        SubjectRejection::Invalid
    );
}

#[tokio::test]
async fn id_token_verifier_requires_its_own_issuer_byte_for_byte() {
    for iss in [
        json!("https://idp.example/"),
        json!("https://IDP.example"),
        json!("https://other.example"),
        json!(7),
    ] {
        id_token_invalid(&rsa_key(), &claims_with("iss", iss)).await;
    }
    id_token_invalid(&rsa_key(), &claims_without("iss")).await;
}

#[tokio::test]
async fn id_token_verifier_checks_the_time_window_within_the_skew() {
    // Skew is 30 s.
    for (name, value) in [
        ("exp", json!(NOW_SECS - 30)),
        ("exp", json!(NOW_SECS - 3600)),
        ("exp", json!("soon")),
        ("iat", json!(NOW_SECS + 31)),
        ("nbf", json!(NOW_SECS + 31)),
        ("iat", json!(-1)),
    ] {
        id_token_invalid(&rsa_key(), &claims_with(name, value)).await;
    }
    id_token_invalid(&rsa_key(), &claims_without("exp")).await;
    for (name, value) in [
        ("exp", json!(NOW_SECS - 29)),
        ("iat", json!(NOW_SECS + 30)),
        ("nbf", json!(NOW_SECS + 30)),
        // NOW_SECS + 0.5: a fractional NumericDate.
        ("exp", json!(1_794_657_600.5)),
    ] {
        let token = sign(&rsa_key(), None, &claims_with(name, value)).await;
        verify_id_token(&token).await.unwrap();
    }
}

#[tokio::test]
async fn id_token_verifier_applies_the_aud_azp_rule() {
    // Several audiences need an `azp` that names one of them.
    let several = json!([CLIENT, "https://rp.example"]);
    id_token_invalid(&rsa_key(), &claims_with("aud", several.clone())).await;
    let mut claims = claims_with("aud", several.clone());
    claims["azp"] = json!("someone-else");
    id_token_invalid(&rsa_key(), &claims).await;
    claims["azp"] = json!(7);
    id_token_invalid(&rsa_key(), &claims).await;
    // No audience at all.
    id_token_invalid(&rsa_key(), &claims_with("aud", json!([]))).await;
    id_token_invalid(&rsa_key(), &claims_with("aud", json!(7))).await;
    id_token_invalid(&rsa_key(), &claims_without("aud")).await;

    // `azp` is who the token was issued to.
    let mut claims = claims_with("aud", json!(["https://rp.example", CLIENT]));
    claims["azp"] = json!(CLIENT);
    let token = sign(&rsa_key(), None, &claims).await;
    assert_eq!(
        verify_id_token(&token)
            .await
            .unwrap()
            .issued_to_client
            .as_deref(),
        Some(CLIENT)
    );
    claims["azp"] = json!("https://rp.example");
    let token = sign(&rsa_key(), None, &claims).await;
    assert_eq!(
        verify_id_token(&token)
            .await
            .unwrap()
            .issued_to_client
            .as_deref(),
        Some("https://rp.example")
    );
}

#[tokio::test]
async fn id_token_verifier_needs_a_subject_the_caller_recognizes() {
    id_token_invalid(&rsa_key(), &claims_with("sub", json!("stranger"))).await;
    id_token_invalid(&rsa_key(), &claims_with("sub", json!(""))).await;
    id_token_invalid(&rsa_key(), &claims_without("sub")).await;
    // Malformed step-up claims are not passed through.
    id_token_invalid(&rsa_key(), &claims_with("auth_time", json!("then"))).await;
    id_token_invalid(&rsa_key(), &claims_with("acr", json!(2))).await;
    id_token_invalid(&rsa_key(), &claims_with("amr", json!("pwd"))).await;
}

#[tokio::test]
async fn id_token_verifier_sends_other_token_types_to_the_fallback() {
    let refresh = RefreshToken::new("opaque");
    let input = SubjectTokenInput::RefreshToken(&refresh);
    // The default fallback accepts nothing.
    assert_eq!(
        id_token_verifier()
            .verify(&input, &authenticated_client(), now())
            .await
            .unwrap_err(),
        SubjectRejection::Invalid
    );
    let verifier = id_token_verifier().with_fallback(ok_subjects());
    assert_eq!(
        verifier
            .verify(&input, &authenticated_client(), now())
            .await
            .unwrap(),
        subject()
    );
    // ID Tokens still go through the built-in checks, not the fallback.
    let bad = IdToken::new("opaque");
    assert_eq!(
        verifier
            .verify(
                &SubjectTokenInput::IdToken(&bad),
                &authenticated_client(),
                now()
            )
            .await
            .unwrap_err(),
        SubjectRejection::Invalid
    );
}

// ----- §5 audience, resource, scope -------------------------------------------------

#[tokio::test]
async fn an_unknown_audience_is_invalid_target() {
    let request = request(&set(pairs(), "audience", "https://unknown.example"));
    let outcome = run(&idp(), &request).await;
    let record = outcome.1.clone();
    rejected(
        outcome,
        &RejectReason::UnknownAudience,
        &OAuthErrorCode::InvalidTarget,
    );
    assert_eq!(record.audience.as_deref(), Some("https://unknown.example"));
    assert_eq!(record.resolved_issuer, None);
}

#[tokio::test]
async fn an_alias_resolves_and_aud_is_the_canonical_issuer() {
    let request = request(&set(pairs(), "audience", RAS_ALIAS));
    let (result, record) = run(&idp(), &request).await;
    let (_, payload) = decode(&result.unwrap());
    assert_eq!(payload["aud"], json!(RAS));
    assert_eq!(record.audience.as_deref(), Some(RAS_ALIAS));
    assert_eq!(record.resolved_issuer, Some(Issuer::new(RAS)));
}

#[tokio::test]
async fn policy_denials_map_to_their_error_codes() {
    let request = request(&pairs());
    for (denial, reason, code) in [
        (
            ExchangeDenial::AccessDenied,
            RejectReason::PolicyDenied,
            OAuthErrorCode::AccessDenied,
        ),
        (
            ExchangeDenial::InvalidTarget,
            RejectReason::PolicyInvalidTarget,
            OAuthErrorCode::InvalidTarget,
        ),
        (
            ExchangeDenial::InvalidScope,
            RejectReason::PolicyInvalidScope,
            OAuthErrorCode::InvalidScope,
        ),
    ] {
        let outcome = run_policy(&request, &Fixed(Err(denial))).await;
        assert_eq!(outcome.1.resolved_issuer, Some(Issuer::new(RAS)));
        rejected(outcome, &reason, &code);
    }
    let step_up = Fixed(Err(ExchangeDenial::StepUpRequired {
        max_age: None,
        acr_values: Some("urn:example:phr".to_owned()),
    }));
    let error = rejected(
        run_policy(&request, &step_up).await,
        &RejectReason::StepUpRequired,
        &OAuthErrorCode::InsufficientUserAuthentication,
    );
    let body = error_body(&error);
    assert_eq!(body.max_age, None);
    assert_eq!(body.acr_values.as_deref(), Some("urn:example:phr"));
}

/// Checks the context it is handed, then grants what was asked.
struct Inspect;

impl ExchangePolicy for Inspect {
    fn evaluate(
        &self,
        ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send {
        assert_eq!(ctx.client, &authenticated_client());
        assert_eq!(ctx.subject, &subject());
        assert_eq!(ctx.subject_token_type, SubjectTokenType::RefreshToken);
        assert_eq!(ctx.audience, RAS_ALIAS);
        assert_eq!(ctx.resource_as.issuer.as_str(), RAS);
        assert_eq!(ctx.resources, [RESOURCE]);
        assert_eq!(ctx.scope.unwrap().as_str(), "todos.read");
        assert_eq!(ctx.authorization_details.unwrap().0.len(), 1);
        assert_eq!(ctx.now, now());
        std::future::ready(Ok(echo_grant(ctx)))
    }
}

#[tokio::test]
async fn policy_sees_the_client_subject_target_and_request() {
    let pairs = add(
        add(
            add(set(pairs(), "audience", RAS_ALIAS), "resource", RESOURCE),
            "scope",
            "todos.read",
        ),
        "authorization_details",
        r#"[{"type":"todo"}]"#,
    );
    run_policy(&request(&pairs), &Inspect).await.0.unwrap();
}

// ----- §5.3 invariants on the grant -------------------------------------------------

#[tokio::test]
async fn a_requested_resource_the_resource_as_does_not_govern_is_invalid_target() {
    for ungoverned in [
        "https://evil.example/",
        // Byte-for-byte: no normalization.
        "https://api.resource.example",
        "https://API.resource.example/",
    ] {
        let pairs = add(add(pairs(), "resource", RESOURCE), "resource", ungoverned);
        rejected(
            run(&idp(), &request(&pairs)).await,
            &RejectReason::ResourceNotGoverned,
            &OAuthErrorCode::InvalidTarget,
        );
    }
}

#[tokio::test]
async fn resources_requested_and_none_granted_is_invalid_target() {
    let request = request(&add(pairs(), "resource", RESOURCE));
    rejected(
        run_policy(&request, &Fixed(Ok(grant()))).await,
        &RejectReason::NoResourceGranted,
        &OAuthErrorCode::InvalidTarget,
    );
}

#[tokio::test]
async fn a_resource_as_can_require_a_resource() {
    let directory = directory_with(|entry| entry.require_resource = true);
    rejected(
        run_directory(&idp(), &request(&pairs()), &directory).await,
        &RejectReason::ResourceRequired,
        &OAuthErrorCode::InvalidTarget,
    );
    let request = request(&add(pairs(), "resource", RESOURCE));
    run_directory(&idp(), &request, &directory).await.0.unwrap();
}

#[tokio::test]
async fn a_granted_resource_that_was_not_requested_is_a_caller_bug() {
    let request = request(&add(pairs(), "resource", RESOURCE));
    for extra in [
        // Governed, but not requested.
        RESOURCE_2,
        // Not byte-identical to the requested value.
        "https://api.resource.example",
    ] {
        let policy = grant_with(|grant| {
            grant.resources = vec![RESOURCE.to_owned(), extra.to_owned()];
        });
        let error = grant_bug(run_policy(&request, &policy).await);
        assert!(matches!(
            error.library_error(),
            Some(Error::GrantExceedsRequest { what: "resource" })
        ));
    }
    // A subset is fine.
    let both = self::request(&add(
        add(pairs(), "resource", RESOURCE),
        "resource",
        RESOURCE_2,
    ));
    let policy = grant_with(|grant| grant.resources = vec![RESOURCE_2.to_owned()]);
    assert_eq!(
        payload(run_policy(&both, &policy).await)["resource"],
        RESOURCE_2
    );
}

#[tokio::test]
async fn default_resources_must_be_governed() {
    let request = request(&pairs());
    let policy = grant_with(|grant| grant.resources = vec!["https://evil.example/".to_owned()]);
    let error = grant_bug(run_policy(&request, &policy).await);
    assert!(matches!(
        error.library_error(),
        Some(Error::GrantExceedsRequest { .. })
    ));
    let policy = grant_with(|grant| grant.resources = vec![RESOURCE.to_owned()]);
    assert_eq!(
        payload(run_policy(&request, &policy).await)["resource"],
        RESOURCE
    );
}

#[tokio::test]
async fn a_granted_scope_wider_than_requested_is_a_caller_bug() {
    let request = request(&add(pairs(), "scope", "todos.read todos.write"));
    let policy = grant_with(|grant| {
        grant.scope = Some(Scope::parse("todos.read admin").unwrap());
    });
    let error = grant_bug(run_policy(&request, &policy).await);
    assert!(matches!(
        error.library_error(),
        Some(Error::GrantExceedsRequest { what: "scope" })
    ));

    // Narrowing is fine, and the response says what was granted.
    let policy = grant_with(|grant| grant.scope = Some(Scope::parse("todos.read").unwrap()));
    let issued = run_policy(&request, &policy).await.0.unwrap();
    assert_eq!(decode(&issued).1["scope"], "todos.read");
    let body: Value = serde_json::from_slice(&issued.to_response().body).unwrap();
    assert_eq!(body["scope"], "todos.read");

    // With no scope requested, policy may grant a default.
    let policy = grant_with(|grant| grant.scope = Some(Scope::parse("todos.read").unwrap()));
    let issued = run_policy(&self::request(&pairs()), &policy)
        .await
        .0
        .unwrap();
    assert_eq!(decode(&issued).1["scope"], "todos.read");
}

#[tokio::test]
async fn granted_authorization_details_wider_than_requested_are_a_caller_bug() {
    let request = request(&add(
        pairs(),
        "authorization_details",
        r#"[{"type":"todo","actions":["read"]}]"#,
    ));
    let policy = grant_with(|grant| {
        grant.authorization_details = Some(
            AuthorizationDetails::from_json_str(r#"[{"type":"todo","actions":["read","write"]}]"#)
                .unwrap(),
        );
    });
    let error = grant_bug(run_policy(&request, &policy).await);
    assert!(matches!(
        error.library_error(),
        Some(Error::GrantExceedsRequest {
            what: "authorization_details"
        })
    ));
}

fn name_id() -> SamlNameId {
    SamlNameId {
        issuer: "https://idp.example/saml".to_owned(),
        nameid: "alice@example.com".to_owned(),
        nameid_format: None,
        name_qualifier: None,
        sp_name_qualifier: None,
        sp_provided_id: None,
    }
}

#[tokio::test]
async fn a_transient_name_id_is_a_caller_bug() {
    let directory = directory_with(|entry| entry.wants_saml_sub_id = true);
    let policy = grant_with(|grant| {
        grant.sub_id = Some(SamlNameId {
            nameid_format: Some(TRANSIENT.to_owned()),
            ..name_id()
        });
    });
    let outcome = idp()
        .exchange(
            &request(&pairs()),
            &client(),
            &ok_subjects(),
            &directory,
            &policy,
            now(),
        )
        .await;
    let error = grant_bug(outcome);
    assert!(matches!(
        error.library_error(),
        Some(Error::TransientNameId)
    ));
}

#[tokio::test]
async fn a_sub_id_for_a_resource_as_that_does_not_want_one_is_a_caller_bug() {
    let policy = grant_with(|grant| grant.sub_id = Some(name_id()));
    let error = grant_bug(run_policy(&request(&pairs()), &policy).await);
    assert!(matches!(error.library_error(), Some(Error::UnwantedSubId)));
}

#[tokio::test]
async fn reserved_extra_claims_and_empty_identifiers_are_caller_bugs() {
    let request = request(&pairs());
    for name in ["act", "aud", "cnf", "sub", "exp", "tenant"] {
        let policy = grant_with(|grant| {
            grant.extra_claims.insert(name.to_owned(), json!("x"));
        });
        let error = grant_bug(run_policy(&request, &policy).await);
        assert!(matches!(
            error.library_error(),
            Some(Error::InvalidConfiguration { .. })
        ));
    }
    for policy in [
        Fixed(Ok(ExchangeGrant::new("", RAS_SUB))),
        Fixed(Ok(ExchangeGrant::new(RAS_CLIENT, ""))),
    ] {
        let error = grant_bug(run_policy(&request, &policy).await);
        assert!(matches!(
            error.library_error(),
            Some(Error::InvalidConfiguration { .. })
        ));
    }
    // A duplicate granted resource cannot be emitted.
    let policy = grant_with(|grant| {
        grant.resources = vec![RESOURCE.to_owned(), RESOURCE.to_owned()];
    });
    grant_bug(run_policy(&request, &policy).await);
}

// ----- §6 sender constraining -------------------------------------------------------

#[tokio::test]
async fn a_valid_dpop_proof_binds_the_id_jag_to_the_proof_key() {
    let key = dpop_key();
    let request = request_with(&pairs(), &dpop_headers(&key, None).await, None);
    assert!(request.has_dpop_proof());
    let (result, record) = run_directory(&dpop_idp(), &request, &supports_jwt_dpop()).await;
    let issued = result.unwrap();
    assert_eq!(decode(&issued).1["cnf"], json!({"jkt": key.thumbprint()}));
    assert!(key.is_confirmed_by(issued.claims().cnf.as_ref()));
    let ExchangeOutcome::Issued { granted, .. } = record.outcome else {
        panic!("not issued");
    };
    assert_eq!(
        granted.confirmation,
        Some(Confirmation::Jkt(key.thumbprint().to_owned()))
    );
}

#[tokio::test]
async fn a_proof_for_a_resource_as_without_jwt_dpop_is_refused_by_default() {
    let request = request_with(&pairs(), &dpop_headers(&dpop_key(), None).await, None);
    // `supports_jwt_dpop` defaults to false: unknown counts as no.
    let outcome = run(&dpop_idp(), &request).await;
    assert_eq!(outcome.1.resolved_issuer, Some(Issuer::new(RAS)));
    let error = rejected(
        outcome,
        &RejectReason::AudienceLacksJwtDpop,
        &OAuthErrorCode::InvalidTarget,
    );
    let response = error.to_response();
    assert_eq!(response.status, 400);
    let body = error_body(&error);
    assert_eq!(body.error, "invalid_target");
    assert_eq!(
        body.error_description.as_deref(),
        Some("The audience does not accept DPoP-bound grants.")
    );

    // Also when a certificate could have been used instead: the client asked
    // for a DPoP binding, and nothing else is silently substituted.
    let idp = idp_with(|config| {
        config.dpop = true;
        config.mtls_binding = true;
    });
    let der = rfc_8705_certificate_der();
    let headers = dpop_headers(&dpop_key(), None).await;
    let request = request_with(&pairs(), &headers, Some(&der));
    let directory = directory_with(|entry| entry.binding_preference = BindingPreference::Mtls);
    rejected(
        run_directory(&idp, &request, &directory).await,
        &RejectReason::AudienceLacksJwtDpop,
        &OAuthErrorCode::InvalidTarget,
    );
}

#[tokio::test]
async fn bind_issues_a_dpop_bound_id_jag_for_a_resource_as_without_jwt_dpop() {
    let idp = idp_with(|config| {
        config.dpop = true;
        config.dpop_to_non_supporting_as = DpopToNonSupportingAs::Bind;
    });
    let key = dpop_key();
    let request = request_with(&pairs(), &dpop_headers(&key, None).await, None);
    assert_eq!(
        payload(run(&idp, &request).await)["cnf"],
        json!({"jkt": key.thumbprint()})
    );
}

#[tokio::test]
async fn a_certificate_binds_the_id_jag_when_mtls_binding_is_set() {
    let der = rfc_8705_certificate_der();
    let request = request_with(&pairs(), &[], Some(&der));
    let idp = idp_with(|config| config.mtls_binding = true);
    assert_eq!(
        payload(run(&idp, &request).await)["cnf"],
        json!({"x5t#S256": RFC_8705_THUMBPRINT})
    );
    // Without `mtls_binding` the certificate is only client authentication.
    assert_eq!(payload(run(&self::idp(), &request).await).get("cnf"), None);
}

#[tokio::test]
async fn a_proof_and_a_certificate_bind_to_one_of_them_never_both() {
    let idp = idp_with(|config| {
        config.dpop = true;
        config.mtls_binding = true;
    });
    let der = rfc_8705_certificate_der();
    let key = dpop_key();
    for (preference, expected) in [
        (BindingPreference::Dpop, json!({"jkt": key.thumbprint()})),
        (
            BindingPreference::Mtls,
            json!({"x5t#S256": RFC_8705_THUMBPRINT}),
        ),
    ] {
        let request = request_with(&pairs(), &dpop_headers(&key, None).await, Some(&der));
        let directory = directory_with(|entry| {
            entry.supports_jwt_dpop = true;
            entry.binding_preference = preference;
        });
        assert_eq!(
            payload(run_directory(&idp, &request, &directory).await)["cnf"],
            expected
        );
    }
}

#[tokio::test]
async fn an_invalid_dpop_proof_is_invalid_dpop_proof() {
    let key = dpop_key();
    // A proof for another URL.
    let wrong_htu = key
        .proof(
            &http::Method::POST,
            &Url::parse("https://idp.example/other").unwrap(),
            None,
            now(),
        )
        .await
        .unwrap();
    // A stale proof.
    let stale = key
        .proof(
            &http::Method::POST,
            &Url::parse(TOKEN_ENDPOINT).unwrap(),
            None,
            now().checked_sub(Duration::from_hours(1)).unwrap(),
        )
        .await
        .unwrap();
    let good = dpop_headers(&key, None).await;
    let two = [good.clone(), dpop_headers(&key, None).await].concat();
    for headers in [
        vec![("DPoP".to_owned(), wrong_htu)],
        vec![("dpop".to_owned(), stale)],
        vec![("DPoP".to_owned(), "not-a-jwt".to_owned())],
        two,
    ] {
        let request = request_with(&pairs(), &headers, None);
        let error = rejected(
            run_directory(&dpop_idp(), &request, &supports_jwt_dpop()).await,
            &RejectReason::InvalidDpopProof,
            &OAuthErrorCode::InvalidDpopProof,
        );
        assert!(error.library_error().is_some());
        assert_eq!(error_body(&error).error, "invalid_dpop_proof");
    }
}

#[tokio::test]
async fn without_a_proof_or_certificate_the_id_jag_is_unbound() {
    let (result, record) =
        run_directory(&dpop_idp(), &request(&pairs()), &supports_jwt_dpop()).await;
    let issued = result.unwrap();
    assert_eq!(decode(&issued).1.get("cnf"), None);
    assert_eq!(issued.claims().cnf, None);
    let ExchangeOutcome::Issued { granted, .. } = record.outcome else {
        panic!("not issued");
    };
    assert_eq!(granted.confirmation, None);
}

#[tokio::test]
async fn a_dpop_header_is_ignored_when_dpop_is_off() {
    let headers = vec![("DPoP".to_owned(), "not-a-jwt".to_owned())];
    let request = request_with(&pairs(), &headers, None);
    assert_eq!(payload(run(&idp(), &request).await).get("cnf"), None);
}

struct FixedNonce;

impl crate::dpop::DpopNonce for FixedNonce {
    fn current(&self, _now: SystemTime) -> String {
        "nonce-1".to_owned()
    }

    fn accept(&self, nonce: &str, _now: SystemTime) -> bool {
        nonce == "nonce-1"
    }
}

#[tokio::test]
async fn a_required_dpop_nonce_is_demanded_with_use_dpop_nonce() {
    let idp = idp_with(|config| {
        config.dpop = true;
        config.dpop_nonce = Some(Arc::new(FixedNonce));
    });
    let key = dpop_key();
    for nonce in [None, Some("stale")] {
        let request = request_with(&pairs(), &dpop_headers(&key, nonce).await, None);
        let error = rejected(
            run_directory(&idp, &request, &supports_jwt_dpop()).await,
            &RejectReason::DpopNonceRequired,
            &OAuthErrorCode::UseDpopNonce,
        );
        let response = error.to_response();
        assert_eq!(response.status, 400);
        assert_eq!(response.header("DPoP-Nonce"), Some("nonce-1"));
        assert_eq!(error_body(&error).error, "use_dpop_nonce");
    }
    let request = request_with(&pairs(), &dpop_headers(&key, Some("nonce-1")).await, None);
    run_directory(&idp, &request, &supports_jwt_dpop())
        .await
        .0
        .unwrap();
    // A request without any proof is not asked for one.
    run_directory(&idp, &self::request(&pairs()), &supports_jwt_dpop())
        .await
        .0
        .unwrap();
}

#[tokio::test]
async fn a_replayed_dpop_proof_is_refused_and_a_refused_request_does_not_burn_it() {
    let idp = idp_with(|config| {
        config.dpop = true;
        config.replay = Some(Arc::new(InMemoryReplayStore::new(16)));
    });
    let key = dpop_key();
    let request = request_with(&pairs(), &dpop_headers(&key, None).await, None);

    // Refused by policy: the proof `jti` is not recorded.
    let outcome = idp
        .exchange(
            &request,
            &client(),
            &ok_subjects(),
            &supports_jwt_dpop(),
            &Fixed(Err(ExchangeDenial::AccessDenied)),
            now(),
        )
        .await;
    outcome.0.unwrap_err();

    run_directory(&idp, &request, &supports_jwt_dpop())
        .await
        .0
        .unwrap();
    let error = rejected(
        run_directory(&idp, &request, &supports_jwt_dpop()).await,
        &RejectReason::InvalidDpopProof,
        &OAuthErrorCode::InvalidDpopProof,
    );
    assert!(matches!(
        error.library_error(),
        Some(Error::Replayed { .. })
    ));
}

// ----- §7 issuance ------------------------------------------------------------------

#[tokio::test]
async fn the_issued_id_jag_carries_exactly_the_specified_header_and_claims() {
    let idp = idp_with(|config| {
        config.tenancy = IdpTenancy::Multi;
        config.id_jag_lifetime = Duration::from_secs(120);
        config.mtls_binding = true;
    });
    let directory = directory_with(|entry| entry.wants_saml_sub_id = true);
    let subjects = Subjects(Ok(VerifiedSubject {
        issuer_tenant: Some("tenant-a".to_owned()),
        auth_time: Some(NumericDate::from_secs(NOW_SECS - 600).unwrap()),
        acr: Some("urn:example:mfa".to_owned()),
        amr: Some(vec!["pwd".to_owned(), "otp".to_owned()]),
        ..subject()
    }));
    let details =
        r#"[{"type":"todo","actions":["read"],"locations":["https://api.resource.example/"]}]"#;
    let policy = grant_with(|grant| {
        grant.resources = vec![RESOURCE_2.to_owned(), RESOURCE.to_owned()];
        grant.scope = Some(Scope::parse("todos.read").unwrap());
        grant.authorization_details = Some(AuthorizationDetails::from_json_str(details).unwrap());
        grant.aud_tenant = Some("ras-tenant-9".to_owned());
        grant.aud_sub = Some("ras-account-7".to_owned());
        grant.email = Some("alice@example.com".to_owned());
        grant.sub_id = Some(SamlNameId {
            nameid_format: Some(
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_owned(),
            ),
            sp_name_qualifier: Some("https://ras.example/sp".to_owned()),
            ..name_id()
        });
        grant
            .extra_claims
            .insert("department".to_owned(), json!("engineering"));
    });
    let pairs = add(
        add(
            add(
                add(
                    add(
                        add(set(pairs(), "audience", RAS_ALIAS), "resource", RESOURCE),
                        "resource",
                        RESOURCE_2,
                    ),
                    "scope",
                    "todos.read todos.write",
                ),
                "authorization_details",
                details,
            ),
            // Accepted and ignored: no `act` is ever emitted.
            "actor_token",
            "actor",
        ),
        "actor_token_type",
        TOKEN_TYPE_ID_TOKEN,
    );
    let der = rfc_8705_certificate_der();
    let request = request_with(&pairs, &[], Some(&der));
    let (result, record) = idp
        .exchange(&request, &client(), &subjects, &directory, &policy, now())
        .await;
    let issued = result.unwrap();

    let (header, payload) = decode(&issued);
    assert_eq!(
        header,
        json!({"alg": "RS256", "typ": "oauth-id-jag+jwt", "kid": "rsa-1"})
    );
    let jti = payload["jti"].as_str().unwrap().to_owned();
    // 128 random bits, base64url.
    assert_eq!(b64url_decode(&jti).unwrap().len(), 16);
    assert_eq!(
        payload,
        json!({
            "iss": ISSUER,
            "sub": RAS_SUB,
            "aud": RAS,
            "client_id": RAS_CLIENT,
            "jti": jti,
            "iat": NOW_SECS,
            "exp": NOW_SECS + 120,
            "resource": [RESOURCE_2, RESOURCE],
            "scope": "todos.read",
            "authorization_details": [{
                "type": "todo",
                "actions": ["read"],
                "locations": ["https://api.resource.example/"],
            }],
            "tenant": "tenant-a",
            "aud_tenant": "ras-tenant-9",
            "aud_sub": "ras-account-7",
            "email": "alice@example.com",
            "auth_time": NOW_SECS - 600,
            "acr": "urn:example:mfa",
            "amr": ["pwd", "otp"],
            "sub_id": {
                "format": "saml-nameid",
                "issuer": "https://idp.example/saml",
                "nameid": "alice@example.com",
                "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "sp_name_qualifier": "https://ras.example/sp",
            },
            "cnf": {"x5t#S256": RFC_8705_THUMBPRINT},
            "department": "engineering",
        })
    );
    // Time claims are JSON integers and `aud` is a single string.
    for name in ["iat", "exp", "auth_time"] {
        assert!(payload[name].is_u64(), "{name} is not an integer");
    }
    assert!(payload["aud"].is_string());

    // It verifies as an ID-JAG against the signer's public key.
    let jws =
        UnverifiedJws::parse(issued.id_jag().expose_secret(), &ParseLimits::default()).unwrap();
    let verified = verify::<IdJagClaims>(
        &jws,
        ExpectedTyp::IdJag,
        &jwks_of(&[&rsa_key()]),
        &AlgorithmPolicy::default_id_jag(),
    )
    .unwrap();
    assert_eq!(verified.claims(), issued.claims());
    assert!(matches!(
        verified.claims().sub_id,
        Some(SubjectIdentifier::SamlNameId(_))
    ));
    assert_eq!(verified.claims().act, None);
    assert_eq!(issued.expires_in(), Duration::from_secs(120));

    // The audit record names what was asked and what was granted, and holds
    // no token.
    assert_eq!(
        record,
        ExchangeRecord {
            at: now(),
            client_id: Some(CLIENT.to_owned()),
            audience: Some(RAS_ALIAS.to_owned()),
            resolved_issuer: Some(Issuer::new(RAS)),
            requested_resources: vec![RESOURCE.to_owned(), RESOURCE_2.to_owned()],
            requested_scope: Some(Scope::parse("todos.read todos.write").unwrap()),
            outcome: ExchangeOutcome::Issued {
                jti,
                granted: GrantedAccess {
                    client_id: RAS_CLIENT.to_owned(),
                    sub: RAS_SUB.to_owned(),
                    resources: vec![RESOURCE_2.to_owned(), RESOURCE.to_owned()],
                    scope: Some(Scope::parse("todos.read").unwrap()),
                    authorization_details: Some(
                        AuthorizationDetails::from_json_str(details).unwrap()
                    ),
                    confirmation: Some(Confirmation::X5tS256(RFC_8705_THUMBPRINT.to_owned())),
                    expires_at: NumericDate::from_secs(NOW_SECS + 120).unwrap(),
                },
            },
        }
    );
    assert!(!format!("{record:?}").contains(issued.id_jag().expose_secret()));
}

#[tokio::test]
async fn a_minimal_id_jag_omits_every_optional_claim() {
    // A sub-second `now` still yields integer times.
    let at = now().checked_add(Duration::from_millis(750)).unwrap();
    let (result, _) = idp()
        .exchange(
            &request(&pairs()),
            &client(),
            &ok_subjects(),
            &directory(),
            &Echo,
            at,
        )
        .await;
    let (_, payload) = decode(&result.unwrap());
    let jti = payload["jti"].clone();
    assert_eq!(
        payload,
        json!({
            "iss": ISSUER,
            "sub": RAS_SUB,
            "aud": RAS,
            "client_id": RAS_CLIENT,
            "jti": jti,
            "iat": NOW_SECS,
            "exp": NOW_SECS + 300,
        })
    );
}

#[tokio::test]
async fn resource_is_a_string_for_one_and_an_array_for_several() {
    let one = request(&add(pairs(), "resource", RESOURCE));
    assert_eq!(
        payload(run(&idp(), &one).await)["resource"],
        json!(RESOURCE)
    );
    let two = request(&add(
        add(pairs(), "resource", RESOURCE),
        "resource",
        RESOURCE_2,
    ));
    assert_eq!(
        payload(run(&idp(), &two).await)["resource"],
        json!([RESOURCE, RESOURCE_2])
    );
}

#[tokio::test]
async fn every_id_jag_gets_a_fresh_jti_and_the_signers_algorithm() {
    let request = request(&pairs());
    let first = payload(run(&idp(), &request).await);
    let second = payload(run(&idp(), &request).await);
    assert_ne!(first["jti"], second["jti"]);

    let idp = idp_with(|config| config.signer = Arc::new(p256_key()));
    let issued = run(&idp, &request).await.0.unwrap();
    assert_eq!(
        decode(&issued).0,
        json!({"alg": "ES256", "typ": "oauth-id-jag+jwt", "kid": "p256-1"})
    );
}

// ----- §8 SAML → Refresh Token ------------------------------------------------------

fn refresh_idp() -> Idp {
    idp_with(|config| {
        config.saml_refresh_exchange = true;
        config.saml_audiences = Some(saml_map());
    })
}

fn saml_subjects() -> Subjects {
    Subjects(Ok(saml_subject()))
}

#[tokio::test]
async fn a_saml_assertion_is_exchanged_for_a_refresh_token_the_caller_mints() {
    let pairs = add(refresh_exchange_pairs(), "scope", "openid offline_access");
    let request = request(&pairs);
    let (result, record) = refresh_idp()
        .exchange_saml_for_refresh_token(&request, &client(), &saml_subjects(), now())
        .await;
    let approved = result.unwrap();
    assert_eq!(approved.client(), &authenticated_client());
    assert_eq!(approved.subject(), &saml_subject());
    assert_eq!(
        approved.requested_scope().unwrap().as_str(),
        "openid offline_access"
    );
    assert_eq!(
        record,
        ExchangeRecord {
            at: now(),
            client_id: Some(CLIENT.to_owned()),
            audience: None,
            resolved_issuer: None,
            requested_resources: Vec::new(),
            requested_scope: Some(Scope::parse("openid offline_access").unwrap()),
            outcome: ExchangeOutcome::RefreshTokenApproved,
        }
    );

    let response = approved.token_response(
        &RefreshToken::new("vF9dft4qmTcXkZ26zL8b6u"),
        approved.requested_scope(),
        Some(Duration::from_hours(336)),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(response.header("pragma"), Some("no-cache"));
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap(),
        json!({
            "issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "access_token": "vF9dft4qmTcXkZ26zL8b6u",
            "token_type": "N_A",
            "scope": "openid offline_access",
            "expires_in": 1_209_600,
        })
    );
    let bare = approved.token_response(&RefreshToken::new("rt"), None, None);
    assert_eq!(
        serde_json::from_slice::<Value>(&bare.body).unwrap(),
        json!({
            "issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "access_token": "rt",
            "token_type": "N_A",
        })
    );
}

#[tokio::test]
async fn a_refresh_token_request_is_refused_when_the_exchange_is_off() {
    let request = request(&refresh_exchange_pairs());
    let idp = idp_with(|config| config.saml_audiences = Some(saml_map()));
    rejected(
        idp.exchange_saml_for_refresh_token(&request, &client(), &saml_subjects(), now())
            .await,
        &RejectReason::RefreshExchangeDisabled,
        &OAuthErrorCode::InvalidRequest,
    );
    // The ID-JAG method refuses it too, with or without the exchange.
    rejected(
        run_subjects(&idp, &request, &saml_subjects()).await,
        &RejectReason::RefreshExchangeDisabled,
        &OAuthErrorCode::InvalidRequest,
    );
    rejected(
        run_subjects(&refresh_idp(), &request, &saml_subjects()).await,
        &RejectReason::WrongRequestedTokenType,
        &OAuthErrorCode::InvalidRequest,
    );
    // And the refresh method refuses an ID-JAG request.
    rejected(
        refresh_idp()
            .exchange_saml_for_refresh_token(
                &self::request(&saml_pairs()),
                &client(),
                &saml_subjects(),
                now(),
            )
            .await,
        &RejectReason::WrongRequestedTokenType,
        &OAuthErrorCode::InvalidRequest,
    );
}

#[tokio::test]
async fn a_refresh_token_is_only_issued_for_a_saml_subject_token() {
    let token = sign(&rsa_key(), None, &id_token_claims()).await;
    for (token_type, token) in [
        (TOKEN_TYPE_ID_TOKEN, token.as_str()),
        (TOKEN_TYPE_REFRESH_TOKEN, "opaque"),
    ] {
        let request = request(&with_subject(refresh_exchange_pairs(), token_type, token));
        rejected(
            refresh_idp()
                .exchange_saml_for_refresh_token(&request, &client(), &ok_subjects(), now())
                .await,
            &RejectReason::RefreshExchangeRequiresSaml,
            &OAuthErrorCode::InvalidRequest,
        );
    }
}

#[tokio::test]
async fn the_refresh_exchange_enforces_authentication_verification_and_the_audience_mapping() {
    let request = request(&refresh_exchange_pairs());
    let idp = refresh_idp();

    let unauthenticated = ClientIdentity::Unauthenticated {
        client_id: Some(CLIENT.to_owned()),
    };
    rejected(
        idp.exchange_saml_for_refresh_token(&request, &unauthenticated, &saml_subjects(), now())
            .await,
        &RejectReason::ClientNotAuthenticated,
        &OAuthErrorCode::InvalidClient,
    );

    rejected(
        idp.exchange_saml_for_refresh_token(
            &request,
            &client(),
            &Subjects(Err(SubjectRejection::Invalid)),
            now(),
        )
        .await,
        &RejectReason::SubjectTokenRejected,
        &OAuthErrorCode::InvalidRequest,
    );

    let other_sp = Subjects(Ok(VerifiedSubject {
        saml_audience: Some("https://other.example/sp".to_owned()),
        ..saml_subject()
    }));
    rejected(
        idp.exchange_saml_for_refresh_token(&request, &client(), &other_sp, now())
            .await,
        &RejectReason::SamlAudienceNotMapped,
        &OAuthErrorCode::InvalidRequest,
    );

    // Another client presenting this SP's assertion.
    let another = ClientIdentity::Authenticated {
        client_id: "another-client".to_owned(),
        method: ClientAuthMethod::PrivateKeyJwt,
    };
    rejected(
        idp.exchange_saml_for_refresh_token(&request, &another, &saml_subjects(), now())
            .await,
        &RejectReason::SamlAudienceNotMapped,
        &OAuthErrorCode::InvalidRequest,
    );
}

// ----- §9 responses -----------------------------------------------------------------

#[tokio::test]
async fn the_success_response_follows_rfc_8693() {
    let pairs = add(
        add(pairs(), "scope", "todos.read"),
        "authorization_details",
        r#"[{"type":"todo"}]"#,
    );
    let issued = run(&idp(), &request(&pairs)).await.0.unwrap();
    let response = issued.to_response();
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(response.header("pragma"), Some("no-cache"));
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap(),
        json!({
            "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "access_token": issued.id_jag().expose_secret(),
            "token_type": "N_A",
            "expires_in": 300,
            "scope": "todos.read",
            "authorization_details": [{"type": "todo"}],
        })
    );

    // Nothing granted: no `scope`, no `authorization_details`, and never a
    // `refresh_token`.
    let issued = run(&idp(), &request(&self::pairs())).await.0.unwrap();
    let body: Value = serde_json::from_slice(&issued.to_response().body).unwrap();
    let mut members: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "access_token",
            "expires_in",
            "issued_token_type",
            "token_type"
        ]
    );
}

#[test]
fn error_responses_use_fixed_descriptions_and_no_store() {
    for (reason, code, status) in [
        (
            RejectReason::SubjectTokenNotIssuedToClient,
            OAuthErrorCode::InvalidRequest,
            400,
        ),
        (
            RejectReason::UnsupportedGrantType,
            OAuthErrorCode::UnsupportedGrantType,
            400,
        ),
        (
            RejectReason::ClientNotAuthenticated,
            OAuthErrorCode::InvalidClient,
            400,
        ),
        (
            RejectReason::UnknownAudience,
            OAuthErrorCode::InvalidTarget,
            400,
        ),
        (
            RejectReason::PolicyDenied,
            OAuthErrorCode::AccessDenied,
            400,
        ),
        (
            RejectReason::PolicyInvalidScope,
            OAuthErrorCode::InvalidScope,
            400,
        ),
        (
            RejectReason::StepUpRequired,
            OAuthErrorCode::InsufficientUserAuthentication,
            400,
        ),
        (
            RejectReason::InvalidDpopProof,
            OAuthErrorCode::InvalidDpopProof,
            400,
        ),
        (
            RejectReason::DpopNonceRequired,
            OAuthErrorCode::UseDpopNonce,
            400,
        ),
        (RejectReason::Internal, OAuthErrorCode::ServerError, 500),
    ] {
        assert_eq!(reason.code(), code);
        let error = ExchangeError::from(reason);
        let response = error.to_response();
        assert_eq!(response.status, status);
        assert_eq!(response.header("content-type"), Some("application/json"));
        assert_eq!(response.header("cache-control"), Some("no-store"));
        let body = error_body(&error);
        assert_eq!(body.error, code.as_str());
        // The description is the per-code constant: nothing about the
        // request or the End-User (draft §10).
        assert_eq!(
            body.error_description.as_deref(),
            Some(code.default_description())
        );
        assert_eq!(error.to_string(), format!("{code}: {}", error.reason()));
    }
}

// ----- §10 audit record -------------------------------------------------------------

#[test]
fn a_refusal_outside_the_exchange_can_be_recorded() {
    let error = parse(&without(pairs(), "audience")).unwrap_err();
    let record = ExchangeRecord::for_rejection(now(), Some(CLIENT), &error);
    assert_eq!(
        record,
        ExchangeRecord {
            at: now(),
            client_id: Some(CLIENT.to_owned()),
            audience: None,
            resolved_issuer: None,
            requested_resources: Vec::new(),
            requested_scope: None,
            outcome: ExchangeOutcome::Rejected {
                code: OAuthErrorCode::InvalidRequest,
                reason: RejectReason::MissingParameter { name: "audience" },
            },
        }
    );
}

// ----- §1, §11 configuration and metadata -------------------------------------------

#[test]
fn configuration_is_checked_at_construction() {
    let mut zero = config();
    zero.id_jag_lifetime = Duration::ZERO;
    let mut unmapped = config();
    unmapped.saml_refresh_exchange = true;
    let mut other_type = config();
    other_type.id_token_typ_allow = vec!["application/AT+jwt".to_owned()];
    for bad in [zero, unmapped, other_type] {
        assert!(matches!(
            Idp::new(bad).unwrap_err(),
            Error::InvalidConfiguration { .. }
        ));
    }

    let config = config();
    assert_eq!(config.id_jag_lifetime, Duration::from_mins(5));
    assert_eq!(config.tenancy, IdpTenancy::Single);
    assert!(!config.dpop && !config.mtls_binding && !config.saml_refresh_exchange);
    assert_eq!(
        config.dpop_to_non_supporting_as,
        DpopToNonSupportingAs::Reject
    );
    let idp = Idp::new(config).unwrap();
    assert_eq!(idp.config().issuer.as_str(), ISSUER);
    assert!(format!("{idp:?}").contains("rsa-1"));

    let entry = ResourceAsEntry::new(Issuer::new(RAS));
    assert!(!entry.supports_jwt_dpop && !entry.require_resource && !entry.wants_saml_sub_id);
}

#[test]
fn metadata_advertises_the_token_exchange_and_the_id_jag_type() {
    let jwks_uri = Url::parse("https://idp.example/jwks").unwrap();
    let metadata = idp().metadata_builder(jwks_uri.clone()).build().unwrap();
    assert_eq!(metadata.issuer.as_str(), ISSUER);
    assert_eq!(metadata.token_endpoint.unwrap().as_str(), TOKEN_ENDPOINT);
    assert_eq!(metadata.jwks_uri, Some(jwks_uri.clone()));
    assert_eq!(
        metadata.identity_chaining_requested_token_types_supported,
        Some(vec![TOKEN_TYPE_ID_JAG.to_owned()])
    );
    assert_eq!(
        metadata.grant_types_supported,
        Some(vec![GRANT_TYPE_TOKEN_EXCHANGE.to_owned()])
    );
    assert_eq!(metadata.id_jag_signing_alg_values_supported, None);
    assert_eq!(metadata.dpop_signing_alg_values_supported, None);

    // The §4.5 exchange and DPoP show up when enabled.
    let idp = idp_with(|config| {
        config.saml_refresh_exchange = true;
        config.saml_audiences = Some(saml_map());
        config.dpop = true;
    });
    let metadata = idp.metadata_builder(jwks_uri.clone()).build().unwrap();
    assert_eq!(
        metadata.identity_chaining_requested_token_types_supported,
        Some(vec![
            TOKEN_TYPE_ID_JAG.to_owned(),
            TOKEN_TYPE_REFRESH_TOKEN.to_owned()
        ])
    );
    assert_eq!(
        metadata.dpop_signing_alg_values_supported,
        Some(vec![
            "ES256".to_owned(),
            "ES384".to_owned(),
            "RS256".to_owned(),
            "PS256".to_owned()
        ])
    );
    let document = metadata.to_value();
    assert_eq!(document["jwks_uri"], "https://idp.example/jwks");

    // An algorithm list without RS256 is refused (draft §7.1 MUST).
    let builder = self::idp().metadata_builder(jwks_uri.clone());
    assert!(matches!(
        builder
            .id_jag_signing_algs(&[SignatureAlgorithm::Es256])
            .build()
            .unwrap_err(),
        Error::InvalidConfiguration { .. }
    ));
    let metadata = self::idp()
        .metadata_builder(jwks_uri)
        .id_jag_signing_algs(&[SignatureAlgorithm::Rs256, SignatureAlgorithm::Es256])
        .build()
        .unwrap();
    assert_eq!(
        metadata.id_jag_signing_alg_values_supported,
        Some(vec!["RS256".to_owned(), "ES256".to_owned()])
    );
}
