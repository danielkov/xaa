//! SAML subject tokens end to end, with the `saml` crate (RFC-005 §4.4,
//! draft §4.5).
//!
//! `saml` plays the SAML side of both parties: its IdP issues the sign-on
//! Response, its SP consumes it and hands back the verified assertion as a
//! standalone document, and its IdP later verifies that document when the
//! `xaa` IdP receives it as a `saml2` subject token. `xaa` never depends on
//! `saml` at runtime; the two meet behind `SubjectTokenVerifier`.

#![cfg(all(feature = "client", feature = "resource-as", feature = "idp"))]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use url::Url;

use xaa::Error;
use xaa::claims::{Issuer, SamlNameId, Scope, SubjectIdentifier};
use xaa::client::{
    AccessTokenRequest, ClientAuth, IdpConnection, Remediation, ResourceAsClientAuth,
    ResourceAsConnection, ResourceIdentifier, SamlEncoding, SamlToRefreshToken, SubjectToken,
    TokenExchange, exchange_for_id_jag, exchange_saml_for_refresh_token, request_access_token,
};
use xaa::client_auth::{ClientAuthMethod, ClientCredentials, ClientIdentity};
use xaa::http::{BoxError, HttpClient, HttpRequest, HttpResponse};
use xaa::idp::{
    AuthenticatedClient, ExchangeContext, ExchangeDenial, ExchangeGrant, ExchangePolicy, Idp,
    IdpConfig, RequestedTokenType, ResourceAsDirectory, ResourceAsEntry, SubjectRef,
    SubjectRejection, SubjectTokenInput, SubjectTokenVerifier, TokenExchangeRequest,
    VerifiedSubject,
};
use xaa::jose::{JwkSet, PrivateKey, SignatureAlgorithm};
use xaa::oauth_error::OAuthErrorCode;
use xaa::replay::InMemoryReplayStore;
use xaa::resource_as::{
    JtiPolicy, RecipientTenant, ResourceAs, ResourceAsConfig, ResourceRegistry, SamlIssuerTrust,
    SamlSubjectKey, SamlSubjectKeyValue, TokenError, TokenRequest, TrustedIssuer,
};
use xaa::secret::{AccessToken, ClientSecret, RefreshToken, SamlAssertion};

const IDP_ISSUER: &str = "https://idp.example";
const IDP_TOKEN: &str = "https://idp.example/token";
const RAS_ISSUER: &str = "https://auth.resource.example";
const RAS_TOKEN: &str = "https://auth.resource.example/token";
const API: &str = "https://api.resource.example/";

/// The same organisation runs SAML SSO and the OAuth token endpoint.
const SAML_IDP_ENTITY: &str = "https://idp.example/saml";
const SAML_IDP_SSO: &str = "https://idp.example/saml/sso";
/// The requesting app is a SAML SP towards the IdP, and an OAuth client
/// towards its token endpoint. The IdP keeps the mapping (draft §3.2.2).
const SP_ENTITY: &str = "https://wiki.example/saml";
const SP_ACS: &str = "https://wiki.example/saml/acs";
const CLIENT_AT_IDP: &str = "wiki-app";
const SECRET_AT_IDP: &str = "idp-secret";
const CLIENT_AT_RAS: &str = "wiki-app-at-todo";
const SECRET_AT_RAS: &str = "ras-secret";

const EMAIL_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const SKEW: Duration = Duration::from_secs(30);

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(498_516))
        .unwrap()
}

// ---------------------------------------------------------------------------
// The SAML side, entirely `saml`
// ---------------------------------------------------------------------------

fn saml_keypair() -> saml::KeyPair {
    saml::KeyPair::from_pkcs8_pem(include_bytes!("fixtures/saml_idp.key"))
        .unwrap()
        .with_certificate(
            saml::X509Certificate::from_pem(include_bytes!("fixtures/saml_idp.crt")).unwrap(),
        )
        .unwrap()
}

fn saml_idp() -> saml::IdentityProvider {
    use saml::dsig::algorithms::{
        C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
    };
    saml::IdentityProvider::new(saml::IdentityProviderConfig {
        entity_id: SAML_IDP_ENTITY.to_owned(),
        sso: vec![saml::Endpoint::post(SAML_IDP_SSO, 0, true)],
        slo: vec![],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![saml::NameIdFormat::EmailAddress],
        default_name_id_format: saml::NameIdFormat::EmailAddress,
        signing_key: saml_keypair(),
        decryption_key: None,
        want_authn_requests_signed: false,
        // The assertion must carry its own signature, or it cannot be
        // verified once it travels without the Response.
        assertion_signing: saml::IdpAssertionSigning {
            sign_responses: false,
            sign_assertions: true,
        },
        encrypt_assertions_when_possible: false,
        default_session_duration: Duration::from_hours(1),
        max_authn_request_age: saml::IdentityProviderConfig::DEFAULT_MAX_AUTHN_REQUEST_AGE,
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        verifier: None,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
    })
    .unwrap()
}

fn saml_sp() -> saml::ServiceProvider {
    use saml::dsig::algorithms::{DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm};
    saml::ServiceProvider::new(saml::ServiceProviderConfig {
        entity_id: SP_ENTITY.to_owned(),
        acs: vec![saml::SsoResponseEndpoint::post(SP_ACS, 0, true)],
        slo: vec![],
        name_id_formats: vec![saml::NameIdFormat::EmailAddress],
        signing_key: None,
        decryption_key: None,
        sign_authn_requests: false,
        want_signed: saml::SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: true,
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        verifier: None,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })
    .unwrap()
}

fn sp_descriptor() -> saml::SpDescriptor {
    let metadata = saml_sp().metadata_xml(false).unwrap();
    saml::SpDescriptor::from_metadata_xml(metadata.as_bytes()).unwrap()
}

/// SAML single sign-on for `alice@example.com`: the IdP issues a Response,
/// the SP consumes it and keeps the verified assertion.
fn sign_on() -> SamlAssertion {
    let idp = saml_idp();
    let sp = saml_sp();
    let idp_descriptor =
        saml::IdpDescriptor::from_metadata_xml(idp.metadata_xml(false).unwrap().as_bytes())
            .unwrap();
    let dispatch = idp
        .issue_unsolicited(saml::IssueUnsolicited {
            sp: &sp_descriptor(),
            acs_url: SP_ACS,
            name_id: saml::NameId::email("alice@example.com"),
            attributes: vec![],
            authn_instant: now(),
            session_index: "sso-1".to_owned(),
            session_not_on_or_after: None,
            authn_context_class_ref: saml::AuthnContextClassRef::PasswordProtectedTransport,
            requested_name_id_format: None,
            relay_state: None,
            force_encrypt_assertion: Some(false),
            now: now(),
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        })
        .unwrap();
    let saml::SsoResponseDispatch::Post(form) = dispatch else {
        panic!("expected a POST dispatch");
    };
    let response = STANDARD.decode(form.saml_response.as_bytes()).unwrap();
    let consumed = sp
        .consume_response_with_assertion(saml::ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &response,
            binding: saml::SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: None,
            expected_destination: SP_ACS,
            now: now(),
            clock_skew: SKEW,
            replay_cache: None,
            replay_mode: saml::ReplayMode::All,
            holder_of_key_cert: None,
        })
        .unwrap();
    assert_eq!(consumed.identity.name_id().value, "alice@example.com");
    let assertion = consumed.assertion.expect("the assertion is signed");
    SamlAssertion::new(assertion.into_xml().into_bytes())
}

// ---------------------------------------------------------------------------
// The adapter: `saml` behind `SubjectTokenVerifier` (RFC-005 §4.4)
// ---------------------------------------------------------------------------

struct SamlSubjects {
    idp: saml::IdentityProvider,
    /// OAuth client_id → the SP that client is.
    service_providers: HashMap<String, saml::SpDescriptor>,
}

impl SubjectTokenVerifier for SamlSubjects {
    fn verify(
        &self,
        token: &SubjectTokenInput<'_>,
        client: &AuthenticatedClient,
        now: SystemTime,
    ) -> impl Future<Output = Result<VerifiedSubject, SubjectRejection>> + Send {
        // `saml` verification is synchronous: no I/O, no clock.
        std::future::ready(self.verify_now(token, client, now))
    }
}

impl SamlSubjects {
    fn verify_now(
        &self,
        token: &SubjectTokenInput<'_>,
        client: &AuthenticatedClient,
        now: SystemTime,
    ) -> Result<VerifiedSubject, SubjectRejection> {
        let SubjectTokenInput::Saml2(assertion) = token else {
            return match token {
                SubjectTokenInput::RefreshToken(token) if token.expose_secret() == "rt-alice" => {
                    let mut subject = VerifiedSubject::new(SubjectRef::new("alice@example.com"));
                    subject.issued_to_client = Some(CLIENT_AT_IDP.to_owned());
                    Ok(subject)
                }
                _ => Err(SubjectRejection::Invalid),
            };
        };
        // The assertion is only acceptable from the client it was issued to:
        // verify it against that client's SP descriptor and no other.
        let sp = self
            .service_providers
            .get(&client.client_id)
            .ok_or(SubjectRejection::Invalid)?;
        let identity = self
            .idp
            .verify_issued_assertion(saml::VerifyIssuedAssertion {
                sp,
                crypto_policy: None,
                assertion: assertion.expose_secret(),
                retired_signing_certs: &[],
                now,
                clock_skew: SKEW,
            })
            .map_err(|_rejected| SubjectRejection::Invalid)?;
        let mut subject = VerifiedSubject::new(SubjectRef::new(identity.name_id().value.clone()));
        subject.saml_audience = Some(sp.entity_id.clone());
        Ok(subject)
    }
}

struct Directory;

impl ResourceAsDirectory for Directory {
    fn resolve_audience(
        &self,
        audience: &str,
        _issuer_tenant: Option<&str>,
    ) -> Option<ResourceAsEntry> {
        (audience == RAS_ISSUER).then(|| {
            let mut entry = ResourceAsEntry::new(Issuer::new(RAS_ISSUER));
            // This Resource AS finds its users by SAML NameID (draft §3.2.1).
            entry.wants_saml_sub_id = true;
            entry
        })
    }

    fn governs(&self, _ras: &ResourceAsEntry, resource: &str) -> bool {
        resource == API
    }
}

struct Policy;

impl ExchangePolicy for Policy {
    fn evaluate(
        &self,
        ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send {
        let mut grant = ExchangeGrant::new(CLIENT_AT_RAS, ctx.subject.subject.as_str());
        grant.resources = ctx.resources.to_vec();
        grant.scope = ctx.scope.cloned();
        // The NameID the Resource AS's own SAML SP would have received.
        grant.sub_id = Some(SamlNameId {
            issuer: SAML_IDP_ENTITY.to_owned(),
            nameid: ctx.subject.subject.as_str().to_owned(),
            nameid_format: Some(EMAIL_FORMAT.to_owned()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        });
        std::future::ready(Ok(grant))
    }
}

struct Registry;

impl ResourceRegistry for Registry {
    fn governs(&self, resource: &str, _tenant: &RecipientTenant) -> bool {
        resource == API
    }

    fn requires_sender_constraint(&self, _resource: &str, _tenant: &RecipientTenant) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Both servers behind one HttpClient
// ---------------------------------------------------------------------------

struct World {
    idp: Idp,
    ras: ResourceAs,
    subjects: SamlSubjects,
    idp_keys: JwkSet,
    replay: InMemoryReplayStore,
    /// What the Resource AS resolved the subject by.
    resolved: Mutex<Vec<SamlSubjectKeyValue>>,
}

impl World {
    fn new() -> Self {
        let signer = PrivateKey::from_pkcs8_pem(include_str!("fixtures/p256.pem"))
            .unwrap()
            .with_key_id("idp-ec");
        let idp_keys = JwkSet::from_keys(vec![
            signer
                .public_jwk()
                .with_algorithm(SignatureAlgorithm::Es256),
        ]);
        let mut idp_config = IdpConfig::new(
            Issuer::new(IDP_ISSUER),
            Url::parse(IDP_TOKEN).unwrap(),
            Arc::new(signer),
        );
        idp_config.saml_refresh_exchange = true;
        idp_config.saml_audiences = Some(Arc::new(HashMap::from([(
            SP_ENTITY.to_owned(),
            CLIENT_AT_IDP.to_owned(),
        )])));

        let mut trusted =
            TrustedIssuer::single_tenant(Issuer::new(IDP_ISSUER), RecipientTenant::new("acme"));
        trusted.saml_issuers = vec![SamlIssuerTrust {
            saml_issuer: SAML_IDP_ENTITY.to_owned(),
            subject_key: SamlSubjectKey::NameIdAndFormat,
        }];
        let mut ras_config = ResourceAsConfig::new(
            Issuer::new(RAS_ISSUER),
            Url::parse(RAS_TOKEN).unwrap(),
            JtiPolicy::SingleUse,
        );
        ras_config.trusted_issuers = vec![trusted];

        Self {
            idp: Idp::new(idp_config).unwrap(),
            ras: ResourceAs::new(ras_config).unwrap(),
            subjects: SamlSubjects {
                idp: saml_idp(),
                service_providers: HashMap::from([(CLIENT_AT_IDP.to_owned(), sp_descriptor())]),
            },
            idp_keys,
            replay: InMemoryReplayStore::new(64),
            resolved: Mutex::new(Vec::new()),
        }
    }

    fn authenticate(
        credentials: &ClientCredentials,
        client_id: &str,
        secret: &str,
    ) -> Option<ClientIdentity> {
        match credentials {
            ClientCredentials::Post {
                client_id: presented,
                secret: presented_secret,
            } if presented == client_id && presented_secret.expose_secret() == secret => {
                Some(ClientIdentity::Authenticated {
                    client_id: client_id.to_owned(),
                    method: ClientAuthMethod::ClientSecretPost,
                })
            }
            _ => None,
        }
    }

    async fn idp_token_endpoint(&self, request: &HttpRequest) -> HttpResponse {
        let exchange = match TokenExchangeRequest::parse(&request.body, &request.headers, None) {
            Ok(exchange) => exchange,
            Err(error) => return error.to_response(),
        };
        let Some(client) =
            Self::authenticate(exchange.client_credentials(), CLIENT_AT_IDP, SECRET_AT_IDP)
        else {
            return exchange.invalid_client().to_response();
        };
        if exchange.requested_token_type() == RequestedTokenType::RefreshToken {
            // Draft §4.5: SAML assertion in, refresh token out. The library
            // approves; the caller mints.
            let (result, _record) = self
                .idp
                .exchange_saml_for_refresh_token(&exchange, &client, &self.subjects, now())
                .await;
            return match result {
                Ok(approved) => approved.token_response(
                    &RefreshToken::new("rt-alice"),
                    approved.requested_scope(),
                    None,
                ),
                Err(error) => error.to_response(),
            };
        }
        let (result, _record) = self
            .idp
            .exchange(
                &exchange,
                &client,
                &self.subjects,
                &Directory,
                &Policy,
                now(),
            )
            .await;
        match result {
            Ok(issued) => issued.to_response(),
            Err(error) => error.to_response(),
        }
    }

    async fn ras_token_endpoint(&self, request: &HttpRequest) -> HttpResponse {
        let token_request = match TokenRequest::parse(&request.body, &request.headers, None) {
            Ok(token_request) => token_request,
            Err(error) => return error.to_response(),
        };
        let Some(client) = Self::authenticate(
            token_request.client_credentials(),
            CLIENT_AT_RAS,
            SECRET_AT_RAS,
        ) else {
            return TokenError::invalid_client_for(token_request.client_credentials())
                .to_response();
        };
        let keys: HashMap<Issuer, JwkSet> =
            HashMap::from([(Issuer::new(IDP_ISSUER), self.idp_keys.clone())]);
        let grant = match self
            .ras
            .validate(
                &token_request,
                &client,
                &keys,
                &Registry,
                Some(&self.replay),
                now(),
                SKEW,
            )
            .await
        {
            Ok(grant) => grant,
            Err(error) => return error.to_response(),
        };
        // Subject resolution is the caller's: by the trusted SAML NameID.
        let Some(key) = grant.saml_subject_key() else {
            return grant.decide(&Registry).deny().to_response();
        };
        self.resolved.lock().unwrap().push(key.clone());
        let mut decision = grant.decide(&Registry);
        if let Some(scope) = &grant.claims().scope {
            decision = decision.scope(scope.clone());
        }
        match decision.build() {
            Ok(decision) => decision.token_response(
                AccessToken::new(format!("at-{}", key.nameid)),
                Duration::from_hours(1),
            ),
            Err(error) => error.to_response(),
        }
    }
}

impl HttpClient for World {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BoxError> {
        Ok(match request.url.as_str() {
            IDP_TOKEN => self.idp_token_endpoint(&request).await,
            RAS_TOKEN => self.ras_token_endpoint(&request).await,
            _ => HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            },
        })
    }
}

fn idp_connection(saml_encoding: SamlEncoding) -> IdpConnection {
    IdpConnection {
        issuer: Issuer::new(IDP_ISSUER),
        token_endpoint: Url::parse(IDP_TOKEN).unwrap(),
        client_auth: ClientAuth::ClientSecretPost {
            client_id: CLIENT_AT_IDP.to_owned(),
            secret: ClientSecret::new(SECRET_AT_IDP),
        },
        saml_encoding,
    }
}

fn ras_connection() -> ResourceAsConnection {
    ResourceAsConnection {
        issuer: Issuer::new(RAS_ISSUER),
        token_endpoint: Url::parse(RAS_TOKEN).unwrap(),
        client_auth: ResourceAsClientAuth::Authenticated(ClientAuth::ClientSecretPost {
            client_id: CLIENT_AT_RAS.to_owned(),
            secret: ClientSecret::new(SECRET_AT_RAS),
        }),
        supports_jwt_dpop: false,
    }
}

async fn access_token_for(
    world: &World,
    idp: &IdpConnection,
    subject: &SubjectToken,
) -> Result<String, Error> {
    let ras = ras_connection();
    let mut exchange = TokenExchange::new(idp, &ras, subject, now());
    exchange.resources = vec![ResourceIdentifier::new(API)];
    exchange.scope = Some(Scope::parse("todos.read").unwrap());
    let issued = exchange_for_id_jag(world, &exchange).await?;
    let token = request_access_token(
        world,
        &AccessTokenRequest {
            resource_as: &ras,
            id_jag: &issued,
            scope: None,
            dpop: None,
            now: now(),
        },
    )
    .await?;
    Ok(token.access_token.expose_secret().to_owned())
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

/// SAML sign-on, then the assertion itself as the subject token. Both
/// encodings of `saml2` must work: RFC 8693 §3 says base64url, the draft
/// §4.5 example uses padded base64.
#[tokio::test]
async fn saml_assertion_to_access_token_in_both_encodings() {
    for encoding in [SamlEncoding::Base64Url, SamlEncoding::Base64] {
        let world = World::new();
        let subject = SubjectToken::SamlAssertion(sign_on());

        let token = access_token_for(&world, &idp_connection(encoding), &subject)
            .await
            .unwrap();
        assert_eq!(token, "at-alice@example.com");

        // The Resource AS resolved the user by the SAML NameID the IdP
        // asserted, under the SAML issuer it trusts for this IdP.
        let resolved = world.resolved.lock().unwrap().clone();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].saml_issuer, SAML_IDP_ENTITY);
        assert_eq!(resolved[0].nameid, "alice@example.com");
        assert_eq!(resolved[0].nameid_format.as_deref(), Some(EMAIL_FORMAT));
    }
}

/// Draft §4.5: exchange the assertion for a refresh token once, then use the
/// refresh token as the subject token from then on.
#[tokio::test]
async fn saml_assertion_to_refresh_token_to_access_token() {
    let world = World::new();
    let idp = idp_connection(SamlEncoding::default());
    let assertion = sign_on();

    let refresh_token = exchange_saml_for_refresh_token(
        &world,
        &SamlToRefreshToken::new(&idp, &assertion, now()).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(refresh_token.expose_secret(), "rt-alice");

    let token = access_token_for(&world, &idp, &SubjectToken::RefreshToken(refresh_token))
        .await
        .unwrap();
    assert_eq!(token, "at-alice@example.com");
}

/// A bearer assertion's confirmation window is minutes long. Presented after
/// it closes, the IdP refuses it and the client is told to sign on again.
#[tokio::test]
async fn expired_assertion_is_refused() {
    struct Later(World);

    impl HttpClient for Later {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BoxError> {
            let exchange =
                TokenExchangeRequest::parse(&request.body, &request.headers, None).unwrap();
            let client = ClientIdentity::Authenticated {
                client_id: CLIENT_AT_IDP.to_owned(),
                method: ClientAuthMethod::ClientSecretPost,
            };
            let later = now().checked_add(Duration::from_mins(30)).unwrap();
            let (result, _record) = self
                .0
                .idp
                .exchange(
                    &exchange,
                    &client,
                    &self.0.subjects,
                    &Directory,
                    &Policy,
                    later,
                )
                .await;
            Ok(match result {
                Ok(issued) => issued.to_response(),
                Err(error) => error.to_response(),
            })
        }
    }

    let world = Later(World::new());
    let idp = idp_connection(SamlEncoding::default());
    let ras = ras_connection();
    let subject = SubjectToken::SamlAssertion(sign_on());
    let mut exchange = TokenExchange::new(&idp, &ras, &subject, now());
    exchange.resources = vec![ResourceIdentifier::new(API)];

    let Error::TokenEndpoint(error) = exchange_for_id_jag(&world, &exchange).await.unwrap_err()
    else {
        panic!("expected a token endpoint error");
    };
    assert_eq!(error.code, OAuthErrorCode::InvalidRequest);
    assert_eq!(error.remediation(true), Remediation::ObtainNewSubjectToken);
}

/// The assertion was issued to the wiki app's SP. Verified against any other
/// SP descriptor, it is refused: an assertion is only good for the client it
/// was issued to.
#[tokio::test]
async fn assertion_issued_to_another_sp_is_refused() {
    let mut world = World::new();
    let mut other_sp = sp_descriptor();
    other_sp.entity_id = "https://other.example/saml".to_owned();
    world.subjects.service_providers = HashMap::from([(CLIENT_AT_IDP.to_owned(), other_sp)]);
    let subject = SubjectToken::SamlAssertion(sign_on());

    let error = access_token_for(&world, &idp_connection(SamlEncoding::default()), &subject)
        .await
        .unwrap_err();
    let Error::TokenEndpoint(error) = error else {
        panic!("expected a token endpoint error");
    };
    assert_eq!(error.code, OAuthErrorCode::InvalidRequest);
    assert_eq!(world.resolved.lock().unwrap().len(), 0);
}

/// The typed claim carries the NameID through unchanged.
#[tokio::test]
async fn issued_id_jag_carries_the_saml_nameid() {
    let world = World::new();
    let idp = idp_connection(SamlEncoding::default());
    let ras = ras_connection();
    let subject = SubjectToken::SamlAssertion(sign_on());
    let mut exchange = TokenExchange::new(&idp, &ras, &subject, now());
    exchange.resources = vec![ResourceIdentifier::new(API)];
    let request = exchange.build().await.unwrap();

    let exchange_request =
        TokenExchangeRequest::parse(&request.body, &request.headers, None).unwrap();
    let client = ClientIdentity::Authenticated {
        client_id: CLIENT_AT_IDP.to_owned(),
        method: ClientAuthMethod::ClientSecretPost,
    };
    let (result, _record) = world
        .idp
        .exchange(
            &exchange_request,
            &client,
            &world.subjects,
            &Directory,
            &Policy,
            now(),
        )
        .await;
    let issued = result.unwrap();
    assert!(matches!(
        &issued.claims().sub_id,
        Some(SubjectIdentifier::SamlNameId(nameid))
            if nameid.issuer == SAML_IDP_ENTITY && nameid.nameid == "alice@example.com"
    ));
}
