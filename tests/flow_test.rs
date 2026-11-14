//! Cross-role flow tests (RFC-001 §9, tier 2).
//!
//! The `client`, `idp`, and `resource-as` components run in one process. The
//! client talks to the two servers through an [`HttpClient`] that routes each
//! request to the matching component, so every byte crosses the same
//! serialize / parse boundary it would on the wire.

#![cfg(all(feature = "client", feature = "resource-as", feature = "idp"))]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use url::Url;

use xaa::Error;
use xaa::claims::{Confirmation, Issuer, Scope};
use xaa::client::{
    AccessTokenRequest, AccessTokenType, ClientAuth, IdpConnection, IssuedIdJag, Remediation,
    ResourceAsClientAuth, ResourceAsConnection, ResourceIdentifier, SamlEncoding, SubjectToken,
    TokenExchange, discover_idp, discover_resource, discover_resource_as, exchange_for_id_jag,
    request_access_token,
};
use xaa::client_auth::{ClientAuthMethod, ClientCredentials, ClientIdentity};
use xaa::dpop::{DpopKey, DpopRequest};
use xaa::http::{BoxError, HttpClient, HttpRequest, HttpResponse};
use xaa::idp::{
    AuthenticatedClient, ExchangeContext, ExchangeDenial, ExchangeGrant, ExchangeOutcome,
    ExchangePolicy, ExchangeRecord, IdTokenSubject, IdTokenVerifier, Idp, IdpConfig,
    ResourceAsDirectory, ResourceAsEntry, SubjectRef, SubjectRejection, SubjectTokenInput,
    SubjectTokenVerifier, TokenExchangeRequest, VerifiedSubject,
};
use xaa::jose::{AlgorithmPolicy, JwkSet, JwsSigner, PrivateKey, SignatureAlgorithm};
use xaa::metadata::{FetchOptions, PrmOrigin};
use xaa::oauth_error::OAuthErrorCode;
use xaa::replay::InMemoryReplayStore;
use xaa::resource_as::{
    JtiPolicy, RecipientTenant, ResourceAs, ResourceAsConfig, ResourceRegistry, TokenRequest,
    TrustedIssuer,
};
use xaa::secret::{AccessToken, ClientSecret, IdToken, RefreshToken};

const IDP_ISSUER: &str = "https://idp.example";
const IDP_TOKEN: &str = "https://idp.example/token";
const IDP_JWKS: &str = "https://idp.example/jwks";
const RAS_ISSUER: &str = "https://auth.resource.example";
const RAS_TOKEN: &str = "https://auth.resource.example/token";
/// With a trailing slash, as the xaa.dev playground publishes it.
const API: &str = "https://api.resource.example/";

/// The client holds two independent registrations (draft §5).
const CLIENT_AT_IDP: &str = "wiki-app";
const SECRET_AT_IDP: &str = "idp-secret";
const CLIENT_AT_RAS: &str = "wiki-app-at-todo";
const SECRET_AT_RAS: &str = "ras-secret";

const SKEW: Duration = Duration::from_secs(30);

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(498_516))
        .unwrap()
}

fn idp_key() -> PrivateKey {
    PrivateKey::from_pkcs8_pem(include_str!("fixtures/rsa2048.pem"))
        .unwrap()
        .with_key_id("idp-1")
}

/// Sign a JWT with the public API only: the crate deliberately has no
/// general-purpose "sign these claims" entry point.
async fn sign_jwt(key: &PrivateKey, claims: &Value) -> String {
    let header = json!({"alg": key.algorithm().as_str(), "kid": key.key_id()});
    let mut token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap()));
    let signature = key.sign(token.as_bytes()).await.unwrap();
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    token
}

/// An ID Token the IdP issued to `audience` for `alice`.
async fn id_token_for(audience: &str) -> SubjectToken {
    let iat = 1_794_657_500_u64;
    let token = sign_jwt(
        &idp_key(),
        &json!({
            "iss": IDP_ISSUER,
            "sub": "alice",
            "aud": audience,
            "iat": iat,
            "exp": iat + 3600,
            "email": "alice@example.com",
        }),
    )
    .await;
    SubjectToken::IdToken(IdToken::new(token))
}

// ---------------------------------------------------------------------------
// IdP-side caller code
// ---------------------------------------------------------------------------

/// Accepts the refresh token `rt-alice`, bound to the IdP-side client.
struct RefreshTokens;

impl SubjectTokenVerifier for RefreshTokens {
    fn verify(
        &self,
        token: &SubjectTokenInput<'_>,
        _client: &AuthenticatedClient,
        _now: SystemTime,
    ) -> impl Future<Output = Result<VerifiedSubject, SubjectRejection>> + Send {
        let result = match token {
            SubjectTokenInput::RefreshToken(token) if token.expose_secret() == "rt-alice" => {
                let mut subject = VerifiedSubject::new(SubjectRef::new("alice"));
                subject.issued_to_client = Some(CLIENT_AT_IDP.to_owned());
                Ok(subject)
            }
            _ => Err(SubjectRejection::Invalid),
        };
        std::future::ready(result)
    }
}

struct Directory {
    supports_jwt_dpop: bool,
}

impl ResourceAsDirectory for Directory {
    fn resolve_audience(
        &self,
        audience: &str,
        _issuer_tenant: Option<&str>,
    ) -> Option<ResourceAsEntry> {
        (audience == RAS_ISSUER).then(|| {
            let mut entry = ResourceAsEntry::new(Issuer::new(RAS_ISSUER));
            entry.supports_jwt_dpop = self.supports_jwt_dpop;
            entry
        })
    }

    fn governs(&self, _ras: &ResourceAsEntry, resource: &str) -> bool {
        resource == API
    }
}

/// Grants what was asked, but never the `todos.admin` scope.
struct Policy;

impl ExchangePolicy for Policy {
    fn evaluate(
        &self,
        ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send {
        let result = if ctx.scope.is_some_and(|scope| scope.contains("todos.admin")) {
            Err(ExchangeDenial::AccessDenied)
        } else {
            let mut grant = ExchangeGrant::new(CLIENT_AT_RAS, ctx.subject.subject.as_str());
            grant.resources = ctx.resources.to_vec();
            grant.scope = ctx.scope.cloned();
            grant.email = Some("alice@example.com".to_owned());
            Ok(grant)
        };
        std::future::ready(result)
    }
}

// ---------------------------------------------------------------------------
// Resource-AS-side caller code
// ---------------------------------------------------------------------------

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
// The world: both servers behind one HttpClient
// ---------------------------------------------------------------------------

struct World {
    idp: Idp,
    ras: ResourceAs,
    directory: Directory,
    idp_keys: JwkSet,
    ras_replay: InMemoryReplayStore,
    records: Mutex<Vec<ExchangeRecord>>,
    requests: Mutex<Vec<String>>,
    minted: Mutex<u32>,
}

impl World {
    fn new(dpop: bool) -> Self {
        let signer = idp_key();
        let idp_keys = JwkSet::from_keys(vec![
            signer
                .public_jwk()
                .with_algorithm(SignatureAlgorithm::Rs256),
        ]);
        let mut idp_config = IdpConfig::new(
            Issuer::new(IDP_ISSUER),
            Url::parse(IDP_TOKEN).unwrap(),
            Arc::new(signer),
        );
        idp_config.dpop = dpop;
        idp_config.replay = Some(Arc::new(InMemoryReplayStore::new(1024)));

        let mut ras_config = ResourceAsConfig::new(
            Issuer::new(RAS_ISSUER),
            Url::parse(RAS_TOKEN).unwrap(),
            JtiPolicy::SingleUse,
        );
        ras_config.trusted_issuers = vec![TrustedIssuer::single_tenant(
            Issuer::new(IDP_ISSUER),
            RecipientTenant::new("acme"),
        )];

        Self {
            idp: Idp::new(idp_config).unwrap(),
            ras: ResourceAs::new(ras_config).unwrap(),
            directory: Directory {
                supports_jwt_dpop: dpop,
            },
            idp_keys,
            ras_replay: InMemoryReplayStore::new(1024),
            records: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            minted: Mutex::new(0),
        }
    }

    fn idp_connection() -> IdpConnection {
        IdpConnection {
            issuer: Issuer::new(IDP_ISSUER),
            token_endpoint: Url::parse(IDP_TOKEN).unwrap(),
            client_auth: ClientAuth::ClientSecretPost {
                client_id: CLIENT_AT_IDP.to_owned(),
                secret: ClientSecret::new(SECRET_AT_IDP),
            },
            saml_encoding: SamlEncoding::default(),
        }
    }

    fn ras_connection(supports_jwt_dpop: bool) -> ResourceAsConnection {
        ResourceAsConnection {
            issuer: Issuer::new(RAS_ISSUER),
            token_endpoint: Url::parse(RAS_TOKEN).unwrap(),
            client_auth: ResourceAsClientAuth::Authenticated(ClientAuth::ClientSecretBasic {
                client_id: CLIENT_AT_RAS.to_owned(),
                secret: ClientSecret::new(SECRET_AT_RAS),
            }),
            supports_jwt_dpop,
        }
    }

    fn requests_to(&self, prefix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|url| url.starts_with(prefix))
            .count()
    }

    fn last_record(&self) -> ExchangeRecord {
        self.records.lock().unwrap().last().cloned().unwrap()
    }

    /// The caller's part of client authentication: check the secret.
    fn authenticate(
        credentials: &ClientCredentials,
        client_id: &str,
        secret: &str,
    ) -> Option<ClientIdentity> {
        let (presented_id, presented_secret, method) = match credentials {
            ClientCredentials::Post { client_id, secret } => {
                (client_id, secret, ClientAuthMethod::ClientSecretPost)
            }
            ClientCredentials::Basic { client_id, secret } => {
                (client_id, secret, ClientAuthMethod::ClientSecretBasic)
            }
            _ => return None,
        };
        (presented_id == client_id && presented_secret.expose_secret() == secret).then(|| {
            ClientIdentity::Authenticated {
                client_id: client_id.to_owned(),
                method,
            }
        })
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
        let subjects = IdTokenVerifier::new(
            Issuer::new(IDP_ISSUER),
            self.idp_keys.clone(),
            AlgorithmPolicy::default_id_jag(),
            SKEW,
            |claims: &xaa::idp::IdTokenClaims| {
                Some(IdTokenSubject {
                    subject: SubjectRef::new(claims.sub.as_str()),
                    issuer_tenant: None,
                })
            },
        )
        .with_fallback(RefreshTokens);
        let (result, record) = self
            .idp
            .exchange(
                &exchange,
                &client,
                &subjects,
                &self.directory,
                &Policy,
                now(),
            )
            .await;
        self.records.lock().unwrap().push(record);
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
            return xaa::resource_as::TokenError::invalid_client_for(
                token_request.client_credentials(),
            )
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
                Some(&self.ras_replay),
                now(),
                SKEW,
            )
            .await
        {
            Ok(grant) => grant,
            Err(error) => return error.to_response(),
        };
        // Caller policy: grant the scope the ID-JAG carries, narrowed to what
        // the client asked for on this request.
        let mut decision = grant.decide(&Registry);
        if let Some(scope) = grant.requested_scope().or(grant.claims().scope.as_ref()) {
            decision = decision.scope(scope.clone());
        }
        let decision = match decision.build() {
            Ok(decision) => decision,
            Err(error) => return error.to_response(),
        };
        let serial = {
            let mut minted = self.minted.lock().unwrap();
            *minted = minted.checked_add(1).unwrap();
            *minted
        };
        decision.token_response(
            AccessToken::new(format!("at-{}-{serial}", grant.claims().sub)),
            Duration::from_hours(2),
        )
    }

    fn json(value: &Value) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(value).unwrap(),
        }
    }

    async fn route(&self, request: HttpRequest) -> HttpResponse {
        self.requests
            .lock()
            .unwrap()
            .push(request.url.as_str().to_owned());
        match request.url.as_str() {
            IDP_TOKEN => self.idp_token_endpoint(&request).await,
            RAS_TOKEN => self.ras_token_endpoint(&request).await,
            // Like the xaa.dev playground, the IdP serves OIDC discovery only.
            "https://idp.example/.well-known/openid-configuration" => Self::json(
                &self
                    .idp
                    .metadata_builder(Url::parse(IDP_JWKS).unwrap())
                    .build()
                    .unwrap()
                    .to_value(),
            ),
            "https://auth.resource.example/.well-known/oauth-authorization-server" => {
                Self::json(&self.ras.metadata().build().unwrap().to_value())
            }
            "https://api.resource.example/.well-known/oauth-protected-resource" => {
                Self::json(&json!({
                    "resource": API,
                    "authorization_servers": [RAS_ISSUER],
                    "scopes_supported": ["todos.read", "todos.write"],
                }))
            }
            _ => HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            },
        }
    }
}

impl HttpClient for World {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BoxError> {
        Ok(self.route(request).await)
    }
}

fn exchange<'a>(
    idp: &'a IdpConnection,
    ras: &'a ResourceAsConnection,
    subject: &'a SubjectToken,
    scope: &str,
) -> TokenExchange<'a> {
    let mut exchange = TokenExchange::new(idp, ras, subject, now());
    exchange.resources = vec![ResourceIdentifier::new(API)];
    exchange.scope = Some(Scope::parse(scope).unwrap());
    exchange
}

fn token_endpoint_error(error: Error) -> xaa::client::TokenEndpointError {
    match error {
        Error::TokenEndpoint(error) => *error,
        other => panic!("expected a token endpoint error, got {other:?}"),
    }
}

async fn id_jag(world: &World, scope: &str) -> (IssuedIdJag, ResourceAsConnection) {
    let idp = World::idp_connection();
    let ras = World::ras_connection(false);
    let subject = id_token_for(CLIENT_AT_IDP).await;
    let issued = exchange_for_id_jag(world, &exchange(&idp, &ras, &subject, scope))
        .await
        .unwrap();
    (issued, ras)
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn id_token_to_bearer_access_token() {
    let world = World::new(false);
    let (issued, ras) = id_jag(&world, "todos.read todos.write").await;

    // What the client can see of its own grant.
    assert_eq!(issued.peek.issuer().as_str(), IDP_ISSUER);
    assert_eq!(issued.peek.client_id(), CLIENT_AT_RAS);
    assert_eq!(issued.peek.confirmation(), None);
    assert_eq!(
        issued.scope.as_ref().map(Scope::as_str),
        Some("todos.read todos.write")
    );

    // The IdP recorded what it issued (draft §9.2).
    let record = world.last_record();
    assert_eq!(record.client_id.as_deref(), Some(CLIENT_AT_IDP));
    assert_eq!(record.audience.as_deref(), Some(RAS_ISSUER));
    assert_eq!(record.requested_resources, [API]);
    assert!(matches!(record.outcome, ExchangeOutcome::Issued { .. }));

    // Downscope at the Resource AS.
    let token = request_access_token(
        &world,
        &AccessTokenRequest {
            resource_as: &ras,
            id_jag: &issued,
            scope: Some(Scope::parse("todos.read").unwrap()),
            dpop: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(token.access_token.expose_secret(), "at-alice-1");
    assert_eq!(token.token_type, AccessTokenType::Bearer);
    assert!(!token.is_sender_constrained());
    assert_eq!(token.scope.as_ref().map(Scope::as_str), Some("todos.read"));
    assert_eq!(token.expires_in, Some(Duration::from_hours(2)));
    assert!(token.refresh_token.is_none());
}

#[tokio::test]
async fn dpop_binds_the_grant_and_the_access_token() {
    let world = World::new(true);
    let idp = World::idp_connection();
    let ras = World::ras_connection(true);
    let subject = id_token_for(CLIENT_AT_IDP).await;
    let key = DpopKey::generate(SignatureAlgorithm::Es256).unwrap();
    let dpop = DpopRequest {
        key: &key,
        nonce: None,
    };

    let mut request = exchange(&idp, &ras, &subject, "todos.read");
    request.dpop = Some(dpop);
    let issued = exchange_for_id_jag(&world, &request).await.unwrap();
    assert_eq!(
        issued.peek.confirmation(),
        Some(&Confirmation::Jkt(key.thumbprint().to_owned()))
    );

    let access_request = AccessTokenRequest {
        resource_as: &ras,
        id_jag: &issued,
        scope: None,
        dpop: Some(dpop),
        now: now(),
    };
    let token = request_access_token(&world, &access_request).await.unwrap();
    assert_eq!(token.token_type, AccessTokenType::DPoP);
    assert!(token.is_sender_constrained());

    // Another key cannot redeem the bound grant: the client refuses to build
    // the request at all.
    let thief = DpopKey::generate(SignatureAlgorithm::Es256).unwrap();
    let stolen = AccessTokenRequest {
        dpop: Some(DpopRequest {
            key: &thief,
            nonce: None,
        }),
        ..access_request
    };
    assert!(matches!(
        stolen.build().await.unwrap_err(),
        Error::DpopKeyRequired
    ));
}

#[tokio::test]
async fn refresh_token_subject() {
    let world = World::new(false);
    let idp = World::idp_connection();
    let ras = World::ras_connection(false);
    let subject = SubjectToken::RefreshToken(RefreshToken::new("rt-alice"));

    let issued = exchange_for_id_jag(&world, &exchange(&idp, &ras, &subject, "todos.read"))
        .await
        .unwrap();
    let token = request_access_token(
        &world,
        &AccessTokenRequest {
            resource_as: &ras,
            id_jag: &issued,
            scope: None,
            dpop: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(token.access_token.expose_secret(), "at-alice-1");
}

#[tokio::test]
async fn single_use_grant_cannot_be_redeemed_twice() {
    let world = World::new(false);
    let (mut issued, ras) = id_jag(&world, "todos.read").await;
    fn request<'a>(
        ras: &'a ResourceAsConnection,
        id_jag: &'a IssuedIdJag,
    ) -> AccessTokenRequest<'a> {
        AccessTokenRequest {
            resource_as: ras,
            id_jag,
            scope: None,
            dpop: None,
            now: now(),
        }
    }

    request_access_token(&world, &request(&ras, &issued))
        .await
        .unwrap();
    issued.mark_presented();

    let error = token_endpoint_error(
        request_access_token(&world, &request(&ras, &issued))
            .await
            .unwrap_err(),
    );
    assert_eq!(error.code, OAuthErrorCode::InvalidGrant);
    // A re-presented grant was refused: fetch a new one (draft §4.4.4).
    assert_eq!(error.remediation(issued.fresh), Remediation::ObtainNewIdJag);
}

#[tokio::test]
async fn id_token_issued_to_another_client_is_refused() {
    let world = World::new(false);
    let idp = World::idp_connection();
    let ras = World::ras_connection(false);
    let subject = id_token_for("some-other-app").await;

    let error = token_endpoint_error(
        exchange_for_id_jag(&world, &exchange(&idp, &ras, &subject, "todos.read"))
            .await
            .unwrap_err(),
    );
    assert_eq!(error.code, OAuthErrorCode::InvalidRequest);
    assert_eq!(error.remediation(true), Remediation::ObtainNewSubjectToken);
    assert!(matches!(
        world.last_record().outcome,
        ExchangeOutcome::Rejected { .. }
    ));
    assert_eq!(world.requests_to(RAS_TOKEN), 0);
}

#[tokio::test]
async fn policy_denial_is_not_remediable_by_the_client() {
    let world = World::new(false);
    let idp = World::idp_connection();
    let ras = World::ras_connection(false);
    let subject = id_token_for(CLIENT_AT_IDP).await;

    let error = token_endpoint_error(
        exchange_for_id_jag(&world, &exchange(&idp, &ras, &subject, "todos.admin"))
            .await
            .unwrap_err(),
    );
    assert_eq!(error.code, OAuthErrorCode::AccessDenied);
    assert_eq!(error.remediation(true), Remediation::NotRemediableByClient);
}

/// The classic integration mistake: configuring the IdP-side client ID for
/// the Resource AS. The client catches it from the ID-JAG before any
/// credential reaches the Resource AS.
#[tokio::test]
async fn wrong_resource_as_registration_is_caught_before_sending() {
    let world = World::new(false);
    let idp = World::idp_connection();
    let mut ras = World::ras_connection(false);
    ras.client_auth = ResourceAsClientAuth::Authenticated(ClientAuth::ClientSecretBasic {
        client_id: CLIENT_AT_IDP.to_owned(),
        secret: ClientSecret::new(SECRET_AT_IDP),
    });
    let subject = id_token_for(CLIENT_AT_IDP).await;

    let error = exchange_for_id_jag(&world, &exchange(&idp, &ras, &subject, "todos.read"))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::IdJagClientIdMismatch), "{error:?}");
    assert_eq!(world.requests_to(RAS_TOKEN), 0);
}

#[tokio::test]
async fn dpop_for_a_resource_as_without_jwt_dpop() {
    // The IdP accepts DPoP proofs, but its directory says this Resource AS
    // does not support the jwt-dpop grant.
    let mut world = World::new(true);
    world.directory.supports_jwt_dpop = false;
    let idp = World::idp_connection();
    let subject = id_token_for(CLIENT_AT_IDP).await;
    let key = DpopKey::generate(SignatureAlgorithm::Es256).unwrap();
    let dpop = Some(DpopRequest {
        key: &key,
        nonce: None,
    });

    // A correctly configured client never sends the proof.
    let honest = World::ras_connection(false);
    let mut request = exchange(&idp, &honest, &subject, "todos.read");
    request.dpop = dpop;
    assert!(matches!(
        request.build().await.unwrap_err(),
        Error::ResourceAsLacksJwtDpop
    ));
    assert_eq!(world.requests_to(IDP_TOKEN), 0);

    // A misconfigured one does, and the IdP refuses rather than issue a
    // bound grant the Resource AS might accept as a bearer grant.
    let mistaken = World::ras_connection(true);
    let mut request = exchange(&idp, &mistaken, &subject, "todos.read");
    request.dpop = dpop;
    let error = token_endpoint_error(exchange_for_id_jag(&world, &request).await.unwrap_err());
    assert_eq!(error.code, OAuthErrorCode::InvalidTarget);
    assert_eq!(error.remediation(true), Remediation::ChangeRequest);
}

#[tokio::test]
async fn discovery_then_flow() {
    let world = World::new(false);
    let options = FetchOptions::default();

    // Start from the resource URL, as an agent or MCP client would.
    let resource = discover_resource(&world, PrmOrigin::ResourceIdentifier(API), &options)
        .await
        .unwrap();
    assert_eq!(resource.resource.as_str(), API);
    let ras_issuer = resource.metadata.authorization_servers()[0].clone();

    let discovered_ras = discover_resource_as(&world, &ras_issuer, &options)
        .await
        .unwrap();
    assert!(discovered_ras.id_jag_profile.is_advertised());
    let ras = discovered_ras.connection(ResourceAsClientAuth::Authenticated(
        ClientAuth::ClientSecretBasic {
            client_id: CLIENT_AT_RAS.to_owned(),
            secret: ClientSecret::new(SECRET_AT_RAS),
        },
    ));

    // RFC 8414 location first, then the OIDC fallback.
    let discovered_idp = discover_idp(&world, &Issuer::new(IDP_ISSUER), &options)
        .await
        .unwrap();
    assert!(discovered_idp.issues_id_jag.is_advertised());
    assert_eq!(
        world.requests_to("https://idp.example/.well-known/"),
        2,
        "one 404, then the OIDC document"
    );
    let idp = discovered_idp.connection(ClientAuth::ClientSecretPost {
        client_id: CLIENT_AT_IDP.to_owned(),
        secret: ClientSecret::new(SECRET_AT_IDP),
    });

    let subject = id_token_for(CLIENT_AT_IDP).await;
    let mut request = TokenExchange::new(&idp, &ras, &subject, now());
    request.resources = vec![resource.resource];
    request.scope = Some(Scope::parse("todos.read").unwrap());
    let issued = exchange_for_id_jag(&world, &request).await.unwrap();
    let token = request_access_token(
        &world,
        &AccessTokenRequest {
            resource_as: &ras,
            id_jag: &issued,
            scope: None,
            dpop: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(token.access_token.expose_secret(), "at-alice-1");
}
