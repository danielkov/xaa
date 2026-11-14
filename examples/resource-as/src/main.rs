//! XAA Resource Authorization Server: validates ID-JAGs at the jwt-bearer grant and issues access tokens.
//!
//! Serves, on `http://127.0.0.1:$XAA_RESOURCE_AS_PORT`:
//!
//! - `POST /token`: the jwt-bearer / jwt-dpop grant with an ID-JAG as the
//!   assertion (`xaa::resource_as`), answered with an opaque access token.
//! - `GET /.well-known/oauth-authorization-server`: RFC 8414 metadata.
//! - `GET /api/todos` and `GET /.well-known/oauth-protected-resource`: a tiny
//!   protected resource, so the demo has something to call.
//!
//! The protected resource is in this binary only to keep the demo to three
//! processes. The Resource Server role is **outside the `xaa` crate**: the
//! token lookup, the scope check and the DPoP `ath` check in the last section
//! of this file are plain caller code, not library features.
//!
//! Everything is in memory. Configuration is read from the environment; see
//! `examples/README.md`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use url::Url;

use xaa::claims::{Issuer, Scope};
use xaa::client_auth::{ClientAuthMethod, ClientCredentials, ClientIdentity};
use xaa::dpop::{DEFAULT_MAX_AGE, DpopValidation, validate_dpop_proof};
use xaa::http::{BoxError, HttpResponse, ReqwestClient};
use xaa::jose::{AlgorithmPolicy, JwkSet};
use xaa::metadata::{
    FetchOptions, ProtectedResourceMetadata, fetch_authorization_server_metadata, fetch_jwks,
};
use xaa::replay::InMemoryReplayStore;
use xaa::resource_as::{
    AccessTokenBinding, JtiPolicy, RecipientTenant, RejectReason, ResourceAs, ResourceAsConfig,
    ResourceRegistry, SamlIssuerTrust, SamlSubjectKey, TokenError, TokenRequest, TrustedIssuer,
    VerifiedGrant,
};
use xaa::secret::AccessToken;

/// Tolerance for clock differences between this server, the IdP and clients.
const CLOCK_SKEW: Duration = Duration::from_secs(30);
const ACCESS_TOKEN_LIFETIME: Duration = Duration::from_hours(2);
/// The IdP's JWK Set is refetched for an unknown `kid` at most this often.
/// Without a limit, anyone able to send assertions with random `kid` values
/// could make this server hammer the IdP's JWKS endpoint.
const MIN_JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(10);
/// The scopes of the todo API.
const SCOPES: [&str; 2] = ["todos.read", "todos.write"];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Demo configuration, from the environment with localhost defaults. The
/// credentials are fake constants: never reuse them.
struct Config {
    port: u16,
    /// This server's issuer identifier: the only accepted ID-JAG `aud`.
    issuer: String,
    /// The protected resource this server issues tokens for. Has a trailing
    /// slash, as the xaa.dev playground's does; compared byte-for-byte.
    resource: String,
    /// The one IdP whose ID-JAGs are accepted.
    idp_issuer: String,
    /// The requesting app's registration here. It is not the app's client
    /// ID at the IdP (draft §5.1).
    client_id: String,
    client_secret: String,
    /// Refuse to issue or accept bearer tokens for the todo API.
    require_dpop: bool,
    /// Give any subject the trusted IdP vouches for an (empty) account,
    /// instead of only the two demo users. For trying the server against an
    /// IdP whose users it has never seen, such as the xaa.dev playground.
    accept_any_subject: bool,
    /// SAML issuers (entity IDs) the IdP may name in a `sub_id` (draft
    /// §9.8). Empty by default, which refuses every SAML-derived ID-JAG.
    saml_issuers: Vec<String>,
    /// Browser origins allowed to call this server cross-origin. Empty by
    /// default; the xaa.dev tester calls from `https://xaa.dev`.
    cors_origins: Vec<String>,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// A comma-separated list from the environment; empty when unset.
fn list_env(name: &str) -> Vec<String> {
    env_or(name, "")
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

impl Config {
    fn from_env() -> Result<Self, BoxError> {
        let port: u16 = env_or("XAA_RESOURCE_AS_PORT", "4001").parse()?;
        let issuer = env_or(
            "XAA_RESOURCE_AS_ISSUER",
            &format!("http://127.0.0.1:{port}"),
        );
        Ok(Self {
            port,
            resource: env_or("XAA_RESOURCE", &format!("{issuer}/")),
            issuer,
            idp_issuer: env_or("XAA_IDP_ISSUER", "http://127.0.0.1:4000"),
            client_id: env_or("XAA_RESOURCE_AS_CLIENT_ID", "demo-app-at-todos"),
            client_secret: env_or(
                "XAA_RESOURCE_AS_CLIENT_SECRET",
                "demo-resource-as-secret-not-a-real-secret",
            ),
            require_dpop: matches!(env_or("XAA_REQUIRE_DPOP", "0").as_str(), "1" | "true"),
            accept_any_subject: matches!(
                env_or("XAA_ACCEPT_ANY_SUBJECT", "0").as_str(),
                "1" | "true"
            ),
            saml_issuers: list_env("XAA_SAML_ISSUERS"),
            cors_origins: list_env("XAA_CORS_ORIGINS"),
        })
    }
}

// ---------------------------------------------------------------------------
// The caller-supplied pieces of `xaa::resource_as`
// ---------------------------------------------------------------------------

/// The protected resources this server governs.
struct Registry {
    resource: String,
    require_dpop: bool,
}

impl ResourceRegistry for Registry {
    fn governs(&self, resource: &str, _tenant: &RecipientTenant) -> bool {
        resource == self.resource
    }

    fn requires_sender_constraint(&self, _resource: &str, _tenant: &RecipientTenant) -> bool {
        self.require_dpop
    }
}

/// The IdP's JWK Set, as last fetched. The library never fetches keys during
/// validation and holds no cache: both are the caller's.
struct CachedKeys {
    keys: HashMap<Issuer, JwkSet>,
    fetched_at: Instant,
}

/// An access token this server issued. The token is opaque: everything it
/// stands for is in this record.
#[derive(Clone)]
struct IssuedToken {
    account: String,
    client_id: String,
    scope: Option<Scope>,
    resources: Vec<String>,
    expires_at: SystemTime,
    /// The sender constraint the token request proved, if any.
    binding: Option<AccessTokenBinding>,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct App {
    config: Config,
    ras: ResourceAs,
    registry: Registry,
    /// For metadata and JWK Set fetches. Never follows redirects.
    http: ReqwestClient,
    fetch: FetchOptions,
    idp_keys: tokio::sync::Mutex<Option<CachedKeys>>,
    /// ID-JAG `jti` values and DPoP proof `jti` values seen at `/token`.
    replay: InMemoryReplayStore,
    tokens: Mutex<HashMap<String, IssuedToken>>,
    /// DPoP proof `jti` values seen at the todo API.
    api_replay: InMemoryReplayStore,
    api_dpop_algorithms: AlgorithmPolicy,
    todos_url: Url,
    resource_metadata_url: String,
    /// Pre-rendered documents.
    metadata: Value,
    protected_resource_metadata: Value,
}

impl App {
    fn new(config: Config) -> Result<Self, BoxError> {
        let issuer = Issuer::new(config.issuer.as_str());
        let token_endpoint = Url::parse(&format!("{}/token", config.issuer))?;

        // Single use: each ID-JAG buys one access token (draft §4.4.4 allows
        // either policy; the library makes the caller choose).
        let mut ras_config =
            ResourceAsConfig::new(issuer.clone(), token_endpoint, JtiPolicy::SingleUse);
        let mut trusted = TrustedIssuer::single_tenant(
            Issuer::new(config.idp_issuer.as_str()),
            RecipientTenant::new("demo"),
        );
        // A NameID is only unique within its SAML issuer and qualifiers, so
        // the account key uses all of them (draft §3.2.2).
        trusted.saml_issuers = config
            .saml_issuers
            .iter()
            .map(|saml_issuer| SamlIssuerTrust {
                saml_issuer: saml_issuer.clone(),
                subject_key: SamlSubjectKey::Qualified,
            })
            .collect();
        ras_config.trusted_issuers = vec![trusted];
        let ras = ResourceAs::new(ras_config)?;

        // Plain http is acceptable in these documents, and for the fetches
        // below, only because the demo runs on loopback.
        let metadata = ras
            .metadata()
            .token_endpoint_auth_methods(vec![
                "client_secret_basic".to_owned(),
                "client_secret_post".to_owned(),
            ])
            // Access tokens here are opaque, so there is nothing to publish.
            // The key set is empty; it exists because testers such as the
            // xaa.dev wizard expect `jwks_uri` in the metadata.
            .jwks_uri(Url::parse(&format!("{}/jwks", config.issuer))?)
            .allow_http_loopback(true)
            .build()?
            .to_value();
        let protected_resource_metadata = ProtectedResourceMetadata {
            resource: config.resource.clone(),
            authorization_servers: Some(vec![issuer]),
            scopes_supported: Some(SCOPES.iter().map(|&scope| scope.to_owned()).collect()),
            bearer_methods_supported: Some(vec!["header".to_owned()]),
            dpop_bound_access_tokens_required: Some(config.require_dpop),
            extra: std::collections::BTreeMap::new(),
        }
        .to_value();

        Ok(Self {
            registry: Registry {
                resource: config.resource.clone(),
                require_dpop: config.require_dpop,
            },
            http: ReqwestClient::new()?,
            fetch: FetchOptions {
                allow_http_loopback: true,
                ..FetchOptions::default()
            },
            idp_keys: tokio::sync::Mutex::new(None),
            replay: InMemoryReplayStore::new(10_000),
            tokens: Mutex::new(HashMap::new()),
            api_replay: InMemoryReplayStore::new(10_000),
            api_dpop_algorithms: ras.config().dpop_algorithms.clone(),
            todos_url: Url::parse(&format!("{}api/todos", config.resource))?,
            resource_metadata_url: format!(
                "{}/.well-known/oauth-protected-resource",
                config.issuer
            ),
            metadata,
            protected_resource_metadata,
            ras,
            config,
        })
    }

    /// The caller's part of client authentication: look the client up and
    /// check its secret. The library only extracts the credentials.
    fn authenticate(&self, credentials: &ClientCredentials) -> Option<ClientIdentity> {
        let (client_id, secret, method) = match credentials {
            ClientCredentials::Basic { client_id, secret } => {
                (client_id, secret, ClientAuthMethod::ClientSecretBasic)
            }
            ClientCredentials::Post { client_id, secret } => {
                (client_id, secret, ClientAuthMethod::ClientSecretPost)
            }
            _ => return None,
        };
        (*client_id == self.config.client_id && secret.ct_eq(&self.config.client_secret)).then(
            || ClientIdentity::Authenticated {
                client_id: client_id.clone(),
                method,
            },
        )
    }

    /// The trusted IdP's keys: from the cache, or fetched through its
    /// metadata (`jwks_uri`). `refetch` asks for a new copy because the cached
    /// one lacks a `kid`; it is honored at most once per
    /// [`MIN_JWKS_REFETCH_INTERVAL`].
    ///
    /// A fetch failure is logged and answered with whatever is cached, so
    /// validation fails with "no keys for issuer" rather than this server
    /// inventing an error of its own.
    async fn idp_keys(&self, refetch: bool) -> HashMap<Issuer, JwkSet> {
        let mut cached = self.idp_keys.lock().await;
        let fresh_enough = cached.as_ref().is_some_and(|cached| {
            !refetch || cached.fetched_at.elapsed() < MIN_JWKS_REFETCH_INTERVAL
        });
        if !fresh_enough {
            match self.fetch_idp_keys().await {
                Ok(keys) => {
                    println!(
                        "jwks: fetched {} key(s) from {}",
                        keys.keys().len(),
                        self.config.idp_issuer
                    );
                    *cached = Some(CachedKeys {
                        keys: HashMap::from([(Issuer::new(self.config.idp_issuer.as_str()), keys)]),
                        fetched_at: Instant::now(),
                    });
                }
                Err(error) => println!(
                    "jwks: fetch from {} failed: {error}",
                    self.config.idp_issuer
                ),
            }
        }
        cached
            .as_ref()
            .map_or_else(HashMap::new, |cached| cached.keys.clone())
    }

    async fn fetch_idp_keys(&self) -> Result<JwkSet, BoxError> {
        let issuer = Issuer::new(self.config.idp_issuer.as_str());
        let metadata =
            fetch_authorization_server_metadata(&self.http, &issuer, &self.fetch).await?;
        let jwks_uri = metadata
            .jwks_uri
            .ok_or("the IdP's metadata has no jwks_uri")?;
        Ok(fetch_jwks(&self.http, &jwks_uri, &self.fetch).await?.keys)
    }

    /// Resolve the ID-JAG's subject to a local account, within the grant's
    /// recipient tenant. The demo knows two accounts, keyed by the IdP's
    /// `sub`; a real server keeps a table keyed by `iss` + `sub`.
    fn resolve_account(&self, grant: &VerifiedGrant) -> Option<String> {
        // A SAML-derived ID-JAG is resolved on its `sub_id`, never on `sub`:
        // there `sub` is the bare NameID, which two SAML issuers can share.
        if let Some(key) = grant.saml_subject_key() {
            return self.config.accept_any_subject.then(|| {
                format!(
                    "saml:{}|{}|{}|{}|{}",
                    key.saml_issuer,
                    key.nameid,
                    key.nameid_format.as_deref().unwrap_or_default(),
                    key.name_qualifier.as_deref().unwrap_or_default(),
                    key.sp_name_qualifier.as_deref().unwrap_or_default(),
                )
            });
        }
        let sub = grant.claims().sub.as_str();
        (self.config.accept_any_subject || todos_of(sub).is_some()).then(|| sub.to_owned())
    }

    /// Scope policy: what the ID-JAG carries, narrowed to what this request
    /// asked for and to the scopes this server knows.
    fn granted_scope(grant: &VerifiedGrant) -> Option<Scope> {
        let carried = grant.claims().scope.as_ref()?;
        let wanted = grant.requested_scope().unwrap_or(carried);
        let granted: Vec<&str> = wanted
            .tokens()
            .filter(|token| carried.contains(token) && SCOPES.contains(token))
            .collect();
        Scope::parse(granted.join(" ")).ok()
    }

    fn mint_access_token(&self, record: IssuedToken) -> AccessToken {
        let mut bytes = [0_u8; 32];
        rand::fill(&mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);

        let now = SystemTime::now();
        let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        tokens.retain(|_, issued| issued.expires_at > now);
        tokens.insert(token.clone(), record);
        AccessToken::new(token)
    }
}

// ---------------------------------------------------------------------------
// HTTP glue
// ---------------------------------------------------------------------------

/// Request headers in the shape the library parses.
fn headers_vec(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let value = value.to_str().ok()?;
            Some((name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

/// Send a response the library built.
fn into_axum(response: HttpResponse) -> Response {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(response.body))
        .unwrap_or_else(|_invalid| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Cross-origin access for the origins in `XAA_CORS_ORIGINS`, and for no one
/// else. A browser-based tester needs it to call the token endpoint and the
/// API directly. Credentials are never allowed cross-origin.
async fn cors(
    State(app): State<Arc<App>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let allowed_origin = request
        .headers()
        .get("origin")
        .and_then(|origin| origin.to_str().ok())
        .filter(|origin| {
            app.config
                .cors_origins
                .iter()
                .any(|allowed| allowed == origin)
        })
        .map(str::to_owned);
    println!(
        "http: {} {} origin={}",
        request.method(),
        request.uri().path(),
        allowed_origin.as_deref().unwrap_or("-"),
    );
    let mut response = if request.method() == axum::http::Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };
    if let Some(origin) = allowed_origin
        && let Ok(origin) = origin.parse()
    {
        let headers = response.headers_mut();
        headers.insert("Access-Control-Allow-Origin", origin);
        headers.insert("Vary", axum::http::HeaderValue::from_static("Origin"));
        headers.insert(
            "Access-Control-Allow-Methods",
            axum::http::HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            "Access-Control-Allow-Headers",
            axum::http::HeaderValue::from_static("authorization, content-type, dpop"),
        );
    }
    response
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    into_axum(HttpResponse {
        status: status.as_u16(),
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: value.to_string().into_bytes(),
    })
}

/// Log why a token request was refused. The reason is for logs only; the
/// client sees just the OAuth error code.
fn rejected(error: &TokenError) -> Response {
    println!(
        "token: rejected error={} reason={:?}",
        error.code(),
        error.reason()
    );
    into_axum(error.to_response())
}

// ---------------------------------------------------------------------------
// The Resource Authorization Server
// ---------------------------------------------------------------------------

/// `POST /token`: the ID-JAG as a jwt-bearer / jwt-dpop grant (draft §4.4).
async fn token(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    let request = match TokenRequest::parse(&body, &headers_vec(&headers), None) {
        Ok(request) => request,
        Err(error) => return rejected(&error),
    };
    let Some(client) = app.authenticate(request.client_credentials()) else {
        return rejected(&TokenError::invalid_client_for(
            request.client_credentials(),
        ));
    };

    let now = SystemTime::now();
    let validate = |keys: HashMap<Issuer, JwkSet>| {
        let (app, request, client) = (&app, &request, &client);
        async move {
            app.ras
                .validate(
                    request,
                    client,
                    &keys,
                    &app.registry,
                    Some(&app.replay),
                    now,
                    CLOCK_SKEW,
                )
                .await
        }
    };
    let mut result = validate(app.idp_keys(false).await).await;
    // The IdP rotated its key since the last fetch: refetch once and retry.
    // A failed validation consumed nothing, so retrying is safe.
    if let Err(error) = &result
        && matches!(error.reason(), Some(RejectReason::UnknownKeyId))
    {
        result = validate(app.idp_keys(true).await).await;
    }
    let grant = match result {
        Ok(grant) => grant,
        Err(error) => return rejected(&error),
    };

    // From here on the ID-JAG is verified; what follows is this server's own
    // policy. The decision builder keeps it within the ID-JAG.
    let Some(account) = app.resolve_account(&grant) else {
        return rejected(&grant.decide(&app.registry).deny());
    };
    let mut decision = grant.decide(&app.registry);
    if grant.claims().resource.is_none() {
        // No `resource` claim: this server's only resource is the default.
        decision = decision.resources(vec![app.config.resource.clone()]);
    }
    match App::granted_scope(&grant) {
        Some(scope) => decision = decision.scope(scope),
        // The client asked for scopes the ID-JAG does not carry.
        None if grant.requested_scope().is_some() => return rejected(&TokenError::invalid_scope()),
        None => {}
    }
    let decision = match decision.build() {
        Ok(decision) => decision,
        Err(error) => return rejected(&error),
    };

    let access_token = app.mint_access_token(IssuedToken {
        account: account.clone(),
        client_id: grant.claims().client_id.clone(),
        scope: decision.scope().cloned(),
        resources: decision.resources().to_vec(),
        expires_at: now
            .checked_add(ACCESS_TOKEN_LIFETIME)
            .unwrap_or(SystemTime::UNIX_EPOCH),
        binding: decision.binding().cloned(),
    });
    println!(
        "token: issued a {} access token account={account} client={} scope={:?}",
        decision.token_type(),
        grant.claims().client_id,
        decision.scope().map(Scope::as_str),
    );
    into_axum(decision.token_response(access_token, ACCESS_TOKEN_LIFETIME))
}

async fn metadata(State(app): State<Arc<App>>) -> Response {
    json_response(StatusCode::OK, &app.metadata)
}

// ---------------------------------------------------------------------------
// The demo protected resource. Not part of the `xaa` crate's scope: a real
// Resource Server is a separate service that introspects the token or
// verifies a JWT access token.
// ---------------------------------------------------------------------------

async fn protected_resource_metadata(State(app): State<Arc<App>>) -> Response {
    json_response(StatusCode::OK, &app.protected_resource_metadata)
}

fn todos_of(account: &str) -> Option<Value> {
    match account {
        "alice" => Some(json!([
            {"id": 1, "title": "Review the ID-JAG draft", "completed": true},
            {"id": 2, "title": "Rotate the demo signing key", "completed": false},
        ])),
        "bob" => Some(json!([
            {"id": 1, "title": "Register the todo app", "completed": false},
        ])),
        _ => None,
    }
}

/// Why a resource request was refused (RFC 6750 §3.1, RFC 9449 §7.1).
struct Refused {
    status: StatusCode,
    scheme: &'static str,
    error: Option<&'static str>,
    reason: &'static str,
}

impl Refused {
    fn unauthorized(scheme: &'static str, reason: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            scheme,
            error: Some("invalid_token"),
            reason,
        }
    }
}

impl App {
    /// The 401/403 answer, pointing at the Protected Resource Metadata
    /// (RFC 9728 §5.1).
    fn refuse(&self, refused: &Refused) -> Response {
        println!("api: refused ({})", refused.reason);
        let mut challenge = format!(
            "{} resource_metadata=\"{}\"",
            refused.scheme, self.resource_metadata_url
        );
        if let Some(error) = refused.error {
            challenge.push_str(", error=\"");
            challenge.push_str(error);
            challenge.push('"');
        }
        let mut response = json_response(
            refused.status,
            &json!({"error": refused.error.unwrap_or("unauthorized")}),
        );
        if let Ok(challenge) = challenge.parse() {
            response
                .headers_mut()
                .insert(axum::http::header::WWW_AUTHENTICATE, challenge);
        }
        response
    }

    /// Check the access token of a `GET` to the todo API and return what it
    /// stands for.
    async fn authorize(
        &self,
        headers: &HeaderMap,
        required_scope: &str,
    ) -> Result<IssuedToken, Refused> {
        let authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '));
        let Some((scheme, token)) = authorization else {
            return Err(Refused {
                status: StatusCode::UNAUTHORIZED,
                scheme: "Bearer",
                error: None,
                reason: "no access token",
            });
        };

        let now = SystemTime::now();
        let issued = self
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(token)
            .filter(|issued| issued.expires_at > now)
            .cloned()
            .ok_or(Refused::unauthorized(
                "Bearer",
                "unknown or expired access token",
            ))?;

        match &issued.binding {
            None if scheme.eq_ignore_ascii_case("Bearer") => {}
            None => return Err(Refused::unauthorized("Bearer", "not a DPoP-bound token")),
            Some(AccessTokenBinding::Dpop { jkt }) if scheme.eq_ignore_ascii_case("DPoP") => {
                self.check_dpop_proof(headers, token, jkt, now).await?;
            }
            Some(AccessTokenBinding::Dpop { .. }) => {
                return Err(Refused::unauthorized(
                    "DPoP",
                    "DPoP-bound token presented as a bearer token",
                ));
            }
            // Certificate-bound tokens need TLS, which the demo does not run.
            Some(_) => return Err(Refused::unauthorized("Bearer", "unsupported token binding")),
        }

        let in_scope = issued
            .scope
            .as_ref()
            .is_some_and(|scope| scope.contains(required_scope));
        if !in_scope || !issued.resources.contains(&self.config.resource) {
            return Err(Refused {
                status: StatusCode::FORBIDDEN,
                scheme: "Bearer",
                error: Some("insufficient_scope"),
                reason: "token lacks the required scope",
            });
        }
        Ok(issued)
    }

    /// RFC 9449 §7.1: the request must carry a proof by the key the token is
    /// bound to, for this method and URL, that names this very token.
    async fn check_dpop_proof(
        &self,
        headers: &HeaderMap,
        token: &str,
        bound_jkt: &str,
        now: SystemTime,
    ) -> Result<(), Refused> {
        let refused = |reason| Refused {
            status: StatusCode::UNAUTHORIZED,
            scheme: "DPoP",
            error: Some("invalid_dpop_proof"),
            reason,
        };
        let headers = headers_vec(headers);
        let validation = DpopValidation {
            expected_htm: "GET",
            expected_htu: &self.todos_url,
            algorithms: &self.api_dpop_algorithms,
            nonce: None,
            max_age: DEFAULT_MAX_AGE,
            now,
            clock_skew: CLOCK_SKEW,
        };
        // Header, signature, `htm`, `htu` and `iat`.
        let proof = validate_dpop_proof(&headers, &validation)
            .map_err(|_invalid| refused("invalid DPoP proof"))?;
        if proof.jkt() != bound_jkt {
            return Err(refused("DPoP proof is by another key"));
        }
        // `ath`: the proof must be for this very access token.
        if !proof.is_for_access_token(&AccessToken::new(token)) {
            return Err(refused("DPoP proof is not for this access token"));
        }
        // Last, so a request refused for another reason does not burn the `jti`.
        proof
            .consume(&self.api_replay, now)
            .await
            .map_err(|_replayed| refused("DPoP proof was replayed"))
    }
}

/// `GET /api/todos`: the caller's todos. Needs scope `todos.read`.
async fn todos(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let issued = match app.authorize(&headers, "todos.read").await {
        Ok(issued) => issued,
        Err(refused) => return app.refuse(&refused),
    };
    println!(
        "api: GET /api/todos account={} client={}",
        issued.account, issued.client_id
    );
    json_response(
        StatusCode::OK,
        &json!({
            "owner": issued.account,
            "todos": todos_of(&issued.account).unwrap_or_else(|| json!([])),
        }),
    )
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let config = Config::from_env()?;
    let port = config.port;
    let app = Arc::new(App::new(config)?);

    println!("xaa-resource-as: issuer {}", app.config.issuer);
    println!("xaa-resource-as: resource {}", app.config.resource);
    println!(
        "xaa-resource-as: trusts IdP {} for client {}",
        app.config.idp_issuer, app.config.client_id
    );

    let router = Router::new()
        .route("/token", post(token))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route("/api/todos", get(todos))
        .route("/health", get(|| async { "ok" }))
        .route(
            "/jwks",
            get(|| async { json_response(StatusCode::OK, &json!({ "keys": [] })) }),
        )
        .layer(axum::middleware::from_fn_with_state(app.clone(), cors))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!(
        "xaa-resource-as: listening on http://{}",
        listener.local_addr()?
    );
    axum::serve(listener, router).await?;
    Ok(())
}
