//! Minimal IdP issuing ID-JAGs at its token-exchange endpoint, so the client and resource AS can be exercised against each other locally.
//!
//! Serves, on `http://127.0.0.1:$XAA_IDP_PORT`:
//!
//! - `POST /token`: RFC 8693 token exchange, ID Token in, ID-JAG out
//!   (`xaa::idp`).
//! - `GET /jwks`: the public half of the signing key.
//! - `GET /.well-known/openid-configuration` and
//!   `GET /.well-known/oauth-authorization-server`: the same metadata
//!   document.
//! - `POST /demo/login`: a **demo-only** stand-in for user login.
//!
//! Everything is in memory and the signing key is generated at startup.
//! Configuration is read from the environment; see `examples/README.md`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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

use xaa::claims::Issuer;
use xaa::client_auth::{ClientAuthMethod, ClientCredentials, ClientIdentity};
use xaa::http::{BoxError, HttpResponse};
use xaa::idp::{
    ExchangeContext, ExchangeDenial, ExchangeGrant, ExchangeOutcome, ExchangePolicy,
    ExchangeRecord, IdTokenClaims, IdTokenSubject, IdTokenVerifier, Idp, IdpConfig,
    ResourceAsDirectory, ResourceAsEntry, SubjectRef, TokenExchangeRequest,
};
use xaa::jose::{AlgorithmPolicy, JwkSet, JwsSigner, PrivateKey, SignatureAlgorithm};
use xaa::replay::InMemoryReplayStore;

/// Tolerance for clock differences when checking an ID Token's time window.
const CLOCK_SKEW: Duration = Duration::from_secs(30);
/// Lifetime of the ID Tokens the demo login hands out.
const ID_TOKEN_LIFETIME: Duration = Duration::from_mins(10);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Demo configuration, from the environment with localhost defaults. The
/// credentials are fake constants: never reuse them.
struct Config {
    port: u16,
    /// This IdP's issuer identifier. No trailing slash: the issuer check is
    /// byte-exact.
    issuer: String,
    /// The one Resource AS this IdP has a trust relationship with.
    resource_as_issuer: String,
    /// The protected resource that Resource AS governs.
    resource: String,
    /// The requesting app's registration here.
    client_id: String,
    client_secret: String,
    /// The same app's client ID *at the Resource AS*. It goes into the
    /// ID-JAG's `client_id` claim.
    resource_as_client_id: String,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

impl Config {
    fn from_env() -> Result<Self, BoxError> {
        let port: u16 = env_or("XAA_IDP_PORT", "4000").parse()?;
        let resource_as_issuer = env_or("XAA_RESOURCE_AS_ISSUER", "http://127.0.0.1:4001");
        Ok(Self {
            port,
            issuer: env_or("XAA_IDP_ISSUER", &format!("http://127.0.0.1:{port}")),
            resource: env_or("XAA_RESOURCE", &format!("{resource_as_issuer}/")),
            resource_as_issuer,
            client_id: env_or("XAA_IDP_CLIENT_ID", "demo-app"),
            client_secret: env_or("XAA_IDP_CLIENT_SECRET", "demo-idp-secret-not-a-real-secret"),
            resource_as_client_id: env_or("XAA_RESOURCE_AS_CLIENT_ID", "demo-app-at-todos"),
        })
    }
}

// ---------------------------------------------------------------------------
// The user directory and the client table (in memory)
// ---------------------------------------------------------------------------

/// What this IdP knows about a user: who they are and what they may delegate.
struct User {
    email: &'static str,
    /// The scopes this user may be granted at the todo API.
    scopes: &'static [&'static str],
}

fn user(name: &str) -> Option<User> {
    match name {
        "alice" => Some(User {
            email: "alice@example.com",
            scopes: &["todos.read", "todos.write"],
        }),
        "bob" => Some(User {
            email: "bob@example.com",
            scopes: &["todos.read"],
        }),
        _ => None,
    }
}

/// A client registered at this IdP.
struct Registration {
    secret: String,
    /// The client's ID at the Resource AS (draft §5.1): a second,
    /// independent registration the IdP has to know about.
    resource_as_client_id: String,
}

// ---------------------------------------------------------------------------
// The caller-supplied pieces of `xaa::idp`
// ---------------------------------------------------------------------------

/// The Resource Authorization Servers this IdP issues ID-JAGs for.
struct Directory {
    resource_as_issuer: String,
    resource: String,
}

impl ResourceAsDirectory for Directory {
    fn resolve_audience(
        &self,
        audience: &str,
        _issuer_tenant: Option<&str>,
    ) -> Option<ResourceAsEntry> {
        (audience == self.resource_as_issuer).then(|| {
            let mut entry = ResourceAsEntry::new(Issuer::new(audience));
            // `examples/resource-as` accepts the jwt-dpop grant, so a DPoP
            // proof on the exchange binds the ID-JAG.
            entry.supports_jwt_dpop = true;
            entry
        })
    }

    fn governs(&self, _ras: &ResourceAsEntry, resource: &str) -> bool {
        // Byte-for-byte, trailing slash included (draft §4.3).
        resource == self.resource
    }
}

/// Access policy: a user may delegate the scopes the directory lists for
/// them, to a client that has a registration at the Resource AS.
struct Policy {
    clients: Arc<HashMap<String, Registration>>,
}

impl Policy {
    fn decide(&self, ctx: &ExchangeContext<'_>) -> Result<ExchangeGrant, ExchangeDenial> {
        let registration = self
            .clients
            .get(&ctx.client.client_id)
            .ok_or(ExchangeDenial::AccessDenied)?;
        let subject = ctx.subject.subject.as_str();
        let user = user(subject).ok_or(ExchangeDenial::AccessDenied)?;
        if let Some(scope) = ctx.scope
            && !scope.tokens().all(|token| user.scopes.contains(&token))
        {
            return Err(ExchangeDenial::AccessDenied);
        }

        // The demo uses the same subject identifier everywhere. A real IdP
        // decides here which identifier the Resource AS knows the user by.
        let mut grant = ExchangeGrant::new(&registration.resource_as_client_id, subject);
        grant.resources = ctx.resources.to_vec();
        grant.scope = ctx.scope.cloned();
        grant.email = Some(user.email.to_owned());
        Ok(grant)
    }
}

impl ExchangePolicy for Policy {
    fn evaluate(
        &self,
        ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send {
        std::future::ready(self.decide(ctx))
    }
}

/// Maps a verified ID Token to a user of this IdP.
fn map_subject(claims: &IdTokenClaims) -> Option<IdTokenSubject> {
    user(&claims.sub).map(|_| IdTokenSubject {
        subject: SubjectRef::new(claims.sub.as_str()),
        issuer_tenant: None,
    })
}

type SubjectMapper = fn(&IdTokenClaims) -> Option<IdTokenSubject>;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct App {
    config: Config,
    idp: Idp,
    /// Signs ID-JAGs (inside `idp`) and the demo ID Tokens.
    signer: Arc<PrivateKey>,
    clients: Arc<HashMap<String, Registration>>,
    subjects: IdTokenVerifier<SubjectMapper>,
    directory: Directory,
    policy: Policy,
    /// Pre-rendered documents.
    jwks: Value,
    metadata: Value,
}

impl App {
    fn new(config: Config) -> Result<Self, BoxError> {
        // An ephemeral key: every restart rotates it. The `kid` is the key's
        // thumbprint, so a Resource AS holding the previous JWK Set sees an
        // unknown `kid` and knows to refetch.
        let key = PrivateKey::generate(SignatureAlgorithm::Es256);
        let kid = key.public_jwk().thumbprint_sha256();
        let signer = Arc::new(key.with_key_id(kid));
        let keys = JwkSet::from_keys(vec![
            signer
                .public_jwk()
                .with_algorithm(SignatureAlgorithm::Es256),
        ]);

        let issuer = Issuer::new(config.issuer.as_str());
        let token_endpoint = Url::parse(&format!("{}/token", config.issuer))?;
        let jwks_uri = Url::parse(&format!("{}/jwks", config.issuer))?;

        let mut idp_config = IdpConfig::new(issuer.clone(), token_endpoint, signer.clone());
        idp_config.dpop = true;
        idp_config.replay = Some(Arc::new(InMemoryReplayStore::new(10_000)));
        let idp = Idp::new(idp_config)?;

        // Plain http is acceptable for this document only because the demo
        // runs on loopback.
        let metadata = idp
            .metadata_builder(jwks_uri)
            .token_endpoint_auth_methods(vec![
                "client_secret_post".to_owned(),
                "client_secret_basic".to_owned(),
            ])
            .allow_http_loopback(true)
            .build()?
            .to_value();

        let clients = Arc::new(HashMap::from([(
            config.client_id.clone(),
            Registration {
                secret: config.client_secret.clone(),
                resource_as_client_id: config.resource_as_client_id.clone(),
            },
        )]));

        Ok(Self {
            idp,
            subjects: IdTokenVerifier::new(
                issuer,
                keys.clone(),
                AlgorithmPolicy::default_id_jag(),
                CLOCK_SKEW,
                map_subject as SubjectMapper,
            ),
            directory: Directory {
                resource_as_issuer: config.resource_as_issuer.clone(),
                resource: config.resource.clone(),
            },
            policy: Policy {
                clients: clients.clone(),
            },
            clients,
            signer,
            jwks: keys.to_value(),
            metadata,
            config,
        })
    }

    /// The caller's part of client authentication: look the client up and
    /// check its secret. The library only extracts the credentials.
    fn authenticate(&self, credentials: &ClientCredentials) -> Option<ClientIdentity> {
        let (client_id, secret, method) = match credentials {
            ClientCredentials::Post { client_id, secret } => {
                (client_id, secret, ClientAuthMethod::ClientSecretPost)
            }
            ClientCredentials::Basic { client_id, secret } => {
                (client_id, secret, ClientAuthMethod::ClientSecretBasic)
            }
            _ => return None,
        };
        let registration = self.clients.get(client_id)?;
        secret
            .ct_eq(&registration.secret)
            .then(|| ClientIdentity::Authenticated {
                client_id: client_id.clone(),
                method,
            })
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

fn json_response(status: StatusCode, value: &Value) -> Response {
    into_axum(HttpResponse {
        status: status.as_u16(),
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Cache-Control".to_owned(), "no-store".to_owned()),
        ],
        body: value.to_string().into_bytes(),
    })
}

/// One audit line per exchange (draft §9.2). The record never holds a token.
fn audit(record: &ExchangeRecord) {
    let client = record.client_id.as_deref().unwrap_or("<unauthenticated>");
    let audience = record.audience.as_deref().unwrap_or("<none>");
    match &record.outcome {
        ExchangeOutcome::Issued { jti, granted } => println!(
            "exchange: issued ID-JAG jti={jti} client={client} audience={audience} sub={} scope={:?} bound={}",
            granted.sub,
            granted.scope.as_ref().map(xaa::claims::Scope::as_str),
            granted.confirmation.is_some(),
        ),
        ExchangeOutcome::RefreshTokenApproved => {
            println!("exchange: refresh token approved client={client}");
        }
        ExchangeOutcome::Rejected { code, reason } => println!(
            "exchange: rejected client={client} audience={audience} error={code} reason={reason:?}"
        ),
        other => println!("exchange: client={client} audience={audience} outcome={other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /token`: the RFC 8693 token exchange (draft §4.3).
async fn token(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    let request = match TokenExchangeRequest::parse(&body, &headers_vec(&headers), None) {
        Ok(request) => request,
        Err(error) => return into_axum(error.to_response()),
    };
    let Some(client) = app.authenticate(request.client_credentials()) else {
        println!("exchange: client authentication failed");
        return into_axum(request.invalid_client().to_response());
    };
    let (result, record) = app
        .idp
        .exchange(
            &request,
            &client,
            &app.subjects,
            &app.directory,
            &app.policy,
            SystemTime::now(),
        )
        .await;
    audit(&record);
    match result {
        Ok(issued) => into_axum(issued.to_response()),
        Err(error) => into_axum(error.to_response()),
    }
}

async fn jwks(State(app): State<Arc<App>>) -> Response {
    let mut response = json_response(StatusCode::OK, &app.jwks);
    // The key lives as long as the process; let verifiers cache it briefly.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=60"),
    );
    response
}

async fn metadata(State(app): State<Arc<App>>) -> Response {
    json_response(StatusCode::OK, &app.metadata)
}

/// `POST /demo/login`: **DEMO ONLY.**
///
/// Stands in for real user authentication (an OpenID Connect authorization
/// code flow with a login page, MFA, consent, sessions). All of that is out
/// of scope for the `xaa` crate, which starts where the client already holds
/// an ID Token. This endpoint takes a form with `username` and `client_id`
/// and returns `{"id_token": …}` for any known user **without checking a
/// password**. Never expose anything like it.
async fn demo_login(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let (username, client_id) = (field("username"), field("client_id"));

    let Some(user) = user(username) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "unknown_user", "error_description": "try alice or bob"}),
        );
    };
    if !app.clients.contains_key(client_id) {
        return json_response(StatusCode::BAD_REQUEST, &json!({"error": "unknown_client"}));
    }
    match sign_id_token(&app, username, user.email, client_id).await {
        Ok(id_token) => {
            println!("demo login: issued an ID Token for {username} to {client_id}");
            json_response(StatusCode::OK, &json!({"id_token": id_token}))
        }
        Err(error) => {
            println!("demo login: signing failed: {error}");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "server_error"}),
            )
        }
    }
}

/// Sign an ID Token for `client_id`. The crate has no "sign these claims"
/// entry point on purpose (it only ever issues ID-JAGs), so the token is
/// assembled here and signed through [`JwsSigner::sign`].
async fn sign_id_token(
    app: &App,
    sub: &str,
    email: &str,
    client_id: &str,
) -> Result<String, BoxError> {
    let iat = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let exp = iat.saturating_add(ID_TOKEN_LIFETIME.as_secs());
    let header = json!({
        "alg": app.signer.algorithm().as_str(),
        "kid": app.signer.key_id(),
        "typ": "JWT",
    });
    let claims = json!({
        "iss": app.config.issuer,
        "sub": sub,
        "aud": client_id,
        "iat": iat,
        "exp": exp,
        "email": email,
    });
    let mut token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?));
    let signature = app.signer.sign(token.as_bytes()).await?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let config = Config::from_env()?;
    let port = config.port;
    let app = Arc::new(App::new(config)?);

    println!("xaa-idp: issuer {}", app.config.issuer);
    println!(
        "xaa-idp: client {} -> {} at Resource AS {}",
        app.config.client_id, app.config.resource_as_client_id, app.config.resource_as_issuer
    );

    let router = Router::new()
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .route("/.well-known/openid-configuration", get(metadata))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/demo/login", post(demo_login))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("xaa-idp: listening on http://{}", listener.local_addr()?);
    axum::serve(listener, router).await?;
    Ok(())
}
