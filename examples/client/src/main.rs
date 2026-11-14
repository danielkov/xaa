//! XAA client (requesting app): OIDC login, token exchange for an ID-JAG, jwt-bearer grant, protected API call.
//!
//! Runs the whole Cross App Access flow once against `examples/idp` and
//! `examples/resource-as`, starting from nothing but the resource URL:
//!
//! 1. log the user in at the IdP (a demo stub) for an ID Token;
//! 2. discover the resource, its authorization server, and the IdP;
//! 3. exchange the ID Token for an ID-JAG at the IdP (RFC 8693);
//! 4. present the ID-JAG at the Resource AS for an access token (RFC 7523);
//! 5. call the todo API.
//!
//! `--dpop` binds the ID-JAG and the access token to a freshly generated key
//! (RFC 9449). Configuration is read from the environment; see
//! `examples/README.md`. Tokens and secrets are never printed, except for the
//! refresh token when `--print-refresh-token` asks for it.
//!
//! `--playground` runs the same flow against the public playground at
//! <https://xaa.dev> instead: a real browser login at its IdP (or a refresh
//! token from an earlier run) replaces the demo stub.
//!
//! `--playground --saml` signs the user in with SAML 2.0 instead and takes
//! the draft §4.5 path: the signed assertion is exchanged for a Refresh
//! Token, and the Refresh Token for the ID-JAG.

mod login;
mod saml_login;

use std::process::ExitCode;
use std::time::SystemTime;

use serde_json::Value;
use url::Url;

use xaa::claims::{Issuer, Scope};
use xaa::client::{
    AccessTokenRequest, ClientAuth, ResourceAsClientAuth, SamlToRefreshToken, SubjectToken,
    TokenExchange, discover_idp, discover_resource, discover_resource_as, exchange_for_id_jag,
    exchange_saml_for_refresh_token, request_access_token,
};
use xaa::dpop::{DpopKey, DpopRequest};
use xaa::http::{BoxError, HttpClient, HttpRequest, Method, ReqwestClient};
use xaa::jose::SignatureAlgorithm;
use xaa::metadata::{FetchOptions, PrmOrigin};
use xaa::secret::{ClientSecret, IdToken, RefreshToken};

const USAGE: &str = "\
Usage: xaa-client [--dpop] [--verbose] [--playground [--saml] [--print-refresh-token]]

Runs the Cross App Access flow against examples/idp and examples/resource-as
and prints the user's todos.

  --dpop                  bind the ID-JAG and the access token to a generated
                          DPoP key
  --verbose               print each token endpoint response, with tokens and
                          secrets redacted
  --playground            run against https://xaa.dev instead: sign in through
                          a browser at https://idp.xaa.dev, or reuse
                          XAA_REFRESH_TOKEN. Needs the four client credentials
                          from https://xaa.dev/developer/register.
  --saml                  with --playground, sign in with SAML 2.0 instead of
                          OpenID Connect and exchange the assertion for a
                          refresh token first (draft section 4.5). Needs the
                          credentials of a SAML app from the same page.
  --print-refresh-token   with --playground, print the refresh token from the
                          login so later runs can skip the browser. It is a
                          credential: treat the output accordingly.

Environment (defaults in brackets):
  XAA_RESOURCE                    the protected resource [http://127.0.0.1:4001/]
  XAA_IDP_ISSUER                  the IdP [http://127.0.0.1:4000]
  XAA_IDP_CLIENT_ID               this app's client ID at the IdP [demo-app]
  XAA_IDP_CLIENT_SECRET           and its secret there
  XAA_RESOURCE_AS_CLIENT_ID       this app's client ID at the Resource AS [demo-app-at-todos]
  XAA_RESOURCE_AS_CLIENT_SECRET   and its secret there
  XAA_USERNAME                    the demo user to log in as [alice]
  XAA_SCOPE                       the scope to ask for [todos.read]

With --playground the defaults for XAA_RESOURCE and XAA_IDP_ISSUER become
https://api.resource.xaa.dev/ and https://idp.xaa.dev, the four client
variables are required, and two more are read:
  XAA_REDIRECT_URI                registered redirect URI for the browser
                                  login [http://127.0.0.1:8765/callback]
  XAA_REFRESH_TOKEN               a refresh token from an earlier login; when
                                  set, no browser login happens

With --saml these replace the last two:
  XAA_SAML_SP_ENTITY_ID           registered SP entity ID
                                  [http://localhost:8765/saml/metadata]
  XAA_SAML_ACS_URL                registered ACS URL
                                  [http://localhost:8765/saml/acs]
  XAA_SAML_IDP_METADATA           the IdP's SAML metadata
                                  [https://idp.xaa.dev/saml/metadata]";

/// Demo configuration, from the environment with localhost defaults. The
/// credentials are fake constants: never reuse them.
struct Config {
    /// The protected resource, exactly as its metadata spells it.
    resource: String,
    idp_issuer: String,
    /// The app holds two independent registrations (draft §5.1): one at the
    /// IdP and one at the Resource AS.
    idp_client_id: String,
    idp_client_secret: String,
    resource_as_client_id: String,
    resource_as_client_secret: String,
    username: String,
    scope: String,
    flags: Flags,
    redirect_uri: String,
    refresh_token: Option<String>,
    saml_sp_entity_id: String,
    saml_acs_url: String,
    saml_idp_metadata: String,
}

/// The command-line switches.
#[derive(Clone, Copy, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "five independent command-line switches, not a state machine"
)]
struct Flags {
    dpop: bool,
    verbose: bool,
    /// Run against xaa.dev: a real login, and `client_secret_post` at the
    /// Resource AS as the playground registers its clients.
    playground: bool,
    /// With `playground`: SAML sign-on and the draft §4.5 exchange.
    saml: bool,
    print_refresh_token: bool,
}

fn required_env(name: &str) -> Result<String, BoxError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("--playground needs {name} to be set").into())
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

impl Config {
    fn from_env(flags: Flags) -> Result<Self, BoxError> {
        if flags.playground {
            return Ok(Self {
                resource: env_or("XAA_RESOURCE", "https://api.resource.xaa.dev/"),
                idp_issuer: env_or("XAA_IDP_ISSUER", "https://idp.xaa.dev"),
                idp_client_id: required_env("XAA_IDP_CLIENT_ID")?,
                idp_client_secret: required_env("XAA_IDP_CLIENT_SECRET")?,
                resource_as_client_id: required_env("XAA_RESOURCE_AS_CLIENT_ID")?,
                resource_as_client_secret: required_env("XAA_RESOURCE_AS_CLIENT_SECRET")?,
                username: String::new(),
                scope: env_or("XAA_SCOPE", "todos.read"),
                flags,
                redirect_uri: env_or("XAA_REDIRECT_URI", "http://127.0.0.1:8765/callback"),
                refresh_token: std::env::var("XAA_REFRESH_TOKEN")
                    .ok()
                    .filter(|value| !value.is_empty()),
                saml_sp_entity_id: env_or(
                    "XAA_SAML_SP_ENTITY_ID",
                    "http://localhost:8765/saml/metadata",
                ),
                saml_acs_url: env_or("XAA_SAML_ACS_URL", "http://localhost:8765/saml/acs"),
                saml_idp_metadata: env_or(
                    "XAA_SAML_IDP_METADATA",
                    "https://idp.xaa.dev/saml/metadata",
                ),
            });
        }
        Ok(Self {
            resource: env_or("XAA_RESOURCE", "http://127.0.0.1:4001/"),
            idp_issuer: env_or("XAA_IDP_ISSUER", "http://127.0.0.1:4000"),
            idp_client_id: env_or("XAA_IDP_CLIENT_ID", "demo-app"),
            idp_client_secret: env_or("XAA_IDP_CLIENT_SECRET", "demo-idp-secret-not-a-real-secret"),
            resource_as_client_id: env_or("XAA_RESOURCE_AS_CLIENT_ID", "demo-app-at-todos"),
            resource_as_client_secret: env_or(
                "XAA_RESOURCE_AS_CLIENT_SECRET",
                "demo-resource-as-secret-not-a-real-secret",
            ),
            username: env_or("XAA_USERNAME", "alice"),
            scope: env_or("XAA_SCOPE", "todos.read"),
            flags,
            redirect_uri: String::new(),
            refresh_token: None,
            saml_sp_entity_id: String::new(),
            saml_acs_url: String::new(),
            saml_idp_metadata: String::new(),
        })
    }
}

/// **Demo only.** Stands in for an OpenID Connect login: asks the example
/// IdP's `/demo/login` stub for an ID Token. A real app gets its ID Token
/// from the authorization code flow, which is outside the `xaa` crate.
async fn demo_login(http: &ReqwestClient, config: &Config) -> Result<IdToken, BoxError> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("username", &config.username)
        .append_pair("client_id", &config.idp_client_id)
        .finish();
    let response = http
        .send(HttpRequest {
            method: Method::POST,
            url: Url::parse(&format!("{}/demo/login", config.idp_issuer))?,
            headers: vec![(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: body.into_bytes(),
        })
        .await?;
    if response.status != 200 {
        return Err(format!("demo login failed with status {}", response.status).into());
    }
    let document: Value = serde_json::from_slice(&response.body)?;
    let id_token = document
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or("the demo login response has no id_token")?;
    Ok(IdToken::new(id_token))
}

/// An [`HttpClient`] that can print what a token endpoint answered, for
/// `--verbose`. Any member that holds a token or a secret is replaced by its
/// length, so the output is safe to paste into a bug report.
struct Verbose<'a> {
    inner: &'a ReqwestClient,
    enabled: bool,
}

impl HttpClient for Verbose<'_> {
    async fn send(&self, request: HttpRequest) -> Result<xaa::http::HttpResponse, BoxError> {
        let response = self.inner.send(request).await?;
        if self.enabled {
            let body = match serde_json::from_slice::<Value>(&response.body) {
                Ok(Value::Object(mut members)) => {
                    for (name, value) in &mut members {
                        let secret = name != "token_type"
                            && name != "issued_token_type"
                            && (name.contains("token") || name.contains("secret"));
                        if secret {
                            let length = value.as_str().map_or(0, str::len);
                            *value = Value::from(format!("<redacted, {length} chars>"));
                        }
                    }
                    Value::Object(members).to_string()
                }
                _ => format!("<{} bytes, not a JSON object>", response.body.len()),
            };
            println!("      <- {} {body}", response.status);
        }
        Ok(response)
    }
}

/// The subject token for a playground run: the refresh token from the
/// environment if there is one, otherwise a browser login at the IdP.
async fn playground_subject(
    http: &ReqwestClient,
    config: &Config,
    idp: &xaa::client::DiscoveredIdp,
) -> Result<SubjectToken, BoxError> {
    if let Some(refresh_token) = &config.refresh_token {
        println!("[1/7] subject token: the refresh token from XAA_REFRESH_TOKEN");
        return Ok(SubjectToken::RefreshToken(RefreshToken::new(
            refresh_token.as_str(),
        )));
    }
    println!(
        "[1/7] sign in at {} (authorization code + PKCE)",
        idp.issuer
    );
    // `authorization_endpoint` is not part of the XAA profile, so the crate's
    // metadata type keeps it among the unmodelled members.
    let authorization_endpoint = idp
        .metadata
        .extra
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .ok_or("the IdP metadata has no authorization_endpoint")?;
    let login = login::authorization_code_login(
        http,
        &login::LoginRequest {
            authorization_endpoint: &Url::parse(authorization_endpoint)?,
            token_endpoint: &idp.token_endpoint,
            client_id: &config.idp_client_id,
            client_secret: &config.idp_client_secret,
            redirect_uri: &Url::parse(&config.redirect_uri)?,
            offline_access: config.flags.print_refresh_token,
        },
    )
    .await?;
    println!("      got an ID Token");
    if config.flags.print_refresh_token {
        match &login.refresh_token {
            Some(refresh_token) => println!(
                "      refresh token (a credential, keep it out of logs):\n      export XAA_REFRESH_TOKEN='{}'",
                refresh_token.expose_secret()
            ),
            None => println!("      the IdP returned no refresh token"),
        }
    }
    Ok(SubjectToken::IdToken(login.id_token))
}

/// The subject token for a `--saml` run (draft §4.5): sign the user in with
/// SAML, then trade the assertion for a Refresh Token at the IdP's token
/// endpoint. The assertion is used once; the Refresh Token is what the
/// ID-JAG exchange takes.
async fn saml_subject<C: HttpClient>(
    http: &ReqwestClient,
    token_http: &C,
    config: &Config,
    idp: &xaa::client::IdpConnection,
) -> Result<SubjectToken, BoxError> {
    println!("[1/7] sign in with SAML at {}", config.saml_idp_metadata);
    let login = saml_login::saml_login(
        http,
        &saml_login::SamlLoginRequest {
            idp_metadata: &Url::parse(&config.saml_idp_metadata)?,
            sp_entity_id: &config.saml_sp_entity_id,
            acs_url: &Url::parse(&config.saml_acs_url)?,
        },
    )
    .await?;
    println!(
        "      got a signed assertion for {} ({} bytes)",
        login.name_id,
        login.assertion.expose_secret().len()
    );
    println!("      exchange the assertion for a refresh token (draft section 4.5)");
    let mut exchange = SamlToRefreshToken::new(idp, &login.assertion, SystemTime::now())?;
    // The playground wants `email` and the resource scopes named here too.
    exchange.scope = Scope::parse(format!("openid offline_access email {}", config.scope))?;
    let refresh_token = exchange_saml_for_refresh_token(token_http, &exchange).await?;
    println!("      got a refresh token");
    Ok(SubjectToken::RefreshToken(refresh_token))
}

async fn run(config: &Config) -> Result<(), BoxError> {
    // Never follows redirects: one from a token endpoint would replay
    // credentials to another origin.
    let http = ReqwestClient::new()?;
    // The demo servers speak plain http on loopback. This is the one switch
    // that permits it; everything else stays as strict as in production.
    let options = FetchOptions {
        allow_http_loopback: true,
        ..FetchOptions::default()
    };

    // The playground login needs the IdP's metadata first, so there step 1
    // runs after discovery (steps 2 to 4) and is printed after them.
    let demo_subject = if config.flags.playground {
        None
    } else {
        println!(
            "[1/7] log in {} at {} (demo stub)",
            config.username, config.idp_issuer
        );
        let id_token = demo_login(&http, config).await?;
        println!("      got an ID Token");
        Some(SubjectToken::IdToken(id_token))
    };

    println!("[2/7] discover the resource {}", config.resource);
    let resource = discover_resource(
        &http,
        PrmOrigin::ResourceIdentifier(&config.resource),
        &options,
    )
    .await?;
    let resource_as_issuer = resource
        .metadata
        .authorization_servers()
        .first()
        .ok_or("the resource names no authorization server")?
        .clone();
    println!("      authorization server: {resource_as_issuer}");

    println!("[3/7] discover the Resource AS");
    let discovered = discover_resource_as(&http, &resource_as_issuer, &options).await?;
    println!(
        "      token endpoint: {} (ID-JAG profile advertised: {}, jwt-dpop: {})",
        discovered.token_endpoint,
        discovered.id_jag_profile.is_advertised(),
        discovered.jwt_dpop.is_advertised(),
    );
    // The playground registers its clients for `client_secret_post`; the
    // local example Resource AS takes either, and Basic is shown there.
    let resource_as_auth = if config.flags.playground {
        ClientAuth::ClientSecretPost {
            client_id: config.resource_as_client_id.clone(),
            secret: ClientSecret::new(config.resource_as_client_secret.as_str()),
        }
    } else {
        ClientAuth::ClientSecretBasic {
            client_id: config.resource_as_client_id.clone(),
            secret: ClientSecret::new(config.resource_as_client_secret.as_str()),
        }
    };
    let resource_as = discovered.connection(ResourceAsClientAuth::Authenticated(resource_as_auth));

    // Which IdP a user belongs to is the app's knowledge, not discoverable
    // from the resource (draft Appendix A.4.2.1).
    println!("[4/7] discover the IdP {}", config.idp_issuer);
    let discovered =
        discover_idp(&http, &Issuer::new(config.idp_issuer.as_str()), &options).await?;
    println!(
        "      token endpoint: {} (issues ID-JAGs: {})",
        discovered.token_endpoint,
        discovered.issues_id_jag.is_advertised(),
    );
    let idp = discovered.connection(ClientAuth::ClientSecretPost {
        client_id: config.idp_client_id.clone(),
        secret: ClientSecret::new(config.idp_client_secret.as_str()),
    });
    let token_http = Verbose {
        inner: &http,
        enabled: config.flags.verbose,
    };
    let subject = match demo_subject {
        Some(subject) => subject,
        None if config.flags.saml => saml_subject(&http, &token_http, config, &idp).await?,
        None => playground_subject(&http, config, &discovered).await?,
    };

    // One key for both legs: the Resource AS only accepts a bound ID-JAG
    // together with a proof by the key it is bound to.
    let dpop_key = config
        .flags
        .dpop
        .then(|| DpopKey::generate(SignatureAlgorithm::Es256))
        .transpose()?;
    let dpop = dpop_key
        .as_ref()
        .map(|key| DpopRequest { key, nonce: None });
    if let Some(key) = &dpop_key {
        println!("      DPoP key thumbprint: {}", key.thumbprint());
    }

    println!("[5/7] exchange the subject token for an ID-JAG (RFC 8693)");
    let mut exchange = TokenExchange::new(&idp, &resource_as, &subject, SystemTime::now());
    exchange.resources = vec![resource.resource.clone()];
    exchange.scope = Some(Scope::parse(config.scope.as_str())?);
    exchange.dpop = dpop;
    // The playground IdP drops the trailing slash of the resource it echoes
    // into the ID-JAG (docs/interop.md). The check stays exact elsewhere.
    exchange.tolerate_resource_trailing_slash = config.flags.playground;
    let id_jag = exchange_for_id_jag(&token_http, &exchange).await?;
    println!(
        "      ID-JAG for client {} at {}, scope: {}, bound to the DPoP key: {}",
        id_jag.peek.client_id(),
        resource_as.issuer,
        id_jag.scope.as_ref().map_or("<none>", Scope::as_str),
        id_jag.peek.confirmation().is_some(),
    );

    println!("[6/7] present the ID-JAG for an access token (RFC 7523)");
    let token = request_access_token(
        &token_http,
        &AccessTokenRequest {
            resource_as: &resource_as,
            id_jag: &id_jag,
            // Name the scope again here. The draft makes it optional, but a
            // Resource AS may read "no scope" as "grant none": the xaa.dev
            // one then issues a token the API refuses with 403.
            scope: id_jag.scope.clone(),
            dpop,
            now: SystemTime::now(),
        },
    )
    .await?;
    println!(
        "      token_type: {:?}, scope: {}, expires in: {}s",
        token.token_type,
        token.scope.as_ref().map_or("<none>", Scope::as_str),
        token.expires_in.map_or(0, |lifetime| lifetime.as_secs()),
    );
    if config.flags.dpop && !token.is_sender_constrained() {
        return Err("asked for a DPoP-bound access token but got a bearer token".into());
    }

    // The Resource Server call is the app's own HTTP request; the crate's
    // part is the DPoP proof for it.
    let todos_url = Url::parse(resource.resource.as_str())?.join("api/todos")?;
    println!("[7/7] GET {todos_url}");
    let mut headers = vec![("Accept".to_owned(), "application/json".to_owned())];
    let secret = token.access_token.expose_secret();
    match &dpop_key {
        Some(key) if token.is_sender_constrained() => {
            let proof = key
                .proof_for_resource(
                    &Method::GET,
                    &todos_url,
                    &token.access_token,
                    None,
                    SystemTime::now(),
                )
                .await?;
            headers.push(("Authorization".to_owned(), format!("DPoP {secret}")));
            headers.push(("DPoP".to_owned(), proof));
        }
        _ => headers.push(("Authorization".to_owned(), format!("Bearer {secret}"))),
    }
    let response = http
        .send(HttpRequest {
            method: Method::GET,
            url: todos_url,
            headers,
            body: Vec::new(),
        })
        .await?;
    if response.status != 200 {
        // The challenge names the reason (for example `insufficient_scope`)
        // and carries no credential.
        return Err(format!(
            "the todo API answered with status {} ({})",
            response.status,
            response
                .header("www-authenticate")
                .unwrap_or("no WWW-Authenticate header"),
        )
        .into());
    }
    let todos: Value = serde_json::from_slice(&response.body)?;
    println!("{}", serde_json::to_string_pretty(&todos)?);
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut flags = Flags::default();
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--dpop" => flags.dpop = true,
            "--playground" => flags.playground = true,
            "--saml" => flags.saml = true,
            "--verbose" => flags.verbose = true,
            "--print-refresh-token" => flags.print_refresh_token = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    if flags.saml && !flags.playground {
        eprintln!("--saml needs --playground\n\n{USAGE}");
        return ExitCode::from(2);
    }
    let outcome = match Config::from_env(flags) {
        Ok(config) => run(&config).await,
        Err(error) => Err(error),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
