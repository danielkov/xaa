//! SAML 2.0 Web Browser SSO as a Service Provider, for `--playground --saml`.
//!
//! User authentication is outside the `xaa` crate (draft §4.2). On the SAML
//! path the crate starts from a signed `<saml:Assertion>` the app already
//! has (draft §4.5). This module gets one with the `saml` crate: it sends an
//! `AuthnRequest` through the browser, receives the Response on a loopback
//! Assertion Consumer Service, validates it, and keeps the verified assertion
//! as a standalone document.

use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use saml::binding::{Binding, Dispatch, SsoResponseBinding};
use saml::dsig::algorithms::{DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm};
use saml::sp::{ConsumeResponse, StartLogin};

use xaa::http::{BoxError, HttpClient, HttpRequest, Method, ReqwestClient};
use xaa::secret::SamlAssertion;

/// Largest ACS request body accepted. A signed Response is a few kilobytes.
const MAX_BODY: usize = 1024 * 1024;
const CLOCK_SKEW: Duration = Duration::from_mins(1);

/// What the sign-on needs to know about the IdP and this app's registration.
pub struct SamlLoginRequest<'a> {
    /// Where the IdP publishes its SAML metadata.
    pub idp_metadata: &'a Url,
    /// This app's registered SP entity ID.
    pub sp_entity_id: &'a str,
    /// This app's registered ACS URL: `http` on `localhost` with a port.
    pub acs_url: &'a Url,
}

pub struct SamlLogin {
    /// The verified assertion, on its own, as the IdP signed it.
    pub assertion: SamlAssertion,
    pub name_id: String,
}

fn service_provider(request: &SamlLoginRequest<'_>) -> Result<saml::ServiceProvider, BoxError> {
    Ok(saml::ServiceProvider::new(saml::ServiceProviderConfig {
        entity_id: request.sp_entity_id.to_owned(),
        acs: vec![saml::SsoResponseEndpoint::post(
            request.acs_url.as_str(),
            0,
            true,
        )],
        slo: vec![],
        name_id_formats: vec![saml::NameIdFormat::EmailAddress],
        signing_key: None,
        decryption_key: None,
        sign_authn_requests: false,
        // The assertion must carry its own signature: it travels to the token
        // endpoint without the Response around it.
        want_signed: saml::SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: false,
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        verifier: None,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })?)
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Run the browser sign-on and return the verified assertion.
pub async fn saml_login(
    http: &ReqwestClient,
    request: &SamlLoginRequest<'_>,
) -> Result<SamlLogin, BoxError> {
    let acs = request.acs_url;
    let port = acs.port().ok_or("the ACS URL needs an explicit port")?;
    if acs.scheme() != "http" || !matches!(acs.host_str(), Some("127.0.0.1" | "localhost")) {
        return Err("the ACS URL must be http on localhost or 127.0.0.1".into());
    }
    // Listen before sending the user away, so the Response cannot arrive
    // while nothing is there to receive it.
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;

    let metadata = http
        .send(HttpRequest {
            method: Method::GET,
            url: request.idp_metadata.clone(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await?;
    if metadata.status != 200 {
        return Err(format!(
            "fetching the IdP SAML metadata failed with status {}",
            metadata.status
        )
        .into());
    }
    let idp = saml::IdpDescriptor::from_metadata_xml(&metadata.body)?;

    let sp = service_provider(request)?;
    let relay_state = random_token();
    let started = sp.start_login(
        &idp,
        StartLogin {
            relay_state: Some(&relay_state),
            binding: Binding::HttpRedirect,
            force_authn: false,
            is_passive: false,
            requested_name_id_format: None,
            requested_authn_context: None,
            acs_index: None,
            acs_url: Some(acs.as_str()),
            response_binding: Some(SsoResponseBinding::HttpPost),
        },
    )?;
    let Dispatch::Redirect(sso_url) = started.dispatch else {
        return Err("expected a redirect to the IdP".into());
    };
    println!("      open this URL in a browser and sign in:\n\n      {sso_url}\n");
    println!("      waiting for the SAML Response at {acs} ...");

    let form = wait_for_response(&listener, acs.path()).await?;
    if form.relay_state.as_deref() != Some(relay_state.as_str()) {
        return Err("the SAML Response carried the wrong RelayState".into());
    }
    let response_xml = STANDARD.decode(form.saml_response.trim().as_bytes())?;

    let consumed = sp.consume_response_with_assertion(ConsumeResponse {
        idp: &idp,
        peer_crypto_policy: None,
        saml_response: &response_xml,
        binding: SsoResponseBinding::HttpPost,
        relay_state: Some(&relay_state),
        tracker: Some(&started.tracker),
        expected_destination: acs.as_str(),
        now: SystemTime::now(),
        clock_skew: CLOCK_SKEW,
        // One Response per run, in a process that then exits.
        replay_cache: None,
        replay_mode: saml::ReplayMode::All,
        holder_of_key_cert: None,
    })?;
    let name_id = consumed.identity.name_id().value.clone();
    let assertion = consumed
        .assertion
        .ok_or("the assertion has no signature of its own, so it cannot be a subject token")?;
    Ok(SamlLogin {
        assertion: SamlAssertion::new(assertion.into_xml()),
        name_id,
    })
}

struct AcsForm {
    saml_response: String,
    relay_state: Option<String>,
}

/// Serve the loopback port until the IdP's form POST arrives at the ACS.
///
/// Each connection is served on its own task: browsers open idle
/// speculative connections, and waiting on one would block the real POST.
async fn wait_for_response(listener: &TcpListener, acs_path: &str) -> Result<AcsForm, BoxError> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let sender = sender.clone();
                let acs_path = acs_path.to_owned();
                tokio::spawn(async move {
                    if let Some(outcome) = serve(stream, &acs_path).await.transpose() {
                        // A closed channel means another connection won.
                        drop(sender.send(outcome.map_err(|error| error.to_string())).await);
                    }
                });
            }
            Some(outcome) = receiver.recv() => return outcome.map_err(Into::into),
        }
    }
}

/// Serve one connection. `Ok(None)` when it was not the POST to the ACS.
async fn serve(stream: TcpStream, acs_path: &str) -> Result<Option<AcsForm>, BoxError> {
    let mut stream = BufReader::new(stream);
    let mut request_line = String::new();
    if stream.read_line(&mut request_line).await? == 0 {
        return Ok(None);
    }
    // "POST /saml/acs HTTP/1.1"
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let path = target.split_once('?').map_or(target, |(path, _)| path);

    let mut content_length = 0_usize;
    loop {
        let mut header = String::new();
        if stream.read_line(&mut header).await? == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse()?;
        }
    }
    if method != "POST" || path != acs_path || content_length > MAX_BODY {
        // Browsers also ask for /favicon.ico and the like.
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(None);
    }
    let mut body = vec![0_u8; content_length];
    stream.read_exact(&mut body).await?;

    let parameter = |name: &str| {
        url::form_urlencoded::parse(&body)
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    let form = parameter("SAMLResponse").map(|saml_response| AcsForm {
        saml_response,
        relay_state: parameter("RelayState"),
    });
    let page = if form.is_some() {
        "Signed in. You can close this tab and return to the terminal."
    } else {
        "Sign-in failed. See the terminal for details."
    };
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await?;
    form.map(Some)
        .ok_or_else(|| "the POST to the ACS carried no SAMLResponse".into())
}
