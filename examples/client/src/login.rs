//! OpenID Connect authorization code login with PKCE, for `--playground`.
//!
//! User authentication is outside the `xaa` crate (draft §4.2): the crate
//! starts from a subject token the app already has. This module is the
//! smallest thing that gets one from a real IdP. It prints the authorization
//! URL, waits on a loopback port for the redirect, and redeems the code. A
//! real app would use an OIDC library, and would validate the ID Token
//! (signature, `nonce`, `aud`) before treating the user as signed in. Here
//! the token is only passed on to the same IdP that issued it, which
//! validates it itself.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use xaa::http::{BoxError, HttpClient, HttpRequest, Method, ReqwestClient};
use xaa::secret::{IdToken, RefreshToken};

/// What the login needs to know about the IdP and this app's registration.
pub struct LoginRequest<'a> {
    pub authorization_endpoint: &'a Url,
    pub token_endpoint: &'a Url,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    /// A loopback `http` URL registered as a redirect URI for the client.
    pub redirect_uri: &'a Url,
    /// Whether to ask for `offline_access`, and so a refresh token.
    pub offline_access: bool,
}

pub struct Login {
    pub id_token: IdToken,
    pub refresh_token: Option<RefreshToken>,
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Run the browser login and return the tokens.
pub async fn authorization_code_login(
    http: &ReqwestClient,
    request: &LoginRequest<'_>,
) -> Result<Login, BoxError> {
    let redirect = request.redirect_uri;
    let host = redirect.host_str().ok_or("the redirect URI has no host")?;
    let port = redirect
        .port()
        .ok_or("the redirect URI needs an explicit port")?;
    if redirect.scheme() != "http" || !matches!(host, "127.0.0.1" | "localhost") {
        return Err("the redirect URI must be http on 127.0.0.1 or localhost".into());
    }
    // Listen before sending the user away, so the redirect cannot arrive
    // while nothing is there to receive it.
    let listener = TcpListener::bind((host, port)).await?;

    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_token();
    let scope = if request.offline_access {
        "openid offline_access"
    } else {
        "openid"
    };
    let mut authorize = request.authorization_endpoint.clone();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", request.client_id)
        .append_pair("redirect_uri", redirect.as_str())
        .append_pair("scope", scope)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    println!("      open this URL in a browser and sign in:\n\n      {authorize}\n");
    println!("      waiting for the redirect to {redirect} ...");

    let code = wait_for_code(&listener, redirect.path(), &state).await?;

    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", redirect.as_str())
        .append_pair("code_verifier", &verifier)
        .append_pair("client_id", request.client_id)
        .append_pair("client_secret", request.client_secret)
        .finish();
    let response = http
        .send(HttpRequest {
            method: Method::POST,
            url: request.token_endpoint.clone(),
            headers: vec![
                (
                    "Content-Type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("Accept".to_owned(), "application/json".to_owned()),
            ],
            body: body.into_bytes(),
        })
        .await?;
    let document: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    if response.status != 200 {
        // The error code and description are not secrets; the body of a
        // success response is, so only these two members are ever printed.
        let member = |name: &str| document.get(name).and_then(Value::as_str).unwrap_or("-");
        return Err(format!(
            "the code exchange failed with status {}: {} ({})",
            response.status,
            member("error"),
            member("error_description"),
        )
        .into());
    }
    let id_token = document
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or("the token response has no id_token")?;
    Ok(Login {
        id_token: IdToken::new(id_token),
        refresh_token: document
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(RefreshToken::new),
    })
}

/// Serve the loopback port until the redirect arrives, and return its `code`.
///
/// Each connection is served on its own task: browsers open idle
/// speculative connections, and waiting on one would block the redirect.
async fn wait_for_code(
    listener: &TcpListener,
    callback_path: &str,
    expected_state: &str,
) -> Result<String, BoxError> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let sender = sender.clone();
                let callback_path = callback_path.to_owned();
                let expected_state = expected_state.to_owned();
                tokio::spawn(async move {
                    let served = serve(stream, &callback_path, &expected_state).await;
                    if let Some(outcome) = served.map_err(|error| error.to_string()).transpose() {
                        // A closed channel means another connection won.
                        drop(sender.send(outcome.and_then(|code| code)).await);
                    }
                });
            }
            Some(outcome) = receiver.recv() => return outcome.map_err(Into::into),
        }
    }
}

/// Serve one connection. `Ok(None)` when it was not the redirect; otherwise
/// the `code`, or why the redirect is unusable.
async fn serve(
    stream: TcpStream,
    callback_path: &str,
    expected_state: &str,
) -> Result<Option<Result<String, String>>, BoxError> {
    let mut stream = BufReader::new(stream);
    let mut request_line = String::new();
    if stream.read_line(&mut request_line).await? == 0 {
        return Ok(None);
    }
    // "GET /callback?code=...&state=... HTTP/1.1"
    let target = request_line.split(' ').nth(1).unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != callback_path {
        // Browsers also ask for /favicon.ico and the like.
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(None);
    }
    let parameter = |name: &str| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    let outcome = match (parameter("code"), parameter("state"), parameter("error")) {
        (_, _, Some(error)) => Err(format!(
            "the IdP returned an error: {error} ({})",
            parameter("error_description").unwrap_or_default()
        )),
        (Some(code), Some(state), None) if state == expected_state => Ok(code),
        (Some(_), _, None) => Err("the redirect carried the wrong state".to_owned()),
        (None, _, None) => Err("the redirect carried no code".to_owned()),
    };
    let page = match &outcome {
        Ok(_) => "Signed in. You can close this tab and return to the terminal.",
        Err(_) => "Sign-in failed. See the terminal for details.",
    };
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(Some(outcome))
}
