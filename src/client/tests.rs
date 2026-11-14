//! One test per row of the RFC-003 rule tables.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use url::Url;

use super::*;
use crate::claims::{AuthorizationDetails, Confirmation, Issuer, Scope};
use crate::dpop::{DpopKey, DpopRequest};
use crate::error::Error;
use crate::http::{HttpRequest, HttpResponse};
use crate::jose::b64url_decode;
use crate::metadata::{FetchOptions, PrmOrigin, Support};
use crate::mtls::tests::{RFC_8705_THUMBPRINT, rfc_8705_certificate_der};
use crate::oauth_error::OAuthErrorCode;
use crate::secret::{ClientSecret, IdToken, RefreshToken, SamlAssertion};
use crate::test_support::{
    MockHttpClient, NOW_SECS, json_response, now, other_rsa_key, p256_key, p384_key, rsa_key, sign,
};

const IDP: &str = "https://idp.example";
const IDP_TOKEN: &str = "https://idp.example/token";
const AS: &str = "https://as.resource.example";
const AS_TOKEN: &str = "https://as.resource.example/token";
const RESOURCE: &str = "https://api.resource.example/";
const IDP_CLIENT: &str = "idp-client";
const AS_CLIENT: &str = "app-at-resource";
const ID_TOKEN: &str = "id-token-value";

const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GRANT_JWT_DPOP: &str = "urn:ietf:params:oauth:grant-type:jwt-dpop";
const TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
const TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
const TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn idp_with(client_auth: ClientAuth) -> IdpConnection {
    IdpConnection {
        issuer: Issuer::new(IDP),
        token_endpoint: Url::parse(IDP_TOKEN).unwrap(),
        client_auth,
        saml_encoding: SamlEncoding::default(),
    }
}

fn idp() -> IdpConnection {
    idp_with(ClientAuth::ClientSecretPost {
        client_id: IDP_CLIENT.to_owned(),
        secret: ClientSecret::new("idp-secret"),
    })
}

fn resource_as_with(client_auth: ResourceAsClientAuth) -> ResourceAsConnection {
    ResourceAsConnection {
        issuer: Issuer::new(AS),
        token_endpoint: Url::parse(AS_TOKEN).unwrap(),
        client_auth,
        supports_jwt_dpop: true,
    }
}

fn resource_as() -> ResourceAsConnection {
    resource_as_with(ResourceAsClientAuth::Authenticated(
        ClientAuth::ClientSecretBasic {
            client_id: AS_CLIENT.to_owned(),
            secret: ClientSecret::new("as-secret"),
        },
    ))
}

fn unauthenticated_resource_as() -> ResourceAsConnection {
    resource_as_with(ResourceAsClientAuth::SenderConstrainedOnly {
        client_id: AS_CLIENT.to_owned(),
    })
}

fn without_jwt_dpop(mut connection: ResourceAsConnection) -> ResourceAsConnection {
    connection.supports_jwt_dpop = false;
    connection
}

fn subject() -> SubjectToken {
    SubjectToken::IdToken(IdToken::new(ID_TOKEN))
}

fn scope(text: &str) -> Scope {
    Scope::parse(text).unwrap()
}

fn dpop_key() -> DpopKey {
    let key = p256_key();
    let public = key.public_jwk();
    DpopKey::from_signer(Arc::new(key), public).unwrap()
}

fn other_dpop_key() -> DpopKey {
    let key = p384_key();
    let public = key.public_jwk();
    DpopKey::from_signer(Arc::new(key), public).unwrap()
}

fn form(request: &HttpRequest) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&request.body)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn param<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut values = form.iter().filter(|(key, _)| key == name);
    let first = values.next().map(|(_, value)| value.as_str());
    assert!(values.next().is_none(), "{name} is repeated");
    first
}

fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Header and payload of a compact JWS.
fn decode_jwt(token: &str) -> (Value, Value) {
    let mut segments = token.split('.');
    let mut next = || {
        let bytes = b64url_decode(segments.next().unwrap()).unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    };
    (next(), next())
}

/// A well-formed ID-JAG claim set for this client at this Resource AS.
fn claims() -> Value {
    json!({
        "iss": IDP,
        "sub": "alice",
        "aud": AS,
        "client_id": AS_CLIENT,
        "jti": "jti-1",
        "iat": NOW_SECS,
        "exp": NOW_SECS + 300,
    })
}

fn with(mut value: Value, name: &str, member: Value) -> Value {
    value
        .as_object_mut()
        .unwrap()
        .insert(name.to_owned(), member);
    value
}

fn without(mut value: Value, name: &str) -> Value {
    value.as_object_mut().unwrap().remove(name);
    value
}

async fn id_jag(claims: &Value) -> String {
    sign(&rsa_key(), Some("oauth-id-jag+jwt"), claims).await
}

fn exchange_body(token: &str) -> Value {
    json!({
        "issued_token_type": TYPE_ID_JAG,
        "access_token": token,
        "token_type": "N_A",
        "expires_in": 300,
    })
}

fn ok(body: &Value) -> HttpResponse {
    json_response(200, body)
}

fn oauth_error(status: u16, code: &str) -> HttpResponse {
    json_response(status, &json!({ "error": code }))
}

/// The ID-JAG the IdP issues for `claims`, as the client holds it after an
/// exchange that asked for no binding.
async fn issued(claims: &Value) -> IssuedIdJag {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange {
        resources: vec![ResourceIdentifier::new(RESOURCE)],
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    parse_token_exchange_response(&exchange, ok(&exchange_body(&id_jag(claims).await))).unwrap()
}

fn jkt(key: &DpopKey) -> Value {
    json!({ "jkt": key.thumbprint() })
}

fn token_body() -> Value {
    json!({ "access_token": "at-value", "token_type": "Bearer", "expires_in": 7200 })
}

// ---------------------------------------------------------------------------
// §3 Token Exchange request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_exchange_golden_request() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange {
        resources: vec![ResourceIdentifier::new(RESOURCE)],
        scope: Some(scope("todos.read")),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let request = exchange.build().await.unwrap();

    assert_eq!(request.method, http::Method::POST);
    assert_eq!(request.url.as_str(), IDP_TOKEN);
    assert_eq!(request.url.query(), None);
    assert_eq!(
        request.headers,
        pairs(&[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
        ])
    );
    assert_eq!(
        String::from_utf8(request.body).unwrap(),
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
         &requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag\
         &audience=https%3A%2F%2Fas.resource.example\
         &resource=https%3A%2F%2Fapi.resource.example%2F\
         &scope=todos.read\
         &subject_token=id-token-value\
         &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token\
         &client_id=idp-client\
         &client_secret=idp-secret"
    );
}

#[tokio::test]
async fn token_exchange_sends_every_parameter_in_order() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let details =
        r#"[{"type":"todo","actions":["read"],"locations":["https://api.resource.example/"]}]"#;
    let exchange = TokenExchange {
        audience: ExchangeAudience::new("urn:example:idp:saas-tool"),
        resources: vec![
            ResourceIdentifier::new("https://b.example/x"),
            ResourceIdentifier::new("https://a.example/"),
        ],
        scope: Some(scope("todos.read todos.write")),
        authorization_details: Some(AuthorizationDetails::from_json_str(details).unwrap()),
        actor_token: Some(ActorToken::new(
            "actor-value",
            "urn:ietf:params:oauth:token-type:jwt",
        )),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let form = form(&exchange.build().await.unwrap());

    let sent_details = param(&form, "authorization_details").unwrap().to_owned();
    assert_eq!(
        serde_json::from_str::<Value>(&sent_details).unwrap(),
        serde_json::from_str::<Value>(details).unwrap()
    );
    assert_eq!(
        form,
        pairs(&[
            ("grant_type", GRANT_TOKEN_EXCHANGE),
            ("requested_token_type", TYPE_ID_JAG),
            ("audience", "urn:example:idp:saas-tool"),
            ("resource", "https://b.example/x"),
            ("resource", "https://a.example/"),
            ("scope", "todos.read todos.write"),
            ("authorization_details", &sent_details),
            ("subject_token", ID_TOKEN),
            ("subject_token_type", TYPE_ID_TOKEN),
            ("actor_token", "actor-value"),
            ("actor_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            ("client_id", IDP_CLIENT),
            ("client_secret", "idp-secret"),
        ])
    );
}

#[tokio::test]
async fn token_exchange_minimal_request_omits_optional_parameters() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let request = TokenExchange::new(&idp, &resource_as, &subject, now())
        .build()
        .await
        .unwrap();
    assert_eq!(
        form(&request),
        pairs(&[
            ("grant_type", GRANT_TOKEN_EXCHANGE),
            ("requested_token_type", TYPE_ID_JAG),
            ("audience", AS),
            ("subject_token", ID_TOKEN),
            ("subject_token_type", TYPE_ID_TOKEN),
            ("client_id", IDP_CLIENT),
            ("client_secret", "idp-secret"),
        ])
    );
    assert_eq!(header(&request, "DPoP"), None);
    assert_eq!(header(&request, "Authorization"), None);
}

#[tokio::test]
async fn resource_identifiers_are_sent_unchanged() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    // No case folding, no trailing-slash or percent-encoding normalization.
    let given = [
        "HTTPS://API.Example/Path",
        "https://api.example",
        "https://api.example/",
        "https://api.example/a%2fb/../c?x=1&y=2",
    ];
    let exchange = TokenExchange {
        resources: given.iter().map(|r| ResourceIdentifier::new(*r)).collect(),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let form = form(&exchange.build().await.unwrap());
    let sent: Vec<&str> = form
        .iter()
        .filter(|(name, _)| name == "resource")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(sent, given);
}

#[tokio::test]
async fn subject_token_types() {
    let idp = idp();
    let resource_as = resource_as();

    let refresh = SubjectToken::RefreshToken(RefreshToken::new("rt-value"));
    let form_of = form(
        &TokenExchange::new(&idp, &resource_as, &refresh, now())
            .build()
            .await
            .unwrap(),
    );
    assert_eq!(param(&form_of, "subject_token"), Some("rt-value"));
    assert_eq!(
        param(&form_of, "subject_token_type"),
        Some(TYPE_REFRESH_TOKEN)
    );

    // Bytes whose two encodings differ in alphabet and padding.
    let saml = SubjectToken::SamlAssertion(SamlAssertion::new(vec![0xfb, 0xef, 0xbe, 0xff]));
    let form_of = form(
        &TokenExchange::new(&idp, &resource_as, &saml, now())
            .build()
            .await
            .unwrap(),
    );
    assert_eq!(param(&form_of, "subject_token"), Some("----_w"));
    assert_eq!(param(&form_of, "subject_token_type"), Some(TYPE_SAML2));

    let mut padded = idp.clone();
    padded.saml_encoding = SamlEncoding::Base64;
    let form_of = form(
        &TokenExchange::new(&padded, &resource_as, &saml, now())
            .build()
            .await
            .unwrap(),
    );
    assert_eq!(param(&form_of, "subject_token"), Some("++++/w=="));
    assert_eq!(param(&form_of, "subject_token_type"), Some(TYPE_SAML2));
}

#[tokio::test]
async fn token_exchange_client_authentication_variants() {
    let resource_as = resource_as();
    let subject = subject();

    // client_secret_basic: header only, nothing in the form.
    let idp = idp_with(ClientAuth::ClientSecretBasic {
        client_id: IDP_CLIENT.to_owned(),
        secret: ClientSecret::new("idp-secret"),
    });
    let request = TokenExchange::new(&idp, &resource_as, &subject, now())
        .build()
        .await
        .unwrap();
    // base64("idp-client:idp-secret")
    assert_eq!(
        header(&request, "Authorization"),
        Some("Basic aWRwLWNsaWVudDppZHAtc2VjcmV0")
    );
    let sent = form(&request);
    assert_eq!(param(&sent, "client_id"), None);
    assert_eq!(param(&sent, "client_secret"), None);

    // private_key_jwt: an assertion whose audience is the IdP issuer.
    let idp = idp_with(ClientAuth::PrivateKeyJwt {
        client_id: IDP_CLIENT.to_owned(),
        signer: Arc::new(rsa_key()),
    });
    let request = TokenExchange::new(&idp, &resource_as, &subject, now())
        .build()
        .await
        .unwrap();
    let sent = form(&request);
    assert_eq!(param(&sent, "client_assertion_type"), Some(ASSERTION_TYPE));
    let (assertion_header, assertion) = decode_jwt(param(&sent, "client_assertion").unwrap());
    assert_eq!(assertion_header["typ"], "client-authentication+jwt");
    assert_eq!(assertion["iss"], IDP_CLIENT);
    assert_eq!(assertion["sub"], IDP_CLIENT);
    assert_eq!(assertion["aud"], IDP);
    assert_eq!(assertion["iat"], NOW_SECS);
    assert_eq!(param(&sent, "client_secret"), None);
    assert_eq!(header(&request, "Authorization"), None);

    // tls_client_auth: client_id only.
    let idp = idp_with(ClientAuth::TlsClientAuth {
        client_id: IDP_CLIENT.to_owned(),
    });
    let request = TokenExchange::new(&idp, &resource_as, &subject, now())
        .build()
        .await
        .unwrap();
    let sent = form(&request);
    assert_eq!(param(&sent, "client_id"), Some(IDP_CLIENT));
    assert_eq!(param(&sent, "client_secret"), None);
    assert_eq!(param(&sent, "client_assertion"), None);
    assert_eq!(header(&request, "Authorization"), None);
}

#[tokio::test]
async fn token_exchange_dpop_proof_targets_the_idp_token_endpoint() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let key = dpop_key();
    let exchange = TokenExchange {
        dpop: Some(DpopRequest {
            key: &key,
            nonce: Some("nonce-1"),
        }),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let request = exchange.build().await.unwrap();
    let (proof_header, proof) = decode_jwt(header(&request, "DPoP").unwrap());
    assert_eq!(proof_header["typ"], "dpop+jwt");
    assert_eq!(
        serde_json::to_value(key.public_jwk()).unwrap(),
        proof_header["jwk"]
    );
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], IDP_TOKEN);
    assert_eq!(proof["iat"], NOW_SECS);
    assert_eq!(proof["nonce"], "nonce-1");
    // The proof is a header; the form and URL are unchanged by it.
    assert_eq!(request.url.as_str(), IDP_TOKEN);
    assert_eq!(param(&form(&request), "dpop"), None);
}

#[tokio::test]
async fn token_exchange_refuses_dpop_for_an_as_without_jwt_dpop() {
    let idp = idp();
    let resource_as = without_jwt_dpop(resource_as());
    let subject = subject();
    let key = dpop_key();
    let exchange = TokenExchange {
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    assert!(matches!(
        exchange.build().await.unwrap_err(),
        Error::ResourceAsLacksJwtDpop
    ));
    // Without the proof the same exchange builds.
    TokenExchange::new(&idp, &resource_as, &subject, now())
        .build()
        .await
        .unwrap();
}

#[tokio::test]
async fn token_exchange_refuses_unusable_inputs() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let base = TokenExchange::new(&idp, &resource_as, &subject, now());

    let empty_audience = TokenExchange {
        audience: ExchangeAudience::new(""),
        ..base.clone()
    };
    let empty_resource = TokenExchange {
        resources: vec![ResourceIdentifier::new("")],
        ..base.clone()
    };
    // RFC 8693 §2.1: actor_token_type is REQUIRED with actor_token.
    let untyped_actor = TokenExchange {
        actor_token: Some(ActorToken::new("actor-value", "")),
        ..base.clone()
    };
    for exchange in [empty_audience, empty_resource, untyped_actor] {
        assert!(matches!(
            exchange.build().await.unwrap_err(),
            Error::InvalidRequest { .. }
        ));
    }

    let empty_subject = SubjectToken::IdToken(IdToken::new(""));
    assert!(matches!(
        TokenExchange::new(&idp, &resource_as, &empty_subject, now())
            .build()
            .await
            .unwrap_err(),
        Error::InvalidRequest { .. }
    ));

    // PEM passed where DER is expected.
    let pem = b"-----BEGIN CERTIFICATE-----";
    let not_der = TokenExchange {
        tls_client_certificate: Some(pem),
        ..base
    };
    assert!(matches!(
        not_der.build().await.unwrap_err(),
        Error::InvalidConfiguration { .. }
    ));
}

// ---------------------------------------------------------------------------
// §4 Token Exchange response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_exchange_response_is_parsed() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange {
        scope: Some(scope("todos.read todos.write")),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let token = id_jag(&with(claims(), "scope", json!("todos.read"))).await;
    let details = json!([{ "type": "todo", "actions": ["read"] }]);
    let body = with(
        with(exchange_body(&token), "scope", json!("todos.read")),
        "authorization_details",
        details.clone(),
    );

    let issued = parse_token_exchange_response(&exchange, ok(&body)).unwrap();
    assert_eq!(issued.id_jag.expose_secret(), token);
    assert_eq!(issued.scope, Some(scope("todos.read")));
    assert_eq!(
        serde_json::to_value(issued.authorization_details.as_ref().unwrap()).unwrap(),
        details
    );
    assert_eq!(issued.expires_in, Some(Duration::from_secs(300)));
    assert_eq!(issued.received_at, now());
    assert!(issued.fresh);

    assert_eq!(issued.peek.issuer().as_str(), IDP);
    assert_eq!(issued.peek.audience().sole(), Some(AS));
    assert_eq!(issued.peek.client_id(), AS_CLIENT);
    assert_eq!(issued.peek.scope(), Some(&scope("todos.read")));
    assert_eq!(issued.peek.resources(), None);
    assert_eq!(issued.peek.confirmation(), None);
    assert_eq!(issued.peek.expires_at().as_secs(), NOW_SECS + 300);
    assert!(!issued.is_expired(now()));
    assert!(issued.is_expired(now().checked_add(Duration::from_secs(300)).unwrap()));
}

#[tokio::test]
async fn omitted_scope_means_the_requested_scope() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let token = id_jag(&claims()).await;

    let exchange = TokenExchange {
        scope: Some(scope("todos.read")),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let issued = parse_token_exchange_response(&exchange, ok(&exchange_body(&token))).unwrap();
    assert_eq!(issued.scope, Some(scope("todos.read")));

    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());
    let body = without(exchange_body(&token), "expires_in");
    let issued = parse_token_exchange_response(&exchange, ok(&body)).unwrap();
    assert_eq!(issued.scope, None);
    assert_eq!(issued.expires_in, None);
    assert!(issued.authorization_details.is_none());
}

#[tokio::test]
async fn token_exchange_response_rules() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());
    let token = id_jag(&claims()).await;
    let good = exchange_body(&token);
    let parse = |body: &Value| parse_token_exchange_response(&exchange, ok(body));

    // Rule 2: a JSON object, with unique member names.
    for body in [&b"not json"[..], b"[]", b"\"x\"", b""] {
        let response = HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.to_vec(),
        };
        assert!(matches!(
            parse_token_exchange_response(&exchange, response).unwrap_err(),
            Error::InvalidTokenResponse { .. }
        ));
    }
    let duplicated = format!(
        r#"{{"issued_token_type":"{TYPE_ID_JAG}","token_type":"N_A","access_token":"x","access_token":"{token}"}}"#
    );
    let response = HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: duplicated.into_bytes(),
    };
    assert!(matches!(
        parse_token_exchange_response(&exchange, response).unwrap_err(),
        Error::InvalidTokenResponse { .. }
    ));

    // Rule 3: issued_token_type.
    let wrong = "urn:ietf:params:oauth:token-type:access_token";
    assert!(matches!(
        parse(&with(good.clone(), "issued_token_type", json!(wrong))).unwrap_err(),
        Error::UnexpectedIssuedTokenType { got: Some(got) } if got == wrong
    ));
    assert!(matches!(
        parse(&without(good.clone(), "issued_token_type")).unwrap_err(),
        Error::UnexpectedIssuedTokenType { got: None }
    ));

    // Rule 4: token_type is N_A, case-insensitively.
    parse(&with(good.clone(), "token_type", json!("n_a"))).unwrap();
    for body in [
        with(good.clone(), "token_type", json!("Bearer")),
        with(good.clone(), "token_type", json!(1)),
        without(good.clone(), "token_type"),
    ] {
        assert!(matches!(
            parse(&body).unwrap_err(),
            Error::InvalidTokenResponse { .. }
        ));
    }

    // Rule 5: access_token is present and non-empty.
    for body in [
        with(good.clone(), "access_token", json!("")),
        with(good.clone(), "access_token", json!(null)),
        with(good.clone(), "access_token", json!(["x"])),
        without(good.clone(), "access_token"),
    ] {
        assert!(matches!(
            parse(&body).unwrap_err(),
            Error::InvalidTokenResponse { .. }
        ));
    }

    // Whitespace in a reported scope is read leniently: blank means none,
    // and stray spaces are dropped.
    for (reported, expected) in [
        ("", None),
        ("   ", None),
        (" todos.read  todos.write ", Some("todos.read todos.write")),
    ] {
        let issued = parse(&with(good.clone(), "scope", json!(reported))).unwrap();
        assert_eq!(issued.scope.as_ref().map(Scope::as_str), expected);
    }

    // Malformed optional members.
    for body in [
        with(good.clone(), "scope", json!("a\"b")),
        with(good.clone(), "scope", json!(["a"])),
        with(good.clone(), "expires_in", json!("300")),
        with(good.clone(), "expires_in", json!(-1)),
        with(
            good.clone(),
            "authorization_details",
            json!({ "type": "x" }),
        ),
    ] {
        assert!(matches!(
            parse(&body).unwrap_err(),
            Error::InvalidTokenResponse { .. }
        ));
    }
}

#[tokio::test]
async fn a_refresh_token_from_the_idp_is_dropped() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());
    let token = id_jag(&claims()).await;
    let body = with(
        exchange_body(&token),
        "refresh_token",
        json!("rt-should-not-surface"),
    );
    let issued = parse_token_exchange_response(&exchange, ok(&body)).unwrap();
    assert_eq!(issued.id_jag.expose_secret(), token);
    assert!(!format!("{issued:?}").contains("rt-should-not-surface"));
}

#[tokio::test]
async fn a_non_200_token_exchange_response_is_a_token_endpoint_error() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());

    let mut response = json_response(
        400,
        &json!({
            "error": "insufficient_user_authentication",
            "error_description": "Step up.",
            "error_uri": "https://idp.example/errors/step-up",
            "max_age": 300,
            "acr_values": "urn:example:acr:mfa",
        }),
    );
    response
        .headers
        .push(("dpop-nonce".to_owned(), "nonce-2".to_owned()));
    let Error::TokenEndpoint(error) =
        parse_token_exchange_response(&exchange, response).unwrap_err()
    else {
        panic!("expected a token endpoint error");
    };
    assert_eq!(
        *error,
        TokenEndpointError {
            endpoint: Endpoint::Idp,
            status: 400,
            code: OAuthErrorCode::InsufficientUserAuthentication,
            description: Some("Step up.".to_owned()),
            uri: Some("https://idp.example/errors/step-up".to_owned()),
            max_age: Some(300),
            acr_values: Some("urn:example:acr:mfa".to_owned()),
            dpop_nonce: Some("nonce-2".to_owned()),
        }
    );
    assert_eq!(error.remediation(true), Remediation::StepUpAuthentication);

    // A 2xx that is not 200 is not a success.
    let body = exchange_body(&id_jag(&claims()).await);
    assert!(matches!(
        parse_token_exchange_response(&exchange, json_response(201, &body)).unwrap_err(),
        Error::UnexpectedResponse { status: 201, .. }
    ));

    // No RFC 6749 §5.2 body: a gateway's HTML, say.
    let response = HttpResponse {
        status: 502,
        headers: Vec::new(),
        body: b"<html>Bad Gateway</html>".to_vec(),
    };
    assert!(matches!(
        parse_token_exchange_response(&exchange, response).unwrap_err(),
        Error::UnexpectedResponse { status: 502, .. }
    ));
}

// ---------------------------------------------------------------------------
// §5 Self-checks on the issued ID-JAG
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_id_jag_that_is_not_a_typed_jws_is_malformed() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());
    let parse = |token: &str| parse_token_exchange_response(&exchange, ok(&exchange_body(token)));

    let untyped = sign(&rsa_key(), None, &claims()).await;
    let other_type = sign(&rsa_key(), Some("JWT"), &claims()).await;
    let access_token = sign(&rsa_key(), Some("at+jwt"), &claims()).await;
    let missing_jti = id_jag(&without(claims(), "jti")).await;
    let bad_exp = id_jag(&with(claims(), "exp", json!("soon"))).await;
    for token in [
        "opaque-token",
        "a.b.c",
        &untyped,
        &other_type,
        &access_token,
        &missing_jti,
        &bad_exp,
    ] {
        assert!(matches!(
            parse(token).unwrap_err(),
            Error::MalformedIdJag { .. }
        ));
    }

    // RFC 7515 §4.1.9: typ is case-insensitive and may carry `application/`.
    let prefixed = sign(&rsa_key(), Some("application/OAuth-ID-JAG+JWT"), &claims()).await;
    parse(&prefixed).unwrap();
    // The client does not verify the signature; any signer will do.
    let other_signer = sign(&other_rsa_key(), Some("oauth-id-jag+jwt"), &claims()).await;
    parse(&other_signer).unwrap();
}

#[tokio::test]
async fn id_jag_audience_must_be_the_resource_as_issuer() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    // An IdP alias as the request audience: the ID-JAG must still name the
    // configured Resource AS.
    let exchange = TokenExchange {
        audience: ExchangeAudience::new("urn:example:idp:saas-tool"),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let parse = |aud: Value| async {
        let token = id_jag(&with(claims(), "aud", aud)).await;
        parse_token_exchange_response(&exchange, ok(&exchange_body(&token)))
    };

    parse(json!(AS)).await.unwrap();
    parse(json!([AS])).await.unwrap();
    for aud in [
        json!("https://other-as.example"),
        json!("urn:example:idp:saas-tool"),
        // Byte-exact: a trailing slash is another issuer.
        json!(format!("{AS}/")),
        json!([AS, "https://other-as.example"]),
    ] {
        assert!(matches!(
            parse(aud).await.unwrap_err(),
            Error::IdJagAudienceMismatch
        ));
    }
}

#[tokio::test]
async fn id_jag_client_id_must_be_the_resource_as_registration() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());
    // The IdP-side client_id: the "used the IdP credentials" mistake.
    let token = id_jag(&with(claims(), "client_id", json!(IDP_CLIENT))).await;
    assert!(matches!(
        parse_token_exchange_response(&exchange, ok(&exchange_body(&token))).unwrap_err(),
        Error::IdJagClientIdMismatch
    ));

    // The unauthenticated registration's client_id counts the same way.
    let unauthenticated = unauthenticated_resource_as();
    let exchange = TokenExchange::new(&idp, &unauthenticated, &subject, now());
    let token = id_jag(&claims()).await;
    parse_token_exchange_response(&exchange, ok(&exchange_body(&token))).unwrap();
}

#[tokio::test]
async fn id_jag_resources_must_be_as_requested() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let exchange = TokenExchange {
        resources: vec![
            ResourceIdentifier::new(RESOURCE),
            ResourceIdentifier::new("https://files.resource.example/"),
        ],
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let parse = |resource: Value| async {
        let token = id_jag(&with(claims(), "resource", resource)).await;
        parse_token_exchange_response(&exchange, ok(&exchange_body(&token)))
    };

    parse(json!(RESOURCE)).await.unwrap();
    parse(json!([RESOURCE])).await.unwrap();
    parse(json!(["https://files.resource.example/", RESOURCE]))
        .await
        .unwrap();
    for resource in [
        // Trailing slash dropped, case changed, an extra one added.
        json!("https://api.resource.example"),
        json!("https://API.resource.example/"),
        json!([RESOURCE, "https://other.example/"]),
    ] {
        assert!(matches!(
            parse(resource).await.unwrap_err(),
            Error::IdJagResourceAltered { .. }
        ));
    }

    // The opt-in tolerates exactly one trailing slash, in either direction,
    // and nothing else.
    let lenient = TokenExchange {
        resources: vec![ResourceIdentifier::new(RESOURCE)],
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    }
    .tolerate_resource_trailing_slash(true);
    let parse_lenient = |resource: Value| async {
        let token = id_jag(&with(claims(), "resource", resource)).await;
        parse_token_exchange_response(&lenient, ok(&exchange_body(&token)))
    };
    parse_lenient(json!("https://api.resource.example"))
        .await
        .unwrap();
    parse_lenient(json!(RESOURCE)).await.unwrap();
    for resource in [
        json!("https://API.resource.example"),
        json!("https://api.resource.example//"),
        json!("https://api.resource.example/v1"),
        json!(["https://api.resource.example", "https://other.example/"]),
    ] {
        assert!(matches!(
            parse_lenient(resource).await.unwrap_err(),
            Error::IdJagResourceAltered { .. }
        ));
    }

    // A resource in the ID-JAG when none was requested is the IdP's
    // default (draft §4.3.3), not an alteration.
    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());
    let token = id_jag(&with(claims(), "resource", json!(RESOURCE))).await;
    parse_token_exchange_response(&exchange, ok(&exchange_body(&token))).unwrap();
}

#[tokio::test]
async fn a_dropped_or_changed_dpop_binding_is_a_downgrade() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let key = dpop_key();
    let exchange = TokenExchange {
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };

    let bound = id_jag(&with(claims(), "cnf", jkt(&key))).await;
    let issued = parse_token_exchange_response(&exchange, ok(&exchange_body(&bound))).unwrap();
    assert_eq!(
        issued.peek.confirmation(),
        Some(&Confirmation::Jkt(key.thumbprint().to_owned()))
    );

    let unbound = id_jag(&claims()).await;
    let other_key = id_jag(&with(claims(), "cnf", jkt(&other_dpop_key()))).await;
    // The right thumbprint under the wrong member is not a DPoP binding.
    let as_certificate = id_jag(&with(
        claims(),
        "cnf",
        json!({ "x5t#S256": key.thumbprint() }),
    ))
    .await;
    for token in [&unbound, &other_key, &as_certificate] {
        assert!(matches!(
            parse_token_exchange_response(&exchange, ok(&exchange_body(token))).unwrap_err(),
            Error::BindingDowngrade
        ));
    }

    // Opt-out for an IdP known to ignore DPoP proofs.
    let lenient = exchange.clone().accept_unbound_id_jag(true);
    parse_token_exchange_response(&lenient, ok(&exchange_body(&unbound))).unwrap();
    // The other self-checks still run.
    let wrong_audience = id_jag(&with(claims(), "aud", json!("https://other.example"))).await;
    assert!(matches!(
        parse_token_exchange_response(&lenient, ok(&exchange_body(&wrong_audience))).unwrap_err(),
        Error::IdJagAudienceMismatch
    ));
    // And it can be turned back on.
    let strict = lenient.accept_unbound_id_jag(false);
    assert!(matches!(
        parse_token_exchange_response(&strict, ok(&exchange_body(&unbound))).unwrap_err(),
        Error::BindingDowngrade
    ));
}

#[tokio::test]
async fn a_dropped_or_changed_certificate_binding_is_a_downgrade() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let certificate = rfc_8705_certificate_der();
    let exchange = TokenExchange {
        tls_client_certificate: Some(&certificate),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    // The certificate is the transport's business: nothing is sent for it.
    let request = exchange.build().await.unwrap();
    assert_eq!(request.headers.len(), 2);

    let bound = id_jag(&with(
        claims(),
        "cnf",
        json!({ "x5t#S256": RFC_8705_THUMBPRINT }),
    ))
    .await;
    parse_token_exchange_response(&exchange, ok(&exchange_body(&bound))).unwrap();

    let unbound = id_jag(&claims()).await;
    let other = id_jag(&with(
        claims(),
        "cnf",
        json!({ "x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
    ))
    .await;
    for token in [&unbound, &other] {
        assert!(matches!(
            parse_token_exchange_response(&exchange, ok(&exchange_body(token))).unwrap_err(),
            Error::BindingDowngrade
        ));
    }
    let lenient = exchange.clone().accept_unbound_id_jag(true);
    parse_token_exchange_response(&lenient, ok(&exchange_body(&unbound))).unwrap();

    // With a proof and a certificate the IdP binds one of them, never both.
    let key = dpop_key();
    let both = TokenExchange {
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        ..exchange
    };
    parse_token_exchange_response(&both, ok(&exchange_body(&bound))).unwrap();
    let bound_to_key = id_jag(&with(claims(), "cnf", jkt(&key))).await;
    parse_token_exchange_response(&both, ok(&exchange_body(&bound_to_key))).unwrap();
    assert!(matches!(
        parse_token_exchange_response(&both, ok(&exchange_body(&unbound))).unwrap_err(),
        Error::BindingDowngrade
    ));
}

#[tokio::test]
async fn an_unrequested_binding_is_not_a_downgrade() {
    // An IdP may bind on its own; whether the client can use the result is
    // decided when the access token request is built (§6).
    let key = dpop_key();
    let issued = issued(&with(claims(), "cnf", jkt(&key))).await;
    assert!(matches!(
        issued.peek.confirmation(),
        Some(Confirmation::Jkt(_))
    ));
}

// ---------------------------------------------------------------------------
// §6 Access Token Request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn access_token_golden_request() {
    let resource_as = resource_as();
    let issued = issued(&with(claims(), "scope", json!("todos.read todos.write"))).await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: Some(scope("todos.read")),
        dpop: None,
        now: now(),
    }
    .build()
    .await
    .unwrap();

    assert_eq!(request.method, http::Method::POST);
    assert_eq!(request.url.as_str(), AS_TOKEN);
    assert_eq!(request.url.query(), None);
    assert_eq!(
        request.headers,
        pairs(&[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
            // base64("app-at-resource:as-secret")
            (
                "Authorization",
                "Basic YXBwLWF0LXJlc291cmNlOmFzLXNlY3JldA=="
            ),
        ])
    );
    assert_eq!(
        String::from_utf8(request.body).unwrap(),
        format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
             &assertion={}\
             &scope=todos.read",
            issued.id_jag.expose_secret()
        )
    );
}

#[tokio::test]
async fn access_token_request_client_authentication_variants() {
    let issued = issued(&claims()).await;
    let build = |client_auth: ResourceAsClientAuth| {
        let issued = &issued;
        async move {
            let resource_as = resource_as_with(client_auth);
            AccessTokenRequest {
                resource_as: &resource_as,
                id_jag: issued,
                scope: None,
                dpop: None,
                now: now(),
            }
            .build()
            .await
            .unwrap()
        }
    };

    let request = build(ResourceAsClientAuth::Authenticated(
        ClientAuth::ClientSecretPost {
            client_id: AS_CLIENT.to_owned(),
            secret: ClientSecret::new("as-secret"),
        },
    ))
    .await;
    assert_eq!(
        form(&request),
        pairs(&[
            ("grant_type", GRANT_JWT_BEARER),
            ("assertion", issued.id_jag.expose_secret()),
            ("client_id", AS_CLIENT),
            ("client_secret", "as-secret"),
        ])
    );
    assert_eq!(header(&request, "Authorization"), None);

    // private_key_jwt: the assertion's audience is the Resource AS issuer.
    let request = build(ResourceAsClientAuth::Authenticated(
        ClientAuth::PrivateKeyJwt {
            client_id: AS_CLIENT.to_owned(),
            signer: Arc::new(p256_key()),
        },
    ))
    .await;
    let sent = form(&request);
    assert_eq!(param(&sent, "client_assertion_type"), Some(ASSERTION_TYPE));
    let (_, assertion) = decode_jwt(param(&sent, "client_assertion").unwrap());
    assert_eq!(assertion["iss"], AS_CLIENT);
    assert_eq!(assertion["aud"], AS);

    let request = build(ResourceAsClientAuth::Authenticated(
        ClientAuth::TlsClientAuth {
            client_id: AS_CLIENT.to_owned(),
        },
    ))
    .await;
    assert_eq!(
        form(&request),
        pairs(&[
            ("grant_type", GRANT_JWT_BEARER),
            ("assertion", issued.id_jag.expose_secret()),
            ("client_id", AS_CLIENT),
        ])
    );
}

#[tokio::test]
async fn a_dpop_bound_id_jag_uses_the_jwt_dpop_grant() {
    let resource_as = resource_as();
    let key = dpop_key();
    let issued = issued(&with(claims(), "cnf", jkt(&key))).await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: None,
        dpop: Some(DpopRequest {
            key: &key,
            nonce: Some("as-nonce"),
        }),
        now: now(),
    }
    .build()
    .await
    .unwrap();

    assert_eq!(param(&form(&request), "grant_type"), Some(GRANT_JWT_DPOP));
    let (proof_header, proof) = decode_jwt(header(&request, "DPoP").unwrap());
    assert_eq!(proof_header["typ"], "dpop+jwt");
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], AS_TOKEN);
    assert_eq!(proof["nonce"], "as-nonce");
    assert_eq!(
        proof_header["jwk"],
        serde_json::to_value(key.public_jwk()).unwrap()
    );
}

#[tokio::test]
async fn other_id_jags_use_the_jwt_bearer_grant() {
    let key = dpop_key();

    // A certificate-bound ID-JAG (draft §9.11.2.2).
    let resource_as = resource_as();
    let bound = issued(&with(
        claims(),
        "cnf",
        json!({ "x5t#S256": RFC_8705_THUMBPRINT }),
    ))
    .await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &bound,
        scope: None,
        dpop: None,
        now: now(),
    }
    .build()
    .await
    .unwrap();
    assert_eq!(param(&form(&request), "grant_type"), Some(GRANT_JWT_BEARER));
    assert_eq!(header(&request, "DPoP"), None);

    // An unbound ID-JAG with a proof, to ask for a DPoP-bound access token
    // (draft §9.11.1.2.3). This works at an AS without jwt-dpop too.
    let resource_as = without_jwt_dpop(resource_as);
    let unbound = issued(&claims()).await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &unbound,
        scope: None,
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        now: now(),
    }
    .build()
    .await
    .unwrap();
    assert_eq!(param(&form(&request), "grant_type"), Some(GRANT_JWT_BEARER));
    let (_, proof) = decode_jwt(header(&request, "DPoP").unwrap());
    assert_eq!(proof["htu"], AS_TOKEN);
}

#[tokio::test]
async fn an_unauthenticated_request_needs_a_bound_id_jag() {
    let resource_as = unauthenticated_resource_as();
    let key = dpop_key();

    let unbound = issued(&claims()).await;
    // A `cnf` this client holds no key for does not constrain the sender.
    let unsupported = issued(&with(claims(), "cnf", json!({ "kid": "some-key" }))).await;
    for id_jag in [&unbound, &unsupported] {
        // A proof on the request does not make the *grant* bound.
        for dpop in [
            None,
            Some(DpopRequest {
                key: &key,
                nonce: None,
            }),
        ] {
            let request = AccessTokenRequest {
                resource_as: &resource_as,
                id_jag,
                scope: None,
                dpop,
                now: now(),
            };
            assert!(matches!(
                request.build().await.unwrap_err(),
                Error::UnauthenticatedUnboundGrant
            ));
        }
    }

    // DPoP-bound: client_id only, no credentials.
    let bound = issued(&with(claims(), "cnf", jkt(&key))).await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &bound,
        scope: None,
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        now: now(),
    }
    .build()
    .await
    .unwrap();
    assert_eq!(
        form(&request),
        pairs(&[
            ("grant_type", GRANT_JWT_DPOP),
            ("assertion", bound.id_jag.expose_secret()),
            ("client_id", AS_CLIENT),
        ])
    );
    assert_eq!(header(&request, "Authorization"), None);
    header(&request, "DPoP").unwrap();

    // Certificate-bound: the transport presents the certificate.
    let bound = issued(&with(
        claims(),
        "cnf",
        json!({ "x5t#S256": RFC_8705_THUMBPRINT }),
    ))
    .await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &bound,
        scope: None,
        dpop: None,
        now: now(),
    }
    .build()
    .await
    .unwrap();
    assert_eq!(param(&form(&request), "grant_type"), Some(GRANT_JWT_BEARER));
    assert_eq!(param(&form(&request), "client_id"), Some(AS_CLIENT));
}

#[tokio::test]
async fn a_dpop_bound_id_jag_needs_the_matching_key() {
    let resource_as = resource_as();
    let key = dpop_key();
    let other = other_dpop_key();
    let bound = issued(&with(claims(), "cnf", jkt(&key))).await;

    for dpop in [
        None,
        Some(DpopRequest {
            key: &other,
            nonce: None,
        }),
    ] {
        let request = AccessTokenRequest {
            resource_as: &resource_as,
            id_jag: &bound,
            scope: None,
            dpop,
            now: now(),
        };
        assert!(matches!(
            request.build().await.unwrap_err(),
            Error::DpopKeyRequired
        ));
    }
}

#[tokio::test]
async fn a_dpop_bound_id_jag_is_not_sent_to_an_as_without_jwt_dpop() {
    let resource_as = without_jwt_dpop(resource_as());
    let key = dpop_key();
    // Bound by an IdP that was not asked to.
    let bound = issued(&with(claims(), "cnf", jkt(&key))).await;
    for dpop in [
        None,
        Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
    ] {
        let request = AccessTokenRequest {
            resource_as: &resource_as,
            id_jag: &bound,
            scope: None,
            dpop,
            now: now(),
        };
        assert!(matches!(
            request.build().await.unwrap_err(),
            Error::ResourceAsLacksJwtDpop
        ));
    }
}

#[tokio::test]
async fn requested_scope_must_be_within_the_id_jag_scope() {
    async fn build(id_jag: &IssuedIdJag, requested: &str) -> Result<HttpRequest, Error> {
        let resource_as = resource_as();
        AccessTokenRequest {
            resource_as: &resource_as,
            id_jag,
            scope: Some(scope(requested)),
            dpop: None,
            now: now(),
        }
        .build()
        .await
    }

    let with_claim = issued(&with(claims(), "scope", json!("todos.read todos.write"))).await;
    build(&with_claim, "todos.write").await.unwrap();
    build(&with_claim, "todos.write todos.read").await.unwrap();
    for requested in ["todos.delete", "todos.read todos.delete", "TODOS.READ"] {
        assert!(matches!(
            build(&with_claim, requested).await.unwrap_err(),
            Error::ScopeNotSubset
        ));
    }

    // No `scope` claim: the scope the IdP's response granted is the bound.
    let mut from_response = issued(&claims()).await;
    from_response.scope = Some(scope("todos.read"));
    build(&from_response, "todos.read").await.unwrap();
    assert!(matches!(
        build(&from_response, "todos.write").await.unwrap_err(),
        Error::ScopeNotSubset
    ));
}

// ---------------------------------------------------------------------------
// §7 Access token response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn access_token_response_is_parsed() {
    let resource_as = resource_as();
    let issued = issued(&with(claims(), "scope", json!("todos.read todos.write"))).await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: Some(scope("todos.read")),
        dpop: None,
        now: now(),
    };
    let details = json!([{ "type": "todo", "actions": ["read"] }]);
    let body = json!({
        "access_token": "at-value",
        "token_type": "Bearer",
        "expires_in": 7200,
        "scope": "todos.read",
        "authorization_details": details,
    });
    let token = parse_access_token_response(&request, ok(&body)).unwrap();
    assert_eq!(token.access_token.expose_secret(), "at-value");
    assert_eq!(token.token_type, AccessTokenType::Bearer);
    assert!(!token.is_sender_constrained());
    assert_eq!(token.expires_in, Some(Duration::from_secs(7200)));
    assert_eq!(token.scope, Some(scope("todos.read")));
    assert_eq!(
        serde_json::to_value(token.authorization_details.as_ref().unwrap()).unwrap(),
        details
    );
    assert!(token.refresh_token.is_none());
    assert_eq!(token.received_at, now());
}

#[tokio::test]
async fn omitted_access_token_scope_means_the_requested_scope() {
    let resource_as = resource_as();
    let issued = issued(&with(claims(), "scope", json!("todos.read todos.write"))).await;
    let body = json!({ "access_token": "at-value", "token_type": "Bearer" });

    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: Some(scope("todos.read")),
        dpop: None,
        now: now(),
    };
    let token = parse_access_token_response(&request, ok(&body)).unwrap();
    assert_eq!(token.scope, Some(scope("todos.read")));
    assert_eq!(token.expires_in, None);

    // No `scope` parameter asks for everything the ID-JAG carries.
    let request = AccessTokenRequest {
        scope: None,
        ..request
    };
    let token = parse_access_token_response(&request, ok(&body)).unwrap();
    assert_eq!(token.scope, Some(scope("todos.read todos.write")));

    // An explicitly empty `scope` is different: the server granted none, and
    // the token must not be reported as carrying what was asked for. The
    // xaa.dev Resource AS answers this way when the request names no scope.
    for blank in ["", "  "] {
        let body = json!({ "access_token": "at-value", "token_type": "Bearer", "scope": blank });
        let token = parse_access_token_response(&request, ok(&body)).unwrap();
        assert_eq!(token.scope, None);
    }
}

#[tokio::test]
async fn access_token_type_rules() {
    let resource_as = resource_as();
    let key = dpop_key();
    let issued = issued(&claims()).await;
    let plain = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: None,
        dpop: None,
        now: now(),
    };
    let with_proof = AccessTokenRequest {
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        ..plain.clone()
    };
    let typed = |token_type: &str| ok(&with(token_body(), "token_type", json!(token_type)));

    // Bearer or DPoP, case-insensitively.
    for token_type in ["Bearer", "bearer", "BEARER"] {
        let token = parse_access_token_response(&plain, typed(token_type)).unwrap();
        assert_eq!(token.token_type, AccessTokenType::Bearer);
    }
    for token_type in ["DPoP", "dpop"] {
        let token = parse_access_token_response(&with_proof, typed(token_type)).unwrap();
        assert_eq!(token.token_type, AccessTokenType::DPoP);
        assert!(token.is_sender_constrained());
    }

    // Anything else is unsupported.
    for token_type in ["mac", "N_A", ""] {
        assert!(matches!(
            parse_access_token_response(&plain, typed(token_type)).unwrap_err(),
            Error::UnsupportedTokenType { got } if got == token_type
        ));
    }

    // DPoP only if a proof was sent.
    assert!(matches!(
        parse_access_token_response(&plain, typed("DPoP")).unwrap_err(),
        Error::InvalidTokenResponse { .. }
    ));

    // Bearer even though a proof was sent: allowed, and reported.
    let token = parse_access_token_response(&with_proof, typed("Bearer")).unwrap();
    assert!(!token.is_sender_constrained());
}

#[tokio::test]
async fn access_token_response_rules() {
    let resource_as = resource_as();
    let issued = issued(&claims()).await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: None,
        dpop: None,
        now: now(),
    };
    for body in [
        without(token_body(), "token_type"),
        without(token_body(), "access_token"),
        with(token_body(), "access_token", json!("")),
        with(token_body(), "access_token", json!(7)),
        with(token_body(), "expires_in", json!("7200")),
        with(token_body(), "scope", json!(7)),
        json!(["at-value"]),
    ] {
        assert!(matches!(
            parse_access_token_response(&request, ok(&body)).unwrap_err(),
            Error::InvalidTokenResponse { .. }
        ));
    }

    // Off-profile, but surfaced (draft §4.4.4).
    let body = with(token_body(), "refresh_token", json!("rt-value"));
    let token = parse_access_token_response(&request, ok(&body)).unwrap();
    assert_eq!(token.refresh_token.unwrap().expose_secret(), "rt-value");

    // Errors carry the Resource AS endpoint.
    let Error::TokenEndpoint(error) =
        parse_access_token_response(&request, oauth_error(400, "invalid_grant")).unwrap_err()
    else {
        panic!("expected a token endpoint error");
    };
    assert_eq!(error.endpoint, Endpoint::ResourceAs);
    assert_eq!(error.status, 400);
    assert_eq!(error.code, OAuthErrorCode::InvalidGrant);
    assert_eq!(error.description, None);
    assert_eq!(error.dpop_nonce, None);
    assert_eq!(
        error.to_string(),
        "Resource AS token endpoint answered invalid_grant (status 400)"
    );
}

// ---------------------------------------------------------------------------
// §8 Errors and remediation
// ---------------------------------------------------------------------------

#[test]
fn remediation_table() {
    use Endpoint::{Idp, ResourceAs};
    use Remediation::{
        ChangeRequest, FixClientConfiguration, NotRemediableByClient, ObtainNewIdJag,
        ObtainNewSubjectToken, RetryWithDpopNonce, StepUpAuthentication, Unknown,
    };

    // (endpoint, code, fresh ID-JAG, re-presented ID-JAG)
    let table = [
        (
            Idp,
            "use_dpop_nonce",
            RetryWithDpopNonce,
            RetryWithDpopNonce,
        ),
        (
            ResourceAs,
            "use_dpop_nonce",
            RetryWithDpopNonce,
            RetryWithDpopNonce,
        ),
        (
            Idp,
            "invalid_request",
            ObtainNewSubjectToken,
            ObtainNewSubjectToken,
        ),
        (
            Idp,
            "invalid_grant",
            ObtainNewSubjectToken,
            ObtainNewSubjectToken,
        ),
        (
            Idp,
            "insufficient_user_authentication",
            StepUpAuthentication,
            StepUpAuthentication,
        ),
        (Idp, "invalid_target", ChangeRequest, ChangeRequest),
        (
            ResourceAs,
            "invalid_grant",
            NotRemediableByClient,
            ObtainNewIdJag,
        ),
        (
            Idp,
            "invalid_client",
            FixClientConfiguration,
            FixClientConfiguration,
        ),
        (
            ResourceAs,
            "invalid_client",
            FixClientConfiguration,
            FixClientConfiguration,
        ),
        (
            Idp,
            "unauthorized_client",
            FixClientConfiguration,
            FixClientConfiguration,
        ),
        (
            ResourceAs,
            "unauthorized_client",
            FixClientConfiguration,
            FixClientConfiguration,
        ),
        (
            Idp,
            "invalid_dpop_proof",
            FixClientConfiguration,
            FixClientConfiguration,
        ),
        (
            ResourceAs,
            "invalid_dpop_proof",
            FixClientConfiguration,
            FixClientConfiguration,
        ),
        (
            Idp,
            "access_denied",
            NotRemediableByClient,
            NotRemediableByClient,
        ),
        (
            ResourceAs,
            "access_denied",
            NotRemediableByClient,
            NotRemediableByClient,
        ),
        // Not mapped by the draft.
        (ResourceAs, "invalid_request", Unknown, Unknown),
        (ResourceAs, "invalid_target", Unknown, Unknown),
        (
            ResourceAs,
            "insufficient_user_authentication",
            Unknown,
            Unknown,
        ),
        (Idp, "invalid_scope", Unknown, Unknown),
        (ResourceAs, "invalid_scope", Unknown, Unknown),
        (ResourceAs, "unsupported_grant_type", Unknown, Unknown),
        (Idp, "server_error", Unknown, Unknown),
        (ResourceAs, "temporarily_unavailable", Unknown, Unknown),
        (Idp, "vendor_specific_code", Unknown, Unknown),
    ];
    for (endpoint, code, fresh, presented) in table {
        let error = TokenEndpointError {
            endpoint,
            status: 400,
            code: OAuthErrorCode::parse(code),
            description: None,
            uri: None,
            max_age: None,
            acr_values: None,
            dpop_nonce: None,
        };
        assert_eq!(error.remediation(true), fresh, "{endpoint:?} {code} fresh");
        assert_eq!(
            error.remediation(false),
            presented,
            "{endpoint:?} {code} re-presented"
        );
    }
}

#[tokio::test]
async fn the_library_never_retries() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let key = dpop_key();
    let token = id_jag(&with(claims(), "cnf", jkt(&key))).await;

    let mut challenge = oauth_error(400, "use_dpop_nonce");
    challenge
        .headers
        .push(("DPoP-Nonce".to_owned(), "idp-nonce".to_owned()));
    let http = MockHttpClient::new()
        .respond(IDP_TOKEN, challenge)
        .respond(IDP_TOKEN, ok(&exchange_body(&token)));

    let exchange = TokenExchange {
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let Error::TokenEndpoint(error) = exchange_for_id_jag(&http, &exchange).await.unwrap_err()
    else {
        panic!("expected a token endpoint error");
    };
    assert_eq!(error.remediation(true), Remediation::RetryWithDpopNonce);
    assert_eq!(http.requests().len(), 1);

    // The caller retries with the nonce.
    let nonce = error.dpop_nonce.as_deref();
    assert_eq!(nonce, Some("idp-nonce"));
    let retry = TokenExchange {
        dpop: Some(DpopRequest { key: &key, nonce }),
        ..exchange.clone()
    };
    exchange_for_id_jag(&http, &retry).await.unwrap();
    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    let (_, proof) = decode_jwt(header(&requests[1], "DPoP").unwrap());
    assert_eq!(proof["nonce"], "idp-nonce");
}

// ---------------------------------------------------------------------------
// §9 SAML → Refresh Token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn saml_exchange_request() {
    let idp = idp();
    let assertion = SamlAssertion::new(vec![0xfb, 0xef, 0xbe, 0xff]);
    let exchange = SamlToRefreshToken::new(&idp, &assertion, now()).unwrap();
    assert_eq!(exchange.scope, scope("openid offline_access"));
    let request = exchange.build().await.unwrap();

    assert_eq!(request.method, http::Method::POST);
    assert_eq!(request.url.as_str(), IDP_TOKEN);
    assert_eq!(
        request.headers,
        pairs(&[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
        ])
    );
    // No `audience`, no `resource`.
    assert_eq!(
        form(&request),
        pairs(&[
            ("grant_type", GRANT_TOKEN_EXCHANGE),
            ("requested_token_type", TYPE_REFRESH_TOKEN),
            ("scope", "openid offline_access"),
            ("subject_token", "----_w"),
            ("subject_token_type", TYPE_SAML2),
            ("client_id", IDP_CLIENT),
            ("client_secret", "idp-secret"),
        ])
    );

    // Padded standard base64 and extra scopes.
    let mut padded = idp.clone();
    padded.saml_encoding = SamlEncoding::Base64;
    let exchange = SamlToRefreshToken {
        scope: scope("openid offline_access profile"),
        ..SamlToRefreshToken::new(&padded, &assertion, now()).unwrap()
    };
    let sent = form(&exchange.build().await.unwrap());
    assert_eq!(param(&sent, "subject_token"), Some("++++/w=="));
    assert_eq!(param(&sent, "scope"), Some("openid offline_access profile"));
    assert_eq!(param(&sent, "audience"), None);

    let empty = SamlAssertion::new(Vec::new());
    assert!(matches!(
        SamlToRefreshToken::new(&idp, &empty, now())
            .unwrap()
            .build()
            .await
            .unwrap_err(),
        Error::InvalidRequest { .. }
    ));
}

#[tokio::test]
async fn saml_exchange_response() {
    let idp = idp();
    let assertion = SamlAssertion::new(b"<Assertion/>".to_vec());
    let exchange = SamlToRefreshToken::new(&idp, &assertion, now()).unwrap();
    let good = json!({
        "issued_token_type": TYPE_REFRESH_TOKEN,
        "access_token": "idp-refresh-token",
        "token_type": "N_A",
        "scope": "openid offline_access",
        "expires_in": 1_209_600,
    });

    let token = parse_saml_exchange_response(&exchange, ok(&good)).unwrap();
    assert_eq!(token.expose_secret(), "idp-refresh-token");

    assert!(matches!(
        parse_saml_exchange_response(&exchange, ok(&with(good.clone(), "issued_token_type", json!(TYPE_ID_JAG)))).unwrap_err(),
        Error::UnexpectedIssuedTokenType { got: Some(got) } if got == TYPE_ID_JAG
    ));
    for body in [
        with(good.clone(), "token_type", json!("Bearer")),
        without(good.clone(), "access_token"),
    ] {
        assert!(matches!(
            parse_saml_exchange_response(&exchange, ok(&body)).unwrap_err(),
            Error::InvalidTokenResponse { .. }
        ));
    }

    let Error::TokenEndpoint(error) =
        parse_saml_exchange_response(&exchange, oauth_error(400, "invalid_request")).unwrap_err()
    else {
        panic!("expected a token endpoint error");
    };
    assert_eq!(error.endpoint, Endpoint::Idp);
    assert_eq!(error.remediation(true), Remediation::ObtainNewSubjectToken);

    // Through the transport, then on to a token exchange.
    let http = MockHttpClient::new().respond(IDP_TOKEN, ok(&good));
    let token = exchange_saml_for_refresh_token(&http, &exchange)
        .await
        .unwrap();
    let subject = SubjectToken::RefreshToken(token);
    let resource_as = resource_as();
    let sent = form(
        &TokenExchange::new(&idp, &resource_as, &subject, now())
            .build()
            .await
            .unwrap(),
    );
    assert_eq!(param(&sent, "subject_token"), Some("idp-refresh-token"));
    assert_eq!(param(&sent, "subject_token_type"), Some(TYPE_REFRESH_TOKEN));
}

// ---------------------------------------------------------------------------
// §10 Discovery
// ---------------------------------------------------------------------------

const PRM_URL: &str = "https://api.resource.example/.well-known/oauth-protected-resource";
const AS_METADATA_URL: &str = "https://as.resource.example/.well-known/oauth-authorization-server";

fn prm_document() -> Value {
    json!({
        "resource": RESOURCE,
        "authorization_servers": [AS],
        "scopes_supported": ["todos.read", "todos.write"],
    })
}

fn as_document() -> Value {
    json!({
        "issuer": AS,
        "token_endpoint": AS_TOKEN,
        "grant_types_supported": [GRANT_JWT_BEARER, GRANT_JWT_DPOP],
        "authorization_grant_profiles_supported": [
            "urn:ietf:params:oauth:grant-profile:id-jag"
        ],
    })
}

#[tokio::test]
async fn discovery_from_a_resource_url() {
    let http = MockHttpClient::new()
        .respond(PRM_URL, ok(&prm_document()))
        .respond(AS_METADATA_URL, ok(&as_document()));
    let opts = FetchOptions::default();

    let resource = discover_resource(&http, PrmOrigin::ResourceIdentifier(RESOURCE), &opts)
        .await
        .unwrap();
    // Byte-for-byte, trailing slash included.
    assert_eq!(resource.resource.as_str(), RESOURCE);
    assert_eq!(
        resource.resource,
        ResourceIdentifier::from_metadata(&resource.metadata)
    );
    let servers = resource.metadata.authorization_servers();
    assert_eq!(servers, [Issuer::new(AS)]);

    let discovered = discover_resource_as(&http, &servers[0], &opts)
        .await
        .unwrap();
    assert_eq!(discovered.issuer.as_str(), AS);
    assert_eq!(discovered.token_endpoint.as_str(), AS_TOKEN);
    assert_eq!(discovered.id_jag_profile, Support::Advertised);
    assert_eq!(discovered.jwt_dpop, Support::Advertised);
    assert_eq!(http.requested_urls(), [PRM_URL, AS_METADATA_URL]);

    let connection = discovered.connection(ResourceAsClientAuth::SenderConstrainedOnly {
        client_id: AS_CLIENT.to_owned(),
    });
    assert_eq!(connection.issuer.as_str(), AS);
    assert_eq!(connection.token_endpoint.as_str(), AS_TOKEN);
    assert_eq!(connection.client_auth.client_id(), AS_CLIENT);
    assert!(connection.supports_jwt_dpop);

    // The discovered values drive a token exchange unchanged.
    let idp = idp();
    let subject = subject();
    let exchange = TokenExchange {
        resources: vec![resource.resource],
        ..TokenExchange::new(&idp, &connection, &subject, now())
    };
    let sent = form(&exchange.build().await.unwrap());
    assert_eq!(param(&sent, "audience"), Some(AS));
    assert_eq!(param(&sent, "resource"), Some(RESOURCE));
}

#[tokio::test]
async fn discovery_reports_what_is_not_advertised() {
    // The xaa.dev shape: the profile but no jwt-dpop.
    let document = with(
        as_document(),
        "grant_types_supported",
        json!([GRANT_JWT_BEARER]),
    );
    let http = MockHttpClient::new().respond(AS_METADATA_URL, ok(&document));
    let discovered = discover_resource_as(&http, &Issuer::new(AS), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(discovered.id_jag_profile, Support::Advertised);
    assert_eq!(discovered.jwt_dpop, Support::NotAdvertised);
    assert!(
        !discovered
            .connection(ResourceAsClientAuth::SenderConstrainedOnly {
                client_id: AS_CLIENT.to_owned(),
            })
            .supports_jwt_dpop
    );

    // Draft §7.2 says SHOULD advertise: absence is reported, not fatal.
    let document = without(
        without(as_document(), "authorization_grant_profiles_supported"),
        "grant_types_supported",
    );
    let http = MockHttpClient::new().respond(AS_METADATA_URL, ok(&document));
    let discovered = discover_resource_as(&http, &Issuer::new(AS), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(discovered.id_jag_profile, Support::NotAdvertised);
    assert_eq!(discovered.jwt_dpop, Support::NotAdvertised);
}

#[tokio::test]
async fn discovery_rejects_a_prm_resource_mismatch() {
    // Draft §9.6: the document names another resource.
    let document = with(
        prm_document(),
        "resource",
        json!("https://api.resource.example"),
    );
    let http = MockHttpClient::new().respond(PRM_URL, ok(&document));
    let error = discover_resource(
        &http,
        PrmOrigin::ResourceIdentifier(RESOURCE),
        &FetchOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        Error::PrmResourceMismatch { expected, got }
            if expected == RESOURCE && got == "https://api.resource.example"
    ));
}

#[tokio::test]
async fn discovery_rejects_a_metadata_issuer_mismatch() {
    // Draft §9.5: metadata fetched for one issuer declares another.
    let document = with(as_document(), "issuer", json!("https://attacker.example"));
    let http = MockHttpClient::new().respond(AS_METADATA_URL, ok(&document));
    let opts = FetchOptions::default();
    assert!(matches!(
        discover_resource_as(&http, &Issuer::new(AS), &opts).await.unwrap_err(),
        Error::MetadataIssuerMismatch { expected, got }
            if expected == AS && got == "https://attacker.example"
    ));
    assert!(matches!(
        discover_idp(&http, &Issuer::new(AS), &opts)
            .await
            .unwrap_err(),
        Error::MetadataIssuerMismatch { .. }
    ));
}

#[tokio::test]
async fn discovery_needs_a_token_endpoint_and_a_transport() {
    let document = without(as_document(), "token_endpoint");
    let http = MockHttpClient::new().respond(AS_METADATA_URL, ok(&document));
    assert!(matches!(
        discover_resource_as(&http, &Issuer::new(AS), &FetchOptions::default())
            .await
            .unwrap_err(),
        Error::InvalidMetadata { .. }
    ));

    let http = MockHttpClient::new().fail(PRM_URL, "connection refused");
    assert!(matches!(
        discover_resource(
            &http,
            PrmOrigin::ResourceIdentifier(RESOURCE),
            &FetchOptions::default()
        )
        .await
        .unwrap_err(),
        Error::Http(_)
    ));
}

#[tokio::test]
async fn idp_discovery_falls_back_to_oidc_discovery() {
    // The xaa.dev IdP serves only openid-configuration (docs/interop.md).
    let document = json!({
        "issuer": IDP,
        "token_endpoint": IDP_TOKEN,
        "jwks_uri": "https://idp.example/jwks",
        "identity_chaining_requested_token_types_supported": [TYPE_ID_JAG, TYPE_REFRESH_TOKEN],
    });
    let http = MockHttpClient::new().respond(
        "https://idp.example/.well-known/openid-configuration",
        ok(&document),
    );
    let discovered = discover_idp(&http, &Issuer::new(IDP), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(discovered.issuer.as_str(), IDP);
    assert_eq!(discovered.token_endpoint.as_str(), IDP_TOKEN);
    assert_eq!(discovered.issues_id_jag, Support::Advertised);

    let connection = discovered.connection(ClientAuth::TlsClientAuth {
        client_id: IDP_CLIENT.to_owned(),
    });
    assert_eq!(connection.issuer.as_str(), IDP);
    assert_eq!(connection.token_endpoint.as_str(), IDP_TOKEN);
    assert_eq!(connection.saml_encoding, SamlEncoding::Base64Url);
}

// ---------------------------------------------------------------------------
// §12 Round trips through the transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exchange_then_access_token_through_the_transport() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let token = id_jag(&with(
        with(claims(), "resource", json!(RESOURCE)),
        "scope",
        json!("todos.read"),
    ))
    .await;
    let http = MockHttpClient::new()
        .respond(IDP_TOKEN, ok(&exchange_body(&token)))
        .respond(AS_TOKEN, ok(&token_body()));

    let exchange = TokenExchange {
        resources: vec![ResourceIdentifier::new(RESOURCE)],
        scope: Some(scope("todos.read")),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let mut issued = exchange_for_id_jag(&http, &exchange).await.unwrap();
    assert!(issued.fresh);

    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: None,
        dpop: None,
        now: now(),
    };
    let access = request_access_token(&http, &request).await.unwrap();
    assert_eq!(access.access_token.expose_secret(), "at-value");
    assert_eq!(access.scope, Some(scope("todos.read")));
    issued.mark_presented();
    assert!(!issued.fresh);

    let requests = http.requests();
    assert_eq!(http.requested_urls(), [IDP_TOKEN, AS_TOKEN]);
    // The subject token goes to the IdP only, the ID-JAG to the AS only, and
    // each server sees only its own credentials.
    let to_idp = String::from_utf8(requests[0].body.clone()).unwrap();
    let to_as = String::from_utf8(requests[1].body.clone()).unwrap();
    assert!(to_idp.contains(ID_TOKEN) && to_idp.contains("idp-secret"));
    assert!(!to_idp.contains(&token));
    assert!(to_as.contains(&token));
    assert!(!to_as.contains(ID_TOKEN) && !to_as.contains("idp-secret"));
    for request in &requests {
        assert_eq!(request.url.query(), None);
        assert_eq!(request.url.fragment(), None);
        assert_eq!(request.url.username(), "");
    }
}

#[tokio::test]
async fn an_error_at_the_resource_as_maps_to_a_next_step() {
    let resource_as = resource_as();
    let mut issued = issued(&claims()).await;
    let http = MockHttpClient::new().respond(AS_TOKEN, oauth_error(400, "invalid_grant"));

    let mut outcomes = Vec::new();
    for _ in 0..2 {
        let request = AccessTokenRequest {
            resource_as: &resource_as,
            id_jag: &issued,
            scope: None,
            dpop: None,
            now: now(),
        };
        let was_fresh = issued.fresh;
        let Error::TokenEndpoint(error) = request_access_token(&http, &request).await.unwrap_err()
        else {
            panic!("expected a token endpoint error");
        };
        issued.mark_presented();
        outcomes.push(error.remediation(was_fresh));
    }
    // Fresh: stop. Re-presented: get a new ID-JAG (draft §4.4.4).
    assert_eq!(
        outcomes,
        [
            Remediation::NotRemediableByClient,
            Remediation::ObtainNewIdJag
        ]
    );
}

#[tokio::test]
async fn transport_failures_are_reported_as_http_errors() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let http = MockHttpClient::new()
        .fail(IDP_TOKEN, "connection reset")
        .fail(AS_TOKEN, "connection reset");

    let exchange = TokenExchange::new(&idp, &resource_as, &subject, now());
    assert!(matches!(
        exchange_for_id_jag(&http, &exchange).await.unwrap_err(),
        Error::Http(_)
    ));

    let issued = issued(&claims()).await;
    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: None,
        dpop: None,
        now: now(),
    };
    assert!(matches!(
        request_access_token(&http, &request).await.unwrap_err(),
        Error::Http(_)
    ));

    let assertion = SamlAssertion::new(b"<Assertion/>".to_vec());
    let saml = SamlToRefreshToken::new(&idp, &assertion, now()).unwrap();
    assert!(matches!(
        exchange_saml_for_refresh_token(&http, &saml)
            .await
            .unwrap_err(),
        Error::Http(_)
    ));

    // A build-time refusal sends nothing.
    let key = dpop_key();
    let no_dpop = without_jwt_dpop(resource_as.clone());
    let refused = TokenExchange {
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        ..TokenExchange::new(&idp, &no_dpop, &subject, now())
    };
    let before = http.requests().len();
    assert!(matches!(
        exchange_for_id_jag(&http, &refused).await.unwrap_err(),
        Error::ResourceAsLacksJwtDpop
    ));
    assert_eq!(http.requests().len(), before);
}

// ---------------------------------------------------------------------------
// §11 Secret handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn debug_output_carries_no_token_bytes() {
    let idp = idp();
    let resource_as = resource_as();
    let subject = subject();
    let key = dpop_key();
    let exchange = TokenExchange {
        actor_token: Some(ActorToken::new(
            "actor-secret-value",
            "urn:ietf:params:oauth:token-type:jwt",
        )),
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        ..TokenExchange::new(&idp, &resource_as, &subject, now())
    };
    let printed = format!("{exchange:?}");
    for secret in [ID_TOKEN, "idp-secret", "as-secret", "actor-secret-value"] {
        assert!(!printed.contains(secret), "{secret} in {printed}");
    }
    assert_eq!(
        format!("{:?}", exchange.actor_token.as_ref().unwrap()),
        r#"ActorToken(<18 bytes>, "urn:ietf:params:oauth:token-type:jwt")"#
    );

    let claims = with(
        with(claims(), "email", json!("alice@example.com")),
        "cnf",
        jkt(&key),
    );
    let token = id_jag(&claims).await;
    let issued = parse_token_exchange_response(&exchange, ok(&exchange_body(&token))).unwrap();
    let printed = format!("{issued:?}");
    assert!(!printed.contains(&token));
    // Only routing claims: no subject, no email.
    assert!(!printed.contains("alice"));
    assert!(printed.contains(AS_CLIENT));

    let request = AccessTokenRequest {
        resource_as: &resource_as,
        id_jag: &issued,
        scope: None,
        dpop: Some(DpopRequest {
            key: &key,
            nonce: None,
        }),
        now: now(),
    };
    let printed = format!("{request:?}");
    assert!(!printed.contains(&token) && !printed.contains("as-secret"));

    let body = with(token_body(), "refresh_token", json!("rt-secret-value"));
    let access = parse_access_token_response(&request, ok(&body)).unwrap();
    let printed = format!("{access:?}");
    assert!(!printed.contains("at-value") && !printed.contains("rt-secret-value"));

    let saml =
        SubjectToken::SamlAssertion(SamlAssertion::new(b"<Assertion>bob</Assertion>".to_vec()));
    let refresh = SubjectToken::RefreshToken(RefreshToken::new("rt-subject-value"));
    assert!(!format!("{saml:?}").contains("bob"));
    assert!(!format!("{refresh:?}").contains("rt-subject-value"));
}
