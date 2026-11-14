# RFC-003: Client (requesting app)

**Status**: Draft
**Date**: 2026-11-14

## Summary

This RFC defines the `client` component: what a requesting app uses to turn an Identity Assertion it already holds into an access token at another app's Resource Authorization Server. It covers the §4.3 Token Exchange at the IdP, the §4.4 Access Token Request at the Resource AS, the SAML-to-refresh-token exchange of §4.5, the self-checks the client should make on the ID-JAG it receives, and how token-endpoint errors map onto next steps.

User authentication itself (draft §4.2, OIDC or SAML SSO) is out of scope. The caller brings the ID Token, SAML assertion, or Refresh Token.

---

## 1. Configuration

The client holds two independent registrations (draft §5): one at the IdP and one at the Resource AS. Each is configured separately.

```rust
pub struct IdpConnection {
    /// RFC 8414 issuer identifier.
    pub issuer: Issuer,
    pub token_endpoint: Url,
    /// Required. The IdP MUST reject unauthenticated token exchange (draft §4.3.3).
    pub client_auth: ClientAuth,
    /// Encoding for `saml2` subject tokens (§2). Default `Base64Url`.
    pub saml_encoding: SamlEncoding,
}

pub struct ResourceAsConnection {
    /// RFC 8414 issuer identifier, used for the `audience` parameter and the ID-JAG `aud` self-check.
    pub issuer: Issuer,
    pub token_endpoint: Url,
    /// The client's credentials *at the Resource AS*. Its client_id is the one the ID-JAG must carry.
    pub client_auth: ResourceAsClientAuth,
    /// Whether this AS supports `urn:ietf:params:oauth:grant-type:jwt-dpop` (from metadata or configuration).
    pub supports_jwt_dpop: bool,
}

pub enum ClientAuth {
    ClientSecretBasic { client_id: String, secret: ClientSecret },
    ClientSecretPost { client_id: String, secret: ClientSecret },
    PrivateKeyJwt { client_id: String, signer: Arc<dyn JwsSigner> },
    /// RFC 8705 §2. The TLS client certificate is the caller's transport's job; the library sends `client_id`.
    TlsClientAuth { client_id: String },
}

pub enum ResourceAsClientAuth {
    Authenticated(ClientAuth),
    /// No client authentication. Allowed only with a sender-constrained ID-JAG (draft §4.4, §9.1).
    SenderConstrainedOnly { client_id: String },
}
```

The types encode two rules:

- There is no way to configure the IdP leg without client authentication.
- The Resource AS leg can drop client authentication only through `SenderConstrainedOnly`, and §6 refuses to build a request in that mode unless the ID-JAG carries a `jkt` or `x5t#S256` binding.

`ClientAuth` is defined in `client_auth` and re-exported from `client`. `ClientAuth::client_id()` and `ResourceAsClientAuth::client_id()` return the client identifier for that server.

Client assertions for `PrivateKeyJwt` are built as in RFC-002 §9, with `aud` set to the target server's issuer identifier.

## 2. Subject tokens

```rust
pub enum SubjectToken {
    /// subject_token_type = urn:ietf:params:oauth:token-type:id_token
    IdToken(IdToken),
    /// subject_token_type = urn:ietf:params:oauth:token-type:saml2
    SamlAssertion(SamlAssertion),
    /// subject_token_type = urn:ietf:params:oauth:token-type:refresh_token
    RefreshToken(RefreshToken),
}
```

- `SamlAssertion` holds the assertion XML bytes. By default it is sent base64url without padding, as RFC 8693 §3 defines for `saml2` ("a base64url-encoded SAML 2.0 assertion"). `IdpConnection::saml_encoding = SamlEncoding::Base64` switches to padded standard base64, as in the draft §4.5 example, for IdPs that only accept that. The `idp` component accepts both (RFC-005 §2). `docs/interop.md` records what real IdPs do.
- Draft §4.3 says IdPs MUST accept Identity Assertions and MAY accept Refresh Tokens, so `RefreshToken` can be refused with `invalid_request` by an IdP that doesn't support it. The client learns this from the error (§8); there is no metadata signal.

## 3. Token Exchange request (§4.3)

```rust
pub struct TokenExchange<'a> {
    pub idp: &'a IdpConnection,
    /// The Resource AS the ID-JAG is for. Used for the DPoP preflight below and the §5 self-checks.
    pub resource_as: &'a ResourceAsConnection,
    /// Exactly one value by construction (draft §4.3). Usually `resource_as.issuer`;
    /// may be an IdP-specific alias such as `urn:example:idp:saas-tool`.
    pub audience: ExchangeAudience,
    /// Zero or more RFC 8707 resource identifiers, sent as repeated `resource` parameters.
    pub resources: Vec<ResourceIdentifier>,
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub subject_token: &'a SubjectToken,
    /// Passed through only. The draft defines no processing for it (§4.3, §9.10).
    pub actor_token: Option<ActorToken>,
    /// Request DPoP binding of the ID-JAG (RFC-007).
    pub dpop: Option<DpopRequest<'a>>,
    /// DER of the TLS client certificate the caller's `HttpClient` presents to the IdP, if any.
    /// Nothing is sent for it; it feeds the §5 downgrade check (draft §9.11.2.1).
    pub tls_client_certificate: Option<&'a [u8]>,
    /// Skip the §5 binding-downgrade checks. Default `false`.
    pub accept_unbound_id_jag: bool,
    pub now: SystemTime,
}

impl<'a> TokenExchange<'a> {
    /// `audience` is `resource_as.issuer`; nothing optional is set.
    pub fn new(
        idp: &'a IdpConnection,
        resource_as: &'a ResourceAsConnection,
        subject_token: &'a SubjectToken,
        now: SystemTime,
    ) -> Self;
    pub fn accept_unbound_id_jag(self, accept: bool) -> Self;
    pub async fn build(&self) -> Result<HttpRequest, Error>;
}
```

`build` is async because a DPoP proof or a `private_key_jwt` client assertion is signed in it (RFC-002 §7). `ExchangeAudience` is a string newtype (`ExchangeAudience::new`, `From<Issuer>`, `From<&Issuer>`), kept exactly as given. `ResourceIdentifier` and `ActorToken` are built with `ResourceIdentifier::new(resource)` and `ActorToken::new(token, token_type)`. `DpopRequest { key, nonce }` is defined in RFC-007 §2.

The request is `POST` to `idp.token_endpoint` with `application/x-www-form-urlencoded` and `Accept: application/json`:

| Parameter | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:id-jag` |
| `audience` | `audience` |
| `resource` | One parameter per entry in `resources`, in order |
| `scope` | Space-joined, if present |
| `authorization_details` | JSON-serialized array, if present |
| `subject_token`, `subject_token_type` | From `SubjectToken` |
| `actor_token`, `actor_token_type` | If present; `actor_token_type` is required with it (RFC 8693 §2.1) |
| Client authentication | Per `ClientAuth` |
| `DPoP` header | If `dpop` is set; `htm=POST`, `htu=idp.token_endpoint` (draft §9.11.1.1) |

Construction rules:

- **Resource identifiers are never rewritten.** A `ResourceIdentifier` made from discovered Protected Resource Metadata (`ResourceIdentifier::from_metadata`, RFC-006 §4) carries the metadata's `resource` value byte-for-byte, which draft §4.3 and §9.6 require. One made by hand from a URL is also kept as given, with no trailing-slash or case normalization.
- **No credentials in URLs.** Tokens and secrets only ever go in the form body or headers (draft §9.2). `HttpRequest.url` is always the bare configured token endpoint.
- `scope` values mean what the Resource AS defines, not their OIDC meaning (draft §4.3). The library doesn't interpret them.
- **No DPoP proof for a Resource AS without `jwt-dpop`.** `dpop` set together with `resource_as.supports_jwt_dpop = false` fails at build time with `Error::ResourceAsLacksJwtDpop`.
  - The resulting ID-JAG could not be used: a conforming IdP either refuses the exchange with `invalid_target` or binds a grant that the Resource AS cannot accept (jwt-dpop-grant §7.1, RFC-005 §6.1).
  - To get a DPoP-bound *access token* from such an AS, leave `dpop` unset here and send the proof on the access token request instead (§6, draft §9.11.1.2.3).
- **Unusable inputs.** An empty `audience`, an empty resource identifier, an empty `subject_token`, or an `actor_token` with an empty value or type fails with `Error::InvalidRequest`. A `tls_client_certificate` that is not DER fails with `Error::InvalidConfiguration`.

## 4. Token Exchange response

```rust
pub struct IssuedIdJag {
    pub id_jag: IdJag,
    /// The scope the IdP granted. Equal to the requested scope when the response omits `scope`.
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub expires_in: Option<Duration>,
    pub received_at: SystemTime,
    /// Unverified view of the ID-JAG's claims for the checks in §5.
    pub peek: IdJagPeek,
    /// True until the ID-JAG has been presented once. Feeds §8.
    pub fresh: bool,
}

impl IssuedIdJag {
    /// Sets `fresh` to false. Call it after sending an access token request.
    pub fn mark_presented(&mut self);
    /// Whether the ID-JAG's `exp` has passed at `now`.
    pub fn is_expired(&self, now: SystemTime) -> bool;
}

pub fn parse_token_exchange_response(
    request: &TokenExchange<'_>,
    response: HttpResponse,
) -> Result<IssuedIdJag, Error>;
```

`received_at` is the request's `now`. The library holds no state, so `fresh` changes only when the caller calls `mark_presented`. The response body is zeroized before `parse_token_exchange_response` returns.

Validation (draft §4.3.4 and RFC 8693 §2.2.1):

1. A non-200 status is parsed as an OAuth error (§8).
2. The body is a JSON object with unique member names, otherwise `Error::InvalidTokenResponse`. Rules 4 and 5, and a `scope`, `expires_in` or `authorization_details` of the wrong shape, fail with the same error.
3. `issued_token_type` equals `urn:ietf:params:oauth:token-type:id-jag`, otherwise `Error::UnexpectedIssuedTokenType`.
4. `token_type` equals `N_A`, case-insensitively (RFC 6749 §7.1).
5. `access_token` is present and non-empty. It is the ID-JAG.
6. If `scope` is absent, the granted scope is the requested scope (draft §4.3.4: REQUIRED when different).
7. A `refresh_token`, which draft §4.3.4 says SHOULD NOT be used, is dropped and zeroized, not surfaced.
8. Then the §5 self-checks run.

## 5. Self-checks on the issued ID-JAG

The client can't, and needn't, verify the IdP's signature. The Resource AS does that. It can still read the claims to catch problems before sending the ID-JAG and its Resource AS credentials anywhere. `IdJagPeek` is a separate type from RFC-002's `Verified<IdJagClaims>` and is never accepted where verified claims are required.

```rust
impl IdJagPeek {
    pub fn issuer(&self) -> &Issuer;
    pub fn audience(&self) -> &Audience;
    pub fn client_id(&self) -> &str;
    pub fn resources(&self) -> Option<&Resources>;
    pub fn scope(&self) -> Option<&Scope>;
    pub fn confirmation(&self) -> Option<&Confirmation>;
    pub fn expires_at(&self) -> NumericDate;
    pub fn is_expired(&self, now: SystemTime) -> bool;
}
```

Every accessor returns an unverified value. `IdJagPeek` has no public constructor; the only one a caller gets is `IssuedIdJag::peek`. Its `Debug` output prints `iss`, `aud`, `client_id`, `exp` and `cnf` only.

| Check | Failure | Source |
| --- | --- | --- |
| The ID-JAG parses as a compact JWS whose `typ` is `oauth-id-jag+jwt` and whose payload is a well-formed ID-JAG claim set (RFC-002 §6) | `Error::MalformedIdJag` | draft §3.1 |
| `aud` is `resource_as.issuer` (or a single-element array of it) | `Error::IdJagAudienceMismatch` | draft §4.4.1. Catches an IdP alias resolved to an unexpected AS before credentials leave. |
| `client_id` is the client_id of `resource_as.client_auth` | `Error::IdJagClientIdMismatch` | draft §4.4.1, §5.1. Fails early on the "used the IdP credentials at the Resource AS" mistake. |
| Each `resource` value is byte-identical to one that was requested. `TokenExchange::tolerate_resource_trailing_slash(true)` relaxes this by exactly one trailing `/`, for IdPs that rewrite the identifier (the xaa.dev IdP drops it). | `Error::IdJagResourceAltered { got, requested }` | draft §4.3.3 ("exactly as the Client sent it") |
| A DPoP proof was sent and `cnf.jkt` is missing or doesn't match the key's thumbprint | `Error::BindingDowngrade` | draft §9.11.1.1 (client SHOULD inspect) |
| The caller says a TLS client certificate was presented and `cnf.x5t#S256` is missing or doesn't match | `Error::BindingDowngrade` | draft §9.11.2.1 |

Both downgrade checks are on by default. `TokenExchange::accept_unbound_id_jag(true)` turns them off for IdPs known to ignore DPoP proofs. The IdP binds to one mechanism, so when a proof was sent and a certificate was presented, a match on either binding passes.

## 6. Access Token Request (§4.4)

```rust
pub struct AccessTokenRequest<'a> {
    pub resource_as: &'a ResourceAsConnection,
    pub id_jag: &'a IssuedIdJag,
    /// Optional downscoping. Must be a subset of the ID-JAG's scope.
    pub scope: Option<Scope>,
    pub dpop: Option<DpopRequest<'a>>,
    pub now: SystemTime,
}

impl AccessTokenRequest<'_> {
    pub async fn build(&self) -> Result<HttpRequest, Error>;
}
```

| Parameter | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:jwt-dpop` if the ID-JAG carries `cnf.jkt` (draft §4.4, jwt-dpop-grant §4.1); otherwise `urn:ietf:params:oauth:grant-type:jwt-bearer`, including for `x5t#S256`-bound ID-JAGs (draft §9.11.2.2) |
| `assertion` | The ID-JAG |
| `scope` | If present |
| Client authentication | Per `resource_as.client_auth`. `SenderConstrainedOnly` sends `client_id` as a form parameter (RFC 6749 §3.2.1). |
| `DPoP` header | Required when the ID-JAG carries `cnf.jkt`; optional otherwise, to request a DPoP-bound access token (draft §9.11.1.2.3). `htm=POST`, `htu=resource_as.token_endpoint`. |

Build-time refusals:

- `SenderConstrainedOnly` together with an ID-JAG that has no `jkt` or `x5t#S256` binding fails with `Error::UnauthenticatedUnboundGrant`. The Resource AS would reject it with `invalid_client` (draft §4.4), and sending a bare bearer grant without authentication is never correct.
- A `cnf.jkt` ID-JAG without `dpop`, or with a key whose thumbprint differs, fails with `Error::DpopKeyRequired`.
- A `cnf.jkt` ID-JAG with `supports_jwt_dpop = false` fails with `Error::ResourceAsLacksJwtDpop`. jwt-dpop-grant §7.1 warns that such an AS may accept the bound grant as a bearer grant and defeat the binding. The §3 preflight normally catches this earlier; this check covers an ID-JAG bound by an IdP that was not asked to.
- A `scope` that is not a subset of the ID-JAG's scope fails with `Error::ScopeNotSubset`. The ID-JAG's scope is its `scope` claim, or `IssuedIdJag::scope` when the claim is absent.

## 7. Access token response

```rust
pub struct IssuedAccessToken {
    pub access_token: AccessToken,
    pub token_type: AccessTokenType, // Bearer | DPoP
    pub expires_in: Option<Duration>,
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    /// Off-profile: draft §4.4.4 says the Resource AS SHOULD NOT issue one. Surfaced if present.
    pub refresh_token: Option<RefreshToken>,
    pub received_at: SystemTime,
}

pub fn parse_access_token_response(
    request: &AccessTokenRequest<'_>,
    response: HttpResponse,
) -> Result<IssuedAccessToken, Error>;
```

- A non-200 status is parsed as an OAuth error (§8). A body that is not a JSON object with unique member names, or a missing or empty `access_token`, fails with `Error::InvalidTokenResponse`.
- `token_type` is `Bearer` or `DPoP`, case-insensitively. Anything else fails with `Error::UnsupportedTokenType`.
- `DPoP` is accepted only if the request carried a DPoP proof; otherwise `Error::InvalidTokenResponse`.
- `Bearer` is accepted even when a proof was sent; draft §9.11.1.2.3 and jwt-dpop-grant §6 allow it. `IssuedAccessToken::is_sender_constrained()` reports which one the client got: it is true for `DPoP`. A certificate-bound token (RFC 8705) is typed `Bearer` and cannot be told apart here.
- If `scope` is absent, the granted scope is the requested one (RFC 6749 §5.1), or the ID-JAG's scope when none was requested.
- `received_at` is the request's `now`. The response body is zeroized before the function returns.

## 8. Errors and remediation

Every non-200 response from either token endpoint whose body is an RFC 6749 §5.2 error object becomes `Error::TokenEndpoint(Box<TokenEndpointError>)`. A non-200 response with any other body is `Error::UnexpectedResponse`.

```rust
pub struct TokenEndpointError {
    pub endpoint: Endpoint, // Idp | ResourceAs
    pub status: u16,
    pub code: OAuthErrorCode,
    pub description: Option<String>,
    pub uri: Option<String>,
    /// From `insufficient_user_authentication` (draft §9.3, RFC 9470).
    pub max_age: Option<u64>,
    pub acr_values: Option<String>,
    /// From the `DPoP-Nonce` response header.
    pub dpop_nonce: Option<String>,
}

#[non_exhaustive]
pub enum Remediation {
    RetryWithDpopNonce,     // use_dpop_nonce at either server (RFC 9449 §8)
    ObtainNewSubjectToken,  // IdP invalid_request or invalid_grant (draft §4.3.4.3)
    StepUpAuthentication,   // IdP insufficient_user_authentication (draft §9.3)
    ChangeRequest,          // IdP invalid_target (includes a DPoP proof for an AS without jwt-dpop, RFC-005 §6.1)
    ObtainNewIdJag,         // Resource AS invalid_grant on a re-presented ID-JAG (draft §4.4.4)
    FixClientConfiguration, // invalid_client, unauthorized_client, invalid_dpop_proof at either server
    NotRemediableByClient,  // access_denied at either server; Resource AS invalid_grant on a fresh ID-JAG
    Unknown,                // every other (code, endpoint) pair
}

impl TokenEndpointError {
    pub fn remediation(&self, id_jag_was_fresh: bool) -> Remediation;
}
```

`id_jag_was_fresh` is `IssuedIdJag::fresh` as it was when the failed access token request was built. It is ignored for IdP errors. `invalid_grant` at the IdP maps to `ObtainNewSubjectToken` because it is RFC 6749 §5.2's code for an expired or revoked grant, which at the IdP is the subject token. `RetryWithDpopNonce` means repeating the request with a proof that carries `dpop_nonce`.

The library is stateless and never retries on its own. `remediation` encodes draft §4.4.4:

| Situation | Next step |
| --- | --- |
| Access token expired | Present the same ID-JAG again if its `exp` hasn't passed (§6). |
| ID-JAG expired, or `invalid_grant` on a re-presented ID-JAG | Request a new ID-JAG with the original subject token (§3). |
| `invalid_grant` on a fresh ID-JAG | Stop. Draft §4.4.4: requesting another "will not resolve the error". |
| ID Token expired | Get a new one through OIDC refresh (outside this crate), or use a Refresh Token as `subject_token` if the IdP supports that (§2). Otherwise re-authenticate the user. |
| `access_denied` at either server | Stop. Fixing it takes an administrative process (IGA) on the server's side (draft §4.3.4.3, §4.4.3). |

## 9. SAML subject tokens (§4.5)

A client that does SSO with SAML exchanges its assertion for an IdP Refresh Token once, then uses that Refresh Token as the `subject_token` in §3.

```rust
pub struct SamlToRefreshToken<'a> {
    pub idp: &'a IdpConnection,
    pub assertion: &'a SamlAssertion,
    /// Defaults to `openid offline_access` (draft §4.5 SHOULD); extra scopes are allowed.
    pub scope: Scope,
    pub now: SystemTime,
}

impl<'a> SamlToRefreshToken<'a> {
    /// Sets `scope` to `openid offline_access`.
    pub fn new(
        idp: &'a IdpConnection,
        assertion: &'a SamlAssertion,
        now: SystemTime,
    ) -> Result<Self, Error>;
    pub async fn build(&self) -> Result<HttpRequest, Error>;
}

pub fn parse_saml_exchange_response(
    request: &SamlToRefreshToken<'_>,
    response: HttpResponse,
) -> Result<RefreshToken, Error>;
```

- The request sets `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token`, `subject_token_type=urn:ietf:params:oauth:token-type:saml2`, and sends no `audience`.
- The assertion is encoded per `idp.saml_encoding` (§2).
- The response must carry `issued_token_type=urn:ietf:params:oauth:token-type:refresh_token` (otherwise `Error::UnexpectedIssuedTokenType`) and `token_type=N_A`. It yields a `RefreshToken`, read from the RFC 8693 §2.2.1 `access_token` member.
- Mapping the SAML `Audience` to the client is the IdP's check (RFC-005 §8).

## 10. Discovery

Clients that start from a resource URL, as AI agents and MCP clients do, go through RFC-006:

1. Fetch and validate the Protected Resource Metadata. `resource` must be identical to the URL used (draft §9.6, RFC 9728 §3.3).
2. Choose an entry from `authorization_servers`. Fetch and validate its metadata; `issuer` must be identical (draft §9.5, RFC 8414 §3.3). On a mismatch, the metadata MUST NOT be used.
3. Record whether `authorization_grant_profiles_supported` contains `urn:ietf:params:oauth:grant-profile:id-jag`. The draft says SHOULD advertise, so its absence is reported, not fatal. Also record whether `grant_types_supported` contains `jwt-dpop`.
4. Build a `ResourceAsConnection` from the result. Build `resources` from `ResourceIdentifier::from_metadata`.

```rust
pub async fn discover_resource<C: HttpClient>(
    http: &C,
    origin: PrmOrigin<'_>,
    opts: &FetchOptions,
) -> Result<DiscoveredResource, Error>;

pub async fn discover_resource_as<C: HttpClient>(
    http: &C,
    issuer: &Issuer,
    opts: &FetchOptions,
) -> Result<DiscoveredResourceAs, Error>;

pub async fn discover_idp<C: HttpClient>(
    http: &C,
    issuer: &Issuer,
    opts: &FetchOptions,
) -> Result<DiscoveredIdp, Error>;

pub struct DiscoveredResource {
    /// The metadata's `resource`, byte-for-byte.
    pub resource: ResourceIdentifier,
    pub metadata: ValidatedPrm,
}

pub struct DiscoveredResourceAs {
    pub issuer: Issuer,
    pub token_endpoint: Url,
    /// `authorization_grant_profiles_supported` lists the ID-JAG profile.
    pub id_jag_profile: Support,
    /// `grant_types_supported` lists the `jwt-dpop` grant.
    pub jwt_dpop: Support,
    pub metadata: AuthorizationServerMetadata,
}

pub struct DiscoveredIdp {
    pub issuer: Issuer,
    pub token_endpoint: Url,
    /// `identity_chaining_requested_token_types_supported` lists the ID-JAG token type (draft §7.1).
    pub issues_id_jag: Support,
    pub metadata: AuthorizationServerMetadata,
}

impl DiscoveredResourceAs {
    pub fn connection(&self, client_auth: ResourceAsClientAuth) -> ResourceAsConnection;
}

impl DiscoveredIdp {
    pub fn connection(&self, client_auth: ClientAuth) -> IdpConnection;
}
```

- `discover_resource` is step 1 and fails with `Error::PrmResourceMismatch`. The caller chooses the Resource AS from `metadata.authorization_servers()`.
- `discover_resource_as` is steps 2 and 3. It fails with `Error::MetadataIssuerMismatch`, or with `Error::InvalidMetadata` when the document has no `token_endpoint`. `Support` is `Advertised` or `NotAdvertised`.
- `DiscoveredResourceAs::connection` sets `supports_jwt_dpop` only if the metadata advertises the grant.
- `discover_idp` does the same for the IdP, with the OIDC Discovery fallback of RFC-006 §3. `DiscoveredIdp::connection` uses the default `SamlEncoding`.
- `PrmOrigin`, `FetchOptions`, `ValidatedPrm`, `Support` and `AuthorizationServerMetadata` are defined in RFC-006.

Which IdP to use for a given user is out of scope (draft Appendix A.4.2.1).

## 11. Handling subject tokens and grants (§9.2)

The library holds no state. These are the guarantees it makes, and the caller's side of draft §9.2:

- **Library.** All tokens are secret newtypes: no `Display`, redacted `Debug`, zeroized on drop (RFC-002 §11). Tokens never go into URLs (§3). `IssuedIdJag` and `IssuedAccessToken` don't implement `Serialize`; persisting one takes an explicit `.expose_secret()`.
- **Caller.** Scope stored subject tokens to the user session. Keep them away from logs and telemetry. Store them in a different protection domain from client credentials (for example, client keys in a KMS behind `JwsSigner`). Prefer requesting a new ID-JAG over caching one.

## 12. Example

```rust
use std::time::SystemTime;
use xaa::claims::Scope;
use xaa::client::{AccessTokenRequest, ResourceIdentifier, SubjectToken, TokenExchange};
use xaa::http::HttpClient;

let subject = SubjectToken::IdToken(id_token);

let mut exchange = TokenExchange::new(&idp, &resource_as, &subject, SystemTime::now());
exchange.resources = vec![ResourceIdentifier::new("https://api.resource.example/")];
exchange.scope = Some(Scope::parse("todos.read")?);
let issued = xaa::client::parse_token_exchange_response(
    &exchange,
    http.send(exchange.build().await?).await?,
)?;

let request = AccessTokenRequest {
    resource_as: &resource_as,
    id_jag: &issued,
    scope: None,
    dpop: None,
    now: SystemTime::now(),
};
let token = xaa::client::parse_access_token_response(
    &request,
    http.send(request.build().await?).await?,
)?;
```

The client also exposes one async free function per round trip that wraps build → `HttpClient::send` → parse:

```rust
pub async fn exchange_for_id_jag<C: HttpClient>(
    http: &C,
    request: &TokenExchange<'_>,
) -> Result<IssuedIdJag, Error>;

pub async fn request_access_token<C: HttpClient>(
    http: &C,
    request: &AccessTokenRequest<'_>,
) -> Result<IssuedAccessToken, Error>;

pub async fn exchange_saml_for_refresh_token<C: HttpClient>(
    http: &C,
    request: &SamlToRefreshToken<'_>,
) -> Result<RefreshToken, Error>;
```

A transport failure is `Error::Http`. The `HttpClient` passed in MUST NOT follow redirects: a redirect would replay the subject token or ID-JAG and the client's credentials to another origin. `request_access_token` does not change `IssuedIdJag::fresh`; the caller calls `mark_presented` afterwards.

## 13. Security checks summary

| Check | Where |
| --- | --- |
| IdP client authentication cannot be configured away | §1 |
| An unauthenticated Resource AS request needs a bound ID-JAG | §1, §6 |
| Exactly one `audience` | §3 (by type) |
| Resource identifiers sent unchanged from metadata | §3, §10 |
| No tokens or secrets in URLs | §3 |
| `issued_token_type` and `token_type` checked | §4 |
| ID-JAG `aud`, `client_id`, `resource` self-checks | §5 |
| DPoP / mTLS downgrade detection | §5 |
| No DPoP binding requested for, and no bound grant sent to, an AS lacking `jwt-dpop` | §3, §6 |
| Metadata `issuer` and PRM `resource` identity checks | §10 |
| Secret handling | §11 |

## 14. Tests

- **Flow tests** (`tests/flow_test.rs`, `--features client,resource-as,idp`): full exchange → access token, with and without DPoP, with an ID Token and a Refresh Token subject, and starting from discovery (§10). A flow test with a SAML subject is not there yet (RFC-001 §9).
- **Negative cases** in `src/client/tests.rs`, covering the rows of §4, §5, §6 and §7.
- **Request shape:** golden form bodies for each request type; a check that the URL carries no query string; repeated `resource` parameters keep their order.
- **Redaction:** the `Debug` output of every token type contains no token bytes.
- **Remediation:** a table-driven test that maps each `(endpoint, code, fresh)` to its `Remediation`.
- **Playground** (`XAA_RUN_PLAYGROUND=1`): ID Token → ID-JAG at `https://idp.xaa.dev/token` → access token at `https://auth.resource.xaa.dev/token` → `GET https://api.resource.xaa.dev/api/todos`. Run by hand with `xaa-client --playground` on 2026-11-14; it passes. There is no automated test, because the login needs a browser.

## 15. Spec coverage

| Section | Covered by |
| --- | --- |
| §4.1 Overview (client steps 2–4) | §3–§7 |
| §4.2 User Authentication | Out of scope; the caller supplies `SubjectToken` (§2) |
| §4.3 Token Exchange parameters, audience/resource profiling | §3 |
| §4.3.1 / §4.3.2 examples | §14 golden tests |
| §4.3.4 Response | §4 |
| §4.3.4.2 RAR | §3, §4, §7 (`authorization_details` round trip) |
| §4.3.4.3 Error Response (client side) | §8 |
| §4.4 Access Token Request | §6 |
| §4.4.2 Response | §7 |
| §4.4.3 Error Response (client side) | §8 |
| §4.4.4 Refresh Token (client behavior) | §7, §8 |
| §4.5 SAML 2.0 Subject Token Interoperability (client side) | §9 |
| §5 / §5.1 client registrations | §1 |
| §8 Client Metadata | RFC-006 §6 |
| §9.1 Client Authentication | §1, §6 |
| §9.2 Storage of Subject Tokens | §11 |
| §9.3 Step-Up Authentication | §8 |
| §9.5, §9.6 metadata validation | §10, RFC-006 |
| §9.10 Actor delegation | §3 (pass-through only) |
| §9.11 sender constraining (client side) | §5, §6, RFC-007 |
| identity-chaining §2.2, §2.3, §2.4 | §3–§7, §10 |
| jwt-dpop-grant §4.1, §7.1 | §3, §6 |
