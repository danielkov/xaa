# RFC-006: Metadata and discovery

**Status**: Draft
**Date**: 2026-11-14

## Summary

This RFC defines what the three components publish and discover:
- **Authorization Server Metadata (RFC 8414):** parse, validate, and emit for the IdP and the Resource AS, including the XAA parameters (draft §7).
- **Protected Resource Metadata (RFC 9728):** parse and validate, so clients can find a resource's AS (draft §9.6).
- **Client metadata:** the client parameter (draft §8).
- **JWK Set retrieval:** fetching the keys the Resource AS needs (draft §4.4.1, §7.1).

Fetching goes through the BYO `HttpClient` (RFC-001 §6). Every fetch also exists sans-IO: one function builds the `HttpRequest`, another validates the `HttpResponse`. Nothing is cached by the library.

The `HttpClient` MUST NOT follow redirects for these fetches. The `issuer` and `resource` checks bind a document to the URL it was requested from, and a followed redirect would let another origin answer for it. A redirect status is treated like any other non-200 response.

---

## 1. Scope

| Document | Parse + validate | Emit | Used by |
| --- | --- | --- | --- |
| RFC 8414 AS metadata (and the OIDC Discovery fallback) | yes | yes | client (discovers both servers), Resource AS (discovers the IdP), both servers (publish) |
| RFC 9728 Protected Resource Metadata | yes | no | client |
| Client metadata (RFC 7591 / Client ID Metadata Document) | no | yes | client (registration) |
| JWK Set | yes | yes | Resource AS (fetch IdP keys), IdP (publish) |

Emitting Protected Resource Metadata belongs to the Resource Server, which is outside this crate (RFC-001 §3). The PRM type does implement `Serialize`, for tests and for callers who want it.

## 2. Authorization Server Metadata

```rust
pub struct AuthorizationServerMetadata {
    pub issuer: Issuer,
    pub token_endpoint: Option<Url>,
    pub jwks_uri: Option<Url>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,              // RFC 9449 §5.1
    pub tls_client_certificate_bound_access_tokens: Option<bool>,            // RFC 8705 §3.3
    // XAA
    pub identity_chaining_requested_token_types_supported: Option<Vec<String>>, // identity-chaining §3, draft §7.1
    pub id_jag_signing_alg_values_supported: Option<Vec<String>>,            // draft §7.1
    pub authorization_grant_profiles_supported: Option<Vec<String>>,         // draft §7.2
    /// Every other member, preserved.
    pub extra: BTreeMap<String, serde_json::Value>,
}
```

Derived views answer the questions the components ask. Each returns `Support`, not `bool`, because identity-chaining §3 warns that "lack of a value does not necessarily mean that the token type is unsupported":

```rust
pub enum Support { Advertised, NotAdvertised }

impl Support {
    pub fn is_advertised(self) -> bool;
}

impl AuthorizationServerMetadata {
    /// Parse and validate a document fetched for `expected_issuer` (§3).
    pub fn from_json(bytes: &[u8], expected_issuer: &Issuer, opts: &FetchOptions) -> Result<Self, Error>;
    pub fn issues_id_jag(&self) -> Support;             // identity_chaining_requested_token_types_supported ∋ …:id-jag
    pub fn accepts_id_jag_profile(&self) -> Support;    // authorization_grant_profiles_supported ∋ …:grant-profile:id-jag
    pub fn accepts_jwt_dpop(&self) -> Support;          // grant_types_supported ∋ …:jwt-dpop
    /// The document as a JSON object. `Serialize` emits the same.
    pub fn to_value(&self) -> serde_json::Value;
}
```

`from_json` is the only way to get the type from received bytes, so a received document has always passed the §3 checks. A member that is JSON `null` is treated as absent. A modelled member of the wrong JSON type, or a duplicated member name, fails the document with `Error::InvalidMetadata`. When emitting, a member in `extra` never overrides a modelled member.

### 2.1 Emit

```rust
pub struct IdpMetadataBuilder { /* … */ }

impl IdpMetadataBuilder {
    pub fn new(issuer: Issuer, token_endpoint: Url, jwks_uri: Url) -> Self;
    pub fn requested_token_type(self, token_type: impl Into<String>) -> Self;
    pub fn grant_type(self, grant_type: impl Into<String>) -> Self;
    pub fn id_jag_signing_algs(self, algs: &[SignatureAlgorithm]) -> Self;
    pub fn token_endpoint_auth_methods(self, methods: Vec<String>) -> Self;
    pub fn token_endpoint_auth_signing_algs(self, algs: &[SignatureAlgorithm]) -> Self;
    pub fn dpop_signing_algs(self, algs: &[SignatureAlgorithm]) -> Self;
    pub fn extra(self, name: impl Into<String>, value: serde_json::Value) -> Self;
    pub fn allow_http_loopback(self, allow: bool) -> Self;
    pub fn build(self) -> Result<AuthorizationServerMetadata, Error>;
}

pub struct ResourceAsMetadataBuilder { /* … */ }

impl ResourceAsMetadataBuilder {
    pub fn new(issuer: Issuer, token_endpoint: Url) -> Self;
    pub fn dpop_grant(self, enabled: bool) -> Self;
    pub fn grant_type(self, grant_type: impl Into<String>) -> Self;
    pub fn jwks_uri(self, jwks_uri: Url) -> Self;
    pub fn token_endpoint_auth_methods(self, methods: Vec<String>) -> Self;
    pub fn token_endpoint_auth_signing_algs(self, algs: &[SignatureAlgorithm]) -> Self;
    pub fn dpop_signing_algs(self, algs: &[SignatureAlgorithm]) -> Self;
    pub fn tls_client_certificate_bound_access_tokens(self, supported: bool) -> Self;
    pub fn extra(self, name: impl Into<String>, value: serde_json::Value) -> Self;
    pub fn allow_http_loopback(self, allow: bool) -> Self;
    pub fn build(self) -> Result<AuthorizationServerMetadata, Error>;
}
```

| Builder | Always emits | Invariant enforced at `build()` | Source |
| --- | --- | --- | --- |
| IdP | `identity_chaining_requested_token_types_supported` ∋ `…:token-type:id-jag`; `grant_types_supported` ∋ `…:token-exchange`; `jwks_uri` | If `id_jag_signing_alg_values_supported` is set, it contains `RS256` | draft §7.1 SHOULD / MUST |
| Resource AS | `authorization_grant_profiles_supported` ∋ `…:grant-profile:id-jag`; `grant_types_supported` ∋ `…:jwt-bearer` | The profile is present only together with `jwt-bearer`; `jwt-dpop` is added by `dpop_grant(true)` | draft §7.2 MUST; jwt-dpop-grant §5.2 SHOULD |

Both `build()` methods also refuse, with `Error::InvalidConfiguration`:
- an empty list (RFC 8414 §2: "Claims with zero elements MUST be omitted");
- an `extra` member whose name is a modelled member, so the profile and grant types cannot be overridden that way.

They apply the §3 URL rules to the issuer, `token_endpoint`, and `jwks_uri` as well, with the §3 errors. `allow_http_loopback(true)` relaxes them as `FetchOptions::allow_http_loopback` does.

The IdP's document serves at both the RFC 8414 location and as OIDC Discovery; OIDC-only members go in through `extra`. `Idp::metadata_builder(jwks_uri)` (RFC-005 §11) and `ResourceAs::metadata()` (RFC-004 §10) return these builders preloaded from their configuration.

The Resource AS builder has no input for trusted issuers, tenants, or clients. Draft §9.7 says MUST NOT disclose issuer allow-lists, and §7.2 says inclusion of the profile "does not indicate that any particular issuer ... will be accepted".

## 3. Fetching and validating AS metadata

```rust
pub async fn fetch_authorization_server_metadata<C: HttpClient>(
    http: &C,
    issuer: &Issuer,
    opts: &FetchOptions,
) -> Result<AuthorizationServerMetadata, Error>;

pub struct FetchOptions {
    /// Accept `http` for loopback hosts. Default `false`.
    pub allow_http_loopback: bool,
    /// Try OIDC Discovery after a non-200 response from the RFC 8414 location. Default `true`.
    pub oidc_discovery_fallback: bool,
    /// Largest response body accepted, in bytes. Default `DEFAULT_MAX_BODY_BYTES` (64 KiB).
    pub max_body_bytes: usize,
}

pub enum MetadataLocation { Rfc8414, OidcDiscovery }

// Sans-IO
pub fn authorization_server_metadata_url(issuer: &Issuer, location: MetadataLocation, opts: &FetchOptions)
    -> Result<Url, Error>;
pub fn authorization_server_metadata_request(issuer: &Issuer, location: MetadataLocation, opts: &FetchOptions)
    -> Result<HttpRequest, Error>;
pub fn parse_authorization_server_metadata_response(issuer: &Issuer, response: &HttpResponse, opts: &FetchOptions)
    -> Result<AuthorizationServerMetadata, Error>;
```

Locations are tried in order:

1. RFC 8414 §3.1: `/.well-known/oauth-authorization-server` inserted between the host and the issuer's path. For example, `https://as.example/tenant1` maps to `https://as.example/.well-known/oauth-authorization-server/tenant1`.
2. Fallback: OIDC Discovery §4, appending `/.well-known/openid-configuration` to the issuer. Draft §7.1 allows this (MAY), and RFC 8414 §5 describes it. It is on by default (`FetchOptions::oidc_discovery_fallback`) because real deployments need it. The xaa.dev IdP serves only `openid-configuration` and returns 404 for the RFC 8414 path (`docs/interop.md`).

One terminating `/` of the issuer's path is removed before either URL is built.

The fallback runs when the first location answers with any status other than 200. It does not run after a 200: a document that is present but invalid is an error. It does not run after a transport error either, which is returned as `Error::Http`. Both locations are on the issuer's own origin and both documents get the same checks, so the fallback does not widen trust. When both locations answer non-200, the error carries the first status, unless that was 404, in which case it carries the second.

Validation:

| Check | Error | Source |
| --- | --- | --- |
| The issuer the caller passes is an `https` URL with no userinfo, query, or fragment. Checked before any request is sent. | `Error::InsecureEndpoint` for the scheme; `Error::InvalidMetadata` for the rest | RFC 8414 §2 |
| Status 200 | `Error::UnexpectedResponse` | RFC 8414 §3.2 |
| Body under the size cap (`FetchOptions::max_body_bytes`, default 64 KiB) and a JSON object with unique member names | `Error::InvalidMetadata` | RFC 8414 §3.2 |
| `issuer` is byte-identical to the issuer used to build the URL. No normalization: a trailing slash or a case difference is a mismatch. | `Error::MetadataIssuerMismatch`. The document is discarded, never partially used. A missing or non-string `issuer` is `Error::InvalidMetadata`. | draft §9.5 MUST, RFC 8414 §3.3 |
| `token_endpoint` and `jwks_uri`, when present, are URLs and use `https` | `Error::InvalidMetadata` if not a URL; `Error::InsecureEndpoint` for the scheme | RFC 8414 §2 |

The issuer check runs before any other member is looked at, so a document for another issuer always reports `Error::MetadataIssuerMismatch`.

`token_endpoint` is optional in the document. The client's discovery functions (RFC-003 §10) require it and fail with `Error::InvalidMetadata` when it is absent.

`FetchOptions::allow_http_loopback` relaxes the `https` rules for `localhost` / `127.0.0.1` / `[::1]`, for tests and `examples/`. It is never on by default.

The issuer check is the main defense against the draft §9.5 attack: an attacker's metadata declares a legitimate Resource AS issuer and so collects an ID-JAG plus the client's credentials. The other two layers are the resource checks (RFC-004 §4 rule 14, RFC-005 §5.3) and sender constraining (RFC-007).

## 4. Protected Resource Metadata

```rust
pub struct ProtectedResourceMetadata {
    pub resource: String,                      // kept byte-for-byte
    pub authorization_servers: Option<Vec<Issuer>>,
    pub scopes_supported: Option<Vec<String>>,
    pub bearer_methods_supported: Option<Vec<String>>,
    pub dpop_bound_access_tokens_required: Option<bool>,
    pub extra: BTreeMap<String, serde_json::Value>,
}

pub async fn fetch_protected_resource_metadata<C: HttpClient>(
    http: &C,
    origin: PrmOrigin<'_>,
    opts: &FetchOptions,
) -> Result<ValidatedPrm, Error>;

pub enum PrmOrigin<'a> {
    /// Build the well-known URL from the resource identifier (RFC 9728 §3.1).
    ResourceIdentifier(&'a str),
    /// A `resource_metadata` URL from a `WWW-Authenticate` challenge (RFC 9728 §5.1), plus the URL that drew it.
    Challenge { metadata_url: &'a Url, request_url: &'a Url },
}

pub struct ValidatedPrm { /* … */ }

impl ValidatedPrm {
    pub fn from_json(bytes: &[u8], origin: &PrmOrigin<'_>, opts: &FetchOptions) -> Result<Self, Error>;
    /// The resource identifier exactly as the document states it.
    pub fn resource(&self) -> &str;
    /// Empty if the document names none.
    pub fn authorization_servers(&self) -> &[Issuer];
    pub fn metadata(&self) -> &ProtectedResourceMetadata;
    pub fn into_metadata(self) -> ProtectedResourceMetadata;
}

// Sans-IO
pub fn protected_resource_metadata_url(origin: &PrmOrigin<'_>, opts: &FetchOptions) -> Result<Url, Error>;
pub fn protected_resource_metadata_request(origin: &PrmOrigin<'_>, opts: &FetchOptions) -> Result<HttpRequest, Error>;
pub fn parse_protected_resource_metadata_response(origin: &PrmOrigin<'_>, response: &HttpResponse, opts: &FetchOptions)
    -> Result<ValidatedPrm, Error>;

pub fn parse_www_authenticate_resource_metadata(header: &str) -> Result<Option<Url>, Error>;
```

Location:

- For `ResourceIdentifier`, `/.well-known/oauth-protected-resource` is inserted between the host and the path, after one terminating `/` of the path is removed (RFC 9728 §3.1). A query is kept. For example, `https://rs.example/mcp` maps to `https://rs.example/.well-known/oauth-protected-resource/mcp`.
- For `Challenge`, `metadata_url` is fetched as given. It must use `https` (`Error::InsecureEndpoint`).

Validation (draft §9.6, RFC 9728 §3.3):

- For `ResourceIdentifier`, `resource` must be identical to the identifier.
- For `Challenge`, `resource` must be identical to `request_url`. There is one allowance: a `Url` cannot represent an empty path, so when `request_url` is an origin with path `/` and no query, `resource` may be spelled with or without that `/`. Nothing else is normalized.
- A mismatch gives `Error::PrmResourceMismatch`, and the document is discarded. The check runs before any other member is looked at.
- `resource` must be an `https` URL with no userinfo or fragment (RFC 9728 §1.2): `Error::InsecureEndpoint` for the scheme, `Error::InvalidMetadata` for the rest. A query is allowed. RFC 9728 §1.2 only discourages one.
- Status, size, and JSON rules are as in §3: `Error::UnexpectedResponse` for a status other than 200, `Error::InvalidMetadata` for an oversized body, a body that is not a JSON object with unique member names, a missing `resource`, or a modelled member of the wrong type.

`ValidatedPrm` is the only way a received document is handed out, and `ResourceIdentifier::from_metadata` takes one. It carries `resource` unchanged into the Token Exchange (draft §4.3 MUST, §9.6), so the metadata check and the grant are bound to the same value. Each entry of `authorization_servers` still needs its own metadata fetched and checked (§3).

`parse_www_authenticate_resource_metadata(header)` extracts the `resource_metadata` parameter from a 401 `WWW-Authenticate` header value (RFC 9728 §5.1). It returns `Ok(None)` when no challenge in the header carries the parameter, and `Error::InvalidMetadata` when the parameter is present but is not a URL. The client starts discovery from the result, passed as `PrmOrigin::Challenge` with the URL that was requested.

## 5. JWK Set retrieval

```rust
pub async fn fetch_jwks<C: HttpClient>(http: &C, jwks_uri: &Url, opts: &FetchOptions)
    -> Result<FetchedJwks, Error>;

pub struct FetchedJwks {
    pub keys: JwkSet,
    /// `Cache-Control: max-age`, if present. A hint only.
    pub max_age: Option<Duration>,
}

// Sans-IO
pub fn jwks_request(jwks_uri: &Url, opts: &FetchOptions) -> Result<HttpRequest, Error>;
pub fn parse_jwks_response(response: &HttpResponse, opts: &FetchOptions) -> Result<FetchedJwks, Error>;
```

- The Resource AS gets each trusted issuer's `jwks_uri` from that issuer's validated metadata (draft §4.4.1 SHOULD, §7.1). A `jwks_uri` configured directly is also accepted.
- The library holds no cache. A recommended caller pattern, documented and exercised in `examples/resource-as`, is to cache per issuer and refetch at most once on `UnknownKeyId`.
- Unknown-`kid` refetches must be rate-limited (default suggestion: once per 60 s per issuer). Otherwise anyone who can send `assertion` values with random `kid`s can make the Resource AS hammer the IdP's JWKS endpoint.
- Size cap: `FetchOptions::max_body_bytes`, default 64 KiB.
- Errors: `Error::InsecureEndpoint` for a `jwks_uri` that is not `https`; `Error::UnexpectedResponse` for a status other than 200; `Error::MalformedJwk` for an oversized or malformed body; `Error::PrivateKeyMaterial` if any key carries private members. Keys of an unsupported type are skipped (RFC-002 §8).

## 6. Client metadata (§8)

```rust
pub struct ClientMetadata {
    pub grant_types: Vec<String>,
    pub authorization_grant_profiles_supported: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub jwks: Option<JwkSet>,
    pub jwks_uri: Option<Url>,
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl ClientMetadata {
    /// A builder preloaded with the id-jag profile and both grant types (draft §8 MUST).
    pub fn xaa_client() -> ClientMetadataBuilder;
    /// The rules `ClientMetadataBuilder::build` enforces, for a value edited by hand.
    pub fn validate(&self) -> Result<(), Error>;
    pub fn to_value(&self) -> serde_json::Value;
}

impl ClientMetadataBuilder {
    pub fn grant_type(self, grant_type: impl Into<String>) -> Self;
    pub fn grant_types(self, grant_types: Vec<String>) -> Self;
    pub fn authorization_grant_profiles(self, profiles: Vec<String>) -> Self;
    pub fn token_endpoint_auth_method(self, method: impl Into<String>) -> Self;
    pub fn jwks(self, jwks: JwkSet) -> Self;
    pub fn jwks_uri(self, jwks_uri: Url) -> Self;
    pub fn extra(self, name: impl Into<String>, value: serde_json::Value) -> Self;
    pub fn build(self) -> Result<ClientMetadata, Error>;
}
```

- Serializes to a Dynamic Client Registration request body (RFC 7591) or a Client ID Metadata Document.
- The builder refuses `…:grant-profile:id-jag` unless `grant_types` contains both `urn:ietf:params:oauth:grant-type:token-exchange` and `urn:ietf:params:oauth:grant-type:jwt-bearer`.
- It also refuses `jwks` together with `jwks_uri` (RFC 7591 §2 MUST NOT), and an `extra` member whose name is a modelled member. All three give `Error::InvalidConfiguration`.
- As with §2.1, advertising the profile implies nothing about which servers will be used (draft §8).

Server-side resolution of Client ID Metadata Documents, an alternative to client_id mapping (draft §5.1, Appendix A.3–A.4), is out of scope for v0.1.

## 7. Tests

- **Parse:** documents in the shape of the xaa.dev IdP, Resource AS, and PRM metadata (inline in the unit tests, per `docs/interop.md`) and of the draft Appendix A.4.2.1 metadata parse, and the `Support` views return the expected values.
- **Locations:** RFC 8414 §3.1 URL construction with and without an issuer path; the OIDC fallback path; RFC 9728 §3.1 URL construction.
- **Fallback:** runs on 404 and on any other non-200 status; does not run when disabled, after an invalid 200, or after a transport error; the fallback document gets the issuer check.
- **Negative:** issuer mismatch (including a trailing-slash difference); PRM `resource` mismatch for both origins; `http` issuer; oversized body; non-JSON; duplicate member names; wrongly typed members.
- **Builders:** each invariant in §2.1 and §6 rejects the bad combination, and built documents pass the §3 checks.
- **Discovery** through a mock `HttpClient`: in the client's unit tests, and in `tests/flow_test.rs` against the in-process `idp` and `resource-as` components.

## 8. Spec coverage

| Section | Covered by |
| --- | --- |
| §4.3 resource from PRM unchanged | §4 |
| §4.4.1 issuer keys from `jwks_uri` | §5 |
| §7 Authorization Server Metadata | §2 |
| §7.1 IdP Metadata (including the OIDC Discovery fallback) | §2.1, §3 |
| §7.2 Resource AS Metadata | §2.1 |
| §8 Client Metadata | §6 |
| §9.5 AS Metadata Validation | §3 |
| §9.6 PRM Validation | §4 |
| §9.7 Metadata Disclosure | §2.1; the protected discovery mechanism is out of scope |
| §11.3 AS metadata registrations | §2 |
| §11.4 DCR metadata registration | §6 |
| identity-chaining §2.2 AS discovery, §3 metadata | §2, §4 |
| jwt-dpop-grant §5.2 `grant_types_supported` | §2.1 |
