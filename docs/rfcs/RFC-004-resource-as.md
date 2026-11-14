# RFC-004: Resource Authorization Server

**Status**: Draft
**Date**: 2026-11-14

## Summary

This RFC defines the `resource-as` component: what an application's authorization server uses to accept ID-JAGs at its token endpoint (draft §4.4). It parses the jwt-bearer / jwt-dpop request, validates the ID-JAG against every §4.4.1 processing rule, returns a `VerifiedGrant`, enforces the invariants on what the caller may grant, and serializes the token and error responses.

The component never mints access tokens and never resolves subjects to local accounts. Both stay with the caller. Draft §1 is explicit that the Resource AS "keeps independent control over its own access tokens".

---

## 1. Configuration

```rust
pub struct ResourceAsConfig {
    /// This AS's RFC 8414 issuer identifier. The only accepted ID-JAG `aud` (§4).
    pub issuer: Issuer,
    /// Token endpoint URL, checked against the DPoP proof's `htu`.
    pub token_endpoint: Url,
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// Upper bound on `exp - iat` (draft §4.4.4). Default 10 minutes.
    pub max_id_jag_lifetime: Duration,
    /// No default: the caller must choose (§8).
    pub jti_policy: JtiPolicy,
    /// Reject ID-JAGs without a `resource` claim (draft §4.4.1 MAY). Default false.
    pub require_resource_claim: bool,
    /// Accept an unauthenticated client presenting a sender-constrained ID-JAG (draft §4.4, §9.1). Default false.
    pub allow_unauthenticated_sender_constrained: bool,
    /// Accept ID-JAGs whose `iss` is this server's own issuer (draft §9.4). Default false.
    pub allow_self_issued: bool,
    /// DPoP proof algorithms accepted (RFC 9449 §5.1). Default `default_dpop_algorithms()`.
    pub dpop_algorithms: AlgorithmPolicy,
    /// How old a DPoP proof's `iat` may be. Default 60 seconds.
    pub dpop_max_age: Duration,
    /// Set to require a server nonce in every DPoP proof (RFC 9449 §8). Default `None`.
    pub dpop_nonce: Option<Arc<dyn DpopNonce>>,
    /// Which binding the access token gets when an unbound ID-JAG arrives with both a DPoP proof and a client certificate. Default DPoP.
    pub binding_preference: BindingPreference,
    /// Size limit applied to the assertion before decoding (RFC-002 §2).
    pub parse_limits: ParseLimits,
}

impl ResourceAsConfig {
    /// No trusted issuers and the defaults above. `jti_policy` has no default.
    pub fn new(issuer: Issuer, token_endpoint: Url, jti_policy: JtiPolicy) -> Self;
}

pub struct TrustedIssuer {
    pub issuer: Issuer,
    /// Per-issuer algorithm allow-list (draft §4.4.1, RFC 8725 §3.1). Default RS256 + ES256.
    pub algorithms: AlgorithmPolicy,
    pub tenancy: Tenancy,
    /// SAML issuer entity IDs this IdP may assert in `sub_id` (draft §9.8).
    pub saml_issuers: Vec<SamlIssuerTrust>,
    /// Reject ID-JAGs from this issuer that lack an authorized `saml-nameid` `sub_id` (draft §3.2.2). Default false.
    pub require_saml_subject: bool,
}

impl TrustedIssuer {
    pub fn single_tenant(issuer: Issuer, recipient_tenant: RecipientTenant) -> Self;
    pub fn multi_tenant(issuer: Issuer, resolver: Arc<dyn TenantResolver>) -> Self;
}

pub enum Tenancy {
    /// `iss` alone identifies the tenant (draft §6.1). The recipient tenant comes from the trust relationship.
    Single { recipient_tenant: RecipientTenant },
    /// `iss` + `tenant` identify the tenant (draft §6.1). Recipient tenant resolution is the caller's.
    Multi(Arc<dyn TenantResolver>),
}

pub trait TenantResolver: Send + Sync {
    fn resolve(&self, issuer: &Issuer, tenant: &str, aud_tenant: Option<&str>) -> TenantDecision;
}

pub enum TenantDecision {
    Trusted(RecipientTenant),
    Untrusted,
    Ambiguous,
}

pub struct SamlIssuerTrust {
    pub saml_issuer: String,
    /// The `saml-nameid` members used for subject resolution. `NameIdOnly` must be chosen explicitly (draft §3.2.2).
    pub subject_key: SamlSubjectKey,
}

pub enum SamlSubjectKey {
    /// `issuer`, `nameid`, `nameid_format`, `name_qualifier`, and `sp_name_qualifier`.
    Qualified,
    /// `issuer`, `nameid`, and `nameid_format`.
    NameIdAndFormat,
    /// `issuer` and `nameid` only.
    NameIdOnly,
}
```

`RecipientTenant` is a string newtype (`RecipientTenant::new`, `as_str`). `SamlSubjectKey` has no default.

`ResourceAs::new(config)` checks the configuration and returns `Error::InvalidConfiguration` for an empty `issuer`, a zero `max_id_jag_lifetime`, or an issuer listed twice in `trusted_issuers`.

Per-call inputs that change over time are not stored in the config:

```rust
/// Caller-cached JWK Sets for trusted issuers, fetched through RFC-006 §5.
pub trait IssuerKeys: Send + Sync {
    /// A `Cow`, so a plain map can lend its entry and a cache behind a lock can hand out a copy.
    fn jwks(&self, issuer: &Issuer) -> Option<Cow<'_, JwkSet>>;
}

/// Which protected resources this AS governs, per recipient tenant (draft §4.4.1).
pub trait ResourceRegistry: Send + Sync {
    fn governs(&self, resource: &str, tenant: &RecipientTenant) -> bool;
    /// Whether tokens for this resource must be sender-constrained (draft §9.11.1.2.4, §9.11.2.2).
    fn requires_sender_constraint(&self, resource: &str, tenant: &RecipientTenant) -> bool;
    /// Whether `client_id` is registered in `tenant`, for tenant-scoped client IDs (draft §6.2). Default: true.
    fn client_belongs_to_tenant(&self, client_id: &str, tenant: &RecipientTenant) -> bool;
}
```

`IssuerKeys` is implemented for `HashMap<Issuer, JwkSet>` and `BTreeMap<Issuer, JwkSet>`. `ResourceRegistry` implementations must not normalize resource identifiers.

## 2. Request parsing

```rust
pub struct TokenRequest { /* grant type, assertion, scope, client credentials, DPoP proof, presented cert */ }

impl TokenRequest {
    pub fn parse(
        form_body: &[u8],
        headers: &[(String, String)],
        tls_client_cert: Option<&[u8]>, // DER, already validated by the TLS layer (RFC 8705 §2)
    ) -> Result<Self, TokenError>;

    pub fn grant_type(&self) -> AssertionGrantType;
    /// Extracted, not verified.
    pub fn client_credentials(&self) -> &ClientCredentials;
    pub fn requested_scope(&self) -> Option<&Scope>;
    pub fn has_dpop_proof(&self) -> bool;
    /// The `x5t#S256` of the presented TLS client certificate.
    pub fn certificate_thumbprint(&self) -> Option<&str>;
}
```

- `grant_type` must be `urn:ietf:params:oauth:grant-type:jwt-bearer` or `urn:ietf:params:oauth:grant-type:jwt-dpop`. Anything else gets `unsupported_grant_type`, so the caller can route other grants elsewhere first. A missing `grant_type` gets `invalid_request`.
- Exactly one `assertion`. A missing `assertion` or any repeated parameter gets `invalid_request` (RFC 6749 §3.2).
- `scope` is optional; it is the client's downscoping request. A malformed `scope` gets `invalid_scope`; an empty one counts as absent.
- More than one DPoP header gets `invalid_dpop_proof` (RFC 9449 §4.3, check 1).
- A `tls_client_cert` that is not DER gets `server_error`: the caller's TLS glue is wrong, not the client.

Client credentials are extracted, not verified:

```rust
pub enum ClientCredentials {
    Basic { client_id: String, secret: ClientSecret },
    Post { client_id: String, secret: ClientSecret },
    Assertion { assertion: ClientAssertion },
    TlsClientAuth { client_id: String },
    None { client_id: Option<String> },
}
```

Presenting more than one method gets `invalid_request` (RFC 6749 §2.3). `TlsClientAuth` is reported when the request has a `client_id`, a TLS client certificate, and no other credentials; whether that certificate authenticates the client is the caller's check. `Assertion` carries no `client_id`: the caller reads the claimed one with `client_assertion_issuer_unverified` to look up the client's keys.

## 3. Client authentication

Secrets live in the caller's store, so the caller verifies them and reports the result:

```rust
pub enum ClientIdentity {
    Authenticated { client_id: String, method: ClientAuthMethod },
    Unauthenticated { client_id: Option<String> },
}
```

- `private_key_jwt` verification uses RFC-002 §9 (`verify_client_assertion`) with the client's registered JWK Set. Its `aud` must be this AS's `issuer`.
- If client authentication fails, the caller returns `invalid_client` itself without reaching §4: `TokenError::invalid_client()`, or `TokenError::invalid_client_for(&credentials)`, which adds the Basic challenge of §7.
- `Unauthenticated` continues into §4 only if `allow_unauthenticated_sender_constrained` is set; otherwise `validate` returns `invalid_client` before rule 1. The ID-JAG must then carry `cnf` (rule 11).

## 4. ID-JAG validation

```rust
impl ResourceAs {
    pub fn new(config: ResourceAsConfig) -> Result<Self, Error>;
    pub fn config(&self) -> &ResourceAsConfig;

    pub async fn validate(
        &self,
        request: &TokenRequest,
        client: &ClientIdentity,
        keys: &dyn IssuerKeys,
        resources: &dyn ResourceRegistry,
        replay: Option<&dyn ReplayStore>,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<VerifiedGrant, TokenError>;
}
```

Rules are checked in this order. The first failure ends validation. Every rule maps to one `RejectReason` variant for logs and one OAuth error code for the wire.

| # | Rule | Error | Source |
| --- | --- | --- | --- |
| 1 | For `jwt-dpop`, the DPoP proof is present and valid (RFC-007 §3), with `htm=POST` and `htu=token_endpoint`. A proof sent with `jwt-bearer` is validated the same way, because the access token may be bound to its key (draft §9.11.1.2.3). A required nonce that is missing or stale gets `use_dpop_nonce`. | `invalid_dpop_proof` / `use_dpop_nonce` | jwt-dpop-grant §5 step 1 |
| 2 | The assertion parses as a compact JWS within limits (RFC-002 §2). | `invalid_grant` | RFC 7521 §5.2 |
| 3 | Header `typ` is `oauth-id-jag+jwt`. | `invalid_grant` | draft §4.4.1, RFC 8725 §3.11 |
| 4 | The unverified `iss` names a `TrustedIssuer`. It is used only to pick keys and is re-checked after rule 6. | `invalid_grant` | draft §4.4.1 |
| 5 | `iss` is not this server's `issuer`, unless `allow_self_issued`. | `invalid_grant` | draft §9.4 |
| 6 | The signature verifies with that issuer's keys (from `IssuerKeys`) and `AlgorithmPolicy`. An unknown `kid` surfaces as `RejectReason::UnknownKeyId`, so the caller can refresh the JWKS and retry once. An issuer with no cached key set is `RejectReason::NoKeysForIssuer`. | `invalid_grant` | draft §4.4.1, RFC 7521 §5.2 |
| 7 | Claims deserialize and the required claims are present (RFC-002 §6). | `invalid_grant` | draft §3.1 |
| 8 | `aud` is exactly `issuer`, either as a string or as a one-element array. A token-endpoint `aud`, which identity-chaining §2.4.2 allows, is rejected: this profile requires the issuer identifier. | `invalid_grant` | draft §4.4.1 |
| 9 | Time: `exp > now - skew`; `iat ≤ now + skew`; `nbf ≤ now + skew` if present; `exp - iat ≤ max_id_jag_lifetime`. | `invalid_grant` | RFC 7523 §3, draft §4.4.4 |
| 10 | Tenancy. For `Single`, the recipient tenant is configured. For `Multi`, `tenant` must be present and the resolver must return `Trusted`; `Untrusted` and `Ambiguous` reject. | `invalid_grant` | draft §4.4.1, §6.1 |
| 11 | Client binding. If `Authenticated`, the `client_id` claim equals the authenticated client_id. If `Unauthenticated`, `cnf` must be present; otherwise the request fails with `invalid_client`. A `client_id` the unauthenticated request claimed must not contradict the claim. In both cases `ResourceRegistry::client_belongs_to_tenant` must hold for the claim's `client_id` and the recipient tenant, which covers tenant-scoped client IDs. | `invalid_grant` / `invalid_client` | draft §4.4, §4.4.1, §6.2 |
| 12 | Sender constraint (RFC-007 §4). `cnf.jkt` requires `grant_type=jwt-dpop` and a proof whose JWK thumbprint matches. With `jwt-bearer` it is rejected even when a DPoP header is present. `cnf.x5t#S256` requires a TLS client certificate whose SHA-256 thumbprint matches. An unsupported `cnf` member rejects. `jwt-dpop` without `cnf.jkt` rejects. An unbound ID-JAG under `jwt-bearer` is accepted; a proof or certificate presented with it becomes the access token's binding, per `binding_preference` when both are present. | `invalid_grant` | draft §9.11, §9.11.1.2.1–2, §9.11.2.2; jwt-dpop-grant §5 step 3, §5.2 |
| 13 | `sub_id`, if present: the format is supported. Only `saml-nameid` is; `email`, `iss_sub`, `opaque`, and any other format reject. For `saml-nameid`, `sub_id.issuer` must appear in this issuer's `saml_issuers`; `sub_id.issuer` never establishes trust by itself. A malformed `sub_id`, including one with the transient NameID format, rejects. If the issuer has `require_saml_subject`, a missing `sub_id` rejects too. | `invalid_grant` | draft §3.2.2, §9.8 |
| 14 | `resource`: every identifier passes `ResourceRegistry::governs` for the recipient tenant, compared by simple string comparison. A missing claim rejects only when `require_resource_claim` is set. | `invalid_grant` | draft §4.4.1 |
| 15 | `authorization_details`, if present, parses as an RFC 9396 array (RFC-002 §6). | `invalid_grant` | draft §4.4.1 |
| 16 | Replay, last (§8): the DPoP proof's `jti` when a `ReplayStore` is given, then the ID-JAG's `jti` under `JtiPolicy::SingleUse`. | `invalid_dpop_proof` / `invalid_grant` | RFC 7523 §3, draft §4.4.4, jwt-dpop-grant §5.1 |

The xaa.dev "bring your own auth server" guide lists `typ`, `iss`, signature, `iat`/`exp`, `client_id`, `aud`, subject. This order covers all of those and moves `aud` ahead of the cheaper checks it depends on. Running replay last means a request rejected for a DPoP nonce (rule 1) or any later rule never burns either `jti`.

Three preconditions are checked before rule 1 and are not rules about the ID-JAG: `JtiPolicy::SingleUse` without a `ReplayStore` (`server_error`, §8), an `Unauthenticated` client when `allow_unauthenticated_sender_constrained` is off (`invalid_client`, §3), and a `now` ± `clock_skew` that is not a representable time (`server_error`).

## 5. The verified grant

```rust
pub struct VerifiedGrant {
    /* the Verified<IdJagClaims> from RFC-002, plus: */
    recipient_tenant: RecipientTenant,
    client: ClientIdentity,
    binding: Option<ProvenBinding>, // Dpop { jkt } | Mtls { x5t_s256 }
    requested_scope: Option<Scope>, // the request's `scope` parameter
    saml_subject_key: Option<SamlSubjectKeyValue>,
}

/// The binding the request proved. The same type as the access token binding (RFC-007 §4.3).
pub type ProvenBinding = AccessTokenBinding;

impl VerifiedGrant {
    pub fn claims(&self) -> &IdJagClaims;
    pub fn header(&self) -> &JoseHeader;
    pub fn recipient_tenant(&self) -> &RecipientTenant;
    pub fn client(&self) -> &ClientIdentity;
    pub fn binding(&self) -> Option<&ProvenBinding>;
    pub fn requested_scope(&self) -> Option<&Scope>;
    /// The local subject key for SAML-based resolution, built from the members in `SamlIssuerTrust::subject_key` (draft §3.2.2). `None` if the ID-JAG has no `sub_id`.
    pub fn saml_subject_key(&self) -> Option<&SamlSubjectKeyValue>;
    /// `email` and `aud_sub`, marked as hints (draft §9.8).
    pub fn subject_hints(&self) -> UnverifiedSubjectHints<'_>;
    /// `resources` is the registry that was passed to `validate`.
    pub fn decide<'a>(&'a self, resources: &'a dyn ResourceRegistry) -> GrantDecisionBuilder<'a>;
}

/// Members outside the `SamlSubjectKey` selection are `None`.
pub struct SamlSubjectKeyValue {
    pub saml_issuer: String,
    pub nameid: String,
    pub nameid_format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
}

pub struct UnverifiedSubjectHints<'a> {
    pub email: Option<&'a str>,
    pub aud_sub: Option<&'a str>,
}
```

Subject resolution and just-in-time provisioning (draft §2.2) belong to the caller:

- Use `iss` + `sub` for single-tenant issuers, and `iss` + `tenant` + `sub` for multi-tenant ones (draft §3.1, §6.3).
- A single-tenant issuer's recipient tenant comes from the trust relationship. If the ID-JAG also carries `aud_tenant`, it must equal `TrustedIssuer::aud_tenant`, or the grant is for another tenant and is rejected with `RejectReason::UntrustedTenant` (draft §6.1). The default `None` rejects every ID-JAG with `aud_tenant` from that issuer.
- Or use `saml_subject_key()`.
- `email` and `aud_sub` should be trusted only when the caller trusts the issuer tenant as authoritative for them (draft §9.8).
- `VerifiedGrant::subject_hints()` returns those claims tagged with that caveat, so they aren't mistaken for verified identifiers.
- Subjects are resolved only within `recipient_tenant()` (draft §4.4.1 MUST).

## 6. Authorization decision

Draft §4.4.1 leaves *what* to grant to local policy, but fixes some invariants on it. The builder enforces them, so a policy bug can't widen access beyond the grant:

```rust
impl GrantDecisionBuilder<'_> {
    pub fn resources(self, granted: Vec<String>) -> Self;
    pub fn scope(self, granted: Scope) -> Self;
    pub fn authorization_details(self, granted: AuthorizationDetails) -> Self;
    pub fn build(self) -> Result<GrantDecision, TokenError>;
    pub fn deny(self) -> TokenError; // access_denied
}
```

| Invariant | On violation | Source |
| --- | --- | --- |
| If `resource` is present, granted resources ⊆ the claim's resources | `Error::GrantExceedsIdJag` (a programming error) | draft §4.4.1 MUST |
| If `resource` is present and `resources` is called with an empty list | `access_denied` | draft §4.4.1 |
| If `resource` is absent, any default resources must pass `ResourceRegistry::governs` | `Error::GrantExceedsIdJag` | draft §4.4.1 |
| Granted scope ⊆ the ID-JAG `scope` ∩ the request's `scope` (when present). An ID-JAG without `scope` admits no granted scope. | `Error::GrantExceedsIdJag` | draft §4.4.1, RFC 7521 §4.1 |
| Granted `authorization_details` are objects taken unchanged from the ID-JAG's `authorization_details` | `Error::GrantExceedsIdJag` | draft §4.4.1 |
| Each `locations` value of the granted `authorization_details` is in the claim's resources, or passes `ResourceRegistry::governs` if `resource` is absent | `Error::GrantExceedsIdJag` | draft §4.4.1 MUST |
| A granted resource or `locations` value that `requires_sender_constraint`, when there is no `ProvenBinding` | `invalid_grant` | draft §9.11.1.2.4, §9.11.2.2 |

This last invariant depends on which resources are granted, so it runs here, after `validate` has recorded a single-use `jti`. One case is certain earlier: an unbound ID-JAG whose `resource` claim lists only resources that require a sender-constrained token can never be granted. `validate` refuses that case itself (`invalid_grant`, `RejectReason::SenderConstraint`) after rule 14 and before the replay store is touched, so it does not burn the `jti`.

Defaults, when a builder method is not called:

- `resources`: all of the claim's resources, or none if the claim is absent.
- `scope`: no scope is granted.
- `authorization_details`: none are granted.

An `Error::GrantExceedsIdJag` violation is returned as a `TokenError` whose code is `server_error` and whose `reason()` is `RejectReason::GrantExceedsIdJag`; `TokenError::error()` holds the `Error::GrantExceedsIdJag`. Nothing about it reaches the client beyond the 500 response.

How to handle a request `scope` that isn't a subset of the ID-JAG scope is the caller's call. Granting the intersection, as xaa.dev does, and replying `invalid_scope` (`TokenError::invalid_scope()`) both satisfy the builder. `Scope::intersection` computes the first; it returns `None` when nothing is left, because an empty scope is not representable.

## 7. Responses

```rust
impl GrantDecision {
    /// `access_token` is minted by the caller (opaque or RFC 9068), using `binding()` for its `cnf`.
    pub fn token_response(&self, access_token: AccessToken, expires_in: Duration) -> HttpResponse;
    pub fn binding(&self) -> Option<&AccessTokenBinding>;
    /// `DPoP` for a DPoP-bound token, `Bearer` otherwise.
    pub fn token_type(&self) -> &'static str;
    pub fn resources(&self) -> &[String];
    pub fn scope(&self) -> Option<&Scope>;
    pub fn authorization_details(&self) -> Option<&AuthorizationDetails>;
}

impl TokenError {
    /// For the caller, after failed client authentication (§3).
    pub fn invalid_client() -> Self;
    pub fn invalid_client_for(credentials: &ClientCredentials) -> Self;
    /// For the caller, to refuse a request `scope` (§6).
    pub fn invalid_scope() -> Self;

    pub fn code(&self) -> &OAuthErrorCode;
    pub fn reason(&self) -> Option<&RejectReason>; // for logs only; `None` for caller-built errors
    pub fn error(&self) -> Option<&Error>;         // the library error behind it, for logs only
    pub fn to_response(&self) -> HttpResponse;
}
```

`RejectReason` is a `#[non_exhaustive]` enum with one variant per failed rule, for example `WrongTyp`, `UntrustedIssuer`, `AudienceMismatch`, `ClientIdMismatch`, `Replayed`. Sender-constraint failures are `RejectReason::SenderConstraint(BindingRejection)` (RFC-007 §4.2). `TokenError` implements `Display` as the code followed by the reason, and that string is for logs.

Token response (draft §4.4.2, RFC 6749 §5.1):

- `token_type` is `DPoP` when `binding()` is `AccessTokenBinding::Dpop` (draft §9.11.1.2.1 SHOULD), and `Bearer` otherwise, including for a certificate-bound token (RFC 8705 §3).
- `scope` and `authorization_details` are always included when granted (draft §4.4.1 MUST).
- No `refresh_token`. Draft §4.4.4 and identity-chaining §5.4 say SHOULD NOT, and the API has no field for one: the ID-JAG replaces it.
- Headers: `Content-Type: application/json`, `Cache-Control: no-store`, `Pragma: no-cache`.

Error responses (RFC 6749 §5.2, draft §4.4.3):

- The body is `{"error", "error_description"}`.
- `error_description` is a fixed per-code string. The detailed `RejectReason` is for the caller's logs only, because draft §10 says error descriptions SHOULD NOT disclose more about the End-User than the code conveys.
- `invalid_client` after a failed `Basic` attempt (`TokenError::invalid_client_for`) is 401 with `WWW-Authenticate: Basic` (RFC 6749 §5.2). `server_error` is 500. Everything else is 400.
- `use_dpop_nonce` carries a `DPoP-Nonce` header (RFC 9449 §8).

## 8. Re-presentation and replay

Draft §4.4.4 lets clients present the same ID-JAG again to get a new access token. It also lets the Resource AS refuse that and accept each ID-JAG only once. Both are legitimate, so the choice is explicit:

```rust
pub enum JtiPolicy {
    /// Accept each ID-JAG once. Uses `ReplayStore` with `ReplayNamespace::IdJag { issuer }`, expiry = `exp + clock_skew`.
    SingleUse,
    /// Accept re-presentation until `exp`. `max_id_jag_lifetime` bounds the window.
    AllowReuse,
}
```

- The `ReplayStore` is a per-call argument of `validate`, so `SingleUse` without one cannot be caught at construction. Every such request fails with `server_error` (`RejectReason::ReplayStoreMissing`) before the ID-JAG is read.
- When a `ReplayStore` is given, a validated DPoP proof's `jti` is recorded too, under either policy (RFC-007 §3). The proof's `jti` goes first and the ID-JAG's second, so a replayed proof (`invalid_dpop_proof`, `RejectReason::DpopProofReplayed`) does not burn the grant.
- A replayed ID-JAG is `invalid_grant` (`RejectReason::Replayed`).
- A `ReplayStore` error fails closed with `RejectReason::ReplayStoreUnavailable` and `server_error`, for the ID-JAG's `jti` and for the proof's. It is a server fault, so the client may retry with the same grant.

## 9. Cross-domain rules (§9.4)

- `allow_self_issued = false` rejects ID-JAGs that this same server issued. Draft §9.4: the IdP "MUST NOT issue access tokens in response to an ID-JAG it issued itself unless explicitly configured to do so".
- A deployment that runs `idp` and `resource-as` in one process, across a tenant boundary, sets `allow_self_issued` and uses `Tenancy::Multi` so the trust domain crossing still applies.
- Reuse of one ID-JAG at a different downstream AS fails rule 8. The component never forwards grants.
- With `allow_self_issued`, the caller's policy MUST NOT grant more than it would grant when issuing an access token for the same subject and resource directly (draft §9.4). The decision builder can't know that ceiling, so it is the caller's.

## 10. Metadata

The Resource AS advertises the profile in its RFC 8414 metadata (RFC-006 §2). `ResourceAs::metadata()` returns a `ResourceAsMetadataBuilder` filled in from the configuration: issuer, token endpoint, the `jwt-dpop` grant, and `dpop_algorithms`.

- `authorization_grant_profiles_supported` containing `urn:ietf:params:oauth:grant-profile:id-jag`, which requires `grant_types_supported` to contain `urn:ietf:params:oauth:grant-type:jwt-bearer` (draft §7.2). The emitter enforces both.
- `urn:ietf:params:oauth:grant-type:jwt-dpop` in `grant_types_supported` (jwt-dpop-grant §5.2). `validate` always accepts DPoP-bound grants, so `metadata()` always advertises it.
- Never the trusted-issuer list. Draft §9.7 says MUST NOT disclose issuer allow-lists there, and the emitter has no input for them.

The protected per-client discovery mechanism that draft §9.7 allows (MAY) is out of scope for v0.1.

## 11. Example

```rust
async fn token(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    let request = match TokenRequest::parse(&body, &headers_vec(&headers), None) {
        Ok(r) => r,
        Err(e) => return e.to_response().into(),
    };
    let client = match app.authenticate(request.client_credentials()).await {
        Some(c) => c,
        None => return TokenError::invalid_client_for(request.client_credentials()).to_response().into(),
    };
    let grant = match app.ras.validate(
        &request, &client, &app.jwks, &app.resources, Some(&app.replay),
        SystemTime::now(), Duration::from_secs(30),
    ).await {
        Ok(g) => g,
        Err(e) => { log_reject(e.reason()); return e.to_response().into(); }
    };
    let account = match app.resolve_subject(&grant).await {
        Some(a) => a,
        None => return grant.decide(&app.resources).deny().to_response().into(),
    };
    let decision = match grant.decide(&app.resources).scope(app.policy_scope(&account, &grant)).build() {
        Ok(d) => d,
        Err(e) => return e.to_response().into(),
    };
    let token = app.mint_access_token(&account, &decision).await;
    decision.token_response(token, Duration::from_hours(2)).into()
}
```

## 12. Security checks summary

| Threat | Defense | Rule |
| --- | --- | --- |
| Forged grant | Signature verified against a trusted issuer's keys with a per-issuer algorithm allow-list | 4, 6 |
| Token-type confusion | Required `typ` | 3 |
| Audience injection or a grant meant for another AS | Exact `aud` = own issuer, single value | 8 |
| Stale or long-lived grants | `exp`, `iat`, `nbf`, maximum lifetime | 9 |
| Cross-tenant confusion | Tenant trust resolution, subject scoped to the recipient tenant | 10 |
| Client substitution | `client_id` claim bound to the authenticated client | 11 |
| Bound grant downgraded to bearer | `cnf.jkt` rejected under `jwt-bearer`; required proof | 12 |
| `sub_id` used to bootstrap trust | `sub_id.issuer` must be pre-associated with the validated `iss` | 13 |
| Grant for resources this AS doesn't govern (the §9.5 relay attack) | `ResourceRegistry::governs` | 14 |
| Replay | Atomic `jti` store, consulted last; explicit policy; fails closed without a store | 16, §8 |
| Self-issued privilege broadening | `allow_self_issued` off by default | 5 |
| Policy bug widening access | Decision builder invariants | §6 |
| Information leak in errors | Generic `error_description` | §7 |

## 13. Tests

- **One negative test per rule** in §4, asserting both the wire code and the `RejectReason`.
- **Ordering:**
  - A request with a valid ID-JAG and a stale DPoP nonce consumes neither `jti`. A retry with the right nonce succeeds.
  - A forged ID-JAG never reaches the replay store, and neither does a request that fails a late rule.
  - A request that breaks two rules reports the earlier one in the §4 table.
  - A replayed DPoP proof is rejected without recording the fresh ID-JAG's `jti`.
- **Invariants:** a property test that `GrantDecisionBuilder` never yields resources or scopes outside the ID-JAG, for arbitrary policy inputs.
- **Draft examples:** claim sets in the shape of the draft §4.3.4 examples, unbound and with `cnf.jkt`, signed by a test IdP key, pass validation. Each one-claim mutation of them fails.
- **Flow tests:** `tests/flow_test.rs`, against tokens issued by the `idp` component.
- **Playground:** register `examples/resource-as` as an "Own" auth server at xaa.dev and validate the playground IdP's ID-JAGs (RFC-001 §9). This has not been run yet.

## 14. Spec coverage

| Section | Covered by |
| --- | --- |
| §3 RS256 MTI / ES256 SHOULD (Resource AS side) | §1 (`AlgorithmPolicy` default), RFC-002 §3 |
| §3.2.2 Subject Identifier Processing (Resource AS side) | §4 rule 13, §5 |
| §4.1 trust configuration per issuer | §1 |
| §4.4 Access Token Request, client authentication | §2, §3, §4 rule 11 |
| §4.4.1 Processing Rules | §4, §6 |
| §4.4.2 Response | §7 |
| §4.4.3 Error Response | §7 |
| §4.4.4 Refresh Token (no refresh token, re-presentation, `jti`) | §7, §8 |
| §5.2 subject identifier consistency (consumer side) | §5 |
| §6.1–§6.3 tenancy | §1, §4 rules 10–11, §5 |
| §7.2 Resource AS Metadata | §10, RFC-006 §2 |
| §9.1 Client Authentication | §3, §4 rule 11 |
| §9.4 Cross-Domain Use | §9 |
| §9.5 relay mitigation (Resource AS side) | §4 rule 14 |
| §9.7 Metadata Disclosure | §10 |
| §9.8 Subject Identifier Trust | §4 rule 13, §5 |
| §9.11 Sender Constraining (Resource AS side) | §4 rule 12, §6, §7, RFC-007 §4 |
| §10 Privacy (errors, retained attributes) | §7; attribute retention is the caller's |
| identity-chaining §2.4.2, §5.4, §5.5 | §4, §7, §8 |
| jwt-dpop-grant §5, §5.1, §5.2, §6 | §4 rules 1, 12, 16; §7 |
