# RFC-005: IdP Authorization Server

**Status**: Draft
**Date**: 2026-11-14

## Summary

This RFC defines the `idp` component: the token-exchange endpoint an IdP Authorization Server uses to issue ID-JAGs (draft §4.3) and, optionally, to exchange SAML assertions for Refresh Tokens (draft §4.5). It parses the request, enforces the §4.3.3 processing rules that can be enforced mechanically, delegates subject-token verification and access policy to the caller, signs the ID-JAG, and serializes the response.

The component is off by default. It exists for three reasons:
- Real IdPs that want to add XAA.
- Proving the `client` and `resource-as` components against each other without third-party software (RFC-001 §9).
- `examples/idp`.

It is not an OpenID Provider. Login, ID Token issuance, refresh-token minting, and session management stay with the caller.

---

## 1. Configuration

```rust
pub struct IdpConfig {
    /// RFC 8414 issuer identifier. Becomes the ID-JAG `iss`.
    pub issuer: Issuer,
    /// Token endpoint URL, checked against the DPoP proof's `htu`.
    pub token_endpoint: Url,
    /// Signs ID-JAGs. Its public key must be published at `jwks_uri` (draft §7.1).
    pub signer: Arc<dyn JwsSigner>,
    /// ID-JAG lifetime. Default 5 minutes; draft §9.2 asks for short-lived grants.
    pub id_jag_lifetime: Duration,
    pub tenancy: IdpTenancy, // Single | Multi
    /// Accept DPoP proofs on token exchange and bind ID-JAGs to them (draft §9.11.1.1).
    pub dpop: bool,
    /// What to do with a valid proof for a Resource AS without `jwt-dpop` (§6.1). Default `Reject`.
    pub dpop_to_non_supporting_as: DpopToNonSupportingAs,
    /// Bind ID-JAGs to the client's TLS certificate when one is presented (draft §9.11.2.1).
    pub mtls_binding: bool,
    /// `typ` values other than absent or "JWT" that this IdP puts on its own ID Tokens (§4.2).
    pub id_token_typ_allow: Vec<String>,
    /// Enable the §4.5 SAML → Refresh Token exchange. Requires `saml_audiences`.
    pub saml_refresh_exchange: bool,
    /// Tolerance for the DPoP proof's `iat` window (RFC-001 §8). Default 60 seconds.
    pub clock_skew: Duration,
    /// DPoP proof algorithms accepted. Default `default_dpop_algorithms()`.
    pub dpop_algorithms: AlgorithmPolicy,
    /// How old a DPoP proof's `iat` may be. Default `DEFAULT_MAX_AGE`.
    pub dpop_max_age: Duration,
    /// Set to require a server nonce in every DPoP proof (RFC 9449 §8).
    pub dpop_nonce: Option<Arc<dyn DpopNonce>>,
    /// Set to reject a replayed DPoP proof `jti` (RFC 9449 §11.1).
    pub replay: Option<Arc<dyn ReplayStore>>,
    /// Maps a SAML `Audience` to the client it was issued to (§4.2). Without one every `saml2` subject token is refused.
    pub saml_audiences: Option<Arc<dyn SamlAudienceMap>>,
}

impl IdpConfig {
    /// The defaults: 5-minute single-tenant bearer ID-JAGs, no DPoP or mTLS binding, no SAML exchange.
    pub fn new(issuer: Issuer, token_endpoint: Url, signer: Arc<dyn JwsSigner>) -> Self;
}

impl Idp {
    pub fn new(config: IdpConfig) -> Result<Self, Error>;
    pub fn config(&self) -> &IdpConfig;
}
```

`Idp::new` fails with `Error::InvalidConfiguration` for a zero `id_jag_lifetime`, for `saml_refresh_exchange` without `saml_audiences`, and for an `id_token_typ_allow` entry that names another token type (`oauth-id-jag+jwt`, `at+jwt`, `dpop+jwt`).

Caller-provided lookups:

```rust
/// The Resource Authorization Servers this IdP has trust relationships with.
pub trait ResourceAsDirectory: Send + Sync {
    /// Resolve an `audience` (an issuer identifier, or an alias such as a URN) to a Resource AS (draft §4.3).
    fn resolve_audience(&self, audience: &str, issuer_tenant: Option<&str>) -> Option<ResourceAsEntry>;
    /// Whether `resource` is governed by `ras` (draft §4.3.3). Out of band per the draft.
    fn governs(&self, ras: &ResourceAsEntry, resource: &str) -> bool;
}

pub struct ResourceAsEntry {
    /// Canonical issuer identifier. Always what goes into `aud`.
    pub issuer: Issuer,
    pub require_resource: bool,
    /// Whether this Resource AS advertises or is configured for the `jwt-dpop` grant. Default false (§6.1).
    pub supports_jwt_dpop: bool,
    /// Whether this Resource AS resolves subjects by SAML NameID (draft §3.2.2, §9.9).
    pub wants_saml_sub_id: bool,
    pub binding_preference: BindingPreference, // Dpop (default) | Mtls; used when both are possible (draft §9.11)
}

impl ResourceAsEntry {
    /// Resources optional, no `jwt-dpop`, no `sub_id`.
    pub fn new(issuer: Issuer) -> Self;
}
```

## 2. Request parsing

```rust
pub struct TokenExchangeRequest { /* … */ }

impl TokenExchangeRequest {
    pub fn parse(
        form_body: &[u8],
        headers: &[(String, String)],
        tls_client_cert: Option<&[u8]>,
    ) -> Result<Self, ExchangeError>;

    pub fn requested_token_type(&self) -> RequestedTokenType; // IdJag | RefreshToken
    pub fn audience(&self) -> Option<&str>;
    pub fn resources(&self) -> &[String];
    pub fn scope(&self) -> Option<&Scope>;
    pub fn subject_token(&self) -> SubjectTokenInput<'_>;
    pub fn subject_token_type(&self) -> SubjectTokenType; // IdToken | Saml2 | RefreshToken
    pub fn authorization_details(&self) -> Option<&AuthorizationDetails>;
    pub fn has_actor_token(&self) -> bool;
    pub fn client_credentials(&self) -> &ClientCredentials;
    pub fn has_dpop_proof(&self) -> bool;
    pub fn certificate_thumbprint(&self) -> Option<&str>;
    /// `invalid_client` for this request, with the 401 challenge after `Basic` (§9).
    pub fn invalid_client(&self) -> ExchangeError;
}
```

`tls_client_cert` is the client certificate in DER, already validated by the TLS layer (RFC 8705 §2). `requested_token_type()` decides which `Idp` method handles the request: `exchange` (§3–§7) or `exchange_saml_for_refresh_token` (§8).

| Condition | Error | Source |
| --- | --- | --- |
| `grant_type` ≠ `urn:ietf:params:oauth:grant-type:token-exchange` | `unsupported_grant_type` | RFC 8693 §2.1 |
| `requested_token_type` is missing, or is neither `…:id-jag` nor `…:refresh_token` | `invalid_request` | draft §4.3, §4.5 |
| `audience` missing (for `id-jag`) | `invalid_request` | draft §4.3 REQUIRED |
| More than one `audience` | `invalid_request` | draft §4.3.3 MUST |
| `subject_token` or `subject_token_type` missing | `invalid_request` | draft §4.3 |
| `subject_token_type` not one of `id_token`, `saml2`, `refresh_token` | `invalid_request` | draft §4.3 |
| `actor_token` without `actor_token_type`, or the reverse | `invalid_request` | RFC 8693 §2.1 |
| `authorization_details` isn't a JSON array of objects with a string `type` | `invalid_request` | draft §4.3.3, RFC 9396 §2 |
| A non-repeatable parameter repeated | `invalid_request` | RFC 6749 §3.2 |
| More than one client authentication method | `invalid_request` | RFC 6749 §2.3 |
| `scope` isn't a list of scope tokens | `invalid_scope` | RFC 6749 §3.3 |
| Client credentials present but unusable | `invalid_client` | RFC 6749 §5.2 |
| `tls_client_cert` isn't DER | `server_error` (a caller bug) | RFC 8705 §2 |

Parsing takes no configuration. A `…:refresh_token` request with `saml_refresh_exchange` off is refused with `invalid_request` by the `Idp` methods.

`resource` may repeat (RFC 8707 §2). The values are kept in order and byte-for-byte. A parameter sent without a value counts as absent (RFC 6749 §3.2), and an exact repeat of an earlier value is dropped.

A `saml2` `subject_token` is accepted in either encoding: base64url (RFC 8693 §3) or standard base64 (the draft §4.5 example), each with or without padding. The alphabets differ only in `-_` versus `+/`, so the decoder picks one by the characters present. A token that mixes characters from both, or decodes to nothing, fails with `invalid_request`. The decoded bytes go to `SubjectTokenVerifier`, which does the signature check.

## 3. Client authentication

The IdP MUST authenticate the client and MUST reject unauthenticated requests with `invalid_client` (draft §4.3.3).

- Credentials are extracted and verified as in RFC-004 §2–§3: `TokenExchangeRequest::client_credentials()` returns the `ClientCredentials`, the caller verifies them and passes the result to `Idp::exchange` as a `ClientIdentity`.
- `ClientIdentity::Unauthenticated` always produces `invalid_client`. Unlike the Resource AS, there is no sender-constrained exception.
- A caller whose verification fails can answer directly with `TokenExchangeRequest::invalid_client()`.

## 4. Subject token verification

### 4.1 The caller verifies

The IdP issued the subject token itself, so the draft lets it identify and validate that token by deployment-specific means (§4.3.3): a marker claim, a dedicated key, or an issuance record. That is the caller's:

```rust
pub trait SubjectTokenVerifier: Send + Sync {
    fn verify(
        &self,
        token: &SubjectTokenInput<'_>, // IdToken | Saml2 | RefreshToken
        client: &AuthenticatedClient,
        now: SystemTime,
    ) -> impl Future<Output = Result<VerifiedSubject, SubjectRejection>> + Send;
}

pub struct VerifiedSubject {
    /// The caller's handle for the End-User.
    pub subject: SubjectRef,
    /// ID Token `aud`, or the client a Refresh Token is bound to (OAuth client_id).
    pub issued_to_client: Option<String>,
    /// For SAML assertions: the AudienceRestriction value (SP entity ID).
    pub saml_audience: Option<String>,
    /// The End-User's tenant at this issuer (draft §6.4).
    pub issuer_tenant: Option<String>,
    pub auth_time: Option<NumericDate>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
}

impl VerifiedSubject {
    /// A subject with nothing else set.
    pub fn new(subject: SubjectRef) -> Self;
}

/// The client that authenticated to the token endpoint (§3).
pub struct AuthenticatedClient {
    pub client_id: String,
    pub method: ClientAuthMethod,
}

pub enum SubjectRejection {
    Invalid,                                        // invalid_request
    StepUpRequired { max_age: Option<u64>, acr_values: Option<String> }, // insufficient_user_authentication
}
```

Two verifiers cover the common cases so that callers don't hand-roll them: §4.3 for ID Tokens and §4.4 for SAML assertions.

### 4.2 The library enforces

Whatever the verifier says, these checks run:

| Check | Error | Source |
| --- | --- | --- |
| A JWT `subject_token` whose header `typ` is present and is neither `JWT` nor in `id_token_typ_allow`. This rejects `at+jwt`, `oauth-id-jag+jwt`, `dpop+jwt`, and every other explicit type. | `invalid_request` | draft §4.3.3 MUST |
| Identity Assertion (`id_token`): `issued_to_client` equals the authenticated client_id | `invalid_request` | draft §4.3.3 MUST |
| Refresh Token: `issued_to_client` equals the authenticated client_id | `invalid_request` | draft §4.3.3 |
| SAML assertion: `saml_audience` maps to the authenticated client_id through `IdpConfig::saml_audiences`. Fails closed when either is `None`. | `invalid_request` | draft §4.5 MUST |
| Multi-tenant issuer and `issuer_tenant` is `None` | `server_error`, with `Error::InvalidConfiguration` as the `library_error()` (a caller bug) | draft §6.1 MUST |

The `typ` rule is an allow-list, which is stricter than the draft's "reject a type that identifies a different token". ID Tokens carry no defined `typ`, so anything explicit is suspect unless this IdP is known to set it. It applies to `id_token` subject tokens and to `refresh_token` subject tokens that parse as a JWS. `typ` values are compared case-insensitively, with an `application/` prefix dropped (RFC 7515 §4.1.9).

```rust
/// Maps a SAML `Audience` (SP entity ID) to the OAuth client it belongs to.
pub trait SamlAudienceMap: Send + Sync {
    fn maps_to_client(&self, saml_audience: &str, client_id: &str) -> bool;
}
```

`HashMap<String, String>` and `BTreeMap<String, String>` (SP entity ID → client_id) implement it.

### 4.3 Built-in ID Token verifier

An ID Token is a JWT the IdP signed itself, and RFC-002 already has everything needed to check one. `IdTokenVerifier` implements the `id_token` arm of `SubjectTokenVerifier`; `saml2` and `refresh_token` subject tokens are passed to a fallback verifier. The default fallback, `RejectOtherSubjectTokens`, accepts nothing; `with_fallback` replaces it.

It is configured with the IdP's own issuer, its own public keys (current and retired, as a `JwkSet`), an `AlgorithmPolicy`, a clock skew, and a caller function that maps the verified claims to a `SubjectRef` and issuer tenant:

```rust
impl<M> IdTokenVerifier<M>
where
    M: Fn(&IdTokenClaims) -> Option<IdTokenSubject> + Send + Sync,
{
    pub fn new(
        issuer: Issuer,
        keys: JwkSet,
        algorithms: AlgorithmPolicy,
        clock_skew: Duration,
        map_subject: M,
    ) -> Self;
}

impl<M, V> IdTokenVerifier<M, V> {
    pub fn with_fallback<W: SubjectTokenVerifier>(self, fallback: W) -> IdTokenVerifier<M, W>;
}

pub struct IdTokenClaims {
    pub sub: String,
    /// The sole `aud`, or `azp`.
    pub issued_to_client: String,
    /// Every claim of the token.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

pub struct IdTokenSubject {
    pub subject: SubjectRef,
    pub issuer_tenant: Option<String>,
}
```

It checks:

| Check | Failure |
| --- | --- |
| The token is a compact JWS that verifies against the IdP's own keys under the algorithm policy (RFC-002 §4, `ExpectedTyp::Any`; the `typ` allow-list of §4.2 has already run) | `SubjectRejection::Invalid` |
| `iss` is this IdP's issuer, byte-for-byte | `SubjectRejection::Invalid` |
| `sub` is a non-empty string | `SubjectRejection::Invalid` |
| `exp` is present and has not passed, and `iat` / `nbf`, when present, are not in the future, within the skew | `SubjectRejection::Invalid` |
| `aud` has one value, or has several and `azp` names one of them (OIDC Core §2) | `SubjectRejection::Invalid` |
| `auth_time`, `acr`, and `amr`, when present, have the OIDC Core §2 types | `SubjectRejection::Invalid` |
| The caller function recognizes the subject (returns `Some`) | `SubjectRejection::Invalid` |

It reports `issued_to_client` as the sole `aud` value, or `azp` when there are several, so the §4.2 client-binding check runs against the party the token was issued to. `auth_time`, `acr`, and `amr` are passed through for step-up decisions (§5).

It does not check `nonce`, `at_hash`, or `c_hash`. Those bind an ID Token to an authentication response, which is the relying party's check at login, not the IdP's at token exchange.

### 4.4 SAML assertions through the `saml` crate

`xaa` has no dependency on `saml`. The two meet behind `SubjectTokenVerifier`:

- **At the IdP.** `saml::IdentityProvider::verify_issued_assertion` (`saml` 0.1.0-alpha.3) verifies a standalone assertion the IdP issued to a given SP: its own signature, issuer, audience, `Recipient`, and time windows. A caller wraps it as a `SubjectTokenVerifier`: it finds the `SpDescriptor` for the authenticated client through the client_id ↔ SP entity ID mapping, verifies, and returns the NameID as the subject with `saml_audience` set to the SP entity ID. `examples/idp` takes ID Tokens only.
- **At the client.** `saml::ServiceProvider::consume_response_with_assertion` returns the verified assertion as a standalone signed document, which is what `SubjectToken::SamlAssertion` carries (RFC-003 §2).

Two limits come from SAML itself and are the caller's to plan for:

- The assertion must carry its own signature. An IdP that only signs the Response cannot support this path.
- A bearer assertion's `SubjectConfirmationData` window is typically a few minutes, so the client exchanges it right after sign-on.

`tests/saml_flow_test.rs` runs the whole path with `saml` as a dev-dependency (RFC-001 §9): the assertion as a subject token in both `saml2` encodings, the draft §4.5 exchange for a refresh token, an expired assertion, an assertion issued to another SP, and the `saml-nameid` claim reaching the Resource AS. Its `SamlSubjects` type is the adapter to copy.

## 5. Audience, resource, scope

### 5.1 Audience

- `ResourceAsDirectory::resolve_audience` returning `None` gives `invalid_target` (draft §4.3.3 MUST).
- Issuer identifiers MUST be supported (draft §4.3). Aliases are whatever the directory resolves.
- The ID-JAG `aud` is always the entry's canonical `issuer` as a single string, never the alias. identity-chaining §2.3.3 recommends a single audience.

### 5.2 Policy

```rust
pub trait ExchangePolicy: Send + Sync {
    fn evaluate(
        &self,
        ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send;
}

pub struct ExchangeContext<'a> {
    pub client: &'a AuthenticatedClient,
    pub subject: &'a VerifiedSubject,
    pub subject_token_type: SubjectTokenType,
    /// The `audience` as requested (possibly an alias).
    pub audience: &'a str,
    pub resource_as: &'a ResourceAsEntry,
    /// The requested resources. Each is governed by the Resource AS.
    pub resources: &'a [String],
    pub scope: Option<&'a Scope>,
    pub authorization_details: Option<&'a AuthorizationDetails>,
    pub now: SystemTime,
}

pub struct ExchangeGrant {
    /// The client's client_id *at the Resource AS* (draft §3.1, §5.1). No default.
    pub client_id: String,
    /// The End-User's identifier *for this Resource AS* (draft §5.2). No default.
    pub sub: String,
    pub resources: Vec<String>,
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub aud_tenant: Option<String>,
    pub aud_sub: Option<String>,
    pub email: Option<String>,
    pub sub_id: Option<SamlNameIdMapping>,
    /// Other ID-Token-style claims (draft §3.1), e.g. a non-NameID SAML subject attribute (draft §3.2.2).
    pub extra_claims: BTreeMap<String, serde_json::Value>,
}

impl ExchangeGrant {
    /// The two required identifiers and nothing else.
    pub fn new(client_id: impl Into<String>, sub: impl Into<String>) -> Self;
}

pub enum ExchangeDenial {
    AccessDenied,                // access_denied (draft §4.3.4.3)
    InvalidTarget,               // invalid_target
    InvalidScope,                // invalid_scope (allowed: "any OAuth error code MAY be returned")
    StepUpRequired { max_age: Option<u64>, acr_values: Option<String> },
}
```

`client_id` and `sub` have no defaults. They must be the values *this Resource AS* knows (draft §5.1, §5.2), which can differ from the requesting client's own client_id and from the `sub` in the ID Token it presented. Making them the two arguments of `ExchangeGrant::new` avoids the easy mistake of copying the ID Token's `sub` into the ID-JAG. `SamlNameIdMapping` is an alias of `claims::SamlNameId`.

Some draft MUSTs depend on data only the caller's directory and policy hold. The library can't check them, so `ExchangePolicy` implementations own them:

- **`sub` stability:** the same `sub` for a given End-User in every ID-JAG for the same Resource AS (and `aud_tenant`), whichever client asks. When the Resource AS does OIDC SSO with this IdP, it is the `sub` the IdP would put in an ID Token for that Resource AS as a Relying Party (draft §5.2).
- **`sub` uniqueness:** unique within `iss` for single-tenant issuers, and within `iss` + `tenant` for multi-tenant ones (draft §3.1, §6.3).
- **`sub` / `sub_id` agreement:** they identify the same End-User (draft §3.1, §3.2.2).
- **`sub_id` derivation:**
  - It comes from the `<NameID>` the IdP would issue to the Resource AS's SAML SP, or from an equivalent configured mapping.
  - Pairwise NameIDs and attributes are scoped to that SP.
  - The IdP keeps the client_id ↔ SP entity ID mapping (draft §3.2.2).
- **`aud_sub` uniqueness:** `aud` + `aud_tenant` + `aud_sub` is unique at the Resource AS (draft §3.1).
- **Client identifier model:** `client_id` follows the Resource AS's model. For tenant-scoped client IDs it is valid within `aud_tenant` (draft §6.2).

### 5.3 Invariants on the grant

Enforced after `evaluate`:

| Invariant | Error | Source |
| --- | --- | --- |
| Every requested resource is governed by the Resource AS | `invalid_target` | draft §4.3.3 SHOULD (always applied here) |
| Resources were requested but none were granted | `invalid_target` | draft §4.3.3 MUST |
| `require_resource` is set and no resource was requested | `invalid_target` | draft §4.3.3, RFC 8707 §2 |
| If resources were requested, granted ⊆ requested, byte-identical | `Error::GrantExceedsRequest` (caller bug) | draft §4.3.3 MUST |
| If none were requested, default resources are governed | `Error::GrantExceedsRequest` | draft §4.3.3 |
| If scope was requested, granted scope ⊆ requested | `Error::GrantExceedsRequest` | draft §4.3.3 |
| If `authorization_details` were requested, granted ⊆ requested | `Error::GrantExceedsRequest` | draft §4.3.3 |
| A `sub_id` NameID format that is transient | `Error::TransientNameId` | draft §3.2.2 MUST NOT |
| A `sub_id` present for a Resource AS without `wants_saml_sub_id` | `Error::UnwantedSubId` | draft §9.9 SHOULD |
| An empty `client_id` or `sub`, or an extra claim that names a claim of §7 or `act` | `Error::InvalidConfiguration` | draft §3.1, §9.10 |

The first three rows are protocol errors. The governance and `require_resource` checks run before `evaluate`, so policy only sees governed resources. The `Error::…` rows are caller bugs: the client gets `server_error`, the `RejectReason` is `GrantInvariantViolated`, and `ExchangeError::library_error()` returns the `Error` that names the invariant.

Scope values mean what the Resource AS defines (draft §4.3). The RFC 6749 §6 refresh-scope comparison is never applied unless the audience is this IdP itself (draft §4.3.3, §9.4).

## 6. Sender constraining

| Situation | Result | Source |
| --- | --- | --- |
| A valid DPoP proof (`htm=POST`, `htu=token_endpoint`, RFC-007 §3), no certificate, `supports_jwt_dpop` true | `cnf.jkt` = the proof key's thumbprint | draft §9.11.1.1 MUST |
| A valid DPoP proof, `supports_jwt_dpop` false | `invalid_target` by default (§6.1) | jwt-dpop-grant §7.1 |
| A certificate presented, `mtls_binding` set, no DPoP proof | `cnf.x5t#S256` = the certificate's thumbprint | draft §9.11.2.1 |
| Both | The entry's `binding_preference` decides. Never both. | draft §9.11 SHOULD NOT |
| An invalid DPoP proof | `invalid_dpop_proof` | RFC 9449 §5 |
| Neither | No `cnf` | draft §9.11.1.1 |

- With `dpop` off, a `DPoP` header is ignored and the ID-JAG is issued without `cnf.jkt`; the client detects the missing binding (RFC-003 §5). With `mtls_binding` off, a presented certificate is ignored.
- A valid proof for a Resource AS without `jwt-dpop` is refused under `Reject` (§6.1) whether or not a certificate is also presented.
- With `dpop_nonce` set, a proof without the current nonce gets `use_dpop_nonce` (RFC 9449 §8).
- With `replay` set, the proof's `jti` is recorded last, just before signing, so a request refused for another reason does not burn the proof (jwt-dpop-grant §5.1). A replayed proof is `invalid_dpop_proof`.
- The decision itself is `IdpBinding::decide()` (RFC-007 §4.1).

### 6.1 A Resource AS without `jwt-dpop`

The draft and jwt-dpop-grant pull in different directions here. Draft §9.11.1.1 says the IdP MUST bind to a valid DPoP proof. jwt-dpop-grant §7.1 says the issuer SHOULD NOT issue a DPoP-bound grant for an AS that doesn't support `jwt-dpop`, because such an AS may ignore `cnf` and accept a stolen grant as a bearer grant.

`IdpConfig::dpop_to_non_supporting_as` decides what happens when a valid proof arrives and the entry's `supports_jwt_dpop` is false. `DpopToNonSupportingAs` and `BindingPreference` are defined in `dpop` and re-exported from `idp`:

```rust
pub enum DpopToNonSupportingAs {
    /// Default. Refuse the exchange with `invalid_target`. Nothing is issued.
    Reject,
    /// Bind anyway (`cnf.jkt`), reading draft §9.11.1.1 literally.
    Bind,
}
```

- **`Reject` (default)** satisfies both texts. The draft's MUST applies to an ID-JAG that is issued, and refusing issues none.
  - The error is `invalid_target`, which RFC 8693 §2.2.2 defines for an IdP "unwilling or unable to issue a token" for the indicated target. Its fixed `error_description` says the audience does not accept DPoP-bound grants.
  - The client maps `invalid_target` to `Remediation::ChangeRequest` (RFC-003 §8): retry without the proof. `invalid_request` would map to "obtain a new subject token" (draft §4.3.4.3), which cannot help.
- **`Bind`** is for deployments that want the literal draft behavior. A conforming Resource AS then rejects the unsupported `cnf` (draft §9.11), and this crate's client refuses to send it (RFC-003 §6).
- **There is no "issue unbound" option.** The client asked for a binding. Dropping it silently is the downgrade that draft §9.11.1.1 tells clients to detect.
- **`supports_jwt_dpop` defaults to false.** Unknown support counts as no support (jwt-dpop-grant §7.1: "unless it knows").
- The `ExchangeRecord` (§10) records the refusal, with `RejectReason::AudienceLacksJwtDpop`.

**Known limitation.** If the subject token is itself DPoP-bound, the client has to send a proof. With a Resource AS that lacks `jwt-dpop`, the exchange is then refused under `Reject`, and the grant is unusable under `Bind`. Neither spec offers a conforming path for this case. It is part of the upstream question in RFC-001 §12.

## 7. Issuance

ID-JAG header: `alg` (from the signer), `typ: oauth-id-jag+jwt`, and `kid` when the signer has a key ID.

Claims:

| Claim | Value |
| --- | --- |
| `iss` | `config.issuer` |
| `sub` | `grant.sub` |
| `aud` | `entry.issuer`, a single string |
| `client_id` | `grant.client_id` |
| `jti` | 128 bits from the OS RNG, base64url |
| `iat` | `now` |
| `exp` | `now + id_jag_lifetime` |
| `resource` | A string for one, an array for several, omitted for none |
| `scope`, `authorization_details` | Granted values, if any (draft §4.3.3 MUST, even when they differ from the request) |
| `tenant` | `issuer_tenant`; required for multi-tenant issuers (draft §6.1) |
| `aud_tenant`, `aud_sub`, `email` | From the grant |
| `auth_time`, `acr`, `amr` | From the verified subject |
| `sub_id` | From the grant's `SamlNameIdMapping`. Optional members are emitted exactly when set (draft §3.2.2). |
| `cnf` | Per §6 |
| Extra claims | From the grant. They may not override any of the above, and may not be `nbf` or `act` (§5.3). |

`act` can't be emitted. The draft defines no processing for `actor_token` (§4.3, §9.10), so the token is accepted and ignored.

## 8. SAML → Refresh Token (§4.5)

With `saml_refresh_exchange` enabled:

- `requested_token_type=…:refresh_token` with `subject_token_type=…:saml2`. Any other subject type on this path gets `invalid_request`.
- The client must be authenticated (§3), and the subject token passes the same verification as in §4.
- The SAML `Audience` → client_id mapping check from §4.2 is mandatory (draft §4.5 MUST). `Idp::new` refuses `saml_refresh_exchange` without `saml_audiences`.
- The caller mints the Refresh Token. The library builds the response: `issued_token_type=urn:ietf:params:oauth:token-type:refresh_token`, the token in `access_token` (RFC 8693 §2.2.1), `token_type=N_A`, and `scope` and `expires_in` when the caller supplies them.
- Requested scope should include `openid offline_access` (draft §4.5 SHOULD). That is the client's job and isn't enforced here.
- A `DPoP` header is ignored: this profile defines no binding for the Refresh Token.

```rust
impl Idp {
    pub async fn exchange_saml_for_refresh_token<S: SubjectTokenVerifier>(
        &self,
        request: &TokenExchangeRequest,
        client: &ClientIdentity,
        subjects: &S,
        now: SystemTime,
    ) -> (Result<SamlRefreshExchange, ExchangeError>, ExchangeRecord);
}

impl SamlRefreshExchange {
    pub fn client(&self) -> &AuthenticatedClient;
    pub fn subject(&self) -> &VerifiedSubject;
    pub fn requested_scope(&self) -> Option<&Scope>;
    pub fn token_response(
        &self,
        refresh_token: &RefreshToken,
        scope: Option<&Scope>,
        expires_in: Option<Duration>,
    ) -> HttpResponse;
}
```

Each exchange method refuses a request whose `requested_token_type` belongs to the other with `invalid_request`.

## 9. Responses

```rust
impl Idp {
    pub async fn exchange<S, D, P>(
        &self,
        request: &TokenExchangeRequest,
        client: &ClientIdentity,
        subjects: &S,
        directory: &D,
        policy: &P,
        now: SystemTime,
    ) -> (Result<IssuedIdJag, ExchangeError>, ExchangeRecord)
    where
        S: SubjectTokenVerifier,
        D: ResourceAsDirectory + ?Sized,
        P: ExchangePolicy;
}

impl IssuedIdJag {
    pub fn id_jag(&self) -> &IdJag;
    pub fn claims(&self) -> &IdJagClaims;
    pub fn expires_in(&self) -> Duration;
    pub fn to_response(&self) -> HttpResponse;
}

impl ExchangeError {
    /// `invalid_client`, for a caller whose verification of the credentials failed.
    pub fn invalid_client() -> Self;
    /// Answer `invalid_client` with 401 and `WWW-Authenticate: Basic`.
    pub fn with_basic_challenge(self, challenge: bool) -> Self;
    pub fn code(&self) -> &OAuthErrorCode;
    /// The exact rule that failed. For logs only.
    pub fn reason(&self) -> &RejectReason;
    /// The library error behind the refusal, if there is one. For logs only.
    pub fn library_error(&self) -> Option<&Error>;
    pub fn to_response(&self) -> HttpResponse;
}
```

`Idp::exchange` runs, in order: client authentication (§3), DPoP proof validation (§6), subject token verification (§4), audience and resource checks (§5.1, §5.3), the binding decision (§6), policy and its invariants (§5.2, §5.3), the DPoP replay check (§6), and signing (§7).

Success (draft §4.3.4, RFC 8693 §2.2.1):

- Body: `issued_token_type: "urn:ietf:params:oauth:token-type:id-jag"`, `access_token` (the ID-JAG), `token_type: "N_A"`, `expires_in`.
- `scope` is always included when any scope was granted. That is simpler than tracking "differs from request", and always compliant.
- `authorization_details` is always included when granted.
- No `refresh_token` (draft §4.3.4 SHOULD NOT; the API has no field for one).
- Headers: `Cache-Control: no-store`, `Pragma: no-cache`.

Errors use RFC 6749 §5.2 JSON, status 400 (401 with `WWW-Authenticate: Basic` for `invalid_client` after a `Basic` attempt, 500 for `server_error`), and a fixed per-code `error_description` (draft §10); the §6.1 refusal has its own fixed description. Codes: `unsupported_grant_type`, `invalid_request`, `invalid_client`, `invalid_target`, `access_denied`, `invalid_scope`, `insufficient_user_authentication` (with `max_age` / `acr_values`, draft §9.3), `invalid_dpop_proof`, `use_dpop_nonce` (with a `DPoP-Nonce` header), and `server_error` (a caller bug, or a failed signer, replay store, or time computation).

`RejectReason` is a `#[non_exhaustive]` enum with one variant per rule of §2–§8 and a `code()` that gives the OAuth error code. It never goes on the wire.

## 10. Audit record

Draft §9.2 says the IdP SHOULD record the audience, resource, scope, and authenticated client of each exchange, so that anomalies can be detected. Every outcome returns one:

```rust
pub struct ExchangeRecord {
    pub at: SystemTime,
    /// The authenticated client. For an `invalid_client` refusal: the client_id the request claimed, if any.
    pub client_id: Option<String>,
    /// As requested. `None` only where the request has none (§8).
    pub audience: Option<String>,
    pub resolved_issuer: Option<Issuer>,
    pub requested_resources: Vec<String>,
    pub requested_scope: Option<Scope>,
    pub outcome: ExchangeOutcome,
}

impl ExchangeRecord {
    /// For a refusal outside `Idp::exchange`: a request that did not parse,
    /// or a client whose credentials the caller rejected.
    pub fn for_rejection(at: SystemTime, client_id: Option<&str>, error: &ExchangeError) -> Self;
}

#[non_exhaustive]
pub enum ExchangeOutcome {
    Issued { jti: String, granted: GrantedAccess },
    /// A §8 exchange was approved; the caller mints the token.
    RefreshTokenApproved,
    Rejected { code: OAuthErrorCode, reason: RejectReason },
}

pub struct GrantedAccess {
    pub client_id: String,
    pub sub: String,
    pub resources: Vec<String>,
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub confirmation: Option<Confirmation>,
    pub expires_at: NumericDate,
}
```

It contains no tokens. How long to keep records, and how users or admins review and revoke cross-app access, is the caller's (draft §10).

## 11. Metadata

`Idp::metadata_builder(jwks_uri: Url) -> IdpMetadataBuilder` starts the IdP's RFC 8414 / OIDC discovery document from the configuration. The document gains (RFC-006 §2, draft §7.1):

- `identity_chaining_requested_token_types_supported`, containing `urn:ietf:params:oauth:token-type:id-jag`, plus `…:refresh_token` when §8 is enabled.
- `id_jag_signing_alg_values_supported` (optional, `IdpMetadataBuilder::id_jag_signing_algs`). If emitted, the builder refuses a list without `RS256` (draft §7.1 MUST).
- `grant_types_supported`, containing `urn:ietf:params:oauth:grant-type:token-exchange`.
- `jwks_uri`. The caller serves the JWK Set there, built from the signer's public key (`JwkSet::from_keys(vec![key.public_jwk()])`).
- `dpop_signing_alg_values_supported`, from `dpop_algorithms`, when `dpop` is set.

## 12. Example

```rust
async fn token(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    let now = SystemTime::now();
    let req = match TokenExchangeRequest::parse(&body, &headers_vec(&headers), None) {
        Ok(r) => r,
        Err(e) => {
            app.audit(ExchangeRecord::for_rejection(now, None, &e)).await;
            return into_axum(e.to_response());
        }
    };
    // The caller checks the credentials against its client registry and
    // reports a `ClientIdentity`.
    let Some(client) = app.authenticate(req.client_credentials()).await else {
        return into_axum(req.invalid_client().to_response());
    };
    let (result, record) = app.idp.exchange(
        &req, &client, &app.subjects, &app.directory, &app.policy, now,
    ).await;
    app.audit(record).await;
    match result {
        Ok(issued) => into_axum(issued.to_response()),
        Err(e) => into_axum(e.to_response()),
    }
}
```

`to_response()` returns an `HttpResponse` (RFC-001 §6); `into_axum` is the caller's conversion to its framework's response type. `examples/idp` is the full version.

## 13. Security checks summary

| Threat | Defense | Where |
| --- | --- | --- |
| Unauthenticated exchange | `invalid_client`, no exception | §3 |
| Token-type confusion as subject token | `typ` allow-list plus caller positive identification | §4 |
| Using another client's ID Token, Refresh Token, or SAML assertion | Bound-client / Audience mapping checks | §4.2 |
| Grant for an untrusted or ambiguous audience | Directory resolution; single `aud` | §2, §5.1 |
| Grant for resources the Resource AS doesn't govern (the §9.5 relay attack) | `governs` check, `invalid_target` | §5.3 |
| Policy bug widening the grant | Invariants after `evaluate` | §5.3 |
| Wrong `sub` or `client_id` for the Resource AS | Required, explicit fields | §5.2 |
| Subject identifier over-disclosure | `sub_id` only for Resource ASes that want it | §5.3 |
| Bearer grant theft | DPoP / mTLS binding; short lifetime | §6, §1 |
| Undetected abuse of a stolen subject token | Audit record on every outcome | §10 |

## 14. Tests

- **One negative test per row** of §2, §4.2, §4.3, §5.3, and §6, plus the §8 refusals, the §9 response shapes, and the §1 configuration checks (`src/idp/tests.rs`).
- **Issuance:** one test asserts the exact header and claim set of a fully populated ID-JAG (multi-tenant, `saml-nameid`, RAR, extra claims, `cnf`), with a fixed clock; another asserts that a minimal ID-JAG omits every optional claim.
- **Round trip:** `tests/flow_test.rs` runs ID-JAGs this component issues through RFC-004 validation, for ID Token and Refresh Token subjects, bearer and DPoP-bound grants, single-tenant.
- **Interop:** the playground client flow (RFC-003 §14) pointed at `examples/idp` instead of `idp.xaa.dev` has not been run.

## 15. Spec coverage

| Section | Covered by |
| --- | --- |
| §3 RS256 MTI (IdP side) | §11 (alg list), RFC-002 §3 |
| §3.1 claims (producer) | §7 |
| §3.2.1, §3.2.2 `saml-nameid` (producer) | §5.2, §5.3, §7 |
| §4.3 parameters, audience/resource profiling, aliases | §2, §5.1 |
| §4.3.3 Processing Rules | §3, §4, §5 |
| §4.3.4, §4.3.4.1 Response | §7, §9 |
| §4.3.4.2 RAR | §2, §5, §7 |
| §4.3.4.3 Error Response | §9 |
| §4.5 SAML → Refresh Token (IdP side) | §8 |
| §5.1 Client ID Mapping | §5.2 |
| §5.2 Subject Identifier Mapping | §5.2 |
| §6.1–§6.4 tenancy (producer) | §1, §4.2, §7 |
| §7.1 IdP Metadata | §11 |
| §9.2 IdP-side mitigations (short lifetimes, logging) | §1, §10 |
| §9.3 Step-Up | §4.1, §5.2, §9 |
| §9.4 scope comparison | §5.3 |
| §9.9 Subject Identifier Disclosure | §5.3 |
| §9.10 Actor delegation | §7 (ignored) |
| §9.11, §9.11.1.1, §9.11.2.1 binding at token exchange | §6 |
| §10 Privacy (IdP records, minimal claims) | §10, §5.3 |
| identity-chaining §2.3.1–§2.3.3, §2.5, §5.3 | §2, §5, §7 |
| jwt-dpop-grant §3, §7.1 | §6 |
