# RFC-001: xaa — Architecture and Principles

**Status**: Draft
**Date**: 2026-11-14

## Summary

`xaa` is a Rust crate for Cross App Access: the Identity Assertion JWT Authorization Grant (`draft-ietf-oauth-identity-assertion-authz-grant`, "ID-JAG"). It covers the draft's three roles (§2.1):

- The **Client** (requesting app) obtains an ID-JAG from its IdP and trades it for an access token at another app's authorization server.
- The **Resource Authorization Server** validates the ID-JAG.
- The optional **IdP Authorization Server** issues ID-JAGs. It also lets the crate prove the other two components against itself.

The crate is stateless, async-runtime-agnostic, and bring-your-own-HTTP. The caller owns the clock, persistence, the replay store, and the access tokens it mints. The library does the mechanics, with security-critical defaults that cannot be silently weakened.

This RFC covers the architecture and maps the whole specification to the RFCs that implement it (§10). Component detail is in:

| RFC | Covers |
| --- | --- |
| [RFC-002](RFC-002-jose-core.md) | JOSE and ID-JAG core: JWS, JWK, claim model, client assertions, replay store |
| [RFC-003](RFC-003-client.md) | Client (requesting app) |
| [RFC-004](RFC-004-resource-as.md) | Resource Authorization Server |
| [RFC-005](RFC-005-idp.md) | IdP Authorization Server |
| [RFC-006](RFC-006-metadata.md) | Metadata and discovery |
| [RFC-007](RFC-007-sender-constraining.md) | Sender constraining (DPoP and mTLS) |

---

## 1. Motivation

Draft-06 defines XAA as a profile of OAuth Identity Chaining. A requesting app reaches another app's API through the IdP both apps already trust for SSO, without a per-integration consent redirect. The draft is at version -06, has a public playground (xaa.dev), and is being adopted for AI agent tool access (draft Appendix A.4).

A correct implementation has to get many cross-cutting details right:
- Typed JWTs and audience pinning.
- Per-issuer algorithm allow-lists.
- Client binding across two independent registrations.
- Tenant-scoped subject resolution.
- Replay ordering under DPoP nonces.
- Metadata issuer checks that defeat the §9.5 relay attack.

Most of these fail silently when missed. This crate implements them once, for all three roles, under the same discipline as the `saml` crate: no C toolchain, stateless, structurally safe.

## 2. Design Principles

1. **Stateless.** No session store, no JWKS cache, no clock. Every time-sensitive check takes `now` explicitly, and `clock_skew` is an argument or a configuration field (§8). Replay protection goes through a caller-provided atomic store (RFC-002 §10).
2. **BYO HTTP.** Network calls go through the `HttpClient` trait (§6). Every round trip is also available sans-IO: one function builds the `HttpRequest`, another parses the `HttpResponse`. Validation at the Resource AS needs no HTTP at all.
3. **Type-honest API.** Each role is its own type. Token types, grant types, algorithms, `cnf` methods, and client authentication methods are enums. Rules the spec states as MUST are encoded in types where possible. For example, there is exactly one `audience`, and the IdP leg cannot be configured without client authentication.
4. **Minimal surface.** Every public item exists because the protocol requires it. There are no builder DSLs and no type-erased runtime dispatch beyond the caller extension traits.
5. **Hard-fail where the spec does not admit choice:** `typ`, signature, issuer trust, `aud`, `client_id` binding, `cnf` proof, metadata `issuer`, and PRM `resource`. **Caller policy where it does:** lifetimes, clock skew, `jti` reuse, which scopes, resources, and authorization details to grant, and subject resolution. Where the spec allows either of two behaviors, the caller must pick one; there is no default (`JtiPolicy`, RFC-004 §8).
6. **Verified-grant handle.** The only way to read ID-JAG claims at the Resource AS is through a `Verified` handle produced by successful validation (RFC-002 §4). The client's unverified view of its own ID-JAG is a different type, and it is never accepted where a verified one is required.
7. **Policy can't widen grants.** Caller policy runs inside builders that enforce the spec's subset invariants: granted ⊆ ID-JAG at the Resource AS (RFC-004 §6), granted ⊆ requested at the IdP (RFC-005 §5.3). A policy bug becomes an error, not extra access.
8. **Secrets stay secret.** Tokens and credentials are newtypes with no `Display` and a redacted `Debug`. They are zeroized on drop and never put into URLs (RFC-002 §11).

## 3. Role model

| Component | Feature | Draft role (§2.1) | Responsibility |
| --- | --- | --- | --- |
| Client | `client` | Client (xaa.dev: Requesting App) | §4.3 Token Exchange at the IdP; §4.4 Access Token Request at the Resource AS; §4.5 SAML → Refresh Token; discovery. |
| Resource AS | `resource-as` | Resource Authorization Server (xaa.dev: Resource App) | Validate the ID-JAG; return a verified grant; enforce grant invariants; serialize responses. |
| IdP | `idp` | IdP Authorization Server | Validate the token-exchange request; apply caller policy; issue the ID-JAG. |

Out of scope as roles:
- **Resource Server.** It validates access tokens the Resource AS issued, which is ordinary OAuth (draft §2.1).
- **User authentication** (draft §4.2). The client brings the subject token; OIDC and SAML SSO are other crates' jobs.

## 4. Protocol constants

| Name | Value | Source |
| --- | --- | --- |
| Token-exchange grant | `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 |
| JWT-bearer grant | `urn:ietf:params:oauth:grant-type:jwt-bearer` | RFC 7523 |
| JWT-DPoP grant | `urn:ietf:params:oauth:grant-type:jwt-dpop` | jwt-dpop-grant-02 §9.1 |
| ID-JAG token type | `urn:ietf:params:oauth:token-type:id-jag` | draft §11.2 |
| Subject token types | `urn:ietf:params:oauth:token-type:id_token`, `…:saml2`, `…:refresh_token` | RFC 8693 §3 |
| ID-JAG JOSE `typ` / media type | `oauth-id-jag+jwt` | draft §3.1, §11.1 |
| Grant profile | `urn:ietf:params:oauth:grant-profile:id-jag` | draft §11.2 |
| Client assertion type | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` | RFC 7523 §2.2 |
| Subject Identifier Format | `saml-nameid` | draft §11.6 |

## 5. Crate layout and features

```text
src/
  lib.rs
  jose/          compact JWS, algorithms, JWK / JWK Set, thumbprints        (RFC-002)
  claims/        IdJagClaims, Resources, Scope, AuthorizationDetails, cnf, sub_id
  client_auth/   ClientAuth (client side), ClientCredentials + assertion verify (server side)
  dpop/          DpopKey, proofs, validation, nonce trait, binding decisions (RFC-007)
  mtls.rs        certificate thumbprint and `x5t#S256` comparison            (RFC-007 §5)
  metadata/      AS metadata, PRM, client metadata, JWKS fetch               (RFC-006)
  replay.rs      ReplayStore + InMemoryReplayStore
  secret.rs      secret newtypes
  http.rs        HttpClient, HttpRequest, HttpResponse, ReqwestClient
  form.rs        form-urlencoded parsing and encoding (crate-private)
  oauth_error.rs OAuthErrorCode, token-endpoint error bodies
  error.rs       Error
  test_support.rs  shared unit-test fixtures (`#[cfg(test)]` only)
  client/        Client                                                      (RFC-003)
  resource_as/   Resource Authorization Server                               (RFC-004)
  idp/           IdP Authorization Server                                    (RFC-005)
```

| Feature | Default | Enables |
| --- | --- | --- |
| `client` | yes | `client/` |
| `resource-as` | yes | `resource_as/` |
| `idp` | no | `idp/` |
| `reqwest-client` | no | `xaa::http::ReqwestClient`, an adapter for `HttpClient` (rustls, redirects disabled). |

### 5.1 Dependencies

All Rust, no C toolchain (`openssl`, `openssl-sys`, `native-tls` are banned in `deny.toml`). The crypto stack is the same RustCrypto generation the `saml` crate uses since it moved to `rsa` 0.10, which closed RUSTSEC-2023-0071:

| Crate | Version | Used for |
| --- | --- | --- |
| `rsa` | 0.10 | RS256/384/512, PS256/384/512 |
| `ecdsa`, `p256`, `p384` | 0.17, 0.14 | ES256, ES384 |
| `sha2` | 0.11 | Digests, JWK and certificate thumbprints |
| `signature` | 3 | Signer/verifier traits |
| `pkcs8` | 0.11 | Key import |
| `rand` | 0.10 | `jti` values, DPoP keys |
| `base64` | 0.22 | base64url (JOSE) and base64 (`saml2` tokens) |
| `serde`, `serde_json` | 1 | Claims, metadata, token-endpoint bodies |
| `http`, `url` | 1, 2 | Request types, URL handling |
| `thiserror` | 2 | `Error` |
| `zeroize`, `subtle` | 1, 2 | Secret handling, constant-time compares |
| `reqwest` (optional) | 0.12, rustls | `reqwest-client` adapter |

Versions move in lockstep with `saml` so that apps using both crates build a single crypto stack.

The shared modules (`jose`, `claims`, `dpop`, `metadata`, …) build under any combination of components. DPoP and mTLS aren't feature-gated: they reuse the JOSE crypto, and gating them would make the binding checks in RFC-004 §4 rule 12 conditional.

## 6. HttpClient trait

The same shape as `saml::HttpClient` (and `arctic-oauth`):

```rust
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub trait HttpClient: Send + Sync {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, BoxError>> + Send;
}

pub struct HttpRequest {
    pub method: http::Method,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first header named `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str>;
}

/// `reqwest-client` feature.
pub struct ReqwestClient(pub reqwest::Client);

impl ReqwestClient {
    /// A client that never follows redirects.
    pub fn new() -> Result<Self, BoxError>;
}
```

It is used only by the client's two token calls and the §4.5 exchange, and by metadata and JWKS fetches. Server components take parsed requests and return `HttpResponse` values for the caller's web framework to send. mTLS client certificates are the `HttpClient` implementation's concern (RFC-007 §5).

An implementation MUST NOT follow redirects: a redirect from a token endpoint would replay credentials to another origin. `ReqwestClient::new()` disables them; a caller who wraps its own `reqwest::Client` has to do the same.

## 7. Error type

There are two layers.

**`Error`** is the library error. It is one `#[non_exhaustive]` enum with a distinct variant per rule, as in `saml::Error`, grouped as:
- JOSE parse and verify: `TokenTooLong`, `MalformedJws`, `EncryptedJwtUnsupported`, `UnsupportedAlgorithm`, `CriticalHeader`, `WrongTyp`, `DisallowedAlgorithm`, `UnknownKeyId`, `AmbiguousKey`, `KeyMismatch`, `WeakKey`, `BadSignature`, `Signing`.
- Keys: `MalformedJwk`, `PrivateKeyMaterial`, `InvalidPrivateKey`.
- Claims and time: `MalformedClaims`, `MissingClaim`, `InvalidClaim`, `TransientNameId`, `Expired`, `NotYetValid`, `TimeOutOfRange`.
- Client assertions and replay: `InvalidClientAssertion`, `Replayed`, `ReplayStore`.
- Sender constraining: `InvalidDpopProof`, `DpopNonceRequired`.
- Client requests and responses: `InvalidRequest`, `InvalidTokenResponse`, `UnexpectedIssuedTokenType`, `UnsupportedTokenType`, `ScopeNotSubset`, `DpopKeyRequired`, `ResourceAsLacksJwtDpop`, `UnauthenticatedUnboundGrant`, and `TokenEndpoint` (with the `client` feature).
- Client self-checks: `MalformedIdJag`, `IdJagAudienceMismatch`, `IdJagClientIdMismatch`, `IdJagResourceAltered`, `BindingDowngrade`.
- Configuration and caller bugs: `InvalidConfiguration`, `GrantExceedsIdJag`, `GrantExceedsRequest`, `UnwantedSubId`.
- Metadata: `InvalidMetadata`, `MetadataIssuerMismatch`, `PrmResourceMismatch`, `InsecureEndpoint`, `UnexpectedResponse`.
- Transport: `Http(BoxError)`.

**`TokenError`** (RFC-004 §7) and **`ExchangeError`** (RFC-005 §9) are the server-side protocol errors. Each is a struct that carries:
- an `OAuthErrorCode`, read with `code()`. The servers emit `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `invalid_scope`, `invalid_target`, `access_denied`, `insufficient_user_authentication`, `invalid_dpop_proof`, `use_dpop_nonce`, and `server_error`. The enum also has `unauthorized_client`, `invalid_authorization_details`, `temporarily_unavailable`, and `Other(String)`, so the client can represent any code it receives;
- a `RejectReason` that names the exact failed rule, for logs only. Each component has its own enum (`resource_as::RejectReason`, `idp::RejectReason`). `TokenError::reason()` is an `Option`: it is `None` for an error the caller built itself, such as `TokenError::invalid_client()`;
- the library `Error` behind the rejection, when there is one: `TokenError::error()`, `ExchangeError::library_error()`;
- `to_response()`, which serializes RFC 6749 §5.2 JSON with a fixed `error_description` per code (draft §10). The status is 400, 401 with a `WWW-Authenticate: Basic` challenge for `invalid_client` after a Basic attempt, or 500 for `server_error`.

On the client side, a token endpoint's OAuth error arrives as `Error::TokenEndpoint` holding a `TokenEndpointError`, which maps the code to a `Remediation` (RFC-003 §8).

## 8. Clock policy

The library has no clock. Every method that compares against `exp`, `iat`, `nbf`, or a DPoP `iat` takes `now: SystemTime`. Wherever a peer-supplied time is compared there is a `clock_skew: Duration`: an argument of `ResourceAs::validate` (RFC-004 §4), and a field of `IdpConfig` (RFC-005 §1), `DpopValidation` (RFC-007 §3), and `ClientAssertionContext` (RFC-002 §9). Issuing methods take `now` for `iat` / `exp`. Tests pass fixed timestamps.

## 9. Testing strategy (proof)

1. **Unit tests** in each module (`#[cfg(test)] mod tests`, and `tests.rs` in `client/`, `resource_as/`, and `idp/`). They include one negative test per validation rule; every rule table in RFC-002 to RFC-007 is a test checklist. The known-answer vectors are the RFC 7638 §3.1 thumbprint (RFC-002 §14), the RFC 9449 example proofs, thumbprint, and `ath`, and the RFC 8705 Appendix A certificate thumbprint (RFC-007 §7).
2. **Cross-role flow tests** (`tests/flow_test.rs`, built with `--features client,resource-as,idp`). `client`, `idp`, and `resource-as` run in one process, behind an `HttpClient` that routes each request to the matching component. They cover ID Token and Refresh Token subjects, bearer and DPoP-bound grants, single-use replay, the client's self-checks, policy denial, a Resource AS without `jwt-dpop`, and discovery. The setup is single-tenant. mTLS, multi-tenant setups, `saml-nameid`, and RAR are covered by the unit tests of each component, not by a flow test.
   - `tests/saml_flow_test.rs` uses the `saml` crate (0.1.0-alpha.3) as a dev-dependency: `saml` issues and consumes the sign-on Response, the client exchanges the exported assertion, and the IdP verifies it through `saml` (RFC-005 §4.4). `saml` is never a runtime dependency.
3. **Closed-loop examples** (`examples/client`, `examples/resource-as`, `examples/idp`): three binaries that talk to each other over real HTTP. `scripts/smoke-examples.sh` runs them, and CI runs the script.
4. **Playground interop** against xaa.dev, with developer credentials:
   - `examples/client --playground` against `https://idp.xaa.dev` and `https://auth.resource.xaa.dev`, then calling `https://api.resource.xaa.dev`. Run by hand on 2026-11-14 and it passes; `docs/interop.md` records what it showed. It is not in CI: the playground's login needs a browser and returned no refresh token.
   - `examples/resource-as` registered as an "Own" auth server at xaa.dev and validating the playground IdP's ID-JAGs. Run by hand on 2026-11-14 behind an ngrok tunnel; the playground's flow test passes with every validation rule at its default. Not in CI: it needs a public URL and a browser login.
   - Both repeated on the playground's SAML path on 2026-11-14: `examples/client --playground --saml` (SAML sign-on, assertion → refresh token → ID-JAG), and `examples/resource-as` with `XAA_SAML_ISSUERS` validating a SAML-derived ID-JAG. Both pass.
   - Observed deltas go in `docs/interop.md`.
5. **Fuzzing** (`fuzz/`): one target, `fuzz_id_jag_decode`, drives the compact-JWS parser and the ID-JAG claim rules on arbitrary bytes. Targets for the token-request form parser and for DPoP proofs are not written yet.
6. **Property tests:** the JWS parser never panics on arbitrary input (RFC-002 §14), and the Resource AS decision builder never grants scopes or resources outside the ID-JAG (RFC-004 §13). The sign→verify round trip for every algorithm is a plain unit test.

## 10. Specification coverage

This is the master map: every section of draft-06 and what implements it. Each component RFC has its own detailed coverage table.

### 10.1 draft-ietf-oauth-identity-assertion-authz-grant-06

| Section | Title | Implemented by |
| --- | --- | --- |
| §1 | Introduction | Informative; §1 here |
| §2.1 | Roles | §3 |
| §2.2 | Terms (subject resolution, JIT, tenant) | RFC-004 §5; RFC-004/005 tenancy |
| §3 | ID-JAG (RS256 MTI, ES256 SHOULD) | RFC-002 §3; RFC-004 §1; RFC-006 §2.1 |
| §3.1 | ID-JAG Claims, `typ` | RFC-002 §5–§6; RFC-005 §7; RFC-004 §4 |
| §3.2.1 | SAML NameID Subject Identifier Format | RFC-002 §6 |
| §3.2.2 | Subject Identifier Processing | RFC-004 §4 rule 13, §5; RFC-005 §5.3, §7 |
| §4.1 | Overview, per-issuer trust configuration | RFC-003; RFC-004 §1 |
| §4.2 | User Authentication | Out of scope (§11); the caller supplies subject tokens |
| §4.3 | Token Exchange parameters; audience vs resource | RFC-003 §3; RFC-005 §2, §5.1 |
| §4.3.1, §4.3.2 | Examples | RFC-003 §14 (golden request bodies, with the crate's own fixture values); RFC-005 §14 |
| §4.3.3 | Processing Rules | RFC-005 §3–§5 |
| §4.3.4, §4.3.4.1 | Response, issued ID-JAG | RFC-005 §7, §9; RFC-003 §4 |
| §4.3.4.2 | RAR example | RFC-002 §6; RFC-003 §3–§7; RFC-004 §6; RFC-005 §5 |
| §4.3.4.3 | Error Response | RFC-005 §9; RFC-003 §8 |
| §4.4 | Access Token Request | RFC-003 §6; RFC-004 §2–§3 |
| §4.4.1 | Processing Rules | RFC-004 §4, §6 |
| §4.4.2 | Response | RFC-004 §7; RFC-003 §7 |
| §4.4.3 | Error Response | RFC-004 §7; RFC-003 §8 |
| §4.4.4 | Refresh Token | RFC-004 §7–§8; RFC-003 §8 |
| §4.5 | SAML 2.0 Subject Token Interoperability | RFC-003 §9; RFC-005 §8 |
| §5 | Cross-Domain Client and Subject Identifier Handling | RFC-003 §1 |
| §5.1 | Client ID Mapping | RFC-005 §5.2; RFC-003 §5 |
| §5.2 | Subject Identifier Mapping | RFC-005 §5.2; RFC-004 §5 |
| §6.1–§6.4 | Tenant relationships | RFC-004 §1, §4 rules 10–11, §5; RFC-005 §1, §4.2, §7 |
| §7 | Authorization Server Metadata | RFC-006 §2–§3 |
| §7.1 | IdP AS Metadata | RFC-006 §2.1, §3; RFC-005 §11 |
| §7.2 | Resource AS Metadata | RFC-006 §2.1; RFC-004 §10 |
| §8 | Client Metadata | RFC-006 §6 |
| §9.1 | Client Authentication | RFC-003 §1; RFC-004 §3, §4 rule 11; RFC-007 |
| §9.2 | Storage of Subject Tokens | RFC-002 §11; RFC-003 §11; RFC-005 §1, §10 |
| §9.3 | Step-Up Authentication | RFC-003 §8; RFC-005 §4.1, §9 |
| §9.4 | Cross-Domain Use | RFC-004 §9; RFC-005 §5.3 |
| §9.5 | AS Metadata Validation | RFC-006 §3; also RFC-004 rule 14, RFC-005 §5.3, RFC-007 |
| §9.6 | PRM Validation | RFC-006 §4; RFC-003 §3, §10 |
| §9.7 | Metadata Disclosure | RFC-006 §2.1; RFC-004 §10. The protected discovery mechanism (MAY) is out of scope. |
| §9.8 | Subject Identifier Trust | RFC-004 §4 rule 13, §5 |
| §9.9 | Subject Identifier Disclosure | RFC-005 §5.3 |
| §9.10 | Actor Delegation Extensions | RFC-003 §3 (pass-through); RFC-005 §7 (ignored, no `act`) |
| §9.11 | Sender Constraining Tokens | RFC-007 §1, §4 |
| §9.11.1, §9.11.1.1, §9.11.1.2.1–4 | DPoP Key Binding | RFC-007 §2–§4; RFC-003 §5–§6; RFC-004 §4; RFC-005 §6 |
| §9.11.2, §9.11.2.1–2 | mTLS Certificate Binding | RFC-007 §4–§5 |
| §10 | Privacy Considerations | RFC-004 §7; RFC-005 §5.3, §10; RFC-007 §2 |
| §11.1 | Media type | RFC-002 §5 |
| §11.2 | OAuth URIs | §4 |
| §11.3 | AS metadata registrations | RFC-006 §2 |
| §11.4 | DCR metadata registration | RFC-006 §6 |
| §11.5 | JWT claims (`resource`, `aud_tenant`) | RFC-002 §6 |
| §11.6 | `saml-nameid` format | RFC-002 §6 |
| §12 | References | §10.3 |
| App. A.1–A.2 | Enterprise, CIAM use cases | Informative |
| App. A.3 | Email/calendar with Client ID Metadata Documents | Client side: RFC-006 §6. Server-side CIMD resolution is out of scope (§11). |
| App. A.4 | AI agent; discovery sequence | RFC-003 §10; RFC-006 |

### 10.2 Normative profiles it builds on

| Document | Sections | Implemented by |
| --- | --- | --- |
| draft-ietf-oauth-identity-chaining-17 | §2.2 discovery; §2.3 token exchange; §2.4 JWT grant; §2.5 claims transcription; §3 metadata; §5.1–§5.5 security | RFC-003, RFC-004, RFC-005, RFC-006. The profile narrows chaining's options (exactly one `audience`; issuer-only `aud`), and the narrower rule wins. |
| draft-parecki-oauth-jwt-dpop-grant-02 | §3, §4.1, §5, §5.1, §5.2, §6, §7, §8 | RFC-007; RFC-003 §6; RFC-004 §4 |

### 10.3 Spec tracking

| Document | Version tracked |
| --- | --- |
| `draft-ietf-oauth-identity-assertion-authz-grant` | -06 (2026-10-31) |
| `draft-ietf-oauth-identity-chaining` | -17 (2026-07-19) |
| `draft-parecki-oauth-jwt-dpop-grant` | -02 (2026-10-30) |
| RFC 10070 (formerly `draft-ietf-oauth-rfc7523bis`) | Client assertion `aud` and `typ` (RFC-002 §9) |
| OpenID Connect Enterprise Extensions 1.0 | draft 01 (`tenant`, `aud_sub`) |
| RFC 6749, 7517, 7518, 7519, 7521, 7523, 7591, 7638, 7800, 8414, 8693, 8705, 8707, 8725, 9396, 9449, 9493, 9728 | — |

A new draft revision is handled by re-running this table section by section, and noting changes in the CHANGELOG and in the affected component RFC.

## 11. Out of scope for v0.1

- User authentication: OIDC authorization-code flow and SAML SSO (draft §4.2). Use an OIDC crate or `saml`.
- Minting and validating access tokens at the Resource Server, including RFC 9068 JWT access tokens and DPoP proof validation at the RS.
- Subject resolution, JIT provisioning, and account storage (RFC-004 §5).
- `actor_token` processing and `act` emission (draft §9.10 defines none).
- JWE-encrypted ID-JAGs (RFC-002 §12).
- Server-side resolution of Client ID Metadata Documents (draft §5.1, App. A.3–A.4).
- The protected per-client issuer-acceptance discovery mechanism (draft §9.7 MAY).
- Requesting an ID-JAG in the authorization request during step-up (draft §9.3 TBD).
- `client_secret_jwt` and `EdDSA`.
- JWKS and metadata caching (by design; §2).

## 12. Decisions and open questions

Resolved:

- **DPoP and mTLS binding are in v0.1** (RFC-007). They are what makes the unauthenticated-client path in draft §4.4 safe, and they defeat the §9.5 relay attack.
- **SAML subject tokens need no `saml` dependency.**
  - The client sends assertion bytes it already has (RFC-003 §2).
  - The IdP verifies its own assertions through `SubjectTokenVerifier` (RFC-005 §4.1), behind which `saml` fits.
  - The Resource AS only sees `sub_id` JSON.
- **Client authentication:** `client_secret_basic`, `client_secret_post`, `private_key_jwt` (RFC 10070: issuer as sole `aud`, `typ: client-authentication+jwt`), and `tls_client_auth`, on both legs. Plus unauthenticated-with-sender-constrained-ID-JAG at the Resource AS only, opt-in.
- **No refresh tokens from the Resource AS.** The API has no field for one (draft §4.4.4 SHOULD NOT).
- **`aud` at the Resource AS is issuer-only.** The draft §4.4.1 rule wins over identity-chaining's token-endpoint option.
- **No default `JtiPolicy`** (RFC-004 §8). The draft permits both single use and re-presentation.
- **RSA signing uses `rsa` 0.10.** That release removed the timing side channel behind RUSTSEC-2023-0071, so there is no advisory exception (§5.1).
- **Client-assertion `typ`** follows RFC 10070 (RFC-002 §9).
- **NumericDate accepts non-integer values**, as RFC 7519 §2 allows (RFC-002 §6).
- **`saml2` subject tokens:** the IdP accepts both base64url and standard base64; the client sends base64url by default (RFC-003 §2, RFC-005 §2).
- **DPoP proof for a Resource AS without `jwt-dpop`:** the IdP refuses the exchange with `invalid_target` by default, and the client doesn't send the proof (RFC-005 §6.1, RFC-003 §3). `DpopToNonSupportingAs::Bind` is the opt-in for the literal draft reading.
- **Missing proof under `jwt-dpop`** is `invalid_dpop_proof`; under `jwt-bearer` a `jkt`-bound ID-JAG is `invalid_grant` (RFC-007 §4.2). There is no option for it.
- **`JwsSigner` and `ReplayStore` return boxed futures**, so both traits are object-safe and configuration can hold `Arc<dyn JwsSigner>` and take `&dyn ReplayStore` (RFC-002 §7, §10).
- **`JtiPolicy::SingleUse` without a replay store** fails each request with `server_error`. The store is an argument of `validate`, not of the configuration, so the mistake cannot be caught at construction (RFC-004 §8).
- **Replay order at the Resource AS:** the DPoP proof's `jti` is recorded first, then the ID-JAG's `jti`, both after every other check (RFC-004 §4 rule 16).
- **`sub_id` at the Resource AS:** only `saml-nameid` is accepted. Any other Subject Identifier Format rejects the grant (RFC-004 §4 rule 13).
- **The `reqwest-client` feature exists** and gives `xaa::http::ReqwestClient`, with redirects disabled (§6).

Open, in this crate:

- The SAML flow test waits for `saml` 0.1.0-alpha.3 on crates.io (§9 tier 2).
- Fuzz targets for the token-request form parser and for DPoP proofs (§9 tier 5).

Open, to raise upstream. Both have a chosen behavior above; only the spec text is unsettled:

1. **DPoP-bound ID-JAG for a Resource AS without `jwt-dpop`.** Draft §9.11.1.1 says the IdP MUST bind, and jwt-dpop-grant §7.1 says it SHOULD NOT issue one. Also unsettled: a DPoP-bound subject token forces a proof, which leaves no conforming path to such an AS (RFC-005 §6.1).
2. **Error code for a `jkt`-bound ID-JAG without a proof.** It is `invalid_grant` in draft §9.11.1.2.2 and `invalid_dpop_proof` in jwt-dpop-grant §5.
