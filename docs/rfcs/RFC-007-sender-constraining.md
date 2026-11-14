# RFC-007: Sender constraining (DPoP and mTLS)

**Status**: Draft
**Date**: 2026-11-14

## Summary

Draft §9.11 defines two ways to bind an ID-JAG to a key the client holds:
- **DPoP:** RFC 9449, with the `jwt-dpop` grant from draft-parecki-oauth-jwt-dpop-grant-02.
- **mTLS certificate binding:** RFC 8705.

Binding happens at the IdP, during the token exchange. It is checked at the Resource AS, during the access token request. This RFC defines the shared machinery: DPoP key and proof creation for the client, proof validation for both servers, nonce and replay handling, certificate thumbprints, and the binding decision table that RFC-003, RFC-004, and RFC-005 refer to.

A bound ID-JAG is useless to anyone who copies it without the key. That defeats the replay risk identity-chaining §5.5 describes and the relay attack in draft §9.5. It is also the only way a Resource AS may accept a client that doesn't authenticate (draft §4.4, §9.1).

---

## 1. Thumbprints

| Binding | `cnf` member | Value | Source |
| --- | --- | --- | --- |
| DPoP | `jkt` | RFC 7638 SHA-256 JWK thumbprint of the proof's `jwk` header, base64url | RFC 9449 §6.1 |
| mTLS | `x5t#S256` | SHA-256 of the DER certificate, base64url | RFC 8705 §3.1 |

Both are compared as exact strings. Draft §9.11.1.1 relies on "simple string comparison of the JWK SHA-256 Thumbprint".

## 2. Client side: DPoP keys and proofs

```rust
pub struct DpopKey { /* signer + public JWK + cached thumbprint */ }

impl DpopKey {
    /// ES256, ES384, RS256, or PS256. Any other algorithm is `Error::InvalidConfiguration`.
    pub fn generate(alg: SignatureAlgorithm) -> Result<Self, Error>;
    /// For an HSM- or KMS-backed key. `Error::KeyMismatch` if `public` cannot verify the signer's algorithm.
    pub fn from_signer(signer: Arc<dyn JwsSigner>, public: Jwk) -> Result<Self, Error>;
    pub fn thumbprint(&self) -> &str;
    pub fn public_jwk(&self) -> &Jwk;
    pub fn algorithm(&self) -> SignatureAlgorithm;
    /// The `cnf` of a token bound to this key.
    pub fn confirmation(&self) -> Confirmation;
    /// True only for a `jkt` equal to `thumbprint()`. A missing `cnf` is not a match.
    pub fn is_confirmed_by(&self, cnf: Option<&Confirmation>) -> bool;
    pub async fn proof(
        &self,
        method: &http::Method,
        url: &Url,
        nonce: Option<&str>,
        now: SystemTime,
    ) -> Result<String, Error>;
}

pub struct DpopRequest<'a> {
    pub key: &'a DpopKey,
    /// The last `DPoP-Nonce` this server sent, if any (RFC 9449 §8).
    pub nonce: Option<&'a str>,
}

impl DpopRequest<'_> {
    /// The proof for a `POST` to `token_endpoint`.
    pub async fn token_endpoint_proof(&self, token_endpoint: &Url, now: SystemTime) -> Result<String, Error>;
}
```

Proof creation is `async` because `JwsSigner::sign` is (RFC-002 §7). `generate` makes 3072-bit keys for the RSA algorithms.

The proof header is `typ: dpop+jwt`, `alg`, and `jwk` (public members only); the signer's `kid` is not emitted. The claims are:
- `jti`: 128 random bits.
- `htm`: `POST` for both token endpoints.
- `htu`: the target URL without query or fragment.
- `iat`: `now`.
- `nonce`: when given.
- `ath`: only for resource requests (§6).

Key reuse rules:

- The **same** `DpopKey` must be used at the IdP token exchange and at the Resource AS that will receive that ID-JAG (jwt-dpop-grant §3). RFC-003 §6 enforces this through the thumbprint check.
- A **different** key should be used per Resource AS. The key must not be reused across unrelated users or sessions, because `jkt` is a stable correlator (jwt-dpop-grant §8). The library doesn't enforce this, but its examples follow it.

## 3. Server side: DPoP proof validation

Used by both the IdP (RFC-005 §6) and the Resource AS (RFC-004 §4 rule 1).

```rust
pub struct DpopValidation<'a> {
    pub expected_htm: &'a str,          // "POST"
    pub expected_htu: &'a Url,          // own token endpoint
    pub algorithms: &'a AlgorithmPolicy,
    pub nonce: Option<&'a dyn DpopNonce>,
    pub max_age: Duration,              // iat window; DEFAULT_MAX_AGE is 60 s
    pub now: SystemTime,
    pub clock_skew: Duration,
}

impl<'a> DpopValidation<'a> {
    /// `POST`, no nonce requirement, `DEFAULT_MAX_AGE`. Set the public fields to change them.
    pub fn token_endpoint(
        token_endpoint: &'a Url,
        algorithms: &'a AlgorithmPolicy,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Self;
}

pub fn validate_dpop_proof(
    headers: &[(String, String)],
    v: &DpopValidation<'_>,
) -> Result<ValidatedDpopProof, DpopError>;

impl ValidatedDpopProof {
    pub fn jkt(&self) -> &str;
    pub fn jti(&self) -> &str;
    pub fn iat(&self) -> NumericDate;
    /// The header `jwk`, which verified the signature.
    pub fn public_jwk(&self) -> &Jwk;
}

#[non_exhaustive]
pub enum DpopError {
    /// A §4.3 rule failed, or the proof `jti` was replayed. The inner error is for logs only.
    InvalidProof(Error),
    /// Carries a fresh nonce for the `DPoP-Nonce` response header.
    UseNonce { nonce: String },
    /// The replay store failed or a time computation overflowed. Fails closed.
    Internal(Error),
}

impl DpopError {
    /// `invalid_dpop_proof`, `use_dpop_nonce`, or `server_error`.
    pub fn code(&self) -> OAuthErrorCode;
    pub fn dpop_nonce(&self) -> Option<&str>;
}
```

`headers` are the request headers; the header name is matched as `DPOP_HEADER` (`DPoP`). `default_dpop_algorithms()` is the policy for a server with no narrower one: `ES256`, `ES384`, `RS256`, `PS256`. `has_dpop_header(headers)` tells "no proof" from "a bad proof" where the grant does not require one (§4.2).

The checks follow RFC 9449 §4.3:

| # | Check | Error |
| --- | --- | --- |
| 1 | Exactly one `DPoP` header | `invalid_dpop_proof` |
| 2 | A well-formed compact JWS within the default `ParseLimits` (RFC-002 §2) | `invalid_dpop_proof` |
| 3 | `typ` is `dpop+jwt` | `invalid_dpop_proof` |
| 4 | `alg` is in `algorithms`; never `none` or symmetric | `invalid_dpop_proof` |
| 5 | `jwk` is present and is a public key: no private members (RFC-002 §8), RSA ≥ 2048 bits | `invalid_dpop_proof` |
| 6 | The signature verifies with `jwk`. This is the one place a header key is trusted (RFC-002 §2 rule 7). | `invalid_dpop_proof` |
| 7 | `jti`, `htm`, `htu`, and `iat` are present; the first three are non-empty strings | `invalid_dpop_proof` |
| 8 | `htm` equals `expected_htm` | `invalid_dpop_proof` |
| 9 | `htu` equals `expected_htu`, ignoring query and fragment, after RFC 3986 §6.2.2 / §6.2.3 normalization | `invalid_dpop_proof` |
| 10 | If `nonce` is configured: the proof's `nonce` is present and accepted. Otherwise the error carries a fresh nonce for the `DPoP-Nonce` header. | `use_dpop_nonce` |
| 11 | `iat` is no later than `now + clock_skew` and no earlier than `now - max_age - clock_skew` | `invalid_dpop_proof` |

The checks run in this order and the first failure ends validation. The nonce check runs before the `iat` window, so a client whose clock is off still learns the nonce. `ath` is not examined (§6).

Proof `jti` replay (RFC 9449 §11.1 SHOULD) is a separate step, run by the component after all of its own checks pass:

```rust
impl ValidatedDpopProof {
    pub async fn consume(&self, replay: &dyn ReplayStore, now: SystemTime) -> Result<(), DpopError>;
}
```

It uses `ReplayNamespace::DpopProof { jkt }`, with expiry `iat + max_age + clock_skew`. A replayed `jti` is `DpopError::InvalidProof` (`invalid_dpop_proof`); a replay store failure is `DpopError::Internal` (`server_error`). Running it last applies the jwt-dpop-grant §5.1 ordering rule to proofs as well as grants. The Resource AS records the proof `jti` first and the ID-JAG `jti` after it, so a replayed proof does not burn the grant (RFC-004 §8). A component configured without a replay store skips this step.

```rust
/// Nonces are the caller's. Stateless implementations (a time-bucketed MAC) work.
pub trait DpopNonce: Send + Sync {
    fn current(&self, now: SystemTime) -> String;
    fn accept(&self, nonce: &str, now: SystemTime) -> bool;
}
```

## 4. Binding decision table

Both tables are pure functions of what the request presented:

```rust
pub struct IdpBinding<'a> {
    pub dpop: Option<&'a ValidatedDpopProof>,
    pub certificate_x5t_s256: Option<&'a str>,
    /// When false, a presented certificate is ignored.
    pub mtls_binding: bool,
    /// Unknown counts as false.
    pub supports_jwt_dpop: bool,
    pub preference: BindingPreference,              // Dpop (default) | Mtls
    pub dpop_to_non_supporting_as: DpopToNonSupportingAs, // Reject (default) | Bind
}

impl IdpBinding<'_> {
    /// The `cnf` for the ID-JAG; `None` for an unbound one.
    pub fn decide(&self) -> Result<Option<Confirmation>, BindingRejection>;
}

pub enum AssertionGrantType { JwtBearer, JwtDpop }

pub struct ResourceAsBinding<'a> {
    pub cnf: Option<&'a Confirmation>,
    pub grant_type: AssertionGrantType,
    pub dpop: Option<&'a ValidatedDpopProof>,
    pub certificate_x5t_s256: Option<&'a str>,
    pub preference: BindingPreference,
}

impl ResourceAsBinding<'_> {
    /// `Ok(None)` accepts the request as Bearer, subject to `require_sender_constraint`.
    pub fn decide(&self) -> Result<Option<AccessTokenBinding>, BindingRejection>;
}

pub fn require_sender_constraint(
    binding: Option<&AccessTokenBinding>,
    requires_sender_constraint: bool,
) -> Result<(), BindingRejection>;

#[non_exhaustive]
pub enum BindingRejection {
    AudienceLacksJwtDpop,     // invalid_target
    DpopProofRequired,        // invalid_dpop_proof
    DpopKeyMismatch,          // invalid_grant
    DpopBoundGrantAsBearer,   // invalid_grant
    JwtDpopRequiresJkt,       // invalid_grant
    CertificateRequired,      // invalid_grant
    CertificateMismatch,      // invalid_grant
    UnsupportedConfirmation,  // invalid_grant
    SenderConstraintRequired, // invalid_grant
}

impl BindingRejection {
    pub fn code(&self) -> OAuthErrorCode;
}
```

An invalid proof never reaches either table: `validate_dpop_proof` has already failed the request. `AssertionGrantType::parse` and `as_str` convert to and from the `grant_type` value (`GRANT_TYPE_JWT_BEARER`, `GRANT_TYPE_JWT_DPOP`). `AssertionGrantType::for_confirmation(cnf)` is the grant type a client must use for an ID-JAG: `jwt-dpop` for `cnf.jkt`, `jwt-bearer` for everything else.

### 4.1 At the IdP (token exchange)

| DPoP proof | Client certificate (with `mtls_binding`) | ID-JAG `cnf` | Source |
| --- | --- | --- | --- |
| Valid | none | `jkt`, if the Resource AS supports `jwt-dpop` | draft §9.11.1.1 MUST |
| Valid | any | Request fails with `invalid_target` by default, if the Resource AS lacks `jwt-dpop` | jwt-dpop-grant §7.1, RFC-005 §6.1 |
| Invalid | any | Request fails with `invalid_dpop_proof` | RFC 9449 §5 |
| none | presented | `x5t#S256` | draft §9.11.2.1 |
| Valid | presented | One of them, per `binding_preference`. Never both. | draft §9.11 SHOULD NOT both |
| none | none | none | draft §9.11.1.1 item 2 |

RFC-005 §6.1 explains the second row and its `Bind` opt-out. The client never sends such a proof in the first place (RFC-003 §3).

`binding_preference` is set per Resource AS (`ResourceAsEntry`, RFC-005 §6) and defaults to `BindingPreference::Dpop`. An IdP configured with `dpop: false` ignores the `DPoP` header altogether, as an authorization server without DPoP support does: the proof is not validated and the ID-JAG carries no `jkt`. The client detects the missing `cnf` (RFC-003 §5).

### 4.2 At the Resource AS (access token request)

| ID-JAG `cnf` | `grant_type` | Proof / certificate presented | Result | Source |
| --- | --- | --- | --- | --- |
| `jkt` | `jwt-dpop` | Valid proof, thumbprint matches | Accept. May issue a DPoP-bound token, SHOULD use the same key. | draft §9.11.1.2.1 |
| `jkt` | `jwt-dpop` | Valid proof, thumbprint differs | `invalid_grant` | draft §9.11.1.2.1 step 4 |
| any | `jwt-dpop` | No proof | `invalid_dpop_proof` (RFC-004 rule 1 runs first) | jwt-dpop-grant §5 |
| `jkt` | `jwt-bearer` | Any, including a valid proof | `invalid_grant` | jwt-dpop-grant §5.2 MUST |
| none or `x5t#S256` | `jwt-dpop` | Valid proof | `invalid_grant` | jwt-dpop-grant §5 step 3 |
| none | `jwt-bearer` | Valid proof | Accept. May issue a DPoP-bound token for the proof key. | draft §9.11.1.2.3 |
| none | `jwt-bearer` | Nothing | Accept as Bearer, unless the resource `requires_sender_constraint` (then `invalid_grant`) | draft §9.11.1.2.4 |
| `x5t#S256` | `jwt-bearer` | Certificate, thumbprint matches | Accept. May issue a certificate-bound token. | draft §9.11.2.2 |
| `x5t#S256` | `jwt-bearer` | Certificate thumbprint differs, or no certificate | `invalid_grant` | draft §9.11.2.2 |
| none | `jwt-bearer` | Certificate | Accept. May issue a certificate-bound token. | draft §9.11.2.2 |
| An unsupported member | any | any | `invalid_grant` | draft §9.11 MUST |

An unbound ID-JAG under `jwt-bearer` that arrives with both a valid proof and a certificate gets one binding, per `preference`. A proof does not stand in for the certificate of an `x5t#S256` ID-JAG. The `requires_sender_constraint` check of row 7 is `require_sender_constraint`, which the Resource AS runs when the grant decision is built (RFC-004 §6).

Draft §9.11.1.2.2 says a `jkt`-bound ID-JAG with no proof is `invalid_grant`. jwt-dpop-grant §5 says a missing proof under `jwt-dpop` is `invalid_dpop_proof`. This RFC follows jwt-dpop-grant, because the request is rejected at rule 1 before the ID-JAG is read. Under `jwt-bearer`, the same case is `invalid_grant` per row 4, which satisfies the draft. Tracked in RFC-001 §12.

### 4.3 Access token binding output

```rust
pub enum AccessTokenBinding {
    Dpop { jkt: String },
    Mtls { x5t_s256: String },
}

impl AccessTokenBinding {
    /// The `cnf` for the access token.
    pub fn confirmation(&self) -> Confirmation;
    /// `DPoP` for a DPoP-bound token, `Bearer` for a certificate-bound one.
    pub fn token_type(&self) -> &'static str;
}
```

`GrantDecision::binding()` (RFC-004 §7) returns this; `ProvenBinding` in `resource_as` is an alias of it. The caller puts it in its access token's `cnf`, or in its introspection response, and answers with `token_type: DPoP` for the DPoP case (RFC 9449 §5). Enforcing the binding at the Resource Server is outside this crate.

## 5. mTLS

```rust
// xaa::mtls
pub fn certificate_thumbprint(certificate_der: &[u8]) -> Result<String, Error>;
pub fn certificate_confirmation(certificate_der: &[u8]) -> Result<Confirmation, Error>;
pub fn certificate_matches(certificate_der: &[u8], cnf: Option<&Confirmation>) -> Result<bool, Error>;
pub fn thumbprint_matches(x5t_s256: &str, cnf: Option<&Confirmation>) -> bool;
```

- The library never sees TLS. On the server side, the caller passes the client certificate's DER after its TLS stack has validated it per RFC 8705 §2 (PKI, or a self-signed certificate registered for the client). The library computes `x5t#S256` and compares.
- The certificate is not parsed. The only check is that the input starts like a DER `SEQUENCE`, which catches PEM text passed by mistake; anything else is `Error::InvalidConfiguration`.
- On the client side, the caller's `HttpClient` presents the certificate. The client passes the same DER to `TokenExchange` (`tls_client_certificate`) so that RFC-003 §5 can detect a silent downgrade (draft §9.11.2.1 SHOULD).
- Binding certificate and authentication certificate are the same certificate (draft §9.11.2). With `tls_client_auth` / `self_signed_tls_client_auth`, that one certificate does both.

## 6. Client DPoP proofs for resource requests

The client uses its DPoP-bound access token at the Resource Server (draft §4.1 step 4). The `client` component can build that proof too:

```rust
impl DpopKey {
    pub async fn proof_for_resource(
        &self,
        method: &http::Method,
        url: &Url,
        access_token: &AccessToken,
        nonce: Option<&str>,
        now: SystemTime,
    ) -> Result<String, Error>; // `proof` plus `ath` (RFC 9449 §4.2)
}
```

The Resource Server role is out of scope, but the proof-side check it needs is here. A Resource Server validates the proof with `validate_dpop_proof`, with `expected_htm` and `expected_htu` set to the request it received, and then calls:

```rust
impl ValidatedDpopProof {
    pub fn ath(&self) -> Option<&str>;
    /// `ath` is present and is the hash of this access token (RFC 9449 §4.3, check 10).
    pub fn is_for_access_token(&self, access_token: &AccessToken) -> bool;
}
```

It must also compare `jkt()` with the key the access token is bound to, and `consume` the proof last. Looking up the access token and its binding is the Resource Server's own job. `examples/resource-as` shows the whole check on its demo API.

## 7. Tests

- **Vectors:** the RFC 9449 proof examples verify (§4.2 Figure 2, §7.1 Figure 13) and give the §6.1 Figure 8 thumbprint; the §7.1 access token hashes to the `ath` of Figure 13; the RFC 8705 Appendix A certificate gives its `x5t#S256`. The RFC 7638 §3.1 thumbprint vector is in `jose` (RFC-002 §14).
- **One negative test per row** of §3 and §4.2, asserting the exact error code, and one test per row of §4.1.
- **Ordering:**
  - A `use_dpop_nonce` rejection consumes neither the proof `jti` nor the ID-JAG `jti`.
  - A retry with the nonce succeeds.
- **Downgrade:** an IdP stub that ignores the proof triggers `Error::BindingDowngrade` in the client (RFC-003 §5).
- **End to end:** client → `idp` → `resource-as` with DPoP (`tests/flow_test.rs`), checking that the issued access token binding matches the key. Certificate binding is tested in each component (client downgrade check, IdP issuance, Resource AS rule 12); there is no cross-role mTLS flow test.

## 8. Spec coverage

| Section | Covered by |
| --- | --- |
| draft §4.4 `jwt-dpop` grant, unauthenticated + sender-constrained | §4.2, RFC-004 §4 rule 11 |
| draft §9.1 Client Authentication trade-off | §4.2 |
| draft §9.11 overview, single mechanism, unsupported `cnf` | §1, §4.1, §4.2 |
| draft §9.11.1 DPoP Key Binding | §1–§4 |
| draft §9.11.1.1 (IdP processing, client inspection) | §3, §4.1, RFC-003 §5 |
| draft §9.11.1.2.1–§9.11.1.2.4 | §4.2 |
| draft §9.11.2, §9.11.2.1, §9.11.2.2 mTLS | §4, §5 |
| jwt-dpop-grant §3, §4.1, §5, §5.1, §5.2, §6, §7.1, §7.2, §8 | §2, §3, §4, RFC-003 §6 |
| identity-chaining §5.2, §5.5 | §4 |
| RFC 9449 §4.2, §4.3, §5, §6.1, §8, §11.1 | §2, §3, §4.3 |
| RFC 8705 §2, §3.1 | §5 |
