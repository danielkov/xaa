# RFC-002: JOSE and ID-JAG core

**Status**: Draft
**Date**: 2026-11-14

## Summary

This RFC defines the shared layer under all three components: compact JWS parse / verify / sign, JWK and JWK Set handling, the typed ID-JAG claim model, client-assertion JWTs, and the replay store. The client, Resource AS, and IdP never touch JOSE directly; they go through the types defined here.

The layer is a deliberately small JOSE subset. It implements what the ID-JAG profile and its normative references need, and rejects everything else at parse time.

---

## 1. Scope

In scope:

- Compact-serialization JWS (RFC 7515 §7.1), signing and verification.
- Asymmetric signature algorithms from RFC 7518 §3 (§3 below).
- JWK / JWK Set public keys (RFC 7517) and JWK SHA-256 thumbprints (RFC 7638).
- The ID-JAG claim set (draft §3.1), including the `saml-nameid` Subject Identifier Format (draft §3.2.1).
- Client-assertion JWTs for `private_key_jwt` (RFC 7523 §2.2 / §3).
- Explicit-type (`typ`) checks (RFC 8725 §3.11).
- The `ReplayStore` trait shared by the Resource AS, IdP, and DPoP layer.

Out of scope: JWE (§12), JSON serialization of JWS, unencoded payloads (RFC 7797), symmetric (`HS*`) algorithms, `none`.

## 2. Compact JWS parsing

```rust
/// A compact JWS whose structure has been checked but whose signature has not.
/// Holding one grants no access to the claims.
pub struct UnverifiedJws<'a> { /* header, signing input, signature, raw payload */ }

pub struct ParseLimits {
    /// Maximum total token length in bytes. Default 16 KiB.
    pub max_len: usize,
}

impl<'a> UnverifiedJws<'a> {
    pub fn parse(token: &'a str, limits: &ParseLimits) -> Result<Self, Error>;
    pub fn header(&self) -> &JoseHeader;
}

impl JoseHeader {
    pub fn algorithm(&self) -> SignatureAlgorithm;
    pub fn typ(&self) -> Option<&str>;
    pub fn key_id(&self) -> Option<&str>;
    /// Any header member by name.
    pub fn member(&self, name: &str) -> Option<&serde_json::Value>;
}
```

Parse rules:

1. Length ≤ `max_len` before any decoding. A longer token fails with `Error::TokenTooLong`.
2. Exactly three `.`-separated segments. Five segments is a JWE and fails with `Error::EncryptedJwtUnsupported`, not a generic parse error, so callers can tell the two apart.
3. Each segment is strict base64url without padding (RFC 7515 §2). Padding, whitespace, or non-alphabet bytes fail. An empty signature fails.
4. The header is a JSON object. Duplicate member names fail (RFC 7515 §4 allows rejecting them; we always do). A `typ` or `kid` that is not a string fails.
5. `alg` is present and names an algorithm from §3. Any other value fails with `Error::UnsupportedAlgorithm`. `none` fails this way unconditionally, whatever any policy says.
6. `crit` present fails with `Error::CriticalHeader`. No extension header parameters are understood, so RFC 7515 §4.1.11 requires rejection.
7. `jku`, `x5u`, `jwk`, `x5c`, and `x5t` are parsed but never used to select or fetch a verification key (RFC 8725 §3.10). The one exception is the `jwk` header of a DPoP proof (RFC-007), which is the key being proven.

Structural failures under rules 2 to 5 (segment count, base64url, header shape, a missing `alg`) share `Error::MalformedJws { reason }`, with a fixed `reason` per rule.

The payload is not deserialized at parse time.

## 3. Algorithms

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    Rs256, // mandatory to implement (draft §3, RFC 7523 §5)
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256, // SHOULD be supported by the Resource AS (draft §3)
    Es384,
}

pub struct AlgorithmPolicy { /* allow-list */ }

impl AlgorithmPolicy {
    /// RS256 + ES256.
    pub fn default_id_jag() -> Self;
    pub fn only(algs: &[SignatureAlgorithm]) -> Self;
    pub fn allows(&self, alg: SignatureAlgorithm) -> bool;
    pub fn algorithms(&self) -> &[SignatureAlgorithm];
}
```

- Every verification takes an `AlgorithmPolicy`. The Resource AS holds one per trusted issuer (draft §4.4.1, RFC 8725 §3.1). An `alg` that is not on the list fails with `Error::DisallowedAlgorithm`.
- Each algorithm is tied to one key type: `RS*` / `PS*` to RSA keys, `ES256` to P-256, `ES384` to P-384. A header `alg` that does not match the selected key's type fails with `Error::KeyMismatch` before any cryptography runs. This rules out algorithm-confusion attacks.
- RSA keys under 2048 bits fail with `Error::WeakKey` for both signing and verification (RFC 7518 §3.3).
- ECDSA signatures use the JOSE fixed-width `r || s` encoding (RFC 7518 §3.4), not DER. Signatures of the wrong length fail with `Error::BadSignature`.
- No `HS*`. The ID-JAG trust model has no shared secret between the IdP and the Resource AS, and accepting HMAC would open the classic public-key-as-HMAC-secret confusion.

## 4. Verification

```rust
pub struct Verified<T> { /* claims, header, thumbprint of the key used */ }

impl<T> Verified<T> {
    pub fn claims(&self) -> &T;
    pub fn into_claims(self) -> T;
    pub fn header(&self) -> &JoseHeader;
    pub fn algorithm(&self) -> SignatureAlgorithm;
    /// RFC 7638 thumbprint of the key that verified the signature.
    pub fn key_thumbprint(&self) -> &str;
}

pub fn verify<T: DeserializeOwned>(
    jws: &UnverifiedJws<'_>,
    expected_typ: ExpectedTyp<'_>,
    keys: &JwkSet,
    policy: &AlgorithmPolicy,
) -> Result<Verified<T>, Error>;

pub fn verify_with_key<T: DeserializeOwned>(
    jws: &UnverifiedJws<'_>,
    expected_typ: ExpectedTyp<'_>,
    key: &Jwk,
    policy: &AlgorithmPolicy,
) -> Result<Verified<T>, Error>;
```

Order:

1. `typ` check (§5).
2. `alg` is in `policy`.
3. Key selection. If the header has a `kid`, use the key in `keys` with that `kid` whose type matches `alg`. If there is no `kid`, use the single key compatible with `alg`; zero or several such keys fail with `Error::AmbiguousKey`. An unknown `kid` fails with `Error::UnknownKeyId`. The caller can then refetch the JWKS once and retry, which handles key rotation without the library holding a cache.
   Without a `kid`, only keys that could verify the header are candidates: a key with `use` other than `sig`, with `key_ops` lacking `verify`, or pinned to a different `alg` is not counted.
4. JWK constraints. If the key's `alg` is present it must equal the header `alg`. If `use` is present it must be `sig`. If `key_ops` is present it must contain `verify`. A violation fails with `Error::KeyMismatch`.
5. Signature over the ASCII signing input. A signature that does not verify fails with `Error::BadSignature`.
6. Only then is the payload deserialized into `T`. A payload that does not deserialize fails with `Error::MalformedClaims`.

`verify_with_key` runs the same steps against one specific `Jwk`, skipping key selection. It exists for DPoP proofs, whose verification key is the proof's own `jwk` header (RFC-007 §3).

`Verified<T>` is the only way to read verified claims, which is the structural property behind RFC-001 §2, principle 6. There is no public "decode without verify". The client's inspection of its own ID-JAG (RFC-003 §5) goes through a separate `IdJagPeek` type that is never accepted where a `Verified` is required.

## 5. Explicit typing

```rust
pub enum ExpectedTyp<'a> {
    IdJag,                                         // "oauth-id-jag+jwt" (draft §3.1)
    DpopProof,                                     // "dpop+jwt" (RFC 9449 §4.2)
    ClientAssertion { also_accept: &'a [String] }, // see §9
    Exactly(&'a str),                              // a caller-defined type, REQUIRED
    Any,                                           // no `typ` rule
}
```

`typ` comparison is case-insensitive, and an `application/` prefix is accepted and ignored (RFC 7515 §4.1.9). For `IdJag`, `DpopProof`, and `Exactly` the header is REQUIRED; if it is missing or different, verification fails with `Error::WrongTyp`.

`Any` exists for tokens whose type the caller identifies by other means. The one use in this crate is an IdP verifying an ID Token it issued itself (RFC-005 §4): OIDC does not require a `typ` on ID Tokens.

`peek_typ(token) -> Option<String>` exposes the raw header `typ` without verification. The IdP uses it to reject a `subject_token` that carries the type of a different token (draft §4.3.3, RFC-005 §4.2).

## 6. ID-JAG claims

```rust
#[derive(Debug, Clone)]
pub struct IdJagClaims {
    pub iss: Issuer,
    pub sub: String,
    pub aud: Audience,
    pub client_id: String,
    pub jti: String,
    pub exp: NumericDate,
    pub iat: NumericDate,
    pub resource: Option<Resources>,
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub act: Option<Actor>,
    pub sub_id: Option<SubjectIdentifier>,
    pub tenant: Option<String>,
    pub aud_tenant: Option<String>,
    pub aud_sub: Option<String>,
    pub email: Option<String>,
    pub auth_time: Option<NumericDate>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub cnf: Option<Confirmation>,
    pub nbf: Option<NumericDate>,
    /// Any other claim. Draft §3.1 allows any claim valid in an ID Token.
    pub extra: BTreeMap<String, serde_json::Value>,
}
```

`IdJagClaims::from_object(object)` applies the shape rules below to a JSON object and returns the specific error (`Error::MissingClaim`, `Error::InvalidClaim`, `Error::TransientNameId`). The Resource AS verifies into a JSON object and then calls it, so each rule keeps its own error (RFC-004 §4). The serde `Deserialize` impl applies the same rules, but through `verify::<IdJagClaims>` a failure surfaces as `Error::MalformedClaims` carrying the message. `to_object()` is the inverse.

Shape rules applied at deserialization (draft §3.1 unless noted):

| Claim | Rule |
| --- | --- |
| `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, `iat` | REQUIRED. A missing claim fails with `Error::MissingClaim { name }`. |
| `aud` | A string or an array of strings. The ID-JAG rule that an array has exactly one element is enforced by the Resource AS (RFC-004 §4). The type preserves which form arrived. |
| `resource` | A string, or a non-empty JSON array of unique strings. An empty array or duplicate entries fail. Values are kept byte-for-byte: they are compared by simple string comparison (draft §4.3, RFC 3986 §6.2.1), never normalized. |
| `scope` | A space-separated string. Each token must match the RFC 6749 §3.3 `scope-token` grammar. Order and the original string are preserved. |
| `authorization_details` | A JSON array of objects, each with a string `type` (RFC 9396 §2). Common fields (`locations`, `actions`, `datatypes`, `identifier`, `privileges`) are typed; everything else is kept as JSON. |
| `cnf` | Exactly one confirmation member, either `jkt` (RFC 9449 §6.1) or `x5t#S256` (RFC 8705 §3.1). Both together fail (draft §9.11, jwt-dpop-grant §3). Any other shape, including a known member next to an unknown one, deserializes as `Confirmation::Unsupported`, which the Resource AS must reject (RFC-004 §4). |
| `sub_id` | An RFC 9493 Subject Identifier. `saml-nameid` (draft §3.2.1) is typed (below). Other registered formats are typed; unknown formats are kept as `SubjectIdentifier::Other`. |
| `act` | An RFC 8693 §4.1 actor object, with recursion depth capped at 8. |
| NumericDate claims | Any non-negative JSON number. RFC 7519 §2 allows non-integer values, so `1311280970.5` is valid. The value is parsed from the JSON number into a `Duration` since the epoch, with no float comparisons, and values beyond year 9999 fail. Emitted values are always integers. |

```rust
pub struct SamlNameId {
    pub issuer: String,             // REQUIRED
    pub nameid: String,             // REQUIRED
    pub nameid_format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub sp_provided_id: Option<String>,
}
```

A `saml-nameid` value whose `nameid_format` is `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` fails at deserialization with `Error::TransientNameId` (draft §3.2.2, Stability). The same check guards the IdP builder (RFC-005 §5.3).

## 7. Signing

```rust
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, BoxError>> + Send + 'a>>;

pub trait JwsSigner: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn key_id(&self) -> Option<&str>;
    fn sign<'a>(&'a self, signing_input: &'a [u8]) -> SignFuture<'a>;
}

pub struct PrivateKey { /* RSA, P-256, or P-384 */ }

impl PrivateKey {
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error>;
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error>;
    /// A fresh P-256 key, the usual choice for DPoP (RFC-007 §2).
    pub fn generate_p256() -> Self;
    /// A fresh key for `algorithm`: P-256, P-384, or 3072-bit RSA.
    pub fn generate(algorithm: SignatureAlgorithm) -> Self;
    /// RSA keys choose between `RS*` and `PS*`; the default is `RS256`.
    pub fn with_algorithm(self, algorithm: SignatureAlgorithm) -> Result<Self, Error>;
    pub fn with_key_id(self, kid: impl Into<String>) -> Self;
    pub fn public_jwk(&self) -> Jwk;
}

impl JwsSigner for PrivateKey { /* … */ }
```

- `sign` is async so that HSM- and KMS-backed keys implement the trait directly. The built-in `PrivateKey` resolves immediately.
- The future is boxed so the trait is object-safe. Configuration holds signers as `Arc<dyn JwsSigner>` (RFC-003 §1), which a `-> impl Future` method would not allow. One allocation per signature is negligible next to the signature itself.
- Emitted headers are `alg`, `typ` (when the token type defines one), and `kid` (when the signer has one). Nothing else is emitted.
- Private key material is zeroized on drop and never appears in `Debug` output.
- Import fails with `Error::InvalidPrivateKey` for anything that is not a PKCS#8 RSA, P-256, or P-384 key, and with `Error::WeakKey` for an RSA key under 2048 bits. An imported key signs with `RS256`, `ES256`, or `ES384` by key type until `with_algorithm` says otherwise; `with_algorithm` fails with `Error::KeyMismatch` if the algorithm does not fit the key type.
- A signer error surfaces as `Error::Signing`.

## 8. JWK and JWK Set

```rust
pub struct Jwk { /* kty, crv, n/e or x/y, kid, alg, use, key_ops */ }
pub struct JwkSet { /* keys */ }

impl JwkSet {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error>;
    /// A set holding exactly these keys.
    pub fn from_keys(keys: Vec<Jwk>) -> Self;
    pub fn keys(&self) -> &[Jwk];
    /// `{"keys":[…]}`
    pub fn to_value(&self) -> serde_json::Value;
}

impl Jwk {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error>;
    pub fn to_value(&self) -> serde_json::Value;
    pub fn key_id(&self) -> Option<&str>;
    pub fn with_key_id(self, kid: impl Into<String>) -> Self;
    /// Publishes `alg` and `use: sig` so verifiers can pin them.
    pub fn with_algorithm(self, alg: SignatureAlgorithm) -> Self;
    /// RFC 7638 SHA-256 thumbprint, base64url without padding.
    pub fn thumbprint_sha256(&self) -> String;
}
```

- `RSA` and `EC` (`P-256`, `P-384`) public keys are supported. In a JWK Set, keys with other `kty` or `crv` values are skipped, not rejected, so a JWKS that also publishes OKP keys is still usable. `Jwk::from_json` on such a key alone fails with `Error::MalformedJwk`, as does any key or set that is not well-formed.
- A key in a JWK Set that does not parse (a missing member, a wrong-length coordinate) is skipped the same way (RFC 7517 §5). Private members are the exception and fail the whole set.
- A JWK carrying private or symmetric members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) fails with `Error::PrivateKeyMaterial`. A published key set should never contain them, and a parser that silently accepts them makes leaks look normal.
- A server publishes its keys with `JwkSet::from_keys(vec![key.public_jwk()])` (RFC-005 §11). `PrivateKey::public_jwk()` carries the key's `kid`; only public members are ever emitted.
- Thumbprints use the RFC 7638 §3.2 required members in lexicographic order (`e`, `kty`, `n` for RSA; `crv`, `kty`, `x`, `y` for EC).
- No fetching or caching here; that is RFC-006 §5.

## 9. Client assertions (`private_key_jwt`)

Used by the client to authenticate at the IdP and the Resource AS (RFC-003 §1), and by those servers to verify it (RFC-004 §3, RFC-005 §3).

```rust
pub async fn build_client_assertion(
    signer: &dyn JwsSigner,
    client_id: &str,
    server: &Issuer,
    now: SystemTime,
) -> Result<ClientAssertion, Error>;

pub struct ClientAssertionPolicy {
    /// Upper bound on `exp - iat`. Default 5 minutes.
    pub max_lifetime: Duration,
    /// Profile-defined `typ` values accepted as well.
    pub also_accept_typ: Vec<String>,
}

pub struct ClientAssertionContext<'a> {
    pub client_id: &'a str,
    /// This server's own issuer identifier: the only accepted `aud`.
    pub server: &'a Issuer,
    pub keys: &'a JwkSet,
    pub algorithms: &'a AlgorithmPolicy,
    pub policy: &'a ClientAssertionPolicy,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// The `iss` of a client assertion, read without verifying anything.
pub fn client_assertion_issuer_unverified(assertion: &ClientAssertion) -> Result<String, Error>;

pub async fn verify_client_assertion(
    assertion: &ClientAssertion,
    context: ClientAssertionContext<'_>,
    replay: &dyn ReplayStore,
) -> Result<(), Error>;
```

These live in the `client_auth` module. A server needs the claimed `client_id` before it can look up that client's keys; `client_assertion_issuer_unverified` gives it, and the value is untrusted until `verify_client_assertion` succeeds for it.

Build (client):

- `iss` = `sub` = the client's `client_id` at that server.
- Header `typ: client-authentication+jwt` (RFC 10070 §3.2 SHOULD).
- `aud` = the server's issuer identifier as the sole value (RFC 10070 MUST). The token endpoint URL MUST NOT be used. This is also why the relay attack in draft §9.5 matters: an assertion with the legitimate `aud` can be replayed by a malicious token endpoint (RFC-006 §3).
- `jti`: 128 bits from the OS RNG. `exp`: `now` + 60 s. `iat`: `now`.

Verify (server), in this order:

- Signature against the client's registered JWK Set with the server's `AlgorithmPolicy`.
- `iss` = `sub` = the claimed `client_id`.
- `aud` is the server's own issuer identifier as the sole value, by simple string comparison. Anything else, including the token endpoint URL or an array with more entries, is rejected (RFC 10070 MUST). There is no legacy opt-in, because the RFC forbids accepting it.
- `exp` within skew, `iat` and `nbf` (when present) not in the future beyond skew, and `exp - iat` ≤ `max_lifetime` (default 5 min). Without an `iat`, `exp` may be at most `max_lifetime` ahead of `now`.
- `jti` is REQUIRED and is consumed through `ReplayStore` (§10) under `ReplayNamespace::ClientAssertion`. This runs last, so a failed assertion does not burn its `jti`.

A broken rule fails with `Error::InvalidClientAssertion { reason }`. The time checks use `Error::Expired` and `Error::NotYetValid`, a second presentation is `Error::Replayed`, and a store failure is `Error::ReplayStore`.

`ExpectedTyp::ClientAssertion` accepts `client-authentication+jwt`, a missing `typ` (RFC 10070 says rejecting untyped assertions is NOT RECOMMENDED), and more specific profile-defined types the caller lists in `also_accept`. Every other `typ` is rejected. A `typ` that names a different token type (`oauth-id-jag+jwt`, `dpop+jwt`, `at+jwt`, `jwt-bearer+jwt`, `id_token`) is rejected even if the caller lists it, because those can never be client assertions.

## 10. Replay store

```rust
pub enum ReplayNamespace<'a> {
    IdJag { issuer: &'a str },
    ClientAssertion { client_id: &'a str },
    DpopProof { jkt: &'a str },
}

pub enum ReplayOutcome { Fresh, Replayed }

pub trait ReplayStore: Send + Sync {
    /// Atomically record `id` in `ns` until `expires_at` and report whether it was already present.
    fn check_and_insert<'a>(
        &'a self,
        ns: ReplayNamespace<'a>,
        id: &'a str,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> ReplayFuture<'a>; // Pin<Box<dyn Future<Output = Result<ReplayOutcome, BoxError>> + Send + 'a>>
}

pub struct InMemoryReplayStore { /* bounded; single-process only */ }

impl InMemoryReplayStore {
    /// Holds at most `capacity` unexpired identifiers.
    pub fn new(capacity: usize) -> Self;
}
```

- The future is boxed so the store can be passed as `&dyn ReplayStore` (RFC-004 §4).
- `check_and_insert` must be atomic. Two concurrent presentations of the same `jti` must have exactly one `Fresh` winner. Shared backends implement this as a Redis `SET NX PX` or a SQL insert on a unique key.
- Callers consult the store only after every other check has passed, so forged or malformed tokens never fill it. jwt-dpop-grant §5.1 also makes this a correctness requirement: a request rejected for a missing or stale DPoP nonce must not burn the ID-JAG's `jti`.
- A store error fails closed. `InMemoryReplayStore` returns one when it is full of unexpired entries, rather than evicting one.

## 11. Secret handling

Draft §9.2 lists subject tokens, ID-JAGs, and access tokens as high-value credentials that must not leak into logs.

- `IdToken`, `RefreshToken`, `IdJag`, `AccessToken`, `ClientSecret`, and `ClientAssertion` are distinct newtypes over `Zeroizing<String>`. `SamlAssertion` holds the XML bytes in a `Zeroizing<Vec<u8>>`.
- Each is built with `new(..)`. None implements `Display`. `Debug` prints the type name and length only.
- Exposing the raw value takes an explicit `.expose_secret()` call, so leaks show up in review.
- `ct_eq(&self, other: &str)` compares a presented credential with a stored one in constant time with respect to the contents. Servers use it to check a `client_secret`, instead of `==` on exposed strings.

## 12. Out of scope for v0.1

- JWE-encrypted ID-JAGs. Draft §4.4.3 lists "decryption" among `invalid_grant` causes but defines no encryption profile. The distinct `EncryptedJwtUnsupported` error keeps the door open.
- `EdDSA`. It can be added without API change because `SignatureAlgorithm` is `#[non_exhaustive]`.
- `client_secret_jwt` (HMAC client assertions).

## 13. Hardening summary

| Threat | Defense |
| --- | --- |
| `alg: none` | Rejected at parse, unconditionally. |
| Algorithm confusion (RSA public key as HMAC secret, RS↔ES swap) | No `HS*`; each `alg` is tied to a key type; per-issuer allow-list. |
| Attacker-chosen keys (`jku`, `x5u`, embedded `jwk`) | Never used for key selection. |
| Token-type confusion (ID Token, access token, or DPoP proof as ID-JAG) | Required `typ`, compared before anything else. |
| Unknown critical extensions | `crit` rejected. |
| Oversized or malformed input | Length cap before decode; strict base64url; duplicate JSON members rejected. |
| Replay | Atomic `ReplayStore`, consulted last. |
| Credential leakage | Secret newtypes without `Display`; redacted `Debug`; zeroize. |

## 14. Tests

- **Known answers:** the RFC 7638 §3.1 thumbprint. There are no RFC 7515 or RFC 7520 signature vectors; signatures are covered by the sign→verify round trip for every algorithm and by the RFC 9449 example proofs (RFC-007 §7).
- **Negative cases**, one test per §2–§9 rule: five-segment input, padded base64, duplicate header members, `none`, `crit`, `alg`/key type mismatch, a 1024-bit RSA key, DER-encoded ECDSA, missing `typ`, `application/OAUTH-ID-JAG+JWT` accepted, an empty `resource` array, a duplicate resource, a bad scope token, a `cnf` with both members, a transient NameID, a fractional `exp` accepted, a negative `exp` rejected, a JWKS with `d`, an unknown `kid`, and two keys without a `kid`.
- **Property:** `parse` never panics on arbitrary bytes (proptest), and sign→verify round-trips for every algorithm.
- **Fuzz:** `fuzz_id_jag_decode` drives §2 parse plus §6 claim deserialization.

## 15. Spec coverage

| Source | Section | Covered by |
| --- | --- | --- |
| draft-06 | §3 (RS256 MTI, ES256 SHOULD) | §3 |
| draft-06 | §3.1 claims, `typ` | §5, §6 |
| draft-06 | §3.2.1 `saml-nameid` format | §6 |
| draft-06 | §3.2.2 Stability (no transient) | §6; producer side in RFC-005 §5.3 |
| draft-06 | §11.1 media type `oauth-id-jag+jwt` | §5 |
| draft-06 | §11.5 `resource`, `aud_tenant` claims | §6 |
| draft-06 | §11.6 `saml-nameid` format registration | §6 |
| RFC 8725 | §3.1, §3.10, §3.11 | §3, §2, §5 |
| RFC 7519 | §2 NumericDate | §6 |
| RFC 7523 / RFC 10070 | §2.2, §3 client assertions | §9 |
| jwt-dpop-grant-02 | §3 single `cnf` member | §6 |
| jwt-dpop-grant-02 | §5.1 `jti` ordering | §10 |
