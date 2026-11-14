//! Compact JWS: parse, verify, sign. See RFC-002 §2, §4, §5, §7.

use std::collections::BTreeMap;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::alg::{AlgorithmPolicy, SignatureAlgorithm};
use super::jwk::{Jwk, JwkSet};
use super::key::JwsSigner;
use super::{b64url_decode, b64url_encode};
use crate::error::Error;

/// `typ` of an ID-JAG (draft §3.1).
pub(crate) const TYP_ID_JAG: &str = "oauth-id-jag+jwt";
/// `typ` of a DPoP proof (RFC 9449 §4.2).
pub(crate) const TYP_DPOP: &str = "dpop+jwt";
/// `typ` of a client-authentication JWT (RFC 10070 §3.2).
pub(crate) const TYP_CLIENT_AUTHENTICATION: &str = "client-authentication+jwt";
/// Types that name a different token and so can never be a client assertion.
const NOT_CLIENT_ASSERTIONS: [&str; 5] =
    [TYP_ID_JAG, TYP_DPOP, "at+jwt", "jwt-bearer+jwt", "id_token"];

/// Limits applied before any decoding.
#[derive(Debug, Clone, Copy)]
pub struct ParseLimits {
    /// Maximum total token length in bytes.
    pub max_len: usize,
}

impl Default for ParseLimits {
    /// 16 KiB.
    fn default() -> Self {
        Self { max_len: 16_384 }
    }
}

/// The protected header of a parsed JWS.
#[derive(Debug, Clone)]
pub struct JoseHeader {
    alg: SignatureAlgorithm,
    typ: Option<String>,
    kid: Option<String>,
    members: Map<String, Value>,
}

impl JoseHeader {
    /// The `alg`. `none` and symmetric algorithms never get this far.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    /// The raw `typ`, if present.
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// The `kid`, if present.
    pub fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Any header member by name.
    ///
    /// `jku`, `x5u`, `jwk`, `x5c`, and `x5t` are readable here but are never
    /// used to choose or fetch a verification key (RFC 8725 §3.10). The one
    /// exception is the `jwk` of a DPoP proof, which is the key being proven.
    pub fn member(&self, name: &str) -> Option<&Value> {
        self.members.get(name)
    }
}

/// A compact JWS whose structure has been checked but whose signature has
/// not. Holding one grants no access to the claims.
#[derive(Debug, Clone)]
pub struct UnverifiedJws<'a> {
    header: JoseHeader,
    signing_input: &'a str,
    signature: Vec<u8>,
    payload: Vec<u8>,
}

impl<'a> UnverifiedJws<'a> {
    /// Check the structure of a compact JWS. See RFC-002 §2 for the rules.
    pub fn parse(token: &'a str, limits: &ParseLimits) -> Result<Self, Error> {
        if token.len() > limits.max_len {
            return Err(Error::TokenTooLong {
                len: token.len(),
                max: limits.max_len,
            });
        }
        let mut segments = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64)) =
            (segments.next(), segments.next(), segments.next())
        else {
            return Err(Error::MalformedJws {
                reason: "fewer than three segments",
            });
        };
        match segments.count() {
            0 => {}
            // header.encrypted_key.iv.ciphertext.tag
            2 => return Err(Error::EncryptedJwtUnsupported),
            _ => {
                return Err(Error::MalformedJws {
                    reason: "not three segments",
                });
            }
        }
        let header_bytes = b64url_decode(header_b64).ok_or(Error::MalformedJws {
            reason: "header is not base64url",
        })?;
        let payload = b64url_decode(payload_b64).ok_or(Error::MalformedJws {
            reason: "payload is not base64url",
        })?;
        let signature = b64url_decode(signature_b64).ok_or(Error::MalformedJws {
            reason: "signature is not base64url",
        })?;
        if signature.is_empty() {
            return Err(Error::MalformedJws {
                reason: "empty signature",
            });
        }
        let header = parse_header(&header_bytes)?;
        // Both segments are ASCII, so this byte length is a char boundary.
        let signing_input_len = header_b64
            .len()
            .checked_add(payload_b64.len())
            .and_then(|len| len.checked_add(1))
            .ok_or(Error::MalformedJws {
                reason: "token length overflow",
            })?;
        let signing_input = token.get(..signing_input_len).ok_or(Error::MalformedJws {
            reason: "signing input is not on a character boundary",
        })?;
        Ok(Self {
            header,
            signing_input,
            signature,
            payload,
        })
    }

    /// The protected header. It is not yet authenticated.
    pub fn header(&self) -> &JoseHeader {
        &self.header
    }

    /// The decoded payload, unauthenticated. Crate-internal: the only public
    /// route to claims is [`verify`].
    pub(crate) fn payload_unverified(&self) -> &[u8] {
        &self.payload
    }
}

fn parse_header(bytes: &[u8]) -> Result<JoseHeader, Error> {
    let members = parse_object_rejecting_duplicates(bytes).map_err(|reason| match reason {
        ObjectParseError::Duplicate => Error::MalformedJws {
            reason: "duplicate header member",
        },
        ObjectParseError::NotAnObject => Error::MalformedJws {
            reason: "header is not a JSON object",
        },
    })?;
    if members.contains_key("crit") {
        return Err(Error::CriticalHeader);
    }
    let alg_text = match members.get("alg") {
        Some(Value::String(alg)) => alg.as_str(),
        Some(_) => {
            return Err(Error::MalformedJws {
                reason: "alg is not a string",
            });
        }
        None => {
            return Err(Error::MalformedJws {
                reason: "header has no alg",
            });
        }
    };
    let alg = SignatureAlgorithm::parse(alg_text).ok_or_else(|| Error::UnsupportedAlgorithm {
        alg: alg_text.to_owned(),
    })?;
    let typ = optional_header_string(&members, "typ")?;
    let kid = optional_header_string(&members, "kid")?;
    Ok(JoseHeader {
        alg,
        typ,
        kid,
        members,
    })
}

fn optional_header_string(
    members: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<String>, Error> {
    match members.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(Error::MalformedJws {
            reason: "a header member that must be a string is not",
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectParseError {
    NotAnObject,
    Duplicate,
}

/// Parse a JSON object, failing on duplicate top-level member names
/// (RFC 7515 §4 lets a parser reject them; this one always does).
pub(crate) fn parse_object_rejecting_duplicates(
    bytes: &[u8],
) -> Result<Map<String, Value>, ObjectParseError> {
    struct NoDuplicates;

    impl<'de> serde::de::Visitor<'de> for NoDuplicates {
        type Value = Result<Map<String, Value>, ObjectParseError>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut members = Map::new();
            let mut duplicate = false;
            while let Some((name, value)) = access.next_entry::<String, Value>()? {
                if members.insert(name, value).is_some() {
                    duplicate = true;
                }
            }
            Ok(if duplicate {
                Err(ObjectParseError::Duplicate)
            } else {
                Ok(members)
            })
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = serde::Deserializer::deserialize_map(&mut deserializer, NoDuplicates)
        .map_err(|_source| ObjectParseError::NotAnObject)?;
    deserializer
        .end()
        .map_err(|_source| ObjectParseError::NotAnObject)?;
    parsed
}

/// The explicit type a JWT must carry in its `typ` header (RFC 8725 §3.11).
#[derive(Debug, Clone, Copy)]
pub enum ExpectedTyp<'a> {
    /// `oauth-id-jag+jwt` (draft §3.1). REQUIRED.
    IdJag,
    /// `dpop+jwt` (RFC 9449 §4.2). REQUIRED.
    DpopProof,
    /// A client-authentication JWT (RFC 10070).
    ///
    /// Accepts `client-authentication+jwt`, a missing `typ` (RFC 10070 says
    /// rejecting untyped assertions is NOT RECOMMENDED), and the more
    /// specific profile-defined types listed in `also_accept`. A `typ` that
    /// names a different token type is always rejected.
    ClientAssertion { also_accept: &'a [String] },
    /// Exactly this type, REQUIRED. For caller-defined token types.
    Exactly(&'a str),
    /// No `typ` rule. For tokens whose type the caller identifies by other
    /// means, such as an IdP checking an ID Token it issued itself.
    Any,
}

impl ExpectedTyp<'_> {
    /// Check a header against this rule. `verify` runs it first; the DPoP
    /// validator also calls it directly to keep the RFC 9449 §4.3 order.
    pub(crate) fn check(&self, header: &JoseHeader) -> Result<(), Error> {
        let got = header.typ().map(normalize_typ);
        let wrong = |expected: &'static str| Error::WrongTyp {
            expected,
            got: header.typ().map(str::to_owned),
        };
        match self {
            Self::IdJag => {
                if got.as_deref() == Some(TYP_ID_JAG) {
                    Ok(())
                } else {
                    Err(wrong(TYP_ID_JAG))
                }
            }
            Self::DpopProof => {
                if got.as_deref() == Some(TYP_DPOP) {
                    Ok(())
                } else {
                    Err(wrong(TYP_DPOP))
                }
            }
            Self::ClientAssertion { also_accept } => match got.as_deref() {
                None | Some(TYP_CLIENT_AUTHENTICATION) => Ok(()),
                Some(other) if NOT_CLIENT_ASSERTIONS.contains(&other) => {
                    Err(wrong(TYP_CLIENT_AUTHENTICATION))
                }
                Some(other) if also_accept.iter().any(|ok| normalize_typ(ok) == other) => Ok(()),
                Some(_) => Err(wrong(TYP_CLIENT_AUTHENTICATION)),
            },
            Self::Exactly(expected) => {
                if got.as_deref() == Some(normalize_typ(expected).as_str()) {
                    Ok(())
                } else {
                    Err(wrong("the caller-specified type"))
                }
            }
            Self::Any => Ok(()),
        }
    }
}

/// Case-insensitive, with an `application/` prefix dropped (RFC 7515 §4.1.9).
fn normalize_typ(typ: &str) -> String {
    let lower = typ.to_ascii_lowercase();
    match lower.strip_prefix("application/") {
        Some(rest) => rest.to_owned(),
        None => lower,
    }
}

/// The raw header `typ` of a compact JWS, without verifying anything.
///
/// The IdP uses this to refuse a `subject_token` that carries the type of a
/// different token (draft §4.3.3). `None` means the token is not a parseable
/// JWS or has no `typ`.
pub fn peek_typ(token: &str) -> Option<String> {
    let (header, _rest) = token.split_once('.')?;
    let members = parse_object_rejecting_duplicates(&b64url_decode(header)?).ok()?;
    members.get("typ")?.as_str().map(str::to_owned)
}

/// The decoded payload of a compact JWS whose `typ` is `oauth-id-jag+jwt`,
/// **without verifying anything** and whatever its `alg`.
///
/// For a party that only forwards the token: the client reads an ID-JAG it
/// cannot verify, which the IdP may have signed with an algorithm this crate
/// does not implement.
#[cfg(any(test, feature = "client"))]
pub(crate) fn id_jag_payload_unverified(
    token: &str,
    limits: ParseLimits,
) -> Result<Vec<u8>, &'static str> {
    if token.len() > limits.max_len {
        return Err("not a compact JWS");
    }
    let mut segments = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err("not a compact JWS");
    };
    if peek_typ(token).map(|typ| normalize_typ(&typ)).as_deref() != Some(TYP_ID_JAG) {
        return Err("typ is not oauth-id-jag+jwt");
    }
    b64url_decode(payload).ok_or("not a compact JWS")
}

/// Claims read from a JWS whose signature has been verified.
///
/// This is the only way to obtain verified claims: there is no public
/// "decode without verify" (RFC-001 §2, principle 6).
#[derive(Debug, Clone)]
pub struct Verified<T> {
    claims: T,
    header: JoseHeader,
    key_thumbprint: String,
}

impl<T> Verified<T> {
    /// The verified claims.
    pub fn claims(&self) -> &T {
        &self.claims
    }

    /// Take the verified claims.
    pub fn into_claims(self) -> T {
        self.claims
    }

    /// The verified header.
    pub fn header(&self) -> &JoseHeader {
        &self.header
    }

    /// The algorithm the signature verified under.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.header.alg
    }

    /// RFC 7638 thumbprint of the key that verified the signature.
    pub fn key_thumbprint(&self) -> &str {
        &self.key_thumbprint
    }

    #[cfg(feature = "resource-as")]
    /// Replace the claims while keeping the verification evidence.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Verified<U> {
        Verified {
            claims: f(self.claims),
            header: self.header,
            key_thumbprint: self.key_thumbprint,
        }
    }
}

/// Verify a JWS against a key set and deserialize its claims.
///
/// Order (RFC-002 §4): `typ`, algorithm allow-list, key selection, JWK
/// constraints, signature, and only then the payload.
pub fn verify<T: DeserializeOwned>(
    jws: &UnverifiedJws<'_>,
    expected_typ: ExpectedTyp<'_>,
    keys: &JwkSet,
    policy: &AlgorithmPolicy,
) -> Result<Verified<T>, Error> {
    expected_typ.check(&jws.header)?;
    let alg = jws.header.alg;
    if !policy.allows(alg) {
        return Err(Error::DisallowedAlgorithm { alg: alg.as_str() });
    }
    let key = keys.select(jws.header.key_id(), alg)?;
    finish_verify(jws, key)
}

/// Verify a JWS against one specific key. Same order as [`verify`], without
/// key selection. Used for DPoP proofs, whose key is the header `jwk`.
pub fn verify_with_key<T: DeserializeOwned>(
    jws: &UnverifiedJws<'_>,
    expected_typ: ExpectedTyp<'_>,
    key: &Jwk,
    policy: &AlgorithmPolicy,
) -> Result<Verified<T>, Error> {
    expected_typ.check(&jws.header)?;
    let alg = jws.header.alg;
    if !policy.allows(alg) {
        return Err(Error::DisallowedAlgorithm { alg: alg.as_str() });
    }
    finish_verify(jws, key)
}

fn finish_verify<T: DeserializeOwned>(
    jws: &UnverifiedJws<'_>,
    key: &Jwk,
) -> Result<Verified<T>, Error> {
    let alg = jws.header.alg;
    key.check_usable_for(alg)?;
    key.verify_signature(alg, jws.signing_input.as_bytes(), &jws.signature)?;
    let claims = serde_json::from_slice(&jws.payload)
        .map_err(|source| Error::MalformedClaims(source.to_string()))?;
    Ok(Verified {
        claims,
        header: jws.header.clone(),
        key_thumbprint: key.thumbprint_sha256(),
    })
}

/// Sign `claims` as a compact JWS.
///
/// The header carries `alg`, `typ` (when given), `kid` (when the signer has
/// one), and the `extra_header` members. Nothing else is emitted.
pub(crate) async fn sign_jws(
    signer: &dyn JwsSigner,
    typ: Option<&str>,
    extra_header: BTreeMap<&'static str, Value>,
    claims: &impl Serialize,
) -> Result<String, Error> {
    let mut header = Map::new();
    header.insert("alg".to_owned(), Value::from(signer.algorithm().as_str()));
    if let Some(typ) = typ {
        header.insert("typ".to_owned(), Value::from(typ));
    }
    if let Some(kid) = signer.key_id() {
        header.insert("kid".to_owned(), Value::from(kid));
    }
    for (name, value) in extra_header {
        header.insert(name.to_owned(), value);
    }
    let header_json = serde_json::to_vec(&Value::Object(header))
        .map_err(|source| Error::Signing(Box::new(source)))?;
    let claims_json =
        serde_json::to_vec(claims).map_err(|source| Error::Signing(Box::new(source)))?;
    let mut token = b64url_encode(&header_json);
    token.push('.');
    token.push_str(&b64url_encode(&claims_json));
    let signature = signer
        .sign(token.as_bytes())
        .await
        .map_err(Error::Signing)?;
    token.push('.');
    token.push_str(&b64url_encode(&signature));
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::PrivateKey;
    use crate::test_support::{
        P256_PEM, RSA_1024_PEM, jwks_of, key_for, other_rsa_key, p256_key, rsa_key, sign, sign_raw,
    };
    use serde_json::json;

    fn limits() -> ParseLimits {
        ParseLimits::default()
    }

    fn id_jag_policy() -> AlgorithmPolicy {
        AlgorithmPolicy::only(&SignatureAlgorithm::ALL)
    }

    #[tokio::test]
    async fn sign_then_verify_round_trips_for_every_algorithm() {
        for alg in SignatureAlgorithm::ALL {
            let key = key_for(alg);
            let token = sign(&key, Some(TYP_ID_JAG), &json!({"sub": "alice"})).await;
            let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
            assert_eq!(jws.header().algorithm(), alg);
            let verified: Verified<Value> = verify(
                &jws,
                ExpectedTyp::IdJag,
                &jwks_of(&[&key]),
                &AlgorithmPolicy::only(&[alg]),
            )
            .unwrap();
            assert_eq!(verified.claims()["sub"], "alice");
            assert_eq!(verified.algorithm(), alg);
            assert_eq!(
                verified.key_thumbprint(),
                key.public_jwk().thumbprint_sha256()
            );
        }
    }

    #[tokio::test]
    async fn emitted_header_is_alg_typ_kid_only() {
        let key = rsa_key();
        let token = sign(&key, Some(TYP_ID_JAG), &json!({})).await;
        let header_b64 = token.split('.').next().unwrap();
        let header: Value = serde_json::from_slice(&b64url_decode(header_b64).unwrap()).unwrap();
        assert_eq!(
            header,
            json!({"alg": "RS256", "kid": "rsa-1", "typ": "oauth-id-jag+jwt"})
        );
    }

    #[test]
    fn length_limit_applies_before_decoding() {
        let token = "a".repeat(100);
        let err = UnverifiedJws::parse(&token, &ParseLimits { max_len: 99 }).unwrap_err();
        assert!(matches!(err, Error::TokenTooLong { len: 100, max: 99 }));
    }

    #[test]
    fn segment_count_rules() {
        for bad in ["", "a", "a.b", "a.b.c.d", "a.b.c.d.e.f"] {
            assert!(
                matches!(
                    UnverifiedJws::parse(bad, &limits()).unwrap_err(),
                    Error::MalformedJws { .. }
                ),
                "{bad}"
            );
        }
        // Five segments is a JWE, reported distinctly.
        assert!(matches!(
            UnverifiedJws::parse("a.b.c.d.e", &limits()).unwrap_err(),
            Error::EncryptedJwtUnsupported
        ));
    }

    #[tokio::test]
    async fn base64_must_be_strict_url_safe_without_padding() {
        let key = p256_key();
        let good = sign(&key, Some(TYP_ID_JAG), &json!({"a": 1})).await;
        UnverifiedJws::parse(&good, &limits()).unwrap();
        let mut parts: Vec<String> = good.split('.').map(str::to_owned).collect();
        for mutate in [
            |segment: &str| format!("{segment}="),
            |segment: &str| format!("{segment} "),
            |segment: &str| format!("+{segment}"),
            |segment: &str| format!("{segment}\n"),
        ] {
            let original = parts[1].clone();
            parts[1] = mutate(&original);
            let token = parts.join(".");
            assert!(
                matches!(
                    UnverifiedJws::parse(&token, &limits()).unwrap_err(),
                    Error::MalformedJws { .. }
                ),
                "{token}"
            );
            parts[1] = original;
        }
    }

    #[tokio::test]
    async fn header_rules() {
        let key = p256_key();
        type Check = fn(&Error) -> bool;
        let cases: [(&str, Check); 8] = [
            (
                r#"{"alg":"none"}"#,
                |e| matches!(e, Error::UnsupportedAlgorithm { alg } if alg == "none"),
            ),
            (r#"{"alg":"HS256"}"#, |e| {
                matches!(e, Error::UnsupportedAlgorithm { .. })
            }),
            (r#"{"typ":"JWT"}"#, |e| {
                matches!(e, Error::MalformedJws { .. })
            }),
            (r#"{"alg":7}"#, |e| matches!(e, Error::MalformedJws { .. })),
            (r#"{"alg":"ES256","alg":"ES256"}"#, |e| {
                matches!(
                    e,
                    Error::MalformedJws {
                        reason: "duplicate header member"
                    }
                )
            }),
            (r#"{"alg":"ES256","crit":["exp"],"exp":1}"#, |e| {
                matches!(e, Error::CriticalHeader)
            }),
            (r#"["ES256"]"#, |e| matches!(e, Error::MalformedJws { .. })),
            (r#"{"alg":"ES256"} trailing"#, |e| {
                matches!(e, Error::MalformedJws { .. })
            }),
        ];
        for (header, expected) in cases {
            let token = sign_raw(&key, header, "{}").await;
            let err = UnverifiedJws::parse(&token, &limits()).unwrap_err();
            assert!(expected(&err), "{header}: {err:?}");
        }
    }

    #[tokio::test]
    async fn typ_is_checked_first_and_normalized() {
        let key = p256_key();
        let keys = jwks_of(&[&key]);
        let policy = id_jag_policy();
        for accepted in [
            "oauth-id-jag+jwt",
            "OAUTH-ID-JAG+JWT",
            "application/oauth-id-jag+jwt",
            "application/OAUTH-ID-JAG+JWT",
        ] {
            let token = sign(&key, Some(accepted), &json!({})).await;
            let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
            assert!(
                verify::<Value>(&jws, ExpectedTyp::IdJag, &keys, &policy).is_ok(),
                "{accepted}"
            );
        }
        for rejected in [None, Some("JWT"), Some("at+jwt"), Some("dpop+jwt")] {
            let token = sign(&key, rejected, &json!({})).await;
            let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
            // An empty key set: the typ check must fail before key selection.
            let err =
                verify::<Value>(&jws, ExpectedTyp::IdJag, &JwkSet::default(), &policy).unwrap_err();
            assert!(
                matches!(err, Error::WrongTyp { .. }),
                "{rejected:?}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn client_assertion_typ_rules() {
        let key = p256_key();
        let keys = jwks_of(&[&key]);
        let policy = id_jag_policy();
        let profile = ["vendor-client+jwt".to_owned()];
        let check = |typ: Option<&'static str>, also_accept: &'static [String]| {
            let key = &key;
            let keys = &keys;
            let policy = &policy;
            async move {
                let token = sign(key, typ, &json!({})).await;
                let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
                verify::<Value>(
                    &jws,
                    ExpectedTyp::ClientAssertion { also_accept },
                    keys,
                    policy,
                )
                .is_ok()
            }
        };
        assert!(check(Some("client-authentication+jwt"), &[]).await);
        assert!(check(None, &[]).await, "untyped assertions are accepted");
        assert!(!check(Some("JWT"), &[]).await);
        for other_token in ["oauth-id-jag+jwt", "dpop+jwt", "at+jwt"] {
            assert!(!check(Some(other_token), &[]).await, "{other_token}");
        }
        let leaked: &'static [String] = Box::leak(Box::new(profile));
        assert!(check(Some("vendor-client+jwt"), leaked).await);
        assert!(!check(Some("vendor-client+jwt"), &[]).await);
    }

    #[tokio::test]
    async fn algorithm_must_be_on_the_allow_list() {
        let key = key_for(SignatureAlgorithm::Ps256);
        let token = sign(&key, Some(TYP_ID_JAG), &json!({})).await;
        let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
        let err = verify::<Value>(
            &jws,
            ExpectedTyp::IdJag,
            &jwks_of(&[&key]),
            &AlgorithmPolicy::default_id_jag(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::DisallowedAlgorithm { alg: "PS256" }));
    }

    #[tokio::test]
    async fn key_selection_errors() {
        let key = rsa_key();
        let other = other_rsa_key();
        let policy = id_jag_policy();
        let token = sign(&key, Some(TYP_ID_JAG), &json!({})).await;
        let jws = UnverifiedJws::parse(&token, &limits()).unwrap();

        // Unknown kid: the caller can refetch the JWKS and retry.
        let err =
            verify::<Value>(&jws, ExpectedTyp::IdJag, &jwks_of(&[&other]), &policy).unwrap_err();
        assert!(matches!(err, Error::UnknownKeyId { kid } if kid == "rsa-1"));

        // Same kid, different key: the signature fails.
        let impostor = other_rsa_key().with_key_id("rsa-1");
        let err =
            verify::<Value>(&jws, ExpectedTyp::IdJag, &jwks_of(&[&impostor]), &policy).unwrap_err();
        assert!(matches!(err, Error::BadSignature));

        // No kid in the header and two compatible keys.
        let no_kid = PrivateKey::from_pkcs8_pem(crate::test_support::RSA_2048_PEM).unwrap();
        let token = sign(&no_kid, Some(TYP_ID_JAG), &json!({})).await;
        let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
        let err = verify::<Value>(&jws, ExpectedTyp::IdJag, &jwks_of(&[&key, &other]), &policy)
            .unwrap_err();
        assert!(matches!(err, Error::AmbiguousKey { candidates: 2 }));
        // One compatible key: selected without a kid.
        verify::<Value>(&jws, ExpectedTyp::IdJag, &jwks_of(&[&key]), &policy).unwrap();
    }

    #[tokio::test]
    async fn algorithm_is_tied_to_the_key_type() {
        // An ES256-signed token whose header claims RS256, verified against an
        // RSA key published under the same kid.
        let ec = p256_key().with_key_id("k");
        let rsa = rsa_key().with_key_id("k");
        let token = sign_raw(
            &ec,
            r#"{"alg":"RS256","typ":"oauth-id-jag+jwt","kid":"k"}"#,
            "{}",
        )
        .await;
        let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
        let err = verify::<Value>(
            &jws,
            ExpectedTyp::IdJag,
            &jwks_of(&[&rsa]),
            &id_jag_policy(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadSignature));
        // Against the EC key the kid matches but the type does not.
        let err = verify::<Value>(&jws, ExpectedTyp::IdJag, &jwks_of(&[&ec]), &id_jag_policy())
            .unwrap_err();
        assert!(matches!(err, Error::UnknownKeyId { .. }));
    }

    #[tokio::test]
    async fn tampered_payload_or_signature_fails() {
        let key = p256_key();
        let keys = jwks_of(&[&key]);
        let token = sign(&key, Some(TYP_ID_JAG), &json!({"sub": "alice"})).await;
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        parts[1] = b64url_encode(br#"{"sub":"mallory"}"#);
        let tampered = parts.join(".");
        let jws = UnverifiedJws::parse(&tampered, &limits()).unwrap();
        assert!(matches!(
            verify::<Value>(&jws, ExpectedTyp::IdJag, &keys, &id_jag_policy()).unwrap_err(),
            Error::BadSignature
        ));
    }

    #[tokio::test]
    async fn der_encoded_ecdsa_signature_is_rejected() {
        use p256::ecdsa::signature::Signer as _;
        use pkcs8::DecodePrivateKey as _;
        let key = p256_key();
        let signing = p256::ecdsa::SigningKey::from_pkcs8_pem(P256_PEM).unwrap();
        let mut token =
            b64url_encode(br#"{"alg":"ES256","typ":"oauth-id-jag+jwt","kid":"p256-1"}"#);
        token.push('.');
        token.push_str(&b64url_encode(b"{}"));
        let der: p256::ecdsa::DerSignature = signing.sign(token.as_bytes());
        token.push('.');
        token.push_str(&b64url_encode(der.as_bytes()));
        let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
        assert!(matches!(
            verify::<Value>(
                &jws,
                ExpectedTyp::IdJag,
                &jwks_of(&[&key]),
                &id_jag_policy()
            )
            .unwrap_err(),
            Error::BadSignature
        ));
    }

    #[test]
    fn rsa_keys_under_2048_bits_are_refused() {
        assert!(matches!(
            PrivateKey::from_pkcs8_pem(RSA_1024_PEM).unwrap_err(),
            Error::WeakKey { bits: 1024 }
        ));
    }

    #[tokio::test]
    async fn weak_rsa_verification_key_is_refused() {
        use pkcs8::DecodePrivateKey as _;
        use rsa::signature::{SignatureEncoding as _, Signer as _};
        use rsa::traits::PublicKeyParts as _;
        let weak = rsa::PrivateKey::from_pkcs8_pem(RSA_1024_PEM).unwrap();
        let jwk = Jwk::from_value(&json!({
            "kty": "RSA",
            "n": b64url_encode(&weak.n_bytes()),
            "e": b64url_encode(&weak.e_bytes()),
        }))
        .unwrap()
        .unwrap();
        let mut token = b64url_encode(br#"{"alg":"RS256","typ":"oauth-id-jag+jwt"}"#);
        token.push('.');
        token.push_str(&b64url_encode(b"{}"));
        let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(weak)
            .try_sign(token.as_bytes())
            .unwrap();
        token.push('.');
        token.push_str(&b64url_encode(&signature.to_bytes()));
        let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
        let err = verify::<Value>(
            &jws,
            ExpectedTyp::IdJag,
            &JwkSet::from_keys(vec![jwk]),
            &id_jag_policy(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::WeakKey { bits: 1024 }), "{err:?}");
    }

    #[tokio::test]
    async fn embedded_keys_are_never_used_for_selection() {
        // The attacker signs with their own key and embeds it as `jwk`.
        let attacker = other_rsa_key();
        let trusted = rsa_key();
        let header = format!(
            r#"{{"alg":"RS256","typ":"oauth-id-jag+jwt","jwk":{},"jku":"https://evil.example/jwks"}}"#,
            attacker.public_jwk().to_value()
        );
        let token = sign_raw(&attacker, &header, "{}").await;
        let jws = UnverifiedJws::parse(&token, &limits()).unwrap();
        assert!(jws.header().member("jwk").is_some());
        assert!(matches!(
            verify::<Value>(
                &jws,
                ExpectedTyp::IdJag,
                &jwks_of(&[&trusted]),
                &id_jag_policy()
            )
            .unwrap_err(),
            Error::BadSignature
        ));
    }

    #[tokio::test]
    async fn peek_typ_reads_the_raw_header() {
        let key = p256_key();
        let token = sign(&key, Some("at+jwt"), &json!({})).await;
        assert_eq!(peek_typ(&token).as_deref(), Some("at+jwt"));
        let token = sign(&key, None, &json!({})).await;
        assert_eq!(peek_typ(&token), None);
        assert_eq!(peek_typ("not a jwt"), None);
    }

    /// The IdP's typ rule must see the type of a token this crate cannot
    /// verify, or an EdDSA access token would pass as an ID Token.
    #[test]
    fn peek_typ_does_not_depend_on_the_algorithm() {
        let header = b64url_encode(br#"{"alg":"EdDSA","typ":"at+jwt","crit":["x"]}"#);
        let token = format!("{header}.e30.c2ln");
        assert_eq!(peek_typ(&token).as_deref(), Some("at+jwt"));
    }

    #[test]
    fn id_jag_payload_is_read_whatever_the_algorithm() {
        let header = b64url_encode(br#"{"alg":"ES512","typ":"oauth-id-jag+jwt"}"#);
        let token = format!("{header}.e30.c2ln");
        assert_eq!(
            id_jag_payload_unverified(&token, ParseLimits::default()).unwrap(),
            b"{}"
        );
        let header = b64url_encode(br#"{"alg":"ES512","typ":"at+jwt"}"#);
        let token = format!("{header}.e30.c2ln");
        assert_eq!(
            id_jag_payload_unverified(&token, ParseLimits::default()).unwrap_err(),
            "typ is not oauth-id-jag+jwt"
        );
        assert_eq!(
            id_jag_payload_unverified("a.b.c.d.e", ParseLimits::default()).unwrap_err(),
            "not a compact JWS"
        );
    }

    #[test]
    fn duplicate_detection_is_top_level_and_exact() {
        assert_eq!(
            parse_object_rejecting_duplicates(br#"{"a":1,"a":2}"#).unwrap_err(),
            ObjectParseError::Duplicate
        );
        parse_object_rejecting_duplicates(br#"{"a":1,"A":2}"#).unwrap();
        assert_eq!(
            parse_object_rejecting_duplicates(b"[]").unwrap_err(),
            ObjectParseError::NotAnObject
        );
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(input in ".{0,300}") {
            drop(UnverifiedJws::parse(&input, &ParseLimits::default()));
            drop(peek_typ(&input));
        }

        #[test]
        fn parse_never_panics_on_jws_shaped_input(
            a in "[A-Za-z0-9_-]{0,60}",
            b in "[A-Za-z0-9_-]{0,60}",
            c in "[A-Za-z0-9_-]{0,60}",
        ) {
            drop(UnverifiedJws::parse(&format!("{a}.{b}.{c}"), &ParseLimits::default()));
        }
    }
}
