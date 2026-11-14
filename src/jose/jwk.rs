//! JWK and JWK Set public keys, and RFC 7638 thumbprints. See RFC-002 §8.

use rsa::signature::Verifier as _;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use super::alg::{KeyFamily, SignatureAlgorithm};
use super::{b64url_decode, b64url_encode};
use crate::error::Error;

/// Members that only a private (or symmetric) key carries (RFC 7518 §6).
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Smallest RSA modulus accepted for signing or verification (RFC 7518 §3.3).
pub(crate) const MIN_RSA_BITS: usize = 2048;

/// The elliptic curves this crate implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
}

impl Curve {
    fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        }
    }

    fn coordinate_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyMaterial {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ec {
        curve: Curve,
        x: Vec<u8>,
        y: Vec<u8>,
    },
}

/// A public JSON Web Key (RFC 7517): `RSA`, or `EC` on `P-256` / `P-384`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    material: KeyMaterial,
    kid: Option<String>,
    alg: Option<String>,
    key_use: Option<String>,
    key_ops: Option<Vec<String>>,
}

impl Jwk {
    /// Parse one JWK.
    ///
    /// Fails with [`Error::PrivateKeyMaterial`] if it carries private members
    /// and with [`Error::MalformedJwk`] if the key type or curve is not one
    /// this crate implements.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_source| Error::MalformedJwk {
                reason: "not valid JSON",
            })?;
        Self::from_value(&value)?.ok_or(Error::MalformedJwk {
            reason: "unsupported key type or curve",
        })
    }

    /// Parse one JWK from a JSON value. `Ok(None)` means the key is well
    /// formed but of a type or curve this crate does not implement.
    pub(crate) fn from_value(value: &Value) -> Result<Option<Self>, Error> {
        let object = value.as_object().ok_or(Error::MalformedJwk {
            reason: "JWK is not a JSON object",
        })?;
        if PRIVATE_MEMBERS
            .iter()
            .any(|name| object.contains_key(*name))
        {
            return Err(Error::PrivateKeyMaterial);
        }
        let kty = required_str(object, "kty")?;
        let material = match kty {
            "RSA" => KeyMaterial::Rsa {
                n: required_b64(object, "n")?,
                e: required_b64(object, "e")?,
            },
            "EC" => {
                let curve = match required_str(object, "crv")? {
                    "P-256" => Curve::P256,
                    "P-384" => Curve::P384,
                    _ => return Ok(None),
                };
                let x = required_b64(object, "x")?;
                let y = required_b64(object, "y")?;
                if x.len() != curve.coordinate_len() || y.len() != curve.coordinate_len() {
                    return Err(Error::MalformedJwk {
                        reason: "EC coordinate has the wrong length for its curve",
                    });
                }
                KeyMaterial::Ec { curve, x, y }
            }
            _ => return Ok(None),
        };
        let key_ops = match object.get("key_ops") {
            None => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(Error::MalformedJwk {
                        reason: "key_ops is not an array of strings",
                    })?,
            ),
            Some(_) => {
                return Err(Error::MalformedJwk {
                    reason: "key_ops is not an array of strings",
                });
            }
        };
        Ok(Some(Self {
            material,
            kid: optional_str(object, "kid")?,
            alg: optional_str(object, "alg")?,
            key_use: optional_str(object, "use")?,
            key_ops,
        }))
    }

    pub(crate) fn from_material(material: KeyMaterial, kid: Option<String>) -> Self {
        Self {
            material,
            kid,
            alg: None,
            key_use: None,
            key_ops: None,
        }
    }

    /// The JWK as a JSON value. Only public members are emitted.
    pub fn to_value(&self) -> Value {
        let mut object = Map::new();
        match &self.material {
            KeyMaterial::Rsa { n, e } => {
                object.insert("kty".to_owned(), Value::from("RSA"));
                object.insert("n".to_owned(), Value::from(b64url_encode(n)));
                object.insert("e".to_owned(), Value::from(b64url_encode(e)));
            }
            KeyMaterial::Ec { curve, x, y } => {
                object.insert("kty".to_owned(), Value::from("EC"));
                object.insert("crv".to_owned(), Value::from(curve.name()));
                object.insert("x".to_owned(), Value::from(b64url_encode(x)));
                object.insert("y".to_owned(), Value::from(b64url_encode(y)));
            }
        }
        if let Some(kid) = &self.kid {
            object.insert("kid".to_owned(), Value::from(kid.as_str()));
        }
        if let Some(alg) = &self.alg {
            object.insert("alg".to_owned(), Value::from(alg.as_str()));
        }
        if let Some(key_use) = &self.key_use {
            object.insert("use".to_owned(), Value::from(key_use.as_str()));
        }
        if let Some(key_ops) = &self.key_ops {
            object.insert("key_ops".to_owned(), Value::from(key_ops.clone()));
        }
        Value::Object(object)
    }

    /// The `kid`, if the key has one.
    pub fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The same key with `kid` set.
    pub fn with_key_id(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The same key marked for signature use with `alg`: `use: sig` and the
    /// algorithm are published so verifiers can pin them.
    pub fn with_algorithm(mut self, alg: SignatureAlgorithm) -> Self {
        self.alg = Some(alg.as_str().to_owned());
        self.key_use = Some("sig".to_owned());
        self
    }

    /// RFC 7638 SHA-256 thumbprint, base64url without padding.
    ///
    /// Hashes the required members in lexicographic order with no whitespace
    /// (RFC 7638 §3.2): `e`, `kty`, `n` for RSA; `crv`, `kty`, `x`, `y` for EC.
    pub fn thumbprint_sha256(&self) -> String {
        // base64url output contains no character that JSON escapes, so the
        // canonical form can be assembled directly.
        let canonical = match &self.material {
            KeyMaterial::Rsa { n, e } => format!(
                r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                b64url_encode(e),
                b64url_encode(n)
            ),
            KeyMaterial::Ec { curve, x, y } => format!(
                r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                curve.name(),
                b64url_encode(x),
                b64url_encode(y)
            ),
        };
        b64url_encode(&Sha256::digest(canonical.as_bytes()))
    }

    pub(crate) fn family(&self) -> KeyFamily {
        match &self.material {
            KeyMaterial::Rsa { .. } => KeyFamily::Rsa,
            KeyMaterial::Ec {
                curve: Curve::P256, ..
            } => KeyFamily::P256,
            KeyMaterial::Ec {
                curve: Curve::P384, ..
            } => KeyFamily::P384,
        }
    }

    /// RFC-002 §4 step 4: the key's own `alg`, `use`, and `key_ops` must not
    /// contradict using it to verify `alg`.
    pub(crate) fn check_usable_for(&self, alg: SignatureAlgorithm) -> Result<(), Error> {
        if self.family() != alg.key_family() {
            return Err(Error::KeyMismatch {
                reason: "key type does not match the algorithm",
            });
        }
        if let Some(key_alg) = &self.alg
            && key_alg != alg.as_str()
        {
            return Err(Error::KeyMismatch {
                reason: "key alg differs from the header alg",
            });
        }
        if let Some(key_use) = &self.key_use
            && key_use != "sig"
        {
            return Err(Error::KeyMismatch {
                reason: "key use is not sig",
            });
        }
        if let Some(key_ops) = &self.key_ops
            && !key_ops.iter().any(|op| op == "verify")
        {
            return Err(Error::KeyMismatch {
                reason: "key_ops does not include verify",
            });
        }
        Ok(())
    }

    /// Verify `signature` over `message` with `alg`. The key family must
    /// already match (`check_usable_for`).
    pub(crate) fn verify_signature(
        &self,
        alg: SignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match &self.material {
            KeyMaterial::Rsa { n, e } => {
                let bits = modulus_bits(n);
                if bits < MIN_RSA_BITS {
                    return Err(Error::WeakKey { bits });
                }
                let key = rsa::PublicKey::new(
                    rsa::BoxedUint::from_be_slice_vartime(n),
                    rsa::BoxedUint::from_be_slice_vartime(e),
                )
                .map_err(|_source| Error::MalformedJwk {
                    reason: "invalid RSA public key",
                })?;
                verify_rsa(&key, alg, message, signature)
            }
            KeyMaterial::Ec { curve, x, y } => {
                let mut sec1 =
                    Vec::with_capacity(x.len().saturating_add(y.len()).saturating_add(1));
                sec1.push(0x04);
                sec1.extend_from_slice(x);
                sec1.extend_from_slice(y);
                match (curve, alg) {
                    (Curve::P256, SignatureAlgorithm::Es256) => {
                        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(
                            |_source| Error::MalformedJwk {
                                reason: "point is not on P-256",
                            },
                        )?;
                        // Fixed-width r || s (RFC 7518 §3.4); DER fails here.
                        let signature = p256::ecdsa::Signature::from_slice(signature)
                            .map_err(|_source| Error::BadSignature)?;
                        key.verify(message, &signature)
                            .map_err(|_source| Error::BadSignature)
                    }
                    (Curve::P384, SignatureAlgorithm::Es384) => {
                        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(
                            |_source| Error::MalformedJwk {
                                reason: "point is not on P-384",
                            },
                        )?;
                        let signature = p384::ecdsa::Signature::from_slice(signature)
                            .map_err(|_source| Error::BadSignature)?;
                        key.verify(message, &signature)
                            .map_err(|_source| Error::BadSignature)
                    }
                    _ => Err(Error::KeyMismatch {
                        reason: "key type does not match the algorithm",
                    }),
                }
            }
        }
    }
}

fn verify_rsa(
    key: &rsa::PublicKey,
    alg: SignatureAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    macro_rules! pkcs1v15 {
        ($digest:ty) => {{
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_source| Error::BadSignature)?;
            rsa::pkcs1v15::VerifyingKey::<$digest>::new(key.clone())
                .verify(message, &signature)
                .map_err(|_source| Error::BadSignature)
        }};
    }
    macro_rules! pss {
        ($digest:ty) => {{
            let signature =
                rsa::pss::Signature::try_from(signature).map_err(|_source| Error::BadSignature)?;
            rsa::pss::VerifyingKey::<$digest>::new(key.clone())
                .verify(message, &signature)
                .map_err(|_source| Error::BadSignature)
        }};
    }
    match alg {
        SignatureAlgorithm::Rs256 => pkcs1v15!(Sha256),
        SignatureAlgorithm::Rs384 => pkcs1v15!(Sha384),
        SignatureAlgorithm::Rs512 => pkcs1v15!(Sha512),
        SignatureAlgorithm::Ps256 => pss!(Sha256),
        SignatureAlgorithm::Ps384 => pss!(Sha384),
        SignatureAlgorithm::Ps512 => pss!(Sha512),
        SignatureAlgorithm::Es256 | SignatureAlgorithm::Es384 => Err(Error::KeyMismatch {
            reason: "key type does not match the algorithm",
        }),
    }
}

/// Bit length of a big-endian unsigned integer, ignoring leading zero bytes.
pub(crate) fn modulus_bits(n: &[u8]) -> usize {
    let mut bytes = n.iter().skip_while(|byte| **byte == 0);
    let Some(first) = bytes.next() else {
        return 0;
    };
    let rest = bytes.count();
    let top_bits =
        usize::try_from(first.leading_zeros()).map_or(0, |zeros| 8_usize.saturating_sub(zeros));
    rest.saturating_mul(8).saturating_add(top_bits)
}

fn required_str<'a>(object: &'a Map<String, Value>, name: &'static str) -> Result<&'a str, Error> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(Error::MalformedJwk {
            reason: "a required member is missing or is not a string",
        })
}

fn optional_str(object: &Map<String, Value>, name: &'static str) -> Result<Option<String>, Error> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(Error::MalformedJwk {
            reason: "an optional member is not a string",
        }),
    }
}

fn required_b64(object: &Map<String, Value>, name: &'static str) -> Result<Vec<u8>, Error> {
    let bytes = b64url_decode(required_str(object, name)?).ok_or(Error::MalformedJwk {
        reason: "a key member is not base64url",
    })?;
    if bytes.is_empty() {
        return Err(Error::MalformedJwk {
            reason: "a key member is empty",
        });
    }
    Ok(bytes)
}

impl serde::Serialize for Jwk {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Jwk {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(&value)
            .map_err(serde::de::Error::custom)?
            .ok_or_else(|| serde::de::Error::custom("unsupported key type or curve"))
    }
}

/// A JWK Set (RFC 7517 §5): the public keys an issuer or client publishes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWK Set document.
    ///
    /// Keys of a type or curve this crate does not implement are skipped, so a
    /// set that also publishes, say, OKP keys is still usable. A key carrying
    /// private members fails the whole set with [`Error::PrivateKeyMaterial`]:
    /// a published set should never contain one, and silently accepting it
    /// would make a leak look normal.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_source| Error::MalformedJwk {
                reason: "JWK Set is not valid JSON",
            })?;
        Self::from_value(&value)
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, Error> {
        let keys = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(Error::MalformedJwk {
                reason: "JWK Set has no keys array",
            })?;
        let mut parsed = Vec::with_capacity(keys.len());
        // RFC 7517 §5: a key this implementation cannot use, or cannot
        // parse, is skipped. One bad entry must not disable the others.
        // Private members are the exception: a published private key is a
        // compromise, and the whole set is refused.
        for key in keys {
            match Jwk::from_value(key) {
                Ok(Some(jwk)) => parsed.push(jwk),
                Err(Error::PrivateKeyMaterial) => return Err(Error::PrivateKeyMaterial),
                Ok(None) | Err(_) => {}
            }
        }
        Ok(Self { keys: parsed })
    }

    /// A set holding exactly these keys.
    pub fn from_keys(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    /// The usable keys.
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// The set as a JSON value: `{"keys":[…]}`.
    pub fn to_value(&self) -> Value {
        let keys: Vec<Value> = self.keys.iter().map(Jwk::to_value).collect();
        let mut object = Map::new();
        object.insert("keys".to_owned(), Value::Array(keys));
        Value::Object(object)
    }

    /// RFC-002 §4 step 3: pick the verification key for a header.
    pub(crate) fn select(&self, kid: Option<&str>, alg: SignatureAlgorithm) -> Result<&Jwk, Error> {
        if let Some(kid) = kid {
            return self
                .keys
                .iter()
                .find(|key| key.kid.as_deref() == Some(kid) && key.family() == alg.key_family())
                .ok_or_else(|| Error::UnknownKeyId {
                    kid: kid.to_owned(),
                });
        }
        // Only keys that could verify this header count: an encryption key
        // or a key pinned to another `alg` is not a candidate.
        let mut compatible = self
            .keys
            .iter()
            .filter(|key| key.check_usable_for(alg).is_ok());
        match (compatible.next(), compatible.next()) {
            (Some(only), None) => Ok(only),
            (None, _) => Err(Error::AmbiguousKey { candidates: 0 }),
            (Some(_), Some(_)) => Err(Error::AmbiguousKey {
                candidates: compatible.count().saturating_add(2),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7638 §3.1.
    const RFC7638_KEY: &str = r#"{
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29"
    }"#;

    const P256_KEY: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"e1"}"#;

    #[test]
    fn rfc7638_thumbprint() {
        let key = Jwk::from_json(RFC7638_KEY.as_bytes()).unwrap();
        assert_eq!(
            key.thumbprint_sha256(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        assert_eq!(key.key_id(), Some("2011-04-29"));
    }

    #[test]
    fn private_members_are_rejected() {
        for member in PRIVATE_MEMBERS {
            let mut value: Value = serde_json::from_str(RFC7638_KEY).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(member.to_owned(), Value::from("AQAB"));
            let err = Jwk::from_value(&value).unwrap_err();
            assert!(matches!(err, Error::PrivateKeyMaterial), "{member}");
        }
    }

    #[test]
    fn set_skips_unsupported_keys_and_fails_on_private_ones() {
        let set = format!(
            r#"{{"keys":[{RFC7638_KEY},{P256_KEY},
                {{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
                {{"kty":"EC","crv":"secp256k1","x":"AA","y":"AA"}}]}}"#
        );
        let parsed = JwkSet::from_json(set.as_bytes()).unwrap();
        assert_eq!(parsed.keys().len(), 2);

        // A key that does not parse is skipped too (RFC 7517 §5).
        let set = format!(
            r#"{{"keys":[{RFC7638_KEY},{{"kty":"RSA","e":"AQAB"}},{{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}},7]}}"#
        );
        assert_eq!(JwkSet::from_json(set.as_bytes()).unwrap().keys().len(), 1);

        let leaked = r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}]}"#;
        assert!(matches!(
            JwkSet::from_json(leaked.as_bytes()).unwrap_err(),
            Error::PrivateKeyMaterial
        ));
    }

    #[test]
    fn ec_coordinate_length_is_checked() {
        let short = r#"{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}"#;
        assert!(matches!(
            Jwk::from_json(short.as_bytes()).unwrap_err(),
            Error::MalformedJwk { .. }
        ));
    }

    #[test]
    fn selection_by_kid_and_without() {
        let set = JwkSet::from_json(format!(r#"{{"keys":[{RFC7638_KEY},{P256_KEY}]}}"#).as_bytes())
            .unwrap();
        assert_eq!(
            set.select(Some("e1"), SignatureAlgorithm::Es256)
                .unwrap()
                .key_id(),
            Some("e1")
        );
        // Right kid, wrong key type for the algorithm.
        assert!(matches!(
            set.select(Some("e1"), SignatureAlgorithm::Rs256)
                .unwrap_err(),
            Error::UnknownKeyId { .. }
        ));
        assert!(matches!(
            set.select(Some("nope"), SignatureAlgorithm::Rs256)
                .unwrap_err(),
            Error::UnknownKeyId { .. }
        ));
        // No kid: exactly one compatible key per family here.
        set.select(None, SignatureAlgorithm::Rs256).unwrap();
        assert!(matches!(
            set.select(None, SignatureAlgorithm::Es384).unwrap_err(),
            Error::AmbiguousKey { candidates: 0 }
        ));
        let two =
            JwkSet::from_json(format!(r#"{{"keys":[{P256_KEY},{P256_KEY}]}}"#).as_bytes()).unwrap();
        assert!(matches!(
            two.select(None, SignatureAlgorithm::Es256).unwrap_err(),
            Error::AmbiguousKey { candidates: 2 }
        ));
    }

    #[test]
    fn jwk_constraints_are_enforced() {
        let key = Jwk::from_json(RFC7638_KEY.as_bytes()).unwrap();
        key.check_usable_for(SignatureAlgorithm::Rs256).unwrap();
        // Key says RS256; header says PS256.
        key.check_usable_for(SignatureAlgorithm::Ps256).unwrap_err();
        key.check_usable_for(SignatureAlgorithm::Es256).unwrap_err();

        let enc = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"enc"}"#;
        assert!(
            Jwk::from_json(enc.as_bytes())
                .unwrap()
                .check_usable_for(SignatureAlgorithm::Es256)
                .is_err()
        );
        let ops = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","key_ops":["sign"]}"#;
        assert!(
            Jwk::from_json(ops.as_bytes())
                .unwrap()
                .check_usable_for(SignatureAlgorithm::Es256)
                .is_err()
        );
    }

    #[test]
    fn modulus_bits_ignores_leading_zeros() {
        assert_eq!(modulus_bits(&[]), 0);
        assert_eq!(modulus_bits(&[0, 0]), 0);
        assert_eq!(modulus_bits(&[0x80, 0]), 16);
        assert_eq!(modulus_bits(&[0, 0x01, 0]), 9);
        let mut n = vec![0u8; 256];
        n[0] = 0xff;
        assert_eq!(modulus_bits(&n), 2048);
    }

    #[test]
    fn serde_round_trip_keeps_public_members() {
        let key = Jwk::from_json(P256_KEY.as_bytes()).unwrap();
        let json = serde_json::to_string(&key).unwrap();
        let back: Jwk = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    /// Without `kid`, only keys that could verify the header are candidates.
    #[test]
    fn select_without_kid_ignores_keys_that_cannot_verify() {
        let mut signing: Value = serde_json::from_str(RFC7638_KEY).unwrap();
        signing.as_object_mut().unwrap().remove("kid");
        let mut encryption = signing.clone();
        encryption["use"] = Value::from("enc");
        let mut other_alg = signing.clone();
        other_alg["alg"] = Value::from("PS256");
        let set = JwkSet::from_value(&serde_json::json!({
            "keys": [signing, encryption, other_alg]
        }))
        .unwrap();
        assert_eq!(set.keys().len(), 3);
        let selected = set.select(None, SignatureAlgorithm::Rs256).unwrap();
        assert_eq!(selected.key_use.as_deref(), None);
        assert_eq!(selected.alg.as_deref(), Some("RS256"));
    }
}
