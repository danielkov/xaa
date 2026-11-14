//! Signing keys. See RFC-002 §7.

use std::future::Future;
use std::pin::Pin;

use pkcs8::DecodePrivateKey as _;
use rsa::Generate as _;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::traits::PublicKeyParts as _;
use sha2::{Sha256, Sha384, Sha512};

use super::alg::{KeyFamily, SignatureAlgorithm};
use super::jwk::{Curve, Jwk, KeyMaterial, MIN_RSA_BITS, modulus_bits};
use crate::error::Error;
use crate::http::BoxError;

/// The future returned by [`JwsSigner::sign`].
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, BoxError>> + Send + 'a>>;

/// Something that can produce JWS signatures.
///
/// `sign` is asynchronous so that HSM- and KMS-backed keys implement the
/// trait directly. The built-in [`PrivateKey`] resolves immediately. The
/// trait is object-safe: configuration holds signers as `Arc<dyn JwsSigner>`.
pub trait JwsSigner: Send + Sync {
    /// The algorithm this signer produces. It becomes the header `alg`.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The key identifier to emit as the header `kid`, if any.
    fn key_id(&self) -> Option<&str>;

    /// Sign the ASCII JWS signing input (`BASE64URL(header) || '.' ||
    /// BASE64URL(payload)`) and return the raw JWS signature: the
    /// PKCS#1 / PSS octets for RSA, or fixed-width `r || s` for ECDSA
    /// (RFC 7518 §3.4), never DER.
    fn sign<'a>(&'a self, signing_input: &'a [u8]) -> SignFuture<'a>;
}

enum Inner {
    Rsa(Box<rsa::PrivateKey>),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

/// An in-process private key: RSA (2048 bits or more), P-256, or P-384.
///
/// The key material is zeroized on drop by the underlying key types and never
/// appears in `Debug` output.
pub struct PrivateKey {
    inner: Inner,
    algorithm: SignatureAlgorithm,
    kid: Option<String>,
}

impl PrivateKey {
    /// Import a PKCS#8 PEM private key (`-----BEGIN PRIVATE KEY-----`).
    ///
    /// The algorithm defaults to `RS256`, `ES256`, or `ES384` by key type.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        if let Ok(key) = rsa::PrivateKey::from_pkcs8_pem(pem) {
            return Self::from_rsa(key);
        }
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::from_inner(
                Inner::P256(key),
                SignatureAlgorithm::Es256,
            ));
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::from_inner(
                Inner::P384(key),
                SignatureAlgorithm::Es384,
            ));
        }
        Err(Error::InvalidPrivateKey {
            reason: "not a PKCS#8 PEM RSA, P-256, or P-384 private key",
        })
    }

    /// Import a PKCS#8 DER private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        if let Ok(key) = rsa::PrivateKey::from_pkcs8_der(der) {
            return Self::from_rsa(key);
        }
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::from_inner(
                Inner::P256(key),
                SignatureAlgorithm::Es256,
            ));
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::from_inner(
                Inner::P384(key),
                SignatureAlgorithm::Es384,
            ));
        }
        Err(Error::InvalidPrivateKey {
            reason: "not a PKCS#8 DER RSA, P-256, or P-384 private key",
        })
    }

    /// Generate a fresh P-256 key from the operating system RNG. This is the
    /// usual choice for a DPoP key (RFC-007 §2).
    pub fn generate_p256() -> Self {
        let key = p256::ecdsa::SigningKey::generate_from_rng(&mut rand::rng());
        Self::from_inner(Inner::P256(key), SignatureAlgorithm::Es256)
    }

    /// Generate a fresh key for `algorithm` from the operating system RNG:
    /// P-256 for `ES256`, P-384 for `ES384`, and a 3072-bit RSA key for the
    /// `RS*` / `PS*` algorithms. RSA generation takes noticeably longer.
    pub fn generate(algorithm: SignatureAlgorithm) -> Self {
        let mut rng = rand::rng();
        let inner = match algorithm.key_family() {
            KeyFamily::Rsa => Inner::Rsa(Box::new(rsa::PrivateKey::generate_from_rng(&mut rng))),
            KeyFamily::P256 => Inner::P256(p256::ecdsa::SigningKey::generate_from_rng(&mut rng)),
            KeyFamily::P384 => Inner::P384(p384::ecdsa::SigningKey::generate_from_rng(&mut rng)),
        };
        Self::from_inner(inner, algorithm)
    }

    fn from_rsa(key: rsa::PrivateKey) -> Result<Self, Error> {
        let bits = modulus_bits(&key.n_bytes());
        if bits < MIN_RSA_BITS {
            return Err(Error::WeakKey { bits });
        }
        Ok(Self::from_inner(
            Inner::Rsa(Box::new(key)),
            SignatureAlgorithm::Rs256,
        ))
    }

    fn from_inner(inner: Inner, algorithm: SignatureAlgorithm) -> Self {
        Self {
            inner,
            algorithm,
            kid: None,
        }
    }

    fn family(&self) -> KeyFamily {
        match self.inner {
            Inner::Rsa(_) => KeyFamily::Rsa,
            Inner::P256(_) => KeyFamily::P256,
            Inner::P384(_) => KeyFamily::P384,
        }
    }

    /// The same key, signing with `algorithm`. Fails if the algorithm does
    /// not match the key type: only an RSA key has a choice (`RS*` / `PS*`).
    pub fn with_algorithm(mut self, algorithm: SignatureAlgorithm) -> Result<Self, Error> {
        if algorithm.key_family() != self.family() {
            return Err(Error::KeyMismatch {
                reason: "key type does not match the algorithm",
            });
        }
        self.algorithm = algorithm;
        Ok(self)
    }

    /// The same key with `kid` set. It is emitted in JWS headers and in
    /// [`public_jwk`](Self::public_jwk).
    pub fn with_key_id(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The public half as a JWK, carrying this key's `kid` if it has one.
    pub fn public_jwk(&self) -> Jwk {
        let material = match &self.inner {
            Inner::Rsa(key) => KeyMaterial::Rsa {
                n: key.n_bytes().into_vec(),
                e: key.e_bytes().into_vec(),
            },
            Inner::P256(key) => ec_material(Curve::P256, &key.verifying_key().to_sec1_bytes()),
            Inner::P384(key) => ec_material(Curve::P384, &key.verifying_key().to_sec1_bytes()),
        };
        Jwk::from_material(material, self.kid.clone())
    }

    fn sign_now(&self, message: &[u8]) -> Result<Vec<u8>, BoxError> {
        macro_rules! pkcs1v15 {
            ($key:expr, $digest:ty) => {{
                let signature = rsa::pkcs1v15::SigningKey::<$digest>::new((**$key).clone())
                    .try_sign(message)?;
                Ok(signature.to_bytes().into_vec())
            }};
        }
        macro_rules! pss {
            ($key:expr, $digest:ty) => {{
                let signature =
                    rsa::pss::SigningKey::<$digest>::new((**$key).clone()).try_sign(message)?;
                Ok(signature.to_bytes().into_vec())
            }};
        }
        match (&self.inner, self.algorithm) {
            (Inner::Rsa(key), SignatureAlgorithm::Rs256) => pkcs1v15!(key, Sha256),
            (Inner::Rsa(key), SignatureAlgorithm::Rs384) => pkcs1v15!(key, Sha384),
            (Inner::Rsa(key), SignatureAlgorithm::Rs512) => pkcs1v15!(key, Sha512),
            (Inner::Rsa(key), SignatureAlgorithm::Ps256) => pss!(key, Sha256),
            (Inner::Rsa(key), SignatureAlgorithm::Ps384) => pss!(key, Sha384),
            (Inner::Rsa(key), SignatureAlgorithm::Ps512) => pss!(key, Sha512),
            (Inner::P256(key), SignatureAlgorithm::Es256) => {
                let signature: p256::ecdsa::Signature = key.try_sign(message)?;
                Ok(signature.to_bytes().to_vec())
            }
            (Inner::P384(key), SignatureAlgorithm::Es384) => {
                let signature: p384::ecdsa::Signature = key.try_sign(message)?;
                Ok(signature.to_bytes().to_vec())
            }
            // `with_algorithm` keeps the pair consistent; this arm is a
            // defensive error, not a reachable state.
            _ => Err("key type does not match the algorithm".into()),
        }
    }
}

/// Split an uncompressed SEC1 point (`0x04 || x || y`) into JWK coordinates.
fn ec_material(curve: Curve, sec1: &[u8]) -> KeyMaterial {
    let coordinates = sec1.get(1..).unwrap_or_default();
    let (x, y) = coordinates.split_at(coordinates.len() / 2);
    KeyMaterial::Ec {
        curve,
        x: x.to_vec(),
        y: y.to_vec(),
    }
}

impl JwsSigner for PrivateKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn sign<'a>(&'a self, signing_input: &'a [u8]) -> SignFuture<'a> {
        Box::pin(std::future::ready(self.sign_now(signing_input)))
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}
