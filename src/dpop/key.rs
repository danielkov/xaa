//! Client side: DPoP keys and proof creation. See RFC-007 §2, §6.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::claims::{Confirmation, NumericDate};
use crate::client_auth::random_id;
use crate::error::Error;
use crate::jose::{
    Jwk, JwsSigner, PrivateKey, SignFuture, SignatureAlgorithm, b64url_encode, sign_jws,
};
use crate::secret::AccessToken;

/// `typ` of a DPoP proof (RFC 9449 §4.2).
const TYP_DPOP: &str = "dpop+jwt";

/// The algorithms [`DpopKey::generate`] accepts (RFC-007 §2).
const GENERATED_ALGORITHMS: [SignatureAlgorithm; 4] = [
    SignatureAlgorithm::Es256,
    SignatureAlgorithm::Es384,
    SignatureAlgorithm::Rs256,
    SignatureAlgorithm::Ps256,
];

/// A DPoP key: a signer, its public JWK, and the RFC 7638 thumbprint that
/// ends up in `cnf.jkt` (RFC 9449 §6.1).
///
/// The same key must sign the proof at the IdP token exchange and the proof
/// at the Resource AS that receives the resulting ID-JAG (jwt-dpop-grant §3).
/// Use a different key per Resource AS, and never share one across unrelated
/// users or sessions: `jkt` is a stable correlator (jwt-dpop-grant §8).
#[derive(Clone)]
pub struct DpopKey {
    signer: Arc<dyn JwsSigner>,
    public: Jwk,
    thumbprint: String,
}

impl DpopKey {
    /// Generate a fresh in-process key. `ES256` is the usual choice; `ES384`,
    /// `RS256`, and `PS256` are also allowed (RSA keys are 3072 bits and
    /// take noticeably longer to generate). Any other algorithm fails with
    /// [`Error::InvalidConfiguration`].
    pub fn generate(alg: SignatureAlgorithm) -> Result<Self, Error> {
        if !GENERATED_ALGORITHMS.contains(&alg) {
            return Err(Error::InvalidConfiguration {
                reason: "DPoP keys are generated for ES256, ES384, RS256, or PS256 only",
            });
        }
        let key = PrivateKey::generate(alg);
        let public = key.public_jwk();
        Self::from_signer(Arc::new(key), public)
    }

    /// Wrap an existing signer, such as an HSM- or KMS-backed key, with its
    /// public JWK.
    ///
    /// Fails with [`Error::KeyMismatch`] if `public` cannot verify the
    /// signer's algorithm. Whether `public` really is the signer's public
    /// half is the caller's responsibility: a wrong key produces proofs that
    /// every server rejects.
    pub fn from_signer(signer: Arc<dyn JwsSigner>, public: Jwk) -> Result<Self, Error> {
        public.check_usable_for(signer.algorithm())?;
        let thumbprint = public.thumbprint_sha256();
        Ok(Self {
            signer,
            public,
            thumbprint,
        })
    }

    /// The RFC 7638 SHA-256 thumbprint of the public key: the value of
    /// `cnf.jkt` in anything bound to this key (RFC 9449 §6.1).
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// The public key, as sent in the proof's `jwk` header.
    pub fn public_jwk(&self) -> &Jwk {
        &self.public
    }

    /// The algorithm proofs are signed with.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.signer.algorithm()
    }

    /// The `cnf` of a token bound to this key.
    pub fn confirmation(&self) -> Confirmation {
        Confirmation::Jkt(self.thumbprint.clone())
    }

    /// Whether `cnf` binds a token to exactly this key: it is `jkt` and
    /// equals [`thumbprint`](Self::thumbprint) by simple string comparison
    /// (draft §9.11.1.1). A missing `cnf` is not a match, which is how the
    /// client detects a silently dropped binding.
    pub fn is_confirmed_by(&self, cnf: Option<&Confirmation>) -> bool {
        matches!(cnf, Some(Confirmation::Jkt(jkt)) if *jkt == self.thumbprint)
    }

    /// Build a DPoP proof for a request with `method` to `url`
    /// (RFC 9449 §4.2).
    ///
    /// The header is `typ: dpop+jwt`, `alg`, and `jwk`. The claims are a
    /// fresh 128-bit `jti`, `htm`, `htu` (`url` without query or fragment),
    /// `iat` = `now`, and `nonce` when given: pass the last `DPoP-Nonce` the
    /// target server sent (RFC 9449 §8).
    pub async fn proof(
        &self,
        method: &http::Method,
        url: &Url,
        nonce: Option<&str>,
        now: SystemTime,
    ) -> Result<String, Error> {
        self.sign_proof(method, url, nonce, None, now).await
    }

    /// Build a DPoP proof for a resource request that carries
    /// `access_token` (RFC 9449 §7.1).
    ///
    /// Same as [`proof`](Self::proof), plus `ath`: the base64url SHA-256 hash
    /// of the access token (RFC 9449 §4.2).
    pub async fn proof_for_resource(
        &self,
        method: &http::Method,
        url: &Url,
        access_token: &AccessToken,
        nonce: Option<&str>,
        now: SystemTime,
    ) -> Result<String, Error> {
        let ath = access_token_hash(access_token);
        self.sign_proof(method, url, nonce, Some(ath), now).await
    }

    async fn sign_proof(
        &self,
        method: &http::Method,
        url: &Url,
        nonce: Option<&str>,
        ath: Option<String>,
        now: SystemTime,
    ) -> Result<String, Error> {
        let mut htu = url.clone();
        htu.set_query(None);
        htu.set_fragment(None);

        let mut claims = Map::new();
        claims.insert("jti".to_owned(), Value::from(random_id()));
        claims.insert("htm".to_owned(), Value::from(method.as_str()));
        claims.insert("htu".to_owned(), Value::from(htu.as_str()));
        claims.insert(
            "iat".to_owned(),
            Value::from(NumericDate::from_system_time(now)?.as_secs()),
        );
        if let Some(nonce) = nonce {
            claims.insert("nonce".to_owned(), Value::from(nonce));
        }
        if let Some(ath) = ath {
            claims.insert("ath".to_owned(), Value::from(ath));
        }

        let mut header = BTreeMap::new();
        header.insert("jwk", self.public.to_value());
        sign_jws(
            &WithoutKeyId(self.signer.as_ref()),
            Some(TYP_DPOP),
            header,
            &Value::Object(claims),
        )
        .await
    }
}

impl std::fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopKey")
            .field("algorithm", &self.signer.algorithm())
            .field("thumbprint", &self.thumbprint)
            .finish_non_exhaustive()
    }
}

/// `ath`: base64url of the SHA-256 hash of the ASCII access token
/// (RFC 9449 §4.2).
pub(crate) fn access_token_hash(access_token: &AccessToken) -> String {
    b64url_encode(&Sha256::digest(access_token.expose_secret().as_bytes()))
}

/// A signer seen without its `kid`: the proof's key is its `jwk` header, so
/// a `kid` would only add a second, unauthenticated name for it.
struct WithoutKeyId<'s>(&'s dyn JwsSigner);

impl JwsSigner for WithoutKeyId<'_> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn sign<'a>(&'a self, signing_input: &'a [u8]) -> SignFuture<'a> {
        self.0.sign(signing_input)
    }
}

/// A request to bind a token to a DPoP key: the key, and the nonce to put in
/// the proof. The client's token calls take one (RFC-003 §3, §6).
#[derive(Debug, Clone, Copy)]
pub struct DpopRequest<'a> {
    pub key: &'a DpopKey,
    /// The last `DPoP-Nonce` this server sent, if any (RFC 9449 §8).
    pub nonce: Option<&'a str>,
}

impl DpopRequest<'_> {
    /// The proof for a `POST` to `token_endpoint`: the IdP's for the token
    /// exchange, or the Resource AS's for the access token request.
    pub async fn token_endpoint_proof(
        &self,
        token_endpoint: &Url,
        now: SystemTime,
    ) -> Result<String, Error> {
        self.key
            .proof(&http::Method::POST, token_endpoint, self.nonce, now)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::{
        AlgorithmPolicy, ExpectedTyp, ParseLimits, UnverifiedJws, b64url_decode, verify_with_key,
    };
    use crate::test_support::{NOW_SECS, now, p256_key, rsa_key};

    fn decode(proof: &str) -> (Value, Value) {
        let mut segments = proof.split('.');
        let mut next = || {
            let bytes = b64url_decode(segments.next().unwrap()).unwrap();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        };
        (next(), next())
    }

    fn fixed_key() -> DpopKey {
        let key = p256_key();
        let public = key.public_jwk();
        DpopKey::from_signer(Arc::new(key), public).unwrap()
    }

    #[tokio::test]
    async fn token_endpoint_proof_has_the_specified_header_and_claims() {
        let key = fixed_key();
        let url = Url::parse("https://as.example/token?tenant=a#frag").unwrap();
        let request = DpopRequest {
            key: &key,
            nonce: None,
        };
        let proof = request.token_endpoint_proof(&url, now()).await.unwrap();
        let (header, claims) = decode(&proof);

        // Exactly typ, alg, jwk: the signer's kid is not emitted.
        let header = header.as_object().unwrap();
        assert_eq!(header.len(), 3);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        let jwk = Jwk::from_value(&header["jwk"]).unwrap().unwrap();
        assert_eq!(jwk.thumbprint_sha256(), key.thumbprint());

        let claims = claims.as_object().unwrap();
        assert_eq!(claims.len(), 4);
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://as.example/token");
        assert_eq!(claims["iat"], NOW_SECS);
        // 128 bits, base64url: 22 characters.
        assert_eq!(claims["jti"].as_str().unwrap().len(), 22);

        // The signature verifies with the embedded key.
        let jws = UnverifiedJws::parse(&proof, &ParseLimits::default()).unwrap();
        verify_with_key::<Value>(
            &jws,
            ExpectedTyp::DpopProof,
            &jwk,
            &AlgorithmPolicy::only(&[SignatureAlgorithm::Es256]),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn every_proof_has_a_fresh_jti_and_carries_the_nonce() {
        let key = fixed_key();
        let url = Url::parse("https://as.example/token").unwrap();
        let request = DpopRequest {
            key: &key,
            nonce: Some("nonce-1"),
        };
        let (_, first) = decode(&request.token_endpoint_proof(&url, now()).await.unwrap());
        let (_, second) = decode(&request.token_endpoint_proof(&url, now()).await.unwrap());
        assert_eq!(first["nonce"], "nonce-1");
        assert_ne!(first["jti"], second["jti"]);
    }

    #[tokio::test]
    async fn resource_proof_adds_ath() {
        // RFC 9449 §7.1, Figures 13 and 14: this access token hashes to this ath.
        let access_token = AccessToken::new("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU");
        let key = fixed_key();
        let url = Url::parse("https://resource.example.org/protectedresource?page=2").unwrap();
        let proof = key
            .proof_for_resource(&http::Method::GET, &url, &access_token, Some("n"), now())
            .await
            .unwrap();
        let (_, claims) = decode(&proof);
        assert_eq!(claims["ath"], "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
        assert_eq!(claims["htm"], "GET");
        assert_eq!(
            claims["htu"],
            "https://resource.example.org/protectedresource"
        );
        assert_eq!(claims["nonce"], "n");
        // A token-endpoint proof has no ath.
        let plain = key
            .proof(&http::Method::GET, &url, None, now())
            .await
            .unwrap();
        assert_eq!(decode(&plain).1.get("ath"), None);
    }

    #[test]
    fn generate_allows_only_the_listed_algorithms() {
        for alg in [SignatureAlgorithm::Es256, SignatureAlgorithm::Es384] {
            let key = DpopKey::generate(alg).unwrap();
            assert_eq!(key.algorithm(), alg);
            assert_eq!(key.thumbprint(), key.public_jwk().thumbprint_sha256());
        }
        // Fresh keys differ.
        assert_ne!(
            DpopKey::generate(SignatureAlgorithm::Es256)
                .unwrap()
                .thumbprint(),
            DpopKey::generate(SignatureAlgorithm::Es256)
                .unwrap()
                .thumbprint()
        );
        for alg in [
            SignatureAlgorithm::Rs384,
            SignatureAlgorithm::Rs512,
            SignatureAlgorithm::Ps384,
            SignatureAlgorithm::Ps512,
        ] {
            assert!(matches!(
                DpopKey::generate(alg).unwrap_err(),
                Error::InvalidConfiguration { .. }
            ));
        }
    }

    #[tokio::test]
    #[ignore = "generates a 3072-bit RSA key: 2 to 30 s in a debug build"]
    async fn generated_rsa_key_signs_proofs() {
        let key = DpopKey::generate(SignatureAlgorithm::Ps256).unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::Ps256);
        let url = Url::parse("https://as.example/token").unwrap();
        let proof = key
            .proof(&http::Method::POST, &url, None, now())
            .await
            .unwrap();
        let (header, _) = decode(&proof);
        assert_eq!(header["alg"], "PS256");
        assert_eq!(header["jwk"]["kty"], "RSA");
        let jws = UnverifiedJws::parse(&proof, &ParseLimits::default()).unwrap();
        verify_with_key::<Value>(
            &jws,
            ExpectedTyp::DpopProof,
            key.public_jwk(),
            &AlgorithmPolicy::only(&[SignatureAlgorithm::Ps256]),
        )
        .unwrap();
    }

    #[test]
    fn from_signer_refuses_a_public_key_of_another_type() {
        let err = DpopKey::from_signer(Arc::new(p256_key()), rsa_key().public_jwk()).unwrap_err();
        assert!(matches!(err, Error::KeyMismatch { .. }));
        // An RSA signer may use PS256.
        let rsa = rsa_key().with_algorithm(SignatureAlgorithm::Ps256).unwrap();
        let public = rsa.public_jwk();
        let key = DpopKey::from_signer(Arc::new(rsa), public).unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::Ps256);
    }

    #[test]
    fn confirmation_matches_only_the_same_thumbprint() {
        let key = fixed_key();
        assert_eq!(
            key.confirmation(),
            Confirmation::Jkt(key.thumbprint().to_owned())
        );
        assert!(key.is_confirmed_by(Some(&key.confirmation())));
        assert!(!key.is_confirmed_by(None));
        let other = Confirmation::Jkt("another-thumbprint".to_owned());
        assert!(!key.is_confirmed_by(Some(&other)));
        // The same string under x5t#S256 is a different binding.
        let x5t = Confirmation::X5tS256(key.thumbprint().to_owned());
        assert!(!key.is_confirmed_by(Some(&x5t)));
    }

    #[test]
    fn debug_shows_no_key_material() {
        let key = fixed_key();
        let debug = format!("{key:?}");
        assert!(debug.contains(key.thumbprint()));
        assert!(!debug.contains("signer"));
    }
}
