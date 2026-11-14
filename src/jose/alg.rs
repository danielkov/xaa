//! Signature algorithms and per-issuer allow-lists. See RFC-002 §3.

/// The asymmetric JWS algorithms this crate implements (RFC 7518 §3).
///
/// There is no `HS*` and no `none`. The ID-JAG trust model has no secret
/// shared between the IdP and the Resource AS, and accepting HMAC would open
/// the public-key-as-HMAC-secret confusion.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256. Mandatory to implement (draft §3).
    Rs256,
    Rs384,
    Rs512,
    /// RSASSA-PSS with SHA-256 and MGF1-SHA-256.
    Ps256,
    Ps384,
    Ps512,
    /// ECDSA P-256 with SHA-256. The Resource AS SHOULD support it (draft §3).
    Es256,
    /// ECDSA P-384 with SHA-384.
    Es384,
}

/// The key type an algorithm is tied to. An `alg` never verifies against a
/// key of another family, which rules out algorithm-confusion attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFamily {
    Rsa,
    P256,
    P384,
}

impl SignatureAlgorithm {
    /// Every implemented algorithm.
    pub const ALL: [Self; 8] = [
        Self::Rs256,
        Self::Rs384,
        Self::Rs512,
        Self::Ps256,
        Self::Ps384,
        Self::Ps512,
        Self::Es256,
        Self::Es384,
    ];

    /// The JWS `alg` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }

    /// Parse a JWS `alg` value. `none`, `HS*`, and anything unknown are `None`.
    pub fn parse(alg: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == alg)
    }

    pub(crate) fn key_family(self) -> KeyFamily {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                KeyFamily::Rsa
            }
            Self::Es256 => KeyFamily::P256,
            Self::Es384 => KeyFamily::P384,
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An allow-list of signature algorithms.
///
/// Every verification takes one. The Resource AS holds one per trusted issuer
/// (draft §4.4.1, RFC 8725 §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmPolicy {
    allowed: Vec<SignatureAlgorithm>,
}

impl AlgorithmPolicy {
    /// `RS256` and `ES256`: the mandatory and the recommended ID-JAG
    /// algorithms (draft §3).
    pub fn default_id_jag() -> Self {
        Self::only(&[SignatureAlgorithm::Rs256, SignatureAlgorithm::Es256])
    }

    /// Exactly these algorithms.
    pub fn only(algs: &[SignatureAlgorithm]) -> Self {
        let mut allowed = Vec::with_capacity(algs.len());
        for alg in algs {
            if !allowed.contains(alg) {
                allowed.push(*alg);
            }
        }
        Self { allowed }
    }

    /// Whether `alg` is allowed.
    pub fn allows(&self, alg: SignatureAlgorithm) -> bool {
        self.allowed.contains(&alg)
    }

    /// The allowed algorithms, in the order given.
    pub fn algorithms(&self) -> &[SignatureAlgorithm] {
        &self.allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_and_rejects_none_and_hmac() {
        for alg in SignatureAlgorithm::ALL {
            assert_eq!(SignatureAlgorithm::parse(alg.as_str()), Some(alg));
        }
        for bad in ["none", "None", "HS256", "HS512", "EdDSA", "rs256", ""] {
            assert_eq!(SignatureAlgorithm::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn default_policy_is_rs256_and_es256() {
        let policy = AlgorithmPolicy::default_id_jag();
        assert!(policy.allows(SignatureAlgorithm::Rs256));
        assert!(policy.allows(SignatureAlgorithm::Es256));
        assert!(!policy.allows(SignatureAlgorithm::Ps256));
        assert!(!policy.allows(SignatureAlgorithm::Es384));
    }

    #[test]
    fn only_deduplicates() {
        let policy = AlgorithmPolicy::only(&[SignatureAlgorithm::Es384, SignatureAlgorithm::Es384]);
        assert_eq!(policy.algorithms(), &[SignatureAlgorithm::Es384]);
    }
}
