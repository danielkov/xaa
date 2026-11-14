//! The binding decision tables. See RFC-007 §4.
//!
//! Binding happens at the IdP during the token exchange ([`IdpBinding`]) and
//! is checked at the Resource AS during the access token request
//! ([`ResourceAsBinding`]). Both are pure functions of what the request
//! presented, so every table row is a unit test.
//!
//! Thumbprints are compared as exact strings (draft §9.11.1.1).

use crate::claims::Confirmation;
use crate::oauth_error::OAuthErrorCode;

use super::validate::ValidatedDpopProof;

/// `grant_type` of the JWT bearer grant (RFC 7523 §2.1).
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// `grant_type` of the DPoP-bound JWT grant (jwt-dpop-grant §4.1).
pub const GRANT_TYPE_JWT_DPOP: &str = "urn:ietf:params:oauth:grant-type:jwt-dpop";

/// The grant type an ID-JAG is presented under (draft §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssertionGrantType {
    /// `urn:ietf:params:oauth:grant-type:jwt-bearer`.
    JwtBearer,
    /// `urn:ietf:params:oauth:grant-type:jwt-dpop`.
    JwtDpop,
}

impl AssertionGrantType {
    /// The `grant_type` parameter value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JwtBearer => GRANT_TYPE_JWT_BEARER,
            Self::JwtDpop => GRANT_TYPE_JWT_DPOP,
        }
    }

    /// Parse a `grant_type` parameter value. Any other grant is `None`.
    pub fn parse(grant_type: &str) -> Option<Self> {
        match grant_type {
            GRANT_TYPE_JWT_BEARER => Some(Self::JwtBearer),
            GRANT_TYPE_JWT_DPOP => Some(Self::JwtDpop),
            _ => None,
        }
    }

    /// The grant type a client must use for an ID-JAG with this `cnf`:
    /// `jwt-dpop` for `cnf.jkt` (jwt-dpop-grant §4.1), `jwt-bearer` for
    /// everything else, including `x5t#S256` (draft §9.11.2.2).
    pub fn for_confirmation(cnf: Option<&Confirmation>) -> Self {
        match cnf {
            Some(Confirmation::Jkt(_)) => Self::JwtDpop,
            Some(Confirmation::X5tS256(_) | Confirmation::Unsupported(_)) | None => Self::JwtBearer,
        }
    }
}

/// Which binding wins when a request presents both a DPoP proof and a TLS
/// client certificate. A token is never bound to both (draft §9.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindingPreference {
    /// Bind to the DPoP key.
    #[default]
    Dpop,
    /// Bind to the certificate.
    Mtls,
}

/// What the IdP does with a valid DPoP proof when the Resource AS is not
/// known to support `jwt-dpop` (RFC-005 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DpopToNonSupportingAs {
    /// Refuse the exchange with `invalid_target`; nothing is issued
    /// (jwt-dpop-grant §7.1).
    #[default]
    Reject,
    /// Bind anyway, reading draft §9.11.1.1 literally.
    Bind,
}

/// The binding a Resource AS proved for a request, and so the binding of the
/// access token it issues (RFC-007 §4.3).
///
/// The caller puts it in the access token's `cnf` or in its introspection
/// response. Enforcing it at the Resource Server is outside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessTokenBinding {
    /// Bound to a DPoP key (RFC 9449 §6).
    Dpop { jkt: String },
    /// Bound to a TLS client certificate (RFC 8705 §3).
    Mtls { x5t_s256: String },
}

impl AccessTokenBinding {
    /// The `cnf` for the access token.
    pub fn confirmation(&self) -> Confirmation {
        match self {
            Self::Dpop { jkt } => Confirmation::Jkt(jkt.clone()),
            Self::Mtls { x5t_s256 } => Confirmation::X5tS256(x5t_s256.clone()),
        }
    }

    /// The `token_type` of the token response: `DPoP` for a DPoP-bound token
    /// (RFC 9449 §5), `Bearer` for a certificate-bound one (RFC 8705 §3).
    pub fn token_type(&self) -> &'static str {
        match self {
            Self::Dpop { .. } => "DPoP",
            Self::Mtls { .. } => "Bearer",
        }
    }
}

/// Why a binding decision rejected the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BindingRejection {
    /// IdP: a DPoP proof was presented for a Resource AS that is not known
    /// to support `jwt-dpop` (jwt-dpop-grant §7.1). `invalid_target`.
    #[error("the audience does not accept DPoP-bound grants")]
    AudienceLacksJwtDpop,
    /// Resource AS: `jwt-dpop` without a DPoP proof (jwt-dpop-grant §5).
    /// `invalid_dpop_proof`.
    #[error("the jwt-dpop grant requires a DPoP proof")]
    DpopProofRequired,
    /// Resource AS: the proof key's thumbprint is not the ID-JAG's `cnf.jkt`
    /// (draft §9.11.1.2.1). `invalid_grant`.
    #[error("the DPoP proof key does not match the ID-JAG's cnf.jkt")]
    DpopKeyMismatch,
    /// Resource AS: a `cnf.jkt` ID-JAG under `jwt-bearer`, with or without a
    /// proof (jwt-dpop-grant §5.2). `invalid_grant`.
    #[error("a DPoP-bound ID-JAG was presented with the jwt-bearer grant")]
    DpopBoundGrantAsBearer,
    /// Resource AS: `jwt-dpop` with an ID-JAG that has no `cnf.jkt`
    /// (jwt-dpop-grant §5 step 3). `invalid_grant`.
    #[error("the jwt-dpop grant requires an ID-JAG with cnf.jkt")]
    JwtDpopRequiresJkt,
    /// Resource AS: an `x5t#S256` ID-JAG and no client certificate
    /// (draft §9.11.2.2). `invalid_grant`.
    #[error("the ID-JAG is certificate-bound and no client certificate was presented")]
    CertificateRequired,
    /// Resource AS: the client certificate's thumbprint is not the ID-JAG's
    /// `cnf.x5t#S256` (draft §9.11.2.2). `invalid_grant`.
    #[error("the client certificate does not match the ID-JAG's cnf.x5t#S256")]
    CertificateMismatch,
    /// Resource AS: a `cnf` member this crate does not support (draft
    /// §9.11). `invalid_grant`.
    #[error("the ID-JAG carries an unsupported cnf")]
    UnsupportedConfirmation,
    /// Resource AS: the resource requires a sender-constrained token and no
    /// binding was proven (draft §9.11.1.2.4). `invalid_grant`.
    #[error("the resource requires a sender-constrained token")]
    SenderConstraintRequired,
}

impl BindingRejection {
    /// The OAuth error code to return.
    pub fn code(&self) -> OAuthErrorCode {
        match self {
            Self::AudienceLacksJwtDpop => OAuthErrorCode::InvalidTarget,
            Self::DpopProofRequired => OAuthErrorCode::InvalidDpopProof,
            Self::DpopKeyMismatch
            | Self::DpopBoundGrantAsBearer
            | Self::JwtDpopRequiresJkt
            | Self::CertificateRequired
            | Self::CertificateMismatch
            | Self::UnsupportedConfirmation
            | Self::SenderConstraintRequired => OAuthErrorCode::InvalidGrant,
        }
    }
}

/// What a token exchange request presented to the IdP, and the IdP's
/// configuration for the target Resource AS (RFC-007 §4.1).
///
/// An invalid DPoP proof never gets here:
/// [`validate_dpop_proof`](super::validate_dpop_proof) has already failed the
/// request with `invalid_dpop_proof` (RFC 9449 §5).
#[derive(Debug, Clone, Copy)]
pub struct IdpBinding<'a> {
    /// The validated DPoP proof, if the request carried one.
    pub dpop: Option<&'a ValidatedDpopProof>,
    /// The `x5t#S256` of the TLS client certificate, if one was presented
    /// ([`certificate_thumbprint`](crate::mtls::certificate_thumbprint)).
    pub certificate_x5t_s256: Option<&'a str>,
    /// Whether this IdP binds ID-JAGs to client certificates at all
    /// (draft §9.11.2.1). When false, a presented certificate is ignored.
    pub mtls_binding: bool,
    /// Whether the Resource AS is known to support `jwt-dpop`. Unknown
    /// counts as false (jwt-dpop-grant §7.1).
    pub supports_jwt_dpop: bool,
    /// Which binding to use when both are possible.
    pub preference: BindingPreference,
    /// What to do with a proof when `supports_jwt_dpop` is false.
    pub dpop_to_non_supporting_as: DpopToNonSupportingAs,
}

impl IdpBinding<'_> {
    /// The `cnf` to put in the ID-JAG: `None` for an unbound ID-JAG.
    ///
    /// | DPoP proof | Certificate (with `mtls_binding`) | Result |
    /// | --- | --- | --- |
    /// | valid | none | `jkt`, if the Resource AS supports `jwt-dpop` |
    /// | valid | any | [`BindingRejection::AudienceLacksJwtDpop`] if it does not, unless [`DpopToNonSupportingAs::Bind`] |
    /// | none | presented | `x5t#S256` |
    /// | valid | presented | one of them, per `preference`; never both |
    /// | none | none | none |
    pub fn decide(&self) -> Result<Option<Confirmation>, BindingRejection> {
        // The client asked for a DPoP binding. If it cannot be honored the
        // exchange is refused whatever else was presented: issuing an
        // unbound or differently bound ID-JAG is the silent downgrade that
        // draft §9.11.1.1 tells clients to detect.
        if self.dpop.is_some()
            && !self.supports_jwt_dpop
            && self.dpop_to_non_supporting_as == DpopToNonSupportingAs::Reject
        {
            return Err(BindingRejection::AudienceLacksJwtDpop);
        }
        let certificate = self.certificate_x5t_s256.filter(|_| self.mtls_binding);
        let jkt = |proof: &ValidatedDpopProof| Confirmation::Jkt(proof.jkt().to_owned());
        let x5t = |thumbprint: &str| Confirmation::X5tS256(thumbprint.to_owned());
        Ok(match (self.dpop, certificate) {
            (None, None) => None,
            (Some(proof), None) => Some(jkt(proof)),
            (None, Some(thumbprint)) => Some(x5t(thumbprint)),
            (Some(proof), Some(thumbprint)) => Some(match self.preference {
                BindingPreference::Dpop => jkt(proof),
                BindingPreference::Mtls => x5t(thumbprint),
            }),
        })
    }
}

/// What an access token request presented to the Resource AS, next to the
/// `cnf` of its verified ID-JAG (RFC-007 §4.2).
#[derive(Debug, Clone, Copy)]
pub struct ResourceAsBinding<'a> {
    /// The ID-JAG's `cnf` claim.
    pub cnf: Option<&'a Confirmation>,
    /// The request's `grant_type`.
    pub grant_type: AssertionGrantType,
    /// The validated DPoP proof, if the request carried one. An invalid
    /// proof has already failed the request with `invalid_dpop_proof`.
    pub dpop: Option<&'a ValidatedDpopProof>,
    /// The `x5t#S256` of the TLS client certificate, if one was presented
    /// ([`certificate_thumbprint`](crate::mtls::certificate_thumbprint)).
    /// A server that never issues certificate-bound tokens may pass `None`
    /// for unbound ID-JAGs; an `x5t#S256` ID-JAG always needs it.
    pub certificate_x5t_s256: Option<&'a str>,
    /// Which binding the access token gets when an unbound ID-JAG arrives
    /// with both a DPoP proof and a certificate.
    pub preference: BindingPreference,
}

impl ResourceAsBinding<'_> {
    /// Apply the table. `Ok(Some(_))` is the proven binding, which the issued
    /// access token should carry; `Ok(None)` accepts the request as Bearer,
    /// subject to [`require_sender_constraint`].
    ///
    /// | ID-JAG `cnf` | `grant_type` | Presented | Result |
    /// | --- | --- | --- | --- |
    /// | any | `jwt-dpop` | no proof | [`DpopProofRequired`](BindingRejection::DpopProofRequired) |
    /// | unsupported | any | any | [`UnsupportedConfirmation`](BindingRejection::UnsupportedConfirmation) |
    /// | `jkt` | `jwt-dpop` | proof, thumbprint matches | DPoP binding |
    /// | `jkt` | `jwt-dpop` | proof, thumbprint differs | [`DpopKeyMismatch`](BindingRejection::DpopKeyMismatch) |
    /// | `jkt` | `jwt-bearer` | any | [`DpopBoundGrantAsBearer`](BindingRejection::DpopBoundGrantAsBearer) |
    /// | none or `x5t#S256` | `jwt-dpop` | proof | [`JwtDpopRequiresJkt`](BindingRejection::JwtDpopRequiresJkt) |
    /// | `x5t#S256` | `jwt-bearer` | certificate, thumbprint matches | mTLS binding |
    /// | `x5t#S256` | `jwt-bearer` | another certificate / none | [`CertificateMismatch`](BindingRejection::CertificateMismatch) / [`CertificateRequired`](BindingRejection::CertificateRequired) |
    /// | none | `jwt-bearer` | proof | DPoP binding to the proof key |
    /// | none | `jwt-bearer` | certificate | mTLS binding |
    /// | none | `jwt-bearer` | both | one of them, per `preference` |
    /// | none | `jwt-bearer` | nothing | no binding |
    pub fn decide(&self) -> Result<Option<AccessTokenBinding>, BindingRejection> {
        // RFC-004 rule 1 runs before the ID-JAG is read, so a missing proof
        // under jwt-dpop is `invalid_dpop_proof` whatever the `cnf`
        // (jwt-dpop-grant §5).
        if self.grant_type == AssertionGrantType::JwtDpop && self.dpop.is_none() {
            return Err(BindingRejection::DpopProofRequired);
        }
        let dpop = |proof: &ValidatedDpopProof| AccessTokenBinding::Dpop {
            jkt: proof.jkt().to_owned(),
        };
        let mtls = |thumbprint: &str| AccessTokenBinding::Mtls {
            x5t_s256: thumbprint.to_owned(),
        };
        match (self.cnf, self.grant_type) {
            // Never treated as unbound (draft §9.11).
            (Some(Confirmation::Unsupported(_)), _) => {
                Err(BindingRejection::UnsupportedConfirmation)
            }
            (Some(Confirmation::Jkt(_)), AssertionGrantType::JwtBearer) => {
                Err(BindingRejection::DpopBoundGrantAsBearer)
            }
            (Some(Confirmation::Jkt(jkt)), AssertionGrantType::JwtDpop) => match self.dpop {
                Some(proof) if proof.jkt() == jkt => Ok(Some(dpop(proof))),
                Some(_) => Err(BindingRejection::DpopKeyMismatch),
                None => Err(BindingRejection::DpopProofRequired),
            },
            (Some(Confirmation::X5tS256(_)) | None, AssertionGrantType::JwtDpop) => {
                Err(BindingRejection::JwtDpopRequiresJkt)
            }
            (Some(Confirmation::X5tS256(bound)), AssertionGrantType::JwtBearer) => {
                match self.certificate_x5t_s256 {
                    Some(presented) if presented == bound => Ok(Some(mtls(presented))),
                    Some(_) => Err(BindingRejection::CertificateMismatch),
                    None => Err(BindingRejection::CertificateRequired),
                }
            }
            (None, AssertionGrantType::JwtBearer) => {
                Ok(match (self.dpop, self.certificate_x5t_s256) {
                    (None, None) => None,
                    (Some(proof), None) => Some(dpop(proof)),
                    (None, Some(thumbprint)) => Some(mtls(thumbprint)),
                    (Some(proof), Some(thumbprint)) => Some(match self.preference {
                        BindingPreference::Dpop => dpop(proof),
                        BindingPreference::Mtls => mtls(thumbprint),
                    }),
                })
            }
        }
    }
}

/// The last row of the Bearer case: a resource that requires a
/// sender-constrained token rejects a request with no proven binding
/// (draft §9.11.1.2.4, RFC-004 §6).
pub fn require_sender_constraint(
    binding: Option<&AccessTokenBinding>,
    requires_sender_constraint: bool,
) -> Result<(), BindingRejection> {
    if requires_sender_constraint && binding.is_none() {
        return Err(BindingRejection::SenderConstraintRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "thumbprint-of-the-dpop-key";
    const OTHER_KEY: &str = "thumbprint-of-another-key";
    const CERT: &str = "thumbprint-of-the-certificate";
    const OTHER_CERT: &str = "thumbprint-of-another-certificate";

    fn proof(jkt: &str) -> ValidatedDpopProof {
        ValidatedDpopProof::for_test(jkt)
    }

    fn jkt(value: &str) -> Confirmation {
        Confirmation::Jkt(value.to_owned())
    }

    fn x5t(value: &str) -> Confirmation {
        Confirmation::X5tS256(value.to_owned())
    }

    fn unsupported() -> Confirmation {
        Confirmation::from_json(&json!({"jwk": {"kty": "EC"}})).unwrap()
    }

    // ----- §4.1: the IdP ----------------------------------------------------

    fn idp<'a>(
        dpop: Option<&'a ValidatedDpopProof>,
        certificate: Option<&'a str>,
    ) -> IdpBinding<'a> {
        IdpBinding {
            dpop,
            certificate_x5t_s256: certificate,
            mtls_binding: true,
            supports_jwt_dpop: true,
            preference: BindingPreference::default(),
            dpop_to_non_supporting_as: DpopToNonSupportingAs::default(),
        }
    }

    #[test]
    fn idp_valid_proof_no_certificate_binds_jkt() {
        let proof = proof(KEY);
        assert_eq!(idp(Some(&proof), None).decide(), Ok(Some(jkt(KEY))));
    }

    #[test]
    fn idp_valid_proof_for_an_as_without_jwt_dpop_is_invalid_target() {
        let proof = proof(KEY);
        // Whatever certificate was presented, and whatever the preference.
        for certificate in [None, Some(CERT)] {
            for preference in [BindingPreference::Dpop, BindingPreference::Mtls] {
                let mut binding = idp(Some(&proof), certificate);
                binding.supports_jwt_dpop = false;
                binding.preference = preference;
                let rejection = binding.decide().unwrap_err();
                assert_eq!(rejection, BindingRejection::AudienceLacksJwtDpop);
                assert_eq!(rejection.code(), OAuthErrorCode::InvalidTarget);
            }
        }
        // Without a proof the missing support is irrelevant.
        let mut binding = idp(None, Some(CERT));
        binding.supports_jwt_dpop = false;
        assert_eq!(binding.decide(), Ok(Some(x5t(CERT))));
    }

    #[test]
    fn idp_bind_opt_out_binds_for_an_as_without_jwt_dpop() {
        let proof = proof(KEY);
        let mut binding = idp(Some(&proof), None);
        binding.supports_jwt_dpop = false;
        binding.dpop_to_non_supporting_as = DpopToNonSupportingAs::Bind;
        assert_eq!(binding.decide(), Ok(Some(jkt(KEY))));
    }

    #[test]
    fn idp_certificate_without_proof_binds_x5t() {
        assert_eq!(idp(None, Some(CERT)).decide(), Ok(Some(x5t(CERT))));
    }

    #[test]
    fn idp_certificate_is_ignored_without_mtls_binding() {
        let proof = proof(KEY);
        let mut binding = idp(None, Some(CERT));
        binding.mtls_binding = false;
        assert_eq!(binding.decide(), Ok(None));
        let mut binding = idp(Some(&proof), Some(CERT));
        binding.mtls_binding = false;
        binding.preference = BindingPreference::Mtls;
        assert_eq!(binding.decide(), Ok(Some(jkt(KEY))));
    }

    #[test]
    fn idp_proof_and_certificate_bind_one_per_preference() {
        let proof = proof(KEY);
        let mut binding = idp(Some(&proof), Some(CERT));
        binding.preference = BindingPreference::Dpop;
        assert_eq!(binding.decide(), Ok(Some(jkt(KEY))));
        binding.preference = BindingPreference::Mtls;
        assert_eq!(binding.decide(), Ok(Some(x5t(CERT))));
    }

    #[test]
    fn idp_nothing_presented_issues_unbound() {
        assert_eq!(idp(None, None).decide(), Ok(None));
    }

    // ----- §4.2: the Resource AS --------------------------------------------

    fn resource_as<'a>(
        cnf: Option<&'a Confirmation>,
        grant_type: AssertionGrantType,
        dpop: Option<&'a ValidatedDpopProof>,
        certificate: Option<&'a str>,
    ) -> Result<Option<AccessTokenBinding>, BindingRejection> {
        ResourceAsBinding {
            cnf,
            grant_type,
            dpop,
            certificate_x5t_s256: certificate,
            preference: BindingPreference::default(),
        }
        .decide()
    }

    fn dpop_bound(jkt: &str) -> AccessTokenBinding {
        AccessTokenBinding::Dpop {
            jkt: jkt.to_owned(),
        }
    }

    fn mtls_bound(x5t_s256: &str) -> AccessTokenBinding {
        AccessTokenBinding::Mtls {
            x5t_s256: x5t_s256.to_owned(),
        }
    }

    use AssertionGrantType::{JwtBearer, JwtDpop};

    #[test]
    fn row_1_jkt_jwt_dpop_matching_proof_is_accepted() {
        let (cnf, proof) = (jkt(KEY), proof(KEY));
        assert_eq!(
            resource_as(Some(&cnf), JwtDpop, Some(&proof), None),
            Ok(Some(dpop_bound(KEY)))
        );
        // A certificate on the connection does not change the binding.
        assert_eq!(
            resource_as(Some(&cnf), JwtDpop, Some(&proof), Some(CERT)),
            Ok(Some(dpop_bound(KEY)))
        );
    }

    #[test]
    fn row_2_jkt_jwt_dpop_other_key_is_invalid_grant() {
        let (cnf, proof) = (jkt(KEY), proof(OTHER_KEY));
        let rejection = resource_as(Some(&cnf), JwtDpop, Some(&proof), None).unwrap_err();
        assert_eq!(rejection, BindingRejection::DpopKeyMismatch);
        assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
    }

    #[test]
    fn row_3_jwt_dpop_without_proof_is_invalid_dpop_proof() {
        // Whatever the cnf: the proof check runs before the ID-JAG is read.
        let (bound, cert_bound, other) = (jkt(KEY), x5t(CERT), unsupported());
        for cnf in [Some(&bound), Some(&cert_bound), Some(&other), None] {
            let rejection = resource_as(cnf, JwtDpop, None, Some(CERT)).unwrap_err();
            assert_eq!(rejection, BindingRejection::DpopProofRequired);
            assert_eq!(rejection.code(), OAuthErrorCode::InvalidDpopProof);
        }
    }

    #[test]
    fn row_4_jkt_jwt_bearer_is_invalid_grant_even_with_a_valid_proof() {
        let (cnf, matching, other) = (jkt(KEY), proof(KEY), proof(OTHER_KEY));
        for presented in [Some(&matching), Some(&other), None] {
            for certificate in [None, Some(CERT)] {
                let rejection =
                    resource_as(Some(&cnf), JwtBearer, presented, certificate).unwrap_err();
                assert_eq!(rejection, BindingRejection::DpopBoundGrantAsBearer);
                assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
            }
        }
    }

    #[test]
    fn row_5_unbound_jwt_dpop_is_invalid_grant() {
        let proof = proof(KEY);
        for certificate in [None, Some(CERT)] {
            let rejection = resource_as(None, JwtDpop, Some(&proof), certificate).unwrap_err();
            assert_eq!(rejection, BindingRejection::JwtDpopRequiresJkt);
            assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
        }
        // A certificate-bound ID-JAG has no cnf.jkt either, even when the
        // certificate matches.
        let cnf = x5t(CERT);
        assert_eq!(
            resource_as(Some(&cnf), JwtDpop, Some(&proof), Some(CERT)),
            Err(BindingRejection::JwtDpopRequiresJkt)
        );
    }

    #[test]
    fn row_6_unbound_jwt_bearer_with_proof_binds_the_proof_key() {
        let proof = proof(KEY);
        assert_eq!(
            resource_as(None, JwtBearer, Some(&proof), None),
            Ok(Some(dpop_bound(KEY)))
        );
    }

    #[test]
    fn row_7_unbound_jwt_bearer_with_nothing_is_bearer_unless_constraint_required() {
        let binding = resource_as(None, JwtBearer, None, None).unwrap();
        assert_eq!(binding, None);
        assert_eq!(require_sender_constraint(binding.as_ref(), false), Ok(()));
        let rejection = require_sender_constraint(binding.as_ref(), true).unwrap_err();
        assert_eq!(rejection, BindingRejection::SenderConstraintRequired);
        assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
        // Any proven binding satisfies the requirement.
        for binding in [dpop_bound(KEY), mtls_bound(CERT)] {
            assert_eq!(require_sender_constraint(Some(&binding), true), Ok(()));
        }
    }

    #[test]
    fn row_8_x5t_jwt_bearer_matching_certificate_is_accepted() {
        let (cnf, proof) = (x5t(CERT), proof(KEY));
        assert_eq!(
            resource_as(Some(&cnf), JwtBearer, None, Some(CERT)),
            Ok(Some(mtls_bound(CERT)))
        );
        // A DPoP proof next to it does not change the binding.
        assert_eq!(
            resource_as(Some(&cnf), JwtBearer, Some(&proof), Some(CERT)),
            Ok(Some(mtls_bound(CERT)))
        );
    }

    #[test]
    fn row_9_x5t_other_or_no_certificate_is_invalid_grant() {
        let (cnf, proof) = (x5t(CERT), proof(KEY));
        let rejection = resource_as(Some(&cnf), JwtBearer, None, Some(OTHER_CERT)).unwrap_err();
        assert_eq!(rejection, BindingRejection::CertificateMismatch);
        assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
        // A proof does not stand in for the certificate.
        for presented in [None, Some(&proof)] {
            let rejection = resource_as(Some(&cnf), JwtBearer, presented, None).unwrap_err();
            assert_eq!(rejection, BindingRejection::CertificateRequired);
            assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
        }
        // Under jwt-dpop the same cases are invalid_grant as well.
        for certificate in [None, Some(OTHER_CERT)] {
            let rejection =
                resource_as(Some(&cnf), JwtDpop, Some(&proof), certificate).unwrap_err();
            assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
        }
        // The thumbprint of the DPoP key is not a certificate thumbprint.
        let cnf = x5t(KEY);
        assert_eq!(
            resource_as(Some(&cnf), JwtBearer, Some(&proof), Some(CERT)),
            Err(BindingRejection::CertificateMismatch)
        );
    }

    #[test]
    fn row_10_unbound_jwt_bearer_with_certificate_binds_the_certificate() {
        assert_eq!(
            resource_as(None, JwtBearer, None, Some(CERT)),
            Ok(Some(mtls_bound(CERT)))
        );
    }

    #[test]
    fn row_11_unsupported_cnf_is_invalid_grant() {
        let (cnf, proof) = (unsupported(), proof(KEY));
        for (grant_type, presented) in [
            (JwtBearer, None),
            (JwtBearer, Some(&proof)),
            (JwtDpop, Some(&proof)),
        ] {
            for certificate in [None, Some(CERT)] {
                let rejection =
                    resource_as(Some(&cnf), grant_type, presented, certificate).unwrap_err();
                assert_eq!(rejection, BindingRejection::UnsupportedConfirmation);
                assert_eq!(rejection.code(), OAuthErrorCode::InvalidGrant);
            }
        }
    }

    #[test]
    fn unbound_jwt_bearer_with_proof_and_certificate_binds_one_per_preference() {
        let proof = proof(KEY);
        let mut binding = ResourceAsBinding {
            cnf: None,
            grant_type: JwtBearer,
            dpop: Some(&proof),
            certificate_x5t_s256: Some(CERT),
            preference: BindingPreference::Dpop,
        };
        assert_eq!(binding.decide(), Ok(Some(dpop_bound(KEY))));
        binding.preference = BindingPreference::Mtls;
        assert_eq!(binding.decide(), Ok(Some(mtls_bound(CERT))));
    }

    // ----- §4.3 and helpers -------------------------------------------------

    #[test]
    fn access_token_binding_output() {
        let dpop = AccessTokenBinding::Dpop {
            jkt: KEY.to_owned(),
        };
        assert_eq!(dpop.confirmation(), jkt(KEY));
        assert_eq!(dpop.token_type(), "DPoP");
        let mtls = AccessTokenBinding::Mtls {
            x5t_s256: CERT.to_owned(),
        };
        assert_eq!(mtls.confirmation(), x5t(CERT));
        assert_eq!(mtls.token_type(), "Bearer");
    }

    #[test]
    fn grant_type_follows_the_confirmation() {
        let (bound, cert_bound, other) = (jkt(KEY), x5t(CERT), unsupported());
        assert_eq!(AssertionGrantType::for_confirmation(Some(&bound)), JwtDpop);
        assert_eq!(
            AssertionGrantType::for_confirmation(Some(&cert_bound)),
            JwtBearer
        );
        assert_eq!(
            AssertionGrantType::for_confirmation(Some(&other)),
            JwtBearer
        );
        assert_eq!(AssertionGrantType::for_confirmation(None), JwtBearer);
        for grant_type in [JwtBearer, JwtDpop] {
            assert_eq!(
                AssertionGrantType::parse(grant_type.as_str()),
                Some(grant_type)
            );
        }
        assert_eq!(
            AssertionGrantType::parse("urn:ietf:params:oauth:grant-type:token-exchange"),
            None
        );
        assert_eq!(AssertionGrantType::parse("jwt-dpop"), None);
    }
}
