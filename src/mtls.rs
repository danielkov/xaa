//! Mutual-TLS certificate binding (RFC 8705). See RFC-007 §1, §5.
//!
//! The library never sees TLS. The caller's TLS stack validates the client
//! certificate (RFC 8705 §2) and passes its DER here; this module computes
//! the `x5t#S256` thumbprint and compares it. The binding certificate and the
//! authentication certificate are the same certificate (draft §9.11.2).

use sha2::{Digest as _, Sha256};

use crate::claims::Confirmation;
use crate::error::Error;
use crate::jose::b64url_encode;

/// The `x5t#S256` thumbprint of a certificate: SHA-256 over its DER
/// encoding, base64url without padding (RFC 8705 §3.1).
///
/// `certificate_der` is the whole X.509 certificate in DER, not PEM. The
/// certificate is not parsed; the only check is that the input starts like a
/// DER `SEQUENCE`, which catches PEM text passed by mistake.
pub fn certificate_thumbprint(certificate_der: &[u8]) -> Result<String, Error> {
    // 0x30 is the DER tag of a SEQUENCE, the outer type of a Certificate.
    if certificate_der.first() != Some(&0x30) || certificate_der.len() < 2 {
        return Err(Error::InvalidConfiguration {
            reason: "client certificate is not DER",
        });
    }
    Ok(b64url_encode(&Sha256::digest(certificate_der)))
}

/// The `cnf` an IdP puts in an ID-JAG bound to this certificate
/// (draft §9.11.2.1).
pub fn certificate_confirmation(certificate_der: &[u8]) -> Result<Confirmation, Error> {
    certificate_thumbprint(certificate_der).map(Confirmation::X5tS256)
}

/// Whether `cnf` binds a token to exactly this certificate: it is
/// `x5t#S256` and equals the certificate's thumbprint by simple string
/// comparison (RFC 8705 §3.1).
///
/// The client uses this to detect an IdP that silently dropped or changed
/// the binding (draft §9.11.2.1); a missing `cnf` is not a match.
pub fn certificate_matches(
    certificate_der: &[u8],
    cnf: Option<&Confirmation>,
) -> Result<bool, Error> {
    let thumbprint = certificate_thumbprint(certificate_der)?;
    Ok(thumbprint_matches(&thumbprint, cnf))
}

/// Whether `cnf` is `x5t#S256` with exactly the value `x5t_s256`.
pub fn thumbprint_matches(x5t_s256: &str, cnf: Option<&Confirmation>) -> bool {
    matches!(cnf, Some(Confirmation::X5tS256(bound)) if bound == x5t_s256)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;

    /// RFC 8705 Appendix A, Figure 6, without the PEM armor.
    const RFC_8705_CERTIFICATE: &str = "MIIBBjCBrAIBAjAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARtdGxzMB4XDTE4MTAx\
        ODEyMzcwOVoXDTIyMDUwMjEyMzcwOVowDzENMAsGA1UEAwwEbXRsczBZMBMGByqG\
        SM49AgEGCCqGSM49AwEHA0IABNcnyxwqV6hY8QnhxxzFQ03C7HKW9OylMbnQZjjJ\
        /Au08/coZwxS7LfA4vOLS9WuneIXhbGGWvsDSb0tH6IxLm8wCgYIKoZIzj0EAwID\
        SQAwRgIhAP0RC1E+vwJD/D1AGHGzuri+hlV/PpQEKTWUVeORWz83AiEA5x2eXZOV\
        bUlJSGQgjwD5vaUaKlLR50Q2DmFfQj1L+SY=";
    /// RFC 8705 Appendix A, Figure 5.
    pub(crate) const RFC_8705_THUMBPRINT: &str = "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0";

    pub(crate) fn rfc_8705_certificate_der() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(RFC_8705_CERTIFICATE)
            .unwrap()
    }

    #[test]
    fn rfc_8705_appendix_a_thumbprint() {
        let der = rfc_8705_certificate_der();
        assert_eq!(certificate_thumbprint(&der).unwrap(), RFC_8705_THUMBPRINT);
        assert_eq!(
            certificate_confirmation(&der).unwrap(),
            Confirmation::X5tS256(RFC_8705_THUMBPRINT.to_owned())
        );
    }

    #[test]
    fn matching_is_exact_and_needs_x5t_s256() {
        let der = rfc_8705_certificate_der();
        let bound = Confirmation::X5tS256(RFC_8705_THUMBPRINT.to_owned());
        assert!(certificate_matches(&der, Some(&bound)).unwrap());

        // Another certificate: one flipped byte.
        let mut other = der.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(!certificate_matches(&other, Some(&bound)).unwrap());

        // Unbound, bound to a DPoP key with the same string, wrong case,
        // padded: none match.
        assert!(!certificate_matches(&der, None).unwrap());
        let jkt = Confirmation::Jkt(RFC_8705_THUMBPRINT.to_owned());
        assert!(!certificate_matches(&der, Some(&jkt)).unwrap());
        let lower = Confirmation::X5tS256(RFC_8705_THUMBPRINT.to_lowercase());
        assert!(!certificate_matches(&der, Some(&lower)).unwrap());
        let padded = Confirmation::X5tS256(format!("{RFC_8705_THUMBPRINT}="));
        assert!(!certificate_matches(&der, Some(&padded)).unwrap());
    }

    #[test]
    fn input_that_is_not_der_is_refused() {
        for bad in [
            &b""[..],
            b"0",
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        ] {
            assert!(matches!(
                certificate_thumbprint(bad).unwrap_err(),
                Error::InvalidConfiguration { .. }
            ));
            certificate_confirmation(bad).unwrap_err();
            certificate_matches(bad, None).unwrap_err();
        }
    }
}
