//! Secret newtypes. See RFC-002 §11 and draft §9.2.
//!
//! Subject tokens, ID-JAGs, access tokens, and client credentials are
//! high-value bearer credentials. Each is a distinct type with no `Display`
//! and a `Debug` that prints only the type name and length. Reading the value
//! takes an explicit [`expose_secret`](IdJag::expose_secret) call, so every
//! place a credential leaves the type shows up in review.

use zeroize::Zeroizing;

macro_rules! secret_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(Zeroizing<String>);

        impl $name {
            /// Wrap a credential. The value is zeroized when dropped.
            pub fn new(value: impl Into<String>) -> Self {
                Self(Zeroizing::new(value.into()))
            }

            /// The raw credential. Do not log it or put it in a URL.
            pub fn expose_secret(&self) -> &str {
                self.0.as_str()
            }

            /// Whether this credential equals `other`, compared in constant
            /// time with respect to the contents. Use this, not `==` on the
            /// exposed strings, when checking a presented credential against
            /// a stored one. The lengths are not hidden.
            pub fn ct_eq(&self, other: &str) -> bool {
                use subtle::ConstantTimeEq as _;
                self.0.as_bytes().ct_eq(other.as_bytes()).into()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "(<{} bytes>)"), self.0.len())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }
    };
}

secret_newtype!(
    /// An OpenID Connect ID Token, used as a `subject_token` (draft §4.3).
    IdToken
);
secret_newtype!(
    /// A refresh token: a `subject_token` (draft §4.3) or the result of the
    /// SAML exchange (draft §4.5).
    RefreshToken
);
secret_newtype!(
    /// An Identity Assertion JWT Authorization Grant in compact form.
    IdJag
);
secret_newtype!(
    /// An access token issued by a Resource Authorization Server.
    AccessToken
);
secret_newtype!(
    /// An OAuth client secret.
    ClientSecret
);
secret_newtype!(
    /// A signed client-authentication JWT (`private_key_jwt`).
    ClientAssertion
);

/// A SAML 2.0 assertion: the XML document, not its transport encoding.
#[derive(Clone)]
pub struct SamlAssertion(Zeroizing<Vec<u8>>);

impl SamlAssertion {
    /// Wrap the assertion XML bytes. The value is zeroized when dropped.
    pub fn new(xml: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(xml.into()))
    }

    /// The raw assertion XML. Do not log it or put it in a URL.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::fmt::Debug for SamlAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SamlAssertion(<{} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_type_and_length_only() {
        let token = IdJag::new("eyJhbGciOiJSUzI1NiJ9.secret.sig");
        let printed = format!("{token:?}");
        assert_eq!(printed, "IdJag(<31 bytes>)");
        assert!(!printed.contains("secret"));

        let saml = SamlAssertion::new(b"<Assertion>alice</Assertion>".to_vec());
        let printed = format!("{saml:?}");
        assert_eq!(printed, "SamlAssertion(<28 bytes>)");
    }

    #[test]
    fn ct_eq_compares_contents() {
        let secret = ClientSecret::new("s3cret");
        assert!(secret.ct_eq("s3cret"));
        assert!(!secret.ct_eq("s3creT"));
        assert!(!secret.ct_eq("s3cre"));
        assert!(!secret.ct_eq(""));
    }

    #[test]
    fn expose_secret_returns_the_value() {
        assert_eq!(ClientSecret::new("s3cret").expose_secret(), "s3cret");
    }
}
