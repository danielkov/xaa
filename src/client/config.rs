//! The client's two registrations and the values a token exchange carries.
//! See RFC-003 §1–§3.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use url::Url;
use zeroize::Zeroizing;

use crate::claims::Issuer;
use crate::client_auth::ClientAuth;
use crate::metadata::ValidatedPrm;
use crate::secret::{IdToken, RefreshToken, SamlAssertion};

pub(super) const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
pub(super) const TOKEN_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
pub(super) const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";

/// The client's registration at the IdP (draft §5).
///
/// There is no way to configure this leg without client authentication: the
/// IdP MUST reject an unauthenticated token exchange (draft §4.3.3).
#[derive(Debug, Clone)]
pub struct IdpConnection {
    /// RFC 8414 issuer identifier. The `aud` of a `private_key_jwt` client
    /// assertion sent to this server.
    pub issuer: Issuer,
    pub token_endpoint: Url,
    pub client_auth: ClientAuth,
    /// Encoding for `saml2` subject tokens.
    pub saml_encoding: SamlEncoding,
}

/// How a SAML assertion is encoded as a `saml2` subject token.
///
/// RFC 8693 §3 defines the token type as base64url; the draft §4.5 example
/// uses padded standard base64. See `docs/interop.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SamlEncoding {
    /// base64url without padding (RFC 8693 §3).
    #[default]
    Base64Url,
    /// Standard base64 with padding, as in the draft §4.5 example.
    Base64,
}

impl SamlEncoding {
    pub(super) fn encode(self, assertion: &SamlAssertion) -> Zeroizing<String> {
        let xml = assertion.expose_secret();
        Zeroizing::new(match self {
            Self::Base64Url => URL_SAFE_NO_PAD.encode(xml),
            Self::Base64 => STANDARD.encode(xml),
        })
    }
}

/// The client's registration at the Resource AS (draft §5), separate from
/// the one at the IdP.
#[derive(Debug, Clone)]
pub struct ResourceAsConnection {
    /// RFC 8414 issuer identifier. The usual `audience` of the token
    /// exchange, and the value the ID-JAG's `aud` is checked against.
    pub issuer: Issuer,
    pub token_endpoint: Url,
    /// The client's credentials at the Resource AS. Its `client_id` is the
    /// one the ID-JAG must carry (draft §5.1).
    pub client_auth: ResourceAsClientAuth,
    /// Whether this AS supports
    /// `urn:ietf:params:oauth:grant-type:jwt-dpop`, from its metadata or
    /// from configuration.
    pub supports_jwt_dpop: bool,
}

/// How the client identifies itself at the Resource AS.
#[derive(Debug, Clone)]
pub enum ResourceAsClientAuth {
    Authenticated(ClientAuth),
    /// No client authentication. Allowed only with a sender-constrained
    /// ID-JAG (draft §4.4, §9.1); [`AccessTokenRequest::build`] refuses
    /// anything else.
    ///
    /// [`AccessTokenRequest::build`]: super::AccessTokenRequest::build
    SenderConstrainedOnly {
        client_id: String,
    },
}

impl ResourceAsClientAuth {
    /// The client identifier at the Resource AS.
    pub fn client_id(&self) -> &str {
        match self {
            Self::Authenticated(auth) => auth.client_id(),
            Self::SenderConstrainedOnly { client_id } => client_id,
        }
    }
}

/// The `subject_token` of a token exchange (draft §4.3).
///
/// IdPs MUST accept Identity Assertions and MAY accept Refresh Tokens; one
/// that does not answers a `RefreshToken` with `invalid_request`.
#[derive(Debug, Clone)]
pub enum SubjectToken {
    /// `urn:ietf:params:oauth:token-type:id_token`.
    IdToken(IdToken),
    /// `urn:ietf:params:oauth:token-type:saml2`. Encoded per
    /// [`IdpConnection::saml_encoding`].
    SamlAssertion(SamlAssertion),
    /// `urn:ietf:params:oauth:token-type:refresh_token`.
    RefreshToken(RefreshToken),
}

impl SubjectToken {
    /// The `subject_token` and `subject_token_type` parameter values.
    pub(super) fn parameters(&self, saml: SamlEncoding) -> (Zeroizing<String>, &'static str) {
        match self {
            Self::IdToken(token) => (
                Zeroizing::new(token.expose_secret().to_owned()),
                TOKEN_TYPE_ID_TOKEN,
            ),
            Self::SamlAssertion(assertion) => (saml.encode(assertion), TOKEN_TYPE_SAML2),
            Self::RefreshToken(token) => (
                Zeroizing::new(token.expose_secret().to_owned()),
                TOKEN_TYPE_REFRESH_TOKEN,
            ),
        }
    }
}

/// An `actor_token` with its `actor_token_type` (RFC 8693 §2.1).
///
/// Passed through only: the draft defines no processing for it (§4.3,
/// §9.10).
#[derive(Clone)]
pub struct ActorToken {
    token: Zeroizing<String>,
    token_type: String,
}

impl ActorToken {
    /// Wrap an actor token. `token_type` is its RFC 8693 §3 token type
    /// identifier. The token is zeroized when dropped.
    pub fn new(token: impl Into<String>, token_type: impl Into<String>) -> Self {
        Self {
            token: Zeroizing::new(token.into()),
            token_type: token_type.into(),
        }
    }

    /// The raw token. Do not log it or put it in a URL.
    pub fn expose_secret(&self) -> &str {
        self.token.as_str()
    }

    /// The `actor_token_type`.
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
}

impl std::fmt::Debug for ActorToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ActorToken(<{} bytes>, {:?})",
            self.token.len(),
            self.token_type
        )
    }
}

/// An RFC 8707 resource identifier, sent as a `resource` parameter.
///
/// The value is never rewritten: no trailing-slash, case, or percent-encoding
/// normalization (draft §4.3, §9.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceIdentifier(String);

impl ResourceIdentifier {
    /// A resource identifier from configuration, kept exactly as given.
    pub fn new(resource: impl Into<String>) -> Self {
        Self(resource.into())
    }

    /// The `resource` value of validated Protected Resource Metadata,
    /// byte-for-byte (draft §4.3 MUST).
    pub fn from_metadata(metadata: &ValidatedPrm) -> Self {
        Self(metadata.resource().to_owned())
    }

    /// The identifier as it is sent.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `audience` of a token exchange: exactly one value by construction
/// (draft §4.3).
///
/// Usually the Resource AS issuer; may be an IdP-specific alias such as
/// `urn:example:idp:saas-tool`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExchangeAudience(String);

impl ExchangeAudience {
    /// An audience value, kept exactly as given.
    pub fn new(audience: impl Into<String>) -> Self {
        Self(audience.into())
    }

    /// The value as it is sent.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<Issuer> for ExchangeAudience {
    fn from(issuer: Issuer) -> Self {
        Self(issuer.as_str().to_owned())
    }
}

impl From<&Issuer> for ExchangeAudience {
    fn from(issuer: &Issuer) -> Self {
        Self(issuer.as_str().to_owned())
    }
}
