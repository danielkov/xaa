//! Token-exchange request parsing. See RFC-005 §2.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use crate::claims::{AuthorizationDetails, Scope};
use crate::client_auth::{ClientCredentials, CredentialsError};
use crate::dpop::DPOP_HEADER;
use crate::form::{Form, Repeated, header_values};
use crate::metadata::{GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ID_JAG};
use crate::mtls::certificate_thumbprint;
use crate::secret::{IdToken, RefreshToken, SamlAssertion};

use super::error::{ExchangeError, RejectReason};
use super::subject::SubjectTokenInput;
use super::{TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_REFRESH_TOKEN, TOKEN_TYPE_SAML2};

const PADDING_OPTIONAL: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
/// base64url, padded or not (RFC 8693 §3).
const BASE64URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, PADDING_OPTIONAL);
/// Standard base64, as in the draft §4.5 example.
const BASE64: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, PADDING_OPTIONAL);

/// What the client asks the IdP to issue (`requested_token_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestedTokenType {
    /// `urn:ietf:params:oauth:token-type:id-jag` (draft §4.3). Handled by
    /// [`Idp::exchange`](super::Idp::exchange).
    IdJag,
    /// `urn:ietf:params:oauth:token-type:refresh_token` (draft §4.5).
    /// Handled by
    /// [`Idp::exchange_saml_for_refresh_token`](super::Idp::exchange_saml_for_refresh_token).
    RefreshToken,
}

impl RequestedTokenType {
    /// The token type URI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdJag => TOKEN_TYPE_ID_JAG,
            Self::RefreshToken => TOKEN_TYPE_REFRESH_TOKEN,
        }
    }
}

/// The kind of subject token presented (`subject_token_type`, draft §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectTokenType {
    IdToken,
    Saml2,
    RefreshToken,
}

impl SubjectTokenType {
    /// The token type URI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdToken => TOKEN_TYPE_ID_TOKEN,
            Self::Saml2 => TOKEN_TYPE_SAML2,
            Self::RefreshToken => TOKEN_TYPE_REFRESH_TOKEN,
        }
    }
}

/// The presented subject token, owned by the parsed request.
#[derive(Debug, Clone)]
enum SubjectToken {
    IdToken(IdToken),
    /// The decoded assertion XML.
    Saml2(SamlAssertion),
    RefreshToken(RefreshToken),
}

/// A parsed RFC 8693 token-exchange request (RFC-005 §2).
///
/// Parsing checks shape only. Nothing in it is trusted until
/// [`Idp::exchange`](super::Idp::exchange) has run.
#[derive(Clone)]
pub struct TokenExchangeRequest {
    requested_token_type: RequestedTokenType,
    audience: Option<String>,
    resources: Vec<String>,
    scope: Option<Scope>,
    subject_token: SubjectToken,
    authorization_details: Option<AuthorizationDetails>,
    has_actor_token: bool,
    credentials: ClientCredentials,
    dpop_headers: Vec<(String, String)>,
    certificate_x5t_s256: Option<String>,
}

impl TokenExchangeRequest {
    /// Parse a token-endpoint request.
    ///
    /// `tls_client_cert` is the client certificate in DER, already validated
    /// by the TLS layer (RFC 8705 §2).
    ///
    /// | Condition | Error |
    /// | --- | --- |
    /// | `grant_type` is not token-exchange | `unsupported_grant_type` |
    /// | `requested_token_type` is missing, or neither the ID-JAG nor the refresh token type | `invalid_request` |
    /// | `audience` missing for an ID-JAG, or repeated | `invalid_request` |
    /// | `subject_token` or `subject_token_type` missing or unsupported | `invalid_request` |
    /// | a `saml2` token that is not base64url or base64, or mixes both | `invalid_request` |
    /// | `actor_token` without `actor_token_type`, or the reverse | `invalid_request` |
    /// | malformed `authorization_details` | `invalid_request` |
    /// | a non-repeatable parameter repeated, or two client authentication methods | `invalid_request` |
    /// | malformed `scope` | `invalid_scope` |
    /// | unusable client credentials | `invalid_client` |
    ///
    /// Whether the refresh token type is enabled is checked later, by
    /// [`Idp::exchange_saml_for_refresh_token`](super::Idp::exchange_saml_for_refresh_token):
    /// parsing takes no configuration.
    pub fn parse(
        form_body: &[u8],
        headers: &[(String, String)],
        tls_client_cert: Option<&[u8]>,
    ) -> Result<Self, ExchangeError> {
        let form = Form::parse(form_body);
        let one = |name: &'static str| {
            form.one(name).map_err(|Repeated(repeated)| {
                ExchangeError::new(RejectReason::RepeatedParameter { name: repeated })
            })
        };
        let required = |name: &'static str| {
            one(name)?.ok_or(ExchangeError::new(RejectReason::MissingParameter { name }))
        };

        // First, so a caller can route other grants elsewhere.
        if one("grant_type")? != Some(GRANT_TYPE_TOKEN_EXCHANGE) {
            return Err(RejectReason::UnsupportedGrantType.into());
        }

        let requested_token_type = match required("requested_token_type")? {
            TOKEN_TYPE_ID_JAG => RequestedTokenType::IdJag,
            TOKEN_TYPE_REFRESH_TOKEN => RequestedTokenType::RefreshToken,
            _ => return Err(RejectReason::UnsupportedRequestedTokenType.into()),
        };

        // Exactly one audience for an ID-JAG (draft §4.3.3). The §4.5
        // exchange names none.
        let audience = one("audience")?.map(str::to_owned);
        if requested_token_type == RequestedTokenType::IdJag && audience.is_none() {
            return Err(RejectReason::MissingParameter { name: "audience" }.into());
        }

        let subject_token = required("subject_token")?;
        let subject_token = match required("subject_token_type")? {
            TOKEN_TYPE_ID_TOKEN => SubjectToken::IdToken(IdToken::new(subject_token)),
            TOKEN_TYPE_REFRESH_TOKEN => {
                SubjectToken::RefreshToken(RefreshToken::new(subject_token))
            }
            TOKEN_TYPE_SAML2 => SubjectToken::Saml2(SamlAssertion::new(
                decode_saml(subject_token).ok_or(RejectReason::MalformedSamlEncoding)?,
            )),
            _ => return Err(RejectReason::UnsupportedSubjectTokenType.into()),
        };

        // Accepted and ignored: the draft defines no processing for it
        // (§4.3, §9.10).
        let has_actor_token = match (one("actor_token")?, one("actor_token_type")?) {
            (Some(_), Some(_)) => true,
            (None, None) => false,
            _ => return Err(RejectReason::ActorTokenTypeMismatch.into()),
        };

        let authorization_details = one("authorization_details")?
            .map(AuthorizationDetails::from_json_str)
            .transpose()
            .map_err(|source| {
                ExchangeError::with_source(RejectReason::MalformedAuthorizationDetails, source)
            })?;

        let scope = one("scope")?
            .map(Scope::parse)
            .transpose()
            .map_err(|source| ExchangeError::with_source(RejectReason::MalformedScope, source))?;

        // RFC 8707 §2: may repeat. Kept in order and byte-for-byte; a
        // parameter without a value is omitted (RFC 6749 §3.2).
        let resources = form
            .all("resource")
            .into_iter()
            .filter(|resource| !resource.is_empty())
            .map(str::to_owned)
            .collect();

        let credentials = ClientCredentials::extract(&form, headers, tls_client_cert.is_some())
            .map_err(|error| match error {
                CredentialsError::MultipleMethods => {
                    ExchangeError::new(RejectReason::MultipleClientAuthMethods)
                }
                CredentialsError::Repeated => ExchangeError::new(RejectReason::RepeatedParameter {
                    name: "client credentials",
                }),
                CredentialsError::Malformed => {
                    ExchangeError::new(RejectReason::MalformedClientCredentials)
                        .with_basic_challenge(has_basic_authorization(headers))
                }
            })?;

        let certificate_x5t_s256 = tls_client_cert
            .map(certificate_thumbprint)
            .transpose()
            .map_err(|source| {
                ExchangeError::with_source(RejectReason::InvalidClientCertificate, source)
            })?;

        let dpop_headers = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(DPOP_HEADER))
            .cloned()
            .collect();

        Ok(Self {
            requested_token_type,
            audience,
            resources,
            scope,
            subject_token,
            authorization_details,
            has_actor_token,
            credentials,
            dpop_headers,
            certificate_x5t_s256,
        })
    }

    /// What the client asks for. Decides which [`Idp`](super::Idp) method
    /// handles the request.
    pub fn requested_token_type(&self) -> RequestedTokenType {
        self.requested_token_type
    }

    /// The `audience` exactly as sent. Always present for an ID-JAG request.
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// The `resource` values, in order and byte-for-byte.
    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    /// The requested scope.
    pub fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    /// The presented subject token. A `saml2` token is already decoded to
    /// the assertion XML.
    pub fn subject_token(&self) -> SubjectTokenInput<'_> {
        match &self.subject_token {
            SubjectToken::IdToken(token) => SubjectTokenInput::IdToken(token),
            SubjectToken::Saml2(assertion) => SubjectTokenInput::Saml2(assertion),
            SubjectToken::RefreshToken(token) => SubjectTokenInput::RefreshToken(token),
        }
    }

    /// The kind of subject token presented.
    pub fn subject_token_type(&self) -> SubjectTokenType {
        self.subject_token().token_type()
    }

    /// The requested RFC 9396 authorization details.
    pub fn authorization_details(&self) -> Option<&AuthorizationDetails> {
        self.authorization_details.as_ref()
    }

    /// Whether an `actor_token` was sent. It is ignored: the draft defines
    /// no processing for it, and no `act` claim is ever emitted (§9.10).
    pub fn has_actor_token(&self) -> bool {
        self.has_actor_token
    }

    /// The client credentials as presented: extracted, not verified. The
    /// caller verifies them and reports a
    /// [`ClientIdentity`](crate::client_auth::ClientIdentity) (RFC-005 §3).
    pub fn client_credentials(&self) -> &ClientCredentials {
        &self.credentials
    }

    /// Whether the request carries a `DPoP` header.
    pub fn has_dpop_proof(&self) -> bool {
        !self.dpop_headers.is_empty()
    }

    /// The `x5t#S256` of the presented TLS client certificate.
    pub fn certificate_thumbprint(&self) -> Option<&str> {
        self.certificate_x5t_s256.as_deref()
    }

    /// `invalid_client` for this request, for a caller whose verification of
    /// the credentials failed: 401 with `WWW-Authenticate: Basic` when the
    /// client used the `Authorization` header (RFC 6749 §5.2), 400 otherwise.
    pub fn invalid_client(&self) -> ExchangeError {
        ExchangeError::invalid_client().with_basic_challenge(self.used_basic())
    }

    pub(crate) fn used_basic(&self) -> bool {
        matches!(self.credentials, ClientCredentials::Basic { .. })
    }

    pub(crate) fn dpop_headers(&self) -> &[(String, String)] {
        &self.dpop_headers
    }
}

impl std::fmt::Debug for TokenExchangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeRequest")
            .field("requested_token_type", &self.requested_token_type)
            .field("audience", &self.audience)
            .field("resources", &self.resources)
            .field("scope", &self.scope)
            .field("subject_token", &self.subject_token)
            .field("authorization_details", &self.authorization_details)
            .field("has_actor_token", &self.has_actor_token)
            .field("credentials", &self.credentials)
            .field("certificate_x5t_s256", &self.certificate_x5t_s256)
            .finish_non_exhaustive()
    }
}

fn has_basic_authorization(headers: &[(String, String)]) -> bool {
    header_values(headers, "authorization").iter().any(|value| {
        value
            .split_once(' ')
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
    })
}

/// Decode a `saml2` subject token (RFC-005 §2).
///
/// RFC 8693 §3 says base64url; the draft §4.5 example uses standard base64.
/// The alphabets differ only in `-_` versus `+/`, so the characters present
/// pick one. A token that mixes them, or decodes to nothing, is refused.
fn decode_saml(token: &str) -> Option<Vec<u8>> {
    let url_safe = token.bytes().any(|byte| matches!(byte, b'-' | b'_'));
    let standard = token.bytes().any(|byte| matches!(byte, b'+' | b'/'));
    let decoded = match (url_safe, standard) {
        (true, true) => return None,
        (false, true) => BASE64.decode(token.as_bytes()),
        (true | false, false) => BASE64URL.decode(token.as_bytes()),
    };
    decoded.ok().filter(|bytes| !bytes.is_empty())
}
