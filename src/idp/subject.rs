//! Subject token verification. See RFC-005 §4.
//!
//! The IdP issued the subject token itself, so the draft lets it identify
//! and validate that token by deployment-specific means (§4.3.3). That is the
//! caller's [`SubjectTokenVerifier`]. [`IdTokenVerifier`] covers the common
//! case of an ID Token signed with the IdP's own keys.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::hash::BuildHasher;
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::claims::{Audience, Issuer, NumericDate};
use crate::client_auth::ClientAuthMethod;
use crate::jose::{AlgorithmPolicy, ExpectedTyp, JwkSet, ParseLimits, UnverifiedJws, verify};
use crate::secret::{IdToken, RefreshToken, SamlAssertion};

use super::request::SubjectTokenType;

/// The client that authenticated to the token endpoint (RFC-005 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedClient {
    /// The client's identifier at this IdP.
    pub client_id: String,
    pub method: ClientAuthMethod,
}

/// The subject token of a request, by type (draft §4.3).
#[derive(Debug, Clone, Copy)]
pub enum SubjectTokenInput<'a> {
    /// An OpenID Connect ID Token.
    IdToken(&'a IdToken),
    /// A SAML 2.0 assertion: the decoded XML. Its signature is not checked
    /// yet; that is the verifier's job.
    Saml2(&'a SamlAssertion),
    /// A refresh token this IdP issued.
    RefreshToken(&'a RefreshToken),
}

impl SubjectTokenInput<'_> {
    /// The kind of token.
    pub fn token_type(&self) -> SubjectTokenType {
        match self {
            Self::IdToken(_) => SubjectTokenType::IdToken,
            Self::Saml2(_) => SubjectTokenType::Saml2,
            Self::RefreshToken(_) => SubjectTokenType::RefreshToken,
        }
    }
}

/// The caller's handle for an End-User: whatever its user directory keys on.
/// It never leaves the IdP; the `sub` of an ID-JAG comes from the
/// [`ExchangeGrant`](super::ExchangeGrant).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectRef(String);

impl SubjectRef {
    /// Wrap the caller's user handle.
    pub fn new(subject: impl Into<String>) -> Self {
        Self(subject.into())
    }

    /// The handle.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a verified subject token says (RFC-005 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSubject {
    /// The caller's handle for the End-User.
    pub subject: SubjectRef,
    /// ID Token `aud`, or the client a Refresh Token is bound to (an OAuth
    /// client_id). Compared with the authenticated client (draft §4.3.3).
    pub issued_to_client: Option<String>,
    /// For SAML assertions: the `AudienceRestriction` value (SP entity ID).
    pub saml_audience: Option<String>,
    /// The End-User's tenant at this issuer (draft §6.4). Required for
    /// multi-tenant issuers.
    pub issuer_tenant: Option<String>,
    pub auth_time: Option<NumericDate>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
}

impl VerifiedSubject {
    /// A subject with nothing else set.
    pub fn new(subject: SubjectRef) -> Self {
        Self {
            subject,
            issued_to_client: None,
            saml_audience: None,
            issuer_tenant: None,
            auth_time: None,
            acr: None,
            amr: None,
        }
    }
}

/// Why a subject token was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectRejection {
    /// Not a valid token of this IdP: `invalid_request` (draft §4.3.4.3).
    Invalid,
    /// The user must authenticate again or more strongly:
    /// `insufficient_user_authentication` (draft §9.3, RFC 9470 §3).
    StepUpRequired {
        max_age: Option<u64>,
        acr_values: Option<String>,
    },
}

/// Verifies subject tokens this IdP issued (RFC-005 §4.1).
///
/// The implementation positively identifies the token as its own (a marker
/// claim, a dedicated key, an issuance record), checks its signature and
/// validity, and says who it was issued to. The library then enforces the
/// client binding whatever the verifier returned (RFC-005 §4.2).
pub trait SubjectTokenVerifier: Send + Sync {
    /// Verify `token`, presented by `client`.
    fn verify(
        &self,
        token: &SubjectTokenInput<'_>,
        client: &AuthenticatedClient,
        now: SystemTime,
    ) -> impl Future<Output = Result<VerifiedSubject, SubjectRejection>> + Send;
}

/// Maps a SAML `Audience` (SP entity ID) to the OAuth client it belongs to
/// (draft §4.5 MUST, §3.2.2).
pub trait SamlAudienceMap: Send + Sync {
    /// Whether an assertion issued to `saml_audience` may be exchanged by
    /// `client_id`.
    fn maps_to_client(&self, saml_audience: &str, client_id: &str) -> bool;
}

/// SP entity ID → client_id.
impl<H: BuildHasher + Send + Sync> SamlAudienceMap for HashMap<String, String, H> {
    fn maps_to_client(&self, saml_audience: &str, client_id: &str) -> bool {
        self.get(saml_audience)
            .is_some_and(|mapped| mapped == client_id)
    }
}

/// SP entity ID → client_id.
impl SamlAudienceMap for BTreeMap<String, String> {
    fn maps_to_client(&self, saml_audience: &str, client_id: &str) -> bool {
        self.get(saml_audience)
            .is_some_and(|mapped| mapped == client_id)
    }
}

/// A verifier that accepts nothing. The default fallback of
/// [`IdTokenVerifier`], for an IdP that takes only ID Tokens.
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectOtherSubjectTokens;

impl SubjectTokenVerifier for RejectOtherSubjectTokens {
    fn verify(
        &self,
        _token: &SubjectTokenInput<'_>,
        _client: &AuthenticatedClient,
        _now: SystemTime,
    ) -> impl Future<Output = Result<VerifiedSubject, SubjectRejection>> + Send {
        std::future::ready(Err(SubjectRejection::Invalid))
    }
}

/// The verified claims of an ID Token, handed to the caller's subject
/// mapping function.
#[derive(Debug, Clone)]
pub struct IdTokenClaims {
    /// The `sub` claim.
    pub sub: String,
    /// The party the token was issued to: the sole `aud`, or `azp`.
    pub issued_to_client: String,
    /// Every claim of the token.
    pub claims: Map<String, Value>,
}

/// What the caller's mapping function returns for a recognized subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenSubject {
    /// The caller's handle for the End-User.
    pub subject: SubjectRef,
    /// The End-User's tenant at this issuer (draft §6.4).
    pub issuer_tenant: Option<String>,
}

/// The built-in ID Token verifier (RFC-005 §4.3).
///
/// Checks that the token is a JWS signed with one of the IdP's own keys,
/// that `iss` is this IdP, the time window, and the OIDC Core §2 `aud` /
/// `azp` rule; then asks `map_subject` who the user is. It reports the sole
/// `aud`, or `azp`, as the party the token was issued to.
///
/// It does not check `nonce`, `at_hash`, or `c_hash`: those bind an ID Token
/// to an authentication response, which is the relying party's check at
/// login.
///
/// `saml2` and `refresh_token` subject tokens go to the fallback verifier.
#[derive(Debug, Clone)]
pub struct IdTokenVerifier<M, V = RejectOtherSubjectTokens> {
    issuer: Issuer,
    keys: JwkSet,
    algorithms: AlgorithmPolicy,
    clock_skew: Duration,
    map_subject: M,
    fallback: V,
}

impl<M> IdTokenVerifier<M>
where
    M: Fn(&IdTokenClaims) -> Option<IdTokenSubject> + Send + Sync,
{
    /// `keys` are the IdP's own public keys, current and retired.
    /// `map_subject` returns `None` for a subject it does not recognize.
    pub fn new(
        issuer: Issuer,
        keys: JwkSet,
        algorithms: AlgorithmPolicy,
        clock_skew: Duration,
        map_subject: M,
    ) -> Self {
        Self {
            issuer,
            keys,
            algorithms,
            clock_skew,
            map_subject,
            fallback: RejectOtherSubjectTokens,
        }
    }
}

impl<M, V> IdTokenVerifier<M, V> {
    /// Send `saml2` and `refresh_token` subject tokens to `fallback`.
    pub fn with_fallback<W: SubjectTokenVerifier>(self, fallback: W) -> IdTokenVerifier<M, W> {
        IdTokenVerifier {
            issuer: self.issuer,
            keys: self.keys,
            algorithms: self.algorithms,
            clock_skew: self.clock_skew,
            map_subject: self.map_subject,
            fallback,
        }
    }
}

impl<M, V> IdTokenVerifier<M, V>
where
    M: Fn(&IdTokenClaims) -> Option<IdTokenSubject> + Send + Sync,
{
    fn verify_id_token(
        &self,
        token: &IdToken,
        now: SystemTime,
    ) -> Result<VerifiedSubject, SubjectRejection> {
        const INVALID: SubjectRejection = SubjectRejection::Invalid;

        // The `typ` allow-list of RFC-005 §4.2 has already run.
        let jws = UnverifiedJws::parse(token.expose_secret(), &ParseLimits::default())
            .map_err(|_source| INVALID)?;
        let claims =
            verify::<Map<String, Value>>(&jws, ExpectedTyp::Any, &self.keys, &self.algorithms)
                .map_err(|_source| INVALID)?
                .into_claims();

        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(INVALID);
        }
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|sub| !sub.is_empty())
            .ok_or(INVALID)?
            .to_owned();

        let date = |name: &str| match claims.get(name) {
            None => Ok(None),
            Some(value) => NumericDate::from_json(value).map(Some).ok_or(INVALID),
        };
        let instant = |name: &str| match date(name)? {
            None => Ok(None),
            Some(date) => date.to_system_time().map(Some).map_err(|_source| INVALID),
        };
        let earliest = now.checked_sub(self.clock_skew).ok_or(INVALID)?;
        let latest = now.checked_add(self.clock_skew).ok_or(INVALID)?;
        if instant("exp")?.ok_or(INVALID)? <= earliest {
            return Err(INVALID);
        }
        for name in ["iat", "nbf"] {
            if instant(name)?.is_some_and(|time| time > latest) {
                return Err(INVALID);
            }
        }

        // OIDC Core §2: one audience, or several with `azp` naming one.
        let audience = claims
            .get("aud")
            .cloned()
            .and_then(|aud| serde_json::from_value::<Audience>(aud).ok())
            .ok_or(INVALID)?;
        let issued_to_client = match audience.values() {
            [] => return Err(INVALID),
            [only] => only.clone(),
            several => {
                let azp = claims.get("azp").and_then(Value::as_str).ok_or(INVALID)?;
                if !several.iter().any(|value| value == azp) {
                    return Err(INVALID);
                }
                azp.to_owned()
            }
        };

        let auth_time = date("auth_time")?;
        let acr = match claims.get("acr") {
            None => None,
            Some(Value::String(acr)) => Some(acr.clone()),
            Some(_) => return Err(INVALID),
        };
        let amr = match claims.get("amr") {
            None => None,
            Some(value) => Some(
                serde_json::from_value::<Vec<String>>(value.clone()).map_err(|_source| INVALID)?,
            ),
        };

        let id_token = IdTokenClaims {
            sub,
            issued_to_client,
            claims,
        };
        let mapped = (self.map_subject)(&id_token).ok_or(INVALID)?;
        Ok(VerifiedSubject {
            subject: mapped.subject,
            issued_to_client: Some(id_token.issued_to_client),
            saml_audience: None,
            issuer_tenant: mapped.issuer_tenant,
            auth_time,
            acr,
            amr,
        })
    }
}

impl<M, V> SubjectTokenVerifier for IdTokenVerifier<M, V>
where
    M: Fn(&IdTokenClaims) -> Option<IdTokenSubject> + Send + Sync,
    V: SubjectTokenVerifier,
{
    async fn verify(
        &self,
        token: &SubjectTokenInput<'_>,
        client: &AuthenticatedClient,
        now: SystemTime,
    ) -> Result<VerifiedSubject, SubjectRejection> {
        match token {
            SubjectTokenInput::IdToken(id_token) => self.verify_id_token(id_token, now),
            SubjectTokenInput::Saml2(_) | SubjectTokenInput::RefreshToken(_) => {
                self.fallback.verify(token, client, now).await
            }
        }
    }
}
