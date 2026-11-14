//! The token exchange itself: the RFC-005 §3–§8 pipeline, the responses of
//! §9, and the audit record of §10.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::claims::{
    Audience, AuthorizationDetails, Confirmation, IdJagClaims, Issuer, NumericDate, Resources,
    Scope, SubjectIdentifier,
};
use crate::client_auth::{ClientIdentity, random_id};
use crate::dpop::{DpopValidation, IdpBinding, ValidatedDpopProof, validate_dpop_proof};
use crate::error::Error;
use crate::http::HttpResponse;
use crate::jose::{peek_typ, sign_jws};
use crate::metadata::TOKEN_TYPE_ID_JAG;
use crate::oauth_error::{OAuthErrorCode, json_no_store_headers};
use crate::secret::{IdJag, RefreshToken};

use super::error::{ExchangeError, RejectReason};
use super::policy::{ExchangeContext, ExchangeDenial, ExchangeGrant, ExchangePolicy};
use super::request::{RequestedTokenType, SubjectTokenType, TokenExchangeRequest};
use super::subject::{
    AuthenticatedClient, SubjectRejection, SubjectTokenInput, SubjectTokenVerifier, VerifiedSubject,
};
use super::{
    ID_JAG_TYP, Idp, IdpTenancy, ResourceAsDirectory, ResourceAsEntry, TOKEN_TYPE_REFRESH_TOKEN,
    normalize_typ,
};

/// `token_type` of a token-exchange response whose token is not an access
/// token (RFC 8693 §2.2.1).
const TOKEN_TYPE_N_A: &str = "N_A";

/// An issued ID-JAG and its response (RFC-005 §7, §9).
#[derive(Debug, Clone)]
pub struct IssuedIdJag {
    id_jag: IdJag,
    claims: IdJagClaims,
    expires_in: Duration,
}

impl IssuedIdJag {
    /// The signed ID-JAG.
    pub fn id_jag(&self) -> &IdJag {
        &self.id_jag
    }

    /// The claims that were signed.
    pub fn claims(&self) -> &IdJagClaims {
        &self.claims
    }

    /// The ID-JAG's lifetime.
    pub fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// The RFC 8693 §2.2.1 response (draft §4.3.4): the ID-JAG in
    /// `access_token`, `token_type` `N_A`, and the granted `scope` and
    /// `authorization_details` whenever there are any. There is never a
    /// `refresh_token` (draft §4.3.4 SHOULD NOT).
    pub fn to_response(&self) -> HttpResponse {
        let mut body = Map::new();
        body.insert("issued_token_type".to_owned(), TOKEN_TYPE_ID_JAG.into());
        body.insert(
            "access_token".to_owned(),
            self.id_jag.expose_secret().into(),
        );
        body.insert("token_type".to_owned(), TOKEN_TYPE_N_A.into());
        body.insert("expires_in".to_owned(), self.expires_in.as_secs().into());
        if let Some(scope) = &self.claims.scope {
            body.insert("scope".to_owned(), scope.as_str().into());
        }
        if let Some(details) = &self.claims.authorization_details
            && let Ok(details) = serde_json::to_value(details)
        {
            body.insert("authorization_details".to_owned(), details);
        }
        success_response(body)
    }
}

/// An approved SAML → Refresh Token exchange (draft §4.5, RFC-005 §8).
///
/// The library has verified the request; the caller mints the Refresh Token
/// for [`subject`](Self::subject) and [`client`](Self::client) and hands it
/// to [`token_response`](Self::token_response).
#[derive(Debug, Clone)]
pub struct SamlRefreshExchange {
    client: AuthenticatedClient,
    subject: VerifiedSubject,
    requested_scope: Option<Scope>,
}

impl SamlRefreshExchange {
    /// The authenticated client the Refresh Token is for.
    pub fn client(&self) -> &AuthenticatedClient {
        &self.client
    }

    /// The End-User the assertion identifies.
    pub fn subject(&self) -> &VerifiedSubject {
        &self.subject
    }

    /// The scope the client asked for. Draft §4.5 says it SHOULD include
    /// `openid offline_access`; that is not enforced.
    pub fn requested_scope(&self) -> Option<&Scope> {
        self.requested_scope.as_ref()
    }

    /// The response carrying the Refresh Token the caller minted:
    /// `issued_token_type` is the refresh token type, the token is in
    /// `access_token` (RFC 8693 §2.2.1), and `token_type` is `N_A`.
    pub fn token_response(
        &self,
        refresh_token: &RefreshToken,
        scope: Option<&Scope>,
        expires_in: Option<Duration>,
    ) -> HttpResponse {
        let mut body = Map::new();
        body.insert(
            "issued_token_type".to_owned(),
            TOKEN_TYPE_REFRESH_TOKEN.into(),
        );
        body.insert(
            "access_token".to_owned(),
            refresh_token.expose_secret().into(),
        );
        body.insert("token_type".to_owned(), TOKEN_TYPE_N_A.into());
        if let Some(scope) = scope {
            body.insert("scope".to_owned(), scope.as_str().into());
        }
        if let Some(expires_in) = expires_in {
            body.insert("expires_in".to_owned(), expires_in.as_secs().into());
        }
        success_response(body)
    }
}

fn success_response(body: Map<String, Value>) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: json_no_store_headers(),
        // Serializing a JSON value to memory cannot fail.
        body: serde_json::to_vec(&Value::Object(body)).unwrap_or_default(),
    }
}

/// The audit record of one exchange (draft §9.2, RFC-005 §10). Every
/// outcome, success or refusal, produces one. It contains no tokens.
///
/// How long to keep records, and how users or admins review and revoke
/// cross-app access, is the caller's (draft §10).
#[derive(Debug, Clone, PartialEq)]
pub struct ExchangeRecord {
    pub at: SystemTime,
    /// The authenticated client. For an `invalid_client` refusal: the
    /// client_id the request claimed, if any, which proves nothing.
    pub client_id: Option<String>,
    /// The `audience` as requested. `None` only where the request has none:
    /// the draft §4.5 exchange, or a request that failed to parse.
    pub audience: Option<String>,
    /// The Resource AS the audience resolved to, if it got that far.
    pub resolved_issuer: Option<Issuer>,
    pub requested_resources: Vec<String>,
    pub requested_scope: Option<Scope>,
    pub outcome: ExchangeOutcome,
}

impl ExchangeRecord {
    /// A record for a refusal that happened outside
    /// [`Idp::exchange`]: a request that did not parse, or a client whose
    /// credentials the caller rejected.
    pub fn for_rejection(at: SystemTime, client_id: Option<&str>, error: &ExchangeError) -> Self {
        Self {
            at,
            client_id: client_id.map(str::to_owned),
            audience: None,
            resolved_issuer: None,
            requested_resources: Vec::new(),
            requested_scope: None,
            outcome: ExchangeOutcome::rejected(error),
        }
    }

    fn of(
        request: &TokenExchangeRequest,
        client: &ClientIdentity,
        resolved_issuer: Option<Issuer>,
        outcome: ExchangeOutcome,
        at: SystemTime,
    ) -> Self {
        let client_id = match client {
            ClientIdentity::Authenticated { client_id, .. } => Some(client_id.clone()),
            ClientIdentity::Unauthenticated { client_id } => client_id.clone(),
        };
        Self {
            at,
            client_id,
            audience: request.audience().map(str::to_owned),
            resolved_issuer,
            requested_resources: request.resources().to_vec(),
            requested_scope: request.scope().cloned(),
            outcome,
        }
    }
}

/// How an exchange ended.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ExchangeOutcome {
    /// An ID-JAG was issued.
    Issued {
        /// The ID-JAG's `jti`.
        jti: String,
        granted: GrantedAccess,
    },
    /// A SAML → Refresh Token exchange was approved; the caller mints the
    /// token (draft §4.5).
    RefreshTokenApproved,
    /// The exchange was refused.
    Rejected {
        code: OAuthErrorCode,
        reason: RejectReason,
    },
}

impl ExchangeOutcome {
    fn rejected(error: &ExchangeError) -> Self {
        Self::Rejected {
            code: error.code().clone(),
            reason: error.reason().clone(),
        }
    }
}

/// What an issued ID-JAG grants, for the audit record.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantedAccess {
    /// The client's identifier at the Resource AS.
    pub client_id: String,
    /// The End-User's identifier at the Resource AS.
    pub sub: String,
    pub resources: Vec<String>,
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    /// The key or certificate the ID-JAG is bound to, if any.
    pub confirmation: Option<Confirmation>,
    pub expires_at: NumericDate,
}

/// The caller's collaborators for one exchange.
struct Parties<'a, S, D: ?Sized, P> {
    subjects: &'a S,
    directory: &'a D,
    policy: &'a P,
}

impl Idp {
    /// Process a token-exchange request for an ID-JAG (draft §4.3.3).
    ///
    /// `client` is the result of the caller's check of
    /// [`TokenExchangeRequest::client_credentials`]. In order:
    ///
    /// 1. The client must be authenticated, with no exception
    ///    (`invalid_client`).
    /// 2. A DPoP proof, if DPoP is enabled and one was sent, must be valid
    ///    (`invalid_dpop_proof`, `use_dpop_nonce`).
    /// 3. The subject token passes the `typ` allow-list, the caller's
    ///    `subjects` verifier, and the client-binding checks of RFC-005 §4.2
    ///    (`invalid_request`, `insufficient_user_authentication`).
    /// 4. The `audience` resolves through `directory`, every requested
    ///    `resource` is governed by it, and one is present if required
    ///    (`invalid_target`).
    /// 5. The sender-constraint decision of RFC-005 §6 (`invalid_target` for
    ///    a proof the Resource AS cannot honor).
    /// 6. `policy` decides, and its grant is checked against the RFC-005
    ///    §5.3 invariants. A grant wider than the request is a caller bug:
    ///    `server_error`, with the [`Error`] in
    ///    [`ExchangeError::library_error`].
    /// 7. The DPoP proof `jti` is recorded, if a replay store is configured.
    /// 8. The ID-JAG is signed.
    ///
    /// Every outcome returns an [`ExchangeRecord`] for the caller's audit
    /// log (draft §9.2).
    pub async fn exchange<S, D, P>(
        &self,
        request: &TokenExchangeRequest,
        client: &ClientIdentity,
        subjects: &S,
        directory: &D,
        policy: &P,
        now: SystemTime,
    ) -> (Result<IssuedIdJag, ExchangeError>, ExchangeRecord)
    where
        S: SubjectTokenVerifier,
        D: ResourceAsDirectory + ?Sized,
        P: ExchangePolicy,
    {
        let parties = Parties {
            subjects,
            directory,
            policy,
        };
        let mut resolved_issuer = None;
        let result = self
            .issue(request, client, &parties, now, &mut resolved_issuer)
            .await;
        let outcome = match &result {
            Ok(issued) => ExchangeOutcome::Issued {
                jti: issued.claims.jti.clone(),
                granted: GrantedAccess {
                    client_id: issued.claims.client_id.clone(),
                    sub: issued.claims.sub.clone(),
                    resources: issued
                        .claims
                        .resource
                        .as_ref()
                        .map(|resources| resources.values().to_vec())
                        .unwrap_or_default(),
                    scope: issued.claims.scope.clone(),
                    authorization_details: issued.claims.authorization_details.clone(),
                    confirmation: issued.claims.cnf.clone(),
                    expires_at: issued.claims.exp,
                },
            },
            Err(error) => ExchangeOutcome::rejected(error),
        };
        let record = ExchangeRecord::of(request, client, resolved_issuer, outcome, now);
        (result, record)
    }

    /// Process a SAML → Refresh Token exchange (draft §4.5, RFC-005 §8).
    ///
    /// Requires `saml_refresh_exchange`, `requested_token_type` of the
    /// refresh token type, an authenticated client, and a `saml2` subject
    /// token that `subjects` verifies and whose `Audience` maps to the
    /// client through the [`SamlAudienceMap`](super::SamlAudienceMap)
    /// (draft §4.5 MUST). Anything else is `invalid_request` or
    /// `invalid_client`.
    ///
    /// On success the caller mints the Refresh Token and builds the response
    /// with [`SamlRefreshExchange::token_response`]. A `DPoP` header is
    /// ignored: this profile defines no binding for the Refresh Token.
    pub async fn exchange_saml_for_refresh_token<S>(
        &self,
        request: &TokenExchangeRequest,
        client: &ClientIdentity,
        subjects: &S,
        now: SystemTime,
    ) -> (Result<SamlRefreshExchange, ExchangeError>, ExchangeRecord)
    where
        S: SubjectTokenVerifier,
    {
        let result = self.approve_refresh(request, client, subjects, now).await;
        let outcome = match &result {
            Ok(_) => ExchangeOutcome::RefreshTokenApproved,
            Err(error) => ExchangeOutcome::rejected(error),
        };
        let record = ExchangeRecord::of(request, client, None, outcome, now);
        (result, record)
    }

    async fn approve_refresh<S: SubjectTokenVerifier>(
        &self,
        request: &TokenExchangeRequest,
        client: &ClientIdentity,
        subjects: &S,
        now: SystemTime,
    ) -> Result<SamlRefreshExchange, ExchangeError> {
        if request.requested_token_type() != RequestedTokenType::RefreshToken {
            return Err(RejectReason::WrongRequestedTokenType.into());
        }
        if !self.config.saml_refresh_exchange {
            return Err(RejectReason::RefreshExchangeDisabled.into());
        }
        let client = authenticated(request, client)?;
        if request.subject_token_type() != SubjectTokenType::Saml2 {
            return Err(RejectReason::RefreshExchangeRequiresSaml.into());
        }
        let subject = self
            .verified_subject(request, &client, subjects, now)
            .await?;
        Ok(SamlRefreshExchange {
            client,
            subject,
            requested_scope: request.scope().cloned(),
        })
    }

    async fn issue<S, D, P>(
        &self,
        request: &TokenExchangeRequest,
        client: &ClientIdentity,
        parties: &Parties<'_, S, D, P>,
        now: SystemTime,
        resolved_issuer: &mut Option<Issuer>,
    ) -> Result<IssuedIdJag, ExchangeError>
    where
        S: SubjectTokenVerifier,
        D: ResourceAsDirectory + ?Sized,
        P: ExchangePolicy,
    {
        let Parties {
            subjects,
            directory,
            policy,
        } = *parties;

        // A refresh token request belongs to the §4.5 method. If that
        // exchange is off, say so (RFC-005 §2).
        if request.requested_token_type() != RequestedTokenType::IdJag {
            return Err(if self.config.saml_refresh_exchange {
                RejectReason::WrongRequestedTokenType.into()
            } else {
                RejectReason::RefreshExchangeDisabled.into()
            });
        }
        let audience = request
            .audience()
            .ok_or(RejectReason::MissingParameter { name: "audience" })?;

        let client = authenticated(request, client)?;
        let proof = self.dpop_proof(request, now)?;
        let subject = self
            .verified_subject(request, &client, subjects, now)
            .await?;

        // Draft §4.3.3: an unknown audience is `invalid_target`.
        let entry = directory
            .resolve_audience(audience, subject.issuer_tenant.as_deref())
            .ok_or(RejectReason::UnknownAudience)?;
        *resolved_issuer = Some(entry.issuer.clone());

        // Draft §4.3.3, §9.5: never issue a grant for a resource the
        // Resource AS does not govern.
        let requested = request.resources();
        if requested
            .iter()
            .any(|resource| !directory.governs(&entry, resource))
        {
            return Err(RejectReason::ResourceNotGoverned.into());
        }
        if entry.require_resource && requested.is_empty() {
            return Err(RejectReason::ResourceRequired.into());
        }

        // RFC-005 §6. The only refusal `decide` makes for an IdP is a proof
        // for a Resource AS without `jwt-dpop` (§6.1).
        let cnf = IdpBinding {
            dpop: proof.as_ref(),
            certificate_x5t_s256: request.certificate_thumbprint(),
            mtls_binding: self.config.mtls_binding,
            supports_jwt_dpop: entry.supports_jwt_dpop,
            preference: entry.binding_preference,
            dpop_to_non_supporting_as: self.config.dpop_to_non_supporting_as,
        }
        .decide()
        .map_err(|_rejection| ExchangeError::new(RejectReason::AudienceLacksJwtDpop))?;

        let context = ExchangeContext {
            client: &client,
            subject: &subject,
            subject_token_type: request.subject_token_type(),
            audience,
            resource_as: &entry,
            resources: requested,
            scope: request.scope(),
            authorization_details: request.authorization_details(),
            now,
        };
        let grant = policy.evaluate(&context).await.map_err(denied)?;

        if !requested.is_empty() && grant.resources.is_empty() {
            return Err(RejectReason::NoResourceGranted.into());
        }
        grant
            .check_invariants(
                requested,
                request.scope(),
                request.authorization_details(),
                &entry,
                |resource| directory.governs(&entry, resource),
            )
            .map_err(grant_bug)?;

        let claims =
            self.claims(grant, &subject, &entry, cnf, now)
                .map_err(|source| match source {
                    Error::InvalidClaim { .. } => grant_bug(source),
                    other => internal(other),
                })?;

        // Last before signing, so a request refused for another reason does
        // not burn the proof's `jti` (jwt-dpop-grant §5.1).
        if let (Some(proof), Some(replay)) = (&proof, &self.config.replay) {
            proof
                .consume(replay.as_ref(), now)
                .await
                .map_err(ExchangeError::from_dpop)?;
        }

        let token = sign_jws(
            self.config.signer.as_ref(),
            Some(ID_JAG_TYP),
            BTreeMap::new(),
            &claims,
        )
        .await
        .map_err(internal)?;
        Ok(IssuedIdJag {
            id_jag: IdJag::new(token),
            claims,
            expires_in: self.config.id_jag_lifetime,
        })
    }

    /// Validate the DPoP proof, if DPoP is enabled and the request has one.
    fn dpop_proof(
        &self,
        request: &TokenExchangeRequest,
        now: SystemTime,
    ) -> Result<Option<ValidatedDpopProof>, ExchangeError> {
        if !self.config.dpop || !request.has_dpop_proof() {
            return Ok(None);
        }
        let mut validation = DpopValidation::token_endpoint(
            &self.config.token_endpoint,
            &self.config.dpop_algorithms,
            now,
            self.config.clock_skew,
        );
        validation.max_age = self.config.dpop_max_age;
        if let Some(nonce) = &self.config.dpop_nonce {
            validation.nonce = Some(nonce.as_ref());
        }
        validate_dpop_proof(request.dpop_headers(), &validation)
            .map(Some)
            .map_err(ExchangeError::from_dpop)
    }

    /// RFC-005 §4: the `typ` allow-list, the caller's verifier, then the
    /// checks the library makes whatever the verifier said.
    async fn verified_subject<S: SubjectTokenVerifier>(
        &self,
        request: &TokenExchangeRequest,
        client: &AuthenticatedClient,
        subjects: &S,
        now: SystemTime,
    ) -> Result<VerifiedSubject, ExchangeError> {
        let token = request.subject_token();

        // Draft §4.3.3 MUST: a subject token that carries the type of
        // another token is refused. ID Tokens define no `typ`, so anything
        // explicit must be allow-listed.
        let jwt = match &token {
            SubjectTokenInput::IdToken(token) => Some(token.expose_secret()),
            SubjectTokenInput::RefreshToken(token) => Some(token.expose_secret()),
            SubjectTokenInput::Saml2(_) => None,
        };
        if let Some(typ) = jwt.and_then(peek_typ)
            && !self.typ_allowed(&typ)
        {
            return Err(RejectReason::SubjectTokenTypNotAllowed.into());
        }

        let subject = subjects
            .verify(&token, client, now)
            .await
            .map_err(|rejection| match rejection {
                SubjectRejection::Invalid => ExchangeError::new(RejectReason::SubjectTokenRejected),
                SubjectRejection::StepUpRequired {
                    max_age,
                    acr_values,
                } => ExchangeError::step_up(max_age, acr_values),
            })?;

        match token {
            // Draft §4.3.3 MUST: issued to the client that presents it.
            SubjectTokenInput::IdToken(_) | SubjectTokenInput::RefreshToken(_) => {
                if subject.issued_to_client.as_deref() != Some(client.client_id.as_str()) {
                    return Err(RejectReason::SubjectTokenNotIssuedToClient.into());
                }
            }
            // Draft §4.5 MUST: the Audience maps to the client. Fails closed
            // without a map.
            SubjectTokenInput::Saml2(_) => {
                let mapped = match (&subject.saml_audience, &self.config.saml_audiences) {
                    (Some(audience), Some(map)) => map.maps_to_client(audience, &client.client_id),
                    _ => false,
                };
                if !mapped {
                    return Err(RejectReason::SamlAudienceNotMapped.into());
                }
            }
        }

        // Draft §6.1 MUST: a multi-tenant issuer always names the tenant.
        if self.config.tenancy == IdpTenancy::Multi && subject.issuer_tenant.is_none() {
            return Err(ExchangeError::with_source(
                RejectReason::MissingIssuerTenant,
                Error::InvalidConfiguration {
                    reason: "a multi-tenant issuer needs VerifiedSubject::issuer_tenant",
                },
            ));
        }
        Ok(subject)
    }

    fn typ_allowed(&self, typ: &str) -> bool {
        let typ = normalize_typ(typ);
        typ == "jwt"
            || self
                .config
                .id_token_typ_allow
                .iter()
                .any(|allowed| normalize_typ(allowed) == typ)
    }

    /// The ID-JAG claim set (RFC-005 §7).
    fn claims(
        &self,
        grant: ExchangeGrant,
        subject: &VerifiedSubject,
        entry: &ResourceAsEntry,
        cnf: Option<Confirmation>,
        now: SystemTime,
    ) -> Result<IdJagClaims, Error> {
        let iat = NumericDate::from_system_time(now)?;
        let exp = NumericDate::from_system_time(
            now.checked_add(self.config.id_jag_lifetime)
                .ok_or(Error::TimeOutOfRange)?,
        )?;
        // A string for one, an array for several, omitted for none.
        let mut resources = grant.resources;
        let resource = match (resources.pop(), resources.is_empty()) {
            (None, _) => None,
            (Some(only), true) => Some(Resources::one(only)),
            (Some(last), false) => {
                resources.push(last);
                Some(Resources::many(resources)?)
            }
        };
        Ok(IdJagClaims {
            iss: self.config.issuer.clone(),
            sub: grant.sub,
            // Always the canonical issuer identifier, never the alias, and a
            // single string (draft §4.3, identity-chaining §2.3.3).
            aud: Audience::single(entry.issuer.as_str()),
            client_id: grant.client_id,
            jti: random_id(),
            exp,
            iat,
            resource,
            scope: grant.scope,
            authorization_details: grant.authorization_details,
            // The draft defines no processing for actor tokens (§9.10).
            act: None,
            sub_id: grant.sub_id.map(SubjectIdentifier::SamlNameId),
            tenant: subject.issuer_tenant.clone(),
            aud_tenant: grant.aud_tenant,
            aud_sub: grant.aud_sub,
            email: grant.email,
            auth_time: subject.auth_time,
            acr: subject.acr.clone(),
            amr: subject.amr.clone(),
            cnf,
            nbf: None,
            extra: grant.extra_claims,
        })
    }
}

/// RFC-005 §3: an unauthenticated request is always `invalid_client`.
fn authenticated(
    request: &TokenExchangeRequest,
    client: &ClientIdentity,
) -> Result<AuthenticatedClient, ExchangeError> {
    match client {
        ClientIdentity::Authenticated { client_id, method } => Ok(AuthenticatedClient {
            client_id: client_id.clone(),
            method: *method,
        }),
        ClientIdentity::Unauthenticated { .. } => {
            Err(ExchangeError::new(RejectReason::ClientNotAuthenticated)
                .with_basic_challenge(request.used_basic()))
        }
    }
}

fn denied(denial: ExchangeDenial) -> ExchangeError {
    match denial {
        ExchangeDenial::AccessDenied => RejectReason::PolicyDenied.into(),
        ExchangeDenial::InvalidTarget => RejectReason::PolicyInvalidTarget.into(),
        ExchangeDenial::InvalidScope => RejectReason::PolicyInvalidScope.into(),
        ExchangeDenial::StepUpRequired {
            max_age,
            acr_values,
        } => ExchangeError::step_up(max_age, acr_values),
    }
}

fn grant_bug(source: Error) -> ExchangeError {
    ExchangeError::with_source(RejectReason::GrantInvariantViolated, source)
}

fn internal(source: Error) -> ExchangeError {
    ExchangeError::with_source(RejectReason::Internal, source)
}
