//! ID-JAG validation (draft §4.4.1). See RFC-004 §4.

use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::claims::{AuthorizationDetails, IdJagClaims, SubjectIdentifier};
use crate::client_auth::ClientIdentity;
use crate::dpop::{
    AssertionGrantType, BindingRejection, DpopValidation, ResourceAsBinding, ValidatedDpopProof,
    validate_dpop_proof,
};
use crate::error::Error;
use crate::jose::{ExpectedTyp, UnverifiedJws, verify};
use crate::metadata::ResourceAsMetadataBuilder;
use crate::oauth_error::OAuthErrorCode;
use crate::replay::{ReplayNamespace, ReplayOutcome, ReplayStore};

use super::config::{
    IssuerKeys, JtiPolicy, RecipientTenant, ResourceAsConfig, ResourceRegistry,
    SamlSubjectKeyValue, Tenancy, TenantDecision, TrustedIssuer,
};
use super::error::{RejectReason, TokenError};
use super::grant::VerifiedGrant;
use super::request::TokenRequest;

/// The Resource Authorization Server: validates ID-JAGs presented at its
/// token endpoint (draft §4.4). It never mints access tokens and never
/// resolves subjects to accounts; both stay with the caller.
#[derive(Debug, Clone)]
pub struct ResourceAs {
    config: ResourceAsConfig,
}

impl ResourceAs {
    /// Check the configuration and build the component.
    ///
    /// Fails with [`Error::InvalidConfiguration`] for an empty issuer, a zero
    /// `max_id_jag_lifetime`, or an issuer listed twice in
    /// `trusted_issuers`.
    pub fn new(config: ResourceAsConfig) -> Result<Self, Error> {
        let invalid = |reason: &'static str| Error::InvalidConfiguration { reason };
        if config.issuer.as_str().is_empty() {
            return Err(invalid("issuer is empty"));
        }
        if config.max_id_jag_lifetime.is_zero() {
            return Err(invalid("max_id_jag_lifetime is zero"));
        }
        for (index, trusted) in config.trusted_issuers.iter().enumerate() {
            if config
                .trusted_issuers
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.issuer == trusted.issuer)
            {
                return Err(invalid("an issuer is listed twice in trusted_issuers"));
            }
        }
        Ok(Self { config })
    }

    /// The configuration.
    pub fn config(&self) -> &ResourceAsConfig {
        &self.config
    }

    /// A metadata builder for this server (draft §7.2, RFC-004 §10): the
    /// ID-JAG grant profile with the jwt-bearer and jwt-dpop grants and the
    /// accepted DPoP algorithms. It has no input for trusted issuers
    /// (draft §9.7).
    pub fn metadata(&self) -> ResourceAsMetadataBuilder {
        ResourceAsMetadataBuilder::new(
            self.config.issuer.clone(),
            self.config.token_endpoint.clone(),
        )
        .dpop_grant(true)
        .dpop_signing_algs(self.config.dpop_algorithms.algorithms())
    }

    /// Validate the ID-JAG of `request` against every draft §4.4.1 rule, in
    /// the order of RFC-004 §4. The first failure ends validation.
    ///
    /// `client` is the caller's client authentication result (RFC-004 §3).
    /// `keys` holds the trusted issuers' cached JWK Sets. `replay` is
    /// required for [`JtiPolicy::SingleUse`] and, when given, also records
    /// DPoP proof `jti`s. Both are consulted last, so a request rejected for
    /// any other reason burns neither `jti` (jwt-dpop-grant §5.1).
    ///
    /// Validating the same request again is therefore safe after a failure.
    /// The usual case is [`RejectReason::UnknownKeyId`]: the issuer rotated
    /// its keys, so the caller refetches that issuer's JWK Set once
    /// (rate-limited) and calls `validate` again.
    #[expect(
        clippy::too_many_arguments,
        reason = "the per-call inputs of RFC-004 §4; the library holds no state"
    )]
    pub async fn validate(
        &self,
        request: &TokenRequest,
        client: &ClientIdentity,
        keys: &dyn IssuerKeys,
        resources: &dyn ResourceRegistry,
        replay: Option<&dyn ReplayStore>,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<VerifiedGrant, TokenError> {
        let config = &self.config;

        // Preconditions. A single-use policy with nowhere to record a `jti`
        // is a deployment error: fail every request rather than accept
        // replays (RFC-004 §8).
        if config.jti_policy == JtiPolicy::SingleUse && replay.is_none() {
            return Err(TokenError::server_error(RejectReason::ReplayStoreMissing));
        }
        if matches!(client, ClientIdentity::Unauthenticated { .. })
            && !config.allow_unauthenticated_sender_constrained
        {
            return Err(TokenError::rejected(
                OAuthErrorCode::InvalidClient,
                RejectReason::UnauthenticatedClientNotAllowed,
            ));
        }
        let out_of_range = || TokenError::server_error(RejectReason::TimeOutOfRange);
        let earliest = now.checked_sub(clock_skew).ok_or_else(out_of_range)?;
        let latest = now.checked_add(clock_skew).ok_or_else(out_of_range)?;

        // 1. The DPoP proof, before the ID-JAG is read.
        let proof = self.check_dpop_proof(request, now, clock_skew)?;

        // 2. A compact JWS within limits.
        let jws = UnverifiedJws::parse(request.assertion.expose_secret(), &config.parse_limits)
            .map_err(|source| {
                TokenError::invalid_grant(RejectReason::MalformedAssertion).with_source(source)
            })?;

        // 3. `typ`.
        ExpectedTyp::IdJag.check(jws.header()).map_err(|source| {
            TokenError::invalid_grant(RejectReason::WrongTyp).with_source(source)
        })?;

        // 4. The unverified `iss` picks the trust relationship, and with it
        // the keys. Nothing else is read before the signature verifies.
        let untrusted = || TokenError::invalid_grant(RejectReason::UntrustedIssuer);
        let trusted = serde_json::from_slice::<Map<String, Value>>(jws.payload_unverified())
            .ok()
            .as_ref()
            .and_then(|payload| payload.get("iss"))
            .and_then(Value::as_str)
            .and_then(|iss| self.trusted_issuer(iss))
            .ok_or_else(untrusted)?;

        // 5. Self-issued grants (draft §9.4).
        if trusted.issuer == config.issuer && !config.allow_self_issued {
            return Err(TokenError::invalid_grant(RejectReason::SelfIssued));
        }

        // 6. Signature, with that issuer's keys and algorithm allow-list.
        let jwks = keys
            .jwks(&trusted.issuer)
            .ok_or_else(|| TokenError::invalid_grant(RejectReason::NoKeysForIssuer))?;
        let verified =
            verify::<Map<String, Value>>(&jws, ExpectedTyp::IdJag, &jwks, &trusted.algorithms)
                .map_err(|source| {
                    let reason = match &source {
                        Error::WrongTyp { .. } => RejectReason::WrongTyp,
                        Error::DisallowedAlgorithm { .. } => RejectReason::DisallowedAlgorithm,
                        Error::UnknownKeyId { .. } => RejectReason::UnknownKeyId,
                        Error::BadSignature => RejectReason::InvalidSignature,
                        Error::MalformedClaims(_) => RejectReason::MalformedClaims,
                        _ => RejectReason::NoUsableKey,
                    };
                    TokenError::invalid_grant(reason).with_source(source)
                })?;

        // 7. Claim shapes. `sub_id` and `authorization_details` are judged
        // by their own rules (13 and 15), so they are set aside here.
        let mut object = verified.claims().clone();
        let sub_id = object.remove("sub_id");
        let authorization_details = object.remove("authorization_details");
        let mut claims = IdJagClaims::from_object(object).map_err(|source| {
            let reason = match &source {
                Error::MissingClaim { name } => RejectReason::MissingClaim { name },
                Error::InvalidClaim { name, .. } => RejectReason::InvalidClaim { name },
                _ => RejectReason::MalformedClaims,
            };
            TokenError::invalid_grant(reason).with_source(source)
        })?;
        // The issuer that picked the keys is the issuer that signed.
        if claims.iss != trusted.issuer {
            return Err(untrusted());
        }

        // 8. `aud` is this server's issuer identifier and nothing else.
        if claims.aud.sole() != Some(config.issuer.as_str()) {
            return Err(TokenError::invalid_grant(RejectReason::AudienceMismatch));
        }

        // 9. Time.
        let system_time = |date: crate::claims::NumericDate| {
            date.to_system_time().map_err(|source| {
                TokenError::invalid_grant(RejectReason::NotYetValid).with_source(source)
            })
        };
        let exp = system_time(claims.exp)?;
        let iat = system_time(claims.iat)?;
        if exp <= earliest {
            return Err(TokenError::invalid_grant(RejectReason::Expired));
        }
        if iat > latest {
            return Err(TokenError::invalid_grant(RejectReason::NotYetValid));
        }
        if let Some(nbf) = claims.nbf
            && system_time(nbf)? > latest
        {
            return Err(TokenError::invalid_grant(RejectReason::NotYetValid));
        }
        let lifetime = exp
            .duration_since(iat)
            .map_err(|_negative| TokenError::invalid_grant(RejectReason::ExpiresBeforeIssued))?;
        if lifetime > config.max_id_jag_lifetime {
            return Err(TokenError::invalid_grant(RejectReason::LifetimeTooLong));
        }

        // 10. Tenancy.
        let recipient_tenant = resolve_tenant(trusted, &claims)?;

        // 11. Client binding.
        match client {
            ClientIdentity::Authenticated { client_id, .. } => {
                if *client_id != claims.client_id {
                    return Err(TokenError::invalid_grant(RejectReason::ClientIdMismatch));
                }
            }
            ClientIdentity::Unauthenticated { client_id } => {
                if claims.cnf.is_none() {
                    return Err(TokenError::rejected(
                        OAuthErrorCode::InvalidClient,
                        RejectReason::UnauthenticatedUnboundGrant,
                    ));
                }
                // A claimed identity proves nothing, but a contradicting one
                // is still a mismatch.
                if client_id
                    .as_deref()
                    .is_some_and(|claimed| claimed != claims.client_id)
                {
                    return Err(TokenError::invalid_grant(RejectReason::ClientIdMismatch));
                }
            }
        }
        if !resources.client_belongs_to_tenant(&claims.client_id, &recipient_tenant) {
            return Err(TokenError::invalid_grant(RejectReason::ClientNotInTenant));
        }

        // 12. Sender constraint (RFC-007 §4.2).
        let binding = ResourceAsBinding {
            cnf: claims.cnf.as_ref(),
            grant_type: request.grant_type,
            dpop: proof.as_ref(),
            certificate_x5t_s256: request.certificate_x5t_s256.as_deref(),
            preference: config.binding_preference,
        }
        .decide()
        .map_err(|rejection| {
            TokenError::rejected(rejection.code(), RejectReason::SenderConstraint(rejection))
        })?;

        // 13. `sub_id`.
        let saml_subject_key = check_sub_id(trusted, sub_id.as_ref(), &mut claims)?;

        // 14. `resource`.
        match &claims.resource {
            Some(claimed) => {
                if !claimed
                    .values()
                    .iter()
                    .all(|resource| resources.governs(resource, &recipient_tenant))
                {
                    return Err(TokenError::invalid_grant(RejectReason::ResourceNotGoverned));
                }
            }
            None if config.require_resource_claim => {
                return Err(TokenError::invalid_grant(RejectReason::MissingResource));
            }
            None => {}
        }

        // A grant that can only fail the sender-constraint requirement is
        // refused here, before its `jti` is recorded. The decision builder
        // still makes the check that depends on which resources are granted
        // (RFC-004 §6).
        if binding.is_none()
            && claims.resource.as_ref().is_some_and(|claimed| {
                claimed.values().iter().all(|resource| {
                    resources.requires_sender_constraint(resource, &recipient_tenant)
                })
            })
        {
            let rejection = BindingRejection::SenderConstraintRequired;
            return Err(TokenError::rejected(
                rejection.code(),
                RejectReason::SenderConstraint(rejection),
            ));
        }

        // 15. `authorization_details`.
        if let Some(value) = &authorization_details {
            claims.authorization_details =
                Some(AuthorizationDetails::from_json(value).map_err(|source| {
                    TokenError::invalid_grant(RejectReason::InvalidAuthorizationDetails)
                        .with_source(source)
                })?);
        }

        // 16. Replay, last: the proof's `jti`, then the ID-JAG's. A proof is
        // single-use and cheap to remake, so it goes first; that way a
        // replayed proof does not burn the grant.
        if let (Some(proof), Some(store)) = (&proof, replay) {
            proof
                .consume(store, now)
                .await
                .map_err(TokenError::from_dpop)?;
        }
        if config.jti_policy == JtiPolicy::SingleUse {
            let store =
                replay.ok_or_else(|| TokenError::server_error(RejectReason::ReplayStoreMissing))?;
            let keep_until = exp.checked_add(clock_skew).ok_or_else(out_of_range)?;
            let namespace = ReplayNamespace::IdJag {
                issuer: claims.iss.as_str(),
            };
            match store
                .check_and_insert(namespace, &claims.jti, keep_until, now)
                .await
            {
                Ok(ReplayOutcome::Fresh) => {}
                Ok(ReplayOutcome::Replayed) => {
                    return Err(TokenError::invalid_grant(RejectReason::Replayed));
                }
                Err(source) => {
                    return Err(
                        TokenError::server_error(RejectReason::ReplayStoreUnavailable)
                            .with_source(Error::ReplayStore(source)),
                    );
                }
            }
        }

        Ok(VerifiedGrant {
            verified: verified.map(|_object| claims),
            recipient_tenant,
            client: client.clone(),
            binding,
            requested_scope: request.scope.clone(),
            saml_subject_key,
        })
    }

    fn trusted_issuer(&self, issuer: &str) -> Option<&TrustedIssuer> {
        self.config
            .trusted_issuers
            .iter()
            .find(|trusted| trusted.issuer.as_str() == issuer)
    }

    /// Rule 1. `jwt-dpop` needs a proof; a proof sent with `jwt-bearer` is
    /// validated too, because the access token may be bound to its key
    /// (draft §9.11.1.2.3). Nothing is recorded here.
    fn check_dpop_proof(
        &self,
        request: &TokenRequest,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<Option<ValidatedDpopProof>, TokenError> {
        if request.dpop_headers.is_empty() {
            return match request.grant_type {
                AssertionGrantType::JwtDpop => Err(TokenError::rejected(
                    OAuthErrorCode::InvalidDpopProof,
                    RejectReason::DpopProofMissing,
                )),
                AssertionGrantType::JwtBearer => Ok(None),
            };
        }
        let mut validation = DpopValidation::token_endpoint(
            &self.config.token_endpoint,
            &self.config.dpop_algorithms,
            now,
            clock_skew,
        );
        validation.nonce = self.config.dpop_nonce.as_deref();
        validation.max_age = self.config.dpop_max_age;
        validate_dpop_proof(&request.dpop_headers, &validation)
            .map(Some)
            .map_err(TokenError::from_dpop)
    }
}

/// Rule 10: the recipient tenant the grant is for (draft §6.1).
fn resolve_tenant(
    trusted: &TrustedIssuer,
    claims: &IdJagClaims,
) -> Result<RecipientTenant, TokenError> {
    match &trusted.tenancy {
        Tenancy::Single { recipient_tenant } => {
            // The trust relationship names the tenant, but an explicit
            // `aud_tenant` wins: it must name the same one.
            if claims.aud_tenant.is_some() && claims.aud_tenant != trusted.aud_tenant {
                return Err(TokenError::invalid_grant(RejectReason::UntrustedTenant));
            }
            Ok(recipient_tenant.clone())
        }
        Tenancy::Multi(resolver) => {
            let tenant = claims
                .tenant
                .as_deref()
                .ok_or_else(|| TokenError::invalid_grant(RejectReason::MissingTenant))?;
            match resolver.resolve(&claims.iss, tenant, claims.aud_tenant.as_deref()) {
                TenantDecision::Trusted(recipient_tenant) => Ok(recipient_tenant),
                TenantDecision::Untrusted => {
                    Err(TokenError::invalid_grant(RejectReason::UntrustedTenant))
                }
                TenantDecision::Ambiguous => {
                    Err(TokenError::invalid_grant(RejectReason::AmbiguousTenant))
                }
            }
        }
    }
}

/// Rule 13: `sub_id` is `saml-nameid` from a SAML issuer pre-associated with
/// the validated `iss` (draft §3.2.2, §9.8). Sets `claims.sub_id` and
/// returns the local subject key.
fn check_sub_id(
    trusted: &TrustedIssuer,
    sub_id: Option<&Value>,
    claims: &mut IdJagClaims,
) -> Result<Option<SamlSubjectKeyValue>, TokenError> {
    let Some(value) = sub_id else {
        if trusted.require_saml_subject {
            return Err(TokenError::invalid_grant(RejectReason::SamlSubjectRequired));
        }
        return Ok(None);
    };
    let sub_id = SubjectIdentifier::from_json(value).map_err(|source| {
        TokenError::invalid_grant(RejectReason::MalformedSubjectIdentifier).with_source(source)
    })?;
    let SubjectIdentifier::SamlNameId(nameid) = &sub_id else {
        return Err(TokenError::invalid_grant(
            RejectReason::UnsupportedSubjectIdentifier,
        ));
    };
    let trust = trusted
        .saml_issuers
        .iter()
        .find(|trust| trust.saml_issuer == nameid.issuer)
        .ok_or_else(|| TokenError::invalid_grant(RejectReason::UntrustedSamlIssuer))?;
    let key = trust.subject_key.key_for(nameid);
    claims.sub_id = Some(sub_id);
    Ok(Some(key))
}
