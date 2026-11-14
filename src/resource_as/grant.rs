//! The verified grant, the authorization decision, and the token response.
//! See RFC-004 §5–§7.

use std::time::Duration;

use serde_json::{Map, Value};

use crate::claims::{AuthorizationDetails, IdJagClaims, Scope};
use crate::client_auth::ClientIdentity;
use crate::dpop::{AccessTokenBinding, BindingRejection, require_sender_constraint};
use crate::http::HttpResponse;
use crate::jose::{JoseHeader, Verified};
use crate::oauth_error::{OAuthErrorCode, json_no_store_headers};
use crate::secret::AccessToken;

use super::config::{RecipientTenant, ResourceRegistry, SamlSubjectKeyValue};
use super::error::{RejectReason, TokenError};

/// The binding a request proved (RFC-004 §5): a DPoP key thumbprint or a
/// client certificate thumbprint.
pub type ProvenBinding = AccessTokenBinding;

/// An ID-JAG that passed every rule of RFC-004 §4.
///
/// Only [`ResourceAs::validate`](super::ResourceAs::validate) produces one,
/// and it is the only way to read ID-JAG claims at the Resource AS.
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    pub(super) verified: Verified<IdJagClaims>,
    pub(super) recipient_tenant: RecipientTenant,
    pub(super) client: ClientIdentity,
    pub(super) binding: Option<ProvenBinding>,
    pub(super) requested_scope: Option<Scope>,
    pub(super) saml_subject_key: Option<SamlSubjectKeyValue>,
}

/// Claims that identify the subject only if the caller trusts the issuer
/// tenant as authoritative for them (draft §9.8). They are not verified
/// identifiers: resolve subjects by `iss` + `sub` (+ `tenant`) or by
/// [`VerifiedGrant::saml_subject_key`] unless that trust exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedSubjectHints<'a> {
    pub email: Option<&'a str>,
    pub aud_sub: Option<&'a str>,
}

impl VerifiedGrant {
    /// The verified claims.
    ///
    /// Resolve the subject by `iss` + `sub` for a single-tenant issuer and
    /// by `iss` + `tenant` + `sub` for a multi-tenant one (draft §3.1,
    /// §6.3), and only within [`recipient_tenant`](Self::recipient_tenant)
    /// (draft §4.4.1 MUST).
    pub fn claims(&self) -> &IdJagClaims {
        self.verified.claims()
    }

    /// The verified JOSE header.
    pub fn header(&self) -> &JoseHeader {
        self.verified.header()
    }

    /// The tenant of this server the grant is for.
    pub fn recipient_tenant(&self) -> &RecipientTenant {
        &self.recipient_tenant
    }

    /// The client that presented the grant.
    pub fn client(&self) -> &ClientIdentity {
        &self.client
    }

    /// The sender constraint the request proved, if any.
    pub fn binding(&self) -> Option<&ProvenBinding> {
        self.binding.as_ref()
    }

    /// The request's `scope` parameter: the client's downscoping request.
    pub fn requested_scope(&self) -> Option<&Scope> {
        self.requested_scope.as_ref()
    }

    /// The local subject key for SAML-based resolution, built from the
    /// members chosen in
    /// [`SamlIssuerTrust::subject_key`](super::SamlIssuerTrust::subject_key)
    /// (draft §3.2.2). `None` if the ID-JAG has no `sub_id`.
    pub fn saml_subject_key(&self) -> Option<&SamlSubjectKeyValue> {
        self.saml_subject_key.as_ref()
    }

    /// `email` and `aud_sub`, marked as hints (draft §9.8).
    pub fn subject_hints(&self) -> UnverifiedSubjectHints<'_> {
        let claims = self.claims();
        UnverifiedSubjectHints {
            email: claims.email.as_deref(),
            aud_sub: claims.aud_sub.as_deref(),
        }
    }

    /// Start the authorization decision (RFC-004 §6). `resources` is the
    /// registry that was passed to validation.
    ///
    /// For a self-issued grant (`allow_self_issued`), policy MUST NOT grant
    /// more than it would when issuing an access token for the same subject
    /// and resource directly (draft §9.4). The builder cannot know that
    /// ceiling; it is the caller's to enforce.
    pub fn decide<'a>(&'a self, resources: &'a dyn ResourceRegistry) -> GrantDecisionBuilder<'a> {
        GrantDecisionBuilder {
            grant: self,
            registry: resources,
            resources: None,
            scope: None,
            authorization_details: None,
        }
    }
}

/// Collects what caller policy grants and enforces the draft §4.4.1
/// invariants on it, so a policy bug cannot widen access beyond the ID-JAG.
#[derive(Clone)]
pub struct GrantDecisionBuilder<'a> {
    grant: &'a VerifiedGrant,
    registry: &'a dyn ResourceRegistry,
    resources: Option<Vec<String>>,
    scope: Option<Scope>,
    authorization_details: Option<AuthorizationDetails>,
}

impl std::fmt::Debug for GrantDecisionBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantDecisionBuilder")
            .field("resources", &self.resources)
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .finish_non_exhaustive()
    }
}

impl GrantDecisionBuilder<'_> {
    /// The resources the access token is for.
    ///
    /// If the ID-JAG has a `resource` claim, these must be a subset of it;
    /// when this is not called, all of the claim's resources are granted.
    /// If it has none, these are the server's defaults and each must be
    /// governed by this server for the recipient tenant.
    pub fn resources(mut self, granted: Vec<String>) -> Self {
        self.resources = Some(granted);
        self
    }

    /// The scope to grant: a subset of the ID-JAG's `scope` and, when the
    /// request carried one, of the request's `scope`. Not calling this
    /// grants no scope.
    pub fn scope(mut self, granted: Scope) -> Self {
        self.scope = Some(granted);
        self
    }

    /// The authorization details to grant: objects taken unchanged from the
    /// ID-JAG's `authorization_details`.
    pub fn authorization_details(mut self, granted: AuthorizationDetails) -> Self {
        self.authorization_details = Some(granted);
        self
    }

    /// Refuse the grant: `access_denied` (draft §4.4.3).
    pub fn deny(self) -> TokenError {
        TokenError::rejected(OAuthErrorCode::AccessDenied, RejectReason::DeniedByPolicy)
    }

    /// Check the invariants of RFC-004 §6.
    ///
    /// A grant wider than the ID-JAG is a bug in the caller's policy: the
    /// error is `server_error` on the wire and
    /// [`TokenError::error`] is
    /// [`Error::GrantExceedsIdJag`](crate::Error::GrantExceedsIdJag).
    /// Granting none of the ID-JAG's resources is `access_denied`. A
    /// resource that requires a sender-constrained token, without a proven
    /// binding, is `invalid_grant`.
    pub fn build(self) -> Result<GrantDecision, TokenError> {
        let Self {
            grant,
            registry,
            resources,
            scope,
            authorization_details,
        } = self;
        let claims = grant.claims();
        let tenant = &grant.recipient_tenant;

        // Resources (draft §4.4.1).
        let mut granted_resources: Vec<String> = Vec::new();
        match (&claims.resource, resources) {
            (Some(claimed), None) => granted_resources.extend_from_slice(claimed.values()),
            (Some(claimed), Some(granted)) => {
                if granted.iter().any(|resource| !claimed.contains(resource)) {
                    return Err(TokenError::grant_exceeds_id_jag(
                        "a granted resource is not in the resource claim",
                    ));
                }
                if granted.is_empty() {
                    return Err(TokenError::rejected(
                        OAuthErrorCode::AccessDenied,
                        RejectReason::NoResourceGranted,
                    ));
                }
                push_unique(&mut granted_resources, granted);
            }
            (None, None) => {}
            (None, Some(defaults)) => {
                if defaults
                    .iter()
                    .any(|resource| !registry.governs(resource, tenant))
                {
                    return Err(TokenError::grant_exceeds_id_jag(
                        "a default resource is not governed by this server",
                    ));
                }
                push_unique(&mut granted_resources, defaults);
            }
        }

        // Scope (draft §4.4.1, RFC 7521 §4.1).
        if let Some(granted) = &scope {
            let within_grant = claims
                .scope
                .as_ref()
                .is_some_and(|claimed| granted.is_subset_of(claimed));
            if !within_grant {
                return Err(TokenError::grant_exceeds_id_jag(
                    "granted scope is not within the scope claim",
                ));
            }
            if let Some(requested) = &grant.requested_scope
                && !granted.is_subset_of(requested)
            {
                return Err(TokenError::grant_exceeds_id_jag(
                    "granted scope is not within the requested scope",
                ));
            }
        }

        // Authorization details, and the resources they name.
        let mut constrained_resources: Vec<&str> =
            granted_resources.iter().map(String::as_str).collect();
        if let Some(granted) = &authorization_details {
            let within_grant = claims
                .authorization_details
                .as_ref()
                .is_some_and(|claimed| granted.is_subset_of(claimed));
            if !within_grant {
                return Err(TokenError::grant_exceeds_id_jag(
                    "granted authorization_details are not in the authorization_details claim",
                ));
            }
            for location in granted
                .0
                .iter()
                .filter_map(|detail| detail.locations.as_ref())
                .flatten()
            {
                let allowed = match &claims.resource {
                    Some(claimed) => claimed.contains(location),
                    None => registry.governs(location, tenant),
                };
                if !allowed {
                    return Err(TokenError::grant_exceeds_id_jag(
                        "an authorization_details location is outside the granted resources",
                    ));
                }
                constrained_resources.push(location);
            }
        }

        // Sender constraint (draft §9.11.1.2.4, §9.11.2.2).
        let required = constrained_resources
            .iter()
            .any(|resource| registry.requires_sender_constraint(resource, tenant));
        require_sender_constraint(grant.binding.as_ref(), required).map_err(
            |rejection: BindingRejection| {
                TokenError::rejected(rejection.code(), RejectReason::SenderConstraint(rejection))
            },
        )?;

        Ok(GrantDecision {
            resources: granted_resources,
            scope,
            authorization_details,
            binding: grant.binding.clone(),
        })
    }
}

fn push_unique(into: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !into.contains(&value) {
            into.push(value);
        }
    }
}

/// What the access token is for. Every part of it is within the ID-JAG.
///
/// There is no refresh token: the ID-JAG replaces it (draft §4.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantDecision {
    resources: Vec<String>,
    scope: Option<Scope>,
    authorization_details: Option<AuthorizationDetails>,
    binding: Option<AccessTokenBinding>,
}

impl GrantDecision {
    /// The resources the access token is for: its audience.
    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    /// The granted scope.
    pub fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    /// The granted authorization details.
    pub fn authorization_details(&self) -> Option<&AuthorizationDetails> {
        self.authorization_details.as_ref()
    }

    /// The binding the access token must carry in its `cnf`, or in its
    /// introspection response (RFC-007 §4.3).
    pub fn binding(&self) -> Option<&AccessTokenBinding> {
        self.binding.as_ref()
    }

    /// The `token_type` of the response: `DPoP` for a DPoP-bound token
    /// (RFC 9449 §5), `Bearer` otherwise.
    pub fn token_type(&self) -> &'static str {
        self.binding
            .as_ref()
            .map_or("Bearer", AccessTokenBinding::token_type)
    }

    /// The token response (draft §4.4.2, RFC 6749 §5.1).
    ///
    /// `access_token` is minted by the caller, opaque or RFC 9068, with
    /// [`binding`](Self::binding) as its `cnf`. `scope` and
    /// `authorization_details` are included whenever granted
    /// (draft §4.4.1 MUST). There is never a `refresh_token`.
    pub fn token_response(&self, access_token: AccessToken, expires_in: Duration) -> HttpResponse {
        let mut body = Map::new();
        body.insert(
            "access_token".to_owned(),
            Value::from(access_token.expose_secret()),
        );
        body.insert("token_type".to_owned(), Value::from(self.token_type()));
        body.insert("expires_in".to_owned(), Value::from(expires_in.as_secs()));
        if let Some(scope) = &self.scope {
            body.insert("scope".to_owned(), Value::from(scope.as_str()));
        }
        if let Some(details) = &self.authorization_details
            && let Ok(details) = serde_json::to_value(details)
        {
            body.insert("authorization_details".to_owned(), details);
        }
        HttpResponse {
            status: 200,
            headers: json_no_store_headers(),
            // Serializing a map of strings and numbers cannot fail; fall
            // back to an error body rather than panic.
            body: serde_json::to_vec(&Value::Object(body))
                .unwrap_or_else(|_infallible| br#"{"error":"server_error"}"#.to_vec()),
        }
    }
}
