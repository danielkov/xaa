//! Caller policy for a token exchange, and the invariants its output must
//! satisfy. See RFC-005 §5.2–§5.3.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::SystemTime;

use serde_json::Value;

use crate::claims::{AuthorizationDetails, NAMEID_FORMAT_TRANSIENT, SamlNameId, Scope};
use crate::error::Error;

use super::ResourceAsEntry;
use super::request::SubjectTokenType;
use super::subject::{AuthenticatedClient, VerifiedSubject};

/// The SAML NameID the IdP would issue to the Resource AS's SAML SP, emitted
/// as a `saml-nameid` `sub_id` (draft §3.2.1). Optional members are emitted
/// exactly when set (draft §3.2.2).
pub type SamlNameIdMapping = SamlNameId;

/// Claims a grant's `extra_claims` may not set: the ones the library emits,
/// and `act`, which this profile never emits (draft §9.10).
const RESERVED_CLAIMS: [&str; 21] = [
    "iss",
    "sub",
    "aud",
    "client_id",
    "jti",
    "iat",
    "exp",
    "nbf",
    "resource",
    "scope",
    "authorization_details",
    "tenant",
    "aud_tenant",
    "aud_sub",
    "email",
    "auth_time",
    "acr",
    "amr",
    "sub_id",
    "cnf",
    "act",
];

/// What policy decides on: who asks, for whom, at which Resource AS, for
/// what.
#[derive(Debug, Clone, Copy)]
pub struct ExchangeContext<'a> {
    /// The authenticated client.
    pub client: &'a AuthenticatedClient,
    /// The verified End-User.
    pub subject: &'a VerifiedSubject,
    /// The kind of subject token presented.
    pub subject_token_type: SubjectTokenType,
    /// The `audience` as requested (possibly an alias).
    pub audience: &'a str,
    /// The Resource AS the audience resolved to.
    pub resource_as: &'a ResourceAsEntry,
    /// The requested resources. Each is governed by the Resource AS.
    pub resources: &'a [String],
    pub scope: Option<&'a Scope>,
    pub authorization_details: Option<&'a AuthorizationDetails>,
    pub now: SystemTime,
}

/// The caller's access policy (RFC-005 §5.2, draft §4.3.3).
///
/// Some draft MUSTs depend on data only the caller holds, so implementations
/// own them:
///
/// - **`sub` stability:** the same `sub` for a given End-User in every
///   ID-JAG for the same Resource AS (and `aud_tenant`), whichever client
///   asks (draft §5.2).
/// - **`sub` uniqueness:** within `iss`, or within `iss` + `tenant` for
///   multi-tenant issuers (draft §3.1, §6.3).
/// - **`sub` / `sub_id` agreement:** they identify the same End-User
///   (draft §3.1, §3.2.2).
/// - **`sub_id` derivation:** from the `<NameID>` the IdP would issue to the
///   Resource AS's SAML SP, scoped to that SP (draft §3.2.2).
/// - **`aud_sub` uniqueness:** `aud` + `aud_tenant` + `aud_sub` is unique at
///   the Resource AS (draft §3.1).
/// - **Client identifier model:** `client_id` follows the Resource AS's
///   model (draft §6.2).
pub trait ExchangePolicy: Send + Sync {
    /// Decide what to grant. The result is checked against the RFC-005 §5.3
    /// invariants: a grant wider than the request is an error, never extra
    /// access.
    fn evaluate(
        &self,
        ctx: &ExchangeContext<'_>,
    ) -> impl Future<Output = Result<ExchangeGrant, ExchangeDenial>> + Send;
}

/// What policy grants. Becomes the ID-JAG's claims (RFC-005 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeGrant {
    /// The client's client_id *at the Resource AS* (draft §3.1, §5.1). No
    /// default: it can differ from the client's ID at this IdP.
    pub client_id: String,
    /// The End-User's identifier *for this Resource AS* (draft §5.2). No
    /// default: it is not the `sub` of the presented ID Token.
    pub sub: String,
    /// The granted resources: a subset of the requested ones, or defaults
    /// the Resource AS governs when none were requested.
    pub resources: Vec<String>,
    /// The granted scope: a subset of the requested one, if any.
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub aud_tenant: Option<String>,
    pub aud_sub: Option<String>,
    pub email: Option<String>,
    /// Only for a Resource AS with `wants_saml_sub_id` (draft §9.9).
    pub sub_id: Option<SamlNameIdMapping>,
    /// Other ID-Token-style claims (draft §3.1), e.g. a non-NameID SAML
    /// subject attribute (draft §3.2.2). May not name a claim the library
    /// emits, nor `act`.
    pub extra_claims: BTreeMap<String, Value>,
}

impl ExchangeGrant {
    /// A grant with the two required identifiers and nothing else.
    pub fn new(client_id: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            sub: sub.into(),
            resources: Vec::new(),
            scope: None,
            authorization_details: None,
            aud_tenant: None,
            aud_sub: None,
            email: None,
            sub_id: None,
            extra_claims: BTreeMap::new(),
        }
    }

    /// The RFC-005 §5.3 invariants that a policy bug would break. Each
    /// failure is a caller bug.
    ///
    /// `governs` answers for the Resource AS's directory entry.
    pub(crate) fn check_invariants(
        &self,
        requested_resources: &[String],
        requested_scope: Option<&Scope>,
        requested_details: Option<&AuthorizationDetails>,
        entry: &ResourceAsEntry,
        governs: impl Fn(&str) -> bool,
    ) -> Result<(), Error> {
        if self.client_id.is_empty() || self.sub.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "an ExchangeGrant needs a non-empty client_id and sub",
            });
        }
        if requested_resources.is_empty() {
            // Defaults chosen by policy must still be this Resource AS's
            // (draft §4.3.3, §9.5).
            if self.resources.iter().any(|resource| !governs(resource)) {
                return Err(Error::GrantExceedsRequest {
                    what: "a default resource is not governed by the Resource AS",
                });
            }
        } else if self
            .resources
            .iter()
            .any(|resource| !requested_resources.contains(resource))
        {
            // Byte-identical to a requested value (draft §4.3.3 MUST).
            return Err(Error::GrantExceedsRequest { what: "resource" });
        }
        if let (Some(requested), Some(granted)) = (requested_scope, &self.scope)
            && !granted.is_subset_of(requested)
        {
            return Err(Error::GrantExceedsRequest { what: "scope" });
        }
        if let (Some(requested), Some(granted)) = (requested_details, &self.authorization_details)
            && !granted.is_subset_of(requested)
        {
            return Err(Error::GrantExceedsRequest {
                what: "authorization_details",
            });
        }
        if let Some(sub_id) = &self.sub_id {
            // Draft §3.2.2 MUST NOT: a transient NameID is not a stable
            // identifier.
            if sub_id.nameid_format.as_deref() == Some(NAMEID_FORMAT_TRANSIENT) {
                return Err(Error::TransientNameId);
            }
            // Draft §9.9: disclose it only to a Resource AS that uses it.
            if !entry.wants_saml_sub_id {
                return Err(Error::UnwantedSubId);
            }
        }
        if self
            .extra_claims
            .keys()
            .any(|name| RESERVED_CLAIMS.contains(&name.as_str()))
        {
            return Err(Error::InvalidConfiguration {
                reason: "an extra claim names a claim the library emits, or act",
            });
        }
        Ok(())
    }
}

/// Why policy refuses an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeDenial {
    /// `access_denied` (draft §4.3.4.3).
    AccessDenied,
    /// `invalid_target`.
    InvalidTarget,
    /// `invalid_scope` (RFC 8693 §2.2.2: any OAuth error code may be
    /// returned).
    InvalidScope,
    /// `insufficient_user_authentication` (draft §9.3).
    StepUpRequired {
        max_age: Option<u64>,
        acr_values: Option<String>,
    },
}
