//! Resource AS configuration and the caller-supplied lookups. See RFC-004 §1.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::claims::{Issuer, SamlNameId};
use crate::dpop::{BindingPreference, DEFAULT_MAX_AGE, DpopNonce, default_dpop_algorithms};
use crate::jose::{AlgorithmPolicy, JwkSet, ParseLimits};

/// Default upper bound on an ID-JAG's `exp - iat` (draft §4.4.4).
pub const DEFAULT_MAX_ID_JAG_LIFETIME: Duration = Duration::from_mins(10);

/// What to do when an ID-JAG is presented again (draft §4.4.4). The draft
/// allows both, so there is no default (RFC-004 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiPolicy {
    /// Accept each ID-JAG once. The `jti` is recorded through the
    /// [`ReplayStore`](crate::replay::ReplayStore) under
    /// [`ReplayNamespace::IdJag`](crate::replay::ReplayNamespace::IdJag)
    /// until `exp + clock_skew`.
    SingleUse,
    /// Accept re-presentation until `exp`.
    /// [`ResourceAsConfig::max_id_jag_lifetime`] bounds the window.
    AllowReuse,
}

/// A tenant of this Resource AS: the scope in which subjects, clients, and
/// resources are resolved (draft §4.4.1, §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecipientTenant(String);

impl RecipientTenant {
    /// Wrap a tenant identifier exactly as given.
    pub fn new(tenant: impl Into<String>) -> Self {
        Self(tenant.into())
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RecipientTenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of resolving an issuer tenant to a recipient tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantDecision {
    /// The issuer tenant is trusted for exactly this recipient tenant.
    Trusted(RecipientTenant),
    /// No trust relationship covers this issuer tenant.
    Untrusted,
    /// More than one recipient tenant matches and `aud_tenant` does not pick
    /// one (draft §6.1). The grant is rejected rather than guessed at.
    Ambiguous,
}

/// Maps a multi-tenant issuer's `tenant` to a recipient tenant (draft §6.1).
pub trait TenantResolver: Send + Sync {
    /// Resolve the verified `iss` + `tenant` (and `aud_tenant`, when the
    /// ID-JAG carries one) to the recipient tenant they are trusted for.
    fn resolve(&self, issuer: &Issuer, tenant: &str, aud_tenant: Option<&str>) -> TenantDecision;
}

/// How an issuer identifies tenants (draft §6.1).
#[derive(Clone)]
pub enum Tenancy {
    /// `iss` alone identifies the tenant. The recipient tenant comes from
    /// the trust relationship.
    Single { recipient_tenant: RecipientTenant },
    /// `iss` + `tenant` identify the tenant. The ID-JAG must carry `tenant`.
    Multi(Arc<dyn TenantResolver>),
}

impl std::fmt::Debug for Tenancy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single { recipient_tenant } => f
                .debug_struct("Single")
                .field("recipient_tenant", recipient_tenant)
                .finish(),
            Self::Multi(_) => f.write_str("Multi(..)"),
        }
    }
}

/// Which `saml-nameid` members identify the subject locally (draft §3.2.2).
/// There is no default: matching on the NameID value alone must be chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlSubjectKey {
    /// `issuer`, `nameid`, `nameid_format`, `name_qualifier`, and
    /// `sp_name_qualifier`: everything SAML scopes a NameID by.
    Qualified,
    /// `issuer`, `nameid`, and `nameid_format`.
    NameIdAndFormat,
    /// `issuer` and `nameid` only.
    NameIdOnly,
}

/// The local lookup key for SAML-based subject resolution: the members
/// selected by [`SamlSubjectKey`]. Members outside the selection are `None`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SamlSubjectKeyValue {
    /// Entity ID of the SAML issuer, pre-associated with the ID-JAG issuer.
    pub saml_issuer: String,
    pub nameid: String,
    pub nameid_format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
}

impl SamlSubjectKey {
    pub(super) fn key_for(self, nameid: &SamlNameId) -> SamlSubjectKeyValue {
        let with_format = matches!(self, Self::Qualified | Self::NameIdAndFormat);
        let with_qualifiers = matches!(self, Self::Qualified);
        SamlSubjectKeyValue {
            saml_issuer: nameid.issuer.clone(),
            nameid: nameid.nameid.clone(),
            nameid_format: nameid.nameid_format.clone().filter(|_| with_format),
            name_qualifier: nameid.name_qualifier.clone().filter(|_| with_qualifiers),
            sp_name_qualifier: nameid.sp_name_qualifier.clone().filter(|_| with_qualifiers),
        }
    }
}

/// A SAML issuer an IdP may assert in `sub_id` (draft §9.8). `sub_id.issuer`
/// never establishes trust by itself: it must be listed here, under the
/// ID-JAG issuer that was validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlIssuerTrust {
    /// The SAML issuer's entity ID, compared byte-for-byte.
    pub saml_issuer: String,
    /// The `saml-nameid` members used for subject resolution.
    pub subject_key: SamlSubjectKey,
}

/// An IdP whose ID-JAGs this server accepts (draft §4.1).
#[derive(Debug, Clone)]
pub struct TrustedIssuer {
    pub issuer: Issuer,
    /// Per-issuer algorithm allow-list (draft §4.4.1, RFC 8725 §3.1).
    /// Default `RS256` + `ES256`.
    pub algorithms: AlgorithmPolicy,
    pub tenancy: Tenancy,
    /// SAML issuer entity IDs this IdP may assert in `sub_id` (draft §9.8).
    pub saml_issuers: Vec<SamlIssuerTrust>,
    /// Reject ID-JAGs from this issuer that lack an authorized `saml-nameid`
    /// `sub_id` (draft §3.2.2). Default false.
    pub require_saml_subject: bool,
    /// For a single-tenant issuer: the `aud_tenant` value that names its
    /// recipient tenant (draft §6.1). An ID-JAG whose `aud_tenant` is
    /// anything else is for another tenant and is rejected. Default `None`,
    /// which rejects every ID-JAG that carries `aud_tenant`. A multi-tenant
    /// issuer's resolver receives the claim instead.
    pub aud_tenant: Option<String>,
}

impl TrustedIssuer {
    /// A single-tenant issuer trusted for `recipient_tenant`.
    pub fn single_tenant(issuer: Issuer, recipient_tenant: RecipientTenant) -> Self {
        Self::with_tenancy(issuer, Tenancy::Single { recipient_tenant })
    }

    /// A multi-tenant issuer whose `tenant` claim `resolver` maps to a
    /// recipient tenant.
    pub fn multi_tenant(issuer: Issuer, resolver: Arc<dyn TenantResolver>) -> Self {
        Self::with_tenancy(issuer, Tenancy::Multi(resolver))
    }

    fn with_tenancy(issuer: Issuer, tenancy: Tenancy) -> Self {
        Self {
            issuer,
            algorithms: AlgorithmPolicy::default_id_jag(),
            tenancy,
            saml_issuers: Vec::new(),
            require_saml_subject: false,
            aud_tenant: None,
        }
    }
}

/// Resource AS configuration (RFC-004 §1).
#[derive(Clone)]
pub struct ResourceAsConfig {
    /// This AS's RFC 8414 issuer identifier. The only accepted ID-JAG `aud`.
    pub issuer: Issuer,
    /// Token endpoint URL, checked against the DPoP proof's `htu`. Never an
    /// accepted `aud`.
    pub token_endpoint: Url,
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// Upper bound on `exp - iat` (draft §4.4.4). Default 10 minutes.
    pub max_id_jag_lifetime: Duration,
    /// No default: the caller must choose (RFC-004 §8).
    pub jti_policy: JtiPolicy,
    /// Reject ID-JAGs without a `resource` claim (draft §4.4.1 MAY).
    /// Default false.
    pub require_resource_claim: bool,
    /// Accept an unauthenticated client presenting a sender-constrained
    /// ID-JAG (draft §4.4, §9.1). Default false.
    pub allow_unauthenticated_sender_constrained: bool,
    /// Accept ID-JAGs whose `iss` is this server's own issuer (draft §9.4).
    /// Default false.
    pub allow_self_issued: bool,
    /// DPoP proof algorithms accepted (RFC 9449 §5.1). Default
    /// [`default_dpop_algorithms`].
    pub dpop_algorithms: AlgorithmPolicy,
    /// How old a DPoP proof's `iat` may be. Default 60 seconds.
    pub dpop_max_age: Duration,
    /// Set to require a server nonce in every DPoP proof (RFC 9449 §8).
    pub dpop_nonce: Option<Arc<dyn DpopNonce>>,
    /// Which binding an access token gets when an unbound ID-JAG arrives
    /// with both a DPoP proof and a client certificate. Default DPoP.
    pub binding_preference: BindingPreference,
    /// Size limit applied to the assertion before decoding (RFC-002 §2).
    pub parse_limits: ParseLimits,
}

impl ResourceAsConfig {
    /// A configuration with no trusted issuers and the documented defaults.
    /// `jti_policy` has no default (draft §4.4.4 allows either behavior).
    pub fn new(issuer: Issuer, token_endpoint: Url, jti_policy: JtiPolicy) -> Self {
        Self {
            issuer,
            token_endpoint,
            trusted_issuers: Vec::new(),
            max_id_jag_lifetime: DEFAULT_MAX_ID_JAG_LIFETIME,
            jti_policy,
            require_resource_claim: false,
            allow_unauthenticated_sender_constrained: false,
            allow_self_issued: false,
            dpop_algorithms: default_dpop_algorithms(),
            dpop_max_age: DEFAULT_MAX_AGE,
            dpop_nonce: None,
            binding_preference: BindingPreference::default(),
            parse_limits: ParseLimits::default(),
        }
    }
}

impl std::fmt::Debug for ResourceAsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceAsConfig")
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint.as_str())
            .field("trusted_issuers", &self.trusted_issuers)
            .field("max_id_jag_lifetime", &self.max_id_jag_lifetime)
            .field("jti_policy", &self.jti_policy)
            .field("require_resource_claim", &self.require_resource_claim)
            .field(
                "allow_unauthenticated_sender_constrained",
                &self.allow_unauthenticated_sender_constrained,
            )
            .field("allow_self_issued", &self.allow_self_issued)
            .field("dpop_algorithms", &self.dpop_algorithms)
            .field("dpop_max_age", &self.dpop_max_age)
            .field("dpop_nonce_required", &self.dpop_nonce.is_some())
            .field("binding_preference", &self.binding_preference)
            .field("parse_limits", &self.parse_limits)
            .finish()
    }
}

/// Caller-cached JWK Sets for trusted issuers, fetched through RFC-006 §5.
/// The library never fetches keys during validation.
pub trait IssuerKeys: Send + Sync {
    /// The current key set of `issuer`, if one is cached.
    ///
    /// Returns a [`Cow`] so that a plain map can lend its entry while a cache
    /// behind a lock can hand out an owned copy.
    fn jwks(&self, issuer: &Issuer) -> Option<Cow<'_, JwkSet>>;
}

impl<S: std::hash::BuildHasher + Send + Sync> IssuerKeys for HashMap<Issuer, JwkSet, S> {
    fn jwks(&self, issuer: &Issuer) -> Option<Cow<'_, JwkSet>> {
        self.get(issuer).map(Cow::Borrowed)
    }
}

impl IssuerKeys for BTreeMap<Issuer, JwkSet> {
    fn jwks(&self, issuer: &Issuer) -> Option<Cow<'_, JwkSet>> {
        self.get(issuer).map(Cow::Borrowed)
    }
}

/// Which protected resources this AS governs, per recipient tenant
/// (draft §4.4.1). Resource identifiers are compared by simple string
/// comparison; implementations must not normalize them.
pub trait ResourceRegistry: Send + Sync {
    /// Whether this AS issues tokens for `resource` in `tenant`.
    fn governs(&self, resource: &str, tenant: &RecipientTenant) -> bool;

    /// Whether tokens for `resource` must be sender-constrained
    /// (draft §9.11.1.2.4, §9.11.2.2).
    fn requires_sender_constraint(&self, resource: &str, tenant: &RecipientTenant) -> bool;

    /// Whether `client_id` is registered in `tenant`, for deployments whose
    /// client identifiers are tenant-scoped (draft §6.2). The default suits
    /// deployments with globally unique client identifiers.
    fn client_belongs_to_tenant(&self, _client_id: &str, _tenant: &RecipientTenant) -> bool {
        true
    }
}
