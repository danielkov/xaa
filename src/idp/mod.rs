//! IdP — the IdP Authorization Server (draft §2.1). Issues ID-JAGs at the
//! §4.3 Token Exchange endpoint. See RFC-005.
//!
//! Off by default. Exists so the client and Resource AS can be proven
//! against each other in-process (`tests/`) and in `examples/idp/`
//! without third-party software in the loop.
//!
//! The component parses the request ([`TokenExchangeRequest`]), enforces the
//! draft §4.3.3 rules that can be enforced mechanically, delegates
//! subject-token verification ([`SubjectTokenVerifier`]) and access policy
//! ([`ExchangePolicy`]) to the caller, signs the ID-JAG, and serializes the
//! response. It is not an OpenID Provider: login, ID Token issuance,
//! refresh-token minting, and session management stay with the caller.
//!
//! ```text
//! TokenExchangeRequest::parse ─► caller authenticates the client ─► Idp::exchange
//!                                                                    ├─ Ok(IssuedIdJag)  ─► to_response()
//!                                                                    ├─ Err(ExchangeError) ─► to_response()
//!                                                                    └─ ExchangeRecord (always)
//! ```

mod error;
mod exchange;
mod policy;
mod request;
mod subject;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::claims::Issuer;
use crate::dpop::{DEFAULT_MAX_AGE, DpopNonce, default_dpop_algorithms};
use crate::error::Error;
use crate::jose::{AlgorithmPolicy, JwsSigner};
use crate::metadata::IdpMetadataBuilder;
use crate::replay::ReplayStore;

pub use crate::dpop::{BindingPreference, DpopToNonSupportingAs};
pub use crate::metadata::{GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ID_JAG};
pub use error::{ExchangeError, RejectReason};
pub use exchange::{
    ExchangeOutcome, ExchangeRecord, GrantedAccess, IssuedIdJag, SamlRefreshExchange,
};
pub use policy::{
    ExchangeContext, ExchangeDenial, ExchangeGrant, ExchangePolicy, SamlNameIdMapping,
};
pub use request::{RequestedTokenType, SubjectTokenType, TokenExchangeRequest};
pub use subject::{
    AuthenticatedClient, IdTokenClaims, IdTokenSubject, IdTokenVerifier, RejectOtherSubjectTokens,
    SamlAudienceMap, SubjectRef, SubjectRejection, SubjectTokenInput, SubjectTokenVerifier,
    VerifiedSubject,
};

/// `subject_token_type` of an OpenID Connect ID Token (RFC 8693 §3).
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
/// `subject_token_type` of a SAML 2.0 assertion (RFC 8693 §3).
pub const TOKEN_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
/// Token type of a refresh token (RFC 8693 §3): a `subject_token_type`, and
/// the `requested_token_type` of the draft §4.5 exchange.
pub const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";

/// The JOSE `typ` of an ID-JAG (draft §3.1).
pub(crate) const ID_JAG_TYP: &str = "oauth-id-jag+jwt";

/// Token types that can never be allow-listed as an ID Token `typ`
/// (draft §4.3.3): they name a different token.
const NEVER_A_SUBJECT_TOKEN_TYP: [&str; 3] = [ID_JAG_TYP, "at+jwt", "dpop+jwt"];

/// Whether `iss` alone identifies the issuer's tenant (draft §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdpTenancy {
    /// One tenant per issuer identifier. The `tenant` claim is optional.
    #[default]
    Single,
    /// Several tenants share the issuer identifier. Every ID-JAG carries
    /// `tenant` (draft §6.1 MUST), so every [`VerifiedSubject`] must name one.
    Multi,
}

/// IdP configuration (RFC-005 §1).
#[derive(Clone)]
pub struct IdpConfig {
    /// RFC 8414 issuer identifier. Becomes the ID-JAG `iss`.
    pub issuer: Issuer,
    /// Token endpoint URL, checked against the DPoP proof's `htu`.
    pub token_endpoint: Url,
    /// Signs ID-JAGs. Its public key must be published at `jwks_uri`
    /// (draft §7.1).
    pub signer: Arc<dyn JwsSigner>,
    /// ID-JAG lifetime. Default 5 minutes; draft §9.2 asks for short-lived
    /// grants.
    pub id_jag_lifetime: Duration,
    pub tenancy: IdpTenancy,
    /// Accept DPoP proofs on token exchange and bind ID-JAGs to them
    /// (draft §9.11.1.1). When false a `DPoP` header is ignored, as an
    /// authorization server without DPoP support does; the client detects
    /// the missing `cnf`.
    pub dpop: bool,
    /// What to do with a valid proof for a Resource AS without `jwt-dpop`
    /// (RFC-005 §6.1). Default [`DpopToNonSupportingAs::Reject`].
    pub dpop_to_non_supporting_as: DpopToNonSupportingAs,
    /// Bind ID-JAGs to the client's TLS certificate when one is presented
    /// (draft §9.11.2.1).
    pub mtls_binding: bool,
    /// `typ` values other than absent or `JWT` that this IdP puts on its own
    /// JWT subject tokens (RFC-005 §4.2).
    pub id_token_typ_allow: Vec<String>,
    /// Enable the draft §4.5 SAML → Refresh Token exchange. Requires
    /// [`saml_audiences`](Self::saml_audiences).
    pub saml_refresh_exchange: bool,
    /// Tolerance for the DPoP proof's `iat` window (RFC-001 §8). Default
    /// 60 seconds.
    pub clock_skew: Duration,
    /// DPoP proof algorithms accepted (`dpop_signing_alg_values_supported`).
    /// Default [`default_dpop_algorithms`].
    pub dpop_algorithms: AlgorithmPolicy,
    /// How old a DPoP proof's `iat` may be. Default
    /// [`DEFAULT_MAX_AGE`].
    pub dpop_max_age: Duration,
    /// Set to require a server nonce in every DPoP proof (RFC 9449 §8).
    pub dpop_nonce: Option<Arc<dyn DpopNonce>>,
    /// Set to reject a replayed DPoP proof `jti` (RFC 9449 §11.1). Consulted
    /// last, after every other check.
    pub replay: Option<Arc<dyn ReplayStore>>,
    /// Maps a SAML `Audience` to the client it was issued to (draft §4.5).
    /// Without one every `saml2` subject token is refused.
    pub saml_audiences: Option<Arc<dyn SamlAudienceMap>>,
}

impl IdpConfig {
    /// The defaults: 5-minute single-tenant bearer ID-JAGs, no DPoP or mTLS
    /// binding, no SAML exchange.
    pub fn new(issuer: Issuer, token_endpoint: Url, signer: Arc<dyn JwsSigner>) -> Self {
        Self {
            issuer,
            token_endpoint,
            signer,
            id_jag_lifetime: Duration::from_mins(5),
            tenancy: IdpTenancy::Single,
            dpop: false,
            dpop_to_non_supporting_as: DpopToNonSupportingAs::Reject,
            mtls_binding: false,
            id_token_typ_allow: Vec::new(),
            saml_refresh_exchange: false,
            clock_skew: Duration::from_mins(1),
            dpop_algorithms: default_dpop_algorithms(),
            dpop_max_age: DEFAULT_MAX_AGE,
            dpop_nonce: None,
            replay: None,
            saml_audiences: None,
        }
    }
}

impl std::fmt::Debug for IdpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdpConfig")
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint.as_str())
            .field("signer_algorithm", &self.signer.algorithm())
            .field("signer_key_id", &self.signer.key_id())
            .field("id_jag_lifetime", &self.id_jag_lifetime)
            .field("tenancy", &self.tenancy)
            .field("dpop", &self.dpop)
            .field("dpop_to_non_supporting_as", &self.dpop_to_non_supporting_as)
            .field("mtls_binding", &self.mtls_binding)
            .field("id_token_typ_allow", &self.id_token_typ_allow)
            .field("saml_refresh_exchange", &self.saml_refresh_exchange)
            .field("clock_skew", &self.clock_skew)
            .field("dpop_algorithms", &self.dpop_algorithms)
            .field("dpop_max_age", &self.dpop_max_age)
            .field("dpop_nonce_required", &self.dpop_nonce.is_some())
            .field("replay_store", &self.replay.is_some())
            .field("saml_audiences", &self.saml_audiences.is_some())
            .finish()
    }
}

/// The Resource Authorization Servers this IdP has trust relationships with.
pub trait ResourceAsDirectory: Send + Sync {
    /// Resolve an `audience` (an issuer identifier, or an alias such as a
    /// URN) to a Resource AS (draft §4.3). Issuer identifiers MUST be
    /// supported. `None` refuses the exchange with `invalid_target`.
    fn resolve_audience(
        &self,
        audience: &str,
        issuer_tenant: Option<&str>,
    ) -> Option<ResourceAsEntry>;

    /// Whether `resource` is governed by `ras` (draft §4.3.3). Out of band
    /// per the draft. Compare byte-for-byte (draft §4.3).
    fn governs(&self, ras: &ResourceAsEntry, resource: &str) -> bool;
}

/// One Resource Authorization Server, as the IdP knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAsEntry {
    /// Canonical issuer identifier. Always what goes into `aud`.
    pub issuer: Issuer,
    /// Refuse an exchange that names no `resource` (RFC 8707 §2).
    pub require_resource: bool,
    /// Whether this Resource AS advertises or is configured for the
    /// `jwt-dpop` grant. Unknown counts as false (RFC-005 §6.1).
    pub supports_jwt_dpop: bool,
    /// Whether this Resource AS resolves subjects by SAML NameID
    /// (draft §3.2.2, §9.9).
    pub wants_saml_sub_id: bool,
    /// Used when both a DPoP proof and a certificate could bind
    /// (draft §9.11).
    pub binding_preference: BindingPreference,
}

impl ResourceAsEntry {
    /// An entry with the defaults: resources optional, no `jwt-dpop`, no
    /// `sub_id`.
    pub fn new(issuer: Issuer) -> Self {
        Self {
            issuer,
            require_resource: false,
            supports_jwt_dpop: false,
            wants_saml_sub_id: false,
            binding_preference: BindingPreference::default(),
        }
    }
}

/// The IdP Authorization Server's token-exchange endpoint (RFC-005).
///
/// Stateless: every call takes `now`, and the only stores it touches are the
/// ones in [`IdpConfig`].
#[derive(Debug, Clone)]
pub struct Idp {
    config: IdpConfig,
}

impl Idp {
    /// Check the configuration.
    ///
    /// Fails with [`Error::InvalidConfiguration`] for a zero ID-JAG
    /// lifetime, for the SAML exchange without a [`SamlAudienceMap`]
    /// (draft §4.5 makes the mapping check mandatory), and for a `typ`
    /// allow-list that names another token type (draft §4.3.3).
    pub fn new(config: IdpConfig) -> Result<Self, Error> {
        if config.id_jag_lifetime.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "id_jag_lifetime must not be zero",
            });
        }
        if config.saml_refresh_exchange && config.saml_audiences.is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "saml_refresh_exchange requires saml_audiences",
            });
        }
        if config.id_token_typ_allow.iter().any(|typ| {
            let typ = normalize_typ(typ);
            NEVER_A_SUBJECT_TOKEN_TYP.contains(&typ.as_str())
        }) {
            return Err(Error::InvalidConfiguration {
                reason: "id_token_typ_allow names the type of a different token",
            });
        }
        Ok(Self { config })
    }

    /// The configuration this IdP runs with.
    pub fn config(&self) -> &IdpConfig {
        &self.config
    }

    /// The IdP's RFC 8414 / OIDC Discovery metadata, ready to extend and
    /// build (RFC-005 §11, draft §7.1).
    ///
    /// Emits `identity_chaining_requested_token_types_supported` with the
    /// ID-JAG type (plus the refresh token type when the draft §4.5 exchange
    /// is enabled), the token-exchange grant type, `jwks_uri`, and the DPoP
    /// algorithms when DPoP is enabled. `jwks_uri` must serve the signer's
    /// public key.
    pub fn metadata_builder(&self, jwks_uri: Url) -> IdpMetadataBuilder {
        let mut builder = IdpMetadataBuilder::new(
            self.config.issuer.clone(),
            self.config.token_endpoint.clone(),
            jwks_uri,
        );
        if self.config.saml_refresh_exchange {
            builder = builder.requested_token_type(TOKEN_TYPE_REFRESH_TOKEN);
        }
        if self.config.dpop {
            builder = builder.dpop_signing_algs(self.config.dpop_algorithms.algorithms());
        }
        builder
    }
}

/// Case-insensitive, with an `application/` prefix dropped (RFC 7515 §4.1.9).
pub(crate) fn normalize_typ(typ: &str) -> String {
    let lower = typ.to_ascii_lowercase();
    match lower.strip_prefix("application/") {
        Some(rest) => rest.to_owned(),
        None => lower,
    }
}
