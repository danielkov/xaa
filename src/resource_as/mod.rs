//! Resource AS — the Resource Authorization Server (draft §2.1). See RFC-004.
//!
//! Accepts ID-JAGs at the token endpoint (draft §4.4):
//!
//! 1. [`TokenRequest::parse`] reads the jwt-bearer / jwt-dpop request and
//!    extracts, without verifying, the client credentials.
//! 2. The caller authenticates the client and reports a [`ClientIdentity`].
//!    On failure it answers [`TokenError::invalid_client`] itself.
//! 3. [`ResourceAs::validate`] applies every draft §4.4.1 rule in a fixed
//!    order and returns a [`VerifiedGrant`]: the only way to read the
//!    ID-JAG's claims.
//! 4. The caller resolves the subject within
//!    [`VerifiedGrant::recipient_tenant`], and its policy decides what to
//!    grant through [`VerifiedGrant::decide`]. The builder enforces that the
//!    grant stays within the ID-JAG.
//! 5. [`GrantDecision::token_response`] and [`TokenError::to_response`]
//!    serialize the answers.
//!
//! The component never mints access tokens and never resolves subjects to
//! accounts: the Resource AS "keeps independent control over its own access
//! tokens" (draft §1). It has no clock and no state; replay protection goes
//! through the caller's [`ReplayStore`](crate::replay::ReplayStore), chosen
//! explicitly with [`JtiPolicy`].

mod config;
mod error;
mod grant;
mod request;
mod validate;

#[cfg(test)]
mod tests;

pub use crate::client_auth::{
    ClientAssertionContext, ClientAssertionPolicy, ClientAuthMethod, ClientCredentials,
    ClientIdentity, client_assertion_issuer_unverified, verify_client_assertion,
};
pub use crate::dpop::{
    AccessTokenBinding, AssertionGrantType, BindingPreference, BindingRejection,
};
pub use crate::metadata::ResourceAsMetadataBuilder;
pub use config::{
    DEFAULT_MAX_ID_JAG_LIFETIME, IssuerKeys, JtiPolicy, RecipientTenant, ResourceAsConfig,
    ResourceRegistry, SamlIssuerTrust, SamlSubjectKey, SamlSubjectKeyValue, Tenancy,
    TenantDecision, TenantResolver, TrustedIssuer,
};
pub use error::{RejectReason, TokenError};
pub use grant::{
    GrantDecision, GrantDecisionBuilder, ProvenBinding, UnverifiedSubjectHints, VerifiedGrant,
};
pub use request::TokenRequest;
pub use validate::ResourceAs;
