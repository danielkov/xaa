//! Discovery for clients that start from a resource URL, as AI agents and
//! MCP clients do. See RFC-003 §10 and RFC-006.
//!
//! Which IdP to use for a given user is out of scope (draft Appendix
//! A.4.2.1).

use url::Url;

use crate::claims::Issuer;
use crate::client_auth::ClientAuth;
use crate::error::Error;
use crate::http::HttpClient;
use crate::metadata::{
    AuthorizationServerMetadata, FetchOptions, PrmOrigin, Support, ValidatedPrm,
    fetch_authorization_server_metadata, fetch_protected_resource_metadata,
};

use super::config::{
    IdpConnection, ResourceAsClientAuth, ResourceAsConnection, ResourceIdentifier, SamlEncoding,
};

/// A protected resource whose metadata passed the draft §9.6 check.
#[derive(Debug, Clone)]
pub struct DiscoveredResource {
    /// The metadata's `resource`, byte-for-byte: send it as the `resource`
    /// of the token exchange (draft §4.3).
    pub resource: ResourceIdentifier,
    /// The validated document. Choose a Resource AS from
    /// [`ValidatedPrm::authorization_servers`].
    pub metadata: ValidatedPrm,
}

/// Fetch and validate Protected Resource Metadata (RFC 9728).
///
/// `resource` must be identical to what `origin` names
/// ([`Error::PrmResourceMismatch`], draft §9.6).
pub async fn discover_resource<C: HttpClient>(
    http: &C,
    origin: PrmOrigin<'_>,
    opts: &FetchOptions,
) -> Result<DiscoveredResource, Error> {
    let metadata = fetch_protected_resource_metadata(http, origin, opts).await?;
    Ok(DiscoveredResource {
        resource: ResourceIdentifier::from_metadata(&metadata),
        metadata,
    })
}

/// A Resource AS whose metadata passed the draft §9.5 issuer check.
#[derive(Debug, Clone)]
pub struct DiscoveredResourceAs {
    pub issuer: Issuer,
    pub token_endpoint: Url,
    /// Whether `authorization_grant_profiles_supported` lists
    /// `urn:ietf:params:oauth:grant-profile:id-jag`. Draft §7.2 says SHOULD
    /// advertise, so `NotAdvertised` is reported, not fatal.
    pub id_jag_profile: Support,
    /// Whether `grant_types_supported` lists the `jwt-dpop` grant.
    pub jwt_dpop: Support,
    pub metadata: AuthorizationServerMetadata,
}

impl DiscoveredResourceAs {
    /// The connection to this Resource AS for a client registered there
    /// with `client_auth`. `supports_jwt_dpop` is set only if the metadata
    /// advertises the grant.
    pub fn connection(&self, client_auth: ResourceAsClientAuth) -> ResourceAsConnection {
        ResourceAsConnection {
            issuer: self.issuer.clone(),
            token_endpoint: self.token_endpoint.clone(),
            client_auth,
            supports_jwt_dpop: self.jwt_dpop.is_advertised(),
        }
    }
}

/// Fetch and validate the metadata of the Resource AS `issuer`, usually an
/// entry of [`ValidatedPrm::authorization_servers`].
///
/// The document's `issuer` must be identical to `issuer`
/// ([`Error::MetadataIssuerMismatch`], draft §9.5); on a mismatch nothing
/// from it is used. A document without a `token_endpoint` fails with
/// [`Error::InvalidMetadata`].
pub async fn discover_resource_as<C: HttpClient>(
    http: &C,
    issuer: &Issuer,
    opts: &FetchOptions,
) -> Result<DiscoveredResourceAs, Error> {
    let metadata = fetch_authorization_server_metadata(http, issuer, opts).await?;
    Ok(DiscoveredResourceAs {
        issuer: metadata.issuer.clone(),
        token_endpoint: token_endpoint(&metadata)?,
        id_jag_profile: metadata.accepts_id_jag_profile(),
        jwt_dpop: metadata.accepts_jwt_dpop(),
        metadata,
    })
}

/// An IdP whose metadata passed the draft §9.5 issuer check.
#[derive(Debug, Clone)]
pub struct DiscoveredIdp {
    pub issuer: Issuer,
    pub token_endpoint: Url,
    /// Whether `identity_chaining_requested_token_types_supported` lists the
    /// ID-JAG token type (draft §7.1). `NotAdvertised` means unknown, not
    /// unsupported.
    pub issues_id_jag: Support,
    pub metadata: AuthorizationServerMetadata,
}

impl DiscoveredIdp {
    /// The connection to this IdP for a client registered there with
    /// `client_auth`, sending `saml2` subject tokens as base64url.
    pub fn connection(&self, client_auth: ClientAuth) -> IdpConnection {
        IdpConnection {
            issuer: self.issuer.clone(),
            token_endpoint: self.token_endpoint.clone(),
            client_auth,
            saml_encoding: SamlEncoding::default(),
        }
    }
}

/// Fetch and validate the metadata of the IdP `issuer`, with the OIDC
/// Discovery fallback of RFC-006 §3.
///
/// Same checks as [`discover_resource_as`].
pub async fn discover_idp<C: HttpClient>(
    http: &C,
    issuer: &Issuer,
    opts: &FetchOptions,
) -> Result<DiscoveredIdp, Error> {
    let metadata = fetch_authorization_server_metadata(http, issuer, opts).await?;
    Ok(DiscoveredIdp {
        issuer: metadata.issuer.clone(),
        token_endpoint: token_endpoint(&metadata)?,
        issues_id_jag: metadata.issues_id_jag(),
        metadata,
    })
}

fn token_endpoint(metadata: &AuthorizationServerMetadata) -> Result<Url, Error> {
    metadata
        .token_endpoint
        .clone()
        .ok_or(Error::InvalidMetadata {
            reason: "token_endpoint is missing",
        })
}
