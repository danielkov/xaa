//! Client — the requesting app (draft §2.1 "Client"). See RFC-003.
//!
//! 1. §4.3 Token Exchange (RFC 8693) at the IdP token endpoint:
//!    `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
//!    `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`,
//!    exactly one `audience` (the resource AS issuer), `resource`, optional
//!    `scope`, and a `subject_token` of type `id_token`, `saml2`, or
//!    `refresh_token`.
//! 2. §4.4 Access Token Request (RFC 7523 jwt-bearer) at the Resource AS
//!    token endpoint:
//!    `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
//!    `assertion=<ID-JAG>`, optional `scope`.
//!
//! Every round trip is available sans-IO and as one call:
//!
//! | Round trip | Build | Parse | One call |
//! | --- | --- | --- | --- |
//! | §4.3 Token Exchange | [`TokenExchange::build`] | [`parse_token_exchange_response`] | [`exchange_for_id_jag`] |
//! | §4.4 Access Token Request | [`AccessTokenRequest::build`] | [`parse_access_token_response`] | [`request_access_token`] |
//! | §4.5 SAML → Refresh Token | [`SamlToRefreshToken::build`] | [`parse_saml_exchange_response`] | [`exchange_saml_for_refresh_token`] |
//!
//! The library holds no state and never retries. A non-200 answer from a
//! token endpoint is [`Error::TokenEndpoint`](crate::Error::TokenEndpoint),
//! and [`TokenEndpointError::remediation`] says what to do next.
//!
//! Subject tokens are high-value credentials (draft §9.2). Scope stored ones
//! to the user session, keep them out of logs, and store them apart from
//! client credentials. Prefer requesting a new ID-JAG over caching one.

mod access_token;
mod config;
mod discovery;
mod exchange;
mod peek;
mod saml;
mod token_error;
mod wire;

#[cfg(test)]
mod tests;

pub use crate::client_auth::ClientAuth;
pub use access_token::{
    AccessTokenRequest, AccessTokenType, IssuedAccessToken, parse_access_token_response,
    request_access_token,
};
pub use config::{
    ActorToken, ExchangeAudience, IdpConnection, ResourceAsClientAuth, ResourceAsConnection,
    ResourceIdentifier, SamlEncoding, SubjectToken,
};
pub use discovery::{
    DiscoveredIdp, DiscoveredResource, DiscoveredResourceAs, discover_idp, discover_resource,
    discover_resource_as,
};
pub use exchange::{
    IssuedIdJag, TokenExchange, exchange_for_id_jag, parse_token_exchange_response,
};
pub use peek::IdJagPeek;
pub use saml::{SamlToRefreshToken, exchange_saml_for_refresh_token, parse_saml_exchange_response};
pub use token_error::{Endpoint, Remediation, TokenEndpointError};
