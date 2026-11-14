//! The §4.5 exchange of a SAML assertion for an IdP Refresh Token. See
//! RFC-003 §9.

use std::time::SystemTime;

use zeroize::Zeroize as _;

use crate::claims::Scope;
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::metadata::GRANT_TYPE_TOKEN_EXCHANGE;
use crate::secret::{RefreshToken, SamlAssertion};

use super::config::{IdpConnection, TOKEN_TYPE_REFRESH_TOKEN, TOKEN_TYPE_SAML2};
use super::token_error::Endpoint;
use super::wire;

/// Draft §4.5: the request SHOULD ask for `openid offline_access`.
const DEFAULT_SCOPE: &str = "openid offline_access";

/// A Token Exchange of a SAML assertion for an IdP Refresh Token (draft
/// §4.5).
///
/// A client that does SSO with SAML runs this once, then uses the Refresh
/// Token as the `subject_token` of [`TokenExchange`](super::TokenExchange).
/// Mapping the assertion's `Audience` to the client is the IdP's check.
#[derive(Debug, Clone)]
pub struct SamlToRefreshToken<'a> {
    pub idp: &'a IdpConnection,
    pub assertion: &'a SamlAssertion,
    /// `openid offline_access` unless changed; extra scopes are allowed.
    pub scope: Scope,
    pub now: SystemTime,
}

impl<'a> SamlToRefreshToken<'a> {
    /// An exchange that asks for `openid offline_access`.
    pub fn new(
        idp: &'a IdpConnection,
        assertion: &'a SamlAssertion,
        now: SystemTime,
    ) -> Result<Self, Error> {
        Ok(Self {
            idp,
            assertion,
            scope: Scope::parse(DEFAULT_SCOPE)?,
            now,
        })
    }

    /// Build the request: a form `POST` to `idp.token_endpoint` with
    /// `requested_token_type=…:refresh_token`, `subject_token_type=…:saml2`,
    /// and no `audience`. The assertion is encoded per
    /// [`IdpConnection::saml_encoding`].
    pub async fn build(&self) -> Result<HttpRequest, Error> {
        let subject_token = self.idp.saml_encoding.encode(self.assertion);
        if subject_token.is_empty() {
            return Err(Error::InvalidRequest {
                reason: "subject_token is empty",
            });
        }
        let mut form = wire::Form::new();
        wire::push(&mut form, "grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
        wire::push(&mut form, "requested_token_type", TOKEN_TYPE_REFRESH_TOKEN);
        wire::push(&mut form, "scope", self.scope.as_str());
        wire::push(&mut form, "subject_token", &subject_token);
        wire::push(&mut form, "subject_token_type", TOKEN_TYPE_SAML2);

        let mut headers = wire::token_request_headers();
        self.idp
            .client_auth
            .apply(&self.idp.issuer, &mut form, &mut headers, self.now)
            .await?;
        Ok(wire::token_request(&self.idp.token_endpoint, form, headers))
    }
}

/// Parse the IdP's answer to a [`SamlToRefreshToken`] request.
///
/// `issued_token_type` must be
/// `urn:ietf:params:oauth:token-type:refresh_token`
/// ([`Error::UnexpectedIssuedTokenType`]) and `token_type` must be `N_A`.
/// The Refresh Token is the RFC 8693 §2.2.1 `access_token` member.
///
/// The response body is zeroized before returning.
pub fn parse_saml_exchange_response(
    _request: &SamlToRefreshToken<'_>,
    mut response: HttpResponse,
) -> Result<RefreshToken, Error> {
    let result = wire::success_members(Endpoint::Idp, &response).and_then(|mut members| {
        let token = wire::take_exchanged_token(&mut members, TOKEN_TYPE_REFRESH_TOKEN)?;
        Ok(RefreshToken::new(token.as_str()))
    });
    response.body.zeroize();
    result
}

/// Build `request`, send it through `http`, and parse the answer.
///
/// `http` MUST NOT follow redirects.
pub async fn exchange_saml_for_refresh_token<C: HttpClient>(
    http: &C,
    request: &SamlToRefreshToken<'_>,
) -> Result<RefreshToken, Error> {
    let response = wire::send(http, request.build().await?).await?;
    parse_saml_exchange_response(request, response)
}
