//! The §4.4 Access Token Request at the Resource AS. See RFC-003 §6–§7.

use std::time::{Duration, SystemTime};

use zeroize::Zeroize as _;

use crate::claims::{AuthorizationDetails, Confirmation, Scope};
use crate::dpop::{AssertionGrantType, DPOP_HEADER, DpopRequest};
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::secret::{AccessToken, RefreshToken};

use super::config::{ResourceAsClientAuth, ResourceAsConnection};
use super::exchange::IssuedIdJag;
use super::token_error::Endpoint;
use super::wire;

/// An Access Token Request that presents an ID-JAG (draft §4.4).
#[derive(Debug, Clone)]
pub struct AccessTokenRequest<'a> {
    pub resource_as: &'a ResourceAsConnection,
    pub id_jag: &'a IssuedIdJag,
    /// Optional downscoping. Must be a subset of the ID-JAG's scope.
    pub scope: Option<Scope>,
    /// Required when the ID-JAG carries `cnf.jkt`, with the same key that
    /// was used at the IdP (jwt-dpop-grant §3). Otherwise optional: it asks
    /// for a DPoP-bound access token (draft §9.11.1.2.3).
    pub dpop: Option<DpopRequest<'a>>,
    pub now: SystemTime,
}

impl AccessTokenRequest<'_> {
    /// The scope the ID-JAG carries: its `scope` claim, or what the IdP's
    /// response said it granted.
    fn id_jag_scope(&self) -> Option<&Scope> {
        self.id_jag.peek.scope().or(self.id_jag.scope.as_ref())
    }

    /// Build the request: a form `POST` to `resource_as.token_endpoint`.
    ///
    /// `grant_type` is `jwt-dpop` when the ID-JAG carries `cnf.jkt`
    /// (jwt-dpop-grant §4.1) and `jwt-bearer` otherwise, including for
    /// `x5t#S256`-bound ID-JAGs (draft §9.11.2.2).
    ///
    /// Refuses, before anything is signed or sent:
    ///
    /// - [`Error::UnauthenticatedUnboundGrant`]: no client authentication
    ///   and an ID-JAG without a `jkt` or `x5t#S256` binding (draft §4.4).
    /// - [`Error::ResourceAsLacksJwtDpop`]: a `cnf.jkt` ID-JAG for an AS
    ///   without the `jwt-dpop` grant, which might accept it as a bearer
    ///   grant and defeat the binding (jwt-dpop-grant §7.1).
    /// - [`Error::DpopKeyRequired`]: a `cnf.jkt` ID-JAG without `dpop`, or
    ///   with another key.
    /// - [`Error::ScopeNotSubset`]: `scope` exceeds the ID-JAG's scope.
    pub async fn build(&self) -> Result<HttpRequest, Error> {
        let cnf = self.id_jag.peek.confirmation();
        let sender_constrained =
            matches!(cnf, Some(Confirmation::Jkt(_) | Confirmation::X5tS256(_)));
        let auth = &self.resource_as.client_auth;
        if matches!(auth, ResourceAsClientAuth::SenderConstrainedOnly { .. }) && !sender_constrained
        {
            return Err(Error::UnauthenticatedUnboundGrant);
        }
        if matches!(cnf, Some(Confirmation::Jkt(_))) {
            if !self.resource_as.supports_jwt_dpop {
                return Err(Error::ResourceAsLacksJwtDpop);
            }
            if !self.dpop.is_some_and(|dpop| dpop.key.is_confirmed_by(cnf)) {
                return Err(Error::DpopKeyRequired);
            }
        }
        if let (Some(requested), Some(granted)) = (&self.scope, self.id_jag_scope())
            && !requested.is_subset_of(granted)
        {
            return Err(Error::ScopeNotSubset);
        }

        let mut form = wire::Form::new();
        wire::push(
            &mut form,
            "grant_type",
            AssertionGrantType::for_confirmation(cnf).as_str(),
        );
        wire::push(&mut form, "assertion", self.id_jag.id_jag.expose_secret());
        if let Some(scope) = &self.scope {
            wire::push(&mut form, "scope", scope.as_str());
        }

        let mut headers = wire::token_request_headers();
        match auth {
            ResourceAsClientAuth::Authenticated(auth) => {
                auth.apply(&self.resource_as.issuer, &mut form, &mut headers, self.now)
                    .await?;
            }
            // RFC 6749 §3.2.1: a client that does not authenticate
            // identifies itself with `client_id`.
            ResourceAsClientAuth::SenderConstrainedOnly { client_id } => {
                wire::push(&mut form, "client_id", client_id);
            }
        }
        if let Some(dpop) = &self.dpop {
            let proof = dpop
                .token_endpoint_proof(&self.resource_as.token_endpoint, self.now)
                .await?;
            headers.push((DPOP_HEADER.to_owned(), proof));
        }
        Ok(wire::token_request(
            &self.resource_as.token_endpoint,
            form,
            headers,
        ))
    }
}

/// The `token_type` of an issued access token (RFC 6749 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessTokenType {
    /// RFC 6750. Also the type of a certificate-bound token (RFC 8705).
    Bearer,
    /// Bound to the DPoP key of the request's proof (RFC 9449 §5).
    DPoP,
}

/// An access token issued by the Resource AS.
///
/// Not `Serialize`: persisting it takes an explicit
/// `access_token.expose_secret()`.
#[derive(Debug, Clone)]
pub struct IssuedAccessToken {
    pub access_token: AccessToken,
    pub token_type: AccessTokenType,
    pub expires_in: Option<Duration>,
    /// The granted scope. Equal to the requested scope when the response
    /// omits `scope` (RFC 6749 §5.1). `None` when the server reports an
    /// empty scope, or when nothing was requested, granted, or carried by
    /// the ID-JAG.
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    /// Off-profile: draft §4.4.4 says the Resource AS SHOULD NOT issue one.
    /// Surfaced if present.
    pub refresh_token: Option<RefreshToken>,
    /// The `now` of the request this answers.
    pub received_at: SystemTime,
}

impl IssuedAccessToken {
    /// Whether the token is DPoP-bound: `token_type` is `DPoP`. A Resource
    /// AS may answer a request that carried a proof with a plain `Bearer`
    /// token (draft §9.11.1.2.3, jwt-dpop-grant §6).
    ///
    /// A certificate-bound token (RFC 8705) is typed `Bearer` and cannot be
    /// told apart here.
    pub fn is_sender_constrained(&self) -> bool {
        self.token_type == AccessTokenType::DPoP
    }
}

/// Parse the Resource AS's answer to `request` (draft §4.4.2, RFC 6749
/// §5.1).
///
/// - A non-200 status is [`Error::TokenEndpoint`].
/// - `token_type` must be `Bearer` or `DPoP`, case-insensitively
///   ([`Error::UnsupportedTokenType`]); `DPoP` only if the request carried
///   a proof.
///
/// The response body is zeroized before returning.
pub fn parse_access_token_response(
    request: &AccessTokenRequest<'_>,
    mut response: HttpResponse,
) -> Result<IssuedAccessToken, Error> {
    let result = parse(request, &response);
    response.body.zeroize();
    result
}

fn parse(
    request: &AccessTokenRequest<'_>,
    response: &HttpResponse,
) -> Result<IssuedAccessToken, Error> {
    let mut members = wire::success_members(Endpoint::ResourceAs, response)?;
    let access_token = wire::take_token(
        &mut members,
        "access_token",
        "access_token is missing or empty",
    )?;
    let refresh_token = wire::take_string(
        &mut members,
        "refresh_token",
        "refresh_token is not a string",
    )?
    .filter(|token| !token.is_empty())
    .map(RefreshToken::from);
    let token_type = wire::take_string(&mut members, "token_type", "token_type is not a string")?
        .ok_or(Error::InvalidTokenResponse {
        reason: "token_type is missing",
    })?;
    let token_type = if token_type.eq_ignore_ascii_case("Bearer") {
        AccessTokenType::Bearer
    } else if token_type.eq_ignore_ascii_case("DPoP") {
        AccessTokenType::DPoP
    } else {
        return Err(Error::UnsupportedTokenType { got: token_type });
    };
    if token_type == AccessTokenType::DPoP && request.dpop.is_none() {
        return Err(Error::InvalidTokenResponse {
            reason: "token_type is DPoP but the request carried no DPoP proof",
        });
    }
    let scope = wire::take_scope(&mut members)?.or_requested(|| {
        request
            .scope
            .clone()
            .or_else(|| request.id_jag_scope().cloned())
    });

    Ok(IssuedAccessToken {
        access_token: AccessToken::new(access_token.as_str()),
        token_type,
        expires_in: wire::take_expires_in(&mut members)?,
        scope,
        authorization_details: wire::take_authorization_details(&mut members)?,
        refresh_token,
        received_at: request.now,
    })
}

/// Build `request`, send it through `http`, and parse the answer.
///
/// The library holds no state: afterwards, call
/// [`IssuedIdJag::mark_presented`] on the ID-JAG that was sent.
///
/// `http` MUST NOT follow redirects: a redirect would replay the ID-JAG and
/// the client's credentials to another origin.
pub async fn request_access_token<C: HttpClient>(
    http: &C,
    request: &AccessTokenRequest<'_>,
) -> Result<IssuedAccessToken, Error> {
    let response = wire::send(http, request.build().await?).await?;
    parse_access_token_response(request, response)
}
