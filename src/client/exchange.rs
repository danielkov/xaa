//! The §4.3 Token Exchange at the IdP: request, response, and the
//! self-checks on the issued ID-JAG. See RFC-003 §3–§5.

use std::time::{Duration, SystemTime};

use zeroize::Zeroize as _;

use crate::claims::{AuthorizationDetails, Scope};
use crate::dpop::{DPOP_HEADER, DpopRequest};
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::metadata::{GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ID_JAG};
use crate::mtls::{certificate_thumbprint, thumbprint_matches};
use crate::secret::IdJag;

use super::config::{
    ActorToken, ExchangeAudience, IdpConnection, ResourceAsConnection, ResourceIdentifier,
    SubjectToken,
};
use super::peek::IdJagPeek;
use super::token_error::Endpoint;
use super::wire;

/// A Token Exchange request for an ID-JAG (draft §4.3).
#[derive(Debug, Clone)]
pub struct TokenExchange<'a> {
    pub idp: &'a IdpConnection,
    /// The Resource AS the ID-JAG is for. Used for the DPoP preflight in
    /// [`build`](Self::build) and for the self-checks on the response.
    pub resource_as: &'a ResourceAsConnection,
    /// Usually `resource_as.issuer`; may be an IdP-specific alias.
    pub audience: ExchangeAudience,
    /// RFC 8707 resource identifiers, sent as repeated `resource`
    /// parameters in this order and never rewritten.
    pub resources: Vec<ResourceIdentifier>,
    /// Scope values mean what the Resource AS defines, not their OIDC
    /// meaning (draft §4.3).
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub subject_token: &'a SubjectToken,
    /// Passed through only (draft §4.3, §9.10).
    pub actor_token: Option<ActorToken>,
    /// Ask the IdP to bind the ID-JAG to this DPoP key (draft §9.11.1.1).
    pub dpop: Option<DpopRequest<'a>>,
    /// The DER of the TLS client certificate the caller's
    /// [`HttpClient`] presents to the IdP, if any. The library sends
    /// nothing for it; it is here so that a dropped certificate binding is
    /// detected (draft §9.11.2.1).
    pub tls_client_certificate: Option<&'a [u8]>,
    /// Skip the binding-downgrade checks. See
    /// [`accept_unbound_id_jag`](Self::accept_unbound_id_jag).
    pub accept_unbound_id_jag: bool,
    /// Accept an ID-JAG whose `resource` differs from a requested one only
    /// by a single trailing `/`. See
    /// [`tolerate_resource_trailing_slash`](Self::tolerate_resource_trailing_slash).
    pub tolerate_resource_trailing_slash: bool,
    pub now: SystemTime,
}

impl<'a> TokenExchange<'a> {
    /// An exchange of `subject_token` for an ID-JAG whose audience is
    /// `resource_as.issuer`, with nothing optional set.
    pub fn new(
        idp: &'a IdpConnection,
        resource_as: &'a ResourceAsConnection,
        subject_token: &'a SubjectToken,
        now: SystemTime,
    ) -> Self {
        Self {
            idp,
            resource_as,
            audience: ExchangeAudience::from(&resource_as.issuer),
            resources: Vec::new(),
            scope: None,
            authorization_details: None,
            subject_token,
            actor_token: None,
            dpop: None,
            tls_client_certificate: None,
            accept_unbound_id_jag: false,
            tolerate_resource_trailing_slash: false,
            now,
        }
    }

    /// Turn the binding-downgrade checks off (`true`) or back on.
    ///
    /// By default an ID-JAG that is not bound to the DPoP key or TLS client
    /// certificate that was presented fails with
    /// [`Error::BindingDowngrade`]. Turn that off only for an IdP known to
    /// ignore DPoP proofs.
    /// Relax the `resource` self-check for an IdP that adds or drops one
    /// trailing `/` instead of echoing the identifier byte for byte.
    ///
    /// Draft §4.3.3 requires the echo to be exact, and the check is exact by
    /// default. The xaa.dev playground IdP returns
    /// `https://api.resource.xaa.dev` for a requested
    /// `https://api.resource.xaa.dev/` (`docs/interop.md`). Nothing else is
    /// tolerated: not letter case, not a different path, and not an extra
    /// resource.
    pub fn tolerate_resource_trailing_slash(mut self, tolerate: bool) -> Self {
        self.tolerate_resource_trailing_slash = tolerate;
        self
    }

    pub fn accept_unbound_id_jag(mut self, accept: bool) -> Self {
        self.accept_unbound_id_jag = accept;
        self
    }

    /// Build the request: a form `POST` to `idp.token_endpoint`.
    ///
    /// Async because a DPoP proof or a `private_key_jwt` assertion is signed
    /// here. Fails with [`Error::ResourceAsLacksJwtDpop`] when `dpop` is set
    /// for a Resource AS without the `jwt-dpop` grant: the resulting ID-JAG
    /// could not be used (jwt-dpop-grant §7.1). For a DPoP-bound access
    /// token from such an AS, send the proof on the access token request
    /// instead.
    pub async fn build(&self) -> Result<HttpRequest, Error> {
        if self.dpop.is_some() && !self.resource_as.supports_jwt_dpop {
            return Err(Error::ResourceAsLacksJwtDpop);
        }
        if let Some(certificate) = self.tls_client_certificate {
            certificate_thumbprint(certificate)?;
        }
        if self.audience.as_str().is_empty() {
            return Err(Error::InvalidRequest {
                reason: "audience is empty",
            });
        }
        if self
            .resources
            .iter()
            .any(|resource| resource.as_str().is_empty())
        {
            return Err(Error::InvalidRequest {
                reason: "a resource identifier is empty",
            });
        }

        let mut form = wire::Form::new();
        wire::push(&mut form, "grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
        wire::push(&mut form, "requested_token_type", TOKEN_TYPE_ID_JAG);
        wire::push(&mut form, "audience", self.audience.as_str());
        for resource in &self.resources {
            wire::push(&mut form, "resource", resource.as_str());
        }
        if let Some(scope) = &self.scope {
            wire::push(&mut form, "scope", scope.as_str());
        }
        if let Some(details) = &self.authorization_details {
            let json = serde_json::to_string(details).map_err(|_source| Error::InvalidRequest {
                reason: "authorization_details cannot be serialized",
            })?;
            wire::push(&mut form, "authorization_details", &json);
        }
        let (subject_token, subject_token_type) =
            self.subject_token.parameters(self.idp.saml_encoding);
        if subject_token.is_empty() {
            return Err(Error::InvalidRequest {
                reason: "subject_token is empty",
            });
        }
        wire::push(&mut form, "subject_token", &subject_token);
        wire::push(&mut form, "subject_token_type", subject_token_type);
        if let Some(actor) = &self.actor_token {
            // RFC 8693 §2.1: actor_token_type is REQUIRED with actor_token.
            if actor.expose_secret().is_empty() || actor.token_type().is_empty() {
                return Err(Error::InvalidRequest {
                    reason: "actor_token needs a value and an actor_token_type",
                });
            }
            wire::push(&mut form, "actor_token", actor.expose_secret());
            wire::push(&mut form, "actor_token_type", actor.token_type());
        }

        let mut headers = wire::token_request_headers();
        self.idp
            .client_auth
            .apply(&self.idp.issuer, &mut form, &mut headers, self.now)
            .await?;
        if let Some(dpop) = &self.dpop {
            let proof = dpop
                .token_endpoint_proof(&self.idp.token_endpoint, self.now)
                .await?;
            headers.push((DPOP_HEADER.to_owned(), proof));
        }
        Ok(wire::token_request(&self.idp.token_endpoint, form, headers))
    }

    /// The RFC-003 §5 self-checks on the issued ID-JAG.
    fn self_check(&self, peek: &IdJagPeek) -> Result<(), Error> {
        // Draft §4.4.1: the audience is the Resource AS issuer. Catches an
        // IdP alias that resolved to another AS before credentials leave.
        if peek.audience().sole() != Some(self.resource_as.issuer.as_str()) {
            return Err(Error::IdJagAudienceMismatch);
        }
        // Draft §5.1: the client_id is the one registered at the Resource
        // AS, not the one used at the IdP.
        if peek.client_id() != self.resource_as.client_auth.client_id() {
            return Err(Error::IdJagClientIdMismatch);
        }
        // Draft §4.3.3: "exactly as the Client sent it". A client that named
        // no resource gets the IdP's default, so there is nothing to compare.
        if let Some(resources) = peek.resources()
            && !self.resources.is_empty()
        {
            let without_slash =
                |value: &str| -> String { value.strip_suffix('/').unwrap_or(value).to_owned() };
            let requested = |value: &String| {
                self.resources.iter().any(|resource| {
                    resource.as_str() == value
                        || (self.tolerate_resource_trailing_slash
                            && without_slash(resource.as_str()) == without_slash(value))
                })
            };
            if let Some(altered) = resources.values().iter().find(|value| !requested(value)) {
                return Err(Error::IdJagResourceAltered {
                    got: altered.clone(),
                    requested: self
                        .resources
                        .iter()
                        .map(|resource| resource.as_str().to_owned())
                        .collect(),
                });
            }
        }
        if self.accept_unbound_id_jag {
            return Ok(());
        }
        // Draft §9.11.1.1, §9.11.2.1. The IdP binds to one mechanism, never
        // both, so with a proof and a certificate either binding will do.
        let cnf = peek.confirmation();
        let bound_to_key = self.dpop.is_some_and(|dpop| dpop.key.is_confirmed_by(cnf));
        let bound_to_certificate = match self.tls_client_certificate {
            Some(certificate) => thumbprint_matches(&certificate_thumbprint(certificate)?, cnf),
            None => false,
        };
        let binding_requested = self.dpop.is_some() || self.tls_client_certificate.is_some();
        if binding_requested && !bound_to_key && !bound_to_certificate {
            return Err(Error::BindingDowngrade);
        }
        Ok(())
    }
}

/// An ID-JAG issued by the IdP, with the response members that came with it.
///
/// Not `Serialize`: persisting the ID-JAG takes an explicit
/// `id_jag.expose_secret()`. Prefer requesting a new one over caching.
#[derive(Debug, Clone)]
pub struct IssuedIdJag {
    pub id_jag: IdJag,
    /// The scope the IdP granted. Equal to the requested scope when the
    /// response omits `scope` (draft §4.3.4).
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub expires_in: Option<Duration>,
    /// The `now` of the request this answers.
    pub received_at: SystemTime,
    /// Unverified view of the ID-JAG's claims.
    pub peek: IdJagPeek,
    /// True until the ID-JAG has been presented once. The library holds no
    /// state: call [`mark_presented`](Self::mark_presented) after sending an
    /// access token request, and pass the earlier value to
    /// [`TokenEndpointError::remediation`](super::TokenEndpointError::remediation).
    pub fresh: bool,
}

impl IssuedIdJag {
    /// Record that the ID-JAG has been presented to the Resource AS.
    pub fn mark_presented(&mut self) {
        self.fresh = false;
    }

    /// Whether the ID-JAG's `exp` has passed at `now`. One that has not
    /// expired may be presented again (draft §4.4.4).
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.peek.is_expired(now)
    }
}

/// Parse the IdP's answer to `request` (draft §4.3.4, RFC 8693 §2.2.1) and
/// run the self-checks on the issued ID-JAG.
///
/// - A non-200 status is [`Error::TokenEndpoint`].
/// - `issued_token_type` must be the ID-JAG token type
///   ([`Error::UnexpectedIssuedTokenType`]) and `token_type` must be `N_A`.
/// - A `refresh_token` is dropped, not surfaced (draft §4.3.4 SHOULD NOT).
/// - The ID-JAG must be typed `oauth-id-jag+jwt`, name the Resource AS as
///   its audience, carry the client's Resource AS `client_id`, carry only
///   resources that were requested, and be bound to the key or certificate
///   that was presented.
///
/// The response body is zeroized before returning.
pub fn parse_token_exchange_response(
    request: &TokenExchange<'_>,
    mut response: HttpResponse,
) -> Result<IssuedIdJag, Error> {
    let result = parse(request, &response);
    response.body.zeroize();
    result
}

fn parse(request: &TokenExchange<'_>, response: &HttpResponse) -> Result<IssuedIdJag, Error> {
    let mut members = wire::success_members(Endpoint::Idp, response)?;
    let token = wire::take_exchanged_token(&mut members, TOKEN_TYPE_ID_JAG)?;
    let scope = wire::take_scope(&mut members)?.or_requested(|| request.scope.clone());
    let authorization_details = wire::take_authorization_details(&mut members)?;
    let expires_in = wire::take_expires_in(&mut members)?;

    let peek = IdJagPeek::read(&token)?;
    request.self_check(&peek)?;

    Ok(IssuedIdJag {
        id_jag: IdJag::new(token.as_str()),
        scope,
        authorization_details,
        expires_in,
        received_at: request.now,
        peek,
        fresh: true,
    })
}

/// Build `request`, send it through `http`, and parse the answer.
///
/// `http` MUST NOT follow redirects: a redirect would replay the subject
/// token and the client's credentials to another origin.
pub async fn exchange_for_id_jag<C: HttpClient>(
    http: &C,
    request: &TokenExchange<'_>,
) -> Result<IssuedIdJag, Error> {
    let response = wire::send(http, request.build().await?).await?;
    parse_token_exchange_response(request, response)
}
