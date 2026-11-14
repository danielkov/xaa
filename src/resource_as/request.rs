//! Access token request parsing (draft §4.4). See RFC-004 §2.

use crate::claims::Scope;
use crate::client_auth::{ClientCredentials, CredentialsError};
use crate::dpop::{AssertionGrantType, DPOP_HEADER};
use crate::form::{Form, Repeated, header_values};
use crate::mtls::certificate_thumbprint;
use crate::oauth_error::OAuthErrorCode;
use crate::secret::IdJag;

use super::error::{RejectReason, TokenError};

/// A parsed jwt-bearer / jwt-dpop token request. Nothing in it has been
/// verified: the assertion is opaque until
/// [`ResourceAs::validate`](super::ResourceAs::validate) accepts it.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub(super) grant_type: AssertionGrantType,
    pub(super) assertion: IdJag,
    pub(super) scope: Option<Scope>,
    pub(super) credentials: ClientCredentials,
    /// The `DPoP` header, if the request carried one.
    pub(super) dpop_headers: Vec<(String, String)>,
    pub(super) certificate_x5t_s256: Option<String>,
}

impl TokenRequest {
    /// Parse a token endpoint request.
    ///
    /// `tls_client_cert` is the client certificate in DER, already validated
    /// by the TLS layer (RFC 8705 §2).
    ///
    /// - `grant_type` other than jwt-bearer or jwt-dpop is
    ///   `unsupported_grant_type`, so other grants can be routed elsewhere
    ///   first.
    /// - A missing or repeated `assertion`, or any other repeated parameter,
    ///   is `invalid_request` (RFC 6749 §3.2).
    /// - A malformed `scope` is `invalid_scope`.
    /// - More than one `DPoP` header is `invalid_dpop_proof` (RFC 9449 §4.3).
    /// - More than one client authentication method is `invalid_request`
    ///   (RFC 6749 §2.3).
    pub fn parse(
        form_body: &[u8],
        headers: &[(String, String)],
        tls_client_cert: Option<&[u8]>,
    ) -> Result<Self, TokenError> {
        let form = Form::parse(form_body);
        let one = |name: &'static str| {
            form.one(name).map_err(|Repeated(name)| {
                TokenError::invalid_request(RejectReason::RepeatedParameter { name })
            })
        };

        let grant_type = one("grant_type")?
            .ok_or_else(|| TokenError::invalid_request(RejectReason::MissingGrantType))?;
        let grant_type = AssertionGrantType::parse(grant_type).ok_or_else(|| {
            TokenError::rejected(
                OAuthErrorCode::UnsupportedGrantType,
                RejectReason::UnsupportedGrantType,
            )
        })?;
        let assertion = one("assertion")?
            .ok_or_else(|| TokenError::invalid_request(RejectReason::MissingAssertion))?;
        let scope = one("scope")?
            .map(Scope::parse)
            .transpose()
            .map_err(|source| {
                TokenError::rejected(OAuthErrorCode::InvalidScope, RejectReason::MalformedScope)
                    .with_source(source)
            })?;

        let dpop_headers: Vec<(String, String)> = header_values(headers, DPOP_HEADER)
            .into_iter()
            .map(|value| (DPOP_HEADER.to_owned(), value.to_owned()))
            .collect();
        if dpop_headers.len() > 1 {
            return Err(TokenError::rejected(
                OAuthErrorCode::InvalidDpopProof,
                RejectReason::MultipleDpopProofs,
            ));
        }

        let credentials = ClientCredentials::extract(&form, headers, tls_client_cert.is_some())
            .map_err(|error| {
                TokenError::invalid_request(match error {
                    CredentialsError::MultipleMethods => RejectReason::MultipleClientAuthMethods,
                    CredentialsError::Repeated => RejectReason::RepeatedParameter {
                        name: "client credentials",
                    },
                    CredentialsError::Malformed => RejectReason::MalformedClientCredentials,
                })
            })?;

        // Not DER means the caller's TLS glue is wrong, not the client.
        let certificate_x5t_s256 = tls_client_cert
            .map(certificate_thumbprint)
            .transpose()
            .map_err(|source| {
                TokenError::server_error(RejectReason::InvalidClientCertificate).with_source(source)
            })?;

        Ok(Self {
            grant_type,
            assertion: IdJag::new(assertion),
            scope,
            credentials,
            dpop_headers,
            certificate_x5t_s256,
        })
    }

    /// The grant type the ID-JAG is presented under.
    pub fn grant_type(&self) -> AssertionGrantType {
        self.grant_type
    }

    /// The client credentials as presented: extracted, not verified. The
    /// caller verifies them and reports a
    /// [`ClientIdentity`](crate::client_auth::ClientIdentity) (RFC-004 §3).
    pub fn client_credentials(&self) -> &ClientCredentials {
        &self.credentials
    }

    /// The request's `scope` parameter: the client's downscoping request.
    pub fn requested_scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    /// Whether the request carries a DPoP proof. It is validated by
    /// [`ResourceAs::validate`](super::ResourceAs::validate).
    pub fn has_dpop_proof(&self) -> bool {
        !self.dpop_headers.is_empty()
    }

    /// The `x5t#S256` thumbprint of the presented TLS client certificate.
    pub fn certificate_thumbprint(&self) -> Option<&str> {
        self.certificate_x5t_s256.as_deref()
    }
}
