//! Authorization Server Metadata (RFC 8414): parse and validate, fetch, and
//! emit for the IdP and the Resource AS. See RFC-006 §2–§3.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use url::Url;

use super::{
    FetchOptions, GRANT_PROFILE_ID_JAG, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_JWT_DPOP,
    GRANT_TYPE_TOKEN_EXCHANGE, IdentifierRules, TOKEN_TYPE_ID_JAG, json_get, parse_document,
    parse_identifier, path_without_terminating_slash, push_unique, put, require_secure, send,
    successful_body, take_bool, take_string, take_strings, take_url,
};
use crate::claims::Issuer;
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::jose::SignatureAlgorithm;

const WHAT: &str = "authorization server metadata";

const ISSUER_RULES: IdentifierRules = IdentifierRules {
    what: "issuer",
    not_a_url: "issuer is not a URL",
    has_userinfo: "issuer has a userinfo component",
    has_query: "issuer has a query component",
    has_fragment: "issuer has a fragment component",
    allow_query: false,
};

/// The members modelled as fields. They never appear in `extra`.
const KNOWN_MEMBERS: [&str; 11] = [
    "issuer",
    "token_endpoint",
    "jwks_uri",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "dpop_signing_alg_values_supported",
    "tls_client_certificate_bound_access_tokens",
    "identity_chaining_requested_token_types_supported",
    "id_jag_signing_alg_values_supported",
    "authorization_grant_profiles_supported",
];

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// Whether a server's metadata advertises a capability.
///
/// Not a `bool`: identity-chaining §3 warns that "lack of a value does not
/// necessarily mean that the token type is unsupported", and draft §7.2 only
/// says SHOULD advertise. `NotAdvertised` means "unknown", not "no".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Support {
    Advertised,
    NotAdvertised,
}

impl Support {
    /// `true` for [`Support::Advertised`].
    pub fn is_advertised(self) -> bool {
        matches!(self, Self::Advertised)
    }

    fn of(list: Option<&Vec<String>>, value: &str) -> Self {
        if list.is_some_and(|values| values.iter().any(|entry| entry == value)) {
            Self::Advertised
        } else {
            Self::NotAdvertised
        }
    }
}

/// Authorization Server Metadata (RFC 8414 §2), with the XAA parameters
/// (draft §7, §11.3).
///
/// The only way to get one from received bytes is
/// [`AuthorizationServerMetadata::from_json`], which runs the draft §9.5
/// issuer check. Servers build one with [`IdpMetadataBuilder`] or
/// [`ResourceAsMetadataBuilder`] and publish it with [`Self::to_value`] or
/// `serde`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationServerMetadata {
    pub issuer: Issuer,
    pub token_endpoint: Option<Url>,
    pub jwks_uri: Option<Url>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9449 §5.1.
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 8705 §3.3.
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// identity-chaining §3, draft §7.1.
    pub identity_chaining_requested_token_types_supported: Option<Vec<String>>,
    /// Draft §7.1.
    pub id_jag_signing_alg_values_supported: Option<Vec<String>>,
    /// Draft §7.2.
    pub authorization_grant_profiles_supported: Option<Vec<String>>,
    /// Every other member, preserved.
    pub extra: BTreeMap<String, Value>,
}

impl AuthorizationServerMetadata {
    /// Parse a metadata document fetched for `expected_issuer` and validate
    /// it (RFC-006 §3):
    ///
    /// - `issuer` is byte-identical to `expected_issuer` (draft §9.5 MUST,
    ///   RFC 8414 §3.3). No normalization: a trailing slash or a case
    ///   difference is a mismatch. On a mismatch nothing from the document
    ///   is returned.
    /// - `issuer` is an `https` URL with no query or fragment (RFC 8414 §2).
    /// - `token_endpoint` and `jwks_uri`, when present, are `https`.
    ///
    /// A member that is `null` is treated as absent. A known member of the
    /// wrong JSON type, or a duplicated member name, fails the document.
    pub fn from_json(
        bytes: &[u8],
        expected_issuer: &Issuer,
        opts: &FetchOptions,
    ) -> Result<Self, Error> {
        let mut members = parse_document(bytes)?;

        // The identity check comes first: a document for another issuer is
        // discarded before anything else in it is looked at.
        let issuer = take_string(&mut members, "issuer", "issuer is not a string")?.ok_or(
            Error::InvalidMetadata {
                reason: "issuer is missing",
            },
        )?;
        if issuer != expected_issuer.as_str() {
            return Err(Error::MetadataIssuerMismatch {
                expected: expected_issuer.as_str().to_owned(),
                got: issuer,
            });
        }
        parse_identifier(&issuer, &ISSUER_RULES, opts.allow_http_loopback)?;

        let token_endpoint = take_url(
            &mut members,
            "token_endpoint",
            "token_endpoint is not a URL",
        )?;
        let jwks_uri = take_url(&mut members, "jwks_uri", "jwks_uri is not a URL")?;
        let metadata = Self {
            issuer: Issuer::new(issuer),
            token_endpoint,
            jwks_uri,
            grant_types_supported: take_strings(
                &mut members,
                "grant_types_supported",
                "grant_types_supported is not an array of strings",
            )?,
            token_endpoint_auth_methods_supported: take_strings(
                &mut members,
                "token_endpoint_auth_methods_supported",
                "token_endpoint_auth_methods_supported is not an array of strings",
            )?,
            token_endpoint_auth_signing_alg_values_supported: take_strings(
                &mut members,
                "token_endpoint_auth_signing_alg_values_supported",
                "token_endpoint_auth_signing_alg_values_supported is not an array of strings",
            )?,
            dpop_signing_alg_values_supported: take_strings(
                &mut members,
                "dpop_signing_alg_values_supported",
                "dpop_signing_alg_values_supported is not an array of strings",
            )?,
            tls_client_certificate_bound_access_tokens: take_bool(
                &mut members,
                "tls_client_certificate_bound_access_tokens",
                "tls_client_certificate_bound_access_tokens is not a boolean",
            )?,
            identity_chaining_requested_token_types_supported: take_strings(
                &mut members,
                "identity_chaining_requested_token_types_supported",
                "identity_chaining_requested_token_types_supported is not an array of strings",
            )?,
            id_jag_signing_alg_values_supported: take_strings(
                &mut members,
                "id_jag_signing_alg_values_supported",
                "id_jag_signing_alg_values_supported is not an array of strings",
            )?,
            authorization_grant_profiles_supported: take_strings(
                &mut members,
                "authorization_grant_profiles_supported",
                "authorization_grant_profiles_supported is not an array of strings",
            )?,
            extra: members.into_iter().collect(),
        };
        metadata.check_endpoints(opts.allow_http_loopback)?;
        Ok(metadata)
    }

    /// Whether the server advertises issuing ID-JAGs:
    /// `identity_chaining_requested_token_types_supported` contains
    /// `urn:ietf:params:oauth:token-type:id-jag` (draft §7.1).
    pub fn issues_id_jag(&self) -> Support {
        Support::of(
            self.identity_chaining_requested_token_types_supported
                .as_ref(),
            TOKEN_TYPE_ID_JAG,
        )
    }

    /// Whether the server advertises accepting ID-JAGs:
    /// `authorization_grant_profiles_supported` contains
    /// `urn:ietf:params:oauth:grant-profile:id-jag` (draft §7.2). This says
    /// nothing about which issuers or clients it accepts.
    pub fn accepts_id_jag_profile(&self) -> Support {
        Support::of(
            self.authorization_grant_profiles_supported.as_ref(),
            GRANT_PROFILE_ID_JAG,
        )
    }

    /// Whether the server advertises the JWT-DPoP grant:
    /// `grant_types_supported` contains
    /// `urn:ietf:params:oauth:grant-type:jwt-dpop` (jwt-dpop-grant §5.2).
    pub fn accepts_jwt_dpop(&self) -> Support {
        Support::of(self.grant_types_supported.as_ref(), GRANT_TYPE_JWT_DPOP)
    }

    /// The document as a JSON object. Members in `extra` never override the
    /// modelled members.
    pub fn to_value(&self) -> Value {
        let mut object: Map<String, Value> = self
            .extra
            .iter()
            .filter(|(name, _)| !KNOWN_MEMBERS.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        object.insert(
            "issuer".to_owned(),
            Value::String(self.issuer.as_str().to_owned()),
        );
        put(
            &mut object,
            "token_endpoint",
            self.token_endpoint.as_ref().map(Url::as_str),
        );
        put(
            &mut object,
            "jwks_uri",
            self.jwks_uri.as_ref().map(Url::as_str),
        );
        put(
            &mut object,
            "grant_types_supported",
            self.grant_types_supported.clone(),
        );
        put(
            &mut object,
            "token_endpoint_auth_methods_supported",
            self.token_endpoint_auth_methods_supported.clone(),
        );
        put(
            &mut object,
            "token_endpoint_auth_signing_alg_values_supported",
            self.token_endpoint_auth_signing_alg_values_supported
                .clone(),
        );
        put(
            &mut object,
            "dpop_signing_alg_values_supported",
            self.dpop_signing_alg_values_supported.clone(),
        );
        put(
            &mut object,
            "tls_client_certificate_bound_access_tokens",
            self.tls_client_certificate_bound_access_tokens,
        );
        put(
            &mut object,
            "identity_chaining_requested_token_types_supported",
            self.identity_chaining_requested_token_types_supported
                .clone(),
        );
        put(
            &mut object,
            "id_jag_signing_alg_values_supported",
            self.id_jag_signing_alg_values_supported.clone(),
        );
        put(
            &mut object,
            "authorization_grant_profiles_supported",
            self.authorization_grant_profiles_supported.clone(),
        );
        Value::Object(object)
    }

    /// `token_endpoint` and `jwks_uri` use `https` (RFC 8414 §2).
    fn check_endpoints(&self, allow_http_loopback: bool) -> Result<(), Error> {
        if let Some(token_endpoint) = &self.token_endpoint {
            require_secure(token_endpoint, "token_endpoint", allow_http_loopback)?;
        }
        if let Some(jwks_uri) = &self.jwks_uri {
            require_secure(jwks_uri, "jwks_uri", allow_http_loopback)?;
        }
        Ok(())
    }

    /// The rules a document must meet before a builder hands it out
    /// (RFC-006 §2.1).
    pub(crate) fn check_publishable(&self, allow_http_loopback: bool) -> Result<(), Error> {
        parse_identifier(self.issuer.as_str(), &ISSUER_RULES, allow_http_loopback)?;
        self.check_endpoints(allow_http_loopback)?;

        let lists = [
            &self.grant_types_supported,
            &self.token_endpoint_auth_methods_supported,
            &self.token_endpoint_auth_signing_alg_values_supported,
            &self.dpop_signing_alg_values_supported,
            &self.identity_chaining_requested_token_types_supported,
            &self.id_jag_signing_alg_values_supported,
            &self.authorization_grant_profiles_supported,
        ];
        if lists
            .iter()
            .any(|list| list.as_ref().is_some_and(Vec::is_empty))
        {
            // RFC 8414 §2: "Claims with zero elements MUST be omitted".
            return Err(Error::InvalidConfiguration {
                reason: "a metadata list is empty; omit it instead",
            });
        }

        // Draft §7.1: if present, the list MUST include RS256.
        if let Some(algs) = &self.id_jag_signing_alg_values_supported
            && !algs
                .iter()
                .any(|alg| alg == SignatureAlgorithm::Rs256.as_str())
        {
            return Err(Error::InvalidConfiguration {
                reason: "id_jag_signing_alg_values_supported must include RS256",
            });
        }

        // Draft §7.2: the profile MUST be advertised together with jwt-bearer.
        if self.accepts_id_jag_profile().is_advertised()
            && !Support::of(self.grant_types_supported.as_ref(), GRANT_TYPE_JWT_BEARER)
                .is_advertised()
        {
            return Err(Error::InvalidConfiguration {
                reason: "the id-jag grant profile requires the jwt-bearer grant type",
            });
        }

        if self
            .extra
            .keys()
            .any(|name| KNOWN_MEMBERS.contains(&name.as_str()))
        {
            return Err(Error::InvalidConfiguration {
                reason: "an extra metadata member shadows a modelled member",
            });
        }
        Ok(())
    }
}

impl serde::Serialize for AuthorizationServerMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

// ---------------------------------------------------------------------------
// Fetch (RFC-006 §3)
// ---------------------------------------------------------------------------

/// Where an authorization server's metadata document is looked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataLocation {
    /// RFC 8414 §3.1: `/.well-known/oauth-authorization-server` inserted
    /// between the host and the issuer's path.
    Rfc8414,
    /// OIDC Discovery §4: `/.well-known/openid-configuration` appended to the
    /// issuer (RFC 8414 §5, draft §7.1 MAY).
    OidcDiscovery,
}

/// The metadata URL for `issuer` at `location`.
///
/// One terminating `/` of the issuer's path is removed first, as both
/// specifications require:
///
/// | Issuer | RFC 8414 | OIDC Discovery |
/// | --- | --- | --- |
/// | `https://as.example` | `https://as.example/.well-known/oauth-authorization-server` | `https://as.example/.well-known/openid-configuration` |
/// | `https://as.example/tenant1` | `https://as.example/.well-known/oauth-authorization-server/tenant1` | `https://as.example/tenant1/.well-known/openid-configuration` |
///
/// Fails if the issuer is not an `https` URL, or has userinfo, a query, or a
/// fragment (RFC 8414 §2).
pub fn authorization_server_metadata_url(
    issuer: &Issuer,
    location: MetadataLocation,
    opts: &FetchOptions,
) -> Result<Url, Error> {
    let mut url = parse_identifier(issuer.as_str(), &ISSUER_RULES, opts.allow_http_loopback)?;
    let path = path_without_terminating_slash(&url);
    let well_known = match location {
        MetadataLocation::Rfc8414 => format!("/.well-known/oauth-authorization-server{path}"),
        MetadataLocation::OidcDiscovery => format!("{path}/.well-known/openid-configuration"),
    };
    url.set_path(&well_known);
    Ok(url)
}

/// Sans-IO: the `GET` request for `issuer`'s metadata at `location`.
pub fn authorization_server_metadata_request(
    issuer: &Issuer,
    location: MetadataLocation,
    opts: &FetchOptions,
) -> Result<HttpRequest, Error> {
    authorization_server_metadata_url(issuer, location, opts).map(json_get)
}

/// Sans-IO: validate the response to an
/// [`authorization_server_metadata_request`] for `issuer`.
///
/// Requires status 200 and a body within `opts.max_body_bytes`, then applies
/// [`AuthorizationServerMetadata::from_json`].
pub fn parse_authorization_server_metadata_response(
    issuer: &Issuer,
    response: &HttpResponse,
    opts: &FetchOptions,
) -> Result<AuthorizationServerMetadata, Error> {
    let body = successful_body(
        response,
        WHAT,
        Error::InvalidMetadata {
            reason: "authorization server metadata exceeds the size limit",
        },
        opts,
    )?;
    AuthorizationServerMetadata::from_json(body, issuer, opts)
}

/// Fetch and validate `issuer`'s metadata (RFC-006 §3).
///
/// Tries [`MetadataLocation::Rfc8414`] first. If that answers with any status
/// other than 200 and `opts.oidc_discovery_fallback` is set, tries
/// [`MetadataLocation::OidcDiscovery`]. Both documents come from the issuer's
/// own origin and both get the same issuer check, so the fallback does not
/// widen trust.
///
/// There is no fallback after a 200: a document that is present but invalid
/// (wrong `issuer`, not JSON, insecure endpoint) is an error. A transport
/// error is returned as [`Error::Http`] without trying the next location.
///
/// When both locations answer non-200, the error carries the first status,
/// unless that was 404, in which case it carries the second.
///
/// `http` MUST NOT follow redirects (see the module documentation).
pub async fn fetch_authorization_server_metadata<C: HttpClient>(
    http: &C,
    issuer: &Issuer,
    opts: &FetchOptions,
) -> Result<AuthorizationServerMetadata, Error> {
    let request = authorization_server_metadata_request(issuer, MetadataLocation::Rfc8414, opts)?;
    let first = send(http, request).await?;
    if first.status == 200 || !opts.oidc_discovery_fallback {
        return parse_authorization_server_metadata_response(issuer, &first, opts);
    }

    let request =
        authorization_server_metadata_request(issuer, MetadataLocation::OidcDiscovery, opts)?;
    let second = send(http, request).await?;
    if second.status != 200 && first.status != 404 {
        return Err(Error::UnexpectedResponse {
            what: WHAT,
            status: first.status,
        });
    }
    parse_authorization_server_metadata_response(issuer, &second, opts)
}

// ---------------------------------------------------------------------------
// Emit (RFC-006 §2.1)
// ---------------------------------------------------------------------------

fn alg_names(algs: &[SignatureAlgorithm]) -> Vec<String> {
    let mut names = Vec::with_capacity(algs.len());
    for alg in algs {
        push_unique(&mut names, alg.as_str());
    }
    names
}

/// Builds the IdP Authorization Server's metadata (draft §7.1).
///
/// Always emits `identity_chaining_requested_token_types_supported`
/// containing `urn:ietf:params:oauth:token-type:id-jag`,
/// `grant_types_supported` containing the token-exchange grant, and
/// `jwks_uri`. The same document serves at the RFC 8414 location and as
/// OIDC Discovery; add OIDC-only members with [`Self::extra`].
#[derive(Debug, Clone)]
pub struct IdpMetadataBuilder {
    metadata: AuthorizationServerMetadata,
    allow_http_loopback: bool,
}

impl IdpMetadataBuilder {
    /// Start from the IdP's issuer, token endpoint, and JWK Set URL.
    pub fn new(issuer: Issuer, token_endpoint: Url, jwks_uri: Url) -> Self {
        Self {
            metadata: AuthorizationServerMetadata {
                issuer,
                token_endpoint: Some(token_endpoint),
                jwks_uri: Some(jwks_uri),
                grant_types_supported: Some(vec![GRANT_TYPE_TOKEN_EXCHANGE.to_owned()]),
                token_endpoint_auth_methods_supported: None,
                token_endpoint_auth_signing_alg_values_supported: None,
                dpop_signing_alg_values_supported: None,
                tls_client_certificate_bound_access_tokens: None,
                identity_chaining_requested_token_types_supported: Some(vec![
                    TOKEN_TYPE_ID_JAG.to_owned(),
                ]),
                id_jag_signing_alg_values_supported: None,
                authorization_grant_profiles_supported: None,
                extra: BTreeMap::new(),
            },
            allow_http_loopback: false,
        }
    }

    /// Advertise another requested token type, such as
    /// `urn:ietf:params:oauth:token-type:refresh_token` for the draft §4.5
    /// exchange.
    pub fn requested_token_type(mut self, token_type: impl Into<String>) -> Self {
        push_unique(
            self.metadata
                .identity_chaining_requested_token_types_supported
                .get_or_insert_with(Vec::new),
            token_type,
        );
        self
    }

    /// Advertise another grant type.
    pub fn grant_type(mut self, grant_type: impl Into<String>) -> Self {
        push_unique(
            self.metadata
                .grant_types_supported
                .get_or_insert_with(Vec::new),
            grant_type,
        );
        self
    }

    /// Emit `id_jag_signing_alg_values_supported`. The list must include
    /// `RS256` (draft §7.1 MUST); [`Self::build`] refuses it otherwise.
    pub fn id_jag_signing_algs(mut self, algs: &[SignatureAlgorithm]) -> Self {
        self.metadata.id_jag_signing_alg_values_supported = Some(alg_names(algs));
        self
    }

    /// Emit `token_endpoint_auth_methods_supported`.
    pub fn token_endpoint_auth_methods(mut self, methods: Vec<String>) -> Self {
        self.metadata.token_endpoint_auth_methods_supported = Some(methods);
        self
    }

    /// Emit `token_endpoint_auth_signing_alg_values_supported`.
    pub fn token_endpoint_auth_signing_algs(mut self, algs: &[SignatureAlgorithm]) -> Self {
        self.metadata
            .token_endpoint_auth_signing_alg_values_supported = Some(alg_names(algs));
        self
    }

    /// Emit `dpop_signing_alg_values_supported` (RFC 9449 §5.1).
    pub fn dpop_signing_algs(mut self, algs: &[SignatureAlgorithm]) -> Self {
        self.metadata.dpop_signing_alg_values_supported = Some(alg_names(algs));
        self
    }

    /// Add a member this type does not model. A name that is modelled is
    /// refused by [`Self::build`].
    pub fn extra(mut self, name: impl Into<String>, value: Value) -> Self {
        self.metadata.extra.insert(name.into(), value);
        self
    }

    /// Accept `http` loopback URLs. For tests and examples only.
    pub fn allow_http_loopback(mut self, allow: bool) -> Self {
        self.allow_http_loopback = allow;
        self
    }

    /// Check the invariants and return the document.
    ///
    /// Fails if the issuer or an endpoint is not `https`, if a list is
    /// empty, if `id_jag_signing_alg_values_supported` is set without
    /// `RS256`, or if an extra member shadows a modelled one.
    pub fn build(self) -> Result<AuthorizationServerMetadata, Error> {
        self.metadata.check_publishable(self.allow_http_loopback)?;
        Ok(self.metadata)
    }
}

/// Builds the Resource Authorization Server's metadata (draft §7.2).
///
/// Always emits `authorization_grant_profiles_supported` containing
/// `urn:ietf:params:oauth:grant-profile:id-jag` together with
/// `grant_types_supported` containing the jwt-bearer grant.
///
/// There is deliberately no input for trusted issuers, tenants, or clients:
/// draft §9.7 says the metadata MUST NOT disclose issuer allow-lists, and
/// §7.2 says the profile "does not indicate that any particular issuer ...
/// will be accepted". Do not put them in [`Self::extra`] either.
#[derive(Debug, Clone)]
pub struct ResourceAsMetadataBuilder {
    metadata: AuthorizationServerMetadata,
    allow_http_loopback: bool,
}

impl ResourceAsMetadataBuilder {
    /// Start from the Resource AS's issuer and token endpoint.
    pub fn new(issuer: Issuer, token_endpoint: Url) -> Self {
        Self {
            metadata: AuthorizationServerMetadata {
                issuer,
                token_endpoint: Some(token_endpoint),
                jwks_uri: None,
                grant_types_supported: Some(vec![GRANT_TYPE_JWT_BEARER.to_owned()]),
                token_endpoint_auth_methods_supported: None,
                token_endpoint_auth_signing_alg_values_supported: None,
                dpop_signing_alg_values_supported: None,
                tls_client_certificate_bound_access_tokens: None,
                identity_chaining_requested_token_types_supported: None,
                id_jag_signing_alg_values_supported: None,
                authorization_grant_profiles_supported: Some(vec![GRANT_PROFILE_ID_JAG.to_owned()]),
                extra: BTreeMap::new(),
            },
            allow_http_loopback: false,
        }
    }

    /// Advertise the JWT-DPoP grant (jwt-dpop-grant §5.2 SHOULD). Set this
    /// exactly when DPoP-bound ID-JAGs are accepted.
    pub fn dpop_grant(mut self, enabled: bool) -> Self {
        let grant_types = self
            .metadata
            .grant_types_supported
            .get_or_insert_with(Vec::new);
        if enabled {
            push_unique(grant_types, GRANT_TYPE_JWT_DPOP);
        } else {
            grant_types.retain(|grant_type| grant_type != GRANT_TYPE_JWT_DPOP);
        }
        self
    }

    /// Advertise another grant type.
    pub fn grant_type(mut self, grant_type: impl Into<String>) -> Self {
        push_unique(
            self.metadata
                .grant_types_supported
                .get_or_insert_with(Vec::new),
            grant_type,
        );
        self
    }

    /// Emit `jwks_uri`: the keys this server signs access tokens with.
    pub fn jwks_uri(mut self, jwks_uri: Url) -> Self {
        self.metadata.jwks_uri = Some(jwks_uri);
        self
    }

    /// Emit `token_endpoint_auth_methods_supported`.
    pub fn token_endpoint_auth_methods(mut self, methods: Vec<String>) -> Self {
        self.metadata.token_endpoint_auth_methods_supported = Some(methods);
        self
    }

    /// Emit `token_endpoint_auth_signing_alg_values_supported`.
    pub fn token_endpoint_auth_signing_algs(mut self, algs: &[SignatureAlgorithm]) -> Self {
        self.metadata
            .token_endpoint_auth_signing_alg_values_supported = Some(alg_names(algs));
        self
    }

    /// Emit `dpop_signing_alg_values_supported` (RFC 9449 §5.1).
    pub fn dpop_signing_algs(mut self, algs: &[SignatureAlgorithm]) -> Self {
        self.metadata.dpop_signing_alg_values_supported = Some(alg_names(algs));
        self
    }

    /// Emit `tls_client_certificate_bound_access_tokens` (RFC 8705 §3.3).
    pub fn tls_client_certificate_bound_access_tokens(mut self, supported: bool) -> Self {
        self.metadata.tls_client_certificate_bound_access_tokens = Some(supported);
        self
    }

    /// Add a member this type does not model. A name that is modelled is
    /// refused by [`Self::build`], so the profile and grant types cannot be
    /// overridden this way.
    pub fn extra(mut self, name: impl Into<String>, value: Value) -> Self {
        self.metadata.extra.insert(name.into(), value);
        self
    }

    /// Accept `http` loopback URLs. For tests and examples only.
    pub fn allow_http_loopback(mut self, allow: bool) -> Self {
        self.allow_http_loopback = allow;
        self
    }

    /// Check the invariants and return the document.
    ///
    /// Fails if the issuer or an endpoint is not `https`, if a list is
    /// empty, or if an extra member shadows a modelled one. The profile is
    /// only ever emitted together with jwt-bearer (draft §7.2 MUST).
    pub fn build(self) -> Result<AuthorizationServerMetadata, Error> {
        self.metadata.check_publishable(self.allow_http_loopback)?;
        Ok(self.metadata)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support::{MockHttpClient, json_response};

    const IDP: &str = "https://idp.xaa.dev";
    const RFC8414_URL: &str = "https://idp.xaa.dev/.well-known/oauth-authorization-server";
    const OIDC_URL: &str = "https://idp.xaa.dev/.well-known/openid-configuration";

    fn opts() -> FetchOptions {
        FetchOptions::default()
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    /// The xaa.dev IdP's discovery document, per `docs/interop.md`.
    fn idp_document() -> Value {
        json!({
            "issuer": IDP,
            "authorization_endpoint": "https://idp.xaa.dev/authorize",
            "token_endpoint": "https://idp.xaa.dev/token",
            "jwks_uri": "https://idp.xaa.dev/jwks",
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "identity_chaining_requested_token_types_supported": [
                "urn:ietf:params:oauth:token-type:id-jag",
                "urn:ietf:params:oauth:token-type:refresh_token"
            ],
            "subject_types_supported": ["public"]
        })
    }

    /// The xaa.dev Resource AS's document, per `docs/interop.md`.
    fn resource_as_document() -> Value {
        json!({
            "issuer": "https://auth.resource.xaa.dev",
            "token_endpoint": "https://auth.resource.xaa.dev/token",
            "jwks_uri": "https://auth.resource.xaa.dev/jwks",
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "refresh_token"
            ],
            "authorization_grant_profiles_supported": [
                "urn:ietf:params:oauth:grant-profile:id-jag"
            ]
        })
    }

    fn parse(document: &Value, issuer: &str) -> Result<AuthorizationServerMetadata, Error> {
        AuthorizationServerMetadata::from_json(
            document.to_string().as_bytes(),
            &Issuer::new(issuer),
            &opts(),
        )
    }

    fn with(mut document: Value, name: &str, value: Value) -> Value {
        document
            .as_object_mut()
            .unwrap()
            .insert(name.to_owned(), value);
        document
    }

    // ----- Well-known locations ---------------------------------------------------

    #[test]
    fn rfc8414_url_inserts_the_well_known_segment_before_the_path() {
        let cases = [
            (
                "https://as.example",
                "https://as.example/.well-known/oauth-authorization-server",
            ),
            (
                "https://as.example/",
                "https://as.example/.well-known/oauth-authorization-server",
            ),
            (
                "https://as.example/tenant1",
                "https://as.example/.well-known/oauth-authorization-server/tenant1",
            ),
            (
                "https://as.example/tenant1/",
                "https://as.example/.well-known/oauth-authorization-server/tenant1",
            ),
            (
                "https://as.example:8443/a/b",
                "https://as.example:8443/.well-known/oauth-authorization-server/a/b",
            ),
        ];
        for (issuer, expected) in cases {
            let built = authorization_server_metadata_url(
                &Issuer::new(issuer),
                MetadataLocation::Rfc8414,
                &opts(),
            )
            .unwrap();
            assert_eq!(built.as_str(), expected, "issuer {issuer}");
        }
    }

    #[test]
    fn oidc_url_appends_the_well_known_segment_after_the_path() {
        let cases = [
            (
                "https://as.example",
                "https://as.example/.well-known/openid-configuration",
            ),
            (
                "https://as.example/",
                "https://as.example/.well-known/openid-configuration",
            ),
            (
                "https://as.example/tenant1",
                "https://as.example/tenant1/.well-known/openid-configuration",
            ),
            (
                "https://as.example/tenant1/",
                "https://as.example/tenant1/.well-known/openid-configuration",
            ),
        ];
        for (issuer, expected) in cases {
            let built = authorization_server_metadata_url(
                &Issuer::new(issuer),
                MetadataLocation::OidcDiscovery,
                &opts(),
            )
            .unwrap();
            assert_eq!(built.as_str(), expected, "issuer {issuer}");
        }
    }

    #[test]
    fn request_is_a_bare_get_for_json() {
        let request = authorization_server_metadata_request(
            &Issuer::new(IDP),
            MetadataLocation::Rfc8414,
            &opts(),
        )
        .unwrap();
        assert_eq!(request.method, http::Method::GET);
        assert_eq!(request.url.as_str(), RFC8414_URL);
        assert_eq!(request.body, Vec::<u8>::new());
        assert_eq!(
            request.headers,
            vec![("accept".to_owned(), "application/json".to_owned())]
        );
    }

    #[test]
    fn issuer_shape_rules_apply_before_any_request() {
        let build = |issuer: &str| {
            authorization_server_metadata_url(
                &Issuer::new(issuer),
                MetadataLocation::Rfc8414,
                &opts(),
            )
        };
        assert!(matches!(
            build("http://as.example"),
            Err(Error::InsecureEndpoint { what: "issuer" })
        ));
        assert!(matches!(
            build("http://localhost:8080"),
            Err(Error::InsecureEndpoint { what: "issuer" })
        ));
        assert!(matches!(
            build("https://as.example?tenant=1"),
            Err(Error::InvalidMetadata {
                reason: "issuer has a query component"
            })
        ));
        assert!(matches!(
            build("https://as.example/#frag"),
            Err(Error::InvalidMetadata {
                reason: "issuer has a fragment component"
            })
        ));
        assert!(matches!(
            build("https://user:secret@as.example"),
            Err(Error::InvalidMetadata {
                reason: "issuer has a userinfo component"
            })
        ));
        assert!(matches!(
            build("not a url"),
            Err(Error::InvalidMetadata {
                reason: "issuer is not a URL"
            })
        ));
    }

    #[test]
    fn loopback_http_issuer_needs_the_option() {
        let relaxed = FetchOptions {
            allow_http_loopback: true,
            ..FetchOptions::default()
        };
        let built = authorization_server_metadata_url(
            &Issuer::new("http://127.0.0.1:8080/idp"),
            MetadataLocation::Rfc8414,
            &relaxed,
        )
        .unwrap();
        assert_eq!(
            built.as_str(),
            "http://127.0.0.1:8080/.well-known/oauth-authorization-server/idp"
        );
        assert!(matches!(
            authorization_server_metadata_url(
                &Issuer::new("http://as.example"),
                MetadataLocation::Rfc8414,
                &relaxed,
            ),
            Err(Error::InsecureEndpoint { what: "issuer" })
        ));
    }

    // ----- Parse and derived views ------------------------------------------------

    #[test]
    fn idp_document_parses_with_the_expected_views() {
        let metadata = parse(&idp_document(), IDP).unwrap();
        assert_eq!(metadata.issuer, Issuer::new(IDP));
        assert_eq!(
            metadata.token_endpoint,
            Some(url("https://idp.xaa.dev/token"))
        );
        assert_eq!(metadata.jwks_uri, Some(url("https://idp.xaa.dev/jwks")));
        assert_eq!(metadata.id_jag_signing_alg_values_supported, None);
        assert_eq!(metadata.issues_id_jag(), Support::Advertised);
        assert_eq!(metadata.accepts_id_jag_profile(), Support::NotAdvertised);
        assert_eq!(metadata.accepts_jwt_dpop(), Support::NotAdvertised);
        assert_eq!(
            metadata.extra.get("subject_types_supported"),
            Some(&json!(["public"]))
        );
        assert_eq!(
            metadata.extra.get("authorization_endpoint"),
            Some(&json!("https://idp.xaa.dev/authorize"))
        );
        assert!(!metadata.extra.contains_key("issuer"));
    }

    #[test]
    fn resource_as_document_parses_with_the_expected_views() {
        let metadata = parse(&resource_as_document(), "https://auth.resource.xaa.dev").unwrap();
        assert_eq!(metadata.accepts_id_jag_profile(), Support::Advertised);
        assert_eq!(metadata.issues_id_jag(), Support::NotAdvertised);
        assert_eq!(metadata.accepts_jwt_dpop(), Support::NotAdvertised);

        let with_dpop = with(
            resource_as_document(),
            "grant_types_supported",
            json!([GRANT_TYPE_JWT_BEARER, GRANT_TYPE_JWT_DPOP]),
        );
        let metadata = parse(&with_dpop, "https://auth.resource.xaa.dev").unwrap();
        assert_eq!(metadata.accepts_jwt_dpop(), Support::Advertised);
        assert!(metadata.accepts_jwt_dpop().is_advertised());
    }

    #[test]
    fn draft_appendix_resource_as_metadata_parses() {
        // In the shape of draft Appendix A.4.2.1: an MCP authorization
        // server's metadata.
        let document = json!({
            "issuer": "https://auth.chat.example/",
            "authorization_endpoint": "https://auth.chat.example/oauth2/authorize",
            "token_endpoint": "https://auth.chat.example/oauth2/token",
            "jwks_uri": "https://auth.chat.example/oauth2/keys",
            "registration_endpoint": "https://auth.chat.example/oauth2/register",
            "scopes_supported": ["chat.read", "chat.history"],
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:jwt-bearer"
            ],
            "authorization_grant_profiles_supported": [
                "urn:ietf:params:oauth:grant-profile:id-jag"
            ]
        });
        let metadata = parse(&document, "https://auth.chat.example/").unwrap();
        assert_eq!(metadata.accepts_id_jag_profile(), Support::Advertised);
        assert_eq!(metadata.extra.len(), 4);
    }

    #[test]
    fn round_trip_preserves_every_member() {
        let document = with(
            with(
                idp_document(),
                "tls_client_certificate_bound_access_tokens",
                json!(true),
            ),
            "dpop_signing_alg_values_supported",
            json!(["ES256"]),
        );
        let metadata = parse(&document, IDP).unwrap();
        assert_eq!(metadata.to_value(), document);
        assert_eq!(serde_json::to_value(&metadata).unwrap(), document);
    }

    #[test]
    fn extra_never_overrides_modelled_members_when_emitting() {
        let mut metadata = parse(&idp_document(), IDP).unwrap();
        metadata
            .extra
            .insert("issuer".to_owned(), json!("https://evil.example"));
        assert_eq!(metadata.to_value().get("issuer"), Some(&json!(IDP)));
    }

    // ----- Validation table (RFC-006 §3) ------------------------------------------

    #[test]
    fn issuer_mismatch_discards_the_document() {
        // One character, a trailing slash, case, and a different host.
        for claimed in [
            "https://idp.xaa.dew",
            "https://idp.xaa.dev/",
            "https://IDP.xaa.dev",
            "HTTPS://idp.xaa.dev",
            "https://idp.xaa.dev:443",
            "https://evil.example",
        ] {
            let document = with(idp_document(), "issuer", json!(claimed));
            match parse(&document, IDP) {
                Err(Error::MetadataIssuerMismatch { expected, got }) => {
                    assert_eq!(expected, IDP);
                    assert_eq!(got, claimed);
                }
                other => panic!("issuer {claimed}: {other:?}"),
            }
        }
    }

    #[test]
    fn issuer_with_trailing_slash_matches_only_itself() {
        let document = with(idp_document(), "issuer", json!("https://idp.xaa.dev/"));
        parse(&document, "https://idp.xaa.dev/").unwrap();
        assert!(matches!(
            parse(&idp_document(), "https://idp.xaa.dev/"),
            Err(Error::MetadataIssuerMismatch { .. })
        ));
    }

    #[test]
    fn issuer_mismatch_wins_over_other_defects() {
        // An attacker's document is rejected for what it is, whatever else
        // is wrong with it.
        let document = json!({
            "issuer": "https://evil.example",
            "token_endpoint": "http://evil.example/token",
            "grant_types_supported": "not-a-list"
        });
        assert!(matches!(
            parse(&document, IDP),
            Err(Error::MetadataIssuerMismatch { .. })
        ));
    }

    #[test]
    fn missing_or_non_string_issuer_fails() {
        let mut document = idp_document();
        document.as_object_mut().unwrap().remove("issuer");
        assert!(matches!(
            parse(&document, IDP),
            Err(Error::InvalidMetadata {
                reason: "issuer is missing"
            })
        ));
        for value in [json!(null), json!(7), json!([IDP])] {
            let document = with(idp_document(), "issuer", value);
            assert!(matches!(
                parse(&document, IDP),
                Err(Error::InvalidMetadata { .. })
            ));
        }
    }

    #[test]
    fn http_issuer_fails_even_when_it_matches() {
        let document = with(idp_document(), "issuer", json!("http://idp.xaa.dev"));
        assert!(matches!(
            parse(&document, "http://idp.xaa.dev"),
            Err(Error::InsecureEndpoint { what: "issuer" })
        ));
    }

    #[test]
    fn issuer_with_query_or_fragment_fails_even_when_it_matches() {
        for issuer in ["https://idp.xaa.dev?x=1", "https://idp.xaa.dev#x"] {
            let document = with(idp_document(), "issuer", json!(issuer));
            assert!(matches!(
                parse(&document, issuer),
                Err(Error::InvalidMetadata { .. })
            ));
        }
    }

    #[test]
    fn http_token_endpoint_fails() {
        let document = with(
            idp_document(),
            "token_endpoint",
            json!("http://idp.xaa.dev/token"),
        );
        assert!(matches!(
            parse(&document, IDP),
            Err(Error::InsecureEndpoint {
                what: "token_endpoint"
            })
        ));
    }

    #[test]
    fn http_jwks_uri_fails() {
        let document = with(idp_document(), "jwks_uri", json!("http://idp.xaa.dev/jwks"));
        assert!(matches!(
            parse(&document, IDP),
            Err(Error::InsecureEndpoint { what: "jwks_uri" })
        ));
    }

    #[test]
    fn loopback_option_relaxes_issuer_and_endpoints_together() {
        let document = json!({
            "issuer": "http://localhost:8080",
            "token_endpoint": "http://localhost:8080/token",
            "jwks_uri": "http://localhost:8080/jwks"
        });
        let issuer = Issuer::new("http://localhost:8080");
        let bytes = document.to_string();
        let relaxed = FetchOptions {
            allow_http_loopback: true,
            ..FetchOptions::default()
        };
        AuthorizationServerMetadata::from_json(bytes.as_bytes(), &issuer, &relaxed).unwrap();
        assert!(matches!(
            AuthorizationServerMetadata::from_json(bytes.as_bytes(), &issuer, &opts()),
            Err(Error::InsecureEndpoint { what: "issuer" })
        ));

        // The relaxation does not reach a non-loopback endpoint.
        let remote = with(document, "token_endpoint", json!("http://as.example/token"));
        assert!(matches!(
            AuthorizationServerMetadata::from_json(
                remote.to_string().as_bytes(),
                &issuer,
                &relaxed
            ),
            Err(Error::InsecureEndpoint {
                what: "token_endpoint"
            })
        ));
    }

    #[test]
    fn wrongly_typed_members_fail() {
        let cases = [
            ("token_endpoint", json!(1)),
            ("token_endpoint", json!("not a url")),
            ("jwks_uri", json!(["https://idp.xaa.dev/jwks"])),
            ("grant_types_supported", json!("authorization_code")),
            ("grant_types_supported", json!(["a", 1])),
            ("token_endpoint_auth_methods_supported", json!({})),
            (
                "token_endpoint_auth_signing_alg_values_supported",
                json!(true),
            ),
            ("dpop_signing_alg_values_supported", json!("ES256")),
            ("tls_client_certificate_bound_access_tokens", json!("true")),
            (
                "identity_chaining_requested_token_types_supported",
                json!("urn:ietf:params:oauth:token-type:id-jag"),
            ),
            ("id_jag_signing_alg_values_supported", json!([1])),
            ("authorization_grant_profiles_supported", json!(1)),
        ];
        for (name, value) in cases {
            let document = with(idp_document(), name, value);
            assert!(
                matches!(parse(&document, IDP), Err(Error::InvalidMetadata { .. })),
                "member {name}"
            );
        }
    }

    #[test]
    fn duplicate_issuer_member_fails() {
        let body = br#"{"issuer":"https://idp.xaa.dev","issuer":"https://evil.example"}"#;
        assert!(matches!(
            AuthorizationServerMetadata::from_json(body, &Issuer::new(IDP), &opts()),
            Err(Error::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn response_must_be_200() {
        for status in [201, 204, 301, 302, 400, 404, 500] {
            let response = json_response(status, &idp_document());
            assert!(matches!(
                parse_authorization_server_metadata_response(
                    &Issuer::new(IDP),
                    &response,
                    &opts()
                ),
                Err(Error::UnexpectedResponse {
                    what: WHAT,
                    status: got,
                }) if got == status
            ));
        }
    }

    #[test]
    fn response_must_be_json() {
        let mut response = json_response(200, &idp_document());
        response.body = b"<html>not found</html>".to_vec();
        assert!(matches!(
            parse_authorization_server_metadata_response(&Issuer::new(IDP), &response, &opts()),
            Err(Error::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn response_must_be_under_the_size_cap() {
        let padded = with(idp_document(), "padding", json!("x".repeat(70_000)));
        let response = json_response(200, &padded);
        assert!(matches!(
            parse_authorization_server_metadata_response(&Issuer::new(IDP), &response, &opts()),
            Err(Error::InvalidMetadata {
                reason: "authorization server metadata exceeds the size limit"
            })
        ));

        // The cap is the caller's to move.
        let roomy = FetchOptions {
            max_body_bytes: 100_000,
            ..FetchOptions::default()
        };
        parse_authorization_server_metadata_response(&Issuer::new(IDP), &response, &roomy).unwrap();

        // A body of exactly the cap is accepted.
        let exact = FetchOptions {
            max_body_bytes: response.body.len(),
            ..FetchOptions::default()
        };
        parse_authorization_server_metadata_response(&Issuer::new(IDP), &response, &exact).unwrap();
    }

    // ----- Fetch ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_uses_the_rfc8414_location_first() {
        let http = MockHttpClient::new().respond(RFC8414_URL, json_response(200, &idp_document()));
        let metadata = fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts())
            .await
            .unwrap();
        assert_eq!(metadata.issuer.as_str(), IDP);
        assert_eq!(http.requested_urls(), vec![RFC8414_URL.to_owned()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_falls_back_to_oidc_discovery_on_404() {
        // docs/interop.md: the xaa.dev IdP serves only openid-configuration.
        let http = MockHttpClient::new().respond(OIDC_URL, json_response(200, &idp_document()));
        let metadata = fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts())
            .await
            .unwrap();
        assert_eq!(metadata.issues_id_jag(), Support::Advertised);
        assert_eq!(
            http.requested_urls(),
            vec![RFC8414_URL.to_owned(), OIDC_URL.to_owned()]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_falls_back_on_any_non_200_status() {
        for status in [301, 400, 403, 405, 500, 503] {
            let http = MockHttpClient::new()
                .respond(RFC8414_URL, json_response(status, &json!({})))
                .respond(OIDC_URL, json_response(200, &idp_document()));
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts())
                .await
                .unwrap();
            assert_eq!(http.requests().len(), 2, "status {status}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_with_issuer_path_uses_both_path_rules() {
        let issuer = Issuer::new("https://as.example/tenant1");
        let document = json!({ "issuer": "https://as.example/tenant1" });
        let http = MockHttpClient::new().respond(
            "https://as.example/tenant1/.well-known/openid-configuration",
            json_response(200, &document),
        );
        fetch_authorization_server_metadata(&http, &issuer, &opts())
            .await
            .unwrap();
        assert_eq!(
            http.requested_urls(),
            vec![
                "https://as.example/.well-known/oauth-authorization-server/tenant1".to_owned(),
                "https://as.example/tenant1/.well-known/openid-configuration".to_owned(),
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_does_not_fall_back_when_disabled() {
        let http = MockHttpClient::new().respond(OIDC_URL, json_response(200, &idp_document()));
        let strict = FetchOptions {
            oidc_discovery_fallback: false,
            ..FetchOptions::default()
        };
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &strict).await,
            Err(Error::UnexpectedResponse { status: 404, .. })
        ));
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_does_not_fall_back_past_an_invalid_200() {
        // The RFC 8414 document claims another issuer. The valid OIDC
        // document must not rescue it.
        let wrong = with(idp_document(), "issuer", json!("https://idp.xaa.dev/"));
        let http = MockHttpClient::new()
            .respond(RFC8414_URL, json_response(200, &wrong))
            .respond(OIDC_URL, json_response(200, &idp_document()));
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts()).await,
            Err(Error::MetadataIssuerMismatch { .. })
        ));
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_checks_the_issuer_of_the_fallback_document() {
        let wrong = with(idp_document(), "issuer", json!("https://evil.example"));
        let http = MockHttpClient::new().respond(OIDC_URL, json_response(200, &wrong));
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts()).await,
            Err(Error::MetadataIssuerMismatch { .. })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_reports_the_more_telling_status_when_both_fail() {
        // Neither exists: the second 404.
        let http = MockHttpClient::new();
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts()).await,
            Err(Error::UnexpectedResponse { status: 404, .. })
        ));
        assert_eq!(http.requests().len(), 2);

        // First is 404, second is a server error: the server error.
        let http = MockHttpClient::new().respond(OIDC_URL, json_response(503, &json!({})));
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts()).await,
            Err(Error::UnexpectedResponse { status: 503, .. })
        ));

        // First is a server error, second does not exist: the server error.
        let http = MockHttpClient::new().respond(RFC8414_URL, json_response(500, &json!({})));
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts()).await,
            Err(Error::UnexpectedResponse { status: 500, .. })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_surfaces_transport_errors_without_falling_back() {
        let http = MockHttpClient::new()
            .fail(RFC8414_URL, "connection reset")
            .respond(OIDC_URL, json_response(200, &idp_document()));
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new(IDP), &opts()).await,
            Err(Error::Http(_))
        ));
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_sends_nothing_for_an_insecure_issuer() {
        let http = MockHttpClient::new();
        assert!(matches!(
            fetch_authorization_server_metadata(&http, &Issuer::new("http://idp.xaa.dev"), &opts())
                .await,
            Err(Error::InsecureEndpoint { what: "issuer" })
        ));
        assert_eq!(http.requests().len(), 0);
    }

    // ----- Builders (RFC-006 §2.1) ------------------------------------------------

    fn idp_builder() -> IdpMetadataBuilder {
        IdpMetadataBuilder::new(
            Issuer::new("https://idp.example"),
            url("https://idp.example/token"),
            url("https://idp.example/jwks"),
        )
    }

    fn resource_as_builder() -> ResourceAsMetadataBuilder {
        ResourceAsMetadataBuilder::new(
            Issuer::new("https://as.example"),
            url("https://as.example/token"),
        )
    }

    #[test]
    fn idp_builder_always_emits_the_required_members() {
        let metadata = idp_builder().build().unwrap();
        assert_eq!(
            metadata.to_value(),
            json!({
                "issuer": "https://idp.example",
                "token_endpoint": "https://idp.example/token",
                "jwks_uri": "https://idp.example/jwks",
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
                "identity_chaining_requested_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:id-jag"
                ]
            })
        );
        assert_eq!(metadata.issues_id_jag(), Support::Advertised);
    }

    #[test]
    fn idp_builder_emits_optional_members() {
        let metadata = idp_builder()
            .requested_token_type("urn:ietf:params:oauth:token-type:refresh_token")
            .requested_token_type(TOKEN_TYPE_ID_JAG)
            .grant_type("authorization_code")
            .grant_type(GRANT_TYPE_TOKEN_EXCHANGE)
            .id_jag_signing_algs(&[SignatureAlgorithm::Rs256, SignatureAlgorithm::Es256])
            .token_endpoint_auth_methods(vec!["private_key_jwt".to_owned()])
            .token_endpoint_auth_signing_algs(&[SignatureAlgorithm::Es256])
            .dpop_signing_algs(&[SignatureAlgorithm::Es256, SignatureAlgorithm::Es256])
            .extra("subject_types_supported", json!(["public"]))
            .build()
            .unwrap();
        assert_eq!(
            metadata.identity_chaining_requested_token_types_supported,
            Some(vec![
                TOKEN_TYPE_ID_JAG.to_owned(),
                "urn:ietf:params:oauth:token-type:refresh_token".to_owned()
            ])
        );
        assert_eq!(
            metadata.grant_types_supported,
            Some(vec![
                GRANT_TYPE_TOKEN_EXCHANGE.to_owned(),
                "authorization_code".to_owned()
            ])
        );
        assert_eq!(
            metadata.id_jag_signing_alg_values_supported,
            Some(vec!["RS256".to_owned(), "ES256".to_owned()])
        );
        assert_eq!(
            metadata.dpop_signing_alg_values_supported,
            Some(vec!["ES256".to_owned()])
        );
        assert_eq!(
            metadata.to_value().get("subject_types_supported"),
            Some(&json!(["public"]))
        );
    }

    #[test]
    fn idp_builder_refuses_id_jag_algs_without_rs256() {
        assert!(matches!(
            idp_builder()
                .id_jag_signing_algs(&[SignatureAlgorithm::Es256])
                .build(),
            Err(Error::InvalidConfiguration {
                reason: "id_jag_signing_alg_values_supported must include RS256"
            })
        ));
    }

    #[test]
    fn idp_builder_refuses_an_empty_list() {
        assert!(matches!(
            idp_builder().id_jag_signing_algs(&[]).build(),
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            idp_builder()
                .token_endpoint_auth_methods(Vec::new())
                .build(),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn builders_refuse_insecure_urls() {
        assert!(matches!(
            IdpMetadataBuilder::new(
                Issuer::new("http://idp.example"),
                url("https://idp.example/token"),
                url("https://idp.example/jwks"),
            )
            .build(),
            Err(Error::InsecureEndpoint { what: "issuer" })
        ));
        assert!(matches!(
            IdpMetadataBuilder::new(
                Issuer::new("https://idp.example"),
                url("http://idp.example/token"),
                url("https://idp.example/jwks"),
            )
            .build(),
            Err(Error::InsecureEndpoint {
                what: "token_endpoint"
            })
        ));
        assert!(matches!(
            IdpMetadataBuilder::new(
                Issuer::new("https://idp.example"),
                url("https://idp.example/token"),
                url("http://idp.example/jwks"),
            )
            .build(),
            Err(Error::InsecureEndpoint { what: "jwks_uri" })
        ));
        assert!(matches!(
            ResourceAsMetadataBuilder::new(
                Issuer::new("https://as.example?x=1"),
                url("https://as.example/token"),
            )
            .build(),
            Err(Error::InvalidMetadata { .. })
        ));
        assert!(matches!(
            resource_as_builder()
                .jwks_uri(url("http://as.example/jwks"))
                .build(),
            Err(Error::InsecureEndpoint { what: "jwks_uri" })
        ));
    }

    #[test]
    fn builders_accept_loopback_http_only_when_asked() {
        let builder = IdpMetadataBuilder::new(
            Issuer::new("http://localhost:8080"),
            url("http://localhost:8080/token"),
            url("http://localhost:8080/jwks"),
        );
        assert!(matches!(
            builder.clone().build(),
            Err(Error::InsecureEndpoint { .. })
        ));
        builder.allow_http_loopback(true).build().unwrap();

        let builder = ResourceAsMetadataBuilder::new(
            Issuer::new("http://127.0.0.1:9000"),
            url("http://127.0.0.1:9000/token"),
        );
        assert!(matches!(
            builder.clone().build(),
            Err(Error::InsecureEndpoint { .. })
        ));
        builder.allow_http_loopback(true).build().unwrap();
    }

    #[test]
    fn builders_refuse_extra_members_that_shadow_modelled_ones() {
        for name in KNOWN_MEMBERS {
            assert!(
                matches!(
                    idp_builder().extra(name, json!([])).build(),
                    Err(Error::InvalidConfiguration { .. })
                ),
                "member {name}"
            );
            assert!(
                matches!(
                    resource_as_builder().extra(name, json!([])).build(),
                    Err(Error::InvalidConfiguration { .. })
                ),
                "member {name}"
            );
        }
    }

    #[test]
    fn resource_as_builder_always_emits_profile_with_jwt_bearer() {
        let metadata = resource_as_builder().build().unwrap();
        assert_eq!(
            metadata.to_value(),
            json!({
                "issuer": "https://as.example",
                "token_endpoint": "https://as.example/token",
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
                "authorization_grant_profiles_supported": [
                    "urn:ietf:params:oauth:grant-profile:id-jag"
                ]
            })
        );
        assert_eq!(metadata.accepts_id_jag_profile(), Support::Advertised);
        assert_eq!(metadata.accepts_jwt_dpop(), Support::NotAdvertised);
    }

    #[test]
    fn resource_as_builder_adds_jwt_dpop_when_enabled() {
        let metadata = resource_as_builder()
            .dpop_grant(true)
            .dpop_grant(true)
            .grant_type("refresh_token")
            .jwks_uri(url("https://as.example/jwks"))
            .token_endpoint_auth_methods(vec!["private_key_jwt".to_owned()])
            .token_endpoint_auth_signing_algs(&[SignatureAlgorithm::Rs256])
            .dpop_signing_algs(&[SignatureAlgorithm::Es256])
            .tls_client_certificate_bound_access_tokens(true)
            .build()
            .unwrap();
        assert_eq!(
            metadata.grant_types_supported,
            Some(vec![
                GRANT_TYPE_JWT_BEARER.to_owned(),
                GRANT_TYPE_JWT_DPOP.to_owned(),
                "refresh_token".to_owned()
            ])
        );
        assert_eq!(metadata.accepts_jwt_dpop(), Support::Advertised);
        assert_eq!(
            metadata.tls_client_certificate_bound_access_tokens,
            Some(true)
        );

        let metadata = resource_as_builder()
            .dpop_grant(true)
            .dpop_grant(false)
            .build()
            .unwrap();
        assert_eq!(metadata.accepts_jwt_dpop(), Support::NotAdvertised);
    }

    #[test]
    fn profile_without_jwt_bearer_is_not_publishable() {
        // The builder cannot produce this, so break a built document by hand.
        let mut metadata = resource_as_builder().build().unwrap();
        metadata.grant_types_supported = Some(vec!["refresh_token".to_owned()]);
        assert!(matches!(
            metadata.check_publishable(false),
            Err(Error::InvalidConfiguration {
                reason: "the id-jag grant profile requires the jwt-bearer grant type"
            })
        ));
        metadata.grant_types_supported = None;
        assert!(matches!(
            metadata.check_publishable(false),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn built_documents_pass_the_consumer_checks() {
        let idp = idp_builder().build().unwrap();
        let parsed = parse(&idp.to_value(), "https://idp.example").unwrap();
        assert_eq!(parsed, idp);

        let resource_as = resource_as_builder().dpop_grant(true).build().unwrap();
        let parsed = parse(&resource_as.to_value(), "https://as.example").unwrap();
        assert_eq!(parsed, resource_as);
    }
}
