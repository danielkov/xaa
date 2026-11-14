//! Protected Resource Metadata (RFC 9728): how a client that starts from a
//! resource finds its authorization server. See RFC-006 §4.

use std::collections::BTreeMap;
use std::iter::Peekable;
use std::str::Chars;

use serde_json::{Map, Value};
use url::Url;

use super::{
    FetchOptions, IdentifierRules, json_get, parse_document, parse_identifier,
    path_without_terminating_slash, put, require_secure, send, successful_body, take_bool,
    take_string, take_strings,
};
use crate::claims::Issuer;
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};

const WHAT: &str = "protected resource metadata";

const RESOURCE_RULES: IdentifierRules = IdentifierRules {
    what: "resource",
    not_a_url: "resource is not a URL",
    has_userinfo: "resource has a userinfo component",
    has_query: "resource has a query component",
    has_fragment: "resource has a fragment component",
    allow_query: true,
};

/// The members modelled as fields. They never appear in `extra`.
const KNOWN_MEMBERS: [&str; 5] = [
    "resource",
    "authorization_servers",
    "scopes_supported",
    "bearer_methods_supported",
    "dpop_bound_access_tokens_required",
];

/// Protected Resource Metadata (RFC 9728 §2).
///
/// Received documents only come wrapped in a [`ValidatedPrm`]. The type
/// implements `Serialize` for tests and for callers that run a resource
/// server; emitting it is otherwise outside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    /// The resource identifier, kept byte-for-byte.
    pub resource: String,
    /// Issuer identifiers of the authorization servers for this resource.
    /// Each still needs its own metadata fetched and checked (draft §9.5).
    pub authorization_servers: Option<Vec<Issuer>>,
    pub scopes_supported: Option<Vec<String>>,
    pub bearer_methods_supported: Option<Vec<String>>,
    /// RFC 9728 §2, RFC 9449.
    pub dpop_bound_access_tokens_required: Option<bool>,
    /// Every other member, preserved. Real deployments publish members that
    /// are not registered for this document (`docs/interop.md`).
    pub extra: BTreeMap<String, Value>,
}

impl ProtectedResourceMetadata {
    fn from_members(mut members: Map<String, Value>, resource: String) -> Result<Self, Error> {
        let authorization_servers = take_strings(
            &mut members,
            "authorization_servers",
            "authorization_servers is not an array of strings",
        )?
        .map(|servers| servers.into_iter().map(Issuer::new).collect());
        Ok(Self {
            resource,
            authorization_servers,
            scopes_supported: take_strings(
                &mut members,
                "scopes_supported",
                "scopes_supported is not an array of strings",
            )?,
            bearer_methods_supported: take_strings(
                &mut members,
                "bearer_methods_supported",
                "bearer_methods_supported is not an array of strings",
            )?,
            dpop_bound_access_tokens_required: take_bool(
                &mut members,
                "dpop_bound_access_tokens_required",
                "dpop_bound_access_tokens_required is not a boolean",
            )?,
            extra: members.into_iter().collect(),
        })
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
        object.insert("resource".to_owned(), Value::String(self.resource.clone()));
        put(
            &mut object,
            "authorization_servers",
            self.authorization_servers.as_ref().map(|servers| {
                servers
                    .iter()
                    .map(|issuer| issuer.as_str().to_owned())
                    .collect::<Vec<_>>()
            }),
        );
        put(
            &mut object,
            "scopes_supported",
            self.scopes_supported.clone(),
        );
        put(
            &mut object,
            "bearer_methods_supported",
            self.bearer_methods_supported.clone(),
        );
        put(
            &mut object,
            "dpop_bound_access_tokens_required",
            self.dpop_bound_access_tokens_required,
        );
        Value::Object(object)
    }
}

impl serde::Serialize for ProtectedResourceMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

/// What a Protected Resource Metadata fetch starts from. It decides both the
/// URL and the value `resource` must equal (RFC 9728 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrmOrigin<'a> {
    /// Build the well-known URL from the resource identifier
    /// (RFC 9728 §3.1). `resource` must be identical to the identifier.
    ResourceIdentifier(&'a str),
    /// A `resource_metadata` URL from a `WWW-Authenticate` challenge
    /// (RFC 9728 §5.1), plus the URL whose request drew the challenge.
    /// `resource` must be identical to `request_url`.
    Challenge {
        metadata_url: &'a Url,
        request_url: &'a Url,
    },
}

impl PrmOrigin<'_> {
    /// Whether `resource` is the value this origin requires.
    ///
    /// Comparison is on bytes. One allowance, for `Challenge` only: a `Url`
    /// cannot represent an empty path, so `https://rs.example` and
    /// `https://rs.example/` are the same `request_url`, and either spelling
    /// of `resource` matches it. Nothing else is normalized.
    fn matches(&self, resource: &str) -> bool {
        match self {
            Self::ResourceIdentifier(identifier) => resource == *identifier,
            Self::Challenge { request_url, .. } => {
                let requested = request_url.as_str();
                let origin_only = request_url.path() == "/"
                    && request_url.query().is_none()
                    && request_url.fragment().is_none();
                resource == requested
                    || (origin_only && requested.strip_suffix('/') == Some(resource))
            }
        }
    }

    fn expected(&self) -> &str {
        match self {
            Self::ResourceIdentifier(identifier) => identifier,
            Self::Challenge { request_url, .. } => request_url.as_str(),
        }
    }
}

/// Protected Resource Metadata whose `resource` was checked against the
/// origin it was fetched for (draft §9.6, RFC 9728 §3.3).
///
/// This is the only source of a metadata-derived resource identifier for the
/// Token Exchange: [`Self::resource`] is the document's value, unchanged
/// (draft §4.3 MUST), so the check and the grant are bound to the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPrm {
    metadata: ProtectedResourceMetadata,
}

impl ValidatedPrm {
    /// Parse a document fetched for `origin` and validate it:
    ///
    /// - `resource` is present and identical to what `origin` requires
    ///   ([`Error::PrmResourceMismatch`] otherwise; nothing from the document
    ///   is returned).
    /// - `resource` is an `https` URL with no fragment (RFC 9728 §1.2).
    ///
    /// A member that is `null` is treated as absent. A known member of the
    /// wrong JSON type, or a duplicated member name, fails the document.
    pub fn from_json(
        bytes: &[u8],
        origin: &PrmOrigin<'_>,
        opts: &FetchOptions,
    ) -> Result<Self, Error> {
        let mut members = parse_document(bytes)?;
        let resource = take_string(&mut members, "resource", "resource is not a string")?.ok_or(
            Error::InvalidMetadata {
                reason: "resource is missing",
            },
        )?;
        if !origin.matches(&resource) {
            return Err(Error::PrmResourceMismatch {
                expected: origin.expected().to_owned(),
                got: resource,
            });
        }
        parse_identifier(&resource, &RESOURCE_RULES, opts.allow_http_loopback)?;
        let metadata = ProtectedResourceMetadata::from_members(members, resource)?;
        Ok(Self { metadata })
    }

    /// The resource identifier exactly as the document states it. Send this
    /// as the `resource` parameter (draft §4.3).
    pub fn resource(&self) -> &str {
        &self.metadata.resource
    }

    /// The authorization servers the resource names; empty if it names none.
    pub fn authorization_servers(&self) -> &[Issuer] {
        self.metadata
            .authorization_servers
            .as_deref()
            .unwrap_or_default()
    }

    /// The whole document.
    pub fn metadata(&self) -> &ProtectedResourceMetadata {
        &self.metadata
    }

    /// The whole document, by value.
    pub fn into_metadata(self) -> ProtectedResourceMetadata {
        self.metadata
    }
}

/// The metadata URL for `origin`.
///
/// For [`PrmOrigin::ResourceIdentifier`], RFC 9728 §3.1:
/// `/.well-known/oauth-protected-resource` is inserted between the host and
/// the path, after removing one terminating `/` of the path. A query is kept.
///
/// | Resource | Metadata URL |
/// | --- | --- |
/// | `https://rs.example` or `https://rs.example/` | `https://rs.example/.well-known/oauth-protected-resource` |
/// | `https://rs.example/mcp` | `https://rs.example/.well-known/oauth-protected-resource/mcp` |
/// | `https://rs.example/a?b=c` | `https://rs.example/.well-known/oauth-protected-resource/a?b=c` |
///
/// For [`PrmOrigin::Challenge`], the `metadata_url` as given.
///
/// Fails unless the URL to fetch is `https`, and for a resource identifier
/// with userinfo or a fragment.
pub fn protected_resource_metadata_url(
    origin: &PrmOrigin<'_>,
    opts: &FetchOptions,
) -> Result<Url, Error> {
    match origin {
        PrmOrigin::ResourceIdentifier(identifier) => {
            let mut url = parse_identifier(identifier, &RESOURCE_RULES, opts.allow_http_loopback)?;
            let path = path_without_terminating_slash(&url);
            url.set_path(&format!("/.well-known/oauth-protected-resource{path}"));
            Ok(url)
        }
        PrmOrigin::Challenge { metadata_url, .. } => {
            require_secure(metadata_url, "resource_metadata", opts.allow_http_loopback)?;
            Ok((*metadata_url).clone())
        }
    }
}

/// Sans-IO: the `GET` request for the metadata of `origin`.
pub fn protected_resource_metadata_request(
    origin: &PrmOrigin<'_>,
    opts: &FetchOptions,
) -> Result<HttpRequest, Error> {
    protected_resource_metadata_url(origin, opts).map(json_get)
}

/// Sans-IO: validate the response to a
/// [`protected_resource_metadata_request`] for `origin`.
///
/// Requires status 200 and a body within `opts.max_body_bytes`, then applies
/// [`ValidatedPrm::from_json`].
pub fn parse_protected_resource_metadata_response(
    origin: &PrmOrigin<'_>,
    response: &HttpResponse,
    opts: &FetchOptions,
) -> Result<ValidatedPrm, Error> {
    let body = successful_body(
        response,
        WHAT,
        Error::InvalidMetadata {
            reason: "protected resource metadata exceeds the size limit",
        },
        opts,
    )?;
    ValidatedPrm::from_json(body, origin, opts)
}

/// Fetch and validate Protected Resource Metadata (RFC-006 §4).
///
/// `http` MUST NOT follow redirects (see the module documentation).
pub async fn fetch_protected_resource_metadata<C: HttpClient>(
    http: &C,
    origin: PrmOrigin<'_>,
    opts: &FetchOptions,
) -> Result<ValidatedPrm, Error> {
    let request = protected_resource_metadata_request(&origin, opts)?;
    let response = send(http, request).await?;
    parse_protected_resource_metadata_response(&origin, &response, opts)
}

// ---------------------------------------------------------------------------
// WWW-Authenticate (RFC 9728 §5.1)
// ---------------------------------------------------------------------------

/// Extract the `resource_metadata` parameter from a `WWW-Authenticate` header
/// value (RFC 9728 §5.1).
///
/// Returns `Ok(None)` when no challenge in the header carries the parameter,
/// and an error when it is present but is not a URL. With several
/// `WWW-Authenticate` headers, call this for each. Pass the result as
/// [`PrmOrigin::Challenge`] together with the URL that was requested.
pub fn parse_www_authenticate_resource_metadata(header: &str) -> Result<Option<Url>, Error> {
    let mut chars = header.chars().peekable();
    loop {
        skip(&mut chars, |c| c.is_ascii_whitespace() || c == ',');
        if chars.peek().is_none() {
            return Ok(None);
        }
        // A token: a scheme name, a parameter name, or token68 credentials.
        let name = take_while(&mut chars, |c| {
            !(c.is_ascii_whitespace() || matches!(c, ',' | '=' | '"'))
        });
        skip(&mut chars, |c| c == ' ' || c == '\t');
        if chars.next_if_eq(&'=').is_none() {
            // Not a parameter. A stray quoted string is skipped whole so its
            // content is never read as parameters.
            if name.is_empty() && chars.next_if_eq(&'"').is_some() {
                quoted_string(&mut chars);
            }
            continue;
        }
        skip(&mut chars, |c| c == ' ' || c == '\t');
        let value = if chars.next_if_eq(&'"').is_some() {
            quoted_string(&mut chars)
        } else {
            take_while(&mut chars, |c| !(c.is_ascii_whitespace() || c == ','))
        };
        if name.eq_ignore_ascii_case("resource_metadata") {
            return Url::parse(&value)
                .map(Some)
                .map_err(|_source| Error::InvalidMetadata {
                    reason: "resource_metadata is not a URL",
                });
        }
    }
}

fn skip(chars: &mut Peekable<Chars<'_>>, matches: impl Fn(char) -> bool) {
    while chars.next_if(|c| matches(*c)).is_some() {}
}

fn take_while(chars: &mut Peekable<Chars<'_>>, matches: impl Fn(char) -> bool) -> String {
    let mut taken = String::new();
    while let Some(c) = chars.next_if(|c| matches(*c)) {
        taken.push(c);
    }
    taken
}

/// The rest of a quoted-string whose opening quote is consumed
/// (RFC 9110 §5.6.4), with `\` escapes resolved.
fn quoted_string(chars: &mut Peekable<Chars<'_>>) -> String {
    let mut text = String::new();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => text.extend(chars.next()),
            other => text.push(other),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support::{MockHttpClient, json_response};

    const RESOURCE: &str = "https://api.resource.xaa.dev/";
    const PRM_URL: &str = "https://api.resource.xaa.dev/.well-known/oauth-protected-resource";

    fn opts() -> FetchOptions {
        FetchOptions::default()
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    /// The xaa.dev resource server's document, per `docs/interop.md`.
    fn document() -> Value {
        json!({
            "resource": RESOURCE,
            "authorization_servers": ["https://auth.resource.xaa.dev"],
            "scopes_supported": ["todos.read", "todos.write"],
            "bearer_methods_supported": ["header"],
            "authorization_grant_profiles_supported": [
                "urn:ietf:params:oauth:grant-profile:id-jag"
            ]
        })
    }

    fn with_resource(resource: &str) -> Value {
        let mut document = document();
        document
            .as_object_mut()
            .unwrap()
            .insert("resource".to_owned(), json!(resource));
        document
    }

    fn parse(document: &Value, origin: &PrmOrigin<'_>) -> Result<ValidatedPrm, Error> {
        ValidatedPrm::from_json(document.to_string().as_bytes(), origin, &opts())
    }

    // ----- Location ---------------------------------------------------------------

    #[test]
    fn well_known_url_follows_rfc9728() {
        let cases = [
            (
                "https://rs.example",
                "https://rs.example/.well-known/oauth-protected-resource",
            ),
            (
                "https://rs.example/",
                "https://rs.example/.well-known/oauth-protected-resource",
            ),
            (
                "https://rs.example/resource1",
                "https://rs.example/.well-known/oauth-protected-resource/resource1",
            ),
            (
                "https://rs.example/a/b/",
                "https://rs.example/.well-known/oauth-protected-resource/a/b",
            ),
            (
                "https://rs.example:8443/mcp?tenant=1",
                "https://rs.example:8443/.well-known/oauth-protected-resource/mcp?tenant=1",
            ),
        ];
        for (resource, expected) in cases {
            let built =
                protected_resource_metadata_url(&PrmOrigin::ResourceIdentifier(resource), &opts())
                    .unwrap();
            assert_eq!(built.as_str(), expected, "resource {resource}");
        }
    }

    #[test]
    fn challenge_url_is_used_as_given() {
        let metadata_url = url("https://rs.example/custom/prm.json");
        let request_url = url("https://rs.example/mcp");
        let origin = PrmOrigin::Challenge {
            metadata_url: &metadata_url,
            request_url: &request_url,
        };
        let request = protected_resource_metadata_request(&origin, &opts()).unwrap();
        assert_eq!(request.url, metadata_url);
        assert_eq!(request.method, http::Method::GET);
        assert_eq!(request.body, Vec::<u8>::new());
    }

    #[test]
    fn insecure_or_malformed_origins_are_refused() {
        let build = |resource: &str| {
            protected_resource_metadata_url(&PrmOrigin::ResourceIdentifier(resource), &opts())
        };
        assert!(matches!(
            build("http://rs.example/mcp"),
            Err(Error::InsecureEndpoint { what: "resource" })
        ));
        assert!(matches!(
            build("https://rs.example/mcp#part"),
            Err(Error::InvalidMetadata {
                reason: "resource has a fragment component"
            })
        ));
        assert!(matches!(
            build("https://user:pw@rs.example/mcp"),
            Err(Error::InvalidMetadata {
                reason: "resource has a userinfo component"
            })
        ));
        assert!(matches!(
            build("rs.example/mcp"),
            Err(Error::InvalidMetadata {
                reason: "resource is not a URL"
            })
        ));

        let metadata_url = url("http://rs.example/.well-known/oauth-protected-resource");
        let request_url = url("https://rs.example/mcp");
        assert!(matches!(
            protected_resource_metadata_url(
                &PrmOrigin::Challenge {
                    metadata_url: &metadata_url,
                    request_url: &request_url,
                },
                &opts()
            ),
            Err(Error::InsecureEndpoint {
                what: "resource_metadata"
            })
        ));
    }

    #[test]
    fn loopback_http_needs_the_option() {
        let relaxed = FetchOptions {
            allow_http_loopback: true,
            ..FetchOptions::default()
        };
        let origin = PrmOrigin::ResourceIdentifier("http://localhost:3000/mcp");
        assert_eq!(
            protected_resource_metadata_url(&origin, &relaxed)
                .unwrap()
                .as_str(),
            "http://localhost:3000/.well-known/oauth-protected-resource/mcp"
        );
        let document = json!({ "resource": "http://localhost:3000/mcp" });
        let bytes = document.to_string();
        ValidatedPrm::from_json(bytes.as_bytes(), &origin, &relaxed).unwrap();
        assert!(matches!(
            ValidatedPrm::from_json(bytes.as_bytes(), &origin, &opts()),
            Err(Error::InsecureEndpoint { what: "resource" })
        ));
    }

    // ----- Parse and validate -----------------------------------------------------

    #[test]
    fn document_parses_and_keeps_the_resource_byte_for_byte() {
        let prm = parse(&document(), &PrmOrigin::ResourceIdentifier(RESOURCE)).unwrap();
        // Trailing slash and all (docs/interop.md).
        assert_eq!(prm.resource(), "https://api.resource.xaa.dev/");
        assert_eq!(
            prm.authorization_servers(),
            &[Issuer::new("https://auth.resource.xaa.dev")]
        );
        assert_eq!(
            prm.metadata().scopes_supported,
            Some(vec!["todos.read".to_owned(), "todos.write".to_owned()])
        );
        assert_eq!(
            prm.metadata().bearer_methods_supported,
            Some(vec!["header".to_owned()])
        );
        assert_eq!(prm.metadata().dpop_bound_access_tokens_required, None);
    }

    #[test]
    fn unknown_members_are_preserved() {
        let prm = parse(&document(), &PrmOrigin::ResourceIdentifier(RESOURCE)).unwrap();
        assert_eq!(
            prm.metadata()
                .extra
                .get("authorization_grant_profiles_supported"),
            Some(&json!(["urn:ietf:params:oauth:grant-profile:id-jag"]))
        );
        assert_eq!(prm.metadata().extra.len(), 1);
        // And they survive a round trip.
        assert_eq!(prm.metadata().to_value(), document());
        assert_eq!(serde_json::to_value(prm.metadata()).unwrap(), document());
        assert_eq!(prm.clone().into_metadata(), *prm.metadata());
    }

    #[test]
    fn extra_never_overrides_modelled_members_when_emitting() {
        let mut metadata = parse(&document(), &PrmOrigin::ResourceIdentifier(RESOURCE))
            .unwrap()
            .into_metadata();
        metadata
            .extra
            .insert("resource".to_owned(), json!("https://evil.example"));
        assert_eq!(metadata.to_value().get("resource"), Some(&json!(RESOURCE)));
    }

    #[test]
    fn absent_authorization_servers_is_an_empty_slice() {
        let prm = parse(
            &json!({ "resource": RESOURCE, "dpop_bound_access_tokens_required": true }),
            &PrmOrigin::ResourceIdentifier(RESOURCE),
        )
        .unwrap();
        assert_eq!(prm.authorization_servers(), &[] as &[Issuer]);
        assert_eq!(prm.metadata().authorization_servers, None);
        assert_eq!(prm.metadata().dpop_bound_access_tokens_required, Some(true));
    }

    #[test]
    fn resource_mismatch_for_a_resource_identifier_discards_the_document() {
        // Trailing slash, one character, case, another host.
        for claimed in [
            "https://api.resource.xaa.dev",
            "https://api.resource.xaa.dew/",
            "https://API.resource.xaa.dev/",
            "https://api.resource.xaa.dev/v2",
            "https://evil.example/",
        ] {
            match parse(
                &with_resource(claimed),
                &PrmOrigin::ResourceIdentifier(RESOURCE),
            ) {
                Err(Error::PrmResourceMismatch { expected, got }) => {
                    assert_eq!(expected, RESOURCE);
                    assert_eq!(got, claimed);
                }
                other => panic!("resource {claimed}: {other:?}"),
            }
        }
        // The identifier without the slash does not match the document with it.
        assert!(matches!(
            parse(
                &document(),
                &PrmOrigin::ResourceIdentifier("https://api.resource.xaa.dev")
            ),
            Err(Error::PrmResourceMismatch { .. })
        ));
    }

    #[test]
    fn resource_mismatch_for_a_challenge_discards_the_document() {
        let metadata_url = url("https://mcp.xaa.dev/.well-known/oauth-protected-resource/mcp");
        let request_url = url("https://mcp.xaa.dev/mcp");
        let origin = PrmOrigin::Challenge {
            metadata_url: &metadata_url,
            request_url: &request_url,
        };
        let prm = parse(&with_resource("https://mcp.xaa.dev/mcp"), &origin).unwrap();
        assert_eq!(prm.resource(), "https://mcp.xaa.dev/mcp");

        for claimed in [
            "https://mcp.xaa.dev/mcp/",
            "https://mcp.xaa.dev/",
            "https://mcp.xaa.dev",
            "https://mcp.xaa.dev/MCP",
            "https://mcp.xaa.dev/mcp?x=1",
            "https://evil.example/mcp",
        ] {
            match parse(&with_resource(claimed), &origin) {
                Err(Error::PrmResourceMismatch { expected, got }) => {
                    assert_eq!(expected, "https://mcp.xaa.dev/mcp");
                    assert_eq!(got, claimed);
                }
                other => panic!("resource {claimed}: {other:?}"),
            }
        }
    }

    #[test]
    fn challenge_for_an_origin_only_url_accepts_both_spellings_of_the_empty_path() {
        let metadata_url = url(PRM_URL);
        let request_url = url("https://api.resource.xaa.dev");
        let origin = PrmOrigin::Challenge {
            metadata_url: &metadata_url,
            request_url: &request_url,
        };
        // The document's spelling is what is carried forward.
        for spelling in [
            "https://api.resource.xaa.dev/",
            "https://api.resource.xaa.dev",
        ] {
            let prm = parse(&with_resource(spelling), &origin).unwrap();
            assert_eq!(prm.resource(), spelling);
        }
        assert!(matches!(
            parse(&with_resource("https://api.resource.xaa.de"), &origin),
            Err(Error::PrmResourceMismatch { .. })
        ));

        // With a query, only the exact URL matches.
        let request_url = url("https://api.resource.xaa.dev/?a=1");
        let origin = PrmOrigin::Challenge {
            metadata_url: &metadata_url,
            request_url: &request_url,
        };
        parse(&with_resource("https://api.resource.xaa.dev/?a=1"), &origin).unwrap();
        assert!(matches!(
            parse(&with_resource("https://api.resource.xaa.dev/"), &origin),
            Err(Error::PrmResourceMismatch { .. })
        ));
    }

    #[test]
    fn resource_mismatch_wins_over_other_defects() {
        let document = json!({
            "resource": "https://evil.example/",
            "authorization_servers": "not-a-list"
        });
        assert!(matches!(
            parse(&document, &PrmOrigin::ResourceIdentifier(RESOURCE)),
            Err(Error::PrmResourceMismatch { .. })
        ));
    }

    #[test]
    fn missing_or_non_string_resource_fails() {
        let origin = PrmOrigin::ResourceIdentifier(RESOURCE);
        assert!(matches!(
            parse(&json!({ "authorization_servers": [] }), &origin),
            Err(Error::InvalidMetadata {
                reason: "resource is missing"
            })
        ));
        assert!(matches!(
            parse(&json!({ "resource": [RESOURCE] }), &origin),
            Err(Error::InvalidMetadata {
                reason: "resource is not a string"
            })
        ));
    }

    #[test]
    fn wrongly_typed_members_fail() {
        let cases = [
            (
                "authorization_servers",
                json!("https://auth.resource.xaa.dev"),
            ),
            ("authorization_servers", json!([1])),
            ("scopes_supported", json!("todos.read")),
            ("bearer_methods_supported", json!({})),
            ("dpop_bound_access_tokens_required", json!("yes")),
        ];
        for (name, value) in cases {
            let mut document = document();
            document
                .as_object_mut()
                .unwrap()
                .insert(name.to_owned(), value);
            assert!(
                matches!(
                    parse(&document, &PrmOrigin::ResourceIdentifier(RESOURCE)),
                    Err(Error::InvalidMetadata { .. })
                ),
                "member {name}"
            );
        }
    }

    #[test]
    fn duplicate_resource_member_fails() {
        let body =
            br#"{"resource":"https://api.resource.xaa.dev/","resource":"https://evil.example/"}"#;
        assert!(matches!(
            ValidatedPrm::from_json(body, &PrmOrigin::ResourceIdentifier(RESOURCE), &opts()),
            Err(Error::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn response_must_be_200_json_under_the_cap() {
        let origin = PrmOrigin::ResourceIdentifier(RESOURCE);
        for status in [204, 302, 401, 404, 500] {
            assert!(matches!(
                parse_protected_resource_metadata_response(
                    &origin,
                    &json_response(status, &document()),
                    &opts()
                ),
                Err(Error::UnexpectedResponse { what: WHAT, status: got }) if got == status
            ));
        }

        let mut not_json = json_response(200, &document());
        not_json.body = b"<!doctype html>".to_vec();
        assert!(matches!(
            parse_protected_resource_metadata_response(&origin, &not_json, &opts()),
            Err(Error::InvalidMetadata { .. })
        ));

        let mut oversized = document();
        oversized
            .as_object_mut()
            .unwrap()
            .insert("padding".to_owned(), json!("x".repeat(70_000)));
        assert!(matches!(
            parse_protected_resource_metadata_response(
                &origin,
                &json_response(200, &oversized),
                &opts()
            ),
            Err(Error::InvalidMetadata {
                reason: "protected resource metadata exceeds the size limit"
            })
        ));
    }

    // ----- Fetch ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_from_a_resource_identifier() {
        let http = MockHttpClient::new().respond(PRM_URL, json_response(200, &document()));
        let prm = fetch_protected_resource_metadata(
            &http,
            PrmOrigin::ResourceIdentifier(RESOURCE),
            &opts(),
        )
        .await
        .unwrap();
        assert_eq!(prm.resource(), RESOURCE);
        assert_eq!(http.requested_urls(), vec![PRM_URL.to_owned()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_from_a_challenge() {
        let header = r#"Bearer resource_metadata="https://mcp.xaa.dev/.well-known/oauth-protected-resource/mcp""#;
        let metadata_url = parse_www_authenticate_resource_metadata(header)
            .unwrap()
            .unwrap();
        let request_url = url("https://mcp.xaa.dev/mcp");
        let http = MockHttpClient::new().respond(
            metadata_url.as_str(),
            json_response(200, &with_resource("https://mcp.xaa.dev/mcp")),
        );
        let prm = fetch_protected_resource_metadata(
            &http,
            PrmOrigin::Challenge {
                metadata_url: &metadata_url,
                request_url: &request_url,
            },
            &opts(),
        )
        .await
        .unwrap();
        assert_eq!(prm.resource(), "https://mcp.xaa.dev/mcp");
        assert_eq!(http.requested_urls(), vec![metadata_url.to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_rejects_a_mismatched_document_and_failures() {
        let http = MockHttpClient::new().respond(
            PRM_URL,
            json_response(200, &with_resource("https://evil.example/")),
        );
        assert!(matches!(
            fetch_protected_resource_metadata(
                &http,
                PrmOrigin::ResourceIdentifier(RESOURCE),
                &opts()
            )
            .await,
            Err(Error::PrmResourceMismatch { .. })
        ));

        let http = MockHttpClient::new();
        assert!(matches!(
            fetch_protected_resource_metadata(
                &http,
                PrmOrigin::ResourceIdentifier(RESOURCE),
                &opts()
            )
            .await,
            Err(Error::UnexpectedResponse { status: 404, .. })
        ));

        let http = MockHttpClient::new().fail(PRM_URL, "timed out");
        assert!(matches!(
            fetch_protected_resource_metadata(
                &http,
                PrmOrigin::ResourceIdentifier(RESOURCE),
                &opts()
            )
            .await,
            Err(Error::Http(_))
        ));

        let http = MockHttpClient::new();
        assert!(matches!(
            fetch_protected_resource_metadata(
                &http,
                PrmOrigin::ResourceIdentifier("http://api.resource.xaa.dev/"),
                &opts()
            )
            .await,
            Err(Error::InsecureEndpoint { what: "resource" })
        ));
        assert_eq!(http.requests().len(), 0);
    }

    // ----- WWW-Authenticate -------------------------------------------------------

    #[test]
    fn resource_metadata_is_extracted_from_a_challenge() {
        let expected = url("https://rs.example/.well-known/oauth-protected-resource");
        let headers = [
            r#"Bearer resource_metadata="https://rs.example/.well-known/oauth-protected-resource""#,
            r#"Bearer realm="api", error="invalid_token", resource_metadata="https://rs.example/.well-known/oauth-protected-resource", scope="a b""#,
            r#"bearer Resource_Metadata = "https://rs.example/.well-known/oauth-protected-resource""#,
            "Bearer resource_metadata=https://rs.example/.well-known/oauth-protected-resource",
            r#"Basic realm="x", DPoP algs="ES256", resource_metadata="https://rs.example/.well-known/oauth-protected-resource""#,
            r#"Bearer realm="a \"quoted\" realm",resource_metadata="https://rs.example/.well-known/oauth-protected-resource""#,
            r#"Negotiate YWJj==, Bearer resource_metadata="https://rs.example/.well-known/oauth-protected-resource""#,
        ];
        for header in headers {
            assert_eq!(
                parse_www_authenticate_resource_metadata(header).unwrap(),
                Some(expected.clone()),
                "header {header}"
            );
        }
    }

    #[test]
    fn resource_metadata_absent_is_none() {
        for header in [
            "",
            "Bearer",
            r#"Bearer realm="api""#,
            // Inside another parameter's quoted value: not a parameter.
            r#"Bearer realm="resource_metadata=\"https://evil.example/\"""#,
            r#"Bearer error_description="see resource_metadata=https://evil.example/ for more""#,
            // A longer name is a different parameter.
            r#"Bearer x_resource_metadata="https://evil.example/""#,
            r#"Bearer realm="unterminated"#,
            r#""stray", =, ,,"#,
        ] {
            assert_eq!(
                parse_www_authenticate_resource_metadata(header).unwrap(),
                None,
                "header {header}"
            );
        }
    }

    #[test]
    fn resource_metadata_that_is_not_a_url_is_an_error() {
        for header in [
            r#"Bearer resource_metadata="/relative/path""#,
            r#"Bearer resource_metadata="""#,
            "Bearer resource_metadata=",
        ] {
            assert!(matches!(
                parse_www_authenticate_resource_metadata(header),
                Err(Error::InvalidMetadata {
                    reason: "resource_metadata is not a URL"
                })
            ));
        }
    }
}
