//! Claim value types.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::Error;

/// The SAML transient NameID format, which is not a stable identifier and is
/// never allowed in a `saml-nameid` subject identifier (draft §3.2.2).
pub(crate) const NAMEID_FORMAT_TRANSIENT: &str =
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

/// 9999-12-31T23:59:59Z. NumericDate values beyond it are rejected.
const MAX_NUMERIC_DATE_SECS: u64 = 253_402_300_799;

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

/// An issuer identifier (RFC 8414 §2): the `iss` of a token and the identity
/// of an authorization server.
///
/// Compared byte-for-byte. `https://idp.example` and `https://idp.example/`
/// are different issuers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Issuer(String);

impl Issuer {
    /// Wrap an issuer identifier exactly as given.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self(issuer.into())
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Issuer {
    fn from(issuer: &str) -> Self {
        Self::new(issuer)
    }
}

impl From<String> for Issuer {
    fn from(issuer: String) -> Self {
        Self::new(issuer)
    }
}

// ---------------------------------------------------------------------------
// Audience
// ---------------------------------------------------------------------------

/// An `aud` claim: a string or an array of strings (RFC 7519 §4.1.3). The
/// type preserves which form arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Many(Vec<String>),
}

impl Audience {
    /// A single-valued audience.
    pub fn single(audience: impl Into<String>) -> Self {
        Self::Single(audience.into())
    }

    /// The audience if there is exactly one: a string, or a one-element
    /// array. The ID-JAG and client-assertion rules both require a sole
    /// audience value (draft §4.4.1, RFC 10070).
    pub fn sole(&self) -> Option<&str> {
        match self {
            Self::Single(audience) => Some(audience),
            Self::Many(audiences) => match audiences.as_slice() {
                [only] => Some(only),
                _ => None,
            },
        }
    }

    /// Every audience value.
    pub fn values(&self) -> &[String] {
        match self {
            Self::Single(audience) => std::slice::from_ref(audience),
            Self::Many(audiences) => audiences,
        }
    }
}

// ---------------------------------------------------------------------------
// NumericDate
// ---------------------------------------------------------------------------

/// A JWT NumericDate (RFC 7519 §2): seconds since the Unix epoch.
///
/// Any non-negative JSON number is accepted, including non-integer values
/// such as `1311280970.5`. The value is held as a [`Duration`], so every
/// comparison is exact. Emitted values are always integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NumericDate(Duration);

impl NumericDate {
    /// The NumericDate for `time`, truncated to whole seconds. Fails for a
    /// time before the epoch or after year 9999.
    pub fn from_system_time(time: SystemTime) -> Result<Self, Error> {
        let since_epoch = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_before_epoch| Error::TimeOutOfRange)?;
        Self::from_secs(since_epoch.as_secs())
    }

    /// A whole number of seconds since the epoch.
    pub fn from_secs(secs: u64) -> Result<Self, Error> {
        if secs > MAX_NUMERIC_DATE_SECS {
            return Err(Error::TimeOutOfRange);
        }
        Ok(Self(Duration::from_secs(secs)))
    }

    /// Whole seconds since the epoch.
    pub fn as_secs(self) -> u64 {
        self.0.as_secs()
    }

    /// The instant this value names.
    pub fn to_system_time(self) -> Result<SystemTime, Error> {
        SystemTime::UNIX_EPOCH
            .checked_add(self.0)
            .ok_or(Error::TimeOutOfRange)
    }

    /// Parse a JSON number. `None` if it is negative, not finite, or beyond
    /// year 9999.
    pub(crate) fn from_json(value: &Value) -> Option<Self> {
        let number = value.as_number()?;
        if let Some(secs) = number.as_u64() {
            return Self::from_secs(secs).ok();
        }
        // A fraction or an exponent. Negative and non-finite values fail the
        // conversion; the range check then runs on the exact Duration.
        let duration = Duration::try_from_secs_f64(number.as_f64()?).ok()?;
        (duration.as_secs() <= MAX_NUMERIC_DATE_SECS).then_some(Self(duration))
    }
}

impl Serialize for NumericDate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0.as_secs())
    }
}

impl<'de> Deserialize<'de> for NumericDate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_json(&value)
            .ok_or_else(|| serde::de::Error::custom("not a non-negative NumericDate"))
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// An OAuth scope: one or more space-separated scope tokens (RFC 6749 §3.3).
///
/// The original string and token order are preserved. Scope values mean what
/// the Resource AS defines; this type does not interpret them (draft §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scope(String);

impl Scope {
    /// Parse a scope string. Each token must match the `scope-token` grammar,
    /// and tokens are separated by exactly one space.
    pub fn parse(scope: impl Into<String>) -> Result<Self, Error> {
        let scope = scope.into();
        let valid = !scope.is_empty()
            && scope.split(' ').all(|token| {
                !token.is_empty()
                    && token
                        .bytes()
                        .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
            });
        if valid {
            Ok(Self(scope))
        } else {
            Err(Error::InvalidClaim {
                name: "scope",
                reason: "not a space-separated list of RFC 6749 scope tokens",
            })
        }
    }

    /// The scope string as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The scope tokens, in order.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.0.split(' ')
    }

    /// Whether `token` is one of the scope tokens.
    pub fn contains(&self, token: &str) -> bool {
        self.tokens().any(|candidate| candidate == token)
    }

    /// Whether every token of `self` is also in `other`.
    pub fn is_subset_of(&self, other: &Scope) -> bool {
        self.tokens().all(|token| other.contains(token))
    }

    /// The tokens of `self` that are also in `other`, in `self`'s order, or
    /// `None` if there are none (an empty scope is not representable).
    ///
    /// This is the usual shape of scope policy: what a grant carries,
    /// narrowed to what the client asked for or to what a server supports.
    pub fn intersection(&self, other: &Scope) -> Option<Scope> {
        let mut common: Vec<&str> = Vec::new();
        for token in self.tokens() {
            if other.contains(token) && !common.contains(&token) {
                common.push(token);
            }
        }
        (!common.is_empty()).then(|| Scope(common.join(" ")))
    }
}

impl std::str::FromStr for Scope {
    type Err = Error;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        Self::parse(scope)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Scope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// The `resource` claim: one or more RFC 8707 resource identifiers.
///
/// On the wire it is a string, or a non-empty array of unique strings; the
/// type preserves which. Values are kept byte-for-byte and compared by simple
/// string comparison, never normalized (draft §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resources {
    values: Vec<String>,
    as_array: bool,
}

impl Resources {
    /// A single resource, serialized as a JSON string.
    pub fn one(resource: impl Into<String>) -> Self {
        Self {
            values: vec![resource.into()],
            as_array: false,
        }
    }

    /// One or more resources, serialized as a JSON array. Fails if the list
    /// is empty or has duplicates.
    pub fn many(resources: Vec<String>) -> Result<Self, Error> {
        if resources.is_empty() {
            return Err(Error::InvalidClaim {
                name: "resource",
                reason: "empty array",
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(resources.len());
        for resource in &resources {
            if seen.contains(&resource.as_str()) {
                return Err(Error::InvalidClaim {
                    name: "resource",
                    reason: "duplicate entry",
                });
            }
            seen.push(resource);
        }
        Ok(Self {
            values: resources,
            as_array: true,
        })
    }

    /// The resource identifiers, in order.
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Whether `resource` is one of the identifiers, byte-for-byte.
    pub fn contains(&self, resource: &str) -> bool {
        self.values.iter().any(|value| value == resource)
    }

    pub(crate) fn from_json(value: &Value) -> Result<Self, Error> {
        match value {
            Value::String(resource) => Ok(Self::one(resource.clone())),
            Value::Array(items) => Self::many(
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(Error::InvalidClaim {
                        name: "resource",
                        reason: "array entry is not a string",
                    })?,
            ),
            _ => Err(Error::InvalidClaim {
                name: "resource",
                reason: "neither a string nor an array",
            }),
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        match (self.as_array, self.values.as_slice()) {
            (false, [only]) => Value::from(only.as_str()),
            _ => Value::from(self.values.clone()),
        }
    }
}

impl Serialize for Resources {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Resources {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_json(&Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Authorization details
// ---------------------------------------------------------------------------

/// One RFC 9396 authorization details object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    /// The authorization details type. REQUIRED (RFC 9396 §2).
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datatypes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<String>>,
    /// Type-specific members, kept as JSON.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The `authorization_details` claim or parameter: a JSON array of RFC 9396
/// objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorizationDetails(pub Vec<AuthorizationDetail>);

impl AuthorizationDetails {
    /// Parse the JSON array carried by the `authorization_details` request
    /// parameter.
    pub fn from_json_str(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|_source| Error::InvalidClaim {
            name: "authorization_details",
            reason: "not an array of objects with a string type",
        })
    }

    pub(crate) fn from_json(value: &Value) -> Result<Self, Error> {
        Self::deserialize(value).map_err(|_source| Error::InvalidClaim {
            name: "authorization_details",
            reason: "not an array of objects with a string type",
        })
    }

    /// Whether every object in `self` also appears, member-for-member, in
    /// `other`. This is the conservative subset test the grant builders use:
    /// a narrowed copy of an object is not recognized as covered.
    pub fn is_subset_of(&self, other: &AuthorizationDetails) -> bool {
        self.0.iter().all(|detail| other.0.contains(detail))
    }
}

// ---------------------------------------------------------------------------
// Confirmation
// ---------------------------------------------------------------------------

/// The `cnf` claim: how the token is bound to its presenter (RFC 7800).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// `jkt`: the RFC 7638 thumbprint of a DPoP key (RFC 9449 §6.1).
    Jkt(String),
    /// `x5t#S256`: the SHA-256 thumbprint of a TLS client certificate
    /// (RFC 8705 §3.1).
    X5tS256(String),
    /// Any other confirmation. A Resource AS MUST reject a `cnf` it does not
    /// support (draft §9.11); it must never treat the token as unbound.
    Unsupported(Map<String, Value>),
}

impl Confirmation {
    pub(crate) fn from_json(value: &Value) -> Result<Self, Error> {
        let object = value.as_object().ok_or(Error::InvalidClaim {
            name: "cnf",
            reason: "not a JSON object",
        })?;
        let jkt = object.get("jkt");
        let x5t = object.get("x5t#S256");
        if jkt.is_some() && x5t.is_some() {
            // Draft §9.11, jwt-dpop-grant §3: one binding, not both.
            return Err(Error::InvalidClaim {
                name: "cnf",
                reason: "carries both jkt and x5t#S256",
            });
        }
        if object.len() == 1 {
            if let Some(Value::String(jkt)) = jkt {
                return Ok(Self::Jkt(jkt.clone()));
            }
            if let Some(Value::String(x5t)) = x5t {
                return Ok(Self::X5tS256(x5t.clone()));
            }
        }
        Ok(Self::Unsupported(object.clone()))
    }

    pub(crate) fn to_json(&self) -> Value {
        let mut object = Map::new();
        match self {
            Self::Jkt(jkt) => {
                object.insert("jkt".to_owned(), Value::from(jkt.as_str()));
            }
            Self::X5tS256(x5t) => {
                object.insert("x5t#S256".to_owned(), Value::from(x5t.as_str()));
            }
            Self::Unsupported(members) => return Value::Object(members.clone()),
        }
        Value::Object(object)
    }
}

// ---------------------------------------------------------------------------
// Subject identifiers
// ---------------------------------------------------------------------------

/// The `saml-nameid` Subject Identifier Format (draft §3.2.1): the SAML
/// NameID a Resource AS that resolves users by SAML uses to find the subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlNameId {
    /// Entity ID of the SAML issuer. REQUIRED.
    pub issuer: String,
    /// The NameID value. REQUIRED.
    pub nameid: String,
    /// The NameID `Format`. Never the transient format.
    pub nameid_format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub sp_provided_id: Option<String>,
}

/// The `sub_id` claim: an RFC 9493 Subject Identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectIdentifier {
    /// `saml-nameid` (draft §3.2.1).
    SamlNameId(SamlNameId),
    /// `email` (RFC 9493 §3.2.2).
    Email { email: String },
    /// `iss_sub` (RFC 9493 §3.2.3).
    IssSub { iss: String, sub: String },
    /// `opaque` (RFC 9493 §3.2.4).
    Opaque { id: String },
    /// Any other format, kept as JSON (including its `format` member).
    Other(Map<String, Value>),
}

impl SubjectIdentifier {
    pub(crate) fn from_json(value: &Value) -> Result<Self, Error> {
        let invalid = |reason: &'static str| Error::InvalidClaim {
            name: "sub_id",
            reason,
        };
        let object = value.as_object().ok_or(invalid("not a JSON object"))?;
        let format = object
            .get("format")
            .and_then(Value::as_str)
            .ok_or(invalid("no string format member"))?;
        let required = |name: &str| {
            object
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(invalid("a required member is missing or not a string"))
        };
        let optional = |name: &str| match object.get(name) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(invalid("an optional member is not a string")),
        };
        match format {
            "saml-nameid" => {
                let nameid_format = optional("nameid_format")?;
                if nameid_format.as_deref() == Some(NAMEID_FORMAT_TRANSIENT) {
                    return Err(Error::TransientNameId);
                }
                Ok(Self::SamlNameId(SamlNameId {
                    issuer: required("issuer")?,
                    nameid: required("nameid")?,
                    nameid_format,
                    name_qualifier: optional("name_qualifier")?,
                    sp_name_qualifier: optional("sp_name_qualifier")?,
                    sp_provided_id: optional("sp_provided_id")?,
                }))
            }
            "email" => Ok(Self::Email {
                email: required("email")?,
            }),
            "iss_sub" => Ok(Self::IssSub {
                iss: required("iss")?,
                sub: required("sub")?,
            }),
            "opaque" => Ok(Self::Opaque {
                id: required("id")?,
            }),
            _ => Ok(Self::Other(object.clone())),
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        let mut object = Map::new();
        let mut put = |name: &str, value: &str| {
            object.insert(name.to_owned(), Value::from(value));
        };
        match self {
            Self::SamlNameId(nameid) => {
                put("format", "saml-nameid");
                put("issuer", &nameid.issuer);
                put("nameid", &nameid.nameid);
                for (name, value) in [
                    ("nameid_format", &nameid.nameid_format),
                    ("name_qualifier", &nameid.name_qualifier),
                    ("sp_name_qualifier", &nameid.sp_name_qualifier),
                    ("sp_provided_id", &nameid.sp_provided_id),
                ] {
                    if let Some(value) = value {
                        put(name, value);
                    }
                }
            }
            Self::Email { email } => {
                put("format", "email");
                put("email", email);
            }
            Self::IssSub { iss, sub } => {
                put("format", "iss_sub");
                put("iss", iss);
                put("sub", sub);
            }
            Self::Opaque { id } => {
                put("format", "opaque");
                put("id", id);
            }
            Self::Other(members) => return Value::Object(members.clone()),
        }
        Value::Object(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audience_sole_and_form() {
        let single: Audience = serde_json::from_value(json!("https://as.example")).unwrap();
        assert_eq!(single.sole(), Some("https://as.example"));
        assert!(matches!(single, Audience::Single(_)));
        let one: Audience = serde_json::from_value(json!(["https://as.example"])).unwrap();
        assert_eq!(one.sole(), Some("https://as.example"));
        assert!(matches!(one, Audience::Many(_)));
        let two: Audience = serde_json::from_value(json!(["a", "b"])).unwrap();
        assert_eq!(two.sole(), None);
        assert_eq!(two.values().len(), 2);
        let none: Audience = serde_json::from_value(json!([])).unwrap();
        assert_eq!(none.sole(), None);
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            json!(["https://as.example"])
        );
    }

    #[test]
    fn numeric_date_accepts_integers_and_fractions() {
        assert_eq!(
            NumericDate::from_json(&json!(1_311_280_970))
                .unwrap()
                .as_secs(),
            1_311_280_970
        );
        let fractional = NumericDate::from_json(&json!(1_311_280_970.5)).unwrap();
        assert_eq!(fractional.as_secs(), 1_311_280_970);
        assert!(fractional > NumericDate::from_secs(1_311_280_970).unwrap());
        assert!(fractional < NumericDate::from_secs(1_311_280_971).unwrap());
        assert_eq!(
            NumericDate::from_json(&json!(1.5e9)).unwrap().as_secs(),
            1_500_000_000
        );
        assert_eq!(NumericDate::from_json(&json!(0)).unwrap().as_secs(), 0);
    }

    #[test]
    fn numeric_date_rejects_negative_huge_and_non_numbers() {
        for bad in [
            json!(-1),
            json!(-0.5),
            json!(253_402_300_800_u64),
            json!(1e300),
            json!("1311280970"),
            json!(null),
            json!(true),
        ] {
            assert!(NumericDate::from_json(&bad).is_none(), "{bad}");
        }
        assert!(NumericDate::from_json(&json!(253_402_300_799_u64)).is_some());
    }

    #[test]
    fn numeric_date_emits_integers() {
        let date = NumericDate::from_json(&json!(1_311_280_970.75)).unwrap();
        assert_eq!(serde_json::to_string(&date).unwrap(), "1311280970");
    }

    #[test]
    fn numeric_date_from_system_time_truncates() {
        let time = SystemTime::UNIX_EPOCH + Duration::from_millis(1_500);
        assert_eq!(NumericDate::from_system_time(time).unwrap().as_secs(), 1);
        assert_eq!(
            NumericDate::from_secs(5).unwrap().to_system_time().unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(5)
        );
    }

    #[test]
    fn scope_grammar() {
        let scope = Scope::parse("todos.read todos.write").unwrap();
        assert_eq!(
            scope.tokens().collect::<Vec<_>>(),
            ["todos.read", "todos.write"]
        );
        assert!(scope.contains("todos.read"));
        assert!(!scope.contains("todos"));
        assert_eq!(scope.as_str(), "todos.read todos.write");
        for bad in [
            "",
            " ",
            "a  b",
            " a",
            "a ",
            "a\tb",
            "a\"b",
            "a\\b",
            "caf\u{e9}",
        ] {
            assert!(Scope::parse(bad).is_err(), "{bad:?}");
        }
        Scope::parse("https://example.com/scope:x!#$%").unwrap();
    }

    #[test]
    fn scope_intersection() {
        let granted = Scope::parse("a b c").unwrap();
        let requested = Scope::parse("c x a a").unwrap();
        assert_eq!(granted.intersection(&requested).unwrap().as_str(), "a c");
        assert_eq!(requested.intersection(&granted).unwrap().as_str(), "c a");
        assert_eq!(granted.intersection(&Scope::parse("x y").unwrap()), None);
    }

    #[test]
    fn scope_subset() {
        let granted = Scope::parse("a b c").unwrap();
        assert!(Scope::parse("c a").unwrap().is_subset_of(&granted));
        assert!(!Scope::parse("a d").unwrap().is_subset_of(&granted));
    }

    #[test]
    fn resources_shape_rules() {
        let one = Resources::from_json(&json!("https://api.example/")).unwrap();
        assert_eq!(one.values(), ["https://api.example/"]);
        assert_eq!(one.to_json(), json!("https://api.example/"));
        let many =
            Resources::from_json(&json!(["https://a.example", "https://b.example"])).unwrap();
        assert_eq!(
            many.to_json(),
            json!(["https://a.example", "https://b.example"])
        );
        // A one-element array stays an array.
        let array_of_one = Resources::from_json(&json!(["https://a.example"])).unwrap();
        assert_eq!(array_of_one.to_json(), json!(["https://a.example"]));
        for bad in [
            json!([]),
            json!(["a", "a"]),
            json!(["a", 1]),
            json!(7),
            json!({}),
        ] {
            assert!(Resources::from_json(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resources_are_never_normalized() {
        let resources = Resources::one("https://api.example/");
        assert!(resources.contains("https://api.example/"));
        assert!(!resources.contains("https://api.example"));
        assert!(!resources.contains("HTTPS://api.example/"));
    }

    #[test]
    fn authorization_details_shape_and_subset() {
        let details = AuthorizationDetails::from_json(&json!([
            {"type": "todo", "actions": ["read"], "custom": {"k": 1}},
            {"type": "calendar"}
        ]))
        .unwrap();
        assert_eq!(details.0[0].kind, "todo");
        assert_eq!(details.0[0].extra["custom"], json!({"k": 1}));
        let subset = AuthorizationDetails::from_json(&json!([{"type": "calendar"}])).unwrap();
        assert!(subset.is_subset_of(&details));
        let narrowed = AuthorizationDetails::from_json(&json!([{"type": "todo"}])).unwrap();
        assert!(!narrowed.is_subset_of(&details));
        for bad in [
            json!({}),
            json!([{"actions": []}]),
            json!([{"type": 1}]),
            json!(["x"]),
        ] {
            assert!(AuthorizationDetails::from_json(&bad).is_err(), "{bad}");
        }
        AuthorizationDetails::from_json_str(r#"[{"type":"todo"}]"#).unwrap();
    }

    #[test]
    fn cnf_rules() {
        assert_eq!(
            Confirmation::from_json(&json!({"jkt": "abc"})).unwrap(),
            Confirmation::Jkt("abc".to_owned())
        );
        assert_eq!(
            Confirmation::from_json(&json!({"x5t#S256": "abc"})).unwrap(),
            Confirmation::X5tS256("abc".to_owned())
        );
        Confirmation::from_json(&json!({"jkt": "a", "x5t#S256": "b"})).unwrap_err();
        for unsupported in [
            json!({"jwk": {"kty": "EC"}}),
            json!({"jkt": "a", "jwk": {}}),
            json!({"jkt": 7}),
            json!({}),
        ] {
            assert!(
                matches!(
                    Confirmation::from_json(&unsupported).unwrap(),
                    Confirmation::Unsupported(_)
                ),
                "{unsupported}"
            );
        }
        Confirmation::from_json(&json!("jkt")).unwrap_err();
        assert_eq!(
            Confirmation::Jkt("abc".to_owned()).to_json(),
            json!({"jkt": "abc"})
        );
    }

    #[test]
    fn saml_nameid_subject_identifier() {
        let value = json!({
            "format": "saml-nameid",
            "issuer": "https://idp.example/saml",
            "nameid": "alice@example.com",
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "sp_name_qualifier": "https://sp.example"
        });
        let parsed = SubjectIdentifier::from_json(&value).unwrap();
        let SubjectIdentifier::SamlNameId(nameid) = &parsed else {
            panic!("expected saml-nameid");
        };
        assert_eq!(nameid.issuer, "https://idp.example/saml");
        assert_eq!(
            nameid.sp_name_qualifier.as_deref(),
            Some("https://sp.example")
        );
        assert_eq!(parsed.to_json(), value);

        let missing = json!({"format": "saml-nameid", "issuer": "x"});
        assert!(matches!(
            SubjectIdentifier::from_json(&missing).unwrap_err(),
            Error::InvalidClaim { name: "sub_id", .. }
        ));
    }

    #[test]
    fn transient_nameid_is_rejected() {
        let value = json!({
            "format": "saml-nameid",
            "issuer": "https://idp.example/saml",
            "nameid": "_abc123",
            "nameid_format": NAMEID_FORMAT_TRANSIENT
        });
        assert!(matches!(
            SubjectIdentifier::from_json(&value).unwrap_err(),
            Error::TransientNameId
        ));
    }

    #[test]
    fn other_subject_identifier_formats() {
        assert_eq!(
            SubjectIdentifier::from_json(&json!({"format": "email", "email": "a@example.com"}))
                .unwrap(),
            SubjectIdentifier::Email {
                email: "a@example.com".to_owned()
            }
        );
        assert!(matches!(
            SubjectIdentifier::from_json(&json!({"format": "phone_number", "phone_number": "+1"}))
                .unwrap(),
            SubjectIdentifier::Other(_)
        ));
        SubjectIdentifier::from_json(&json!({"email": "a@example.com"})).unwrap_err();
    }
}
