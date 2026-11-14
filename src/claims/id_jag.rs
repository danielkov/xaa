//! The ID-JAG claim set (draft §3.1).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::types::{
    Audience, AuthorizationDetails, Confirmation, Issuer, NumericDate, Resources, Scope,
    SubjectIdentifier,
};
use crate::error::Error;

/// Deepest `act` nesting accepted (RFC 8693 §4.1 allows arbitrary chains).
const MAX_ACTOR_DEPTH: usize = 8;

/// An RFC 8693 §4.1 actor: who is acting on the subject's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// Members other than `act`, typically `sub` and `iss`.
    pub claims: BTreeMap<String, Value>,
    /// The prior actor in a delegation chain.
    pub act: Option<Box<Actor>>,
}

impl Actor {
    fn from_json(value: &Value, depth: usize) -> Result<Self, Error> {
        if depth >= MAX_ACTOR_DEPTH {
            return Err(Error::InvalidClaim {
                name: "act",
                reason: "actor chain is too deep",
            });
        }
        let object = value.as_object().ok_or(Error::InvalidClaim {
            name: "act",
            reason: "not a JSON object",
        })?;
        let mut claims = BTreeMap::new();
        let mut act = None;
        for (name, member) in object {
            if name == "act" {
                act = Some(Box::new(Self::from_json(member, depth.saturating_add(1))?));
            } else {
                claims.insert(name.clone(), member.clone());
            }
        }
        Ok(Self { claims, act })
    }

    fn to_json(&self) -> Value {
        let mut object: Map<String, Value> = self
            .claims
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        if let Some(act) = &self.act {
            object.insert("act".to_owned(), act.to_json());
        }
        Value::Object(object)
    }
}

/// The claims of an Identity Assertion JWT Authorization Grant.
///
/// At the Resource AS these are only reachable through a verified grant
/// (RFC-004 §5). Constructing a value here proves nothing about a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdJagClaims {
    /// The IdP that issued the grant.
    pub iss: Issuer,
    /// The subject at the IdP.
    pub sub: String,
    /// The Resource AS issuer identifier.
    pub aud: Audience,
    /// The client's identifier at the Resource AS.
    pub client_id: String,
    pub jti: String,
    pub exp: NumericDate,
    pub iat: NumericDate,
    pub resource: Option<Resources>,
    pub scope: Option<Scope>,
    pub authorization_details: Option<AuthorizationDetails>,
    pub act: Option<Actor>,
    pub sub_id: Option<SubjectIdentifier>,
    /// The subject's tenant at the IdP (draft §6.4).
    pub tenant: Option<String>,
    /// The tenant at the Resource AS the grant is for (draft §6.1).
    pub aud_tenant: Option<String>,
    /// The subject's identifier at the Resource AS (draft §3.1).
    pub aud_sub: Option<String>,
    pub email: Option<String>,
    pub auth_time: Option<NumericDate>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub cnf: Option<Confirmation>,
    pub nbf: Option<NumericDate>,
    /// Any other claim. Draft §3.1 allows any claim valid in an ID Token.
    pub extra: BTreeMap<String, Value>,
}

impl IdJagClaims {
    /// Build the claim set from a JSON object, applying every shape rule in
    /// RFC-002 §6.
    pub fn from_object(mut object: Map<String, Value>) -> Result<Self, Error> {
        let iss = Issuer::new(take_required_string(&mut object, "iss")?);
        let sub = take_required_string(&mut object, "sub")?;
        let aud = match object.remove("aud") {
            None => return Err(Error::MissingClaim { name: "aud" }),
            Some(value) => serde_json::from_value::<Audience>(value).map_err(|_source| {
                Error::InvalidClaim {
                    name: "aud",
                    reason: "neither a string nor an array of strings",
                }
            })?,
        };
        let client_id = take_required_string(&mut object, "client_id")?;
        let jti = take_required_string(&mut object, "jti")?;
        let exp = take_date(&mut object, "exp")?.ok_or(Error::MissingClaim { name: "exp" })?;
        let iat = take_date(&mut object, "iat")?.ok_or(Error::MissingClaim { name: "iat" })?;

        let resource = object
            .remove("resource")
            .map(|value| Resources::from_json(&value))
            .transpose()?;
        let scope = take_optional_string(&mut object, "scope")?
            .map(Scope::parse)
            .transpose()?;
        let authorization_details = object
            .remove("authorization_details")
            .map(|value| AuthorizationDetails::from_json(&value))
            .transpose()?;
        let act = object
            .remove("act")
            .map(|value| Actor::from_json(&value, 0))
            .transpose()?;
        let sub_id = object
            .remove("sub_id")
            .map(|value| SubjectIdentifier::from_json(&value))
            .transpose()?;
        let cnf = object
            .remove("cnf")
            .map(|value| Confirmation::from_json(&value))
            .transpose()?;
        let amr = match object.remove("amr") {
            None => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(Error::InvalidClaim {
                        name: "amr",
                        reason: "not an array of strings",
                    })?,
            ),
            Some(_) => {
                return Err(Error::InvalidClaim {
                    name: "amr",
                    reason: "not an array of strings",
                });
            }
        };

        Ok(Self {
            iss,
            sub,
            aud,
            client_id,
            jti,
            exp,
            iat,
            resource,
            scope,
            authorization_details,
            act,
            sub_id,
            tenant: take_optional_string(&mut object, "tenant")?,
            aud_tenant: take_optional_string(&mut object, "aud_tenant")?,
            aud_sub: take_optional_string(&mut object, "aud_sub")?,
            email: take_optional_string(&mut object, "email")?,
            auth_time: take_date(&mut object, "auth_time")?,
            acr: take_optional_string(&mut object, "acr")?,
            amr,
            cnf,
            nbf: take_date(&mut object, "nbf")?,
            extra: object.into_iter().collect(),
        })
    }

    /// The claim set as a JSON object. Absent optional claims are omitted and
    /// time values are integers.
    pub fn to_object(&self) -> Map<String, Value> {
        // Extra claims first, so a typed claim always wins over an `extra`
        // entry of the same name.
        let mut object: Map<String, Value> = self
            .extra
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let mut put = |name: &str, value: Value| {
            object.insert(name.to_owned(), value);
        };
        put("iss", Value::from(self.iss.as_str()));
        put("sub", Value::from(self.sub.as_str()));
        put(
            "aud",
            match &self.aud {
                Audience::Single(audience) => Value::from(audience.as_str()),
                Audience::Many(audiences) => Value::from(audiences.clone()),
            },
        );
        put("client_id", Value::from(self.client_id.as_str()));
        put("jti", Value::from(self.jti.as_str()));
        put("exp", Value::from(self.exp.as_secs()));
        put("iat", Value::from(self.iat.as_secs()));
        if let Some(resource) = &self.resource {
            put("resource", resource.to_json());
        }
        if let Some(scope) = &self.scope {
            put("scope", Value::from(scope.as_str()));
        }
        if let Some(details) = &self.authorization_details {
            put(
                "authorization_details",
                serde_json::to_value(details).unwrap_or(Value::Null),
            );
        }
        if let Some(act) = &self.act {
            put("act", act.to_json());
        }
        if let Some(sub_id) = &self.sub_id {
            put("sub_id", sub_id.to_json());
        }
        if let Some(cnf) = &self.cnf {
            put("cnf", cnf.to_json());
        }
        if let Some(amr) = &self.amr {
            put("amr", Value::from(amr.clone()));
        }
        for (name, value) in [
            ("tenant", &self.tenant),
            ("aud_tenant", &self.aud_tenant),
            ("aud_sub", &self.aud_sub),
            ("email", &self.email),
            ("acr", &self.acr),
        ] {
            if let Some(value) = value {
                put(name, Value::from(value.as_str()));
            }
        }
        for (name, value) in [("auth_time", self.auth_time), ("nbf", self.nbf)] {
            if let Some(value) = value {
                put(name, Value::from(value.as_secs()));
            }
        }
        object
    }
}

fn take_required_string(
    object: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, Error> {
    take_optional_string(object, name)?.ok_or(Error::MissingClaim { name })
}

fn take_optional_string(
    object: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Option<String>, Error> {
    match object.remove(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(Error::InvalidClaim {
            name,
            reason: "not a string",
        }),
    }
}

fn take_date(
    object: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Option<NumericDate>, Error> {
    match object.remove(name) {
        None => Ok(None),
        Some(value) => NumericDate::from_json(&value)
            .map(Some)
            .ok_or(Error::InvalidClaim {
                name,
                reason: "not a non-negative NumericDate",
            }),
    }
}

impl serde::Serialize for IdJagClaims {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_object().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for IdJagClaims {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let object = <Map<String, Value> as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_object(object).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> Map<String, Value> {
        json!({
            "iss": "https://idp.example",
            "sub": "user-1",
            "aud": "https://as.resource.example",
            "client_id": "client-at-resource",
            "jti": "j-1",
            "exp": 1_794_657_900_u64,
            "iat": 1_794_657_600_u64
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn with(name: &str, value: Value) -> Map<String, Value> {
        let mut object = minimal();
        object.insert(name.to_owned(), value);
        object
    }

    #[test]
    fn minimal_claim_set_parses() {
        let claims = IdJagClaims::from_object(minimal()).unwrap();
        assert_eq!(claims.iss.as_str(), "https://idp.example");
        assert_eq!(claims.aud.sole(), Some("https://as.resource.example"));
        assert_eq!(claims.exp.as_secs(), 1_794_657_900);
        assert!(claims.extra.is_empty());
        assert!(claims.resource.is_none());
    }

    #[test]
    fn each_required_claim_is_required() {
        for name in ["iss", "sub", "aud", "client_id", "jti", "exp", "iat"] {
            let mut object = minimal();
            object.remove(name);
            let err = IdJagClaims::from_object(object).unwrap_err();
            assert!(
                matches!(err, Error::MissingClaim { name: missing } if missing == name),
                "{name}: {err:?}"
            );
        }
    }

    #[test]
    fn wrong_types_are_invalid_not_missing() {
        for (name, value) in [
            ("iss", json!(7)),
            ("sub", json!(["a"])),
            ("aud", json!(7)),
            ("aud", json!(["a", 7])),
            ("exp", json!("soon")),
            ("exp", json!(-5)),
            ("iat", json!(null)),
            ("scope", json!(["a"])),
            ("scope", json!("a  b")),
            ("resource", json!([])),
            ("resource", json!(["a", "a"])),
            ("amr", json!("pwd")),
            ("amr", json!([1])),
            ("cnf", json!({"jkt": "a", "x5t#S256": "b"})),
            ("tenant", json!(1)),
            ("auth_time", json!("x")),
            ("authorization_details", json!([{"no_type": true}])),
        ] {
            let err = IdJagClaims::from_object(with(name, value.clone())).unwrap_err();
            assert!(
                matches!(err, Error::InvalidClaim { name: got, .. } if got == name),
                "{name}={value}: {err:?}"
            );
        }
    }

    #[test]
    fn fractional_exp_is_accepted() {
        let claims = IdJagClaims::from_object(with("exp", json!(1_794_657_900.5))).unwrap();
        assert_eq!(claims.exp.as_secs(), 1_794_657_900);
    }

    #[test]
    fn full_claim_set_round_trips() {
        let value = json!({
            "iss": "https://idp.example",
            "sub": "user-1",
            "aud": ["https://as.resource.example"],
            "client_id": "client-at-resource",
            "jti": "j-1",
            "exp": 1_794_657_900_u64,
            "iat": 1_794_657_600_u64,
            "nbf": 1_794_657_590_u64,
            "auth_time": 1_794_650_000_u64,
            "resource": ["https://api.example/", "https://api2.example"],
            "scope": "todos.read todos.write",
            "authorization_details": [{"type": "todo", "actions": ["read"]}],
            "act": {"sub": "agent-1", "act": {"sub": "agent-0"}},
            "sub_id": {"format": "email", "email": "alice@example.com"},
            "tenant": "t-idp",
            "aud_tenant": "t-res",
            "aud_sub": "res-user-9",
            "email": "alice@example.com",
            "acr": "urn:example:mfa",
            "amr": ["pwd", "otp"],
            "cnf": {"jkt": "thumb"},
            "groups": ["eng"],
            "custom": {"k": 1}
        });
        let claims = IdJagClaims::from_object(value.as_object().unwrap().clone()).unwrap();
        assert_eq!(claims.aud_tenant.as_deref(), Some("t-res"));
        assert_eq!(
            claims.act.as_ref().unwrap().act.as_ref().unwrap().claims["sub"],
            "agent-0"
        );
        assert_eq!(claims.extra.len(), 2);
        assert_eq!(Value::Object(claims.to_object()), value);
        // And through serde.
        let back: IdJagClaims =
            serde_json::from_str(&serde_json::to_string(&claims).unwrap()).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn actor_depth_is_capped() {
        let mut act = json!({"sub": "leaf"});
        for _ in 0..8 {
            act = json!({"sub": "a", "act": act});
        }
        assert!(matches!(
            IdJagClaims::from_object(with("act", act)).unwrap_err(),
            Error::InvalidClaim { name: "act", .. }
        ));
        let mut ok = json!({"sub": "leaf"});
        for _ in 0..7 {
            ok = json!({"sub": "a", "act": ok});
        }
        IdJagClaims::from_object(with("act", ok)).unwrap();
    }

    #[test]
    fn transient_nameid_fails_the_claim_set() {
        let sub_id = json!({
            "format": "saml-nameid",
            "issuer": "https://idp.example/saml",
            "nameid": "_x",
            "nameid_format": super::super::NAMEID_FORMAT_TRANSIENT
        });
        assert!(matches!(
            IdJagClaims::from_object(with("sub_id", sub_id)).unwrap_err(),
            Error::TransientNameId
        ));
    }

    #[test]
    fn typed_claims_win_over_extra_on_emit() {
        let mut claims = IdJagClaims::from_object(minimal()).unwrap();
        claims
            .extra
            .insert("iss".to_owned(), json!("https://evil.example"));
        assert_eq!(claims.to_object()["iss"], "https://idp.example");
    }
}
