//! Client metadata (draft §8, §11.4): what the requesting app registers.
//! See RFC-006 §6.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use url::Url;

use super::{
    GRANT_PROFILE_ID_JAG, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_TOKEN_EXCHANGE, push_unique, put,
};
use crate::error::Error;
use crate::jose::JwkSet;

/// The members modelled as fields. They never appear in `extra`.
const KNOWN_MEMBERS: [&str; 5] = [
    "grant_types",
    "authorization_grant_profiles_supported",
    "token_endpoint_auth_method",
    "jwks",
    "jwks_uri",
];

/// Client metadata: serializes to a Dynamic Client Registration request body
/// (RFC 7591 §2) or a Client ID Metadata Document.
///
/// Advertising the ID-JAG profile says nothing about which authorization
/// servers the client will use (draft §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMetadata {
    pub grant_types: Vec<String>,
    /// Draft §8, §11.4.
    pub authorization_grant_profiles_supported: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub jwks: Option<JwkSet>,
    pub jwks_uri: Option<Url>,
    /// Every other member (`client_name`, `redirect_uris`, `client_id` for a
    /// Client ID Metadata Document, …).
    pub extra: BTreeMap<String, Value>,
}

impl ClientMetadata {
    /// A builder preloaded for an XAA client: the ID-JAG profile and both
    /// grant types it requires (draft §8 MUST).
    pub fn xaa_client() -> ClientMetadataBuilder {
        ClientMetadataBuilder {
            metadata: Self {
                grant_types: vec![
                    GRANT_TYPE_TOKEN_EXCHANGE.to_owned(),
                    GRANT_TYPE_JWT_BEARER.to_owned(),
                ],
                authorization_grant_profiles_supported: vec![GRANT_PROFILE_ID_JAG.to_owned()],
                token_endpoint_auth_method: None,
                jwks: None,
                jwks_uri: None,
                extra: BTreeMap::new(),
            },
        }
    }

    /// Check the rules [`ClientMetadataBuilder::build`] enforces. Useful for
    /// a value assembled or edited by hand.
    ///
    /// - The ID-JAG profile requires both the token-exchange and jwt-bearer
    ///   grant types (draft §8 MUST).
    /// - `jwks` and `jwks_uri` are not both present (RFC 7591 §2 MUST NOT).
    /// - No `extra` member shadows a modelled one.
    pub fn validate(&self) -> Result<(), Error> {
        let has = |list: &[String], value: &str| list.iter().any(|entry| entry == value);
        if has(
            &self.authorization_grant_profiles_supported,
            GRANT_PROFILE_ID_JAG,
        ) && !(has(&self.grant_types, GRANT_TYPE_TOKEN_EXCHANGE)
            && has(&self.grant_types, GRANT_TYPE_JWT_BEARER))
        {
            return Err(Error::InvalidConfiguration {
                reason: "the id-jag grant profile requires the token-exchange and jwt-bearer grant types",
            });
        }
        if self.jwks.is_some() && self.jwks_uri.is_some() {
            return Err(Error::InvalidConfiguration {
                reason: "jwks and jwks_uri must not both be present",
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

    /// The document as a JSON object. Members in `extra` never override the
    /// modelled members. An empty profile list is omitted.
    pub fn to_value(&self) -> Value {
        let mut object: Map<String, Value> = self
            .extra
            .iter()
            .filter(|(name, _)| !KNOWN_MEMBERS.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        object.insert("grant_types".to_owned(), self.grant_types.clone().into());
        put(
            &mut object,
            "authorization_grant_profiles_supported",
            Some(self.authorization_grant_profiles_supported.clone())
                .filter(|profiles| !profiles.is_empty()),
        );
        put(
            &mut object,
            "token_endpoint_auth_method",
            self.token_endpoint_auth_method.clone(),
        );
        put(
            &mut object,
            "jwks",
            self.jwks.as_ref().map(JwkSet::to_value),
        );
        put(
            &mut object,
            "jwks_uri",
            self.jwks_uri.as_ref().map(Url::as_str),
        );
        Value::Object(object)
    }
}

impl serde::Serialize for ClientMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

/// Builds a [`ClientMetadata`]. Start from [`ClientMetadata::xaa_client`].
#[derive(Debug, Clone)]
pub struct ClientMetadataBuilder {
    metadata: ClientMetadata,
}

impl ClientMetadataBuilder {
    /// Add a grant type, such as
    /// `urn:ietf:params:oauth:grant-type:jwt-dpop` or `refresh_token`.
    pub fn grant_type(mut self, grant_type: impl Into<String>) -> Self {
        push_unique(&mut self.metadata.grant_types, grant_type);
        self
    }

    /// Replace the grant types. [`Self::build`] refuses a list that drops
    /// token-exchange or jwt-bearer while the ID-JAG profile is advertised.
    pub fn grant_types(mut self, grant_types: Vec<String>) -> Self {
        self.metadata.grant_types = grant_types;
        self
    }

    /// Replace the advertised authorization grant profiles.
    pub fn authorization_grant_profiles(mut self, profiles: Vec<String>) -> Self {
        self.metadata.authorization_grant_profiles_supported = profiles;
        self
    }

    /// Set `token_endpoint_auth_method` (for example `private_key_jwt`).
    pub fn token_endpoint_auth_method(mut self, method: impl Into<String>) -> Self {
        self.metadata.token_endpoint_auth_method = Some(method.into());
        self
    }

    /// Publish the client's public keys by value. Excludes `jwks_uri`.
    pub fn jwks(mut self, jwks: JwkSet) -> Self {
        self.metadata.jwks = Some(jwks);
        self
    }

    /// Publish the client's public keys by reference. Excludes `jwks`.
    pub fn jwks_uri(mut self, jwks_uri: Url) -> Self {
        self.metadata.jwks_uri = Some(jwks_uri);
        self
    }

    /// Add a member this type does not model. A name that is modelled is
    /// refused by [`Self::build`].
    pub fn extra(mut self, name: impl Into<String>, value: Value) -> Self {
        self.metadata.extra.insert(name.into(), value);
        self
    }

    /// Check the rules of [`ClientMetadata::validate`] and return the
    /// metadata.
    pub fn build(self) -> Result<ClientMetadata, Error> {
        self.metadata.validate()?;
        Ok(self.metadata)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::metadata::GRANT_TYPE_JWT_DPOP;
    use crate::test_support::{jwks_of, p256_key};

    #[test]
    fn xaa_client_includes_the_profile_and_both_grant_types() {
        let metadata = ClientMetadata::xaa_client().build().unwrap();
        assert_eq!(
            metadata.to_value(),
            json!({
                "grant_types": [
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer"
                ],
                "authorization_grant_profiles_supported": [
                    "urn:ietf:params:oauth:grant-profile:id-jag"
                ]
            })
        );
    }

    #[test]
    fn serializes_as_a_registration_request() {
        let jwks = jwks_of(&[&p256_key()]);
        let metadata = ClientMetadata::xaa_client()
            .grant_type(GRANT_TYPE_JWT_DPOP)
            .grant_type(GRANT_TYPE_JWT_BEARER)
            .token_endpoint_auth_method("private_key_jwt")
            .jwks(jwks.clone())
            .extra("client_name", json!("Requesting App"))
            .build()
            .unwrap();
        let value = serde_json::to_value(&metadata).unwrap();
        assert_eq!(
            value.get("grant_types"),
            Some(&json!([
                GRANT_TYPE_TOKEN_EXCHANGE,
                GRANT_TYPE_JWT_BEARER,
                GRANT_TYPE_JWT_DPOP
            ]))
        );
        assert_eq!(
            value.get("token_endpoint_auth_method"),
            Some(&json!("private_key_jwt"))
        );
        assert_eq!(value.get("jwks"), Some(&jwks.to_value()));
        assert_eq!(value.get("jwks_uri"), None);
        assert_eq!(value.get("client_name"), Some(&json!("Requesting App")));
        assert_eq!(value, metadata.to_value());
    }

    #[test]
    fn jwks_uri_is_emitted_as_a_string() {
        let metadata = ClientMetadata::xaa_client()
            .jwks_uri(Url::parse("https://app.example/jwks.json").unwrap())
            .build()
            .unwrap();
        assert_eq!(
            metadata.to_value().get("jwks_uri"),
            Some(&json!("https://app.example/jwks.json"))
        );
    }

    #[test]
    fn profile_without_token_exchange_is_refused() {
        assert!(matches!(
            ClientMetadata::xaa_client()
                .grant_types(vec![GRANT_TYPE_JWT_BEARER.to_owned()])
                .build(),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn profile_without_jwt_bearer_is_refused() {
        assert!(matches!(
            ClientMetadata::xaa_client()
                .grant_types(vec![GRANT_TYPE_TOKEN_EXCHANGE.to_owned()])
                .build(),
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            ClientMetadata::xaa_client().grant_types(Vec::new()).build(),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn without_the_profile_any_grant_types_are_accepted() {
        let metadata = ClientMetadata::xaa_client()
            .authorization_grant_profiles(Vec::new())
            .grant_types(vec!["authorization_code".to_owned()])
            .build()
            .unwrap();
        assert_eq!(
            metadata.to_value(),
            json!({ "grant_types": ["authorization_code"] })
        );
    }

    #[test]
    fn jwks_and_jwks_uri_together_are_refused() {
        assert!(matches!(
            ClientMetadata::xaa_client()
                .jwks(jwks_of(&[&p256_key()]))
                .jwks_uri(Url::parse("https://app.example/jwks.json").unwrap())
                .build(),
            Err(Error::InvalidConfiguration {
                reason: "jwks and jwks_uri must not both be present"
            })
        ));
    }

    #[test]
    fn extra_members_that_shadow_modelled_ones_are_refused() {
        for name in KNOWN_MEMBERS {
            assert!(
                matches!(
                    ClientMetadata::xaa_client().extra(name, json!([])).build(),
                    Err(Error::InvalidConfiguration { .. })
                ),
                "member {name}"
            );
        }
    }

    #[test]
    fn hand_edited_metadata_is_checked_by_validate_and_never_shadowed_on_emit() {
        let mut metadata = ClientMetadata::xaa_client().build().unwrap();
        metadata
            .extra
            .insert("grant_types".to_owned(), json!(["implicit"]));
        assert!(matches!(
            metadata.validate(),
            Err(Error::InvalidConfiguration { .. })
        ));
        assert_eq!(
            metadata.to_value().get("grant_types"),
            Some(&json!([GRANT_TYPE_TOKEN_EXCHANGE, GRANT_TYPE_JWT_BEARER]))
        );
    }
}
