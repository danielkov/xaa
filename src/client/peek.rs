//! The client's unverified view of an ID-JAG it was issued. See RFC-003 §5.

use std::time::SystemTime;

use crate::claims::{Audience, Confirmation, IdJagClaims, Issuer, NumericDate, Resources, Scope};
use crate::error::Error;
use crate::jose::{ParseLimits, id_jag_payload_unverified, parse_object_rejecting_duplicates};

/// Claims read from an ID-JAG **without verifying its signature**.
///
/// The client cannot, and need not, verify the IdP's signature; the Resource
/// AS does that. Reading the claims still lets the client catch a wrong
/// audience, client, resource, or binding before the ID-JAG and its Resource
/// AS credentials go anywhere.
///
/// This is a different type from [`Verified`](crate::jose::Verified) and is
/// never accepted where verified claims are required. Do not make
/// authorization decisions from it.
#[derive(Clone)]
pub struct IdJagPeek {
    claims: IdJagClaims,
}

impl IdJagPeek {
    /// Read `token`: a compact JWS typed `oauth-id-jag+jwt` (draft §3.1)
    /// whose payload is a well-formed ID-JAG claim set.
    pub(super) fn read(token: &str) -> Result<Self, Error> {
        // Not the verifying parser: the client never checks the signature,
        // so an `alg` this crate cannot verify is no reason to refuse.
        let payload = id_jag_payload_unverified(token, ParseLimits::default())
            .map_err(|reason| Error::MalformedIdJag { reason })?;
        let object = parse_object_rejecting_duplicates(&payload).map_err(|_reason| {
            Error::MalformedIdJag {
                reason: "payload is not a JSON object with unique member names",
            }
        })?;
        let claims = IdJagClaims::from_object(object).map_err(|_source| Error::MalformedIdJag {
            reason: "claims are not a well-formed ID-JAG claim set",
        })?;
        Ok(Self { claims })
    }

    /// `iss`, unverified.
    pub fn issuer(&self) -> &Issuer {
        &self.claims.iss
    }

    /// `aud`, unverified.
    pub fn audience(&self) -> &Audience {
        &self.claims.aud
    }

    /// `client_id`, unverified.
    pub fn client_id(&self) -> &str {
        &self.claims.client_id
    }

    /// `resource`, unverified.
    pub fn resources(&self) -> Option<&Resources> {
        self.claims.resource.as_ref()
    }

    /// `scope`, unverified.
    pub fn scope(&self) -> Option<&Scope> {
        self.claims.scope.as_ref()
    }

    /// `cnf`, unverified: the key the ID-JAG is bound to, if any.
    pub fn confirmation(&self) -> Option<&Confirmation> {
        self.claims.cnf.as_ref()
    }

    /// `exp`, unverified.
    pub fn expires_at(&self) -> NumericDate {
        self.claims.exp
    }

    /// Whether `exp` has passed at `now`. An ID-JAG that has not expired may
    /// be presented again after its access token expires (draft §4.4.4).
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.claims
            .exp
            .to_system_time()
            .map_or(true, |exp| now >= exp)
    }
}

/// Prints the routing claims only; `sub`, `email`, and the like stay out of
/// logs.
impl std::fmt::Debug for IdJagPeek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdJagPeek")
            .field("iss", &self.claims.iss)
            .field("aud", &self.claims.aud)
            .field("client_id", &self.claims.client_id)
            .field("exp", &self.claims.exp)
            .field("cnf", &self.claims.cnf)
            .finish_non_exhaustive()
    }
}
