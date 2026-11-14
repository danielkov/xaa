//! Replay protection. See RFC-002 §10.
//!
//! The library is stateless, so single-use enforcement goes through a store
//! the caller provides. Components consult it only after every other check on
//! a token has passed, so forged or malformed tokens never fill it, and a
//! request rejected for another reason does not burn a `jti`
//! (jwt-dpop-grant §5.1).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::http::BoxError;

/// What kind of identifier is being recorded, and whose it is. Identifiers
/// are unique only within their namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayNamespace<'a> {
    /// An ID-JAG `jti`, scoped to the IdP that issued it.
    IdJag { issuer: &'a str },
    /// A client-assertion `jti`, scoped to the client.
    ClientAssertion { client_id: &'a str },
    /// A DPoP proof `jti`, scoped to the proof key's thumbprint.
    DpopProof { jkt: &'a str },
}

/// Result of [`ReplayStore::check_and_insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The identifier had not been seen; it is now recorded.
    Fresh,
    /// The identifier was already recorded.
    Replayed,
}

/// The future returned by [`ReplayStore::check_and_insert`].
pub type ReplayFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ReplayOutcome, BoxError>> + Send + 'a>>;

/// An atomic "seen before?" store. The trait is object-safe: components take
/// it as `&dyn ReplayStore`.
pub trait ReplayStore: Send + Sync {
    /// Atomically record `id` in `ns` until `expires_at` and report whether
    /// it was already present.
    ///
    /// Two concurrent calls with the same `ns` and `id` MUST produce exactly
    /// one [`ReplayOutcome::Fresh`]. Shared backends implement this as a
    /// Redis `SET NX PX` or an insert on a unique key. An error fails the
    /// request closed.
    fn check_and_insert<'a>(
        &'a self,
        ns: ReplayNamespace<'a>,
        id: &'a str,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> ReplayFuture<'a>;
}

/// A bounded in-memory [`ReplayStore`] for single-process deployments, tests,
/// and examples. It does not coordinate across processes: a deployment with
/// more than one instance needs a shared store.
#[derive(Debug)]
pub struct InMemoryReplayStore {
    capacity: usize,
    entries: Mutex<HashMap<String, SystemTime>>,
}

impl InMemoryReplayStore {
    /// A store holding at most `capacity` unexpired identifiers. When full of
    /// unexpired entries it fails closed rather than evicting one.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn key(ns: ReplayNamespace<'_>, id: &str) -> String {
        // Length-prefix the scope so no (scope, id) pair collides with another.
        let (kind, scope) = match ns {
            ReplayNamespace::IdJag { issuer } => ("id-jag", issuer),
            ReplayNamespace::ClientAssertion { client_id } => ("client-assertion", client_id),
            ReplayNamespace::DpopProof { jkt } => ("dpop", jkt),
        };
        format!("{kind}:{}:{scope}:{id}", scope.len())
    }

    fn check_and_insert_sync(
        &self,
        ns: ReplayNamespace<'_>,
        id: &str,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<ReplayOutcome, BoxError> {
        let key = Self::key(ns, id);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_poisoned| "replay store lock poisoned")?;
        if let Some(recorded_until) = entries.get(&key)
            && *recorded_until > now
        {
            return Ok(ReplayOutcome::Replayed);
        }
        if entries.len() >= self.capacity {
            entries.retain(|_, until| *until > now);
            if entries.len() >= self.capacity {
                return Err("replay store is full".into());
            }
        }
        entries.insert(key, expires_at);
        Ok(ReplayOutcome::Fresh)
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn check_and_insert<'a>(
        &'a self,
        ns: ReplayNamespace<'a>,
        id: &'a str,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> ReplayFuture<'a> {
        Box::pin(std::future::ready(
            self.check_and_insert_sync(ns, id, expires_at, now),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const NS: ReplayNamespace<'static> = ReplayNamespace::IdJag {
        issuer: "https://idp.example",
    };

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))
            .unwrap()
    }

    #[tokio::test]
    async fn second_presentation_is_replayed() {
        let store = InMemoryReplayStore::new(8);
        assert_eq!(
            store
                .check_and_insert(NS, "a", at(100), at(10))
                .await
                .unwrap(),
            ReplayOutcome::Fresh
        );
        assert_eq!(
            store
                .check_and_insert(NS, "a", at(100), at(11))
                .await
                .unwrap(),
            ReplayOutcome::Replayed
        );
    }

    #[tokio::test]
    async fn namespaces_are_independent() {
        let store = InMemoryReplayStore::new(8);
        let other = ReplayNamespace::IdJag {
            issuer: "https://other.example",
        };
        let dpop = ReplayNamespace::DpopProof {
            jkt: "https://idp.example",
        };
        for ns in [NS, other, dpop] {
            assert_eq!(
                store
                    .check_and_insert(ns, "a", at(100), at(10))
                    .await
                    .unwrap(),
                ReplayOutcome::Fresh
            );
        }
    }

    #[tokio::test]
    async fn scope_and_id_cannot_be_confused() {
        let store = InMemoryReplayStore::new(8);
        let a = ReplayNamespace::IdJag { issuer: "a:b" };
        let b = ReplayNamespace::IdJag { issuer: "a" };
        assert_eq!(
            store
                .check_and_insert(a, "c", at(100), at(10))
                .await
                .unwrap(),
            ReplayOutcome::Fresh
        );
        assert_eq!(
            store
                .check_and_insert(b, "b:c", at(100), at(10))
                .await
                .unwrap(),
            ReplayOutcome::Fresh
        );
    }

    #[tokio::test]
    async fn expired_entry_is_fresh_again() {
        let store = InMemoryReplayStore::new(8);
        store
            .check_and_insert(NS, "a", at(100), at(10))
            .await
            .unwrap();
        assert_eq!(
            store
                .check_and_insert(NS, "a", at(300), at(200))
                .await
                .unwrap(),
            ReplayOutcome::Fresh
        );
    }

    #[tokio::test]
    async fn full_store_fails_closed_then_recovers() {
        let store = InMemoryReplayStore::new(2);
        store
            .check_and_insert(NS, "a", at(100), at(10))
            .await
            .unwrap();
        store
            .check_and_insert(NS, "b", at(100), at(10))
            .await
            .unwrap();
        store
            .check_and_insert(NS, "c", at(100), at(10))
            .await
            .unwrap_err();
        assert_eq!(
            store
                .check_and_insert(NS, "c", at(300), at(200))
                .await
                .unwrap(),
            ReplayOutcome::Fresh
        );
    }
}
