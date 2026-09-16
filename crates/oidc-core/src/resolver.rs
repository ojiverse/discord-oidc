//! Data-plane client resolution across the static and dynamic registries.
//!
//! Protocol handlers never touch storage directly; they resolve clients and
//! verify secrets through [`ClientResolver`]. Resolution is uncached so
//! disable/enable/metadata changes take effect on the next request.
//!
//! Lookup contract: a `client_id` present in the static registry always wins;
//! otherwise the dynamic registry is consulted. `find_client` returns only
//! *active* clients — unknown and disabled clients are indistinguishable in
//! the data plane.

use subtle::ConstantTimeEq;

use crate::client::ClientConfig;
use crate::config::Config;
use crate::registry::{is_dynamic_client_id, DynamicClientRegistry, RegistryStoreError};

/// Resolves OIDC clients for the authorization/token data plane.
///
/// Implementations combine the read-only static registry with the dynamic
/// Durable Object registry; results must not be cached so that registry
/// changes take effect immediately.
pub trait ClientResolver {
    /// Returns the *active* client with this `client_id`, or `None` when the
    /// client is unknown or disabled. Static entries are always active.
    fn find_client(
        &self,
        client_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<ClientConfig>, RegistryStoreError>>;

    /// Verifies a presented `client_secret` for `client_id`. Returns `false`
    /// for unknown or disabled clients, for clients without a secret, and on
    /// mismatch. Comparison is constant-time; dynamic secrets are compared as
    /// SHA-256 hashes and the previous secret is accepted while its rotation
    /// overlap window is open.
    fn verify_client_secret(
        &self,
        client_id: &str,
        presented_secret: &str,
        now: i64,
    ) -> impl std::future::Future<Output = Result<bool, RegistryStoreError>>;
}

/// Static-only resolution: [`Config`] is a valid resolver so tests and
/// fallback paths keep working without a dynamic registry.
impl ClientResolver for Config {
    fn find_client(
        &self,
        client_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<ClientConfig>, RegistryStoreError>> {
        std::future::ready(Ok(self.clients.find(client_id).cloned()))
    }

    fn verify_client_secret(
        &self,
        client_id: &str,
        presented_secret: &str,
        _now: i64,
    ) -> impl std::future::Future<Output = Result<bool, RegistryStoreError>> {
        let ok = self.client_secret(client_id).is_some_and(|expected| {
            bool::from(expected.as_bytes().ct_eq(presented_secret.as_bytes()))
        });
        std::future::ready(Ok(ok))
    }
}

/// Static-first resolver backed by a [`DynamicClientRegistry`].
///
/// The static registry is consulted first; only `client_id`s absent from it
/// fall through to the dynamic registry.
pub struct RegistryResolver<'a, D: DynamicClientRegistry> {
    cfg: &'a Config,
    dynamic: &'a D,
}

impl<'a, D: DynamicClientRegistry> RegistryResolver<'a, D> {
    /// Combines the static registry in `cfg` with the dynamic `registry`.
    pub fn new(cfg: &'a Config, dynamic: &'a D) -> Self {
        Self { cfg, dynamic }
    }
}

impl<D: DynamicClientRegistry> ClientResolver for RegistryResolver<'_, D> {
    async fn find_client(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientConfig>, RegistryStoreError> {
        if let Some(client) = self.cfg.clients.find(client_id) {
            return Ok(Some(client.clone()));
        }
        // Only well-formed dynamic IDs reach the store: an arbitrary request
        // `client_id` is untrusted input, and one containing `/`/`.` segments
        // could alias an existing record through URL normalization inside the
        // Durable Object stub.
        if !is_dynamic_client_id(client_id) {
            return Ok(None);
        }
        let record = self.dynamic.get(client_id).await?;
        Ok(record
            .filter(|r| r.is_active())
            .map(|r| r.to_client_config()))
    }

    async fn verify_client_secret(
        &self,
        client_id: &str,
        presented_secret: &str,
        now: i64,
    ) -> Result<bool, RegistryStoreError> {
        if self.cfg.clients.find(client_id).is_some() {
            return Ok(self.cfg.client_secret(client_id).is_some_and(|expected| {
                bool::from(expected.as_bytes().ct_eq(presented_secret.as_bytes()))
            }));
        }
        // Same format guard as `find_client` — see there.
        if !is_dynamic_client_id(client_id) {
            return Ok(false);
        }
        let Some(record) = self.dynamic.get(client_id).await? else {
            return Ok(false);
        };
        Ok(record.verify_secret(presented_secret, now))
    }
}
