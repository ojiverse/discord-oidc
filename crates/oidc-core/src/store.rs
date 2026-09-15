//! Short-lived authorization state storage.
//!
//! The production implementation lives in the `AuthorizationState` Durable
//! Object; `InMemoryStore` is a reference implementation for tests and local
//! reasoning. `take_transaction` / `consume_authorization_code` must be
//! atomic check-and-remove operations.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::code::{evaluate_code_exchange, ConsumeDeny, ExchangeCheck, StoredAuthorizationCode};
use crate::transaction::AuthorizationTransaction;

/// Storage backend failure.
#[derive(Debug, thiserror::Error)]
#[error("authorization state storage failure")]
pub struct StoreError;

/// Result of consuming an authorization transaction by upstream state.
#[derive(Debug)]
pub enum TakeTransaction {
    /// No transaction matches the presented `discord_oauth_state`.
    Missing,
    /// A live transaction; it has been removed from storage.
    Active(Box<AuthorizationTransaction>),
    /// The transaction existed but was expired; it has been removed.
    Expired(Box<AuthorizationTransaction>),
}

/// Short-lived state store for authorization transactions and codes.
///
/// Implementations must guarantee that `take_transaction` and
/// `consume_authorization_code` are atomic: no concurrent caller may observe
/// or consume the same record.
pub trait AuthorizationStore {
    /// Persists a new authorization transaction keyed by `discord_oauth_state`.
    fn put_transaction(
        &self,
        tx: &AuthorizationTransaction,
    ) -> impl std::future::Future<Output = Result<(), StoreError>>;

    /// Atomically removes and returns the transaction for `discord_oauth_state`.
    fn take_transaction(
        &self,
        discord_oauth_state: &str,
        now: i64,
    ) -> impl std::future::Future<Output = Result<TakeTransaction, StoreError>>;

    /// Persists a newly issued authorization code record.
    fn put_authorization_code(
        &self,
        code: &StoredAuthorizationCode,
    ) -> impl std::future::Future<Output = Result<(), StoreError>>;

    /// Atomically validates and consumes a code. On success the record is
    /// deleted and returned; `Expired` records are deleted as a side effect;
    /// binding/PKCE mismatches leave the record in place.
    fn consume_authorization_code(
        &self,
        code_hash: &str,
        check: &ExchangeCheck<'_>,
        now: i64,
    ) -> impl std::future::Future<
        Output = Result<Result<StoredAuthorizationCode, ConsumeDeny>, StoreError>,
    >;

    /// Deletes expired transactions and codes. Returns the number removed.
    fn sweep_expired(&self, now: i64)
        -> impl std::future::Future<Output = Result<u64, StoreError>>;
}

/// In-memory [`AuthorizationStore`] for tests. Atomicity is trivially
/// provided by holding the mutex across each check-and-remove.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    transactions: Mutex<HashMap<String, AuthorizationTransaction>>,
    codes: Mutex<HashMap<String, StoredAuthorizationCode>>,
}

impl InMemoryStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live transactions (test helper).
    pub fn transaction_count(&self) -> usize {
        self.transactions.lock().unwrap().len()
    }

    /// Number of live codes (test helper).
    pub fn code_count(&self) -> usize {
        self.codes.lock().unwrap().len()
    }
}

impl AuthorizationStore for InMemoryStore {
    async fn put_transaction(&self, tx: &AuthorizationTransaction) -> Result<(), StoreError> {
        self.transactions
            .lock()
            .unwrap()
            .insert(tx.discord_oauth_state.clone(), tx.clone());
        Ok(())
    }

    async fn take_transaction(
        &self,
        discord_oauth_state: &str,
        now: i64,
    ) -> Result<TakeTransaction, StoreError> {
        let removed = self
            .transactions
            .lock()
            .unwrap()
            .remove(discord_oauth_state);
        Ok(match removed {
            None => TakeTransaction::Missing,
            Some(tx) if tx.is_expired(now) => TakeTransaction::Expired(Box::new(tx)),
            Some(tx) => TakeTransaction::Active(Box::new(tx)),
        })
    }

    async fn put_authorization_code(
        &self,
        code: &StoredAuthorizationCode,
    ) -> Result<(), StoreError> {
        self.codes
            .lock()
            .unwrap()
            .insert(code.code_hash.clone(), code.clone());
        Ok(())
    }

    async fn consume_authorization_code(
        &self,
        code_hash: &str,
        check: &ExchangeCheck<'_>,
        now: i64,
    ) -> Result<Result<StoredAuthorizationCode, ConsumeDeny>, StoreError> {
        let mut codes = self.codes.lock().unwrap();
        let Some(record) = codes.get(code_hash).cloned() else {
            return Ok(Err(ConsumeDeny::Unknown));
        };
        match evaluate_code_exchange(&record, check, now) {
            Ok(()) => {
                codes.remove(code_hash);
                Ok(Ok(record))
            }
            Err(ConsumeDeny::Expired) => {
                codes.remove(code_hash);
                Ok(Err(ConsumeDeny::Expired))
            }
            Err(deny) => Ok(Err(deny)),
        }
    }

    async fn sweep_expired(&self, now: i64) -> Result<u64, StoreError> {
        let mut removed = 0u64;
        self.transactions.lock().unwrap().retain(|_, tx| {
            !tx.is_expired(now) || {
                removed += 1;
                false
            }
        });
        self.codes.lock().unwrap().retain(|_, c| {
            let keep = c.expires_at > now;
            if !keep {
                removed += 1;
            }
            keep
        });
        Ok(removed)
    }
}
