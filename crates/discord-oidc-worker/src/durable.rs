//! `AuthorizationState` — the singleton SQLite-backed Durable Object holding
//! authorization transactions and authorization codes. The storage key-value
//! API on a `new_sqlite_classes` object is transactional per event; the check
//! -and-remove operations below run inside one fetch invocation, which the
//! runtime serializes (no `allowConcurrency`), giving atomic consume.

use std::time::Duration;

use oidc_core::code::{evaluate_code_exchange, ConsumeDeny, StoredAuthorizationCode};
use oidc_core::registry::{ClientMetadata, DynamicClientRecord};
use oidc_core::transaction::AuthorizationTransaction;
use serde::{Deserialize, Serialize};
use worker::js_sys;
use worker::{durable_object, DurableObject, Env, Method, Request, Response, State};

/// How often the alarm sweeps expired records.
const SWEEP_INTERVAL: Duration = Duration::from_secs(120);

const TX_PREFIX: &str = "tx:";
const CODE_PREFIX: &str = "code:";

fn tx_key(discord_oauth_state: &str) -> String {
    format!("{TX_PREFIX}{discord_oauth_state}")
}

fn code_key(code_hash: &str) -> String {
    format!("{CODE_PREFIX}{code_hash}")
}

/// Wire reply for `POST /take-transaction`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TakeTransactionReply {
    /// No transaction for the presented state.
    Missing,
    /// Live transaction, consumed.
    Active(AuthorizationTransaction),
    /// Expired transaction, consumed.
    Expired(AuthorizationTransaction),
}

/// Wire reply for `POST /consume-code`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsumeCodeReply {
    /// Code validated and consumed; the record is returned for token issuance.
    Consumed(Box<StoredAuthorizationCode>),
    /// Exchange denied; the record is untouched (expired records are deleted).
    Denied(ConsumeDeny),
}

#[derive(Deserialize)]
struct TakeTransactionRequest {
    discord_oauth_state: String,
    now: i64,
}

#[derive(Deserialize)]
struct ConsumeCodeRequest {
    code_hash: String,
    client_id: String,
    redirect_uri: String,
    code_verifier: String,
    now: i64,
}

#[derive(Deserialize)]
struct SweepRequest {
    now: i64,
}

/// Singleton authorization-state authority.
#[durable_object]
pub struct AuthorizationState {
    state: State,
}

impl AuthorizationState {
    async fn sweep(&self, now: i64) -> worker::Result<u64> {
        let storage = self.state.storage();
        let map = storage.list().await?;
        let mut expired: Vec<String> = Vec::new();
        let mut remaining = 0usize;
        let entries = map.entries();
        loop {
            let next = entries.next()?;
            if next.done() {
                break;
            }
            let pair = js_sys::Array::from(&next.value());
            let key = pair.get(0).as_string().unwrap_or_default();
            let value: serde_json::Value = serde_wasm_bindgen::from_value(pair.get(1))?;
            match value.get("expires_at").and_then(|v| v.as_i64()) {
                Some(expires_at) if expires_at <= now => expired.push(key),
                _ => remaining += 1,
            }
        }
        let removed = expired.len() as u64;
        if !expired.is_empty() {
            storage.delete_multiple(expired).await?;
        }
        if remaining > 0 {
            storage.set_alarm(SWEEP_INTERVAL).await?;
        }
        Ok(removed)
    }

    /// Schedules the sweep alarm if none is pending.
    async fn ensure_alarm(&self) -> worker::Result<()> {
        if self.state.storage().get_alarm().await?.is_none() {
            self.state.storage().set_alarm(SWEEP_INTERVAL).await?;
        }
        Ok(())
    }
}

impl DurableObject for AuthorizationState {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let url = req.url()?;
        let storage = self.state.storage();
        match (req.method(), url.path()) {
            (Method::Put, "/transactions") => {
                let tx: AuthorizationTransaction = req.json().await?;
                storage.put(&tx_key(&tx.discord_oauth_state), &tx).await?;
                self.ensure_alarm().await?;
                Response::from_json(&serde_json::json!({ "ok": true }))
            }
            (Method::Put, "/codes") => {
                let code: StoredAuthorizationCode = req.json().await?;
                storage.put(&code_key(&code.code_hash), &code).await?;
                self.ensure_alarm().await?;
                Response::from_json(&serde_json::json!({ "ok": true }))
            }
            (Method::Post, "/take-transaction") => {
                let body: TakeTransactionRequest = req.json().await?;
                let key = tx_key(&body.discord_oauth_state);
                // Single fetch invocation: get + delete are serialized with
                // respect to other requests — the consume is atomic.
                let reply = match storage.get::<AuthorizationTransaction>(&key).await? {
                    None => TakeTransactionReply::Missing,
                    Some(tx) => {
                        storage.delete(&key).await?;
                        if tx.is_expired(body.now) {
                            TakeTransactionReply::Expired(tx)
                        } else {
                            TakeTransactionReply::Active(tx)
                        }
                    }
                };
                Response::from_json(&reply)
            }
            (Method::Post, "/consume-code") => {
                let body: ConsumeCodeRequest = req.json().await?;
                let key = code_key(&body.code_hash);
                let check = oidc_core::code::ExchangeCheck {
                    client_id: &body.client_id,
                    redirect_uri: &body.redirect_uri,
                    code_verifier: &body.code_verifier,
                };
                let reply = match storage.get::<StoredAuthorizationCode>(&key).await? {
                    None => ConsumeCodeReply::Denied(ConsumeDeny::Unknown),
                    Some(record) => match evaluate_code_exchange(&record, &check, body.now) {
                        Ok(()) => {
                            storage.delete(&key).await?;
                            ConsumeCodeReply::Consumed(Box::new(record))
                        }
                        Err(ConsumeDeny::Expired) => {
                            storage.delete(&key).await?;
                            ConsumeCodeReply::Denied(ConsumeDeny::Expired)
                        }
                        Err(deny) => ConsumeCodeReply::Denied(deny),
                    },
                };
                Response::from_json(&reply)
            }
            (Method::Post, "/sweep") => {
                let body: SweepRequest = req.json().await?;
                let removed = self.sweep(body.now).await?;
                Response::from_json(&serde_json::json!({ "removed": removed }))
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn alarm(&self) -> worker::Result<Response> {
        let now = (worker::Date::now().as_millis() / 1000) as i64;
        self.sweep(now).await?;
        Response::ok("ok")
    }
}

const CLIENT_PREFIX: &str = "client:";

fn client_key(client_id: &str) -> String {
    format!("{CLIENT_PREFIX}{client_id}")
}

/// Wire reply for `PUT /clients/{id}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InsertReply {
    /// Whether the record was inserted (`false` = `client_id` already used).
    pub inserted: bool,
}

/// Wire reply for `POST /clients/{id}/rotate-secret`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RotateSecretReply {
    /// Rotation applied; carries the updated record.
    Rotated(Box<DynamicClientRecord>),
    /// No client with that `client_id`.
    NotFound,
    /// The client has no secret to rotate (public type).
    NoSecret,
}

#[derive(Deserialize)]
struct UpdateMetadataRequest {
    metadata: ClientMetadata,
    now: i64,
}

#[derive(Deserialize)]
struct StatusRequest {
    now: i64,
}

#[derive(Deserialize)]
struct RotateSecretRequest {
    new_secret_hash: String,
    now: i64,
}

/// Singleton dynamic client registry.
///
/// Internal contract (not a public API — only the Worker stub calls it):
///
/// ```text
/// GET  /clients
/// GET  /clients/{client_id}
/// PUT  /clients/{client_id}                 (insert; 409 on existing id)
/// POST /clients/{client_id}/disable
/// POST /clients/{client_id}/enable
/// POST /clients/{client_id}/rotate-secret
/// POST /clients/{client_id}/update          (metadata replace; the one
///                                           endpoint beyond the minimum
///                                           contract, needed for an atomic
///                                           read-modify-write)
/// ```
///
/// Storage adapter only: every endpoint performs its read-modify-write inside
/// one fetch invocation, which the runtime serializes — no concurrent update
/// or rotation can be lost. All validation and transition policy lives in
/// `oidc_core::registry`; this object trusts the Worker (its only caller) to
/// have applied it.
#[durable_object]
pub struct ClientRegistryState {
    state: State,
}

impl ClientRegistryState {
    /// `GET /clients` — all records ordered by `client_id`.
    async fn list(&self) -> worker::Result<Response> {
        let map = self.state.storage().list().await?;
        let mut records: Vec<DynamicClientRecord> = Vec::new();
        let entries = map.entries();
        loop {
            let next = entries.next()?;
            if next.done() {
                break;
            }
            let pair = js_sys::Array::from(&next.value());
            let key = pair.get(0).as_string().unwrap_or_default();
            if !key.starts_with(CLIENT_PREFIX) {
                continue;
            }
            records.push(serde_wasm_bindgen::from_value(pair.get(1))?);
        }
        records.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Response::from_json(&records)
    }

    /// Applies `f` to the stored record and persists it. Returns the
    /// updated record (`None` when absent).
    async fn mutate<F>(&self, client_id: &str, f: F) -> worker::Result<Option<DynamicClientRecord>>
    where
        F: FnOnce(&mut DynamicClientRecord),
    {
        let storage = self.state.storage();
        let key = client_key(client_id);
        let record: Option<DynamicClientRecord> =
            match storage.get::<DynamicClientRecord>(&key).await? {
                Some(mut r) => {
                    f(&mut r);
                    storage.put(&key, &r).await?;
                    Some(r)
                }
                None => None,
            };
        Ok(record)
    }
}

impl DurableObject for ClientRegistryState {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let url = req.url()?;
        let Some(rest) = url.path().strip_prefix("/clients") else {
            return Response::error("not found", 404);
        };
        if rest.is_empty() {
            return match req.method() {
                Method::Get => self.list().await,
                _ => Response::error("method not allowed", 405),
            };
        }
        if !rest.starts_with('/') {
            return Response::error("not found", 404);
        }
        let segments: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
        match (req.method(), segments.as_slice()) {
            (Method::Get, [id]) => {
                let record: Option<DynamicClientRecord> =
                    self.state.storage().get(&client_key(id)).await?;
                match record {
                    Some(r) => Response::from_json(&r),
                    None => Response::error("not found", 404),
                }
            }
            (Method::Put, [id]) => {
                let record: DynamicClientRecord = req.json().await?;
                if &record.client_id != id {
                    return Response::error("client_id mismatch", 400);
                }
                let storage = self.state.storage();
                let key = client_key(id);
                let inserted = storage.get::<serde_json::Value>(&key).await?.is_none();
                if inserted {
                    storage.put(&key, &record).await?;
                }
                Response::from_json(&InsertReply { inserted })
                    .map(|r| r.with_status(if inserted { 201 } else { 409 }))
            }
            (Method::Post, [id, "update"]) => {
                let body: UpdateMetadataRequest = req.json().await?;
                let record = self
                    .mutate(id, |r| r.apply_metadata(body.metadata, body.now))
                    .await?;
                Response::from_json(&record)
            }
            (Method::Post, [id, "disable"]) => {
                let body: StatusRequest = req.json().await?;
                let record = self.mutate(id, |r| r.disable(body.now)).await?;
                Response::from_json(&record)
            }
            (Method::Post, [id, "enable"]) => {
                let body: StatusRequest = req.json().await?;
                let record = self.mutate(id, |r| r.enable(body.now)).await?;
                Response::from_json(&record)
            }
            (Method::Post, [id, "rotate-secret"]) => {
                let body: RotateSecretRequest = req.json().await?;
                let key = client_key(id);
                let storage = self.state.storage();
                let reply = match storage.get::<DynamicClientRecord>(&key).await? {
                    Some(mut r) => match r.rotate_secret(body.new_secret_hash, body.now) {
                        Ok(_) => {
                            storage.put(&key, &r).await?;
                            RotateSecretReply::Rotated(Box::new(r))
                        }
                        Err(_) => RotateSecretReply::NoSecret,
                    },
                    None => RotateSecretReply::NotFound,
                };
                Response::from_json(&reply)
            }
            _ => Response::error("not found", 404),
        }
    }
}
