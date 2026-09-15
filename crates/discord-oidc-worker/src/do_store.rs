//! `AuthorizationStore` implementation that delegates to the
//! `AuthorizationState` Durable Object over a stub fetch. All consistency-
//! sensitive work happens inside the DO; this client only serializes calls.

use oidc_core::code::{ConsumeDeny, ExchangeCheck, StoredAuthorizationCode};
use oidc_core::store::{AuthorizationStore, StoreError, TakeTransaction};
use oidc_core::transaction::AuthorizationTransaction;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{Env, Method, Request, RequestInit};

use crate::durable::{ConsumeCodeReply, TakeTransactionReply};

/// Stub client for the singleton `AuthorizationState` object.
pub struct DoStore {
    stub: worker::durable::Stub,
}

impl DoStore {
    /// Resolves the singleton object.
    pub fn from_env(env: &Env) -> worker::Result<Self> {
        let ns = env.durable_object("AUTHORIZATION_STATE")?;
        let id = ns.id_from_name("v1")?;
        Ok(Self {
            stub: id.get_stub()?,
        })
    }

    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, StoreError> {
        let mut init = RequestInit::new();
        init.with_method(method);
        if let Some(b) = body {
            let text = serde_json::to_string(b).map_err(|_| StoreError)?;
            init.with_body(Some(JsValue::from_str(&text)));
        }
        let req = Request::new_with_init(&format!("https://authorization-state{path}"), &init)
            .map_err(|_| StoreError)?;
        if body.is_some() {
            req.headers()
                .set("Content-Type", "application/json")
                .map_err(|_| StoreError)?;
        }
        let mut resp = self
            .stub
            .fetch_with_request(req)
            .await
            .map_err(|_| StoreError)?;
        if !(200..300).contains(&resp.status_code()) {
            return Err(StoreError);
        }
        resp.json::<T>().await.map_err(|_| StoreError)
    }
}

impl AuthorizationStore for DoStore {
    async fn put_transaction(&self, tx: &AuthorizationTransaction) -> Result<(), StoreError> {
        let _: serde_json::Value = self.post(Method::Put, "/transactions", Some(tx)).await?;
        Ok(())
    }

    async fn take_transaction(
        &self,
        discord_oauth_state: &str,
        now: i64,
    ) -> Result<TakeTransaction, StoreError> {
        #[derive(Serialize)]
        struct TakeRequest<'a> {
            discord_oauth_state: &'a str,
            now: i64,
        }
        let reply: TakeTransactionReply = self
            .post(
                Method::Post,
                "/take-transaction",
                Some(&TakeRequest {
                    discord_oauth_state,
                    now,
                }),
            )
            .await?;
        Ok(match reply {
            TakeTransactionReply::Missing => TakeTransaction::Missing,
            TakeTransactionReply::Active(tx) => TakeTransaction::Active(Box::new(tx)),
            TakeTransactionReply::Expired(tx) => TakeTransaction::Expired(Box::new(tx)),
        })
    }

    async fn put_authorization_code(
        &self,
        code: &StoredAuthorizationCode,
    ) -> Result<(), StoreError> {
        let _: serde_json::Value = self.post(Method::Put, "/codes", Some(code)).await?;
        Ok(())
    }

    async fn consume_authorization_code(
        &self,
        code_hash: &str,
        check: &ExchangeCheck<'_>,
        now: i64,
    ) -> Result<Result<StoredAuthorizationCode, ConsumeDeny>, StoreError> {
        #[derive(Serialize)]
        struct ConsumeRequest<'a> {
            code_hash: &'a str,
            client_id: &'a str,
            redirect_uri: &'a str,
            code_verifier: &'a str,
            now: i64,
        }
        let reply: ConsumeCodeReply = self
            .post(
                Method::Post,
                "/consume-code",
                Some(&ConsumeRequest {
                    code_hash,
                    client_id: check.client_id,
                    redirect_uri: check.redirect_uri,
                    code_verifier: check.code_verifier,
                    now,
                }),
            )
            .await?;
        Ok(match reply {
            ConsumeCodeReply::Consumed(record) => Ok(*record),
            ConsumeCodeReply::Denied(deny) => Err(deny),
        })
    }

    async fn sweep_expired(&self, now: i64) -> Result<u64, StoreError> {
        #[derive(Serialize)]
        struct SweepRequest {
            now: i64,
        }
        #[derive(Deserialize)]
        struct SweepReply {
            removed: u64,
        }
        let reply: SweepReply = self
            .post(Method::Post, "/sweep", Some(&SweepRequest { now }))
            .await?;
        Ok(reply.removed)
    }
}
