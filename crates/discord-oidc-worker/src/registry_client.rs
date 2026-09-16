//! `DynamicClientRegistry` implementation that delegates to the
//! `ClientRegistryState` Durable Object over a stub fetch. All transitions
//! happen inside the DO; this client only serializes calls.
//!
//! If the `CLIENT_REGISTRY` binding is missing or unresolvable the client
//! still constructs, with every operation failing as `RegistryStoreError` —
//! the data plane degrades to static-clients-only instead of panicking.

use oidc_core::registry::{
    ClientMetadata, ClientStatus, DynamicClientRecord, DynamicClientRegistry, RegistryStoreError,
    RotateOutcome,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{Env, Method, Request, RequestInit};

use crate::durable::{InsertReply, RotateSecretReply};

/// Stub client for the singleton `ClientRegistryState` object.
pub struct RegistryClient {
    stub: Option<worker::durable::Stub>,
}

impl RegistryClient {
    /// Resolves the singleton object; `stub` is `None` when the binding is
    /// unavailable (misconfigured deployment), which surfaces as
    /// `RegistryStoreError` on every call.
    pub fn from_env(env: &Env) -> Self {
        let stub = Self::resolve_stub(env)
            .map_err(|e| {
                worker::console_error!("client registry binding error: {e}");
            })
            .ok();
        Self { stub }
    }

    fn resolve_stub(env: &Env) -> worker::Result<worker::durable::Stub> {
        let ns = env.durable_object("CLIENT_REGISTRY")?;
        let id = ns.id_from_name("v1")?;
        id.get_stub()
    }

    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, RegistryStoreError> {
        let Some(stub) = &self.stub else {
            return Err(RegistryStoreError);
        };
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        let text = serde_json::to_string(body).map_err(|_| RegistryStoreError)?;
        init.with_body(Some(JsValue::from_str(&text)));
        let req = Request::new_with_init(&format!("https://client-registry{path}"), &init)
            .map_err(|_| RegistryStoreError)?;
        req.headers()
            .set("Content-Type", "application/json")
            .map_err(|_| RegistryStoreError)?;
        let mut resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|_| RegistryStoreError)?;
        if !(200..300).contains(&resp.status_code()) {
            return Err(RegistryStoreError);
        }
        resp.json::<T>().await.map_err(|_| RegistryStoreError)
    }
}

impl DynamicClientRegistry for RegistryClient {
    async fn get(
        &self,
        client_id: &str,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        #[derive(Serialize)]
        struct GetRequest<'a> {
            client_id: &'a str,
        }
        self.post("/get", &GetRequest { client_id }).await
    }

    async fn list(&self) -> Result<Vec<DynamicClientRecord>, RegistryStoreError> {
        self.post("/list", &serde_json::json!({})).await
    }

    async fn insert(&self, record: &DynamicClientRecord) -> Result<bool, RegistryStoreError> {
        let reply: InsertReply = self.post("/insert", record).await?;
        Ok(reply.inserted)
    }

    async fn update_metadata(
        &self,
        client_id: &str,
        metadata: &ClientMetadata,
        now: i64,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        #[derive(Serialize)]
        struct UpdateRequest<'a> {
            client_id: &'a str,
            metadata: &'a ClientMetadata,
            now: i64,
        }
        self.post(
            "/update-metadata",
            &UpdateRequest {
                client_id,
                metadata,
                now,
            },
        )
        .await
    }

    async fn set_status(
        &self,
        client_id: &str,
        status: ClientStatus,
        now: i64,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        #[derive(Serialize)]
        struct SetStatusRequest<'a> {
            client_id: &'a str,
            status: ClientStatus,
            now: i64,
        }
        self.post(
            "/set-status",
            &SetStatusRequest {
                client_id,
                status,
                now,
            },
        )
        .await
    }

    async fn rotate_secret(
        &self,
        client_id: &str,
        new_secret_hash: &str,
        now: i64,
    ) -> Result<RotateOutcome, RegistryStoreError> {
        #[derive(Serialize)]
        struct RotateRequest<'a> {
            client_id: &'a str,
            new_secret_hash: &'a str,
            now: i64,
        }
        let reply: RotateSecretReply = self
            .post(
                "/rotate-secret",
                &RotateRequest {
                    client_id,
                    new_secret_hash,
                    now,
                },
            )
            .await?;
        Ok(match reply {
            RotateSecretReply::Rotated(record) => RotateOutcome::Rotated(record),
            RotateSecretReply::NotFound => RotateOutcome::NotFound,
            RotateSecretReply::NoSecret => RotateOutcome::NoSecret,
        })
    }
}
