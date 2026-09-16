//! Worker-side `DynamicClientRegistry` implementation.
//!
//! Calls the `ClientRegistryState` Durable Object over its internal contract
//! (`GET/PUT/POST /clients/...`); every mutation is a single stub fetch so
//! the DO's read-modify-write is serialized there.

use oidc_core::registry::{
    ClientMetadata, DynamicClientRecord, DynamicClientRegistry, RegistryStoreError, RotateOutcome,
};
use serde::Serialize;
use wasm_bindgen::JsValue;
use worker::durable::Stub;
use worker::{Env, Method, ObjectNamespace, Request, RequestInit, Response};

use crate::durable::{InsertReply, RotateSecretReply};

/// `DynamicClientRegistry` backed by the `CLIENT_REGISTRY` Durable Object.
pub struct RegistryClient {
    stub: Option<Stub>,
}

impl RegistryClient {
    /// Resolves the registry stub; `None` when the binding is absent (all
    /// operations then fail with a storage error — static clients keep
    /// working since the resolver never reaches the dynamic layer for them).
    pub fn from_env(env: &Env) -> Self {
        let namespace: Option<ObjectNamespace> = env.durable_object("CLIENT_REGISTRY").ok();
        let stub =
            namespace.and_then(|ns| ns.id_from_name("v1").ok().and_then(|id| id.get_stub().ok()));
        Self { stub }
    }

    async fn send<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Response, RegistryStoreError> {
        let Some(stub) = &self.stub else {
            return Err(RegistryStoreError);
        };
        let mut init = RequestInit::new();
        init.with_method(method);
        if let Some(b) = body {
            let text = serde_json::to_string(b).map_err(|_| RegistryStoreError)?;
            init.with_body(Some(JsValue::from_str(&text)));
        }
        let url = format!("https://client-registry{path}");
        let req = Request::new_with_init(&url, &init).map_err(|_| RegistryStoreError)?;
        if body.is_some() {
            req.headers()
                .set("Content-Type", "application/json")
                .map_err(|_| RegistryStoreError)?;
        }
        stub.fetch_with_request(req)
            .await
            .map_err(|_| RegistryStoreError)
    }
}

impl DynamicClientRegistry for RegistryClient {
    async fn get(
        &self,
        client_id: &str,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        let mut resp = self
            .send::<serde_json::Value>(Method::Get, &format!("/clients/{client_id}"), None)
            .await?;
        match resp.status_code() {
            200 => resp.json().await.map(Some).map_err(|_| RegistryStoreError),
            404 => Ok(None),
            _ => Err(RegistryStoreError),
        }
    }

    async fn list(&self) -> Result<Vec<DynamicClientRecord>, RegistryStoreError> {
        let mut resp = self
            .send::<serde_json::Value>(Method::Get, "/clients", None)
            .await?;
        match resp.status_code() {
            200 => resp.json().await.map_err(|_| RegistryStoreError),
            _ => Err(RegistryStoreError),
        }
    }

    async fn insert(&self, record: &DynamicClientRecord) -> Result<bool, RegistryStoreError> {
        let mut resp = self
            .send(
                Method::Put,
                &format!("/clients/{}", record.client_id),
                Some(record),
            )
            .await?;
        match resp.status_code() {
            201 | 409 => resp
                .json::<InsertReply>()
                .await
                .map(|r| r.inserted)
                .map_err(|_| RegistryStoreError),
            _ => Err(RegistryStoreError),
        }
    }

    async fn update_metadata(
        &self,
        client_id: &str,
        metadata: &ClientMetadata,
        now: i64,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        #[derive(Serialize)]
        struct Req<'a> {
            metadata: &'a ClientMetadata,
            now: i64,
        }
        let mut resp = self
            .send(
                Method::Post,
                &format!("/clients/{client_id}/update"),
                Some(&Req { metadata, now }),
            )
            .await?;
        match resp.status_code() {
            200 => resp.json().await.map_err(|_| RegistryStoreError),
            _ => Err(RegistryStoreError),
        }
    }

    async fn set_status(
        &self,
        client_id: &str,
        status: oidc_core::registry::ClientStatus,
        now: i64,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        let action = match status {
            oidc_core::registry::ClientStatus::Active => "enable",
            oidc_core::registry::ClientStatus::Disabled => "disable",
        };
        #[derive(Serialize)]
        struct Req {
            now: i64,
        }
        let mut resp = self
            .send(
                Method::Post,
                &format!("/clients/{client_id}/{action}"),
                Some(&Req { now }),
            )
            .await?;
        match resp.status_code() {
            200 => resp.json().await.map_err(|_| RegistryStoreError),
            _ => Err(RegistryStoreError),
        }
    }

    async fn rotate_secret(
        &self,
        client_id: &str,
        new_secret_hash: &str,
        now: i64,
    ) -> Result<RotateOutcome, RegistryStoreError> {
        #[derive(Serialize)]
        struct Req<'a> {
            new_secret_hash: &'a str,
            now: i64,
        }
        let mut resp = self
            .send(
                Method::Post,
                &format!("/clients/{client_id}/rotate-secret"),
                Some(&Req {
                    new_secret_hash,
                    now,
                }),
            )
            .await?;
        if resp.status_code() != 200 {
            return Err(RegistryStoreError);
        }
        let reply: RotateSecretReply = resp.json().await.map_err(|_| RegistryStoreError)?;
        Ok(match reply {
            RotateSecretReply::Rotated(r) => RotateOutcome::Rotated(r),
            RotateSecretReply::NotFound => RotateOutcome::NotFound,
            RotateSecretReply::NoSecret => RotateOutcome::NoSecret,
        })
    }
}
