//! Admin REST API for the dynamic client registry (`/admin/clients/*`).
//!
//! This is a private control-plane API for OJIverse operators — not RFC 7591
//! self-service registration. Every request requires
//! `Authorization: Bearer <OIDC_ADMIN_API_TOKEN>`; the token is compared in
//! constant time and is never logged. All responses are JSON with
//! `Cache-Control: no-store` and no CORS headers.
//!
//! Plaintext client secrets appear exactly once, in the create/rotate
//! response. Nothing here returns `client_secret`, `current_secret_hash`, or
//! `previous_secret_hash` on any other path.

use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use crate::client::{ClientConfig, ClientType};
use crate::config::Config;
use crate::registry::{
    generate_client_id, generate_client_secret, validate_metadata, ClientStatus,
    DynamicClientRecord, DynamicClientRegistry, RotateOutcome,
};
use crate::response::CoreResponse;
use crate::util::Entropy;

/// Maximum accepted admin request body size.
pub const MAX_ADMIN_BODY_LEN: usize = 8192;
/// `client_id` generation retries when the random id collides.
const MAX_ID_ATTEMPTS: usize = 4;

/// Constant-time check of the `Authorization` header against
/// `OIDC_ADMIN_API_TOKEN`. Returns `false` when the token binding is unset —
/// the admin API fails closed rather than exposing its configuration state.
pub fn authorize_admin(authorization: Option<&str>, expected_token: Option<&str>) -> bool {
    let Some(expected) = expected_token else {
        return false;
    };
    let Some(token) = authorization.and_then(|h| h.trim().strip_prefix("Bearer ")) else {
        return false;
    };
    !token.is_empty() && bool::from(token.as_bytes().ct_eq(expected.as_bytes()))
}

/// `POST /admin/clients` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateClientRequest {
    /// Service display name (1..=128 UTF-8 bytes after trimming).
    pub display_name: String,
    /// OJIverse-internal owner contact (Discord snowflake).
    pub owner_discord_user_id: String,
    /// Exact redirect URIs (1..=16, unique).
    pub redirect_uris: Vec<String>,
    /// `public` or `confidential`.
    pub client_type: ClientType,
}

/// `PUT /admin/clients/{client_id}` body — full replacement of the mutable
/// metadata fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateClientRequest {
    /// Service display name.
    pub display_name: String,
    /// Owner contact Discord snowflake.
    pub owner_discord_user_id: String,
    /// Exact redirect URIs.
    pub redirect_uris: Vec<String>,
}

fn admin_error(status: u16, code: &str, description: Option<String>) -> CoreResponse {
    let mut body = json!({ "error": code });
    if let Some(d) = description {
        body["error_description"] = Value::String(d);
    }
    CoreResponse::Json {
        status,
        body,
        no_store: true,
        extra_headers: Vec::new(),
    }
}

fn invalid_request(description: impl Into<String>) -> CoreResponse {
    admin_error(400, "invalid_request", Some(description.into()))
}

fn client_not_found() -> CoreResponse {
    admin_error(404, "client_not_found", None)
}

fn storage_error() -> CoreResponse {
    admin_error(500, "storage_error", None)
}

fn not_found() -> CoreResponse {
    admin_error(404, "not_found", None)
}

fn method_not_allowed() -> CoreResponse {
    admin_error(405, "method_not_allowed", None)
}

/// Public view of a static (legacy) client: registry-defined fields plus
/// `source`. Dynamic-only fields are never present on static entries.
fn static_view(client: &ClientConfig) -> Value {
    json!({
        "client_id": client.client_id,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "client_type": client.client_type,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "source": "static",
    })
}

/// Public view of a dynamic client. `secret` is set only on the
/// create/rotate response — the one time plaintext is returned.
fn dynamic_view(record: &DynamicClientRecord, secret: Option<&str>) -> Value {
    let mut view = json!({
        "client_id": record.client_id,
        "display_name": record.display_name,
        "owner_discord_user_id": record.owner_discord_user_id,
        "redirect_uris": record.redirect_uris,
        "client_type": record.client_type,
        "token_endpoint_auth_method": record.token_endpoint_auth_method,
        "allowed_scopes": record.allowed_scopes,
        "status": record.status,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "source": "dynamic",
    });
    if let Some(disabled_at) = record.disabled_at {
        view["disabled_at"] = json!(disabled_at);
    }
    if let Some(secret) = secret {
        view["client_secret"] = json!(secret);
    }
    view
}

fn parse_body<T: for<'de> Deserialize<'de>>(body: Option<&str>) -> Result<T, CoreResponse> {
    let Some(body) = body else {
        return Err(invalid_request("missing request body"));
    };
    if body.len() > MAX_ADMIN_BODY_LEN {
        return Err(invalid_request("request body too large"));
    }
    serde_json::from_str(body).map_err(|_| invalid_request("malformed JSON body"))
}

fn static_conflict(cfg: &Config, client_id: &str) -> Option<CoreResponse> {
    cfg.clients
        .find(client_id)
        .map(|_| admin_error(409, "static_client_immutable", None))
}

async fn create_client<D: DynamicClientRegistry, E: Entropy>(
    body: Option<&str>,
    cfg: &Config,
    registry: &D,
    entropy: &mut E,
    now: i64,
) -> CoreResponse {
    let req: CreateClientRequest = match parse_body(body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let metadata = match validate_metadata(
        &req.display_name,
        &req.owner_discord_user_id,
        &req.redirect_uris,
    ) {
        Ok(m) => m,
        Err(e) => return invalid_request(e.to_string()),
    };
    let secret =
        (req.client_type == ClientType::Confidential).then(|| generate_client_secret(entropy));
    for _ in 0..MAX_ID_ATTEMPTS {
        let client_id = generate_client_id(entropy);
        // A dynamic client must never shadow a static `client_id`: static
        // lookup wins in the data plane, so a colliding id would be
        // permanently unreachable.
        if cfg.clients.find(&client_id).is_some() {
            continue;
        }
        let record = DynamicClientRecord::new(
            client_id,
            metadata.clone(),
            req.client_type,
            secret.as_ref().map(|s| s.hash.clone()),
            now,
        );
        match registry.insert(&record).await {
            Ok(true) => {
                return CoreResponse::Json {
                    status: 201,
                    body: dynamic_view(&record, secret.as_ref().map(|s| s.plaintext.as_str())),
                    no_store: true,
                    extra_headers: Vec::new(),
                }
            }
            Ok(false) => continue,
            Err(_) => return storage_error(),
        }
    }
    storage_error()
}

async fn list_clients<D: DynamicClientRegistry>(cfg: &Config, registry: &D) -> CoreResponse {
    let dynamic = match registry.list().await {
        Ok(records) => records,
        Err(_) => return storage_error(),
    };
    let mut clients: Vec<Value> = cfg.clients.iter().map(static_view).collect();
    clients.extend(dynamic.iter().map(|r| dynamic_view(r, None)));
    CoreResponse::Json {
        status: 200,
        body: json!({ "clients": clients }),
        no_store: true,
        extra_headers: Vec::new(),
    }
}

async fn get_client<D: DynamicClientRegistry>(
    cfg: &Config,
    registry: &D,
    client_id: &str,
) -> CoreResponse {
    if let Some(client) = cfg.clients.find(client_id) {
        return CoreResponse::Json {
            status: 200,
            body: static_view(client),
            no_store: true,
            extra_headers: Vec::new(),
        };
    }
    match registry.get(client_id).await {
        Ok(Some(record)) => CoreResponse::Json {
            status: 200,
            body: dynamic_view(&record, None),
            no_store: true,
            extra_headers: Vec::new(),
        },
        Ok(None) => client_not_found(),
        Err(_) => storage_error(),
    }
}

async fn update_client<D: DynamicClientRegistry>(
    cfg: &Config,
    registry: &D,
    client_id: &str,
    body: Option<&str>,
    now: i64,
) -> CoreResponse {
    if let Some(resp) = static_conflict(cfg, client_id) {
        return resp;
    }
    let req: UpdateClientRequest = match parse_body(body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let metadata = match validate_metadata(
        &req.display_name,
        &req.owner_discord_user_id,
        &req.redirect_uris,
    ) {
        Ok(m) => m,
        Err(e) => return invalid_request(e.to_string()),
    };
    match registry.update_metadata(client_id, &metadata, now).await {
        Ok(Some(record)) => CoreResponse::Json {
            status: 200,
            body: dynamic_view(&record, None),
            no_store: true,
            extra_headers: Vec::new(),
        },
        Ok(None) => client_not_found(),
        Err(_) => storage_error(),
    }
}

async fn set_status<D: DynamicClientRegistry>(
    cfg: &Config,
    registry: &D,
    client_id: &str,
    status: ClientStatus,
    now: i64,
) -> CoreResponse {
    if let Some(resp) = static_conflict(cfg, client_id) {
        return resp;
    }
    match registry.set_status(client_id, status, now).await {
        Ok(Some(record)) => CoreResponse::Json {
            status: 200,
            body: dynamic_view(&record, None),
            no_store: true,
            extra_headers: Vec::new(),
        },
        Ok(None) => client_not_found(),
        Err(_) => storage_error(),
    }
}

async fn rotate_secret<D: DynamicClientRegistry, E: Entropy>(
    cfg: &Config,
    registry: &D,
    client_id: &str,
    entropy: &mut E,
    now: i64,
) -> CoreResponse {
    if let Some(resp) = static_conflict(cfg, client_id) {
        return resp;
    }
    let secret = generate_client_secret(entropy);
    match registry.rotate_secret(client_id, &secret.hash, now).await {
        Ok(RotateOutcome::Rotated(record)) => CoreResponse::Json {
            status: 200,
            body: json!({
                "client_id": record.client_id,
                "client_secret": secret.plaintext,
                "previous_secret_valid_until": record.previous_secret_valid_until,
            }),
            no_store: true,
            extra_headers: Vec::new(),
        },
        Ok(RotateOutcome::NotFound) => client_not_found(),
        Ok(RotateOutcome::NoSecret) => admin_error(400, "client_has_no_secret", None),
        Err(_) => storage_error(),
    }
}

/// Routes an authenticated admin request. `authorization` is re-checked
/// against `admin_token` so this entry point is self-contained; callers may
/// pre-check with [`authorize_admin`] to skip loading configuration for
/// unauthenticated requests.
///
/// `path` is the request path; only `/admin/clients[...]` routes exist.
/// `body` is the raw request body for POST/PUT routes.
#[allow(clippy::too_many_arguments)]
pub async fn handle_admin_request<D: DynamicClientRegistry, E: Entropy>(
    method: &str,
    path: &str,
    body: Option<&str>,
    authorization: Option<&str>,
    admin_token: Option<&str>,
    cfg: &Config,
    registry: &D,
    entropy: &mut E,
    now: i64,
) -> CoreResponse {
    if !authorize_admin(authorization, admin_token) {
        return admin_error(401, "unauthorized", None);
    }
    let Some(rest) = path.strip_prefix("/admin/clients") else {
        return not_found();
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return not_found();
    }
    let tail = rest.trim_start_matches('/');
    if rest.is_empty() {
        return match method {
            "POST" => create_client(body, cfg, registry, entropy, now).await,
            "GET" => list_clients(cfg, registry).await,
            _ => method_not_allowed(),
        };
    }
    let segments: Vec<&str> = tail.split('/').collect();
    match segments.as_slice() {
        [id] if !id.is_empty() => match method {
            "GET" => get_client(cfg, registry, id).await,
            "PUT" => update_client(cfg, registry, id, body, now).await,
            _ => method_not_allowed(),
        },
        [id, "disable"] if !id.is_empty() => match method {
            "POST" => set_status(cfg, registry, id, ClientStatus::Disabled, now).await,
            _ => method_not_allowed(),
        },
        [id, "enable"] if !id.is_empty() => match method {
            "POST" => set_status(cfg, registry, id, ClientStatus::Active, now).await,
            _ => method_not_allowed(),
        },
        [id, "rotate-secret"] if !id.is_empty() => match method {
            "POST" => rotate_secret(cfg, registry, id, entropy, now).await,
            _ => method_not_allowed(),
        },
        _ => not_found(),
    }
}
