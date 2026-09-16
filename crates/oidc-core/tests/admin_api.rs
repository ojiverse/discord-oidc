//! Admin REST API and dynamic client registry coverage: authentication,
//! CRUD semantics, rotation, immutability rules, and response hygiene — all
//! exercised on the host through `handle_admin_request` and
//! `InMemoryClientRegistry`.

mod support;

use oidc_core::admin::{authorize_admin, handle_admin_request};
use oidc_core::registry::{
    generate_client_id, ClientMetadata, ClientStatus, DynamicClientRecord, DynamicClientRegistry,
    InMemoryClientRegistry,
};
use oidc_core::response::CoreResponse;
use oidc_core::util::sha256_b64url;
use oidc_core::{ClientType, Config, TokenEndpointAuthMethod};
use pollster::block_on;
use serde_json::{json, Value};
use support::*;

const ADMIN_TOKEN: &str = "test-admin-token";
const BEARER: &str = "Bearer test-admin-token";

#[allow(clippy::too_many_arguments)]
fn call(
    method: &str,
    path: &str,
    body: Option<&str>,
    authorization: Option<&str>,
    admin_token: Option<&str>,
    cfg: &Config,
    registry: &InMemoryClientRegistry,
    seed: u64,
) -> CoreResponse {
    let mut entropy = seeded_entropy(seed);
    block_on(handle_admin_request(
        method,
        path,
        body,
        authorization,
        admin_token,
        cfg,
        registry,
        &mut entropy,
        NOW,
    ))
}

fn authed(
    method: &str,
    path: &str,
    body: Option<&str>,
    cfg: &Config,
    registry: &InMemoryClientRegistry,
    seed: u64,
) -> (u16, Value) {
    json_of(&call(
        method,
        path,
        body,
        Some(BEARER),
        Some(ADMIN_TOKEN),
        cfg,
        registry,
        seed,
    ))
}

fn create_body(client_type: &str) -> String {
    json!({
        "display_name": "Example OJIverse Service",
        "owner_discord_user_id": DISCORD_USER_ID,
        "redirect_uris": ["https://svc.ojiverse.example/auth/callback"],
        "client_type": client_type,
    })
    .to_string()
}

fn create_client(
    cfg: &Config,
    registry: &InMemoryClientRegistry,
    client_type: &str,
    seed: u64,
) -> Value {
    let (status, body) = authed(
        "POST",
        "/admin/clients",
        Some(&create_body(client_type)),
        cfg,
        registry,
        seed,
    );
    assert_eq!(status, 201, "create failed: {body}");
    body
}

// ---------- admin authentication ----------

#[test]
fn authorize_admin_truth_table() {
    // Unset Worker token: every request is unauthorized regardless of header.
    for auth in [None, Some("Bearer x"), Some(BEARER)] {
        assert!(!authorize_admin(auth, None));
    }
    // Missing, malformed, or wrong token -> unauthorized.
    for auth in [
        None,
        Some(""),
        Some("Bearer"),
        Some("Bearer "),
        Some("bearer test-admin-token"),
        Some("Basic dGVzdA=="),
        Some("Bearer wrong-token"),
        Some(ADMIN_TOKEN),
    ] {
        assert!(!authorize_admin(auth, Some(ADMIN_TOKEN)), "auth: {auth:?}");
    }
    assert!(authorize_admin(Some(BEARER), Some(ADMIN_TOKEN)));
}

#[test]
fn admin_requires_valid_bearer_on_every_route() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    for (method, path) in [
        ("POST", "/admin/clients"),
        ("GET", "/admin/clients"),
        ("GET", "/admin/clients/some-id"),
        ("PUT", "/admin/clients/some-id"),
        ("POST", "/admin/clients/some-id/disable"),
        ("POST", "/admin/clients/some-id/enable"),
        ("POST", "/admin/clients/some-id/rotate-secret"),
    ] {
        for auth in [None, Some("Bearer wrong")] {
            let (status, body) = json_of(&call(
                method,
                path,
                None,
                auth,
                Some(ADMIN_TOKEN),
                &cfg,
                &reg,
                1,
            ));
            assert_eq!(status, 401, "{method} {path} auth={auth:?}");
            assert_eq!(body["error"], "unauthorized");
        }
    }
}

#[test]
fn admin_unset_token_means_401() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let (status, body) = json_of(&call(
        "GET",
        "/admin/clients",
        None,
        Some(BEARER),
        None,
        &cfg,
        &reg,
        1,
    ));
    assert_eq!(status, 401);
    assert_eq!(body["error"], "unauthorized");
}

#[test]
fn admin_responses_are_no_store_without_cors() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    for (method, path) in [
        ("GET", "/admin/clients"),
        ("POST", "/admin/clients"),
        ("GET", "/admin/nowhere"),
    ] {
        let resp = call(
            method,
            path,
            Some(&create_body("public")),
            Some(BEARER),
            Some(ADMIN_TOKEN),
            &cfg,
            &reg,
            1,
        );
        match resp {
            CoreResponse::Json {
                no_store,
                extra_headers,
                ..
            } => {
                assert!(no_store, "{method} {path} missing no-store");
                assert!(
                    !extra_headers
                        .iter()
                        .any(|(k, _)| k.to_lowercase().starts_with("access-control")),
                    "{method} {path} leaked a CORS header"
                );
            }
            other => panic!("expected json for {method} {path}, got {other:?}"),
        }
    }
}

// ---------- create ----------

#[test]
fn create_public_client_shape() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let body = create_client(&cfg, &reg, "public", 1);
    let client_id = body["client_id"].as_str().unwrap();
    assert!(client_id.starts_with("oji_"));
    assert_eq!(client_id.len(), 26); // "oji_" + 22 base64url chars (128 bits)
                                     // Public clients carry no `client_secret` field at all.
    assert!(body.get("client_secret").is_none());
    assert_eq!(body["client_type"], "public");
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(body["allowed_scopes"], json!(["openid"]));
    assert_eq!(body["status"], "active");
    assert_eq!(body["display_name"], "Example OJIverse Service");
    assert_eq!(body["owner_discord_user_id"], DISCORD_USER_ID);
    assert_eq!(body["created_at"], NOW);
    assert_eq!(body["updated_at"], NOW);
    // Persisted record matches; no secret material anywhere.
    let record = block_on(reg.get(client_id)).unwrap().unwrap();
    assert!(record.current_secret_hash.is_none());
    assert_eq!(record.client_type, ClientType::Public);
    assert_eq!(
        record.token_endpoint_auth_method,
        TokenEndpointAuthMethod::None
    );
}

#[test]
fn create_confidential_returns_secret_once() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let body = create_client(&cfg, &reg, "confidential", 1);
    let client_id = body["client_id"].as_str().unwrap();
    let secret = body["client_secret"].as_str().unwrap();
    assert_eq!(secret.len(), 43); // 256-bit base64url
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");

    // Only the SHA-256 hash is persisted; the plaintext never reaches storage.
    let record = block_on(reg.get(client_id)).unwrap().unwrap();
    assert_eq!(
        record.current_secret_hash.as_deref(),
        Some(sha256_b64url(secret.as_bytes()).as_str())
    );
    let serialized = serde_json::to_string(&record).unwrap();
    assert!(!serialized.contains(secret));

    // Neither GET nor LIST ever returns a secret or hash.
    let (_, get_body) = authed(
        "GET",
        &format!("/admin/clients/{client_id}"),
        None,
        &cfg,
        &reg,
        1,
    );
    for field in [
        "client_secret",
        "current_secret_hash",
        "previous_secret_hash",
    ] {
        assert!(get_body.get(field).is_none(), "GET leaked {field}");
    }
    let (_, list_body) = authed("GET", "/admin/clients", None, &cfg, &reg, 1);
    for entry in list_body["clients"].as_array().unwrap() {
        for field in [
            "client_secret",
            "current_secret_hash",
            "previous_secret_hash",
        ] {
            assert!(entry.get(field).is_none(), "list leaked {field}");
        }
    }
}

#[test]
fn create_rejects_invalid_metadata() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let base = json!({
        "display_name": "ok",
        "owner_discord_user_id": DISCORD_USER_ID,
        "redirect_uris": ["https://svc.ojiverse.example/cb"],
        "client_type": "public",
    });
    let long_name = "x".repeat(129);
    let uris_17: Vec<String> = (0..17)
        .map(|i| format!("https://svc.ojiverse.example/cb{i}"))
        .collect();
    for (field, value) in [
        ("display_name", json!("")),
        ("display_name", json!("   ")),
        ("display_name", json!(long_name)),
        ("owner_discord_user_id", json!("not-a-snowflake")),
        ("owner_discord_user_id", json!("12345")),
        ("redirect_uris", json!([])),
        ("redirect_uris", json!(uris_17)),
        (
            "redirect_uris",
            json!(["https://a.example/cb", "https://a.example/cb"]),
        ),
        ("redirect_uris", json!(["not-a-url"])),
        ("redirect_uris", json!(["https://a.example/cb#frag"])),
        ("redirect_uris", json!(["https://a.example/cb/*"])),
        ("client_type", json!("Public")),
        ("client_type", json!("server")),
    ] {
        let mut req = base.clone();
        req[field] = value.clone();
        let (status, body) = authed(
            "POST",
            "/admin/clients",
            Some(&req.to_string()),
            &cfg,
            &reg,
            1,
        );
        assert_eq!(status, 400, "accepted {field}={value}");
        assert_eq!(body["error"], "invalid_request");
    }
    assert_eq!(reg.len(), 0);
}

#[test]
fn create_rejects_unknown_fields_and_bad_json() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    for body in [
        json!({
            "display_name": "x",
            "owner_discord_user_id": DISCORD_USER_ID,
            "redirect_uris": ["https://a.example/cb"],
            "client_type": "public",
            "allowed_scopes": ["openid", "email"],
        })
        .to_string(),
        "{not json".to_string(),
        "".to_string(),
    ] {
        let (status, _) = authed("POST", "/admin/clients", Some(&body), &cfg, &reg, 1);
        assert_eq!(status, 400, "accepted body: {body}");
    }
    // Missing body entirely.
    let (status, _) = authed("POST", "/admin/clients", None, &cfg, &reg, 1);
    assert_eq!(status, 400);
    // Oversized body.
    let big = format!("{{\"display_name\":\"{}\"}}", "x".repeat(9000));
    let (status, _) = authed("POST", "/admin/clients", Some(&big), &cfg, &reg, 1);
    assert_eq!(status, 400);
    assert_eq!(reg.len(), 0);
}

#[test]
fn create_retries_past_dynamic_collision() {
    // Seed the entropy stream and predict the first generated client_id, then
    // occupy it: create must retry and land on the next draw.
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let first_id = generate_client_id(&mut seeded_entropy(7));
    let occupied = DynamicClientRecord::new(
        first_id.clone(),
        ClientMetadata {
            display_name: "taken".to_string(),
            owner_discord_user_id: DISCORD_USER_ID.to_string(),
            redirect_uris: vec!["https://taken.example/cb".to_string()],
        },
        ClientType::Public,
        None,
        NOW,
    );
    assert!(block_on(reg.insert(&occupied)).unwrap());
    // Inserting the same id again is the conflict signal create relies on.
    assert!(!block_on(reg.insert(&occupied)).unwrap());

    let body = create_client(&cfg, &reg, "public", 7);
    assert_ne!(body["client_id"], first_id);
    assert_eq!(reg.len(), 2);
}

#[test]
fn create_never_shadows_static_client_id() {
    // The static registry wins resolution, so a dynamic client colliding
    // with a static client_id would be unreachable; generation skips it.
    let collision_id = generate_client_id(&mut seeded_entropy(11));
    let cfg = test_config_with_clients(json!([
        {
            "client_id": PUBLIC_CLIENT,
            "redirect_uris": [PUBLIC_REDIRECT],
            "allowed_scopes": ["openid"],
            "type": "public",
            "token_endpoint_auth_method": "none",
        },
        {
            "client_id": collision_id,
            "redirect_uris": ["https://static.example/cb"],
            "allowed_scopes": ["openid"],
            "type": "public",
            "token_endpoint_auth_method": "none",
        }
    ]));
    let reg = InMemoryClientRegistry::new();
    let body = create_client(&cfg, &reg, "public", 11);
    assert_ne!(body["client_id"], collision_id);
}

// ---------- read / list ----------

#[test]
fn get_and_list_cover_static_and_dynamic() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let created = create_client(&cfg, &reg, "public", 1);
    let dyn_id = created["client_id"].as_str().unwrap();

    let (status, body) = authed(
        "GET",
        &format!("/admin/clients/{dyn_id}"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 200);
    assert_eq!(body["source"], "dynamic");
    assert_eq!(body["status"], "active");

    // Static clients are readable and marked, without dynamic-only fields.
    let (status, body) = authed(
        "GET",
        &format!("/admin/clients/{PUBLIC_CLIENT}"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 200);
    assert_eq!(body["source"], "static");
    assert_eq!(body["client_id"], PUBLIC_CLIENT);
    for field in [
        "display_name",
        "owner_discord_user_id",
        "status",
        "created_at",
        "updated_at",
        "client_secret",
    ] {
        assert!(body.get(field).is_none(), "static view leaked {field}");
    }

    let (status, body) = authed("GET", "/admin/clients", None, &cfg, &reg, 1);
    assert_eq!(status, 200);
    let clients = body["clients"].as_array().unwrap();
    // 2 static (public + confidential test fixtures) + 1 dynamic.
    assert_eq!(clients.len(), 3);
    let statics: Vec<_> = clients.iter().filter(|c| c["source"] == "static").collect();
    assert_eq!(statics.len(), 2);
    for s in statics {
        assert!(s.get("status").is_none());
        assert!(s.get("display_name").is_none());
    }
    assert!(clients.iter().any(|c| c["client_id"] == dyn_id));
}

#[test]
fn get_unknown_client_is_404() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let (status, body) = authed(
        "GET",
        "/admin/clients/oji_missing_0123456789abcd",
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 404);
    assert_eq!(body["error"], "client_not_found");
}

#[test]
fn malformed_client_id_is_not_found_without_registry_lookup() {
    // A path id outside the dynamic ID format must be rejected before the
    // registry is consulted: `..`, `?`, or wrong-length ids could otherwise
    // alias a stored record through URL normalization in the DO stub URL.
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    for path in [
        "/admin/clients/..",
        "/admin/clients/oji_x%3f..%2fother",
        "/admin/clients/oji_missing_0123456789abc", // one char short
    ] {
        let (status, body) = authed("GET", path, None, &cfg, &reg, 1);
        assert_eq!(status, 404, "{path}");
        assert_eq!(body["error"], "client_not_found", "{path}");
    }
    // Same on a mutation route.
    let (status, body) = authed("POST", "/admin/clients/../disable", None, &cfg, &reg, 1);
    assert_eq!(status, 404);
    assert_eq!(body["error"], "client_not_found");
}

// ---------- update ----------

#[test]
fn update_replaces_exactly_mutable_fields() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let created = create_client(&cfg, &reg, "confidential", 1);
    let id = created["client_id"].as_str().unwrap().to_string();
    let secret = created["client_secret"].as_str().unwrap().to_string();

    let put = json!({
        "display_name": "Renamed Service",
        "owner_discord_user_id": GUILD,
        "redirect_uris": ["https://svc.ojiverse.example/new-cb", "https://svc.ojiverse.example/cb2"],
    });
    let (status, body) = authed(
        "PUT",
        &format!("/admin/clients/{id}"),
        Some(&put.to_string()),
        &cfg,
        &reg,
        2,
    );
    assert_eq!(status, 200);
    assert_eq!(body["display_name"], "Renamed Service");
    assert_eq!(body["owner_discord_user_id"], GUILD);
    assert_eq!(body["redirect_uris"].as_array().unwrap().len(), 2);

    // Immutable fields are untouched; secret survives; status unchanged.
    let record = block_on(reg.get(&id)).unwrap().unwrap();
    assert_eq!(record.client_id, id);
    assert_eq!(record.client_type, ClientType::Confidential);
    assert_eq!(
        record.token_endpoint_auth_method,
        TokenEndpointAuthMethod::ClientSecretBasic
    );
    assert_eq!(record.allowed_scopes, vec!["openid".to_string()]);
    assert_eq!(
        record.current_secret_hash.as_deref(),
        Some(sha256_b64url(secret.as_bytes()).as_str())
    );
    assert_eq!(record.status, ClientStatus::Active);
    assert!(record.updated_at >= record.created_at);

    // Immutable fields / unknown fields in the body are rejected.
    for extra in [
        json!({"client_id": "other"}),
        json!({"client_type": "public"}),
        json!({"status": "disabled"}),
        json!({"allowed_scopes": ["openid"]}),
        json!({"token_endpoint_auth_method": "none"}),
    ] {
        let mut req = json!({
            "display_name": "x",
            "owner_discord_user_id": DISCORD_USER_ID,
            "redirect_uris": ["https://a.example/cb"],
        });
        req.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (status, body) = authed(
            "PUT",
            &format!("/admin/clients/{id}"),
            Some(&req.to_string()),
            &cfg,
            &reg,
            3,
        );
        assert_eq!(status, 400, "accepted extra field {extra}");
        assert_eq!(body["error"], "invalid_request");
    }
}

#[test]
fn update_unknown_is_404_and_static_is_409() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let put = json!({
        "display_name": "x",
        "owner_discord_user_id": DISCORD_USER_ID,
        "redirect_uris": ["https://a.example/cb"],
    })
    .to_string();
    let (status, body) = authed(
        "PUT",
        "/admin/clients/oji_missing_0123456789abcd",
        Some(&put),
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 404);
    assert_eq!(body["error"], "client_not_found");

    let (status, body) = authed(
        "PUT",
        &format!("/admin/clients/{PUBLIC_CLIENT}"),
        Some(&put),
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 409);
    assert_eq!(body["error"], "static_client_immutable");
}

// ---------- disable / enable ----------

#[test]
fn disable_and_enable_are_idempotent() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let id = create_client(&cfg, &reg, "public", 1)["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{id}/disable"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "disabled");
    assert_eq!(body["disabled_at"], NOW);

    // Second disable: same state, no timestamp bump.
    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{id}/disable"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "disabled");
    assert_eq!(body["disabled_at"], NOW);

    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{id}/enable"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "active");
    assert!(body.get("disabled_at").is_none());

    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{id}/enable"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "active");
}

#[test]
fn disable_enable_on_unknown_and_static() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    for action in ["disable", "enable"] {
        let (status, body) = authed(
            "POST",
            &format!("/admin/clients/oji_missing_0123456789abcd/{action}"),
            None,
            &cfg,
            &reg,
            1,
        );
        assert_eq!(status, 404, "{action}");
        assert_eq!(body["error"], "client_not_found");

        let (status, body) = authed(
            "POST",
            &format!("/admin/clients/{PUBLIC_CLIENT}/{action}"),
            None,
            &cfg,
            &reg,
            1,
        );
        assert_eq!(status, 409, "{action}");
        assert_eq!(body["error"], "static_client_immutable");
    }
}

#[test]
fn update_on_disabled_keeps_status() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let id = create_client(&cfg, &reg, "public", 1)["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    authed(
        "POST",
        &format!("/admin/clients/{id}/disable"),
        None,
        &cfg,
        &reg,
        1,
    );
    let put = json!({
        "display_name": "still disabled",
        "owner_discord_user_id": DISCORD_USER_ID,
        "redirect_uris": ["https://svc.ojiverse.example/other"],
    });
    let (status, body) = authed(
        "PUT",
        &format!("/admin/clients/{id}"),
        Some(&put.to_string()),
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "disabled");
    assert_eq!(body["display_name"], "still disabled");
}

// ---------- rotate-secret ----------

#[test]
fn rotate_secret_returns_new_secret_once() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let created = create_client(&cfg, &reg, "confidential", 1);
    let id = created["client_id"].as_str().unwrap().to_string();
    let first_secret = created["client_secret"].as_str().unwrap().to_string();

    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{id}/rotate-secret"),
        None,
        &cfg,
        &reg,
        2,
    );
    assert_eq!(status, 200);
    let new_secret = body["client_secret"].as_str().unwrap();
    assert_eq!(new_secret.len(), 43);
    assert_ne!(new_secret, first_secret);
    assert_eq!(body["previous_secret_valid_until"], NOW + 600);

    let record = block_on(reg.get(&id)).unwrap().unwrap();
    assert_eq!(
        record.current_secret_hash.as_deref(),
        Some(sha256_b64url(new_secret.as_bytes()).as_str())
    );
    assert_eq!(
        record.previous_secret_hash.as_deref(),
        Some(sha256_b64url(first_secret.as_bytes()).as_str())
    );
    // The rotation response is the only place the new plaintext appears.
    let (_, get_body) = authed("GET", &format!("/admin/clients/{id}"), None, &cfg, &reg, 1);
    assert!(get_body.get("client_secret").is_none());
}

#[test]
fn rotate_on_public_is_400_and_static_or_unknown_rejected() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let id = create_client(&cfg, &reg, "public", 1)["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{id}/rotate-secret"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"], "client_has_no_secret");

    let (status, body) = authed(
        "POST",
        "/admin/clients/oji_missing_0123456789abcd/rotate-secret",
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 404);
    assert_eq!(body["error"], "client_not_found");

    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{CONF_CLIENT}/rotate-secret"),
        None,
        &cfg,
        &reg,
        1,
    );
    assert_eq!(status, 409);
    assert_eq!(body["error"], "static_client_immutable");
}

#[test]
fn rotate_on_disabled_keeps_status() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let id = create_client(&cfg, &reg, "confidential", 1)["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    authed(
        "POST",
        &format!("/admin/clients/{id}/disable"),
        None,
        &cfg,
        &reg,
        1,
    );
    let (status, body) = authed(
        "POST",
        &format!("/admin/clients/{id}/rotate-secret"),
        None,
        &cfg,
        &reg,
        2,
    );
    assert_eq!(status, 200);
    assert_eq!(body["client_id"], id);
    let record = block_on(reg.get(&id)).unwrap().unwrap();
    assert_eq!(record.status, ClientStatus::Disabled);
}

// ---------- routing ----------

#[test]
fn no_delete_or_unknown_routes() {
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let id = create_client(&cfg, &reg, "public", 1)["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    for (method, path, expect) in [
        ("DELETE", "/admin/clients", 405u16),
        ("PUT", "/admin/clients", 405),
        ("DELETE", "/admin/clients/{id}", 405),
        ("POST", "/admin/clients/{id}", 405),
        ("GET", "/admin/clients/{id}/disable", 405),
        ("DELETE", "/admin/clients/{id}/disable", 405),
        ("GET", "/admin", 404),
        ("GET", "/admin/", 404),
        ("GET", "/admin/users", 404),
        ("POST", "/admin/clientsfoo", 404),
        ("GET", "/admin/clients/{id}/bogus", 404),
        ("GET", "/admin/clients/a/b/c", 404),
    ] {
        let real = path.replace("{id}", &id);
        let (status, _) = authed(method, &real, None, &cfg, &reg, 1);
        assert_eq!(status, expect, "{method} {real}");
    }
}
