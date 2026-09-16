//! Dynamic-client data-plane coverage: `/authorize`, the Discord callback,
//! and `/token` driven through `RegistryResolver` (static-first,
//! dynamic-second) with `InMemoryClientRegistry` standing in for the
//! `ClientRegistryState` Durable Object.

mod support;

use oidc_core::registry::{
    ClientMetadata, ClientStatus, DynamicClientRecord, DynamicClientRegistry,
    InMemoryClientRegistry, SECRET_ROTATION_OVERLAP_SECS,
};
use oidc_core::resolver::{ClientResolver, RegistryResolver};
use oidc_core::response::CoreResponse;
use oidc_core::store::{AuthorizationStore, InMemoryStore};
use oidc_core::util::sha256_b64url;
use oidc_core::{handle_authorize, handle_callback, handle_token, ClientType, Config};
use pollster::block_on;
use support::*;

const DYN_REDIRECT: &str = "https://svc.ojiverse.example/auth/callback";
const DYN_REDIRECT_ALT: &str = "https://svc.ojiverse.example/auth/alt";
const DYN_SECRET: &str = "rp-dynamic-secret-value";
const DYN_SECRET_2: &str = "rp-dynamic-secret-rotated";
const DYN_SECRET_3: &str = "rp-dynamic-secret-rotated-again";

fn meta(uris: &[&str]) -> ClientMetadata {
    ClientMetadata {
        display_name: "Dynamic Service".to_string(),
        owner_discord_user_id: DISCORD_USER_ID.to_string(),
        redirect_uris: uris.iter().map(|s| s.to_string()).collect(),
    }
}

/// Registers a dynamic client directly (the admin create path has its own
/// suite; these tests control the registry contents).
fn insert_client(
    reg: &InMemoryClientRegistry,
    client_id: &str,
    client_type: ClientType,
    uris: &[&str],
    secret: Option<&str>,
) -> DynamicClientRecord {
    let record = DynamicClientRecord::new(
        client_id.to_string(),
        meta(uris),
        client_type,
        secret.map(|s| sha256_b64url(s.as_bytes())),
        NOW,
    );
    assert!(block_on(reg.insert(&record)).unwrap());
    record
}

fn authorize_dyn(
    cfg: &Config,
    store: &InMemoryStore,
    resolver: &RegistryResolver<'_, InMemoryClientRegistry>,
    client_id: &str,
    redirect: &str,
) -> CoreResponse {
    let q = authorize_query(&[
        ("client_id", Some(client_id)),
        ("redirect_uri", Some(redirect)),
    ]);
    block_on(handle_authorize(
        &q,
        cfg,
        store,
        resolver,
        &mut entropy(),
        NOW,
    ))
}

/// Issues a provider authorization code for `client_id` through the full
/// authorize→callback path and returns the plaintext code. `seed` must be
/// unique per call within a test so codes don't collide in storage.
fn issue_code(
    cfg: &Config,
    store: &InMemoryStore,
    resolver: &RegistryResolver<'_, InMemoryClientRegistry>,
    client_id: &str,
    redirect: &str,
    seed: u64,
) -> String {
    block_on(issue_code_via_callback_seeded(
        cfg, store, resolver, client_id, redirect, "openid", seed,
    ))
}

#[allow(clippy::too_many_arguments)]
fn exchange(
    cfg: &Config,
    store: &InMemoryStore,
    resolver: &RegistryResolver<'_, InMemoryClientRegistry>,
    client_id: &str,
    redirect: &str,
    code: &str,
    auth: Option<&str>,
    now: i64,
) -> CoreResponse {
    let body = token_body(&[
        ("client_id", Some(client_id)),
        ("redirect_uri", Some(redirect)),
        ("code", Some(code)),
    ]);
    block_on(handle_token(
        &body,
        auth,
        cfg,
        store,
        resolver,
        &test_signer(),
        &mut entropy(),
        now,
    ))
}

// ---------- resolver semantics ----------

#[test]
fn resolver_prefers_static_over_dynamic() {
    // A dynamic record shadowing a static client_id cannot exist through the
    // admin API, but if one ever landed in storage the static definition
    // still wins — including when the dynamic record is disabled.
    let cfg = test_config();
    let reg = InMemoryClientRegistry::new();
    let _shadow = insert_client(
        &reg,
        PUBLIC_CLIENT,
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    block_on(reg.set_status(PUBLIC_CLIENT, ClientStatus::Disabled, NOW)).unwrap();
    let resolver = RegistryResolver::new(&cfg, &reg);
    let client = block_on(resolver.find_client(PUBLIC_CLIENT))
        .unwrap()
        .expect("static client resolves");
    assert_eq!(client.redirect_uris, vec![PUBLIC_REDIRECT.to_string()]);
}

// ---------- /authorize ----------

#[test]
fn authorize_accepts_dynamic_public_and_confidential() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    insert_client(
        &reg,
        "oji_dyn_conf",
        ClientType::Confidential,
        &[DYN_REDIRECT],
        Some(DYN_SECRET),
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    for client_id in ["oji_dyn_pub", "oji_dyn_conf"] {
        let resp = authorize_dyn(&cfg, &store, &resolver, client_id, DYN_REDIRECT);
        let loc = location_of(&resp);
        assert!(
            loc.starts_with("https://discord.com/oauth2/authorize?"),
            "{client_id}: {loc}"
        );
        // The transaction is keyed by the dynamic client_id.
        let state = query_params(&loc)["state"].clone();
        match block_on(store.take_transaction(&state, NOW + 1)) {
            Ok(oidc_core::store::TakeTransaction::Active(tx)) => {
                assert_eq!(tx.oidc_client_id, client_id)
            }
            other => panic!("expected live transaction for {client_id}, got {other:?}"),
        }
    }
}

#[test]
fn authorize_rejects_unknown_and_disabled_dynamic() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    for client_id in ["oji_never_registered", "oji_dyn_pub_disabled"] {
        if client_id == "oji_dyn_pub_disabled" {
            insert_client(&reg, client_id, ClientType::Public, &[DYN_REDIRECT], None);
            block_on(reg.set_status(client_id, ClientStatus::Disabled, NOW)).unwrap();
        }
        let resp = authorize_dyn(&cfg, &store, &resolver, client_id, DYN_REDIRECT);
        // Rejected outright — no redirect to Discord, no transaction.
        let (status, _) = html_of(&resp);
        assert_eq!(status, 400, "{client_id}");
    }
    assert_eq!(store.transaction_count(), 0);
}

#[test]
fn authorize_dynamic_enforces_exact_redirect_match() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT, DYN_REDIRECT_ALT],
        None,
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    // Both registered URIs work.
    for uri in [DYN_REDIRECT, DYN_REDIRECT_ALT] {
        let resp = authorize_dyn(&cfg, &store, &resolver, "oji_dyn_pub", uri);
        assert!(matches!(resp, CoreResponse::Redirect(_)), "{uri}");
    }
    // Unregistered values — including near-misses — render a local error,
    // never a redirect to the attacker's URI.
    for uri in [
        "https://svc.ojiverse.example/auth/callback/evil",
        "https://svc.ojiverse.example/auth/callback?x=1",
        "https://evil.example/auth/callback",
    ] {
        let resp = authorize_dyn(&cfg, &store, &resolver, "oji_dyn_pub", uri);
        let (status, _) = html_of(&resp);
        assert_eq!(status, 400, "{uri}");
    }
}

// ---------- callback ----------

#[test]
fn callback_rejects_client_disabled_mid_flow() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    let discord = MockDiscord::default();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    // /authorize succeeds while the client is active.
    let resp = authorize_dyn(&cfg, &store, &resolver, "oji_dyn_pub", DYN_REDIRECT);
    let state = query_params(&location_of(&resp))["state"].clone();

    // Admin disables the client before Discord redirects back.
    block_on(reg.set_status("oji_dyn_pub", ClientStatus::Disabled, NOW + 1)).unwrap();

    let q = format!("code=discord-auth-code&state={state}");
    let resp = block_on(handle_callback(
        &q,
        &cfg,
        &store,
        &resolver,
        &discord,
        &mut entropy(),
        NOW + 2,
    ));
    let (status, html) = html_of(&resp);
    assert_eq!(status, 403);
    assert!(html.contains("unauthorized_client"));
    // Nothing happened upstream and nothing was issued: no Discord token
    // exchange, no authorization code, no redirect to the RP.
    assert_eq!(discord.exchange_count.get(), 0);
    assert_eq!(store.code_count(), 0);
}

#[test]
fn callback_rejects_client_gone_mid_flow() {
    // Same guarantee when the client_id resolves to nothing at all.
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    let discord = MockDiscord::default();
    let resolver = RegistryResolver::new(&cfg, &reg);
    let tx = block_on(seed_transaction_for(
        &store,
        "oji_ghost",
        DYN_REDIRECT,
        "openid",
    ));
    let q = format!("code=discord-auth-code&state={}", tx.discord_oauth_state);
    let resp = block_on(handle_callback(
        &q,
        &cfg,
        &store,
        &resolver,
        &discord,
        &mut entropy(),
        NOW,
    ));
    let (status, _) = html_of(&resp);
    assert_eq!(status, 403);
    assert_eq!(discord.exchange_count.get(), 0);
    assert_eq!(store.code_count(), 0);
}

#[test]
fn callback_rejects_redirect_uri_removed_mid_flow() {
    // /authorize succeeds with redirect A, then an admin PUT removes A from
    // the client's redirect_uris. The callback must not redirect there —
    // even though the client is still active — and must not touch Discord
    // or issue a code.
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    let discord = MockDiscord::default();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT, DYN_REDIRECT_ALT],
        None,
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    let resp = authorize_dyn(&cfg, &store, &resolver, "oji_dyn_pub", DYN_REDIRECT);
    let state = query_params(&location_of(&resp))["state"].clone();

    // Admin removes the in-flight redirect URI from the registration.
    block_on(reg.update_metadata("oji_dyn_pub", &meta(&[DYN_REDIRECT_ALT]), NOW + 1)).unwrap();

    let q = format!("code=discord-auth-code&state={state}");
    let resp = block_on(handle_callback(
        &q,
        &cfg,
        &store,
        &resolver,
        &discord,
        &mut entropy(),
        NOW + 2,
    ));
    let (status, html) = html_of(&resp);
    assert_eq!(status, 403);
    assert!(html.contains("unauthorized_client"));
    assert_eq!(discord.exchange_count.get(), 0);
    assert_eq!(store.code_count(), 0);
}

#[test]
fn callback_allows_client_reenabled_before_return() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    let discord = MockDiscord::default();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    let resp = authorize_dyn(&cfg, &store, &resolver, "oji_dyn_pub", DYN_REDIRECT);
    let state = query_params(&location_of(&resp))["state"].clone();

    // Disable then re-enable before the callback arrives.
    block_on(reg.set_status("oji_dyn_pub", ClientStatus::Disabled, NOW + 1)).unwrap();
    block_on(reg.set_status("oji_dyn_pub", ClientStatus::Active, NOW + 2)).unwrap();

    let q = format!("code=discord-auth-code&state={state}");
    let resp = block_on(handle_callback(
        &q,
        &cfg,
        &store,
        &resolver,
        &discord,
        &mut entropy(),
        NOW + 3,
    ));
    let loc = location_of(&resp);
    let params = query_params(&loc);
    assert_eq!(params["state"], "rp-state-123");
    assert!(params["code"].len() == 43);
    assert_eq!(discord.exchange_count.get(), 1);
}

// ---------- /token ----------

#[test]
fn token_dynamic_public_pkce_success() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    let resolver = RegistryResolver::new(&cfg, &reg);
    let code = issue_code(&cfg, &store, &resolver, "oji_dyn_pub", DYN_REDIRECT, 1);
    let resp = exchange(
        &cfg,
        &store,
        &resolver,
        "oji_dyn_pub",
        DYN_REDIRECT,
        &code,
        None,
        NOW,
    );
    let (status, json) = json_of(&resp);
    assert_eq!(status, 200);
    let (_, claims, ..) = decode_jwt(json["id_token"].as_str().unwrap());
    assert_eq!(claims["aud"], "oji_dyn_pub");
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], DISCORD_USER_ID);
}

#[test]
fn token_dynamic_confidential_basic_success() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_conf",
        ClientType::Confidential,
        &[DYN_REDIRECT],
        Some(DYN_SECRET),
    );
    let resolver = RegistryResolver::new(&cfg, &reg);
    let code = issue_code(&cfg, &store, &resolver, "oji_dyn_conf", DYN_REDIRECT, 1);
    let auth = basic_auth("oji_dyn_conf", DYN_SECRET);
    let resp = exchange(
        &cfg,
        &store,
        &resolver,
        "oji_dyn_conf",
        DYN_REDIRECT,
        &code,
        Some(&auth),
        NOW,
    );
    let (status, json) = json_of(&resp);
    assert_eq!(status, 200);
    assert_eq!(json["token_type"], "Bearer");
}

#[test]
fn token_dynamic_confidential_wrong_or_missing_secret() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_conf",
        ClientType::Confidential,
        &[DYN_REDIRECT],
        Some(DYN_SECRET),
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    for (i, auth) in [
        Some(basic_auth("oji_dyn_conf", "wrong-secret")),
        // A confidential client that skips Basic entirely is also
        // `invalid_client`, never a public-client exchange.
        None,
    ]
    .into_iter()
    .enumerate()
    {
        let code = issue_code(
            &cfg,
            &store,
            &resolver,
            "oji_dyn_conf",
            DYN_REDIRECT,
            i as u64 + 1,
        );
        let resp = exchange(
            &cfg,
            &store,
            &resolver,
            "oji_dyn_conf",
            DYN_REDIRECT,
            &code,
            auth.as_deref(),
            NOW,
        );
        let (status, json) = json_of(&resp);
        assert_eq!(status, 401, "auth={auth:?}");
        assert_eq!(json["error"], "invalid_client");
        match &resp {
            CoreResponse::Json { extra_headers, .. } => {
                assert!(extra_headers.iter().any(|(k, _)| k == "WWW-Authenticate"))
            }
            _ => unreachable!(),
        }
        // The code was never consumed by the failed attempt.
        assert_eq!(store.code_count(), i + 1);
    }
}

#[test]
fn token_dynamic_public_rejects_basic_header() {
    // Presenting Basic credentials for a public client is an authentication
    // failure, not a downgrade to the public path.
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    let resolver = RegistryResolver::new(&cfg, &reg);
    let code = issue_code(&cfg, &store, &resolver, "oji_dyn_pub", DYN_REDIRECT, 1);
    let auth = basic_auth("oji_dyn_pub", "any-secret");
    let resp = exchange(
        &cfg,
        &store,
        &resolver,
        "oji_dyn_pub",
        DYN_REDIRECT,
        &code,
        Some(&auth),
        NOW,
    );
    let (status, json) = json_of(&resp);
    assert_eq!(status, 401);
    assert_eq!(json["error"], "invalid_client");
}

#[test]
fn token_rotation_overlap_accepts_previous_secret() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_conf",
        ClientType::Confidential,
        &[DYN_REDIRECT],
        Some(DYN_SECRET),
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    // Rotate at NOW: current -> DYN_SECRET_2, previous -> DYN_SECRET until
    // NOW + 600.
    block_on(reg.rotate_secret("oji_dyn_conf", &sha256_b64url(DYN_SECRET_2.as_bytes()), NOW))
        .unwrap();

    // End-to-end within the authorization-code TTL (60s): both the current
    // and the rotated-out previous secret authenticate.
    for (i, secret) in [DYN_SECRET_2, DYN_SECRET].into_iter().enumerate() {
        let code = issue_code(
            &cfg,
            &store,
            &resolver,
            "oji_dyn_conf",
            DYN_REDIRECT,
            i as u64 + 1,
        );
        let auth = basic_auth("oji_dyn_conf", secret);
        let resp = exchange(
            &cfg,
            &store,
            &resolver,
            "oji_dyn_conf",
            DYN_REDIRECT,
            &code,
            Some(&auth),
            NOW + 10,
        );
        let (status, _) = json_of(&resp);
        assert_eq!(status, 200, "secret={secret}");
    }

    // Overlap window boundary at the resolver level: the previous secret is
    // accepted while `now < previous_secret_valid_until` (NOW + 600).
    for (now, expect) in [
        (NOW + SECRET_ROTATION_OVERLAP_SECS - 1, true),
        (NOW + SECRET_ROTATION_OVERLAP_SECS, false),
        (NOW + SECRET_ROTATION_OVERLAP_SECS + 3600, false),
    ] {
        assert_eq!(
            block_on(resolver.verify_client_secret("oji_dyn_conf", DYN_SECRET, now)).unwrap(),
            expect,
            "previous secret at now={now}"
        );
        // The current secret is unaffected by the window.
        assert!(
            block_on(resolver.verify_client_secret("oji_dyn_conf", DYN_SECRET_2, now)).unwrap(),
            "current secret at now={now}"
        );
    }
}

#[test]
fn token_second_rotation_drops_oldest_secret() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_conf",
        ClientType::Confidential,
        &[DYN_REDIRECT],
        Some(DYN_SECRET),
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    block_on(reg.rotate_secret("oji_dyn_conf", &sha256_b64url(DYN_SECRET_2.as_bytes()), NOW))
        .unwrap();
    // Second rotation inside the first overlap: only the immediately
    // previous secret is retained — the original is dead immediately.
    block_on(reg.rotate_secret(
        "oji_dyn_conf",
        &sha256_b64url(DYN_SECRET_3.as_bytes()),
        NOW + 5,
    ))
    .unwrap();

    for (i, (secret, expect)) in [
        (DYN_SECRET, 401u16), // two rotations old — dropped
        (DYN_SECRET_2, 200),  // previous
        (DYN_SECRET_3, 200),  // current
    ]
    .into_iter()
    .enumerate()
    {
        let code = issue_code(
            &cfg,
            &store,
            &resolver,
            "oji_dyn_conf",
            DYN_REDIRECT,
            i as u64 + 1,
        );
        let auth = basic_auth("oji_dyn_conf", secret);
        let resp = exchange(
            &cfg,
            &store,
            &resolver,
            "oji_dyn_conf",
            DYN_REDIRECT,
            &code,
            Some(&auth),
            NOW + 10,
        );
        let (status, _) = json_of(&resp);
        assert_eq!(status, expect, "secret={secret}");
    }
}

#[test]
fn token_rejects_disabled_dynamic_clients() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    insert_client(
        &reg,
        "oji_dyn_pub",
        ClientType::Public,
        &[DYN_REDIRECT],
        None,
    );
    insert_client(
        &reg,
        "oji_dyn_conf",
        ClientType::Confidential,
        &[DYN_REDIRECT],
        Some(DYN_SECRET),
    );
    let resolver = RegistryResolver::new(&cfg, &reg);

    // Codes are issued while both clients are active.
    let pub_code = issue_code(&cfg, &store, &resolver, "oji_dyn_pub", DYN_REDIRECT, 1);
    let conf_code = issue_code(&cfg, &store, &resolver, "oji_dyn_conf", DYN_REDIRECT, 2);

    // Disable both; issued codes cannot be exchanged afterward — the
    // exchange fails authentication before the code is even evaluated.
    block_on(reg.set_status("oji_dyn_pub", ClientStatus::Disabled, NOW)).unwrap();
    block_on(reg.set_status("oji_dyn_conf", ClientStatus::Disabled, NOW)).unwrap();

    let resp = exchange(
        &cfg,
        &store,
        &resolver,
        "oji_dyn_pub",
        DYN_REDIRECT,
        &pub_code,
        None,
        NOW,
    );
    let (status, json) = json_of(&resp);
    assert_eq!(status, 401);
    assert_eq!(json["error"], "invalid_client");

    let auth = basic_auth("oji_dyn_conf", DYN_SECRET);
    let resp = exchange(
        &cfg,
        &store,
        &resolver,
        "oji_dyn_conf",
        DYN_REDIRECT,
        &conf_code,
        Some(&auth),
        NOW,
    );
    let (status, json) = json_of(&resp);
    assert_eq!(status, 401);
    assert_eq!(json["error"], "invalid_client");

    // The failed exchanges did not burn the codes: after re-enable they
    // still work.
    block_on(reg.set_status("oji_dyn_pub", ClientStatus::Active, NOW)).unwrap();
    let resp = exchange(
        &cfg,
        &store,
        &resolver,
        "oji_dyn_pub",
        DYN_REDIRECT,
        &pub_code,
        None,
        NOW,
    );
    let (status, _) = json_of(&resp);
    assert_eq!(status, 200);
}

#[test]
fn token_static_confidential_still_works_via_composite_resolver() {
    // Regression: existing static clients keep working when the resolver is
    // the static+dynamic composite rather than the config itself.
    let cfg = test_config();
    let store = InMemoryStore::new();
    let reg = InMemoryClientRegistry::new();
    let resolver = RegistryResolver::new(&cfg, &reg);
    let code = issue_code(&cfg, &store, &resolver, CONF_CLIENT, CONF_REDIRECT, 1);
    let auth = basic_auth(CONF_CLIENT, CONF_SECRET);
    let resp = exchange(
        &cfg,
        &store,
        &resolver,
        CONF_CLIENT,
        CONF_REDIRECT,
        &code,
        Some(&auth),
        NOW,
    );
    let (status, json) = json_of(&resp);
    assert_eq!(status, 200);
    let (_, claims, ..) = decode_jwt(json["id_token"].as_str().unwrap());
    assert_eq!(claims["aud"], CONF_CLIENT);
}
