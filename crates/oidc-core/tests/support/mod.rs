//! Shared fixtures for the host-side test suite: deterministic entropy,
//! config, request/response helpers, and mock upstreams.
#![allow(dead_code)]

use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;

use base64::Engine;
use oidc_core::discord::{DiscordError, DiscordMember, DiscordTokenResponse, DiscordUser};
use oidc_core::jwk::Jwk;
use oidc_core::jwt::{IdTokenSigner, KeyError};
use oidc_core::response::CoreResponse;
use oidc_core::store::{AuthorizationStore, InMemoryStore};
use oidc_core::transaction::AuthorizationTransaction;
use oidc_core::{Config, ConfigInput, Entropy};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const NOW: i64 = 1_800_000_000;
pub const ISSUER: &str = "https://discord.id.ojiverse.example";
pub const PUBLIC_CLIENT: &str = "rp-a-client-id";
pub const PUBLIC_REDIRECT: &str = "https://rp-a.ojiverse.example/auth/callback";
pub const CONF_CLIENT: &str = "rp-b-client-id";
pub const CONF_REDIRECT: &str = "https://rp-b.ojiverse.example/oidc/callback";
pub const CONF_SECRET: &str = "0123456789abcdef-super-secret";
pub const GUILD: &str = "123456789012345678";
pub const DISCORD_USER_ID: &str = "987654321098765432";
pub const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY0123";

pub fn challenge_for(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

pub fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// base64url of a 2048-bit unsigned integer (0x80 followed by zeroes) — a
/// stand-in RSA modulus for JWK structure tests.
pub const TEST_MODULUS_2048: &str = "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ";
/// base64url of a 1024-bit integer — below the accepted key-size floor.
pub const TEST_MODULUS_1024: &str = "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Deterministic stand-in for the platform signing backend (production uses
/// Cloudflare Web Crypto). Produces structurally valid JWTs; cryptographic
/// correctness of the real signer is a runtime property verified against
/// the deployed Worker's JWKS, not on the host.
pub struct TestSigner {
    kid: String,
}

impl TestSigner {
    pub fn new(kid: &str) -> Self {
        Self {
            kid: kid.to_string(),
        }
    }
}

impl IdTokenSigner for TestSigner {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn public_jwk(&self) -> Jwk {
        Jwk::new_rsa(
            TEST_MODULUS_2048.to_string(),
            "AQAB".to_string(),
            self.kid.clone(),
        )
    }

    fn sign(
        &self,
        signing_input: String,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, KeyError>> + '_ {
        let sig = Sha256::digest(format!("{}:{signing_input}", self.kid).as_bytes());
        std::future::ready(Ok(sig.to_vec()))
    }
}

pub fn test_signer() -> TestSigner {
    TestSigner::new("test-key-1")
}

/// Builds a config with the static `PUBLIC_CLIENT` (public) and
/// `CONF_CLIENT` (confidential) registered.
pub fn test_config() -> Config {
    test_config_with_clients(json!([
        {
            "client_id": PUBLIC_CLIENT,
            "redirect_uris": [PUBLIC_REDIRECT],
            "allowed_scopes": ["openid"],
            "type": "public",
            "token_endpoint_auth_method": "none",
        },
        {
            "client_id": CONF_CLIENT,
            "redirect_uris": [CONF_REDIRECT],
            "allowed_scopes": ["openid"],
            "type": "confidential",
            "token_endpoint_auth_method": "client_secret_basic",
        }
    ]))
}

/// Builds a config from a raw `OIDC_CLIENTS_JSON` value; the confidential
/// `CONF_CLIENT` secret is registered whenever that client is present.
pub fn test_config_with_clients(clients: Value) -> Config {
    let has_conf = clients
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["client_id"] == CONF_CLIENT);
    let secrets_json = has_conf.then(|| json!({ CONF_CLIENT: CONF_SECRET }).to_string());
    Config::from_input(&ConfigInput {
        issuer_url: Some(ISSUER.to_string()),
        discord_client_id: Some("111111111111111111".to_string()),
        discord_client_secret: Some("discord-secret".to_string()),
        required_guild_id: Some(GUILD.to_string()),
        clients_json: Some(clients.to_string()),
        client_secrets_json: secrets_json,
        signing_key_id: Some("test-key-1".to_string()),
        signing_private_key: Some("unused-in-these-tests".to_string()),
        ..Default::default()
    })
    .unwrap()
}

/// Deterministic entropy: a seeded stream so successive draws differ.
pub fn entropy() -> impl Entropy {
    let mut rng = StdRng::seed_from_u64(1);
    move |d: &mut [u8]| rng.fill_bytes(d)
}

/// Entropy seeded with `seed` — used to make generated client ids/secrets
/// reproducible for collision tests.
pub fn seeded_entropy(seed: u64) -> impl Entropy {
    let mut rng = StdRng::seed_from_u64(seed);
    move |d: &mut [u8]| rng.fill_bytes(d)
}

pub fn authorize_query(overrides: &[(&str, Option<&str>)]) -> String {
    let mut params: Vec<(String, String)> = vec![
        ("response_type", "code"),
        ("client_id", PUBLIC_CLIENT),
        ("redirect_uri", PUBLIC_REDIRECT),
        ("scope", "openid"),
        ("state", "rp-state-123"),
        ("nonce", "nonce-abc"),
        ("code_challenge_method", "S256"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    params.push(("code_challenge".to_string(), challenge_for(VERIFIER)));
    for (k, v) in overrides {
        params.retain(|(pk, _)| pk != k);
        if let Some(val) = v {
            params.push((k.to_string(), val.to_string()));
        }
    }
    params
        .iter()
        .map(|(k, v)| format!("{}={}", urlenc(k), urlenc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn location_of(resp: &CoreResponse) -> String {
    match resp {
        CoreResponse::Redirect(loc) => loc.clone(),
        other => panic!("expected redirect, got {other:?}"),
    }
}

pub fn json_of(resp: &CoreResponse) -> (u16, Value) {
    match resp {
        CoreResponse::Json { status, body, .. } => (*status, body.clone()),
        other => panic!("expected json, got {other:?}"),
    }
}

pub fn html_of(resp: &CoreResponse) -> (u16, String) {
    match resp {
        CoreResponse::Html { status, body } => (*status, body.clone()),
        other => panic!("expected html, got {other:?}"),
    }
}

pub fn query_params(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Mock Discord API. `exchange_count` records how often `exchange_code` ran
/// so tests can prove no upstream call happened.
#[derive(Clone)]
pub struct MockDiscord {
    pub exchange_status: Option<u16>,
    pub user: Option<DiscordUser>,
    pub member_status: u16,
    pub exchange_count: Rc<Cell<usize>>,
}

impl Default for MockDiscord {
    fn default() -> Self {
        Self {
            exchange_status: None,
            user: Some(DiscordUser {
                id: DISCORD_USER_ID.to_string(),
            }),
            member_status: 200,
            exchange_count: Rc::new(Cell::new(0)),
        }
    }
}

impl oidc_core::DiscordApi for MockDiscord {
    async fn exchange_code(
        &self,
        _code: &str,
        _redirect_uri: &str,
    ) -> Result<DiscordTokenResponse, DiscordError> {
        self.exchange_count.set(self.exchange_count.get() + 1);
        match self.exchange_status {
            None => Ok(DiscordTokenResponse {
                access_token: "discord-access-token".to_string(),
            }),
            Some(status) => Err(DiscordError::HttpStatus(status)),
        }
    }

    async fn fetch_user(&self, _access_token: &str) -> Result<DiscordUser, DiscordError> {
        self.user.clone().ok_or(DiscordError::MalformedResponse)
    }

    async fn fetch_guild_member(
        &self,
        _access_token: &str,
        _guild_id: &str,
    ) -> Result<Option<DiscordMember>, DiscordError> {
        match self.member_status {
            200 => Ok(Some(DiscordMember { roles: vec![] })),
            404 => Ok(None),
            s => Err(DiscordError::HttpStatus(s)),
        }
    }
}

pub fn basic_auth(id: &str, secret: &str) -> String {
    let enc = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        urlenc(id),
        urlenc(secret)
    ));
    format!("Basic {enc}")
}

pub fn token_body(overrides: &[(&str, Option<&str>)]) -> String {
    let mut params = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", "PLACEHOLDER".to_string()),
        ("redirect_uri", PUBLIC_REDIRECT.to_string()),
        ("code_verifier", VERIFIER.to_string()),
        ("client_id", PUBLIC_CLIENT.to_string()),
    ];
    for (k, v) in overrides {
        params.retain(|(pk, _)| pk != k);
        if let Some(val) = v {
            params.push((k, val.to_string()));
        }
    }
    params
        .iter()
        .map(|(k, v)| format!("{}={}", urlenc(k), urlenc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn decode_jwt(token: &str) -> (Value, Value, Vec<u8>, String) {
    let mut parts = token.split('.');
    let (h, p, s) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    assert!(parts.next().is_none());
    let header: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(h)
            .unwrap(),
    )
    .unwrap();
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p)
            .unwrap(),
    )
    .unwrap();
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap();
    (header, claims, sig, format!("{h}.{p}"))
}

pub async fn seed_transaction(store: &InMemoryStore, scope: &str) -> AuthorizationTransaction {
    seed_transaction_for(store, PUBLIC_CLIENT, PUBLIC_REDIRECT, scope).await
}

pub async fn seed_transaction_for(
    store: &InMemoryStore,
    client: &str,
    redirect: &str,
    scope: &str,
) -> AuthorizationTransaction {
    let tx = AuthorizationTransaction::new(
        client.to_string(),
        redirect.to_string(),
        scope.to_string(),
        Some("rp-state-123".to_string()),
        Some("nonce-abc".to_string()),
        challenge_for(VERIFIER),
        &mut entropy(),
        NOW,
    );
    store.put_transaction(&tx).await.unwrap();
    tx
}

/// Drives a transaction through a successful callback and returns the
/// provider-issued plaintext authorization code.
pub async fn issue_code_via_callback<R: oidc_core::ClientResolver + ?Sized>(
    cfg: &Config,
    store: &InMemoryStore,
    resolver: &R,
    client: &str,
    redirect: &str,
    scope: &str,
) -> String {
    issue_code_via_callback_seeded(cfg, store, resolver, client, redirect, scope, 1).await
}

/// Same as [`issue_code_via_callback`] but draws transaction state and code
/// randomness from `seeded_entropy(seed)` so a test can issue multiple
/// distinct codes in one store.
pub async fn issue_code_via_callback_seeded<R: oidc_core::ClientResolver + ?Sized>(
    cfg: &Config,
    store: &InMemoryStore,
    resolver: &R,
    client: &str,
    redirect: &str,
    scope: &str,
    seed: u64,
) -> String {
    let mut e = seeded_entropy(seed);
    let tx = AuthorizationTransaction::new(
        client.to_string(),
        redirect.to_string(),
        scope.to_string(),
        Some("rp-state-123".to_string()),
        Some("nonce-abc".to_string()),
        challenge_for(VERIFIER),
        &mut e,
        NOW,
    );
    store.put_transaction(&tx).await.unwrap();
    let q = format!("code=discord-auth-code&state={}", tx.discord_oauth_state);
    let resp = oidc_core::handle_callback(
        &q,
        cfg,
        store,
        resolver,
        &MockDiscord::default(),
        &mut e,
        NOW,
    )
    .await;
    query_params(&location_of(&resp))["code"].clone()
}
