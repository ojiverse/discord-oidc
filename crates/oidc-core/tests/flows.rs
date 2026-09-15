//! End-to-end coverage of the security properties required of the provider
//! (see docs/SECURITY.md), exercised entirely on the host.

use std::collections::HashMap;

use base64::Engine;
use oidc_core::code::{hash_presented_code, ConsumeDeny, ExchangeCheck};
use oidc_core::discord::{DiscordError, DiscordMember, DiscordTokenResponse, DiscordUser};
use oidc_core::error::OAuthErrorCode;
use oidc_core::jwk::{jwks_document, Jwk, JwkError};
use oidc_core::jwt::{encode_claims, IdTokenSigner, KeyError};
use oidc_core::response::CoreResponse;
use oidc_core::store::{AuthorizationStore, InMemoryStore};
use oidc_core::transaction::AuthorizationTransaction;
use oidc_core::{
    handle_authorize, handle_callback, handle_token, validate_authorize_request, AuthorizeVerdict,
    Config, ConfigInput, Entropy,
};
use pollster::block_on;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000;
const ISSUER: &str = "https://discord.id.ojiverse.example";
const PUBLIC_CLIENT: &str = "rp-a-client-id";
const PUBLIC_REDIRECT: &str = "https://rp-a.ojiverse.example/auth/callback";
const CONF_CLIENT: &str = "rp-b-client-id";
const CONF_REDIRECT: &str = "https://rp-b.ojiverse.example/oidc/callback";
const CONF_SECRET: &str = "0123456789abcdef-super-secret";
const GUILD: &str = "123456789012345678";
const DISCORD_USER_ID: &str = "987654321098765432";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY0123";

fn challenge_for(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// base64url of a 2048-bit unsigned integer (0x80 followed by zeroes) — a
/// stand-in RSA modulus for JWK structure tests.
const TEST_MODULUS_2048: &str = "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ";
/// base64url of a 1024-bit integer — below the accepted key-size floor.
const TEST_MODULUS_1024: &str = "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Deterministic stand-in for the platform signing backend (production uses
/// Cloudflare Web Crypto). Produces structurally valid JWTs; cryptographic
/// correctness of the real signer is a runtime property verified against
/// the deployed Worker's JWKS, not on the host.
struct TestSigner {
    kid: String,
}

impl TestSigner {
    fn new(kid: &str) -> Self {
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

fn test_signer() -> TestSigner {
    TestSigner::new("test-key-1")
}

fn test_config() -> Config {
    let clients_json = json!([
        {
            "client_id": PUBLIC_CLIENT,
            "redirect_uris": [PUBLIC_REDIRECT],
            "allowed_scopes": ["openid", "profile"],
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
    ])
    .to_string();
    let secrets_json = json!({ CONF_CLIENT: CONF_SECRET }).to_string();
    Config::from_input(&ConfigInput {
        issuer_url: Some(ISSUER.to_string()),
        discord_client_id: Some("111111111111111111".to_string()),
        discord_client_secret: Some("discord-secret".to_string()),
        required_guild_id: Some(GUILD.to_string()),
        clients_json: Some(clients_json),
        client_secrets_json: Some(secrets_json),
        signing_key_id: Some("test-key-1".to_string()),
        signing_private_key: Some("unused-in-these-tests".to_string()),
        ..Default::default()
    })
    .unwrap()
}

fn entropy() -> impl Entropy {
    let mut rng = StdRng::seed_from_u64(1);
    move |d: &mut [u8]| rng.fill_bytes(d)
}

fn authorize_query(overrides: &[(&str, Option<&str>)]) -> String {
    let mut params: Vec<(String, String)> = vec![
        ("response_type", "code"),
        ("client_id", PUBLIC_CLIENT),
        ("redirect_uri", PUBLIC_REDIRECT),
        ("scope", "openid profile"),
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

fn location_of(resp: &CoreResponse) -> String {
    match resp {
        CoreResponse::Redirect(loc) => loc.clone(),
        other => panic!("expected redirect, got {other:?}"),
    }
}

fn json_of(resp: &CoreResponse) -> (u16, Value) {
    match resp {
        CoreResponse::Json { status, body, .. } => (*status, body.clone()),
        other => panic!("expected json, got {other:?}"),
    }
}

fn query_params(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

struct MockDiscord {
    exchange_status: Option<u16>,
    user: Option<DiscordUser>,
    member_status: u16,
}

impl Default for MockDiscord {
    fn default() -> Self {
        Self {
            exchange_status: None,
            user: Some(DiscordUser {
                id: DISCORD_USER_ID.to_string(),
                username: Some("tester".to_string()),
                global_name: Some("Test User".to_string()),
                avatar: Some("abc123".to_string()),
            }),
            member_status: 200,
        }
    }
}

impl oidc_core::DiscordApi for MockDiscord {
    async fn exchange_code(
        &self,
        _code: &str,
        _redirect_uri: &str,
    ) -> Result<DiscordTokenResponse, DiscordError> {
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

fn basic_auth(id: &str, secret: &str) -> String {
    let enc = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        urlenc(id),
        urlenc(secret)
    ));
    format!("Basic {enc}")
}

fn token_body(overrides: &[(&str, Option<&str>)]) -> String {
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

fn decode_jwt(token: &str) -> (Value, Value, Vec<u8>, String) {
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

async fn seed_transaction(store: &InMemoryStore, scope: &str) -> AuthorizationTransaction {
    let tx = AuthorizationTransaction::new(
        PUBLIC_CLIENT.to_string(),
        PUBLIC_REDIRECT.to_string(),
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
async fn issue_code_via_callback(
    cfg: &Config,
    store: &InMemoryStore,
    client: &str,
    redirect: &str,
    scope: &str,
) -> String {
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
    let q = format!("code=discord-auth-code&state={}", tx.discord_oauth_state);
    let resp = handle_callback(&q, cfg, store, &MockDiscord::default(), &mut entropy(), NOW).await;
    query_params(&location_of(&resp))["code"].clone()
}

// ---------- /authorize ----------

#[test]
fn authorize_rejects_unknown_client() {
    let cfg = test_config();
    let q = authorize_query(&[("client_id", Some("nobody"))]);
    match validate_authorize_request(&q, &cfg) {
        AuthorizeVerdict::RenderError { status, .. } => assert_eq!(status, 400),
        other => panic!("expected render error, got {other:?}"),
    }
}

#[test]
fn authorize_rejects_nonexact_redirect_uri() {
    let cfg = test_config();
    for uri in [
        "https://rp-a.ojiverse.example/auth/callback/evil",
        "https://rp-a.ojiverse.example/auth/callback?x=1",
        "https://evil.ojiverse.example/auth/callback",
        "https://rp-a.ojiverse.example.evil.com/auth/callback",
    ] {
        let q = authorize_query(&[("redirect_uri", Some(uri))]);
        match validate_authorize_request(&q, &cfg) {
            AuthorizeVerdict::RenderError { status, .. } => assert_eq!(status, 400),
            other => panic!("expected render error for {uri}, got {other:?}"),
        }
    }
}

#[test]
fn authorize_rejects_missing_openid_scope() {
    let cfg = test_config();
    let q = authorize_query(&[("scope", Some("profile"))]);
    match validate_authorize_request(&q, &cfg) {
        AuthorizeVerdict::RedirectError {
            redirect_uri,
            code,
            state,
            ..
        } => {
            assert_eq!(redirect_uri, PUBLIC_REDIRECT);
            assert_eq!(code, OAuthErrorCode::InvalidScope);
            assert_eq!(state.as_deref(), Some("rp-state-123"));
        }
        other => panic!("expected redirect invalid_scope, got {other:?}"),
    }
}

#[test]
fn authorize_rejects_scope_outside_allowlist() {
    let cfg = test_config();
    let q = authorize_query(&[("scope", Some("openid email"))]);
    match validate_authorize_request(&q, &cfg) {
        AuthorizeVerdict::RedirectError { code, .. } => {
            assert_eq!(code, OAuthErrorCode::InvalidScope)
        }
        other => panic!("expected redirect invalid_scope, got {other:?}"),
    }
}

#[test]
fn authorize_rejects_wrong_response_type() {
    let cfg = test_config();
    let q = authorize_query(&[("response_type", Some("token"))]);
    match validate_authorize_request(&q, &cfg) {
        AuthorizeVerdict::RedirectError { code, .. } => {
            assert_eq!(code, OAuthErrorCode::UnsupportedResponseType)
        }
        other => panic!("expected unsupported_response_type, got {other:?}"),
    }
}

#[test]
fn authorize_rejects_bad_pkce() {
    let cfg = test_config();
    for q in [
        // Missing challenge.
        authorize_query(&[("code_challenge", None)]),
        // `plain` method is rejected.
        authorize_query(&[("code_challenge_method", Some("plain"))]),
        // Missing method.
        authorize_query(&[("code_challenge_method", None)]),
        // Too-short challenge.
        {
            let mut q = authorize_query(&[("code_challenge", None)]);
            q.push_str("&code_challenge=short");
            q
        },
    ] {
        match validate_authorize_request(&q, &cfg) {
            AuthorizeVerdict::RedirectError { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidRequest, "query: {q}")
            }
            other => panic!("expected redirect invalid_request for {q}, got {other:?}"),
        }
    }
}

#[test]
fn authorize_happy_path_redirects_to_discord() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let q = authorize_query(&[]);
    let resp = block_on(handle_authorize(&q, &cfg, &store, &mut entropy(), NOW));
    let loc = location_of(&resp);
    assert!(loc.starts_with("https://discord.com/oauth2/authorize?"));
    let p = query_params(&loc);
    assert_eq!(p["client_id"], "111111111111111111");
    assert_eq!(
        p["redirect_uri"],
        format!("{ISSUER}/oauth/discord/callback")
    );
    assert_eq!(p["scope"], "identify guilds.members.read");
    assert_eq!(p["response_type"], "code");
    assert_eq!(p["state"].len(), 43); // 256-bit base64url
    assert_eq!(store.transaction_count(), 1);
}

#[test]
fn authorize_rejects_duplicate_params() {
    let cfg = test_config();
    let mut q = authorize_query(&[]);
    q.push_str("&nonce=second");
    match validate_authorize_request(&q, &cfg) {
        AuthorizeVerdict::RedirectError { code, .. } => {
            assert_eq!(code, OAuthErrorCode::InvalidRequest)
        }
        other => panic!("expected redirect invalid_request, got {other:?}"),
    }
}

#[test]
fn authorize_ignores_unrecognized_parameters() {
    // The authorization server must ignore unrecognized request parameters —
    // OIDC extension params sent by conforming clients must not break the
    // flow, even when duplicated or over-length.
    let cfg = test_config();
    let mut q = authorize_query(&[]);
    q.push_str("&prompt=consent&login_hint=u&resource=https://api.example&prompt=again");
    match validate_authorize_request(&q, &cfg) {
        AuthorizeVerdict::Proceed(_) => {}
        other => panic!("expected proceed, got {other:?}"),
    }
}

// ---------- /oauth/discord/callback ----------

#[test]
fn callback_rejects_unknown_state() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let resp = block_on(handle_callback(
        "code=x&state=unknown-state",
        &cfg,
        &store,
        &MockDiscord::default(),
        &mut entropy(),
        NOW,
    ));
    match resp {
        CoreResponse::Html { status, .. } => assert_eq!(status, 400),
        other => panic!("expected rendered error, got {other:?}"),
    }
}

#[test]
fn callback_forwards_discord_error_with_rp_state() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let tx = block_on(seed_transaction(&store, "openid profile"));
    let resp = block_on(handle_callback(
        &format!("error=access_denied&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &MockDiscord::default(),
        &mut entropy(),
        NOW,
    ));
    let loc = location_of(&resp);
    let p = query_params(&loc);
    assert!(loc.starts_with(PUBLIC_REDIRECT));
    assert_eq!(p["error"], "access_denied");
    assert_eq!(p["state"], "rp-state-123");
    // Transaction is consumed — replaying the same upstream state fails.
    let resp = block_on(handle_callback(
        &format!("code=x&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &MockDiscord::default(),
        &mut entropy(),
        NOW,
    ));
    assert!(matches!(resp, CoreResponse::Html { status: 400, .. }));
}

#[test]
fn callback_expired_transaction_redirects_error() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let tx = block_on(seed_transaction(&store, "openid"));
    let resp = block_on(handle_callback(
        &format!("code=x&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &MockDiscord::default(),
        &mut entropy(),
        NOW + 601,
    ));
    let p = query_params(&location_of(&resp));
    assert_eq!(p["error"], "temporarily_unavailable");
    assert_eq!(p["state"], "rp-state-123");
}

#[test]
fn callback_exchange_failure_is_server_error() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let tx = block_on(seed_transaction(&store, "openid"));
    let discord = MockDiscord {
        exchange_status: Some(400),
        ..Default::default()
    };
    let resp = block_on(handle_callback(
        &format!("code=x&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &discord,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(query_params(&location_of(&resp))["error"], "server_error");
}

#[test]
fn callback_rejects_malformed_user_id() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let tx = block_on(seed_transaction(&store, "openid"));
    let discord = MockDiscord {
        user: Some(DiscordUser {
            id: "not-a-snowflake".to_string(),
            username: None,
            global_name: None,
            avatar: None,
        }),
        ..Default::default()
    };
    let resp = block_on(handle_callback(
        &format!("code=x&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &discord,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(query_params(&location_of(&resp))["error"], "server_error");
}

#[test]
fn callback_denies_non_guild_member() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let tx = block_on(seed_transaction(&store, "openid"));
    let discord = MockDiscord {
        member_status: 404,
        ..Default::default()
    };
    let resp = block_on(handle_callback(
        &format!("code=x&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &discord,
        &mut entropy(),
        NOW,
    ));
    let p = query_params(&location_of(&resp));
    assert_eq!(p["error"], "access_denied");
    assert_eq!(p["state"], "rp-state-123");
}

#[test]
fn callback_guild_api_failure_fails_closed() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let tx = block_on(seed_transaction(&store, "openid"));
    let discord = MockDiscord {
        member_status: 500,
        ..Default::default()
    };
    let resp = block_on(handle_callback(
        &format!("code=x&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &discord,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(query_params(&location_of(&resp))["error"], "server_error");
}

#[test]
fn callback_success_issues_bound_code() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let tx = block_on(seed_transaction(&store, "openid profile"));
    let resp = block_on(handle_callback(
        &format!("code=x&state={}", tx.discord_oauth_state),
        &cfg,
        &store,
        &MockDiscord::default(),
        &mut entropy(),
        NOW,
    ));
    let loc = location_of(&resp);
    let p = query_params(&loc);
    assert!(loc.starts_with(PUBLIC_REDIRECT));
    assert_eq!(p["state"], "rp-state-123");
    let code = &p["code"];
    assert_eq!(code.len(), 43);
    assert_eq!(store.code_count(), 1);
    // Only the hash is stored; the record is bound to the transaction values.
    let check = ExchangeCheck {
        client_id: PUBLIC_CLIENT,
        redirect_uri: PUBLIC_REDIRECT,
        code_verifier: VERIFIER,
    };
    let outcome =
        block_on(store.consume_authorization_code(&hash_presented_code(code), &check, NOW))
            .unwrap();
    let record = outcome.unwrap();
    assert_eq!(record.subject, DISCORD_USER_ID);
    assert_eq!(record.expires_at, NOW + 60);
    assert_eq!(record.client_id, PUBLIC_CLIENT);
    assert_eq!(record.nonce.as_deref(), Some("nonce-abc"));
}

// ---------- /token ----------

#[test]
fn token_full_flow_issues_valid_id_token() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let code = block_on(issue_code_via_callback(
        &cfg,
        &store,
        PUBLIC_CLIENT,
        PUBLIC_REDIRECT,
        "openid profile",
    ));
    let body = token_body(&[("code", Some(&code))]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    let CoreResponse::Json {
        status,
        body: json,
        no_store,
        ..
    } = &resp
    else {
        panic!("expected json")
    };
    assert_eq!(*status, 200);
    assert!(no_store);
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 900);
    assert_eq!(json["scope"], "openid profile");
    assert_eq!(json["access_token"].as_str().unwrap().len(), 43);

    let id_token = json["id_token"].as_str().unwrap();
    let (header, claims, sig, input) = decode_jwt(id_token);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["kid"], "test-key-1");
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], DISCORD_USER_ID);
    assert_eq!(claims["aud"], PUBLIC_CLIENT);
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["exp"], NOW + 900);
    assert_eq!(claims["nonce"], "nonce-abc");
    assert_eq!(claims["preferred_username"], "tester");
    assert_eq!(claims["name"], "Test User");
    assert!(claims["picture"]
        .as_str()
        .unwrap()
        .starts_with("https://cdn.discordapp.com/avatars/"));
    let digest = Sha256::digest(json["access_token"].as_str().unwrap().as_bytes());
    let expected_ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16]);
    assert_eq!(claims["at_hash"], expected_ath);

    // The deterministic TestSigner binds the signature to the signing input.
    let expected_sig = Sha256::digest(format!("test-key-1:{input}").as_bytes());
    assert_eq!(sig.as_slice(), expected_sig.as_slice());
}

#[test]
fn token_rejects_wrong_grant_type() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let body = token_body(&[("grant_type", Some("implicit"))]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    let (status, json) = json_of(&resp);
    assert_eq!(status, 400);
    assert_eq!(json["error"], "unsupported_grant_type");
}

#[test]
fn token_rejects_unknown_code() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let body = token_body(&[("code", Some("nonexistent-code"))]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&resp).1["error"], "invalid_grant");
}

#[test]
fn token_rejects_expired_code() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let code = block_on(issue_code_via_callback(
        &cfg,
        &store,
        PUBLIC_CLIENT,
        PUBLIC_REDIRECT,
        "openid",
    ));
    let body = token_body(&[("code", Some(&code))]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW + 61,
    ));
    assert_eq!(json_of(&resp).1["error"], "invalid_grant");
}

#[test]
fn token_rejects_reused_code() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let code = block_on(issue_code_via_callback(
        &cfg,
        &store,
        PUBLIC_CLIENT,
        PUBLIC_REDIRECT,
        "openid",
    ));
    let body = token_body(&[("code", Some(&code))]);
    let first = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&first).0, 200);
    let second = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&second).1["error"], "invalid_grant");
}

#[test]
fn token_rejects_wrong_client() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    // Code issued to the public client; exchange attempt as the confidential
    // client (authenticates fine, but the binding fails).
    let code = block_on(issue_code_via_callback(
        &cfg,
        &store,
        PUBLIC_CLIENT,
        PUBLIC_REDIRECT,
        "openid",
    ));
    let body = token_body(&[
        ("code", Some(&code)),
        ("client_id", None),
        ("redirect_uri", Some(CONF_REDIRECT)),
    ]);
    let resp = block_on(handle_token(
        &body,
        Some(&basic_auth(CONF_CLIENT, CONF_SECRET)),
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&resp).1["error"], "invalid_grant");
}

#[test]
fn token_rejects_wrong_redirect_uri() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let code = block_on(issue_code_via_callback(
        &cfg,
        &store,
        PUBLIC_CLIENT,
        PUBLIC_REDIRECT,
        "openid",
    ));
    let body = token_body(&[
        ("code", Some(&code)),
        ("redirect_uri", Some("https://rp-a.ojiverse.example/other")),
    ]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&resp).1["error"], "invalid_grant");
}

#[test]
fn token_rejects_wrong_verifier() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let code = block_on(issue_code_via_callback(
        &cfg,
        &store,
        PUBLIC_CLIENT,
        PUBLIC_REDIRECT,
        "openid",
    ));
    let body = token_body(&[
        ("code", Some(&code)),
        (
            "code_verifier",
            Some("zbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY0zzz"),
        ),
    ]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&resp).1["error"], "invalid_grant");
}

#[test]
fn token_confidential_requires_basic_auth() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let body = token_body(&[
        ("client_id", Some(CONF_CLIENT)),
        ("redirect_uri", Some(CONF_REDIRECT)),
    ]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    match resp {
        CoreResponse::Json {
            status,
            extra_headers,
            ..
        } => {
            assert_eq!(status, 401);
            assert!(extra_headers
                .iter()
                .any(|(k, v)| k == "WWW-Authenticate" && v.starts_with("Basic")));
        }
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn token_rejects_bad_secret() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let body = token_body(&[("client_id", None), ("redirect_uri", Some(CONF_REDIRECT))]);
    let resp = block_on(handle_token(
        &body,
        Some(&basic_auth(CONF_CLIENT, "wrong-secret-value")),
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    let (status, json) = json_of(&resp);
    assert_eq!(status, 401);
    assert_eq!(json["error"], "invalid_client");
}

#[test]
fn token_confidential_full_flow() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let code = block_on(issue_code_via_callback(
        &cfg,
        &store,
        CONF_CLIENT,
        CONF_REDIRECT,
        "openid",
    ));
    let body = token_body(&[
        ("client_id", None),
        ("code", Some(&code)),
        ("redirect_uri", Some(CONF_REDIRECT)),
    ]);
    let resp = block_on(handle_token(
        &body,
        Some(&basic_auth(CONF_CLIENT, CONF_SECRET)),
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    let (status, json) = json_of(&resp);
    assert_eq!(status, 200);
    let (_, claims, _, _) = decode_jwt(json["id_token"].as_str().unwrap());
    assert_eq!(claims["aud"], CONF_CLIENT);
    // No profile scope granted -> no profile claims.
    assert!(claims.get("preferred_username").is_none());
    assert!(claims.get("picture").is_none());
}

#[test]
fn token_rejects_unknown_client_body() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let body = token_body(&[("client_id", Some("nobody"))]);
    let resp = block_on(handle_token(
        &body,
        None,
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    let (status, json) = json_of(&resp);
    assert_eq!(status, 401);
    assert_eq!(json["error"], "invalid_client");
}

#[test]
fn token_rejects_basic_with_public_client() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let body = token_body(&[("client_id", None)]);
    let resp = block_on(handle_token(
        &body,
        Some(&basic_auth(PUBLIC_CLIENT, "anything")),
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&resp).0, 401);
}

#[test]
fn token_rejects_client_id_mismatch_basic_vs_body() {
    let cfg = test_config();
    let store = InMemoryStore::new();
    let signer = test_signer();
    let body = token_body(&[("client_id", Some(PUBLIC_CLIENT))]);
    let resp = block_on(handle_token(
        &body,
        Some(&basic_auth(CONF_CLIENT, CONF_SECRET)),
        &cfg,
        &store,
        &signer,
        &mut entropy(),
        NOW,
    ));
    assert_eq!(json_of(&resp).0, 401);
}

// ---------- JWKS / discovery / key rotation ----------

#[test]
fn jwks_contains_only_public_material() {
    let signer = test_signer();
    let jwk = signer.public_jwk();
    let doc = jwks_document(&[jwk]);
    let text = doc.to_string();
    for field in ["\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\""] {
        assert!(!text.contains(field), "JWKS leaked {field}");
    }
    let key = &doc["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["kid"], "test-key-1");
}

#[test]
fn additional_jwks_rejects_private_material() {
    let evil = json!({"kty":"RSA","n":"abc","e":"AQAB","d":"secret"});
    assert_eq!(
        Jwk::validate_public(&evil).unwrap_err(),
        JwkError::PrivateMaterial
    );
}

#[test]
fn additional_jwks_validates_key_material() {
    let cases: Vec<(serde_json::Value, JwkError)> = vec![
        // n / e must be valid base64url.
        (
            json!({"kty":"RSA","n":"!!!","e":"AQAB","kid":"r1"}),
            JwkError::InvalidKeyMaterial,
        ),
        (
            json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"***","kid":"r1"}),
            JwkError::InvalidKeyMaterial,
        ),
        // Modulus below the 2048-bit floor.
        (
            json!({"kty":"RSA","n":TEST_MODULUS_1024,"e":"AQAB","kid":"r1"}),
            JwkError::WeakKey,
        ),
        // alg / use inconsistent with an RS256 signing key, when present.
        (
            json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"AQAB","kid":"r1","alg":"ES256"}),
            JwkError::UnsupportedAlgOrUse,
        ),
        (
            json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"AQAB","kid":"r1","use":"enc"}),
            JwkError::UnsupportedAlgOrUse,
        ),
        // kid is required and must use the allowed charset.
        (
            json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"AQAB"}),
            JwkError::InvalidKid,
        ),
        (
            json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"AQAB","kid":""}),
            JwkError::InvalidKid,
        ),
        (
            json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"AQAB","kid":"bad kid!"}),
            JwkError::InvalidKid,
        ),
    ];
    for (key, err) in cases {
        assert_eq!(Jwk::validate_public(&key).unwrap_err(), err, "key: {key}");
    }
    // alg/use are optional; both absent and matching values are accepted.
    for extra in [
        json!({}),
        json!({"alg":"RS256"}),
        json!({"use":"sig"}),
        json!({"alg":"RS256","use":"sig"}),
    ] {
        let mut key = json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"AQAB","kid":"r1"});
        key.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(Jwk::validate_public(&key).is_ok(), "key: {key}");
    }
}

fn config_with_additional_jwks(keys: serde_json::Value) -> Result<Config, oidc_core::ConfigError> {
    let clients_json = json!([{
        "client_id": PUBLIC_CLIENT,
        "redirect_uris": [PUBLIC_REDIRECT],
        "allowed_scopes": ["openid"],
        "type": "public",
        "token_endpoint_auth_method": "none",
    }])
    .to_string();
    Config::from_input(&ConfigInput {
        issuer_url: Some(ISSUER.to_string()),
        discord_client_id: Some("111111111111111111".to_string()),
        discord_client_secret: Some("discord-secret".to_string()),
        required_guild_id: Some(GUILD.to_string()),
        clients_json: Some(clients_json),
        signing_key_id: Some("test-key-1".to_string()),
        signing_private_key: Some("unused-in-these-tests".to_string()),
        additional_public_jwks_json: Some(keys.to_string()),
        ..Default::default()
    })
}

#[test]
fn additional_jwks_rejects_duplicate_kids() {
    let key = |kid: &str| json!({"kty":"RSA","n":TEST_MODULUS_2048,"e":"AQAB","kid":kid});
    // Colliding with the active signing key id is rejected.
    assert!(matches!(
        config_with_additional_jwks(json!([key("test-key-1")])),
        Err(oidc_core::ConfigError::Jwk(JwkError::DuplicateKeyId(_)))
    ));
    // Duplicates among the additional keys themselves are rejected.
    assert!(matches!(
        config_with_additional_jwks(json!([key("r1"), key("r1")])),
        Err(oidc_core::ConfigError::Jwk(JwkError::DuplicateKeyId(_)))
    ));
    // Distinct kids are accepted.
    assert!(config_with_additional_jwks(json!([key("r1"), key("r2")])).is_ok());
}

#[test]
fn rotation_overlap_keeps_old_tokens_verifiable() {
    // During rotation overlap the retired key stays published, so a token
    // signed under the old `kid` still resolves to a JWKS entry.
    let old_signer = TestSigner::new("old-kid");
    let new_signer = TestSigner::new("new-kid");

    let claims = oidc_core::jwt::IdTokenClaims {
        iss: ISSUER.to_string(),
        sub: DISCORD_USER_ID.to_string(),
        aud: PUBLIC_CLIENT.to_string(),
        iat: NOW,
        exp: NOW + 900,
        nonce: None,
        at_hash: None,
        preferred_username: None,
        name: None,
        picture: None,
    };
    let token = block_on(encode_claims(&old_signer, &claims)).unwrap();

    let doc = jwks_document(&[new_signer.public_jwk(), old_signer.public_jwk()]);
    assert_eq!(doc["keys"].as_array().unwrap().len(), 2);

    let (header, _, sig, input) = decode_jwt(&token);
    assert_eq!(header["kid"], "old-kid");
    let matching = doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == "old-kid")
        .unwrap();
    assert_eq!(matching["kty"], "RSA");
    assert_eq!(matching["n"], TEST_MODULUS_2048);
    // The token's signature is bound to its signing input and the `kid` it
    // was produced under.
    let expected = Sha256::digest(format!("old-kid:{input}").as_bytes());
    assert_eq!(sig.as_slice(), expected.as_slice());
}

#[test]
fn discovery_matches_implementation() {
    let cfg = test_config();
    let doc = oidc_core::discovery::discovery_document(&cfg);
    assert_eq!(doc["issuer"], ISSUER);
    assert_eq!(doc["authorization_endpoint"], format!("{ISSUER}/authorize"));
    assert_eq!(doc["token_endpoint"], format!("{ISSUER}/token"));
    assert_eq!(doc["jwks_uri"], format!("{ISSUER}/jwks.json"));
    assert_eq!(doc["response_types_supported"], json!(["code"]));
    assert_eq!(doc["grant_types_supported"], json!(["authorization_code"]));
    assert_eq!(doc["subject_types_supported"], json!(["public"]));
    assert_eq!(
        doc["id_token_signing_alg_values_supported"],
        json!(["RS256"])
    );
    assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        doc["token_endpoint_auth_methods_supported"],
        json!(["client_secret_basic", "none"])
    );
    // /userinfo is not implemented -> not advertised.
    assert!(doc.get("userinfo_endpoint").is_none());
}

// ---------- configuration validation ----------

#[test]
fn issuer_validation() {
    use oidc_core::config::validate_issuer;
    assert_eq!(
        validate_issuer("https://discord.id.ojiverse.example/").unwrap(),
        "https://discord.id.ojiverse.example"
    );
    for bad in [
        "http://discord.id.ojiverse.example",
        "https://discord.id.ojiverse.example?x=1",
        "https://discord.id.ojiverse.example#frag",
        "https://user@discord.id.ojiverse.example",
        // Path-bearing issuers are rejected: endpoints are routed at fixed
        // root paths, so discovery metadata under a prefix would 404.
        "https://discord.id.ojiverse.example/oidc",
        "https://discord.id.ojiverse.example//",
        "not-a-url",
    ] {
        assert!(validate_issuer(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn registry_rejects_secret_for_public_client() {
    let clients = json!([{
        "client_id": "c1",
        "redirect_uris": ["https://a.example/cb"],
        "allowed_scopes": ["openid"],
        "type": "public",
        "token_endpoint_auth_method": "none"
    }])
    .to_string();
    let secrets = json!({"c1": "x".repeat(16)}).to_string();
    assert!(oidc_core::client::build_registry(&clients, Some(&secrets)).is_err());
}

#[test]
fn registry_rejects_confidential_without_secret() {
    let clients = json!([{
        "client_id": "c1",
        "redirect_uris": ["https://a.example/cb"],
        "allowed_scopes": ["openid"],
        "type": "confidential",
        "token_endpoint_auth_method": "client_secret_basic"
    }])
    .to_string();
    assert!(oidc_core::client::build_registry(&clients, None).is_err());
}

#[test]
fn registry_rejects_method_type_mismatch() {
    for (ty, method) in [("public", "client_secret_basic"), ("confidential", "none")] {
        let clients = json!([{
            "client_id": "c1",
            "redirect_uris": ["https://a.example/cb"],
            "allowed_scopes": ["openid"],
            "type": ty,
            "token_endpoint_auth_method": method
        }])
        .to_string();
        assert!(oidc_core::client::build_registry(&clients, None).is_err());
    }
}

#[test]
fn registry_rejects_wildcard_and_relative_redirects() {
    for uri in [
        "https://a.example/cb/*",
        "/relative/path",
        "ftp://a.example/cb",
        "https://a.example/cb#frag",
    ] {
        let clients = json!([{
            "client_id": "c1",
            "redirect_uris": [uri],
            "allowed_scopes": ["openid"],
            "type": "public",
            "token_endpoint_auth_method": "none"
        }])
        .to_string();
        assert!(
            oidc_core::client::build_registry(&clients, None).is_err(),
            "accepted {uri}"
        );
    }
}

#[test]
fn sweep_removes_expired_entries() {
    let store = InMemoryStore::new();
    let tx = AuthorizationTransaction::new(
        PUBLIC_CLIENT.to_string(),
        PUBLIC_REDIRECT.to_string(),
        "openid".to_string(),
        None,
        None,
        challenge_for(VERIFIER),
        &mut entropy(),
        NOW,
    );
    block_on(store.put_transaction(&tx)).unwrap();
    assert_eq!(block_on(store.sweep_expired(NOW + 601)).unwrap(), 1);
    assert_eq!(store.transaction_count(), 0);
}

#[test]
fn consume_reports_deny_kinds() {
    let store = InMemoryStore::new();
    let tx = AuthorizationTransaction::new(
        PUBLIC_CLIENT.to_string(),
        PUBLIC_REDIRECT.to_string(),
        "openid".to_string(),
        None,
        None,
        challenge_for(VERIFIER),
        &mut entropy(),
        NOW,
    );
    let issued =
        oidc_core::code::issue_code(&tx, DISCORD_USER_ID.to_string(), None, &mut entropy(), NOW);
    block_on(store.put_authorization_code(&issued.record)).unwrap();
    let hash = hash_presented_code(&issued.plaintext);
    let bad = ExchangeCheck {
        client_id: "other",
        redirect_uri: PUBLIC_REDIRECT,
        code_verifier: VERIFIER,
    };
    let outcome = block_on(store.consume_authorization_code(&hash, &bad, NOW)).unwrap();
    assert_eq!(outcome.unwrap_err(), ConsumeDeny::ClientMismatch);
    // Record survives binding mismatches.
    let good = ExchangeCheck {
        client_id: PUBLIC_CLIENT,
        redirect_uri: PUBLIC_REDIRECT,
        code_verifier: VERIFIER,
    };
    assert!(
        block_on(store.consume_authorization_code(&hash, &good, NOW))
            .unwrap()
            .is_ok()
    );
    // Second consume is Unknown (single-use).
    let outcome = block_on(store.consume_authorization_code(&hash, &good, NOW)).unwrap();
    assert_eq!(outcome.unwrap_err(), ConsumeDeny::Unknown);
}
