//! `discord-oidc` Cloudflare Worker entry point: an OpenID Provider that
//! delegates authentication to Discord OAuth2 and requires membership in one
//! configured Guild.

mod discord_http;
mod do_store;
mod durable;

use std::cell::OnceCell;
use std::sync::Arc;

use oidc_core::config::{Config, ConfigInput};
use oidc_core::jwk::{jwks_document, Jwk};
use oidc_core::jwt::Rs256Signer;
use oidc_core::response::CoreResponse;
use oidc_core::util::Entropy;
use serde_json::json;
use worker::{console_error, console_log, event, Context, Date, Env, Method, Request, Response};

use discord_http::DiscordHttp;
use do_store::DoStore;

/// Config + signing key, parsed once per isolate.
struct Runtime {
    cfg: Config,
    signer: Rs256Signer,
}

thread_local! {
    static RUNTIME: OnceCell<Result<Arc<Runtime>, String>> = const { OnceCell::new() };
}

fn runtime(env: &Env) -> Result<Arc<Runtime>, String> {
    RUNTIME.with(|cell| cell.get_or_init(|| load_runtime(env).map(Arc::new)).clone())
}

fn load_runtime(env: &Env) -> Result<Runtime, String> {
    let var = |name: &str| env.var(name).ok().map(|v| v.to_string());
    let secret = |name: &str| env.secret(name).ok().map(|s| s.to_string());
    let signing_key = secret("OIDC_SIGNING_PRIVATE_KEY");
    let input = ConfigInput {
        issuer_url: var("OIDC_ISSUER_URL"),
        discord_client_id: var("DISCORD_CLIENT_ID"),
        discord_client_secret: secret("DISCORD_CLIENT_SECRET"),
        required_guild_id: var("DISCORD_REQUIRED_GUILD_ID"),
        clients_json: var("OIDC_CLIENTS_JSON"),
        client_secrets_json: secret("OIDC_CLIENT_SECRETS_JSON"),
        signing_key_id: var("OIDC_SIGNING_KEY_ID"),
        signing_private_key: signing_key.clone(),
        additional_public_jwks_json: var("OIDC_JWKS_ADDITIONAL_PUBLIC_KEYS"),
        id_token_ttl_seconds: var("OIDC_ID_TOKEN_TTL_SECONDS"),
    };
    let cfg = Config::from_input(&input).map_err(|e| e.to_string())?;
    let signer = Rs256Signer::from_secret_str(
        signing_key.as_deref().unwrap_or_default(),
        cfg.signing_key_id.clone(),
    )
    .map_err(|e| e.to_string())?;
    Ok(Runtime { cfg, signer })
}

/// Cryptographically secure entropy from the Workers runtime.
struct WorkerEntropy;

impl Entropy for WorkerEntropy {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("crypto.getRandomValues unavailable");
    }
}

fn now_unix() -> i64 {
    (Date::now().as_millis() / 1000) as i64
}

fn to_response(core: CoreResponse) -> worker::Result<Response> {
    match core {
        CoreResponse::Redirect(location) => {
            let url = url::Url::parse(&location)
                .map_err(|_| worker::Error::RustError("bad redirect target".into()))?;
            Response::redirect(url)
        }
        CoreResponse::Json {
            status,
            body,
            no_store,
            extra_headers,
        } => {
            let mut resp = Response::from_json(&body)?.with_status(status);
            let headers = resp.headers_mut();
            if no_store {
                headers.set("Cache-Control", "no-store")?;
                headers.set("Pragma", "no-cache")?;
            }
            for (k, v) in extra_headers {
                headers.set(&k, &v)?;
            }
            Ok(resp)
        }
        CoreResponse::Html { status, body } => Ok(Response::from_html(body)?.with_status(status)),
    }
}

fn json_response(status: u16, body: serde_json::Value) -> worker::Result<Response> {
    to_response(CoreResponse::json(status, body))
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    let ray = req
        .headers()
        .get("cf-ray")
        .ok()
        .flatten()
        .unwrap_or_default();
    let method = req.method();
    let path = req.url()?.path().to_string();

    let result = route(&mut req, &env, method.clone(), &path).await;
    match &result {
        Ok(resp) => console_log!("{method} {path} -> {} ray={ray}", resp.status_code()),
        Err(e) => console_error!("{method} {path} -> error ray={ray}: {e}"),
    }
    result
}

async fn route(
    req: &mut Request,
    env: &Env,
    method: Method,
    path: &str,
) -> worker::Result<Response> {
    // Config errors are logged server-side; the client gets a bare 500.
    let rt = match runtime(env) {
        Ok(rt) => rt,
        Err(e) => {
            console_error!("configuration error: {e}");
            return json_response(500, json!({ "error": "server_error" }));
        }
    };
    let store = match DoStore::from_env(env) {
        Ok(s) => s,
        Err(e) => {
            console_error!("durable object binding error: {e}");
            return json_response(500, json!({ "error": "server_error" }));
        }
    };
    let now = now_unix();
    let mut entropy = WorkerEntropy;
    let query = req.url()?.query().unwrap_or_default().to_string();

    match (method, path) {
        (Method::Get, "/.well-known/openid-configuration") => {
            json_response(200, oidc_core::discovery::discovery_document(&rt.cfg))
        }
        (Method::Get, "/jwks.json") => {
            let mut keys = vec![Jwk::from_public_key(
                &rt.signer.public_key(),
                rt.signer.kid(),
            )];
            keys.extend(rt.cfg.additional_public_jwks.iter().cloned());
            json_response(200, jwks_document(&keys))
        }
        (Method::Get, "/authorize") => to_response(
            oidc_core::handle_authorize(&query, &rt.cfg, &store, &mut entropy, now).await,
        ),
        (Method::Get, "/oauth/discord/callback") => {
            let discord = DiscordHttp::new(&rt.cfg);
            to_response(
                oidc_core::handle_callback(&query, &rt.cfg, &store, &discord, &mut entropy, now)
                    .await,
            )
        }
        (Method::Post, "/token") => {
            let content_type = req
                .headers()
                .get("content-type")
                .ok()
                .flatten()
                .unwrap_or_default();
            if !content_type.starts_with("application/x-www-form-urlencoded") {
                return to_response(CoreResponse::json_no_store(
                    400,
                    json!({ "error": "invalid_request" }),
                ));
            }
            let auth_header = req.headers().get("authorization").ok().flatten();
            let body = req.text().await.unwrap_or_default();
            to_response(
                oidc_core::handle_token(
                    &body,
                    auth_header.as_deref(),
                    &rt.cfg,
                    &store,
                    &rt.signer,
                    &mut entropy,
                    now,
                )
                .await,
            )
        }
        (Method::Get, _) | (Method::Post, _) => json_response(404, json!({ "error": "not_found" })),
        _ => json_response(405, json!({ "error": "method_not_allowed" })),
    }
}
