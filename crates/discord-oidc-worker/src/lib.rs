//! `discord-oidc` Cloudflare Worker entry point: an OpenID Provider that
//! delegates authentication to Discord OAuth2 and requires membership in one
//! configured Guild.

mod discord_http;
mod do_store;
mod durable;
mod registry_client;
mod webcrypto;

use std::cell::RefCell;
use std::sync::Arc;

use futures_util::future::{FutureExt, LocalBoxFuture, Shared};
use oidc_core::config::{Config, ConfigInput};
use oidc_core::jwk::jwks_document;
use oidc_core::jwt::IdTokenSigner;
use oidc_core::resolver::RegistryResolver;
use oidc_core::response::CoreResponse;
use oidc_core::util::Entropy;
use serde_json::json;
use worker::{console_error, console_log, event, Context, Date, Env, Method, Request, Response};

use discord_http::DiscordHttp;
use do_store::DoStore;
use registry_client::RegistryClient;
use webcrypto::WebCryptoSigner;

/// Config + Web Crypto signing key, initialized once per isolate.
struct Runtime {
    cfg: Config,
    signer: WebCryptoSigner,
    /// `OIDC_ADMIN_API_TOKEN` secret; `None` disables the admin API (all
    /// requests fail closed as `401 unauthorized`).
    admin_token: Option<String>,
}

/// `load_runtime` is async (Web Crypto `importKey`), so initialization is
/// memoized as a shared future: the first request drives it, concurrent and
/// later requests await the same result.
type RuntimeFuture = Shared<LocalBoxFuture<'static, Result<Arc<Runtime>, String>>>;

thread_local! {
    static RUNTIME: RefCell<Option<RuntimeFuture>> = const { RefCell::new(None) };
}

fn runtime(env: &Env) -> RuntimeFuture {
    RUNTIME.with(|cell| {
        cell.borrow_mut()
            .get_or_insert_with(|| {
                load_runtime(env.clone())
                    .map(|r| r.map(Arc::new))
                    .boxed_local()
                    .shared()
            })
            .clone()
    })
}

async fn load_runtime(env: Env) -> Result<Runtime, String> {
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
    let signer = WebCryptoSigner::from_secret_str(
        signing_key.as_deref().unwrap_or_default(),
        cfg.signing_key_id.clone(),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(Runtime {
        cfg,
        signer,
        admin_token: secret("OIDC_ADMIN_API_TOKEN"),
    })
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
    let rt = match runtime(env).await {
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
    // The registry client degrades to always-error when the binding is
    // absent; static clients keep working in that case.
    let registry = RegistryClient::from_env(env);
    let resolver = RegistryResolver::new(&rt.cfg, &registry);
    let now = now_unix();
    let mut entropy = WorkerEntropy;
    let query = req.url()?.query().unwrap_or_default().to_string();

    // Private control plane: bearer-authenticated admin API. The
    // Authorization header and any request body are never logged.
    if path == "/admin" || path.starts_with("/admin/") {
        let body = match method {
            Method::Post | Method::Put => Some(req.text().await.unwrap_or_default()),
            _ => None,
        };
        let authorization = req.headers().get("authorization").ok().flatten();
        return to_response(
            oidc_core::admin::handle_admin_request(
                method.as_ref(),
                path,
                body.as_deref(),
                authorization.as_deref(),
                rt.admin_token.as_deref(),
                &rt.cfg,
                &registry,
                &mut entropy,
                now,
            )
            .await,
        );
    }

    match (method, path) {
        (Method::Get, "/.well-known/openid-configuration") => {
            json_response(200, oidc_core::discovery::discovery_document(&rt.cfg))
        }
        (Method::Get, "/jwks.json") => {
            let mut keys = vec![rt.signer.public_jwk()];
            keys.extend(rt.cfg.additional_public_jwks.iter().cloned());
            json_response(200, jwks_document(&keys))
        }
        (Method::Get, "/authorize") => to_response(
            oidc_core::handle_authorize(&query, &rt.cfg, &store, &resolver, &mut entropy, now)
                .await,
        ),
        (Method::Get, "/oauth/discord/callback") => {
            let discord = DiscordHttp::new(&rt.cfg);
            to_response(
                oidc_core::handle_callback(
                    &query,
                    &rt.cfg,
                    &store,
                    &resolver,
                    &discord,
                    &mut entropy,
                    now,
                )
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
                    &resolver,
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
