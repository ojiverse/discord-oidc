//! `/authorize` handling.
//!
//! Until `client_id` and `redirect_uri` are both validated, errors are
//! rendered in place — never redirected. After validation, protocol errors
//! redirect to the registered URI with `error` and the echoed `state`.

use std::collections::BTreeMap;

use url::{form_urlencoded, Url};

use crate::config::Config;
use crate::error::{error_page, OAuthErrorCode};
use crate::pkce;
use crate::resolver::ClientResolver;
use crate::response::CoreResponse;
use crate::store::AuthorizationStore;
use crate::transaction::AuthorizationTransaction;
use crate::util::Entropy;

/// Maximum accepted length of the raw query string.
pub const MAX_QUERY_LEN: usize = 8192;
/// Maximum length of an individual parameter value.
const MAX_PARAM_LEN: usize = 2048;
/// Maximum `state`/`nonce` length.
const MAX_STATE_LEN: usize = 1024;

/// Authorization request parameters this provider understands. Everything
/// else is ignored — the authorization server must not fail on unrecognized
/// request parameters (RFC 6749). OIDC-defined `prompt`/`max_age` are known
/// parameters with explicit fail-closed semantics below.
const KNOWN_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "prompt",
    "max_age",
];

/// A validated authorization request.
#[derive(Debug)]
pub struct ValidatedAuthorize {
    /// Registered client.
    pub client_id: String,
    /// Registered redirect URI (exact match).
    pub redirect_uri: String,
    /// Granted scope string: the intersection of the requested scopes
    /// and the client's `allowed_scopes`.
    pub scope: String,
    /// RP `state` to echo back.
    pub rp_state: Option<String>,
    /// RP `nonce` for the ID Token.
    pub nonce: Option<String>,
    /// PKCE S256 challenge.
    pub code_challenge: String,
    /// The RP asked for `prompt=consent`; forwarded to Discord's own
    /// consent re-approval prompt on the authorization redirect.
    pub discord_consent: bool,
}

/// The outcome of validating an `/authorize` request.
#[derive(Debug)]
pub enum AuthorizeVerdict {
    /// Validation passed; proceed to create a transaction and redirect to
    /// Discord.
    Proceed(ValidatedAuthorize),
    /// Redirect to the *registered* redirect URI with an OAuth error.
    RedirectError {
        /// Registered redirect URI.
        redirect_uri: String,
        /// OAuth error code.
        code: OAuthErrorCode,
        /// Safe, non-sensitive description.
        description: Option<&'static str>,
        /// RP `state` to echo, if one was provided.
        state: Option<String>,
    },
    /// Render an error page; no redirect target is trustworthy.
    RenderError {
        /// HTTP status.
        status: u16,
        /// Short title.
        title: &'static str,
        /// Detail text.
        description: String,
    },
}

type Params = BTreeMap<String, Vec<String>>;

fn parse_query(query: &str) -> Params {
    let mut params: Params = BTreeMap::new();
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        params
            .entry(k.into_owned())
            .or_default()
            .push(v.into_owned());
    }
    params
}

/// Extracts a single-valued parameter. `Err(())` signals duplicates.
fn single<'a>(params: &'a Params, name: &str) -> Result<Option<&'a str>, ()> {
    match params.get(name).map(Vec::as_slice) {
        None => Ok(None),
        Some([v]) => Ok(Some(v.as_str())),
        Some(_) => Err(()),
    }
}

fn render(status: u16, title: &'static str, description: impl Into<String>) -> AuthorizeVerdict {
    AuthorizeVerdict::RenderError {
        status,
        title,
        description: description.into(),
    }
}

fn redirect_err(
    redirect_uri: &str,
    code: OAuthErrorCode,
    description: &'static str,
    state: Option<String>,
) -> AuthorizeVerdict {
    AuthorizeVerdict::RedirectError {
        redirect_uri: redirect_uri.to_string(),
        code,
        description: Some(description),
        state,
    }
}

/// Validates a raw `/authorize` query string.
///
/// The client is resolved through `resolver` (static registry first, then the
/// dynamic registry); unknown *or disabled* clients are rejected in place —
/// their redirect URIs are never treated as trustworthy.
pub async fn validate_authorize_request<R: ClientResolver + ?Sized>(
    query: &str,
    resolver: &R,
) -> AuthorizeVerdict {
    if query.len() > MAX_QUERY_LEN {
        return render(400, "invalid_request", "request too large");
    }
    let params = parse_query(query);

    // Steps 1-2: client_id + redirect_uri must validate before any redirect.
    let client_id = match single(&params, "client_id") {
        Ok(Some(id)) if id.len() <= MAX_PARAM_LEN => id,
        _ => return render(400, "invalid_request", "missing or invalid client_id"),
    };
    let client = match resolver.find_client(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return render(400, "unauthorized_client", "unknown or disabled client_id"),
        Err(_) => return render(500, "server_error", "client registry failure"),
    };
    let redirect_uri = match single(&params, "redirect_uri") {
        Ok(Some(uri)) if uri.len() <= MAX_PARAM_LEN => uri,
        _ => return render(400, "invalid_request", "missing or invalid redirect_uri"),
    };
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return render(400, "invalid_request", "redirect_uri is not registered");
    }
    let state = single(&params, "state").ok().flatten().map(str::to_string);

    // From here on, errors redirect to the registered redirect_uri.
    let err = |code: OAuthErrorCode, desc: &'static str| {
        redirect_err(redirect_uri, code, desc, state.clone())
    };

    // The authorization server must ignore unrecognized request parameters.
    // Only the known parameter set is checked for duplicates and length so
    // that OIDC extension parameters (`login_hint`, `resource`, ...) sent by
    // conforming clients do not break the flow.
    for name in KNOWN_PARAMETERS {
        if let Some(values) = params.get(*name) {
            if values.len() > 1 {
                return err(OAuthErrorCode::InvalidRequest, "duplicated parameter");
            }
            if values.iter().any(|v| v.len() > MAX_PARAM_LEN) {
                return err(OAuthErrorCode::InvalidRequest, "parameter too long");
            }
        }
    }

    match single(&params, "response_type") {
        Ok(Some("code")) => {}
        Ok(Some(_)) => {
            return err(
                OAuthErrorCode::UnsupportedResponseType,
                "unsupported response_type",
            )
        }
        _ => return err(OAuthErrorCode::InvalidRequest, "invalid response_type"),
    }

    let scope = match single(&params, "scope") {
        Ok(Some(s)) if s.len() <= MAX_PARAM_LEN => s,
        _ => return err(OAuthErrorCode::InvalidScope, "missing scope"),
    };
    let requested: Vec<&str> = scope.split_whitespace().collect();
    if !requested.contains(&"openid") {
        return err(OAuthErrorCode::InvalidScope, "openid scope required");
    }
    // Grant the intersection of requested and allowed scopes; values the
    // provider cannot grant are ignored (RFC 6749 §3.3, OIDC Core
    // 3.1.2.1). Some clients — e.g. Cloudflare Access generic OIDC —
    // unconditionally request `openid email profile`; failing closed
    // would make such conforming clients unusable. The granted subset is
    // what the token response echoes in its `scope` field.
    let mut granted: Vec<&str> = Vec::new();
    for s in &requested {
        if client.allowed_scopes.iter().any(|a| a == s) && !granted.contains(s) {
            granted.push(s);
        }
    }

    match single(&params, "code_challenge_method") {
        Ok(Some(pkce::REQUIRED_CHALLENGE_METHOD)) => {}
        _ => {
            return err(
                OAuthErrorCode::InvalidRequest,
                "code_challenge_method must be S256",
            )
        }
    }
    let code_challenge = match single(&params, "code_challenge") {
        Ok(Some(c)) if pkce::is_valid_code_challenge(c) => c.to_string(),
        _ => return err(OAuthErrorCode::InvalidRequest, "invalid code_challenge"),
    };

    let nonce = single(&params, "nonce").ok().flatten().map(str::to_string);
    if nonce.as_deref().is_some_and(|n| n.len() > MAX_STATE_LEN) {
        return err(OAuthErrorCode::InvalidRequest, "nonce too long");
    }
    if state.as_deref().is_some_and(|s| s.len() > MAX_STATE_LEN) {
        return err(OAuthErrorCode::InvalidRequest, "state too long");
    }

    // `prompt` is a space-delimited list of OIDC authentication request
    // values. Values this provider cannot satisfy fail closed with an OIDC
    // error rather than being silently ignored; unrecognized values are
    // ignored so extension values do not break conforming clients.
    let prompt: Vec<&str> = single(&params, "prompt")
        .ok()
        .flatten()
        .map(|p| p.split_whitespace().collect())
        .unwrap_or_default();
    let mut discord_consent = false;
    if !prompt.is_empty() {
        // `none` must not be combined with any other value.
        if prompt.contains(&"none") && prompt.len() > 1 {
            return err(
                OAuthErrorCode::InvalidRequest,
                "prompt=none must not be combined with other values",
            );
        }
        // No provider-side session exists and Discord exposes no verified
        // upstream authentication time, so silent authentication (`none`)
        // and guaranteed reauthentication (`login`) are unsatisfiable.
        // Discord's `prompt=consent` only re-prompts authorization consent
        // and is never a substitute for reauthentication.
        if prompt.contains(&"none") || prompt.contains(&"login") {
            return err(
                OAuthErrorCode::LoginRequired,
                "interactive authentication cannot be guaranteed",
            );
        }
        if prompt.contains(&"select_account") {
            return err(
                OAuthErrorCode::AccountSelectionRequired,
                "account selection is not supported",
            );
        }
        if prompt.contains(&"consent") {
            discord_consent = true;
        }
    }

    // `max_age` demands proof that the upstream authentication is recent
    // enough. Discord provides no trustworthy authentication timestamp and
    // no guaranteed reauthentication hook, so any `max_age` request fails
    // closed — never fabricate `auth_time` from the callback arrival time.
    if let Some(max_age) = single(&params, "max_age").ok().flatten() {
        if max_age.parse::<u64>().is_err() {
            return err(OAuthErrorCode::InvalidRequest, "invalid max_age");
        }
        return err(OAuthErrorCode::LoginRequired, "max_age cannot be satisfied");
    }

    AuthorizeVerdict::Proceed(ValidatedAuthorize {
        client_id: client.client_id.clone(),
        redirect_uri: redirect_uri.to_string(),
        scope: granted.join(" "),
        rp_state: state,
        nonce,
        code_challenge,
        discord_consent,
    })
}

/// Builds the redirect location for an authorization error or success.
pub fn redirect_with_params(uri: &str, pairs: &[(&str, &str)]) -> String {
    let mut url = match Url::parse(uri) {
        Ok(u) => u,
        Err(_) => return uri.to_string(),
    };
    url.query_pairs_mut()
        .extend_pairs(pairs.iter().map(|(k, v)| (*k, *v)));
    url.into()
}

/// Full `/authorize` handler: validate, persist a transaction, and produce
/// the Discord redirect (or an error response).
pub async fn handle_authorize<S: AuthorizationStore, E: Entropy, R: ClientResolver + ?Sized>(
    query: &str,
    cfg: &Config,
    store: &S,
    resolver: &R,
    entropy: &mut E,
    now: i64,
) -> CoreResponse {
    match validate_authorize_request(query, resolver).await {
        AuthorizeVerdict::RenderError {
            status,
            title,
            description,
        } => CoreResponse::Html {
            status,
            body: error_page(title, &description),
        },
        AuthorizeVerdict::RedirectError {
            redirect_uri,
            code,
            description,
            state,
        } => {
            let mut pairs = vec![("error", code.as_str())];
            if let Some(d) = description {
                pairs.push(("error_description", d));
            }
            if let Some(s) = state.as_deref() {
                pairs.push(("state", s));
            }
            CoreResponse::Redirect(redirect_with_params(&redirect_uri, &pairs))
        }
        AuthorizeVerdict::Proceed(v) => {
            let tx = AuthorizationTransaction::new(
                v.client_id,
                v.redirect_uri,
                v.scope,
                v.rp_state,
                v.nonce,
                v.code_challenge,
                entropy,
                now,
            );
            if store.put_transaction(&tx).await.is_err() {
                return CoreResponse::Html {
                    status: 500,
                    body: error_page("server_error", "authorization storage failure"),
                };
            }
            CoreResponse::Redirect(crate::discord::discord_authorize_url(
                cfg,
                &tx.discord_oauth_state,
                v.discord_consent,
            ))
        }
    }
}
