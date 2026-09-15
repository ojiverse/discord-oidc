//! `/token` handling.
//!
//! Order of checks: client authentication first (`invalid_client` -> 401 +
//! `WWW-Authenticate`), then grant validation (`invalid_grant` -> 400) with
//! the consume performed atomically by the store. Every response carries
//! `Cache-Control: no-store` / `Pragma: no-cache`.

use std::collections::BTreeMap;

use base64::Engine;
use serde_json::json;
use subtle::ConstantTimeEq;
use url::form_urlencoded;

use crate::client::{ClientConfig, ClientType, TokenEndpointAuthMethod};
use crate::code::{hash_presented_code, ExchangeCheck};
use crate::config::Config;
use crate::error::{ErrorBody, OAuthErrorCode};
use crate::jwt::{at_hash, encode_claims, IdTokenClaims, IdTokenSigner};
use crate::response::CoreResponse;
use crate::store::AuthorizationStore;
use crate::util::{random_token, Entropy};

/// Maximum accepted `/token` body size.
pub const MAX_TOKEN_BODY_LEN: usize = 8192;

const WWW_AUTHENTICATE_BASIC: &str = "Basic realm=\"discord-oidc\"";

fn json_error(
    status: u16,
    code: OAuthErrorCode,
    description: Option<&'static str>,
    extra_headers: Vec<(String, String)>,
) -> CoreResponse {
    let body = serde_json::to_value(ErrorBody {
        error: code,
        error_description: description,
    })
    .expect("ErrorBody serializes");
    CoreResponse::Json {
        status,
        body,
        no_store: true,
        extra_headers,
    }
}

fn invalid_client() -> CoreResponse {
    json_error(
        401,
        OAuthErrorCode::InvalidClient,
        Some("client authentication failed"),
        vec![(
            "WWW-Authenticate".to_string(),
            WWW_AUTHENTICATE_BASIC.to_string(),
        )],
    )
}

fn invalid_request(desc: &'static str) -> CoreResponse {
    json_error(400, OAuthErrorCode::InvalidRequest, Some(desc), Vec::new())
}

fn invalid_grant() -> CoreResponse {
    json_error(
        400,
        OAuthErrorCode::InvalidGrant,
        Some("authorization grant is invalid or expired"),
        Vec::new(),
    )
}

type Params = BTreeMap<String, Vec<String>>;

fn parse_form(body: &str) -> Params {
    let mut params: Params = BTreeMap::new();
    for (k, v) in form_urlencoded::parse(body.as_bytes()) {
        params
            .entry(k.into_owned())
            .or_default()
            .push(v.into_owned());
    }
    params
}

fn single<'a>(params: &'a Params, name: &str) -> Result<Option<&'a str>, ()> {
    match params.get(name).map(Vec::as_slice) {
        None => Ok(None),
        Some([v]) => Ok(Some(v.as_str())),
        Some(_) => Err(()),
    }
}

/// Decodes an HTTP Basic client credential: the `client_id` and secret are
/// each form-url-encoded before `id:secret` is base64'd.
fn decode_basic(auth: &str) -> Option<(String, String)> {
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((form_decode_part(id)?, form_decode_part(secret)?))
}

fn form_decode_part(s: &str) -> Option<String> {
    percent_encoding::percent_decode(s.replace('+', " ").as_bytes())
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

/// Authenticates the client at the token endpoint.
///
/// - `Basic` header present: must belong to a registered confidential client
///   using `client_secret_basic`; secret compared in constant time. A body
///   `client_id` that disagrees fails authentication.
/// - No header: body `client_id` must name a registered *public* client.
fn authenticate_client<'a>(
    params: &Params,
    auth_header: Option<&str>,
    cfg: &'a Config,
) -> Result<&'a ClientConfig, CoreResponse> {
    let body_client_id = single(params, "client_id").ok().flatten();

    if let Some(auth) = auth_header {
        if auth.trim().is_empty() {
            return Err(invalid_client());
        }
        let Some((client_id, secret)) = decode_basic(auth.trim()) else {
            return Err(invalid_client());
        };
        if body_client_id.is_some_and(|id| id != client_id) {
            return Err(invalid_client());
        }
        let Some(client) = cfg.clients.find(&client_id) else {
            return Err(invalid_client());
        };
        if client.client_type != ClientType::Confidential
            || client.token_endpoint_auth_method != TokenEndpointAuthMethod::ClientSecretBasic
        {
            return Err(invalid_client());
        }
        let Some(expected) = cfg.client_secret(&client_id) else {
            return Err(invalid_client());
        };
        if !bool::from(expected.as_bytes().ct_eq(secret.as_bytes())) {
            return Err(invalid_client());
        }
        return Ok(client);
    }

    let Some(client_id) = body_client_id else {
        return Err(invalid_client());
    };
    let Some(client) = cfg.clients.find(client_id) else {
        return Err(invalid_client());
    };
    // Public clients carry no secret; confidential clients must use Basic.
    if client.client_type != ClientType::Public
        || client.token_endpoint_auth_method != TokenEndpointAuthMethod::None
    {
        return Err(invalid_client());
    }
    Ok(client)
}

/// Full `/token` handler. `form_body` must already be known to be
/// `application/x-www-form-urlencoded` (the adapter checks Content-Type).
pub async fn handle_token<S: AuthorizationStore, E: Entropy, G: IdTokenSigner>(
    form_body: &str,
    auth_header: Option<&str>,
    cfg: &Config,
    store: &S,
    signer: &G,
    entropy: &mut E,
    now: i64,
) -> CoreResponse {
    if form_body.len() > MAX_TOKEN_BODY_LEN {
        return invalid_request("request body too large");
    }
    let params = parse_form(form_body);
    if params.values().any(|v| v.len() > 1) {
        return invalid_request("duplicated parameter");
    }

    match single(&params, "grant_type") {
        Ok(Some("authorization_code")) => {}
        Ok(Some(_)) => {
            return json_error(
                400,
                OAuthErrorCode::UnsupportedGrantType,
                Some("unsupported grant_type"),
                Vec::new(),
            )
        }
        _ => return invalid_request("invalid grant_type"),
    }

    let client = match authenticate_client(&params, auth_header, cfg) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let code = match single(&params, "code") {
        Ok(Some(c)) if !c.is_empty() && c.len() <= 256 => c,
        _ => return invalid_request("missing or invalid code"),
    };
    let redirect_uri = match single(&params, "redirect_uri") {
        Ok(Some(u)) if !u.is_empty() && u.len() <= 2048 => u,
        _ => return invalid_request("missing or invalid redirect_uri"),
    };
    let code_verifier = match single(&params, "code_verifier") {
        Ok(Some(v)) if !v.is_empty() && v.len() <= 128 => v,
        _ => return invalid_request("missing or invalid code_verifier"),
    };

    let check = ExchangeCheck {
        client_id: &client.client_id,
        redirect_uri,
        code_verifier,
    };
    let record = match store
        .consume_authorization_code(&hash_presented_code(code), &check, now)
        .await
    {
        Ok(Ok(record)) => record,
        Ok(Err(_deny)) => return invalid_grant(),
        Err(_) => {
            return json_error(500, OAuthErrorCode::ServerError, None, Vec::new());
        }
    };

    let access_token = random_token(entropy);
    let profile = record
        .profile
        .as_ref()
        .filter(|_| record.scope.split_whitespace().any(|s| s == "profile"));
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: record.subject.clone(),
        aud: client.client_id.clone(),
        iat: now,
        exp: now + cfg.id_token_ttl_secs,
        nonce: record.nonce.clone(),
        at_hash: Some(at_hash(&access_token)),
        preferred_username: profile.and_then(|p| p.preferred_username.clone()),
        name: profile.and_then(|p| p.name.clone()),
        picture: profile.and_then(|p| p.picture.clone()),
    };
    let id_token = match encode_claims(signer, &claims).await {
        Ok(t) => t,
        Err(_) => return json_error(500, OAuthErrorCode::ServerError, None, Vec::new()),
    };

    CoreResponse::Json {
        status: 200,
        body: json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": cfg.id_token_ttl_secs,
            "scope": record.scope,
            "id_token": id_token,
        }),
        no_store: true,
        extra_headers: Vec::new(),
    }
}
