//! `/oauth/discord/callback` handling (DESIGN §6.3).
//!
//! Validates the provider-generated upstream `state`, exchanges the Discord
//! code, verifies required-Guild membership, then issues a provider
//! authorization code and redirects to the RP's registered `redirect_uri`.

use url::form_urlencoded;

use crate::authorize::redirect_with_params;
use crate::code::{issue_code, ProfileClaims};
use crate::config::Config;
use crate::discord::DiscordApi;
use crate::error::{error_page, OAuthErrorCode};
use crate::response::CoreResponse;
use crate::store::{AuthorizationStore, TakeTransaction};
use crate::transaction::AuthorizationTransaction;
use crate::util::Entropy;

fn redirect_error(
    tx: &AuthorizationTransaction,
    code: OAuthErrorCode,
    description: &'static str,
) -> CoreResponse {
    let mut pairs = vec![("error", code.as_str()), ("error_description", description)];
    let owned;
    if let Some(state) = &tx.rp_state {
        owned = state.as_str();
        pairs.push(("state", owned));
    }
    CoreResponse::Redirect(redirect_with_params(&tx.redirect_uri, &pairs))
}

fn render(status: u16, title: &'static str, description: &str) -> CoreResponse {
    CoreResponse::Html {
        status,
        body: error_page(title, description),
    }
}

/// Discord may return any `error` string; only known-safe codes are forwarded
/// to the RP, everything else collapses to `access_denied`.
fn sanitize_upstream_error(code: &str) -> OAuthErrorCode {
    match code {
        "access_denied" => OAuthErrorCode::AccessDenied,
        "server_error" => OAuthErrorCode::ServerError,
        "temporarily_unavailable" => OAuthErrorCode::TemporarilyUnavailable,
        "invalid_request" => OAuthErrorCode::InvalidRequest,
        _ => OAuthErrorCode::AccessDenied,
    }
}

/// Full Discord callback handler.
///
/// `query` is the raw callback query string (`code`/`state`/`error`).
pub async fn handle_callback<S: AuthorizationStore, D: DiscordApi, E: Entropy>(
    query: &str,
    cfg: &Config,
    store: &S,
    discord: &D,
    entropy: &mut E,
    now: i64,
) -> CoreResponse {
    let mut state = None;
    let mut code = None;
    let mut error = None;
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        match k.as_ref() {
            "state" if state.is_none() => state = Some(v.into_owned()),
            "code" if code.is_none() => code = Some(v.into_owned()),
            "error" if error.is_none() => error = Some(v.into_owned()),
            _ => {}
        }
    }

    let Some(state) = state else {
        return render(400, "invalid_request", "missing state");
    };
    if state.len() > 256 {
        return render(400, "invalid_request", "invalid state");
    }

    let tx = match store.take_transaction(&state, now).await {
        Ok(TakeTransaction::Active(tx)) => tx,
        Ok(TakeTransaction::Expired(tx)) => {
            return redirect_error(
                &tx,
                OAuthErrorCode::TemporarilyUnavailable,
                "session expired",
            );
        }
        Ok(TakeTransaction::Missing) => {
            return render(
                400,
                "invalid_request",
                "authorization session not found or already used",
            );
        }
        Err(_) => {
            return render(500, "server_error", "authorization storage failure");
        }
    };

    if let Some(upstream_error) = error {
        return redirect_error(
            &tx,
            sanitize_upstream_error(&upstream_error),
            "discord authorization failed",
        );
    }
    let Some(code) = code else {
        return redirect_error(&tx, OAuthErrorCode::InvalidRequest, "missing code");
    };

    let token = match discord
        .exchange_code(&code, &cfg.discord_callback_url())
        .await
    {
        Ok(t) => t,
        Err(_) => {
            return redirect_error(
                &tx,
                OAuthErrorCode::ServerError,
                "discord token exchange failed",
            )
        }
    };
    let user = match discord.fetch_user(&token.access_token).await {
        Ok(u) => u,
        Err(_) => {
            return redirect_error(
                &tx,
                OAuthErrorCode::ServerError,
                "discord user lookup failed",
            )
        }
    };
    // `sub` must be a stable Discord snowflake.
    if user.id.is_empty() || !user.id.bytes().all(|b| b.is_ascii_digit()) {
        return redirect_error(
            &tx,
            OAuthErrorCode::ServerError,
            "invalid discord user response",
        );
    }
    match discord
        .fetch_guild_member(&token.access_token, &cfg.required_guild_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return redirect_error(
                &tx,
                OAuthErrorCode::AccessDenied,
                "not a member of the required guild",
            )
        }
        Err(_) => {
            return redirect_error(
                &tx,
                OAuthErrorCode::ServerError,
                "guild membership check failed",
            )
        }
    }

    let profile = Some(ProfileClaims {
        preferred_username: user.username.clone(),
        name: user.global_name.clone(),
        picture: user.avatar_url(),
    })
    .filter(|p| p.preferred_username.is_some() || p.name.is_some() || p.picture.is_some());

    let issued = issue_code(&tx, user.id, profile, entropy, now);
    if store.put_authorization_code(&issued.record).await.is_err() {
        return redirect_error(
            &tx,
            OAuthErrorCode::ServerError,
            "authorization storage failure",
        );
    }

    let mut pairs = vec![("code", issued.plaintext.as_str())];
    if let Some(state) = tx.rp_state.as_deref() {
        pairs.push(("state", state));
    }
    CoreResponse::Redirect(redirect_with_params(&tx.redirect_uri, &pairs))
}
