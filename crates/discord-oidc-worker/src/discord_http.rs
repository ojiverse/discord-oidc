//! `DiscordApi` implementation over the Workers `Fetch` API. Destinations are
//! fixed `discord.com` URLs — never derived from request input.

use oidc_core::config::Config;
use oidc_core::discord::{
    DiscordApi, DiscordError, DiscordMember, DiscordTokenResponse, DiscordUser, DISCORD_API_BASE,
    DISCORD_TOKEN_URL,
};
use url::form_urlencoded;
use wasm_bindgen::JsValue;
use worker::{Fetch, Headers, Method, Request, RequestInit, Response};

/// Discord API client bound to the configured application credentials.
pub struct DiscordHttp<'a> {
    cfg: &'a Config,
}

impl<'a> DiscordHttp<'a> {
    /// Creates a client for the configured Discord application.
    pub fn new(cfg: &'a Config) -> Self {
        Self { cfg }
    }
}

fn to_err(e: worker::Error) -> DiscordError {
    worker::console_error!("discord fetch error: {e}");
    DiscordError::Transport
}

async fn send(req: Request) -> Result<Response, DiscordError> {
    Fetch::Request(req).send().await.map_err(to_err)
}

fn get(url: &str, access_token: &str) -> Result<Request, DiscordError> {
    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {access_token}"))
        .and_then(|_| headers.set("Accept", "application/json"))
        .and_then(|_| headers.set("User-Agent", "discord-oidc"))
        .map_err(to_err)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    Request::new_with_init(url, &init).map_err(to_err)
}

impl DiscordApi for DiscordHttp<'_> {
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<DiscordTokenResponse, DiscordError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &self.cfg.discord_client_id)
            .append_pair("client_secret", &self.cfg.discord_client_secret)
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", redirect_uri)
            .finish();
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/x-www-form-urlencoded")
            .and_then(|_| headers.set("Accept", "application/json"))
            .map_err(to_err)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(JsValue::from_str(&body)));
        let req = Request::new_with_init(DISCORD_TOKEN_URL, &init).map_err(to_err)?;
        let mut resp = send(req).await?;
        if resp.status_code() != 200 {
            return Err(DiscordError::HttpStatus(resp.status_code()));
        }
        resp.json::<DiscordTokenResponse>()
            .await
            .map_err(|_| DiscordError::MalformedResponse)
    }

    async fn fetch_user(&self, access_token: &str) -> Result<DiscordUser, DiscordError> {
        let req = get(&format!("{DISCORD_API_BASE}/users/@me"), access_token)?;
        let mut resp = send(req).await?;
        if resp.status_code() != 200 {
            return Err(DiscordError::HttpStatus(resp.status_code()));
        }
        resp.json::<DiscordUser>()
            .await
            .map_err(|_| DiscordError::MalformedResponse)
    }

    async fn fetch_guild_member(
        &self,
        access_token: &str,
        guild_id: &str,
    ) -> Result<Option<DiscordMember>, DiscordError> {
        let req = get(
            &format!("{DISCORD_API_BASE}/users/@me/guilds/{guild_id}/member"),
            access_token,
        )?;
        let mut resp = send(req).await?;
        match resp.status_code() {
            200 => resp
                .json::<DiscordMember>()
                .await
                .map(Some)
                .map_err(|_| DiscordError::MalformedResponse),
            404 => Ok(None),
            status => Err(DiscordError::HttpStatus(status)),
        }
    }
}
