//! Discord OAuth2 / API boundary. Endpoints are fixed constants — request
//! parameters can never steer outbound requests (SECURITY §4.12).

use serde::Deserialize;
use url::Url;

use crate::config::Config;

/// Discord OAuth2 authorization endpoint (fixed).
pub const DISCORD_AUTHORIZE_URL: &str = "https://discord.com/oauth2/authorize";
/// Discord token endpoint (fixed, API version pinned).
pub const DISCORD_TOKEN_URL: &str = "https://discord.com/api/v10/oauth2/token";
/// Discord REST API base (fixed, API version pinned).
pub const DISCORD_API_BASE: &str = "https://discord.com/api/v10";
/// OAuth scopes requested from Discord: `identify guilds.members.read`.
pub const DISCORD_SCOPES: &str = "identify guilds.members.read";

/// Builds the Discord authorization redirect for an in-flight transaction.
pub fn discord_authorize_url(cfg: &Config, discord_oauth_state: &str) -> String {
    let mut url = Url::parse(DISCORD_AUTHORIZE_URL).expect("constant URL");
    url.query_pairs_mut()
        .append_pair("client_id", &cfg.discord_client_id)
        .append_pair("redirect_uri", &cfg.discord_callback_url())
        .append_pair("response_type", "code")
        .append_pair("scope", DISCORD_SCOPES)
        .append_pair("state", discord_oauth_state);
    url.into()
}

/// Discord `/oauth2/token` success response.
#[derive(Debug, Deserialize)]
pub struct DiscordTokenResponse {
    /// Discord access token (used only for `/users/@me` and the guild member
    /// lookup; never stored or returned to an RP).
    pub access_token: String,
}

/// Discord `GET /users/@me` fields we consume.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscordUser {
    /// Stable user snowflake -> `sub`.
    pub id: String,
    /// Discord username -> `preferred_username` (profile scope).
    pub username: Option<String>,
    /// Display name -> `name` (profile scope).
    pub global_name: Option<String>,
    /// Avatar hash -> `picture` (profile scope).
    pub avatar: Option<String>,
}

impl DiscordUser {
    /// CDN avatar URL, if the user has a custom avatar.
    pub fn avatar_url(&self) -> Option<String> {
        self.avatar.as_ref().map(|hash| {
            format!(
                "https://cdn.discordapp.com/avatars/{}/{}.png",
                self.id, hash
            )
        })
    }
}

/// Discord `GET /users/@me/guilds/{id}/member` response. Presence is what
/// matters; fields are deserialized leniently.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscordMember {
    /// Guild role IDs (unused today; reserved for future claims).
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Failure talking to Discord. Never carries token material.
#[derive(Debug, thiserror::Error)]
pub enum DiscordError {
    /// Network/transport failure.
    #[error("discord request failed")]
    Transport,
    /// Discord returned a non-success status (404 on the member lookup is
    /// handled separately and is not an error).
    #[error("discord returned HTTP {0}")]
    HttpStatus(u16),
    /// Response body did not match the expected shape.
    #[error("malformed discord response")]
    MalformedResponse,
}

/// Discord API operations required by the authentication flow.
pub trait DiscordApi {
    /// Exchanges a Discord authorization code for tokens.
    /// `redirect_uri` is this provider's own callback URL.
    fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> impl std::future::Future<Output = Result<DiscordTokenResponse, DiscordError>>;

    /// `GET /users/@me`.
    fn fetch_user(
        &self,
        access_token: &str,
    ) -> impl std::future::Future<Output = Result<DiscordUser, DiscordError>>;

    /// `GET /users/@me/guilds/{guild_id}/member`. `Ok(None)` means Discord
    /// returned 404 — the user is not a member.
    fn fetch_guild_member(
        &self,
        access_token: &str,
        guild_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<DiscordMember>, DiscordError>>;
}
