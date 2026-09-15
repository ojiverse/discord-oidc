//! Provider configuration assembled from environment variables and secrets.
//!
//! The configured `OIDC_ISSUER_URL` is the single source of issuer identity;
//! nothing is ever derived from request `Host` headers.

use std::collections::HashMap;

use url::Url;

use crate::client::{build_registry, ClientRegistry, RegistryError};
use crate::jwk::{Jwk, JwkError};

/// Authorization transaction lifetime (seconds): long enough for a user to
/// complete the Discord login, short enough to bound stored state.
pub const TRANSACTION_TTL_SECS: i64 = 600;
/// Provider authorization code lifetime (seconds): exchanged immediately by
/// the relying party, so a short window suffices.
pub const AUTHORIZATION_CODE_TTL_SECS: i64 = 60;
/// Default ID Token lifetime (seconds).
pub const DEFAULT_ID_TOKEN_TTL_SECS: i64 = 900;

/// Raw configuration strings as read from bindings. `None` means the binding
/// is absent.
#[derive(Debug, Default)]
pub struct ConfigInput {
    /// `OIDC_ISSUER_URL` — stable HTTPS issuer origin, no path/query/fragment.
    pub issuer_url: Option<String>,
    /// `DISCORD_CLIENT_ID`.
    pub discord_client_id: Option<String>,
    /// `DISCORD_CLIENT_SECRET` (secret).
    pub discord_client_secret: Option<String>,
    /// `DISCORD_REQUIRED_GUILD_ID`.
    pub required_guild_id: Option<String>,
    /// `OIDC_CLIENTS_JSON` — static client registry.
    pub clients_json: Option<String>,
    /// `OIDC_CLIENT_SECRETS_JSON` — confidential client secrets (secret).
    pub client_secrets_json: Option<String>,
    /// `OIDC_SIGNING_KEY_ID` — `kid` for the active signing key.
    pub signing_key_id: Option<String>,
    /// `OIDC_SIGNING_PRIVATE_KEY` — PKCS#8 PEM / base64 DER, RSA ≥2048
    /// (secret). PKCS#1 is not accepted by Web Crypto `importKey`.
    pub signing_private_key: Option<String>,
    /// `OIDC_JWKS_ADDITIONAL_PUBLIC_KEYS` — retired public JWKs kept in JWKS
    /// during rotation overlap.
    pub additional_public_jwks_json: Option<String>,
    /// `OIDC_ID_TOKEN_TTL_SECONDS` — defaults to 900.
    pub id_token_ttl_seconds: Option<String>,
}

/// Validated provider configuration.
#[derive(Debug)]
pub struct Config {
    /// Canonical issuer identifier (no trailing slash). Used verbatim for
    /// `iss` and discovery metadata.
    pub issuer: String,
    /// Discord application client ID.
    pub discord_client_id: String,
    /// Discord application client secret.
    pub discord_client_secret: String,
    /// Discord Guild snowflake whose membership is required.
    pub required_guild_id: String,
    /// Static OIDC client registry.
    pub clients: ClientRegistry,
    /// `client_id` -> secret for confidential clients.
    pub client_secrets: HashMap<String, String>,
    /// `kid` of the active signing key.
    pub signing_key_id: String,
    /// Retired public JWKs still advertised during rotation overlap.
    pub additional_public_jwks: Vec<Jwk>,
    /// ID Token lifetime in seconds.
    pub id_token_ttl_secs: i64,
}

/// Configuration validation failure. Safe to log (contains no secret values).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is absent.
    #[error("missing required configuration: {0}")]
    Missing(&'static str),
    /// `OIDC_ISSUER_URL` is not an absolute HTTPS origin (no
    /// path/query/fragment/userinfo).
    #[error("invalid OIDC_ISSUER_URL: {0}")]
    InvalidIssuer(String),
    /// A Discord snowflake field is not all digits.
    #[error("invalid Discord snowflake in {0}")]
    InvalidSnowflake(&'static str),
    /// `OIDC_SIGNING_KEY_ID` contains characters unsafe for a `kid`.
    #[error("invalid OIDC_SIGNING_KEY_ID")]
    InvalidKeyId,
    /// Client registry or secrets JSON failed validation.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// `OIDC_JWKS_ADDITIONAL_PUBLIC_KEYS` failed validation.
    #[error(transparent)]
    Jwk(#[from] JwkError),
    /// `OIDC_ID_TOKEN_TTL_SECONDS` is not a positive integer.
    #[error("invalid OIDC_ID_TOKEN_TTL_SECONDS")]
    InvalidIdTokenTtl,
}

/// Returns true if `value` looks like a Discord snowflake (all ASCII digits,
/// plausible length).
fn is_snowflake(value: &str) -> bool {
    (15..=22).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
}

impl Config {
    /// Parses and validates the whole configuration.
    pub fn from_input(input: &ConfigInput) -> Result<Self, ConfigError> {
        let issuer_raw = required(input.issuer_url.as_deref(), "OIDC_ISSUER_URL")?;
        let issuer = validate_issuer(issuer_raw)?;

        let discord_client_id = required(input.discord_client_id.as_deref(), "DISCORD_CLIENT_ID")?;
        if !is_snowflake(discord_client_id) {
            return Err(ConfigError::InvalidSnowflake("DISCORD_CLIENT_ID"));
        }
        let required_guild_id = required(
            input.required_guild_id.as_deref(),
            "DISCORD_REQUIRED_GUILD_ID",
        )?;
        if !is_snowflake(required_guild_id) {
            return Err(ConfigError::InvalidSnowflake("DISCORD_REQUIRED_GUILD_ID"));
        }
        let discord_client_secret = required(
            input.discord_client_secret.as_deref(),
            "DISCORD_CLIENT_SECRET",
        )?;
        if discord_client_secret.is_empty() {
            return Err(ConfigError::Missing("DISCORD_CLIENT_SECRET"));
        }

        let signing_key_id = required(input.signing_key_id.as_deref(), "OIDC_SIGNING_KEY_ID")?;
        if signing_key_id.is_empty()
            || signing_key_id.len() > 64
            || !signing_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ConfigError::InvalidKeyId);
        }

        required(
            input.signing_private_key.as_deref(),
            "OIDC_SIGNING_PRIVATE_KEY",
        )?;

        let (clients, secrets) = build_registry(
            required(input.clients_json.as_deref(), "OIDC_CLIENTS_JSON")?,
            input.client_secrets_json.as_deref(),
        )?;

        let additional_public_jwks = match input.additional_public_jwks_json.as_deref() {
            None => Vec::new(),
            Some(json) => {
                let raw: Vec<serde_json::Value> = serde_json::from_str(json)
                    .map_err(|e| ConfigError::Jwk(JwkError::Malformed(e.to_string())))?;
                let mut seen_kids = std::collections::HashSet::with_capacity(raw.len() + 1);
                seen_kids.insert(signing_key_id.to_string());
                let mut keys = Vec::with_capacity(raw.len());
                for value in raw {
                    let jwk = Jwk::validate_public(&value)?;
                    if let Some(kid) = jwk.kid.as_deref() {
                        if !seen_kids.insert(kid.to_string()) {
                            return Err(ConfigError::Jwk(JwkError::DuplicateKeyId(
                                kid.to_string(),
                            )));
                        }
                    }
                    keys.push(jwk);
                }
                keys
            }
        };

        let id_token_ttl_secs = match input.id_token_ttl_seconds.as_deref() {
            None => DEFAULT_ID_TOKEN_TTL_SECS,
            Some(s) => {
                let ttl: i64 = s.parse().map_err(|_| ConfigError::InvalidIdTokenTtl)?;
                if !(60..=3600).contains(&ttl) {
                    return Err(ConfigError::InvalidIdTokenTtl);
                }
                ttl
            }
        };

        Ok(Self {
            issuer,
            discord_client_id: discord_client_id.to_string(),
            discord_client_secret: discord_client_secret.to_string(),
            required_guild_id: required_guild_id.to_string(),
            clients,
            client_secrets: secrets.into_iter().collect(),
            signing_key_id: signing_key_id.to_string(),
            additional_public_jwks,
            id_token_ttl_secs,
        })
    }

    /// Discord OAuth2 redirect URI for this provider:
    /// `{issuer}/oauth/discord/callback`.
    pub fn discord_callback_url(&self) -> String {
        format!("{}/oauth/discord/callback", self.issuer)
    }

    /// Secret configured for a confidential client, if any.
    pub fn client_secret(&self, client_id: &str) -> Option<&str> {
        self.client_secrets.get(client_id).map(String::as_str)
    }
}

fn required<'a>(value: Option<&'a str>, name: &'static str) -> Result<&'a str, ConfigError> {
    match value {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(name)),
    }
}

/// Validates `OIDC_ISSUER_URL`: an absolute HTTPS *origin* — no userinfo, no
/// query, no fragment, and no path components. Endpoints are routed at fixed
/// root paths (`/authorize`, `/token`, ...), so a path-bearing issuer would
/// produce discovery metadata that cannot be served.
pub fn validate_issuer(raw: &str) -> Result<String, ConfigError> {
    let url = Url::parse(raw).map_err(|_| ConfigError::InvalidIssuer(raw.to_string()))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.path() != "/"
    {
        return Err(ConfigError::InvalidIssuer(raw.to_string()));
    }
    Ok(raw.trim_end_matches('/').to_string())
}
