//! Static OIDC client registry.
//!
//! Dynamic Client Registration is out of scope; a small set of trusted clients
//! is configured explicitly via `OIDC_CLIENTS_JSON` (public settings) and
//! `OIDC_CLIENT_SECRETS_JSON` (secret storage).

use serde::Deserialize;
use url::Url;

/// Scopes this provider can grant. Mirrors `scopes_supported` in discovery.
pub const SUPPORTED_SCOPES: &[&str] = &["openid", "profile"];

/// Client classification (`type` in `OIDC_CLIENTS_JSON`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    /// Public client (native app, CLI). No secret; PKCE is the protection.
    /// Browser SPAs are out of scope: `/token` sends no CORS headers.
    Public,
    /// Confidential client. Authenticates at `/token` via `client_secret_basic`.
    Confidential,
}

/// Authentication method a client uses at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum TokenEndpointAuthMethod {
    /// No client authentication (public clients only).
    #[serde(rename = "none")]
    None,
    /// HTTP Basic client authentication (confidential clients only).
    #[serde(rename = "client_secret_basic")]
    ClientSecretBasic,
}

/// One statically registered OIDC client.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// Unique client identifier.
    pub client_id: String,
    /// Exact redirect URIs allowed for this client.
    pub redirect_uris: Vec<String>,
    /// Scopes this client may request.
    pub allowed_scopes: Vec<String>,
    /// `public` or `confidential`.
    #[serde(rename = "type")]
    pub client_type: ClientType,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
}

/// Registry of statically configured clients, keyed by `client_id`.
#[derive(Debug)]
pub struct ClientRegistry {
    clients: Vec<ClientConfig>,
}

impl ClientRegistry {
    /// Looks a client up by exact `client_id`.
    pub fn find(&self, client_id: &str) -> Option<&ClientConfig> {
        self.clients.iter().find(|c| c.client_id == client_id)
    }

    /// Iterates over registered clients.
    pub fn iter(&self) -> impl Iterator<Item = &ClientConfig> {
        self.clients.iter()
    }
}

/// Error produced while parsing/validating `OIDC_CLIENTS_JSON` or
/// `OIDC_CLIENT_SECRETS_JSON`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// The JSON document is malformed or has the wrong shape.
    #[error("invalid clients JSON: {0}")]
    MalformedJson(String),
    /// A `client_id` is empty or duplicated.
    #[error("invalid client_id: {0}")]
    InvalidClientId(String),
    /// A redirect URI is missing, not absolute, non-HTTPS (non-loopback),
    /// has a fragment, or contains a wildcard.
    #[error("invalid redirect_uri for client {client_id}: {uri}")]
    InvalidRedirectUri {
        /// Owning client.
        client_id: String,
        /// Offending URI.
        uri: String,
    },
    /// `allowed_scopes` is empty, misses `openid`, or contains an
    /// unsupported scope.
    #[error("invalid allowed_scopes for client {0}")]
    InvalidScopes(String),
    /// `type` and `token_endpoint_auth_method` disagree (public must use
    /// `none`, confidential must use `client_secret_basic`).
    #[error("client {0}: type and token_endpoint_auth_method mismatch")]
    AuthMethodMismatch(String),
    /// The registry is empty; a provider with no clients cannot serve anyone.
    #[error("client registry is empty")]
    Empty,
    /// A confidential client has no entry in `OIDC_CLIENT_SECRETS_JSON`, or
    /// the secrets map references an unknown/public client.
    #[error("client secret configuration error: {0}")]
    SecretConfig(String),
}

/// Validates a redirect URI string.
///
/// Rules: absolute URL, HTTPS (HTTP allowed only on loopback hosts for local
/// development), no fragment, no `*` wildcard.
pub fn is_valid_redirect_uri(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() || uri.contains('*') {
        return false;
    }
    match url.scheme() {
        "https" => true,
        "http" => url
            .host_str()
            .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]"),
        _ => false,
    }
}

fn validate_client(raw: ClientConfig) -> Result<ClientConfig, RegistryError> {
    if raw.client_id.is_empty() || raw.client_id.len() > 128 {
        return Err(RegistryError::InvalidClientId(raw.client_id));
    }
    if raw.redirect_uris.is_empty() {
        return Err(RegistryError::InvalidRedirectUri {
            client_id: raw.client_id,
            uri: String::new(),
        });
    }
    for uri in &raw.redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return Err(RegistryError::InvalidRedirectUri {
                client_id: raw.client_id.clone(),
                uri: uri.clone(),
            });
        }
    }
    if raw.allowed_scopes.is_empty()
        || !raw.allowed_scopes.iter().any(|s| s == "openid")
        || raw
            .allowed_scopes
            .iter()
            .any(|s| !SUPPORTED_SCOPES.contains(&s.as_str()))
    {
        return Err(RegistryError::InvalidScopes(raw.client_id));
    }
    let consistent = matches!(
        (raw.client_type, raw.token_endpoint_auth_method),
        (ClientType::Public, TokenEndpointAuthMethod::None)
            | (
                ClientType::Confidential,
                TokenEndpointAuthMethod::ClientSecretBasic
            )
    );
    if !consistent {
        return Err(RegistryError::AuthMethodMismatch(raw.client_id));
    }
    Ok(raw)
}

/// Parses and validates `OIDC_CLIENTS_JSON` plus `OIDC_CLIENT_SECRETS_JSON`.
///
/// `secrets_json` is a JSON object mapping `client_id` to its secret; every
/// confidential client must have a secret, and secrets may only reference
/// confidential clients.
pub fn build_registry(
    clients_json: &str,
    secrets_json: Option<&str>,
) -> Result<(ClientRegistry, Vec<(String, String)>), RegistryError> {
    let raw: Vec<ClientConfig> = serde_json::from_str(clients_json)
        .map_err(|e| RegistryError::MalformedJson(e.to_string()))?;
    if raw.is_empty() {
        return Err(RegistryError::Empty);
    }
    let mut clients = Vec::with_capacity(raw.len());
    for client in raw {
        let client = validate_client(client)?;
        if clients
            .iter()
            .any(|c: &ClientConfig| c.client_id == client.client_id)
        {
            return Err(RegistryError::InvalidClientId(format!(
                "duplicate client_id {}",
                client.client_id
            )));
        }
        clients.push(client);
    }

    let secrets: Vec<(String, String)> = match secrets_json {
        None => Vec::new(),
        Some(s) => {
            let map: std::collections::BTreeMap<String, String> =
                serde_json::from_str(s).map_err(|e| RegistryError::MalformedJson(e.to_string()))?;
            map.into_iter().collect()
        }
    };
    for (id, secret) in &secrets {
        match clients.iter().find(|c| &c.client_id == id) {
            Some(c) if c.client_type == ClientType::Confidential => {
                if secret.len() < 16 {
                    return Err(RegistryError::SecretConfig(format!(
                        "secret for client {id} is shorter than 16 characters"
                    )));
                }
            }
            _ => {
                return Err(RegistryError::SecretConfig(format!(
                    "secret defined for unknown or public client {id}"
                )))
            }
        }
    }
    for client in &clients {
        if client.client_type == ClientType::Confidential
            && !secrets.iter().any(|(id, _)| id == &client.client_id)
        {
            return Err(RegistryError::SecretConfig(format!(
                "confidential client {} has no secret",
                client.client_id
            )));
        }
    }

    Ok((ClientRegistry { clients }, secrets))
}
