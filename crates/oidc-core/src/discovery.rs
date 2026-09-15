//! `/.well-known/openid-configuration` metadata. Everything advertised here
//! must match the implementation — no capabilities we do not serve.

use serde_json::{json, Value};

use crate::client::SUPPORTED_SCOPES;
use crate::config::Config;

/// Builds the discovery document for the configured issuer.
pub fn discovery_document(cfg: &Config) -> Value {
    let issuer = &cfg.issuer;
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": SUPPORTED_SCOPES,
        "claims_supported": [
            "iss", "sub", "aud", "iat", "exp", "nonce", "at_hash",
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
    })
}
