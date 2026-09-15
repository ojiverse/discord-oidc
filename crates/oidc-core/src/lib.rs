//! Platform-agnostic OpenID Provider core for `discord-oidc`.
//!
//! This crate contains every security-relevant decision of the provider:
//! authorization request validation, PKCE verification, authorization code
//! lifecycle, client authentication, ID Token issuance, and Discord callback
//! orchestration. It has no dependency on the Cloudflare Workers runtime; the
//! `discord-oidc-worker` crate adapts it to Workers, and tests exercise it on
//! the host.

pub mod authorize;
pub mod callback;
pub mod client;
pub mod code;
pub mod config;
pub mod discord;
pub mod discovery;
pub mod error;
pub mod jwk;
pub mod jwt;
pub mod pkce;
pub mod response;
pub mod store;
pub mod token;
pub mod transaction;
pub mod util;

pub use authorize::{
    handle_authorize, validate_authorize_request, AuthorizeVerdict, ValidatedAuthorize,
};
pub use callback::handle_callback;
pub use client::{ClientConfig, ClientRegistry, ClientType, TokenEndpointAuthMethod};
pub use code::{ConsumeDeny, ExchangeCheck, StoredAuthorizationCode};
pub use config::{Config, ConfigError, ConfigInput};
pub use discord::{DiscordApi, DiscordError, DiscordMember, DiscordTokenResponse, DiscordUser};
pub use error::OAuthErrorCode;
pub use jwk::{Jwk, JwkError};
pub use jwt::{encode_claims, IdTokenClaims, IdTokenSigner, KeyError};
pub use response::CoreResponse;
pub use store::{AuthorizationStore, InMemoryStore, StoreError, TakeTransaction};
pub use token::handle_token;
pub use transaction::AuthorizationTransaction;
pub use util::Entropy;
