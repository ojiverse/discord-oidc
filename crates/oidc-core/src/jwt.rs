//! RS256 JWT issuance. Signing is delegated to an [`IdTokenSigner`]
//! implementation supplied by the runtime — production uses Cloudflare Web
//! Crypto so private-key operations run in constant-time native code; tests
//! use a deterministic fake. Only the public JWK is ever exposed via JWKS.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::jwk::Jwk;
use crate::util::b64url_encode;

/// ID Token claims. `aud` is the single validated client ID; optional
/// `profile`-scope claims come from the Discord snapshot.
#[derive(Debug, Serialize)]
pub struct IdTokenClaims {
    /// Issuer (exact configured `OIDC_ISSUER_URL`).
    pub iss: String,
    /// Subject: Discord user snowflake.
    pub sub: String,
    /// Audience: validated `client_id`.
    pub aud: String,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// RP nonce, when provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access token hash claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    /// `preferred_username` (profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// `name` (profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `picture` (profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// Computes the OIDC `at_hash`: `base64url(leftmost_half(SHA-256(token)))`.
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    b64url_encode(&digest[..16])
}

/// Signing key load, validation, or sign failure.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The key material could not be parsed / imported.
    #[error("could not import OIDC signing private key (expected PKCS#8 PEM or DER)")]
    Unparseable,
    /// The signing key is weaker than the required RSA-2048 floor.
    #[error("OIDC signing key must be RSA-2048 or stronger")]
    WeakKey,
    /// Signing failed.
    #[error("JWT signing failed")]
    Sign,
}

/// Signs ID Token signing-inputs and exposes the corresponding public JWK.
///
/// Implemented by the platform adapter (Cloudflare Web Crypto in production,
/// a deterministic fake in tests) so `oidc-core` carries no cryptographic
/// signing implementation of its own.
pub trait IdTokenSigner {
    /// The `kid` placed in JWT headers and the public JWK.
    fn kid(&self) -> &str;

    /// The public JWK advertised in `/jwks.json`.
    fn public_jwk(&self) -> Jwk;

    /// Produces an RS256 signature over `signing_input` (`header.payload`).
    fn sign(
        &self,
        signing_input: String,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, KeyError>> + '_;
}

/// Serializes and signs claims with `signer`, returning a compact JWT.
pub async fn encode_claims<S: IdTokenSigner, T: Serialize>(
    signer: &S,
    claims: &T,
) -> Result<String, KeyError> {
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": signer.kid(),
    });
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(
            serde_json::to_string(claims)
                .map_err(|_| KeyError::Sign)?
                .as_bytes()
        )
    );
    let signature = signer.sign(input.clone()).await?;
    Ok(format!("{}.{}", input, b64url_encode(&signature)))
}
