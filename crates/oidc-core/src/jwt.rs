//! RS256 JWT issuance. Signing uses the `rsa` crate (no private key material
//! ever leaves the provider; only the public JWK is exposed via JWKS).

use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

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

fn parse_private_key(material: &str) -> Result<RsaPrivateKey, KeyError> {
    if material.contains("BEGIN RSA PRIVATE KEY") {
        return RsaPrivateKey::from_pkcs1_pem(material).map_err(|_| KeyError::Unparseable);
    }
    if material.contains("BEGIN") {
        return RsaPrivateKey::from_pkcs8_pem(material).map_err(|_| KeyError::Unparseable);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(material.trim())
        .map_err(|_| KeyError::Unparseable)?;
    RsaPrivateKey::from_pkcs8_der(&der)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(&der))
        .map_err(|_| KeyError::Unparseable)
}

/// Signing key load failure.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The key material could not be parsed as PKCS#8 / PKCS#1 PEM or DER.
    #[error("could not parse OIDC signing private key (expected PKCS#8 PEM or DER)")]
    Unparseable,
    /// Signing failed.
    #[error("RSA signing failed")]
    Sign,
}

/// An RS256 signer bound to a `kid`.
pub struct Rs256Signer {
    private: RsaPrivateKey,
    kid: String,
}

impl Rs256Signer {
    /// Loads a private key from a PEM (PKCS#8 `PRIVATE KEY` or PKCS#1
    /// `RSA PRIVATE KEY`) or base64-encoded DER string.
    pub fn from_secret_str(material: &str, kid: impl Into<String>) -> Result<Self, KeyError> {
        Ok(Self {
            private: parse_private_key(&material.replace("\\n", "\n"))?,
            kid: kid.into(),
        })
    }

    /// Wraps an existing key (tests).
    pub fn from_private_key(private: RsaPrivateKey, kid: impl Into<String>) -> Self {
        Self {
            private,
            kid: kid.into(),
        }
    }

    /// The `kid` placed in JWT headers and the public JWK.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The corresponding RSA public key.
    pub fn public_key(&self) -> RsaPublicKey {
        self.private.to_public_key()
    }

    /// Produces an RS256 signature over `signing_input`.
    pub fn sign_rs256(&self, signing_input: &str) -> Result<Vec<u8>, KeyError> {
        let digest = Sha256::digest(signing_input.as_bytes());
        self.private
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|_| KeyError::Sign)
    }

    /// Serializes and signs claims, returning a compact JWT.
    pub fn encode_claims<T: Serialize>(&self, claims: &T) -> Result<String, KeyError> {
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.kid,
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
        let signature = self.sign_rs256(&input)?;
        Ok(format!("{}.{}", input, b64url_encode(&signature)))
    }
}
