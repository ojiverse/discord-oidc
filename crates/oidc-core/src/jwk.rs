//! JWK / JWKS handling. Only public key material is ever represented; the
//! validator for operator-supplied rotation keys actively rejects private
//! fields.

use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::b64url_encode;

/// JWK field names that constitute private key material.
const PRIVATE_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth"];

/// A public RSA JWK (`RS256`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Always `RSA`.
    pub kty: String,
    /// Always `sig` when present.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Always `RS256` when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Modulus, base64url.
    pub n: String,
    /// Exponent, base64url.
    pub e: String,
}

/// Errors validating an operator-supplied public JWK.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwkError {
    /// JSON was malformed.
    #[error("malformed JWK JSON: {0}")]
    Malformed(String),
    /// A private field (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`) is present.
    #[error("JWK contains private key material")]
    PrivateMaterial,
    /// `kty`, `n` or `e` is missing/mistyped, or `kty` is not `RSA`.
    #[error("JWK is not a valid RSA public key")]
    NotRsaPublic,
    /// `kid` collides with the active signing key ID.
    #[error("duplicate kid in additional JWKS: {0}")]
    DuplicateKeyId(String),
}

impl Jwk {
    /// Derives the public JWK for an RSA public key.
    pub fn from_public_key(key: &RsaPublicKey, kid: &str) -> Self {
        Self {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            alg: Some("RS256".to_string()),
            kid: Some(kid.to_string()),
            n: b64url_encode(&key.n().to_bytes_be()),
            e: b64url_encode(&key.e().to_bytes_be()),
        }
    }

    /// Validates an operator-supplied JWK JSON value as a *public* RSA key.
    /// Rejects any private key material outright.
    pub fn validate_public(value: &Value) -> Result<Self, JwkError> {
        let obj = value
            .as_object()
            .ok_or_else(|| JwkError::Malformed("not a JSON object".to_string()))?;
        if PRIVATE_FIELDS.iter().any(|f| obj.contains_key(*f)) {
            return Err(JwkError::PrivateMaterial);
        }
        let get_str =
            |name: &str| -> Option<String> { obj.get(name)?.as_str().map(str::to_string) };
        match get_str("kty").as_deref() {
            Some("RSA") => {}
            _ => return Err(JwkError::NotRsaPublic),
        }
        let n = get_str("n").ok_or(JwkError::NotRsaPublic)?;
        let e = get_str("e").ok_or(JwkError::NotRsaPublic)?;
        Ok(Self {
            kty: "RSA".to_string(),
            use_: get_str("use"),
            alg: get_str("alg"),
            kid: get_str("kid"),
            n,
            e,
        })
    }
}

/// Builds the `{ "keys": [...] }` JWKS document.
pub fn jwks_document(keys: &[Jwk]) -> Value {
    Value::Object(serde_json::Map::from_iter([(
        "keys".to_string(),
        Value::Array(
            keys.iter()
                .map(|k| serde_json::to_value(k).unwrap())
                .collect(),
        ),
    )]))
}
