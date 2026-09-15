//! JWK / JWKS handling. Only public key material is ever represented; the
//! validator for operator-supplied rotation keys actively rejects private
//! fields and malformed or undersized keys.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JWK field names that constitute private key material.
const PRIVATE_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth"];

/// Minimum accepted RSA modulus size, in bits.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;

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
    /// `n` or `e` is not valid base64url.
    #[error("JWK n/e is not valid base64url")]
    InvalidKeyMaterial,
    /// The RSA modulus is smaller than [`MIN_RSA_MODULUS_BITS`].
    #[error("JWK RSA modulus is smaller than {MIN_RSA_MODULUS_BITS} bits")]
    WeakKey,
    /// `alg` is present and not `RS256`, or `use` is present and not `sig`.
    #[error("JWK alg/use is inconsistent with RS256 signing")]
    UnsupportedAlgOrUse,
    /// `kid` is missing, empty, or uses characters outside the allowed set.
    #[error("JWK kid is missing or invalid")]
    InvalidKid,
    /// `kid` collides with the active signing key ID or another additional
    /// key.
    #[error("duplicate kid in JWKS: {0}")]
    DuplicateKeyId(String),
}

/// Returns true if `kid` uses only characters safe for a JOSE `kid` (the same
/// policy applied to `OIDC_SIGNING_KEY_ID`).
pub fn is_valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 64
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Returns the bit length of a base64url-encoded unsigned big-endian integer,
/// or `None` if the input is not valid base64url or encodes zero.
pub fn b64url_uint_bits(s: &str) -> Option<usize> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()?;
    let mut iter = bytes.iter().skip_while(|&&b| b == 0);
    let first = *iter.next()?;
    let rest = iter.count();
    Some(8 * (rest + 1) - first.leading_zeros() as usize)
}

/// Returns the bit length of the RSA modulus encoded in a JWK `n` member.
pub fn rsa_modulus_bits(n_b64url: &str) -> Option<usize> {
    b64url_uint_bits(n_b64url)
}

impl Jwk {
    /// Builds the public JWK for an RSA key from its base64url `n`/`e` and
    /// `kid`, marking it as an `RS256` signing key.
    pub fn new_rsa(n: String, e: String, kid: impl Into<String>) -> Self {
        Self {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            alg: Some("RS256".to_string()),
            kid: Some(kid.into()),
            n,
            e,
        }
    }

    /// Validates an operator-supplied JWK JSON value as a *public* RSA key.
    ///
    /// Rejects private key material outright, requires `n`/`e` to be valid
    /// base64url with a modulus of at least [`MIN_RSA_MODULUS_BITS`], enforces
    /// `alg == RS256` / `use == sig` when those members are present, and
    /// requires a well-formed `kid`.
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
        let n_bits = rsa_modulus_bits(&n).ok_or(JwkError::InvalidKeyMaterial)?;
        if n_bits < MIN_RSA_MODULUS_BITS {
            return Err(JwkError::WeakKey);
        }
        if b64url_uint_bits(&e).is_none() {
            return Err(JwkError::InvalidKeyMaterial);
        }
        match get_str("alg").as_deref() {
            None | Some("RS256") => {}
            _ => return Err(JwkError::UnsupportedAlgOrUse),
        }
        match get_str("use").as_deref() {
            None | Some("sig") => {}
            _ => return Err(JwkError::UnsupportedAlgOrUse),
        }
        let kid = get_str("kid")
            .filter(|k| is_valid_kid(k))
            .ok_or(JwkError::InvalidKid)?;
        Ok(Self {
            kty: "RSA".to_string(),
            use_: get_str("use"),
            alg: get_str("alg"),
            kid: Some(kid),
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
