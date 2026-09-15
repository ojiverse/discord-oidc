//! `IdTokenSigner` backed by the Workers Web Crypto API (`crypto.subtle`).
//!
//! The private key is imported once per isolate and only ever lives inside
//! the platform's native crypto implementation — signing runs in
//! constant-time native code rather than a pure-Rust RSA implementation
//! (see RUSTSEC-2023-0071). The public JWK for `/jwks.json` is derived via
//! `exportKey("jwk")`.

use base64::Engine;
use js_sys::{Array, Object, Reflect, Uint8Array};
use oidc_core::jwk::{rsa_modulus_bits, Jwk, MIN_RSA_MODULUS_BITS};
use oidc_core::jwt::{IdTokenSigner, KeyError};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// RS256 signer holding a `CryptoKey` imported into Web Crypto.
pub struct WebCryptoSigner {
    key: web_sys::CryptoKey,
    jwk: Jwk,
    kid: String,
}

fn subtle() -> Result<web_sys::SubtleCrypto, KeyError> {
    let global = js_sys::global();
    let crypto = Reflect::get(&global, &"crypto".into()).map_err(|_| KeyError::Sign)?;
    Ok(crypto.unchecked_into::<web_sys::Crypto>().subtle())
}

fn rs256_algo(with_hash: bool) -> Result<Object, KeyError> {
    let algo = Object::new();
    Reflect::set(&algo, &"name".into(), &"RSASSA-PKCS1-v1_5".into()).map_err(|_| KeyError::Sign)?;
    if with_hash {
        Reflect::set(&algo, &"hash".into(), &"SHA-256".into()).map_err(|_| KeyError::Sign)?;
    }
    Ok(algo)
}

/// Converts a PKCS#8 private key supplied as PEM armor or base64 DER into
/// DER bytes for `importKey("pkcs8")`. PKCS#1 (`RSA PRIVATE KEY`) is
/// explicitly rejected — Web Crypto only accepts PKCS#8 / JWK.
fn pkcs8_to_der(material: &str) -> Option<Vec<u8>> {
    let normalized = material.replace("\\n", "\n");
    if normalized.contains("RSA PRIVATE KEY") {
        return None;
    }
    let b64: String = normalized
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn jwk_str(value: &wasm_bindgen::JsValue, name: &str) -> Option<String> {
    Reflect::get(value, &name.into()).ok()?.as_string()
}

impl WebCryptoSigner {
    /// Imports `OIDC_SIGNING_PRIVATE_KEY` (PKCS#8 PEM or base64 DER) via
    /// `crypto.subtle.importKey` and derives the public JWK via
    /// `exportKey("jwk")`. Rejects keys smaller than RSA-2048.
    pub async fn from_secret_str(material: &str, kid: impl Into<String>) -> Result<Self, KeyError> {
        let kid = kid.into();
        let der = pkcs8_to_der(material).ok_or(KeyError::Unparseable)?;
        let subtle = subtle()?;
        let usages = Array::of1(&"sign".into());
        let promise = subtle
            .import_key_with_object(
                "pkcs8",
                &Uint8Array::from(der.as_slice()),
                &rs256_algo(true)?,
                true,
                &usages,
            )
            .map_err(|_| KeyError::Unparseable)?;
        let key: web_sys::CryptoKey = JsFuture::from(promise)
            .await
            .map_err(|_| KeyError::Unparseable)?
            .unchecked_into();

        let exported = JsFuture::from(
            subtle
                .export_key("jwk", &key)
                .map_err(|_| KeyError::Unparseable)?,
        )
        .await
        .map_err(|_| KeyError::Unparseable)?;
        let n = jwk_str(&exported, "n").ok_or(KeyError::Unparseable)?;
        let e = jwk_str(&exported, "e").ok_or(KeyError::Unparseable)?;
        if rsa_modulus_bits(&n).unwrap_or(0) < MIN_RSA_MODULUS_BITS {
            return Err(KeyError::WeakKey);
        }
        Ok(Self {
            key,
            jwk: Jwk::new_rsa(n, e, kid.clone()),
            kid,
        })
    }
}

impl IdTokenSigner for WebCryptoSigner {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn public_jwk(&self) -> Jwk {
        self.jwk.clone()
    }

    async fn sign(&self, signing_input: String) -> Result<Vec<u8>, KeyError> {
        let subtle = subtle()?;
        let promise = subtle
            .sign_with_object_and_u8_array(&rs256_algo(false)?, &self.key, signing_input.as_bytes())
            .map_err(|_| KeyError::Sign)?;
        let out = JsFuture::from(promise).await.map_err(|_| KeyError::Sign)?;
        let buf: js_sys::ArrayBuffer = out.unchecked_into();
        Ok(Uint8Array::new(&buf).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::pkcs8_to_der;
    use base64::Engine;

    const PKCS8_PEM: &str =
        "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBg==\n-----END PRIVATE KEY-----\n";

    #[test]
    fn pem_armor_is_stripped() {
        assert_eq!(
            pkcs8_to_der(PKCS8_PEM).unwrap(),
            base64::engine::general_purpose::STANDARD
                .decode("MIIEvwIBADANBg==")
                .unwrap()
        );
    }

    #[test]
    fn bare_base64_der_and_escaped_newlines() {
        assert!(pkcs8_to_der("  MIIEvwIBADANBg== \n").is_some());
        assert!(pkcs8_to_der(PKCS8_PEM.replace('\n', "\\n").as_str()).is_some());
    }

    #[test]
    fn pkcs1_and_garbage_rejected() {
        assert!(pkcs8_to_der(
            "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----"
        )
        .is_none());
        assert!(pkcs8_to_der("not a key").is_none());
    }
}
