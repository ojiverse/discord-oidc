//! Small shared primitives: entropy injection and base64url / SHA-256 helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Source of cryptographically secure random bytes.
///
/// The Workers runtime implements this via `getrandom` (WebCrypto
/// `crypto.getRandomValues`); tests implement it with a seeded RNG so flows
/// are deterministic.
pub trait Entropy {
    /// Fills `dest` with cryptographically secure random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

impl<F: FnMut(&mut [u8])> Entropy for F {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self(dest);
    }
}

/// Number of raw random bytes behind a 256-bit token such as the upstream
/// Discord `state`, a provider authorization code, or an opaque access token.
pub const TOKEN_BYTES: usize = 32;

/// Returns `base64url(sha256(data))` without padding.
pub fn sha256_b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}

/// Encodes `data` as unpadded base64url.
pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes unpadded base64url, rejecting any other encoding.
pub fn b64url_decode(data: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(data.as_bytes()).ok()
}

/// Generates a cryptographically random base64url token with 256 bits of
/// entropy (43 characters).
pub fn random_token(entropy: &mut impl Entropy) -> String {
    let mut buf = [0u8; TOKEN_BYTES];
    entropy.fill_bytes(&mut buf);
    b64url_encode(&buf)
}
