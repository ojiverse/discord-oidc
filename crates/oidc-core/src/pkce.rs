//! PKCE (RFC 7636) — `S256` only. `plain` is never accepted.

use subtle::ConstantTimeEq;

use crate::util::sha256_b64url;

/// `code_challenge_method` value we require.
pub const REQUIRED_CHALLENGE_METHOD: &str = "S256";

/// RFC 7636 `code_verifier` alphabet: `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Returns true if `verifier` is a well-formed RFC 7636 `code_verifier`
/// (43–128 `unreserved` characters).
pub fn is_valid_code_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len()) && verifier.bytes().all(is_unreserved)
}

/// Returns true if `challenge` is a well-formed `code_challenge` for `S256`:
/// 43–128 characters from the base64url alphabet.
pub fn is_valid_code_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Verifies `BASE64URL-ENCODE(SHA256(verifier)) == challenge` in constant time.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    if !is_valid_code_verifier(verifier) || !is_valid_code_challenge(challenge) {
        return false;
    }
    let computed = sha256_b64url(verifier.as_bytes());
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}
