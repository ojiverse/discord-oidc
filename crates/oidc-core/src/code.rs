//! Provider-issued authorization code: 256-bit random, TTL 60 s, single-use,
//! bound to client + redirect URI + PKCE challenge + authenticated subject.
//! Only the SHA-256 hash is persisted (DESIGN §6.4).

use serde::{Deserialize, Serialize};

use subtle::ConstantTimeEq;

use crate::config::AUTHORIZATION_CODE_TTL_SECS;
use crate::pkce;
use crate::transaction::AuthorizationTransaction;
use crate::util::{random_token, sha256_b64url, Entropy};

/// Discord profile fields snapshotted at authentication time for use as
/// ID Token claims when the `profile` scope was granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileClaims {
    /// Discord `username` -> `preferred_username`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Discord `global_name` -> `name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Discord avatar CDN URL -> `picture`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// Persisted authorization code record. The plaintext code never touches
/// storage; `code_hash` is `base64url(SHA-256(code))`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthorizationCode {
    /// `base64url(SHA-256(code))` — the storage key.
    pub code_hash: String,
    /// Client the code was issued to.
    pub client_id: String,
    /// Redirect URI the code was issued for.
    pub redirect_uri: String,
    /// Authenticated subject: the Discord user snowflake.
    pub subject: String,
    /// Granted scope string.
    pub scope: String,
    /// RP nonce to embed in the ID Token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// PKCE challenge bound to this code.
    pub code_challenge: String,
    /// Discord profile snapshot for `profile`-scope claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileClaims>,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Expiry time (unix seconds).
    pub expires_at: i64,
}

/// A freshly issued plaintext authorization code plus its stored record.
pub struct IssuedCode {
    /// The plaintext code returned to the RP (never persisted).
    pub plaintext: String,
    /// The stored record keyed by `code_hash`.
    pub record: StoredAuthorizationCode,
}

/// Issues a new authorization code for a successfully authenticated
/// transaction.
pub fn issue_code(
    tx: &AuthorizationTransaction,
    subject: String,
    profile: Option<ProfileClaims>,
    entropy: &mut impl Entropy,
    now: i64,
) -> IssuedCode {
    let plaintext = random_token(entropy);
    IssuedCode {
        record: StoredAuthorizationCode {
            code_hash: sha256_b64url(plaintext.as_bytes()),
            client_id: tx.oidc_client_id.clone(),
            redirect_uri: tx.redirect_uri.clone(),
            subject,
            scope: tx.requested_scope.clone(),
            nonce: tx.nonce.clone(),
            code_challenge: tx.code_challenge.clone(),
            profile,
            created_at: now,
            expires_at: now + AUTHORIZATION_CODE_TTL_SECS,
        },
        plaintext,
    }
}

/// Inputs the token endpoint binds against a stored code.
pub struct ExchangeCheck<'a> {
    /// Authenticated/provided `client_id`.
    pub client_id: &'a str,
    /// Provided `redirect_uri`.
    pub redirect_uri: &'a str,
    /// Provided `code_verifier`.
    pub code_verifier: &'a str,
}

/// Why an exchange was denied. All variants surface to the client as
/// `invalid_grant`; the distinction exists for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumeDeny {
    /// No live record for the presented code (unknown or already consumed).
    Unknown,
    /// The code is past `expires_at`.
    Expired,
    /// `client_id` differs from the bound client.
    ClientMismatch,
    /// `redirect_uri` differs from the bound URI.
    RedirectMismatch,
    /// PKCE verification failed.
    PkceMismatch,
}

/// Validates a stored code against an exchange request. Pure check; callers
/// delete the record on `Ok` and on `Err(Expired)`.
pub fn evaluate_code_exchange(
    record: &StoredAuthorizationCode,
    check: &ExchangeCheck,
    now: i64,
) -> Result<(), ConsumeDeny> {
    if record.expires_at <= now {
        return Err(ConsumeDeny::Expired);
    }
    if !bool::from(
        record
            .client_id
            .as_bytes()
            .ct_eq(check.client_id.as_bytes()),
    ) {
        return Err(ConsumeDeny::ClientMismatch);
    }
    if !bool::from(
        record
            .redirect_uri
            .as_bytes()
            .ct_eq(check.redirect_uri.as_bytes()),
    ) {
        return Err(ConsumeDeny::RedirectMismatch);
    }
    if !pkce::verify_s256(check.code_verifier, &record.code_challenge) {
        return Err(ConsumeDeny::PkceMismatch);
    }
    Ok(())
}

/// Computes `code_hash` for a plaintext code presented at `/token`.
pub fn hash_presented_code(plaintext: &str) -> String {
    sha256_b64url(plaintext.as_bytes())
}
