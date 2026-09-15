//! Authorization transaction: the internal state bridging `/authorize` and
//! the Discord OAuth2 callback. TTL is 10 minutes — long enough for a user
//! to complete the Discord login.

use serde::{Deserialize, Serialize};

use crate::config::TRANSACTION_TTL_SECS;
use crate::util::{random_token, Entropy};

/// State carried between an RP's `/authorize` request and the Discord
/// callback. `discord_oauth_state` is provider-generated and is what Discord
/// echoes back; `rp_state` is the RP's value, replayed verbatim on the final
/// redirect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationTransaction {
    /// Internal identifier (random, non-secret).
    pub id: String,
    /// Validated `client_id` of the requesting OIDC client.
    pub oidc_client_id: String,
    /// Exact-match validated redirect URI of the client.
    pub redirect_uri: String,
    /// Requested scope string as received.
    pub requested_scope: String,
    /// RP-provided `state`, echoed back to the RP.
    pub rp_state: Option<String>,
    /// RP-provided `nonce`, propagated into the ID Token.
    pub nonce: Option<String>,
    /// PKCE `code_challenge` (S256) bound to the eventual code.
    pub code_challenge: String,
    /// Provider-generated upstream OAuth state sent to Discord.
    pub discord_oauth_state: String,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Expiry time (unix seconds); transaction cannot continue past this.
    pub expires_at: i64,
}

impl AuthorizationTransaction {
    /// Creates a transaction for a validated authorize request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        oidc_client_id: String,
        redirect_uri: String,
        requested_scope: String,
        rp_state: Option<String>,
        nonce: Option<String>,
        code_challenge: String,
        entropy: &mut impl Entropy,
        now: i64,
    ) -> Self {
        Self {
            id: random_token(entropy),
            oidc_client_id,
            redirect_uri,
            requested_scope,
            rp_state,
            nonce,
            code_challenge,
            discord_oauth_state: random_token(entropy),
            created_at: now,
            expires_at: now + TRANSACTION_TTL_SECS,
        }
    }

    /// Whether the transaction has expired at `now`.
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at <= now
    }
}
