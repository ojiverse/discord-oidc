//! OAuth 2.0 / OIDC error codes and rendered error pages.

use serde::Serialize;

/// OAuth 2.0 error codes used by this provider.
///
/// `as_str` returns the wire value used in `error` parameters and JSON bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    /// RFC 6749 `invalid_request`.
    InvalidRequest,
    /// RFC 6749 `invalid_client`.
    InvalidClient,
    /// RFC 6749 `invalid_grant`.
    InvalidGrant,
    /// RFC 6749 `invalid_scope`.
    InvalidScope,
    /// RFC 6749 `unauthorized_client`.
    UnauthorizedClient,
    /// RFC 6749 `unsupported_grant_type`.
    UnsupportedGrantType,
    /// RFC 6749 `unsupported_response_type`.
    UnsupportedResponseType,
    /// RFC 6749 `access_denied`.
    AccessDenied,
    /// RFC 6749 `server_error`.
    ServerError,
    /// RFC 6749 `temporarily_unavailable`.
    TemporarilyUnavailable,
    /// OIDC `login_required` — interactive authentication is required but
    /// cannot be guaranteed by this provider.
    LoginRequired,
    /// OIDC `account_selection_required` — the RP asked for account
    /// selection the provider cannot perform.
    AccountSelectionRequired,
}

impl OAuthErrorCode {
    /// Wire representation for `error` fields.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::LoginRequired => "login_required",
            Self::AccountSelectionRequired => "account_selection_required",
        }
    }
}

impl Serialize for OAuthErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// JSON body of an OAuth error response: `{ "error": ..., "error_description": ... }`.
#[derive(Debug, Serialize)]
pub struct ErrorBody<'a> {
    /// OAuth error code.
    pub error: OAuthErrorCode,
    /// Short, non-sensitive human-readable detail. Never contains internal
    /// state, tokens, or upstream payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<&'a str>,
}

/// Escapes a string for inclusion in an HTML error page.
pub fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Minimal HTML error page rendered when no redirect target is trustworthy.
pub fn error_page(title: &str, description: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>discord-oidc: {t}</title></head><body><h1>{t}</h1><p>{d}</p></body></html>",
        t = html_escape(title),
        d = html_escape(description),
    )
}
