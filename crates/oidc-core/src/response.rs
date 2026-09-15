//! Runtime-agnostic HTTP response model produced by core handlers.

use serde_json::Value;

/// Response produced by a core handler; the Workers adapter maps it onto
/// `worker::Response`.
#[derive(Debug)]
pub enum CoreResponse {
    /// `302 Found` redirect to the given absolute location.
    Redirect(String),
    /// JSON body with the given status code. `no_store` adds
    /// `Cache-Control: no-store` and `Pragma: no-cache` (required on `/token`).
    Json {
        /// HTTP status code.
        status: u16,
        /// JSON body.
        body: Value,
        /// Whether to emit `Cache-Control: no-store` / `Pragma: no-cache`.
        no_store: bool,
        /// Extra headers, e.g. `WWW-Authenticate` on `invalid_client`.
        extra_headers: Vec<(String, String)>,
    },
    /// Rendered HTML error page (used when no redirect URI is trustworthy).
    Html {
        /// HTTP status code.
        status: u16,
        /// HTML body.
        body: String,
    },
}

impl CoreResponse {
    /// Builds a JSON response without cache headers.
    pub fn json(status: u16, body: Value) -> Self {
        Self::Json {
            status,
            body,
            no_store: false,
            extra_headers: Vec::new(),
        }
    }

    /// Builds a JSON response with `Cache-Control: no-store` / `Pragma: no-cache`.
    pub fn json_no_store(status: u16, body: Value) -> Self {
        Self::Json {
            status,
            body,
            no_store: true,
            extra_headers: Vec::new(),
        }
    }
}
