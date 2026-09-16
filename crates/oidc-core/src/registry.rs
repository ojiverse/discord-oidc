//! Dynamic OIDC client registry: persistent records and pure transitions.
//!
//! Dynamic clients are registered at runtime through the admin API and stored
//! in the `ClientRegistryState` Durable Object. This module carries every
//! security-relevant decision — validation, fixed OIDC policy, identifier and
//! secret generation, rotation and status transitions — as pure logic so the
//! Durable Object stays a storage-IO adapter and the behavior is testable on
//! the host.
//!
//! Confidential client secrets are never persisted: only
//! `SHA-256(client_secret)` (base64url) is stored, and the plaintext is
//! returned exactly once at create/rotate time.

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::client::{
    is_valid_redirect_uri, ClientConfig, ClientType, TokenEndpointAuthMethod, SUPPORTED_SCOPES,
};
use crate::config::is_snowflake;
use crate::util::{b64url_encode, random_token, sha256_b64url, Entropy};

/// `client_id` prefix for dynamically registered clients.
pub const CLIENT_ID_PREFIX: &str = "oji_";
/// Random bits behind a generated `client_id`.
const CLIENT_ID_BYTES: usize = 16;
/// Maximum `display_name` length in UTF-8 bytes (after trimming).
pub const MAX_DISPLAY_NAME_BYTES: usize = 128;
/// Maximum number of redirect URIs per client.
pub const MAX_REDIRECT_URIS: usize = 16;
/// How long a rotated-out secret remains valid (seconds).
pub const SECRET_ROTATION_OVERLAP_SECS: i64 = 600;

/// Lifecycle status of a dynamic client.
///
/// `disabled` clients are immediately unusable for new authorizations and
/// token exchanges; `active` is the only state that can authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientStatus {
    /// Usable in the data plane.
    Active,
    /// Rejected everywhere in the data plane.
    Disabled,
}

/// Persistent record for a dynamically registered client.
///
/// Storage key: `client:<client_id>`. `client_id`, `client_type`,
/// `token_endpoint_auth_method`, and `allowed_scopes` are immutable after
/// creation; `display_name`, `owner_discord_user_id`, and `redirect_uris` are
/// replaced via metadata update; `status` changes only through
/// enable/disable; the secret changes only through rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicClientRecord {
    /// Server-generated identifier (`oji_` + base64url of 128 random bits).
    pub client_id: String,
    /// Human-readable service name for operators.
    pub display_name: String,
    /// OJIverse-internal owner contact (Discord snowflake). Accountability
    /// metadata only — not used in authorization decisions and never
    /// verified against the Discord API.
    pub owner_discord_user_id: String,
    /// Exact redirect URIs allowed for this client.
    pub redirect_uris: Vec<String>,
    /// `public` or `confidential`.
    pub client_type: ClientType,
    /// Derived from `client_type`; fixed provider policy.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Derived from `client_type`; always `["openid"]`.
    pub allowed_scopes: Vec<String>,
    /// `active` or `disabled`.
    pub status: ClientStatus,
    /// `base64url(SHA-256(current client_secret))`; confidential only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_secret_hash: Option<String>,
    /// Hash of the most recently rotated-out secret; accepted at `/token`
    /// until `previous_secret_valid_until`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_secret_hash: Option<String>,
    /// Unix seconds until which `previous_secret_hash` is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_secret_valid_until: Option<i64>,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Last mutation time (unix seconds).
    pub updated_at: i64,
    /// When the client was disabled (unix seconds); cleared on enable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<i64>,
}

/// Validated mutable client metadata (create / replace input).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Trimmed human-readable name.
    pub display_name: String,
    /// Owner contact Discord snowflake.
    pub owner_discord_user_id: String,
    /// Exact redirect URIs (deduplicated).
    pub redirect_uris: Vec<String>,
}

/// Client metadata validation failure; `Display` strings are safe to return
/// to the API caller as `error_description`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    /// `display_name` is empty or exceeds 128 UTF-8 bytes after trimming.
    #[error("display_name must be 1..=128 UTF-8 bytes after trimming")]
    DisplayName,
    /// `owner_discord_user_id` is not a Discord snowflake.
    #[error("owner_discord_user_id must be a Discord snowflake (15..=22 ASCII digits)")]
    OwnerSnowflake,
    /// `redirect_uris` is empty or has more than 16 entries.
    #[error("redirect_uris must contain 1..=16 entries")]
    RedirectCount,
    /// The same redirect URI appears twice.
    #[error("redirect_uris contains duplicates")]
    RedirectDuplicate,
    /// A redirect URI fails `is_valid_redirect_uri` policy.
    #[error("invalid redirect_uri: {0}")]
    RedirectUri(String),
}

/// Validates create/update client metadata and returns the normalized form
/// (trimmed `display_name`, verified-unique `redirect_uris`).
pub fn validate_metadata(
    display_name: &str,
    owner_discord_user_id: &str,
    redirect_uris: &[String],
) -> Result<ClientMetadata, ValidationError> {
    let name = display_name.trim();
    if name.is_empty() || name.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(ValidationError::DisplayName);
    }
    if !is_snowflake(owner_discord_user_id) {
        return Err(ValidationError::OwnerSnowflake);
    }
    if redirect_uris.is_empty() || redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(ValidationError::RedirectCount);
    }
    let mut seen = HashSet::with_capacity(redirect_uris.len());
    for uri in redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return Err(ValidationError::RedirectUri(uri.clone()));
        }
        if !seen.insert(uri.as_str()) {
            return Err(ValidationError::RedirectDuplicate);
        }
    }
    Ok(ClientMetadata {
        display_name: name.to_string(),
        owner_discord_user_id: owner_discord_user_id.to_string(),
        redirect_uris: redirect_uris.to_vec(),
    })
}

/// Fixed OIDC policy for a client type: scopes and token-endpoint auth
/// method are never caller-controlled.
pub fn fixed_policy(client_type: ClientType) -> (Vec<String>, TokenEndpointAuthMethod) {
    let scopes = SUPPORTED_SCOPES.iter().map(|s| s.to_string()).collect();
    let method = match client_type {
        ClientType::Public => TokenEndpointAuthMethod::None,
        ClientType::Confidential => TokenEndpointAuthMethod::ClientSecretBasic,
    };
    (scopes, method)
}

/// Generates a `client_id`: `oji_` + base64url-no-pad of 128 random bits
/// (22 characters). Callers must still check the registry for collisions.
pub fn generate_client_id(entropy: &mut impl Entropy) -> String {
    let mut buf = [0u8; CLIENT_ID_BYTES];
    entropy.fill_bytes(&mut buf);
    format!("{CLIENT_ID_PREFIX}{}", b64url_encode(&buf))
}

/// Whether `client_id` matches the dynamic-ID format (`oji_` + 22
/// base64url-no-pad characters).
///
/// The data plane must apply this filter before consulting the dynamic
/// registry: an arbitrary request `client_id` is untrusted input, and an
/// identifier containing `/` or `.` segments could alias an existing record
/// through URL path normalization inside the Durable Object stub. OIDC
/// `client_id`s are opaque and must match exactly.
pub fn is_dynamic_client_id(client_id: &str) -> bool {
    let Some(rest) = client_id.strip_prefix(CLIENT_ID_PREFIX) else {
        return false;
    };
    rest.len() == 22
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A freshly generated confidential client secret.
pub struct IssuedSecret {
    /// 256-bit base64url plaintext; returned to the caller exactly once.
    pub plaintext: String,
    /// `base64url(SHA-256(plaintext))`; the only persisted form.
    pub hash: String,
}

/// Generates a 256-bit client secret. Only `hash` may be persisted.
pub fn generate_client_secret(entropy: &mut impl Entropy) -> IssuedSecret {
    let plaintext = random_token(entropy);
    let hash = sha256_b64url(plaintext.as_bytes());
    IssuedSecret { plaintext, hash }
}

/// Rotation failure: the client has no secret to rotate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("client has no secret")]
pub struct NoSecret;

impl DynamicClientRecord {
    /// Builds a new active record. `secret_hash` is required for confidential
    /// clients and must be `None` for public clients.
    pub fn new(
        client_id: String,
        metadata: ClientMetadata,
        client_type: ClientType,
        secret_hash: Option<String>,
        now: i64,
    ) -> Self {
        let (allowed_scopes, token_endpoint_auth_method) = fixed_policy(client_type);
        Self {
            client_id,
            display_name: metadata.display_name,
            owner_discord_user_id: metadata.owner_discord_user_id,
            redirect_uris: metadata.redirect_uris,
            client_type,
            token_endpoint_auth_method,
            allowed_scopes,
            status: ClientStatus::Active,
            current_secret_hash: secret_hash,
            previous_secret_hash: None,
            previous_secret_valid_until: None,
            created_at: now,
            updated_at: now,
            disabled_at: None,
        }
    }

    /// Whether the client may authenticate in the data plane.
    pub fn is_active(&self) -> bool {
        self.status == ClientStatus::Active
    }

    /// The record as the data-plane client shape shared with static clients.
    pub fn to_client_config(&self) -> ClientConfig {
        ClientConfig {
            client_id: self.client_id.clone(),
            redirect_uris: self.redirect_uris.clone(),
            allowed_scopes: self.allowed_scopes.clone(),
            client_type: self.client_type,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
        }
    }

    /// Replaces the mutable metadata fields. Never touches `status`.
    pub fn apply_metadata(&mut self, metadata: ClientMetadata, now: i64) {
        self.display_name = metadata.display_name;
        self.owner_discord_user_id = metadata.owner_discord_user_id;
        self.redirect_uris = metadata.redirect_uris;
        self.updated_at = now;
    }

    /// Disables the client. Idempotent: an already-disabled record is
    /// returned unchanged.
    pub fn disable(&mut self, now: i64) {
        if self.status == ClientStatus::Active {
            self.status = ClientStatus::Disabled;
            self.disabled_at = Some(now);
            self.updated_at = now;
        }
    }

    /// Re-enables the client. Idempotent.
    pub fn enable(&mut self, now: i64) {
        if self.status == ClientStatus::Disabled {
            self.status = ClientStatus::Active;
            self.disabled_at = None;
            self.updated_at = now;
        }
    }

    /// Rotates the secret: the current hash becomes the previous hash,
    /// accepted for [`SECRET_ROTATION_OVERLAP_SECS`]; only the immediately
    /// preceding secret is kept — any older previous hash is dropped.
    /// Returns the unix time the previous secret stops being accepted.
    pub fn rotate_secret(&mut self, new_secret_hash: String, now: i64) -> Result<i64, NoSecret> {
        if self.client_type != ClientType::Confidential {
            return Err(NoSecret);
        }
        let valid_until = now + SECRET_ROTATION_OVERLAP_SECS;
        self.previous_secret_hash = self.current_secret_hash.replace(new_secret_hash);
        self.previous_secret_valid_until =
            self.previous_secret_hash.is_some().then_some(valid_until);
        self.updated_at = now;
        Ok(valid_until)
    }

    /// Constant-time verification of a presented secret against the current
    /// hash, then the previous hash while its overlap window is open.
    /// Disabled clients never verify.
    pub fn verify_secret(&self, presented: &str, now: i64) -> bool {
        if !self.is_active() {
            return false;
        }
        let presented_hash = sha256_b64url(presented.as_bytes());
        if let Some(current) = &self.current_secret_hash {
            if bool::from(current.as_bytes().ct_eq(presented_hash.as_bytes())) {
                return true;
            }
        }
        if self
            .previous_secret_valid_until
            .is_some_and(|until| until > now)
        {
            if let Some(previous) = &self.previous_secret_hash {
                return bool::from(previous.as_bytes().ct_eq(presented_hash.as_bytes()));
            }
        }
        false
    }
}

/// Registry storage failure (Durable Object IO).
#[derive(Debug, thiserror::Error)]
#[error("client registry storage failure")]
pub struct RegistryStoreError;

/// Result of a secret rotation applied inside the registry.
#[derive(Debug)]
pub enum RotateOutcome {
    /// Rotation applied; carries the updated record.
    Rotated(Box<DynamicClientRecord>),
    /// No client with that `client_id`.
    NotFound,
    /// The client is public and has no secret to rotate.
    NoSecret,
}

/// Persistent store of dynamic client records.
///
/// Mutations are read-modify-write operations; implementations must apply
/// each transition atomically (the Durable Object adapter relies on object
/// serialization within a single fetch invocation) so concurrent
/// update/rotation cannot lose updates.
pub trait DynamicClientRegistry {
    /// Returns the record for `client_id`, if present.
    fn get(
        &self,
        client_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<DynamicClientRecord>, RegistryStoreError>>;

    /// Returns all records, ordered by `client_id`.
    fn list(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<DynamicClientRecord>, RegistryStoreError>>;

    /// Inserts a new record. `Ok(false)` means `client_id` already exists;
    /// the record is unchanged in that case.
    fn insert(
        &self,
        record: &DynamicClientRecord,
    ) -> impl std::future::Future<Output = Result<bool, RegistryStoreError>>;

    /// Atomically replaces the mutable metadata fields of an existing
    /// record; `status` and secret state are preserved.
    fn update_metadata(
        &self,
        client_id: &str,
        metadata: &ClientMetadata,
        now: i64,
    ) -> impl std::future::Future<Output = Result<Option<DynamicClientRecord>, RegistryStoreError>>;

    /// Atomically applies an idempotent status transition.
    fn set_status(
        &self,
        client_id: &str,
        status: ClientStatus,
        now: i64,
    ) -> impl std::future::Future<Output = Result<Option<DynamicClientRecord>, RegistryStoreError>>;

    /// Atomically rotates the secret to `new_secret_hash`.
    fn rotate_secret(
        &self,
        client_id: &str,
        new_secret_hash: &str,
        now: i64,
    ) -> impl std::future::Future<Output = Result<RotateOutcome, RegistryStoreError>>;
}

/// In-memory [`DynamicClientRegistry`] for tests and host-side reasoning.
/// Atomicity is trivially provided by holding the mutex across each
/// transition.
#[derive(Debug, Default)]
pub struct InMemoryClientRegistry {
    records: Mutex<BTreeMap<String, DynamicClientRecord>>,
}

impl InMemoryClientRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered clients (test helper).
    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    /// Whether no clients are registered (test helper).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DynamicClientRegistry for InMemoryClientRegistry {
    async fn get(
        &self,
        client_id: &str,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        Ok(self.records.lock().unwrap().get(client_id).cloned())
    }

    async fn list(&self) -> Result<Vec<DynamicClientRecord>, RegistryStoreError> {
        Ok(self.records.lock().unwrap().values().cloned().collect())
    }

    async fn insert(&self, record: &DynamicClientRecord) -> Result<bool, RegistryStoreError> {
        let mut records = self.records.lock().unwrap();
        if records.contains_key(&record.client_id) {
            return Ok(false);
        }
        records.insert(record.client_id.clone(), record.clone());
        Ok(true)
    }

    async fn update_metadata(
        &self,
        client_id: &str,
        metadata: &ClientMetadata,
        now: i64,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        let mut records = self.records.lock().unwrap();
        let Some(record) = records.get_mut(client_id) else {
            return Ok(None);
        };
        record.apply_metadata(metadata.clone(), now);
        Ok(Some(record.clone()))
    }

    async fn set_status(
        &self,
        client_id: &str,
        status: ClientStatus,
        now: i64,
    ) -> Result<Option<DynamicClientRecord>, RegistryStoreError> {
        let mut records = self.records.lock().unwrap();
        let Some(record) = records.get_mut(client_id) else {
            return Ok(None);
        };
        match status {
            ClientStatus::Active => record.enable(now),
            ClientStatus::Disabled => record.disable(now),
        }
        Ok(Some(record.clone()))
    }

    async fn rotate_secret(
        &self,
        client_id: &str,
        new_secret_hash: &str,
        now: i64,
    ) -> Result<RotateOutcome, RegistryStoreError> {
        let mut records = self.records.lock().unwrap();
        let Some(record) = records.get_mut(client_id) else {
            return Ok(RotateOutcome::NotFound);
        };
        match record.rotate_secret(new_secret_hash.to_string(), now) {
            Ok(_) => Ok(RotateOutcome::Rotated(Box::new(record.clone()))),
            Err(NoSecret) => Ok(RotateOutcome::NoSecret),
        }
    }
}
