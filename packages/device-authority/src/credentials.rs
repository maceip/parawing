// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Blind credential and passkey brokers supporting tokenized and sealed fill modes.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::keychain;
use crate::webauthn::authenticator::{
    Authenticator, CeremonyContext, MemoryPasskeyStore, PasskeyStore, StoredPasskey,
};
use crate::webauthn::origin::{
    OriginValidation, ValidatedOrigin, registrable_suffix, validate_origin_and_effective_rp_id,
};
use crate::webauthn::types::{
    AssertionCredential, AuthenticatorSelectionCriteria, ExtensionInputs,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity, RegistrationCredential, WebAuthnError,
};

/// Default macOS Keychain service holding serialized WebAuthn passkey records.
pub const PASSKEY_KEYCHAIN_SERVICE: &str = "ai.parawing.authority.webauthn.passkeys";
/// Default macOS Keychain account holding the JSON passkey record array.
pub const PASSKEY_KEYCHAIN_ACCOUNT: &str = "passkey_records_v1";
/// Default macOS Keychain service holding site-scoped password items.
pub const PASSWORD_KEYCHAIN_SERVICE: &str = "ai.parawing.authority.credentials";

/// Environment variable overriding the passkey Keychain service name.
pub const PASSKEY_SERVICE_ENV: &str = "PARAWING_PASSKEY_KEYCHAIN_SERVICE";
/// Environment variable overriding the password Keychain service name.
pub const PASSWORD_SERVICE_ENV: &str = "PARAWING_PASSWORD_KEYCHAIN_SERVICE";

static PASSKEY_SERVICE_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Resolves the active passkey Keychain service name.
pub fn passkey_service_name() -> String {
    if let Some(service) = PASSKEY_SERVICE_OVERRIDE.get() {
        return service.clone();
    }
    std::env::var(PASSKEY_SERVICE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| PASSKEY_KEYCHAIN_SERVICE.to_string())
}

/// Overrides the passkey Keychain service name for isolated test processes.
pub fn set_passkey_service_override(service: &str) {
    let _ = PASSKEY_SERVICE_OVERRIDE.set(service.to_string());
}

/// Resolves the active password Keychain service name.
pub fn password_service_name() -> String {
    std::env::var(PASSWORD_SERVICE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| PASSWORD_KEYCHAIN_SERVICE.to_string())
}

fn validated_origin(
    origin: &str,
    requested_rp_id: Option<&str>,
    cross_origin: bool,
    is_create: bool,
    related_origin_validated: bool,
) -> Result<ValidatedOrigin, BrokerError> {
    match validate_origin_and_effective_rp_id(origin, requested_rp_id, cross_origin, is_create)
        .map_err(BrokerError::from)?
    {
        OriginValidation::Suffix(validated) => Ok(validated),
        OriginValidation::NeedsRelatedOrigins {
            validated,
            caller_origin,
            rp_id,
        } => {
            if !related_origin_validated {
                return Err(BrokerError::from(WebAuthnError::Security(format!(
                    "The origin '{caller_origin}' is not related to '{rp_id}'"
                ))));
            }
            Ok(validated)
        }
    }
}

/// Errors raised by credential and passkey broker operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerError {
    /// Operation was denied by origin policy or user verification policy.
    NotAllowed(String),
    /// Ceremony or approval does not match current broker state.
    InvalidState(String),
    /// Requested credential or ceremony does not exist.
    NotFound(String),
    /// Request parameters were malformed.
    Invalid(String),
    /// Underlying Keychain or backing store failed.
    Storage(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed(m) => write!(f, "NotAllowed: {m}"),
            Self::InvalidState(m) => write!(f, "InvalidState: {m}"),
            Self::NotFound(m) => write!(f, "NotFound: {m}"),
            Self::Invalid(m) => write!(f, "Invalid: {m}"),
            Self::Storage(m) => write!(f, "Storage: {m}"),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<String> for BrokerError {
    fn from(message: String) -> Self {
        Self::Storage(message)
    }
}

impl From<WebAuthnError> for BrokerError {
    fn from(error: WebAuthnError) -> Self {
        match error {
            WebAuthnError::NotAllowed(m) => Self::NotAllowed(m),
            WebAuthnError::InvalidState(m) => Self::InvalidState(m),
            WebAuthnError::Type(m) | WebAuthnError::Constraint(m) => Self::Invalid(m),
            other => Self::Storage(other.to_string()),
        }
    }
}

/// Metadata summary for a stored credential item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Site host (`kSecAttrLabel`).
    pub host: String,
    /// Account identifier (`kSecAttrAccount`).
    pub username: String,
    /// True when backed by a WebAuthn passkey rather than a password.
    pub is_passkey: bool,
}

impl StoredCredential {
    /// Internal composite key (`host|username|kind`), never exposed to agents.
    pub fn id(&self) -> String {
        let kind = if self.is_passkey {
            "passkey"
        } else {
            "password"
        };
        format!("{}|{}|{kind}", self.host, self.username)
    }
}

/// Backing store trait for site-scoped password secrets.
pub trait PasswordStore: Send {
    /// Stores or replaces `(host, username)` secret material.
    fn save(&self, host: &str, username: &str, secret: &str) -> Result<(), BrokerError>;
    /// Reads the secret only when `(host, username)` matches the stored site label.
    fn secret(&self, host: &str, username: &str) -> Option<String>;
    /// Lists non-secret metadata for stored password items.
    fn list(&self) -> Result<Vec<StoredCredential>, BrokerError>;
    /// Deletes a stored password scoped to `(host, username)`.
    fn delete(&self, host: &str, username: &str) -> Result<(), BrokerError>;
}

/// macOS Keychain-backed `PasskeyStore`.
#[derive(Clone, Debug)]
pub struct KeychainPasskeyStore {
    service: String,
    account: String,
}

impl Default for KeychainPasskeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainPasskeyStore {
    /// Creates a store targeting the configured passkey Keychain service.
    pub fn new() -> Self {
        Self {
            service: passkey_service_name(),
            account: PASSKEY_KEYCHAIN_ACCOUNT.to_string(),
        }
    }

    /// Creates a store targeting an explicit `(service, account)` pair.
    pub fn with_service(service: &str, account: &str) -> Self {
        Self {
            service: service.to_string(),
            account: account.to_string(),
        }
    }

    fn write_all(&self, records: &[StoredPasskey]) -> Result<(), String> {
        let data = serde_json::to_vec(records).map_err(|e| format!("encode passkeys: {e}"))?;
        keychain::set_generic_item(
            &self.service,
            &self.account,
            Some("Parawing passkeys"),
            &data,
        )
        .map_err(|e| keychain::describe_error(&e))
    }

    /// Deletes the passkey record item from the Keychain.
    pub fn clear(&self) -> Result<(), String> {
        keychain::delete_generic_item(&self.service, &self.account);
        Ok(())
    }
}

impl PasskeyStore for KeychainPasskeyStore {
    fn all(&self) -> Result<Vec<StoredPasskey>, String> {
        let Some(data) = keychain::get_generic_item(&self.service, &self.account) else {
            return Ok(Vec::new());
        };
        if data.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&data).map_err(|e| format!("decode passkey records: {e}"))
    }

    fn insert(&mut self, record: StoredPasskey) -> Result<(), String> {
        let mut records = self.all()?;
        records.push(record);
        self.write_all(&records)
    }

    fn update(&mut self, record: StoredPasskey) -> Result<(), String> {
        let mut records = self.all()?;
        match records
            .iter_mut()
            .find(|r| r.credential_id == record.credential_id)
        {
            Some(existing) => *existing = record,
            None => return Err("no such passkey".to_string()),
        }
        self.write_all(&records)
    }

    fn delete(&mut self, credential_id: &[u8]) -> Result<(), String> {
        let mut records = self.all()?;
        records.retain(|r| r.credential_id != credential_id);
        self.write_all(&records)
    }
}

/// macOS Keychain-backed `PasswordStore`.
#[derive(Clone, Debug)]
pub struct KeychainPasswordStore {
    service: String,
}

impl Default for KeychainPasswordStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainPasswordStore {
    /// Creates a store targeting the configured password Keychain service.
    pub fn new() -> Self {
        Self {
            service: password_service_name(),
        }
    }

    /// Creates a store targeting an explicit Keychain `service`.
    pub fn with_service(service: &str) -> Self {
        Self {
            service: service.to_string(),
        }
    }
}

impl PasswordStore for KeychainPasswordStore {
    fn save(&self, host: &str, username: &str, secret: &str) -> Result<(), BrokerError> {
        keychain::set_generic_item(&self.service, username, Some(host), secret.as_bytes())
            .map_err(|e| BrokerError::Storage(keychain::describe_error(&e)))
    }

    fn secret(&self, host: &str, username: &str) -> Option<String> {
        let data = keychain::get_generic_item(&self.service, username)?;
        let secret = String::from_utf8(data).ok()?;
        let entries = keychain::list_generic_items(&self.service);
        let matches_site = entries
            .iter()
            .any(|e| e.account == username && e.label.as_deref() == Some(host));
        if matches_site {
            Some(secret)
        } else {
            None
        }
    }

    fn list(&self) -> Result<Vec<StoredCredential>, BrokerError> {
        let mut out: Vec<StoredCredential> = keychain::list_generic_items(&self.service)
            .into_iter()
            .map(|item| StoredCredential {
                host: item.label.unwrap_or_default(),
                username: item.account,
                is_passkey: false,
            })
            .collect();
        out.sort_by(|a, b| a.host.cmp(&b.host));
        Ok(out)
    }

    fn delete(&self, host: &str, username: &str) -> Result<(), BrokerError> {
        let entries = keychain::list_generic_items(&self.service);
        let matches_site = entries
            .iter()
            .any(|e| e.account == username && e.label.as_deref() == Some(host));
        if matches_site {
            keychain::delete_generic_item(&self.service, username);
        }
        Ok(())
    }
}

/// Ephemeral in-memory `PasswordStore` for unit tests and isolated sandboxes.
#[derive(Debug, Default)]
pub struct MemoryPasswordStore {
    items: Mutex<Vec<(String, String, String)>>,
}

impl MemoryPasswordStore {
    /// Creates an empty in-memory password store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PasswordStore for MemoryPasswordStore {
    fn save(&self, host: &str, username: &str, secret: &str) -> Result<(), BrokerError> {
        let mut guard = self
            .items
            .lock()
            .map_err(|_| BrokerError::Storage("poisoned memory password store".to_string()))?;
        guard.retain(|(h, u, _)| !(h.eq_ignore_ascii_case(host) && u == username));
        guard.push((host.to_string(), username.to_string(), secret.to_string()));
        Ok(())
    }

    fn secret(&self, host: &str, username: &str) -> Option<String> {
        let guard = self.items.lock().ok()?;
        guard
            .iter()
            .find(|(h, u, _)| h.eq_ignore_ascii_case(host) && u == username)
            .map(|(_, _, s)| s.clone())
    }

    fn list(&self) -> Result<Vec<StoredCredential>, BrokerError> {
        let guard = self
            .items
            .lock()
            .map_err(|_| BrokerError::Storage("poisoned memory password store".to_string()))?;
        let mut out: Vec<StoredCredential> = guard
            .iter()
            .map(|(host, username, _)| StoredCredential {
                host: host.clone(),
                username: username.clone(),
                is_passkey: false,
            })
            .collect();
        out.sort_by(|a, b| a.host.cmp(&b.host));
        Ok(out)
    }

    fn delete(&self, host: &str, username: &str) -> Result<(), BrokerError> {
        let mut guard = self
            .items
            .lock()
            .map_err(|_| BrokerError::Storage("poisoned memory password store".to_string()))?;
        guard.retain(|(h, u, _)| !(h.eq_ignore_ascii_case(host) && u == username));
        Ok(())
    }
}

/// Sensitive field categories handled by the credential broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialFieldKind {
    /// Account username or email input.
    Username,
    /// Existing account password input (`current-password`).
    CurrentPassword,
    /// Account password creation/change input (`new-password`).
    NewPassword,
    /// Multi-factor one-time code input (`one-time-code`).
    OneTimeCode,
    /// Payment card number, CVC, or expiry input.
    PaymentCard,
    /// Any other classified sensitive field.
    OtherSensitive,
}

impl CredentialFieldKind {
    /// Returns the wire identifier for this field kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::CurrentPassword => "current_password",
            Self::NewPassword => "new_password",
            Self::OneTimeCode => "one_time_code",
            Self::PaymentCard => "payment_card",
            Self::OtherSensitive => "other_sensitive",
        }
    }
}

/// Credential injection mode (`PLAN.md` section 9.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFillMode {
    /// Host-side `$cred:<token>` transport substitution for HTTP/API requests.
    Tokenized,
    /// Direct host-to-DOM fill while blacking out agent observation on the target.
    #[default]
    Sealed,
}

/// Host-only substitution table produced by `CredentialFillMode::Tokenized`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenizedSubstitutionSpec {
    /// Normalized origin this token table is strictly bound to.
    pub origin: String,
    /// Opaque one-time placeholder token for the username (`$cred:...`), if requested.
    pub username_token: Option<String>,
    /// Raw username value substituted by the host transport layer.
    pub username_value: Option<String>,
    /// Opaque one-time placeholder token for the password (`$cred:...`), if requested.
    pub secret_token: Option<String>,
    /// Raw password secret substituted by the host transport layer.
    pub secret_value: Option<String>,
}

/// Request to describe candidate credentials for a supervised task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialFillRequest {
    /// Supervised task identifier.
    pub task_id: String,
    /// Document origin observed by the host.
    pub origin: String,
    /// Sensitive fields requiring credential fill.
    pub fields: Vec<CredentialFieldKind>,
    /// Monotonic document generation the request was bound against.
    pub document_generation: u64,
}

/// Redacted summary of a matching credential safe to expose to the agent and UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMatch {
    /// Redacted username hint (e.g. `"a**@example.com"`).
    pub username_hint: String,
    /// Site or relying party domain.
    pub site: String,
    /// True when backed by a passkey rather than a password.
    pub is_passkey: bool,
}

/// Human-facing prompt payload describing candidate credentials for an origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPrompt {
    /// Normalized document origin.
    pub origin: String,
    /// Registrable domain displayed for anti-phishing verification.
    pub registrable_domain: String,
    /// Redacted matching credentials.
    pub matches: Vec<CredentialMatch>,
    /// Whether the UI can offer storing a new password for this origin.
    pub can_add_credential: bool,
}

/// Human approval decision authorizing a single credential fill ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialApproval {
    /// Ceremony identifier bound to the pending prompt.
    pub ceremony_id: String,
    /// Redacted credential selected by the human.
    pub chosen: Option<CredentialMatch>,
    /// Whether the approval should be remembered for the site.
    pub remember: bool,
    /// Target document origin.
    #[serde(default)]
    pub origin: String,
    /// Explicit subset of fields authorized to be filled.
    #[serde(default)]
    pub fields: Vec<CredentialFieldKind>,
    /// Fill execution mode (`sealed` DOM fill or `tokenized` transport substitution).
    #[serde(default)]
    pub mode: CredentialFillMode,
}

/// Redacted receipt returned after an approved credential fill executes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialFillReceipt {
    /// Origin where the fill applied.
    pub origin: String,
    /// Fields populated by the broker.
    pub filled_fields: Vec<CredentialFieldKind>,
    /// Redacted account hint used for the fill.
    pub account_hint: Option<String>,
    /// Fill mode applied (`sealed` or `tokenized`).
    pub mode: CredentialFillMode,
    /// True when agent observation on this page must be blacked out until navigation.
    pub blackout_agent_observation: bool,
    /// Opaque `$cred:<token>` placeholders (values omitted) when `mode` is `Tokenized`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub field_tokens: HashMap<String, String>,
}

/// DOM field writer sink invoked during `CredentialFillMode::Sealed` fills.
pub trait CredentialSink {
    /// Injects `value` directly into `field` inside the isolated page runtime.
    fn set_field(&mut self, field: CredentialFieldKind, value: &str) -> Result<(), BrokerError>;
}

/// Blind password credential broker trait.
pub trait CredentialBroker {
    /// Lists redacted candidate matches for `req` without touching page state.
    fn describe_fill(&self, req: CredentialFillRequest) -> Result<CredentialPrompt, BrokerError>;

    /// Executes a human-approved fill into `engine`, returning a redacted receipt.
    fn apply_approved_fill(
        &mut self,
        approval: CredentialApproval,
        engine: &mut dyn CredentialSink,
    ) -> Result<CredentialFillReceipt, BrokerError>;
}

/// Opaque identifier of an in-flight WebAuthn ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PasskeyCeremonyId(pub String);

/// Broker request for a WebAuthn `navigator.credentials.get` assertion ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyRequest {
    /// Supervised task identifier.
    pub task_id: String,
    /// Trusted caller origin observed by the host.
    pub origin: String,
    /// Optional explicit relying party identifier.
    pub rp_id: Option<String>,
    /// Raw challenge bytes.
    pub challenge: Vec<u8>,
    /// Allowed credential descriptors.
    #[serde(default)]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// User verification preference.
    #[serde(default)]
    pub user_verification: Option<String>,
    /// Client extension inputs.
    #[serde(default)]
    pub extensions: Option<ExtensionInputs>,
    /// True if invoked from a cross-origin iframe.
    #[serde(default)]
    pub cross_origin: bool,
    /// Top-level frame origin when `cross_origin` is true.
    #[serde(default)]
    pub top_origin: Option<String>,
    /// True only when `related_origins::validate` has verified `(origin, rp_id)`.
    #[serde(default)]
    pub related_origin_validated: bool,
}

impl PasskeyRequest {
    /// Parses a `PasskeyRequest` from a control-protocol JSON operation object.
    pub fn from_operation(operation: &serde_json::Value) -> Result<Self, BrokerError> {
        let origin = operation
            .get("origin")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| BrokerError::Invalid("origin is required".to_string()))?
            .to_string();
        let challenge = decode_challenge(operation.get("challenge"))?;
        let allow_credentials = decode_credential_descriptors(operation.get("allow_credentials"))?;
        let extensions = decode_optional_field(operation, "extensions")?;

        Ok(Self {
            task_id: str_field(operation, "task_id"),
            origin,
            rp_id: opt_str_field(operation, "rp_id"),
            challenge,
            allow_credentials,
            user_verification: opt_str_field(operation, "user_verification"),
            extensions,
            cross_origin: bool_field(operation, "cross_origin"),
            top_origin: opt_str_field(operation, "top_origin"),
            related_origin_validated: bool_field(operation, "related_origin_validated"),
        })
    }
}

/// Broker request for a WebAuthn `navigator.credentials.create` registration ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRequest {
    /// Supervised task identifier.
    pub task_id: String,
    /// Trusted caller origin observed by the host.
    pub origin: String,
    /// Relying party entity.
    pub rp: PublicKeyCredentialRpEntity,
    /// User account entity.
    pub user: PublicKeyCredentialUserEntity,
    /// Raw challenge bytes.
    pub challenge: Vec<u8>,
    /// Offered public-key credential algorithms.
    #[serde(default)]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Credentials excluded from re-registration.
    #[serde(default)]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// Authenticator selection criteria.
    #[serde(default)]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference.
    #[serde(default)]
    pub attestation: Option<String>,
    /// Client extension inputs.
    #[serde(default)]
    pub extensions: Option<ExtensionInputs>,
    /// True if invoked from a cross-origin iframe.
    #[serde(default)]
    pub cross_origin: bool,
    /// True only when `related_origins::validate` has verified `(origin, rp.id)`.
    #[serde(default)]
    pub related_origin_validated: bool,
}

impl RegistrationRequest {
    /// Parses a `RegistrationRequest` from a control-protocol JSON operation object.
    pub fn from_operation(operation: &serde_json::Value) -> Result<Self, BrokerError> {
        let origin = operation
            .get("origin")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| BrokerError::Invalid("origin is required".to_string()))?
            .to_string();
        let challenge = decode_challenge(operation.get("challenge"))?;
        let rp = operation
            .get("rp")
            .ok_or_else(|| BrokerError::Invalid("rp is required".to_string()))
            .and_then(|v| {
                serde_json::from_value::<PublicKeyCredentialRpEntity>(v.clone())
                    .map_err(|e| BrokerError::Invalid(format!("rp: {e}")))
            })?;
        let user_value = operation
            .get("user")
            .ok_or_else(|| BrokerError::Invalid("user is required".to_string()))?;
        let user = decode_user_entity(user_value)?;
        let pub_key_cred_params = match operation.get("pub_key_cred_params") {
            Some(v @ serde_json::Value::Array(_)) => serde_json::from_value(v.clone())
                .map_err(|e| BrokerError::Invalid(format!("pub_key_cred_params: {e}")))?,
            _ => Vec::new(),
        };
        let exclude_credentials =
            decode_credential_descriptors(operation.get("exclude_credentials"))?;
        let authenticator_selection = decode_optional_field(operation, "authenticator_selection")?;
        let extensions = decode_optional_field(operation, "extensions")?;

        Ok(Self {
            task_id: str_field(operation, "task_id"),
            origin,
            rp,
            user,
            challenge,
            pub_key_cred_params,
            exclude_credentials,
            authenticator_selection,
            attestation: opt_str_field(operation, "attestation"),
            extensions,
            cross_origin: bool_field(operation, "cross_origin"),
            related_origin_validated: bool_field(operation, "related_origin_validated"),
        })
    }
}

fn str_field(op: &serde_json::Value, key: &str) -> String {
    op.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn opt_str_field(op: &serde_json::Value, key: &str) -> Option<String> {
    op.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn bool_field(op: &serde_json::Value, key: &str) -> bool {
    op.get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn decode_optional_field<T: serde::de::DeserializeOwned>(
    op: &serde_json::Value,
    key: &str,
) -> Result<Option<T>, BrokerError> {
    match op.get(key) {
        Some(value) if !value.is_null() => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|e| BrokerError::Invalid(format!("{key}: {e}"))),
        _ => Ok(None),
    }
}

fn decode_user_entity(
    user_value: &serde_json::Value,
) -> Result<PublicKeyCredentialUserEntity, BrokerError> {
    if let Ok(mut parsed) =
        serde_json::from_value::<PublicKeyCredentialUserEntity>(user_value.clone())
    {
        if parsed.id.is_empty() {
            if let Some(raw) = user_value.get("id").and_then(serde_json::Value::as_str) {
                parsed.id = decode_b64_any(raw, "user.id")?;
            }
        }
        return Ok(parsed);
    }
    let raw = user_value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BrokerError::Invalid("user.id is required".to_string()))?;
    let id = decode_b64_any(raw, "user.id")?;
    let name = str_field(user_value, "name");
    let display_name = opt_str_field(user_value, "displayName").unwrap_or_else(|| name.clone());
    Ok(PublicKeyCredentialUserEntity {
        id,
        name,
        display_name,
    })
}

fn decode_credential_descriptors(
    value: Option<&serde_json::Value>,
) -> Result<Vec<PublicKeyCredentialDescriptor>, BrokerError> {
    let Some(items) = value.and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let mut cloned = item.clone();
        if let Some(raw) = cloned.get("id").and_then(serde_json::Value::as_str) {
            let bytes = decode_b64_any(raw, "credential id")?;
            cloned["id"] =
                serde_json::Value::Array(bytes.into_iter().map(serde_json::Value::from).collect());
        }
        let desc = serde_json::from_value(cloned)
            .map_err(|e| BrokerError::Invalid(format!("credential descriptor: {e}")))?;
        out.push(desc);
    }
    Ok(out)
}

fn decode_challenge(value: Option<&serde_json::Value>) -> Result<Vec<u8>, BrokerError> {
    let raw = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BrokerError::Invalid("challenge is required".to_string()))?;
    decode_b64_any(raw, "challenge")
}

fn decode_b64_any(raw: &str, label: &str) -> Result<Vec<u8>, BrokerError> {
    if raw.contains('-') || raw.contains('_') {
        return crate::webauthn::b64::b64url_decode(raw)
            .ok_or_else(|| BrokerError::Invalid(format!("{label} is not valid base64url")));
    }
    crate::control::b64_decode(raw)
        .or_else(|| crate::webauthn::b64::b64url_decode(raw))
        .ok_or_else(|| BrokerError::Invalid(format!("{label} is not valid base64")))
}

/// Completed WebAuthn ceremony credential payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyOutcome {
    /// Signed `navigator.credentials.get` assertion credential.
    Assertion(AssertionCredential),
    /// Newly registered `navigator.credentials.create` credential.
    Registration(RegistrationCredential),
}

/// Lifecycle state of a brokered WebAuthn ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasskeyStatus {
    /// Ceremony is gated on explicit human approval.
    AwaitingApproval {
        /// Human-readable approval prompt.
        prompt: String,
        /// Validated caller origin.
        origin: String,
        /// Redacted account hint, when known.
        account_hint: Option<String>,
    },
    /// Ceremony was approved and executed to completion.
    Complete(Box<CeremonyOutcome>),
    /// Ceremony execution failed with an error detail.
    Failed(String),
    /// Ceremony was explicitly cancelled before approval.
    Cancelled,
}

/// Passkey ceremony broker trait gating WebAuthn operations on human approval.
pub trait PasskeyBroker {
    /// Begins an assertion ceremony in `AwaitingApproval` state.
    fn begin_assertion(&mut self, req: PasskeyRequest) -> Result<PasskeyCeremonyId, BrokerError>;
    /// Polls the status of an assertion ceremony.
    fn poll_assertion(&mut self, id: PasskeyCeremonyId) -> Result<PasskeyStatus, BrokerError>;
    /// Cancels a pending assertion ceremony.
    fn cancel_assertion(&mut self, id: PasskeyCeremonyId) -> Result<(), BrokerError>;
    /// Begins a registration ceremony in `AwaitingApproval` state.
    fn begin_registration(
        &mut self,
        req: RegistrationRequest,
    ) -> Result<PasskeyCeremonyId, BrokerError>;
    /// Polls the status of a registration ceremony.
    fn poll_registration(&mut self, id: PasskeyCeremonyId) -> Result<PasskeyStatus, BrokerError>;
    /// Cancels a pending registration ceremony.
    fn cancel_registration(&mut self, id: PasskeyCeremonyId) -> Result<(), BrokerError>;
    /// Records human approval and executes the pending cryptographic ceremony.
    fn approve_ceremony(
        &mut self,
        id: PasskeyCeremonyId,
        decided_by: &str,
        surface: &str,
    ) -> Result<(), BrokerError>;
}

/// Redacts a username/email so agents learn existence and domain without full PII.
pub fn redact_username(username: &str) -> String {
    if let Some((local, domain)) = username.split_once('@') {
        if !local.is_empty() && !domain.is_empty() {
            let first = local.chars().next().unwrap_or('*');
            return format!("{first}**@{domain}");
        }
    }
    match username.chars().count() {
        0 => String::new(),
        1 => "*".to_string(),
        n => {
            let first: String = username.chars().take(1).collect();
            format!("{first}{}", "*".repeat(n - 1))
        }
    }
}

struct Ceremony {
    status: PasskeyStatus,
    request: CeremonyRequest,
}

enum CeremonyRequest {
    Assertion(PasskeyRequest),
    Registration(RegistrationRequest),
}

impl Ceremony {
    fn status_kind(&self) -> &'static str {
        match self.status {
            PasskeyStatus::AwaitingApproval { .. } => "awaiting-approval",
            PasskeyStatus::Complete(_) => "complete",
            PasskeyStatus::Failed(_) => "failed",
            PasskeyStatus::Cancelled => "cancelled",
        }
    }
}

/// Concrete `PasskeyBroker` backed by any `PasskeyStore` (macOS Keychain by default).
pub struct LocalPasskeyBroker {
    store: Box<dyn PasskeyStore + Send>,
    authenticator: Authenticator,
    ceremonies: HashMap<String, Ceremony>,
    next_id: u64,
}

impl Default for LocalPasskeyBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPasskeyBroker {
    /// Creates a passkey broker backed by `KeychainPasskeyStore`.
    pub fn new() -> Self {
        Self::with_store(Box::new(KeychainPasskeyStore::new()))
    }

    /// Creates an ephemeral passkey broker backed by `MemoryPasskeyStore`.
    pub fn in_memory() -> Self {
        Self::with_store(Box::new(MemoryPasskeyStore::new()))
    }

    /// Creates a passkey broker over an explicit `PasskeyStore`.
    pub fn with_store(store: Box<dyn PasskeyStore + Send>) -> Self {
        Self {
            store,
            authenticator: Authenticator::new(),
            ceremonies: HashMap::new(),
            next_id: 1,
        }
    }

    /// Returns the 16-byte AAGUID advertised by the underlying authenticator.
    pub fn aaguid(&self) -> [u8; 16] {
        self.authenticator.aaguid
    }

    /// Returns the most recently allocated ceremony identifier, if any.
    pub fn latest_ceremony_id(&self) -> Option<PasskeyCeremonyId> {
        let mut latest: Option<(u64, &String)> = None;
        for id in self.ceremonies.keys() {
            let seq = id
                .rsplit('-')
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
            match latest {
                Some((best, _)) if best >= seq => {}
                _ => latest = Some((seq, id)),
            }
        }
        latest.map(|(_, id)| PasskeyCeremonyId(id.clone()))
    }

    /// Lists redacted metadata for all stored passkeys.
    pub fn list_passkeys(&self) -> Result<Vec<CredentialMatch>, BrokerError> {
        let records = self.store.all().map_err(BrokerError::Storage)?;
        Ok(records
            .iter()
            .map(|r| CredentialMatch {
                username_hint: redact_username(&r.user_name),
                site: r.relying_party_identifier.clone(),
                is_passkey: true,
            })
            .collect())
    }

    /// Deletes a stored passkey by raw `credential_id`.
    pub fn delete_passkey(&mut self, credential_id: &[u8]) -> Result<bool, BrokerError> {
        let existed = self
            .store
            .by_credential_id(credential_id)
            .map_err(BrokerError::Storage)?
            .is_some();
        self.store
            .delete(credential_id)
            .map_err(BrokerError::Storage)?;
        Ok(existed)
    }

    /// Returns a stored passkey record by raw `credential_id`.
    pub fn stored_passkey(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, BrokerError> {
        self.store
            .by_credential_id(credential_id)
            .map_err(BrokerError::Storage)
    }

    /// Returns only the SPKI PEM public key for `credential_id`.
    pub fn public_key_pem(&self, credential_id: &[u8]) -> Result<Option<String>, BrokerError> {
        Ok(self
            .stored_passkey(credential_id)?
            .map(|record| record.public_key_pem))
    }

    /// Builds a redacted human prompt for an assertion ceremony.
    pub fn describe_assertion(
        &self,
        req: &PasskeyRequest,
    ) -> Result<CredentialPrompt, BrokerError> {
        let validated = validated_origin(
            &req.origin,
            req.rp_id.as_deref(),
            req.cross_origin,
            false,
            req.related_origin_validated,
        )?;
        let records = self.store.all().map_err(BrokerError::Storage)?;
        let matches: Vec<CredentialMatch> = records
            .iter()
            .filter(|r| {
                r.relying_party_identifier
                    .eq_ignore_ascii_case(&validated.effective_rp_id)
            })
            .map(|r| CredentialMatch {
                username_hint: redact_username(&r.user_name),
                site: r.relying_party_identifier.clone(),
                is_passkey: true,
            })
            .collect();
        if matches.is_empty() {
            return Err(BrokerError::NotFound(format!(
                "No passkey for {}",
                validated.effective_rp_id
            )));
        }
        Ok(CredentialPrompt {
            origin: validated.normalized_origin,
            registrable_domain: validated.effective_rp_id,
            matches,
            can_add_credential: false,
        })
    }

    fn run_assertion(&mut self, req: &PasskeyRequest) -> Result<CeremonyOutcome, BrokerError> {
        let options = PublicKeyCredentialRequestOptions {
            challenge: req.challenge.clone(),
            rp_id: req.rp_id.clone(),
            timeout: None,
            allow_credentials: req.allow_credentials.clone(),
            user_verification: req.user_verification.clone(),
            extensions: req.extensions.clone(),
            hints: Vec::new(),
        };
        let now = crate::control::now_iso();
        let ctx = CeremonyContext {
            origin: &req.origin,
            cross_origin: req.cross_origin,
            top_origin: req.top_origin.as_deref(),
            now_iso: &now,
            related_origin_validated: req.related_origin_validated,
        };
        let (credential, _) = self
            .authenticator
            .get(&mut *self.store, &options, &ctx)
            .map_err(BrokerError::from)?;
        Ok(CeremonyOutcome::Assertion(credential))
    }

    fn run_registration(
        &mut self,
        req: &RegistrationRequest,
    ) -> Result<CeremonyOutcome, BrokerError> {
        let options = PublicKeyCredentialCreationOptions {
            rp: req.rp.clone(),
            user: req.user.clone(),
            challenge: req.challenge.clone(),
            pub_key_cred_params: req.pub_key_cred_params.clone(),
            timeout: None,
            exclude_credentials: req.exclude_credentials.clone(),
            authenticator_selection: req.authenticator_selection.clone(),
            attestation: req.attestation.clone(),
            extensions: req.extensions.clone(),
        };
        let now = crate::control::now_iso();
        let ctx = CeremonyContext {
            origin: &req.origin,
            cross_origin: req.cross_origin,
            top_origin: None,
            now_iso: &now,
            related_origin_validated: req.related_origin_validated,
        };
        let (credential, _) = self
            .authenticator
            .create(&mut *self.store, &options, &ctx)
            .map_err(BrokerError::from)?;
        Ok(CeremonyOutcome::Registration(credential))
    }
}

impl PasskeyBroker for LocalPasskeyBroker {
    fn begin_assertion(&mut self, req: PasskeyRequest) -> Result<PasskeyCeremonyId, BrokerError> {
        let prompt = self.describe_assertion(&req)?;
        let id = format!("passkey-assert-{}", self.next_id);
        self.next_id += 1;
        let account_hint = prompt.matches.first().map(|m| m.username_hint.clone());
        let who = account_hint
            .clone()
            .unwrap_or_else(|| "this account".to_string());
        self.ceremonies.insert(
            id.clone(),
            Ceremony {
                status: PasskeyStatus::AwaitingApproval {
                    prompt: format!(
                        "Use the passkey for {who} to sign in to {}?",
                        prompt.registrable_domain
                    ),
                    origin: prompt.origin,
                    account_hint,
                },
                request: CeremonyRequest::Assertion(req),
            },
        );
        Ok(PasskeyCeremonyId(id))
    }

    fn poll_assertion(&mut self, id: PasskeyCeremonyId) -> Result<PasskeyStatus, BrokerError> {
        self.ceremonies
            .get(&id.0)
            .map(|c| c.status.clone())
            .ok_or_else(|| BrokerError::NotFound("no such ceremony".to_string()))
    }

    fn cancel_assertion(&mut self, id: PasskeyCeremonyId) -> Result<(), BrokerError> {
        let ceremony = self
            .ceremonies
            .get_mut(&id.0)
            .ok_or_else(|| BrokerError::NotFound("no such ceremony".to_string()))?;
        ceremony.status = PasskeyStatus::Cancelled;
        Ok(())
    }

    fn begin_registration(
        &mut self,
        req: RegistrationRequest,
    ) -> Result<PasskeyCeremonyId, BrokerError> {
        validated_origin(
            &req.origin,
            Some(req.rp.id.as_str()),
            req.cross_origin,
            true,
            req.related_origin_validated,
        )?;
        let id = format!("passkey-register-{}", self.next_id);
        self.next_id += 1;
        self.ceremonies.insert(
            id.clone(),
            Ceremony {
                status: PasskeyStatus::AwaitingApproval {
                    prompt: format!("Create a passkey for {} on {}?", req.user.name, req.rp.id),
                    origin: req.origin.clone(),
                    account_hint: Some(redact_username(&req.user.name)),
                },
                request: CeremonyRequest::Registration(req),
            },
        );
        Ok(PasskeyCeremonyId(id))
    }

    fn poll_registration(&mut self, id: PasskeyCeremonyId) -> Result<PasskeyStatus, BrokerError> {
        self.poll_assertion(id)
    }

    fn cancel_registration(&mut self, id: PasskeyCeremonyId) -> Result<(), BrokerError> {
        self.cancel_assertion(id)
    }

    fn approve_ceremony(
        &mut self,
        id: PasskeyCeremonyId,
        decided_by: &str,
        surface: &str,
    ) -> Result<(), BrokerError> {
        let request = {
            let ceremony = self
                .ceremonies
                .get(&id.0)
                .ok_or_else(|| BrokerError::NotFound("no such ceremony".to_string()))?;
            if matches!(ceremony.status, PasskeyStatus::Cancelled) {
                return Err(BrokerError::InvalidState(
                    "the ceremony was cancelled".to_string(),
                ));
            }
            if matches!(ceremony.status, PasskeyStatus::Complete(_)) {
                return Err(BrokerError::InvalidState(
                    "the ceremony already completed".to_string(),
                ));
            }
            match &ceremony.request {
                CeremonyRequest::Assertion(r) => CeremonyRequest::Assertion(r.clone()),
                CeremonyRequest::Registration(r) => CeremonyRequest::Registration(r.clone()),
            }
        };

        let outcome = match request {
            CeremonyRequest::Assertion(req) => self.run_assertion(&req),
            CeremonyRequest::Registration(req) => self.run_registration(&req),
        };
        let status = match outcome {
            Ok(done) => PasskeyStatus::Complete(Box::new(done)),
            Err(err) => PasskeyStatus::Failed(err.to_string()),
        };
        let ceremony = self
            .ceremonies
            .get_mut(&id.0)
            .ok_or_else(|| BrokerError::NotFound("no such ceremony".to_string()))?;
        ceremony.status = status;
        let _ = (decided_by, surface, ceremony.status_kind());
        Ok(())
    }
}

/// Concrete `CredentialBroker` supporting both `Sealed` DOM fill and `Tokenized` substitution.
pub struct LocalCredentialBroker {
    passwords: Box<dyn PasswordStore>,
    passkeys: Box<dyn PasskeyStore + Send>,
    pending_tokens: HashMap<String, TokenizedSubstitutionSpec>,
}

impl Default for LocalCredentialBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalCredentialBroker {
    /// Creates a credential broker backed by macOS Keychain stores.
    pub fn new() -> Self {
        Self::with_stores(
            Box::new(KeychainPasswordStore::new()),
            Box::new(KeychainPasskeyStore::new()),
        )
    }

    /// Creates an ephemeral credential broker backed by in-memory stores.
    pub fn in_memory() -> Self {
        Self::with_stores(
            Box::new(MemoryPasswordStore::new()),
            Box::new(MemoryPasskeyStore::new()),
        )
    }

    /// Creates a credential broker over explicit password and passkey stores.
    pub fn with_stores(
        passwords: Box<dyn PasswordStore>,
        passkeys: Box<dyn PasskeyStore + Send>,
    ) -> Self {
        Self {
            passwords,
            passkeys,
            pending_tokens: HashMap::new(),
        }
    }

    /// Saves a site-scoped password in the underlying `PasswordStore`.
    pub fn save_password(
        &self,
        host: &str,
        username: &str,
        secret: &str,
    ) -> Result<(), BrokerError> {
        self.passwords.save(host, username, secret)
    }

    /// Deletes a site-scoped password from the underlying `PasswordStore`.
    pub fn delete_password(&self, host: &str, username: &str) -> Result<(), BrokerError> {
        self.passwords.delete(host, username)
    }

    /// Consumes a one-time `TokenizedSubstitutionSpec` bound to `ceremony_id` and `origin`.
    pub fn take_tokenized_spec(
        &mut self,
        ceremony_id: &str,
        origin: &str,
    ) -> Result<TokenizedSubstitutionSpec, BrokerError> {
        let spec = self
            .pending_tokens
            .remove(ceremony_id)
            .ok_or_else(|| BrokerError::NotFound("no tokenized fill spec".to_string()))?;
        if !spec.origin.eq_ignore_ascii_case(origin) {
            return Err(BrokerError::NotAllowed(format!(
                "tokenized credential bound to '{}' cannot be sent to '{origin}'",
                spec.origin
            )));
        }
        Ok(spec)
    }

    /// Lists redacted metadata across both password and passkey stores.
    pub fn list(&self) -> Result<Vec<CredentialMatch>, BrokerError> {
        let mut out: Vec<CredentialMatch> = self
            .passwords
            .list()?
            .into_iter()
            .map(|c| CredentialMatch {
                username_hint: redact_username(&c.username),
                site: c.host,
                is_passkey: false,
            })
            .collect();
        for record in self.passkeys.all().map_err(BrokerError::Storage)? {
            out.push(CredentialMatch {
                username_hint: redact_username(&record.user_name),
                site: record.relying_party_identifier,
                is_passkey: true,
            });
        }
        Ok(out)
    }
}

fn fresh_cred_token() -> Result<String, BrokerError> {
    let raw = crate::webauthn::random::bytes(16).map_err(BrokerError::Storage)?;
    let mut hex = String::with_capacity(38);
    hex.push_str("$cred:");
    for byte in raw {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

impl CredentialBroker for LocalCredentialBroker {
    fn describe_fill(&self, req: CredentialFillRequest) -> Result<CredentialPrompt, BrokerError> {
        let validated = validated_origin(&req.origin, None, false, false, false)?;
        let host = validated.effective_rp_id.clone();
        let registrable_domain = registrable_suffix(&host);
        let matches_host = |candidate: &str| {
            candidate.eq_ignore_ascii_case(&host)
                || candidate.eq_ignore_ascii_case(&registrable_domain)
        };

        let mut matches: Vec<CredentialMatch> = self
            .passwords
            .list()?
            .into_iter()
            .filter(|c| matches_host(&c.host))
            .map(|c| CredentialMatch {
                username_hint: redact_username(&c.username),
                site: c.host,
                is_passkey: false,
            })
            .collect();
        for record in self.passkeys.all().map_err(BrokerError::Storage)? {
            if record.relying_party_identifier.eq_ignore_ascii_case(&host) {
                matches.push(CredentialMatch {
                    username_hint: redact_username(&record.user_name),
                    site: record.relying_party_identifier,
                    is_passkey: true,
                });
            }
        }

        Ok(CredentialPrompt {
            origin: validated.normalized_origin,
            registrable_domain,
            matches,
            can_add_credential: true,
        })
    }

    fn apply_approved_fill(
        &mut self,
        approval: CredentialApproval,
        engine: &mut dyn CredentialSink,
    ) -> Result<CredentialFillReceipt, BrokerError> {
        let chosen = approval
            .chosen
            .ok_or_else(|| BrokerError::Invalid("no credential was chosen".to_string()))?;

        let candidate = self
            .passwords
            .list()?
            .into_iter()
            .find(|c| {
                c.host.eq_ignore_ascii_case(&chosen.site)
                    && redact_username(&c.username) == chosen.username_hint
            })
            .ok_or_else(|| {
                BrokerError::NotFound(format!(
                    "no credential matching {} on {}",
                    chosen.username_hint, chosen.site
                ))
            })?;

        let secret = self
            .passwords
            .secret(&candidate.host, &candidate.username)
            .ok_or_else(|| {
                BrokerError::NotFound(format!(
                    "the secret for {} on {} is no longer stored",
                    chosen.username_hint, chosen.site
                ))
            })?;

        let requested = if approval.fields.is_empty() {
            vec![
                CredentialFieldKind::Username,
                CredentialFieldKind::CurrentPassword,
            ]
        } else {
            approval.fields.clone()
        };
        let target_origin = if approval.origin.is_empty() {
            chosen.site.clone()
        } else {
            approval.origin.clone()
        };

        if approval.mode == CredentialFillMode::Tokenized {
            return self.apply_tokenized_fill(
                &approval.ceremony_id,
                &target_origin,
                &chosen.username_hint,
                &candidate.username,
                &secret,
                &requested,
            );
        }

        let filled_fields = apply_sealed_fields(engine, &requested, &candidate.username, &secret)?;
        Ok(CredentialFillReceipt {
            origin: target_origin,
            filled_fields,
            account_hint: Some(chosen.username_hint),
            mode: CredentialFillMode::Sealed,
            blackout_agent_observation: true,
            field_tokens: HashMap::new(),
        })
    }
}

impl LocalCredentialBroker {
    fn apply_tokenized_fill(
        &mut self,
        ceremony_id: &str,
        target_origin: &str,
        username_hint: &str,
        username: &str,
        secret: &str,
        requested: &[CredentialFieldKind],
    ) -> Result<CredentialFillReceipt, BrokerError> {
        let mut filled_fields = Vec::new();
        let mut field_tokens = HashMap::new();
        let mut username_token = None;
        let mut username_value = None;
        let mut secret_token = None;
        let mut secret_value = None;

        for field in requested {
            match field {
                CredentialFieldKind::Username => {
                    let tok = fresh_cred_token()?;
                    field_tokens.insert(field.as_str().to_string(), tok.clone());
                    username_token = Some(tok);
                    username_value = Some(username.to_string());
                    filled_fields.push(*field);
                }
                CredentialFieldKind::CurrentPassword => {
                    let tok = fresh_cred_token()?;
                    field_tokens.insert(field.as_str().to_string(), tok.clone());
                    secret_token = Some(tok);
                    secret_value = Some(secret.to_string());
                    filled_fields.push(*field);
                }
                other => {
                    return Err(BrokerError::Invalid(format!(
                        "the credential broker cannot fill a {} field",
                        other.as_str()
                    )));
                }
            }
        }

        self.pending_tokens.insert(
            ceremony_id.to_string(),
            TokenizedSubstitutionSpec {
                origin: target_origin.to_string(),
                username_token,
                username_value,
                secret_token,
                secret_value,
            },
        );
        Ok(CredentialFillReceipt {
            origin: target_origin.to_string(),
            filled_fields,
            account_hint: Some(username_hint.to_string()),
            mode: CredentialFillMode::Tokenized,
            blackout_agent_observation: false,
            field_tokens,
        })
    }
}

fn apply_sealed_fields(
    engine: &mut dyn CredentialSink,
    requested: &[CredentialFieldKind],
    username: &str,
    secret: &str,
) -> Result<Vec<CredentialFieldKind>, BrokerError> {
    let mut filled_fields = Vec::new();
    for field in requested {
        match field {
            CredentialFieldKind::Username => {
                engine.set_field(CredentialFieldKind::Username, username)?;
                filled_fields.push(CredentialFieldKind::Username);
            }
            CredentialFieldKind::CurrentPassword => {
                engine.set_field(CredentialFieldKind::CurrentPassword, secret)?;
                filled_fields.push(CredentialFieldKind::CurrentPassword);
            }
            other => {
                return Err(BrokerError::Invalid(format!(
                    "the credential broker cannot fill a {} field",
                    other.as_str()
                )));
            }
        }
    }
    Ok(filled_fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingSink {
        written: Vec<(CredentialFieldKind, String)>,
    }

    impl CredentialSink for RecordingSink {
        fn set_field(
            &mut self,
            field: CredentialFieldKind,
            value: &str,
        ) -> Result<(), BrokerError> {
            self.written.push((field, value.to_string()));
            Ok(())
        }
    }

    #[test]
    fn redacts_usernames_without_hiding_the_domain() {
        assert_eq!(redact_username("ada@example.com"), "a**@example.com");
        assert_eq!(redact_username("a@example.com"), "a**@example.com");
        assert_eq!(redact_username("ada"), "a**");
        assert_eq!(redact_username(""), "");
    }

    #[test]
    fn describes_a_fill_without_leaking_the_secret() {
        let broker = LocalCredentialBroker::in_memory();
        broker
            .save_password("example.com", "ada", "hunter2")
            .unwrap();
        let prompt = broker
            .describe_fill(CredentialFillRequest {
                task_id: "t1".to_string(),
                origin: "https://login.example.com".to_string(),
                fields: vec![CredentialFieldKind::CurrentPassword],
                document_generation: 1,
            })
            .unwrap();
        assert_eq!(prompt.registrable_domain, "example.com");
        assert_eq!(prompt.matches.len(), 1);
        assert_eq!(prompt.matches[0].username_hint, "a**");
        assert_eq!(prompt.matches[0].site, "example.com");
        assert!(!format!("{prompt:?}").contains("hunter2"));
    }

    #[test]
    fn sealed_fill_writes_only_requested_fields_and_requests_blackout() {
        let mut broker = LocalCredentialBroker::in_memory();
        broker
            .save_password("example.com", "ada", "hunter2")
            .unwrap();
        let mut sink = RecordingSink {
            written: Vec::new(),
        };
        let receipt = broker
            .apply_approved_fill(
                CredentialApproval {
                    ceremony_id: "c1".to_string(),
                    chosen: Some(CredentialMatch {
                        username_hint: redact_username("ada"),
                        site: "example.com".to_string(),
                        is_passkey: false,
                    }),
                    remember: false,
                    origin: "https://example.com".to_string(),
                    fields: vec![CredentialFieldKind::Username],
                    mode: CredentialFillMode::Sealed,
                },
                &mut sink,
            )
            .unwrap();
        assert_eq!(
            sink.written,
            vec![(CredentialFieldKind::Username, "ada".into())]
        );
        assert_eq!(receipt.filled_fields, vec![CredentialFieldKind::Username]);
        assert!(receipt.blackout_agent_observation);
    }

    #[test]
    fn tokenized_fill_binds_one_time_tokens_to_origin_without_exposing_secret() {
        let mut broker = LocalCredentialBroker::in_memory();
        broker
            .save_password("example.com", "ada@example.com", "s3cr3t-pw")
            .unwrap();
        let mut sink = RecordingSink {
            written: Vec::new(),
        };
        let receipt = broker
            .apply_approved_fill(
                CredentialApproval {
                    ceremony_id: "cer-tok-1".to_string(),
                    chosen: Some(CredentialMatch {
                        username_hint: redact_username("ada@example.com"),
                        site: "example.com".to_string(),
                        is_passkey: false,
                    }),
                    remember: false,
                    origin: "https://example.com".to_string(),
                    fields: vec![
                        CredentialFieldKind::Username,
                        CredentialFieldKind::CurrentPassword,
                    ],
                    mode: CredentialFillMode::Tokenized,
                },
                &mut sink,
            )
            .unwrap();

        assert!(sink.written.is_empty());
        assert!(!receipt.blackout_agent_observation);
        assert!(!format!("{receipt:?}").contains("s3cr3t-pw"));
        let pw_tok = receipt.field_tokens.get("current_password").unwrap();
        assert!(pw_tok.starts_with("$cred:"));

        // Wrong origin cannot redeem the tokenized substitution spec.
        assert!(broker
            .take_tokenized_spec("cer-tok-1", "https://evil.example")
            .is_err());

        // Single-use: redeeming for the exact origin works once, then is gone.
        let mut broker2 = LocalCredentialBroker::in_memory();
        broker2
            .save_password("example.com", "ada@example.com", "s3cr3t-pw")
            .unwrap();
        let _ = broker2
            .apply_approved_fill(
                CredentialApproval {
                    ceremony_id: "cer-tok-2".to_string(),
                    chosen: Some(CredentialMatch {
                        username_hint: redact_username("ada@example.com"),
                        site: "example.com".to_string(),
                        is_passkey: false,
                    }),
                    remember: false,
                    origin: "https://example.com".to_string(),
                    fields: vec![CredentialFieldKind::CurrentPassword],
                    mode: CredentialFillMode::Tokenized,
                },
                &mut sink,
            )
            .unwrap();
        let spec = broker2
            .take_tokenized_spec("cer-tok-2", "https://example.com")
            .unwrap();
        assert_eq!(spec.secret_value.as_deref(), Some("s3cr3t-pw"));
        assert!(broker2
            .take_tokenized_spec("cer-tok-2", "https://example.com")
            .is_err());
    }

    #[test]
    fn registration_assertion_discovery_and_allow_list_round_trip() {
        let mut broker = LocalPasskeyBroker::in_memory();
        let reg_id = broker
            .begin_registration(RegistrationRequest {
                task_id: "t1".to_string(),
                origin: "https://example.com".to_string(),
                rp: PublicKeyCredentialRpEntity {
                    id: "example.com".to_string(),
                    name: Some("Example".to_string()),
                },
                user: PublicKeyCredentialUserEntity {
                    id: b"user-1".to_vec(),
                    name: "ada@example.com".to_string(),
                    display_name: "Ada".to_string(),
                },
                challenge: b"challenge-1".to_vec(),
                pub_key_cred_params: Vec::new(),
                exclude_credentials: Vec::new(),
                authenticator_selection: None,
                attestation: None,
                extensions: None,
                cross_origin: false,
                related_origin_validated: false,
            })
            .unwrap();
        assert!(matches!(
            broker.poll_registration(reg_id.clone()).unwrap(),
            PasskeyStatus::AwaitingApproval { .. }
        ));
        broker
            .approve_ceremony(reg_id.clone(), "user", "socket")
            .unwrap();
        let PasskeyStatus::Complete(first_outcome) = broker.poll_registration(reg_id).unwrap()
        else {
            panic!("registration must complete");
        };
        let CeremonyOutcome::Registration(first_cred) = *first_outcome else {
            panic!("expected registration outcome");
        };

        // Cross-RP discovery must fail.
        let cross_rp = broker.begin_assertion(PasskeyRequest {
            task_id: "t-cross".to_string(),
            origin: "https://other.test".to_string(),
            rp_id: Some("other.test".to_string()),
            challenge: b"challenge-x".to_vec(),
            allow_credentials: Vec::new(),
            user_verification: None,
            extensions: None,
            cross_origin: false,
            top_origin: None,
            related_origin_validated: false,
        });
        assert!(matches!(cross_rp, Err(BrokerError::NotFound(_))));

        // Same-RP assertion succeeds.
        let assert_id = broker
            .begin_assertion(PasskeyRequest {
                task_id: "t2".to_string(),
                origin: "https://example.com".to_string(),
                rp_id: Some("example.com".to_string()),
                challenge: b"challenge-2".to_vec(),
                allow_credentials: Vec::new(),
                user_verification: Some("preferred".to_string()),
                extensions: None,
                cross_origin: false,
                top_origin: None,
                related_origin_validated: false,
            })
            .unwrap();
        broker
            .approve_ceremony(assert_id.clone(), "user", "socket")
            .unwrap();
        let PasskeyStatus::Complete(assert_outcome) = broker.poll_assertion(assert_id).unwrap()
        else {
            panic!("assertion must complete");
        };
        let CeremonyOutcome::Assertion(assertion) = *assert_outcome else {
            panic!("expected assertion outcome");
        };
        assert_eq!(assertion.id, first_cred.id);
    }

    #[test]
    fn cancelled_ceremony_cannot_be_approved() {
        let mut broker = LocalPasskeyBroker::in_memory();
        let id = broker
            .begin_registration(RegistrationRequest {
                task_id: "t1".to_string(),
                origin: "https://example.com".to_string(),
                rp: PublicKeyCredentialRpEntity {
                    id: "example.com".to_string(),
                    name: None,
                },
                user: PublicKeyCredentialUserEntity {
                    id: b"user-1".to_vec(),
                    name: "ada@example.com".to_string(),
                    display_name: "Ada".to_string(),
                },
                challenge: b"challenge-1".to_vec(),
                pub_key_cred_params: Vec::new(),
                exclude_credentials: Vec::new(),
                authenticator_selection: None,
                attestation: None,
                extensions: None,
                cross_origin: false,
                related_origin_validated: false,
            })
            .unwrap();
        broker.cancel_registration(id.clone()).unwrap();
        assert_eq!(
            broker.poll_registration(id.clone()).unwrap(),
            PasskeyStatus::Cancelled
        );
        assert!(matches!(
            broker.approve_ceremony(id, "user", "socket"),
            Err(BrokerError::InvalidState(_))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_password_and_passkey_stores_round_trip_live() {
        crate::keychain::ensure_test_keychain();
        let pid = std::process::id();
        let pw_store =
            KeychainPasswordStore::with_service(&format!("ai.parawing.authority.test.pw.{pid}"));
        pw_store.save("example.com", "ada", "hunter2").unwrap();
        assert_eq!(
            pw_store.secret("example.com", "ada").as_deref(),
            Some("hunter2")
        );
        assert!(pw_store.secret("other.com", "ada").is_none());
        pw_store.delete("example.com", "ada").unwrap();
        assert!(pw_store.secret("example.com", "ada").is_none());

        let pk_store = KeychainPasskeyStore::with_service(
            &format!("ai.parawing.authority.test.pk.{pid}"),
            "passkey_records_v1",
        );
        let cleanup = pk_store.clone();
        let mut broker = LocalPasskeyBroker::with_store(Box::new(pk_store));
        let reg_id = broker
            .begin_registration(RegistrationRequest {
                task_id: "t-kc".to_string(),
                origin: "https://example.com".to_string(),
                rp: PublicKeyCredentialRpEntity {
                    id: "example.com".to_string(),
                    name: Some("Example".to_string()),
                },
                user: PublicKeyCredentialUserEntity {
                    id: b"u1".to_vec(),
                    name: "ada@example.com".to_string(),
                    display_name: "Ada".to_string(),
                },
                challenge: b"kc-chal".to_vec(),
                pub_key_cred_params: Vec::new(),
                exclude_credentials: Vec::new(),
                authenticator_selection: None,
                attestation: None,
                extensions: None,
                cross_origin: false,
                related_origin_validated: false,
            })
            .unwrap();
        broker
            .approve_ceremony(reg_id.clone(), "user", "socket")
            .unwrap();
        let PasskeyStatus::Complete(kc_outcome) = broker.poll_registration(reg_id).unwrap() else {
            panic!("keychain registration must complete");
        };
        assert!(matches!(*kc_outcome, CeremonyOutcome::Registration(_)));
        let _ = cleanup.clear();
    }
}
