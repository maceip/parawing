// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! W3C WebAuthn Level 2 and Level 3 data models and extension structures.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Errors raised by the authenticator, mapped to W3C DOMException names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebAuthnError {
    /// The request was not allowed (`NotAllowedError`).
    NotAllowed(String),
    /// The credential is already registered (`InvalidStateError`).
    InvalidState(String),
    /// The requested algorithm or capability is unsupported (`NotSupportedError`).
    NotSupported(String),
    /// An origin, RP-ID, or related-origins security check failed (`SecurityError`).
    Security(String),
    /// An argument had an invalid type or empty challenge (`TypeError`).
    Type(String),
    /// A protocol constraint was violated (`ConstraintError`).
    Constraint(String),
    /// The ceremony was aborted (`AbortError`).
    Abort(String),
    /// Encoding or decoding failed (`EncodingError`).
    Encoding(String),
    /// Unclassified authenticator failure (`UnknownError`).
    Unknown(String),
}

impl WebAuthnError {
    /// Returns the W3C `DOMException` name for this error variant.
    pub fn dom_exception_name(&self) -> &'static str {
        match self {
            Self::NotAllowed(_) => "NotAllowedError",
            Self::InvalidState(_) => "InvalidStateError",
            Self::NotSupported(_) => "NotSupportedError",
            Self::Security(_) => "SecurityError",
            Self::Type(_) => "TypeError",
            Self::Constraint(_) => "ConstraintError",
            Self::Abort(_) => "AbortError",
            Self::Encoding(_) => "EncodingError",
            Self::Unknown(_) => "UnknownError",
        }
    }

    /// Returns the human-readable detail without the `DOMException` prefix.
    pub fn detail(&self) -> &str {
        match self {
            Self::NotAllowed(m)
            | Self::InvalidState(m)
            | Self::NotSupported(m)
            | Self::Security(m)
            | Self::Type(m)
            | Self::Constraint(m)
            | Self::Abort(m)
            | Self::Encoding(m)
            | Self::Unknown(m) => m,
        }
    }

    /// Builds an `UnknownError` from a plain error string.
    pub fn unknown(message: impl Into<String>) -> Self {
        Self::Unknown(message.into())
    }
}

impl std::fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.dom_exception_name(), self.detail())
    }
}

impl std::error::Error for WebAuthnError {}

impl From<String> for WebAuthnError {
    fn from(message: String) -> Self {
        Self::Unknown(message)
    }
}

/// CTAP2.1 `largeBlob` extension client inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LargeBlobInputs {
    /// Registration support preference (`"preferred"` or `"required"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<String>,
    /// Requests reading the stored blob during assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    /// Uncompressed blob bytes to seal and write during assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<Vec<u8>>,
}

/// CTAP2.1 `largeBlob` extension client outputs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LargeBlobOutputs {
    /// Whether the credential supports `largeBlob`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    /// Decrypted and decompressed blob bytes on read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<Vec<u8>>,
    /// Whether a requested write succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
}

/// WebAuthn `prf` extension salt or output byte pairs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfValues {
    /// Primary salt or 32-byte PRF output.
    #[serde(default)]
    pub first: Vec<u8>,
    /// Optional secondary salt or 32-byte PRF output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<Vec<u8>>,
}

/// WebAuthn `prf` extension client inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfInputs {
    /// Default salts evaluated for any selected credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<PrfValues>,
    /// Per-credential salts keyed by base64url credential ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "evalByCredential"
    )]
    pub eval_by_credential: Option<HashMap<String, PrfValues>>,
}

/// WebAuthn `prf` extension client outputs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfOutputs {
    /// Whether PRF is enabled on a newly created credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Evaluated HMAC-SHA-256 outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<PrfValues>,
}

/// WebAuthn `credProps` extension output.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredPropsOutput {
    /// Whether the credential is discoverable (resident key).
    #[serde(default)]
    pub rk: bool,
}

/// WebAuthn client extension inputs supported by the authenticator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInputs {
    /// `largeBlob` extension inputs.
    #[serde(default, rename = "largeBlob", skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobInputs>,
    /// `prf` extension inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfInputs>,
    /// `credProps` boolean flag.
    #[serde(default, rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    /// `credProtect` policy name.
    #[serde(
        default,
        rename = "credProtect",
        skip_serializing_if = "Option::is_none"
    )]
    pub cred_protect: Option<String>,
    /// `enforceCredentialProtectionPolicy` flag.
    #[serde(
        default,
        rename = "enforceCredentialProtectionPolicy",
        skip_serializing_if = "Option::is_none"
    )]
    pub enforce_credential_protection_policy: Option<bool>,
    /// `minPinLength` request flag.
    #[serde(
        default,
        rename = "minPinLength",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_pin_length: Option<bool>,
    /// `uvm` user verification method request flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uvm: Option<bool>,
    /// Legacy FIDO `appid` extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    /// Legacy FIDO `appidExclude` extension.
    #[serde(
        default,
        rename = "appidExclude",
        skip_serializing_if = "Option::is_none"
    )]
    pub appid_exclude: Option<String>,
    /// `largeBlobKey` request flag.
    #[serde(
        default,
        rename = "largeBlobKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub large_blob_key: Option<bool>,
}

/// WebAuthn client extension outputs produced by the authenticator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionOutputs {
    /// `largeBlob` extension outputs.
    #[serde(default, rename = "largeBlob", skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobOutputs>,
    /// `prf` extension outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfOutputs>,
    /// `credProps` extension output.
    #[serde(default, rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredPropsOutput>,
    /// Applied numeric `credProtect` level (`1..=3`).
    #[serde(
        default,
        rename = "credProtect",
        skip_serializing_if = "Option::is_none"
    )]
    pub cred_protect: Option<i64>,
    /// Reported minimum PIN length.
    #[serde(
        default,
        rename = "minPinLength",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_pin_length: Option<i64>,
    /// Reported user verification methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uvm: Option<Vec<Vec<i64>>>,
    /// Whether the legacy `appid` matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appid: Option<bool>,
    /// Whether `appidExclude` matched.
    #[serde(
        default,
        rename = "appidExclude",
        skip_serializing_if = "Option::is_none"
    )]
    pub appid_exclude: Option<bool>,
    /// Raw 32-byte `largeBlobKey` material when requested.
    #[serde(
        default,
        rename = "largeBlobKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub large_blob_key: Option<Vec<u8>>,
}

/// Credential descriptor for `excludeCredentials` and `allowCredentials`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    /// Raw credential ID bytes.
    #[serde(default)]
    pub id: Vec<u8>,
    /// Transport hints (`"internal"`, `"hybrid"`, `"usb"`, `"nfc"`, `"ble"`).
    #[serde(default)]
    pub transports: Vec<String>,
    /// Optional discoverable hint.
    #[serde(default, rename = "rk", skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
    /// Credential type (defaults to `"public-key"`).
    #[serde(rename = "type", default = "default_credential_type")]
    pub kind: String,
}

fn default_credential_type() -> String {
    "public-key".to_string()
}

/// Relying party entity for passkey registration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// Relying party domain identifier.
    #[serde(default)]
    pub id: String,
    /// Human-readable relying party name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// User account entity for passkey registration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    /// Opaque user handle bytes.
    #[serde(default)]
    pub id: Vec<u8>,
    /// Account username or email identifier.
    #[serde(default)]
    pub name: String,
    /// Human-readable display name.
    #[serde(default, rename = "displayName")]
    pub display_name: String,
}

/// Requested public-key credential type and COSE algorithm identifier.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    /// COSE algorithm identifier (`-7` for ES256).
    #[serde(default)]
    pub alg: i64,
    /// Credential type (`"public-key"`).
    #[serde(rename = "type", default)]
    pub kind: String,
}

/// `authenticatorSelection` criteria for registration ceremonies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// Attachment modality (`"platform"` or `"cross-platform"`).
    #[serde(
        default,
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<String>,
    /// Legacy boolean resident-key requirement.
    #[serde(
        default,
        rename = "requireResidentKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub require_resident_key: Option<bool>,
    /// Resident-key preference (`"required"`, `"preferred"`, `"discouraged"`).
    #[serde(
        default,
        rename = "residentKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub resident_key: Option<String>,
    /// User verification preference (`"required"`, `"preferred"`, `"discouraged"`).
    #[serde(
        default,
        rename = "userVerification",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_verification: Option<String>,
}

/// W3C `PublicKeyCredentialCreationOptions`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialCreationOptions {
    /// Relying party metadata.
    #[serde(default)]
    pub rp: PublicKeyCredentialRpEntity,
    /// User account metadata.
    #[serde(default)]
    pub user: PublicKeyCredentialUserEntity,
    /// Challenge bytes chosen by the relying party.
    #[serde(default)]
    pub challenge: Vec<u8>,
    /// Acceptable public-key algorithms.
    #[serde(default, rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Ceremony timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Credentials that must not be re-registered.
    #[serde(default, rename = "excludeCredentials")]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// Authenticator attachment and resident-key selection criteria.
    #[serde(
        default,
        rename = "authenticatorSelection",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    /// Client extension inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionInputs>,
}

/// W3C `PublicKeyCredentialRequestOptions`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialRequestOptions {
    /// Challenge bytes chosen by the relying party.
    #[serde(default)]
    pub challenge: Vec<u8>,
    /// Optional explicit relying party identifier.
    #[serde(default, rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    /// Ceremony timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Allowed non-discoverable or filtered credentials.
    #[serde(default, rename = "allowCredentials")]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// User verification preference.
    #[serde(
        default,
        rename = "userVerification",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_verification: Option<String>,
    /// Client extension inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionInputs>,
    /// WebAuthn Level 3 hints (`"security-key"`, `"client-device"`, `"hybrid"`).
    #[serde(default)]
    pub hints: Vec<String>,
}

/// Registration credential returned from `navigator.credentials.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationCredential {
    /// Base64url credential ID.
    pub id: String,
    /// Base64url raw credential ID.
    pub raw_id: String,
    /// Credential type (`"public-key"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Attestation response payload.
    pub response: RegistrationResponse,
    /// Reported authenticator attachment.
    #[serde(
        default,
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<String>,
    /// Client extension outputs.
    #[serde(default, rename = "clientExtensionResults")]
    pub client_extension_results: ExtensionOutputs,
}

/// `AuthenticatorAttestationResponse` wire fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// Base64url CBOR `attestationObject`.
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// Base64url `clientDataJSON`.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Supported transports reported for this credential.
    #[serde(default)]
    pub transports: Vec<String>,
}

/// Assertion credential returned from `navigator.credentials.get`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionCredential {
    /// Base64url credential ID.
    pub id: String,
    /// Base64url raw credential ID.
    pub raw_id: String,
    /// Credential type (`"public-key"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Assertion response payload.
    pub response: AssertionResponse,
    /// Reported authenticator attachment.
    #[serde(
        default,
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<String>,
    /// Client extension outputs.
    #[serde(default, rename = "clientExtensionResults")]
    pub client_extension_results: ExtensionOutputs,
}

/// `AuthenticatorAssertionResponse` wire fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionResponse {
    /// Base64url `authenticatorData`.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Base64url `clientDataJSON`.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Base64url DER-encoded ES256 signature.
    pub signature: String,
    /// Base64url user handle.
    #[serde(
        default,
        rename = "userHandle",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_handle: Option<String>,
}

/// Maps a `credProtect` policy string to CTAP numeric level `1`, `2`, or `3`.
pub fn cred_protect_level(policy: &str) -> Option<i64> {
    match policy {
        "userVerificationOptional" => Some(1),
        "userVerificationOptionalWithCredentialIDList" => Some(2),
        "userVerificationRequired" => Some(3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_names_match_the_dom_exception_names() {
        assert_eq!(
            WebAuthnError::NotAllowed("x".into()).dom_exception_name(),
            "NotAllowedError"
        );
        assert_eq!(
            WebAuthnError::Security("x".into()).dom_exception_name(),
            "SecurityError"
        );
        assert_eq!(
            WebAuthnError::InvalidState("x".into()).dom_exception_name(),
            "InvalidStateError"
        );
    }

    #[test]
    fn cred_protect_levels_follow_the_spec() {
        assert_eq!(cred_protect_level("userVerificationOptional"), Some(1));
        assert_eq!(
            cred_protect_level("userVerificationOptionalWithCredentialIDList"),
            Some(2)
        );
        assert_eq!(cred_protect_level("userVerificationRequired"), Some(3));
        assert_eq!(cred_protect_level("nonsense"), None);
    }

    #[test]
    fn extension_inputs_use_the_spec_member_names() {
        let json = serde_json::json!({
            "largeBlob": {"support": "preferred", "read": true},
            "prf": {"eval": {"first": [1, 2, 3]}},
            "credProps": true,
            "credProtect": "userVerificationRequired",
            "appidExclude": "https://example.com/appid.json",
            "largeBlobKey": true
        });
        let parsed: ExtensionInputs = serde_json::from_value(json).unwrap();
        assert_eq!(
            parsed.large_blob.as_ref().unwrap().support.as_deref(),
            Some("preferred")
        );
        assert!(parsed.cred_props.unwrap());
        assert_eq!(
            parsed.cred_protect.as_deref(),
            Some("userVerificationRequired")
        );
        assert_eq!(
            parsed.appid_exclude.as_deref(),
            Some("https://example.com/appid.json")
        );
        assert!(parsed.large_blob_key.unwrap());
    }

    #[test]
    fn extension_outputs_use_the_spec_member_names() {
        let outputs = ExtensionOutputs {
            cred_props: Some(CredPropsOutput { rk: true }),
            cred_protect: Some(2),
            ..Default::default()
        };
        let value = serde_json::to_value(&outputs).unwrap();
        assert_eq!(value["credProps"]["rk"], serde_json::json!(true));
        assert_eq!(value["credProtect"], serde_json::json!(2));
    }
}
