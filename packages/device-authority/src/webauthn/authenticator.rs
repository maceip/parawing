// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! W3C WebAuthn Level 2 and Level 3 software authenticator ceremonies.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::webauthn::authdata::{
    AttestedCredentialData, AuthenticatorData, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV,
};
use crate::webauthn::b64::b64url_encode;
use crate::webauthn::cbor::Cbor;
use crate::webauthn::clientdata::{CeremonyType, client_data_json};
use crate::webauthn::cose::{
    cose_key_from_pem, generate_p256_keypair, sign_es256_der, validate_p256_public_pem,
};
use crate::webauthn::largeblob;
use crate::webauthn::origin::{OriginValidation, ValidatedOrigin, validate_origin_and_effective_rp_id};
use crate::webauthn::prf;
use crate::webauthn::random;
use crate::webauthn::types::{
    AssertionCredential, AssertionResponse, CredPropsOutput, ExtensionInputs, ExtensionOutputs,
    LargeBlobInputs, LargeBlobOutputs, PrfOutputs, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions, RegistrationCredential,
    RegistrationResponse, WebAuthnError, cred_protect_level,
};

/// Equipped/Parawing software authenticator AAGUID (`"EQUIPPEDPASSKEY\x01"`).
pub const EQUIPPED_AAGUID: [u8; 16] = [
    0x45, 0x51, 0x55, 0x49, 0x50, 0x50, 0x45, 0x44, 0x50, 0x41, 0x53, 0x53, 0x4b, 0x45, 0x59, 0x01,
];

/// COSE algorithm identifier for ECDSA P-256 with SHA-256 (`ES256`).
pub const COSE_ALG_ES256: i64 = -7;

const MIN_PIN_LENGTH: i64 = 6;
const MAX_CHALLENGE_LEN: usize = 1024;

fn uvm_output() -> Vec<Vec<i64>> {
    vec![vec![0x0000_0002, 0x0000_0004, 0x0000_0000]]
}

/// Trusted host-supplied context for a registration or assertion ceremony.
#[derive(Clone, Copy, Debug)]
pub struct CeremonyContext<'a> {
    /// Document origin observed by the host (never trusted from page JS).
    pub origin: &'a str,
    /// Whether the ceremony originated inside a cross-origin iframe.
    pub cross_origin: bool,
    /// Top-level frame origin when `cross_origin` is true.
    pub top_origin: Option<&'a str>,
    /// ISO-8601 timestamp recorded for newly created credentials.
    pub now_iso: &'a str,
    /// True only after `related_origins::validate` has succeeded for `(origin, rp_id)`.
    pub related_origin_validated: bool,
}

impl<'a> CeremonyContext<'a> {
    /// Creates a same-origin ceremony context with explicit timestamp.
    pub fn same_origin(origin: &'a str, now_iso: &'a str) -> Self {
        Self {
            origin,
            cross_origin: false,
            top_origin: None,
            now_iso,
            related_origin_validated: false,
        }
    }
}

/// Persisted passkey record managed by a `PasskeyStore`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredPasskey {
    /// Raw 32-byte credential ID.
    pub credential_id: Vec<u8>,
    /// Relying party identifier this credential is bound to.
    pub relying_party_identifier: String,
    /// User handle (`user.id`).
    pub user_id: Vec<u8>,
    /// Account username or email (`user.name`).
    pub user_name: String,
    /// Human-readable display name (`user.displayName`).
    pub user_display_name: String,
    /// COSE algorithm identifier (`-7` for ES256).
    pub algorithm: i64,
    /// PKCS#8 PEM P-256 private signing key.
    pub private_key_pem: String,
    /// SPKI PEM P-256 public verification key.
    pub public_key_pem: String,
    /// Monotonic assertion signature counter.
    pub sign_count: u32,
    /// Whether the credential is discoverable without `allowCredentials`.
    pub is_resident_key: bool,
    /// CTAP `credProtect` level (`1`, `2`, or `3`).
    pub cred_protect_level: i64,
    /// Whether CTAP2.1 `largeBlob` storage is enabled.
    pub large_blob_supported: bool,
    /// 32-byte AES-256-GCM key for `largeBlob` payloads.
    pub large_blob_key: Vec<u8>,
    /// Sealed `largeBlob` ciphertext (`nonce || ciphertext || tag`).
    pub compressed_large_blob: Option<Vec<u8>>,
    /// Uncompressed byte length of `compressed_large_blob`.
    pub large_blob_original_size: Option<usize>,
    /// 32-byte credential-specific secret for the `prf` (`hmac-secret`) extension.
    pub prf_secret: Vec<u8>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

impl StoredPasskey {
    /// Returns the base64url-encoded credential ID.
    pub fn credential_id_b64url(&self) -> String {
        b64url_encode(&self.credential_id)
    }
}

/// Backing store trait for persisted passkey records.
pub trait PasskeyStore {
    /// Returns every stored passkey record.
    fn all(&self) -> Result<Vec<StoredPasskey>, String>;

    /// Inserts a newly created passkey record.
    fn insert(&mut self, record: StoredPasskey) -> Result<(), String>;

    /// Replaces an existing passkey record matched by `credential_id`.
    fn update(&mut self, record: StoredPasskey) -> Result<(), String>;

    /// Deletes a passkey record by `credential_id`.
    fn delete(&mut self, credential_id: &[u8]) -> Result<(), String>;

    /// Lists passkey records scoped to `rp_id` (case-insensitive).
    fn for_rp(&self, rp_id: &str) -> Result<Vec<StoredPasskey>, String> {
        Ok(self
            .all()?
            .into_iter()
            .filter(|p| p.relying_party_identifier.eq_ignore_ascii_case(rp_id))
            .collect())
    }

    /// Looks up a single passkey record by raw `credential_id`.
    fn by_credential_id(&self, credential_id: &[u8]) -> Result<Option<StoredPasskey>, String> {
        Ok(self
            .all()?
            .into_iter()
            .find(|p| p.credential_id == credential_id))
    }
}

fn validated_origin(
    ctx: &CeremonyContext<'_>,
    requested_rp_id: Option<&str>,
    is_create: bool,
) -> Result<ValidatedOrigin, WebAuthnError> {
    match validate_origin_and_effective_rp_id(
        ctx.origin,
        requested_rp_id,
        ctx.cross_origin,
        is_create,
    )? {
        OriginValidation::Suffix(validated) => Ok(validated),
        OriginValidation::NeedsRelatedOrigins {
            validated,
            caller_origin,
            rp_id,
        } => {
            if !ctx.related_origin_validated {
                return Err(WebAuthnError::Security(format!(
                    "The origin '{caller_origin}' is not related to '{rp_id}'"
                )));
            }
            Ok(validated)
        }
    }
}

/// Software WebAuthn authenticator backed by any `PasskeyStore`.
pub struct Authenticator {
    /// AAGUID embedded into registration `attestedCredentialData`.
    pub aaguid: [u8; 16],
}

impl Default for Authenticator {
    fn default() -> Self {
        Self {
            aaguid: EQUIPPED_AAGUID,
        }
    }
}

impl Authenticator {
    /// Creates an `Authenticator` with `EQUIPPED_AAGUID`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Executes a `navigator.credentials.create` registration ceremony.
    pub fn create(
        &self,
        store: &mut dyn PasskeyStore,
        options: &PublicKeyCredentialCreationOptions,
        ctx: &CeremonyContext<'_>,
    ) -> Result<(RegistrationCredential, StoredPasskey), WebAuthnError> {
        validate_challenge(&options.challenge)?;
        let validated = validated_origin(ctx, Some(options.rp.id.as_str()), true)?;
        ensure_es256_accepted(options)?;
        ensure_not_excluded(store, &options.exclude_credentials)?;

        let extensions = options.extensions.clone().unwrap_or_default();
        let is_resident_key = registration_resident_key(options);
        let protect_level = registration_cred_protect_level(&extensions);

        let credential_id = random::bytes(32).map_err(WebAuthnError::unknown)?;
        let large_blob_key = random::bytes(32).map_err(WebAuthnError::unknown)?;
        let prf_secret = random::bytes(32).map_err(WebAuthnError::unknown)?;
        let (private_key_pem, public_key_pem) =
            generate_p256_keypair().map_err(WebAuthnError::unknown)?;
        validate_p256_public_pem(&public_key_pem).map_err(WebAuthnError::unknown)?;
        let cose_key = cose_key_from_pem(&public_key_pem).map_err(WebAuthnError::unknown)?;

        let client_data = client_data_json(
            CeremonyType::Create,
            &options.challenge,
            &validated.normalized_origin,
            ctx.cross_origin,
            ctx.top_origin,
        );

        let (outputs, extensions_cbor) = evaluate_create_extensions(
            &extensions,
            is_resident_key,
            protect_level,
            &large_blob_key,
            &prf_secret,
        )?;
        let mut flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT;
        if extensions_cbor.is_some() {
            flags |= FLAG_ED;
        }

        let authenticator_data = AuthenticatorData {
            rp_id_hash: AuthenticatorData::rp_id_hash(&validated.effective_rp_id),
            flags,
            sign_count: 0,
            attested_credential_data: Some(AttestedCredentialData::new(
                self.aaguid,
                credential_id.clone(),
                cose_key,
            )),
            extensions: extensions_cbor,
        };
        let attestation_object = authenticator_data.attestation_object();

        replace_existing_resident_credentials(
            store,
            is_resident_key,
            &validated.effective_rp_id,
            &options.user.id,
        )?;

        let record = StoredPasskey {
            credential_id: credential_id.clone(),
            relying_party_identifier: validated.effective_rp_id,
            user_id: options.user.id.clone(),
            user_name: options.user.name.clone(),
            user_display_name: options.user.display_name.clone(),
            algorithm: COSE_ALG_ES256,
            private_key_pem,
            public_key_pem,
            sign_count: 0,
            is_resident_key,
            cred_protect_level: protect_level,
            large_blob_supported: true,
            large_blob_key,
            compressed_large_blob: None,
            large_blob_original_size: None,
            prf_secret,
            created_at: ctx.now_iso.to_string(),
        };
        store.insert(record.clone())?;

        let credential = RegistrationCredential {
            id: b64url_encode(&credential_id),
            raw_id: b64url_encode(&credential_id),
            kind: "public-key".to_string(),
            response: RegistrationResponse {
                attestation_object: b64url_encode(&attestation_object),
                client_data_json: b64url_encode(&client_data),
                transports: vec!["internal".to_string(), "hybrid".to_string()],
            },
            authenticator_attachment: Some(registration_attachment(options)),
            client_extension_results: outputs,
        };
        Ok((credential, record))
    }

    /// Executes a `navigator.credentials.get` assertion ceremony.
    pub fn get(
        &self,
        store: &mut dyn PasskeyStore,
        options: &PublicKeyCredentialRequestOptions,
        ctx: &CeremonyContext<'_>,
    ) -> Result<(AssertionCredential, StoredPasskey), WebAuthnError> {
        validate_challenge(&options.challenge)?;
        let validated = validated_origin(ctx, options.rp_id.as_deref(), false)?;
        let extensions = options.extensions.clone().unwrap_or_default();

        let all = store.all()?;
        let mut record = select_assertion_credential(
            &all,
            &validated.effective_rp_id,
            &options.allow_credentials,
            extensions.appid.as_deref(),
        )?;

        if record.cred_protect_level == 3
            && options.user_verification.as_deref() == Some("discouraged")
        {
            return Err(WebAuthnError::NotAllowed(
                "Credential requires user verification (credProtect level 3)".to_string(),
            ));
        }

        record.sign_count = record.sign_count.wrapping_add(1);
        let outputs = evaluate_get_extensions(&extensions, &mut record)?;

        let client_data = client_data_json(
            CeremonyType::Get,
            &options.challenge,
            &validated.normalized_origin,
            ctx.cross_origin,
            ctx.top_origin,
        );
        let authenticator_data = AuthenticatorData {
            rp_id_hash: AuthenticatorData::rp_id_hash(&record.relying_party_identifier),
            flags: FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS,
            sign_count: record.sign_count,
            attested_credential_data: None,
            extensions: None,
        };
        let authenticator_data_bytes = authenticator_data.encode();

        let client_data_hash = Sha256::digest(&client_data);
        let mut signed_bytes = Vec::with_capacity(authenticator_data_bytes.len() + 32);
        signed_bytes.extend_from_slice(&authenticator_data_bytes);
        signed_bytes.extend_from_slice(&client_data_hash);

        let signature = sign_es256_der(&record.private_key_pem, &signed_bytes)
            .map_err(WebAuthnError::unknown)?;
        store.update(record.clone())?;

        let attachment = if options.hints.iter().any(|h| h == "security-key") {
            "cross-platform"
        } else {
            "platform"
        };

        let credential = AssertionCredential {
            id: b64url_encode(&record.credential_id),
            raw_id: b64url_encode(&record.credential_id),
            kind: "public-key".to_string(),
            response: AssertionResponse {
                authenticator_data: b64url_encode(&authenticator_data_bytes),
                client_data_json: b64url_encode(&client_data),
                signature: b64url_encode(&signature),
                user_handle: Some(b64url_encode(&record.user_id)),
            },
            authenticator_attachment: Some(attachment.to_string()),
            client_extension_results: outputs,
        };
        Ok((credential, record))
    }
}

fn ensure_es256_accepted(
    options: &PublicKeyCredentialCreationOptions,
) -> Result<(), WebAuthnError> {
    let accepts_es256 = options.pub_key_cred_params.is_empty()
        || options
            .pub_key_cred_params
            .iter()
            .any(|p| p.alg == COSE_ALG_ES256 && p.kind == "public-key");
    if !accepts_es256 {
        return Err(WebAuthnError::NotSupported(
            "No supported public key algorithm was offered (ES256 is required)".to_string(),
        ));
    }
    Ok(())
}

fn ensure_not_excluded(
    store: &dyn PasskeyStore,
    excluded_list: &[PublicKeyCredentialDescriptor],
) -> Result<(), WebAuthnError> {
    for excluded in excluded_list {
        if excluded.kind != "public-key" && !excluded.kind.is_empty() {
            continue;
        }
        if store.by_credential_id(&excluded.id)?.is_some() {
            return Err(WebAuthnError::InvalidState(
                "A credential with this identifier is already registered".to_string(),
            ));
        }
    }
    Ok(())
}

fn replace_existing_resident_credentials(
    store: &mut dyn PasskeyStore,
    is_resident_key: bool,
    effective_rp_id: &str,
    user_id: &[u8],
) -> Result<(), WebAuthnError> {
    if !is_resident_key {
        return Ok(());
    }
    for existing in store.for_rp(effective_rp_id)? {
        if existing.user_id == user_id {
            store.delete(&existing.credential_id)?;
        }
    }
    Ok(())
}

fn registration_attachment(options: &PublicKeyCredentialCreationOptions) -> String {
    let requested = options
        .authenticator_selection
        .as_ref()
        .and_then(|s| s.authenticator_attachment.as_deref());
    if requested == Some("cross-platform") {
        "cross-platform".to_string()
    } else {
        "platform".to_string()
    }
}

fn evaluate_create_extensions(
    extensions: &ExtensionInputs,
    is_resident_key: bool,
    protect_level: i64,
    large_blob_key: &[u8],
    prf_secret: &[u8],
) -> Result<(ExtensionOutputs, Option<Vec<u8>>), WebAuthnError> {
    let mut outputs = ExtensionOutputs::default();
    let mut cbor_pairs: Vec<(Cbor, Cbor)> = Vec::new();

    if extensions.large_blob.is_some() {
        outputs.large_blob = Some(LargeBlobOutputs {
            supported: Some(true),
            ..Default::default()
        });
    }
    if extensions.large_blob_key == Some(true) {
        outputs.large_blob_key = Some(large_blob_key.to_vec());
    }
    if let Some(prf_input) = &extensions.prf {
        let results = match &prf_input.eval {
            Some(values) => Some(
                prf::evaluate(prf_secret, &values.first, values.second.as_deref())
                    .map_err(WebAuthnError::unknown)?,
            ),
            None => None,
        };
        outputs.prf = Some(PrfOutputs {
            enabled: Some(true),
            results,
        });
        cbor_pairs.push((Cbor::text("hmac-secret"), Cbor::Bool(true)));
    }
    if extensions.cred_props == Some(true) {
        outputs.cred_props = Some(CredPropsOutput {
            rk: is_resident_key,
        });
    }
    if extensions.cred_protect.is_some() {
        outputs.cred_protect = Some(protect_level);
        cbor_pairs.push((Cbor::text("credProtect"), Cbor::Uint(protect_level as u64)));
    }
    if extensions.min_pin_length == Some(true) {
        outputs.min_pin_length = Some(MIN_PIN_LENGTH);
        cbor_pairs.push((
            Cbor::text("minPinLength"),
            Cbor::Uint(MIN_PIN_LENGTH as u64),
        ));
    }
    if extensions.uvm == Some(true) {
        outputs.uvm = Some(uvm_output());
    }

    let encoded = if cbor_pairs.is_empty() {
        None
    } else {
        Some(Cbor::Map(cbor_pairs).encode())
    };
    Ok((outputs, encoded))
}

fn select_assertion_credential(
    all: &[StoredPasskey],
    effective_rp_id: &str,
    allow_credentials: &[PublicKeyCredentialDescriptor],
    appid: Option<&str>,
) -> Result<StoredPasskey, WebAuthnError> {
    let selected = if allow_credentials.is_empty() {
        all.iter().rev().find(|p| {
            p.relying_party_identifier
                .eq_ignore_ascii_case(effective_rp_id)
                && p.is_resident_key
                && p.cred_protect_level < 2
        })
    } else {
        let allowed: Vec<&[u8]> = allow_credentials
            .iter()
            .filter(|c| c.kind == "public-key" || c.kind.is_empty())
            .map(|c| c.id.as_slice())
            .collect();
        all.iter().rev().find(|p| {
            let rp_matches = p
                .relying_party_identifier
                .eq_ignore_ascii_case(effective_rp_id)
                || appid.is_some_and(|a| p.relying_party_identifier.eq_ignore_ascii_case(a));
            rp_matches && allowed.contains(&p.credential_id.as_slice())
        })
    };

    selected.cloned().ok_or_else(|| {
        WebAuthnError::NotAllowed(format!(
            "No matching passkey found for relying party {effective_rp_id}"
        ))
    })
}

fn evaluate_get_extensions(
    extensions: &ExtensionInputs,
    record: &mut StoredPasskey,
) -> Result<ExtensionOutputs, WebAuthnError> {
    let mut outputs = ExtensionOutputs::default();
    if let Some(large_blob_input) = &extensions.large_blob {
        outputs.large_blob = apply_get_large_blob(large_blob_input, record)?;
    }
    if extensions.large_blob_key == Some(true) && record.large_blob_supported {
        outputs.large_blob_key = Some(record.large_blob_key.clone());
    }
    if let Some(prf_input) = &extensions.prf {
        let cred_b64 = record.credential_id_b64url();
        let chosen = prf_input
            .eval_by_credential
            .as_ref()
            .and_then(|by_cred| by_cred.get(&cred_b64))
            .or(prf_input.eval.as_ref());
        if let Some(values) = chosen {
            let evaluated =
                prf::evaluate(&record.prf_secret, &values.first, values.second.as_deref())
                    .map_err(WebAuthnError::unknown)?;
            outputs.prf = Some(PrfOutputs {
                enabled: None,
                results: Some(evaluated),
            });
        }
    }
    if let Some(appid) = extensions.appid.as_deref() {
        outputs.appid = Some(record.relying_party_identifier.eq_ignore_ascii_case(appid));
    }
    if extensions.uvm == Some(true) {
        outputs.uvm = Some(uvm_output());
    }
    Ok(outputs)
}

fn apply_get_large_blob(
    input: &LargeBlobInputs,
    record: &mut StoredPasskey,
) -> Result<Option<LargeBlobOutputs>, WebAuthnError> {
    if input.read == Some(true) {
        let blob = match (
            record.large_blob_supported,
            &record.compressed_large_blob,
            record.large_blob_original_size,
        ) {
            (true, Some(ciphertext), Some(original_size)) => Some(
                largeblob::decrypt_and_decompress(
                    ciphertext,
                    original_size,
                    &record.large_blob_key,
                )
                .map_err(WebAuthnError::unknown)?,
            ),
            _ => None,
        };
        return Ok(Some(LargeBlobOutputs {
            blob,
            ..Default::default()
        }));
    }

    let Some(write_data) = &input.write else {
        return Ok(None);
    };
    let can_write =
        record.large_blob_supported && write_data.len() <= largeblob::MAX_UNCOMPRESSED_BYTES;
    let written = if can_write {
        seal_record_large_blob(record, write_data)
    } else {
        false
    };
    Ok(Some(LargeBlobOutputs {
        written: Some(written),
        ..Default::default()
    }))
}

fn seal_record_large_blob(record: &mut StoredPasskey, write_data: &[u8]) -> bool {
    let Ok((ciphertext, original_size)) =
        largeblob::compress_and_encrypt(write_data, &record.large_blob_key)
    else {
        return false;
    };
    record.compressed_large_blob = Some(ciphertext);
    record.large_blob_original_size = Some(original_size);
    true
}

fn validate_challenge(challenge: &[u8]) -> Result<(), WebAuthnError> {
    if challenge.is_empty() {
        return Err(WebAuthnError::Type(
            "The challenge must not be empty".to_string(),
        ));
    }
    if challenge.len() > MAX_CHALLENGE_LEN {
        return Err(WebAuthnError::Constraint(format!(
            "The challenge must not exceed {MAX_CHALLENGE_LEN} bytes"
        )));
    }
    Ok(())
}

fn registration_resident_key(options: &PublicKeyCredentialCreationOptions) -> bool {
    let Some(selection) = options.authenticator_selection.as_ref() else {
        return true;
    };
    match selection.resident_key.as_deref() {
        Some("discouraged") => selection.require_resident_key.unwrap_or(false),
        Some(_) => true,
        None => selection.require_resident_key.unwrap_or(true),
    }
}

fn registration_cred_protect_level(extensions: &ExtensionInputs) -> i64 {
    extensions
        .cred_protect
        .as_deref()
        .and_then(cred_protect_level)
        .unwrap_or(1)
}

/// Ephemeral in-memory `PasskeyStore` for cross-platform unit tests and sandboxes.
#[derive(Clone, Debug, Default)]
pub struct MemoryPasskeyStore {
    records: Vec<StoredPasskey>,
}

impl MemoryPasskeyStore {
    /// Creates an empty in-memory passkey store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PasskeyStore for MemoryPasskeyStore {
    fn all(&self) -> Result<Vec<StoredPasskey>, String> {
        Ok(self.records.clone())
    }

    fn insert(&mut self, record: StoredPasskey) -> Result<(), String> {
        self.records.push(record);
        Ok(())
    }

    fn update(&mut self, record: StoredPasskey) -> Result<(), String> {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|p| p.credential_id == record.credential_id)
        {
            *existing = record;
            Ok(())
        } else {
            Err("no such passkey".to_string())
        }
    }

    fn delete(&mut self, credential_id: &[u8]) -> Result<(), String> {
        self.records.retain(|p| p.credential_id != credential_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::cose::verify_es256_der;
    use crate::webauthn::types::{
        AuthenticatorSelectionCriteria, PrfInputs, PrfValues, PublicKeyCredentialParameters,
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    };

    fn creation_options(challenge: &[u8]) -> PublicKeyCredentialCreationOptions {
        PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"user-handle-1".to_vec(),
                name: "ada@example.com".to_string(),
                display_name: "Ada Lovelace".to_string(),
            },
            challenge: challenge.to_vec(),
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                alg: COSE_ALG_ES256,
                kind: "public-key".to_string(),
            }],
            timeout: None,
            exclude_credentials: Vec::new(),
            authenticator_selection: None,
            attestation: Some("none".to_string()),
            extensions: None,
        }
    }

    fn request_options(challenge: &[u8]) -> PublicKeyCredentialRequestOptions {
        PublicKeyCredentialRequestOptions {
            challenge: challenge.to_vec(),
            rp_id: Some("example.com".to_string()),
            timeout: None,
            allow_credentials: Vec::new(),
            user_verification: Some("preferred".to_string()),
            extensions: None,
            hints: Vec::new(),
        }
    }

    fn ctx(origin: &str) -> CeremonyContext<'_> {
        CeremonyContext::same_origin(origin, "2026-11-06T00:00:00Z")
    }

    #[test]
    fn registration_produces_a_verifiable_credential() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        let (credential, record) = authenticator
            .create(
                &mut store,
                &creation_options(b"challenge-1"),
                &ctx("https://example.com"),
            )
            .unwrap();

        assert_eq!(credential.kind, "public-key");
        assert_eq!(credential.id, record.credential_id_b64url());
        assert!(!credential.response.attestation_object.is_empty());
        assert!(!credential.response.client_data_json.is_empty());
        assert_eq!(store.all().unwrap().len(), 1);
        assert_eq!(record.sign_count, 0);
        assert!(record.is_resident_key);
        assert_eq!(record.cred_protect_level, 1);
    }

    #[test]
    fn assertion_signature_verifies_against_the_stored_public_key() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        let (credential, _) = authenticator
            .create(
                &mut store,
                &creation_options(b"challenge-1"),
                &ctx("https://example.com"),
            )
            .unwrap();

        let (assertion, record) = authenticator
            .get(
                &mut store,
                &request_options(b"challenge-2"),
                &ctx("https://example.com"),
            )
            .unwrap();

        let auth_data =
            crate::webauthn::b64::b64url_decode(&assertion.response.authenticator_data).unwrap();
        let client_data =
            crate::webauthn::b64::b64url_decode(&assertion.response.client_data_json).unwrap();
        let signature = crate::webauthn::b64::b64url_decode(&assertion.response.signature).unwrap();

        let client_data_hash = Sha256::digest(&client_data);
        let mut signed = auth_data;
        signed.extend_from_slice(&client_data_hash);

        assert!(verify_es256_der(&record.public_key_pem, &signed, &signature).unwrap());

        let json: serde_json::Value = serde_json::from_slice(&client_data).unwrap();
        assert_eq!(json["type"], "webauthn.get");
        assert_eq!(
            json["challenge"],
            crate::webauthn::b64::b64url_encode(b"challenge-2")
        );
        assert_eq!(json["origin"], "https://example.com");
        assert_eq!(credential.kind, "public-key");
    }

    #[test]
    fn the_signature_counter_advances_monotonically() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        authenticator
            .create(
                &mut store,
                &creation_options(b"c1"),
                &ctx("https://example.com"),
            )
            .unwrap();
        let (_, first) = authenticator
            .get(
                &mut store,
                &request_options(b"c2"),
                &ctx("https://example.com"),
            )
            .unwrap();
        let (_, second) = authenticator
            .get(
                &mut store,
                &request_options(b"c3"),
                &ctx("https://example.com"),
            )
            .unwrap();
        assert_eq!(first.sign_count, 1);
        assert_eq!(second.sign_count, 2);
    }

    #[test]
    fn an_assertion_for_an_unknown_relying_party_fails() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        authenticator
            .create(
                &mut store,
                &creation_options(b"c1"),
                &ctx("https://example.com"),
            )
            .unwrap();
        let err = authenticator
            .get(
                &mut store,
                &request_options(b"c2"),
                &ctx("https://other.com"),
            )
            .unwrap_err();
        assert_eq!(err.dom_exception_name(), "SecurityError");
    }

    #[test]
    fn an_excluded_credential_is_refused() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        let (credential, _) = authenticator
            .create(
                &mut store,
                &creation_options(b"c1"),
                &ctx("https://example.com"),
            )
            .unwrap();
        let mut options = creation_options(b"c2");
        options.exclude_credentials = vec![PublicKeyCredentialDescriptor {
            id: crate::webauthn::b64::b64url_decode(&credential.raw_id).unwrap(),
            transports: Vec::new(),
            rk: None,
            kind: "public-key".to_string(),
        }];
        let err = authenticator
            .create(&mut store, &options, &ctx("https://example.com"))
            .unwrap_err();
        assert_eq!(err.dom_exception_name(), "InvalidStateError");
    }

    #[test]
    fn the_prf_extension_evaluates_during_registration_and_assertion() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        let mut options = creation_options(b"c1");
        options.extensions = Some(ExtensionInputs {
            prf: Some(PrfInputs {
                eval: Some(PrfValues {
                    first: b"salt".to_vec(),
                    second: None,
                }),
                eval_by_credential: None,
            }),
            ..Default::default()
        });
        let (credential, _) = authenticator
            .create(&mut store, &options, &ctx("https://example.com"))
            .unwrap();
        let prf_out = credential
            .client_extension_results
            .prf
            .as_ref()
            .expect("prf output");
        assert_eq!(prf_out.enabled, Some(true));
        assert!(prf_out.results.is_some());

        let mut request = request_options(b"c2");
        request.extensions = Some(ExtensionInputs {
            prf: Some(PrfInputs {
                eval: Some(PrfValues {
                    first: b"salt".to_vec(),
                    second: None,
                }),
                eval_by_credential: None,
            }),
            ..Default::default()
        });
        let (assertion, _) = authenticator
            .get(&mut store, &request, &ctx("https://example.com"))
            .unwrap();
        let results = assertion
            .client_extension_results
            .prf
            .as_ref()
            .and_then(|p| p.results.as_ref())
            .expect("prf results");
        assert_eq!(results.first.len(), 32);
        assert_eq!(results.first, prf_out.results.as_ref().unwrap().first);
    }

    #[test]
    fn the_large_blob_extension_round_trips_through_the_store() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        authenticator
            .create(
                &mut store,
                &creation_options(b"c1"),
                &ctx("https://example.com"),
            )
            .unwrap();

        let mut write = request_options(b"c2");
        write.extensions = Some(ExtensionInputs {
            large_blob: Some(LargeBlobInputs {
                support: Some("required".to_string()),
                read: None,
                write: Some(b"secret resident data".to_vec()),
            }),
            ..Default::default()
        });
        let (assertion, record) = authenticator
            .get(&mut store, &write, &ctx("https://example.com"))
            .unwrap();
        assert_eq!(
            assertion
                .client_extension_results
                .large_blob
                .as_ref()
                .and_then(|l| l.written),
            Some(true)
        );
        assert!(record.compressed_large_blob.is_some());

        let mut read = request_options(b"c3");
        read.extensions = Some(ExtensionInputs {
            large_blob: Some(LargeBlobInputs {
                support: None,
                read: Some(true),
                write: None,
            }),
            ..Default::default()
        });
        let (assertion, _) = authenticator
            .get(&mut store, &read, &ctx("https://example.com"))
            .unwrap();
        let blob = assertion
            .client_extension_results
            .large_blob
            .as_ref()
            .and_then(|l| l.blob.clone())
            .expect("blob must be returned");
        assert_eq!(blob, b"secret resident data");
    }

    #[test]
    fn a_non_resident_credential_is_not_discoverable() {
        let mut store = MemoryPasskeyStore::new();
        let authenticator = Authenticator::new();
        let mut options = creation_options(b"c1");
        options.authenticator_selection = Some(AuthenticatorSelectionCriteria {
            resident_key: Some("discouraged".to_string()),
            require_resident_key: Some(false),
            ..Default::default()
        });
        let (_, record) = authenticator
            .create(&mut store, &options, &ctx("https://example.com"))
            .unwrap();
        assert!(!record.is_resident_key);

        let err = authenticator
            .get(
                &mut store,
                &request_options(b"c2"),
                &ctx("https://example.com"),
            )
            .unwrap_err();
        assert_eq!(err.dom_exception_name(), "NotAllowedError");
    }
}
