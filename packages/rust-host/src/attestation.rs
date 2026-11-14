// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! A4 ordered passkey chain and A5 Ed25519/SHA-256 cryptographic capsule attestation.

use crate::capsule::{sha256_hex, CapsuleManifest, CAPSULE_PINNED_PAGE_SIZE};
use crate::freeze_thaw::{decrypt_aes256_gcm, encrypt_aes256_gcm, KeyLease};
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey as _, EncodePublicKey as _, LineEnding};
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use parawing_authority::webauthn::authenticator::{
    Authenticator, CeremonyContext, PasskeyStore, StoredPasskey,
};
use parawing_authority::webauthn::types::{
    AssertionCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegistrationCredential, WebAuthnError,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

const ATTESTATION_DOMAIN_PREFIX: &[u8] = b"PARAWING-A5-CAP-ATTESTATION-V1\0";
const KEY_WRAP_DOMAIN: &[u8] = b"PARAWING-A5-ECDH-WRAP-V1\0";
const DBSC_JWT_TYP: &str = "dbsc+jwt";
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PasskeyProviderKind {
    PlatformBridge,
    OwnP256Authenticator,
    CtapSecurityKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    WebAuthn {
        provider: PasskeyProviderKind,
        err: WebAuthnError,
    },
    BiometricRequired(String),
    BiometricFailed(String),
    NoProviderSucceeded(Vec<String>),
    InvalidInput(String),
    Expired {
        expires_at_ms: u64,
        now_ms: u64,
    },
    NotYetValid {
        issued_at_ms: u64,
        now_ms: u64,
    },
    NonceReplayed(String),
    CapsuleHashMismatch {
        expected: String,
        actual: String,
    },
    BaselineMismatch {
        expected: String,
        actual: String,
    },
    DigestMismatch,
    UntrustedSigner,
    InvalidSignature,
    Crypto(String),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebAuthn { provider, err } => write!(f, "{provider:?} WebAuthn error: {err}"),
            Self::BiometricRequired(m) => write!(f, "biometric gate required: {m}"),
            Self::BiometricFailed(m) => write!(f, "biometric verification failed: {m}"),
            Self::NoProviderSucceeded(reasons) => {
                write!(f, "no passkey provider succeeded: {}", reasons.join("; "))
            }
            Self::InvalidInput(m) => write!(f, "invalid attestation input: {m}"),
            Self::Expired {
                expires_at_ms,
                now_ms,
            } => write!(f, "attestation expired ({now_ms} > {expires_at_ms})"),
            Self::NotYetValid {
                issued_at_ms,
                now_ms,
            } => write!(f, "attestation not yet valid ({now_ms} < {issued_at_ms})"),
            Self::NonceReplayed(n) => write!(f, "replayed attestation nonce: {n}"),
            Self::CapsuleHashMismatch { expected, actual } => {
                write!(
                    f,
                    "capsule_hash mismatch: expected {expected}, got {actual}"
                )
            }
            Self::BaselineMismatch { expected, actual } => {
                write!(f, "baseline mismatch: expected {expected}, got {actual}")
            }
            Self::DigestMismatch => write!(f, "attestation claims SHA-256 mismatch"),
            Self::UntrustedSigner => write!(f, "attestation signer public key is not trusted"),
            Self::InvalidSignature => write!(f, "invalid Ed25519 capsule attestation signature"),
            Self::Crypto(m) => write!(f, "attestation crypto error: {m}"),
        }
    }
}

impl std::error::Error for AttestationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricDecision {
    Verified,
    Denied(String),
}

/// Host biometric/UV gate consulted before unlocking P-256 WebAuthn keys.
pub trait BiometricGate {
    fn verify_user(&self, operation: &str, rp_id: &str, origin: &str) -> BiometricDecision;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAttempt<T> {
    Completed(T),
    Unavailable(String),
    SecurityFailure(AttestationError),
}

pub trait PlatformPasskeyBridge {
    fn create(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        origin: &str,
    ) -> ProviderAttempt<RegistrationCredential>;

    fn get(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        origin: &str,
    ) -> ProviderAttempt<AssertionCredential>;
}

pub trait CtapTransport {
    fn create(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        origin: &str,
    ) -> ProviderAttempt<RegistrationCredential>;

    fn get(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        origin: &str,
    ) -> ProviderAttempt<AssertionCredential>;
}

/// Platform OS passkey bridge reporting explicit unavailability when no OS daemon exists.
pub struct UnavailablePlatformBridge;

impl PlatformPasskeyBridge for UnavailablePlatformBridge {
    fn create(
        &mut self,
        _: &PublicKeyCredentialCreationOptions,
        _: &str,
    ) -> ProviderAttempt<RegistrationCredential> {
        ProviderAttempt::Unavailable("platform passkey daemon unavailable on host".to_string())
    }

    fn get(
        &mut self,
        _: &PublicKeyCredentialRequestOptions,
        _: &str,
    ) -> ProviderAttempt<AssertionCredential> {
        ProviderAttempt::Unavailable("platform passkey daemon unavailable on host".to_string())
    }
}

/// CTAP security-key transport reporting explicit unavailability when no USB/NFC token exists.
pub struct UnavailableCtapTransport;

impl CtapTransport for UnavailableCtapTransport {
    fn create(
        &mut self,
        _: &PublicKeyCredentialCreationOptions,
        _: &str,
    ) -> ProviderAttempt<RegistrationCredential> {
        ProviderAttempt::Unavailable("no CTAP hardware authenticator attached".to_string())
    }

    fn get(
        &mut self,
        _: &PublicKeyCredentialRequestOptions,
        _: &str,
    ) -> ProviderAttempt<AssertionCredential> {
        ProviderAttempt::Unavailable("no CTAP hardware authenticator attached".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRegistrationResult {
    pub provider: PasskeyProviderKind,
    pub credential: RegistrationCredential,
    pub stored_passkey: Option<StoredPasskey>,
    pub attempted_providers: Vec<PasskeyProviderKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainAssertionResult {
    pub provider: PasskeyProviderKind,
    pub credential: AssertionCredential,
    pub updated_passkey: Option<StoredPasskey>,
    pub attempted_providers: Vec<PasskeyProviderKind>,
}

/// A4 ordered passkey resolver: Platform bridge -> Own P-256 Authenticator -> CTAP key.
pub struct OrderedPasskeyChain<'a, P: PlatformPasskeyBridge, C: CtapTransport> {
    pub platform_bridge: P,
    pub authenticator: Authenticator,
    pub passkey_store: &'a mut dyn PasskeyStore,
    pub biometric_gate: Option<&'a dyn BiometricGate>,
    pub ctap: C,
}

impl<'a, P: PlatformPasskeyBridge, C: CtapTransport> OrderedPasskeyChain<'a, P, C> {
    pub fn new(
        platform_bridge: P,
        passkey_store: &'a mut dyn PasskeyStore,
        biometric_gate: Option<&'a dyn BiometricGate>,
        ctap: C,
    ) -> Self {
        Self {
            platform_bridge,
            authenticator: Authenticator::new(),
            passkey_store,
            biometric_gate,
            ctap,
        }
    }

    pub fn create(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        ctx: &CeremonyContext<'_>,
    ) -> Result<ChainRegistrationResult, AttestationError> {
        let mut attempted = Vec::new();
        let mut unavailable = Vec::new();

        attempted.push(PasskeyProviderKind::PlatformBridge);
        match self.platform_bridge.create(options, ctx.origin) {
            ProviderAttempt::Completed(credential) => {
                return Ok(ChainRegistrationResult {
                    provider: PasskeyProviderKind::PlatformBridge,
                    credential,
                    stored_passkey: None,
                    attempted_providers: attempted,
                });
            }
            ProviderAttempt::SecurityFailure(err) => return Err(err),
            ProviderAttempt::Unavailable(reason) => unavailable.push(format!("platform: {reason}")),
        }

        attempted.push(PasskeyProviderKind::OwnP256Authenticator);
        match self.run_own_create(options, ctx) {
            Ok((credential, stored)) => {
                return Ok(ChainRegistrationResult {
                    provider: PasskeyProviderKind::OwnP256Authenticator,
                    credential,
                    stored_passkey: Some(stored),
                    attempted_providers: attempted,
                });
            }
            Err(AttestationError::WebAuthn {
                err: WebAuthnError::NotSupported(reason),
                ..
            }) => unavailable.push(format!("own-p256: {reason}")),
            Err(err) => return Err(err),
        }

        attempted.push(PasskeyProviderKind::CtapSecurityKey);
        match self.ctap.create(options, ctx.origin) {
            ProviderAttempt::Completed(credential) => Ok(ChainRegistrationResult {
                provider: PasskeyProviderKind::CtapSecurityKey,
                credential,
                stored_passkey: None,
                attempted_providers: attempted,
            }),
            ProviderAttempt::SecurityFailure(err) => Err(err),
            ProviderAttempt::Unavailable(reason) => {
                unavailable.push(format!("ctap: {reason}"));
                Err(AttestationError::NoProviderSucceeded(unavailable))
            }
        }
    }

    pub fn get(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        ctx: &CeremonyContext<'_>,
    ) -> Result<ChainAssertionResult, AttestationError> {
        let mut attempted = Vec::new();
        let mut unavailable = Vec::new();

        attempted.push(PasskeyProviderKind::PlatformBridge);
        match self.platform_bridge.get(options, ctx.origin) {
            ProviderAttempt::Completed(credential) => {
                return Ok(ChainAssertionResult {
                    provider: PasskeyProviderKind::PlatformBridge,
                    credential,
                    updated_passkey: None,
                    attempted_providers: attempted,
                });
            }
            ProviderAttempt::SecurityFailure(err) => return Err(err),
            ProviderAttempt::Unavailable(reason) => unavailable.push(format!("platform: {reason}")),
        }

        attempted.push(PasskeyProviderKind::OwnP256Authenticator);
        match self.run_own_get(options, ctx) {
            Ok((credential, updated)) => {
                return Ok(ChainAssertionResult {
                    provider: PasskeyProviderKind::OwnP256Authenticator,
                    credential,
                    updated_passkey: Some(updated),
                    attempted_providers: attempted,
                });
            }
            Err(AttestationError::WebAuthn {
                err: WebAuthnError::NotAllowed(reason),
                ..
            }) if is_no_matching_credential(&reason) => {
                unavailable.push(format!("own-p256: {reason}"));
            }
            Err(err) => return Err(err),
        }

        attempted.push(PasskeyProviderKind::CtapSecurityKey);
        match self.ctap.get(options, ctx.origin) {
            ProviderAttempt::Completed(credential) => Ok(ChainAssertionResult {
                provider: PasskeyProviderKind::CtapSecurityKey,
                credential,
                updated_passkey: None,
                attempted_providers: attempted,
            }),
            ProviderAttempt::SecurityFailure(err) => Err(err),
            ProviderAttempt::Unavailable(reason) => {
                unavailable.push(format!("ctap: {reason}"));
                Err(AttestationError::NoProviderSucceeded(unavailable))
            }
        }
    }

    fn run_own_create(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        ctx: &CeremonyContext<'_>,
    ) -> Result<(RegistrationCredential, StoredPasskey), AttestationError> {
        let uv_pref = options
            .authenticator_selection
            .as_ref()
            .and_then(|s| s.user_verification.as_deref());
        enforce_biometric_if_needed(self.biometric_gate, uv_pref, "create", &options.rp.id, ctx)?;
        self.authenticator
            .create(self.passkey_store, options, ctx)
            .map_err(|err| AttestationError::WebAuthn {
                provider: PasskeyProviderKind::OwnP256Authenticator,
                err,
            })
    }

    fn run_own_get(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        ctx: &CeremonyContext<'_>,
    ) -> Result<(AssertionCredential, StoredPasskey), AttestationError> {
        let rp = options.rp_id.as_deref().unwrap_or("");
        enforce_biometric_if_needed(
            self.biometric_gate,
            options.user_verification.as_deref(),
            "get",
            rp,
            ctx,
        )?;
        self.authenticator
            .get(self.passkey_store, options, ctx)
            .map_err(|err| AttestationError::WebAuthn {
                provider: PasskeyProviderKind::OwnP256Authenticator,
                err,
            })
    }
}

fn is_no_matching_credential(reason: &str) -> bool {
    reason.contains("No matching passkey") || reason.contains("not found")
}

fn enforce_biometric_if_needed(
    gate: Option<&dyn BiometricGate>,
    _uv: Option<&str>,
    operation: &str,
    rp_id: &str,
    ctx: &CeremonyContext<'_>,
) -> Result<(), AttestationError> {
    let Some(gate) = gate else {
        return Err(AttestationError::BiometricRequired(
            "own P-256 authenticator requires a mandatory biometric gate".to_string(),
        ));
    };
    match gate.verify_user(operation, rp_id, ctx.origin) {
        BiometricDecision::Verified => Ok(()),
        BiometricDecision::Denied(reason) => Err(AttestationError::BiometricFailed(reason)),
    }
}

/// Canonical A5 capsule attestation claims signed by an attested runtime enclave/host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleAttestationClaims {
    pub capsule_hash: String,
    pub rust_target: String,
    pub baseline_id: String,
    pub page_size: u32,
    pub ephemeral_p256_pubkey_spki_b64: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCapsuleAttestation {
    pub claims: CapsuleAttestationClaims,
    pub claims_sha256_hex: String,
    pub signer_pubkey_spki_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedCapsuleAttestation {
    pub claims: CapsuleAttestationClaims,
    pub claims_sha256_hex: String,
    pub recipient_p256_pubkey_spki: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKeyLeaseRelease {
    pub lease_id: String,
    pub session_id: String,
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub authority_ephemeral_p256_spki_b64: String,
    pub wrap_salt_nonce_b64: String,
    pub ciphertext_b64: String,
    pub tag_b64: String,
    pub iv_b64: String,
    pub claims_sha256_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbscSessionCredential {
    pub dbsc_session_id: String,
    pub origin: String,
    pub challenge: String,
    pub device_pubkey_spki_b64: String,
    pub jwt_proof: String,
    pub claims_sha256_hex: String,
}

pub fn canonical_claims_bytes(
    claims: &CapsuleAttestationClaims,
) -> Result<Vec<u8>, AttestationError> {
    serde_json::to_vec(claims).map_err(|e| AttestationError::InvalidInput(e.to_string()))
}

pub fn attestation_signing_input(
    claims: &CapsuleAttestationClaims,
) -> Result<Vec<u8>, AttestationError> {
    let canonical = canonical_claims_bytes(claims)?;
    let mut input = Vec::with_capacity(ATTESTATION_DOMAIN_PREFIX.len() + canonical.len());
    input.extend_from_slice(ATTESTATION_DOMAIN_PREFIX);
    input.extend_from_slice(&canonical);
    Ok(input)
}

pub fn ed25519_raw_to_spki(raw_32: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if raw_32.len() != 32 {
        return Err(AttestationError::InvalidInput(
            "raw Ed25519 public key must be 32 bytes".to_string(),
        ));
    }
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(raw_32);
    Ok(spki)
}

pub fn ed25519_spki_to_raw(spki: &[u8]) -> Result<[u8; 32], AttestationError> {
    if spki.len() != 44 || spki[..12] != ED25519_SPKI_PREFIX {
        return Err(AttestationError::InvalidInput(
            "expected 44-byte Ed25519 SPKI DER public key".to_string(),
        ));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&spki[12..]);
    Ok(raw)
}

pub fn generate_p256_secret_key() -> Result<P256SecretKey, AttestationError> {
    let mut seed = [0u8; 32];
    for _ in 0..8 {
        getrandom::fill(&mut seed).map_err(|e| AttestationError::Crypto(format!("rng: {e}")))?;
        if let Ok(sk) = P256SecretKey::from_slice(&seed) {
            return Ok(sk);
        }
    }
    Err(AttestationError::Crypto(
        "failed to generate non-zero P-256 scalar".to_string(),
    ))
}

pub fn generate_ephemeral_p256_keypair() -> Result<(P256SecretKey, String), AttestationError> {
    let sk = generate_p256_secret_key()?;
    let spki = sk
        .public_key()
        .to_public_key_der()
        .map_err(|e| AttestationError::Crypto(format!("ECDH P-256 spki: {e}")))?;
    Ok((sk, BASE64_STANDARD.encode(spki.as_bytes())))
}

pub fn generate_p256_signing_key() -> Result<SigningKey, AttestationError> {
    Ok(SigningKey::from(generate_p256_secret_key()?))
}

pub fn sign_capsule_attestation(
    claims: CapsuleAttestationClaims,
    ed25519_keypair: &Ed25519KeyPair,
) -> Result<SignedCapsuleAttestation, AttestationError> {
    let canonical = canonical_claims_bytes(&claims)?;
    let claims_sha256_hex = sha256_hex(&canonical);
    let input = attestation_signing_input(&claims)?;
    let sig = ed25519_keypair.sign(&input);
    let spki = ed25519_raw_to_spki(ed25519_keypair.public_key().as_ref())?;
    Ok(SignedCapsuleAttestation {
        claims,
        claims_sha256_hex,
        signer_pubkey_spki_b64: BASE64_STANDARD.encode(&spki),
        signature_b64: BASE64_STANDARD.encode(sig.as_ref()),
    })
}

pub fn unwrap_leased_aes_key(
    recipient_secret: &P256SecretKey,
    release: &WrappedKeyLeaseRelease,
) -> Result<[u8; 32], AttestationError> {
    let auth_spki = BASE64_STANDARD
        .decode(&release.authority_ephemeral_p256_spki_b64)
        .map_err(|e| AttestationError::InvalidInput(format!("authority P-256 SPKI b64: {e}")))?;
    let peer_pk = P256PublicKey::from_public_key_der(&auth_spki)
        .map_err(|e| AttestationError::InvalidInput(format!("authority P-256 SPKI DER: {e}")))?;
    let shared = diffie_hellman(recipient_secret.to_nonzero_scalar(), peer_pk.as_affine());
    let kek = derive_wrap_kek(
        shared.raw_secret_bytes().as_slice(),
        &release.claims_sha256_hex,
    );

    let ct = BASE64_STANDARD
        .decode(&release.ciphertext_b64)
        .map_err(|e| AttestationError::InvalidInput(format!("ciphertext b64: {e}")))?;
    let tag = BASE64_STANDARD
        .decode(&release.tag_b64)
        .map_err(|e| AttestationError::InvalidInput(format!("tag b64: {e}")))?;
    if tag.len() != 16 {
        return Err(AttestationError::InvalidInput(
            "AES-GCM tag must be 16 bytes".to_string(),
        ));
    }
    let mut combined = Vec::with_capacity(ct.len() + 16);
    combined.extend_from_slice(&ct);
    combined.extend_from_slice(&tag);
    let plain = decrypt_aes256_gcm(
        &kek,
        release.claims_sha256_hex.as_bytes(),
        &release.iv_b64,
        &BASE64_STANDARD.encode(&combined),
    )
    .map_err(|e| AttestationError::Crypto(format!("AES-GCM unwrap failed: {e}")))?;
    if plain.len() != 32 {
        return Err(AttestationError::Crypto(
            "unwrapped lease key length != 32".to_string(),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plain);
    Ok(key)
}

fn derive_wrap_kek(shared_secret: &[u8], claims_sha256_hex: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_WRAP_DOMAIN);
    hasher.update(shared_secret);
    hasher.update(claims_sha256_hex.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Authority verifier gating session key leases and DBSC credentials on A5 capsule attestation.
pub struct CapsuleAttestationAuthority {
    expected_capsule_hash: String,
    expected_rust_target: String,
    expected_baseline_id: String,
    trusted_signers: HashSet<Vec<u8>>,
    seen_nonces: HashSet<String>,
    dbsc_signing_key: SigningKey,
}

impl CapsuleAttestationAuthority {
    pub fn from_manifest(
        manifest: &CapsuleManifest,
        trusted_ed25519_pubkeys: Vec<Vec<u8>>,
    ) -> Result<Self, AttestationError> {
        let mut normalized = HashSet::with_capacity(trusted_ed25519_pubkeys.len());
        for key in trusted_ed25519_pubkeys {
            if key.len() == 32 {
                normalized.insert(ed25519_raw_to_spki(&key)?);
            } else {
                let _ = ed25519_spki_to_raw(&key)?;
                normalized.insert(key);
            }
        }
        let dbsc_signing_key = generate_p256_signing_key()?;
        Ok(Self {
            expected_capsule_hash: manifest.capsule_hash_hex(),
            expected_rust_target: manifest.rust_target.clone(),
            expected_baseline_id: manifest.baseline.as_str().to_string(),
            trusted_signers: normalized,
            seen_nonces: HashSet::new(),
            dbsc_signing_key,
        })
    }

    pub fn from_manifest_spki_b64(
        manifest: &CapsuleManifest,
        trusted_spki_b64s: &[String],
    ) -> Result<Self, AttestationError> {
        let mut keys = Vec::with_capacity(trusted_spki_b64s.len());
        for b64 in trusted_spki_b64s {
            let der = BASE64_STANDARD
                .decode(b64)
                .map_err(|e| AttestationError::InvalidInput(format!("trusted spki b64: {e}")))?;
            keys.push(der);
        }
        Self::from_manifest(manifest, keys)
    }

    pub fn dbsc_public_key_spki_b64(&self) -> Result<String, AttestationError> {
        let vk = VerifyingKey::from(&self.dbsc_signing_key);
        let spki = vk
            .to_public_key_der()
            .map_err(|e| AttestationError::Crypto(format!("dbsc spki: {e}")))?;
        Ok(BASE64_STANDARD.encode(spki.as_bytes()))
    }

    pub fn dbsc_public_key_pem(&self) -> Result<String, AttestationError> {
        let vk = VerifyingKey::from(&self.dbsc_signing_key);
        vk.to_public_key_pem(LineEnding::LF)
            .map_err(|e| AttestationError::Crypto(format!("dbsc pem: {e}")))
    }

    pub fn verify_attestation(
        &mut self,
        report: &SignedCapsuleAttestation,
        now_ms: u64,
    ) -> Result<VerifiedCapsuleAttestation, AttestationError> {
        validate_attestation_fields(&report.claims, now_ms)?;
        if self.seen_nonces.contains(&report.claims.nonce) {
            return Err(AttestationError::NonceReplayed(report.claims.nonce.clone()));
        }
        self.check_manifest_match(&report.claims)?;
        let canonical = canonical_claims_bytes(&report.claims)?;
        if sha256_hex(&canonical) != report.claims_sha256_hex {
            return Err(AttestationError::DigestMismatch);
        }
        verify_ed25519_report(&self.trusted_signers, report)?;
        let recipient_p256_pubkey_spki = BASE64_STANDARD
            .decode(&report.claims.ephemeral_p256_pubkey_spki_b64)
            .map_err(|e| AttestationError::InvalidInput(format!("ephemeral key b64: {e}")))?;
        let _ = P256PublicKey::from_public_key_der(&recipient_p256_pubkey_spki).map_err(|e| {
            AttestationError::InvalidInput(format!("ephemeral P-256 SPKI DER: {e}"))
        })?;

        self.seen_nonces.insert(report.claims.nonce.clone());
        Ok(VerifiedCapsuleAttestation {
            claims: report.claims.clone(),
            claims_sha256_hex: report.claims_sha256_hex.clone(),
            recipient_p256_pubkey_spki,
        })
    }

    pub fn release_wrapped_key_lease(
        &mut self,
        report: &SignedCapsuleAttestation,
        lease: &KeyLease,
        now_ms: u64,
    ) -> Result<WrappedKeyLeaseRelease, AttestationError> {
        let verified = self.verify_attestation(report, now_ms)?;
        lease
            .validate(now_ms, &lease.session_id)
            .map_err(|_| AttestationError::Expired {
                expires_at_ms: lease.expires_at_ms,
                now_ms,
            })?;
        let (auth_sk, auth_spki_b64) = generate_ephemeral_p256_keypair()?;
        let peer_pk = P256PublicKey::from_public_key_der(&verified.recipient_p256_pubkey_spki)
            .map_err(|e| AttestationError::InvalidInput(format!("recipient SPKI DER: {e}")))?;
        let shared = diffie_hellman(auth_sk.to_nonzero_scalar(), peer_pk.as_affine());
        let kek = derive_wrap_kek(
            shared.raw_secret_bytes().as_slice(),
            &verified.claims_sha256_hex,
        );

        let (iv_b64, combined_b64) = encrypt_aes256_gcm(
            &kek,
            verified.claims_sha256_hex.as_bytes(),
            &lease.aes256_key,
        )
        .map_err(|e| AttestationError::Crypto(format!("AES-GCM wrap: {e}")))?;
        let combined = BASE64_STANDARD
            .decode(&combined_b64)
            .map_err(|e| AttestationError::Crypto(format!("wrap decode: {e}")))?;
        if combined.len() < 16 {
            return Err(AttestationError::Crypto(
                "wrapped AES-GCM output shorter than tag".to_string(),
            ));
        }
        let split = combined.len() - 16;
        let ciphertext_b64 = BASE64_STANDARD.encode(&combined[..split]);
        let tag_b64 = BASE64_STANDARD.encode(&combined[split..]);

        Ok(WrappedKeyLeaseRelease {
            lease_id: lease.lease_id.clone(),
            session_id: lease.session_id.clone(),
            epoch: lease.epoch,
            issued_at_ms: lease.issued_at_ms,
            expires_at_ms: lease.expires_at_ms,
            authority_ephemeral_p256_spki_b64: auth_spki_b64,
            wrap_salt_nonce_b64: iv_b64.clone(),
            ciphertext_b64,
            tag_b64,
            iv_b64,
            claims_sha256_hex: verified.claims_sha256_hex,
        })
    }

    pub fn release_dbsc_credential(
        &mut self,
        report: &SignedCapsuleAttestation,
        dbsc_session_id: &str,
        origin: &str,
        challenge: &str,
        now_ms: u64,
    ) -> Result<DbscSessionCredential, AttestationError> {
        let verified = self.verify_attestation(report, now_ms)?;
        let header = serde_json::json!({ "alg": "ES256", "typ": DBSC_JWT_TYP });
        let payload = serde_json::json!({
            "aud": origin,
            "jti": challenge,
            "sub": dbsc_session_id,
            "iat": now_ms / 1000,
            "capsuleClaimsSha256": verified.claims_sha256_hex,
            "capsuleHash": verified.claims.capsule_hash,
        });
        let h_b64 = B64URL.encode(
            serde_json::to_vec(&header).map_err(|e| AttestationError::Crypto(e.to_string()))?,
        );
        let p_b64 = B64URL.encode(
            serde_json::to_vec(&payload).map_err(|e| AttestationError::Crypto(e.to_string()))?,
        );
        let signing_input = format!("{h_b64}.{p_b64}");
        let sig: P256Signature = self.dbsc_signing_key.sign(signing_input.as_bytes());
        let jwt_proof = format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()));
        Ok(DbscSessionCredential {
            dbsc_session_id: dbsc_session_id.to_string(),
            origin: origin.to_string(),
            challenge: challenge.to_string(),
            device_pubkey_spki_b64: self.dbsc_public_key_spki_b64()?,
            jwt_proof,
            claims_sha256_hex: verified.claims_sha256_hex,
        })
    }

    fn check_manifest_match(
        &self,
        claims: &CapsuleAttestationClaims,
    ) -> Result<(), AttestationError> {
        if claims.capsule_hash != self.expected_capsule_hash {
            return Err(AttestationError::CapsuleHashMismatch {
                expected: self.expected_capsule_hash.clone(),
                actual: claims.capsule_hash.clone(),
            });
        }
        if claims.rust_target != self.expected_rust_target
            || claims.baseline_id != self.expected_baseline_id
        {
            return Err(AttestationError::BaselineMismatch {
                expected: format!(
                    "{}:{}",
                    self.expected_rust_target, self.expected_baseline_id
                ),
                actual: format!("{}:{}", claims.rust_target, claims.baseline_id),
            });
        }
        if claims.page_size != CAPSULE_PINNED_PAGE_SIZE {
            return Err(AttestationError::BaselineMismatch {
                expected: format!("page_size={CAPSULE_PINNED_PAGE_SIZE}"),
                actual: format!("page_size={}", claims.page_size),
            });
        }
        Ok(())
    }
}

pub fn verify_dbsc_jwt_proof(cred: &DbscSessionCredential) -> Result<(), AttestationError> {
    let parts: Vec<&str> = cred.jwt_proof.split('.').collect();
    if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
        return Err(AttestationError::InvalidInput(
            "DBSC proof must have 3 non-empty JWT parts".to_string(),
        ));
    }
    let header_bytes = B64URL
        .decode(parts[0])
        .map_err(|e| AttestationError::InvalidInput(format!("dbsc hdr b64url: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| AttestationError::InvalidInput(format!("dbsc hdr json: {e}")))?;
    if header.get("alg").and_then(serde_json::Value::as_str) != Some("ES256")
        || header.get("typ").and_then(serde_json::Value::as_str) != Some(DBSC_JWT_TYP)
    {
        return Err(AttestationError::InvalidInput(
            "DBSC JWT header requires alg=ES256 and typ=dbsc+jwt".to_string(),
        ));
    }

    let claims_bytes = B64URL
        .decode(parts[1])
        .map_err(|e| AttestationError::InvalidInput(format!("dbsc payload b64url: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|e| AttestationError::InvalidInput(format!("dbsc payload json: {e}")))?;
    validate_dbsc_jwt_claims(&claims, cred)?;

    let spki = BASE64_STANDARD
        .decode(&cred.device_pubkey_spki_b64)
        .map_err(|e| AttestationError::InvalidInput(format!("dbsc spki b64: {e}")))?;
    let vk = VerifyingKey::from_public_key_der(&spki)
        .map_err(|e| AttestationError::Crypto(format!("parse dbsc vk: {e}")))?;
    let sig_bytes = B64URL
        .decode(parts[2])
        .map_err(|e| AttestationError::InvalidInput(format!("dbsc sig b64url: {e}")))?;
    let sig =
        P256Signature::from_slice(&sig_bytes).map_err(|_| AttestationError::InvalidSignature)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| AttestationError::InvalidSignature)
}

fn validate_dbsc_jwt_claims(
    claims: &serde_json::Value,
    cred: &DbscSessionCredential,
) -> Result<(), AttestationError> {
    if claims.get("aud").and_then(serde_json::Value::as_str) != Some(cred.origin.as_str()) {
        return Err(AttestationError::InvalidInput(
            "DBSC JWT aud claim mismatch".to_string(),
        ));
    }
    if claims.get("jti").and_then(serde_json::Value::as_str) != Some(cred.challenge.as_str()) {
        return Err(AttestationError::InvalidInput(
            "DBSC JWT jti claim mismatch".to_string(),
        ));
    }
    if claims.get("sub").and_then(serde_json::Value::as_str) != Some(cred.dbsc_session_id.as_str())
    {
        return Err(AttestationError::InvalidInput(
            "DBSC JWT sub claim mismatch".to_string(),
        ));
    }
    if claims
        .get("capsuleClaimsSha256")
        .and_then(serde_json::Value::as_str)
        != Some(cred.claims_sha256_hex.as_str())
    {
        return Err(AttestationError::DigestMismatch);
    }
    if claims
        .get("iat")
        .and_then(serde_json::Value::as_u64)
        .is_none()
        || claims
            .get("capsuleHash")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|h| h.len() != 64)
    {
        return Err(AttestationError::InvalidInput(
            "DBSC JWT missing valid iat or capsuleHash claim".to_string(),
        ));
    }
    Ok(())
}

fn validate_attestation_fields(
    claims: &CapsuleAttestationClaims,
    now_ms: u64,
) -> Result<(), AttestationError> {
    if claims.nonce.trim().is_empty() || claims.expires_at_ms <= claims.issued_at_ms {
        return Err(AttestationError::InvalidInput(
            "attestation requires non-empty nonce and expires_at_ms > issued_at_ms".to_string(),
        ));
    }
    if now_ms < claims.issued_at_ms {
        return Err(AttestationError::NotYetValid {
            issued_at_ms: claims.issued_at_ms,
            now_ms,
        });
    }
    if now_ms > claims.expires_at_ms {
        return Err(AttestationError::Expired {
            expires_at_ms: claims.expires_at_ms,
            now_ms,
        });
    }
    Ok(())
}

fn verify_ed25519_report(
    trusted_signers_spki: &HashSet<Vec<u8>>,
    report: &SignedCapsuleAttestation,
) -> Result<(), AttestationError> {
    let pub_spki = BASE64_STANDARD
        .decode(&report.signer_pubkey_spki_b64)
        .map_err(|e| AttestationError::InvalidInput(format!("signer spki b64: {e}")))?;
    if !trusted_signers_spki.contains(&pub_spki) {
        return Err(AttestationError::UntrustedSigner);
    }
    let raw_key = ed25519_spki_to_raw(&pub_spki)?;
    let sig_bytes = BASE64_STANDARD
        .decode(&report.signature_b64)
        .map_err(|e| AttestationError::InvalidInput(format!("signature b64: {e}")))?;
    let input = attestation_signing_input(&report.claims)?;
    UnparsedPublicKey::new(&ED25519, &raw_key)
        .verify(&input, &sig_bytes)
        .map_err(|_| AttestationError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::CpuBaseline;
    use crate::freeze_thaw::generate_test_ed25519_keypair;
    use parawing_authority::webauthn::authenticator::MemoryPasskeyStore;
    use parawing_authority::webauthn::b64::b64url_decode;
    use parawing_authority::webauthn::cose::verify_es256_der;
    use parawing_authority::webauthn::types::{
        AuthenticatorSelectionCriteria, PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
    };
    use sha2::Sha256;

    struct FixedGate(BiometricDecision);

    impl BiometricGate for FixedGate {
        fn verify_user(&self, _: &str, _: &str, _: &str) -> BiometricDecision {
            self.0.clone()
        }
    }

    struct StubPlatformBridge {
        respond: bool,
    }

    impl PlatformPasskeyBridge for StubPlatformBridge {
        fn create(
            &mut self,
            _: &PublicKeyCredentialCreationOptions,
            _: &str,
        ) -> ProviderAttempt<RegistrationCredential> {
            if !self.respond {
                return ProviderAttempt::Unavailable("platform not signed in".to_string());
            }
            ProviderAttempt::SecurityFailure(AttestationError::BiometricFailed(
                "platform OS TouchID cancelled".to_string(),
            ))
        }

        fn get(
            &mut self,
            _: &PublicKeyCredentialRequestOptions,
            _: &str,
        ) -> ProviderAttempt<AssertionCredential> {
            ProviderAttempt::Unavailable("platform not present".to_string())
        }
    }

    struct TrackingCtap {
        called: bool,
    }

    impl CtapTransport for TrackingCtap {
        fn create(
            &mut self,
            _: &PublicKeyCredentialCreationOptions,
            _: &str,
        ) -> ProviderAttempt<RegistrationCredential> {
            self.called = true;
            ProviderAttempt::Unavailable("no token inserted".to_string())
        }

        fn get(
            &mut self,
            _: &PublicKeyCredentialRequestOptions,
            _: &str,
        ) -> ProviderAttempt<AssertionCredential> {
            self.called = true;
            ProviderAttempt::Unavailable("no token inserted".to_string())
        }
    }

    fn creation_opts(rp_id: &str, uv: &str) -> PublicKeyCredentialCreationOptions {
        PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: rp_id.to_string(),
                name: Some("Example".to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"user-1".to_vec(),
                name: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
            },
            challenge: vec![11; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                alg: -7,
                kind: "public-key".to_string(),
            }],
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                user_verification: Some(uv.to_string()),
                resident_key: Some("required".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a4_chain_falls_back_from_unavailable_platform_to_own_p256_and_verifies_sig() {
        let mut store = MemoryPasskeyStore::new();
        let gate = FixedGate(BiometricDecision::Verified);
        let ctap = TrackingCtap { called: false };
        let mut chain = OrderedPasskeyChain::new(
            StubPlatformBridge { respond: false },
            &mut store,
            Some(&gate),
            ctap,
        );
        let ctx = CeremonyContext::same_origin("https://login.example.com", "2026-11-14T00:00:00Z");
        let reg = chain
            .create(&creation_opts("example.com", "required"), &ctx)
            .expect("create via own P-256");
        assert_eq!(reg.provider, PasskeyProviderKind::OwnP256Authenticator);
        assert_eq!(
            reg.attempted_providers,
            vec![
                PasskeyProviderKind::PlatformBridge,
                PasskeyProviderKind::OwnP256Authenticator,
            ]
        );
        assert!(!chain.ctap.called);

        let stored = reg.stored_passkey.expect("stored passkey");
        let get_opts = PublicKeyCredentialRequestOptions {
            challenge: vec![22; 32],
            rp_id: Some("example.com".to_string()),
            user_verification: Some("required".to_string()),
            ..Default::default()
        };
        let assertion = chain.get(&get_opts, &ctx).expect("get assertion");
        assert_eq!(
            assertion.provider,
            PasskeyProviderKind::OwnP256Authenticator
        );

        let auth_data = b64url_decode(&assertion.credential.response.authenticator_data).unwrap();
        let client_data = b64url_decode(&assertion.credential.response.client_data_json).unwrap();
        let sig = b64url_decode(&assertion.credential.response.signature).unwrap();
        let mut signed = auth_data;
        signed.extend_from_slice(&Sha256::digest(&client_data));
        verify_es256_der(&stored.public_key_pem, &signed, &sig).expect("valid ES256 sig");
    }

    #[test]
    fn a4_chain_never_falls_through_on_biometric_or_rpid_security_errors() {
        let mut store = MemoryPasskeyStore::new();
        let deny_gate = FixedGate(BiometricDecision::Denied("TouchID rejected".to_string()));
        let mut chain = OrderedPasskeyChain::new(
            StubPlatformBridge { respond: false },
            &mut store,
            Some(&deny_gate),
            TrackingCtap { called: false },
        );
        let ctx = CeremonyContext::same_origin("https://login.example.com", "2026-11-14T00:00:00Z");
        let bio_err = chain
            .create(&creation_opts("example.com", "required"), &ctx)
            .unwrap_err();
        assert!(matches!(bio_err, AttestationError::BiometricFailed(_)));
        assert!(!chain.ctap.called);

        let allow_gate = FixedGate(BiometricDecision::Verified);
        let mut chain2 = OrderedPasskeyChain::new(
            StubPlatformBridge { respond: false },
            &mut store,
            Some(&allow_gate),
            TrackingCtap { called: false },
        );
        let rp_err = chain2
            .create(&creation_opts("evil.org", "required"), &ctx)
            .unwrap_err();
        assert!(matches!(
            rp_err,
            AttestationError::WebAuthn {
                err: WebAuthnError::Security(_),
                ..
            }
        ));
        assert!(!chain2.ctap.called);

        let mut no_gate_chain = OrderedPasskeyChain::new(
            StubPlatformBridge { respond: false },
            &mut store,
            None,
            TrackingCtap { called: false },
        );
        let no_gate_err = no_gate_chain
            .create(&creation_opts("example.com", "discouraged"), &ctx)
            .unwrap_err();
        assert!(matches!(
            no_gate_err,
            AttestationError::BiometricRequired(_)
        ));
        assert!(!no_gate_chain.ctap.called);

        let mut discouraged_deny = OrderedPasskeyChain::new(
            StubPlatformBridge { respond: false },
            &mut store,
            Some(&deny_gate),
            TrackingCtap { called: false },
        );
        let deny_disc_err = discouraged_deny
            .create(&creation_opts("example.com", "discouraged"), &ctx)
            .unwrap_err();
        assert!(matches!(
            deny_disc_err,
            AttestationError::BiometricFailed(_)
        ));
    }

    #[test]
    fn a5_attestation_gates_wrapped_key_lease_and_dbsc_against_tamper_expiry_and_replay() {
        let manifest = CapsuleManifest::new(
            CpuBaseline::Aarch64Armv8Baseline,
            "sha256:host-v1",
            "sha256:v8-v1",
            true,
        );
        let capsule_hash = manifest.capsule_hash_hex();
        let signer = generate_test_ed25519_keypair();
        let (eph_sk, eph_p256_spki_b64) = generate_ephemeral_p256_keypair().unwrap();

        let claims = CapsuleAttestationClaims {
            capsule_hash,
            rust_target: manifest.rust_target.clone(),
            baseline_id: manifest.baseline.as_str().to_string(),
            page_size: CAPSULE_PINNED_PAGE_SIZE,
            ephemeral_p256_pubkey_spki_b64: eph_p256_spki_b64,
            nonce: "att-nonce-1".to_string(),
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
        };
        let signed = sign_capsule_attestation(claims.clone(), &signer).unwrap();
        assert_eq!(
            BASE64_STANDARD
                .decode(&signed.signer_pubkey_spki_b64)
                .unwrap()
                .len(),
            44
        );
        let mut authority = CapsuleAttestationAuthority::from_manifest(
            &manifest,
            vec![signer.public_key().as_ref().to_vec()],
        )
        .unwrap();

        let raw_key = [0x5Au8; 32];
        let lease = KeyLease {
            lease_id: "lease-a5".to_string(),
            session_id: "s1".to_string(),
            epoch: 1,
            issued_at_ms: 1_000,
            expires_at_ms: 50_000,
            revoked: false,
            aes256_key: raw_key,
        };
        let wrapped = authority
            .release_wrapped_key_lease(&signed, &lease, 2_000)
            .expect("valid attestation releases wrapped key");
        assert_eq!(unwrap_leased_aes_key(&eph_sk, &wrapped).unwrap(), raw_key);

        let replay = authority
            .release_dbsc_credential(&signed, "dbsc-1", "https://app.example", "chal-1", 2_000)
            .unwrap_err();
        assert!(matches!(replay, AttestationError::NonceReplayed(_)));

        let claims2 = CapsuleAttestationClaims {
            nonce: "att-nonce-2".to_string(),
            ..claims.clone()
        };
        let signed2 = sign_capsule_attestation(claims2, &signer).unwrap();
        let dbsc = authority
            .release_dbsc_credential(&signed2, "dbsc-1", "https://app.example", "chal-1", 2_000)
            .expect("valid attestation releases DBSC");
        verify_dbsc_jwt_proof(&dbsc).expect("valid ES256 DBSC proof");

        let mut bad_aud = dbsc.clone();
        bad_aud.origin = "https://evil.example".to_string();
        assert!(verify_dbsc_jwt_proof(&bad_aud).is_err());

        let mut bad_claims_sha = dbsc.clone();
        bad_claims_sha.claims_sha256_hex = "f".repeat(64);
        assert!(verify_dbsc_jwt_proof(&bad_claims_sha).is_err());

        let drifted = CapsuleAttestationClaims {
            capsule_hash: "0".repeat(64),
            nonce: "att-nonce-3".to_string(),
            ..claims.clone()
        };
        let drifted_signed = sign_capsule_attestation(drifted, &signer).unwrap();
        assert!(matches!(
            authority
                .verify_attestation(&drifted_signed, 2_000)
                .unwrap_err(),
            AttestationError::CapsuleHashMismatch { .. }
        ));

        let expired_claims = CapsuleAttestationClaims {
            nonce: "att-nonce-4".to_string(),
            ..claims
        };
        let expired_signed = sign_capsule_attestation(expired_claims, &signer).unwrap();
        assert!(matches!(
            authority
                .verify_attestation(&expired_signed, 20_000)
                .unwrap_err(),
            AttestationError::Expired { .. }
        ));
    }
}
