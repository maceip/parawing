// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! WebAuthn Level 3 section 6.1 `authenticatorData` and `attestationObject` encoding.

use sha2::{Digest, Sha256};

use crate::webauthn::cbor::Cbor;

/// Bit 0: User Present (`UP`).
pub const FLAG_UP: u8 = 0x01;
/// Bit 2: User Verified (`UV`).
pub const FLAG_UV: u8 = 0x04;
/// Bit 3: Backup Eligible (`BE`).
pub const FLAG_BE: u8 = 0x08;
/// Bit 4: Backup State (`BS`).
pub const FLAG_BS: u8 = 0x10;
/// Bit 6: Attested credential data included (`AT`).
pub const FLAG_AT: u8 = 0x40;
/// Bit 7: Extension data included (`ED`).
pub const FLAG_ED: u8 = 0x80;

/// Attested credential data appended to `authenticatorData` during registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedCredentialData {
    /// 16-byte Authenticator Attestation GUID.
    pub aaguid: [u8; 16],
    /// Raw credential ID bytes.
    pub credential_id: Vec<u8>,
    /// CBOR-encoded `COSE_Key` public key bytes.
    pub credential_public_key: Vec<u8>,
}

impl AttestedCredentialData {
    /// Constructs attested credential data from its AAGUID, ID, and COSE public key.
    pub fn new(aaguid: [u8; 16], credential_id: Vec<u8>, credential_public_key: Vec<u8>) -> Self {
        Self {
            aaguid,
            credential_id,
            credential_public_key,
        }
    }
}

/// Complete WebAuthn `authenticatorData` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 digest of the effective relying party identifier.
    pub rp_id_hash: [u8; 32],
    /// Authenticator bit flags (`FLAG_*`).
    pub flags: u8,
    /// Big-endian 32-bit signature counter.
    pub sign_count: u32,
    /// Optional attested credential data (serialized when `FLAG_AT` is set).
    pub attested_credential_data: Option<AttestedCredentialData>,
    /// Optional CBOR-encoded extension map (serialized when `FLAG_ED` is set).
    pub extensions: Option<Vec<u8>>,
}

impl AuthenticatorData {
    /// Computes the 32-byte `rpIdHash` (`SHA-256(rp_id)`).
    pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
        let digest = Sha256::digest(rp_id.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Serializes `authenticatorData` to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(37 + 64);
        out.extend_from_slice(&self.rp_id_hash);
        out.push(self.flags);
        out.extend_from_slice(&self.sign_count.to_be_bytes());
        if self.flags & FLAG_AT != 0 {
            if let Some(attested) = &self.attested_credential_data {
                out.extend_from_slice(&attested.aaguid);
                let len = attested.credential_id.len() as u16;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&attested.credential_id);
                out.extend_from_slice(&attested.credential_public_key);
            }
        }
        if self.flags & FLAG_ED != 0 {
            if let Some(extensions) = &self.extensions {
                out.extend_from_slice(extensions);
            }
        }
        out
    }

    /// Wraps this `authenticatorData` in a self-attested (`fmt: "none"`) CBOR object.
    pub fn attestation_object(&self) -> Vec<u8> {
        let auth_data = self.encode();
        Cbor::Map(vec![
            (Cbor::text("fmt"), Cbor::text("none")),
            (Cbor::text("attStmt"), Cbor::Map(Vec::new())),
            (Cbor::text("authData"), Cbor::Bytes(auth_data)),
        ])
        .encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_fixed_prefix() {
        let data = AuthenticatorData {
            rp_id_hash: AuthenticatorData::rp_id_hash("example.com"),
            flags: FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS,
            sign_count: 7,
            attested_credential_data: None,
            extensions: None,
        };
        let encoded = data.encode();
        assert_eq!(encoded.len(), 37);
        assert_eq!(&encoded[32..33], &[FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS]);
        assert_eq!(&encoded[33..37], &7u32.to_be_bytes());
    }

    #[test]
    fn appends_attested_credential_data_when_the_at_flag_is_set() {
        let cose = Cbor::Map(vec![(Cbor::Uint(1), Cbor::Uint(2))]).encode();
        let data = AuthenticatorData {
            rp_id_hash: AuthenticatorData::rp_id_hash("example.com"),
            flags: FLAG_UP | FLAG_UV | FLAG_AT,
            sign_count: 0,
            attested_credential_data: Some(AttestedCredentialData::new(
                [0u8; 16],
                vec![9u8; 32],
                cose.clone(),
            )),
            extensions: None,
        };
        let encoded = data.encode();
        assert_eq!(encoded.len(), 37 + 16 + 2 + 32 + cose.len());
        assert_eq!(&encoded[37..53], &[0u8; 16]);
        assert_eq!(&encoded[53..55], &32u16.to_be_bytes());
        assert_eq!(&encoded[55..87], &[9u8; 32]);
        assert_eq!(&encoded[87..], &cose[..]);
    }

    #[test]
    fn attestation_object_is_a_cbor_map_with_fmt_none() {
        let data = AuthenticatorData {
            rp_id_hash: AuthenticatorData::rp_id_hash("example.com"),
            flags: FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS,
            sign_count: 0,
            attested_credential_data: None,
            extensions: None,
        };
        let object = data.attestation_object();
        assert_eq!(object[0], 0xa3);
        let text = String::from_utf8_lossy(&object);
        assert!(text.contains("fmt"));
        assert!(text.contains("none"));
        assert!(text.contains("attStmt"));
        assert!(text.contains("authData"));
    }
}
