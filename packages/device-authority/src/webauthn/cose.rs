// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Pure-Rust NIST P-256 key generation, COSE_Key encoding, and ES256 signing.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use p256::{EncodedPoint, PublicKey, SecretKey};

use crate::webauthn::cbor::Cbor;

/// COSE key type: Elliptic Curve with x and y coordinates (`EC2`).
pub const COSE_KTY_EC2: u64 = 2;
/// COSE algorithm: ECDSA over P-256 with SHA-256 (`ES256`).
pub const COSE_ALG_ES256: i64 = -7;
/// COSE elliptic curve: NIST P-256 (`secp256r1`).
pub const COSE_CRV_P256: u64 = 1;

/// Builds the canonical `COSE_Key` CBOR map for an uncompressed P-256 public key.
pub fn cose_ec2_p256(x: &[u8; 32], y: &[u8; 32]) -> Cbor {
    Cbor::Map(vec![
        (Cbor::Uint(1), Cbor::Uint(COSE_KTY_EC2)),
        (Cbor::Uint(3), Cbor::Neg(COSE_ALG_ES256)),
        (Cbor::Neg(-1), Cbor::Uint(COSE_CRV_P256)),
        (Cbor::Neg(-2), Cbor::Bytes(x.to_vec())),
        (Cbor::Neg(-3), Cbor::Bytes(y.to_vec())),
    ])
}

/// Extracts the 32-byte affine `(x, y)` coordinates from a P-256 SPKI PEM public key.
pub fn public_key_xy_from_pem(pem: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let public_key =
        PublicKey::from_public_key_pem(pem).map_err(|e| format!("parse public key: {e}"))?;
    let point = public_key.to_encoded_point(false);
    let x_slice = point
        .x()
        .ok_or_else(|| "missing P-256 x coordinate".to_string())?;
    let y_slice = point
        .y()
        .ok_or_else(|| "missing P-256 y coordinate".to_string())?;
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&x_slice[..]);
    y.copy_from_slice(&y_slice[..]);
    Ok((x, y))
}

/// Encodes a P-256 SPKI PEM public key as a deterministic `COSE_Key` CBOR byte vector.
pub fn cose_key_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let (x, y) = public_key_xy_from_pem(pem)?;
    Ok(cose_ec2_p256(&x, &y).encode())
}

/// Generates a fresh NIST P-256 keypair as `(private_pkcs8_pem, public_spki_pem)`.
pub fn generate_p256_keypair() -> Result<(String, String), String> {
    let secret = generate_secret_key()?;
    let private_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("private pem: {e}"))?
        .to_string();
    let public_pem = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("public pem: {e}"))?;
    Ok((private_pem, public_pem))
}

fn generate_secret_key() -> Result<SecretKey, String> {
    for _ in 0..8 {
        let seed = crate::webauthn::random::bytes(32)?;
        if let Ok(secret) = SecretKey::from_slice(&seed) {
            return Ok(secret);
        }
    }
    Err("failed to sample non-zero P-256 scalar".to_string())
}

/// Validates that a PEM string is a well-formed P-256 SPKI public key on the curve.
pub fn validate_p256_public_pem(pem: &str) -> Result<(), String> {
    let (x, y) = public_key_xy_from_pem(pem)?;
    let _ = public_key_from_xy(&x, &y)?;
    Ok(())
}

/// Reconstructs and validates a P-256 `PublicKey` from affine `(x, y)` coordinates.
pub fn public_key_from_xy(x: &[u8; 32], y: &[u8; 32]) -> Result<PublicKey, String> {
    let encoded = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    Option::from(PublicKey::from_encoded_point(&encoded))
        .ok_or_else(|| "public key point is not on the P-256 curve".to_string())
}

/// Signs `payload` with a PKCS#8 PEM P-256 private key, returning DER-encoded ES256 bytes.
pub fn sign_es256_der(private_key_pem: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("parse private key: {e}"))?;
    let sig: Signature = signing_key.sign(payload);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Verifies a DER-encoded ES256 signature over `payload` against a P-256 SPKI PEM key.
pub fn verify_es256_der(
    public_key_pem: &str,
    payload: &[u8],
    signature_der: &[u8],
) -> Result<bool, String> {
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("parse public key: {e}"))?;
    let sig = Signature::from_der(signature_der).map_err(|e| format!("parse DER sig: {e}"))?;
    Ok(verifying_key.verify(payload, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_p256_keypair_and_reads_back_its_coordinates() {
        let (private_pem, public_pem) = generate_p256_keypair().unwrap();
        assert!(private_pem.contains("PRIVATE KEY"));
        assert!(public_pem.contains("PUBLIC KEY"));
        validate_p256_public_pem(&public_pem).unwrap();
        let (x, y) = public_key_xy_from_pem(&public_pem).unwrap();
        let recovered = public_key_from_xy(&x, &y).unwrap();
        let recovered_pem = recovered.to_public_key_pem(LineEnding::LF).unwrap();
        assert_eq!(recovered_pem, public_pem);
    }

    #[test]
    fn cose_key_has_the_expected_labels_and_order() {
        let (_private_pem, public_pem) = generate_p256_keypair().unwrap();
        let encoded = cose_key_from_pem(&public_pem).unwrap();
        // RFC 8949 canonical key order: 1, 3, -1, -2 (32B), -3 (32B).
        assert_eq!(
            &encoded[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(encoded.len(), 10 + 32 + 3 + 32);
        assert_eq!(&encoded[42..45], &[0x22, 0x58, 0x20]);
    }

    #[test]
    fn signs_and_verifies_der_es256_payloads() {
        let (private_pem, public_pem) = generate_p256_keypair().unwrap();
        let sig = sign_es256_der(&private_pem, b"authenticator-payload").unwrap();
        assert!(verify_es256_der(&public_pem, b"authenticator-payload", &sig).unwrap());
        assert!(!verify_es256_der(&public_pem, b"tampered-payload", &sig).unwrap());
    }
}
