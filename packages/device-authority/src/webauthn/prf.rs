// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! W3C WebAuthn Level 3 section 10.1.4 PRF (`hmac-secret`) evaluator.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::webauthn::types::PrfValues;

type HmacSha256 = Hmac<Sha256>;

const PRF_PREFIX: &[u8] = b"WebAuthn PRF";

/// Evaluates the WebAuthn PRF extension over `first_salt` and optional `second_salt`.
pub fn evaluate(
    secret: &[u8],
    first_salt: &[u8],
    second_salt: Option<&[u8]>,
) -> Result<PrfValues, String> {
    let first = evaluate_single_salt(secret, first_salt)?;
    let second = match second_salt {
        Some(salt) => Some(evaluate_single_salt(secret, salt)?),
        None => None,
    };
    Ok(PrfValues { first, second })
}

fn evaluate_single_salt(secret: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt_input = Vec::with_capacity(PRF_PREFIX.len() + 1 + salt.len());
    salt_input.extend_from_slice(PRF_PREFIX);
    salt_input.push(0x00);
    salt_input.extend_from_slice(salt);
    let salt_hash = Sha256::digest(&salt_input);

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).map_err(|e| format!("prf hmac key: {e}"))?;
    mac.update(&salt_hash);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_a_32_byte_hmac() {
        let values = evaluate(b"secret", b"salt", None).unwrap();
        assert_eq!(values.first.len(), 32);
        assert!(values.second.is_none());
    }

    #[test]
    fn is_deterministic_and_salt_dependent() {
        let a = evaluate(b"secret", b"salt", None).unwrap();
        let b = evaluate(b"secret", b"salt", None).unwrap();
        assert_eq!(a.first, b.first);
        let c = evaluate(b"secret", b"other", None).unwrap();
        assert_ne!(a.first, c.first);
        let d = evaluate(b"different", b"salt", None).unwrap();
        assert_ne!(a.first, d.first);
    }

    #[test]
    fn computes_the_second_output_when_a_second_salt_is_supplied() {
        let values = evaluate(b"secret", b"salt1", Some(b"salt2")).unwrap();
        let second = values.second.unwrap();
        assert_eq!(second.len(), 32);
        assert_ne!(values.first, second);
    }

    #[test]
    fn matches_the_specified_salt_construction() {
        let secret = b"credential-secret";
        let salt = b"rpsalt";
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(b"WebAuthn PRF");
        salt_input.push(0x00);
        salt_input.extend_from_slice(salt);
        let expected_hash = Sha256::digest(&salt_input);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).unwrap();
        mac.update(&expected_hash);
        let expected = mac.finalize().into_bytes().to_vec();

        let values = evaluate(secret, salt, None).unwrap();
        assert_eq!(values.first, expected);
    }
}
