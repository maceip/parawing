// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Operating-system cryptographically secure random byte generation.

/// Fills `buf` with cryptographically secure random bytes from OS entropy.
pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buf).map_err(|e| format!("system entropy: {e}"))
}

/// Returns `count` cryptographically secure random bytes.
pub fn bytes(count: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; count];
    fill(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_values() {
        let a = bytes(32).unwrap();
        let b = bytes(32).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn produces_the_requested_length() {
        for len in [0usize, 1, 16, 32, 65] {
            assert_eq!(bytes(len).unwrap().len(), len);
        }
    }
}
