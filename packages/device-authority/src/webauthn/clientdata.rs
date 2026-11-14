// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! WebAuthn `clientDataJSON` serialization with deterministic member ordering.

use crate::webauthn::b64::b64url_encode;

/// Ceremony discriminator written to the `type` member of `clientDataJSON`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyType {
    /// Registration ceremony (`"webauthn.create"`).
    Create,
    /// Assertion ceremony (`"webauthn.get"`).
    Get,
}

impl CeremonyType {
    /// Returns the W3C ceremony type string literal.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// Serializes `clientDataJSON` bytes hashed into the attestation or assertion signature.
pub fn client_data_json(
    ceremony: CeremonyType,
    challenge: &[u8],
    origin: &str,
    cross_origin: bool,
    top_origin: Option<&str>,
) -> Vec<u8> {
    let mut parts: Vec<String> = Vec::with_capacity(5);
    parts.push(format!("\"type\":\"{}\"", escape_json(ceremony.as_str())));
    parts.push(format!("\"challenge\":\"{}\"", b64url_encode(challenge)));
    parts.push(format!("\"origin\":\"{}\"", escape_json(origin)));
    parts.push(format!("\"crossOrigin\":{cross_origin}"));
    if let Some(top) = top_origin {
        parts.push(format!("\"topOrigin\":\"{}\"", escape_json(top)));
    }
    format!("{{{}}}", parts.join(",")).into_bytes()
}

fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_canonical_field_order() {
        let json = client_data_json(
            CeremonyType::Get,
            b"chal",
            "https://example.com",
            false,
            None,
        );
        assert_eq!(
            String::from_utf8(json).unwrap(),
            r#"{"type":"webauthn.get","challenge":"Y2hhbA","origin":"https://example.com","crossOrigin":false}"#
        );
    }

    #[test]
    fn emits_create_with_top_origin_when_present() {
        let json = client_data_json(
            CeremonyType::Create,
            b"chal",
            "https://example.com",
            true,
            Some("https://top.example"),
        );
        let text = String::from_utf8(json).unwrap();
        assert!(text.starts_with(r#"{"type":"webauthn.create","challenge":"Y2hhbA""#));
        assert!(text.contains(r#""crossOrigin":true"#));
        assert!(text.contains(r#""topOrigin":"https://top.example""#));
        assert!(text.ends_with('}'));
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        let json = client_data_json(
            CeremonyType::Get,
            b"c",
            r#"https://example.com/"a\b"#,
            false,
            None,
        );
        let text = String::from_utf8(json).unwrap();
        assert!(text.contains(r#""origin":"https://example.com/\"a\\b""#));
    }
}
