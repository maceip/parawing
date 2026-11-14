// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Minimal deterministic RFC 8949 CBOR encoder for WebAuthn attestation objects,
//! COSE_Key maps, and authenticator extension outputs.

/// A CBOR data item covering the major types required by WebAuthn and CTAP2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cbor {
    /// Major type 0: unsigned integer.
    Uint(u64),
    /// Major type 1: negative integer (holds the negative value, e.g. `-7`).
    Neg(i64),
    /// Major type 2: byte string.
    Bytes(Vec<u8>),
    /// Major type 3: UTF-8 text string.
    Text(String),
    /// Major type 4: array of CBOR items.
    Array(Vec<Cbor>),
    /// Major type 5: map encoded in RFC 8949 section 4.2.1 deterministic key order.
    Map(Vec<(Cbor, Cbor)>),
    /// Major type 7: boolean simple values (20 and 21).
    Bool(bool),
}

impl Cbor {
    /// Constructs a negative integer CBOR item.
    pub fn neg(value: i64) -> Self {
        Self::Neg(value)
    }

    /// Constructs a UTF-8 text CBOR item.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Constructs a byte-string CBOR item.
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// Encodes the item to deterministic CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Uint(u) => header(0, *u, out),
            Self::Neg(n) => {
                let arg = (-1i128 - i128::from(*n)) as u64;
                header(1, arg, out);
            }
            Self::Bytes(b) => {
                header(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Self::Text(t) => {
                let utf8 = t.as_bytes();
                header(3, utf8.len() as u64, out);
                out.extend_from_slice(utf8);
            }
            Self::Array(items) => {
                header(4, items.len() as u64, out);
                for item in items {
                    item.encode_into(out);
                }
            }
            Self::Map(pairs) => encode_map(pairs, out),
            Self::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        }
    }
}

fn encode_map(pairs: &[(Cbor, Cbor)], out: &mut Vec<u8>) {
    let mut sorted: Vec<(Vec<u8>, Vec<u8>)> = pairs
        .iter()
        .map(|(k, v)| (k.encode(), v.encode()))
        .collect();
    // RFC 8949 section 4.2.1: sort by encoded key bytes; duplicate keys keep last value.
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut deduped: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(sorted.len());
    for (k, v) in sorted {
        if let Some(last) = deduped.last_mut() {
            if last.0 == k {
                last.1 = v;
                continue;
            }
        }
        deduped.push((k, v));
    }
    header(5, deduped.len() as u64, out);
    for (k, v) in deduped {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
}

fn header(major: u8, argument: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    if argument < 24 {
        out.push(prefix | argument as u8);
    } else if argument <= u64::from(u8::MAX) {
        out.push(prefix | 24);
        out.push(argument as u8);
    } else if argument <= u64::from(u16::MAX) {
        out.push(prefix | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(prefix | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_shortest_integer_forms() {
        assert_eq!(Cbor::Uint(0).encode(), vec![0x00]);
        assert_eq!(Cbor::Uint(23).encode(), vec![0x17]);
        assert_eq!(Cbor::Uint(24).encode(), vec![0x18, 0x18]);
        assert_eq!(Cbor::Uint(256).encode(), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            Cbor::Uint(65536).encode(),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn encodes_negative_integers_as_major_type_one() {
        assert_eq!(Cbor::neg(-1).encode(), vec![0x20]);
        assert_eq!(Cbor::neg(-7).encode(), vec![0x26]);
    }

    #[test]
    fn encodes_text_bytes_and_booleans() {
        assert_eq!(Cbor::text("").encode(), vec![0x60]);
        assert_eq!(Cbor::text("a").encode(), vec![0x61, 0x61]);
        assert_eq!(Cbor::bytes(vec![1, 2, 3]).encode(), vec![0x43, 1, 2, 3]);
        assert_eq!(Cbor::Bool(true).encode(), vec![0xf5]);
        assert_eq!(Cbor::Bool(false).encode(), vec![0xf4]);
    }

    #[test]
    fn encodes_arrays_and_maps() {
        let arr = Cbor::Array(vec![Cbor::Uint(1), Cbor::Uint(2)]);
        assert_eq!(arr.encode(), vec![0x82, 0x01, 0x02]);

        let map = Cbor::Map(vec![
            (Cbor::text("b"), Cbor::Uint(2)),
            (Cbor::text("a"), Cbor::Uint(1)),
        ]);
        assert_eq!(map.encode(), vec![0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x02]);
    }

    #[test]
    fn map_duplicate_keys_keep_the_last_value() {
        let map = Cbor::Map(vec![
            (Cbor::text("k"), Cbor::Uint(1)),
            (Cbor::text("k"), Cbor::Uint(2)),
        ]);
        assert_eq!(map.encode(), vec![0xa1, 0x61, b'k', 0x02]);
    }

    #[test]
    fn cose_style_integer_keys_sort_numerically_by_encoded_bytes() {
        let map = Cbor::Map(vec![
            (Cbor::Neg(-3), Cbor::bytes(vec![0x01])),
            (Cbor::Neg(-1), Cbor::Uint(1)),
            (Cbor::Uint(3), Cbor::Neg(-7)),
            (Cbor::Uint(1), Cbor::Uint(2)),
            (Cbor::Neg(-2), Cbor::bytes(vec![0x02])),
        ]);
        assert_eq!(
            map.encode(),
            vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x41, 0x02, 0x22, 0x41, 0x01,]
        );
    }
}
