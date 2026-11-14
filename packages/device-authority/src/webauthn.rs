// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! W3C WebAuthn Level 2 and Level 3 authenticator, CBOR/COSE codecs, extensions,
//! origin/RP-ID validation, and Related Origin Requests (`/.well-known/webauthn`).

pub mod authdata;
pub mod authenticator;
pub mod b64;
pub mod cbor;
pub mod clientdata;
pub mod cose;
pub mod largeblob;
pub mod origin;
pub mod prf;
pub mod random;
pub mod related_origins;
#[cfg(test)]
pub mod test_server;
pub mod types;
