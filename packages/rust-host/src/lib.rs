// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Native Rust Parawing browser host, capsule identity, freeze/thaw, roaming, and attestation.

pub const RELEASE_VERSION: &str = include_str!("../../../VERSION").trim_ascii();

pub mod attestation;
pub mod authority_backend;
pub mod capsule;
pub mod engine_host;
pub mod freeze_thaw;
pub mod macos_capsule;
pub mod roam;
pub mod rpc_pipe;
