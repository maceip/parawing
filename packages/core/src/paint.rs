// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Paint scenes (record, decode, replay), canvas rasterization, and PDF and image
//! output.

pub(crate) mod scene_record;
pub(crate) mod scene_decode;
pub(crate) mod scene_replay;
#[allow(
    dead_code,
    reason = "KSC2 codec is shared with scene-host-wasm; renderSceneV2 and host tests use it."
)]
pub(crate) mod scene_v2;
#[allow(
    dead_code,
    reason = "CompositorV2 is shared with scene-host-wasm and exercised in host tests."
)]
pub(crate) mod compositor_v2;
pub(crate) mod scene_v2_builder;
pub(crate) mod font_container;
pub(crate) mod screenshot;
pub(crate) mod canvas2d;
pub(crate) mod pdf;
pub(crate) mod pdf_paint;
pub(crate) mod render;
pub(crate) mod canvas;
pub(crate) mod print;

#[cfg(test)]
mod tests;
