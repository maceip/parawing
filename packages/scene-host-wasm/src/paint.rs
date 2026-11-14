// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! The paint files shared with parawing-core, in core's module tree so `crate::paint::*`
//! paths resolve here too.

#[allow(
    dead_code,
    reason = "The byte ABI uses decode paths; parawing-core checks the full decoder."
)]
#[path = "../../core/src/paint/scene_decode.rs"]
pub(crate) mod scene_decode;
#[allow(
    dead_code,
    reason = "The byte ABI borrows codec definitions; parawing-core checks the full recorder."
)]
#[path = "../../core/src/paint/scene_record.rs"]
pub(crate) mod scene_record;
#[allow(
    dead_code,
    reason = "The byte ABI exposes a replay subset; parawing-core checks the full replay module."
)]
#[path = "../../core/src/paint/scene_replay.rs"]
pub(crate) mod scene_replay;
#[path = "../../core/src/paint/font_container.rs"]
pub(crate) mod font_container;
#[allow(
    dead_code,
    reason = "The byte ABI uses PNG/RGBA paths; parawing-core checks retained JPEG support."
)]
#[path = "../../core/src/paint/screenshot.rs"]
pub(crate) mod screenshot;
#[allow(dead_code, reason = "Shared KSC2 codec with parawing-core.")]
#[path = "../../core/src/paint/scene_v2.rs"]
pub(crate) mod scene_v2;
#[allow(
    dead_code,
    reason = "Shared Client Compositor v2 implementation with parawing-core."
)]
#[path = "../../core/src/paint/compositor_v2.rs"]
pub(crate) mod compositor_v2;
