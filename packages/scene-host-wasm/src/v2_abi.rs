// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Byte ABI handlers (ops 20..=28) for Client Compositor v2 in scene-host-wasm.

use crate::paint::compositor_v2::{CompositeOptsV2, CompositorV2, ScrollInputV2, ScrollOutcomeV2};
use crate::paint::scene_replay::SceneRasterizer;
use crate::paint::scene_v2::SceneFrameV2;

pub(crate) const OP_V2_INGEST_FRAME: u32 = 20;
pub(crate) const OP_V2_COMPOSITE: u32 = 21;
pub(crate) const OP_V2_SCROLL_INPUT: u32 = 22;
pub(crate) const OP_V2_STEP_FLING: u32 = 23;
pub(crate) const OP_V2_HIT_TEST: u32 = 24;
pub(crate) const OP_V2_SELECT_TEXT: u32 = 25;
pub(crate) const OP_V2_PREDICT_TYPE: u32 = 26;
pub(crate) const OP_V2_KNOWN_HASHES: u32 = 27;
pub(crate) const OP_V2_METRICS: u32 = 28;

pub(crate) fn dispatch_v2_op(
    op: u32,
    input: &[u8],
    raster: &SceneRasterizer,
    comp: &mut CompositorV2,
) -> Vec<u8> {
    match op {
        OP_V2_INGEST_FRAME => handle_ingest(input, comp),
        OP_V2_COMPOSITE => handle_composite(input, raster, comp),
        OP_V2_SCROLL_INPUT => handle_scroll_input(input, comp),
        OP_V2_STEP_FLING => handle_step_fling(input, comp),
        OP_V2_HIT_TEST => handle_hit_test(input, comp),
        OP_V2_SELECT_TEXT => handle_select_text(input, comp),
        OP_V2_PREDICT_TYPE => handle_predict_type(input, comp),
        OP_V2_KNOWN_HASHES => handle_known_hashes(comp),
        OP_V2_METRICS => handle_metrics(input, comp),
        _ => Vec::new(),
    }
}

fn handle_ingest(input: &[u8], comp: &mut CompositorV2) -> Vec<u8> {
    let Ok(frame) = SceneFrameV2::decode(input) else {
        return Vec::new();
    };
    let stats = comp.apply_frame(frame);
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&stats.acked_scroll_seq.to_le_bytes());
    out.extend_from_slice(&stats.acked_input_seq.to_le_bytes());
    out.extend_from_slice(&stats.tiles_cached.to_le_bytes());
    out.extend_from_slice(&stats.tiles_evicted.to_le_bytes());
    out
}

fn handle_composite(input: &[u8], raster: &SceneRasterizer, comp: &mut CompositorV2) -> Vec<u8> {
    if input.len() < 24 {
        return Vec::new();
    }
    let t_ms = f64_le(input, 0);
    let pinch_scale = f32_le(input, 8);
    let pan_x = f32_le(input, 12);
    let pan_y = f32_le(input, 16);
    let raw_rgba = u32_le(input, 20) != 0;
    let opts = CompositeOptsV2 {
        t_ms,
        pinch_scale,
        pan_x,
        pan_y,
        raw_rgba,
    };
    raster
        .with_store_and_renderer(|store, renderer| comp.composite_rgba(store, renderer, opts))
        .map(|(bytes, _)| bytes)
        .unwrap_or_default()
}

fn handle_scroll_input(input: &[u8], comp: &mut CompositorV2) -> Vec<u8> {
    if input.len() < 33 {
        return Vec::new();
    }
    let outcome = comp.handle_scroll_input(ScrollInputV2 {
        node_id: u64_le(input, 0),
        pt_x: f32_le(input, 8),
        pt_y: f32_le(input, 12),
        dx: f32_le(input, 16),
        dy: f32_le(input, 20),
        vx: f32_le(input, 24),
        vy: f32_le(input, 28),
        event_mask: input[32],
    });
    let mut out = Vec::with_capacity(21);
    match outcome {
        ScrollOutcomeV2::ForwardToServer => {
            out.push(1);
            out.extend_from_slice(&[0u8; 20]);
        }
        ScrollOutcomeV2::Local(u) => {
            out.push(0);
            out.extend_from_slice(&u.seq.to_le_bytes());
            out.extend_from_slice(&u.x.to_le_bytes());
            out.extend_from_slice(&u.y.to_le_bytes());
            out.extend_from_slice(&u.node_id.to_le_bytes());
        }
    }
    out
}

fn handle_step_fling(input: &[u8], comp: &mut CompositorV2) -> Vec<u8> {
    if input.len() < 4 {
        return Vec::new();
    }
    let dt_ms = f32_le(input, 0);
    let mut out = Vec::with_capacity(17);
    match comp.step_fling(dt_ms) {
        None => out.push(0),
        Some(u) => {
            out.push(1);
            out.extend_from_slice(&u.seq.to_le_bytes());
            out.extend_from_slice(&u.x.to_le_bytes());
            out.extend_from_slice(&u.y.to_le_bytes());
            out.extend_from_slice(&u.node_id.to_le_bytes());
        }
    }
    out
}

fn handle_hit_test(input: &[u8], comp: &CompositorV2) -> Vec<u8> {
    if input.len() < 16 {
        return Vec::new();
    }
    let view_x = f32_le(input, 0);
    let view_y = f32_le(input, 4);
    let t_ms = f64_le(input, 8);
    let hit = comp.hit_test(view_x, view_y, t_ms);
    let link = hit.link_url.as_deref().unwrap_or("");
    let mut out = Vec::with_capacity(24 + link.len());
    out.push(u8::from(hit.hit));
    out.push(hit.cursor as u8);
    out.push(u8::from(hit.editable));
    out.push(u8::from(hit.forward_pointer_move));
    out.extend_from_slice(&hit.node_id.to_le_bytes());
    out.extend_from_slice(&hit.scroll_node_id.to_le_bytes());
    out.extend_from_slice(&(link.len() as u32).to_le_bytes());
    out.extend_from_slice(link.as_bytes());
    out
}

fn handle_select_text(input: &[u8], comp: &mut CompositorV2) -> Vec<u8> {
    if input.len() < 24 {
        return Vec::new();
    }
    let res = comp.select_text(
        f32_le(input, 0),
        f32_le(input, 4),
        f32_le(input, 8),
        f32_le(input, 12),
        f64_le(input, 16),
    );
    let mut out = Vec::with_capacity(32 + res.quads.len() * 16 + res.text.len());
    match res.caret {
        Some(c) => {
            out.push(1);
            out.extend_from_slice(&c.x.to_le_bytes());
            out.extend_from_slice(&c.y.to_le_bytes());
            out.extend_from_slice(&c.w.to_le_bytes());
            out.extend_from_slice(&c.h.to_le_bytes());
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; 16]);
        }
    }
    out.extend_from_slice(&(res.quads.len() as u32).to_le_bytes());
    for q in &res.quads {
        out.extend_from_slice(&q.x.to_le_bytes());
        out.extend_from_slice(&q.y.to_le_bytes());
        out.extend_from_slice(&q.w.to_le_bytes());
        out.extend_from_slice(&q.h.to_le_bytes());
    }
    out.extend_from_slice(&(res.text.len() as u32).to_le_bytes());
    out.extend_from_slice(res.text.as_bytes());
    out
}

fn handle_predict_type(input: &[u8], comp: &mut CompositorV2) -> Vec<u8> {
    if input.len() < 17 {
        return Vec::new();
    }
    let kind = input[0];
    let node_id = u64_le(input, 1);
    let seq = u32_le(input, 9);
    let len = u32_le(input, 13) as usize;
    let Some(text_bytes) = input.get(17..17 + len) else {
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(text_bytes) else {
        return Vec::new();
    };
    if kind == 1 {
        let (mispredictions, suppressed) = comp.reconcile_echo(node_id, seq, text);
        let mut out = Vec::with_capacity(5);
        out.extend_from_slice(&mispredictions.to_le_bytes());
        out.push(u8::from(suppressed));
        return out;
    }
    let res = comp.predict_key_input(node_id, seq, text);
    let mut out = Vec::with_capacity(19 + res.glyph_ids.len() * 2);
    out.push(u8::from(res.suppressed));
    out.push(res.reason as u8);
    out.push(u8::from(res.is_bullet));
    out.extend_from_slice(&res.caret_x.to_le_bytes());
    out.extend_from_slice(&res.caret_y.to_le_bytes());
    out.extend_from_slice(&res.predicted_advance_px.to_le_bytes());
    out.extend_from_slice(&(res.glyph_ids.len() as u32).to_le_bytes());
    for gid in res.glyph_ids {
        out.extend_from_slice(&gid.to_le_bytes());
    }
    out
}

fn handle_known_hashes(comp: &CompositorV2) -> Vec<u8> {
    let hashes = comp.known_tile_hashes();
    let mut out = Vec::with_capacity(4 + hashes.len() * 8);
    out.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    for h in hashes {
        out.extend_from_slice(&h.to_le_bytes());
    }
    out
}

fn handle_metrics(input: &[u8], comp: &CompositorV2) -> Vec<u8> {
    let node_id = if input.len() >= 8 {
        u64_le(input, 0)
    } else {
        0
    };
    let vp = comp.visual_viewport();
    let st = comp.last_stats();
    let (misp, sup) = comp.echo_metrics(node_id);
    let mut out = Vec::with_capacity(41);
    out.extend_from_slice(&vp.x.to_le_bytes());
    out.extend_from_slice(&vp.y.to_le_bytes());
    out.extend_from_slice(&vp.width.to_le_bytes());
    out.extend_from_slice(&vp.height.to_le_bytes());
    out.extend_from_slice(&vp.scale.to_le_bytes());
    out.extend_from_slice(&st.width.to_le_bytes());
    out.extend_from_slice(&st.height.to_le_bytes());
    out.extend_from_slice(&st.checkerboard_tiles.to_le_bytes());
    out.extend_from_slice(&st.total_visible_tiles.to_le_bytes());
    out.extend_from_slice(&misp.to_le_bytes());
    out.push(u8::from(sup));
    out
}

fn u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64_le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

fn f32_le(b: &[u8], off: usize) -> f32 {
    f32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn f64_le(b: &[u8], off: usize) -> f64 {
    f64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}
