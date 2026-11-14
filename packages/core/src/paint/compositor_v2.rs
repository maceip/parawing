// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Client Compositor v2 runtime (S1-S6): tile cache, local scroll/fling, handler regions,
//! sticky/fixed solver, pinch zoom vector re-rasterization, hit-test/selection/copy,
//! predictive typing echo, and declarative animations.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyrender::{Glyph as AnyGlyph, ImageRenderer as _, NormalizedCoord, PaintRef, PaintScene};
use kurbo::{Affine, BezPath, Circle, Line, Point, Rect, RoundedRect, Shape, Stroke, Vec2};
use peniko::{BlendMode, Blob, Color, Fill, FontData, StyleRef};

use crate::paint::scene_replay::{ensure_cached_renderer, replay_into, CachedRenderer, ResourceStore};
use crate::paint::scene_v2::{
    decode_vector_ops_v2, AnimationCurveV2, AnimationPropertyV2, CursorKindV2, EasingV2,
    EditableEchoSpecV2, HandlerRegionV2, KeyframeV2, KeyframeValueV2, LayerKindV2, LayerV2,
    OverscrollBehaviorV2, RectV2, SceneFrameV2, ScrollNodeV2, TextRunMapV2, TilePayloadV2,
    VectorOpV2, KSC2_MAGIC,
};
use crate::paint::screenshot::encode_png;

const MAX_CACHED_TILES: usize = 4096;
const FLING_DECAY_PER_MS: f32 = 0.004;
const FLING_STOP_SPEED_PX_PER_SEC: f32 = 15.0;
const SNAP_SETTLE_MAX_DIST_PX: f32 = 48.0;
const MIN_PINCH_SCALE: f32 = 0.5;
const MAX_PINCH_SCALE: f32 = 5.0;
const MISPREDICTION_SUPPRESS_THRESHOLD: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScrollUpdateV2 {
    pub node_id: u64,
    pub x: f32,
    pub y: f32,
    pub seq: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PendingScrollDelta {
    node_id: u64,
    seq: u32,
    dx: f32,
    dy: f32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScrollInputV2 {
    pub node_id: u64,
    pub pt_x: f32,
    pub pt_y: f32,
    pub dx: f32,
    pub dy: f32,
    pub vx: f32,
    pub vy: f32,
    pub event_mask: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScrollOutcomeV2 {
    Local(ScrollUpdateV2),
    ForwardToServer,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct FlingState {
    node_id: u64,
    vx: f32,
    vy: f32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct VisualViewportV2 {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub scale: f32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyFrameStatsV2 {
    pub acked_scroll_seq: u32,
    pub acked_input_seq: u32,
    pub tiles_cached: u32,
    pub tiles_evicted: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HitTestResultV2 {
    pub hit: bool,
    pub node_id: u64,
    pub scroll_node_id: u64,
    pub cursor: CursorKindV2,
    pub link_url: Option<String>,
    pub editable: bool,
    pub forward_pointer_move: bool,
}

impl Default for HitTestResultV2 {
    fn default() -> Self {
        Self {
            hit: false,
            node_id: 0,
            scroll_node_id: 0,
            cursor: CursorKindV2::Default,
            link_url: None,
            editable: false,
            forward_pointer_move: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SelectionResultV2 {
    pub text: String,
    pub quads: Vec<RectV2>,
    pub caret: Option<RectV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressReasonV2 {
    None = 0,
    UnknownNode = 1,
    ComplexShaping = 2,
    Ligatures = 3,
    MispredictionLimit = 4,
    UnsupportedCharOrFont = 5,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PredictResultV2 {
    pub suppressed: bool,
    pub reason: SuppressReasonV2,
    pub is_bullet: bool,
    pub caret_x: f32,
    pub caret_y: f32,
    pub predicted_advance_px: f32,
    pub glyph_ids: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq)]
struct PendingEchoChar {
    seq: u32,
    codepoint: u32,
    glyph_id: u16,
    displayed: char,
    x: f32,
    advance_px: f32,
}

#[derive(Debug, Clone, Default)]
struct NodeEchoState {
    pending: Vec<PendingEchoChar>,
    mispredictions: u32,
    suppressed: bool,
    last_auth_text: String,
}

#[derive(Debug, Clone, Copy)]
pub struct CompositeOptsV2 {
    pub t_ms: f64,
    pub pinch_scale: f32,
    pub pan_x: f32,
    pub pan_y: f32,
    pub raw_rgba: bool,
}

impl Default for CompositeOptsV2 {
    fn default() -> Self {
        Self {
            t_ms: 0.0,
            pinch_scale: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            raw_rgba: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompositeStatsV2 {
    pub width: u32,
    pub height: u32,
    pub checkerboard_tiles: u32,
    pub total_visible_tiles: u32,
}

pub struct CompositorV2 {
    tile_cache: HashMap<u64, TilePayloadV2>,
    tile_lru: VecDeque<u64>,
    current_frame: Option<SceneFrameV2>,
    scroll_offsets: HashMap<u64, (f32, f32)>,
    pending_scrolls: VecDeque<PendingScrollDelta>,
    next_scroll_seq: u32,
    fling: Option<FlingState>,
    visual_viewport: VisualViewportV2,
    last_stats: CompositeStatsV2,
    active_selection: SelectionResultV2,
    echo_nodes: HashMap<u64, NodeEchoState>,
    echo_fonts: HashMap<u64, FontData>,
    queued_scroll_updates: VecDeque<ScrollUpdateV2>,
    scratch_rgba: Vec<u8>,
}

impl Default for CompositorV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositorV2 {
    pub fn new() -> Self {
        Self {
            tile_cache: HashMap::new(),
            tile_lru: VecDeque::new(),
            current_frame: None,
            scroll_offsets: HashMap::new(),
            pending_scrolls: VecDeque::new(),
            next_scroll_seq: 1,
            fling: None,
            visual_viewport: VisualViewportV2 {
                x: 0.0,
                y: 0.0,
                width: 800.0,
                height: 600.0,
                scale: 1.0,
            },
            last_stats: CompositeStatsV2::default(),
            active_selection: SelectionResultV2::default(),
            echo_nodes: HashMap::new(),
            echo_fonts: HashMap::new(),
            queued_scroll_updates: VecDeque::new(),
            scratch_rgba: Vec::new(),
        }
    }

    pub fn apply_frame(&mut self, frame: SceneFrameV2) -> ApplyFrameStatsV2 {
        let mut tiles_evicted = 0u32;
        for layer in &frame.layers {
            for hash in &layer.invalidated_hashes {
                if self.tile_cache.remove(hash).is_some() {
                    tiles_evicted += 1;
                }
            }
        }
        let mut tiles_cached = 0u32;
        for tile in &frame.tiles {
            self.insert_tile(tile.clone());
            tiles_cached += 1;
        }
        for spec in &frame.editable_specs {
            cache_echo_font(&mut self.echo_fonts, spec);
        }
        self.pending_scrolls
            .retain(|u| u.seq > frame.acked_scroll_seq);
        self.rebase_scroll_offsets(&frame.scroll_nodes);
        if frame.acked_input_seq > 0 {
            for spec in &frame.editable_specs {
                if !spec.is_password {
                    self.reconcile_echo(spec.node_id, frame.acked_input_seq, &spec.auth_text);
                }
            }
        }
        self.reconcile_acked_inputs(frame.acked_input_seq);

        let scale = self.visual_viewport.scale.max(MIN_PINCH_SCALE);
        let vw = frame.viewport_w.max(1) as f32;
        let vh = frame.viewport_h.max(1) as f32;
        self.visual_viewport.width = vw / scale;
        self.visual_viewport.height = vh / scale;
        let acked_scroll_seq = frame.acked_scroll_seq;
        let acked_input_seq = frame.acked_input_seq;
        self.current_frame = Some(frame);
        ApplyFrameStatsV2 {
            acked_scroll_seq,
            acked_input_seq,
            tiles_cached,
            tiles_evicted,
        }
    }

    fn insert_tile(&mut self, tile: TilePayloadV2) {
        let hash = tile.content_hash;
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.tile_cache.entry(hash) {
            e.insert(tile);
            return;
        }
        while self.tile_cache.len() >= MAX_CACHED_TILES {
            let Some(oldest) = self.tile_lru.pop_front() else {
                break;
            };
            self.tile_cache.remove(&oldest);
        }
        self.tile_lru.push_back(hash);
        self.tile_cache.insert(hash, tile);
    }

    fn rebase_scroll_offsets(&mut self, nodes: &[ScrollNodeV2]) {
        for node in nodes {
            if node.server_driven {
                self.scroll_offsets
                    .insert(node.node_id, (node.auth_offset_x, node.auth_offset_y));
                continue;
            }
            let (mut unacked_dx, mut unacked_dy) = (0.0f32, 0.0f32);
            for p in &self.pending_scrolls {
                if p.node_id == node.node_id {
                    unacked_dx += p.dx;
                    unacked_dy += p.dy;
                }
            }
            let clamped = clamp_scroll_offset(
                node,
                node.auth_offset_x + unacked_dx,
                node.auth_offset_y + unacked_dy,
            );
            self.scroll_offsets.insert(node.node_id, clamped);
        }
    }

    fn reconcile_acked_inputs(&mut self, acked_input_seq: u32) {
        for st in self.echo_nodes.values_mut() {
            st.pending.retain(|entry| entry.seq > acked_input_seq);
        }
    }

    pub fn known_tile_hashes(&self) -> Vec<u64> {
        let mut hashes: Vec<u64> = self.tile_cache.keys().copied().collect();
        hashes.sort_unstable();
        hashes
    }

    pub fn cached_tile_count(&self) -> usize {
        self.tile_cache.len()
    }

    pub fn scroll_offset(&self, node_id: u64) -> (f32, f32) {
        self.scroll_offsets
            .get(&node_id)
            .copied()
            .unwrap_or((0.0, 0.0))
    }

    pub fn visual_viewport(&self) -> VisualViewportV2 {
        self.visual_viewport
    }

    pub fn last_stats(&self) -> CompositeStatsV2 {
        self.last_stats
    }

    pub fn echo_metrics(&self, node_id: u64) -> (u32, bool) {
        self.echo_nodes
            .get(&node_id)
            .map(|s| (s.mispredictions, s.suppressed))
            .unwrap_or((0, false))
    }

    pub fn set_visual_viewport(&mut self, scale: f32, pan_x: f32, pan_y: f32) -> VisualViewportV2 {
        let scale = if scale.is_finite() {
            scale.clamp(MIN_PINCH_SCALE, MAX_PINCH_SCALE)
        } else {
            1.0
        };
        let (lw, lh) = self.layout_viewport_size();
        let vw = lw / scale;
        let vh = lh / scale;
        let max_pan_x = (lw - vw).max(0.0);
        let max_pan_y = (lh - vh).max(0.0);
        let x = if pan_x.is_finite() {
            pan_x.clamp(0.0, max_pan_x)
        } else {
            0.0
        };
        let y = if pan_y.is_finite() {
            pan_y.clamp(0.0, max_pan_y)
        } else {
            0.0
        };
        self.visual_viewport = VisualViewportV2 {
            x,
            y,
            width: vw,
            height: vh,
            scale,
        };
        self.visual_viewport
    }

    fn layout_viewport_size(&self) -> (f32, f32) {
        match &self.current_frame {
            Some(f) => (f.viewport_w.max(1) as f32, f.viewport_h.max(1) as f32),
            None => (800.0, 600.0),
        }
    }

    pub fn take_scroll_updates(&mut self) -> Vec<ScrollUpdateV2> {
        self.queued_scroll_updates.drain(..).collect()
    }

    pub fn handle_scroll_input(&mut self, input: ScrollInputV2) -> ScrollOutcomeV2 {
        let Some(frame) = self.current_frame.as_ref() else {
            return ScrollOutcomeV2::ForwardToServer;
        };
        if has_blocking_handler(&frame.handler_regions, input) {
            self.fling = None;
            return ScrollOutcomeV2::ForwardToServer;
        }
        let target_id = resolve_scroll_node_id(&frame.scroll_nodes, input.node_id);
        let chain_nodes = collect_scroll_chain_nodes(&frame.scroll_nodes, target_id);
        if chain_nodes.is_empty() {
            return ScrollOutcomeV2::ForwardToServer;
        }
        let Ok((consumed, active_node)) = self.apply_scroll_chain(&chain_nodes, input.dx, input.dy)
        else {
            self.fling = None;
            return ScrollOutcomeV2::ForwardToServer;
        };
        let fling_node = active_node.unwrap_or(target_id);
        if input.vx.abs() > 1.0 || input.vy.abs() > 1.0 {
            self.fling = Some(FlingState {
                node_id: fling_node,
                vx: input.vx,
                vy: input.vy,
            });
        }
        if let Some(u) = consumed {
            return ScrollOutcomeV2::Local(u);
        }
        let fallback_node = &chain_nodes[0];
        let offset = self.node_scroll_or_auth(fallback_node);
        let seq = self.next_scroll_seq.saturating_sub(1);
        ScrollOutcomeV2::Local(ScrollUpdateV2 {
            node_id: fallback_node.node_id,
            x: offset.0,
            y: offset.1,
            seq,
        })
    }

    fn node_scroll_or_auth(&self, node: &ScrollNodeV2) -> (f32, f32) {
        self.scroll_offsets
            .get(&node.node_id)
            .copied()
            .unwrap_or((node.auth_offset_x, node.auth_offset_y))
    }

    fn apply_scroll_chain(
        &mut self,
        chain_nodes: &[ScrollNodeV2],
        dx: f32,
        dy: f32,
    ) -> Result<(Option<ScrollUpdateV2>, Option<u64>), ()> {
        let mut rem_dx = dx;
        let mut rem_dy = dy;
        let mut first_update: Option<ScrollUpdateV2> = None;
        let mut active_node: Option<u64> = None;
        for node in chain_nodes {
            if node.server_driven {
                return Err(());
            }
            let prev = self.node_scroll_or_auth(node);
            let next = clamp_scroll_offset(node, prev.0 + rem_dx, prev.1 + rem_dy);
            let adx = next.0 - prev.0;
            let ady = next.1 - prev.1;
            self.scroll_offsets.insert(node.node_id, next);
            if adx.abs() > 1e-4 || ady.abs() > 1e-4 {
                let u = self.record_scroll_delta(node.node_id, next, adx, ady);
                self.queued_scroll_updates.push_back(u);
                if first_update.is_none() {
                    first_update = Some(u);
                }
                active_node = Some(node.node_id);
            }
            rem_dx = next_chain_delta(rem_dx, adx, node.overscroll_x);
            rem_dy = next_chain_delta(rem_dy, ady, node.overscroll_y);
            if rem_dx.abs() <= 1e-4 && rem_dy.abs() <= 1e-4 {
                break;
            }
        }
        Ok((first_update, active_node))
    }

    fn record_scroll_delta(
        &mut self,
        node_id: u64,
        offset: (f32, f32),
        dx: f32,
        dy: f32,
    ) -> ScrollUpdateV2 {
        let seq = self.next_scroll_seq;
        self.next_scroll_seq = self.next_scroll_seq.saturating_add(1).max(1);
        if dx.abs() > 1e-6 || dy.abs() > 1e-6 {
            self.pending_scrolls.push_back(PendingScrollDelta {
                node_id,
                seq,
                dx,
                dy,
            });
        }
        ScrollUpdateV2 {
            node_id,
            x: offset.0,
            y: offset.1,
            seq,
        }
    }

    pub fn step_fling(&mut self, dt_ms: f32) -> Option<ScrollUpdateV2> {
        let mut fling = self.fling?;
        let dt = dt_ms.clamp(0.0, 250.0);
        let chain_nodes = {
            let frame = self.current_frame.as_ref()?;
            collect_scroll_chain_nodes(&frame.scroll_nodes, fling.node_id)
        };
        let active_node_ref = chain_nodes.first()?;
        if active_node_ref.server_driven {
            self.fling = None;
            return None;
        }
        let decay = (-dt * FLING_DECAY_PER_MS).exp();
        let dt_s = dt / 1000.0;
        let dx = fling.vx * dt_s * (1.0 + decay) * 0.5;
        let dy = fling.vy * dt_s * (1.0 + decay) * 0.5;
        fling.vx *= decay;
        fling.vy *= decay;

        let Ok((consumed, active_id)) = self.apply_fling_chain(&chain_nodes, dx, dy, &mut fling)
        else {
            self.fling = None;
            return None;
        };
        if let Some(nid) = active_id {
            fling.node_id = nid;
        }
        if fling.vx.hypot(fling.vy) < FLING_STOP_SPEED_PX_PER_SEC {
            return self.settle_fling(&chain_nodes, fling.node_id, consumed);
        }
        self.fling = Some(fling);
        consumed
    }

    fn apply_fling_chain(
        &mut self,
        chain_nodes: &[ScrollNodeV2],
        dx: f32,
        dy: f32,
        fling: &mut FlingState,
    ) -> Result<(Option<ScrollUpdateV2>, Option<u64>), ()> {
        let mut rem_dx = dx;
        let mut rem_dy = dy;
        let mut primary: Option<ScrollUpdateV2> = None;
        let mut active_id: Option<u64> = None;
        for node in chain_nodes {
            if node.server_driven {
                return Err(());
            }
            let prev = self.node_scroll_or_auth(node);
            let next = clamp_scroll_offset(node, prev.0 + rem_dx, prev.1 + rem_dy);
            let adx = next.0 - prev.0;
            let ady = next.1 - prev.1;
            self.scroll_offsets.insert(node.node_id, next);
            if adx.abs() > 1e-4 || ady.abs() > 1e-4 {
                let u = self.record_scroll_delta(node.node_id, next, adx, ady);
                self.queued_scroll_updates.push_back(u);
                if primary.is_none() {
                    primary = Some(u);
                }
                active_id = Some(node.node_id);
            }
            if (rem_dx - adx).abs() > 1e-3 && node.overscroll_x != OverscrollBehaviorV2::Auto {
                fling.vx = 0.0;
            }
            if (rem_dy - ady).abs() > 1e-3 && node.overscroll_y != OverscrollBehaviorV2::Auto {
                fling.vy = 0.0;
            }
            rem_dx = next_chain_delta(rem_dx, adx, node.overscroll_x);
            rem_dy = next_chain_delta(rem_dy, ady, node.overscroll_y);
            if rem_dx.abs() <= 1e-4 && rem_dy.abs() <= 1e-4 {
                break;
            }
        }
        Ok((primary, active_id))
    }

    fn settle_fling(
        &mut self,
        chain_nodes: &[ScrollNodeV2],
        node_id: u64,
        consumed: Option<ScrollUpdateV2>,
    ) -> Option<ScrollUpdateV2> {
        self.fling = None;
        let node = chain_nodes
            .iter()
            .find(|n| n.node_id == node_id)
            .or_else(|| chain_nodes.first())?;
        let cur = self.node_scroll_or_auth(node);
        let snapped = clamp_scroll_offset(
            node,
            snap_axis(cur.0, &node.snap_points_x),
            snap_axis(cur.1, &node.snap_points_y),
        );
        self.scroll_offsets.insert(node.node_id, snapped);
        let sdx = snapped.0 - cur.0;
        let sdy = snapped.1 - cur.1;
        if sdx.abs() > 1e-4 || sdy.abs() > 1e-4 || consumed.is_none() {
            let u = self.record_scroll_delta(node.node_id, snapped, sdx, sdy);
            self.queued_scroll_updates.push_back(u);
            return Some(u);
        }
        consumed
    }

    pub fn sticky_layer_shift(&self, layer: &LayerV2) -> (f32, f32) {
        if let Some(frame) = self.current_frame.as_ref() {
            return self.layer_scroll_offset(frame, layer);
        }
        let (sx, sy) = self.scroll_offset(layer.scroll_node_id);
        let (w, h) = self.layout_viewport_size();
        compute_layer_offset(layer, sx, sy, RectV2::new(0.0, 0.0, w, h))
    }

    pub fn eval_layer_animations(&self, layer: &LayerV2, t_ms: f64) -> (f32, Affine) {
        eval_layer_state(layer, t_ms)
    }

    pub fn composite_rgba(
        &mut self,
        store: &ResourceStore,
        renderer_slot: &mut Option<CachedRenderer>,
        opts: CompositeOptsV2,
    ) -> Result<(Vec<u8>, CompositeStatsV2), String> {
        let Some(frame) = self.current_frame.clone() else {
            return Err("no KSC2 frame ingested".to_string());
        };
        let vp = self.set_visual_viewport(opts.pinch_scale, opts.pan_x, opts.pan_y);
        let out_w = frame.viewport_w.clamp(1, 4096);
        let out_h = frame.viewport_h.clamp(1, 4096);
        let view_affine =
            Affine::scale(vp.scale as f64) * Affine::translate((-vp.x as f64, -vp.y as f64));
        let mut checker_count = 0u32;
        let mut visible_count = 0u32;
        let mut scratch = std::mem::take(&mut self.scratch_rgba);
        {
            let renderer = ensure_cached_renderer(renderer_slot, out_w, out_h);
            scratch.clear();
            scratch.resize((out_w as usize) * (out_h as usize) * 4, 0);
            let ctx = CompositeRenderCtx {
                frame: &frame,
                compositor: self,
                store,
                view_affine,
                vp,
                out_w,
                out_h,
                t_ms: opts.t_ms,
                checker_count: &mut checker_count,
                visible_count: &mut visible_count,
            };
            let mut render_ctx = ctx;
            renderer.render(|scene| render_ctx.paint(scene), &mut scratch);
        }
        let stats = CompositeStatsV2 {
            width: out_w,
            height: out_h,
            checkerboard_tiles: checker_count,
            total_visible_tiles: visible_count,
        };
        self.last_stats = stats;
        if opts.raw_rgba {
            let mut framed = Vec::with_capacity(8 + scratch.len());
            framed.extend_from_slice(&out_w.to_le_bytes());
            framed.extend_from_slice(&out_h.to_le_bytes());
            framed.extend_from_slice(&scratch);
            self.scratch_rgba = scratch;
            Ok((framed, stats))
        } else {
            let png = encode_png(&scratch, out_w, out_h);
            self.scratch_rgba = scratch;
            png.map(|p| (p, stats))
        }
    }

    pub fn hit_test(&self, view_x: f32, view_y: f32, t_ms: f64) -> HitTestResultV2 {
        let Some(frame) = self.current_frame.as_ref() else {
            return HitTestResultV2::default();
        };
        let doc_view = Point::new(
            (view_x / self.visual_viewport.scale + self.visual_viewport.x) as f64,
            (view_y / self.visual_viewport.scale + self.visual_viewport.y) as f64,
        );
        for layer in frame.layers.iter().rev() {
            if let Some(hit) = self.hit_test_layer(frame, layer, doc_view, t_ms) {
                return hit;
            }
        }
        HitTestResultV2::default()
    }

    fn hit_test_layer(
        &self,
        frame: &SceneFrameV2,
        layer: &LayerV2,
        doc_view: Point,
        t_ms: f64,
    ) -> Option<HitTestResultV2> {
        let (opacity, anim_affine) = eval_layer_state(layer, t_ms);
        if opacity <= 0.001 {
            return None;
        }
        if !matches!(layer.kind, LayerKindV2::Fixed { .. })
            && !self.point_in_scroll_clips(frame, layer.scroll_node_id, doc_view)
        {
            return None;
        }
        let (ox, oy) = self.layer_scroll_offset(frame, layer);
        let layer_affine = anim_affine * Affine::translate((ox as f64, oy as f64));
        let local = layer_affine.inverse() * doc_view;
        let lx = local.x as f32;
        let ly = local.y as f32;
        for tr in layer.tile_refs.iter().rev() {
            if !tr.bounds.contains_point(lx, ly) {
                continue;
            }
            let Some(tile) = self.tile_cache.get(&tr.content_hash) else {
                continue;
            };
            let tx = lx - tr.bounds.x;
            let ty = ly - tr.bounds.y;
            for hit in tile.hit_rects.iter().rev() {
                if hit.rect.contains_point(tx, ty) {
                    return Some(HitTestResultV2 {
                        hit: true,
                        node_id: hit.node_id,
                        scroll_node_id: hit.scroll_node_id,
                        cursor: hit.cursor,
                        link_url: hit.link_url.clone(),
                        editable: hit.editable,
                        forward_pointer_move: hit.hover_or_pointer,
                    });
                }
            }
        }
        None
    }

    pub fn select_text(
        &mut self,
        start_vx: f32,
        start_vy: f32,
        end_vx: f32,
        end_vy: f32,
        t_ms: f64,
    ) -> SelectionResultV2 {
        let Some(frame) = self.current_frame.as_ref() else {
            self.active_selection = SelectionResultV2::default();
            return self.active_selection.clone();
        };
        let p0 = self.view_to_viewport_pt(start_vx, start_vy);
        let p1 = self.view_to_viewport_pt(end_vx, end_vy);
        let mut selected = String::new();
        let mut quads = Vec::new();
        let mut caret = None;
        for layer in &frame.layers {
            self.collect_layer_selection(
                frame,
                layer,
                p0,
                p1,
                t_ms,
                &mut selected,
                &mut quads,
                &mut caret,
            );
        }
        let res = SelectionResultV2 {
            text: selected,
            quads,
            caret,
        };
        self.active_selection = res.clone();
        res
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Selection collection accumulates text, quads, and caret in one pass."
    )]
    fn collect_layer_selection(
        &self,
        frame: &SceneFrameV2,
        layer: &LayerV2,
        p0: Point,
        p1: Point,
        t_ms: f64,
        selected: &mut String,
        quads: &mut Vec<RectV2>,
        caret: &mut Option<RectV2>,
    ) {
        let (_, anim_affine) = eval_layer_state(layer, t_ms);
        let (ox, oy) = self.layer_scroll_offset(frame, layer);
        let layer_affine = anim_affine * Affine::translate((ox as f64, oy as f64));
        let inv = layer_affine.inverse();
        let a = inv * p0;
        let b = inv * p1;
        let (start, end) = order_points(a, b);
        for tr in &layer.tile_refs {
            let Some(tile) = self.tile_cache.get(&tr.content_hash) else {
                continue;
            };
            collect_tile_selection(
                tile,
                tr.bounds,
                layer_affine,
                start,
                end,
                selected,
                quads,
                caret,
            );
        }
    }

    fn view_to_viewport_pt(&self, vx: f32, vy: f32) -> Point {
        Point::new(
            (vx / self.visual_viewport.scale + self.visual_viewport.x) as f64,
            (vy / self.visual_viewport.scale + self.visual_viewport.y) as f64,
        )
    }

    pub fn copy_selected_text(&self) -> String {
        self.active_selection.text.clone()
    }

    pub fn predict_key_input(
        &mut self,
        node_id: u64,
        input_seq: u32,
        text: &str,
    ) -> PredictResultV2 {
        let Some(spec) = self
            .current_frame
            .as_ref()
            .and_then(|f| f.editable_specs.iter().find(|s| s.node_id == node_id))
            .cloned()
        else {
            return suppressed_predict(SuppressReasonV2::UnknownNode, 0.0, 0.0);
        };
        let state = self.echo_nodes.entry(node_id).or_default();
        if let Some(reason) = echo_block_reason(&spec, state) {
            return suppressed_predict(reason, spec.caret_x, spec.caret_y);
        }
        let cursor_offset: f32 = state.pending.iter().map(|p| p.advance_px).sum();
        let cur_x = spec.caret_x + cursor_offset;
        let Some((entries, glyph_ids, adv_total)) =
            build_echo_entries(&spec, input_seq, text, cur_x)
        else {
            return suppressed_predict(
                SuppressReasonV2::UnsupportedCharOrFont,
                cur_x,
                spec.caret_y,
            );
        };
        state.pending.extend(entries);
        PredictResultV2 {
            suppressed: false,
            reason: SuppressReasonV2::None,
            is_bullet: spec.is_password,
            caret_x: cur_x + adv_total,
            caret_y: spec.caret_y,
            predicted_advance_px: adv_total,
            glyph_ids,
        }
    }

    pub fn reconcile_echo(
        &mut self,
        node_id: u64,
        acked_seq: u32,
        observed_auth_text: &str,
    ) -> (u32, bool) {
        let state = self.echo_nodes.entry(node_id).or_default();
        let confirmed: String = state
            .pending
            .iter()
            .filter(|e| e.seq <= acked_seq)
            .map(|e| char::from_u32(e.codepoint).unwrap_or(e.displayed))
            .collect();
        state.pending.retain(|e| e.seq > acked_seq);
        if !confirmed.is_empty() && !observed_auth_text.ends_with(&confirmed) {
            state.mispredictions += 1;
            if state.mispredictions >= MISPREDICTION_SUPPRESS_THRESHOLD {
                state.suppressed = true;
            }
        }
        state.last_auth_text = observed_auth_text.to_string();
        (state.mispredictions, state.suppressed)
    }

    fn layer_scroll_offset(&self, frame: &SceneFrameV2, layer: &LayerV2) -> (f32, f32) {
        if matches!(layer.kind, LayerKindV2::Fixed { .. }) {
            return compute_layer_offset(layer, 0.0, 0.0, RectV2::default());
        }
        let (sx, sy) = self.scroll_offset(layer.scroll_node_id);
        let clip = frame
            .scroll_nodes
            .iter()
            .find(|n| n.node_id == layer.scroll_node_id)
            .map(|n| n.clip)
            .unwrap_or_else(|| {
                RectV2::new(0.0, 0.0, frame.viewport_w as f32, frame.viewport_h as f32)
            });
        let (lx, ly) = compute_layer_offset(layer, sx, sy, clip);
        let (ax, ay) = self.ancestor_scroll_offset(frame, layer.scroll_node_id);
        (lx - ax, ly - ay)
    }

    fn ancestor_scroll_offset(&self, frame: &SceneFrameV2, node_id: u64) -> (f32, f32) {
        let chain = scroll_ancestor_chain(&frame.scroll_nodes, node_id);
        let strict_count = chain.len().saturating_sub(1);
        let (mut ax, mut ay) = (0.0f32, 0.0f32);
        for &anc_id in &chain[..strict_count] {
            let (sx, sy) = self.scroll_offset(anc_id);
            ax += sx;
            ay += sy;
        }
        (ax, ay)
    }

    fn point_in_scroll_clips(&self, frame: &SceneFrameV2, node_id: u64, doc_view: Point) -> bool {
        let chain = scroll_ancestor_chain(&frame.scroll_nodes, node_id);
        let (mut cum_sx, mut cum_sy) = (0.0f32, 0.0f32);
        for &nid in &chain {
            let Some(node) = frame.scroll_nodes.iter().find(|n| n.node_id == nid) else {
                continue;
            };
            let lx = doc_view.x as f32 + cum_sx;
            let ly = doc_view.y as f32 + cum_sy;
            if !node.clip.contains_point(lx, ly) {
                return false;
            }
            let (sx, sy) = self.scroll_offset(nid);
            cum_sx += sx;
            cum_sy += sy;
        }
        true
    }
}

struct CompositeRenderCtx<'a> {
    frame: &'a SceneFrameV2,
    compositor: &'a CompositorV2,
    store: &'a ResourceStore,
    view_affine: Affine,
    vp: VisualViewportV2,
    out_w: u32,
    out_h: u32,
    t_ms: f64,
    checker_count: &'a mut u32,
    visible_count: &'a mut u32,
}

impl CompositeRenderCtx<'_> {
    fn paint<S: PaintScene>(&mut self, scene: &mut S) {
        let bg = Rect::new(0.0, 0.0, self.out_w as f64, self.out_h as f64);
        scene.fill(Fill::NonZero, Affine::IDENTITY, Color::WHITE, None, &bg);
        for layer in &self.frame.layers {
            self.paint_layer(scene, layer);
        }
        self.paint_selection(scene);
        self.paint_echo(scene);
    }

    fn paint_layer<S: PaintScene>(&mut self, scene: &mut S, layer: &LayerV2) {
        let (opacity, anim_affine) = eval_layer_state(layer, self.t_ms);
        if opacity <= 0.001 {
            return;
        }
        let clips_pushed = if matches!(layer.kind, LayerKindV2::Fixed { .. }) {
            0
        } else {
            self.push_scroll_clips(scene, layer.scroll_node_id)
        };
        let (ox, oy) = self.compositor.layer_scroll_offset(self.frame, layer);
        let layer_affine =
            self.view_affine * anim_affine * Affine::translate((ox as f64, oy as f64));
        let vp_bounds = RectV2::new(self.vp.x, self.vp.y, self.vp.width, self.vp.height);
        let pushed_opacity = opacity < 0.999;
        if pushed_opacity {
            let layer_rect = Rect::new(
                layer.bounds.x as f64,
                layer.bounds.y as f64,
                layer.bounds.right() as f64,
                layer.bounds.bottom() as f64,
            );
            scene.push_layer(
                Fill::NonZero,
                BlendMode::default(),
                opacity,
                layer_affine,
                &layer_rect,
                None,
                None,
            );
        }
        self.paint_layer_bg_and_tiles(scene, layer, anim_affine, ox, oy, vp_bounds);
        if pushed_opacity {
            scene.pop_layer();
        }
        for _ in 0..clips_pushed {
            scene.pop_layer();
        }
    }

    fn push_scroll_clips<S: PaintScene>(&self, scene: &mut S, node_id: u64) -> usize {
        let chain = scroll_ancestor_chain(&self.frame.scroll_nodes, node_id);
        let (mut cum_sx, mut cum_sy) = (0.0f32, 0.0f32);
        let mut pushed = 0usize;
        for &nid in &chain {
            let Some(node) = self.frame.scroll_nodes.iter().find(|n| n.node_id == nid) else {
                continue;
            };
            let clip_affine =
                self.view_affine * Affine::translate((-cum_sx as f64, -cum_sy as f64));
            let clip_rect = Rect::new(
                node.clip.x as f64,
                node.clip.y as f64,
                node.clip.right() as f64,
                node.clip.bottom() as f64,
            );
            scene.push_clip_layer(Fill::NonZero, clip_affine, &clip_rect);
            pushed += 1;
            let (sx, sy) = self.compositor.scroll_offset(nid);
            cum_sx += sx;
            cum_sy += sy;
        }
        pushed
    }

    fn paint_layer_bg_and_tiles<S: PaintScene>(
        &mut self,
        scene: &mut S,
        layer: &LayerV2,
        anim_affine: Affine,
        ox: f32,
        oy: f32,
        vp_bounds: RectV2,
    ) {
        let post_anim = anim_affine * Affine::translate((ox as f64, oy as f64));
        let layer_affine = self.view_affine * post_anim;
        if layer.bg_rgba[3] > 0 {
            let r = Rect::new(
                layer.bounds.x as f64,
                layer.bounds.y as f64,
                layer.bounds.right() as f64,
                layer.bounds.bottom() as f64,
            );
            scene.fill(
                Fill::NonZero,
                layer_affine,
                Color::from_rgba8(
                    layer.bg_rgba[0],
                    layer.bg_rgba[1],
                    layer.bg_rgba[2],
                    layer.bg_rgba[3],
                ),
                None,
                &r,
            );
        }
        for tr in &layer.tile_refs {
            let world_bounds = transform_rect_v2(post_anim, tr.bounds);
            if !world_bounds.intersects(vp_bounds) {
                continue;
            }
            *self.visible_count += 1;
            let tile_affine =
                layer_affine * Affine::translate((tr.bounds.x as f64, tr.bounds.y as f64));
            if let Some(tile) = self.compositor.tile_cache.get(&tr.content_hash) {
                paint_tile_vectors(scene, tile, self.store, tile_affine);
            } else {
                *self.checker_count += 1;
                paint_checkerboard(scene, tile_affine, tr.bounds.w, tr.bounds.h);
            }
        }
    }

    fn paint_selection<S: PaintScene>(&mut self, scene: &mut S) {
        let sel_color = Color::from_rgba8(59, 130, 246, 96);
        for q in &self.compositor.active_selection.quads {
            let r = Rect::new(q.x as f64, q.y as f64, q.right() as f64, q.bottom() as f64);
            scene.fill(Fill::NonZero, self.view_affine, sel_color, None, &r);
        }
        if let Some(c) = self.compositor.active_selection.caret {
            let r = Rect::new(c.x as f64, c.y as f64, c.right() as f64, c.bottom() as f64);
            scene.fill(
                Fill::NonZero,
                self.view_affine,
                Color::from_rgba8(15, 23, 42, 255),
                None,
                &r,
            );
        }
    }

    fn resolve_echo_font(&self, spec: &EditableEchoSpecV2) -> Option<FontData> {
        if spec.font_hash != 0 {
            if let Some(f) = self.compositor.echo_fonts.get(&spec.font_hash) {
                return Some(f.clone());
            }
            if let Some(f) = self.store.font(spec.font_hash) {
                return Some(f.clone());
            }
        }
        let fallback_key = echo_font_key(spec);
        if let Some(f) = self.compositor.echo_fonts.get(&fallback_key) {
            return Some(f.clone());
        }
        if !spec.font_data.is_empty()
            && skrifa::FontRef::from_index(&spec.font_data, spec.font_index).is_ok()
        {
            return Some(FontData::new(
                Blob::from(spec.font_data.clone()),
                spec.font_index,
            ));
        }
        None
    }

    fn echo_layer_transform(&self, spec: &EditableEchoSpecV2) -> (Affine, bool) {
        let matching = self
            .frame
            .layers
            .iter()
            .find(|l| l.scroll_node_id == spec.scroll_node_id && l.bounds.intersects(spec.rect))
            .or_else(|| {
                self.frame
                    .layers
                    .iter()
                    .find(|l| l.scroll_node_id == spec.scroll_node_id)
            });
        if let Some(layer) = matching {
            let (_, anim_affine) = eval_layer_state(layer, self.t_ms);
            let (ox, oy) = self.compositor.layer_scroll_offset(self.frame, layer);
            let is_fixed = matches!(layer.kind, LayerKindV2::Fixed { .. });
            let affine = self.view_affine * anim_affine * Affine::translate((ox as f64, oy as f64));
            return (affine, is_fixed);
        }
        let (sx, sy) = self.compositor.scroll_offset(spec.scroll_node_id);
        let (ax, ay) = self
            .compositor
            .ancestor_scroll_offset(self.frame, spec.scroll_node_id);
        let affine = self.view_affine * Affine::translate(((-sx - ax) as f64, (-sy - ay) as f64));
        (affine, false)
    }

    fn paint_echo<S: PaintScene>(&mut self, scene: &mut S) {
        for spec in &self.frame.editable_specs {
            let Some(st) = self.compositor.echo_nodes.get(&spec.node_id) else {
                continue;
            };
            if st.pending.is_empty() {
                continue;
            }
            let (echo_affine, is_fixed) = self.echo_layer_transform(spec);
            let clips_pushed = if is_fixed {
                0
            } else {
                self.push_scroll_clips(scene, spec.scroll_node_id)
            };
            let color = Color::from_rgba8(
                spec.color_rgba[0],
                spec.color_rgba[1],
                spec.color_rgba[2],
                spec.color_rgba[3],
            );
            let font_opt = if spec.is_password {
                None
            } else {
                self.resolve_echo_font(spec)
            };
            paint_echo_entries(scene, spec, st, echo_affine, color, font_opt.as_ref());
            for _ in 0..clips_pushed {
                scene.pop_layer();
            }
        }
    }
}

fn paint_echo_entries<S: PaintScene>(
    scene: &mut S,
    spec: &EditableEchoSpecV2,
    st: &NodeEchoState,
    echo_affine: Affine,
    color: Color,
    font_opt: Option<&FontData>,
) {
    let baseline_y = if spec.baseline_y.is_finite() && spec.baseline_y != 0.0 {
        spec.baseline_y
    } else {
        spec.caret_y + spec.caret_height * 0.78
    };
    if spec.is_password {
        for entry in &st.pending {
            let r = (spec.font_size * 0.18).max(2.0) as f64;
            let cy = (spec.caret_y + spec.caret_height * 0.5) as f64;
            let cx = (entry.x + entry.advance_px * 0.5) as f64;
            scene.fill(
                Fill::NonZero,
                echo_affine,
                color,
                None,
                &Circle::new((cx, cy), r),
            );
        }
    } else if let Some(font) = font_opt {
        let glyphs: Vec<AnyGlyph> = st
            .pending
            .iter()
            .map(|entry| AnyGlyph {
                id: entry.glyph_id as u32,
                x: entry.x,
                y: baseline_y,
            })
            .collect();
        if !glyphs.is_empty() {
            scene.draw_glyphs(
                font,
                spec.font_size,
                true,
                &[],
                Vec2::ZERO,
                Fill::NonZero,
                color,
                1.0,
                echo_affine,
                None,
                glyphs.into_iter(),
            );
        }
    }
    let total_adv: f32 = st.pending.iter().map(|e| e.advance_px).sum();
    let caret = Rect::new(
        (spec.caret_x + total_adv) as f64,
        spec.caret_y as f64,
        (spec.caret_x + total_adv + 1.5) as f64,
        (spec.caret_y + spec.caret_height) as f64,
    );
    scene.fill(Fill::NonZero, echo_affine, color, None, &caret);
}

struct TransformedPaintScene<'a, S: PaintScene> {
    inner: &'a mut S,
    base: Affine,
}

impl<S: PaintScene> anyrender::RenderContext for TransformedPaintScene<'_, S> {}

impl<S: PaintScene> PaintScene for TransformedPaintScene<'_, S> {
    fn reset(&mut self) {}

    fn push_layer(
        &mut self,
        fill: Fill,
        blend: impl Into<BlendMode>,
        alpha: f32,
        transform: Affine,
        clip: &impl Shape,
        filter: Option<Arc<anyrender::Filter>>,
        backdrop_filter: Option<Arc<anyrender::Filter>>,
    ) {
        self.inner.push_layer(
            fill,
            blend,
            alpha,
            self.base * transform,
            clip,
            filter,
            backdrop_filter,
        );
    }

    fn push_clip_layer(&mut self, fill: Fill, transform: Affine, clip: &impl Shape) {
        self.inner
            .push_clip_layer(fill, self.base * transform, clip);
    }

    fn push_clip_path(&mut self, fill: Fill, transform: Affine, clip: &impl Shape) {
        self.inner.push_clip_path(fill, self.base * transform, clip);
    }

    fn pop_layer(&mut self) {
        self.inner.pop_layer();
    }

    fn pop_clip_path(&mut self) {
        self.inner.pop_clip_path();
    }

    fn stroke<'p>(
        &mut self,
        style: &Stroke,
        transform: Affine,
        brush: impl Into<PaintRef<'p>>,
        brush_transform: Option<Affine>,
        shape: &impl Shape,
    ) {
        self.inner
            .stroke(style, self.base * transform, brush, brush_transform, shape);
    }

    fn fill<'p>(
        &mut self,
        style: Fill,
        transform: Affine,
        brush: impl Into<PaintRef<'p>>,
        brush_transform: Option<Affine>,
        shape: &impl Shape,
    ) {
        self.inner
            .fill(style, self.base * transform, brush, brush_transform, shape);
    }

    fn draw_glyphs<'p, 's: 'p>(
        &'s mut self,
        font: &'p FontData,
        font_size: f32,
        hint: bool,
        normalized_coords: &'p [NormalizedCoord],
        embolden: Vec2,
        style: impl Into<StyleRef<'p>>,
        brush: impl Into<PaintRef<'p>>,
        brush_alpha: f32,
        transform: Affine,
        glyph_transform: Option<Affine>,
        glyphs: impl Iterator<Item = AnyGlyph> + Clone,
    ) {
        self.inner.draw_glyphs(
            font,
            font_size,
            hint,
            normalized_coords,
            embolden,
            style,
            brush,
            brush_alpha,
            self.base * transform,
            glyph_transform,
            glyphs,
        );
    }

    fn draw_box_shadow(
        &mut self,
        transform: Affine,
        rect: Rect,
        brush: Color,
        radius: f64,
        std_dev: f64,
    ) {
        self.inner
            .draw_box_shadow(self.base * transform, rect, brush, radius, std_dev);
    }
}

fn paint_tile_vectors<S: PaintScene>(
    scene: &mut S,
    tile: &TilePayloadV2,
    store: &ResourceStore,
    tile_affine: Affine,
) {
    if tile.vector_ops.starts_with(&KSC2_MAGIC) {
        return;
    }
    if tile.vector_ops.starts_with(b"KSC0") {
        let mut wrapped = TransformedPaintScene {
            inner: scene,
            base: tile_affine,
        };
        let _ = replay_into(&tile.vector_ops, store, &mut wrapped);
        return;
    }
    let Ok(ops) = decode_vector_ops_v2(&tile.vector_ops) else {
        return;
    };
    for op in ops {
        paint_vector_op(scene, tile_affine, &op);
    }
}

fn paint_vector_op<S: PaintScene>(scene: &mut S, transform: Affine, op: &VectorOpV2) {
    match op {
        VectorOpV2::FillRect { rect, rgba, radius } => {
            let color = Color::from_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            if *radius > 0.0 {
                let rr = RoundedRect::new(
                    rect.x as f64,
                    rect.y as f64,
                    rect.right() as f64,
                    rect.bottom() as f64,
                    *radius as f64,
                );
                scene.fill(Fill::NonZero, transform, color, None, &rr);
            } else {
                let r = Rect::new(
                    rect.x as f64,
                    rect.y as f64,
                    rect.right() as f64,
                    rect.bottom() as f64,
                );
                scene.fill(Fill::NonZero, transform, color, None, &r);
            }
        }
        VectorOpV2::StrokeLine {
            x0,
            y0,
            x1,
            y1,
            width,
            rgba,
        } => {
            let color = Color::from_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            let stroke = Stroke::new(*width as f64);
            let line = Line::new((*x0 as f64, *y0 as f64), (*x1 as f64, *y1 as f64));
            scene.stroke(&stroke, transform, color, None, &line);
        }
        VectorOpV2::FillCircle { cx, cy, r, rgba } => {
            let color = Color::from_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            let circle = Circle::new((*cx as f64, *cy as f64), *r as f64);
            scene.fill(Fill::NonZero, transform, color, None, &circle);
        }
        VectorOpV2::FillCubicShape { points, rgba } => {
            if points.len() < 3 {
                return;
            }
            let color = Color::from_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            let mut path = BezPath::new();
            path.move_to((points[0][0] as f64, points[0][1] as f64));
            let mut idx = 1usize;
            while idx + 2 < points.len() {
                path.curve_to(
                    (points[idx][0] as f64, points[idx][1] as f64),
                    (points[idx + 1][0] as f64, points[idx + 1][1] as f64),
                    (points[idx + 2][0] as f64, points[idx + 2][1] as f64),
                );
                idx += 3;
            }
            while idx < points.len() {
                path.line_to((points[idx][0] as f64, points[idx][1] as f64));
                idx += 1;
            }
            path.close_path();
            scene.fill(Fill::NonZero, transform, color, None, &path);
        }
    }
}

fn paint_checkerboard<S: PaintScene>(scene: &mut S, transform: Affine, w: f32, h: f32) {
    let light = Color::from_rgba8(242, 242, 242, 255);
    let dark = Color::from_rgba8(224, 224, 224, 255);
    let cell = 16.0f32;
    scene.fill(
        Fill::NonZero,
        transform,
        light,
        None,
        &Rect::new(0.0, 0.0, w as f64, h as f64),
    );
    let cols = (w / cell).ceil().max(0.0) as u32;
    let rows = (h / cell).ceil().max(0.0) as u32;
    for r in 0..rows {
        let y0 = (r as f32 * cell) as f64;
        let y1 = ((r as f32 + 1.0) * cell).min(h) as f64;
        for c in 0..cols {
            if (r + c) % 2 == 0 {
                continue;
            }
            let x0 = (c as f32 * cell) as f64;
            let x1 = ((c as f32 + 1.0) * cell).min(w) as f64;
            scene.fill(
                Fill::NonZero,
                transform,
                dark,
                None,
                &Rect::new(x0, y0, x1, y1),
            );
        }
    }
}

fn has_blocking_handler(regions: &[HandlerRegionV2], input: ScrollInputV2) -> bool {
    for region in regions {
        if !region.non_passive {
            continue;
        }
        if (region.event_mask & input.event_mask) == 0 {
            continue;
        }
        if region.rect.contains_point(input.pt_x, input.pt_y) {
            return true;
        }
    }
    false
}

fn resolve_scroll_node_id(nodes: &[ScrollNodeV2], requested: u64) -> u64 {
    if nodes.iter().any(|n| n.node_id == requested) {
        return requested;
    }
    nodes.first().map(|n| n.node_id).unwrap_or(requested)
}

fn scroll_ancestor_chain(nodes: &[ScrollNodeV2], target_id: u64) -> Vec<u64> {
    let mut rev = Vec::new();
    let mut cur = target_id;
    for _ in 0..64 {
        let Some(node) = nodes.iter().find(|n| n.node_id == cur) else {
            break;
        };
        if rev.contains(&cur) {
            break;
        }
        rev.push(cur);
        if node.parent_id == cur || !nodes.iter().any(|n| n.node_id == node.parent_id) {
            break;
        }
        cur = node.parent_id;
    }
    rev.reverse();
    rev
}

fn collect_scroll_chain_nodes(nodes: &[ScrollNodeV2], target_id: u64) -> Vec<ScrollNodeV2> {
    let chain = scroll_ancestor_chain(nodes, target_id);
    let mut leaf_to_root = Vec::with_capacity(chain.len());
    for &nid in chain.iter().rev() {
        if let Some(n) = nodes.iter().find(|s| s.node_id == nid) {
            leaf_to_root.push(n.clone());
        }
    }
    leaf_to_root
}

fn next_chain_delta(rem: f32, applied: f32, behavior: OverscrollBehaviorV2) -> f32 {
    if behavior == OverscrollBehaviorV2::Auto {
        rem - applied
    } else {
        0.0
    }
}

fn echo_font_key(spec: &EditableEchoSpecV2) -> u64 {
    if spec.font_hash != 0 {
        return spec.font_hash;
    }
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ (spec.font_index as u64);
    for &b in &spec.font_data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn cache_echo_font(cache: &mut HashMap<u64, FontData>, spec: &EditableEchoSpecV2) {
    if spec.font_data.is_empty() {
        return;
    }
    if skrifa::FontRef::from_index(&spec.font_data, spec.font_index).is_err() {
        return;
    }
    let key = echo_font_key(spec);
    if cache.len() >= 64 && !cache.contains_key(&key) {
        cache.clear();
    }
    cache.insert(
        key,
        FontData::new(Blob::from(spec.font_data.clone()), spec.font_index),
    );
}

fn clamp_scroll_offset(node: &ScrollNodeV2, x: f32, y: f32) -> (f32, f32) {
    let max_x = (node.extent_w - node.clip.w).max(0.0);
    let max_y = (node.extent_h - node.clip.h).max(0.0);
    let nx = if x.is_finite() {
        x.clamp(0.0, max_x)
    } else {
        0.0
    };
    let ny = if y.is_finite() {
        y.clamp(0.0, max_y)
    } else {
        0.0
    };
    (nx, ny)
}

fn snap_axis(offset: f32, snap_points: &[f32]) -> f32 {
    let mut best = offset;
    let mut best_dist = SNAP_SETTLE_MAX_DIST_PX;
    for &p in snap_points {
        let d = (p - offset).abs();
        if d <= best_dist {
            best_dist = d;
            best = p;
        }
    }
    best
}

fn compute_layer_offset(layer: &LayerV2, sx: f32, sy: f32, clip: RectV2) -> (f32, f32) {
    match &layer.kind {
        LayerKindV2::Normal => (-sx, -sy),
        LayerKindV2::Fixed { viewport_anchor } => (
            viewport_anchor.x - layer.bounds.x,
            viewport_anchor.y - layer.bounds.y,
        ),
        LayerKindV2::Sticky {
            static_rect,
            constraint_rect,
            top_inset,
            right_inset,
            bottom_inset,
            left_inset,
        } => {
            let dx = sticky_axis_shift(
                static_rect.x,
                static_rect.w,
                constraint_rect.x,
                constraint_rect.w,
                sx,
                clip.w,
                *left_inset,
                *right_inset,
            );
            let dy = sticky_axis_shift(
                static_rect.y,
                static_rect.h,
                constraint_rect.y,
                constraint_rect.h,
                sy,
                clip.h,
                *top_inset,
                *bottom_inset,
            );
            (-sx + dx, -sy + dy)
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Sticky solver axis inputs map directly to CSS sticky box and constraint rects."
)]
fn sticky_axis_shift(
    box_start: f32,
    box_size: f32,
    cb_start: f32,
    cb_size: f32,
    scroll_pos: f32,
    scrollport_size: f32,
    start_inset: Option<f32>,
    mut end_inset: Option<f32>,
) -> f32 {
    let box_end = box_start + box_size;
    let cb_end = cb_start + cb_size;
    if let (Some(s), Some(e)) = (start_inset, end_inset) {
        if scrollport_size - s - e < box_size {
            end_inset = Some((scrollport_size - s - box_size).min(e));
        }
    }
    let mut shift = 0.0f32;
    if let Some(start_off) = start_inset {
        let limit_start = scroll_pos + start_off;
        shift = (limit_start - box_start).max(0.0);
    }
    if shift == 0.0 {
        if let Some(end_off) = end_inset {
            let limit_end = scroll_pos + scrollport_size - end_off;
            shift = (limit_end - box_end).min(0.0);
        }
    }
    let max_up = (cb_start - box_start).min(0.0);
    let max_down = (cb_end - box_end).max(0.0);
    shift.clamp(max_up, max_down)
}

fn eval_layer_state(layer: &LayerV2, t_ms: f64) -> (f32, Affine) {
    let mut opacity = layer.opacity.clamp(0.0, 1.0);
    let m = layer.transform;
    let mut matrix = [
        m[0] as f64,
        m[1] as f64,
        m[2] as f64,
        m[3] as f64,
        m[4] as f64,
        m[5] as f64,
    ];
    for curve in &layer.animations {
        let Some(p) = animation_progress(curve, t_ms) else {
            continue;
        };
        match (curve.property, sample_keyframes(&curve.keyframes, p)) {
            (AnimationPropertyV2::Opacity, Some(KeyframeValueV2::Scalar(a))) => {
                opacity = a.clamp(0.0, 1.0);
            }
            (AnimationPropertyV2::Transform, Some(KeyframeValueV2::Transform(arr))) => {
                matrix = [
                    arr[0] as f64,
                    arr[1] as f64,
                    arr[2] as f64,
                    arr[3] as f64,
                    arr[4] as f64,
                    arr[5] as f64,
                ];
            }
            _ => {}
        }
    }
    (opacity, Affine::new(matrix))
}

fn animation_progress(curve: &AnimationCurveV2, t_ms: f64) -> Option<f32> {
    if curve.keyframes.is_empty() || curve.duration_ms <= 0.0 || t_ms < curve.start_ms {
        return None;
    }
    let elapsed = t_ms - curve.start_ms;
    let raw_iter = elapsed / curve.duration_ms;
    if curve.iterations.is_finite() && curve.iterations > 0.0 && raw_iter >= curve.iterations as f64
    {
        return if curve.fill_forwards { Some(1.0) } else { None };
    }
    let frac = raw_iter.fract();
    if raw_iter > 0.0 && frac == 0.0 {
        Some(1.0)
    } else {
        Some((frac as f32).clamp(0.0, 1.0))
    }
}

fn sample_keyframes(kfs: &[KeyframeV2], progress: f32) -> Option<KeyframeValueV2> {
    if kfs.is_empty() {
        return None;
    }
    if progress <= kfs[0].offset {
        return Some(kfs[0].value);
    }
    for win in kfs.windows(2) {
        let (a, b) = (&win[0], &win[1]);
        if progress > b.offset {
            continue;
        }
        let span = (b.offset - a.offset).max(1e-6);
        let local_t = ((progress - a.offset) / span).clamp(0.0, 1.0);
        let eased = apply_easing(a.easing, local_t);
        return Some(interpolate_kf(a.value, b.value, eased));
    }
    kfs.last().map(|k| k.value)
}

fn apply_easing(easing: EasingV2, t: f32) -> f32 {
    match easing {
        EasingV2::Linear => t,
        EasingV2::StepEnd => {
            if t >= 1.0 {
                1.0
            } else {
                0.0
            }
        }
        EasingV2::CubicBezier { x1, y1, x2, y2 } => solve_cubic_bezier(x1, y1, x2, y2, t),
    }
}

fn solve_cubic_bezier(x1: f32, y1: f32, x2: f32, y2: f32, x: f32) -> f32 {
    let mut u = x.clamp(0.0, 1.0);
    for _ in 0..8 {
        let cur_x = bezier_sample(x1, x2, u) - x;
        let dx = bezier_deriv(x1, x2, u);
        if cur_x.abs() < 1e-5 || dx.abs() < 1e-5 {
            break;
        }
        u = (u - cur_x / dx).clamp(0.0, 1.0);
    }
    bezier_sample(y1, y2, u)
}

fn bezier_sample(p1: f32, p2: f32, u: f32) -> f32 {
    let v = 1.0 - u;
    3.0 * v * v * u * p1 + 3.0 * v * u * u * p2 + u * u * u
}

fn bezier_deriv(p1: f32, p2: f32, u: f32) -> f32 {
    let v = 1.0 - u;
    3.0 * v * v * p1 + 6.0 * v * u * (p2 - p1) + 3.0 * u * u * (1.0 - p2)
}

fn interpolate_kf(a: KeyframeValueV2, b: KeyframeValueV2, t: f32) -> KeyframeValueV2 {
    match (a, b) {
        (KeyframeValueV2::Scalar(x), KeyframeValueV2::Scalar(y)) => {
            KeyframeValueV2::Scalar(x + (y - x) * t)
        }
        (KeyframeValueV2::Transform(m1), KeyframeValueV2::Transform(m2)) => {
            let mut out = [0.0f32; 6];
            for i in 0..6 {
                out[i] = m1[i] + (m2[i] - m1[i]) * t;
            }
            KeyframeValueV2::Transform(out)
        }
        _ => a,
    }
}

fn order_points(a: Point, b: Point) -> (Point, Point) {
    if (a.y, a.x) <= (b.y, b.x) {
        (a, b)
    } else {
        (b, a)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Tile text selection aggregates runs and transforms quads into viewport space."
)]
fn collect_tile_selection(
    tile: &TilePayloadV2,
    tile_bounds: RectV2,
    layer_affine: Affine,
    start: Point,
    end: Point,
    selected: &mut String,
    quads: &mut Vec<RectV2>,
    caret: &mut Option<RectV2>,
) {
    let tile_affine =
        layer_affine * Affine::translate((tile_bounds.x as f64, tile_bounds.y as f64));
    let ls = Point::new(
        start.x - tile_bounds.x as f64,
        start.y - tile_bounds.y as f64,
    );
    let le = Point::new(end.x - tile_bounds.x as f64, end.y - tile_bounds.y as f64);
    for run in &tile.text_runs {
        collect_run_selection(run, tile_affine, ls, le, selected, quads, caret);
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Run selection scans ordered glyph clusters and updates selection output."
)]
fn collect_run_selection(
    run: &TextRunMapV2,
    tile_affine: Affine,
    start: Point,
    end: Point,
    selected: &mut String,
    quads: &mut Vec<RectV2>,
    caret: &mut Option<RectV2>,
) {
    let run_top = (run.origin_y - run.ascent) as f64;
    let run_bottom = (run.origin_y + run.descent) as f64;
    if end.y < run_top || start.y > run_bottom {
        return;
    }
    let min_x = if start.y >= run_top && start.y <= run_bottom {
        start.x as f32
    } else {
        f32::NEG_INFINITY
    };
    let max_x = if end.y >= run_top && end.y <= run_bottom {
        end.x as f32
    } else {
        f32::INFINITY
    };
    for c in &run.cluster_advances {
        let mid_x = c.x + c.width * 0.5;
        if mid_x < min_x || mid_x > max_x {
            continue;
        }
        let b0 = c.byte_start as usize;
        let b1 = (c.byte_start + c.byte_len) as usize;
        if let Some(slice) = run.text.get(b0..b1) {
            selected.push_str(slice);
        }
        let q = transform_rect_v2(tile_affine, c.selection_bounds);
        quads.push(q);
        *caret = Some(RectV2::new(q.right(), q.y, 1.5, q.h.max(1.0)));
    }
    if caret.is_none() && (start.x - end.x).abs() < 2.0 {
        let r = transform_rect_v2(
            tile_affine,
            RectV2::new(
                end.x as f32,
                run.origin_y - run.ascent,
                1.5,
                (run.ascent + run.descent).max(1.0),
            ),
        );
        *caret = Some(r);
    }
}

fn transform_rect_v2(a: Affine, r: RectV2) -> RectV2 {
    let pts = [
        a * Point::new(r.x as f64, r.y as f64),
        a * Point::new(r.right() as f64, r.y as f64),
        a * Point::new(r.right() as f64, r.bottom() as f64),
        a * Point::new(r.x as f64, r.bottom() as f64),
    ];
    let x0 = pts.iter().map(|p| p.x).fold(f64::INFINITY, f64::min) as f32;
    let y0 = pts.iter().map(|p| p.y).fold(f64::INFINITY, f64::min) as f32;
    let x1 = pts.iter().map(|p| p.x).fold(f64::NEG_INFINITY, f64::max) as f32;
    let y1 = pts.iter().map(|p| p.y).fold(f64::NEG_INFINITY, f64::max) as f32;
    RectV2::new(x0, y0, (x1 - x0).max(0.0), (y1 - y0).max(0.0))
}

fn echo_block_reason(spec: &EditableEchoSpecV2, state: &NodeEchoState) -> Option<SuppressReasonV2> {
    if spec.complex_shaping {
        return Some(SuppressReasonV2::ComplexShaping);
    }
    if spec.has_ligatures {
        return Some(SuppressReasonV2::Ligatures);
    }
    if state.suppressed || state.mispredictions >= MISPREDICTION_SUPPRESS_THRESHOLD {
        return Some(SuppressReasonV2::MispredictionLimit);
    }
    if spec.upem == 0 || spec.font_size <= 0.0 {
        return Some(SuppressReasonV2::UnsupportedCharOrFont);
    }
    if !spec.is_password && spec.font_hash == 0 && spec.font_data.is_empty() {
        return Some(SuppressReasonV2::UnsupportedCharOrFont);
    }
    None
}

fn suppressed_predict(reason: SuppressReasonV2, caret_x: f32, caret_y: f32) -> PredictResultV2 {
    PredictResultV2 {
        suppressed: true,
        reason,
        is_bullet: false,
        caret_x,
        caret_y,
        predicted_advance_px: 0.0,
        glyph_ids: Vec::new(),
    }
}

fn build_echo_entries(
    spec: &EditableEchoSpecV2,
    input_seq: u32,
    text: &str,
    start_x: f32,
) -> Option<(Vec<PendingEchoChar>, Vec<u16>, f32)> {
    let mut entries = Vec::new();
    let mut gids = Vec::new();
    let mut cur_x = start_x;
    let scale = spec.font_size / spec.upem as f32;
    for ch in text.chars() {
        if is_combining_or_bidi_complex(ch) {
            return None;
        }
        let target_cp = if spec.is_password {
            '\u{2022}' as u32
        } else {
            ch as u32
        };
        let gid = lookup_cmap_gid(&spec.cmap, target_cp)?;
        let raw_adv = *spec.advances.get(gid as usize)?;
        let adv_px = raw_adv as f32 * scale;
        entries.push(PendingEchoChar {
            seq: input_seq,
            codepoint: ch as u32,
            glyph_id: gid,
            displayed: if spec.is_password { '\u{2022}' } else { ch },
            x: cur_x,
            advance_px: adv_px,
        });
        gids.push(gid);
        cur_x += adv_px;
    }
    Some((entries, gids, cur_x - start_x))
}

fn is_combining_or_bidi_complex(ch: char) -> bool {
    let u = ch as u32;
    (0x0300..=0x036F).contains(&u)
        || (0x0590..=0x08FF).contains(&u)
        || (0x0900..=0x0DFF).contains(&u)
}

fn lookup_cmap_gid(cmap: &[(u32, u16)], cp: u32) -> Option<u16> {
    cmap.iter().find(|&&(c, _)| c == cp).map(|&(_, gid)| gid)
}

pub fn build_checkerboard_ratio(stats: CompositeStatsV2) -> f32 {
    if stats.total_visible_tiles == 0 {
        return 0.0;
    }
    stats.checkerboard_tiles as f32 / stats.total_visible_tiles as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use crate::paint::scene_v2::{
        compute_interest_rect, encode_vector_ops_v2, ClusterAdvanceV2, HitRectMapV2,
        ServerDrivenReasonV2, TileRefV2, HANDLER_WHEEL,
    };

    const TEST_FONT_BYTES: &[u8] = include_bytes!("../../../engine/public/fonts/NotoSans.ttf");

    fn build_real_font_spec(
        node_id: u64,
        scroll_node_id: u64,
        caret_x: f32,
        caret_y: f32,
    ) -> EditableEchoSpecV2 {
        use skrifa::raw::TableProvider;
        use skrifa::MetadataProvider;
        let font = skrifa::FontRef::from_index(TEST_FONT_BYTES, 0).expect("NotoSans font");
        let upem = font.head().map(|h| h.units_per_em()).unwrap_or(1000);
        let charmap = font.charmap();
        let hmtx = font.hmtx().expect("hmtx");
        let num_glyphs = font.maxp().map(|m| m.num_glyphs()).unwrap_or(256).min(1024);
        let mut advances = Vec::with_capacity(num_glyphs as usize);
        for gid in 0..num_glyphs {
            advances.push(hmtx.advance(skrifa::GlyphId::from(gid)).unwrap_or(0));
        }
        let mut cmap = Vec::new();
        for ch in ' '..='~' {
            if let Some(gid) = charmap.map(ch) {
                if (gid.to_u32() as usize) < advances.len() {
                    cmap.push((ch as u32, gid.to_u32() as u16));
                }
            }
        }
        EditableEchoSpecV2 {
            node_id,
            scroll_node_id,
            field_key: format!("input#{node_id}"),
            auth_text: String::new(),
            rect: RectV2::new(caret_x - 2.0, caret_y - 2.0, 200.0, 32.0),
            is_password: false,
            complex_shaping: false,
            has_ligatures: false,
            font_size: 16.0,
            upem,
            color_rgba: [10, 10, 10, 255],
            caret_x,
            caret_y,
            caret_height: 18.0,
            baseline_y: caret_y + 14.0,
            font_hash: 0x5555_6666,
            font_index: 0,
            font_data: TEST_FONT_BYTES.to_vec(),
            cmap,
            advances,
        }
    }

    fn make_tile(hash: u64, color: [u8; 4], hit_rect: Option<HitRectMapV2>) -> TilePayloadV2 {
        let vector_ops = encode_vector_ops_v2(&[
            VectorOpV2::FillRect {
                rect: RectV2::new(0.0, 0.0, 256.0, 256.0),
                rgba: color,
                radius: 0.0,
            },
            VectorOpV2::FillCubicShape {
                points: vec![
                    [20.0, 20.0],
                    [90.0, 10.0],
                    [160.0, 80.0],
                    [200.0, 200.0],
                    [120.0, 220.0],
                    [40.0, 180.0],
                    [10.0, 90.0],
                ],
                rgba: [15, 25, 45, 255],
            },
        ]);
        TilePayloadV2 {
            content_hash: hash,
            width: 256,
            height: 256,
            vector_ops,
            text_runs: vec![TextRunMapV2 {
                node_id: 90,
                text: "Copy café UTF8".into(),
                font_hash: 1,
                font_size: 16.0,
                rtl: false,
                origin_x: 10.0,
                origin_y: 30.0,
                ascent: 14.0,
                descent: 4.0,
                cluster_advances: vec![
                    ClusterAdvanceV2 {
                        byte_start: 0,
                        byte_len: 5,
                        x: 10.0,
                        width: 40.0,
                        selection_bounds: RectV2::new(10.0, 16.0, 40.0, 18.0),
                    },
                    ClusterAdvanceV2 {
                        byte_start: 5,
                        byte_len: 5,
                        x: 50.0,
                        width: 40.0,
                        selection_bounds: RectV2::new(50.0, 16.0, 40.0, 18.0),
                    },
                ],
            }],
            hit_rects: hit_rect.into_iter().collect(),
        }
    }

    fn scrollable_frame(rows: u32, with_tiles: bool) -> SceneFrameV2 {
        let mut tile_refs = Vec::new();
        let mut tiles = Vec::new();
        for r in 0..rows {
            let hash = 1000 + r as u64;
            tile_refs.push(TileRefV2 {
                col: 0,
                row: r,
                bounds: RectV2::new(0.0, (r * 256) as f32, 256.0, 256.0),
                content_hash: hash,
            });
            if with_tiles {
                let hit = HitRectMapV2 {
                    rect: RectV2::new(10.0, 10.0, 100.0, 30.0),
                    node_id: 500 + r as u64,
                    scroll_node_id: 1,
                    cursor: CursorKindV2::Pointer,
                    link_url: Some("https://parawing.test/".into()),
                    editable: false,
                    hover_or_pointer: r % 2 == 0,
                };
                tiles.push(make_tile(hash, [(r * 30) as u8, 120, 200, 255], Some(hit)));
            }
        }
        SceneFrameV2 {
            acked_scroll_seq: 0,
            acked_input_seq: 0,
            viewport_w: 256,
            viewport_h: 512,
            scroll_nodes: vec![ScrollNodeV2 {
                node_id: 1,
                parent_id: 0,
                extent_w: 256.0,
                extent_h: (rows * 256) as f32,
                clip: RectV2::new(0.0, 0.0, 256.0, 512.0),
                auth_offset_x: 0.0,
                auth_offset_y: 0.0,
                snap_points_x: Vec::new(),
                snap_points_y: vec![0.0, 512.0, 1024.0],
                overscroll_x: OverscrollBehaviorV2::Contain,
                overscroll_y: OverscrollBehaviorV2::Contain,
                server_driven: false,
                server_driven_reason: ServerDrivenReasonV2::None,
            }],
            layers: vec![LayerV2 {
                layer_id: 1,
                scroll_node_id: 1,
                kind: LayerKindV2::Normal,
                bounds: RectV2::new(0.0, 0.0, 256.0, (rows * 256) as f32),
                bg_rgba: [255, 255, 255, 255],
                opacity: 1.0,
                transform: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
                animations: Vec::new(),
                tile_size: 256,
                tile_refs,
                invalidated_hashes: Vec::new(),
            }],
            tiles,
            handler_regions: vec![HandlerRegionV2 {
                rect: RectV2::new(180.0, 180.0, 60.0, 60.0),
                scroll_node_id: 1,
                event_mask: HANDLER_WHEEL,
                non_passive: true,
            }],
            editable_specs: vec![
                EditableEchoSpecV2 {
                    node_id: 10,
                    scroll_node_id: 1,
                    field_key: "search".into(),
                    auth_text: String::new(),
                    rect: RectV2::new(10.0, 10.0, 200.0, 30.0),
                    is_password: false,
                    complex_shaping: false,
                    has_ligatures: false,
                    font_size: 16.0,
                    upem: 1000,
                    color_rgba: [10, 10, 10, 255],
                    caret_x: 12.0,
                    caret_y: 15.0,
                    caret_height: 18.0,
                    baseline_y: 29.0,
                    font_hash: 0x1010,
                    font_index: 0,
                    font_data: TEST_FONT_BYTES.to_vec(),
                    cmap: vec![(b'a' as u32, 1), (b'b' as u32, 2), (b'c' as u32, 3)],
                    advances: vec![0, 500, 600, 550],
                },
                EditableEchoSpecV2 {
                    node_id: 11,
                    scroll_node_id: 1,
                    field_key: "pwd".into(),
                    auth_text: String::new(),
                    rect: RectV2::new(10.0, 50.0, 200.0, 30.0),
                    is_password: true,
                    complex_shaping: false,
                    has_ligatures: false,
                    font_size: 16.0,
                    upem: 1000,
                    color_rgba: [10, 10, 10, 255],
                    caret_x: 12.0,
                    caret_y: 55.0,
                    caret_height: 18.0,
                    baseline_y: 69.0,
                    font_hash: 0,
                    font_index: 0,
                    font_data: Vec::new(),
                    cmap: vec![(0x2022, 1)],
                    advances: vec![0, 450],
                },
            ],
        }
    }

    #[test]
    fn s1_scroll_rebase_and_s2_handler_interception() {
        let mut comp = CompositorV2::new();
        comp.apply_frame(scrollable_frame(12, true));

        let blocked = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 200.0,
            pt_y: 200.0,
            dx: 0.0,
            dy: 50.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        assert_eq!(blocked, ScrollOutcomeV2::ForwardToServer);

        let local1 = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 50.0,
            pt_y: 50.0,
            dx: 0.0,
            dy: 120.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        let ScrollOutcomeV2::Local(u1) = local1 else {
            panic!("expected local scroll");
        };
        assert_eq!(u1.y, 120.0);

        // Next scroll frame acks seq=u1.seq with auth_offset_y=120, plus server bump +30.
        let mut frame2 = scrollable_frame(12, false);
        frame2.acked_scroll_seq = u1.seq;
        frame2.scroll_nodes[0].auth_offset_y = 150.0;
        comp.apply_frame(frame2);
        assert_eq!(comp.scroll_offset(1), (0.0, 150.0));
    }

    #[test]
    fn s2_sticky_solver_clamps_within_constraint_rect() {
        let mut comp = CompositorV2::new();
        let mut frame = scrollable_frame(10, true);
        let sticky = LayerV2 {
            layer_id: 2,
            scroll_node_id: 1,
            kind: LayerKindV2::Sticky {
                static_rect: RectV2::new(0.0, 100.0, 256.0, 40.0),
                constraint_rect: RectV2::new(0.0, 100.0, 256.0, 300.0),
                top_inset: Some(10.0),
                right_inset: None,
                bottom_inset: None,
                left_inset: None,
            },
            bounds: RectV2::new(0.0, 100.0, 256.0, 40.0),
            bg_rgba: [255, 0, 0, 255],
            opacity: 1.0,
            transform: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
            animations: Vec::new(),
            tile_size: 256,
            tile_refs: Vec::new(),
            invalidated_hashes: Vec::new(),
        };
        frame.layers.push(sticky.clone());
        comp.apply_frame(frame);

        let _ = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 10.0,
            pt_y: 10.0,
            dx: 0.0,
            dy: 200.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        let (_, sy) = comp.sticky_layer_shift(&sticky);
        // At scroll=200, top_inset=10 pins static top 100 to doc y=210 => shift=-200+110=-90.
        assert_eq!(100.0 + sy, 10.0);

        let _ = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 10.0,
            pt_y: 10.0,
            dx: 0.0,
            dy: 300.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        let (_, sy2) = comp.sticky_layer_shift(&sticky);
        // Max doc bottom = 400 -> max doc top = 360 -> shift = -500 + (360-100) = -240.
        assert_eq!(100.0 + sy2, -140.0);
    }

    #[test]
    fn s3_pinch_zoom_rerasterizes_vectors_and_visual_viewport() {
        let mut comp = CompositorV2::new();
        comp.apply_frame(scrollable_frame(4, true));
        let store = ResourceStore::default();
        let mut slot = None;

        let (png1, st1) = comp
            .composite_rgba(
                &store,
                &mut slot,
                CompositeOptsV2 {
                    t_ms: 0.0,
                    pinch_scale: 1.0,
                    pan_x: 0.0,
                    pan_y: 0.0,
                    raw_rgba: false,
                },
            )
            .expect("png 1x");
        assert_eq!(&png1[0..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(st1.checkerboard_tiles, 0);

        let (rgba_zoom, _) = comp
            .composite_rgba(
                &store,
                &mut slot,
                CompositeOptsV2 {
                    t_ms: 0.0,
                    pinch_scale: 2.5,
                    pan_x: 30.0,
                    pan_y: 40.0,
                    raw_rgba: true,
                },
            )
            .expect("rgba 2.5x");
        let vp = comp.visual_viewport();
        assert!((vp.scale - 2.5).abs() < 1e-4);
        assert!((vp.width - 256.0 / 2.5).abs() < 1e-3);

        let (rgba_1x, _) = comp
            .composite_rgba(
                &store,
                &mut slot,
                CompositeOptsV2 {
                    t_ms: 0.0,
                    pinch_scale: 1.0,
                    pan_x: 0.0,
                    pan_y: 0.0,
                    raw_rgba: true,
                },
            )
            .expect("rgba 1x");
        assert_ne!(rgba_zoom, rgba_1x);
    }

    #[test]
    fn s4_hit_test_selection_caret_and_utf8_copy() {
        let mut comp = CompositorV2::new();
        comp.apply_frame(scrollable_frame(4, true));

        let hit0 = comp.hit_test(25.0, 20.0, 0.0);
        assert!(hit0.hit);
        assert_eq!(hit0.cursor, CursorKindV2::Pointer);
        assert!(hit0.forward_pointer_move);
        assert_eq!(hit0.link_url.as_deref(), Some("https://parawing.test/"));

        let hit1 = comp.hit_test(25.0, 270.0, 0.0);
        assert!(hit1.hit);
        assert!(!hit1.forward_pointer_move);

        let sel = comp.select_text(15.0, 20.0, 80.0, 24.0, 0.0);
        assert_eq!(sel.text, "Copy café");
        assert_eq!(sel.quads.len(), 2);
        assert!(sel.caret.is_some());
        assert_eq!(comp.copy_selected_text(), "Copy café");
    }

    #[test]
    fn s5_predictive_echo_password_suppression_and_ack() {
        let mut comp = CompositorV2::new();
        comp.apply_frame(scrollable_frame(2, true));

        let r1 = comp.predict_key_input(10, 1, "ab");
        assert!(!r1.suppressed);
        assert!(!r1.is_bullet);
        assert!((r1.predicted_advance_px - 17.6).abs() < 0.01);

        let pwd = comp.predict_key_input(11, 2, "x");
        assert!(!pwd.suppressed);
        assert!(pwd.is_bullet);

        let (m1, sup1) = comp.reconcile_echo(10, 1, "zz");
        assert_eq!(m1, 1);
        assert!(!sup1);

        let _ = comp.predict_key_input(10, 3, "c");
        let (m2, sup2) = comp.reconcile_echo(10, 3, "yy");
        assert_eq!(m2, 2);
        assert!(sup2);
        let blocked = comp.predict_key_input(10, 4, "a");
        assert!(blocked.suppressed);
        assert_eq!(blocked.reason, SuppressReasonV2::MispredictionLimit);
    }

    #[test]
    fn s6_animations_and_simulated_100ms_rtt_fling_benchmark() {
        let mut comp = CompositorV2::new();
        let mut frame = scrollable_frame(30, false);
        frame.layers[0].animations.push(AnimationCurveV2 {
            property: AnimationPropertyV2::Opacity,
            start_ms: 0.0,
            duration_ms: 1000.0,
            iterations: 1.0,
            fill_forwards: true,
            keyframes: vec![
                KeyframeV2 {
                    offset: 0.0,
                    value: KeyframeValueV2::Scalar(0.0),
                    easing: EasingV2::Linear,
                },
                KeyframeV2 {
                    offset: 1.0,
                    value: KeyframeValueV2::Scalar(1.0),
                    easing: EasingV2::Linear,
                },
            ],
        });
        let (op_mid, _) = eval_layer_state(&frame.layers[0], 500.0);
        assert!((op_mid - 0.5).abs() < 1e-4);

        // Prefetch tiles via compute_interest_rect under 2000px/s fling.
        let all_frame = scrollable_frame(30, true);
        let mut client_known = HashSet::new();
        comp.apply_frame(frame);
        let mut total_bytes_sent = 0usize;
        let mut total_visible = 0u32;
        let mut total_checker = 0u32;
        let store = ResourceStore::default();
        let mut slot = None;

        // Prime initial viewport + overscan at t=0.
        let mut seed_frame = all_frame.clone();
        let interest0 = compute_interest_rect(RectV2::new(0.0, 0.0, 256.0, 512.0), 0.0, 2000.0);
        crate::paint::scene_v2::cull_frame_for_interest(&mut seed_frame, interest0, &client_known);
        total_bytes_sent += seed_frame.encode().len();
        for t in &seed_frame.tiles {
            client_known.insert(t.content_hash);
        }
        comp.apply_frame(seed_frame);

        let start = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 20.0,
            pt_y: 20.0,
            dx: 0.0,
            dy: 10.0,
            vx: 0.0,
            vy: 2000.0,
            event_mask: HANDLER_WHEEL,
        });
        assert!(matches!(start, ScrollOutcomeV2::Local(_)));

        // Simulate 100ms RTT: server delivers delta tiles every ~100ms (every 6 frames @ 16ms)
        // while client scrolls smoothly at 0-RTT every 16ms.
        for step in 0..30 {
            let _ = comp.step_fling(16.0);
            let (_, stats) = comp
                .composite_rgba(
                    &store,
                    &mut slot,
                    CompositeOptsV2 {
                        t_ms: step as f64 * 16.0,
                        pinch_scale: 1.0,
                        pan_x: 0.0,
                        pan_y: 0.0,
                        raw_rgba: true,
                    },
                )
                .expect("composite frame");
            total_visible += stats.total_visible_tiles;
            total_checker += stats.checkerboard_tiles;

            if step % 6 == 0 {
                let (_, sy) = comp.scroll_offset(1);
                let mut delta_frame = all_frame.clone();
                let interest =
                    compute_interest_rect(RectV2::new(0.0, sy, 256.0, 512.0), 0.0, 2000.0);
                crate::paint::scene_v2::cull_frame_for_interest(
                    &mut delta_frame,
                    interest,
                    &client_known,
                );
                total_bytes_sent += delta_frame.encode().len();
                for t in &delta_frame.tiles {
                    client_known.insert(t.content_hash);
                }
                comp.apply_frame(delta_frame);
            }
        }
        let ratio = total_checker as f32 / total_visible.max(1) as f32;
        assert!(ratio < 0.01, "checkerboard ratio too high: {ratio}");
        assert!(total_bytes_sent > 0);
    }

    #[test]
    fn s1_scroll_rebase_does_not_drop_later_deltas_when_earlier_seq_is_acked() {
        let mut comp = CompositorV2::new();
        comp.apply_frame(scrollable_frame(12, true));

        let ScrollOutcomeV2::Local(u1) = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 20.0,
            pt_y: 20.0,
            dx: 0.0,
            dy: 40.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        }) else {
            panic!("expected u1 local");
        };
        let ScrollOutcomeV2::Local(u2) = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 20.0,
            pt_y: 20.0,
            dx: 0.0,
            dy: 60.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        }) else {
            panic!("expected u2 local");
        };
        assert_ne!(u1.seq, u2.seq);
        assert_eq!(comp.scroll_offset(1), (0.0, 100.0));

        let mut ack1 = scrollable_frame(12, false);
        ack1.acked_scroll_seq = u1.seq;
        ack1.scroll_nodes[0].auth_offset_y = 40.0;
        comp.apply_frame(ack1);
        assert_eq!(comp.scroll_offset(1), (0.0, 100.0));

        let mut ack2 = scrollable_frame(12, false);
        ack2.acked_scroll_seq = u2.seq;
        ack2.scroll_nodes[0].auth_offset_y = 100.0;
        comp.apply_frame(ack2);
        assert_eq!(comp.scroll_offset(1), (0.0, 100.0));
    }

    #[test]
    fn s1_s2_scroll_tree_chaining_ancestor_offsets_and_clip() {
        let mut comp = CompositorV2::new();
        let red_tile = TilePayloadV2 {
            content_hash: 0xBEEF_0001,
            width: 300,
            height: 300,
            vector_ops: encode_vector_ops_v2(&[VectorOpV2::FillRect {
                rect: RectV2::new(0.0, 0.0, 300.0, 300.0),
                rgba: [220, 40, 40, 255],
                radius: 0.0,
            }]),
            text_runs: Vec::new(),
            hit_rects: Vec::new(),
        };
        let frame = SceneFrameV2 {
            acked_scroll_seq: 0,
            acked_input_seq: 0,
            viewport_w: 300,
            viewport_h: 300,
            scroll_nodes: vec![
                ScrollNodeV2 {
                    node_id: 1,
                    parent_id: 1,
                    extent_w: 300.0,
                    extent_h: 900.0,
                    clip: RectV2::new(0.0, 0.0, 300.0, 300.0),
                    auth_offset_x: 0.0,
                    auth_offset_y: 0.0,
                    snap_points_x: Vec::new(),
                    snap_points_y: Vec::new(),
                    overscroll_x: OverscrollBehaviorV2::Contain,
                    overscroll_y: OverscrollBehaviorV2::Contain,
                    server_driven: false,
                    server_driven_reason: ServerDrivenReasonV2::None,
                },
                ScrollNodeV2 {
                    node_id: 2,
                    parent_id: 1,
                    extent_w: 200.0,
                    extent_h: 250.0,
                    clip: RectV2::new(50.0, 50.0, 100.0, 100.0),
                    auth_offset_x: 0.0,
                    auth_offset_y: 0.0,
                    snap_points_x: Vec::new(),
                    snap_points_y: Vec::new(),
                    overscroll_x: OverscrollBehaviorV2::Auto,
                    overscroll_y: OverscrollBehaviorV2::Auto,
                    server_driven: false,
                    server_driven_reason: ServerDrivenReasonV2::None,
                },
                ScrollNodeV2 {
                    node_id: 3,
                    parent_id: 1,
                    extent_w: 100.0,
                    extent_h: 120.0,
                    clip: RectV2::new(10.0, 10.0, 80.0, 80.0),
                    auth_offset_x: 0.0,
                    auth_offset_y: 0.0,
                    snap_points_x: Vec::new(),
                    snap_points_y: Vec::new(),
                    overscroll_x: OverscrollBehaviorV2::Contain,
                    overscroll_y: OverscrollBehaviorV2::Contain,
                    server_driven: false,
                    server_driven_reason: ServerDrivenReasonV2::None,
                },
            ],
            layers: vec![LayerV2 {
                layer_id: 20,
                scroll_node_id: 2,
                kind: LayerKindV2::Normal,
                bounds: RectV2::new(0.0, 0.0, 300.0, 300.0),
                bg_rgba: [0, 0, 0, 0],
                opacity: 1.0,
                transform: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
                animations: Vec::new(),
                tile_size: 300,
                tile_refs: vec![TileRefV2 {
                    col: 0,
                    row: 0,
                    bounds: RectV2::new(0.0, 0.0, 300.0, 300.0),
                    content_hash: 0xBEEF_0001,
                }],
                invalidated_hashes: Vec::new(),
            }],
            tiles: vec![red_tile],
            handler_regions: Vec::new(),
            editable_specs: Vec::new(),
        };
        comp.apply_frame(frame.clone());

        // Child node 2 has max_y=150; dy=210 chains 60px to parent node 1.
        let out = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 2,
            pt_x: 80.0,
            pt_y: 80.0,
            dx: 0.0,
            dy: 210.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        assert!(matches!(out, ScrollOutcomeV2::Local(_)));
        assert_eq!(comp.scroll_offset(2), (0.0, 150.0));
        assert_eq!(comp.scroll_offset(1), (0.0, 60.0));
        assert_eq!(
            comp.layer_scroll_offset(&frame, &frame.layers[0]),
            (0.0, -210.0)
        );

        // Node 3 has OverscrollBehavior::Contain so excess does not chain to parent 1.
        let _ = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 3,
            pt_x: 20.0,
            pt_y: 20.0,
            dx: 0.0,
            dy: 200.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        assert_eq!(comp.scroll_offset(3), (0.0, 40.0));
        assert_eq!(comp.scroll_offset(1), (0.0, 60.0));

        // Composite: node 2 clip (50..150, 50..150) shifted up by parent scroll 60 -> y in [0..90).
        let store = ResourceStore::default();
        let mut slot = None;
        let (rgba, _) = comp
            .composite_rgba(&store, &mut slot, CompositeOptsV2::default())
            .expect("composite clipped hierarchy");
        let px_inside = 8 + (70 * 300 + 80) * 4;
        let px_outside_clip = 8 + (200 * 300 + 80) * 4;
        assert!(rgba[px_inside] > 200 && rgba[px_inside + 1] < 80);
        assert_eq!(
            &rgba[px_outside_clip..px_outside_clip + 4],
            &[255, 255, 255, 255]
        );
    }

    #[test]
    fn s5_predictive_echo_renders_real_glyphs_at_scrolled_layer_offset() {
        let mut comp = CompositorV2::new();
        let bg_tile = TilePayloadV2 {
            content_hash: 0xE501,
            width: 256,
            height: 256,
            vector_ops: encode_vector_ops_v2(&[VectorOpV2::FillRect {
                rect: RectV2::new(0.0, 0.0, 256.0, 256.0),
                rgba: [255, 255, 255, 255],
                radius: 0.0,
            }]),
            text_runs: Vec::new(),
            hit_rects: Vec::new(),
        };
        let mut frame = scrollable_frame(4, false);
        frame.layers[0].tile_refs = vec![TileRefV2 {
            col: 0,
            row: 0,
            bounds: RectV2::new(0.0, 0.0, 256.0, 256.0),
            content_hash: 0xE501,
        }];
        frame.tiles = vec![bg_tile];
        frame.editable_specs = vec![build_real_font_spec(42, 1, 20.0, 80.0)];
        comp.apply_frame(frame);

        let pred = comp.predict_key_input(42, 1, "H");
        assert!(!pred.suppressed);
        assert!(!pred.glyph_ids.is_empty());

        let _ = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 30.0,
            pt_y: 85.0,
            dx: 0.0,
            dy: 40.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        let store = ResourceStore::default();
        let mut slot = None;
        let (rgba, _) = comp
            .composite_rgba(&store, &mut slot, CompositeOptsV2::default())
            .expect("composite echo glyph");
        let count_dark_in_band = |y0: usize, y1: usize| -> usize {
            let mut dark = 0usize;
            for y in y0..y1 {
                for x in 18..42 {
                    let off = 8 + (y * 256 + x) * 4;
                    if rgba[off] < 200 || rgba[off + 1] < 200 || rgba[off + 2] < 200 {
                        dark += 1;
                    }
                }
            }
            dark
        };
        // At scroll=40, y=80..98 shifts to viewport y=40..58; unscrolled y=80..98 stays white.
        assert!(count_dark_in_band(40, 58) > 10);
        assert_eq!(count_dark_in_band(80, 98), 0);
    }

    #[test]
    fn s6_offscreen_animated_tile_paints_and_dual_sticky_inset_preserves_end() {
        let mut comp = CompositorV2::new();
        let blue_tile = TilePayloadV2 {
            content_hash: 0xA601,
            width: 120,
            height: 120,
            vector_ops: encode_vector_ops_v2(&[VectorOpV2::FillRect {
                rect: RectV2::new(0.0, 0.0, 120.0, 120.0),
                rgba: [20, 80, 230, 255],
                radius: 0.0,
            }]),
            text_runs: Vec::new(),
            hit_rects: Vec::new(),
        };
        let frame = SceneFrameV2 {
            acked_scroll_seq: 0,
            acked_input_seq: 0,
            viewport_w: 256,
            viewport_h: 256,
            scroll_nodes: vec![ScrollNodeV2 {
                node_id: 1,
                parent_id: 1,
                extent_w: 256.0,
                extent_h: 256.0,
                clip: RectV2::new(0.0, 0.0, 256.0, 256.0),
                auth_offset_x: 0.0,
                auth_offset_y: 0.0,
                snap_points_x: Vec::new(),
                snap_points_y: Vec::new(),
                overscroll_x: OverscrollBehaviorV2::Contain,
                overscroll_y: OverscrollBehaviorV2::Contain,
                server_driven: false,
                server_driven_reason: ServerDrivenReasonV2::None,
            }],
            layers: vec![LayerV2 {
                layer_id: 9,
                scroll_node_id: 1,
                kind: LayerKindV2::Normal,
                bounds: RectV2::new(-180.0, 20.0, 120.0, 120.0),
                bg_rgba: [0, 0, 0, 0],
                opacity: 1.0,
                transform: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
                animations: vec![AnimationCurveV2 {
                    property: AnimationPropertyV2::Transform,
                    start_ms: 0.0,
                    duration_ms: 100.0,
                    iterations: 1.0,
                    fill_forwards: true,
                    keyframes: vec![
                        KeyframeV2 {
                            offset: 0.0,
                            value: KeyframeValueV2::Transform([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]),
                            easing: EasingV2::Linear,
                        },
                        KeyframeV2 {
                            offset: 1.0,
                            value: KeyframeValueV2::Transform([1.0, 0.0, 0.0, 1.0, 200.0, 0.0]),
                            easing: EasingV2::Linear,
                        },
                    ],
                }],
                tile_size: 120,
                tile_refs: vec![TileRefV2 {
                    col: 0,
                    row: 0,
                    bounds: RectV2::new(-180.0, 20.0, 120.0, 120.0),
                    content_hash: 0xA601,
                }],
                invalidated_hashes: Vec::new(),
            }],
            tiles: vec![blue_tile],
            handler_regions: Vec::new(),
            editable_specs: Vec::new(),
        };
        comp.apply_frame(frame);
        let store = ResourceStore::default();
        let mut slot = None;
        let (rgba, stats) = comp
            .composite_rgba(
                &store,
                &mut slot,
                CompositeOptsV2 {
                    t_ms: 100.0,
                    ..Default::default()
                },
            )
            .expect("composite animated tile");
        assert_eq!(stats.total_visible_tiles, 1);
        let px = 8 + (50 * 256 + 40) * 4;
        assert!(rgba[px + 2] > 200 && rgba[px] < 50);

        let shift = sticky_axis_shift(300.0, 40.0, 0.0, 500.0, 0.0, 100.0, Some(10.0), Some(10.0));
        assert_eq!(shift, -250.0);
    }

    #[test]
    fn apply_frame_reconciles_auth_text_and_suppresses_echo() {
        let mut comp = CompositorV2::new();
        let mut f0 = scrollable_frame(0, false);
        f0.acked_input_seq = 0;
        comp.apply_frame(f0);

        let p1 = comp.predict_key_input(10, 1, "a");
        assert!(!p1.suppressed);

        let mut f1 = scrollable_frame(0, false);
        f1.acked_input_seq = 1;
        f1.editable_specs[0].auth_text = "A".into();
        comp.apply_frame(f1);

        let p2 = comp.predict_key_input(10, 2, "b");
        assert!(!p2.suppressed);

        let mut f2 = scrollable_frame(0, false);
        f2.acked_input_seq = 2;
        f2.editable_specs[0].auth_text = "AB".into();
        comp.apply_frame(f2);

        let p3 = comp.predict_key_input(10, 3, "c");
        assert!(p3.suppressed);
        assert_eq!(p3.reason, SuppressReasonV2::MispredictionLimit);

        // Password fields leave auth_text empty and must not trigger misprediction suppression.
        let pw1 = comp.predict_key_input(11, 4, "x");
        assert!(!pw1.suppressed);
        assert!(pw1.is_bullet);
        let mut f3 = scrollable_frame(0, false);
        f3.acked_input_seq = 4;
        comp.apply_frame(f3);
        let pw2 = comp.predict_key_input(11, 5, "y");
        assert!(!pw2.suppressed);
    }

    #[test]
    fn sub_element_handler_region_forwards_inside_and_rebases_outside() {
        let mut comp = CompositorV2::new();
        let mut f0 = scrollable_frame(6, false);
        f0.scroll_nodes[0].clip = RectV2::new(0.0, 0.0, 800.0, 600.0);
        f0.scroll_nodes[0].extent_w = 800.0;
        f0.scroll_nodes[0].extent_h = 1600.0;
        f0.handler_regions = vec![HandlerRegionV2 {
            scroll_node_id: 1,
            rect: RectV2::new(10.0, 50.0, 160.0, 90.0),
            event_mask: HANDLER_WHEEL,
            non_passive: true,
        }];
        comp.apply_frame(f0);

        let blocked = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 50.0,
            pt_y: 80.0,
            dx: 0.0,
            dy: 40.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        assert_eq!(blocked, ScrollOutcomeV2::ForwardToServer);

        let local = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 1,
            pt_x: 400.0,
            pt_y: 300.0,
            dx: 0.0,
            dy: 80.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        let ScrollOutcomeV2::Local(u) = local else {
            panic!("expected local scroll outside region");
        };
        assert_eq!(u.seq, 1);
        assert_eq!(u.x, 0.0);
        assert_eq!(u.y, 80.0);

        let mut f1 = scrollable_frame(6, false);
        f1.scroll_nodes[0].clip = RectV2::new(0.0, 0.0, 800.0, 600.0);
        f1.scroll_nodes[0].extent_w = 800.0;
        f1.scroll_nodes[0].extent_h = 1600.0;
        f1.acked_scroll_seq = 0;
        f1.scroll_nodes[0].auth_offset_y = 0.0;
        comp.apply_frame(f1);
        assert_eq!(comp.scroll_offset(1), (0.0, 80.0));

        let mut f2 = scrollable_frame(6, false);
        f2.scroll_nodes[0].clip = RectV2::new(0.0, 0.0, 800.0, 600.0);
        f2.scroll_nodes[0].extent_w = 800.0;
        f2.scroll_nodes[0].extent_h = 1600.0;
        f2.acked_scroll_seq = 1;
        f2.scroll_nodes[0].auth_offset_y = 80.0;
        comp.apply_frame(f2);
        assert_eq!(comp.scroll_offset(1), (0.0, 80.0));
    }
}
