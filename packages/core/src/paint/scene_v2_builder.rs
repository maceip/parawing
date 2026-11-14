// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Builds full `SceneFrameV2` payloads from a laid-out `DomHandle`: scroll tree,
//! multi-tile `256x256` interest-culled KSC0 vector layers, fixed/sticky layers,
//! CSS animation curves, Parley text runs, hit rects, handler regions, and echo specs.

use std::collections::{HashMap, HashSet};

use blitz_dom::{local_name, BaseDocument, ElementData, Node};
use blitz_traits::NodeId;
use skrifa::raw::TableProvider;
use skrifa::{FontRef, GlyphId, MetadataProvider};
use style::animation::{AnimationState, ElementAnimationSet, KeyframesIterationState};
use style::properties::animated_properties::{AnimationValue, AnimationValueMap};
use style::properties::generated::longhands::animation_fill_mode::single_value::computed_value::T as AnimationFillMode;
use style::properties::generated::longhands::position::computed_value::T as Position;
use style::properties::generated::longhands::visibility::computed_value::T as Visibility;
use style::properties::{LonghandId, OwnedPropertyDeclarationId};
use style::values::animated::ToAnimatedValue;
use style::values::computed::{Overflow, OverscrollBehavior, Transform};
use style::values::specified::ui::CursorKind;

use crate::layout::geometry::doc_position;
use crate::paint::scene_record::{blob_content_hash, fx_hash_u64};
use crate::paint::scene_v2::{
    compute_interest_rect, cull_frame_for_interest, deduplicate_tiles_delta, AnimationCurveV2,
    AnimationPropertyV2, ClusterAdvanceV2, CursorKindV2, EasingV2, EditableEchoSpecV2,
    HandlerRegionV2, HitRectMapV2, KeyframeV2, KeyframeValueV2, LayerKindV2, LayerV2,
    OverscrollBehaviorV2, RectV2, SceneFrameV2, ScrollNodeV2, ServerDrivenReasonV2, TextRunMapV2,
    TilePayloadV2, TileRefV2, HANDLER_TOUCH_MOVE, HANDLER_TOUCH_START, HANDLER_WHEEL,
};
use crate::DomHandle;

#[derive(Clone, Copy)]
struct PointV2 {
    x: f32,
    y: f32,
}

impl PointV2 {
    fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }
}

fn abs_color_to_rgba8(c: &style::color::AbsoluteColor) -> [u8; 4] {
    let srgb = c.to_color_space(style::color::ColorSpace::Srgb);
    let raw = srgb.raw_components();
    let to_u8 = |v: f32| -> u8 { (v.clamp(0.0, 1.0) * 255.0).round() as u8 };
    [to_u8(raw[0]), to_u8(raw[1]), to_u8(raw[2]), to_u8(raw[3])]
}

const TILE_SIZE_PX: u32 = 256;
const MAX_SCENE_TILES: usize = 512;

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct HandlerRegionInput {
    target_node_id: Option<u64>,
    scroll_node_id: Option<u64>,
    x: Option<f32>,
    y: Option<f32>,
    width: Option<f32>,
    height: Option<f32>,
    rect: Option<[f32; 4]>,
    event_mask: Option<u8>,
    non_passive: Option<bool>,
    #[serde(rename = "coversScrollNode")]
    covers_scroll_node: Option<bool>,
    wheel: Option<bool>,
    touchstart: Option<bool>,
    touchmove: Option<bool>,
}

struct CollectedTextRun {
    scroll_node_id: u64,
    doc_rect: RectV2,
    run: TextRunMapV2,
}

struct CollectedHitRect {
    scroll_node_id: u64,
    doc_rect: RectV2,
    hit: HitRectMapV2,
}

struct SpecialLayerSpec {
    internal_id: NodeId,
    ext_id: u64,
    scroll_node_id: u64,
    kind: LayerKindV2,
    doc_rect: RectV2,
    bg_rgba: [u8; 4],
    opacity: f32,
    transform: [f32; 6],
    animations: Vec<AnimationCurveV2>,
    is_fixed: bool,
}

struct CollectedDomMetadata {
    vw: u32,
    vh: u32,
    root_ext_id: Option<u64>,
    root_extent: (f32, f32),
    scroll_nodes: Vec<ScrollNodeV2>,
    node_scroll_map: HashMap<NodeId, u64>,
    special_layers: Vec<SpecialLayerSpec>,
    root_animations: Vec<AnimationCurveV2>,
    root_opacity: f32,
    root_transform: [f32; 6],
    root_bg_rgba: [u8; 4],
    text_runs: Vec<CollectedTextRun>,
    hit_rects: Vec<CollectedHitRect>,
    editable_specs: Vec<EditableEchoSpecV2>,
}

pub(crate) fn parse_u64_hash_set(bytes: &[u8]) -> HashSet<u64> {
    let mut set = HashSet::new();
    for chunk in bytes.chunks_exact(8) {
        let arr: [u8; 8] = [
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ];
        set.insert(u64::from_le_bytes(arr));
    }
    set
}

struct ParsedHandlerRegion {
    region: HandlerRegionV2,
    covers_scroll_node: bool,
}

fn region_encloses_rect(outer: RectV2, inner: RectV2) -> bool {
    if outer.w <= 0.0 || outer.h <= 0.0 || inner.w <= 0.0 || inner.h <= 0.0 {
        return false;
    }
    const EPS: f32 = 0.5;
    outer.x <= inner.x + EPS
        && outer.y <= inner.y + EPS
        && (outer.x + outer.w) + EPS >= (inner.x + inner.w)
        && (outer.y + outer.h) + EPS >= (inner.y + inner.h)
}

fn parse_handler_regions(json: &str, root_ext_id: Option<u64>) -> Vec<ParsedHandlerRegion> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(items) = serde_json::from_str::<Vec<HandlerRegionInput>>(trimmed) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let mut mask = item.event_mask.unwrap_or(0);
        if item.wheel.unwrap_or(false) {
            mask |= HANDLER_WHEEL;
        }
        if item.touchstart.unwrap_or(false) {
            mask |= HANDLER_TOUCH_START;
        }
        if item.touchmove.unwrap_or(false) {
            mask |= HANDLER_TOUCH_MOVE;
        }
        if mask == 0 {
            continue;
        }
        let rect = match item.rect {
            Some([x, y, w, h]) => RectV2::new(x, y, w.max(0.0), h.max(0.0)),
            None => RectV2::new(
                item.x.unwrap_or(0.0),
                item.y.unwrap_or(0.0),
                item.width.unwrap_or(0.0).max(0.0),
                item.height.unwrap_or(0.0).max(0.0),
            ),
        };
        if rect.w <= 0.0 || rect.h <= 0.0 {
            continue;
        }
        let raw_sn = item.scroll_node_id.or(item.target_node_id).unwrap_or(0);
        let scroll_node_id = if Some(raw_sn) == root_ext_id {
            0
        } else {
            raw_sn
        };
        out.push(ParsedHandlerRegion {
            region: HandlerRegionV2 {
                scroll_node_id,
                rect,
                event_mask: mask,
                non_passive: item.non_passive.unwrap_or(true),
            },
            covers_scroll_node: item.covers_scroll_node.unwrap_or(false),
        });
    }
    out
}

fn apply_non_passive_handler_regions(
    scroll_nodes: &mut [ScrollNodeV2],
    parsed: &[ParsedHandlerRegion],
) -> Vec<HandlerRegionV2> {
    let mut regions = Vec::with_capacity(parsed.len());
    for entry in parsed {
        regions.push(entry.region);
        if !entry.region.non_passive {
            continue;
        }
        for sn in scroll_nodes.iter_mut() {
            let covers =
                entry.covers_scroll_node || region_encloses_rect(entry.region.rect, sn.clip);
            if sn.node_id == entry.region.scroll_node_id && covers {
                sn.server_driven = true;
                sn.server_driven_reason = ServerDrivenReasonV2::NonPassiveHandler;
            }
        }
    }
    regions
}

fn to_overscroll_v2(behavior: OverscrollBehavior) -> OverscrollBehaviorV2 {
    match behavior {
        OverscrollBehavior::Auto => OverscrollBehaviorV2::Auto,
        OverscrollBehavior::Contain => OverscrollBehaviorV2::Contain,
        OverscrollBehavior::None => OverscrollBehaviorV2::None,
    }
}

fn is_viewport_propagated_node(doc: &BaseDocument, id: NodeId) -> bool {
    let Some(root) = doc.try_root_element() else {
        return false;
    };
    if root.id == id {
        return true;
    }
    let Some(node) = doc.get_node(id) else {
        return false;
    };
    let is_body = node
        .element_data()
        .is_some_and(|e| e.name.local == local_name!("body"));
    if !is_body || node.parent != Some(root.id) {
        return false;
    }
    root.primary_styles().is_some_and(|s| {
        let b = s.get_box();
        b.overflow_x == Overflow::Visible && b.overflow_y == Overflow::Visible
    })
}

fn is_element_scroll_container(doc: &BaseDocument, node: &Node) -> bool {
    if is_viewport_propagated_node(doc, node.id) {
        return false;
    }
    node.primary_styles().is_some_and(|styles| {
        let ox = styles.clone_overflow_x();
        let oy = styles.clone_overflow_y();
        matches!(ox, Overflow::Scroll | Overflow::Auto | Overflow::Hidden)
            || matches!(oy, Overflow::Scroll | Overflow::Auto | Overflow::Hidden)
    })
}

fn unscrolled_ancestor_box_pos(doc: &BaseDocument, node: &Node) -> PointV2 {
    let base = doc_position(doc, node);
    let mut add_x = 0.0f64;
    let mut add_y = 0.0f64;
    let mut cur = node.layout_parent.get().or(node.parent);
    for _ in 0..512 {
        let Some(anc_id) = cur else {
            break;
        };
        let Some(anc) = doc.get_node(anc_id) else {
            break;
        };
        let s = anc.scroll_offset();
        add_x += s.x;
        add_y += s.y;
        cur = anc.layout_parent.get().or(anc.parent);
    }
    PointV2::new(base.x + add_x as f32, base.y + add_y as f32)
}

fn root_document_extent(doc: &BaseDocument, vw: u32, vh: u32) -> (f32, f32) {
    let mut extent_w = vw.max(1) as f32;
    let mut extent_h = vh.max(1) as f32;
    let Some(root) = doc.try_root_element() else {
        return (extent_w, extent_h);
    };
    let root_layout = root.final_layout();
    extent_w = extent_w.max(root_layout.size.width + root_layout.scroll_width());
    extent_h = extent_h.max(root_layout.size.height + root_layout.scroll_height());
    for &child_id in &root.children {
        let Some(child) = doc.get_node(child_id) else {
            continue;
        };
        let is_body = child
            .element_data()
            .is_some_and(|e| e.name.local == local_name!("body"));
        let is_fixed = child
            .primary_styles()
            .is_some_and(|s| s.clone_position() == Position::Fixed);
        if is_body && !is_fixed {
            let bl = child.final_layout();
            extent_w = extent_w.max(bl.location.x + bl.size.width + bl.scroll_width());
            extent_h = extent_h.max(bl.location.y + bl.size.height + bl.scroll_height());
        }
    }
    let layout_children = root.layout_children.borrow();
    let hoisted_children = root.hoisted_children.borrow();
    for id in layout_children
        .iter()
        .flatten()
        .chain(hoisted_children.iter())
    {
        let Some(child) = doc.get_node(*id) else {
            continue;
        };
        if child
            .primary_styles()
            .is_some_and(|s| s.clone_position() == Position::Fixed)
        {
            continue;
        }
        let cl = child.final_layout();
        extent_w = extent_w.max(cl.location.x + cl.size.width + cl.scroll_width());
        extent_h = extent_h.max(cl.location.y + cl.size.height + cl.scroll_height());
    }
    (
        extent_w.max(vw.max(1) as f32),
        extent_h.max(vh.max(1) as f32),
    )
}

fn collect_scroll_nodes(
    dom: &DomHandle,
    doc: &BaseDocument,
    vw: u32,
    vh: u32,
    extent: (f32, f32),
    page_scroll: (f32, f32),
) -> (Vec<ScrollNodeV2>, HashMap<NodeId, u64>, Option<u64>) {
    let root_id = doc.try_root_element().map(|n| n.id);
    let root_ext_id = root_id.map(|id| dom.external_node_id(id) as u64);
    let (root_ox, root_oy, root_snap_reason) = doc
        .try_root_element()
        .and_then(|r| r.primary_styles())
        .map(|s| {
            let ox = to_overscroll_v2(s.clone_overscroll_behavior_x());
            let oy = to_overscroll_v2(s.clone_overscroll_behavior_y());
            (ox, oy, ServerDrivenReasonV2::None)
        })
        .unwrap_or((
            OverscrollBehaviorV2::Auto,
            OverscrollBehaviorV2::Auto,
            ServerDrivenReasonV2::None,
        ));
    let mut infos = vec![ScrollNodeV2 {
        node_id: 0,
        parent_id: 0,
        extent_w: extent.0,
        extent_h: extent.1,
        clip: RectV2::new(0.0, 0.0, vw.max(1) as f32, vh.max(1) as f32),
        auth_offset_x: page_scroll.0,
        auth_offset_y: page_scroll.1,
        snap_points_x: Vec::new(),
        snap_points_y: Vec::new(),
        overscroll_x: root_ox,
        overscroll_y: root_oy,
        server_driven: root_snap_reason != ServerDrivenReasonV2::None,
        server_driven_reason: root_snap_reason,
    }];

    let mut scroll_ext_by_internal: HashMap<NodeId, u64> = HashMap::new();
    for (nid, node) in doc.tree().iter() {
        if !node.is_element() || !is_element_scroll_container(doc, node) {
            continue;
        }
        let ext_id = dom.external_node_id(nid) as u64;
        scroll_ext_by_internal.insert(nid, ext_id);
    }

    for (nid, node) in doc.tree().iter() {
        let Some(&ext_id) = scroll_ext_by_internal.get(&nid) else {
            continue;
        };
        let parent_id = nearest_scroll_parent(doc, &scroll_ext_by_internal, nid);
        let pos = unscrolled_ancestor_box_pos(doc, node);
        let layout = node.final_layout();
        let client_w = (layout.size.width - layout.border.left - layout.border.right).max(0.0);
        let client_h = (layout.size.height - layout.border.top - layout.border.bottom).max(0.0);
        let clip_x = pos.x + layout.border.left;
        let clip_y = pos.y + layout.border.top;
        let ew = (client_w + layout.scroll_width()).max(client_w);
        let eh = (client_h + layout.scroll_height()).max(client_h);
        let so = node.scroll_offset();
        let (ox, oy, snap_reason) = node
            .primary_styles()
            .map(|s| {
                let ox = to_overscroll_v2(s.clone_overscroll_behavior_x());
                let oy = to_overscroll_v2(s.clone_overscroll_behavior_y());
                (ox, oy, ServerDrivenReasonV2::None)
            })
            .unwrap_or((
                OverscrollBehaviorV2::Auto,
                OverscrollBehaviorV2::Auto,
                ServerDrivenReasonV2::None,
            ));
        infos.push(ScrollNodeV2 {
            node_id: ext_id,
            parent_id,
            extent_w: ew,
            extent_h: eh,
            clip: RectV2::new(clip_x, clip_y, client_w, client_h),
            auth_offset_x: so.x as f32,
            auth_offset_y: so.y as f32,
            snap_points_x: Vec::new(),
            snap_points_y: Vec::new(),
            overscroll_x: ox,
            overscroll_y: oy,
            server_driven: snap_reason != ServerDrivenReasonV2::None,
            server_driven_reason: snap_reason,
        });
    }

    let mut node_scroll_map = HashMap::new();
    for (nid, _) in doc.tree().iter() {
        let sn = resolve_containing_scroll_node(doc, &scroll_ext_by_internal, nid);
        node_scroll_map.insert(nid, sn);
    }
    (infos, node_scroll_map, root_ext_id)
}

fn nearest_scroll_parent(
    doc: &BaseDocument,
    scroll_map: &HashMap<NodeId, u64>,
    nid: NodeId,
) -> u64 {
    let mut cur = doc
        .get_node(nid)
        .and_then(|n| n.layout_parent.get().or(n.parent));
    for _ in 0..512 {
        let Some(anc) = cur else {
            return 0;
        };
        if let Some(&ext_id) = scroll_map.get(&anc) {
            return ext_id;
        }
        cur = doc
            .get_node(anc)
            .and_then(|n| n.layout_parent.get().or(n.parent));
    }
    0
}

fn resolve_containing_scroll_node(
    doc: &BaseDocument,
    scroll_map: &HashMap<NodeId, u64>,
    nid: NodeId,
) -> u64 {
    let mut cur = Some(nid);
    for _ in 0..512 {
        let Some(c) = cur else {
            return 0;
        };
        if let Some(&ext_id) = scroll_map.get(&c) {
            return ext_id;
        }
        cur = doc
            .get_node(c)
            .and_then(|n| n.layout_parent.get().or(n.parent));
    }
    0
}

fn extract_node_transform_and_bg(node: &Node) -> (f32, [f32; 6], [u8; 4], bool) {
    let Some(styles) = node.primary_styles() else {
        return (1.0, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0], [0, 0, 0, 0], true);
    };
    let visible = styles.get_inherited_box().visibility == Visibility::Visible;
    let opacity = styles.get_effects().opacity;
    let bg = &styles.get_background().background_color;
    let abs_bg = bg.resolve_to_absolute(&styles.get_inherited_text().color);
    let rgba = abs_color_to_rgba8(&abs_bg);
    let layout = node.final_layout();
    let matrix = transform_to_2d(
        &styles.get_box().clone_transform(),
        layout.size.width,
        layout.size.height,
    );
    (opacity, matrix, rgba, visible)
}

fn transform_to_2d(transform: &Transform, width: f32, height: f32) -> [f32; 6] {
    type CLen = style::values::computed::Length;
    if transform.0.is_empty() {
        return [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
    }
    let ref_box = euclid::default::Rect::new(
        euclid::point2(CLen::new(0.0), CLen::new(0.0)),
        euclid::size2(CLen::new(width.max(1.0)), CLen::new(height.max(1.0))),
    );
    let Ok((m, _)) = transform.to_transform_3d_matrix_f64(Some(&ref_box)) else {
        return [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
    };
    let a = m.to_array();
    [
        a[0] as f32,
        a[1] as f32,
        a[4] as f32,
        a[5] as f32,
        a[12] as f32,
        a[13] as f32,
    ]
}

fn collect_animation_curves(
    set: &ElementAnimationSet,
    box_w: f32,
    box_h: f32,
) -> Vec<AnimationCurveV2> {
    let mut curves = Vec::new();
    for anim in &set.animations {
        if anim.state == AnimationState::Canceled || anim.duration <= 0.0 {
            continue;
        }
        let duration_ms = anim.duration * 1000.0;
        let start_ms = anim.started_at * 1000.0;
        let iterations = match anim.iteration_state {
            KeyframesIterationState::Finite(_, max) => max as f32,
            KeyframesIterationState::Infinite(_) => f32::INFINITY,
        };
        let fill_forwards = matches!(
            anim.fill_mode,
            AnimationFillMode::Forwards | AnimationFillMode::Both
        );
        let steps = 4usize;
        let mut op_frames = Vec::new();
        let mut tr_frames = Vec::new();
        for s in 0..=steps {
            let frac = (s as f64) / (steps as f64);
            let t = anim.started_at + frac * anim.duration;
            let Some(map) = sample_single_animation_at(set, t) else {
                continue;
            };
            if let Some(AnimationValue::Opacity(v)) =
                map.get(&OwnedPropertyDeclarationId::Longhand(LonghandId::Opacity))
            {
                op_frames.push(KeyframeV2 {
                    offset: frac as f32,
                    value: KeyframeValueV2::Scalar(*v),
                    easing: EasingV2::Linear,
                });
            }
            if let Some(AnimationValue::Transform(tr)) =
                map.get(&OwnedPropertyDeclarationId::Longhand(LonghandId::Transform))
            {
                let mat = animated_transform_to_2d(tr, box_w, box_h);
                tr_frames.push(KeyframeV2 {
                    offset: frac as f32,
                    value: KeyframeValueV2::Transform(mat),
                    easing: EasingV2::Linear,
                });
            }
        }
        if op_frames.len() >= 2 {
            curves.push(AnimationCurveV2 {
                property: AnimationPropertyV2::Opacity,
                start_ms,
                duration_ms,
                iterations,
                fill_forwards,
                keyframes: op_frames,
            });
        }
        if tr_frames.len() >= 2 {
            curves.push(AnimationCurveV2 {
                property: AnimationPropertyV2::Transform,
                start_ms,
                duration_ms,
                iterations,
                fill_forwards,
                keyframes: tr_frames,
            });
        }
    }
    curves
}

fn sample_single_animation_at(set: &ElementAnimationSet, t: f64) -> Option<AnimationValueMap> {
    set.get_value_map_for_active_animations(t)
}

fn animated_transform_to_2d<T>(tr: &T, width: f32, height: f32) -> [f32; 6]
where
    Transform: ToAnimatedValue<AnimatedValue = T>,
    T: Clone,
{
    let computed: Transform = ToAnimatedValue::from_animated_value(tr.clone());
    transform_to_2d(&computed, width, height)
}

fn node_cursor_v2(doc: &BaseDocument, node: &Node) -> (CursorKindV2, Option<String>, bool, bool) {
    let mut editable = false;
    if let Some(el) = node.element_data() {
        editable = el.text_input_data().is_some()
            || node
                .attr(local_name!("contenteditable"))
                .is_some_and(|v| !v.eq_ignore_ascii_case("false"));
    }
    let mut link_url: Option<String> = None;
    let mut cur = Some(node);
    for _ in 0..128 {
        let Some(c) = cur else {
            break;
        };
        if let Some(href) = c.attr(local_name!("href")) {
            link_url = Some(href.to_string());
            break;
        }
        cur = c.layout_parent.get().and_then(|id| doc.get_node(id));
    }
    let keyword = node
        .primary_styles()
        .map(|s| s.clone_cursor().keyword)
        .unwrap_or(CursorKind::Auto);
    let cursor = match keyword {
        CursorKind::Pointer => CursorKindV2::Pointer,
        CursorKind::Text | CursorKind::VerticalText => CursorKindV2::Text,
        CursorKind::Grab => CursorKindV2::Grab,
        CursorKind::Grabbing => CursorKindV2::Grabbing,
        CursorKind::NotAllowed | CursorKind::NoDrop => CursorKindV2::NotAllowed,
        CursorKind::Auto => {
            if editable {
                CursorKindV2::Text
            } else if link_url.is_some() {
                CursorKindV2::Pointer
            } else {
                CursorKindV2::Default
            }
        }
        _ => CursorKindV2::Default,
    };
    let hover_or_pointer = link_url.is_some()
        || cursor != CursorKindV2::Default
        || node.attr(local_name!("onmousemove")).is_some()
        || node.attr(local_name!("onmouseenter")).is_some()
        || node.attr(local_name!("onmouseover")).is_some();
    (cursor, link_url, editable, hover_or_pointer)
}

fn build_text_run_from_layout(
    ext_id: u64,
    scroll_node_id: u64,
    origin_doc: (f32, f32),
    layout: &parley::Layout<blitz_dom::node::TextBrush>,
    full_text: &str,
    rtl: bool,
    out: &mut Vec<CollectedTextRun>,
) {
    let scale = layout.scale().max(1e-3);
    for line in layout.lines() {
        let lm = line.metrics();
        let ascent = (lm.baseline - lm.block_min_coord).max(1.0) / scale;
        let descent = (lm.block_max_coord - lm.baseline).max(0.0) / scale;
        let baseline_y = origin_doc.1 + lm.baseline / scale;
        let mut cursor_x = origin_doc.0 + (lm.offset + lm.inline_min_coord) / scale;
        for run in line.runs() {
            let font = run.font();
            let font_hash = blob_content_hash(font.data.data());
            let font_size = run.font_size() / scale;
            let mut clusters = Vec::new();
            let mut run_start_x = None;
            let mut min_byte = usize::MAX;
            let mut max_byte = 0usize;
            for cluster in run.visual_clusters() {
                let cw = cluster.advance() / scale;
                let range = cluster.text_range();
                min_byte = min_byte.min(range.start);
                max_byte = max_byte.max(range.end);
                if run_start_x.is_none() {
                    run_start_x = Some(cursor_x);
                }
                clusters.push((range.start, range.end, cursor_x, cw));
                cursor_x += cw;
            }
            if clusters.is_empty() || min_byte >= max_byte {
                continue;
            }
            let slice = full_text.get(min_byte..max_byte).unwrap_or("");
            if slice.is_empty() {
                continue;
            }
            let run_ox = run_start_x.unwrap_or(origin_doc.0);
            let mut cluster_advances = Vec::with_capacity(clusters.len());
            let mut min_x = f32::MAX;
            let mut max_x = f32::MIN;
            for (b0, b1, cx, cw) in clusters {
                min_x = min_x.min(cx);
                max_x = max_x.max(cx + cw);
                cluster_advances.push(ClusterAdvanceV2 {
                    byte_start: (b0 - min_byte) as u32,
                    byte_len: (b1 - b0) as u32,
                    x: cx,
                    width: cw,
                    selection_bounds: RectV2::new(
                        cx,
                        baseline_y - ascent,
                        cw.max(1.0),
                        (ascent + descent).max(1.0),
                    ),
                });
            }
            let bounds = RectV2::new(
                min_x,
                baseline_y - ascent,
                (max_x - min_x).max(1.0),
                (ascent + descent).max(1.0),
            );
            out.push(CollectedTextRun {
                scroll_node_id,
                doc_rect: bounds,
                run: TextRunMapV2 {
                    node_id: ext_id,
                    text: slice.to_string(),
                    font_hash,
                    font_size,
                    rtl,
                    origin_x: run_ox,
                    origin_y: baseline_y,
                    ascent,
                    descent,
                    cluster_advances,
                },
            });
        }
    }
}

fn resolve_default_font(dom: &DomHandle) -> Option<(peniko::Blob<u8>, u32)> {
    if let Ok(fb) = dom.rbi_font_bytes.try_borrow() {
        if let Some((_, pair)) = fb.iter().next() {
            return Some(pair.clone());
        }
    }
    let mut font_ctx = crate::resources::fonts::get_or_init_font_context();
    let mut layout_ctx: parley::LayoutContext<[u8; 4]> = parley::LayoutContext::new();
    let builder = layout_ctx.ranged_builder(&mut font_ctx, "a", 1.0, false);
    let layout = builder.build("a");
    let picked = layout.lines().find_map(|line| {
        line.runs().next().map(|run| {
            let f = run.font();
            (f.data.clone(), f.index)
        })
    });
    drop(layout);
    picked
}

fn build_font_metrics_for_echo(blob: &[u8], face_index: u32) -> (u16, Vec<(u32, u16)>, Vec<u16>) {
    let Ok(font_ref) = FontRef::from_index(blob, face_index) else {
        return (1000, Vec::new(), Vec::new());
    };
    let upem = font_ref.head().map(|h| h.units_per_em()).unwrap_or(1000);
    let num_glyphs = font_ref.maxp().map(|m| m.num_glyphs() as u32).unwrap_or(0);
    let mut cmap = Vec::new();
    for (cp, gid) in font_ref.charmap().mappings() {
        let gid_u16 = u32::from(gid) as u16;
        if gid_u16 != 0 {
            cmap.push((cp, gid_u16));
        }
    }
    cmap.sort_by_key(|(cp, _)| *cp);
    let metrics = font_ref.glyph_metrics(
        skrifa::instance::Size::unscaled(),
        skrifa::instance::LocationRef::default(),
    );
    let mut advances = Vec::with_capacity(num_glyphs as usize);
    for gid in 0..num_glyphs {
        let adv = metrics.advance_width(GlyphId::new(gid)).unwrap_or(0.0);
        advances.push(adv.round().clamp(0.0, u16::MAX as f32) as u16);
    }
    (upem, cmap, advances)
}

fn collect_editable_spec(
    dom: &DomHandle,
    doc: &BaseDocument,
    node: &Node,
    el: &ElementData,
    scroll_node_id: u64,
    fallback_font: &Option<(peniko::Blob<u8>, u32)>,
) -> Option<EditableEchoSpecV2> {
    let input = el.text_input_data()?;
    let ext_id = dom.external_node_id(node.id) as u64;
    let pos = unscrolled_ancestor_box_pos(doc, node);
    let layout = node.final_layout();
    let pad_l = layout.padding.left + layout.border.left;
    let pad_t = layout.padding.top + layout.border.top;
    let rect = RectV2::new(pos.x, pos.y, layout.size.width, layout.size.height);
    let is_password = node
        .attr(local_name!("type"))
        .is_some_and(|t| t.eq_ignore_ascii_case("password"));
    let styles = node.primary_styles();
    let font_size = styles
        .as_ref()
        .map(|s| s.get_font().font_size.computed_size().px())
        .unwrap_or(16.0);
    let color_rgba = styles
        .as_ref()
        .map(|s| abs_color_to_rgba8(&s.get_inherited_text().color))
        .unwrap_or([0, 0, 0, 255]);
    let rtl = styles.as_ref().is_some_and(|s| {
        s.get_inherited_box().direction
            == style::properties::generated::longhands::direction::computed_value::T::Rtl
    });
    let field_key = node
        .attr(local_name!("id"))
        .or_else(|| node.attr(local_name!("name")))
        .map(str::to_string)
        .unwrap_or_else(|| format!("node:{ext_id}"));
    drop(styles);

    let (mut caret_x, mut caret_y, mut caret_h, mut baseline_y) = (
        pos.x + pad_l,
        pos.y + pad_t,
        font_size * 1.2,
        pos.y + pad_t + font_size * 0.9,
    );
    let mut picked_font: Option<(peniko::Blob<u8>, u32)> = None;
    if let Some(tlayout) = input.editor.try_layout() {
        let scale = tlayout.scale().max(1e-3);
        if let Some(c) = input.editor.cursor_geometry(1.5) {
            caret_x = pos.x + pad_l + c.x0 as f32 / scale - input.scroll_offset;
            caret_y = pos.y + pad_t + c.y0 as f32 / scale;
            caret_h = ((c.y1 - c.y0) as f32 / scale).max(font_size);
        }
        if let Some(first_line) = tlayout.lines().next() {
            baseline_y = pos.y + pad_t + first_line.metrics().baseline / scale;
            if let Some(run) = first_line.runs().next() {
                let f = run.font();
                picked_font = Some((f.data.clone(), f.index));
            }
        }
    }
    let font_pair = picked_font.or_else(|| fallback_font.clone());
    let (font_hash, font_index, font_data, upem, cmap, advances) =
        if let Some((blob, idx)) = font_pair {
            let data = blob.data().to_vec();
            let h = fx_hash_u64(&data);
            let (upem, cmap, adv) = build_font_metrics_for_echo(&data, idx);
            (h, idx, data, upem, cmap, adv)
        } else {
            (0, 0, Vec::new(), 1000, Vec::new(), Vec::new())
        };
    let complex_shaping = rtl || input.is_multiline;
    let auth_text = if is_password {
        String::new()
    } else {
        input.editor.raw_text().to_string()
    };
    Some(EditableEchoSpecV2 {
        node_id: ext_id,
        scroll_node_id,
        field_key,
        auth_text,
        rect,
        is_password,
        complex_shaping,
        has_ligatures: false,
        font_size,
        upem,
        color_rgba,
        caret_x,
        caret_y,
        caret_height: caret_h,
        baseline_y,
        font_hash,
        font_index,
        font_data,
        cmap,
        advances,
    })
}

fn special_layer_kind(
    doc: &BaseDocument,
    node: &Node,
    pos_kind: Position,
    doc_rect: RectV2,
    root_extent: (f32, f32),
    sticky_insets: Option<&HashMap<NodeId, [Option<f32>; 4]>>,
) -> LayerKindV2 {
    if pos_kind == Position::Fixed {
        let anc_pos = doc_position(doc, node);
        return LayerKindV2::Fixed {
            viewport_anchor: RectV2::new(anc_pos.x, anc_pos.y, doc_rect.w, doc_rect.h),
        };
    }
    if pos_kind != Position::Sticky {
        return LayerKindV2::Normal;
    }
    let insets = sticky_insets
        .and_then(|m| m.get(&node.id))
        .copied()
        .unwrap_or([None; 4]);
    let cb_rect = node
        .layout_parent
        .get()
        .or(node.parent)
        .and_then(|p| doc.get_node(p))
        .map(|p| {
            let pp = unscrolled_ancestor_box_pos(doc, p);
            let pl = p.final_layout();
            RectV2::new(pp.x, pp.y, pl.size.width, pl.size.height)
        })
        .unwrap_or(RectV2::new(0.0, 0.0, root_extent.0, root_extent.1));
    LayerKindV2::Sticky {
        static_rect: doc_rect,
        constraint_rect: cb_rect,
        top_inset: insets[0],
        right_inset: insets[1],
        bottom_inset: insets[2],
        left_inset: insets[3],
    }
}

fn collect_dom_metadata(dom: &DomHandle, doc: &BaseDocument) -> CollectedDomMetadata {
    let vp = doc.viewport();
    let (vw, vh) = vp.window_size;
    let page_scroll_pt = doc.viewport_scroll();
    let page_scroll = (page_scroll_pt.x as f32, page_scroll_pt.y as f32);
    let root_extent = root_document_extent(doc, vw, vh);
    let (scroll_nodes, node_scroll_map, root_ext_id) =
        collect_scroll_nodes(dom, doc, vw, vh, root_extent, page_scroll);
    let sticky_insets = dom.sticky_insets.try_borrow().ok();
    let anim_sets = doc.animations().sets.read();
    let fallback_font = resolve_default_font(dom);

    let mut special_layers = Vec::new();
    let mut root_animations = Vec::new();
    let (mut root_opacity, mut root_transform, mut root_bg_rgba) =
        (1.0f32, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0], [255, 255, 255, 255]);
    let mut text_runs = Vec::new();
    let mut hit_rects = Vec::new();
    let mut editable_specs = Vec::new();

    for (nid, node) in doc.tree().iter() {
        let Some(el) = node.element_data() else {
            continue;
        };
        let (opacity, transform, bg_rgba, visible) = extract_node_transform_and_bg(node);
        if !visible {
            continue;
        }
        let sn_id = node_scroll_map.get(&nid).copied().unwrap_or(0);
        let ext_id = dom.external_node_id(nid) as u64;
        let pos = unscrolled_ancestor_box_pos(doc, node);
        let layout = node.final_layout();
        let doc_rect = RectV2::new(pos.x, pos.y, layout.size.width, layout.size.height);

        let key = style::animation::AnimationSetKey::new_for_non_pseudo(style::dom::OpaqueNode(
            nid.as_u64() as usize,
        ));
        let animations = anim_sets
            .get(&key)
            .map(|s| collect_animation_curves(s, layout.size.width, layout.size.height))
            .unwrap_or_default();

        if Some(ext_id) == root_ext_id {
            root_opacity = opacity;
            root_transform = transform;
            if bg_rgba[3] > 0 {
                root_bg_rgba = bg_rgba;
            }
            root_animations = animations;
        } else if doc_rect.w > 0.0 && doc_rect.h > 0.0 {
            let pos_kind = node
                .primary_styles()
                .map(|s| s.clone_position())
                .unwrap_or(Position::Static);
            if matches!(pos_kind, Position::Fixed | Position::Sticky) || !animations.is_empty() {
                let kind = special_layer_kind(
                    doc,
                    node,
                    pos_kind,
                    doc_rect,
                    root_extent,
                    sticky_insets.as_deref(),
                );
                special_layers.push(SpecialLayerSpec {
                    internal_id: nid,
                    ext_id,
                    scroll_node_id: if pos_kind == Position::Fixed {
                        0
                    } else {
                        sn_id
                    },
                    kind,
                    doc_rect,
                    bg_rgba,
                    opacity,
                    transform,
                    animations,
                    is_fixed: pos_kind == Position::Fixed,
                });
            }
        }

        if let Some(inline) = el.inline_layout_data.as_ref() {
            let pad_l = layout.padding.left + layout.border.left;
            let pad_t = layout.padding.top + layout.border.top + inline.block_offset;
            let rtl = node.primary_styles().is_some_and(|s| {
                s.get_inherited_box().direction
                    == style::properties::generated::longhands::direction::computed_value::T::Rtl
            });
            build_text_run_from_layout(
                ext_id,
                sn_id,
                (pos.x + pad_l, pos.y + pad_t),
                &inline.layout,
                &inline.text,
                rtl,
                &mut text_runs,
            );
        }

        let (cursor, link_url, editable, hover_or_pointer) = node_cursor_v2(doc, node);
        if (cursor != CursorKindV2::Default || link_url.is_some() || editable || hover_or_pointer)
            && doc_rect.w > 0.0
            && doc_rect.h > 0.0
        {
            hit_rects.push(CollectedHitRect {
                scroll_node_id: sn_id,
                doc_rect,
                hit: HitRectMapV2 {
                    rect: doc_rect,
                    node_id: ext_id,
                    scroll_node_id: sn_id,
                    cursor,
                    link_url,
                    editable,
                    hover_or_pointer,
                },
            });
        }

        if el.text_input_data().is_some() {
            if let Some(spec) = collect_editable_spec(dom, doc, node, el, sn_id, &fallback_font) {
                editable_specs.push(spec);
            }
        }
    }
    drop(anim_sets);
    drop(sticky_insets);

    CollectedDomMetadata {
        vw: vw.max(1),
        vh: vh.max(1),
        root_ext_id,
        root_extent,
        scroll_nodes,
        node_scroll_map,
        special_layers,
        root_animations,
        root_opacity,
        root_transform,
        root_bg_rgba,
        text_runs,
        hit_rects,
        editable_specs,
    }
}

fn filter_runs_for_tile(
    runs: &[CollectedTextRun],
    scroll_node_id: u64,
    tile_bounds: RectV2,
) -> Vec<TextRunMapV2> {
    let mut out = Vec::new();
    for item in runs {
        if item.scroll_node_id != scroll_node_id || !item.doc_rect.intersects(tile_bounds) {
            continue;
        }
        let mut r = item.run.clone();
        r.origin_x -= tile_bounds.x;
        r.origin_y -= tile_bounds.y;
        for c in &mut r.cluster_advances {
            c.x -= tile_bounds.x;
            c.selection_bounds.x -= tile_bounds.x;
            c.selection_bounds.y -= tile_bounds.y;
        }
        out.push(r);
    }
    out
}

fn filter_hits_for_tile(
    hits: &[CollectedHitRect],
    scroll_node_id: u64,
    tile_bounds: RectV2,
) -> Vec<HitRectMapV2> {
    let mut out = Vec::new();
    for item in hits {
        if item.scroll_node_id != scroll_node_id || !item.doc_rect.intersects(tile_bounds) {
            continue;
        }
        let mut h = item.hit.clone();
        h.rect.x -= tile_bounds.x;
        h.rect.y -= tile_bounds.y;
        out.push(h);
    }
    out
}

fn compute_tile_hash(ksc0: &[u8], runs: &[TextRunMapV2], hits: &[HitRectMapV2]) -> u64 {
    let mut h = fx_hash_u64(ksc0);
    h ^= (runs.len() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= (hits.len() as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    for r in runs {
        h ^= fx_hash_u64(r.text.as_bytes()).wrapping_mul(0x94D0_49BB_1331_11EB);
    }
    h
}

pub(crate) fn build_scene_frame_v2(
    dom: &DomHandle,
    acked_scroll_seq: u32,
    acked_input_seq: u32,
    known_hashes_bytes: &[u8],
    vel_x: f32,
    vel_y: f32,
    handler_regions_json: &str,
) -> Vec<u8> {
    if dom.layout_mode.get() == crate::LayoutMode::Off {
        return Vec::new();
    }
    dom.resolve_until_images_settle();

    let mut meta = {
        let Ok(doc) = dom.doc.try_borrow() else {
            return Vec::new();
        };
        let collected = collect_dom_metadata(dom, doc.as_ref());
        drop(doc);
        collected
    };

    let parsed_regions = parse_handler_regions(handler_regions_json, meta.root_ext_id);
    let handler_regions =
        apply_non_passive_handler_regions(&mut meta.scroll_nodes, &parsed_regions);

    let root_interest = compute_interest_rect(meta.scroll_nodes[0].clip, vel_x, vel_y);
    let cols = ((meta.root_extent.0 / TILE_SIZE_PX as f32).ceil().max(1.0)) as u32;
    let rows = ((meta.root_extent.1 / TILE_SIZE_PX as f32).ceil().max(1.0)) as u32;

    let mut tile_payloads: Vec<TilePayloadV2> = Vec::new();
    let mut root_tile_refs: Vec<TileRefV2> = Vec::new();
    let mut recorded_count = 0usize;

    for row in 0..rows {
        let ty = row * TILE_SIZE_PX;
        let th = ((meta.root_extent.1 - ty as f32).ceil().max(1.0) as u32).min(TILE_SIZE_PX);
        for col in 0..cols {
            let tx = col * TILE_SIZE_PX;
            let tw = ((meta.root_extent.0 - tx as f32).ceil().max(1.0) as u32).min(TILE_SIZE_PX);
            let bounds = RectV2::new(tx as f32, ty as f32, tw as f32, th as f32);
            if !bounds.intersects(root_interest) || recorded_count >= MAX_SCENE_TILES {
                continue;
            }
            recorded_count += 1;
            let ksc0 = dom.record_ksc0_tile(tx as i32, ty as i32, tw, th, false);
            let runs = filter_runs_for_tile(&meta.text_runs, 0, bounds);
            let hits = filter_hits_for_tile(&meta.hit_rects, 0, bounds);
            let hash = compute_tile_hash(&ksc0, &runs, &hits);
            root_tile_refs.push(TileRefV2 {
                col,
                row,
                bounds,
                content_hash: hash,
            });
            tile_payloads.push(TilePayloadV2 {
                content_hash: hash,
                width: tw,
                height: th,
                vector_ops: ksc0,
                text_runs: runs,
                hit_rects: hits,
            });
        }
    }

    let mut layers = vec![LayerV2 {
        layer_id: 0,
        scroll_node_id: 0,
        kind: LayerKindV2::Normal,
        bounds: RectV2::new(0.0, 0.0, meta.root_extent.0, meta.root_extent.1),
        bg_rgba: meta.root_bg_rgba,
        opacity: meta.root_opacity,
        transform: meta.root_transform,
        animations: meta.root_animations.clone(),
        tile_size: TILE_SIZE_PX,
        tile_refs: root_tile_refs,
        invalidated_hashes: Vec::new(),
    }];

    build_nested_and_special_layers(dom, &meta, &mut layers, &mut tile_payloads, root_interest);

    let known = parse_u64_hash_set(known_hashes_bytes);
    let mut frame = SceneFrameV2 {
        acked_scroll_seq,
        acked_input_seq,
        viewport_w: meta.vw,
        viewport_h: meta.vh,
        scroll_nodes: meta.scroll_nodes,
        layers,
        tiles: deduplicate_tiles_delta(tile_payloads, &known),
        handler_regions,
        editable_specs: meta.editable_specs,
    };
    cull_frame_for_interest(&mut frame, root_interest, &known);
    frame.encode()
}

fn build_nested_and_special_layers(
    dom: &DomHandle,
    meta: &CollectedDomMetadata,
    layers: &mut Vec<LayerV2>,
    tile_payloads: &mut Vec<TilePayloadV2>,
    root_interest: RectV2,
) {
    let mut next_layer_id = 1u64;
    for sn in &meta.scroll_nodes {
        if sn.node_id == 0 {
            continue;
        }
        let layer_bounds = RectV2::new(sn.clip.x, sn.clip.y, sn.extent_w, sn.extent_h);
        if !layer_bounds.intersects(root_interest) {
            continue;
        }
        let tw = (sn.extent_w.ceil().max(1.0) as u32).min(2560);
        let th = (sn.extent_h.ceil().max(1.0) as u32).min(2560);
        let ksc0 = dom.record_ksc0_tile(
            layer_bounds.x.floor() as i32,
            layer_bounds.y.floor() as i32,
            tw,
            th,
            true,
        );
        let tile_bounds = RectV2::new(layer_bounds.x, layer_bounds.y, tw as f32, th as f32);
        let runs = filter_runs_for_tile(&meta.text_runs, sn.node_id, tile_bounds);
        let hits = filter_hits_for_tile(&meta.hit_rects, sn.node_id, tile_bounds);
        let hash = compute_tile_hash(&ksc0, &runs, &hits);
        let tile_ref = TileRefV2 {
            col: 0,
            row: 0,
            bounds: tile_bounds,
            content_hash: hash,
        };
        tile_payloads.push(TilePayloadV2 {
            content_hash: hash,
            width: tw,
            height: th,
            vector_ops: ksc0,
            text_runs: runs,
            hit_rects: hits,
        });
        layers.push(LayerV2 {
            layer_id: next_layer_id,
            scroll_node_id: sn.node_id,
            kind: LayerKindV2::Normal,
            bounds: layer_bounds,
            bg_rgba: [0, 0, 0, 0],
            opacity: 1.0,
            transform: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
            animations: Vec::new(),
            tile_size: tw.max(th).max(TILE_SIZE_PX),
            tile_refs: vec![tile_ref],
            invalidated_hashes: Vec::new(),
        });
        next_layer_id += 1;
    }

    for spec in &meta.special_layers {
        let _ = (&spec.internal_id, &spec.ext_id, &meta.node_scroll_map);
        let clip_x = if spec.is_fixed {
            if let LayerKindV2::Fixed { viewport_anchor } = spec.kind {
                viewport_anchor.x.floor() as i32
            } else {
                spec.doc_rect.x.floor() as i32
            }
        } else {
            spec.doc_rect.x.floor() as i32
        };
        let clip_y = if spec.is_fixed {
            if let LayerKindV2::Fixed { viewport_anchor } = spec.kind {
                viewport_anchor.y.floor() as i32
            } else {
                spec.doc_rect.y.floor() as i32
            }
        } else {
            spec.doc_rect.y.floor() as i32
        };
        let tw = (spec.doc_rect.w.ceil().max(1.0) as u32).min(2560);
        let th = (spec.doc_rect.h.ceil().max(1.0) as u32).min(2560);
        let ksc0 = dom.record_ksc0_tile(clip_x, clip_y, tw, th, true);
        let runs = filter_runs_for_tile(&meta.text_runs, spec.scroll_node_id, spec.doc_rect);
        let hits = filter_hits_for_tile(&meta.hit_rects, spec.scroll_node_id, spec.doc_rect);
        let hash = compute_tile_hash(&ksc0, &runs, &hits);
        let tile_ref = TileRefV2 {
            col: 0,
            row: 0,
            bounds: RectV2::new(spec.doc_rect.x, spec.doc_rect.y, tw as f32, th as f32),
            content_hash: hash,
        };
        tile_payloads.push(TilePayloadV2 {
            content_hash: hash,
            width: tw,
            height: th,
            vector_ops: ksc0,
            text_runs: runs,
            hit_rects: hits,
        });
        layers.push(LayerV2 {
            layer_id: next_layer_id,
            scroll_node_id: spec.scroll_node_id,
            kind: spec.kind.clone(),
            bounds: spec.doc_rect,
            bg_rgba: spec.bg_rgba,
            opacity: spec.opacity,
            transform: spec.transform,
            animations: spec.animations.clone(),
            tile_size: tw.max(th).max(TILE_SIZE_PX),
            tile_refs: vec![tile_ref],
            invalidated_hashes: Vec::new(),
        });
        next_layer_id += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paint::compositor_v2::{CompositeOptsV2, CompositorV2, ScrollInputV2, ScrollOutcomeV2};
    use crate::paint::scene_replay::ResourceStore;

    #[test]
    fn render_scene_v2_splits_tiles_culls_interest_and_dedups() {
        let html = r#"<!DOCTYPE html><html><body style="margin:0">
          <div style="width:1280px;height:3000px;background:#fefefe">
            <p style="margin:20px;font-size:16px">Hello World selectable text</p>
            <a href="https://example.org" style="display:block;width:120px;height:30px">Link</a>
            <input type="text" value="ab" style="width:200px;height:30px">
            <input type="password" value="" style="width:200px;height:30px">
          </div>
        </body></html>"#;
        let dom = DomHandle::new(html, "https://example.test/");
        dom.resolve_layout();
        let bytes = dom.render_scene_v2(3, 5, &[]);
        let frame = SceneFrameV2::decode(&bytes).expect("decode KSC2");
        assert_eq!(frame.acked_scroll_seq, 3);
        assert_eq!(frame.acked_input_seq, 5);
        assert!(
            frame.layers[0].tile_refs.len() > 1,
            "expected multi-tile split"
        );
        assert!(frame.tiles.len() == frame.layers[0].tile_refs.len());
        assert!(frame.scroll_nodes[0].extent_h >= 3000.0);
        // Interest culling leaves tiles well below full 1280x3000 grid (~5x12=60 tiles).
        assert!(frame.layers[0].tile_refs.len() < 45);
        assert!(frame.tiles.iter().any(|t| !t.text_runs.is_empty()));
        assert!(frame
            .tiles
            .iter()
            .any(|t| t.hit_rects.iter().any(|h| h.link_url.is_some())));
        assert_eq!(frame.editable_specs.len(), 2);
        assert!(!frame.editable_specs[0].is_password);
        assert!(!frame.editable_specs[0].font_data.is_empty());
        assert!(!frame.editable_specs[0].cmap.is_empty());
        assert!(frame.editable_specs[1].is_password);

        // Delta deduplication omits known tile payloads on second build.
        let mut known_bytes = Vec::new();
        for t in &frame.tiles {
            known_bytes.extend_from_slice(&t.content_hash.to_le_bytes());
        }
        let delta_bytes = dom.render_scene_v2(4, 5, &known_bytes);
        let delta_frame = SceneFrameV2::decode(&delta_bytes).expect("decode delta");
        assert!(delta_frame.tiles.is_empty());
        assert_eq!(
            delta_frame.layers[0].tile_refs.len(),
            frame.layers[0].tile_refs.len()
        );

        let mut comp = CompositorV2::new();
        comp.apply_frame(frame.clone());
        let store = ResourceStore::default();
        let mut slot = None;
        let (rgba, stats) = comp
            .composite_rgba(&store, &mut slot, CompositeOptsV2::default())
            .expect("composite RGBA");
        assert_eq!(rgba.len(), 8 + (stats.width * stats.height * 4) as usize);
        assert_eq!(stats.checkerboard_tiles, 0);
    }

    #[test]
    fn render_scene_v2_nested_scroller_sticky_fixed_and_handler_regions() {
        let html = r#"<!DOCTYPE html><html><body style="margin:0">
          <div style="position:fixed;top:0;left:0;width:200px;height:40px;background:#112233">Fixed</div>
          <div id="scroller" style="width:300px;height:200px;overflow:auto;overscroll-behavior:contain">
            <div style="position:sticky;top:8px;height:30px;background:#334455">Sticky</div>
            <div style="height:800px">Tall inner content</div>
          </div>
        </body></html>"#;
        let dom = DomHandle::new(html, "https://example.test/");
        dom.resolve_layout();
        let scroller_id = dom.query_selector("#scroller").expect("scroller");
        let regions = format!(
            r#"[{{"scrollNodeId":{scroller_id},"x":0,"y":0,"width":300,"height":200,"eventMask":1,"nonPassive":true}}]"#
        );
        let bytes = dom.render_scene_v2_with_interest(0, 0, &[], 0.0, 0.0, &regions);
        let frame = SceneFrameV2::decode(&bytes).expect("decode");
        assert!(frame.scroll_nodes.len() >= 2, "expected nested scroll node");
        let nested = frame
            .scroll_nodes
            .iter()
            .find(|n| n.node_id == scroller_id as u64)
            .expect("nested node present");
        assert_eq!(nested.overscroll_y, OverscrollBehaviorV2::Contain);
        assert!(nested.server_driven);
        assert_eq!(
            nested.server_driven_reason,
            ServerDrivenReasonV2::NonPassiveHandler
        );
        assert!(frame
            .layers
            .iter()
            .any(|l| matches!(l.kind, LayerKindV2::Fixed { .. })));
        assert!(frame
            .layers
            .iter()
            .any(|l| matches!(l.kind, LayerKindV2::Sticky { .. })));
        assert_eq!(frame.handler_regions.len(), 1);

        let mut comp = CompositorV2::new();
        comp.apply_frame(frame);
        let resp = comp.handle_scroll_input(ScrollInputV2 {
            node_id: scroller_id as u64,
            pt_x: 50.0,
            pt_y: 50.0,
            dx: 0.0,
            dy: 40.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        assert_eq!(resp, ScrollOutcomeV2::ForwardToServer);
    }

    #[test]
    fn render_scene_v2_extracts_css_animation_curves() {
        let html = r#"<!DOCTYPE html><html><head><style>
          @keyframes fadeMove {
            from { opacity: 0.2; transform: translateX(0px); }
            to { opacity: 1.0; transform: translateX(40px); }
          }
          #anim { width: 100px; height: 50px; background: #224466; animation: fadeMove 2s linear 1 forwards; }
        </style></head><body style="margin:0"><div id="anim">Anim</div></body></html>"#;
        let dom = DomHandle::new(html, "https://example.test/");
        dom.resolve_layout();
        let bytes = dom.render_scene_v2(0, 0, &[]);
        let frame = SceneFrameV2::decode(&bytes).expect("decode KSC2");
        let has_opacity_curve = frame.layers.iter().any(|l| {
            l.animations
                .iter()
                .any(|a| a.property == AnimationPropertyV2::Opacity && a.keyframes.len() >= 2)
        });
        assert!(has_opacity_curve, "expected CSS @keyframes opacity curve");
    }

    #[test]
    fn sub_element_non_passive_handler_keeps_root_client_driven() {
        let html = r#"<!DOCTYPE html><html><body style="margin:0;height:1600px">
          <div id="trap" style="position:absolute;top:50px;left:10px;width:160px;height:90px">Trap</div>
        </body></html>"#;
        let dom = DomHandle::new(html, "https://example.test/");
        dom.resolve_layout();
        let root_id = dom.query_selector("html").expect("html");
        let trap_id = dom.query_selector("#trap").expect("trap");

        let sub_regions = format!(
            r#"[{{"targetNodeId":{trap_id},"scrollNodeId":{root_id},"x":10,"y":50,"width":160,"height":90,"eventMask":1,"nonPassive":true,"coversScrollNode":false}}]"#
        );
        let sub_bytes = dom.render_scene_v2_with_interest(0, 0, &[], 0.0, 0.0, &sub_regions);
        let sub_frame = SceneFrameV2::decode(&sub_bytes).expect("decode sub_frame");
        assert!(!sub_frame.scroll_nodes[0].server_driven);
        assert_eq!(sub_frame.handler_regions.len(), 1);
        assert_eq!(sub_frame.handler_regions[0].scroll_node_id, 0);

        let mut comp = CompositorV2::new();
        comp.apply_frame(sub_frame);
        let inside = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 0,
            pt_x: 40.0,
            pt_y: 80.0,
            dx: 0.0,
            dy: 40.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        assert_eq!(inside, ScrollOutcomeV2::ForwardToServer);
        let outside = comp.handle_scroll_input(ScrollInputV2 {
            node_id: 0,
            pt_x: 400.0,
            pt_y: 300.0,
            dx: 0.0,
            dy: 40.0,
            vx: 0.0,
            vy: 0.0,
            event_mask: HANDLER_WHEEL,
        });
        let ScrollOutcomeV2::Local(u) = outside else {
            panic!("expected local scroll outside #trap");
        };
        assert_eq!(u.seq, 1);
        assert_eq!(u.x, 0.0);
        assert_eq!(u.y, 40.0);

        let doc_regions = r#"[{"targetNodeId":0,"scrollNodeId":0,"x":0,"y":0,"width":1280,"height":1600,"eventMask":1,"nonPassive":true,"coversScrollNode":true}]"#;
        let doc_bytes = dom.render_scene_v2_with_interest(0, 0, &[], 0.0, 0.0, doc_regions);
        let doc_frame = SceneFrameV2::decode(&doc_bytes).expect("decode doc_frame");
        assert!(doc_frame.scroll_nodes[0].server_driven);
        assert_eq!(
            doc_frame.scroll_nodes[0].server_driven_reason,
            ServerDrivenReasonV2::NonPassiveHandler
        );
    }

    #[test]
    fn editable_spec_populates_auth_text_and_redacts_password() {
        let html = r#"<!DOCTYPE html><html><body>
          <input id="usr" type="text" value="HELLO" />
          <input id="pwd" type="password" value="s3cr3t" />
        </body></html>"#;
        let dom = DomHandle::new(html, "https://example.test/");
        dom.resolve_layout();
        let usr_id = dom.query_selector("#usr").expect("usr") as u64;
        let pwd_id = dom.query_selector("#pwd").expect("pwd") as u64;
        let bytes = dom.render_scene_v2(0, 0, &[]);
        let frame = SceneFrameV2::decode(&bytes).expect("decode");
        let usr_spec = frame
            .editable_specs
            .iter()
            .find(|s| s.node_id == usr_id)
            .expect("usr spec");
        let pwd_spec = frame
            .editable_specs
            .iter()
            .find(|s| s.node_id == pwd_id)
            .expect("pwd spec");
        assert_eq!(usr_spec.auth_text, "HELLO");
        assert!(!usr_spec.is_password);
        assert!(pwd_spec.is_password);
        assert_eq!(pwd_spec.auth_text, "");
        assert!(!frame
            .editable_specs
            .iter()
            .any(|s| s.auth_text.contains("s3cr3t") || s.field_key.contains("s3cr3t")));
        assert!(
            !frame
                .tiles
                .iter()
                .any(|t| t.text_runs.iter().any(|r| r.text.contains("s3cr3t"))),
            "password value leaked into text_runs"
        );
    }
}
