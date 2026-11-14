// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! KSC2 wire codec, interest-area culler, and delta tile deduplicator for Client Compositor v2.
//! Preserves KSC0 (`scene_record`/`scene_decode`) intact alongside KSC2.

use std::collections::HashSet;
use std::fmt;

pub const KSC2_MAGIC: [u8; 4] = *b"KSC2";
pub const KSC2_VERSION: u32 = 1;
pub const KSV2_MAGIC: [u8; 4] = *b"KSV2";

pub const HANDLER_WHEEL: u8 = 1 << 0;
pub const HANDLER_TOUCH_START: u8 = 1 << 1;
pub const HANDLER_TOUCH_MOVE: u8 = 1 << 2;

const INTEREST_REF_VELOCITY_PX_PER_SEC: f32 = 2000.0;
const MAX_ARRAY_ITEMS: usize = 262_144;
const MAX_BLOB_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeV2Error {
    BadMagic([u8; 4]),
    UnsupportedVersion(u32),
    UnexpectedEof {
        offset: usize,
        needed: usize,
    },
    InvalidTag {
        offset: usize,
        kind: &'static str,
        tag: u8,
    },
    InvalidUtf8 {
        offset: usize,
    },
    CountTooLarge {
        offset: usize,
        count: usize,
    },
}

impl fmt::Display for DecodeV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeV2Error::BadMagic(m) => write!(f, "bad KSC2 magic: {:?}", m),
            DecodeV2Error::UnsupportedVersion(v) => write!(f, "unsupported KSC2 version: {}", v),
            DecodeV2Error::UnexpectedEof { offset, needed } => {
                write!(f, "unexpected EOF at {} (need {} bytes)", offset, needed)
            }
            DecodeV2Error::InvalidTag { offset, kind, tag } => {
                write!(f, "invalid {} tag {} at offset {}", kind, tag, offset)
            }
            DecodeV2Error::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at {}", offset),
            DecodeV2Error::CountTooLarge { offset, count } => {
                write!(f, "count {} exceeds limit at offset {}", count, offset)
            }
        }
    }
}

impl std::error::Error for DecodeV2Error {}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RectV2 {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl RectV2 {
    pub const fn new(x: f32, y: f32, w: f32, h: f32) -> Self {
        Self { x, y, w, h }
    }

    pub fn right(self) -> f32 {
        self.x + self.w
    }

    pub fn bottom(self) -> f32 {
        self.y + self.h
    }

    pub fn contains_point(self, px: f32, py: f32) -> bool {
        px >= self.x && px < self.right() && py >= self.y && py < self.bottom()
    }

    pub fn intersects(self, other: RectV2) -> bool {
        self.x < other.right()
            && self.right() > other.x
            && self.y < other.bottom()
            && self.bottom() > other.y
    }

    pub fn union(self, other: RectV2) -> RectV2 {
        if self.w <= 0.0 || self.h <= 0.0 {
            return other;
        }
        if other.w <= 0.0 || other.h <= 0.0 {
            return self;
        }
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = self.right().max(other.right());
        let y1 = self.bottom().max(other.bottom());
        RectV2::new(x0, y0, (x1 - x0).max(0.0), (y1 - y0).max(0.0))
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverscrollBehaviorV2 {
    #[default]
    Auto = 0,
    Contain = 1,
    None = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServerDrivenReasonV2 {
    #[default]
    None = 0,
    NonPassiveHandler = 1,
    ScrollLinkedEffect = 2,
    SnapStrictnessUnsupported = 3,
    CustomScrollbar = 4,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScrollNodeV2 {
    pub node_id: u64,
    pub parent_id: u64,
    pub extent_w: f32,
    pub extent_h: f32,
    pub clip: RectV2,
    pub auth_offset_x: f32,
    pub auth_offset_y: f32,
    pub snap_points_x: Vec<f32>,
    pub snap_points_y: Vec<f32>,
    pub overscroll_x: OverscrollBehaviorV2,
    pub overscroll_y: OverscrollBehaviorV2,
    pub server_driven: bool,
    pub server_driven_reason: ServerDrivenReasonV2,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LayerKindV2 {
    Normal,
    Fixed {
        viewport_anchor: RectV2,
    },
    Sticky {
        static_rect: RectV2,
        constraint_rect: RectV2,
        top_inset: Option<f32>,
        right_inset: Option<f32>,
        bottom_inset: Option<f32>,
        left_inset: Option<f32>,
    },
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnimationPropertyV2 {
    Opacity = 0,
    Transform = 1,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EasingV2 {
    Linear,
    StepEnd,
    CubicBezier { x1: f32, y1: f32, x2: f32, y2: f32 },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyframeValueV2 {
    Scalar(f32),
    Transform([f32; 6]),
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyframeV2 {
    pub offset: f32,
    pub value: KeyframeValueV2,
    pub easing: EasingV2,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnimationCurveV2 {
    pub property: AnimationPropertyV2,
    pub start_ms: f64,
    pub duration_ms: f64,
    pub iterations: f32,
    pub fill_forwards: bool,
    pub keyframes: Vec<KeyframeV2>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TileRefV2 {
    pub col: u32,
    pub row: u32,
    pub bounds: RectV2,
    pub content_hash: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LayerV2 {
    pub layer_id: u64,
    pub scroll_node_id: u64,
    pub kind: LayerKindV2,
    pub bounds: RectV2,
    pub bg_rgba: [u8; 4],
    pub opacity: f32,
    pub transform: [f32; 6],
    pub animations: Vec<AnimationCurveV2>,
    pub tile_size: u32,
    pub tile_refs: Vec<TileRefV2>,
    pub invalidated_hashes: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClusterAdvanceV2 {
    pub byte_start: u32,
    pub byte_len: u32,
    pub x: f32,
    pub width: f32,
    pub selection_bounds: RectV2,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TextRunMapV2 {
    pub node_id: u64,
    pub text: String,
    pub font_hash: u64,
    pub font_size: f32,
    pub rtl: bool,
    pub origin_x: f32,
    pub origin_y: f32,
    pub ascent: f32,
    pub descent: f32,
    pub cluster_advances: Vec<ClusterAdvanceV2>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CursorKindV2 {
    #[default]
    Default = 0,
    Pointer = 1,
    Text = 2,
    Grab = 3,
    Grabbing = 4,
    NotAllowed = 5,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HitRectMapV2 {
    pub rect: RectV2,
    pub node_id: u64,
    pub scroll_node_id: u64,
    pub cursor: CursorKindV2,
    pub link_url: Option<String>,
    pub editable: bool,
    pub hover_or_pointer: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VectorOpV2 {
    FillRect {
        rect: RectV2,
        rgba: [u8; 4],
        radius: f32,
    },
    StrokeLine {
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
        width: f32,
        rgba: [u8; 4],
    },
    FillCircle {
        cx: f32,
        cy: f32,
        r: f32,
        rgba: [u8; 4],
    },
    FillCubicShape {
        points: Vec<[f32; 2]>,
        rgba: [u8; 4],
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct TilePayloadV2 {
    pub content_hash: u64,
    pub width: u32,
    pub height: u32,
    pub vector_ops: Vec<u8>,
    pub text_runs: Vec<TextRunMapV2>,
    pub hit_rects: Vec<HitRectMapV2>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HandlerRegionV2 {
    pub rect: RectV2,
    pub scroll_node_id: u64,
    pub event_mask: u8,
    pub non_passive: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EditableEchoSpecV2 {
    pub node_id: u64,
    pub scroll_node_id: u64,
    pub field_key: String,
    pub auth_text: String,
    pub rect: RectV2,
    pub is_password: bool,
    pub complex_shaping: bool,
    pub has_ligatures: bool,
    pub font_size: f32,
    pub upem: u16,
    pub color_rgba: [u8; 4],
    pub caret_x: f32,
    pub caret_y: f32,
    pub caret_height: f32,
    pub baseline_y: f32,
    pub font_hash: u64,
    pub font_index: u32,
    pub font_data: Vec<u8>,
    pub cmap: Vec<(u32, u16)>,
    pub advances: Vec<u16>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SceneFrameV2 {
    pub acked_scroll_seq: u32,
    pub acked_input_seq: u32,
    pub viewport_w: u32,
    pub viewport_h: u32,
    pub scroll_nodes: Vec<ScrollNodeV2>,
    pub layers: Vec<LayerV2>,
    pub tiles: Vec<TilePayloadV2>,
    pub handler_regions: Vec<HandlerRegionV2>,
    pub editable_specs: Vec<EditableEchoSpecV2>,
}

pub fn encode_vector_ops_v2(ops: &[VectorOpV2]) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(&KSV2_MAGIC);
    w.u32(ops.len() as u32);
    for op in ops {
        write_vector_op(&mut w, op);
    }
    w.out
}

pub fn decode_vector_ops_v2(bytes: &[u8]) -> Result<Vec<VectorOpV2>, DecodeV2Error> {
    let mut r = Reader::new(bytes);
    let magic = r.fixed4()?;
    if magic != KSV2_MAGIC {
        return Err(DecodeV2Error::BadMagic(magic));
    }
    let count = r.count("vector_ops")?;
    let mut ops = Vec::with_capacity(count);
    for _ in 0..count {
        ops.push(read_vector_op(&mut r)?);
    }
    Ok(ops)
}

impl SceneFrameV2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&KSC2_MAGIC);
        w.u32(KSC2_VERSION);
        w.u32(self.acked_scroll_seq);
        w.u32(self.acked_input_seq);
        w.u32(self.viewport_w);
        w.u32(self.viewport_h);
        w.u32(self.scroll_nodes.len() as u32);
        for node in &self.scroll_nodes {
            write_scroll_node(&mut w, node);
        }
        w.u32(self.layers.len() as u32);
        for layer in &self.layers {
            write_layer(&mut w, layer);
        }
        w.u32(self.tiles.len() as u32);
        for tile in &self.tiles {
            write_tile_payload(&mut w, tile);
        }
        w.u32(self.handler_regions.len() as u32);
        for region in &self.handler_regions {
            write_handler_region(&mut w, region);
        }
        w.u32(self.editable_specs.len() as u32);
        for spec in &self.editable_specs {
            write_editable_spec(&mut w, spec);
        }
        w.out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeV2Error> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed4()?;
        if magic != KSC2_MAGIC {
            return Err(DecodeV2Error::BadMagic(magic));
        }
        let version = r.u32()?;
        if version != KSC2_VERSION {
            return Err(DecodeV2Error::UnsupportedVersion(version));
        }
        let acked_scroll_seq = r.u32()?;
        let acked_input_seq = r.u32()?;
        let viewport_w = r.u32()?;
        let viewport_h = r.u32()?;
        let scroll_nodes = r.vec("scroll_nodes", read_scroll_node)?;
        let layers = r.vec("layers", read_layer)?;
        let tiles = r.vec("tiles", read_tile_payload)?;
        let handler_regions = r.vec("handler_regions", read_handler_region)?;
        let editable_specs = r.vec("editable_specs", read_editable_spec)?;
        Ok(Self {
            acked_scroll_seq,
            acked_input_seq,
            viewport_w,
            viewport_h,
            scroll_nodes,
            layers,
            tiles,
            handler_regions,
            editable_specs,
        })
    }
}

/// Computes an interest rect covering the viewport, 1 viewport behind scroll direction,
/// and up to 2 viewports ahead scaled linearly by velocity.
pub fn compute_interest_rect(viewport: RectV2, velocity_x: f32, velocity_y: f32) -> RectV2 {
    let (x0, x1) = axis_interest_span(viewport.x, viewport.w, velocity_x);
    let (y0, y1) = axis_interest_span(viewport.y, viewport.h, velocity_y);
    RectV2::new(x0, y0, (x1 - x0).max(0.0), (y1 - y0).max(0.0))
}

fn axis_interest_span(pos: f32, dim: f32, velocity: f32) -> (f32, f32) {
    let size = if dim.is_finite() { dim.max(0.0) } else { 0.0 };
    let v = if velocity.is_finite() { velocity } else { 0.0 };
    let scale = (v.abs() / INTEREST_REF_VELOCITY_PX_PER_SEC).min(1.0);
    let ahead = 2.0 * size * scale;
    let behind = size;
    if v >= 0.0 {
        let min = (pos - behind).max(0.0);
        let max = pos + size + ahead;
        (min, max)
    } else {
        let min = (pos - ahead).max(0.0);
        let max = pos + size + behind;
        (min, max)
    }
}

/// Removes tile payloads whose `content_hash` is already present on the client
/// or duplicated within the same batch.
pub fn deduplicate_tiles_delta(
    tiles: Vec<TilePayloadV2>,
    known_hashes: &HashSet<u64>,
) -> Vec<TilePayloadV2> {
    let mut seen = HashSet::with_capacity(tiles.len());
    let mut out = Vec::with_capacity(tiles.len());
    for tile in tiles {
        if known_hashes.contains(&tile.content_hash) {
            continue;
        }
        if seen.insert(tile.content_hash) {
            out.push(tile);
        }
    }
    out
}

/// Culls `tile_refs` outside `interest` and strips tile payloads already in `known_hashes`.
pub fn cull_frame_for_interest(
    frame: &mut SceneFrameV2,
    interest: RectV2,
    known_hashes: &HashSet<u64>,
) {
    let mut needed = HashSet::new();
    for layer in &mut frame.layers {
        let fixed = matches!(layer.kind, LayerKindV2::Fixed { .. });
        layer
            .tile_refs
            .retain(|tr| fixed || tr.bounds.intersects(interest));
        for tr in &layer.tile_refs {
            needed.insert(tr.content_hash);
        }
    }
    let tiles = std::mem::take(&mut frame.tiles);
    let filtered: Vec<TilePayloadV2> = tiles
        .into_iter()
        .filter(|t| needed.contains(&t.content_hash))
        .collect();
    frame.tiles = deduplicate_tiles_delta(filtered, known_hashes);
}

struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self {
            out: Vec::with_capacity(512),
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    fn bool(&mut self, v: bool) {
        self.out.push(u8::from(v));
    }

    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn f32(&mut self, v: f32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn f64(&mut self, v: f64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn rect(&mut self, r: RectV2) {
        self.f32(r.x);
        self.f32(r.y);
        self.f32(r.w);
        self.f32(r.h);
    }

    fn opt_f32(&mut self, v: Option<f32>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.f32(x);
            }
            None => self.u8(0),
        }
    }

    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.raw(b);
    }

    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
}

struct Reader<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeV2Error> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DecodeV2Error::UnexpectedEof {
                offset: self.pos,
                needed: n,
            })?;
        let slice = self
            .src
            .get(self.pos..end)
            .ok_or(DecodeV2Error::UnexpectedEof {
                offset: self.pos,
                needed: n,
            })?;
        self.pos = end;
        Ok(slice)
    }

    fn fixed4(&mut self) -> Result<[u8; 4], DecodeV2Error> {
        let s = self.take(4)?;
        Ok([s[0], s[1], s[2], s[3]])
    }

    fn u8(&mut self) -> Result<u8, DecodeV2Error> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, DecodeV2Error> {
        Ok(self.u8()? != 0)
    }

    fn u16(&mut self) -> Result<u16, DecodeV2Error> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32, DecodeV2Error> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> Result<u64, DecodeV2Error> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn f32(&mut self) -> Result<f32, DecodeV2Error> {
        Ok(f32::from_le_bytes(self.fixed4()?))
    }

    fn f64(&mut self) -> Result<f64, DecodeV2Error> {
        let s = self.take(8)?;
        Ok(f64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn rect(&mut self) -> Result<RectV2, DecodeV2Error> {
        Ok(RectV2::new(
            self.f32()?,
            self.f32()?,
            self.f32()?,
            self.f32()?,
        ))
    }

    fn opt_f32(&mut self) -> Result<Option<f32>, DecodeV2Error> {
        let present = self.u8()?;
        if present == 0 {
            return Ok(None);
        }
        Ok(Some(self.f32()?))
    }

    fn count(&mut self, _label: &str) -> Result<usize, DecodeV2Error> {
        let off = self.pos;
        let count = self.u32()? as usize;
        if count > MAX_ARRAY_ITEMS {
            return Err(DecodeV2Error::CountTooLarge { offset: off, count });
        }
        Ok(count)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, DecodeV2Error> {
        let off = self.pos;
        let len = self.u32()? as usize;
        if len > MAX_BLOB_BYTES {
            return Err(DecodeV2Error::CountTooLarge {
                offset: off,
                count: len,
            });
        }
        Ok(self.take(len)?.to_vec())
    }

    fn str(&mut self) -> Result<String, DecodeV2Error> {
        let off = self.pos;
        let bytes = self.bytes()?;
        String::from_utf8(bytes).map_err(|_| DecodeV2Error::InvalidUtf8 { offset: off })
    }

    fn vec<T>(
        &mut self,
        label: &str,
        mut f: impl FnMut(&mut Self) -> Result<T, DecodeV2Error>,
    ) -> Result<Vec<T>, DecodeV2Error> {
        let count = self.count(label)?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(f(self)?);
        }
        Ok(out)
    }
}

fn write_vector_op(w: &mut Writer, op: &VectorOpV2) {
    match op {
        VectorOpV2::FillRect { rect, rgba, radius } => {
            w.u8(0);
            w.rect(*rect);
            w.raw(rgba);
            w.f32(*radius);
        }
        VectorOpV2::StrokeLine {
            x0,
            y0,
            x1,
            y1,
            width,
            rgba,
        } => {
            w.u8(1);
            w.f32(*x0);
            w.f32(*y0);
            w.f32(*x1);
            w.f32(*y1);
            w.f32(*width);
            w.raw(rgba);
        }
        VectorOpV2::FillCircle { cx, cy, r, rgba } => {
            w.u8(2);
            w.f32(*cx);
            w.f32(*cy);
            w.f32(*r);
            w.raw(rgba);
        }
        VectorOpV2::FillCubicShape { points, rgba } => {
            w.u8(3);
            w.u32(points.len() as u32);
            for pt in points {
                w.f32(pt[0]);
                w.f32(pt[1]);
            }
            w.raw(rgba);
        }
    }
}

fn read_vector_op(r: &mut Reader<'_>) -> Result<VectorOpV2, DecodeV2Error> {
    let off = r.pos;
    match r.u8()? {
        0 => Ok(VectorOpV2::FillRect {
            rect: r.rect()?,
            rgba: r.fixed4()?,
            radius: r.f32()?,
        }),
        1 => Ok(VectorOpV2::StrokeLine {
            x0: r.f32()?,
            y0: r.f32()?,
            x1: r.f32()?,
            y1: r.f32()?,
            width: r.f32()?,
            rgba: r.fixed4()?,
        }),
        2 => Ok(VectorOpV2::FillCircle {
            cx: r.f32()?,
            cy: r.f32()?,
            r: r.f32()?,
            rgba: r.fixed4()?,
        }),
        3 => {
            let points = r.vec("cubic_points", |rd| Ok([rd.f32()?, rd.f32()?]))?;
            Ok(VectorOpV2::FillCubicShape {
                points,
                rgba: r.fixed4()?,
            })
        }
        tag => Err(DecodeV2Error::InvalidTag {
            offset: off,
            kind: "VectorOpV2",
            tag,
        }),
    }
}

fn write_overscroll(w: &mut Writer, b: OverscrollBehaviorV2) {
    w.u8(b as u8);
}

fn read_overscroll(r: &mut Reader<'_>) -> Result<OverscrollBehaviorV2, DecodeV2Error> {
    let off = r.pos;
    match r.u8()? {
        0 => Ok(OverscrollBehaviorV2::Auto),
        1 => Ok(OverscrollBehaviorV2::Contain),
        2 => Ok(OverscrollBehaviorV2::None),
        tag => Err(DecodeV2Error::InvalidTag {
            offset: off,
            kind: "OverscrollBehaviorV2",
            tag,
        }),
    }
}

fn write_server_reason(w: &mut Writer, reason: ServerDrivenReasonV2) {
    w.u8(reason as u8);
}

fn read_server_reason(r: &mut Reader<'_>) -> Result<ServerDrivenReasonV2, DecodeV2Error> {
    let off = r.pos;
    match r.u8()? {
        0 => Ok(ServerDrivenReasonV2::None),
        1 => Ok(ServerDrivenReasonV2::NonPassiveHandler),
        2 => Ok(ServerDrivenReasonV2::ScrollLinkedEffect),
        3 => Ok(ServerDrivenReasonV2::SnapStrictnessUnsupported),
        4 => Ok(ServerDrivenReasonV2::CustomScrollbar),
        tag => Err(DecodeV2Error::InvalidTag {
            offset: off,
            kind: "ServerDrivenReasonV2",
            tag,
        }),
    }
}

fn write_scroll_node(w: &mut Writer, n: &ScrollNodeV2) {
    w.u64(n.node_id);
    w.u64(n.parent_id);
    w.f32(n.extent_w);
    w.f32(n.extent_h);
    w.rect(n.clip);
    w.f32(n.auth_offset_x);
    w.f32(n.auth_offset_y);
    w.u32(n.snap_points_x.len() as u32);
    for &p in &n.snap_points_x {
        w.f32(p);
    }
    w.u32(n.snap_points_y.len() as u32);
    for &p in &n.snap_points_y {
        w.f32(p);
    }
    write_overscroll(w, n.overscroll_x);
    write_overscroll(w, n.overscroll_y);
    w.bool(n.server_driven);
    write_server_reason(w, n.server_driven_reason);
}

fn read_scroll_node(r: &mut Reader<'_>) -> Result<ScrollNodeV2, DecodeV2Error> {
    let node_id = r.u64()?;
    let parent_id = r.u64()?;
    let extent_w = r.f32()?;
    let extent_h = r.f32()?;
    let clip = r.rect()?;
    let auth_offset_x = r.f32()?;
    let auth_offset_y = r.f32()?;
    let snap_points_x = r.vec("snap_x", |rd| rd.f32())?;
    let snap_points_y = r.vec("snap_y", |rd| rd.f32())?;
    let overscroll_x = read_overscroll(r)?;
    let overscroll_y = read_overscroll(r)?;
    let server_driven = r.bool()?;
    let server_driven_reason = read_server_reason(r)?;
    Ok(ScrollNodeV2 {
        node_id,
        parent_id,
        extent_w,
        extent_h,
        clip,
        auth_offset_x,
        auth_offset_y,
        snap_points_x,
        snap_points_y,
        overscroll_x,
        overscroll_y,
        server_driven,
        server_driven_reason,
    })
}

fn write_layer_kind(w: &mut Writer, kind: &LayerKindV2) {
    match kind {
        LayerKindV2::Normal => w.u8(0),
        LayerKindV2::Fixed { viewport_anchor } => {
            w.u8(1);
            w.rect(*viewport_anchor);
        }
        LayerKindV2::Sticky {
            static_rect,
            constraint_rect,
            top_inset,
            right_inset,
            bottom_inset,
            left_inset,
        } => {
            w.u8(2);
            w.rect(*static_rect);
            w.rect(*constraint_rect);
            w.opt_f32(*top_inset);
            w.opt_f32(*right_inset);
            w.opt_f32(*bottom_inset);
            w.opt_f32(*left_inset);
        }
    }
}

fn read_layer_kind(r: &mut Reader<'_>) -> Result<LayerKindV2, DecodeV2Error> {
    let off = r.pos;
    match r.u8()? {
        0 => Ok(LayerKindV2::Normal),
        1 => Ok(LayerKindV2::Fixed {
            viewport_anchor: r.rect()?,
        }),
        2 => Ok(LayerKindV2::Sticky {
            static_rect: r.rect()?,
            constraint_rect: r.rect()?,
            top_inset: r.opt_f32()?,
            right_inset: r.opt_f32()?,
            bottom_inset: r.opt_f32()?,
            left_inset: r.opt_f32()?,
        }),
        tag => Err(DecodeV2Error::InvalidTag {
            offset: off,
            kind: "LayerKindV2",
            tag,
        }),
    }
}

fn write_easing(w: &mut Writer, easing: EasingV2) {
    match easing {
        EasingV2::Linear => w.u8(0),
        EasingV2::StepEnd => w.u8(1),
        EasingV2::CubicBezier { x1, y1, x2, y2 } => {
            w.u8(2);
            w.f32(x1);
            w.f32(y1);
            w.f32(x2);
            w.f32(y2);
        }
    }
}

fn read_easing(r: &mut Reader<'_>) -> Result<EasingV2, DecodeV2Error> {
    let off = r.pos;
    match r.u8()? {
        0 => Ok(EasingV2::Linear),
        1 => Ok(EasingV2::StepEnd),
        2 => Ok(EasingV2::CubicBezier {
            x1: r.f32()?,
            y1: r.f32()?,
            x2: r.f32()?,
            y2: r.f32()?,
        }),
        tag => Err(DecodeV2Error::InvalidTag {
            offset: off,
            kind: "EasingV2",
            tag,
        }),
    }
}

fn write_animation_curve(w: &mut Writer, curve: &AnimationCurveV2) {
    w.u8(curve.property as u8);
    w.f64(curve.start_ms);
    w.f64(curve.duration_ms);
    w.f32(curve.iterations);
    w.bool(curve.fill_forwards);
    w.u32(curve.keyframes.len() as u32);
    for kf in &curve.keyframes {
        w.f32(kf.offset);
        match kf.value {
            KeyframeValueV2::Scalar(s) => {
                w.u8(0);
                w.f32(s);
            }
            KeyframeValueV2::Transform(m) => {
                w.u8(1);
                for v in m {
                    w.f32(v);
                }
            }
        }
        write_easing(w, kf.easing);
    }
}

fn read_animation_curve(r: &mut Reader<'_>) -> Result<AnimationCurveV2, DecodeV2Error> {
    let prop_off = r.pos;
    let property = match r.u8()? {
        0 => AnimationPropertyV2::Opacity,
        1 => AnimationPropertyV2::Transform,
        tag => {
            return Err(DecodeV2Error::InvalidTag {
                offset: prop_off,
                kind: "AnimationPropertyV2",
                tag,
            });
        }
    };
    let start_ms = r.f64()?;
    let duration_ms = r.f64()?;
    let iterations = r.f32()?;
    let fill_forwards = r.bool()?;
    let keyframes = r.vec("keyframes", |rd| {
        let offset = rd.f32()?;
        let val_off = rd.pos;
        let value = match rd.u8()? {
            0 => KeyframeValueV2::Scalar(rd.f32()?),
            1 => KeyframeValueV2::Transform([
                rd.f32()?,
                rd.f32()?,
                rd.f32()?,
                rd.f32()?,
                rd.f32()?,
                rd.f32()?,
            ]),
            tag => {
                return Err(DecodeV2Error::InvalidTag {
                    offset: val_off,
                    kind: "KeyframeValueV2",
                    tag,
                });
            }
        };
        let easing = read_easing(rd)?;
        Ok(KeyframeV2 {
            offset,
            value,
            easing,
        })
    })?;
    Ok(AnimationCurveV2 {
        property,
        start_ms,
        duration_ms,
        iterations,
        fill_forwards,
        keyframes,
    })
}

fn write_layer(w: &mut Writer, layer: &LayerV2) {
    w.u64(layer.layer_id);
    w.u64(layer.scroll_node_id);
    write_layer_kind(w, &layer.kind);
    w.rect(layer.bounds);
    w.raw(&layer.bg_rgba);
    w.f32(layer.opacity);
    for v in layer.transform {
        w.f32(v);
    }
    w.u32(layer.animations.len() as u32);
    for anim in &layer.animations {
        write_animation_curve(w, anim);
    }
    w.u32(layer.tile_size);
    w.u32(layer.tile_refs.len() as u32);
    for tr in &layer.tile_refs {
        w.u32(tr.col);
        w.u32(tr.row);
        w.rect(tr.bounds);
        w.u64(tr.content_hash);
    }
    w.u32(layer.invalidated_hashes.len() as u32);
    for &h in &layer.invalidated_hashes {
        w.u64(h);
    }
}

fn read_layer(r: &mut Reader<'_>) -> Result<LayerV2, DecodeV2Error> {
    let layer_id = r.u64()?;
    let scroll_node_id = r.u64()?;
    let kind = read_layer_kind(r)?;
    let bounds = r.rect()?;
    let bg_rgba = r.fixed4()?;
    let opacity = r.f32()?;
    let transform = [r.f32()?, r.f32()?, r.f32()?, r.f32()?, r.f32()?, r.f32()?];
    let animations = r.vec("animations", read_animation_curve)?;
    let tile_size = r.u32()?;
    let tile_refs = r.vec("tile_refs", |rd| {
        Ok(TileRefV2 {
            col: rd.u32()?,
            row: rd.u32()?,
            bounds: rd.rect()?,
            content_hash: rd.u64()?,
        })
    })?;
    let invalidated_hashes = r.vec("invalidated_hashes", |rd| rd.u64())?;
    Ok(LayerV2 {
        layer_id,
        scroll_node_id,
        kind,
        bounds,
        bg_rgba,
        opacity,
        transform,
        animations,
        tile_size,
        tile_refs,
        invalidated_hashes,
    })
}

fn write_text_run(w: &mut Writer, run: &TextRunMapV2) {
    w.u64(run.node_id);
    w.str(&run.text);
    w.u64(run.font_hash);
    w.f32(run.font_size);
    w.bool(run.rtl);
    w.f32(run.origin_x);
    w.f32(run.origin_y);
    w.f32(run.ascent);
    w.f32(run.descent);
    w.u32(run.cluster_advances.len() as u32);
    for c in &run.cluster_advances {
        w.u32(c.byte_start);
        w.u32(c.byte_len);
        w.f32(c.x);
        w.f32(c.width);
        w.rect(c.selection_bounds);
    }
}

fn read_text_run(r: &mut Reader<'_>) -> Result<TextRunMapV2, DecodeV2Error> {
    Ok(TextRunMapV2 {
        node_id: r.u64()?,
        text: r.str()?,
        font_hash: r.u64()?,
        font_size: r.f32()?,
        rtl: r.bool()?,
        origin_x: r.f32()?,
        origin_y: r.f32()?,
        ascent: r.f32()?,
        descent: r.f32()?,
        cluster_advances: r.vec("clusters", |rd| {
            Ok(ClusterAdvanceV2 {
                byte_start: rd.u32()?,
                byte_len: rd.u32()?,
                x: rd.f32()?,
                width: rd.f32()?,
                selection_bounds: rd.rect()?,
            })
        })?,
    })
}

fn write_hit_rect(w: &mut Writer, hit: &HitRectMapV2) {
    w.rect(hit.rect);
    w.u64(hit.node_id);
    w.u64(hit.scroll_node_id);
    w.u8(hit.cursor as u8);
    match &hit.link_url {
        Some(url) => {
            w.u8(1);
            w.str(url);
        }
        None => w.u8(0),
    }
    w.bool(hit.editable);
    w.bool(hit.hover_or_pointer);
}

fn read_cursor(r: &mut Reader<'_>) -> Result<CursorKindV2, DecodeV2Error> {
    let off = r.pos;
    match r.u8()? {
        0 => Ok(CursorKindV2::Default),
        1 => Ok(CursorKindV2::Pointer),
        2 => Ok(CursorKindV2::Text),
        3 => Ok(CursorKindV2::Grab),
        4 => Ok(CursorKindV2::Grabbing),
        5 => Ok(CursorKindV2::NotAllowed),
        tag => Err(DecodeV2Error::InvalidTag {
            offset: off,
            kind: "CursorKindV2",
            tag,
        }),
    }
}

fn read_hit_rect(r: &mut Reader<'_>) -> Result<HitRectMapV2, DecodeV2Error> {
    let rect = r.rect()?;
    let node_id = r.u64()?;
    let scroll_node_id = r.u64()?;
    let cursor = read_cursor(r)?;
    let link_url = if r.u8()? != 0 { Some(r.str()?) } else { None };
    let editable = r.bool()?;
    let hover_or_pointer = r.bool()?;
    Ok(HitRectMapV2 {
        rect,
        node_id,
        scroll_node_id,
        cursor,
        link_url,
        editable,
        hover_or_pointer,
    })
}

fn write_tile_payload(w: &mut Writer, tile: &TilePayloadV2) {
    w.u64(tile.content_hash);
    w.u32(tile.width);
    w.u32(tile.height);
    w.bytes(&tile.vector_ops);
    w.u32(tile.text_runs.len() as u32);
    for run in &tile.text_runs {
        write_text_run(w, run);
    }
    w.u32(tile.hit_rects.len() as u32);
    for hit in &tile.hit_rects {
        write_hit_rect(w, hit);
    }
}

fn read_tile_payload(r: &mut Reader<'_>) -> Result<TilePayloadV2, DecodeV2Error> {
    Ok(TilePayloadV2 {
        content_hash: r.u64()?,
        width: r.u32()?,
        height: r.u32()?,
        vector_ops: r.bytes()?,
        text_runs: r.vec("text_runs", read_text_run)?,
        hit_rects: r.vec("hit_rects", read_hit_rect)?,
    })
}

fn write_handler_region(w: &mut Writer, region: &HandlerRegionV2) {
    w.rect(region.rect);
    w.u64(region.scroll_node_id);
    w.u8(region.event_mask);
    w.bool(region.non_passive);
}

fn read_handler_region(r: &mut Reader<'_>) -> Result<HandlerRegionV2, DecodeV2Error> {
    Ok(HandlerRegionV2 {
        rect: r.rect()?,
        scroll_node_id: r.u64()?,
        event_mask: r.u8()?,
        non_passive: r.bool()?,
    })
}

fn write_editable_spec(w: &mut Writer, spec: &EditableEchoSpecV2) {
    w.u64(spec.node_id);
    w.u64(spec.scroll_node_id);
    w.str(&spec.field_key);
    w.str(&spec.auth_text);
    w.rect(spec.rect);
    w.bool(spec.is_password);
    w.bool(spec.complex_shaping);
    w.bool(spec.has_ligatures);
    w.f32(spec.font_size);
    w.u16(spec.upem);
    w.raw(&spec.color_rgba);
    w.f32(spec.caret_x);
    w.f32(spec.caret_y);
    w.f32(spec.caret_height);
    w.f32(spec.baseline_y);
    w.u64(spec.font_hash);
    w.u32(spec.font_index);
    w.bytes(&spec.font_data);
    w.u32(spec.cmap.len() as u32);
    for &(cp, gid) in &spec.cmap {
        w.u32(cp);
        w.u16(gid);
    }
    w.u32(spec.advances.len() as u32);
    for &adv in &spec.advances {
        w.u16(adv);
    }
}

fn read_editable_spec(r: &mut Reader<'_>) -> Result<EditableEchoSpecV2, DecodeV2Error> {
    Ok(EditableEchoSpecV2 {
        node_id: r.u64()?,
        scroll_node_id: r.u64()?,
        field_key: r.str()?,
        auth_text: r.str()?,
        rect: r.rect()?,
        is_password: r.bool()?,
        complex_shaping: r.bool()?,
        has_ligatures: r.bool()?,
        font_size: r.f32()?,
        upem: r.u16()?,
        color_rgba: r.fixed4()?,
        caret_x: r.f32()?,
        caret_y: r.f32()?,
        caret_height: r.f32()?,
        baseline_y: r.f32()?,
        font_hash: r.u64()?,
        font_index: r.u32()?,
        font_data: r.bytes()?,
        cmap: r.vec("cmap", |rd| Ok((rd.u32()?, rd.u16()?)))?,
        advances: r.vec("advances", |rd| rd.u16())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> SceneFrameV2 {
        let vector_ops = encode_vector_ops_v2(&[
            VectorOpV2::FillRect {
                rect: RectV2::new(0.0, 0.0, 256.0, 256.0),
                rgba: [240, 240, 255, 255],
                radius: 8.0,
            },
            VectorOpV2::FillCircle {
                cx: 64.0,
                cy: 64.0,
                r: 24.0,
                rgba: [10, 90, 200, 255],
            },
        ]);
        SceneFrameV2 {
            acked_scroll_seq: 42,
            acked_input_seq: 17,
            viewport_w: 800,
            viewport_h: 600,
            scroll_nodes: vec![ScrollNodeV2 {
                node_id: 1,
                parent_id: 0,
                extent_w: 800.0,
                extent_h: 4800.0,
                clip: RectV2::new(0.0, 0.0, 800.0, 600.0),
                auth_offset_x: 0.0,
                auth_offset_y: 120.0,
                snap_points_x: vec![0.0],
                snap_points_y: vec![0.0, 600.0, 1200.0],
                overscroll_x: OverscrollBehaviorV2::Contain,
                overscroll_y: OverscrollBehaviorV2::Auto,
                server_driven: false,
                server_driven_reason: ServerDrivenReasonV2::None,
            }],
            layers: vec![LayerV2 {
                layer_id: 10,
                scroll_node_id: 1,
                kind: LayerKindV2::Sticky {
                    static_rect: RectV2::new(0.0, 100.0, 800.0, 50.0),
                    constraint_rect: RectV2::new(0.0, 100.0, 800.0, 900.0),
                    top_inset: Some(12.0),
                    right_inset: None,
                    bottom_inset: None,
                    left_inset: None,
                },
                bounds: RectV2::new(0.0, 0.0, 800.0, 4800.0),
                bg_rgba: [255, 255, 255, 255],
                opacity: 1.0,
                transform: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
                animations: vec![AnimationCurveV2 {
                    property: AnimationPropertyV2::Opacity,
                    start_ms: 0.0,
                    duration_ms: 500.0,
                    iterations: 1.0,
                    fill_forwards: true,
                    keyframes: vec![
                        KeyframeV2 {
                            offset: 0.0,
                            value: KeyframeValueV2::Scalar(0.2),
                            easing: EasingV2::Linear,
                        },
                        KeyframeV2 {
                            offset: 1.0,
                            value: KeyframeValueV2::Scalar(1.0),
                            easing: EasingV2::CubicBezier {
                                x1: 0.4,
                                y1: 0.0,
                                x2: 0.2,
                                y2: 1.0,
                            },
                        },
                    ],
                }],
                tile_size: 256,
                tile_refs: vec![
                    TileRefV2 {
                        col: 0,
                        row: 0,
                        bounds: RectV2::new(0.0, 0.0, 256.0, 256.0),
                        content_hash: 0xAABB_CCDD_0001,
                    },
                    TileRefV2 {
                        col: 0,
                        row: 12,
                        bounds: RectV2::new(0.0, 3072.0, 256.0, 256.0),
                        content_hash: 0xAABB_CCDD_0002,
                    },
                ],
                invalidated_hashes: vec![0x9999],
            }],
            tiles: vec![TilePayloadV2 {
                content_hash: 0xAABB_CCDD_0001,
                width: 256,
                height: 256,
                vector_ops,
                text_runs: vec![TextRunMapV2 {
                    node_id: 77,
                    text: "Hello世界".into(),
                    font_hash: 55,
                    font_size: 16.0,
                    rtl: false,
                    origin_x: 10.0,
                    origin_y: 24.0,
                    ascent: 14.0,
                    descent: 4.0,
                    cluster_advances: vec![ClusterAdvanceV2 {
                        byte_start: 0,
                        byte_len: 5,
                        x: 10.0,
                        width: 40.0,
                        selection_bounds: RectV2::new(10.0, 10.0, 40.0, 18.0),
                    }],
                }],
                hit_rects: vec![HitRectMapV2 {
                    rect: RectV2::new(10.0, 10.0, 120.0, 24.0),
                    node_id: 77,
                    scroll_node_id: 1,
                    cursor: CursorKindV2::Pointer,
                    link_url: Some("https://example.com".into()),
                    editable: false,
                    hover_or_pointer: true,
                }],
            }],
            handler_regions: vec![HandlerRegionV2 {
                rect: RectV2::new(0.0, 0.0, 200.0, 200.0),
                scroll_node_id: 1,
                event_mask: HANDLER_WHEEL | HANDLER_TOUCH_MOVE,
                non_passive: true,
            }],
            editable_specs: vec![EditableEchoSpecV2 {
                node_id: 88,
                scroll_node_id: 1,
                field_key: "input#email".into(),
                auth_text: "ab".into(),
                rect: RectV2::new(20.0, 80.0, 240.0, 32.0),
                is_password: false,
                complex_shaping: false,
                has_ligatures: false,
                font_size: 16.0,
                upem: 1000,
                color_rgba: [20, 20, 20, 255],
                caret_x: 24.0,
                caret_y: 84.0,
                caret_height: 20.0,
                baseline_y: 100.0,
                font_hash: 55,
                font_index: 0,
                font_data: vec![0x00, 0x01, 0x00, 0x00],
                cmap: vec![(b'a' as u32, 1), (b'b' as u32, 2), (0x2022, 3)],
                advances: vec![0, 500, 550, 400],
            }],
        }
    }

    #[test]
    fn ksc2_round_trip_preserves_all_fields() {
        let frame = sample_frame();
        let encoded = frame.encode();
        assert_eq!(&encoded[0..4], b"KSC2");
        let decoded = SceneFrameV2::decode(&encoded).expect("decode KSC2");
        assert_eq!(frame, decoded);
        let ops = decode_vector_ops_v2(&decoded.tiles[0].vector_ops).expect("decode KSV2");
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn ksc2_rejects_bad_magic_version_and_truncated_input() {
        let encoded = sample_frame().encode();
        let mut bad_magic = encoded.clone();
        bad_magic[0..4].copy_from_slice(b"KSC0");
        assert!(matches!(
            SceneFrameV2::decode(&bad_magic),
            Err(DecodeV2Error::BadMagic(_))
        ));
        let mut bad_ver = encoded.clone();
        bad_ver[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            SceneFrameV2::decode(&bad_ver),
            Err(DecodeV2Error::UnsupportedVersion(99))
        ));
        assert!(matches!(
            SceneFrameV2::decode(&encoded[..12]),
            Err(DecodeV2Error::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn interest_rect_scales_up_to_two_viewports_ahead_and_one_behind() {
        let vp = RectV2::new(0.0, 1000.0, 800.0, 600.0);
        let static_r = compute_interest_rect(vp, 0.0, 0.0);
        assert_eq!(static_r, RectV2::new(0.0, 400.0, 800.0, 1200.0));

        let mid_x = compute_interest_rect(RectV2::new(800.0, 1000.0, 800.0, 600.0), 0.0, 0.0);
        assert_eq!(mid_x, RectV2::new(0.0, 400.0, 1600.0, 1200.0));

        let fast_down = compute_interest_rect(vp, 0.0, 3000.0);
        assert_eq!(fast_r_y(fast_down), (400.0, 2800.0));

        let fast_up = compute_interest_rect(vp, 0.0, -2000.0);
        assert_eq!(fast_r_y(fast_up), (0.0, 2200.0));
    }

    fn fast_r_y(r: RectV2) -> (f32, f32) {
        (r.y, r.bottom())
    }

    #[test]
    fn deduplicate_and_cull_tiles_by_interest_and_known_hashes() {
        let mut frame = sample_frame();
        frame.tiles.push(TilePayloadV2 {
            content_hash: 0xAABB_CCDD_0002,
            width: 256,
            height: 256,
            vector_ops: Vec::new(),
            text_runs: Vec::new(),
            hit_rects: Vec::new(),
        });
        let interest = compute_interest_rect(RectV2::new(0.0, 0.0, 800.0, 600.0), 0.0, 0.0);
        let mut known = HashSet::new();
        known.insert(0xAABB_CCDD_0001);
        cull_frame_for_interest(&mut frame, interest, &known);
        assert_eq!(frame.layers[0].tile_refs.len(), 1);
        assert_eq!(frame.layers[0].tile_refs[0].content_hash, 0xAABB_CCDD_0001);
        assert!(frame.tiles.is_empty());

        known.clear();
        let dedup = deduplicate_tiles_delta(
            vec![
                TilePayloadV2 {
                    content_hash: 1,
                    width: 10,
                    height: 10,
                    vector_ops: Vec::new(),
                    text_runs: Vec::new(),
                    hit_rects: Vec::new(),
                },
                TilePayloadV2 {
                    content_hash: 1,
                    width: 10,
                    height: 10,
                    vector_ops: Vec::new(),
                    text_runs: Vec::new(),
                    hit_rects: Vec::new(),
                },
                TilePayloadV2 {
                    content_hash: 2,
                    width: 10,
                    height: 10,
                    vector_ops: Vec::new(),
                    text_runs: Vec::new(),
                    hit_rects: Vec::new(),
                },
            ],
            &known,
        );
        assert_eq!(dedup.len(), 2);
    }
}
