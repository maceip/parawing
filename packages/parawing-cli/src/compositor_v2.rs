// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Typed host wrapper around the Client Compositor v2 byte ABI (`ops 20..=28`) in scene-host.

use crate::wasm::Raster;
use std::error::Error;

const OP_V2_INGEST_FRAME: u32 = 20;
const OP_V2_COMPOSITE: u32 = 21;
const OP_V2_SCROLL_INPUT: u32 = 22;
const OP_V2_STEP_FLING: u32 = 23;
const OP_V2_HIT_TEST: u32 = 24;
const OP_V2_SELECT_TEXT: u32 = 25;
const OP_V2_PREDICT_TYPE: u32 = 26;
const OP_V2_KNOWN_HASHES: u32 = 27;
const OP_V2_METRICS: u32 = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameAckStatsV2 {
    pub acked_scroll_seq: u32,
    pub acked_input_seq: u32,
    pub tiles_cached: u32,
    pub tiles_evicted: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScrollResultV2 {
    pub forwarded: bool,
    pub seq: u32,
    pub x: f32,
    pub y: f32,
    pub node_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HitTestHostV2 {
    pub hit: bool,
    pub cursor: u8,
    pub editable: bool,
    pub forward_pointer_move: bool,
    pub node_id: u64,
    pub scroll_node_id: u64,
    pub link_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RectHostV2 {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SelectionHostV2 {
    pub caret: Option<RectHostV2>,
    pub quads: Vec<RectHostV2>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PredictHostV2 {
    pub suppressed: bool,
    pub reason: u8,
    pub is_bullet: bool,
    pub caret_x: f32,
    pub caret_y: f32,
    pub advance_px: f32,
    pub glyph_ids: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricsHostV2 {
    pub vp_x: f32,
    pub vp_y: f32,
    pub vp_w: f32,
    pub vp_h: f32,
    pub vp_scale: f32,
    pub width: u32,
    pub height: u32,
    pub checkerboard_tiles: u32,
    pub total_visible_tiles: u32,
    pub mispredictions: u32,
    pub suppressed: bool,
}

pub struct CompositorV2Host {
    raster: Raster,
}

impl CompositorV2Host {
    pub fn new(wasm_bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            raster: Raster::new(wasm_bytes)?,
        })
    }

    pub fn ingest_frame(&mut self, ksc2_bytes: &[u8]) -> Result<FrameAckStatsV2, Box<dyn Error>> {
        let out = self.raster.run(OP_V2_INGEST_FRAME, ksc2_bytes)?;
        if out.len() < 16 {
            return Err("short ingestFrameV2 reply".into());
        }
        Ok(FrameAckStatsV2 {
            acked_scroll_seq: u32_le(&out, 0),
            acked_input_seq: u32_le(&out, 4),
            tiles_cached: u32_le(&out, 8),
            tiles_evicted: u32_le(&out, 12),
        })
    }

    pub fn composite(
        &mut self,
        t_ms: f64,
        pinch_scale: f32,
        pan_x: f32,
        pan_y: f32,
        raw_rgba: bool,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut input = Vec::with_capacity(24);
        input.extend_from_slice(&t_ms.to_le_bytes());
        input.extend_from_slice(&pinch_scale.to_le_bytes());
        input.extend_from_slice(&pan_x.to_le_bytes());
        input.extend_from_slice(&pan_y.to_le_bytes());
        input.extend_from_slice(&u32::from(raw_rgba).to_le_bytes());
        let out = self.raster.run(OP_V2_COMPOSITE, &input)?;
        if out.is_empty() {
            return Err("compositeV2 returned empty output".into());
        }
        Ok(out)
    }

    pub fn scroll_input(
        &mut self,
        node_id: u64,
        pt: (f32, f32),
        delta: (f32, f32),
        vel: (f32, f32),
        event_mask: u8,
    ) -> Result<ScrollResultV2, Box<dyn Error>> {
        let mut input = Vec::with_capacity(33);
        input.extend_from_slice(&node_id.to_le_bytes());
        input.extend_from_slice(&pt.0.to_le_bytes());
        input.extend_from_slice(&pt.1.to_le_bytes());
        input.extend_from_slice(&delta.0.to_le_bytes());
        input.extend_from_slice(&delta.1.to_le_bytes());
        input.extend_from_slice(&vel.0.to_le_bytes());
        input.extend_from_slice(&vel.1.to_le_bytes());
        input.push(event_mask);
        let out = self.raster.run(OP_V2_SCROLL_INPUT, &input)?;
        decode_scroll_reply(&out)
    }

    pub fn step_fling(&mut self, dt_ms: f32) -> Result<Option<ScrollResultV2>, Box<dyn Error>> {
        let out = self.raster.run(OP_V2_STEP_FLING, &dt_ms.to_le_bytes())?;
        if out.is_empty() {
            return Err("empty stepFlingV2 reply".into());
        }
        if out[0] == 0 {
            return Ok(None);
        }
        decode_scroll_opt_reply(&out).map(Some)
    }

    pub fn hit_test(&mut self, x: f32, y: f32, t_ms: f64) -> Result<HitTestHostV2, Box<dyn Error>> {
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&x.to_le_bytes());
        input.extend_from_slice(&y.to_le_bytes());
        input.extend_from_slice(&t_ms.to_le_bytes());
        let out = self.raster.run(OP_V2_HIT_TEST, &input)?;
        if out.len() < 24 {
            return Err("short hitTestV2 reply".into());
        }
        let link_len = u32_le(&out, 20) as usize;
        let link_bytes = out.get(24..24 + link_len).ok_or("truncated link url")?;
        Ok(HitTestHostV2 {
            hit: out[0] != 0,
            cursor: out[1],
            editable: out[2] != 0,
            forward_pointer_move: out[3] != 0,
            node_id: u64_le(&out, 4),
            scroll_node_id: u64_le(&out, 12),
            link_url: String::from_utf8(link_bytes.to_vec())?,
        })
    }

    pub fn select_text(
        &mut self,
        start: (f32, f32),
        end: (f32, f32),
        t_ms: f64,
    ) -> Result<SelectionHostV2, Box<dyn Error>> {
        let mut input = Vec::with_capacity(24);
        input.extend_from_slice(&start.0.to_le_bytes());
        input.extend_from_slice(&start.1.to_le_bytes());
        input.extend_from_slice(&end.0.to_le_bytes());
        input.extend_from_slice(&end.1.to_le_bytes());
        input.extend_from_slice(&t_ms.to_le_bytes());
        let out = self.raster.run(OP_V2_SELECT_TEXT, &input)?;
        decode_selection_reply(&out)
    }

    pub fn predict_key(
        &mut self,
        node_id: u64,
        seq: u32,
        text: &str,
    ) -> Result<PredictHostV2, Box<dyn Error>> {
        let mut input = Vec::with_capacity(17 + text.len());
        input.push(0);
        input.extend_from_slice(&node_id.to_le_bytes());
        input.extend_from_slice(&seq.to_le_bytes());
        input.extend_from_slice(&(text.len() as u32).to_le_bytes());
        input.extend_from_slice(text.as_bytes());
        let out = self.raster.run(OP_V2_PREDICT_TYPE, &input)?;
        decode_predict_reply(&out)
    }

    pub fn reconcile_echo(
        &mut self,
        node_id: u64,
        acked_seq: u32,
        observed_text: &str,
    ) -> Result<(u32, bool), Box<dyn Error>> {
        let mut input = Vec::with_capacity(17 + observed_text.len());
        input.push(1);
        input.extend_from_slice(&node_id.to_le_bytes());
        input.extend_from_slice(&acked_seq.to_le_bytes());
        input.extend_from_slice(&(observed_text.len() as u32).to_le_bytes());
        input.extend_from_slice(observed_text.as_bytes());
        let out = self.raster.run(OP_V2_PREDICT_TYPE, &input)?;
        if out.len() < 5 {
            return Err("short reconcile echo reply".into());
        }
        Ok((u32_le(&out, 0), out[4] != 0))
    }

    pub fn known_tile_hashes(&mut self) -> Result<Vec<u64>, Box<dyn Error>> {
        let out = self.raster.run(OP_V2_KNOWN_HASHES, &[])?;
        if out.len() < 4 {
            return Err("short knownHashesV2 reply".into());
        }
        let count = u32_le(&out, 0) as usize;
        if out.len() < 4 + count * 8 {
            return Err("truncated knownHashesV2 reply".into());
        }
        let mut hashes = Vec::with_capacity(count);
        for i in 0..count {
            hashes.push(u64_le(&out, 4 + i * 8));
        }
        Ok(hashes)
    }

    pub fn metrics(&mut self, node_id: u64) -> Result<MetricsHostV2, Box<dyn Error>> {
        let out = self.raster.run(OP_V2_METRICS, &node_id.to_le_bytes())?;
        if out.len() < 41 {
            return Err("short metricsV2 reply".into());
        }
        Ok(MetricsHostV2 {
            vp_x: f32_le(&out, 0),
            vp_y: f32_le(&out, 4),
            vp_w: f32_le(&out, 8),
            vp_h: f32_le(&out, 12),
            vp_scale: f32_le(&out, 16),
            width: u32_le(&out, 20),
            height: u32_le(&out, 24),
            checkerboard_tiles: u32_le(&out, 28),
            total_visible_tiles: u32_le(&out, 32),
            mispredictions: u32_le(&out, 36),
            suppressed: out[40] != 0,
        })
    }
}

fn decode_scroll_reply(out: &[u8]) -> Result<ScrollResultV2, Box<dyn Error>> {
    if out.len() < 21 {
        return Err("short scrollInputV2 reply".into());
    }
    Ok(ScrollResultV2 {
        forwarded: out[0] != 0,
        seq: u32_le(out, 1),
        x: f32_le(out, 5),
        y: f32_le(out, 9),
        node_id: u64_le(out, 13),
    })
}

fn decode_scroll_opt_reply(out: &[u8]) -> Result<ScrollResultV2, Box<dyn Error>> {
    if out.len() < 21 {
        return Err("short stepFlingV2 reply".into());
    }
    Ok(ScrollResultV2 {
        forwarded: false,
        seq: u32_le(out, 1),
        x: f32_le(out, 5),
        y: f32_le(out, 9),
        node_id: u64_le(out, 13),
    })
}

fn decode_selection_reply(out: &[u8]) -> Result<SelectionHostV2, Box<dyn Error>> {
    if out.len() < 25 {
        return Err("short selectTextV2 reply".into());
    }
    let caret = if out[0] != 0 {
        Some(rect_le(out, 1))
    } else {
        None
    };
    let count = u32_le(out, 17) as usize;
    let quads_end = 21 + count * 16;
    if out.len() < quads_end + 4 {
        return Err("truncated selectTextV2 quads".into());
    }
    let mut quads = Vec::with_capacity(count);
    for i in 0..count {
        quads.push(rect_le(out, 21 + i * 16));
    }
    let text_len = u32_le(out, quads_end) as usize;
    let text_bytes = out
        .get(quads_end + 4..quads_end + 4 + text_len)
        .ok_or("truncated selectTextV2 text")?;
    Ok(SelectionHostV2 {
        caret,
        quads,
        text: String::from_utf8(text_bytes.to_vec())?,
    })
}

fn decode_predict_reply(out: &[u8]) -> Result<PredictHostV2, Box<dyn Error>> {
    if out.len() < 19 {
        return Err("short predictTypeV2 reply".into());
    }
    let count = u32_le(out, 15) as usize;
    if out.len() < 19 + count * 2 {
        return Err("truncated predictTypeV2 glyph ids".into());
    }
    let mut glyph_ids = Vec::with_capacity(count);
    for i in 0..count {
        let off = 19 + i * 2;
        glyph_ids.push(u16::from_le_bytes([out[off], out[off + 1]]));
    }
    Ok(PredictHostV2 {
        suppressed: out[0] != 0,
        reason: out[1],
        is_bullet: out[2] != 0,
        caret_x: f32_le(out, 3),
        caret_y: f32_le(out, 7),
        advance_px: f32_le(out, 11),
        glyph_ids,
    })
}

fn rect_le(b: &[u8], off: usize) -> RectHostV2 {
    RectHostV2 {
        x: f32_le(b, off),
        y: f32_le(b, off + 4),
        w: f32_le(b, off + 8),
        h: f32_le(b, off + 12),
    }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    fn w_rect(out: &mut Vec<u8>, x: f32, y: f32, w: f32, h: f32) {
        out.extend_from_slice(&x.to_le_bytes());
        out.extend_from_slice(&y.to_le_bytes());
        out.extend_from_slice(&w.to_le_bytes());
        out.extend_from_slice(&h.to_le_bytes());
    }

    fn w_str(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }

    pub(crate) fn build_ksc2_test_frame() -> Vec<u8> {
        build_ksc2_test_frame_with_echo(0, "")
    }

    pub(crate) fn build_ksc2_test_frame_with_echo(
        acked_input_seq: u32,
        auth_text: &str,
    ) -> Vec<u8> {
        let mut ops = b"KSV2".to_vec();
        ops.extend_from_slice(&1u32.to_le_bytes());
        ops.push(2); // FillCircle
        ops.extend_from_slice(&64.0f32.to_le_bytes());
        ops.extend_from_slice(&64.0f32.to_le_bytes());
        ops.extend_from_slice(&40.0f32.to_le_bytes());
        ops.extend_from_slice(&[20, 120, 220, 255]);

        let mut b = b"KSC2".to_vec();
        b.extend_from_slice(&1u32.to_le_bytes()); // version
        b.extend_from_slice(&0u32.to_le_bytes()); // acked_scroll_seq
        b.extend_from_slice(&acked_input_seq.to_le_bytes()); // acked_input_seq
        b.extend_from_slice(&256u32.to_le_bytes()); // vw
        b.extend_from_slice(&256u32.to_le_bytes()); // vh

        // 1 ScrollNodeV2
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes()); // node_id
        b.extend_from_slice(&0u64.to_le_bytes()); // parent_id
        b.extend_from_slice(&256.0f32.to_le_bytes());
        b.extend_from_slice(&1024.0f32.to_le_bytes());
        w_rect(&mut b, 0.0, 0.0, 256.0, 256.0);
        b.extend_from_slice(&0.0f32.to_le_bytes());
        b.extend_from_slice(&0.0f32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // snap_x
        b.extend_from_slice(&0u32.to_le_bytes()); // snap_y
        b.push(1); // overscroll Contain
        b.push(1);
        b.push(0); // server_driven = false
        b.push(0);

        // 1 LayerV2
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes()); // layer_id
        b.extend_from_slice(&1u64.to_le_bytes()); // scroll_node_id
        b.push(0); // Normal
        w_rect(&mut b, 0.0, 0.0, 256.0, 1024.0);
        b.extend_from_slice(&[255, 255, 255, 255]);
        b.extend_from_slice(&1.0f32.to_le_bytes());
        for v in [1.0f32, 0.0, 0.0, 1.0, 0.0, 0.0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&0u32.to_le_bytes()); // animations
        b.extend_from_slice(&256u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // 1 tile_ref
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        w_rect(&mut b, 0.0, 0.0, 256.0, 256.0);
        b.extend_from_slice(&0xBEEF_u64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // invalidated

        // 1 TilePayloadV2
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0xBEEF_u64.to_le_bytes());
        b.extend_from_slice(&256u32.to_le_bytes());
        b.extend_from_slice(&256u32.to_le_bytes());
        b.extend_from_slice(&(ops.len() as u32).to_le_bytes());
        b.extend_from_slice(&ops);
        b.extend_from_slice(&1u32.to_le_bytes()); // 1 TextRunMapV2
        b.extend_from_slice(&7u64.to_le_bytes());
        w_str(&mut b, "Hello");
        b.extend_from_slice(&1u64.to_le_bytes());
        b.extend_from_slice(&16.0f32.to_le_bytes());
        b.push(0);
        b.extend_from_slice(&10.0f32.to_le_bytes());
        b.extend_from_slice(&30.0f32.to_le_bytes());
        b.extend_from_slice(&14.0f32.to_le_bytes());
        b.extend_from_slice(&4.0f32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // 1 cluster
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&10.0f32.to_le_bytes());
        b.extend_from_slice(&45.0f32.to_le_bytes());
        w_rect(&mut b, 10.0, 16.0, 45.0, 18.0);
        b.extend_from_slice(&1u32.to_le_bytes()); // 1 HitRectMapV2
        w_rect(&mut b, 10.0, 10.0, 80.0, 30.0);
        b.extend_from_slice(&7u64.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes());
        b.push(1); // Cursor Pointer
        b.push(1); // has link_url
        w_str(&mut b, "https://parawing.example/");
        b.push(0); // editable
        b.push(1); // hover_or_pointer

        // 1 HandlerRegionV2
        b.extend_from_slice(&1u32.to_le_bytes());
        w_rect(&mut b, 200.0, 200.0, 50.0, 50.0);
        b.extend_from_slice(&1u64.to_le_bytes());
        b.push(1); // WHEEL
        b.push(1); // non_passive

        // 1 EditableEchoSpecV2
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&99u64.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes()); // scroll_node_id
        w_str(&mut b, "field#msg");
        w_str(&mut b, auth_text);
        w_rect(&mut b, 10.0, 60.0, 200.0, 30.0);
        b.push(0); // is_password
        b.push(0); // complex_shaping
        b.push(0); // has_ligatures
        b.extend_from_slice(&16.0f32.to_le_bytes());
        b.extend_from_slice(&1000u16.to_le_bytes());
        b.extend_from_slice(&[0, 0, 0, 255]);
        b.extend_from_slice(&12.0f32.to_le_bytes());
        b.extend_from_slice(&65.0f32.to_le_bytes());
        b.extend_from_slice(&18.0f32.to_le_bytes());
        b.extend_from_slice(&79.0f32.to_le_bytes()); // baseline_y
        b.extend_from_slice(&1u64.to_le_bytes()); // font_hash
        b.extend_from_slice(&0u32.to_le_bytes()); // font_index
        b.extend_from_slice(&4u32.to_le_bytes()); // font_data len
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // minimal bytes
        b.extend_from_slice(&1u32.to_le_bytes()); // cmap entry 'a' -> 1
        b.extend_from_slice(&(b'a' as u32).to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes()); // advances [0, 500]
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&500u16.to_le_bytes());
        b
    }

    #[test]
    fn wasm_compositor_v2_abi_runs_s1_through_s6_end_to_end() {
        let wasm = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let mut host = CompositorV2Host::new(&wasm).unwrap();
        let frame_bytes = build_ksc2_test_frame();
        let ack = host.ingest_frame(&frame_bytes).unwrap();
        assert_eq!(ack.tiles_cached, 1);

        let hashes = host.known_tile_hashes().unwrap();
        assert_eq!(hashes, vec![0xBEEF]);

        let blocked = host
            .scroll_input(1, (220.0, 220.0), (0.0, 40.0), (0.0, 0.0), 1)
            .unwrap();
        assert!(blocked.forwarded);

        let local = host
            .scroll_input(1, (50.0, 50.0), (0.0, 80.0), (0.0, 400.0), 1)
            .unwrap();
        assert!(!local.forwarded);
        assert_eq!(local.y, 80.0);
        let step = host.step_fling(16.0).unwrap().unwrap();
        assert!(step.y > 80.0);

        let png_zoom = host.composite(0.0, 2.0, 10.0, 10.0, false).unwrap();
        assert!(png_zoom.starts_with(b"\x89PNG\r\n\x1a\n"));

        let metrics = host.metrics(99).unwrap();
        assert_eq!(metrics.vp_scale, 2.0);
        assert_eq!(metrics.checkerboard_tiles, 0);

        // Reset viewport to 1x to test S4 hit-test & text copy accurately.
        let _ = host.composite(0.0, 1.0, 0.0, 0.0, true).unwrap();
        let _ = host
            .scroll_input(1, (50.0, 50.0), (0.0, -200.0), (0.0, 0.0), 1)
            .unwrap();
        let hit = host.hit_test(20.0, 20.0, 0.0).unwrap();
        assert!(hit.hit);
        assert!(hit.forward_pointer_move);
        assert_eq!(hit.link_url, "https://parawing.example/");

        let sel = host.select_text((12.0, 20.0), (50.0, 24.0), 0.0).unwrap();
        assert_eq!(sel.text, "Hello");

        let pred = host.predict_key(99, 1, "aa").unwrap();
        assert!(!pred.suppressed);
        assert_eq!(pred.glyph_ids, vec![1, 1]);
        assert!((pred.advance_px - 16.0).abs() < 0.01);
    }

    #[test]
    fn wasm_compositor_v2_abi_ingest_frame_auto_suppresses_on_misprediction() {
        let wasm = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let mut host = CompositorV2Host::new(&wasm).unwrap();
        host.ingest_frame(&build_ksc2_test_frame_with_echo(0, ""))
            .unwrap();

        let p1 = host.predict_key(99, 1, "a").unwrap();
        assert!(!p1.suppressed);
        host.ingest_frame(&build_ksc2_test_frame_with_echo(1, "A"))
            .unwrap();
        let m1 = host.metrics(99).unwrap();
        assert_eq!(m1.mispredictions, 1);
        assert!(!m1.suppressed);

        let p2 = host.predict_key(99, 2, "a").unwrap();
        assert!(!p2.suppressed);
        host.ingest_frame(&build_ksc2_test_frame_with_echo(2, "AA"))
            .unwrap();
        let m2 = host.metrics(99).unwrap();
        assert_eq!(m2.mispredictions, 2);
        assert!(m2.suppressed);

        let p3 = host.predict_key(99, 3, "a").unwrap();
        assert!(p3.suppressed);
    }
}
