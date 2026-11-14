// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Binary framing codec for the S7 `/rbi/ws` WebSocket channel (`KV2\x01`).

use std::error::Error;

const MAGIC: [u8; 4] = *b"KV2\x01";
const HEADER_BYTES: usize = 5;
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_TILE_HASHES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RbiV2PacketKind {
    ReliableFrame = 1,
    CreditGrant = 2,
    ReattachWithTileHashes = 3,
    DatagramScroll = 4,
    DatagramPointer = 5,
    DatagramAnimTick = 6,
    DeltaResyncAck = 7,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecodedRbiV2Packet {
    ReliableFrame {
        frame_seq: u32,
        base_seq: u32,
        tile_count: u32,
        payload: Vec<u8>,
    },
    CreditGrant {
        credits_granted: u32,
        acked_frame_seq: u32,
    },
    ReattachWithTileHashes {
        last_frame_seq: u32,
        viewport: [f32; 4],
        vel: [f32; 2],
        known_hashes: Vec<u64>,
    },
    DeltaResyncAck {
        resumed_from_seq: u32,
        pruned_known_tiles: u32,
        payload: Vec<u8>,
    },
    DatagramScroll {
        seq: u32,
        scroll_node_id: u64,
        x: f32,
        y: f32,
        vel_x: f32,
        vel_y: f32,
    },
    DatagramPointer {
        seq: u32,
        x: f32,
        y: f32,
        buttons: u8,
    },
    DatagramAnimTick {
        seq: u32,
        t_ms: f64,
    },
}

pub fn encode_credit_grant_packet(credits_granted: u32, acked_frame_seq: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(13);
    out.extend_from_slice(&MAGIC);
    out.push(RbiV2PacketKind::CreditGrant as u8);
    out.extend_from_slice(&credits_granted.to_le_bytes());
    out.extend_from_slice(&acked_frame_seq.to_le_bytes());
    out
}

pub fn encode_reattach_packet(
    last_frame_seq: u32,
    known_hashes: &[u64],
    viewport: [f32; 4],
    vel: [f32; 2],
) -> Vec<u8> {
    let count = known_hashes.len().min(MAX_TILE_HASHES);
    let mut out = Vec::with_capacity(37 + count * 8);
    out.extend_from_slice(&MAGIC);
    out.push(RbiV2PacketKind::ReattachWithTileHashes as u8);
    out.extend_from_slice(&last_frame_seq.to_le_bytes());
    for v in viewport {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for v in vel {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&(count as u32).to_le_bytes());
    for &h in &known_hashes[..count] {
        out.extend_from_slice(&h.to_le_bytes());
    }
    out
}

pub fn encode_scroll_datagram(
    seq: u32,
    scroll_node_id: u64,
    x: f32,
    y: f32,
    vel_x: f32,
    vel_y: f32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES + 28);
    out.extend_from_slice(&MAGIC);
    out.push(RbiV2PacketKind::DatagramScroll as u8);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&scroll_node_id.to_le_bytes());
    out.extend_from_slice(&x.to_le_bytes());
    out.extend_from_slice(&y.to_le_bytes());
    out.extend_from_slice(&vel_x.to_le_bytes());
    out.extend_from_slice(&vel_y.to_le_bytes());
    out
}

pub fn encode_pointer_datagram(seq: u32, x: f32, y: f32, buttons: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES + 13);
    out.extend_from_slice(&MAGIC);
    out.push(RbiV2PacketKind::DatagramPointer as u8);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&x.to_le_bytes());
    out.extend_from_slice(&y.to_le_bytes());
    out.push(buttons);
    out
}

pub fn decode_rbi_v2_packet(bytes: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if bytes.len() < HEADER_BYTES {
        return Err("RBI v2 packet too short".into());
    }
    if bytes[..4] != MAGIC {
        return Err("RBI v2 packet missing KV2v1 magic".into());
    }
    let kind = bytes[4];
    match kind {
        1 => decode_reliable_frame(bytes),
        2 => decode_credit_grant(bytes),
        3 => decode_reattach(bytes),
        4 => decode_scroll_datagram(bytes),
        5 => decode_pointer_datagram(bytes),
        6 => decode_anim_datagram(bytes),
        7 => decode_delta_resync_ack(bytes),
        other => Err(format!("unknown RBI v2 packet kind {other}").into()),
    }
}

fn decode_reliable_frame(b: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if b.len() < 21 {
        return Err("ReliableFrame truncated".into());
    }
    let frame_seq = u32_at(b, 5)?;
    let base_seq = u32_at(b, 9)?;
    let tile_count = u32_at(b, 13)?;
    let len = u32_at(b, 17)? as usize;
    if len > MAX_PAYLOAD_BYTES || 21 + len > b.len() {
        return Err("ReliableFrame payload invalid".into());
    }
    Ok(DecodedRbiV2Packet::ReliableFrame {
        frame_seq,
        base_seq,
        tile_count,
        payload: b[21..21 + len].to_vec(),
    })
}

fn decode_credit_grant(b: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if b.len() < 13 {
        return Err("CreditGrant truncated".into());
    }
    Ok(DecodedRbiV2Packet::CreditGrant {
        credits_granted: u32_at(b, 5)?,
        acked_frame_seq: u32_at(b, 9)?,
    })
}

fn decode_reattach(b: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if b.len() < 37 {
        return Err("ReattachWithTileHashes truncated".into());
    }
    let count = u32_at(b, 33)? as usize;
    if count > MAX_TILE_HASHES || 37 + count * 8 > b.len() {
        return Err("ReattachWithTileHashes invalid count".into());
    }
    let mut known_hashes = Vec::with_capacity(count);
    for i in 0..count {
        known_hashes.push(u64_at(b, 37 + i * 8)?);
    }
    Ok(DecodedRbiV2Packet::ReattachWithTileHashes {
        last_frame_seq: u32_at(b, 5)?,
        viewport: [
            f32_at(b, 9)?,
            f32_at(b, 13)?,
            f32_at(b, 17)?,
            f32_at(b, 21)?,
        ],
        vel: [f32_at(b, 25)?, f32_at(b, 29)?],
        known_hashes,
    })
}

fn decode_delta_resync_ack(b: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if b.len() < 17 {
        return Err("DeltaResyncAck truncated".into());
    }
    let len = u32_at(b, 13)? as usize;
    if len > MAX_PAYLOAD_BYTES || 17 + len > b.len() {
        return Err("DeltaResyncAck payload invalid".into());
    }
    Ok(DecodedRbiV2Packet::DeltaResyncAck {
        resumed_from_seq: u32_at(b, 5)?,
        pruned_known_tiles: u32_at(b, 9)?,
        payload: b[17..17 + len].to_vec(),
    })
}

fn decode_scroll_datagram(b: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if b.len() < 33 {
        return Err("DatagramScroll truncated".into());
    }
    Ok(DecodedRbiV2Packet::DatagramScroll {
        seq: u32_at(b, 5)?,
        scroll_node_id: u64_at(b, 9)?,
        x: f32_at(b, 17)?,
        y: f32_at(b, 21)?,
        vel_x: f32_at(b, 25)?,
        vel_y: f32_at(b, 29)?,
    })
}

fn decode_pointer_datagram(b: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if b.len() < 18 {
        return Err("DatagramPointer truncated".into());
    }
    Ok(DecodedRbiV2Packet::DatagramPointer {
        seq: u32_at(b, 5)?,
        x: f32_at(b, 9)?,
        y: f32_at(b, 13)?,
        buttons: b[17],
    })
}

fn decode_anim_datagram(b: &[u8]) -> Result<DecodedRbiV2Packet, Box<dyn Error>> {
    if b.len() < 17 {
        return Err("DatagramAnimTick truncated".into());
    }
    let slice = b.get(9..17).ok_or("DatagramAnimTick truncated")?;
    let bits: [u8; 8] = slice.try_into()?;
    Ok(DecodedRbiV2Packet::DatagramAnimTick {
        seq: u32_at(b, 5)?,
        t_ms: f64::from_le_bytes(bits),
    })
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, Box<dyn Error>> {
    let slice = b.get(off..off + 4).ok_or("truncated u32")?;
    Ok(u32::from_le_bytes(slice.try_into()?))
}

fn u64_at(b: &[u8], off: usize) -> Result<u64, Box<dyn Error>> {
    let slice = b.get(off..off + 8).ok_or("truncated u64")?;
    Ok(u64::from_le_bytes(slice.try_into()?))
}

fn f32_at(b: &[u8], off: usize) -> Result<f32, Box<dyn Error>> {
    let slice = b.get(off..off + 4).ok_or("truncated f32")?;
    Ok(f32::from_le_bytes(slice.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_credit_reattach_and_datagrams() {
        let credit = encode_credit_grant_packet(2, 9);
        assert_eq!(
            decode_rbi_v2_packet(&credit).unwrap(),
            DecodedRbiV2Packet::CreditGrant {
                credits_granted: 2,
                acked_frame_seq: 9
            }
        );

        let reattach = encode_reattach_packet(7, &[11, 22], [1.0, 2.0, 800.0, 600.0], [0.0, 12.0]);
        assert_eq!(
            decode_rbi_v2_packet(&reattach).unwrap(),
            DecodedRbiV2Packet::ReattachWithTileHashes {
                last_frame_seq: 7,
                viewport: [1.0, 2.0, 800.0, 600.0],
                vel: [0.0, 12.0],
                known_hashes: vec![11, 22],
            }
        );

        let scroll = encode_scroll_datagram(3, 42, 10.0, 250.0, 0.0, 18.5);
        assert_eq!(
            decode_rbi_v2_packet(&scroll).unwrap(),
            DecodedRbiV2Packet::DatagramScroll {
                seq: 3,
                scroll_node_id: 42,
                x: 10.0,
                y: 250.0,
                vel_x: 0.0,
                vel_y: 18.5,
            }
        );

        let ptr = encode_pointer_datagram(5, 100.0, 200.0, 1);
        assert_eq!(
            decode_rbi_v2_packet(&ptr).unwrap(),
            DecodedRbiV2Packet::DatagramPointer {
                seq: 5,
                x: 100.0,
                y: 200.0,
                buttons: 1,
            }
        );
    }
}
