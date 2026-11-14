// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Native Tokio HTTP + WebSocket CDP/Viewer v2 server backed by Blitz and Deno PRWP.

use crate::attestation::{
    sign_capsule_attestation, CapsuleAttestationAuthority, CapsuleAttestationClaims,
    SignedCapsuleAttestation,
};
use crate::authority_backend::{AuthoritySocketDaemon, AuthoritySupervisor, BlitzDenoAuthorityBackend};
use parawing_authority::control::{ControlHub, ControlServerConfig};
use crate::capsule::{
    resolved_v8_flags, sha256_hex, CapsuleManifest, CpuBaseline, RuntimeEnvironmentSpec,
    CAPSULE_PINNED_PAGE_SIZE,
};
use crate::freeze_thaw::{
    default_prwp_inherit_fd_labels, freeze_session, generate_test_ed25519_keypair,
    probe_criu_binary, thaw_session, verify_bundle_signature, BrokerRequestTracker,
    CriuBackendKind, FreezeError, FreezeParams, FreezeStateSnapshot, KeyLease,
    SealedCheckpointBundle, ThawOutcome, ThawParams,
};
use crate::macos_capsule::{
    CapsuleDenoWorker, CapsuleDumpTarget, CapsuleInspectReport, CapsuleRestoredWorker,
    MacosLinuxCapsuleDriver,
};
use crate::roam::{
    AbruptLossDecision, EgressMode, EgressStreamTable, EpochControlPlane, EpochLease,
    IntentCoordinator, PreCopyBatch, PreCopySession, StreamKind,
};
use crate::rpc_pipe::{spawn_deno_worker, DenoWorkerProcess, RpcCallResult, RpcPipeError};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use parawing_core_host::native_host::{ksc2_tile_metadata, NativeBlitzDocument};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, Once};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot, Notify};
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::Message;

pub const KSV2_WIRE_MAGIC: [u8; 4] = [0x4b, 0x56, 0x32, 0x01];
const KIND_RELIABLE_FRAME: u8 = 1;
const KIND_CREDIT_GRANT: u8 = 2;
const KIND_REATTACH_WITH_TILE_HASHES: u8 = 3;
const KIND_DATAGRAM_SCROLL: u8 = 4;
const KIND_DELTA_RESYNC_ACK: u8 = 7;

#[derive(Debug)]
pub enum HostError {
    Io(String),
    Render(String),
    Rpc(String),
    Http(String),
    Freeze(String),
    EpochFenced(String),
    Attestation(String),
    Roam(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "host IO error: {m}"),
            Self::Render(m) => write!(f, "render error: {m}"),
            Self::Rpc(m) => write!(f, "RPC error: {m}"),
            Self::Http(m) => write!(f, "HTTP fetch error: {m}"),
            Self::Freeze(m) => write!(f, "freeze/thaw error: {m}"),
            Self::EpochFenced(m) => write!(f, "epoch fenced: {m}"),
            Self::Attestation(m) => write!(f, "attestation error: {m}"),
            Self::Roam(m) => write!(f, "roam error: {m}"),
        }
    }
}

impl std::error::Error for HostError {}

impl From<RpcPipeError> for HostError {
    fn from(err: RpcPipeError) -> Self {
        Self::Rpc(err.to_string())
    }
}

impl From<FreezeError> for HostError {
    fn from(err: FreezeError) -> Self {
        Self::Freeze(err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum DomOpById {
    SetTextById {
        id: String,
        text: String,
    },
    SetAttributeById {
        id: String,
        name: String,
        value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfoSnapshot {
    pub target_id: String,
    pub url: String,
    pub title: String,
    pub node_count: usize,
    pub viewport_w: u32,
    pub viewport_h: u32,
    pub scroll_x: f64,
    pub scroll_y: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ksc2RenderResult {
    pub ksc2_bytes: Vec<u8>,
    pub tile_count: u32,
    pub payload_hashes: Vec<u64>,
    pub invalidated_hashes: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedHostState {
    pub url: String,
    pub title: String,
    pub html: String,
    pub viewport_w: u32,
    pub viewport_h: u32,
    pub scroll_x: f64,
    pub scroll_y: f64,
}

enum RenderCommand {
    EnsureTarget {
        target_id: String,
        reply: oneshot::Sender<TargetInfoSnapshot>,
    },
    NavigateHtml {
        target_id: String,
        url: String,
        html: String,
        width: u32,
        height: u32,
        reply: oneshot::Sender<Result<TargetInfoSnapshot, String>>,
    },
    ApplyOpsById {
        target_id: String,
        ops: Vec<DomOpById>,
        reply: oneshot::Sender<Result<u32, String>>,
    },
    SetViewport {
        target_id: String,
        width: u32,
        height: u32,
        reply: oneshot::Sender<Result<(), String>>,
    },
    SetScroll {
        target_id: String,
        x: f64,
        y: f64,
        reply: oneshot::Sender<Result<(), String>>,
    },
    PaintPng {
        target_id: String,
        reply: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    RenderKsc2 {
        target_id: String,
        acked_scroll_seq: u32,
        acked_input_seq: u32,
        known_hashes: Vec<u64>,
        reply: oneshot::Sender<Result<Ksc2RenderResult, String>>,
    },
    GetInfo {
        target_id: String,
        reply: oneshot::Sender<Result<TargetInfoSnapshot, String>>,
    },
    SnapshotHtml {
        target_id: String,
        reply: oneshot::Sender<Result<CapturedHostState, String>>,
    },
    WithDocsSync(DocSyncCallback),
    Shutdown,
}

type DocSyncCallback = Box<dyn FnOnce(&mut HashMap<String, DocEntry>) + Send>;

struct DocEntry {
    doc: NativeBlitzDocument,
    url: String,
}

#[derive(Clone)]
pub struct RenderActorHandle {
    tx: mpsc::Sender<RenderCommand>,
}

impl RenderActorHandle {
    pub fn spawn() -> Result<Self, HostError> {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("parawing-blitz-render".to_string())
            .spawn(move || run_render_thread(rx))
            .map_err(|e| HostError::Render(format!("spawn render thread: {e}")))?;
        Ok(Self { tx })
    }

    pub async fn ensure_target(&self, target_id: &str) -> Result<TargetInfoSnapshot, HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::EnsureTarget {
            target_id: target_id.to_string(),
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))
    }

    pub async fn navigate_html(
        &self,
        target_id: &str,
        url: &str,
        html: &str,
        width: u32,
        height: u32,
    ) -> Result<TargetInfoSnapshot, HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::NavigateHtml {
            target_id: target_id.to_string(),
            url: url.to_string(),
            html: html.to_string(),
            width,
            height,
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    pub async fn apply_ops_by_id(
        &self,
        target_id: &str,
        ops: Vec<DomOpById>,
    ) -> Result<u32, HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::ApplyOpsById {
            target_id: target_id.to_string(),
            ops,
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    pub async fn set_viewport(
        &self,
        target_id: &str,
        width: u32,
        height: u32,
    ) -> Result<(), HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::SetViewport {
            target_id: target_id.to_string(),
            width,
            height,
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    pub async fn set_scroll(&self, target_id: &str, x: f64, y: f64) -> Result<(), HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::SetScroll {
            target_id: target_id.to_string(),
            x,
            y,
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    pub async fn paint_png(&self, target_id: &str) -> Result<Vec<u8>, HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::PaintPng {
            target_id: target_id.to_string(),
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    pub async fn render_ksc2(
        &self,
        target_id: &str,
        acked_scroll_seq: u32,
        acked_input_seq: u32,
        known_hashes: Vec<u64>,
    ) -> Result<Ksc2RenderResult, HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::RenderKsc2 {
            target_id: target_id.to_string(),
            acked_scroll_seq,
            acked_input_seq,
            known_hashes,
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    pub async fn get_info(&self, target_id: &str) -> Result<TargetInfoSnapshot, HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::GetInfo {
            target_id: target_id.to_string(),
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    pub async fn snapshot_html(&self, target_id: &str) -> Result<CapturedHostState, HostError> {
        let (reply, rx) = oneshot::channel();
        self.send_cmd(RenderCommand::SnapshotHtml {
            target_id: target_id.to_string(),
            reply,
        })?;
        rx.await
            .map_err(|_| HostError::Render("render actor dropped".to_string()))?
            .map_err(HostError::Render)
    }

    /// Synchronously replaces or initializes `target_id` with parsed HTML on the render actor.
    pub fn navigate_html_sync(
        &self,
        target_id: &str,
        url: &str,
        html: &str,
        width: u32,
        height: u32,
    ) -> Result<(), String> {
        let (tx, rx) = mpsc::sync_channel(1);
        let key = target_id.to_string();
        let nav_url = url.to_string();
        let body = html.to_string();
        let w = width.max(1);
        let h = height.max(1);
        self.send_cmd(RenderCommand::WithDocsSync(Box::new(move |docs| {
            let doc = NativeBlitzDocument::from_html(&body, &nav_url, w, h);
            docs.insert(key, DocEntry { doc, url: nav_url });
            let _ = tx.send(());
        })))
        .map_err(|e| e.to_string())?;
        rx.recv().map_err(|_| "render actor dropped".to_string())
    }

    /// Synchronously removes `target_id` from the render actor document map.
    pub fn remove_target_sync(&self, target_id: &str) {
        let (tx, rx) = mpsc::sync_channel(1);
        let key = target_id.to_string();
        if self
            .send_cmd(RenderCommand::WithDocsSync(Box::new(move |docs| {
                docs.remove(&key);
                let _ = tx.send(());
            })))
            .is_ok()
        {
            let _ = rx.recv();
        }
    }

    /// Runs `op` against the live `NativeBlitzDocument` for `target_id` on the render thread.
    pub fn with_doc_sync<R: Send + 'static>(
        &self,
        target_id: &str,
        op: impl FnOnce(&mut NativeBlitzDocument, &str) -> Result<R, String> + Send + 'static,
    ) -> Result<R, String> {
        let (tx, rx) = mpsc::sync_channel(1);
        let key = target_id.to_string();
        self.send_cmd(RenderCommand::WithDocsSync(Box::new(move |docs| {
            let res = match docs.get_mut(&key) {
                Some(entry) => op(&mut entry.doc, &entry.url),
                None => Err(format!("unknown target: {key}")),
            };
            let _ = tx.send(res);
        })))
        .map_err(|e| e.to_string())?;
        rx.recv().map_err(|_| "render actor dropped".to_string())?
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(RenderCommand::Shutdown);
    }

    fn send_cmd(&self, cmd: RenderCommand) -> Result<(), HostError> {
        self.tx
            .send(cmd)
            .map_err(|_| HostError::Render("render thread exited".to_string()))
    }
}

fn run_render_thread(rx: mpsc::Receiver<RenderCommand>) {
    let mut docs: HashMap<String, DocEntry> = HashMap::new();
    while let Ok(cmd) = rx.recv() {
        match cmd {
            RenderCommand::EnsureTarget { target_id, reply } => {
                let entry = docs.entry(target_id.clone()).or_insert_with(|| DocEntry {
                    doc: NativeBlitzDocument::from_html(
                        "<html><body></body></html>",
                        "about:blank",
                        800,
                        600,
                    ),
                    url: "about:blank".to_string(),
                });
                let _ = reply.send(snapshot_info(&target_id, entry));
            }
            RenderCommand::NavigateHtml {
                target_id,
                url,
                html,
                width,
                height,
                reply,
            } => {
                let doc = NativeBlitzDocument::from_html(&html, &url, width.max(1), height.max(1));
                let entry = DocEntry { doc, url };
                let info = snapshot_info(&target_id, &entry);
                docs.insert(target_id, entry);
                let _ = reply.send(Ok(info));
            }
            RenderCommand::ApplyOpsById {
                target_id,
                ops,
                reply,
            } => {
                let res = apply_ops_to_entry(docs.get_mut(&target_id), &ops);
                let _ = reply.send(res);
            }
            RenderCommand::SetViewport {
                target_id,
                width,
                height,
                reply,
            } => {
                let _ = reply.send(update_viewport(docs.get_mut(&target_id), width, height));
            }
            RenderCommand::SetScroll {
                target_id,
                x,
                y,
                reply,
            } => {
                let _ = reply.send(update_scroll(docs.get_mut(&target_id), x, y));
            }
            RenderCommand::PaintPng { target_id, reply } => {
                let res = match docs.get_mut(&target_id) {
                    Some(entry) => entry.doc.paint_png(),
                    None => Err(format!("unknown target: {target_id}")),
                };
                let _ = reply.send(res);
            }
            RenderCommand::RenderKsc2 {
                target_id,
                acked_scroll_seq,
                acked_input_seq,
                known_hashes,
                reply,
            } => {
                let res = render_ksc2_entry(
                    docs.get_mut(&target_id),
                    acked_scroll_seq,
                    acked_input_seq,
                    &known_hashes,
                );
                let _ = reply.send(res);
            }
            RenderCommand::GetInfo { target_id, reply } => {
                let res = match docs.get(&target_id) {
                    Some(entry) => Ok(snapshot_info(&target_id, entry)),
                    None => Err(format!("unknown target: {target_id}")),
                };
                let _ = reply.send(res);
            }
            RenderCommand::SnapshotHtml { target_id, reply } => {
                let _ = reply.send(snapshot_state(docs.get(&target_id)));
            }
            RenderCommand::WithDocsSync(op) => op(&mut docs),
            RenderCommand::Shutdown => break,
        }
    }
}

fn snapshot_info(target_id: &str, entry: &DocEntry) -> TargetInfoSnapshot {
    let (viewport_w, viewport_h) = entry.doc.viewport();
    let (scroll_x, scroll_y) = entry.doc.page_scroll();
    TargetInfoSnapshot {
        target_id: target_id.to_string(),
        url: entry.url.clone(),
        title: entry.doc.title(),
        node_count: entry.doc.node_count(),
        viewport_w,
        viewport_h,
        scroll_x,
        scroll_y,
    }
}

fn snapshot_state(entry: Option<&DocEntry>) -> Result<CapturedHostState, String> {
    let entry = entry.ok_or_else(|| "unknown target".to_string())?;
    let (viewport_w, viewport_h) = entry.doc.viewport();
    let (scroll_x, scroll_y) = entry.doc.page_scroll();
    let root_id = entry.doc.document_node_id();
    Ok(CapturedHostState {
        url: entry.url.clone(),
        title: entry.doc.title(),
        html: entry.doc.outer_html(root_id),
        viewport_w,
        viewport_h,
        scroll_x,
        scroll_y,
    })
}

fn apply_ops_to_entry(entry: Option<&mut DocEntry>, ops: &[DomOpById]) -> Result<u32, String> {
    let entry = entry.ok_or_else(|| "unknown target".to_string())?;
    let mut json_ops = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            DomOpById::SetTextById { id, text } => {
                let node = entry.doc.get_element_by_id(id);
                if node < 0 {
                    return Err(format!("element #{id} not found"));
                }
                json_ops.push(json!({
                    "kind": "setTextContent",
                    "node": node as u32,
                    "text": text,
                }));
            }
            DomOpById::SetAttributeById { id, name, value } => {
                let node = entry.doc.get_element_by_id(id);
                if node < 0 {
                    return Err(format!("element #{id} not found"));
                }
                json_ops.push(json!({
                    "kind": "setAttribute",
                    "node": node as u32,
                    "name": name,
                    "value": value,
                }));
            }
        }
    }
    let payload = serde_json::to_string(&json_ops).map_err(|e| e.to_string())?;
    let applied = entry.doc.apply_ops_json(&payload)?;
    entry.doc.resolve_layout();
    Ok(applied)
}

fn update_viewport(entry: Option<&mut DocEntry>, width: u32, height: u32) -> Result<(), String> {
    let entry = entry.ok_or_else(|| "unknown target".to_string())?;
    entry.doc.set_viewport(width.max(1), height.max(1));
    entry.doc.resolve_layout();
    Ok(())
}

fn update_scroll(entry: Option<&mut DocEntry>, x: f64, y: f64) -> Result<(), String> {
    let entry = entry.ok_or_else(|| "unknown target".to_string())?;
    entry.doc.set_page_scroll(x, y);
    Ok(())
}

fn render_ksc2_entry(
    entry: Option<&mut DocEntry>,
    acked_scroll_seq: u32,
    acked_input_seq: u32,
    known_hashes: &[u64],
) -> Result<Ksc2RenderResult, String> {
    let entry = entry.ok_or_else(|| "unknown target".to_string())?;
    let mut known_le = Vec::with_capacity(known_hashes.len() * 8);
    for h in known_hashes {
        known_le.extend_from_slice(&h.to_le_bytes());
    }
    let ksc2_bytes = entry
        .doc
        .render_ksc2(acked_scroll_seq, acked_input_seq, &known_le);
    let (tile_count, payload_hashes, invalidated_hashes) = ksc2_tile_metadata(&ksc2_bytes)?;
    Ok(Ksc2RenderResult {
        ksc2_bytes,
        tile_count,
        payload_hashes,
        invalidated_hashes,
    })
}

pub fn encode_ksv2_reliable_frame(
    frame_seq: u32,
    base_seq: u32,
    tile_count: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(21 + payload.len());
    out.extend_from_slice(&KSV2_WIRE_MAGIC);
    out.push(KIND_RELIABLE_FRAME);
    out.extend_from_slice(&frame_seq.to_le_bytes());
    out.extend_from_slice(&base_seq.to_le_bytes());
    out.extend_from_slice(&tile_count.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn encode_ksv2_delta_resync_ack(
    resumed_from_seq: u32,
    pruned_known_tiles: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + payload.len());
    out.extend_from_slice(&KSV2_WIRE_MAGIC);
    out.push(KIND_DELTA_RESYNC_ACK);
    out.extend_from_slice(&resumed_from_seq.to_le_bytes());
    out.extend_from_slice(&pruned_known_tiles.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn encode_ksv2_reattach_with_hashes(last_frame_seq: u32, known_hashes: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + known_hashes.len() * 8);
    out.extend_from_slice(&KSV2_WIRE_MAGIC);
    out.push(KIND_REATTACH_WITH_TILE_HASHES);
    out.extend_from_slice(&last_frame_seq.to_le_bytes());
    for v in [0.0f32, 0.0, 800.0, 600.0, 0.0, 0.0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&(known_hashes.len() as u32).to_le_bytes());
    for h in known_hashes {
        out.extend_from_slice(&h.to_le_bytes());
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecodedKsv2ClientPacket {
    CreditGrant {
        credits: u32,
        acked_frame_seq: u32,
    },
    ReattachWithTileHashes {
        last_frame_seq: u32,
        known_hashes: Vec<u64>,
    },
    DatagramScroll {
        seq: u32,
        x: f32,
        y: f32,
    },
}

pub fn decode_ksv2_client_packet(bytes: &[u8]) -> Result<DecodedKsv2ClientPacket, HostError> {
    if bytes.len() < 5 || bytes[0..4] != KSV2_WIRE_MAGIC {
        return Err(HostError::Render("invalid KSV2 packet magic".to_string()));
    }
    match bytes[4] {
        KIND_CREDIT_GRANT => {
            if bytes.len() < 13 {
                return Err(HostError::Render(
                    "truncated CreditGrant packet".to_string(),
                ));
            }
            let credits = u32::from_le_bytes(bytes[5..9].try_into().unwrap_or([0; 4]));
            let acked_frame_seq = u32::from_le_bytes(bytes[9..13].try_into().unwrap_or([0; 4]));
            Ok(DecodedKsv2ClientPacket::CreditGrant {
                credits,
                acked_frame_seq,
            })
        }
        KIND_REATTACH_WITH_TILE_HASHES => decode_ksv2_reattach(bytes),
        KIND_DATAGRAM_SCROLL => {
            if bytes.len() < 33 {
                return Err(HostError::Render(
                    "truncated DatagramScroll packet".to_string(),
                ));
            }
            let seq = u32::from_le_bytes(bytes[5..9].try_into().unwrap_or([0; 4]));
            let x = f32::from_le_bytes(bytes[17..21].try_into().unwrap_or([0; 4]));
            let y = f32::from_le_bytes(bytes[21..25].try_into().unwrap_or([0; 4]));
            Ok(DecodedKsv2ClientPacket::DatagramScroll { seq, x, y })
        }
        other => Err(HostError::Render(format!(
            "unsupported KSV2 client packet {other}"
        ))),
    }
}

fn decode_ksv2_reattach(bytes: &[u8]) -> Result<DecodedKsv2ClientPacket, HostError> {
    if bytes.len() < 37 {
        return Err(HostError::Render(
            "truncated ReattachWithTileHashes".to_string(),
        ));
    }
    let last_frame_seq = u32::from_le_bytes(bytes[5..9].try_into().unwrap_or([0; 4]));
    let count = u32::from_le_bytes(bytes[33..37].try_into().unwrap_or([0; 4])) as usize;
    if count > 65_536 || 37 + count * 8 > bytes.len() {
        return Err(HostError::Render(
            "invalid tile hash count in Reattach".to_string(),
        ));
    }
    let mut known_hashes = Vec::with_capacity(count);
    for idx in 0..count {
        let off = 37 + idx * 8;
        known_hashes.push(u64::from_le_bytes(
            bytes[off..off + 8].try_into().unwrap_or([0; 8]),
        ));
    }
    Ok(DecodedKsv2ClientPacket::ReattachWithTileHashes {
        last_frame_seq,
        known_hashes,
    })
}

/// Zero-permission Deno child PRWP isolate script supporting DOM mutations and state export.
pub fn build_engine_isolate_script() -> &'static str {
    r#"import vm from "node:vm";
const PRWP_MAGIC = 0x50525750;
const PRWP_VERSION = 1;
const HEADER = 16;
const FT = { HANDSHAKE: 1, CALL: 2, REPLY: 3, CALLBACK: 4, BIN: 7, CREDIT: 8, ERROR: 9, PREPARE_FREEZE: 10, FREEZE_READY: 11 };
const FLAG = { FIN: 1, HAS_BINARY: 2, P_CALL: 4, P_REPLY: 8, P_CB: 16 };
const enc = new TextEncoder();
const dec = new TextDecoder();
const reader = Deno.stdin.readable.getReader();
const writer = Deno.stdout.writable.getWriter();
let recvBuf = new Uint8Array(0);
let lastRecvSeq = 0;
let nextCbId = 2;
const pendingCbs = new Map();
const domOps = [];
const docProxy = {
  getElementById(id) {
    const key = String(id);
    return {
      id: key,
      set textContent(v) { domOps.push({ kind: "setTextById", id: key, text: String(v) }); },
      setAttribute(name, value) { domOps.push({ kind: "setAttributeById", id: key, name: String(name), value: String(value) }); },
    };
  },
};
const sandbox = vm.createContext(
  { __ticks: 0, __state: { visited: 0 }, document: docProxy, setInterval, clearInterval, setTimeout, clearTimeout },
  { codeGeneration: { strings: false, wasm: false } },
);
const prngState = new Uint32Array(4);
crypto.getRandomValues(prngState);
let prngReseedCount = 0;

function sfc32Next() {
  let a = prngState[0] >>> 0;
  let b = prngState[1] >>> 0;
  let c = prngState[2] >>> 0;
  let d = prngState[3] >>> 0;
  const t = (a + b) | 0;
  a = b ^ (b >>> 9);
  b = (c + (c << 3)) | 0;
  c = ((c << 21) | (c >>> 11));
  d = (d + 1) | 0;
  const out = (t + d) | 0;
  c = (c + out) | 0;
  prngState[0] = a; prngState[1] = b; prngState[2] = c; prngState[3] = d;
  return (out >>> 0) / 4294967296;
}

function reseedPrngFromHex(seedHex) {
  const clean = String(seedHex ?? "").replace(/[^0-9a-fA-F]/g, "");
  if (clean.length < 32) throw new Error("reseedPrng requires >= 16 bytes hex entropy");
  for (let i = 0; i < 4; i++) {
    const word = parseInt(clean.slice(i * 8, i * 8 + 8) || "0", 16) >>> 0;
    const hi = parseInt(clean.slice(((i + 4) * 8) % clean.length, (((i + 4) * 8) % clean.length) + 8) || "0", 16) >>> 0;
    prngState[i] = (prngState[i] ^ word ^ hi ^ ((i + 1) * 0x9e3779b9)) >>> 0;
  }
  for (let i = 0; i < 12; i++) sfc32Next();
  prngReseedCount += 1;
  return { reseedCount: prngReseedCount, sample: sfc32Next() };
}

vm.runInContext("Math", sandbox).random = sfc32Next;

function encodeFrame(frameType, flags, reqId, payload) {
  const out = new Uint8Array(HEADER + payload.byteLength);
  const v = new DataView(out.buffer);
  v.setUint32(0, PRWP_MAGIC, true);
  v.setUint8(4, PRWP_VERSION);
  v.setUint8(5, frameType);
  v.setUint16(6, flags, true);
  v.setUint32(8, reqId >>> 0, true);
  v.setUint32(12, payload.byteLength >>> 0, true);
  if (payload.byteLength > 0) out.set(payload, HEADER);
  return out;
}

async function sendJson(frameType, flags, reqId, obj) {
  await writer.write(encodeFrame(frameType, flags, reqId, enc.encode(JSON.stringify(obj))));
}

async function callHostCallback(capId, method, args) {
  const id = nextCbId;
  nextCbId += 2;
  const p = new Promise((resolve, reject) => pendingCbs.set(id, { resolve, reject }));
  await sendJson(FT.CALLBACK, 0, id, { c: capId, m: method, a: args, bc: 0 });
  return await p;
}

async function dispatchCall(reqId, msg) {
  try {
    const method = String(msg.m ?? "");
    const args = Array.isArray(msg.a) ? msg.a : [];
    if (method === "evalJs") {
      const val = vm.runInContext(String(args[0] ?? ""), sandbox);
      let appliedOps = 0;
      if (domOps.length > 0) {
        const res = await callHostCallback(1, "applyDomOpsById", [domOps.splice(0)]);
        appliedOps = Number(res?.applied ?? 0);
      }
      await sendJson(FT.REPLY, FLAG.P_CALL, reqId, { r: { ok: true, value: val ?? null, appliedOps }, bc: 0 });
      return;
    }
    if (method === "startInterval") {
      setInterval(() => { sandbox.__ticks += 1; }, Math.max(5, Number(args[0] ?? 10)));
      await sendJson(FT.REPLY, FLAG.P_CALL, reqId, { r: { started: true }, bc: 0 });
      return;
    }
    if (method === "getState") {
      await sendJson(FT.REPLY, FLAG.P_CALL, reqId, { r: { ticks: sandbox.__ticks, state: sandbox.__state, prngReseedCount }, bc: 0 });
      return;
    }
    if (method === "restoreState") {
      const snap = args[0] ?? {};
      sandbox.__ticks = Number(snap.ticks ?? 0);
      sandbox.__state = typeof snap.state === "object" && snap.state !== null ? snap.state : {};
      await sendJson(FT.REPLY, FLAG.P_CALL, reqId, { r: { restored: true }, bc: 0 });
      return;
    }
    if (method === "reseedPrng") {
      const info = reseedPrngFromHex(args[0]);
      await sendJson(FT.REPLY, FLAG.P_CALL, reqId, { r: info, bc: 0 });
      return;
    }
    if (method === "authoritySync") {
      const payload = args[0] ?? {};
      sandbox.__state.authorityAction = String(payload.action ?? "");
      if (payload.url) sandbox.__state.url = String(payload.url);
      sandbox.__state.authorityCount = Number(sandbox.__state.authorityCount ?? 0) + 1;
      await sendJson(FT.REPLY, FLAG.P_CALL, reqId, {
        r: { ok: true, count: sandbox.__state.authorityCount },
        bc: 0,
      });
      return;
    }
    await sendJson(FT.ERROR, FLAG.P_CALL, reqId, { e: { name: "Error", message: `Unknown method: ${method}` } });
  } catch (err) {
    await sendJson(FT.ERROR, FLAG.P_CALL, reqId, { e: { name: err?.name ?? "Error", message: err?.message ?? String(err) } });
  }
}

await sendJson(FT.HANDSHAKE, 0, 0, { version: 1, ackedSeq: 0, windowBytes: 262144 });
while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  const merged = new Uint8Array(recvBuf.byteLength + value.byteLength);
  merged.set(recvBuf); merged.set(value, recvBuf.byteLength);
  recvBuf = merged;
  while (recvBuf.byteLength >= HEADER) {
    const view = new DataView(recvBuf.buffer, recvBuf.byteOffset, HEADER);
    const len = view.getUint32(12, true);
    if (recvBuf.byteLength < HEADER + len) break;
    const ft = view.getUint8(5);
    const reqId = view.getUint32(8, true);
    const payload = recvBuf.slice(HEADER, HEADER + len);
    recvBuf = recvBuf.slice(HEADER + len);
    if (ft === FT.CREDIT) continue;
    if (ft === FT.HANDSHAKE) {
      let hsMsg = null;
      try { hsMsg = JSON.parse(dec.decode(payload)); } catch (_) {}
      if (hsMsg && hsMsg.replug) {
        await sendJson(FT.HANDSHAKE, 0, 0, { version: 1, ackedSeq: lastRecvSeq, windowBytes: 262144 });
      }
      continue;
    }
    if (ft === FT.PREPARE_FREEZE) {
      await sendJson(FT.FREEZE_READY, 0, 0, { ackedSeq: lastRecvSeq });
      continue;
    }
    lastRecvSeq += 1;
    if (ft === FT.CALL) {
      void dispatchCall(reqId, JSON.parse(dec.decode(payload)));
    } else if (ft === FT.REPLY) {
      const entry = pendingCbs.get(reqId);
      if (entry) { pendingCbs.delete(reqId); entry.resolve(JSON.parse(dec.decode(payload)).r); }
    }
    await sendJson(FT.CREDIT, 0, 0, { bytes: Math.max(1, payload.byteLength), ackedSeq: lastRecvSeq });
  }
}
"#
}

struct TargetRuntime {
    id: String,
    deno: tokio::sync::Mutex<Option<DenoWorkerProcess>>,
    capsule_worker: Mutex<Option<CapsuleDenoWorker>>,
    frame_seq: AtomicU32,
    acked_scroll_seq: AtomicU32,
    acked_input_seq: AtomicU32,
    viewer_tx: broadcast::Sender<Vec<u8>>,
}

impl TargetRuntime {
    fn new(id: String) -> Self {
        let (viewer_tx, _) = broadcast::channel(64);
        Self {
            id,
            deno: tokio::sync::Mutex::new(None),
            capsule_worker: Mutex::new(None),
            frame_seq: AtomicU32::new(0),
            acked_scroll_seq: AtomicU32::new(0),
            acked_input_seq: AtomicU32::new(0),
            viewer_tx,
        }
    }
}

pub struct EngineHostConfig {
    pub bind_addr: String,
    pub capsule_manifest: CapsuleManifest,
    pub enable_linux_capsule: bool,
    pub trusted_signer_pubkeys: Vec<Vec<u8>>,
}

impl Default for EngineHostConfig {
    fn default() -> Self {
        let baseline = CpuBaseline::host_default();
        let enable_linux_capsule =
            std::env::var("PARAWING_ENABLE_LINUX_CAPSULE").as_deref() == Ok("1");
        let criu_flag = cfg!(target_os = "linux") || enable_linux_capsule;
        let manifest =
            CapsuleManifest::from_env(baseline, "parawing-rust-host:0.1.0", "deno-v8:1", criu_flag)
                .unwrap_or_else(|_| {
                    CapsuleManifest::new(
                        baseline,
                        "parawing-rust-host:0.1.0",
                        "deno-v8:1",
                        criu_flag,
                    )
                });
        Self {
            bind_addr: "127.0.0.1:8788".to_string(),
            capsule_manifest: manifest,
            enable_linux_capsule,
            trusted_signer_pubkeys: Vec::new(),
        }
    }
}

/// Configuration for `parawing_authority` supervision, Keychain brokers, and Unix control socket.
#[derive(Clone, Debug, Default)]
pub struct AuthorityHostConfig {
    pub use_keychain: bool,
    pub password_service: Option<String>,
    pub passkey_service: Option<String>,
    pub passkey_account: Option<String>,
    pub control_socket: Option<ControlServerConfig>,
}

static HOST_INSTANCE_SEQ: AtomicU64 = AtomicU64::new(1);

struct HostInner {
    render: RenderActorHandle,
    targets: Mutex<HashMap<String, Arc<TargetRuntime>>>,
    manifest: CapsuleManifest,
    criu_root_dir: PathBuf,
    freeze_generation: AtomicU64,
    next_req_id: AtomicU64,
    signer_keypair: Ed25519KeyPair,
    trusted_signer_pubkeys: Vec<Vec<u8>>,
    enable_linux_capsule: bool,
    http_client: reqwest::Client,
    broker_tracker: BrokerRequestTracker,
    epoch_plane: Mutex<EpochControlPlane>,
    precopy: Mutex<HashMap<String, PreCopySession>>,
    replica_pages: Mutex<BTreeMap<u64, Vec<u8>>>,
    intents: Mutex<IntentCoordinator>,
    egress_streams: Mutex<EgressStreamTable>,
    attestation_authority: Mutex<CapsuleAttestationAuthority>,
    issued_leases: Mutex<HashMap<String, KeyLease>>,
    authority_supervisor: Arc<Mutex<AuthoritySupervisor>>,
    authority_hub: Arc<ControlHub>,
    authority_daemon: Mutex<Option<AuthoritySocketDaemon>>,
    addr_str: String,
    shutdown: Notify,
}

#[derive(Clone)]
pub struct EngineHostHandle {
    inner: Arc<HostInner>,
}

impl EngineHostHandle {
    pub fn origin_http(&self) -> String {
        format!("http://{}", self.inner.addr_str)
    }

    pub fn addr(&self) -> &str {
        &self.inner.addr_str
    }

    pub fn manifest(&self) -> &CapsuleManifest {
        &self.inner.manifest
    }

    pub fn signer_public_key_bytes(&self) -> Vec<u8> {
        self.inner.signer_keypair.public_key().as_ref().to_vec()
    }

    pub fn register_issued_lease(&self, lease: KeyLease) {
        let mut leases = self
            .inner
            .issued_leases
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        leases.insert(lease.lease_id.clone(), lease);
    }

    pub fn current_epoch_lease(&self) -> EpochLease {
        let plane = self
            .inner
            .epoch_plane
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        plane.current_lease()
    }

    pub fn transfer_roam_ownership(&self, new_owner: &str) -> EpochLease {
        let mut plane = self
            .inner
            .epoch_plane
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        plane.transfer_ownership(new_owner)
    }

    pub fn authorize_mutation(
        &self,
        claimed_epoch: u64,
        caller_node_id: &str,
    ) -> Result<(), HostError> {
        let mut plane = self
            .inner
            .epoch_plane
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        plane
            .authorize_mutation(claimed_epoch, caller_node_id)
            .map_err(|e| HostError::EpochFenced(e.to_string()))
    }

    pub fn sign_host_attestation(
        &self,
        ephemeral_p256_pubkey_spki_b64: String,
        nonce: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<SignedCapsuleAttestation, HostError> {
        let claims = CapsuleAttestationClaims {
            capsule_hash: self.inner.manifest.capsule_hash_hex(),
            rust_target: self.inner.manifest.rust_target.clone(),
            baseline_id: self.inner.manifest.baseline.as_str().to_string(),
            page_size: CAPSULE_PINNED_PAGE_SIZE,
            ephemeral_p256_pubkey_spki_b64,
            nonce: nonce.into(),
            issued_at_ms,
            expires_at_ms,
        };
        sign_capsule_attestation(claims, &self.inner.signer_keypair)
            .map_err(|e| HostError::Attestation(e.to_string()))
    }

    pub fn issue_attested_key_lease(
        &self,
        report: &SignedCapsuleAttestation,
        lease_id: impl Into<String>,
        session_id: impl Into<String>,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<crate::attestation::WrappedKeyLeaseRelease, HostError> {
        let mut aes256_key = [0u8; 32];
        getrandom::fill(&mut aes256_key)
            .map_err(|e| HostError::Attestation(format!("lease key rng: {e}")))?;
        let epoch = self.current_epoch_lease().epoch;
        let lease_id_str = lease_id.into();
        let lease = KeyLease {
            lease_id: lease_id_str.clone(),
            session_id: session_id.into(),
            epoch,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            revoked: false,
            aes256_key,
        };
        let wrapped = {
            let mut auth = self
                .inner
                .attestation_authority
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            auth.release_wrapped_key_lease(report, &lease, now_ms)
                .map_err(|e| HostError::Attestation(e.to_string()))?
        };
        let mut leases = self
            .inner
            .issued_leases
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        leases.insert(lease_id_str, lease);
        Ok(wrapped)
    }

    pub fn release_attested_dbsc(
        &self,
        report: &SignedCapsuleAttestation,
        dbsc_session_id: &str,
        origin: &str,
        challenge: &str,
        now_ms: u64,
    ) -> Result<crate::attestation::DbscSessionCredential, HostError> {
        let mut auth = self
            .inner
            .attestation_authority
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        auth.release_dbsc_credential(report, dbsc_session_id, origin, challenge, now_ms)
            .map_err(|e| HostError::Attestation(e.to_string()))
    }

    pub fn get_issued_lease(&self, lease_id: &str) -> Result<KeyLease, HostError> {
        let guard = self
            .inner
            .issued_leases
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.get(lease_id).cloned().ok_or_else(|| {
            HostError::Attestation(format!("unknown or unattested lease {lease_id}"))
        })
    }

    pub fn authority(&self) -> Arc<Mutex<AuthoritySupervisor>> {
        Arc::clone(&self.inner.authority_supervisor)
    }

    pub fn authority_hub(&self) -> Arc<ControlHub> {
        Arc::clone(&self.inner.authority_hub)
    }

    pub fn start_authority_socket(
        &self,
        config: ControlServerConfig,
    ) -> Result<PathBuf, HostError> {
        let daemon = AuthoritySocketDaemon::spawn(self.authority(), config)
            .map_err(|e| HostError::Io(format!("start authority control socket: {e}")))?;
        let path = daemon.socket_path().to_path_buf();
        let mut guard = self
            .inner
            .authority_daemon
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(mut old) = guard.take() {
            old.shutdown();
        }
        *guard = Some(daemon);
        Ok(path)
    }

    pub fn resolve_tokenized_submission(
        &self,
        ceremony_id: &str,
        target_url: &str,
        fields: &[(String, String)],
    ) -> Result<Vec<(String, String)>, HostError> {
        let mut sup = self
            .inner
            .authority_supervisor
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sup.resolve_tokenized_submission(ceremony_id, target_url, fields)
            .map_err(HostError::Attestation)
    }

    pub fn audit_verify_chain(&self) -> Result<(), usize> {
        let sup = self
            .inner
            .authority_supervisor
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sup.engine.audit_log().verify_chain()
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
        let daemon = self
            .inner
            .authority_daemon
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(mut d) = daemon {
            d.shutdown();
        }
        if let Ok(mut sup) = self.inner.authority_supervisor.lock() {
            sup.stop_socket_server();
            sup.engine.backend_mut().shutdown();
        }
        let targets: Vec<Arc<TargetRuntime>> = {
            let guard = self.inner.targets.lock().unwrap_or_else(|e| e.into_inner());
            guard.values().cloned().collect()
        };
        for target in targets {
            let mut worker_guard = target.deno.lock().await;
            if let Some(mut worker) = worker_guard.take() {
                worker.shutdown().await;
            }
            drop(worker_guard);
            let dead_cap = target
                .capsule_worker
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            destroy_capsule_worker_async(dead_cap).await;
        }
        self.inner.render.shutdown();
    }

    pub async fn ensure_target_capsule_worker(&self, target_id: &str) -> Result<(), HostError> {
        let runtime = self.ensure_target(target_id).await?;
        let probe = tokio::task::spawn_blocking(MacosLinuxCapsuleDriver::probe)
            .await
            .map_err(|e| HostError::Freeze(format!("capsule probe task: {e}")))?;
        if !probe.available {
            return Err(HostError::Freeze(probe.reason));
        }
        let docker_bin = PathBuf::from(
            probe
                .docker_bin
                .ok_or_else(|| HostError::Freeze("missing capsule docker_bin".to_string()))?,
        );
        let _ = self
            .ensure_capsule_worker_for_runtime(&runtime, &docker_bin)
            .await?;
        Ok(())
    }

    pub async fn set_target_capsule_secret(
        &self,
        target_id: &str,
        secret: &str,
    ) -> Result<(), HostError> {
        let runtime = self.ensure_target(target_id).await?;
        let target = runtime
            .capsule_worker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|w| w.dump_target().clone())
            .ok_or_else(|| HostError::Freeze("missing capsule worker for target".to_string()))?;
        let owned = secret.to_string();
        tokio::task::spawn_blocking(move || target.set_heap_secret(&owned))
            .await
            .map_err(|e| HostError::Freeze(format!("capsule secret task: {e}")))?
            .map_err(|e| HostError::Freeze(e.to_string()))
    }

    pub async fn inspect_target_capsule(
        &self,
        target_id: &str,
        timeout: Duration,
    ) -> Result<Option<CapsuleInspectReport>, HostError> {
        let runtime = self.ensure_target(target_id).await?;
        let target = runtime
            .capsule_worker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|w| w.dump_target().clone());
        let Some(target) = target else {
            return Ok(None);
        };
        let report = tokio::task::spawn_blocking(move || target.inspect(timeout))
            .await
            .map_err(|e| HostError::Freeze(format!("capsule inspect task: {e}")))?
            .map_err(|e| HostError::Freeze(e.to_string()))?;
        Ok(Some(report))
    }

    async fn ensure_capsule_worker_for_runtime(
        &self,
        runtime: &Arc<TargetRuntime>,
        docker_bin: &std::path::Path,
    ) -> Result<CapsuleDumpTarget, HostError> {
        let existing = runtime
            .capsule_worker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|w| w.dump_target().clone());
        if let Some(target) = existing {
            return Ok(target);
        }
        let baseline = self.inner.manifest.baseline;
        let db = docker_bin.to_path_buf();
        let spawned = tokio::task::spawn_blocking(move || {
            MacosLinuxCapsuleDriver::spawn_deno_worker(&db, baseline)
        })
        .await
        .map_err(|e| HostError::Freeze(format!("spawn capsule worker task: {e}")))?
        .map_err(|e| HostError::Freeze(e.to_string()))?;
        let (chosen, duplicate) = install_capsule_worker(runtime, spawned);
        destroy_capsule_worker_async(duplicate).await;
        Ok(chosen)
    }

    async fn prepare_capsule_freeze(
        &self,
        runtime: &Arc<TargetRuntime>,
    ) -> Result<Option<(CapsuleDumpTarget, RuntimeEnvironmentSpec)>, HostError> {
        let probe = tokio::task::spawn_blocking(MacosLinuxCapsuleDriver::probe)
            .await
            .map_err(|e| HostError::Freeze(format!("capsule probe task: {e}")))?;
        if !probe.available {
            return Ok(None);
        }
        let Some(docker_str) = probe.docker_bin else {
            return Ok(None);
        };
        let docker_bin = PathBuf::from(docker_str);
        let dump_target = self
            .ensure_capsule_worker_for_runtime(runtime, &docker_bin)
            .await?;
        let env = tokio::task::spawn_blocking(move || {
            MacosLinuxCapsuleDriver::probe_capsule_environment(&docker_bin)
        })
        .await
        .map_err(|e| HostError::Freeze(format!("probe capsule env task: {e}")))?
        .map_err(|e| HostError::Freeze(e.to_string()))?;
        Ok(Some((dump_target, env)))
    }

    fn select_bundle_signer_pubkey<'a>(&'a self, bundle: &SealedCheckpointBundle) -> &'a [u8] {
        let own = self.inner.signer_keypair.public_key().as_ref();
        if verify_bundle_signature(bundle, own).is_ok() {
            return own;
        }
        for candidate in &self.inner.trusted_signer_pubkeys {
            if verify_bundle_signature(bundle, candidate).is_ok() {
                return candidate.as_slice();
            }
        }
        own
    }

    async fn resolve_thaw_env(
        &self,
        uses_capsule: bool,
    ) -> Result<RuntimeEnvironmentSpec, HostError> {
        if !uses_capsule {
            return Ok(RuntimeEnvironmentSpec::probe_host(
                probe_criu_binary(None).available,
            ));
        }
        let probe = tokio::task::spawn_blocking(MacosLinuxCapsuleDriver::probe)
            .await
            .map_err(|e| HostError::Freeze(format!("capsule probe task: {e}")))?;
        if !probe.available {
            return Ok(RuntimeEnvironmentSpec::probe_host(false));
        }
        let Some(docker_str) = probe.docker_bin else {
            return Ok(RuntimeEnvironmentSpec::probe_host(false));
        };
        let docker_bin = PathBuf::from(docker_str);
        let res = tokio::task::spawn_blocking(move || {
            MacosLinuxCapsuleDriver::probe_capsule_environment(&docker_bin)
        })
        .await
        .map_err(|e| HostError::Freeze(format!("probe capsule env task: {e}")))?;
        Ok(res.unwrap_or_else(|_| RuntimeEnvironmentSpec::probe_host(false)))
    }

    async fn install_restored_state_and_deno(
        &self,
        runtime: &Arc<TargetRuntime>,
        target_id: &str,
        restored: &FreezeStateSnapshot,
        old_worker: Option<DenoWorkerProcess>,
    ) -> Result<(), HostError> {
        self.inner
            .render
            .navigate_html(
                target_id,
                &restored.url,
                &restored.html,
                restored.viewport_width,
                restored.viewport_height,
            )
            .await?;
        self.inner
            .render
            .set_scroll(target_id, restored.scroll_x, restored.scroll_y)
            .await?;
        if let Some(worker) = old_worker {
            let mut deno_guard = runtime.deno.lock().await;
            *deno_guard = Some(worker);
            return Ok(());
        }
        let worker = spawn_target_deno_worker(
            target_id,
            runtime,
            &self.inner.render,
            &self.inner.manifest.v8_flags,
        )
        .await?;
        let parsed_js: Value = serde_json::from_str(&restored.js_state_json).unwrap_or(Value::Null);
        let _ = worker
            .session
            .call("restoreState", vec![parsed_js], Vec::new())
            .await?;
        let mut reseed_entropy = [0u8; 32];
        getrandom::fill(&mut reseed_entropy)
            .map_err(|e| HostError::Freeze(format!("thaw reseed entropy: {e}")))?;
        let reseed_hex = crate::capsule::hex_encode(&reseed_entropy);
        let _ = worker
            .session
            .call("reseedPrng", vec![Value::String(reseed_hex)], Vec::new())
            .await?;
        let mut deno_guard = runtime.deno.lock().await;
        *deno_guard = Some(worker);
        Ok(())
    }

    async fn ensure_target(&self, target_id: &str) -> Result<Arc<TargetRuntime>, HostError> {
        let existing = {
            let guard = self.inner.targets.lock().unwrap_or_else(|e| e.into_inner());
            guard.get(target_id).cloned()
        };
        if let Some(runtime) = existing {
            return Ok(runtime);
        }
        self.inner.render.ensure_target(target_id).await?;
        let mut guard = self.inner.targets.lock().unwrap_or_else(|e| e.into_inner());
        let rt = guard
            .entry(target_id.to_string())
            .or_insert_with(|| Arc::new(TargetRuntime::new(target_id.to_string())))
            .clone();
        Ok(rt)
    }

    pub async fn navigate(
        &self,
        target_id: &str,
        url: &str,
        explicit_html: Option<&str>,
    ) -> Result<TargetInfoSnapshot, HostError> {
        let runtime = self.ensure_target(target_id).await?;
        let req_id = self.inner.next_req_id.fetch_add(1, Ordering::SeqCst);
        let html = resolve_navigation_html(
            &self.inner.http_client,
            &self.inner.broker_tracker,
            req_id,
            url,
            explicit_html,
        )
        .await?;
        let info = self
            .inner
            .render
            .navigate_html(target_id, url, &html, 800, 600)
            .await?;

        let worker = spawn_target_deno_worker(
            target_id,
            &runtime,
            &self.inner.render,
            &self.inner.manifest.v8_flags,
        )
        .await?;
        let mut deno_guard = runtime.deno.lock().await;
        if let Some(mut old) = deno_guard.take() {
            old.shutdown().await;
        }
        *deno_guard = Some(worker);
        drop(deno_guard);

        broadcast_ksc2_frame(&self.inner.render, &runtime).await?;
        Ok(info)
    }

    pub async fn evaluate_js(&self, target_id: &str, expression: &str) -> Result<Value, HostError> {
        let runtime = self.ensure_target(target_id).await?;
        ensure_deno_worker_for_target(
            target_id,
            &runtime,
            &self.inner.render,
            &self.inner.manifest.v8_flags,
        )
        .await?;
        let deno_guard = runtime.deno.lock().await;
        let worker = deno_guard
            .as_ref()
            .ok_or_else(|| HostError::Rpc("missing Deno worker".to_string()))?;
        let res = worker
            .session
            .call(
                "evalJs",
                vec![Value::String(expression.to_string())],
                Vec::new(),
            )
            .await?;
        drop(deno_guard);
        if res
            .value
            .get("appliedOps")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
        {
            let _ = broadcast_ksc2_frame(&self.inner.render, &runtime).await;
        }
        Ok(res.value)
    }

    pub async fn capture_png(&self, target_id: &str) -> Result<Vec<u8>, HostError> {
        self.inner.render.paint_png(target_id).await
    }

    pub async fn freeze_target(
        &self,
        target_id: &str,
        lease: &KeyLease,
        now_ms: u64,
    ) -> Result<SealedCheckpointBundle, HostError> {
        let runtime = self.ensure_target(target_id).await?;
        ensure_deno_worker_for_target(
            target_id,
            &runtime,
            &self.inner.render,
            &self.inner.manifest.v8_flags,
        )
        .await?;
        let captured = self.inner.render.snapshot_html(target_id).await?;
        let capsule_ctx = if self.inner.enable_linux_capsule {
            self.prepare_capsule_freeze(&runtime).await?
        } else {
            None
        };

        let deno_guard = runtime.deno.lock().await;
        let worker = deno_guard
            .as_ref()
            .ok_or_else(|| HostError::Rpc("missing Deno worker".to_string()))?;
        let js_state = worker
            .session
            .call("getState", Vec::new(), Vec::new())
            .await?;
        let (env, dump_pid, capsule_target) = match &capsule_ctx {
            Some((target, cap_env)) => (cap_env.clone(), Some(target.pid), Some(target)),
            None => (
                RuntimeEnvironmentSpec::probe_host(probe_criu_binary(None).available),
                worker.pid(),
                None,
            ),
        };
        let gen = self.inner.freeze_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let criu_dir = self
            .inner
            .criu_root_dir
            .join(format!("{target_id}-gen-{gen}"));

        let snapshot = FreezeStateSnapshot {
            session_id: lease.session_id.clone(),
            target_id: target_id.to_string(),
            url: captured.url.clone(),
            html: captured.html,
            history: vec![captured.url],
            viewport_width: captured.viewport_w,
            viewport_height: captured.viewport_h,
            scroll_x: captured.scroll_x,
            scroll_y: captured.scroll_y,
            session_storage: BTreeMap::new(),
            non_credential_form_values: BTreeMap::new(),
            js_state_json: js_state.value.to_string(),
            last_input_seq: runtime.acked_input_seq.load(Ordering::SeqCst),
            acked_scroll_seq: runtime.acked_scroll_seq.load(Ordering::SeqCst),
            freeze_wall_ms: now_ms,
            monotonic_offset_ns: now_ms.saturating_mul(1_000_000),
        };
        let bundle = freeze_session(FreezeParams {
            rpc: Some(&worker.session),
            broker: &self.inner.broker_tracker,
            drain_budget: Duration::from_millis(50),
            manifest: &self.inner.manifest,
            env: &env,
            key_lease: lease,
            signer: &self.inner.signer_keypair,
            snapshot: &snapshot,
            epoch: lease.epoch,
            generation: gen,
            pid: dump_pid,
            criu_images_dir: Some(&criu_dir),
            inherit_fd_labels: default_prwp_inherit_fd_labels(),
            capsule_target,
        })
        .await?;
        drop(deno_guard);
        if capsule_ctx.is_some() && bundle.criu_images.is_some() {
            let dead_cap = runtime
                .capsule_worker
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            destroy_capsule_worker_async(dead_cap).await;
        }
        Ok(bundle)
    }

    pub async fn thaw_target(
        &self,
        target_id: &str,
        bundle: &SealedCheckpointBundle,
        lease: &KeyLease,
        now_ms: u64,
    ) -> Result<ThawOutcome, HostError> {
        let runtime = self.ensure_target(target_id).await?;
        let uses_capsule = self.inner.enable_linux_capsule
            || bundle
                .criu_images
                .as_ref()
                .is_some_and(|i| i.backend == CriuBackendKind::MacosLinuxCapsule);
        let target_env = self.resolve_thaw_env(uses_capsule).await?;
        let trusted_pubkey = self.select_bundle_signer_pubkey(bundle);
        let mut old_worker = runtime.deno.lock().await.take();
        let parked_ref = old_worker.as_ref().and_then(|w| {
            if w.session.stats().state == crate::rpc_pipe::TransportState::Unplugged {
                Some(&w.session)
            } else {
                None
            }
        });
        let restored_slot: Mutex<Option<CapsuleRestoredWorker>> = Mutex::new(None);
        let outcome = thaw_session(ThawParams {
            bundle,
            target_manifest: &self.inner.manifest,
            target_env: &target_env,
            trusted_signer_pubkey: trusted_pubkey,
            key_lease: lease,
            now_wall_ms: now_ms,
            monotonic_elapsed_ms: 20,
            replug_rpc: None,
            replug_parked_rpc: parked_ref,
            reseed_target_rpc: None,
            inherit_fd_labels: default_prwp_inherit_fd_labels(),
            capsule_restore_out: if uses_capsule {
                Some(&restored_slot)
            } else {
                None
            },
        })
        .await?;

        if let ThawOutcome::Tier2Criu { ref snapshot, .. } = outcome {
            let restored_cap = restored_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .map(CapsuleRestoredWorker::into_deno_worker);
            if let Some(cw) = restored_cap {
                let evicted = replace_capsule_worker(&runtime, cw);
                destroy_capsule_worker_async(evicted).await;
            }
            self.install_restored_state_and_deno(&runtime, target_id, snapshot, old_worker)
                .await?;
            broadcast_ksc2_frame(&self.inner.render, &runtime).await?;
            return Ok(outcome);
        }

        if let Some(mut w) = old_worker.take() {
            w.shutdown().await;
        }
        let restored = match &outcome {
            ThawOutcome::Tier2Criu { snapshot, .. }
            | ThawOutcome::Tier1Fallback { snapshot, .. } => snapshot.clone(),
        };
        self.install_restored_state_and_deno(&runtime, target_id, &restored, None)
            .await?;
        broadcast_ksc2_frame(&self.inner.render, &runtime).await?;
        Ok(outcome)
    }
}

fn install_capsule_worker(
    runtime: &Arc<TargetRuntime>,
    spawned: CapsuleDenoWorker,
) -> (CapsuleDumpTarget, Option<CapsuleDenoWorker>) {
    let mut guard = runtime
        .capsule_worker
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = guard.as_ref() {
        return (existing.dump_target().clone(), Some(spawned));
    }
    let chosen = spawned.dump_target().clone();
    *guard = Some(spawned);
    (chosen, None)
}

fn replace_capsule_worker(
    runtime: &Arc<TargetRuntime>,
    next: CapsuleDenoWorker,
) -> Option<CapsuleDenoWorker> {
    let mut guard = runtime
        .capsule_worker
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard.replace(next)
}

async fn destroy_capsule_worker_async(worker: Option<CapsuleDenoWorker>) {
    if let Some(cw) = worker {
        let _ = tokio::task::spawn_blocking(move || cw.destroy_now()).await;
    }
}

async fn ensure_deno_worker_for_target(
    target_id: &str,
    runtime: &Arc<TargetRuntime>,
    render: &RenderActorHandle,
    v8_flags: &[String],
) -> Result<(), HostError> {
    let needs_spawn = runtime.deno.lock().await.is_none();
    if !needs_spawn {
        return Ok(());
    }
    let worker = spawn_target_deno_worker(target_id, runtime, render, v8_flags).await?;
    let mut guard = runtime.deno.lock().await;
    if guard.is_none() {
        *guard = Some(worker);
    }
    Ok(())
}

async fn spawn_target_deno_worker(
    target_id: &str,
    runtime: &Arc<TargetRuntime>,
    render: &RenderActorHandle,
    v8_flags: &[String],
) -> Result<DenoWorkerProcess, HostError> {
    let flag_refs: Vec<&str> = v8_flags.iter().map(String::as_str).collect();
    let worker = spawn_deno_worker(None, build_engine_isolate_script(), &flag_refs).await?;
    let render_cb = render.clone();
    let rt_cb = runtime.clone();
    let tid = target_id.to_string();
    worker
        .session
        .set_callback_handler(Arc::new(move |_, method, args, _| {
            let render = render_cb.clone();
            let rt = rt_cb.clone();
            let target_id = tid.clone();
            Box::pin(async move {
                handle_isolate_callback(&render, &rt, &target_id, method, args).await
            })
        }));
    Ok(worker)
}

async fn handle_isolate_callback(
    render: &RenderActorHandle,
    runtime: &Arc<TargetRuntime>,
    target_id: &str,
    method: Option<String>,
    args: Vec<Value>,
) -> Result<RpcCallResult, String> {
    if method.as_deref() != Some("applyDomOpsById") {
        return Err(format!("unsupported isolate callback method: {method:?}"));
    }
    let raw = args.into_iter().next().unwrap_or(Value::Array(Vec::new()));
    let ops: Vec<DomOpById> = serde_json::from_value(raw).map_err(|e| e.to_string())?;
    let applied = render
        .apply_ops_by_id(target_id, ops)
        .await
        .map_err(|e| e.to_string())?;
    let _ = broadcast_ksc2_frame(render, runtime).await;
    Ok(RpcCallResult {
        value: json!({ "applied": applied }),
        binaries: Vec::new(),
    })
}

async fn broadcast_ksc2_frame(
    render: &RenderActorHandle,
    runtime: &Arc<TargetRuntime>,
) -> Result<(), HostError> {
    let seq = runtime.frame_seq.fetch_add(1, Ordering::SeqCst) + 1;
    let acked_scroll = runtime.acked_scroll_seq.load(Ordering::SeqCst);
    let acked_input = runtime.acked_input_seq.load(Ordering::SeqCst);
    let rendered = render
        .render_ksc2(&runtime.id, acked_scroll, acked_input, Vec::new())
        .await?;
    let pkt = encode_ksv2_reliable_frame(
        seq,
        seq.saturating_sub(1),
        rendered.tile_count,
        &rendered.ksc2_bytes,
    );
    let _ = runtime.viewer_tx.send(pkt);
    Ok(())
}

async fn resolve_navigation_html(
    client: &reqwest::Client,
    broker: &BrokerRequestTracker,
    req_id: u64,
    url: &str,
    explicit_html: Option<&str>,
) -> Result<String, HostError> {
    if let Some(html) = explicit_html {
        return Ok(html.to_string());
    }
    if url == "about:blank" || url.is_empty() {
        return Ok("<html><head><title>about:blank</title></head><body></body></html>".to_string());
    }
    if let Some(rest) = url.strip_prefix("data:text/html;base64,") {
        let bytes = BASE64_STANDARD
            .decode(rest)
            .map_err(|e| HostError::Http(format!("base64 data url: {e}")))?;
        return String::from_utf8(bytes)
            .map_err(|e| HostError::Http(format!("utf8 data url: {e}")));
    }
    if let Some(rest) = url.strip_prefix("data:text/html,") {
        return Ok(urlencoding_decode(rest));
    }
    broker.begin(req_id, true);
    let res = client
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    let resp = match res {
        Ok(r) => r,
        Err(e) => {
            broker.complete(req_id);
            return Err(HostError::Http(format!("GET {url}: {e}")));
        }
    };
    let text = resp
        .text()
        .await
        .map_err(|e| HostError::Http(format!("read body {url}: {e}")));
    broker.complete(req_id);
    text
}

fn urlencoding_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let raw = input.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let Ok(val) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                bytes.push(val);
                i += 3;
                continue;
            }
        }
        bytes.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

static RUSTLS_INIT: Once = Once::new();

pub fn ensure_rustls_provider() {
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn start_engine_host(config: EngineHostConfig) -> Result<EngineHostHandle, HostError> {
    start_engine_host_with_authority(config, AuthorityHostConfig::default()).await
}

/// Starts the native Parawing engine host with an explicit `parawing_authority` configuration.
pub async fn start_engine_host_with_authority(
    config: EngineHostConfig,
    auth_cfg: AuthorityHostConfig,
) -> Result<EngineHostHandle, HostError> {
    ensure_rustls_provider();
    let mut manifest = config.capsule_manifest;
    if config.enable_linux_capsule {
        manifest.criu_enabled = true;
    }
    manifest.v8_flags = resolved_v8_flags(manifest.baseline)
        .map_err(|e| HostError::Freeze(format!("PARAWING_V8_BASELINE_FLAGS rejected: {e}")))?;
    let listener = TcpListener::bind(&config.bind_addr)
        .await
        .map_err(|e| HostError::Io(format!("bind {}: {e}", config.bind_addr)))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| HostError::Io(format!("local_addr: {e}")))?;
    let render = RenderActorHandle::spawn()?;
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| HostError::Http(format!("client build: {e}")))?;
    let default_target = "parawing";
    render.ensure_target(default_target).await?;
    let mut targets = HashMap::new();
    targets.insert(
        default_target.to_string(),
        Arc::new(TargetRuntime::new(default_target.to_string())),
    );
    let seq = HOST_INSTANCE_SEQ.fetch_add(1, Ordering::SeqCst);
    let criu_root_dir =
        std::env::temp_dir().join(format!("parawing-criu-{}-{seq}", std::process::id()));
    let signer_keypair = generate_test_ed25519_keypair();
    let mut all_trusted_pubkeys = vec![signer_keypair.public_key().as_ref().to_vec()];
    all_trusted_pubkeys.extend(config.trusted_signer_pubkeys.iter().cloned());
    let authority = CapsuleAttestationAuthority::from_manifest(&manifest, all_trusted_pubkeys)
        .map_err(|e| HostError::Attestation(e.to_string()))?;
    let node_id = "rust-host-primary".to_string();
    let auth_backend =
        BlitzDenoAuthorityBackend::with_render(render.clone(), manifest.v8_flags.clone())
            .map_err(HostError::Render)?;
    let supervisor = if auth_cfg.use_keychain {
        AuthoritySupervisor::with_keychain(
            auth_backend,
            auth_cfg
                .password_service
                .as_deref()
                .unwrap_or("parawing-passwords"),
            auth_cfg
                .passkey_service
                .as_deref()
                .unwrap_or("parawing-passkeys"),
            auth_cfg
                .passkey_account
                .as_deref()
                .unwrap_or("default-account"),
        )
    } else {
        AuthoritySupervisor::in_memory(auth_backend)
    };
    let authority_hub = supervisor.hub();
    let authority_supervisor = Arc::new(Mutex::new(supervisor));
    let initial_daemon = match auth_cfg.control_socket {
        Some(sock_cfg) => Some(
            AuthoritySocketDaemon::spawn(Arc::clone(&authority_supervisor), sock_cfg)
                .map_err(|e| HostError::Io(format!("start authority socket: {e}")))?,
        ),
        None => None,
    };

    let inner = Arc::new(HostInner {
        render,
        targets: Mutex::new(targets),
        manifest,
        criu_root_dir,
        freeze_generation: AtomicU64::new(0),
        next_req_id: AtomicU64::new(1),
        signer_keypair,
        trusted_signer_pubkeys: config.trusted_signer_pubkeys,
        enable_linux_capsule: config.enable_linux_capsule,
        http_client,
        broker_tracker: BrokerRequestTracker::default(),
        epoch_plane: Mutex::new(EpochControlPlane::new(node_id)),
        precopy: Mutex::new(HashMap::new()),
        replica_pages: Mutex::new(BTreeMap::new()),
        intents: Mutex::new(IntentCoordinator::default()),
        egress_streams: Mutex::new(EgressStreamTable::default()),
        attestation_authority: Mutex::new(authority),
        issued_leases: Mutex::new(HashMap::new()),
        authority_supervisor,
        authority_hub,
        authority_daemon: Mutex::new(initial_daemon),
        addr_str: local_addr.to_string(),
        shutdown: Notify::new(),
    });
    let handle = EngineHostHandle { inner };
    spawn_accept_loop(listener, handle.clone());
    Ok(handle)
}

impl EngineHostHandle {
    pub fn stage_precopy_pages(
        &self,
        pages: &[(u64, &[u8])],
        lease: &KeyLease,
    ) -> Result<PreCopyBatch, HostError> {
        let mut precopy_map = self.inner.precopy.lock().unwrap_or_else(|e| e.into_inner());
        let precopy = precopy_map
            .entry(lease.session_id.clone())
            .or_insert_with(|| PreCopySession::new(&lease.session_id));
        precopy
            .stage_dirty_pages(pages, lease)
            .map_err(|e| HostError::Roam(e.to_string()))
    }

    pub fn apply_precopy_batch(
        &self,
        session_id: &str,
        lease: &KeyLease,
        batch: &PreCopyBatch,
    ) -> Result<usize, HostError> {
        let mut pages = self
            .inner
            .replica_pages
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        PreCopySession::apply_precopy_batch(session_id, lease, batch, &mut pages)
            .map_err(|e| HostError::Roam(e.to_string()))
    }

    pub fn replica_page(&self, page_index: u64) -> Option<Vec<u8>> {
        let pages = self
            .inner
            .replica_pages
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pages.get(&page_index).cloned()
    }

    pub fn record_intent(
        &self,
        intent_id: &str,
        generation: u64,
        method: &str,
        url: &str,
        body: &[u8],
    ) {
        let mut intents = self.inner.intents.lock().unwrap_or_else(|e| e.into_inner());
        intents.record_outbound_intent(intent_id, generation, method, url, body);
    }

    pub fn commit_intent(&self, intent_id: &str) -> bool {
        let mut intents = self.inner.intents.lock().unwrap_or_else(|e| e.into_inner());
        intents.mark_committed(intent_id)
    }

    pub fn resolve_abrupt_loss(&self, last_complete_generation: u64) -> AbruptLossDecision {
        let intents = self.inner.intents.lock().unwrap_or_else(|e| e.into_inner());
        intents.resolve_abrupt_loss(last_complete_generation)
    }

    pub fn open_egress_stream(&self, site_origin: &str, kind: StreamKind, mode: EgressMode) -> u64 {
        let mut table = self
            .inner
            .egress_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.open_stream(site_origin, kind, mode)
    }

    pub fn begin_roam_streams(&self) {
        let mut table = self
            .inner
            .egress_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.begin_roam();
    }

    pub fn push_egress_frame(&self, stream_id: u64, data: Vec<u8>) -> Result<(), HostError> {
        let mut table = self
            .inner
            .egress_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table
            .push_external_frame(stream_id, data)
            .map_err(|e| HostError::Roam(e.to_string()))
    }

    pub fn replug_roam_streams(&self) -> Vec<u64> {
        let mut table = self
            .inner
            .egress_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.replug_after_roam()
    }

    pub fn get_egress_stream(&self, stream_id: u64) -> Option<crate::roam::EgressStreamEntry> {
        let table = self
            .inner
            .egress_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.entry(stream_id).cloned()
    }
}

fn spawn_accept_loop(listener: TcpListener, handle: EngineHostHandle) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = handle.inner.shutdown.notified() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    let h = handle.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(h, stream).await;
                    });
                }
            }
        }
    });
}

struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let avail = &self.prefix[self.pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct ParsedHttpRequest {
    method: String,
    raw_target: String,
    host: String,
    is_websocket: bool,
    raw_head: Vec<u8>,
    body: Vec<u8>,
}

fn host_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn parse_http_headers(header_bytes: &[u8]) -> (String, String, String, bool, usize) {
    let text = String::from_utf8_lossy(header_bytes);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let raw_target = parts.next().unwrap_or("/").to_string();
    let mut host = String::new();
    let mut is_websocket = false;
    let mut content_length = 0usize;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        if key == "host" {
            host = val.to_string();
        } else if key == "upgrade" && val.eq_ignore_ascii_case("websocket") {
            is_websocket = true;
        } else if key == "content-length" {
            content_length = val.parse::<usize>().unwrap_or(0);
        }
    }
    (method, raw_target, host, is_websocket, content_length)
}

async fn read_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, HostError> {
    let mut raw = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if let Some(end) = find_http_header_end(&raw) {
            break end;
        }
        if raw.len() > 16 * 1024 {
            return Err(HostError::Http("HTTP header exceeded 16 KiB".to_string()));
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| HostError::Io(format!("read http head: {e}")))?;
        if n == 0 {
            return Err(HostError::Io("EOF reading http head".to_string()));
        }
        raw.extend_from_slice(&tmp[..n]);
    };
    let (method, raw_target, host, is_websocket, content_len) =
        parse_http_headers(&raw[..header_end]);
    let mut body = Vec::new();
    if !is_websocket && content_len > 0 {
        if content_len > 2 * 1024 * 1024 {
            return Err(HostError::Http("HTTP body exceeded 2 MiB".to_string()));
        }
        body.extend_from_slice(&raw[header_end..]);
        while body.len() < content_len {
            let need = content_len - body.len();
            let mut chunk = vec![0u8; need.min(16 * 1024)];
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| HostError::Io(format!("read http body: {e}")))?;
            if n == 0 {
                return Err(HostError::Io("EOF reading http body".to_string()));
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(content_len);
    }
    Ok(ParsedHttpRequest {
        method,
        raw_target,
        host,
        is_websocket,
        raw_head: raw,
        body,
    })
}

fn parse_ws_caller_identity(raw_target: &str, current: &EpochLease) -> (u64, String) {
    let mut epoch = current.epoch;
    let mut node_id = current.owner_node_id.clone();
    let Some((_, query)) = raw_target.split_once('?') else {
        return (epoch, node_id);
    };
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        if k == "epoch" {
            if let Ok(parsed) = v.parse::<u64>() {
                epoch = parsed;
            }
        } else if k == "nodeId" && !v.is_empty() {
            node_id = v.into_owned();
        }
    }
    (epoch, node_id)
}

async fn handle_connection(
    handle: EngineHostHandle,
    mut stream: TcpStream,
) -> Result<(), HostError> {
    let req = read_http_request(&mut stream).await?;
    let path = req.raw_target.split('?').next().unwrap_or("/");
    if req.is_websocket {
        let lease = handle.current_epoch_lease();
        let caller = parse_ws_caller_identity(&req.raw_target, &lease);
        let prefixed = PrefixedStream {
            prefix: req.raw_head,
            pos: 0,
            inner: stream,
        };
        if let Some(target_id) = path.strip_prefix("/devtools/page/") {
            return serve_cdp_ws(handle, target_id.to_string(), caller, prefixed).await;
        }
        if path == "/devtools/browser" {
            return serve_cdp_ws(handle, "parawing".to_string(), caller, prefixed).await;
        }
        if let Some(target_id) = path.strip_prefix("/viewer/") {
            return serve_viewer_ws(handle, target_id.to_string(), caller, prefixed).await;
        }
        return Err(HostError::Http(format!("unknown WS path: {path}")));
    }
    serve_http_route(handle, &req.method, path, &req.host, &req.body, stream).await
}

fn host_error_status(err: &HostError) -> u16 {
    match err {
        HostError::Http(_) | HostError::Rpc(_) => 400,
        HostError::Attestation(_) | HostError::Freeze(_) => 403,
        HostError::EpochFenced(_) | HostError::Roam(_) => 409,
        _ => 500,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpIssueLeaseReq {
    attestation: SignedCapsuleAttestation,
    lease_id: String,
    session_id: String,
    ttl_ms: Option<u64>,
    now_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpDbscReq {
    attestation: SignedCapsuleAttestation,
    dbsc_session_id: String,
    origin: String,
    challenge: String,
    now_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreCopyPageInput {
    page_index: u64,
    data_b64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpPreCopyStageReq {
    lease_id: String,
    pages: Vec<PreCopyPageInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpPreCopyApplyReq {
    lease_id: String,
    session_id: String,
    batch: PreCopyBatch,
}

fn decode_precopy_pages(pages: &[PreCopyPageInput]) -> Result<Vec<(u64, Vec<u8>)>, HostError> {
    let mut out = Vec::with_capacity(pages.len());
    for p in pages {
        let bytes = BASE64_STANDARD
            .decode(&p.data_b64)
            .map_err(|e| HostError::Http(format!("invalid page base64: {e}")))?;
        out.push((p.page_index, bytes));
    }
    Ok(out)
}

async fn write_result_json(
    stream: &mut TcpStream,
    res: Result<Value, HostError>,
) -> Result<(), HostError> {
    match res {
        Ok(val) => write_json_response(stream, 200, &val).await,
        Err(err) => {
            let status = host_error_status(&err);
            let body = json!({ "error": err.to_string() });
            write_json_response(stream, status, &body).await
        }
    }
}

fn http_issue_lease(handle: &EngineHostHandle, body: &[u8]) -> Result<Value, HostError> {
    let req: HttpIssueLeaseReq =
        serde_json::from_slice(body).map_err(|e| HostError::Http(e.to_string()))?;
    let wrapped = handle.issue_attested_key_lease(
        &req.attestation,
        req.lease_id,
        req.session_id,
        req.ttl_ms.unwrap_or(60_000),
        req.now_ms.unwrap_or_else(host_now_ms),
    )?;
    serde_json::to_value(wrapped).map_err(|e| HostError::Http(e.to_string()))
}

fn http_dbsc_credential(handle: &EngineHostHandle, body: &[u8]) -> Result<Value, HostError> {
    let req: HttpDbscReq =
        serde_json::from_slice(body).map_err(|e| HostError::Http(e.to_string()))?;
    let cred = handle.release_attested_dbsc(
        &req.attestation,
        &req.dbsc_session_id,
        &req.origin,
        &req.challenge,
        req.now_ms.unwrap_or_else(host_now_ms),
    )?;
    serde_json::to_value(cred).map_err(|e| HostError::Http(e.to_string()))
}

fn http_precopy_stage(handle: &EngineHostHandle, body: &[u8]) -> Result<Value, HostError> {
    let req: HttpPreCopyStageReq =
        serde_json::from_slice(body).map_err(|e| HostError::Http(e.to_string()))?;
    let lease = handle.get_issued_lease(&req.lease_id)?;
    let owned = decode_precopy_pages(&req.pages)?;
    let refs: Vec<(u64, &[u8])> = owned
        .iter()
        .map(|(idx, data)| (*idx, data.as_slice()))
        .collect();
    let batch = handle.stage_precopy_pages(&refs, &lease)?;
    serde_json::to_value(batch).map_err(|e| HostError::Http(e.to_string()))
}

fn http_precopy_apply(handle: &EngineHostHandle, body: &[u8]) -> Result<Value, HostError> {
    let req: HttpPreCopyApplyReq =
        serde_json::from_slice(body).map_err(|e| HostError::Http(e.to_string()))?;
    let lease = handle.get_issued_lease(&req.lease_id)?;
    let applied = handle.apply_precopy_batch(&req.session_id, &lease, &req.batch)?;
    Ok(json!({ "appliedChunks": applied }))
}

fn handle_http_post_json(
    handle: &EngineHostHandle,
    path: &str,
    body: &[u8],
) -> Option<Result<Value, HostError>> {
    match path {
        "/authority/issue-attested-lease" => Some(http_issue_lease(handle, body)),
        "/authority/dbsc-credential" => Some(http_dbsc_credential(handle, body)),
        "/roam/precopy/stage" => Some(http_precopy_stage(handle, body)),
        "/roam/precopy/apply" => Some(http_precopy_apply(handle, body)),
        _ => None,
    }
}

async fn serve_http_route(
    handle: EngineHostHandle,
    method: &str,
    path: &str,
    host_header: &str,
    body: &[u8],
    mut stream: TcpStream,
) -> Result<(), HostError> {
    let host = if host_header.is_empty() {
        handle.addr()
    } else {
        host_header
    };
    if method == "POST" {
        if let Some(res) = handle_http_post_json(&handle, path, body) {
            return write_result_json(&mut stream, res).await;
        }
    }
    if method == "GET" && path == "/health" {
        return write_http_response(
            &mut stream,
            200,
            "text/plain; charset=utf-8",
            b"parawing-rust-host: OK\n",
        )
        .await;
    }
    if method == "GET" && (path == "/json/version" || path == "/json/version/") {
        let product = format!("Parawing-Rust-Host/{}", crate::RELEASE_VERSION);
        let out = json!({
            "Browser": product,
            "Protocol-Version": "1.3",
            "User-Agent": format!("Parawing-Rust-Host/{}", crate::RELEASE_VERSION),
            "webSocketDebuggerUrl": format!("ws://{host}/devtools/browser"),
        });
        return write_json_response(&mut stream, 200, &out).await;
    }
    if method == "GET" && (path == "/json" || path == "/json/list" || path == "/json/list/") {
        let out = list_targets_json(&handle, host).await?;
        return write_json_response(&mut stream, 200, &out).await;
    }
    if method == "GET" && path == "/roam/epoch" {
        return write_json_response(&mut stream, 200, &json!(handle.current_epoch_lease())).await;
    }
    if method == "GET" && path == "/capsule/manifest" {
        let criu = probe_criu_binary(None);
        let capsule_hash = handle.manifest().capsule_hash_hex();
        let out = json!({
            "manifest": handle.manifest(),
            "capsuleHash": capsule_hash,
            "pageSize": CAPSULE_PINNED_PAGE_SIZE,
            "criu": criu,
        });
        return write_json_response(&mut stream, 200, &out).await;
    }
    if method == "GET" {
        if let Some(target_id) = path
            .strip_prefix("/screenshot/")
            .and_then(|s| s.strip_suffix(".png"))
        {
            let png = handle.capture_png(target_id).await?;
            return write_http_response(&mut stream, 200, "image/png", &png).await;
        }
    }
    write_http_response(
        &mut stream,
        404,
        "text/plain; charset=utf-8",
        b"Not Found\n",
    )
    .await
}

async fn list_targets_json(handle: &EngineHostHandle, host: &str) -> Result<Value, HostError> {
    let ids: Vec<String> = {
        let guard = handle
            .inner
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.keys().cloned().collect()
    };
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        let info = handle.inner.render.get_info(&id).await?;
        items.push(json!({
            "id": id,
            "type": "page",
            "title": info.title,
            "url": info.url,
            "description": "parawing native rust target",
            "webSocketDebuggerUrl": format!("ws://{host}/devtools/page/{id}"),
            "devtoolsFrontendUrl": format!("devtools://devtools/bundled/inspector.html?ws={host}/devtools/page/{id}"),
        }));
    }
    Ok(Value::Array(items))
}

async fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    value: &Value,
) -> Result<(), HostError> {
    let bytes = serde_json::to_vec(value).map_err(|e| HostError::Http(e.to_string()))?;
    write_http_response(stream, status, "application/json; charset=utf-8", &bytes).await
}

fn http_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    }
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), HostError> {
    let reason = http_reason_phrase(status);
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| HostError::Io(e.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| HostError::Io(e.to_string()))?;
    let _ = stream.flush().await;
    Ok(())
}

fn target_for_cdp_session<'a>(default_target: &'a str, session_id: Option<&'a str>) -> &'a str {
    let Some(sid) = session_id else {
        return default_target;
    };
    sid.strip_prefix("session-").unwrap_or(default_target)
}

fn build_cdp_reply(id: u64, session_id: Option<&str>, reply: Result<Value, HostError>) -> Value {
    let mut payload = match reply {
        Ok(result) => json!({ "id": id, "result": result }),
        Err(err) => json!({ "id": id, "error": { "code": -32000, "message": err.to_string() } }),
    };
    if let (Some(sid), Some(obj)) = (session_id, payload.as_object_mut()) {
        obj.insert("sessionId".to_string(), Value::String(sid.to_string()));
    }
    payload
}

async fn serve_cdp_ws(
    handle: EngineHostHandle,
    target_id: String,
    caller: (u64, String),
    stream: PrefixedStream,
) -> Result<(), HostError> {
    handle.ensure_target(&target_id).await?;
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| HostError::Io(format!("cdp ws handshake: {e}")))?;
    while let Some(msg) = ws.next().await {
        let Ok(Message::Text(text)) = msg else {
            continue;
        };
        let req: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let id = req.get("id").and_then(Value::as_u64).unwrap_or(0);
        let session_id = req.get("sessionId").and_then(Value::as_str);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        let effective_target = target_for_cdp_session(&target_id, session_id);
        let reply = dispatch_cdp_method(&handle, effective_target, &caller, method, &params).await;
        let payload = build_cdp_reply(id, session_id, reply);
        if ws
            .send(Message::Text(payload.to_string().into()))
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

fn cdp_str_field<'a>(params: &'a Value, key: &str) -> Result<&'a str, HostError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| HostError::Rpc(format!("missing or empty string param: {key}")))
}

fn dispatch_parawing_authority_cdp(
    handle: &EngineHostHandle,
    method: &str,
    params: &Value,
) -> Result<Value, HostError> {
    match method {
        "Parawing.signCapsuleAttestation" => {
            let eph = cdp_str_field(params, "ephemeralP256PubkeySpkiB64")?.to_string();
            let nonce = cdp_str_field(params, "nonce")?;
            let now = host_now_ms();
            let issued = params
                .get("issuedAtMs")
                .and_then(Value::as_u64)
                .unwrap_or(now);
            let expires = params
                .get("expiresAtMs")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| issued.saturating_add(60_000));
            let report = handle.sign_host_attestation(eph, nonce, issued, expires)?;
            serde_json::to_value(report).map_err(|e| HostError::Rpc(e.to_string()))
        }
        "Parawing.issueAttestedKeyLease" => {
            let att_val = params
                .get("attestation")
                .cloned()
                .ok_or_else(|| HostError::Attestation("missing attestation report".to_string()))?;
            let report: SignedCapsuleAttestation = serde_json::from_value(att_val)
                .map_err(|e| HostError::Attestation(format!("invalid attestation JSON: {e}")))?;
            let lease_id = cdp_str_field(params, "leaseId")?;
            let session_id = cdp_str_field(params, "sessionId")?;
            let ttl_ms = params
                .get("ttlMs")
                .and_then(Value::as_u64)
                .unwrap_or(60_000);
            let now_ms = params
                .get("nowMs")
                .and_then(Value::as_u64)
                .unwrap_or_else(host_now_ms);
            let wrapped =
                handle.issue_attested_key_lease(&report, lease_id, session_id, ttl_ms, now_ms)?;
            serde_json::to_value(wrapped).map_err(|e| HostError::Rpc(e.to_string()))
        }
        "Parawing.releaseDbscCredential" => {
            let att_val = params
                .get("attestation")
                .cloned()
                .ok_or_else(|| HostError::Attestation("missing attestation report".to_string()))?;
            let report: SignedCapsuleAttestation = serde_json::from_value(att_val)
                .map_err(|e| HostError::Attestation(format!("invalid attestation JSON: {e}")))?;
            let sid = cdp_str_field(params, "dbscSessionId")?;
            let origin = cdp_str_field(params, "origin")?;
            let challenge = cdp_str_field(params, "challenge")?;
            let now_ms = params
                .get("nowMs")
                .and_then(Value::as_u64)
                .unwrap_or_else(host_now_ms);
            let cred = handle.release_attested_dbsc(&report, sid, origin, challenge, now_ms)?;
            serde_json::to_value(cred).map_err(|e| HostError::Rpc(e.to_string()))
        }
        _ => Err(HostError::Rpc(format!("unsupported CDP method: {method}"))),
    }
}

fn dispatch_parawing_roam_mut_cdp(
    handle: &EngineHostHandle,
    method: &str,
    params: &Value,
) -> Result<Value, HostError> {
    match method {
        "Parawing.transferOwnership" => {
            let new_owner = cdp_str_field(params, "newOwner")?;
            let lease = handle.transfer_roam_ownership(new_owner);
            serde_json::to_value(lease).map_err(|e| HostError::Rpc(e.to_string()))
        }
        "Parawing.stagePreCopy" => {
            let bytes = serde_json::to_vec(params).map_err(|e| HostError::Rpc(e.to_string()))?;
            http_precopy_stage(handle, &bytes)
        }
        "Parawing.applyPreCopy" => {
            let bytes = serde_json::to_vec(params).map_err(|e| HostError::Rpc(e.to_string()))?;
            http_precopy_apply(handle, &bytes)
        }
        "Parawing.recordIntent" => {
            let id = cdp_str_field(params, "intentId")?;
            let generation = params
                .get("generation")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            let http_method = cdp_str_field(params, "method")?;
            let url = cdp_str_field(params, "url")?;
            let body_b64 = params.get("bodyB64").and_then(Value::as_str).unwrap_or("");
            let body = BASE64_STANDARD
                .decode(body_b64)
                .map_err(|e| HostError::Rpc(format!("invalid bodyB64: {e}")))?;
            handle.record_intent(id, generation, http_method, url, &body);
            Ok(json!({ "ok": true }))
        }
        "Parawing.commitIntent" => {
            let id = cdp_str_field(params, "intentId")?;
            Ok(json!({ "committed": handle.commit_intent(id) }))
        }
        "Parawing.openEgressStream" => {
            let origin = cdp_str_field(params, "siteOrigin")?;
            let kind: StreamKind = serde_json::from_value(
                params
                    .get("kind")
                    .cloned()
                    .unwrap_or_else(|| json!("web-socket")),
            )
            .map_err(|e| HostError::Rpc(e.to_string()))?;
            let mode: EgressMode = serde_json::from_value(
                params
                    .get("mode")
                    .cloned()
                    .unwrap_or_else(|| json!("stable-egress")),
            )
            .map_err(|e| HostError::Rpc(e.to_string()))?;
            Ok(json!({ "streamId": handle.open_egress_stream(origin, kind, mode) }))
        }
        "Parawing.beginRoamStreams" => {
            handle.begin_roam_streams();
            Ok(json!({ "ok": true }))
        }
        "Parawing.pushEgressFrame" => {
            let stream_id = params
                .get("streamId")
                .and_then(Value::as_u64)
                .ok_or_else(|| HostError::Rpc("missing streamId".to_string()))?;
            let data_b64 = cdp_str_field(params, "dataB64")?;
            let data = BASE64_STANDARD
                .decode(data_b64)
                .map_err(|e| HostError::Rpc(format!("invalid dataB64: {e}")))?;
            handle.push_egress_frame(stream_id, data)?;
            Ok(json!({ "ok": true }))
        }
        "Parawing.replugRoamStreams" => {
            Ok(json!({ "repluggedStreamIds": handle.replug_roam_streams() }))
        }
        _ => Err(HostError::Rpc(format!("unsupported CDP method: {method}"))),
    }
}

async fn dispatch_parawing_freeze_cdp(
    handle: &EngineHostHandle,
    target_id: &str,
    method: &str,
    params: &Value,
) -> Result<Value, HostError> {
    let lease_id = cdp_str_field(params, "leaseId")?;
    let lease = handle.get_issued_lease(lease_id)?;
    let now_ms = params
        .get("nowMs")
        .and_then(Value::as_u64)
        .unwrap_or_else(host_now_ms);
    if method == "Parawing.freezeSession" {
        let bundle = handle.freeze_target(target_id, &lease, now_ms).await?;
        return serde_json::to_value(bundle).map_err(|e| HostError::Rpc(e.to_string()));
    }
    let bundle_val = params
        .get("bundle")
        .cloned()
        .ok_or_else(|| HostError::Freeze("missing bundle param".to_string()))?;
    let bundle: SealedCheckpointBundle = serde_json::from_value(bundle_val)
        .map_err(|e| HostError::Freeze(format!("invalid bundle JSON: {e}")))?;
    let outcome = handle
        .thaw_target(target_id, &bundle, &lease, now_ms)
        .await?;
    Ok(serialize_thaw_outcome(&outcome))
}

fn serialize_thaw_outcome(outcome: &ThawOutcome) -> Value {
    match outcome {
        ThawOutcome::Tier2Criu {
            snapshot,
            full_ksc2_frame,
            viewer_metrics,
            csprng_reseed_sha256,
            criu_restore_args,
        } => json!({
            "tier": "tier2-criu",
            "snapshot": snapshot,
            "fullSceneBytes": full_ksc2_frame.len(),
            "viewerMetrics": viewer_metrics,
            "csprngReseedSha256": csprng_reseed_sha256,
            "criuRestoreArgs": criu_restore_args,
        }),
        ThawOutcome::Tier1Fallback {
            reason,
            snapshot,
            full_ksc2_frame,
            viewer_metrics,
            csprng_reseed_sha256,
        } => json!({
            "tier": "tier1-fallback",
            "reason": reason,
            "snapshot": snapshot,
            "fullSceneBytes": full_ksc2_frame.len(),
            "viewerMetrics": viewer_metrics,
            "csprngReseedSha256": csprng_reseed_sha256,
        }),
    }
}

fn dispatch_parawing_readonly_cdp(
    handle: &EngineHostHandle,
    method: &str,
    params: &Value,
) -> Result<Value, HostError> {
    match method {
        "Parawing.getEpochLease" => serde_json::to_value(handle.current_epoch_lease())
            .map_err(|e| HostError::Rpc(e.to_string())),
        "Parawing.resolveAbruptLoss" => {
            let gen = params
                .get("lastCompleteGeneration")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            match handle.resolve_abrupt_loss(gen) {
                AbruptLossDecision::RestoreExactState { generation } => Ok(json!({
                    "decision": "RestoreExactState",
                    "generation": generation,
                })),
                AbruptLossDecision::ForceTier1GetReload {
                    blocked_intent_ids,
                    zero_double_submissions,
                } => Ok(json!({
                    "decision": "ForceTier1GetReload",
                    "blockedIntentIds": blocked_intent_ids,
                    "zeroDoubleSubmissions": zero_double_submissions,
                })),
            }
        }
        "Parawing.getEgressStream" => {
            let stream_id = params
                .get("streamId")
                .and_then(Value::as_u64)
                .ok_or_else(|| HostError::Rpc("missing streamId".to_string()))?;
            let entry = handle
                .get_egress_stream(stream_id)
                .ok_or_else(|| HostError::Roam(format!("unknown egress stream {stream_id}")))?;
            Ok(json!({
                "streamId": entry.stream_id,
                "siteOrigin": entry.site_origin,
                "kind": entry.kind,
                "mode": entry.mode,
                "state": entry.state,
                "bufferedCount": entry.buffered_inbound.len(),
                "deliveredCount": entry.delivered_frames.len(),
                "reconnectCount": entry.reconnect_count,
            }))
        }
        _ => Err(HostError::Rpc(format!("unsupported CDP method: {method}"))),
    }
}

fn push_non_empty_env_dir(dirs: &mut Vec<PathBuf>, var_name: &str) {
    let Ok(raw) = std::env::var(var_name) else {
        return;
    };
    if !raw.trim().is_empty() {
        dirs.push(PathBuf::from(raw));
    }
}

fn scene_host_candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    push_non_empty_env_dir(&mut dirs, "PARAWING_SCENE_HOST_DIR");
    if let Some(parent) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
    {
        dirs.push(parent.join("rbi"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join("rbi"));
        dirs.push(cwd.join("packages/engine/public/rbi"));
    }
    dirs.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../engine/public/rbi"));
    dirs
}

fn find_scene_host_dir() -> Result<PathBuf, HostError> {
    for dir in scene_host_candidate_dirs() {
        if dir.join("scene_host.json").is_file() && dir.join("scene_host.wasm").is_file() {
            return Ok(dir);
        }
    }
    Err(HostError::Http(
        "scene_host.json and scene_host.wasm not found; set PARAWING_SCENE_HOST_DIR".to_string(),
    ))
}

fn dispatch_parawing_get_scene_host_manifest() -> Result<Value, HostError> {
    let dir = find_scene_host_dir()?;
    let raw = std::fs::read(dir.join("scene_host.json"))
        .map_err(|e| HostError::Io(format!("read scene_host.json: {e}")))?;
    serde_json::from_slice(&raw).map_err(|e| HostError::Http(format!("parse scene_host.json: {e}")))
}

fn dispatch_parawing_read_scene_host(params: &Value) -> Result<Value, HostError> {
    let dir = find_scene_host_dir()?;
    let bytes = std::fs::read(dir.join("scene_host.wasm"))
        .map_err(|e| HostError::Io(format!("read scene_host.wasm: {e}")))?;
    let actual_sha = sha256_hex(&bytes);
    let requested = params.get("sha256").and_then(Value::as_str);
    if requested.is_some_and(|req_sha| req_sha != actual_sha) {
        return Err(HostError::Http(format!(
            "scene_host.wasm sha256 mismatch (actual {actual_sha})"
        )));
    }
    let total = bytes.len();
    let offset = params
        .get("offset")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(total as u64) as usize;
    let max_chunk: u64 = 4 * 1024 * 1024;
    let length = params
        .get("length")
        .and_then(Value::as_u64)
        .unwrap_or(max_chunk)
        .min(max_chunk) as usize;
    let end = offset.saturating_add(length).min(total);
    Ok(json!({
        "sha256": actual_sha,
        "offset": offset,
        "totalBytes": total,
        "dataB64": BASE64_STANDARD.encode(&bytes[offset..end]),
    }))
}

async fn dispatch_parawing_cdp_method(
    handle: &EngineHostHandle,
    target_id: &str,
    caller: &(u64, String),
    method: &str,
    params: &Value,
) -> Result<Value, HostError> {
    if matches!(
        method,
        "Parawing.getEpochLease" | "Parawing.resolveAbruptLoss" | "Parawing.getEgressStream"
    ) {
        return dispatch_parawing_readonly_cdp(handle, method, params);
    }
    match method {
        "Parawing.getSceneHostManifest" => return dispatch_parawing_get_scene_host_manifest(),
        "Parawing.readSceneHost" => return dispatch_parawing_read_scene_host(params),
        _ => {}
    }
    handle.authorize_mutation(caller.0, &caller.1)?;
    match method {
        "Parawing.signCapsuleAttestation"
        | "Parawing.issueAttestedKeyLease"
        | "Parawing.releaseDbscCredential" => {
            dispatch_parawing_authority_cdp(handle, method, params)
        }
        "Parawing.freezeSession" | "Parawing.thawSession" => {
            dispatch_parawing_freeze_cdp(handle, target_id, method, params).await
        }
        "Parawing.startSceneStreamV2" => {
            let w = params.get("width").and_then(Value::as_u64).unwrap_or(800) as u32;
            let h = params.get("height").and_then(Value::as_u64).unwrap_or(600) as u32;
            handle.inner.render.set_viewport(target_id, w, h).await?;
            Ok(json!({ "wsPath": format!("/viewer/{target_id}"), "wireVersion": 2 }))
        }
        "Parawing.stopSceneStreamV2" => Ok(json!({})),
        _ => dispatch_parawing_roam_mut_cdp(handle, method, params),
    }
}

async fn dispatch_cdp_method(
    handle: &EngineHostHandle,
    target_id: &str,
    caller: &(u64, String),
    method: &str,
    params: &Value,
) -> Result<Value, HostError> {
    if method.starts_with("Parawing.") {
        return dispatch_parawing_cdp_method(handle, target_id, caller, method, params).await;
    }
    match method {
        "Browser.getVersion" => Ok(json!({
            "protocolVersion": "1.3",
            "product": format!("Parawing-Rust-Host/{}", crate::RELEASE_VERSION),
            "jsVersion": "Deno-V8",
        })),
        "Target.getTargets" => {
            let _ = handle.ensure_target(target_id).await?;
            let info = handle.inner.render.get_info(target_id).await?;
            Ok(
                json!({ "targetInfos": [{ "targetId": info.target_id, "type": "page", "title": info.title, "url": info.url, "attached": false }] }),
            )
        }
        "Target.createTarget" => {
            let tid = params
                .get("targetId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(target_id);
            let _ = handle.ensure_target(tid).await?;
            let url = params.get("url").and_then(Value::as_str).unwrap_or("");
            if !url.is_empty() && url != "about:blank" {
                handle.navigate(tid, url, None).await?;
            }
            Ok(json!({ "targetId": tid }))
        }
        "Target.attachToTarget" => {
            let tid = params
                .get("targetId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(target_id);
            let _ = handle.ensure_target(tid).await?;
            Ok(json!({ "sessionId": format!("session-{tid}") }))
        }
        "Target.getTargetInfo" => {
            let info = handle.inner.render.get_info(target_id).await?;
            Ok(
                json!({ "targetInfo": { "targetId": info.target_id, "type": "page", "title": info.title, "url": info.url, "attached": true } }),
            )
        }
        "DOM.getDocument" => {
            let snap = handle.inner.render.snapshot_html(target_id).await?;
            Ok(
                json!({ "root": { "nodeId": 1, "nodeName": "#document", "documentURL": snap.url, "title": snap.title, "outerHTML": snap.html } }),
            )
        }
        "Page.captureScreenshot" => {
            let png = handle.capture_png(target_id).await?;
            Ok(json!({ "data": BASE64_STANDARD.encode(&png) }))
        }
        "Page.navigate" => {
            handle.authorize_mutation(caller.0, &caller.1)?;
            let url = params
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or("about:blank");
            let html = params.get("html").and_then(Value::as_str);
            let info = handle.navigate(target_id, url, html).await?;
            Ok(
                json!({ "frameId": info.target_id, "loaderId": sha256_hex(url.as_bytes()), "url": info.url }),
            )
        }
        "Page.setDocumentContent" => {
            handle.authorize_mutation(caller.0, &caller.1)?;
            let html = params.get("html").and_then(Value::as_str).unwrap_or("");
            let info = handle
                .navigate(target_id, "about:blank", Some(html))
                .await?;
            Ok(json!({ "title": info.title, "nodeCount": info.node_count }))
        }
        "Runtime.evaluate" => {
            handle.authorize_mutation(caller.0, &caller.1)?;
            let expr = params
                .get("expression")
                .and_then(Value::as_str)
                .unwrap_or("");
            let eval = handle.evaluate_js(target_id, expr).await?;
            Ok(json!({ "result": { "type": "object", "value": eval } }))
        }
        "Emulation.setDeviceMetricsOverride" => {
            handle.authorize_mutation(caller.0, &caller.1)?;
            let w = params.get("width").and_then(Value::as_u64).unwrap_or(800) as u32;
            let h = params.get("height").and_then(Value::as_u64).unwrap_or(600) as u32;
            handle.inner.render.set_viewport(target_id, w, h).await?;
            Ok(json!({}))
        }
        _ => Err(HostError::Rpc(format!("unsupported CDP method: {method}"))),
    }
}

enum ViewerLoopAction {
    Continue,
    Break,
}

async fn handle_viewer_inbound(
    handle: &EngineHostHandle,
    runtime: &Arc<TargetRuntime>,
    caller: &(u64, String),
    ws: &mut tokio_tungstenite::WebSocketStream<PrefixedStream>,
    msg: Message,
) -> Result<ViewerLoopAction, HostError> {
    let Message::Binary(bytes) = msg else {
        let action = if matches!(msg, Message::Close(_)) {
            ViewerLoopAction::Break
        } else {
            ViewerLoopAction::Continue
        };
        return Ok(action);
    };
    match handle_viewer_packet(handle, runtime, caller, &bytes).await {
        Ok(Some(reply_pkt)) => {
            if ws.send(Message::Binary(reply_pkt.into())).await.is_err() {
                return Ok(ViewerLoopAction::Break);
            }
            Ok(ViewerLoopAction::Continue)
        }
        Ok(None) => Ok(ViewerLoopAction::Continue),
        Err(HostError::EpochFenced(reason)) => {
            let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                reason: reason.into(),
            };
            let _ = ws.send(Message::Close(Some(frame))).await;
            Ok(ViewerLoopAction::Break)
        }
        Err(e) => Err(e),
    }
}

async fn serve_viewer_ws(
    handle: EngineHostHandle,
    target_id: String,
    caller: (u64, String),
    stream: PrefixedStream,
) -> Result<(), HostError> {
    let runtime = handle.ensure_target(&target_id).await?;
    let mut rx = runtime.viewer_tx.subscribe();
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| HostError::Io(format!("viewer ws handshake: {e}")))?;

    let initial = handle
        .inner
        .render
        .render_ksc2(
            &target_id,
            runtime.acked_scroll_seq.load(Ordering::SeqCst),
            runtime.acked_input_seq.load(Ordering::SeqCst),
            Vec::new(),
        )
        .await?;
    let seq = runtime.frame_seq.fetch_add(1, Ordering::SeqCst) + 1;
    let init_pkt =
        encode_ksv2_reliable_frame(seq, seq - 1, initial.tile_count, &initial.ksc2_bytes);
    ws.send(Message::Binary(init_pkt.into()))
        .await
        .map_err(|e| HostError::Io(format!("viewer send initial: {e}")))?;

    loop {
        tokio::select! {
            bcast = rx.recv() => {
                let Ok(pkt) = bcast else { continue };
                if ws.send(Message::Binary(pkt.into())).await.is_err() {
                    break;
                }
            }
            inbound = ws.next() => {
                let Some(Ok(msg)) = inbound else { break };
                let action = handle_viewer_inbound(&handle, &runtime, &caller, &mut ws, msg).await?;
                if matches!(action, ViewerLoopAction::Break) {
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn handle_viewer_packet(
    handle: &EngineHostHandle,
    runtime: &Arc<TargetRuntime>,
    caller: &(u64, String),
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, HostError> {
    let pkt = decode_ksv2_client_packet(bytes)?;
    match pkt {
        DecodedKsv2ClientPacket::CreditGrant { .. } => Ok(None),
        DecodedKsv2ClientPacket::DatagramScroll { seq, x, y } => {
            handle.authorize_mutation(caller.0, &caller.1)?;
            runtime.acked_scroll_seq.store(seq, Ordering::SeqCst);
            handle
                .inner
                .render
                .set_scroll(&runtime.id, f64::from(x), f64::from(y))
                .await?;
            let rendered = handle
                .inner
                .render
                .render_ksc2(
                    &runtime.id,
                    seq,
                    runtime.acked_input_seq.load(Ordering::SeqCst),
                    Vec::new(),
                )
                .await?;
            let fseq = runtime.frame_seq.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(Some(encode_ksv2_reliable_frame(
                fseq,
                fseq - 1,
                rendered.tile_count,
                &rendered.ksc2_bytes,
            )))
        }
        DecodedKsv2ClientPacket::ReattachWithTileHashes {
            last_frame_seq,
            known_hashes,
        } => {
            let known_set: HashSet<u64> = known_hashes.iter().copied().collect();
            let baseline = handle
                .inner
                .render
                .render_ksc2(
                    &runtime.id,
                    runtime.acked_scroll_seq.load(Ordering::SeqCst),
                    runtime.acked_input_seq.load(Ordering::SeqCst),
                    Vec::new(),
                )
                .await?;
            let pruned = baseline
                .payload_hashes
                .iter()
                .filter(|h| known_set.contains(h))
                .count() as u32;
            let delta = handle
                .inner
                .render
                .render_ksc2(
                    &runtime.id,
                    runtime.acked_scroll_seq.load(Ordering::SeqCst),
                    runtime.acked_input_seq.load(Ordering::SeqCst),
                    known_hashes,
                )
                .await?;
            Ok(Some(encode_ksv2_delta_resync_ack(
                last_frame_seq,
                pruned,
                &delta.ksc2_bytes,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::freeze_thaw::ThawOutcome;
    use tokio_tungstenite::connect_async;

    #[tokio::test]
    async fn engine_host_cdp_deno_v8_native_png_and_viewer_v2_roundtrip() {
        let host = start_engine_host(EngineHostConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            capsule_manifest: CapsuleManifest::new(
                CpuBaseline::host_default(),
                "parawing-test:1",
                "deno-v8:1",
                false,
            ),
            ..EngineHostConfig::default()
        })
        .await
        .expect("start host");

        let client = reqwest::Client::new();
        let health = client
            .get(format!("{}/health", host.origin_http()))
            .send()
            .await
            .expect("GET /health")
            .text()
            .await
            .expect("health text");
        assert!(health.contains("OK"));

        let version: Value = client
            .get(format!("{}/json/version", host.origin_http()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(version["webSocketDebuggerUrl"]
            .as_str()
            .unwrap()
            .contains("/devtools/browser"));

        let cdp_url = format!("ws://{}/devtools/page/parawing", host.addr());
        let (mut cdp_ws, _) = connect_async(&cdp_url).await.expect("connect CDP WS");

        let html = r#"<!DOCTYPE html><html><head><title>Rust Host Live</title></head>
            <body style="margin:0;background:#ffffff">
              <div id="banner" style="width:120px;height:60px;background:#0066ff"></div>
              <p id="status">initial-text</p>
            </body></html>"#;
        let nav_req = json!({
            "id": 1,
            "method": "Page.navigate",
            "params": { "url": "https://example.test/app", "html": html }
        });
        cdp_ws
            .send(Message::Text(nav_req.to_string().into()))
            .await
            .unwrap();
        let nav_reply: Value = match cdp_ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("unexpected msg: {other:?}"),
        };
        assert_eq!(nav_reply["result"]["url"], "https://example.test/app");

        let eval_req = json!({
            "id": 2,
            "method": "Runtime.evaluate",
            "params": { "expression": "document.getElementById('status').textContent = 'updated-by-deno'; __state.visited = 7; 6 * 7" }
        });
        cdp_ws
            .send(Message::Text(eval_req.to_string().into()))
            .await
            .unwrap();
        let eval_reply: Value = match cdp_ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("unexpected eval reply: {other:?}"),
        };
        assert_eq!(eval_reply["result"]["result"]["value"]["value"], 42);
        assert_eq!(eval_reply["result"]["result"]["value"]["appliedOps"], 1);

        let png = client
            .get(format!("{}/screenshot/parawing.png", host.origin_http()))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));

        let dom_req = json!({ "id": 3, "method": "DOM.getDocument", "params": {} });
        cdp_ws
            .send(Message::Text(dom_req.to_string().into()))
            .await
            .unwrap();
        let dom_reply: Value = match cdp_ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("unexpected dom reply: {other:?}"),
        };
        let outer = dom_reply["result"]["root"]["outerHTML"].as_str().unwrap();
        assert!(outer.contains("updated-by-deno"));

        let viewer_url = format!("ws://{}/viewer/parawing", host.addr());
        let (mut viewer_ws, _) = connect_async(&viewer_url).await.expect("connect Viewer v2");
        let init_bin = match viewer_ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            other => panic!("expected KSV2 binary frame: {other:?}"),
        };
        assert_eq!(&init_bin[0..4], &KSV2_WIRE_MAGIC);
        assert_eq!(init_bin[4], KIND_RELIABLE_FRAME);
        let ksc2_payload = &init_bin[21..];
        let (_, hashes, _) = ksc2_tile_metadata(ksc2_payload).expect("valid KSC2");
        assert!(!hashes.is_empty());

        let reattach = encode_ksv2_reattach_with_hashes(1, &hashes);
        viewer_ws
            .send(Message::Binary(reattach.into()))
            .await
            .unwrap();
        let ack_bin = match viewer_ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            other => panic!("expected DeltaResyncAck: {other:?}"),
        };
        assert_eq!(ack_bin[4], KIND_DELTA_RESYNC_ACK);
        let pruned = u32::from_le_bytes(ack_bin[9..13].try_into().unwrap());
        assert_eq!(pruned as usize, hashes.len());

        let lease = KeyLease {
            lease_id: "host-lease-1".to_string(),
            session_id: "s1".to_string(),
            epoch: 1,
            issued_at_ms: 1_000,
            expires_at_ms: 60_000,
            revoked: false,
            aes256_key: [0x42u8; 32],
        };
        let bundle = host
            .freeze_target("parawing", &lease, 5_000)
            .await
            .expect("freeze live host target");
        let roam_lease = host.transfer_roam_ownership("cloud-b");
        assert_eq!(roam_lease.epoch, 2);

        let thaw = host
            .thaw_target("parawing", &bundle, &lease, 8_000)
            .await
            .expect("thaw live host target");
        let (restored, ksc2_after, _is_tier2) = match thaw {
            ThawOutcome::Tier2Criu {
                snapshot,
                full_ksc2_frame,
                ..
            } => (snapshot, full_ksc2_frame, true),
            ThawOutcome::Tier1Fallback {
                reason,
                snapshot,
                full_ksc2_frame,
                ..
            } => {
                if std::env::var("PARAWING_REQUIRE_LINUX_CRIU").as_deref() == Ok("1") {
                    panic!("PARAWING_REQUIRE_LINUX_CRIU=1 but got Tier1Fallback: {reason}");
                }
                assert!(!reason.is_empty());
                (snapshot, full_ksc2_frame, false)
            }
        };
        assert!(restored.html.contains("updated-by-deno"));
        let js_val: Value = serde_json::from_str(&restored.js_state_json).unwrap();
        assert_eq!(js_val["state"]["visited"], 7);
        assert_eq!(&ksc2_after[0..4], b"KSC2");

        let _ = cdp_ws.close(None).await;
        let _ = viewer_ws.close(None).await;
        host.shutdown().await;
    }

    async fn send_cdp_rpc(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        id: u64,
        method: &str,
        params: Value,
    ) -> Value {
        let req = json!({ "id": id, "method": method, "params": params });
        ws.send(Message::Text(req.to_string().into()))
            .await
            .unwrap();
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("unexpected CDP message: {other:?}"),
        }
    }

    fn random_p256_spki_b64() -> String {
        use p256::pkcs8::EncodePublicKey as _;
        let mut raw = [0u8; 32];
        loop {
            getrandom::fill(&mut raw).expect("entropy");
            if let Ok(sk) = p256::SecretKey::from_slice(&raw) {
                let spki = sk.public_key().to_public_key_der().expect("spki");
                return BASE64_STANDARD.encode(spki.as_bytes());
            }
        }
    }

    #[tokio::test]
    async fn engine_host_live_a5_freeze_roam_fencing_and_egress() {
        let host = start_engine_host(EngineHostConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            capsule_manifest: CapsuleManifest::new(
                CpuBaseline::host_default(),
                "parawing-live-wire:1",
                "deno-v8:1",
                false,
            ),
            ..EngineHostConfig::default()
        })
        .await
        .expect("start host");

        let client = reqwest::Client::new();
        let manifest_resp: Value = client
            .get(format!("{}/capsule/manifest", host.origin_http()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let flags: Vec<String> = manifest_resp["manifest"]["v8Flags"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        assert!(flags
            .iter()
            .any(|f| f == "--disallow-code-generation-from-strings"));

        let (mut cdp_ws, _) =
            connect_async(&format!("ws://{}/devtools/page/parawing", host.addr()))
                .await
                .unwrap();
        let _ = send_cdp_rpc(
            &mut cdp_ws,
            1,
            "Page.navigate",
            json!({ "url": "https://roam.example/", "html": "<p id='p'>live</p>" }),
        )
        .await;
        let v8_block = send_cdp_rpc(
            &mut cdp_ws,
            2,
            "Runtime.evaluate",
            json!({
                "expression": "(() => { __state.visited = 19; const r = Math.random(); try { new Function('return 1')(); return { r, status: 'allowed' }; } catch (e) { return { r, status: 'blocked:' + e.name }; } })()"
            }),
        )
        .await;
        assert_eq!(
            v8_block["result"]["result"]["value"]["value"]["status"],
            "blocked:EvalError"
        );
        let r0 = v8_block["result"]["result"]["value"]["value"]["r"]
            .as_f64()
            .unwrap();

        let eph_b64 = random_p256_spki_b64();
        let now_ms = host_now_ms();
        let sign_cdp = send_cdp_rpc(
            &mut cdp_ws,
            3,
            "Parawing.signCapsuleAttestation",
            json!({
                "ephemeralP256PubkeySpkiB64": eph_b64,
                "nonce": "nonce-cdp-1",
                "issuedAtMs": now_ms,
                "expiresAtMs": now_ms + 60_000,
            }),
        )
        .await;
        let att_valid = sign_cdp["result"].clone();
        let mut att_tampered = att_valid.clone();
        att_tampered["claims"]["nonce"] = json!("tampered-nonce");

        let bad_http = client
            .post(format!(
                "{}/authority/issue-attested-lease",
                host.origin_http()
            ))
            .json(&json!({
                "attestation": att_tampered,
                "leaseId": "bad-lease",
                "sessionId": "s-live",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(bad_http.status().as_u16(), 403);

        let bad_cdp = send_cdp_rpc(
            &mut cdp_ws,
            4,
            "Parawing.issueAttestedKeyLease",
            json!({ "attestation": att_tampered, "leaseId": "bad-2", "sessionId": "s-live" }),
        )
        .await;
        assert!(bad_cdp["error"].is_object());

        let lease_cdp = send_cdp_rpc(
            &mut cdp_ws,
            5,
            "Parawing.issueAttestedKeyLease",
            json!({ "attestation": att_valid, "leaseId": "lease-live-1", "sessionId": "s-live", "nowMs": now_ms + 1 }),
        )
        .await;
        assert_eq!(lease_cdp["result"]["leaseId"], "lease-live-1");

        let sign_http = send_cdp_rpc(
            &mut cdp_ws,
            6,
            "Parawing.signCapsuleAttestation",
            json!({
                "ephemeralP256PubkeySpkiB64": random_p256_spki_b64(),
                "nonce": "nonce-dbsc-2",
                "issuedAtMs": now_ms,
                "expiresAtMs": now_ms + 60_000,
            }),
        )
        .await;
        let dbsc_http = client
            .post(format!("{}/authority/dbsc-credential", host.origin_http()))
            .json(&json!({
                "attestation": sign_http["result"],
                "dbscSessionId": "dbsc-live-1",
                "origin": "https://roam.example",
                "challenge": "chal-live",
                "nowMs": now_ms + 2,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(dbsc_http.status().as_u16(), 200);
        let dbsc_cred: crate::attestation::DbscSessionCredential = dbsc_http.json().await.unwrap();
        assert_eq!(dbsc_cred.origin, "https://roam.example");
        assert_eq!(dbsc_cred.challenge, "chal-live");
        assert_eq!(dbsc_cred.dbsc_session_id, "dbsc-live-1");
        crate::attestation::verify_dbsc_jwt_proof(&dbsc_cred)
            .expect("verified DBSC JWT proof from live HTTP endpoint");

        let frozen = send_cdp_rpc(
            &mut cdp_ws,
            7,
            "Parawing.freezeSession",
            json!({ "leaseId": "lease-live-1", "nowMs": now_ms + 100 }),
        )
        .await;
        let bundle = frozen["result"].clone();
        if bundle["criuImages"].is_object() {
            assert!(!bundle["criuImages"]["imagesDir"]
                .as_str()
                .unwrap()
                .is_empty());
            let labels = bundle["criuImages"]["inheritFdLabels"].as_array().unwrap();
            assert!(labels.iter().any(|l| l == "fd[0]:prwp_stdin"));
        } else {
            let err_str = bundle["criuDumpError"].as_str().unwrap_or_default();
            if std::env::var("PARAWING_REQUIRE_LINUX_CRIU").as_deref() == Ok("1") {
                panic!("PARAWING_REQUIRE_LINUX_CRIU=1 but criuImages missing: {err_str}");
            }
            assert!(!err_str.is_empty());
        }

        let thawed = send_cdp_rpc(
            &mut cdp_ws,
            8,
            "Parawing.thawSession",
            json!({ "bundle": bundle, "leaseId": "lease-live-1", "nowMs": now_ms + 500 }),
        )
        .await;
        if bundle["criuImages"].is_object() {
            assert_eq!(thawed["result"]["tier"], "tier2-criu");
        } else {
            assert_eq!(thawed["result"]["tier"], "tier1-fallback");
        }
        assert_eq!(thawed["result"]["viewerMetrics"]["streamsReplugged"], true);
        assert_eq!(
            thawed["result"]["csprngReseedSha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        let after_eval = send_cdp_rpc(
            &mut cdp_ws,
            9,
            "Runtime.evaluate",
            json!({ "expression": "({ visited: __state.visited, r1: Math.random() })" }),
        )
        .await;
        assert_eq!(
            after_eval["result"]["result"]["value"]["value"]["visited"],
            19
        );
        let r1 = after_eval["result"]["result"]["value"]["value"]["r1"]
            .as_f64()
            .unwrap();
        assert_ne!(r0, r1);

        let transfer = send_cdp_rpc(
            &mut cdp_ws,
            10,
            "Parawing.transferOwnership",
            json!({ "newOwner": "cloud-b" }),
        )
        .await;
        assert_eq!(transfer["result"]["epoch"], 2);

        let fenced_mut = send_cdp_rpc(
            &mut cdp_ws,
            11,
            "Runtime.evaluate",
            json!({ "expression": "1 + 1" }),
        )
        .await;
        let err_msg = fenced_mut["error"]["message"].as_str().unwrap();
        assert!(err_msg.contains("stale epoch") && err_msg.contains("downgraded to viewer"));

        let viewer_read = send_cdp_rpc(&mut cdp_ws, 12, "DOM.getDocument", json!({})).await;
        assert!(viewer_read["result"]["root"]["outerHTML"]
            .as_str()
            .unwrap()
            .contains("live"));

        let stale_viewer_url = format!(
            "ws://{}/viewer/parawing?epoch=1&nodeId=rust-host-primary",
            host.addr()
        );
        let (mut stale_vws, _) = connect_async(&stale_viewer_url).await.unwrap();
        let _ = stale_vws.next().await.unwrap().unwrap();
        stale_vws
            .send(Message::Binary(
                encode_ksv2_reattach_with_hashes(1, &[]).into(),
            ))
            .await
            .unwrap();
        let ack = match stale_vws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            other => panic!("expected DeltaResyncAck for downgraded viewer: {other:?}"),
        };
        assert_eq!(ack[4], KIND_DELTA_RESYNC_ACK);

        let mut scroll_pkt = vec![0u8; 33];
        scroll_pkt[0..4].copy_from_slice(&KSV2_WIRE_MAGIC);
        scroll_pkt[4] = KIND_DATAGRAM_SCROLL;
        scroll_pkt[5..9].copy_from_slice(&1u32.to_le_bytes());
        scroll_pkt[21..25].copy_from_slice(&40f32.to_le_bytes());
        stale_vws
            .send(Message::Binary(scroll_pkt.into()))
            .await
            .unwrap();
        match stale_vws.next().await.unwrap().unwrap() {
            Message::Close(Some(frame)) => assert!(frame.reason.contains("stale epoch")),
            other => panic!("expected Close frame on fenced viewer scroll: {other:?}"),
        }

        let new_cdp_url = format!(
            "ws://{}/devtools/page/parawing?epoch=2&nodeId=cloud-b",
            host.addr()
        );
        let (mut cdp_new, _) = connect_async(&new_cdp_url).await.unwrap();
        let stage_http = client
            .post(format!("{}/roam/precopy/stage", host.origin_http()))
            .json(&json!({
                "leaseId": "lease-live-1",
                "pages": [{ "pageIndex": 7, "dataB64": BASE64_STANDARD.encode(b"dirty-page-bytes") }],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(stage_http.status().as_u16(), 200);
        let batch: Value = stage_http.json().await.unwrap();
        let apply_http = client
            .post(format!("{}/roam/precopy/apply", host.origin_http()))
            .json(&json!({
                "leaseId": "lease-live-1",
                "sessionId": "s-live",
                "batch": batch,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(apply_http.status().as_u16(), 200);
        let apply_json: Value = apply_http.json().await.unwrap();
        assert_eq!(apply_json["appliedChunks"], 1);
        assert_eq!(
            host.replica_page(7).as_deref(),
            Some(b"dirty-page-bytes".as_slice())
        );

        let _ = send_cdp_rpc(
            &mut cdp_new,
            20,
            "Parawing.recordIntent",
            json!({
                "intentId": "post-uncommitted",
                "generation": 2,
                "method": "POST",
                "url": "https://roam.example/pay",
                "bodyB64": BASE64_STANDARD.encode(b"amount=50"),
            }),
        )
        .await;
        let loss = send_cdp_rpc(
            &mut cdp_new,
            21,
            "Parawing.resolveAbruptLoss",
            json!({ "lastCompleteGeneration": 1 }),
        )
        .await;
        assert_eq!(loss["result"]["decision"], "ForceTier1GetReload");
        assert_eq!(loss["result"]["zeroDoubleSubmissions"], true);

        let stable_id = send_cdp_rpc(
            &mut cdp_new,
            22,
            "Parawing.openEgressStream",
            json!({ "siteOrigin": "https://roam.example", "kind": "web-socket", "mode": "stable-egress" }),
        )
        .await["result"]["streamId"]
            .as_u64()
            .unwrap();
        let home_id = send_cdp_rpc(
            &mut cdp_new,
            23,
            "Parawing.openEgressStream",
            json!({ "siteOrigin": "https://roam.example", "kind": "http", "mode": "home-egress" }),
        )
        .await["result"]["streamId"]
            .as_u64()
            .unwrap();
        let _ = send_cdp_rpc(&mut cdp_new, 24, "Parawing.beginRoamStreams", json!({})).await;
        let _ = send_cdp_rpc(
            &mut cdp_new,
            25,
            "Parawing.pushEgressFrame",
            json!({ "streamId": stable_id, "dataB64": BASE64_STANDARD.encode(b"ws-frame-1") }),
        )
        .await;
        let _ = send_cdp_rpc(&mut cdp_new, 26, "Parawing.replugRoamStreams", json!({})).await;
        let stable_info = send_cdp_rpc(
            &mut cdp_new,
            27,
            "Parawing.getEgressStream",
            json!({ "streamId": stable_id }),
        )
        .await;
        assert_eq!(stable_info["result"]["state"], "open");
        assert_eq!(stable_info["result"]["deliveredCount"], 1);
        assert_eq!(stable_info["result"]["reconnectCount"], 0);
        let home_info = send_cdp_rpc(
            &mut cdp_new,
            28,
            "Parawing.getEgressStream",
            json!({ "streamId": home_id }),
        )
        .await;
        assert_eq!(home_info["result"]["state"], "closed-reset");

        let _ = cdp_ws.close(None).await;
        let _ = cdp_new.close(None).await;
        host.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn engine_host_capsule_cdp_tier2_criu_freeze_and_cross_host_thaw() {
        let probe = tokio::task::spawn_blocking(MacosLinuxCapsuleDriver::probe)
            .await
            .expect("probe task");
        if std::env::var("PARAWING_REQUIRE_CAPSULE_CRIU").as_deref() == Ok("1") {
            assert!(probe.available, "capsule CRIU required: {}", probe.reason);
        }
        if !probe.available {
            eprintln!("skipping host capsule CRIU test: {}", probe.reason);
            return;
        }

        let manifest = CapsuleManifest::new(
            CpuBaseline::host_default(),
            "parawing-rust-host:0.1.0",
            "deno-v8:1",
            true,
        );
        let host_a = start_engine_host(EngineHostConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            capsule_manifest: manifest.clone(),
            enable_linux_capsule: true,
            trusted_signer_pubkeys: Vec::new(),
        })
        .await
        .expect("start host_a");
        let host_a_pubkey = host_a.signer_public_key_bytes();

        let (mut cdp_a, _) =
            connect_async(format!("ws://{}/devtools/page/parawing", host_a.addr()))
                .await
                .expect("connect host_a cdp");
        let _ = send_cdp_rpc(
            &mut cdp_a,
            1,
            "Page.navigate",
            json!({
                "url": "data:text/html,<!DOCTYPE html><html><body>capsule-roam</body></html>"
            }),
        )
        .await;
        let _ = send_cdp_rpc(
            &mut cdp_a,
            2,
            "Runtime.evaluate",
            json!({ "expression": "globalThis.__state = { visited: 42 }; globalThis.__state.visited" }),
        )
        .await;

        host_a
            .ensure_target_capsule_worker("parawing")
            .await
            .expect("ensure host_a capsule worker");
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).expect("secret nonce");
        let expected_secret = format!("host-capsule-secret-{}", crate::capsule::hex_encode(&nonce));
        host_a
            .set_target_capsule_secret("parawing", &expected_secret)
            .await
            .expect("inject V8 heap secret on host_a");

        let now_ms = host_now_ms();
        let att_resp = send_cdp_rpc(
            &mut cdp_a,
            3,
            "Parawing.signCapsuleAttestation",
            json!({
                "ephemeralP256PubkeySpkiB64": random_p256_spki_b64(),
                "nonce": "cap-roam-nonce-1",
                "issuedAtMs": now_ms.saturating_sub(1_000),
                "expiresAtMs": now_ms + 60_000,
            }),
        )
        .await;
        let _ = send_cdp_rpc(
            &mut cdp_a,
            4,
            "Parawing.issueAttestedKeyLease",
            json!({
                "attestation": att_resp["result"],
                "leaseId": "lease-cap-1",
                "sessionId": "s-cap-roam",
                "ttlMs": 120_000,
                "nowMs": now_ms,
            }),
        )
        .await;
        let lease = host_a
            .get_issued_lease("lease-cap-1")
            .expect("retrieve host_a lease");

        let frozen = send_cdp_rpc(
            &mut cdp_a,
            5,
            "Parawing.freezeSession",
            json!({ "leaseId": "lease-cap-1", "nowMs": now_ms + 100 }),
        )
        .await;
        let bundle = frozen["result"].clone();
        assert_eq!(bundle["criuImages"]["backend"], "macos-linux-capsule");
        assert!(bundle["criuDumpError"].is_null());

        let _ = cdp_a.close(None).await;
        host_a.shutdown().await;

        let host_b = start_engine_host(EngineHostConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            capsule_manifest: manifest,
            enable_linux_capsule: true,
            trusted_signer_pubkeys: vec![host_a_pubkey],
        })
        .await
        .expect("start host_b");
        host_b.register_issued_lease(lease);

        let (mut cdp_b, _) =
            connect_async(format!("ws://{}/devtools/page/parawing", host_b.addr()))
                .await
                .expect("connect host_b cdp");
        let thawed = send_cdp_rpc(
            &mut cdp_b,
            6,
            "Parawing.thawSession",
            json!({ "bundle": bundle, "leaseId": "lease-cap-1", "nowMs": now_ms + 500 }),
        )
        .await;
        assert_eq!(thawed["result"]["tier"], "tier2-criu");
        let reseed_sha = thawed["result"]["csprngReseedSha256"]
            .as_str()
            .expect("reseed sha");
        assert_eq!(reseed_sha.len(), 64);

        let inspect = host_b
            .inspect_target_capsule("parawing", Duration::from_secs(10))
            .await
            .expect("inspect host_b capsule")
            .expect("restored capsule worker present");
        assert_eq!(
            inspect.dynamic_secret.as_deref(),
            Some(expected_secret.as_str())
        );
        assert_eq!(inspect.reseed_sha256.as_deref(), Some(reseed_sha));

        let eval_b = send_cdp_rpc(
            &mut cdp_b,
            7,
            "Runtime.evaluate",
            json!({ "expression": "globalThis.__state.visited" }),
        )
        .await;
        assert_eq!(eval_b["result"]["result"]["value"]["value"], 42);

        let _ = cdp_b.close(None).await;
        host_b.shutdown().await;
    }

    #[tokio::test]
    async fn browser_targets_session_routing_and_scene_host_cdp_roundtrip() {
        let host = start_engine_host(EngineHostConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            capsule_manifest: CapsuleManifest::new(
                CpuBaseline::host_default(),
                "parawing-test:v2-cdp",
                "deno-v8:1",
                false,
            ),
            ..EngineHostConfig::default()
        })
        .await
        .expect("start host");

        let ws_url = format!("ws://{}/devtools/browser", host.addr());
        let (mut cdp, _) = connect_async(&ws_url).await.expect("connect browser cdp");

        let ver = send_cdp_rpc(&mut cdp, 1, "Browser.getVersion", json!({})).await;
        assert!(ver["result"]["product"]
            .as_str()
            .unwrap_or("")
            .contains(crate::RELEASE_VERSION));

        let targets = send_cdp_rpc(&mut cdp, 2, "Target.getTargets", json!({})).await;
        assert_eq!(targets["result"]["targetInfos"][0]["targetId"], "parawing");

        let attach = send_cdp_rpc(
            &mut cdp,
            3,
            "Target.attachToTarget",
            json!({ "targetId": "parawing", "flatten": true }),
        )
        .await;
        let sid = attach["result"]["sessionId"]
            .as_str()
            .expect("sessionId")
            .to_string();
        assert_eq!(sid, "session-parawing");

        let manifest = send_cdp_rpc(&mut cdp, 4, "Parawing.getSceneHostManifest", json!({})).await;
        let expected_sha = manifest["result"]["sha256"]
            .as_str()
            .expect("scene_host sha256")
            .to_string();
        let expected_bytes = manifest["result"]["bytes"].as_u64().expect("bytes") as usize;
        assert!(expected_bytes > 0);

        let chunk = send_cdp_rpc(
            &mut cdp,
            5,
            "Parawing.readSceneHost",
            json!({ "sha256": expected_sha, "offset": 0, "length": 16 }),
        )
        .await;
        assert_eq!(chunk["result"]["totalBytes"], expected_bytes);
        let decoded = BASE64_STANDARD
            .decode(chunk["result"]["dataB64"].as_str().expect("dataB64"))
            .expect("decode chunk");
        assert_eq!(&decoded[..4], b"\0asm");

        let req = json!({
            "id": 6,
            "sessionId": sid,
            "method": "Parawing.startSceneStreamV2",
            "params": { "width": 800, "height": 600, "fps": 60 },
        });
        cdp.send(Message::Text(req.to_string().into()))
            .await
            .expect("send startSceneStreamV2");
        let msg = tokio::time::timeout(Duration::from_secs(5), cdp.next())
            .await
            .expect("reply timeout")
            .expect("reply item")
            .expect("reply msg");
        let reply: Value = serde_json::from_str(&msg.into_text().expect("text")).expect("json");
        assert_eq!(reply["id"], 6);
        assert_eq!(reply["sessionId"], "session-parawing");
        assert_eq!(reply["result"]["wsPath"], "/viewer/parawing");

        let _ = cdp.close(None).await;
        host.shutdown().await;
    }
}
