// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Framed PRWP (0x50525750) RPC over child stdio/Unix pipes with freeze and replug.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, watch, Notify};
use tokio::time::{timeout, Duration};

pub const PRWP_MAGIC: u32 = 0x5052_5750;
pub const PRWP_VERSION: u8 = 1;
pub const PRWP_HEADER_BYTES: usize = 16;
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_WINDOW_BYTES: u32 = 256 * 1024;
pub const DEFAULT_CHUNK_BYTES: usize = 16 * 1024;

pub const FLAG_NONE: u16 = 0;
pub const FLAG_FIN: u16 = 1 << 0;
pub const FLAG_HAS_BINARY: u16 = 1 << 1;
pub const FLAG_PHASE_CALL: u16 = 1 << 2;
pub const FLAG_PHASE_REPLY: u16 = 1 << 3;
pub const FLAG_PHASE_CALLBACK: u16 = 1 << 4;

pub type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Handshake = 1,
    Call = 2,
    Reply = 3,
    Callback = 4,
    Cancel = 5,
    Dispose = 6,
    BinaryChunk = 7,
    Credit = 8,
    Error = 9,
    PrepareFreeze = 10,
    FreezeReady = 11,
}

impl FrameType {
    pub fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Handshake),
            2 => Some(Self::Call),
            3 => Some(Self::Reply),
            4 => Some(Self::Callback),
            5 => Some(Self::Cancel),
            6 => Some(Self::Dispose),
            7 => Some(Self::BinaryChunk),
            8 => Some(Self::Credit),
            9 => Some(Self::Error),
            10 => Some(Self::PrepareFreeze),
            11 => Some(Self::FreezeReady),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub magic: u32,
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: u16,
    pub request_id: u32,
    pub payload_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrwpFrame {
    pub frame_type: FrameType,
    pub flags: u16,
    pub request_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcPipeError {
    Frame(String),
    Io(String),
    Timeout(String),
    Closed(String),
    Remote { name: String, message: String },
    Spawn(String),
}

impl fmt::Display for RpcPipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(m) => write!(f, "PRWP frame error: {m}"),
            Self::Io(m) => write!(f, "PRWP pipe I/O error: {m}"),
            Self::Timeout(m) => write!(f, "PRWP timeout: {m}"),
            Self::Closed(m) => write!(f, "PRWP closed: {m}"),
            Self::Remote { name, message } => write!(f, "{name}: {message}"),
            Self::Spawn(m) => write!(f, "Deno worker spawn error: {m}"),
        }
    }
}

impl std::error::Error for RpcPipeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Idle,
    Handshaking,
    Open,
    Freezing,
    Frozen,
    Unplugged,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcPipeStats {
    pub state: TransportState,
    pub next_outbound_seq: u64,
    pub last_recv_seq: u64,
    pub replay_ring_len: usize,
    pub send_credits: u32,
    pub credits_sent: u64,
    pub credits_received: u64,
    pub binary_chunks_sent: u64,
    pub binary_chunks_received: u64,
    pub unplug_count: u64,
    pub replug_count: u64,
}

#[derive(Debug, Clone)]
pub struct RpcCallResult {
    pub value: Value,
    pub binaries: Vec<Vec<u8>>,
}

pub type CallbackFuture = Pin<Box<dyn Future<Output = Result<RpcCallResult, String>> + Send>>;
pub type CallbackHandler =
    Arc<dyn Fn(u32, Option<String>, Vec<Value>, Vec<Vec<u8>>) -> CallbackFuture + Send + Sync>;

pub fn encode_frame(frame: &PrwpFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(PRWP_HEADER_BYTES + frame.payload.len());
    out.extend_from_slice(&PRWP_MAGIC.to_le_bytes());
    out.push(PRWP_VERSION);
    out.push(frame.frame_type as u8);
    out.extend_from_slice(&frame.flags.to_le_bytes());
    out.extend_from_slice(&frame.request_id.to_le_bytes());
    out.extend_from_slice(&(frame.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&frame.payload);
    out
}

pub fn decode_header(bytes: &[u8]) -> Result<FrameHeader, RpcPipeError> {
    if bytes.len() < PRWP_HEADER_BYTES {
        return Err(RpcPipeError::Frame("PRWP header truncated".to_string()));
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap_or([0; 4]));
    if magic != PRWP_MAGIC {
        return Err(RpcPipeError::Frame(format!(
            "Invalid PRWP magic: 0x{magic:08x}"
        )));
    }
    let version = bytes[4];
    if version != PRWP_VERSION {
        return Err(RpcPipeError::Frame(format!(
            "Unsupported PRWP version: {version}"
        )));
    }
    let frame_type = FrameType::from_u8(bytes[5])
        .ok_or_else(|| RpcPipeError::Frame(format!("Unknown PRWP frame type: {}", bytes[5])))?;
    let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
    let request_id = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
    let payload_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap_or([0; 4]));
    Ok(FrameHeader {
        magic,
        version,
        frame_type,
        flags,
        request_id,
        payload_len,
    })
}

pub struct FrameDecoder {
    max_payload_bytes: usize,
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new(max_payload_bytes: usize) -> Self {
        Self {
            max_payload_bytes,
            buf: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<PrwpFrame>, RpcPipeError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while self.buf.len() >= PRWP_HEADER_BYTES {
            let hdr = decode_header(&self.buf)?;
            let len = hdr.payload_len as usize;
            if len > self.max_payload_bytes {
                return Err(RpcPipeError::Frame(format!(
                    "Payload length {len} exceeds max {}",
                    self.max_payload_bytes
                )));
            }
            let total = PRWP_HEADER_BYTES + len;
            if self.buf.len() < total {
                break;
            }
            let payload = self.buf[PRWP_HEADER_BYTES..total].to_vec();
            self.buf.drain(..total);
            out.push(PrwpFrame {
                frame_type: hdr.frame_type,
                flags: hdr.flags,
                request_id: hdr.request_id,
                payload,
            });
        }
        Ok(out)
    }
}

pub fn build_binary_chunk_payload(
    blob_index: u32,
    byte_offset: u32,
    total_len: u32,
    slice: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + slice.len());
    out.extend_from_slice(&blob_index.to_le_bytes());
    out.extend_from_slice(&byte_offset.to_le_bytes());
    out.extend_from_slice(&total_len.to_le_bytes());
    out.extend_from_slice(slice);
    out
}

fn phase_flag_of(frame_type: FrameType) -> u16 {
    match frame_type {
        FrameType::Call => FLAG_PHASE_CALL,
        FrameType::Callback => FLAG_PHASE_CALLBACK,
        FrameType::Reply | FrameType::Error => FLAG_PHASE_REPLY,
        _ => FLAG_NONE,
    }
}

fn phase_key_of(flags: u16, request_id: u32) -> String {
    if (flags & FLAG_PHASE_CALLBACK) != 0 {
        format!("cb:{request_id}")
    } else if (flags & FLAG_PHASE_REPLY) != 0 {
        format!("r:{request_id}")
    } else {
        format!("c:{request_id}")
    }
}

struct ReplayEntry {
    seq: u64,
    bytes: Vec<u8>,
    credit_cost: u32,
}

struct PendingBinary {
    blobs: HashMap<u32, Vec<u8>>,
}

struct PendingCall {
    tx: oneshot::Sender<Result<RpcCallResult, RpcPipeError>>,
}

struct SessionInner {
    state: TransportState,
    stream_gen: u64,
    handshake_done: bool,
    local_window_bytes: u32,
    peer_window_bytes: u32,
    send_credits: u32,
    next_outbound_seq: u64,
    last_recv_seq: u64,
    last_acked_seq_sent: u64,
    uncredited_bytes: u32,
    next_req_id: u32,
    credits_sent: u64,
    credits_received: u64,
    binary_chunks_sent: u64,
    binary_chunks_received: u64,
    unplug_count: u64,
    replug_count: u64,
    pending_control: VecDeque<Vec<u8>>,
    send_queue: VecDeque<ReplayEntry>,
    replay_ring: VecDeque<ReplayEntry>,
    pending_calls: HashMap<u32, PendingCall>,
    pending_binaries: HashMap<String, PendingBinary>,
    freeze_waiters: Vec<oneshot::Sender<Result<u64, RpcPipeError>>>,
    handshake_waiters: Vec<oneshot::Sender<Result<(), RpcPipeError>>>,
    disposed_caps: Vec<u32>,
    callback_handler: Option<CallbackHandler>,
    last_error: Option<String>,
    reader_park_rx: Option<oneshot::Receiver<BoxedRead>>,
    writer_park_rx: Option<oneshot::Receiver<BoxedWrite>>,
    parked_reader: Option<BoxedRead>,
    parked_writer: Option<BoxedWrite>,
}

impl SessionInner {
    fn new(window_bytes: u32) -> Self {
        let win = window_bytes.max(1);
        Self {
            state: TransportState::Idle,
            stream_gen: 0,
            handshake_done: false,
            local_window_bytes: win,
            peer_window_bytes: win,
            send_credits: win,
            next_outbound_seq: 1,
            last_recv_seq: 0,
            last_acked_seq_sent: 0,
            uncredited_bytes: 0,
            next_req_id: 1,
            credits_sent: 0,
            credits_received: 0,
            binary_chunks_sent: 0,
            binary_chunks_received: 0,
            unplug_count: 0,
            replug_count: 0,
            pending_control: VecDeque::new(),
            send_queue: VecDeque::new(),
            replay_ring: VecDeque::new(),
            pending_calls: HashMap::new(),
            pending_binaries: HashMap::new(),
            freeze_waiters: Vec::new(),
            handshake_waiters: Vec::new(),
            disposed_caps: Vec::new(),
            callback_handler: None,
            last_error: None,
            reader_park_rx: None,
            writer_park_rx: None,
            parked_reader: None,
            parked_writer: None,
        }
    }

    fn alloc_req_id(&mut self) -> u32 {
        let id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(2).max(1);
        id
    }

    fn trim_replay_ring(&mut self, acked_seq: u64) {
        while let Some(front) = self.replay_ring.front() {
            if front.seq > acked_seq {
                break;
            }
            self.replay_ring.pop_front();
        }
    }

    fn enqueue_control(&mut self, frame: &PrwpFrame) {
        self.pending_control.push_back(encode_frame(frame));
    }

    fn enqueue_reliable(&mut self, frame: &PrwpFrame) {
        let bytes = encode_frame(frame);
        let cost = (frame.payload.len() as u32).max(1);
        let seq = self.next_outbound_seq;
        self.next_outbound_seq += 1;
        let entry = ReplayEntry {
            seq,
            bytes: bytes.clone(),
            credit_cost: cost,
        };
        self.replay_ring.push_back(ReplayEntry {
            seq,
            bytes,
            credit_cost: cost,
        });
        self.send_queue.push_back(entry);
    }

    fn enqueue_binaries(&mut self, frame_type: FrameType, req_id: u32, binaries: &[Vec<u8>]) {
        let phase = phase_flag_of(frame_type);
        for (idx, blob) in binaries.iter().enumerate() {
            self.enqueue_single_blob(phase, req_id, idx as u32, blob);
        }
    }

    fn enqueue_single_blob(&mut self, phase: u16, req_id: u32, idx: u32, blob: &[u8]) {
        if blob.is_empty() {
            let payload = build_binary_chunk_payload(idx, 0, 0, &[]);
            self.enqueue_reliable(&PrwpFrame {
                frame_type: FrameType::BinaryChunk,
                flags: phase | FLAG_FIN,
                request_id: req_id,
                payload,
            });
            self.binary_chunks_sent += 1;
            return;
        }
        let mut offset = 0usize;
        while offset < blob.len() {
            let end = (offset + DEFAULT_CHUNK_BYTES).min(blob.len());
            let fin = if end >= blob.len() { FLAG_FIN } else { 0 };
            let payload = build_binary_chunk_payload(
                idx,
                offset as u32,
                blob.len() as u32,
                &blob[offset..end],
            );
            self.enqueue_reliable(&PrwpFrame {
                frame_type: FrameType::BinaryChunk,
                flags: phase | fin,
                request_id: req_id,
                payload,
            });
            self.binary_chunks_sent += 1;
            offset = end;
        }
    }

    fn take_binaries(&mut self, key: &str) -> Vec<Vec<u8>> {
        let Some(entry) = self.pending_binaries.remove(key) else {
            return Vec::new();
        };
        if entry.blobs.is_empty() {
            return Vec::new();
        }
        let max_idx = entry.blobs.keys().copied().max().unwrap_or(0) as usize;
        let mut out = vec![Vec::new(); max_idx + 1];
        for (i, blob) in entry.blobs {
            if let Some(slot) = out.get_mut(i as usize) {
                *slot = blob;
            }
        }
        out
    }

    fn pop_next_outbound(&mut self, gen: u64) -> Option<Vec<u8>> {
        if gen != self.stream_gen
            || matches!(
                self.state,
                TransportState::Closed | TransportState::Unplugged
            )
        {
            return None;
        }
        if let Some(ctrl) = self.pending_control.pop_front() {
            return Some(ctrl);
        }
        if !self.handshake_done || self.state != TransportState::Open {
            return None;
        }
        let next = self.send_queue.front()?;
        let needed = next.credit_cost.min(self.peer_window_bytes);
        if self.send_credits < needed {
            return None;
        }
        let popped = self.send_queue.pop_front()?;
        self.send_credits = self.send_credits.saturating_sub(popped.credit_cost);
        Some(popped.bytes)
    }

    fn fail_all_waiters(&mut self, msg: &str) {
        let calls: Vec<_> = self.pending_calls.drain().collect();
        for (_, call) in calls {
            let _ = call.tx.send(Err(RpcPipeError::Closed(msg.to_string())));
        }
        for w in self.handshake_waiters.drain(..) {
            let _ = w.send(Err(RpcPipeError::Closed(msg.to_string())));
        }
        for w in self.freeze_waiters.drain(..) {
            let _ = w.send(Err(RpcPipeError::Closed(msg.to_string())));
        }
    }
}

/// Async PRWP session operating over pluggable child pipes or sockets.
#[derive(Clone)]
pub struct PrwpPipeSession {
    inner: Arc<Mutex<SessionInner>>,
    write_notify: Arc<Notify>,
    unplug_notify: Arc<Notify>,
    gen_watch: Arc<watch::Sender<u64>>,
    _gen_rx: watch::Receiver<u64>,
}

impl PrwpPipeSession {
    pub fn new(window_bytes: u32) -> Self {
        let (gen_watch, gen_rx) = watch::channel(0u64);
        Self {
            inner: Arc::new(Mutex::new(SessionInner::new(window_bytes))),
            write_notify: Arc::new(Notify::new()),
            unplug_notify: Arc::new(Notify::new()),
            gen_watch: Arc::new(gen_watch),
            _gen_rx: gen_rx,
        }
    }

    pub fn set_callback_handler(&self, handler: CallbackHandler) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.callback_handler = Some(handler);
        }
    }

    pub fn plug_streams(&self, reader: BoxedRead, writer: BoxedWrite) {
        let (r_tx, r_rx) = oneshot::channel();
        let (w_tx, w_rx) = oneshot::channel();
        let gen = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.state == TransportState::Closed {
                return;
            }
            let is_replug = guard.state != TransportState::Idle || guard.unplug_count > 0;
            if guard.state != TransportState::Idle {
                guard.replug_count += 1;
            }
            guard.stream_gen += 1;
            guard.handshake_done = false;
            guard.pending_control.clear();
            guard.parked_reader = None;
            guard.parked_writer = None;
            guard.reader_park_rx = Some(r_rx);
            guard.writer_park_rx = Some(w_rx);
            guard.state = TransportState::Handshaking;
            let hs = serde_json::json!({
                "version": 1,
                "ackedSeq": guard.last_recv_seq,
                "windowBytes": guard.local_window_bytes,
                "replug": is_replug,
            });
            guard.enqueue_control(&PrwpFrame {
                frame_type: FrameType::Handshake,
                flags: FLAG_NONE,
                request_id: 0,
                payload: hs.to_string().into_bytes(),
            });
            guard.stream_gen
        };
        let _ = self.gen_watch.send_replace(gen);
        self.unplug_notify.notify_waiters();
        self.spawn_writer_loop(gen, writer, w_tx);
        self.spawn_reader_loop(gen, reader, r_tx);
        self.write_notify.notify_waiters();
    }

    pub fn replug(&self, reader: BoxedRead, writer: BoxedWrite) {
        self.plug_streams(reader, writer);
    }

    /// Take parked stdio/pipe streams after `unplug()` without closing the child pipes.
    pub async fn take_unplugged_streams(
        &self,
        deadline: Duration,
    ) -> Result<(BoxedRead, BoxedWrite), RpcPipeError> {
        let (cached_r, cached_w, r_rx, w_rx) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            (
                guard.parked_reader.take(),
                guard.parked_writer.take(),
                guard.reader_park_rx.take(),
                guard.writer_park_rx.take(),
            )
        };
        let reader = match cached_r {
            Some(r) => r,
            None => recv_parked(r_rx, deadline, "reader").await?,
        };
        let writer = match cached_w {
            Some(w) => w,
            None => recv_parked(w_rx, deadline, "writer").await?,
        };
        Ok((reader, writer))
    }

    /// Re-plug the previously parked child streams after an `unplug()` pause.
    pub async fn replug_parked(&self, deadline: Duration) -> Result<(), RpcPipeError> {
        let (reader, writer) = self.take_unplugged_streams(deadline).await?;
        self.plug_streams(reader, writer);
        Ok(())
    }

    pub fn unplug(&self) {
        let gen = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(
                guard.state,
                TransportState::Closed | TransportState::Unplugged
            ) {
                return;
            }
            guard.stream_gen += 1;
            guard.handshake_done = false;
            guard.unplug_count += 1;
            guard.state = TransportState::Unplugged;
            for w in guard.freeze_waiters.drain(..) {
                let _ = w.send(Err(RpcPipeError::Closed(
                    "RPC session unplugged before FREEZE_READY".to_string(),
                )));
            }
            guard.stream_gen
        };
        let _ = self.gen_watch.send_replace(gen);
        self.unplug_notify.notify_waiters();
        self.write_notify.notify_waiters();
    }

    pub fn close(&self, reason: &str) {
        let gen = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.state == TransportState::Closed {
                return;
            }
            guard.stream_gen += 1;
            guard.state = TransportState::Closed;
            guard.handshake_done = false;
            guard.reader_park_rx = None;
            guard.writer_park_rx = None;
            guard.parked_reader = None;
            guard.parked_writer = None;
            guard.fail_all_waiters(reason);
            guard.stream_gen
        };
        let _ = self.gen_watch.send_replace(gen);
        self.unplug_notify.notify_waiters();
        self.write_notify.notify_waiters();
    }

    pub async fn wait_handshake(&self, deadline: Duration) -> Result<(), RpcPipeError> {
        let rx = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.handshake_done && guard.state == TransportState::Open {
                return Ok(());
            }
            if guard.state == TransportState::Closed {
                return Err(RpcPipeError::Closed("session closed".to_string()));
            }
            let (tx, rx) = oneshot::channel();
            guard.handshake_waiters.push(tx);
            rx
        };
        match timeout(deadline, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(RpcPipeError::Closed("handshake dropped".to_string())),
            Err(_) => Err(RpcPipeError::Timeout("PRWP handshake timeout".to_string())),
        }
    }

    pub async fn call(
        &self,
        method: &str,
        args: Vec<Value>,
        binaries: Vec<Vec<u8>>,
    ) -> Result<RpcCallResult, RpcPipeError> {
        self.call_with_timeout(method, args, binaries, Duration::from_secs(10))
            .await
    }

    pub async fn call_with_timeout(
        &self,
        method: &str,
        args: Vec<Value>,
        binaries: Vec<Vec<u8>>,
        deadline: Duration,
    ) -> Result<RpcCallResult, RpcPipeError> {
        let (req_id, rx) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.state == TransportState::Closed {
                return Err(RpcPipeError::Closed("RPC session closed".to_string()));
            }
            let req_id = guard.alloc_req_id();
            let (tx, rx) = oneshot::channel();
            guard.pending_calls.insert(req_id, PendingCall { tx });
            guard.enqueue_binaries(FrameType::Call, req_id, &binaries);
            let flags = if binaries.is_empty() {
                FLAG_NONE
            } else {
                FLAG_HAS_BINARY
            };
            let body = serde_json::json!({
                "m": method,
                "a": args,
                "bc": binaries.len(),
            });
            guard.enqueue_reliable(&PrwpFrame {
                frame_type: FrameType::Call,
                flags,
                request_id: req_id,
                payload: body.to_string().into_bytes(),
            });
            (req_id, rx)
        };
        self.write_notify.notify_waiters();
        match timeout(deadline, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(RpcPipeError::Closed("call dropped".to_string())),
            Err(_) => {
                self.cancel_call(req_id, "call timed out");
                Err(RpcPipeError::Timeout(format!("call '{method}' timed out")))
            }
        }
    }

    pub fn cancel_call(&self, request_id: u32, reason: &str) {
        let removed = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let existed = guard.pending_calls.remove(&request_id).is_some();
            if existed && guard.state != TransportState::Closed {
                let body = serde_json::json!({ "reason": reason });
                guard.enqueue_reliable(&PrwpFrame {
                    frame_type: FrameType::Cancel,
                    flags: FLAG_PHASE_CALL,
                    request_id,
                    payload: body.to_string().into_bytes(),
                });
            }
            existed
        };
        if removed {
            self.write_notify.notify_waiters();
        }
    }

    pub fn send_dispose(&self, cap_id: u32) {
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.state == TransportState::Closed {
                return;
            }
            let body = serde_json::json!({ "c": cap_id });
            guard.enqueue_reliable(&PrwpFrame {
                frame_type: FrameType::Dispose,
                flags: FLAG_NONE,
                request_id: 0,
                payload: body.to_string().into_bytes(),
            });
        }
        self.write_notify.notify_waiters();
    }

    pub async fn prepare_freeze(&self, deadline: Duration) -> Result<u64, RpcPipeError> {
        let rx = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.state == TransportState::Closed {
                return Err(RpcPipeError::Closed("session closed".to_string()));
            }
            if matches!(
                guard.state,
                TransportState::Frozen | TransportState::Unplugged
            ) {
                return Ok(guard.last_recv_seq);
            }
            if guard.state != TransportState::Open {
                return Err(RpcPipeError::Io(
                    "cannot prepareFreeze while not open".to_string(),
                ));
            }
            guard.state = TransportState::Freezing;
            let last_sent = guard.next_outbound_seq.saturating_sub(1);
            let body = serde_json::json!({ "lastSentSeq": last_sent });
            guard.enqueue_control(&PrwpFrame {
                frame_type: FrameType::PrepareFreeze,
                flags: FLAG_NONE,
                request_id: 0,
                payload: body.to_string().into_bytes(),
            });
            let (tx, rx) = oneshot::channel();
            guard.freeze_waiters.push(tx);
            rx
        };
        self.write_notify.notify_waiters();
        match timeout(deadline, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(RpcPipeError::Closed("freeze waiter dropped".to_string())),
            Err(_) => Err(RpcPipeError::Timeout("PREPARE_FREEZE timeout".to_string())),
        }
    }

    pub fn stats(&self) -> RpcPipeStats {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        RpcPipeStats {
            state: guard.state,
            next_outbound_seq: guard.next_outbound_seq,
            last_recv_seq: guard.last_recv_seq,
            replay_ring_len: guard.replay_ring.len(),
            send_credits: guard.send_credits,
            credits_sent: guard.credits_sent,
            credits_received: guard.credits_received,
            binary_chunks_sent: guard.binary_chunks_sent,
            binary_chunks_received: guard.binary_chunks_received,
            unplug_count: guard.unplug_count,
            replug_count: guard.replug_count,
        }
    }

    pub fn disposed_caps(&self) -> Vec<u32> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .disposed_caps
            .clone()
    }

    fn spawn_writer_loop(
        &self,
        gen: u64,
        writer: BoxedWrite,
        park_tx: oneshot::Sender<BoxedWrite>,
    ) {
        let session = self.clone();
        let gen_rx = self.gen_watch.subscribe();
        tokio::spawn(async move {
            run_writer_task(session, gen, writer, gen_rx, park_tx).await;
        });
    }

    fn spawn_reader_loop(&self, gen: u64, reader: BoxedRead, park_tx: oneshot::Sender<BoxedRead>) {
        let session = self.clone();
        let gen_rx = self.gen_watch.subscribe();
        tokio::spawn(async move {
            run_reader_task(session, gen, reader, gen_rx, park_tx).await;
        });
    }

    fn is_unplugged_now(&self) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.state == TransportState::Unplugged
    }

    fn current_gen(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stream_gen
    }

    fn record_io_error(&self, gen: u64, msg: String) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.stream_gen == gen
            && !matches!(
                guard.state,
                TransportState::Closed | TransportState::Unplugged
            )
        {
            guard.last_error = Some(msg);
        }
    }

    fn process_bytes(&self, decoder: &mut FrameDecoder, bytes: &[u8]) -> Result<(), RpcPipeError> {
        let frames = decoder.push(bytes)?;
        for frame in frames {
            self.handle_frame(frame);
        }
        Ok(())
    }

    fn handle_frame(&self, frame: PrwpFrame) {
        match frame.frame_type {
            FrameType::Handshake => self.on_handshake(&frame.payload),
            FrameType::Credit => self.on_credit(&frame.payload),
            FrameType::PrepareFreeze => self.on_prepare_freeze(),
            FrameType::FreezeReady => self.on_freeze_ready(&frame.payload),
            _ => self.on_reliable_frame(frame),
        }
    }

    fn on_handshake(&self, payload: &[u8]) {
        let msg: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
        let acked = msg.get("ackedSeq").and_then(Value::as_u64).unwrap_or(0);
        let win = msg
            .get("windowBytes")
            .and_then(Value::as_u64)
            .unwrap_or(u64::from(DEFAULT_WINDOW_BYTES)) as u32;
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.peer_window_bytes = win.max(1);
            guard.send_credits = guard.peer_window_bytes;
            guard.trim_replay_ring(acked);
            guard.send_queue = guard
                .replay_ring
                .iter()
                .map(|e| ReplayEntry {
                    seq: e.seq,
                    bytes: e.bytes.clone(),
                    credit_cost: e.credit_cost,
                })
                .collect();
            guard.handshake_done = true;
            guard.state = TransportState::Open;
            for w in guard.handshake_waiters.drain(..) {
                let _ = w.send(Ok(()));
            }
        }
        self.write_notify.notify_waiters();
    }

    fn on_credit(&self, payload: &[u8]) {
        let msg: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
        let acked = msg.get("ackedSeq").and_then(Value::as_u64).unwrap_or(0);
        let bytes = msg.get("bytes").and_then(Value::as_u64).unwrap_or(0) as u32;
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.credits_received += 1;
            guard.trim_replay_ring(acked);
            if bytes > 0 {
                guard.send_credits = guard
                    .send_credits
                    .saturating_add(bytes)
                    .min(guard.peer_window_bytes);
            }
        }
        self.write_notify.notify_waiters();
    }

    fn on_prepare_freeze(&self) {
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.state = TransportState::Frozen;
            let body = serde_json::json!({ "ackedSeq": guard.last_recv_seq });
            guard.enqueue_control(&PrwpFrame {
                frame_type: FrameType::FreezeReady,
                flags: FLAG_NONE,
                request_id: 0,
                payload: body.to_string().into_bytes(),
            });
        }
        self.write_notify.notify_waiters();
    }

    fn on_freeze_ready(&self, payload: &[u8]) {
        let msg: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
        let acked = msg.get("ackedSeq").and_then(Value::as_u64).unwrap_or(0);
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.trim_replay_ring(acked);
        guard.state = TransportState::Frozen;
        for w in guard.freeze_waiters.drain(..) {
            let _ = w.send(Ok(acked));
        }
    }

    fn on_reliable_frame(&self, frame: PrwpFrame) {
        let cost = (frame.payload.len() as u32).max(1);
        let mut flush_credit = false;
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.last_recv_seq += 1;
            guard.uncredited_bytes = guard.uncredited_bytes.saturating_add(cost);
            if guard.uncredited_bytes >= (guard.local_window_bytes / 2).max(1)
                || matches!(
                    frame.frame_type,
                    FrameType::Reply | FrameType::Error | FrameType::Callback
                )
            {
                let bytes = guard.uncredited_bytes;
                let acked = guard.last_recv_seq;
                guard.uncredited_bytes = 0;
                guard.last_acked_seq_sent = acked;
                guard.credits_sent += 1;
                let body = serde_json::json!({ "bytes": bytes, "ackedSeq": acked });
                guard.enqueue_control(&PrwpFrame {
                    frame_type: FrameType::Credit,
                    flags: FLAG_NONE,
                    request_id: 0,
                    payload: body.to_string().into_bytes(),
                });
                flush_credit = true;
            }
        }
        if flush_credit {
            self.write_notify.notify_waiters();
        }
        self.dispatch_reliable(frame);
    }

    fn dispatch_reliable(&self, frame: PrwpFrame) {
        match frame.frame_type {
            FrameType::BinaryChunk => self.on_binary_chunk(frame),
            FrameType::Reply => self.on_reply(frame),
            FrameType::Error => self.on_error(frame),
            FrameType::Callback => self.on_callback(frame),
            FrameType::Dispose => self.on_dispose(&frame.payload),
            _ => {}
        }
    }

    fn on_binary_chunk(&self, frame: PrwpFrame) {
        if frame.payload.len() < 12 {
            return;
        }
        let blob_index = u32::from_le_bytes(frame.payload[0..4].try_into().unwrap_or([0; 4]));
        let byte_offset =
            u32::from_le_bytes(frame.payload[4..8].try_into().unwrap_or([0; 4])) as usize;
        let total_len =
            u32::from_le_bytes(frame.payload[8..12].try_into().unwrap_or([0; 4])) as usize;
        let slice = &frame.payload[12..];
        if byte_offset.saturating_add(slice.len()) > total_len {
            return;
        }
        let key = phase_key_of(frame.flags, frame.request_id);
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.binary_chunks_received += 1;
        let entry = guard
            .pending_binaries
            .entry(key)
            .or_insert_with(|| PendingBinary {
                blobs: HashMap::new(),
            });
        let blob = entry
            .blobs
            .entry(blob_index)
            .or_insert_with(|| vec![0u8; total_len]);
        if !slice.is_empty() && byte_offset + slice.len() <= blob.len() {
            blob[byte_offset..byte_offset + slice.len()].copy_from_slice(slice);
        }
    }

    fn on_reply(&self, frame: PrwpFrame) {
        let msg: Value = serde_json::from_slice(&frame.payload).unwrap_or(Value::Null);
        let value = msg.get("r").cloned().unwrap_or(Value::Null);
        let pending = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let bins = guard.take_binaries(&format!("r:{}", frame.request_id));
            (guard.pending_calls.remove(&frame.request_id), bins)
        };
        if let (Some(call), binaries) = pending {
            let _ = call.tx.send(Ok(RpcCallResult { value, binaries }));
        }
    }

    fn on_error(&self, frame: PrwpFrame) {
        let msg: Value = serde_json::from_slice(&frame.payload).unwrap_or(Value::Null);
        let err_obj = msg.get("e").unwrap_or(&Value::Null);
        let name = err_obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Error")
            .to_string();
        let message = err_obj
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Unknown PRWP remote error")
            .to_string();
        let call = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.take_binaries(&format!("r:{}", frame.request_id));
            guard.pending_calls.remove(&frame.request_id)
        };
        if let Some(pending) = call {
            let _ = pending.tx.send(Err(RpcPipeError::Remote { name, message }));
        }
    }

    fn on_callback(&self, frame: PrwpFrame) {
        let msg: Value = serde_json::from_slice(&frame.payload).unwrap_or(Value::Null);
        let cap_id = msg.get("c").and_then(Value::as_u64).unwrap_or(0) as u32;
        let method = msg.get("m").and_then(Value::as_str).map(ToOwned::to_owned);
        let args = msg
            .get("a")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let (binaries, handler) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let bins = guard.take_binaries(&format!("cb:{}", frame.request_id));
            (bins, guard.callback_handler.clone())
        };
        let session = self.clone();
        let req_id = frame.request_id;
        tokio::spawn(async move {
            let result = match handler {
                Some(h) => h(cap_id, method, args, binaries).await,
                None => Err("no host callback handler registered".to_string()),
            };
            session.send_callback_reply(req_id, result);
        });
    }

    fn send_callback_reply(&self, req_id: u32, result: Result<RpcCallResult, String>) {
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.state == TransportState::Closed {
                return;
            }
            match result {
                Ok(res) => {
                    guard.enqueue_binaries(FrameType::Reply, req_id, &res.binaries);
                    let flags = FLAG_PHASE_CALLBACK
                        | if res.binaries.is_empty() {
                            FLAG_NONE
                        } else {
                            FLAG_HAS_BINARY
                        };
                    let body = serde_json::json!({ "r": res.value, "bc": res.binaries.len() });
                    guard.enqueue_reliable(&PrwpFrame {
                        frame_type: FrameType::Reply,
                        flags,
                        request_id: req_id,
                        payload: body.to_string().into_bytes(),
                    });
                }
                Err(msg) => {
                    let body = serde_json::json!({
                        "e": { "name": "Error", "message": msg }
                    });
                    guard.enqueue_reliable(&PrwpFrame {
                        frame_type: FrameType::Error,
                        flags: FLAG_PHASE_CALLBACK,
                        request_id: req_id,
                        payload: body.to_string().into_bytes(),
                    });
                }
            }
        }
        self.write_notify.notify_waiters();
    }

    fn on_dispose(&self, payload: &[u8]) {
        let msg: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
        if let Some(cap_id) = msg.get("c").and_then(Value::as_u64) {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.disposed_caps.push(cap_id as u32);
        }
    }
}

async fn recv_parked<T>(
    rx: Option<oneshot::Receiver<T>>,
    deadline: Duration,
    label: &str,
) -> Result<T, RpcPipeError> {
    let Some(rx) = rx else {
        return Err(RpcPipeError::Closed(format!(
            "no unplugged {label} stream available for replug"
        )));
    };
    match timeout(deadline, rx).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err(RpcPipeError::Closed(format!(
            "unplugged {label} stream was dropped"
        ))),
        Err(_) => Err(RpcPipeError::Timeout(format!(
            "timed out waiting to park {label} stream"
        ))),
    }
}

async fn run_writer_task(
    session: PrwpPipeSession,
    gen: u64,
    mut writer: BoxedWrite,
    mut gen_rx: watch::Receiver<u64>,
    park_tx: oneshot::Sender<BoxedWrite>,
) {
    loop {
        if *gen_rx.borrow_and_update() != gen || session.current_gen() != gen {
            if session.is_unplugged_now() {
                let _ = park_tx.send(writer);
            }
            break;
        }
        let next = {
            let mut guard = session.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.pop_next_outbound(gen)
        };
        if let Some(bytes) = next {
            if let Err(err) = writer.write_all(&bytes).await {
                session.record_io_error(gen, format!("write: {err}"));
                break;
            }
            let _ = writer.flush().await;
            continue;
        }
        tokio::select! {
            _ = session.write_notify.notified() => {}
            _ = gen_rx.changed() => {}
        }
    }
}

async fn run_reader_task(
    session: PrwpPipeSession,
    gen: u64,
    mut reader: BoxedRead,
    mut gen_rx: watch::Receiver<u64>,
    park_tx: oneshot::Sender<BoxedRead>,
) {
    let mut decoder = FrameDecoder::new(DEFAULT_MAX_PAYLOAD_BYTES);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if *gen_rx.borrow_and_update() != gen || session.current_gen() != gen {
            if session.is_unplugged_now() {
                let _ = park_tx.send(reader);
            }
            break;
        }
        let read_res = tokio::select! {
            res = reader.read(&mut buf) => res,
            _ = gen_rx.changed() => continue,
        };
        let n = match read_res {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                session.record_io_error(gen, format!("read: {err}"));
                break;
            }
        };
        if session.current_gen() != gen {
            if session.is_unplugged_now() {
                let _ = park_tx.send(reader);
            }
            break;
        }
        if let Err(err) = session.process_bytes(&mut decoder, &buf[..n]) {
            session.record_io_error(gen, err.to_string());
            break;
        }
    }
}

/// Live child Deno worker connected exclusively over stdio PRWP pipes.
pub struct DenoWorkerProcess {
    pub child: Child,
    pub session: PrwpPipeSession,
    pub deno_bin: String,
}

impl DenoWorkerProcess {
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub async fn shutdown(&mut self) {
        self.session.close("worker shutdown");
        let _ = self.child.kill().await;
    }
}

pub fn resolve_deno_binary(explicit: Option<&str>) -> String {
    if let Some(bin) = explicit.filter(|s| !s.trim().is_empty()) {
        return bin.to_string();
    }
    if let Ok(env_bin) = std::env::var("PARAWING_DENO_BIN") {
        if !env_bin.trim().is_empty() {
            return env_bin;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let user_deno = std::path::PathBuf::from(home).join(".deno/bin/deno");
        if user_deno.exists() {
            return user_deno.display().to_string();
        }
    }
    for candidate in [
        "/usr/local/bin/deno",
        "/opt/homebrew/bin/deno",
        "/usr/bin/deno",
    ] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "deno".to_string()
}

pub async fn spawn_deno_worker(
    explicit_deno: Option<&str>,
    module_script_js: &str,
    v8_flags: &[&str],
) -> Result<DenoWorkerProcess, RpcPipeError> {
    let deno_bin = resolve_deno_binary(explicit_deno);
    let data_url = format!(
        "data:text/javascript;base64,{}",
        BASE64_STANDARD.encode(module_script_js.as_bytes())
    );
    let mut joined_flags = vec!["--disallow-code-generation-from-strings".to_string()];
    for f in v8_flags {
        if !joined_flags.iter().any(|x| x == f) {
            joined_flags.push((*f).to_string());
        }
    }
    let mut cmd = Command::new(&deno_bin);
    cmd.args([
        "run",
        "--no-prompt",
        "--no-config",
        "--no-lock",
        "--no-code-cache",
        &format!("--v8-flags={}", joined_flags.join(",")),
        &data_url,
    ])
    .env_clear()
    .env("DENO_DIR", "/nonexistent-parawing-deno-dir")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| RpcPipeError::Spawn(format!("{deno_bin}: {e}")))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| RpcPipeError::Spawn("missing child stdin".to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| RpcPipeError::Spawn("missing child stdout".to_string()))?;

    let session = PrwpPipeSession::new(DEFAULT_WINDOW_BYTES);
    session.plug_streams(Box::new(stdout), Box::new(stdin));
    session.wait_handshake(Duration::from_secs(10)).await?;
    Ok(DenoWorkerProcess {
        child,
        session,
        deno_bin,
    })
}

/// Zero-permission Deno child runtime implementing the PRWP wire peer over stdin/stdout.
pub fn build_prwp_deno_v8_script() -> &'static str {
    r#"import vm from "node:vm";
const PRWP_MAGIC = 0x50525750;
const PRWP_VERSION = 1;
const HEADER = 16;
const FT = { HANDSHAKE: 1, CALL: 2, REPLY: 3, CALLBACK: 4, CANCEL: 5, DISPOSE: 6, BIN: 7, CREDIT: 8, ERROR: 9, PREPARE_FREEZE: 10, FREEZE_READY: 11 };
const FLAG = { FIN: 1, HAS_BINARY: 2, P_CALL: 4, P_REPLY: 8, P_CB: 16 };
const enc = new TextEncoder();
const dec = new TextDecoder();
const reader = Deno.stdin.readable.getReader();
const writer = Deno.stdout.writable.getWriter();
let recvBuf = new Uint8Array(0);
let lastRecvSeq = 0;
let nextCbId = 2;
const pendingBins = new Map();
const pendingCbs = new Map();
const sandbox = vm.createContext(
  { __ticks: 0, __state: { visited: 0 }, setInterval, clearInterval, setTimeout, clearTimeout },
  { codeGeneration: { strings: false, wasm: false } },
);
const intervalTimers = new Set();
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

async function sendBinReply(reqId, value, binaries) {
  for (let i = 0; i < binaries.length; i++) {
    const b = binaries[i];
    const p = new Uint8Array(12 + b.byteLength);
    const v = new DataView(p.buffer);
    v.setUint32(0, i, true);
    v.setUint32(4, 0, true);
    v.setUint32(8, b.byteLength, true);
    p.set(b, 12);
    await writer.write(encodeFrame(FT.BIN, FLAG.P_REPLY | FLAG.FIN, reqId, p));
  }
  const fl = FLAG.P_CALL | (binaries.length > 0 ? FLAG.HAS_BINARY : 0);
  await sendJson(FT.REPLY, fl, reqId, { r: value, bc: binaries.length });
}

function probePermissions() {
  const denied = [];
  for (const [name, fn] of [
    ["fsRead", () => Deno.readTextFileSync("/etc/passwd")],
    ["envGet", () => Deno.env.get("HOME")],
    ["run", () => new Deno.Command("echo", { args: ["x"] }).outputSync()],
    ["connect", () => Deno.listen({ port: 0 })],
  ]) {
    try { fn(); denied.push({ name, ok: false }); } catch (e) { denied.push({ name, ok: true, err: e?.name ?? String(e) }); }
  }
  return denied;
}

async function callHostCallback(capId, method, args) {
  const id = nextCbId;
  nextCbId += 2;
  const p = new Promise((resolve, reject) => pendingCbs.set(id, { resolve, reject }));
  await sendJson(FT.CALLBACK, 0, id, { c: capId, m: method, a: args, bc: 0 });
  return await p;
}

async function dispatchCall(reqId, msg, bins) {
  try {
    const method = String(msg.m ?? "");
    const args = Array.isArray(msg.a) ? msg.a : [];
    if (method === "evalJs") {
      const val = vm.runInContext(String(args[0] ?? ""), sandbox);
      await sendBinReply(reqId, { ok: true, value: val ?? null }, []);
      return;
    }
    if (method === "echoBinary") {
      const bin = bins[0] ?? new Uint8Array(0);
      await sendBinReply(reqId, { bytes: bin.byteLength }, [bin]);
      return;
    }
    if (method === "probePermissions") {
      await sendBinReply(reqId, probePermissions(), []);
      return;
    }
    if (method === "invokeHostCallback") {
      const res = await callHostCallback(Number(args[0] ?? 1), String(args[1] ?? "ping"), args.slice(2));
      await sendBinReply(reqId, { hostReply: res }, []);
      return;
    }
    if (method === "startInterval") {
      const id = setInterval(() => { sandbox.__ticks += 1; }, Math.max(5, Number(args[0] ?? 10)));
      intervalTimers.add(id);
      await sendBinReply(reqId, { timerId: Number(id) }, []);
      return;
    }
    if (method === "getState") {
      await sendBinReply(reqId, { ticks: sandbox.__ticks, state: sandbox.__state, prngReseedCount }, []);
      return;
    }
    if (method === "reseedPrng") {
      const info = reseedPrngFromHex(args[0]);
      await sendBinReply(reqId, info, []);
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
  merged.set(recvBuf);
  merged.set(value, recvBuf.byteLength);
  recvBuf = merged;
  while (recvBuf.byteLength >= HEADER) {
    const view = new DataView(recvBuf.buffer, recvBuf.byteOffset, HEADER);
    const len = view.getUint32(12, true);
    if (recvBuf.byteLength < HEADER + len) break;
    const ft = view.getUint8(5);
    const fl = view.getUint16(6, true);
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
    if (ft === FT.BIN) {
      const bv = new DataView(payload.buffer, payload.byteOffset, 12);
      const bi = bv.getUint32(0, true);
      const off = bv.getUint32(4, true);
      const tot = bv.getUint32(8, true);
      const k = (fl & FLAG.P_CB) ? `cb:${reqId}` : `c:${reqId}`;
      const arr = pendingBins.get(k) ?? [];
      if (!arr[bi]) arr[bi] = new Uint8Array(tot);
      arr[bi].set(payload.subarray(12), off);
      pendingBins.set(k, arr);
    } else if (ft === FT.CALL) {
      const bins = pendingBins.get(`c:${reqId}`) ?? [];
      pendingBins.delete(`c:${reqId}`);
      void dispatchCall(reqId, JSON.parse(dec.decode(payload)), bins);
    } else if (ft === FT.REPLY) {
      const entry = pendingCbs.get(reqId);
      if (entry) {
        pendingCbs.delete(reqId);
        entry.resolve(JSON.parse(dec.decode(payload)).r);
      }
    }
    await sendJson(FT.CREDIT, 0, 0, { bytes: Math.max(1, payload.byteLength), ackedSeq: lastRecvSeq });
  }
}
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn frame_codec_handles_partial_reads_and_binary_chunk_layout() {
        let f1 = PrwpFrame {
            frame_type: FrameType::Call,
            flags: FLAG_HAS_BINARY,
            request_id: 7,
            payload: br#"{"m":"echo","a":[],"bc":1}"#.to_vec(),
        };
        let encoded = encode_frame(&f1);
        let mut dec = FrameDecoder::new(DEFAULT_MAX_PAYLOAD_BYTES);
        assert!(dec.push(&encoded[..5]).expect("partial hdr").is_empty());
        assert!(dec.push(&encoded[5..18]).expect("partial body").is_empty());
        let decoded = dec.push(&encoded[18..]).expect("rest");
        assert_eq!(decoded, vec![f1]);

        let chunk = build_binary_chunk_payload(2, 4, 10, b"hello");
        assert_eq!(&chunk[0..4], &2u32.to_le_bytes());
        assert_eq!(&chunk[4..8], &4u32.to_le_bytes());
        assert_eq!(&chunk[8..12], &10u32.to_le_bytes());
        assert_eq!(&chunk[12..], b"hello");
    }

    #[tokio::test]
    async fn live_zero_permission_deno_worker_executes_prwp_calls_binary_callbacks_and_freeze() {
        let mut worker = spawn_deno_worker(None, build_prwp_deno_v8_script(), &[])
            .await
            .expect("spawn zero-permission deno worker");
        assert!(worker.pid().is_some());

        worker
            .session
            .set_callback_handler(Arc::new(|cap_id, method, args, _bins| {
                Box::pin(async move {
                    Ok(RpcCallResult {
                        value: serde_json::json!({
                            "capId": cap_id,
                            "method": method,
                            "echo": args,
                        }),
                        binaries: Vec::new(),
                    })
                })
            }));

        let perms = worker
            .session
            .call("probePermissions", vec![], vec![])
            .await
            .expect("probePermissions");
        let list = perms.value.as_array().expect("permissions list");
        assert_eq!(list.len(), 4);
        assert!(list.iter().all(|item| item["ok"] == true));

        let eval_res = worker
            .session
            .call(
                "evalJs",
                vec![Value::String(
                    "(() => { __state.visited += 7; return 6 * 7; })()".to_string(),
                )],
                vec![],
            )
            .await
            .expect("evalJs");
        assert_eq!(eval_res.value["value"], serde_json::json!(42));

        let bin_payload = vec![0xAAu8; 32 * 1024 + 13];
        let bin_res = worker
            .session
            .call("echoBinary", vec![], vec![bin_payload.clone()])
            .await
            .expect("echoBinary");
        assert_eq!(bin_res.value["bytes"], serde_json::json!(bin_payload.len()));
        assert_eq!(bin_res.binaries.len(), 1);
        assert_eq!(bin_res.binaries[0], bin_payload);

        let cb_res = worker
            .session
            .call(
                "invokeHostCallback",
                vec![
                    Value::from(9),
                    Value::String("greet".to_string()),
                    Value::String("rust".to_string()),
                ],
                vec![],
            )
            .await
            .expect("invokeHostCallback");
        assert_eq!(
            cb_res.value["hostReply"]["method"],
            serde_json::json!("greet")
        );
        assert_eq!(cb_res.value["hostReply"]["capId"], serde_json::json!(9));

        let acked = worker
            .session
            .prepare_freeze(Duration::from_secs(5))
            .await
            .expect("prepare_freeze");
        assert!(acked >= 4);
        assert_eq!(worker.session.stats().state, TransportState::Frozen);

        worker.session.unplug();
        assert_eq!(worker.session.stats().state, TransportState::Unplugged);
        assert_eq!(worker.session.stats().unplug_count, 1);

        worker
            .session
            .replug_parked(Duration::from_secs(2))
            .await
            .expect("replug parked live deno stdio pipes");
        worker
            .session
            .wait_handshake(Duration::from_secs(2))
            .await
            .expect("replug handshake");
        assert_eq!(worker.session.stats().state, TransportState::Open);
        assert_eq!(worker.session.stats().replug_count, 1);

        let state_after = worker
            .session
            .call("getState", vec![], vec![])
            .await
            .expect("getState after replug");
        assert_eq!(state_after.value["state"]["visited"], serde_json::json!(7));

        let r1 = worker
            .session
            .call(
                "reseedPrng",
                vec![Value::String(
                    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
                )],
                vec![],
            )
            .await
            .expect("reseedPrng 1");
        let m1 = worker
            .session
            .call(
                "evalJs",
                vec![Value::String("Math.random()".to_string())],
                vec![],
            )
            .await
            .expect("Math.random 1");
        let r2 = worker
            .session
            .call(
                "reseedPrng",
                vec![Value::String(
                    "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100".to_string(),
                )],
                vec![],
            )
            .await
            .expect("reseedPrng 2");
        let m2 = worker
            .session
            .call(
                "evalJs",
                vec![Value::String("Math.random()".to_string())],
                vec![],
            )
            .await
            .expect("Math.random 2");
        assert_eq!(r1.value["reseedCount"], serde_json::json!(1));
        assert_eq!(r2.value["reseedCount"], serde_json::json!(2));
        assert_ne!(m1.value["value"], m2.value["value"]);

        worker.shutdown().await;
    }

    #[tokio::test]
    async fn unplug_and_replug_resumes_reliable_pipe_session_without_losing_state() {
        let (a_left, b_left) = duplex(64 * 1024);
        let (a_r, a_w) = tokio::io::split(a_left);
        let (b_r, b_w) = tokio::io::split(b_left);

        let client = PrwpPipeSession::new(DEFAULT_WINDOW_BYTES);
        let server = PrwpPipeSession::new(DEFAULT_WINDOW_BYTES);
        client.plug_streams(Box::new(a_r), Box::new(a_w));
        server.plug_streams(Box::new(b_r), Box::new(b_w));

        client
            .wait_handshake(Duration::from_secs(2))
            .await
            .expect("client hs");
        server
            .wait_handshake(Duration::from_secs(2))
            .await
            .expect("server hs");

        let acked = client
            .prepare_freeze(Duration::from_secs(2))
            .await
            .expect("freeze");
        assert_eq!(acked, 0);
        client.unplug();
        server.unplug();

        let (c2_left, s2_left) = duplex(64 * 1024);
        let (c2_r, c2_w) = tokio::io::split(c2_left);
        let (s2_r, s2_w) = tokio::io::split(s2_left);
        client.replug(Box::new(c2_r), Box::new(c2_w));
        server.replug(Box::new(s2_r), Box::new(s2_w));

        client
            .wait_handshake(Duration::from_secs(2))
            .await
            .expect("client replug hs");
        server
            .wait_handshake(Duration::from_secs(2))
            .await
            .expect("server replug hs");
        assert_eq!(client.stats().replug_count, 1);
        assert_eq!(server.stats().replug_count, 1);
    }

    #[test]
    fn resolve_deno_binary_honors_explicit_and_resolves_nonempty_fallback() {
        assert_eq!(
            resolve_deno_binary(Some("/custom/bin/deno")),
            "/custom/bin/deno"
        );
        let default_resolved = resolve_deno_binary(Some("   "));
        assert!(!default_resolved.trim().is_empty());
    }
}
