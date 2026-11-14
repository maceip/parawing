// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Runs terminal playback over CDP, rendering scene updates and forwarding user input.

use crate::compositor_v2::CompositorV2Host;
use crate::font_cache::FontCache;
use crate::rbi_v2::{
    decode_rbi_v2_packet, encode_credit_grant_packet, encode_pointer_datagram,
    encode_reattach_packet, encode_scroll_datagram, DecodedRbiV2Packet,
};
use crate::scene_host;
use crate::wasm::Raster;
#[cfg(test)]
use crate::{scene_host::Manifest, wasm};

use base64::Engine as _;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind},
    execute, terminal,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::{
    collections::{HashSet, VecDeque},
    env::var_os,
    fs::{DirBuilder, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use crate::{
    CdpSocket, FontSource, Message, PlaybackMode as Mode, PlaybackOptions, PlaybackResult, Result,
    V2Endpoint,
};

const CONNECTION_LOST: &str =
    "Connection to the Parawing server was lost. Check that it is still running, then try again.";
const SERVER_UNRESPONSIVE: &str =
    "Parawing server stopped responding. The Worker may have restarted or hit a resource limit; try reconnecting.";
const SCENE_STREAM_STALLED: &str =
    "Scene stream stopped responding. The server may have evicted or stalled an isolate; try reconnecting.";
const CDP_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
// Servers without scene heartbeats get a `Browser.getVersion` probe this often; recent scene
// activity suppresses it, and a probe still needs a reply within `CDP_REPLY_TIMEOUT`.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const MEMORY_INTERVAL: Duration = Duration::from_secs(10);
// Applies only once a heartbeat-capable stream has shown activity. Buffered messages are read
// before deadlines are checked, so slow work does not turn queued heartbeats into stalls.
const SCENE_STALL_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn cache_directory() -> Result<PathBuf> {
    Ok(var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or("no cache directory")?
        .join("parawing"))
}

pub(crate) struct Diagnostics {
    enabled: bool,
    display: bool,
    pending: Vec<String>,
}

impl Diagnostics {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            display: false,
            pending: Vec::new(),
        }
    }

    pub(crate) fn log(&mut self, message: impl Into<String>) {
        if !self.enabled {
            return;
        }
        let message = message.into();
        if self.display {
            self.pending.push(message);
        } else {
            eprintln!("parawing: debug: {message}");
        }
    }

    fn flush(&mut self) {
        let mut stderr = io::stderr().lock();
        for message in self.pending.drain(..) {
            let _ = writeln!(stderr, "parawing: debug: {message}");
        }
    }
}

impl Drop for Diagnostics {
    fn drop(&mut self) {
        self.flush();
    }
}

const MIN_VIEWPORT_WIDTH: u16 = 320;
const MIN_VIEWPORT_HEIGHT: u16 = 240;
const MAX_VIEWPORT_WIDTH: u16 = 2560;
const MAX_VIEWPORT_HEIGHT: u16 = 1440;
const NOMINAL_MAX_ANSI_CELL_PIXELS: u16 = 64;
const ANSI_DEFAULT_CELL_WIDTH_PX: u16 = 8;
const ANSI_DEFAULT_CELL_HEIGHT_PX: u16 = 17;
const ANSI_ZOOM_CELL_HEIGHT_PX: f64 = 24.0;
const ANSI_ZOOM_FACTOR: f64 = 2.0;

const KITTY_CHUNK_BYTES: usize = 4096;
const BASE64_INPUT_BYTES_PER_QUANTUM: usize = 3;
const BASE64_OUTPUT_BYTES_PER_QUANTUM: u64 = 4;
const BYTES_PER_KIB: f64 = 1024.0;
const BYTES_PER_MIB: u64 = 1024 * 1024;

const FRAME_HEADER_BYTES: usize = 11;
const PARTIAL_FRAME_HEADER_BYTES: usize = 31;
const RGBA_HEADER_BYTES: usize = 8;
const NO_BASE_SEQUENCE: i32 = -1;

const NO_MISSING_RESOURCES: [u8; 4] = [0; 4];

const INFO_MESSAGE: u8 = 2;
const SCENE_MESSAGE: u8 = 3;
const RESOURCE_MESSAGE: u8 = 4;
const PARTIAL_MESSAGE: u8 = 5;

const CDP_ALT_MODIFIER: u32 = 1;
const CDP_CONTROL_MODIFIER: u32 = 2;
const CDP_META_MODIFIER: u32 = 4;
const CDP_SHIFT_MODIFIER: u32 = 8;
const TEXT_SUPPRESSING_MODIFIERS: u32 = CDP_ALT_MODIFIER | CDP_CONTROL_MODIFIER | CDP_META_MODIFIER;

const MOUSE_WHEEL_DELTA: i32 = 80;

const INPUT_CHANNEL_CAPACITY: usize = 64;

const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const RESIZE_TICK_INTERVAL: Duration = Duration::from_millis(200);
const RESIZE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const DEADLINE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const FPS_WINDOW: Duration = Duration::from_secs(1);
const SCENE_HEARTBEAT_MS: u64 = 1_000;

const DEBUG_BAR_ROWS: u16 = 1;

const OP_PUT_RESOURCES: u32 = 1;
const OP_SCENE_MISSING_RESOURCES: u32 = 2;
const OP_RENDER_PNG: u32 = 3;
const OP_PENDING_FONTS: u32 = 5;
const OP_PUT_FONT: u32 = 6;
const OP_LAST_ERROR: u32 = 7;
const OP_PENDING_IMAGES: u32 = 8;
const OP_ABANDON_IMAGE: u32 = 9;
const OP_ENABLE_ANSI: u32 = 12;
const OP_RENDER_ANSI: u32 = 13;
const OP_RENDER_RGBA: u32 = 14;
const OP_RETAIN_FRAME: u32 = 15;
const OP_COMPOSITE_FRAME: u32 = 16;
const MIN_RAW_FILE_ABI: u32 = 4;

const V2_MIN_PINCH_SCALE: f32 = 0.5;
const V2_MAX_PINCH_SCALE: f32 = 4.0;
const V2_ZOOM_STEP: f32 = 1.25;
const V2_WHEEL_ZOOM_STEP: f32 = 1.1;
const V2_MAX_CONSECUTIVE_REATTACH: u32 = 3;
const V2_INITIAL_CREDITS: u32 = 2;

#[derive(Deserialize)]
struct FontAsset {
    path: String,
}

struct Frame {
    scene: Vec<u8>,
    seq: u32,
    partial: bool,
    width: u16,
    height: u16,
    x: i32,
    y: i32,
    base: i32,
}

#[derive(Clone, Copy)]
struct SceneStreamOptions {
    mode: Mode,
    cell: AnsiCell,
    fps: u8,
    allow_partial: bool,
}

struct DisplaySize {
    cell_w: f64,
    cell_h: f64,
    cols: u16,
    rows: u16,
}

#[derive(Clone, Copy)]
struct AnsiCell {
    w: u16,
    h: u16,
}

impl AnsiCell {
    fn new(size: &DisplaySize) -> Self {
        let zoom = if size.cell_h >= ANSI_ZOOM_CELL_HEIGHT_PX {
            ANSI_ZOOM_FACTOR
        } else {
            1.0
        };
        let page_rows = size.rows.saturating_sub(DEBUG_BAR_ROWS).max(1);
        let fit = |px: f64, cells: u16, min: u16, max: u16| {
            let min_cell = min.div_ceil(cells.max(1));
            (px / zoom).round().clamp(
                f64::from(min_cell),
                f64::from(
                    NOMINAL_MAX_ANSI_CELL_PIXELS
                        .min(max / cells.max(1))
                        .max(min_cell),
                ),
            ) as u16
        };
        Self {
            w: fit(
                size.cell_w,
                size.cols,
                MIN_VIEWPORT_WIDTH,
                MAX_VIEWPORT_WIDTH,
            ),
            h: fit(
                size.cell_h,
                page_rows,
                MIN_VIEWPORT_HEIGHT,
                MAX_VIEWPORT_HEIGHT,
            ),
        }
    }

    fn viewport(self, size: &DisplaySize) -> (u16, u16) {
        (
            size.cols
                .saturating_mul(self.w)
                .clamp(MIN_VIEWPORT_WIDTH, MAX_VIEWPORT_WIDTH),
            size.rows
                .saturating_sub(DEBUG_BAR_ROWS)
                .max(1)
                .saturating_mul(self.h)
                .clamp(MIN_VIEWPORT_HEIGHT, MAX_VIEWPORT_HEIGHT),
        )
    }
}

struct ResizeSync {
    awaiting: bool,
    sent_at: Instant,
}

#[derive(Default)]
struct DebugBar {
    visible: bool,
    painted_at: VecDeque<Instant>,
    mode: Mode,
    accounted_bytes: Option<u64>,
}

impl DebugBar {
    fn painted(&mut self) {
        self.discard_expired_timestamps();
        self.painted_at.push_back(Instant::now());
    }

    fn fps(&mut self) -> usize {
        self.discard_expired_timestamps();
        self.painted_at.len()
    }

    fn discard_expired_timestamps(&mut self) {
        while self
            .painted_at
            .front()
            .is_some_and(|at| at.elapsed() > FPS_WINDOW)
        {
            self.painted_at.pop_front();
        }
    }

    fn line(&mut self, wire_bytes: u64, frames: u64, w: u16, h: u16) -> String {
        let wire = if wire_bytes >= BYTES_PER_MIB {
            format!("{:.1} MiB", wire_bytes as f64 / BYTES_PER_MIB as f64)
        } else {
            format!("{:.1} KiB", wire_bytes as f64 / BYTES_PER_KIB)
        };
        format!(
            " FPS {} | wire {} | acct {} | mode {} | frames {} | {}x{}",
            self.fps(),
            wire,
            self.accounted_bytes
                .map_or("--".to_owned(), |bytes| format!(
                    "{:.1}MiB",
                    bytes as f64 / BYTES_PER_MIB as f64
                )),
            self.mode.slug(),
            frames,
            w,
            h
        )
    }

    fn paint(&mut self, wire_bytes: u64, frames: u64, w: u16, h: u16) -> io::Result<()> {
        if !self.visible {
            return Ok(());
        }
        let (cols, rows) = terminal::size()?;
        if rows <= DEBUG_BAR_ROWS {
            return Ok(());
        }
        let mut line = self.line(wire_bytes, frames, w, h);
        line.truncate(usize::from(cols));
        let line = format!("{line:<width$}", width = usize::from(cols));
        let mut out = io::stdout().lock();
        write!(
            out,
            "\x1b7\x1b[{};1H\x1b[?7l\x1b[48;5;236m\x1b[97m{}\x1b[0m\x1b[?7h\x1b8",
            rows, line
        )?;
        out.flush()
    }

    fn clear(&self) -> io::Result<()> {
        let (_, rows) = terminal::size()?;
        if rows < 2 {
            return Ok(());
        }
        let mut out = io::stdout().lock();
        write!(out, "\x1b7\x1b[{};1H\x1b[0m\x1b[2K\x1b8", rows)?;
        out.flush()
    }
}

#[derive(Default)]
struct KittyImages {
    displayed: Option<u32>,
    local_files: bool,
    raw_files: bool,
    temp_dir: Option<PathBuf>,
    file_seq: u64,
    last_bytes: u64,
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    if !dir.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "temporary frame directory must be absolute",
        ));
    }
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)
}

impl KittyImages {
    fn temp_file(&mut self, pixels: &[u8], rgba: bool) -> io::Result<PathBuf> {
        if self.temp_dir.is_none() {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "tty-graphics-protocol-parawing-{}-{nonce}",
                std::process::id()
            ));
            create_private_dir(&dir)?;
            self.temp_dir = Some(dir);
        }
        self.file_seq += 1;
        let path = self
            .temp_dir
            .as_ref()
            .expect("temp directory created above")
            .join(format!(
                "{}.{}",
                self.file_seq,
                if rgba { "rgba" } else { "png" }
            ));
        write_private_file(&path, pixels)?;
        Ok(path)
    }
}

impl Drop for KittyImages {
    fn drop(&mut self) {
        if let Some(dir) = &self.temp_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl ResizeSync {
    fn new() -> Self {
        Self {
            awaiting: false,
            sent_at: Instant::now(),
        }
    }

    fn sent(&mut self) {
        self.awaiting = true;
        self.sent_at = Instant::now();
    }

    fn painted(&mut self, frame: &Frame) {
        // A resize stays pending until a full frame for the requested viewport arrives.
        if !frame.partial {
            self.awaiting = false;
        }
    }

    fn retry_due(&self) -> bool {
        self.awaiting && self.sent_at.elapsed() >= RESIZE_RETRY_INTERVAL
    }
}

enum ReplayResult {
    Skipped,
    MissingResources(Vec<u8>),
    Painted,
}

struct ReplayState {
    cell: AnsiCell,
    painted_seq: Option<u32>,
    pending: Option<Frame>,
    resize_sync: ResizeSync,
    kitty_images: KittyImages,
    debug: DebugBar,
    frames: u64,
    wire_bytes: u64,
    terminal_bytes: u64,
    raster_time: Duration,
    retained_frames: bool,
}

impl ReplayState {
    fn new(mode: Mode, cell: AnsiCell, kitty_images: KittyImages) -> Self {
        Self {
            cell,
            painted_seq: None,
            pending: None,
            resize_sync: ResizeSync::new(),
            kitty_images,
            debug: DebugBar {
                mode,
                ..DebugBar::default()
            },
            frames: 0,
            wire_bytes: 0,
            terminal_bytes: 0,
            raster_time: Duration::ZERO,
            retained_frames: false,
        }
    }

    fn paint_pending(
        &mut self,
        raster: &mut Raster,
        w: u16,
        h: u16,
        display: bool,
        size: &DisplaySize,
    ) -> Result<()> {
        if let Some(frame) = self.pending.take() {
            self.paint(raster, &frame, w, h, display, size)?;
        }
        Ok(())
    }

    fn paint(
        &mut self,
        raster: &mut Raster,
        frame: &Frame,
        w: u16,
        h: u16,
        display: bool,
        size: &DisplaySize,
    ) -> Result<ReplayResult> {
        if !can_paint(frame, self.painted_seq, w, h) {
            return Ok(ReplayResult::Skipped);
        }
        if frame.partial && (self.debug.mode != Mode::Kitty || !self.retained_frames) {
            return Ok(ReplayResult::Skipped);
        }

        let missing = raster.run(OP_SCENE_MISSING_RESOURCES, &frame.scene)?;
        if !missing.starts_with(&NO_MISSING_RESOURCES) {
            return Ok(ReplayResult::MissingResources(missing));
        }

        let started = Instant::now();
        let is_ansi = self.debug.mode == Mode::Ansi;
        let output = if is_ansi {
            render_ansi(raster, frame, size, self.cell)?
        } else {
            render(
                raster,
                frame,
                w,
                h,
                self.kitty_images.raw_files,
                self.retained_frames,
            )?
        };
        if output.is_empty() {
            // A failed composite drops its retained base. Reject subsequent patches
            // until a full frame establishes both the local and server baselines.
            self.painted_seq = None;
            return Ok(ReplayResult::Skipped);
        }
        self.raster_time += started.elapsed();
        if display {
            if is_ansi {
                display_ansi(&output)?;
            } else {
                // The rasterizer composites server patches locally. Ghostty needs
                // a complete image and does not implement Kitty's a=f patches.
                kitty(&output, &mut self.kitty_images, self.debug.visible)?;
            }
        }
        self.terminal_bytes += if is_ansi {
            output.len() as u64
        } else if display {
            self.kitty_images.last_bytes
        } else {
            output.len().div_ceil(BASE64_INPUT_BYTES_PER_QUANTUM) as u64
                * BASE64_OUTPUT_BYTES_PER_QUANTUM
        };
        self.painted_seq = Some(frame.seq);
        self.frames += 1;
        self.debug.painted();
        self.debug.paint(self.wire_bytes, self.frames, w, h)?;
        self.resize_sync.painted(frame);
        Ok(ReplayResult::Painted)
    }
}

impl DisplaySize {
    fn new() -> Self {
        let window = terminal::window_size().ok();
        let (cols, rows) = window
            .as_ref()
            .map_or((100, 35), |size| (size.columns, size.rows));
        let (reported_w, reported_h) = window
            .as_ref()
            .map_or((0, 0), |size| (size.width, size.height));
        let (cell_w, cell_h) = if reported_w > 0 && reported_h > 0 {
            (
                f64::from(reported_w) / f64::from(cols.max(1)),
                f64::from(reported_h) / f64::from(rows.max(1)),
            )
        } else {
            (
                f64::from(ANSI_DEFAULT_CELL_WIDTH_PX),
                f64::from(ANSI_DEFAULT_CELL_HEIGHT_PX),
            )
        };
        Self {
            cell_w,
            cell_h,
            cols,
            rows,
        }
    }

    fn pixels(&self, debug: bool) -> (u16, u16) {
        let zoom = if self.cell_h >= ANSI_ZOOM_CELL_HEIGHT_PX {
            ANSI_ZOOM_FACTOR
        } else {
            1.0
        };
        let w = (f64::from(self.cols) * self.cell_w / zoom)
            .round()
            .min(f64::from(u16::MAX)) as u16;
        let h = (f64::from(self.rows - u16::from(debug && self.rows > 1)) * self.cell_h / zoom)
            .round()
            .min(f64::from(u16::MAX)) as u16;
        viewport_size(self.cols, self.rows, w, h)
    }

    fn resize(&mut self, cols: u16, rows: u16, debug: bool) -> (u16, u16) {
        self.cols = cols;
        self.rows = rows;
        self.pixels(debug)
    }
}

fn viewport_size(cols: u16, rows: u16, width: u16, height: u16) -> (u16, u16) {
    let w = f64::from(if width > 0 {
        width
    } else {
        cols.saturating_mul(ANSI_DEFAULT_CELL_WIDTH_PX)
    });
    let h = f64::from(if height > 0 {
        height
    } else {
        rows.saturating_mul(ANSI_DEFAULT_CELL_HEIGHT_PX)
    });
    let max_scale = (f64::from(MAX_VIEWPORT_WIDTH) / w.max(1.0))
        .min(f64::from(MAX_VIEWPORT_HEIGHT) / h.max(1.0));
    let min_scale = (f64::from(MIN_VIEWPORT_WIDTH) / w.max(1.0))
        .max(f64::from(MIN_VIEWPORT_HEIGHT) / h.max(1.0));
    let scale = if min_scale <= max_scale {
        min_scale.max(1.0).min(max_scale)
    } else {
        max_scale.min(1.0)
    };
    (
        (w * scale)
            .round()
            .clamp(f64::from(MIN_VIEWPORT_WIDTH), f64::from(MAX_VIEWPORT_WIDTH)) as u16,
        (h * scale).round().clamp(
            f64::from(MIN_VIEWPORT_HEIGHT),
            f64::from(MAX_VIEWPORT_HEIGHT),
        ) as u16,
    )
}

fn kitty_to(
    out: &mut impl Write,
    output: &[u8],
    cols: u16,
    rows: Option<u16>,
    images: &mut KittyImages,
    rgba: bool,
) -> io::Result<()> {
    let id = if images.displayed == Some(1) { 2 } else { 1 };
    write!(out, "\x1b[1;1H")?;
    let (pixels, format) = if rgba {
        let header = output
            .get(..RGBA_HEADER_BYTES)
            .ok_or(io::ErrorKind::InvalidData)?;
        let width = u32::from_le_bytes(header[..4].try_into().expect("eight-byte RGBA header"));
        let height = u32::from_le_bytes(header[4..].try_into().expect("eight-byte RGBA header"));
        if width == 0
            || height == 0
            || usize::try_from(u64::from(width) * u64::from(height) * 4).ok()
                != Some(output.len() - RGBA_HEADER_BYTES)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        (
            &output[RGBA_HEADER_BYTES..],
            format!("f=32,s={width},v={height}"),
        )
    } else {
        (output, "f=100".to_owned())
    };
    let placement = if let Some(rows) = rows {
        format!("a=T,{format},i={id},q=1,C=1,c={cols},r={rows}")
    } else {
        format!("a=T,{format},i={id},q=1,C=1,c={cols}")
    };
    if images.local_files {
        if let Ok(path) = images.temp_file(pixels, rgba) {
            let path = path.to_string_lossy();
            kitty_transmit_to(out, path.as_bytes(), &format!("{placement},t=t"))?;
            images.last_bytes = path.len().div_ceil(BASE64_INPUT_BYTES_PER_QUANTUM) as u64
                * BASE64_OUTPUT_BYTES_PER_QUANTUM;
        } else {
            kitty_transmit_to(out, pixels, &placement)?;
            images.last_bytes = pixels.len().div_ceil(BASE64_INPUT_BYTES_PER_QUANTUM) as u64
                * BASE64_OUTPUT_BYTES_PER_QUANTUM;
        }
    } else {
        kitty_transmit_to(out, pixels, &placement)?;
        images.last_bytes = pixels.len().div_ceil(BASE64_INPUT_BYTES_PER_QUANTUM) as u64
            * BASE64_OUTPUT_BYTES_PER_QUANTUM;
    }
    if let Some(old) = images.displayed {
        write!(out, "\x1b_Ga=d,d=I,i={old},q=1;\x1b\\")?;
    }
    out.flush()?;
    images.displayed = Some(id);
    Ok(())
}

fn kitty_transmit_to(out: &mut impl Write, payload: &[u8], first: &str) -> io::Result<()> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    for (chunk_index, chunk) in encoded.as_bytes().chunks(KITTY_CHUNK_BYTES).enumerate() {
        let more = if (chunk_index + 1) * KITTY_CHUNK_BYTES < encoded.len() {
            1
        } else {
            0
        };
        if chunk_index == 0 {
            write!(out, "\x1b_G{first},m={more};")?;
        } else {
            // q=1 suppresses success replies; q=2 suppresses errors instead.
            // Continuation chunks may specify their own response policy.
            write!(out, "\x1b_Gm={more},q=1;")?;
        }
        out.write_all(chunk)?;
        out.write_all(b"\x1b\\")?;
    }
    Ok(())
}

fn intersects_viewport(frame: &Frame, w: u16, h: u16) -> bool {
    let x = i64::from(frame.x);
    let y = i64::from(frame.y);
    frame.width > 0
        && frame.height > 0
        && x < i64::from(w)
        && y < i64::from(h)
        && x + i64::from(frame.width) > 0
        && y + i64::from(frame.height) > 0
}

fn kitty(output: &[u8], images: &mut KittyImages, debug: bool) -> io::Result<()> {
    let (cols, rows) = terminal::size()?;
    let rgba = images.raw_files;
    kitty_to(
        &mut io::stdout().lock(),
        output,
        cols,
        debug.then_some(rows.saturating_sub(DEBUG_BAR_ROWS).max(1)),
        images,
        rgba,
    )
}

fn display_ansi(bytes: &[u8]) -> io::Result<()> {
    let text = bytes.strip_suffix(b"\r\n").unwrap_or(bytes);
    let mut out = io::stdout().lock();
    out.write_all(b"\x1b[1;1H")?;
    out.write_all(text)?;
    out.flush()
}

fn resize_view(
    size: &mut DisplaySize,
    cols: u16,
    rows: u16,
    debug: bool,
    mode: Mode,
    cell: AnsiCell,
) -> (u16, u16) {
    if mode == Mode::Kitty {
        size.resize(cols, rows, debug)
    } else {
        size.cols = cols;
        size.rows = rows;
        cell.viewport(size)
    }
}

fn key_message(
    key: event::KeyEvent,
    input_seq: Option<u32>,
) -> Option<(&'static str, serde_json::Value)> {
    let modifiers = (if key.modifiers.contains(KeyModifiers::ALT) {
        CDP_ALT_MODIFIER
    } else {
        0
    }) | (if key.modifiers.contains(KeyModifiers::CONTROL) {
        CDP_CONTROL_MODIFIER
    } else {
        0
    }) | (if key.modifiers.contains(KeyModifiers::SUPER) {
        CDP_META_MODIFIER
    } else {
        0
    }) | (if key.modifiers.contains(KeyModifiers::SHIFT) {
        CDP_SHIFT_MODIFIER
    } else {
        0
    });
    let (name, code, virtual_key_code, text) = match key.code {
        KeyCode::Char(c) => (
            c.to_string(),
            format!("Key{}", c.to_ascii_uppercase()),
            u32::from(c.to_ascii_uppercase()),
            c.to_string(),
        ),
        KeyCode::Enter => ("Enter".into(), "Enter".into(), 13, "\r".into()),
        KeyCode::Backspace => ("Backspace".into(), "Backspace".into(), 8, "".into()),
        KeyCode::Tab | KeyCode::BackTab => ("Tab".into(), "Tab".into(), 9, "".into()),
        KeyCode::Esc => ("Escape".into(), "Escape".into(), 27, "".into()),
        KeyCode::Up => ("ArrowUp".into(), "ArrowUp".into(), 38, "".into()),
        KeyCode::Down => ("ArrowDown".into(), "ArrowDown".into(), 40, "".into()),
        KeyCode::Left => ("ArrowLeft".into(), "ArrowLeft".into(), 37, "".into()),
        KeyCode::Right => ("ArrowRight".into(), "ArrowRight".into(), 39, "".into()),
        KeyCode::PageUp => ("PageUp".into(), "PageUp".into(), 33, "".into()),
        KeyCode::PageDown => ("PageDown".into(), "PageDown".into(), 34, "".into()),
        _ => return None,
    };
    let kind = if key.kind == KeyEventKind::Release {
        "keyUp"
    } else {
        "rawKeyDown"
    };
    let text = if modifiers & TEXT_SUPPRESSING_MODIFIERS != 0 {
        ""
    } else {
        text.as_str()
    };
    let mut params = serde_json::json!({
        "type": kind,
        "key": name,
        "code": code,
        "windowsVirtualKeyCode": virtual_key_code,
        "text": text,
        "modifiers": modifiers,
    });
    if let (Some(seq), Some(obj)) = (input_seq, params.as_object_mut()) {
        obj.insert("_parawingInputSeq".to_string(), serde_json::json!(seq));
    }
    Some(("Input.dispatchKeyEvent", params))
}

fn input_event(
    ev: Event,
    w: u16,
    h: u16,
    grid: Option<(u16, u16)>,
    page_rows: Option<u16>,
    mouse_down: &mut bool,
) -> Option<(&'static str, serde_json::Value)> {
    match ev {
        Event::Key(key) => key_message(key, None),
        Event::Mouse(mouse) => {
            let (cols, rows) = grid?;
            let rows = page_rows.unwrap_or(rows);
            if mouse.row >= rows {
                return None;
            }
            let x = u32::from(mouse.column) * u32::from(w) / u32::from(cols.max(1));
            let y = u32::from(mouse.row) * u32::from(h) / u32::from(rows.max(1));
            let params = match mouse.kind {
                MouseEventKind::ScrollDown => serde_json::json!({
                    "type": "mouseWheel", "x": x, "y": y,
                    "deltaX": 0, "deltaY": MOUSE_WHEEL_DELTA,
                }),
                MouseEventKind::ScrollUp => serde_json::json!({
                    "type": "mouseWheel", "x": x, "y": y,
                    "deltaX": 0, "deltaY": -MOUSE_WHEEL_DELTA,
                }),
                MouseEventKind::Down(_) => {
                    *mouse_down = true;
                    serde_json::json!({
                        "type": "mousePressed", "x": x, "y": y,
                        "button": "left", "buttons": 1, "clickCount": 1,
                    })
                }
                MouseEventKind::Up(_) => {
                    *mouse_down = false;
                    serde_json::json!({
                        "type": "mouseReleased", "x": x, "y": y,
                        "button": "left", "buttons": 0, "clickCount": 1,
                    })
                }
                MouseEventKind::Drag(_) | MouseEventKind::Moved => serde_json::json!({
                    "type": "mouseMoved", "x": x, "y": y,
                    "button": if *mouse_down { "left" } else { "none" },
                    "buttons": if *mouse_down { 1 } else { 0 }, "clickCount": 1,
                }),
                _ => return None,
            };
            Some(("Input.dispatchMouseEvent", params))
        }
        _ => None,
    }
}

async fn cdp_send(
    ws: &mut CdpSocket,
    id: &mut u64,
    method: &str,
    params: serde_json::Value,
    session: Option<&str>,
) -> Result<u64> {
    *id += 1;
    let current = *id;
    let text = serde_json::json!({
        "id": current, "method": method, "params": params, "sessionId": session,
    })
    .to_string();
    tokio::time::timeout(CDP_REPLY_TIMEOUT, ws.send(Message::Text(text.into())))
        .await
        .map_err(|_| SERVER_UNRESPONSIVE)??;
    Ok(current)
}

pub(crate) async fn cdp_call(
    ws: &mut CdpSocket,
    id: &mut u64,
    method: &str,
    params: serde_json::Value,
    session: Option<&str>,
    queued: &mut VecDeque<Message>,
) -> Result<serde_json::Value> {
    let sent = cdp_send(ws, id, method, params, session).await?;
    let deadline = tokio::time::Instant::now() + CDP_REPLY_TIMEOUT;
    while let Some(message) = tokio::time::timeout_at(deadline, ws.next())
        .await
        .map_err(|_| SERVER_UNRESPONSIVE)?
    {
        let message = message?;
        if let Message::Text(text) = &message {
            let reply: serde_json::Value = serde_json::from_str(text)?;
            if reply["id"].as_u64() == Some(sent) {
                if !reply["error"].is_null() {
                    return Err(format!("{method}: {}", reply["error"]).into());
                }
                return Ok(reply["result"].clone());
            }
        }
        queued.push_back(message);
    }
    Err(CONNECTION_LOST.into())
}

fn acknowledge_probe(
    reply: &serde_json::Value,
    pending: &mut Option<(u64, Instant)>,
) -> Result<()> {
    if pending.is_some_and(|(id, _)| reply["id"].as_u64() == Some(id)) {
        if !reply["error"].is_null() {
            return Err(format!(
                "Parawing server rejected the liveness check: {}",
                reply["error"]
            )
            .into());
        }
        *pending = None;
    }
    Ok(())
}

fn scene_stall_deadline(last: Option<Instant>, heartbeat: bool) -> Option<tokio::time::Instant> {
    last.filter(|_| heartbeat)
        .map(|at| (at + SCENE_STALL_TIMEOUT).into())
}

async fn cdp_resize(
    ws: &mut CdpSocket,
    id: &mut u64,
    session: &str,
    w: u16,
    h: u16,
    options: SceneStreamOptions,
    queued: &mut VecDeque<Message>,
) -> Result<bool> {
    cdp_call(
        ws,
        id,
        "Emulation.setDeviceMetricsOverride",
        serde_json::json!({
            "width": w, "height": h, "deviceScaleFactor": 1, "mobile": false,
        }),
        Some(session),
        queued,
    )
    .await?;
    let started = cdp_call(
        ws,
        id,
        "Parawing.startSceneStream",
        serde_json::json!({
            "width": w, "height": h, "fps": options.fps,
            "text": options.mode == Mode::Ansi,
            "allowPartial": options.allow_partial,
            "terminal": true, "cellW": options.cell.w, "cellH": options.cell.h,
        }),
        Some(session),
        queued,
    )
    .await?;
    Ok(started["heartbeatMs"].as_u64() == Some(SCENE_HEARTBEAT_MS))
}

async fn cdp_ack(
    ws: &mut CdpSocket,
    id: &mut u64,
    session: &str,
    seq: u32,
    painted: bool,
) -> Result<()> {
    cdp_send(
        ws,
        id,
        "Parawing.sceneFrameAck",
        serde_json::json!({
            "seq": seq, "painted": painted,
        }),
        Some(session),
    )
    .await?;
    Ok(())
}

fn keyboard_flags() -> event::KeyboardEnhancementFlags {
    event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
        | event::KeyboardEnhancementFlags::REPORT_EVENT_TYPES
        | event::KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES
}

struct Terminal {
    keyboard_enhanced: bool,
}
impl Terminal {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        let mut terminal = Self {
            keyboard_enhanced: false,
        };
        execute!(
            io::stdout(),
            terminal::EnterAlternateScreen,
            event::EnableMouseCapture,
            cursor::Hide
        )?;
        execute!(
            io::stdout(),
            event::PushKeyboardEnhancementFlags(keyboard_flags())
        )?;
        terminal.keyboard_enhanced = true;
        Ok(terminal)
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        if self.keyboard_enhanced {
            let _ = execute!(io::stdout(), event::PopKeyboardEnhancementFlags);
        }
        let _ = execute!(
            io::stdout(),
            event::DisableMouseCapture,
            cursor::Show,
            terminal::LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

/// Validated font paths awaiting a fetch, deduplicated per path: one put resolves every hash
/// aliased to a path, so the snapshot's duplicate hashes must not become repeated loads.
pub(crate) fn queue_pending_fonts(raster: &mut Raster) -> Result<VecDeque<String>> {
    let pending = raster.run(OP_PENDING_FONTS, &[])?;
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    for asset in serde_json::from_slice::<Vec<FontAsset>>(&pending)? {
        if !asset.path.starts_with("/fonts/") || asset.path.contains("..") {
            continue;
        }
        if seen.insert(asset.path.clone()) {
            queue.push_back(asset.path);
        }
    }
    Ok(queue)
}

pub(crate) async fn load_font(
    cache: &FontCache,
    raster: &mut Raster,
    diagnostics: &mut Diagnostics,
    path: &str,
) -> Result<()> {
    let bytes = cache.get(path, diagnostics).await?;
    let path_len = u32::try_from(path.len())?;
    diagnostics.log(format!("loaded {} font bytes for {path}", bytes.len()));
    let mut data = Vec::with_capacity(4 + path.len() + bytes.len());
    data.extend_from_slice(&path_len.to_le_bytes());
    data.extend_from_slice(path.as_bytes());
    data.extend_from_slice(&bytes);
    raster.run(OP_PUT_FONT, &data)?;
    Ok(())
}

fn retire_unavailable_images(raster: &mut Raster) -> Result<()> {
    let pending: Vec<String> = serde_json::from_slice(&raster.run(OP_PENDING_IMAGES, &[])?)?;
    for key in pending {
        raster.run(OP_ABANDON_IMAGE, key.as_bytes())?;
    }
    Ok(())
}

fn parse_frame(bytes: &[u8]) -> Result<Frame> {
    if bytes.len() < FRAME_HEADER_BYTES {
        return Err("short RBI frame".into());
    }
    let partial = bytes[0] == PARTIAL_MESSAGE;
    if partial && bytes.len() < PARTIAL_FRAME_HEADER_BYTES {
        return Err("short partial frame".into());
    }
    let (x, y, base, offset) = if partial {
        (
            i32::from_le_bytes(bytes[11..15].try_into()?),
            i32::from_le_bytes(bytes[15..19].try_into()?),
            i32::from_le_bytes(bytes[27..31].try_into()?),
            PARTIAL_FRAME_HEADER_BYTES,
        )
    } else {
        (0, 0, NO_BASE_SEQUENCE, FRAME_HEADER_BYTES)
    };
    Ok(Frame {
        scene: bytes[offset..].to_vec(),
        seq: u32::from_le_bytes(bytes[3..7].try_into()?),
        partial,
        width: u16::from_le_bytes(bytes[7..9].try_into()?),
        height: u16::from_le_bytes(bytes[9..11].try_into()?),
        x,
        y,
        base,
    })
}

fn can_paint(frame: &Frame, painted_seq: Option<u32>, w: u16, h: u16) -> bool {
    if painted_seq.is_some_and(|painted_seq| frame.seq < painted_seq) {
        return false;
    }
    // A resize can land between the server's envelope snapshot and
    // the scene record. Trust the raster's own viewport as well as
    // the envelope before letting Ghostty scale it to the window.
    let dimensions_match = frame.scene.get(8..16).is_some_and(|dims| {
        (
            u32::from_le_bytes(dims[..4].try_into().expect("four-byte scene width")),
            u32::from_le_bytes(dims[4..].try_into().expect("four-byte scene height")),
        ) == (u32::from(frame.width), u32::from(frame.height))
    });
    dimensions_match
        && if frame.partial {
            painted_seq.is_some_and(|seq| frame.base.to_le_bytes() == seq.to_le_bytes())
                && intersects_viewport(frame, w, h)
        } else {
            (frame.width, frame.height) == (w, h)
        }
}

fn scene_version(scene: &[u8]) -> Option<u32> {
    scene
        .get(4..8)
        .and_then(|bytes| bytes.try_into().ok().map(u32::from_le_bytes))
}

/// Run a browser session in the terminal using a browser-level CDP WebSocket.
struct V2PlayArgs {
    url: String,
    session: String,
    endpoint: V2Endpoint,
    mode: Mode,
    seconds: Option<Duration>,
    display: bool,
    fps: u8,
    wasm_bytes: Vec<u8>,
    raw_files: bool,
    w: u16,
    h: u16,
    cell: AnsiCell,
    display_size: Option<DisplaySize>,
    fallback_size: DisplaySize,
}

struct V2RuntimeState {
    host: CompositorV2Host,
    kitty_images: KittyImages,
    debug: DebugBar,
    start: Instant,
    display: bool,
    mode: Mode,
    session: String,
    endpoint: V2Endpoint,
    fps: u8,
    w: u16,
    h: u16,
    raw_files: bool,
    has_frame: bool,
    mouse_down: bool,
    drag_anchor: Option<(f32, f32)>,
    last_copied_text: Option<String>,
    last_pointer: (f32, f32),
    active_editable_node: Option<u64>,
    key_seq: u32,
    ptr_seq: u32,
    pinch_scale: f32,
    pan_x: f32,
    pan_y: f32,
    last_vel: (f32, f32),
    last_frame_seq: u32,
    consecutive_reattaches: u32,
    frames: u64,
    wire_bytes: u64,
    size: DisplaySize,
    cell: AnsiCell,
}

async fn attach_page_target(
    ws: &mut CdpSocket,
    next_id: &mut u64,
    queued: &mut VecDeque<Message>,
) -> Result<(String, String)> {
    let targets = cdp_call(
        ws,
        next_id,
        "Target.getTargets",
        serde_json::json!({}),
        None,
        queued,
    )
    .await?;
    let existing_page = targets["targetInfos"]
        .as_array()
        .and_then(|targets| targets.iter().find(|target| target["type"] == "page"))
        .and_then(|page| page["targetId"].as_str())
        .map(str::to_owned);
    let page_id = match existing_page {
        Some(id) => id,
        None => cdp_call(
            ws,
            next_id,
            "Target.createTarget",
            serde_json::json!({"url": "about:blank"}),
            None,
            queued,
        )
        .await?["targetId"]
            .as_str()
            .ok_or("CDP target creation failed")?
            .to_owned(),
    };
    let attached = cdp_call(
        ws,
        next_id,
        "Target.attachToTarget",
        serde_json::json!({"targetId": page_id, "flatten": true}),
        None,
        queued,
    )
    .await?;
    let session = attached["sessionId"]
        .as_str()
        .ok_or("CDP attach failed")?
        .to_owned();
    Ok((page_id, session))
}

async fn connect_v2_socket(endpoint: &V2Endpoint, ws_path: &str) -> Result<CdpSocket> {
    let base = endpoint.origin_ws.trim_end_matches('/');
    let path = if ws_path.starts_with('/') {
        ws_path.to_owned()
    } else {
        format!("/{ws_path}")
    };
    let full_url = format!("{base}{path}");
    let mut request = full_url.into_client_request()?;
    for (name, value) in &endpoint.headers {
        let header_name =
            tokio_tungstenite::tungstenite::http::header::HeaderName::from_bytes(name.as_bytes())?;
        let header_val =
            tokio_tungstenite::tungstenite::http::header::HeaderValue::from_str(value)?;
        request.headers_mut().insert(header_name, header_val);
    }
    let (socket, _) = tokio_tungstenite::connect_async(request).await?;
    Ok(socket)
}

fn rgba_to_ansi_halfblocks(rgba: &[u8]) -> Vec<u8> {
    if rgba.len() < RGBA_HEADER_BYTES {
        return Vec::new();
    }
    let w = u32::from_le_bytes(rgba[..4].try_into().unwrap_or([0; 4])) as usize;
    let h = u32::from_le_bytes(rgba[4..8].try_into().unwrap_or([0; 4])) as usize;
    let pixels = &rgba[RGBA_HEADER_BYTES..];
    if w == 0 || h == 0 || pixels.len() < w * h * 4 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(w * h);
    let step_x = (w / 80).max(1);
    let step_y = ((h / 24).max(1)) * 2;
    let mut y = 0;
    while y + 1 < h {
        let mut x = 0;
        while x < w {
            let top = (y * w + x) * 4;
            let bot = ((y + 1) * w + x) * 4;
            let _ = write!(
                out,
                "\x1b[38;2;{};{};{};48;2;{};{};{}m▀",
                pixels[top],
                pixels[top + 1],
                pixels[top + 2],
                pixels[bot],
                pixels[bot + 1],
                pixels[bot + 2],
            );
            x += step_x;
        }
        out.extend_from_slice(b"\x1b[0m\r\n");
        y += step_y;
    }
    out
}

fn present_v2_frame(state: &mut V2RuntimeState) -> Result<()> {
    if !state.has_frame {
        return Ok(());
    }
    let t_ms = state.start.elapsed().as_secs_f64() * 1000.0;
    let is_ansi = state.mode == Mode::Ansi;
    let raw_rgba = is_ansi || state.raw_files;
    let output =
        state
            .host
            .composite(t_ms, state.pinch_scale, state.pan_x, state.pan_y, raw_rgba)?;
    if state.display {
        if is_ansi {
            let ansi = rgba_to_ansi_halfblocks(&output);
            if !ansi.is_empty() {
                display_ansi(&ansi)?;
            }
        } else {
            state.kitty_images.raw_files = raw_rgba;
            kitty(&output, &mut state.kitty_images, state.debug.visible)?;
        }
    }
    state.frames += 1;
    state.debug.painted();
    if state.debug.visible {
        state
            .debug
            .paint(state.wire_bytes, state.frames, state.w, state.h)?;
    }
    Ok(())
}

fn encode_osc52_copy(text: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    format!("\x1b]52;c;{b64}\x07")
}

fn emit_osc52_copy(state: &V2RuntimeState, text: &str) -> Result<()> {
    if text.is_empty() || !state.display {
        return Ok(());
    }
    let osc = encode_osc52_copy(text);
    let mut out = io::stdout().lock();
    out.write_all(osc.as_bytes())?;
    out.flush()?;
    Ok(())
}

fn apply_v2_zoom(state: &mut V2RuntimeState, factor: f32, anchor: (f32, f32)) -> Result<()> {
    let old_scale = state.pinch_scale.max(V2_MIN_PINCH_SCALE);
    let next_scale = (old_scale * factor).clamp(V2_MIN_PINCH_SCALE, V2_MAX_PINCH_SCALE);
    let inv_delta = (1.0 / old_scale) - (1.0 / next_scale);
    let max_pan_x = (f32::from(state.w) - f32::from(state.w) / next_scale).max(0.0);
    let max_pan_y = (f32::from(state.h) - f32::from(state.h) / next_scale).max(0.0);
    state.pan_x = (state.pan_x + anchor.0 * inv_delta).clamp(0.0, max_pan_x);
    state.pan_y = (state.pan_y + anchor.1 * inv_delta).clamp(0.0, max_pan_y);
    state.pinch_scale = next_scale;
    present_v2_frame(state)
}

fn reset_v2_zoom(state: &mut V2RuntimeState) -> Result<()> {
    state.pinch_scale = 1.0;
    state.pan_x = 0.0;
    state.pan_y = 0.0;
    present_v2_frame(state)
}

fn handle_v2_zoom_key(key: event::KeyEvent, state: &mut V2RuntimeState) -> Result<bool> {
    if key.kind != KeyEventKind::Press || !key.modifiers.contains(KeyModifiers::CONTROL) {
        return Ok(false);
    }
    let anchor = if state.last_pointer == (0.0, 0.0) {
        (f32::from(state.w) * 0.5, f32::from(state.h) * 0.5)
    } else {
        state.last_pointer
    };
    match key.code {
        KeyCode::Char('+') | KeyCode::Char('=') => {
            apply_v2_zoom(state, V2_ZOOM_STEP, anchor)?;
            Ok(true)
        }
        KeyCode::Char('-') | KeyCode::Char('_') => {
            apply_v2_zoom(state, 1.0 / V2_ZOOM_STEP, anchor)?;
            Ok(true)
        }
        KeyCode::Char('0') => {
            reset_v2_zoom(state)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn update_v2_drag_selection(state: &mut V2RuntimeState, pos: (f32, f32), t_ms: f64) -> Result<()> {
    let Some(anchor) = state.drag_anchor else {
        return Ok(());
    };
    let _ = state.host.select_text(anchor, pos, t_ms)?;
    present_v2_frame(state)
}

fn finalize_v2_drag_selection(
    state: &mut V2RuntimeState,
    end: (f32, f32),
    t_ms: f64,
) -> Result<()> {
    let Some(anchor) = state.drag_anchor.take() else {
        return Ok(());
    };
    if (anchor.0 - end.0).abs() <= 0.5 && (anchor.1 - end.1).abs() <= 0.5 {
        return Ok(());
    }
    let sel = state.host.select_text(anchor, end, t_ms)?;
    if !sel.text.is_empty() {
        state.last_copied_text = Some(sel.text.clone());
        emit_osc52_copy(state, &sel.text)?;
    }
    present_v2_frame(state)
}

async fn handle_v2_binary_message(
    state: &mut V2RuntimeState,
    v2_ws: &mut CdpSocket,
    bin: &[u8],
) -> Result<()> {
    state.wire_bytes += bin.len() as u64;
    let frame_seq = match decode_rbi_v2_packet(bin)? {
        DecodedRbiV2Packet::ReliableFrame {
            frame_seq, payload, ..
        } => {
            state.host.ingest_frame(&payload)?;
            state.has_frame = true;
            state.last_frame_seq = frame_seq;
            Some(frame_seq)
        }
        DecodedRbiV2Packet::DeltaResyncAck {
            resumed_from_seq,
            payload,
            ..
        } => {
            state.host.ingest_frame(&payload)?;
            state.has_frame = true;
            if resumed_from_seq > 0 {
                state.last_frame_seq = state.last_frame_seq.max(resumed_from_seq);
            }
            None
        }
        _ => None,
    };
    present_v2_frame(state)?;
    if let Some(seq) = frame_seq {
        let ack = encode_credit_grant_packet(1, seq);
        v2_ws.send(Message::Binary(ack.into())).await?;
    }
    Ok(())
}

async fn handle_v2_scroll(
    mouse: crossterm::event::MouseEvent,
    pos: (f32, f32),
    state: &mut V2RuntimeState,
    cdp_ws: &mut CdpSocket,
    v2_ws: &mut CdpSocket,
    next_id: &mut u64,
    session: &str,
) -> Result<()> {
    let down = matches!(mouse.kind, MouseEventKind::ScrollDown);
    if mouse.modifiers.contains(KeyModifiers::CONTROL) {
        let factor = if down {
            1.0 / V2_WHEEL_ZOOM_STEP
        } else {
            V2_WHEEL_ZOOM_STEP
        };
        return apply_v2_zoom(state, factor, pos);
    }
    let dy = if down {
        MOUSE_WHEEL_DELTA as f32
    } else {
        -(MOUSE_WHEEL_DELTA as f32)
    };
    let res = state
        .host
        .scroll_input(0, pos, (0.0, dy), (0.0, dy * 4.0), 1)?;
    if res.forwarded {
        cdp_send(
            cdp_ws,
            next_id,
            "Input.dispatchMouseEvent",
            serde_json::json!({ "type": "mouseWheel", "x": pos.0, "y": pos.1, "deltaX": 0, "deltaY": dy }),
            Some(session),
        )
        .await?;
        return Ok(());
    }
    state.last_vel = (0.0, dy * 4.0);
    let dgram = encode_scroll_datagram(res.seq, res.node_id, res.x, res.y, 0.0, dy * 4.0);
    v2_ws.send(Message::Binary(dgram.into())).await?;
    present_v2_frame(state)
}

async fn handle_v2_mouse_event(
    mouse: crossterm::event::MouseEvent,
    state: &mut V2RuntimeState,
    cdp_ws: &mut CdpSocket,
    v2_ws: &mut CdpSocket,
    next_id: &mut u64,
    session: &str,
    grid: Option<(u16, u16)>,
) -> Result<()> {
    let Some((cols, rows)) = grid else {
        return Ok(());
    };
    let x = f32::from(mouse.column) * f32::from(state.w) / f32::from(cols.max(1));
    let y = f32::from(mouse.row) * f32::from(state.h) / f32::from(rows.max(1));
    state.last_pointer = (x, y);
    let t_ms = state.start.elapsed().as_secs_f64() * 1000.0;
    match mouse.kind {
        MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
            handle_v2_scroll(mouse, (x, y), state, cdp_ws, v2_ws, next_id, session).await?;
        }
        MouseEventKind::Down(_) => {
            state.mouse_down = true;
            state.drag_anchor = Some((x, y));
            let hit = state.host.hit_test(x, y, t_ms)?;
            state.active_editable_node = hit.editable.then_some(hit.node_id);
            cdp_send(
                cdp_ws,
                next_id,
                "Input.dispatchMouseEvent",
                serde_json::json!({ "type": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1 }),
                Some(session),
            )
            .await?;
        }
        MouseEventKind::Up(_) => {
            state.mouse_down = false;
            finalize_v2_drag_selection(state, (x, y), t_ms)?;
            cdp_send(
                cdp_ws,
                next_id,
                "Input.dispatchMouseEvent",
                serde_json::json!({ "type": "mouseReleased", "x": x, "y": y, "button": "left", "buttons": 0, "clickCount": 1 }),
                Some(session),
            )
            .await?;
        }
        MouseEventKind::Drag(_) => {
            update_v2_drag_selection(state, (x, y), t_ms)?;
            let hit = state.host.hit_test(x, y, t_ms)?;
            if hit.forward_pointer_move {
                state.ptr_seq += 1;
                let dgram = encode_pointer_datagram(state.ptr_seq, x, y, 1);
                v2_ws.send(Message::Binary(dgram.into())).await?;
            }
        }
        MouseEventKind::Moved => {
            let hit = state.host.hit_test(x, y, t_ms)?;
            if hit.forward_pointer_move {
                state.ptr_seq += 1;
                let buttons = u8::from(state.mouse_down);
                let dgram = encode_pointer_datagram(state.ptr_seq, x, y, buttons);
                v2_ws.send(Message::Binary(dgram.into())).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_v2_input_event(
    ev: Event,
    state: &mut V2RuntimeState,
    cdp_ws: &mut CdpSocket,
    v2_ws: &mut CdpSocket,
    next_id: &mut u64,
    session: &str,
) -> Result<()> {
    if let Event::Mouse(mouse) = ev {
        let grid = terminal::size().ok();
        return handle_v2_mouse_event(mouse, state, cdp_ws, v2_ws, next_id, session, grid).await;
    }
    if let Event::Key(key) = ev {
        if handle_v2_zoom_key(key, state)? {
            return Ok(());
        }
        let mut predicted_seq = None;
        if let (KeyCode::Char(c), Some(node_id)) = (key.code, state.active_editable_node) {
            if key.kind == KeyEventKind::Press
                && !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
            {
                state.key_seq += 1;
                predicted_seq = Some(state.key_seq);
                let mut buf = [0u8; 4];
                let text = c.encode_utf8(&mut buf);
                let pred = state.host.predict_key(node_id, state.key_seq, text)?;
                if !pred.suppressed {
                    present_v2_frame(state)?;
                }
            }
        }
        if let Some((method, params)) = key_message(key, predicted_seq) {
            cdp_send(cdp_ws, next_id, method, params, Some(session)).await?;
        }
    }
    Ok(())
}

fn spawn_input_reader(
    display: bool,
    initial_grid: Option<(u16, u16)>,
) -> tokio::sync::mpsc::Receiver<Event> {
    let (tx, rx) = tokio::sync::mpsc::channel(INPUT_CHANNEL_CAPACITY);
    if !display {
        return rx;
    }
    std::thread::spawn(move || {
        let mut last_size = initial_grid;
        loop {
            match event::poll(INPUT_POLL_INTERVAL) {
                Ok(true) => {
                    if let Ok(ev) = event::read() {
                        if tx.blocking_send(ev).is_err() {
                            break;
                        }
                    }
                }
                Ok(false) => {}
                Err(_) => break,
            }
            if let Ok(size) = terminal::size() {
                if last_size != Some(size) {
                    last_size = Some(size);
                    if tx.blocking_send(Event::Resize(size.0, size.1)).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

enum V2WsStep {
    Continue,
    Reconnect,
}

async fn handle_v2_ws_event(
    event: Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>,
    state: &mut V2RuntimeState,
    v2_ws: &mut CdpSocket,
) -> Result<V2WsStep> {
    match event {
        Some(Ok(Message::Binary(bin))) => {
            state.consecutive_reattaches = 0;
            handle_v2_binary_message(state, v2_ws, &bin).await?;
            Ok(V2WsStep::Continue)
        }
        Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_) | Message::Text(_))) => {
            Ok(V2WsStep::Continue)
        }
        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => Ok(V2WsStep::Reconnect),
    }
}

async fn reattach_v2_socket(
    state: &mut V2RuntimeState,
    cdp_ws: &mut CdpSocket,
    next_id: &mut u64,
    queued: &mut VecDeque<Message>,
    diagnostics: &mut Diagnostics,
) -> Result<CdpSocket> {
    let (known, viewport) = if state.has_frame {
        let hashes = state.host.known_tile_hashes().unwrap_or_default();
        let vp = match state.host.metrics(0) {
            Ok(m) if m.vp_w > 0.0 && m.vp_h > 0.0 => [m.vp_x, m.vp_y, m.vp_w, m.vp_h],
            _ => [
                state.pan_x,
                state.pan_y,
                f32::from(state.w),
                f32::from(state.h),
            ],
        };
        (hashes, vp)
    } else {
        (
            Vec::new(),
            [
                state.pan_x,
                state.pan_y,
                f32::from(state.w),
                f32::from(state.h),
            ],
        )
    };
    let started = cdp_call(
        cdp_ws,
        next_id,
        "Parawing.startSceneStreamV2",
        serde_json::json!({ "width": state.w, "height": state.h, "fps": state.fps }),
        Some(&state.session),
        queued,
    )
    .await?;
    let ws_path = started["wsPath"]
        .as_str()
        .ok_or("Parawing.startSceneStreamV2 missing wsPath")?;
    let mut v2_ws = connect_v2_socket(&state.endpoint, ws_path).await?;
    let reattach = encode_reattach_packet(
        state.last_frame_seq,
        &known,
        viewport,
        [state.last_vel.0, state.last_vel.1],
    );
    v2_ws.send(Message::Binary(reattach.into())).await?;
    let credit = encode_credit_grant_packet(V2_INITIAL_CREDITS, state.last_frame_seq);
    v2_ws.send(Message::Binary(credit.into())).await?;
    diagnostics.log(format!(
        "reattached S7 /rbi/ws from seq {} with {} cached tiles",
        state.last_frame_seq,
        known.len(),
    ));
    Ok(v2_ws)
}

async fn try_reattach_v2_socket(
    state: &mut V2RuntimeState,
    v2_ws: &mut CdpSocket,
    ws: &mut CdpSocket,
    next_id: &mut u64,
    queued: &mut VecDeque<Message>,
    diagnostics: &mut Diagnostics,
) -> Result<bool> {
    if state.consecutive_reattaches >= V2_MAX_CONSECUTIVE_REATTACH {
        return Ok(false);
    }
    state.consecutive_reattaches += 1;
    *v2_ws = reattach_v2_socket(state, ws, next_id, queued, diagnostics).await?;
    Ok(true)
}

async fn play_v2(
    mut ws: CdpSocket,
    next_id: &mut u64,
    queued: &mut VecDeque<Message>,
    args: V2PlayArgs,
    diagnostics: &mut Diagnostics,
) -> PlaybackResult<()> {
    let host = CompositorV2Host::new(&args.wasm_bytes)?;
    cdp_call(
        &mut ws,
        next_id,
        "Emulation.setDeviceMetricsOverride",
        serde_json::json!({ "width": args.w, "height": args.h, "deviceScaleFactor": 1, "mobile": false }),
        Some(&args.session),
        queued,
    )
    .await?;
    let started = cdp_call(
        &mut ws,
        next_id,
        "Parawing.startSceneStreamV2",
        serde_json::json!({ "width": args.w, "height": args.h, "fps": args.fps }),
        Some(&args.session),
        queued,
    )
    .await?;
    let ws_path = started["wsPath"]
        .as_str()
        .ok_or("Parawing.startSceneStreamV2 missing wsPath")?;
    let mut v2_ws = connect_v2_socket(&args.endpoint, ws_path).await?;
    diagnostics.log(format!("connected S7 /rbi/ws stream at {ws_path}"));
    cdp_call(
        &mut ws,
        next_id,
        "Page.navigate",
        serde_json::json!({"url": args.url}),
        Some(&args.session),
        queued,
    )
    .await?;
    let credit = encode_credit_grant_packet(V2_INITIAL_CREDITS, 0);
    v2_ws.send(Message::Binary(credit.into())).await?;

    let _terminal = if args.display {
        Some(Terminal::enter()?)
    } else {
        None
    };
    diagnostics.display = args.display;
    let initial_grid = args.display_size.as_ref().map(|s| (s.cols, s.rows));
    let mut rx = spawn_input_reader(args.display, initial_grid);
    let size = args.display_size.unwrap_or(args.fallback_size);
    let session = args.session;
    let start = Instant::now();
    let deadline = args.seconds.map(|d| start + d);
    let mut state = V2RuntimeState {
        host,
        kitty_images: KittyImages::default(),
        debug: DebugBar {
            visible: args.display,
            mode: args.mode,
            ..DebugBar::default()
        },
        start,
        display: args.display,
        mode: args.mode,
        session: session.clone(),
        endpoint: args.endpoint,
        fps: args.fps,
        w: args.w,
        h: args.h,
        raw_files: args.raw_files,
        has_frame: false,
        mouse_down: false,
        drag_anchor: None,
        last_copied_text: None,
        last_pointer: (0.0, 0.0),
        active_editable_node: None,
        key_seq: 0,
        ptr_seq: 0,
        pinch_scale: 1.0,
        pan_x: 0.0,
        pan_y: 0.0,
        last_vel: (0.0, 0.0),
        last_frame_seq: 0,
        consecutive_reattaches: 0,
        frames: 0,
        wire_bytes: 0,
        size,
        cell: args.cell,
    };
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut fling_tick = tokio::time::interval(Duration::from_millis(16));
    fling_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        tokio::select! {
            biased;
            signal = &mut shutdown, if state.display => { signal?; break; }
            Some(ev) = rx.recv(), if state.display => {
                if matches!(&ev, Event::Key(k) if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL)) {
                    break;
                }
                if let Event::Resize(cols, rows) = ev {
                    let (cols, rows) = terminal::size().unwrap_or((cols, rows));
                    (state.w, state.h) = resize_view(&mut state.size, cols, rows, state.debug.visible, state.mode, state.cell);
                    let _ = cdp_send(&mut ws, next_id, "Emulation.setDeviceMetricsOverride",
                        serde_json::json!({ "width": state.w, "height": state.h, "deviceScaleFactor": 1, "mobile": false }),
                        Some(&session)).await;
                } else {
                    handle_v2_input_event(ev, &mut state, &mut ws, &mut v2_ws, next_id, &session).await?;
                }
            }
            event = v2_ws.next() => {
                if matches!(
                    handle_v2_ws_event(event, &mut state, &mut v2_ws).await?,
                    V2WsStep::Reconnect
                ) && !try_reattach_v2_socket(
                    &mut state, &mut v2_ws, &mut ws, next_id, queued, diagnostics,
                ).await? {
                    break;
                }
            }
            _ = ws.next() => {}
            _ = fling_tick.tick() => {
                if let Some(res) = state.host.step_fling(16.0)? {
                    state.last_vel = (state.last_vel.0 * 0.9, state.last_vel.1 * 0.9);
                    let dgram = encode_scroll_datagram(res.seq, res.node_id, res.x, res.y, 0.0, 0.0);
                    v2_ws.send(Message::Binary(dgram.into())).await?;
                    present_v2_frame(&mut state)?;
                }
            }
            _ = tokio::time::sleep(DEADLINE_POLL_INTERVAL), if deadline.is_some() => {}
        }
    }
    let _ = cdp_send(
        &mut ws,
        next_id,
        "Parawing.stopSceneStreamV2",
        serde_json::json!({}),
        Some(&session),
    )
    .await;
    if !state.display && args.seconds.is_some() {
        println!(
            "parawing-v2: frames={} wire_bytes={} width={} height={}",
            state.frames, state.wire_bytes, state.w, state.h
        );
    }
    Ok(())
}

/// Takes ownership of `ws`; connection, font-fetch, Wasm, and terminal errors are returned.
pub async fn play(
    mut ws: CdpSocket,
    opts: PlaybackOptions,
    font_source: FontSource,
) -> PlaybackResult<()> {
    let PlaybackOptions {
        url: target,
        seconds,
        display,
        debug: verbose,
        mode,
        fps,
        v2,
    } = opts;
    let mut diagnostics = Diagnostics::new(verbose);
    let font_cache = FontCache::new(font_source)?;
    diagnostics.log("CDP WebSocket connected");
    let mut next_id = 0;
    let mut queued = VecDeque::new();
    let (manifest, bytes) =
        scene_host::artifact(&mut ws, &mut next_id, &mut queued, &mut diagnostics).await?;
    let mut display_size = display.then(DisplaySize::new);
    let fallback_size = DisplaySize {
        cell_w: f64::from(ANSI_DEFAULT_CELL_WIDTH_PX),
        cell_h: f64::from(ANSI_DEFAULT_CELL_HEIGHT_PX),
        cols: 100,
        rows: 36,
    };
    let size = display_size.as_ref().unwrap_or(&fallback_size);
    let cell = AnsiCell::new(size);
    let (mut w, mut h) = if mode == Mode::Ansi {
        cell.viewport(size)
    } else {
        display_size
            .as_ref()
            .map_or((800, 600), |size| size.pixels(display))
    };
    let local_files = std::env::var("TERM_PROGRAM")
        .is_ok_and(|name| name.eq_ignore_ascii_case("ghostty"))
        && var_os("SSH_CONNECTION").is_none()
        && var_os("TMUX").is_none();
    let raw_files =
        local_files && manifest.abi >= MIN_RAW_FILE_ABI && var_os("PARAWING_KITTY_PNG").is_none();
    let (page_id, session) = attach_page_target(&mut ws, &mut next_id, &mut queued).await?;
    if let Some(endpoint) = v2 {
        return play_v2(
            ws,
            &mut next_id,
            &mut queued,
            V2PlayArgs {
                url: target,
                session,
                endpoint,
                mode,
                seconds,
                display,
                fps,
                wasm_bytes: bytes,
                raw_files,
                w,
                h,
                cell,
                display_size,
                fallback_size,
            },
            &mut diagnostics,
        )
        .await;
    }
    let compile_start = Instant::now();
    diagnostics.log(format!(
        "compiling scene rasterizer ({} Wasm bytes)",
        bytes.len()
    ));
    let mut raster = Raster::new(&bytes)?;
    let partial_scenes = mode == Mode::Kitty && manifest.retained_frames;
    if mode == Mode::Ansi {
        raster.run(OP_ENABLE_ANSI, &[])?;
    }
    diagnostics.log(format!(
        "scene rasterizer ready ({}) in {:.1}s",
        mode.slug(),
        compile_start.elapsed().as_secs_f64()
    ));
    let stream_options = SceneStreamOptions {
        mode,
        cell,
        fps,
        allow_partial: partial_scenes,
    };
    let mut mouse_down = false;
    diagnostics.log(format!(
        "attached to page target {page_id}; starting scene stream at {w}x{h}, {fps} fps"
    ));
    let scene_heartbeat = cdp_resize(
        &mut ws,
        &mut next_id,
        &session,
        w,
        h,
        stream_options,
        &mut queued,
    )
    .await?;
    diagnostics.log(format!("navigating to {target}"));
    cdp_call(
        &mut ws,
        &mut next_id,
        "Page.navigate",
        serde_json::json!({"url": target}),
        Some(&session),
        &mut queued,
    )
    .await?;
    let _terminal = if display {
        Some(Terminal::enter()?)
    } else {
        None
    };
    diagnostics.display = display;
    let initial_grid = display_size.as_ref().map(|size| (size.cols, size.rows));
    let mut rx = spawn_input_reader(display, initial_grid);
    let start = Instant::now();
    let mut kitty_images = KittyImages::default();
    kitty_images.local_files = local_files;
    kitty_images.raw_files = raw_files;
    let mut replay = ReplayState::new(mode, cell, kitty_images);
    replay.retained_frames = partial_scenes;
    replay.debug.visible = display;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut resize_tick = tokio::time::interval(RESIZE_TICK_INTERVAL);
    resize_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat_tick = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending_probe: Option<(u64, Instant)> = None;
    let mut last_scene_activity: Option<Instant> = None;
    let mut memory_tick = tokio::time::interval(MEMORY_INTERVAL);
    memory_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending_memory: Option<(u64, Instant)> = None;
    let mut scenes = 0u64;
    let mut font_queue: VecDeque<String> = VecDeque::new();
    let deadline = seconds.map(|duration| start + duration);
    loop {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        let scene_stall_at = scene_stall_deadline(last_scene_activity, scene_heartbeat);
        tokio::select! {
            biased;
            signal = &mut shutdown, if display => { signal?; break; }
            Some(ev) = rx.recv(), if display => {
                if matches!(&ev, Event::Key(key) if key.code == KeyCode::Char('c') &&
                    key.modifiers.contains(event::KeyModifiers::CONTROL)) { break; }
                if matches!(&ev, Event::Key(key) if key.code == KeyCode::Char('b') &&
                    key.modifiers.contains(KeyModifiers::CONTROL)) {
                    if matches!(&ev, Event::Key(key) if key.kind == KeyEventKind::Press) {
                        replay.debug.visible = !replay.debug.visible;
                        if replay.debug.visible {
                            replay.debug.accounted_bytes = None;
                            let id = cdp_send(&mut ws, &mut next_id, "Parawing.getMemoryStats",
                                serde_json::json!({}), None).await?;
                            pending_memory = Some((id, Instant::now()));
                        }
                        if mode == Mode::Kitty {
                            let size = display_size.as_ref().expect("display mode has terminal size");
                            (w, h) = size.pixels(replay.debug.visible);
                            replay.painted_seq = None;
                            replay.pending = None;
                            replay.resize_sync.sent();
                        }
                        if replay.debug.visible { replay.debug.paint(replay.wire_bytes, replay.frames, w, h)?; }
                        else { replay.debug.clear()?; }
                        if mode == Mode::Kitty {
                            cdp_resize(&mut ws, &mut next_id, &session, w, h, stream_options, &mut queued).await?;
                        }
                    }
                    continue;
                }
                if matches!(&ev, Event::Mouse(mouse) if replay.debug.visible &&
                    display_size.as_ref().is_some_and(|size| {
                        mouse.row >= size.rows.saturating_sub(DEBUG_BAR_ROWS)
                    })
                ) {
                    continue;
                }
                if let Event::Resize(cols, rows) = ev {
                    let (cols, rows) = terminal::size().unwrap_or((cols, rows));
                    let size = display_size.as_mut().expect("display mode has terminal size");
                    let grid_changed = (cols, rows) != (size.cols, size.rows);
                    let next = resize_view(size, cols, rows, replay.debug.visible, mode, cell);
                    if grid_changed || next != (w, h) {
                        (w, h) = next;
                        replay.painted_seq = None;
                        replay.pending = None;
                        replay.resize_sync.sent();
                        cdp_resize(&mut ws, &mut next_id, &session, w, h, stream_options, &mut queued).await?;
                    }
                } else {
                    let grid = if matches!(&ev, Event::Mouse(_)) {
                        terminal::size().ok()
                    } else {
                        None
                    };
                    if let Some((method, params)) = input_event(
                        ev,
                        w,
                        h,
                        grid,
                        (mode == Mode::Ansi).then(|| {
                            display_size
                                .as_ref()
                                .expect("display mode has terminal size")
                                .rows
                                .saturating_sub(DEBUG_BAR_ROWS)
                        }),
                        &mut mouse_down,
                    ) {
                        cdp_send(&mut ws, &mut next_id, method, params, Some(&session)).await?;
                    }
                }
            }
            msg = async {
                if let Some(message) = queued.pop_front() { Some(Ok(message)) }
                else { ws.next().await }
            } => {
                let Some(msg) = msg else {
                    diagnostics.log("CDP WebSocket disconnected");
                    return Err(CONNECTION_LOST.into());
                };
                let msg = msg?;
                if matches!(msg, Message::Close(_)) {
                    diagnostics.log("CDP WebSocket closed");
                    return Err(CONNECTION_LOST.into());
                }
                let Message::Text(text) = msg else { continue; };
                replay.wire_bytes += text.len() as u64;
                let event: serde_json::Value = serde_json::from_str(&text)?;
                acknowledge_probe(&event, &mut pending_probe)?;
                if pending_memory.is_some_and(|(id, _)| event["id"].as_u64() == Some(id)) {
                    pending_memory = None;
                    replay.debug.accounted_bytes = event["result"]["total"]["bytes"].as_u64();
                    replay.debug.paint(replay.wire_bytes, replay.frames, w, h)?;
                }
                if event["method"] != "Parawing.sceneFrame" {
                    if let Some(batch) = event["result"]["batchB64"].as_str() {
                        let resources = base64::engine::general_purpose::STANDARD.decode(batch)?;
                        raster.run(OP_PUT_RESOURCES, &resources)?;
                        retire_unavailable_images(&mut raster)?;
                        font_queue = queue_pending_fonts(&mut raster)?;
                        if font_queue.is_empty() {
                            replay.paint_pending(&mut raster, w, h, display, display_size.as_ref().unwrap_or(&fallback_size))?;
                        }
                    }
                    continue;
                }
                let Some(data) = event["params"]["data"].as_str() else { continue; };
                let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
                if bytes.len() < FRAME_HEADER_BYTES { continue; }
                if scene_heartbeat { last_scene_activity = Some(Instant::now()); }
                if let Some(size) = display_size.as_mut() {
                    if let Ok((cols, rows)) = terminal::size() {
                        if (cols, rows) != (size.cols, size.rows) {
                            (w, h) = resize_view(size, cols, rows, replay.debug.visible, mode, cell);
                            replay.painted_seq = None;
                            replay.pending = None;
                            replay.resize_sync.sent();
                            diagnostics.log(format!("terminal resized; requesting {w}x{h} scene stream"));
                            cdp_resize(&mut ws, &mut next_id, &session, w, h, stream_options, &mut queued).await?;
                        }
                    }
                }
                match bytes[0] {
                    INFO_MESSAGE => {
                        if serde_json::from_slice::<serde_json::Value>(
                            &bytes[FRAME_HEADER_BYTES..],
                        )?
                            .get("t").and_then(|value| value.as_str()) == Some("sceneReset") {
                            replay.painted_seq = None;
                            replay.pending = None;
                            diagnostics.log("scene stream reset after navigation");
                            last_scene_activity = None;
                        }
                    }
                    RESOURCE_MESSAGE => {
                        raster.run(OP_PUT_RESOURCES, &bytes[FRAME_HEADER_BYTES..])?;
                        retire_unavailable_images(&mut raster)?;
                        font_queue = queue_pending_fonts(&mut raster)?;
                        if font_queue.is_empty() {
                            replay.paint_pending(&mut raster, w, h, display, display_size.as_ref().unwrap_or(&fallback_size))?;
                        }
                    }
                    SCENE_MESSAGE | PARTIAL_MESSAGE => {
                        let frame = parse_frame(&bytes)?;
                        let seq = frame.seq;
                        scenes += 1;
                        if scenes == 1 {
                            diagnostics.log(format!("received first scene ({}x{}, seq {seq})", frame.width, frame.height));
                        }
                        let mut ok = false;
                        if scene_version(&frame.scene) != Some(manifest.wire_version) {
                            return Err(
                                "Scene wire version does not match the rasterizer supplied by the connected engine."
                                    .into(),
                            );
                        }
                        match replay.paint(
                            &mut raster,
                            &frame,
                            w,
                            h,
                            display,
                            display_size.as_ref().unwrap_or(&fallback_size),
                        )? {
                            ReplayResult::Painted => ok = true,
                            ReplayResult::MissingResources(missing) => {
                                replay.pending = Some(frame);
                                cdp_send(&mut ws, &mut next_id, "Parawing.getSceneResources", serde_json::json!({
                                    "missingB64": base64::engine::general_purpose::STANDARD.encode(missing),
                                }), Some(&session)).await?;
                            }
                            ReplayResult::Skipped => {}
                        }
                        cdp_ack(&mut ws, &mut next_id, &session, seq, ok).await?;
                    }
                    _ => {}
                }
            }
            _ = resize_tick.tick(), if display => {
                if let (Some(size), Ok((cols, rows))) = (display_size.as_mut(), terminal::size()) {
                    if (cols, rows) != (size.cols, size.rows) {
                        (w, h) = resize_view(size, cols, rows, replay.debug.visible, mode, cell);
                        replay.painted_seq = None;
                        replay.pending = None;
                        replay.resize_sync.sent();
                        cdp_resize(&mut ws, &mut next_id, &session, w, h, stream_options, &mut queued).await?;
                    } else if replay.resize_sync.retry_due() {
                        replay.resize_sync.sent();
                        cdp_resize(&mut ws, &mut next_id, &session, w, h, stream_options, &mut queued).await?;
                    }
                }
                replay.debug.paint(replay.wire_bytes, replay.frames, w, h)?;
            }
            _ = heartbeat_tick.tick() => {
                if pending_probe.is_none() &&
                    !last_scene_activity.is_some_and(|at| at.elapsed() < HEARTBEAT_INTERVAL) {
                    let id = cdp_send(&mut ws, &mut next_id, "Browser.getVersion",
                        serde_json::json!({}), None).await?;
                    pending_probe = Some((id, Instant::now()));
                }
            }
            _ = memory_tick.tick(), if replay.debug.visible => {
                if pending_memory.is_some_and(|(_, sent)| sent.elapsed() >= CDP_REPLY_TIMEOUT) {
                    pending_memory = None;
                    replay.debug.accounted_bytes = None;
                    replay.debug.paint(replay.wire_bytes, replay.frames, w, h)?;
                }
                if pending_memory.is_none() {
                    let id = cdp_send(&mut ws, &mut next_id, "Parawing.getMemoryStats",
                        serde_json::json!({}), None).await?;
                    pending_memory = Some((id, Instant::now()));
                }
            }
            _ = async {
                if let Some((_, sent)) = pending_probe {
                    tokio::time::sleep_until((sent + CDP_REPLY_TIMEOUT).into()).await;
                }
            }, if pending_probe.is_some() => return Err(SERVER_UNRESPONSIVE.into()),
            _ = async {
                if let Some(at) = scene_stall_at {
                    tokio::time::sleep_until(at).await;
                }
            }, if scene_stall_at.is_some() => return Err(SCENE_STREAM_STALLED.into()),
            _ = tokio::time::sleep(DEADLINE_POLL_INTERVAL), if deadline.is_some() => {}
            // One queued path per iteration: a fetch never delays input, Ctrl-C or the timers
            // above by more than itself, and the pending frame paints once the queue drains.
            _ = std::future::ready(()), if !font_queue.is_empty() => {
                let path = font_queue.pop_front().expect("checked non-empty font queue");
                load_font(&font_cache, &mut raster, &mut diagnostics, &path).await?;
                if font_queue.is_empty() {
                    replay.paint_pending(&mut raster, w, h, display, display_size.as_ref().unwrap_or(&fallback_size))?;
                }
            }
        }
    }
    drop(_terminal);
    diagnostics.flush();
    eprintln!("scenes={scenes} displayed={} elapsed={:.2}s fps={:.1} scene_wire={}KB kitty_est={}KB raster={:.1}ms/frame",
        replay.frames, start.elapsed().as_secs_f64(),
        replay.frames as f64 / start.elapsed().as_secs_f64(),
        replay.wire_bytes / 1024, replay.terminal_bytes / 1024,
        replay.raster_time.as_secs_f64() * 1000.0 / replay.frames.max(1) as f64);
    Ok(())
}

fn render(
    raster: &mut Raster,
    frame: &Frame,
    w: u16,
    h: u16,
    raw_rgba: bool,
    retain: bool,
) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(frame.scene.len() + 20);
    let operation = if retain {
        input.extend_from_slice(&frame.seq.to_le_bytes());
        if frame.partial {
            input.extend_from_slice(&frame.base.to_le_bytes());
            input.extend_from_slice(&frame.x.to_le_bytes());
            input.extend_from_slice(&frame.y.to_le_bytes());
        }
        input.extend_from_slice(&u32::from(raw_rgba).to_le_bytes());
        if frame.partial {
            OP_COMPOSITE_FRAME
        } else {
            OP_RETAIN_FRAME
        }
    } else if raw_rgba {
        OP_RENDER_RGBA
    } else {
        OP_RENDER_PNG
    };
    input.extend_from_slice(&frame.scene);
    let output = raster.run(operation, &input)?;
    if output.is_empty() {
        if retain && frame.partial {
            return Ok(output);
        }
        return Err(String::from_utf8_lossy(&raster.run(OP_LAST_ERROR, &[])?)
            .into_owned()
            .into());
    }
    if !raw_rgba && !output.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("scene replay returned a non-PNG frame".into());
    }
    let dimensions = if raw_rgba {
        output.get(..8)
    } else {
        output.get(16..24)
    };
    let decode: fn([u8; 4]) -> u32 = if raw_rgba {
        u32::from_le_bytes
    } else {
        u32::from_be_bytes
    };
    let dimensions = dimensions.and_then(|bytes| {
        let (width, rest) = bytes.split_first_chunk::<4>()?;
        let height = rest.first_chunk::<4>()?;
        Some((decode(*width), decode(*height)))
    });
    if dimensions != Some((u32::from(w), u32::from(h))) {
        return Err("scene replay returned an unexpected viewport".into());
    }
    Ok(output)
}

fn render_ansi(
    raster: &mut Raster,
    frame: &Frame,
    size: &DisplaySize,
    cell: AnsiCell,
) -> Result<Vec<u8>> {
    if frame.partial {
        return Err("ANSI requires a full scene".into());
    }
    let mut input = Vec::with_capacity(frame.scene.len() + 16);
    for dimension in [
        u32::from(size.cols),
        u32::from(size.rows.saturating_sub(DEBUG_BAR_ROWS).max(1)),
    ] {
        input.extend_from_slice(&dimension.to_le_bytes());
    }
    for cell_pixels in [f32::from(cell.w), f32::from(cell.h)] {
        input.extend_from_slice(&cell_pixels.to_le_bytes());
    }
    input.extend_from_slice(&frame.scene);
    let output = raster.run(OP_RENDER_ANSI, &input)?;
    if output.is_empty() {
        return Err("scene did not decode as ANSI".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tokio_tungstenite::connect_async;

    #[cfg(unix)]
    #[test]
    fn kitty_temp_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let mut images = KittyImages::default();
        let path = images.temp_file(b"frame", false).unwrap();
        let dir = images.temp_dir.clone().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"frame");
        assert!(write_private_file(&path, b"again").is_err());
    }

    #[test]
    fn liveness_probe_only_accepts_its_own_successful_reply() {
        let mut pending = Some((7, Instant::now()));
        acknowledge_probe(
            &serde_json::json!({"method": "Parawing.sceneFrame"}),
            &mut pending,
        )
        .unwrap();
        acknowledge_probe(&serde_json::json!({"id": 6, "result": {}}), &mut pending).unwrap();
        assert!(pending.is_some());
        assert!(acknowledge_probe(
            &serde_json::json!({"id": 7, "error": {"message": "failed"}}),
            &mut pending
        )
        .is_err());
        assert!(pending.is_some());
        acknowledge_probe(&serde_json::json!({"id": 7, "result": {}}), &mut pending).unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn scene_stall_requires_heartbeat_support_and_recent_stream_activity() {
        let stalled = Instant::now() - Duration::from_secs(6);
        assert!(scene_stall_deadline(Some(stalled), true).unwrap() <= tokio::time::Instant::now());
        assert!(
            scene_stall_deadline(Some(Instant::now()), true).unwrap() > tokio::time::Instant::now()
        );
        assert!(scene_stall_deadline(Some(stalled), false).is_none());
        assert!(scene_stall_deadline(None, true).is_none());
    }

    const CDP_MESSAGE_TIMEOUT: Duration = Duration::from_secs(5);
    const EXPIRED_PAINT_AGE: Duration = Duration::from_secs(2);

    fn full_frame(seq: u32, width: u16, height: u16) -> Frame {
        let mut scene = vec![0; 16];
        scene[8..12].copy_from_slice(&u32::from(width).to_le_bytes());
        scene[12..16].copy_from_slice(&u32::from(height).to_le_bytes());
        Frame {
            scene,
            seq,
            partial: false,
            width,
            height,
            x: 0,
            y: 0,
            base: -1,
        }
    }

    #[test]
    fn hidden_stats_discard_expired_paint_timestamps() {
        let mut debug = DebugBar::default();
        debug
            .painted_at
            .push_back(Instant::now() - EXPIRED_PAINT_AGE);
        assert_eq!(debug.fps(), 0);
        debug
            .painted_at
            .push_back(Instant::now() - EXPIRED_PAINT_AGE);
        assert!(!debug.visible);
        assert_eq!(debug.painted_at.len(), 1);

        debug.painted();

        assert_eq!(debug.painted_at.len(), 1);
        assert_eq!(debug.fps(), 1);
    }

    #[test]
    fn high_unsigned_scene_sequence_is_not_rejected() {
        let frame = full_frame(0x8000_0000, 320, 240);

        assert!(can_paint(&frame, None, 320, 240));
    }

    #[test]
    fn full_scene_older_than_high_painted_sequence_is_rejected() {
        let frame = full_frame(0x7fff_ffff, 320, 240);

        assert!(!can_paint(&frame, Some(0x8000_0000), 320, 240));
    }

    #[test]
    fn partial_scene_matches_high_sequence_wire_base() {
        let mut frame = full_frame(0x8000_0001, 20, 10);
        frame.partial = true;
        frame.base = i32::MIN;
        assert!(can_paint(&frame, Some(0x8000_0000), 320, 240));

        frame.base += 1;
        assert!(!can_paint(&frame, Some(0x8000_0000), 320, 240));
    }

    #[test]
    fn partial_scene_cannot_establish_a_base() {
        let mut frame = full_frame(0, 20, 10);
        frame.partial = true;
        frame.base = -1;
        assert!(!can_paint(&frame, None, 320, 240));
        frame.base = 0;
        assert!(!can_paint(&frame, None, 320, 240));
    }

    #[test]
    fn retained_replay_reports_corrupt_full_scenes() {
        let bytes = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let mut raster = Raster::new(&bytes).unwrap();
        let size = DisplaySize {
            cols: 100,
            rows: 35,
            cell_w: 8.0,
            cell_h: 17.0,
        };
        let mut frame = full_frame(1, 320, 240);
        frame.scene = wasm::test_scene(320, 240, [0, 0, 255, 255]);
        frame.scene.truncate(frame.scene.len() - 3);
        for retained_frames in [false, true] {
            for raw_files in [false, true] {
                let mut images = KittyImages::default();
                images.raw_files = raw_files;
                let mut replay = ReplayState::new(Mode::Kitty, AnsiCell { w: 8, h: 17 }, images);
                replay.retained_frames = retained_frames;
                let error = replay
                    .paint(&mut raster, &frame, 320, 240, false, &size)
                    .err()
                    .expect(
                        "a corrupt full scene must fail instead of requesting another full scene",
                    );
                assert!(error.to_string().contains("scene truncated"), "{error}");
            }
        }
    }

    #[test]
    fn partial_replay_composites_without_a_display_and_recovers_a_lost_base() {
        let bytes = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let mut raster = Raster::new(&bytes).unwrap();
        let mut replay = ReplayState::new(
            Mode::Kitty,
            AnsiCell { w: 8, h: 17 },
            KittyImages::default(),
        );
        replay.retained_frames = true;
        let size = DisplaySize {
            cols: 100,
            rows: 35,
            cell_w: 8.0,
            cell_h: 17.0,
        };
        let mut base = full_frame(1, 320, 240);
        base.scene = wasm::test_scene(320, 240, [0, 0, 255, 255]);
        assert!(matches!(
            replay
                .paint(&mut raster, &base, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Painted
        ));
        let mut patch = full_frame(2, 20, 10);
        patch.partial = true;
        patch.base = 1;
        patch.x = 30;
        patch.y = 40;
        patch.scene = wasm::test_scene(20, 10, [255, 0, 0, 255]);
        assert!(matches!(
            replay
                .paint(&mut raster, &patch, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Painted
        ));
        assert_eq!(replay.painted_seq, Some(2));

        // Simulate a rasterizer with no matching retained pixels despite the CLI's seq.
        render(&mut raster, &base, 320, 240, true, true).unwrap();
        patch.seq = 3;
        patch.base = 2;
        assert!(matches!(
            replay
                .paint(&mut raster, &patch, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Skipped
        ));
        assert_eq!(replay.painted_seq, None);
        assert!(matches!(
            replay
                .paint(&mut raster, &patch, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Skipped
        ));
        base.seq = 4;
        assert!(matches!(
            replay
                .paint(&mut raster, &base, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Painted
        ));
        patch.seq = 5;
        patch.base = 4;
        assert!(matches!(
            replay
                .paint(&mut raster, &patch, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Painted
        ));

        patch.seq = 6;
        patch.base = 5;
        patch.scene.truncate(patch.scene.len() - 3);
        assert!(matches!(
            replay
                .paint(&mut raster, &patch, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Skipped
        ));
        assert_eq!(replay.painted_seq, None);
        base.seq = 7;
        assert!(matches!(
            replay
                .paint(&mut raster, &base, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Painted
        ));
        patch.seq = 8;
        patch.base = 7;
        patch.scene = wasm::test_scene(20, 10, [255, 0, 0, 255]);
        assert!(matches!(
            replay
                .paint(&mut raster, &patch, 320, 240, false, &size)
                .unwrap(),
            ReplayResult::Painted
        ));
    }

    #[test]
    fn partial_replay_preserves_full_rgba_dimensions_and_terminal_placement() {
        let bytes = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let mut raster = Raster::new(&bytes).unwrap();
        let mut base = full_frame(1, 320, 240);
        base.scene = wasm::test_scene(320, 240, [0, 0, 255, 255]);
        let mut images = KittyImages::default();
        let mut out = Vec::new();
        let full = render(&mut raster, &base, 320, 240, true, true).unwrap();
        kitty_to(&mut out, &full, 80, None, &mut images, true).unwrap();
        out.clear();
        let mut patch = full_frame(2, 20, 10);
        patch.partial = true;
        patch.base = 1;
        patch.x = 30;
        patch.y = 40;
        patch.scene = wasm::test_scene(20, 10, [255, 0, 0, 255]);
        let composite = render(&mut raster, &patch, 320, 240, true, true).unwrap();
        assert_eq!(composite.len(), 8 + 320 * 240 * 4);
        assert_eq!(
            &composite[8 + (45 * 320 + 35) * 4..8 + (45 * 320 + 36) * 4],
            [255, 0, 0, 255]
        );
        assert_eq!(&composite[8..12], [0, 0, 255, 255]);
        kitty_to(&mut out, &composite, 80, None, &mut images, true).unwrap();
        assert!(out.starts_with(b"\x1b[1;1H\x1b_Ga=T,f=32,s=320,v=240,i=2,"));
        assert!(out.ends_with(b"\x1b_Ga=d,d=I,i=1,q=1;\x1b\\"));
        assert!(!out.windows(4).any(|bytes| bytes == b"a=f,"));
    }

    #[test]
    fn retained_frame_capability_is_optional_for_older_manifests() {
        let mut value = serde_json::json!({ "abi": 4, "wireVersion": 13,
            "wasm": "scene_host.wasm", "sha256": "unused", "bytes": 1 });
        assert!(
            !serde_json::from_value::<Manifest>(value.clone())
                .unwrap()
                .retained_frames
        );
        value["retainedFrames"] = true.into();
        assert!(
            serde_json::from_value::<Manifest>(value)
                .unwrap()
                .retained_frames
        );
    }

    #[test]
    fn rbi_keys_preserve_modifiers_without_typing_control_shortcuts() {
        let (method, ctrl_d) = key_message(
            event::KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
            None,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchKeyEvent");
        assert_eq!(ctrl_d["type"], "rawKeyDown");
        assert_eq!(ctrl_d["modifiers"], 2);
        assert_eq!(ctrl_d["text"], "");
        assert!(ctrl_d.get("_parawingInputSeq").is_none());

        let (method, shift_tab) = key_message(
            event::KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT),
            None,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchKeyEvent");
        assert_eq!(shift_tab["type"], "rawKeyDown");
        assert_eq!(shift_tab["modifiers"], 8);

        let (method, alt_meta) = key_message(
            event::KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT | KeyModifiers::SUPER),
            None,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchKeyEvent");
        assert_eq!(alt_meta["modifiers"], 5);
        assert_eq!(alt_meta["text"], "");

        let (method, plain) = key_message(
            event::KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
            None,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchKeyEvent");
        assert_eq!(plain["type"], "rawKeyDown");
        assert_eq!(plain["text"], "j");
        assert_eq!(plain["modifiers"], 0);
        assert_eq!(plain["windowsVirtualKeyCode"], 74);
    }

    #[test]
    fn rbi_shift_tab_reaches_the_page() {
        let (method, message) = key_message(
            event::KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
            None,
        )
        .expect("Shift-Tab must produce a CDP key event");
        assert_eq!(method, "Input.dispatchKeyEvent");
        assert_eq!(message["key"], "Tab");
        assert_eq!(message["code"], "Tab");
        assert_eq!(message["windowsVirtualKeyCode"], 9);
        assert_eq!(message["modifiers"], 8);
        assert_eq!(message["type"], "rawKeyDown");
    }

    #[test]
    fn rbi_key_release_clears_the_held_key() {
        use crossterm::Command as _;

        let mut enable = String::new();
        event::PushKeyboardEnhancementFlags(keyboard_flags())
            .write_ansi(&mut enable)
            .unwrap();
        assert_eq!(enable, "\x1b[>11u");
        let mut restore = String::new();
        event::PopKeyboardEnhancementFlags
            .write_ansi(&mut restore)
            .unwrap();
        assert_eq!(restore, "\x1b[<1u");

        let press =
            event::KeyEvent::new_with_kind(KeyCode::Up, KeyModifiers::NONE, KeyEventKind::Press);
        let release =
            event::KeyEvent::new_with_kind(KeyCode::Up, KeyModifiers::NONE, KeyEventKind::Release);
        let (press_method, press) = key_message(press, None).unwrap();
        let (release_method, release) = key_message(release, None).unwrap();
        let repeat =
            event::KeyEvent::new_with_kind(KeyCode::Up, KeyModifiers::NONE, KeyEventKind::Repeat);
        let (repeat_method, repeat) = key_message(repeat, None).unwrap();
        assert_eq!(press_method, "Input.dispatchKeyEvent");
        assert_eq!(release_method, "Input.dispatchKeyEvent");
        assert_eq!(repeat_method, "Input.dispatchKeyEvent");
        assert_eq!(press["type"], "rawKeyDown");
        assert_eq!(repeat["type"], "rawKeyDown");
        assert_eq!(release["type"], "keyUp");
        assert_eq!(release["code"], press["code"]);
    }

    #[tokio::test]
    async fn rbi_key_event_is_sent_as_a_cdp_command() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let message = tokio::time::timeout(CDP_MESSAGE_TIMEOUT, socket.next())
                .await
                .expect("CDP input should arrive")
                .unwrap()
                .unwrap();
            match message {
                Message::Text(text) => text.to_string(),
                message => panic!("expected CDP text, got {message:?}"),
            }
        });
        let (mut socket, _) = connect_async(format!("ws://{address}/devtools/browser"))
            .await
            .unwrap();
        let mut mouse_down = false;
        let (method, params) = input_event(
            Event::Key(event::KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)),
            0,
            0,
            None,
            None,
            &mut mouse_down,
        )
        .unwrap();
        let mut id = 0;
        cdp_send(&mut socket, &mut id, method, params, Some("page"))
            .await
            .unwrap();
        drop(socket);

        let message: serde_json::Value = serde_json::from_str(&server.await.unwrap()).unwrap();
        assert_eq!(
            message,
            serde_json::json!({
                "id": 1,
                "method": "Input.dispatchKeyEvent",
                "params": {
                    "type": "rawKeyDown",
                    "key": "j",
                    "code": "KeyJ",
                    "windowsVirtualKeyCode": 74,
                    "text": "j",
                    "modifiers": 0,
                },
                "sessionId": "page",
            })
        );
    }

    #[test]
    fn rbi_mouse_input_preserves_held_buttons_and_wheel_deltas() {
        let mouse_event = |kind, column, row| {
            Event::Mouse(event::MouseEvent {
                kind,
                column,
                row,
                modifiers: KeyModifiers::NONE,
            })
        };
        let mut mouse_down = false;
        let (method, pressed) = input_event(
            mouse_event(MouseEventKind::Down(event::MouseButton::Left), 10, 5),
            1000,
            500,
            Some((100, 50)),
            None,
            &mut mouse_down,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchMouseEvent");
        assert_eq!(
            pressed,
            serde_json::json!({
                "type": "mousePressed", "x": 100, "y": 50,
                "button": "left", "buttons": 1, "clickCount": 1,
            })
        );

        let (method, moved) = input_event(
            mouse_event(MouseEventKind::Drag(event::MouseButton::Left), 11, 6),
            1000,
            500,
            Some((100, 50)),
            None,
            &mut mouse_down,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchMouseEvent");
        assert_eq!(
            moved,
            serde_json::json!({
                "type": "mouseMoved", "x": 110, "y": 60,
                "button": "left", "buttons": 1, "clickCount": 1,
            })
        );

        let (method, released) = input_event(
            mouse_event(MouseEventKind::Up(event::MouseButton::Left), 11, 6),
            1000,
            500,
            Some((100, 50)),
            None,
            &mut mouse_down,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchMouseEvent");
        assert_eq!(
            released,
            serde_json::json!({
                "type": "mouseReleased", "x": 110, "y": 60,
                "button": "left", "buttons": 0, "clickCount": 1,
            })
        );

        let (method, after_release) = input_event(
            mouse_event(MouseEventKind::Moved, 11, 6),
            1000,
            500,
            Some((100, 50)),
            None,
            &mut mouse_down,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchMouseEvent");
        assert_eq!(
            after_release,
            serde_json::json!({
                "type": "mouseMoved", "x": 110, "y": 60,
                "button": "none", "buttons": 0, "clickCount": 1,
            })
        );

        let (method, wheel_down) = input_event(
            mouse_event(MouseEventKind::ScrollDown, 10, 5),
            1000,
            500,
            Some((100, 50)),
            None,
            &mut mouse_down,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchMouseEvent");
        assert_eq!(
            wheel_down,
            serde_json::json!({
                "type": "mouseWheel", "x": 100, "y": 50,
                "deltaX": 0, "deltaY": 80,
            })
        );

        let (method, wheel_up) = input_event(
            mouse_event(MouseEventKind::ScrollUp, 10, 5),
            1000,
            500,
            Some((100, 50)),
            None,
            &mut mouse_down,
        )
        .unwrap();
        assert_eq!(method, "Input.dispatchMouseEvent");
        assert_eq!(
            wheel_up,
            serde_json::json!({
                "type": "mouseWheel", "x": 100, "y": 50,
                "deltaX": 0, "deltaY": -80,
            })
        );

        assert!(input_event(
            mouse_event(MouseEventKind::Moved, 10, 49),
            1000,
            500,
            Some((100, 50)),
            Some(49),
            &mut mouse_down,
        )
        .is_none());
    }

    #[test]
    fn kitty_placement_keeps_png_aspect_ratio() {
        let mut output = Vec::new();
        kitty_to(
            &mut output,
            b"png",
            120,
            None,
            &mut KittyImages::default(),
            false,
        )
        .unwrap();
        assert_eq!(
            output,
            b"\x1b[1;1H\x1b_Ga=T,f=100,i=1,q=1,C=1,c=120,m=0;cG5n\x1b\\"
        );
    }

    #[test]
    fn debug_bar_reserves_one_row_and_reports_the_scene_wire() {
        let size = DisplaySize {
            cell_w: 10.0,
            cell_h: 20.0,
            cols: 80,
            rows: 30,
        };
        assert_eq!(size.pixels(false), (800, 600));
        assert_eq!(size.pixels(true), (800, 580));
        let mut output = Vec::new();
        kitty_to(
            &mut output,
            b"png",
            80,
            Some(29),
            &mut KittyImages::default(),
            false,
        )
        .unwrap();
        assert!(output.starts_with(b"\x1b[1;1H\x1b_Ga=T,f=100,i=1,q=1,C=1,c=80,r=29,m=0;"));
        let line = DebugBar::default().line(2 * 1024 * 1024, 12, 800, 580);
        assert!(line.contains("wire 2.0 MiB | acct -- | mode kitty | frames 12 | 800x580"));
        let mut debug = DebugBar {
            accounted_bytes: Some(48 * 1024 * 1024),
            ..DebugBar::default()
        };
        let line = debug.line(2 * 1024 * 1024, 12_345, 800, 580);
        assert!(line.contains("acct 48.0MiB | mode kitty"));
        assert!(line.len() <= 80);
    }

    #[test]
    fn hidpi_uses_remote_zoom_with_or_without_debug_bar() {
        let size = DisplaySize {
            cell_w: 16.0,
            cell_h: 34.0,
            cols: 80,
            rows: 20,
        };
        assert_eq!(size.pixels(false), (640, 340));
        assert_eq!(size.pixels(true), (640, 323));
        let cell = AnsiCell::new(&size);
        assert_eq!((cell.w, cell.h), (8, 17));
        assert_eq!(cell.viewport(&size), (640, 323));
        let mut debug = DebugBar {
            mode: Mode::Ansi,
            ..DebugBar::default()
        };
        assert!(debug.line(0, 1, 640, 323).contains("mode ansi"));
    }

    #[test]
    fn each_repaint_places_the_new_image_before_deleting_the_old_one() {
        let mut output = Vec::new();
        let mut images = KittyImages::default();
        kitty_to(&mut output, b"old", 120, None, &mut images, false).unwrap();
        kitty_to(&mut output, b"new", 80, None, &mut images, false).unwrap();
        kitty_to(&mut output, b"next", 80, None, &mut images, false).unwrap();
        assert_eq!(
            output,
            b"\x1b[1;1H\x1b_Ga=T,f=100,i=1,q=1,C=1,c=120,m=0;b2xk\x1b\\\
              \x1b[1;1H\x1b_Ga=T,f=100,i=2,q=1,C=1,c=80,m=0;bmV3\x1b\\\
              \x1b_Ga=d,d=I,i=1,q=1;\x1b\\\
              \x1b[1;1H\x1b_Ga=T,f=100,i=1,q=1,C=1,c=80,m=0;bmV4dA==\x1b\\\
              \x1b_Ga=d,d=I,i=2,q=1;\x1b\\"
        );
    }

    #[test]
    fn partial_scene_requires_matching_dimensions_and_visible_intersection() {
        let mut patch = full_frame(2, 20, 10);
        patch.partial = true;
        patch.base = 1;
        for (x, y) in [(-1, 0), (90, 0), (0, -2)] {
            patch.x = x;
            patch.y = y;
            assert!(can_paint(&patch, Some(1), 100, 80));
        }
        for (x, y) in [(100, 0), (0, 80), (i32::MIN, 0), (0, i32::MAX)] {
            patch.x = x;
            patch.y = y;
            assert!(!can_paint(&patch, Some(1), 100, 80));
        }
        patch.x = 0;
        patch.y = 0;
        patch.width += 1;
        assert!(!can_paint(&patch, Some(1), 100, 80));
    }

    #[test]
    fn chunked_full_image_suppresses_success_replies_on_continuations() {
        let mut out = Vec::new();
        let png = vec![42; 3073];
        kitty_to(&mut out, &png, 80, None, &mut KittyImages::default(), false).unwrap();
        assert!(out.starts_with(b"\x1b[1;1H\x1b_Ga=T,f=100,i=1,q=1,C=1,c=80,m=1;"));
        assert!(out
            .windows(b"\x1b_Gm=0,q=1;".len())
            .any(|chunk| chunk == b"\x1b_Gm=0,q=1;"));
    }

    #[test]
    fn local_kitty_file_transmits_a_path_instead_of_png_chunks() {
        let png = vec![42; 3073];
        let mut images = KittyImages::default();
        images.local_files = true;
        let mut out = Vec::new();
        kitty_to(&mut out, &png, 80, None, &mut images, false).unwrap();
        let prefix = b"\x1b[1;1H\x1b_Ga=T,f=100,i=1,q=1,C=1,c=80,t=t,m=0;";
        assert!(out.starts_with(prefix));
        let encoded = out[prefix.len()..].strip_suffix(b"\x1b\\").unwrap();
        let path = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap();
        assert!(path.contains("tty-graphics-protocol"));
        assert_eq!(fs::read(&path).unwrap(), png);
        assert_eq!(images.last_bytes, encoded.len() as u64);
        drop(images);
        assert!(!std::path::Path::new(&path).exists());
    }

    #[test]
    fn local_kitty_file_transmits_uncompressed_rgba() {
        let mut images = KittyImages::default();
        images.local_files = true;
        let mut rgba = Vec::from([2, 0, 0, 0, 1, 0, 0, 0]);
        rgba.extend_from_slice(&[255, 0, 0, 255, 0, 255, 0, 255]);
        let mut out = Vec::new();
        kitty_to(&mut out, &rgba, 80, None, &mut images, true).unwrap();
        let prefix = b"\x1b[1;1H\x1b_Ga=T,f=32,s=2,v=1,i=1,q=1,C=1,c=80,t=t,m=0;";
        assert!(out.starts_with(prefix));
        let path = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(out[prefix.len()..].strip_suffix(b"\x1b\\").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read(path).unwrap(), rgba[8..]);
    }

    #[test]
    fn viewport_uses_all_rows_and_preserves_aspect_ratio_under_the_cap() {
        assert_eq!(viewport_size(120, 40, 1200, 800), (1200, 800));
        assert_eq!(viewport_size(120, 40, 0, 0), (960, 680));
        assert_eq!(viewport_size(200, 60, 3840, 2160), (2560, 1440));
        assert_eq!(viewport_size(25, 40, 250, 800), (320, 1024));
        assert_eq!(viewport_size(20, 10, 160, 170), (320, 340));
    }

    #[test]
    fn resize_uses_new_grid_when_terminal_pixel_fields_are_stale() {
        let mut size = DisplaySize {
            cell_w: 10.0,
            cell_h: 20.0,
            cols: 120,
            rows: 40,
        };
        assert_eq!(size.resize(80, 30, false), (800, 600));
        assert_eq!(size.resize(100, 35, false), (1000, 700));
    }

    #[test]
    fn stale_full_scene_cannot_replace_a_resized_viewport() {
        let mut bytes = vec![3, 1, 0];
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&800u16.to_le_bytes());
        bytes.extend_from_slice(&600u16.to_le_bytes());
        bytes.extend_from_slice(b"KSC0");
        bytes.extend_from_slice(&11u32.to_le_bytes());
        bytes.extend_from_slice(&800u32.to_le_bytes());
        bytes.extend_from_slice(&600u32.to_le_bytes());
        let old = parse_frame(&bytes).unwrap();
        assert!(!can_paint(&old, None, 1000, 700));

        bytes[7..9].copy_from_slice(&1000u16.to_le_bytes());
        bytes[9..11].copy_from_slice(&700u16.to_le_bytes());
        assert!(!can_paint(&parse_frame(&bytes).unwrap(), None, 1000, 700));
        bytes[19..23].copy_from_slice(&1000u32.to_le_bytes());
        bytes[23..27].copy_from_slice(&700u32.to_le_bytes());
        let resized = parse_frame(&bytes).unwrap();
        assert!(can_paint(&resized, None, 1000, 700));
        assert!(!can_paint(&old, Some(resized.seq), 1000, 700));
    }

    #[test]
    fn resize_retries_until_a_full_scene_is_painted() {
        let mut sync = ResizeSync::new();
        sync.sent();
        sync.sent_at = Instant::now() - Duration::from_secs(2);
        assert!(sync.retry_due());
        sync.sent();
        assert!(!sync.retry_due());

        let mut frame = Frame {
            scene: vec![],
            seq: 1,
            partial: true,
            width: 0,
            height: 0,
            x: 0,
            y: 0,
            base: -1,
        };
        sync.painted(&frame);
        assert!(sync.awaiting);
        frame.partial = false;
        sync.painted(&frame);
        assert!(!sync.retry_due());
    }

    async fn read_ws_binary<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Vec<u8>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Binary(bin) => return bin.to_vec(),
                Message::Close(frame) => panic!("unexpected close: {frame:?}"),
                _ => {}
            }
        }
    }

    async fn read_cdp_req<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> serde_json::Value
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        loop {
            if let Message::Text(text) = ws.next().await.unwrap().unwrap() {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    async fn send_cdp_ok<S>(
        ws: &mut tokio_tungstenite::WebSocketStream<S>,
        id: u64,
        result: serde_json::Value,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let msg = serde_json::json!({ "id": id, "result": result }).to_string();
        ws.send(Message::Text(msg.into())).await.unwrap();
    }

    fn encode_reliable_frame_test(frame_seq: u32, tile_count: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(21 + payload.len());
        out.extend_from_slice(b"KV2\x01");
        out.push(1);
        out.extend_from_slice(&frame_seq.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&tile_count.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn encode_delta_resync_ack_test(
        resumed_from_seq: u32,
        pruned_known_tiles: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(17 + payload.len());
        out.extend_from_slice(b"KV2\x01");
        out.push(7);
        out.extend_from_slice(&resumed_from_seq.to_le_bytes());
        out.extend_from_slice(&pruned_known_tiles.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn play_v2_connects_s7_ws_ingests_ksc2_and_routes_events() {
        use tokio_tungstenite::tungstenite::handshake::server;

        let wasm_bytes = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let ksc2 = crate::compositor_v2::tests::build_ksc2_test_frame();

        let cdp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cdp_addr = cdp_listener.local_addr().unwrap();
        let v2_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v2_addr = v2_listener.local_addr().unwrap();

        let cdp_task = tokio::spawn(async move {
            let (stream, _) = cdp_listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut methods = Vec::new();
            loop {
                let Some(Ok(msg)) = ws.next().await else {
                    break;
                };
                if let Message::Text(text) = msg {
                    let req: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let method = req["method"].as_str().unwrap().to_owned();
                    let id = req["id"].as_u64().unwrap();
                    methods.push(method.clone());
                    let res = match method.as_str() {
                        "Parawing.startSceneStreamV2" => {
                            serde_json::json!({ "wsPath": "/rbi/ws?token=t1" })
                        }
                        _ => serde_json::json!({}),
                    };
                    send_cdp_ok(&mut ws, id, res).await;
                    if method == "Parawing.stopSceneStreamV2" {
                        break;
                    }
                }
            }
            methods
        });

        let v2_task = tokio::spawn(async move {
            let (stream, _) = v2_listener.accept().await.unwrap();
            let mut seen_auth = String::new();
            let mut seen_uri = String::new();
            #[allow(clippy::result_large_err)]
            let mut ws = tokio_tungstenite::accept_hdr_async(
                stream,
                |req: &server::Request, resp: server::Response| {
                    seen_uri = req.uri().to_string();
                    seen_auth = req
                        .headers()
                        .get("cf-access-token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    Ok(resp)
                },
            )
            .await
            .unwrap();
            let init = decode_rbi_v2_packet(&read_ws_binary(&mut ws).await).unwrap();
            assert!(matches!(
                init,
                DecodedRbiV2Packet::CreditGrant {
                    credits_granted: 2,
                    ..
                }
            ));
            let frame_pkt = encode_reliable_frame_test(1, 1, &ksc2);
            ws.send(Message::Binary(frame_pkt.into())).await.unwrap();
            let ack = decode_rbi_v2_packet(&read_ws_binary(&mut ws).await).unwrap();
            assert!(matches!(
                ack,
                DecodedRbiV2Packet::CreditGrant {
                    credits_granted: 1,
                    acked_frame_seq: 1
                }
            ));
            while matches!(
                ws.next().await,
                Some(Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_)))
            ) {}
            (seen_uri, seen_auth)
        });

        let (cdp_ws, _) = tokio_tungstenite::connect_async(format!("ws://{cdp_addr}"))
            .await
            .unwrap();
        let endpoint = V2Endpoint {
            origin_ws: format!("ws://{v2_addr}"),
            headers: vec![("Cf-Access-Token".to_owned(), "tok-v2".to_owned())],
        };
        let args = V2PlayArgs {
            url: "https://example.com".to_owned(),
            session: "sess-1".to_owned(),
            endpoint,
            mode: Mode::Ansi,
            seconds: Some(Duration::from_millis(120)),
            display: false,
            fps: 30,
            wasm_bytes: wasm_bytes.clone(),
            raw_files: false,
            w: 256,
            h: 256,
            cell: AnsiCell { w: 8, h: 16 },
            display_size: None,
            fallback_size: DisplaySize {
                cell_w: 8.0,
                cell_h: 16.0,
                cols: 32,
                rows: 16,
            },
        };
        let mut next_id = 1;
        let mut queued = VecDeque::new();
        let mut diag = Diagnostics::new(false);
        play_v2(cdp_ws, &mut next_id, &mut queued, args, &mut diag)
            .await
            .unwrap();

        let methods = cdp_task.await.unwrap();
        assert_eq!(
            methods,
            vec![
                "Emulation.setDeviceMetricsOverride",
                "Parawing.startSceneStreamV2",
                "Page.navigate",
                "Parawing.stopSceneStreamV2",
            ]
        );
        let (seen_uri, seen_auth) = v2_task.await.unwrap();
        assert_eq!(seen_uri, "/rbi/ws?token=t1");
        assert_eq!(seen_auth, "tok-v2");
    }

    #[tokio::test]
    async fn handle_v2_events_route_passive_datagrams_and_forward_handlers() {
        let wasm_bytes = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let mut host = CompositorV2Host::new(&wasm_bytes).unwrap();
        host.ingest_frame(&crate::compositor_v2::tests::build_ksc2_test_frame())
            .unwrap();

        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap();
        let a2 = l2.local_addr().unwrap();

        let cdp_srv = tokio::spawn(async move {
            let (s, _) = l1.accept().await.unwrap();
            tokio_tungstenite::accept_async(s).await.unwrap()
        });
        let v2_srv = tokio::spawn(async move {
            let (s, _) = l2.accept().await.unwrap();
            tokio_tungstenite::accept_async(s).await.unwrap()
        });

        let (mut cdp_cli, _) = tokio_tungstenite::connect_async(format!("ws://{a1}"))
            .await
            .unwrap();
        let (mut v2_cli, _) = tokio_tungstenite::connect_async(format!("ws://{a2}"))
            .await
            .unwrap();
        let mut cdp_srv = cdp_srv.await.unwrap();
        let mut v2_srv = v2_srv.await.unwrap();

        let mut state = V2RuntimeState {
            host,
            kitty_images: KittyImages::default(),
            debug: DebugBar::default(),
            start: Instant::now(),
            display: false,
            mode: Mode::Ansi,
            session: "s".to_owned(),
            endpoint: V2Endpoint {
                origin_ws: String::new(),
                headers: Vec::new(),
            },
            fps: 30,
            w: 256,
            h: 256,
            raw_files: false,
            has_frame: true,
            mouse_down: false,
            drag_anchor: None,
            last_copied_text: None,
            last_pointer: (0.0, 0.0),
            active_editable_node: Some(99),
            key_seq: 0,
            ptr_seq: 0,
            pinch_scale: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            last_vel: (0.0, 0.0),
            last_frame_seq: 0,
            consecutive_reattaches: 0,
            frames: 0,
            wire_bytes: 0,
            size: DisplaySize {
                cell_w: 8.0,
                cell_h: 16.0,
                cols: 32,
                rows: 16,
            },
            cell: AnsiCell { w: 8, h: 16 },
        };
        let mut next_id = 1;
        let grid = Some((256, 256));

        // 1. Non-passive region (220, 220) forwards mouseWheel over CDP.
        let blocked = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 220,
            row: 220,
            modifiers: KeyModifiers::NONE,
        };
        handle_v2_mouse_event(
            blocked,
            &mut state,
            &mut cdp_cli,
            &mut v2_cli,
            &mut next_id,
            "s",
            grid,
        )
        .await
        .unwrap();
        let cdp_wheel = read_cdp_req(&mut cdp_srv).await;
        assert_eq!(cdp_wheel["method"], "Input.dispatchMouseEvent");
        assert_eq!(cdp_wheel["params"]["type"], "mouseWheel");

        // 2. Passive region (50, 50) compositing sends S7 DatagramScroll.
        let local = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 50,
            row: 50,
            modifiers: KeyModifiers::NONE,
        };
        handle_v2_mouse_event(
            local,
            &mut state,
            &mut cdp_cli,
            &mut v2_cli,
            &mut next_id,
            "s",
            grid,
        )
        .await
        .unwrap();
        let dgram = decode_rbi_v2_packet(&read_ws_binary(&mut v2_srv).await).unwrap();
        assert!(matches!(
            dgram,
            DecodedRbiV2Packet::DatagramScroll {
                scroll_node_id: 1,
                ..
            }
        ));

        // 3. Key press on active editable node triggers S5 prediction and CDP key dispatch.
        let ev = Event::Key(event::KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        handle_v2_input_event(ev, &mut state, &mut cdp_cli, &mut v2_cli, &mut next_id, "s")
            .await
            .unwrap();
        assert_eq!(state.key_seq, 1);
        let cdp_key = read_cdp_req(&mut cdp_srv).await;
        assert_eq!(cdp_key["method"], "Input.dispatchKeyEvent");
        assert_eq!(cdp_key["params"]["_parawingInputSeq"], 1);

        // Non-predicted key release omits _parawingInputSeq.
        let rel = Event::Key(event::KeyEvent::new_with_kind(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ));
        handle_v2_input_event(
            rel,
            &mut state,
            &mut cdp_cli,
            &mut v2_cli,
            &mut next_id,
            "s",
        )
        .await
        .unwrap();
        assert_eq!(state.key_seq, 1);
        let cdp_rel = read_cdp_req(&mut cdp_srv).await;
        assert_eq!(cdp_rel["method"], "Input.dispatchKeyEvent");
        assert!(cdp_rel["params"].get("_parawingInputSeq").is_none());
    }

    type TestServerSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

    async fn make_v2_test_env() -> (
        V2RuntimeState,
        CdpSocket,
        CdpSocket,
        TestServerSocket,
        TestServerSocket,
    ) {
        let wasm_bytes = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let mut host = CompositorV2Host::new(&wasm_bytes).unwrap();
        host.ingest_frame(&crate::compositor_v2::tests::build_ksc2_test_frame())
            .unwrap();
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap();
        let a2 = l2.local_addr().unwrap();
        let cdp_srv = tokio::spawn(async move {
            let (s, _) = l1.accept().await.unwrap();
            tokio_tungstenite::accept_async(s).await.unwrap()
        });
        let v2_srv = tokio::spawn(async move {
            let (s, _) = l2.accept().await.unwrap();
            tokio_tungstenite::accept_async(s).await.unwrap()
        });
        let (cdp_cli, _) = tokio_tungstenite::connect_async(format!("ws://{a1}"))
            .await
            .unwrap();
        let (v2_cli, _) = tokio_tungstenite::connect_async(format!("ws://{a2}"))
            .await
            .unwrap();
        let state = V2RuntimeState {
            host,
            kitty_images: KittyImages::default(),
            debug: DebugBar::default(),
            start: Instant::now(),
            display: false,
            mode: Mode::Ansi,
            session: "s".to_owned(),
            endpoint: V2Endpoint {
                origin_ws: String::new(),
                headers: Vec::new(),
            },
            fps: 30,
            w: 256,
            h: 256,
            raw_files: false,
            has_frame: true,
            mouse_down: false,
            drag_anchor: None,
            last_copied_text: None,
            last_pointer: (0.0, 0.0),
            active_editable_node: Some(99),
            key_seq: 0,
            ptr_seq: 0,
            pinch_scale: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            last_vel: (0.0, 0.0),
            last_frame_seq: 0,
            consecutive_reattaches: 0,
            frames: 0,
            wire_bytes: 0,
            size: DisplaySize {
                cell_w: 8.0,
                cell_h: 16.0,
                cols: 32,
                rows: 16,
            },
            cell: AnsiCell { w: 8, h: 16 },
        };
        (
            state,
            cdp_cli,
            v2_cli,
            cdp_srv.await.unwrap(),
            v2_srv.await.unwrap(),
        )
    }

    #[tokio::test]
    async fn v2_pinch_zoom_updates_compositor_visual_viewport() {
        let (mut state, mut cdp_cli, mut v2_cli, _cdp_srv, _v2_srv) = make_v2_test_env().await;
        let mut next_id = 1;
        let grid = Some((256, 256));

        let zoom_in = Event::Key(event::KeyEvent::new(
            KeyCode::Char('='),
            KeyModifiers::CONTROL,
        ));
        handle_v2_input_event(
            zoom_in,
            &mut state,
            &mut cdp_cli,
            &mut v2_cli,
            &mut next_id,
            "s",
        )
        .await
        .unwrap();
        assert!((state.pinch_scale - V2_ZOOM_STEP).abs() < 1e-4);
        assert!((state.host.metrics(99).unwrap().vp_scale - V2_ZOOM_STEP).abs() < 1e-4);

        let wheel_zoom = event::MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 128,
            row: 128,
            modifiers: KeyModifiers::CONTROL,
        };
        handle_v2_mouse_event(
            wheel_zoom,
            &mut state,
            &mut cdp_cli,
            &mut v2_cli,
            &mut next_id,
            "s",
            grid,
        )
        .await
        .unwrap();
        assert!(state.pinch_scale > V2_ZOOM_STEP);
        assert!(state.pan_x > 0.0 && state.pan_y > 0.0);
        assert!((state.host.metrics(99).unwrap().vp_scale - state.pinch_scale).abs() < 1e-4);

        let reset = Event::Key(event::KeyEvent::new(
            KeyCode::Char('0'),
            KeyModifiers::CONTROL,
        ));
        handle_v2_input_event(
            reset,
            &mut state,
            &mut cdp_cli,
            &mut v2_cli,
            &mut next_id,
            "s",
        )
        .await
        .unwrap();
        assert_eq!(state.pinch_scale, 1.0);
        assert_eq!(state.pan_x, 0.0);
        assert_eq!(state.pan_y, 0.0);
        assert_eq!(state.host.metrics(99).unwrap().vp_scale, 1.0);
    }

    #[tokio::test]
    async fn v2_drag_selection_extracts_text_and_formats_osc52() {
        let (mut state, mut cdp_cli, mut v2_cli, mut cdp_srv, _v2_srv) = make_v2_test_env().await;
        let mut next_id = 1;
        let grid = Some((256, 256));

        for (kind, col, row) in [
            (MouseEventKind::Down(event::MouseButton::Left), 12, 20),
            (MouseEventKind::Drag(event::MouseButton::Left), 50, 24),
            (MouseEventKind::Up(event::MouseButton::Left), 50, 24),
        ] {
            let ev = event::MouseEvent {
                kind,
                column: col,
                row,
                modifiers: KeyModifiers::NONE,
            };
            handle_v2_mouse_event(
                ev,
                &mut state,
                &mut cdp_cli,
                &mut v2_cli,
                &mut next_id,
                "s",
                grid,
            )
            .await
            .unwrap();
        }
        assert_eq!(state.last_copied_text.as_deref(), Some("Hello"));
        assert_eq!(encode_osc52_copy("Hello"), "\x1b]52;c;SGVsbG8=\x07");
        let pressed = read_cdp_req(&mut cdp_srv).await;
        let released = read_cdp_req(&mut cdp_srv).await;
        assert_eq!(pressed["params"]["type"], "mousePressed");
        assert_eq!(released["params"]["type"], "mouseReleased");
    }

    #[tokio::test]
    async fn play_v2_reconnects_on_ws_close_with_tile_hashes_and_resync_ack() {
        use tokio_tungstenite::tungstenite::handshake::server;

        let wasm_bytes = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../engine/public/rbi/scene_host.wasm"
        ))
        .unwrap();
        let ksc2 = crate::compositor_v2::tests::build_ksc2_test_frame();

        let cdp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cdp_addr = cdp_listener.local_addr().unwrap();
        let v2_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v2_addr = v2_listener.local_addr().unwrap();

        let cdp_task = tokio::spawn(async move {
            let (stream, _) = cdp_listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut methods = Vec::new();
            let mut stream_starts = 0u32;
            loop {
                let Some(Ok(msg)) = ws.next().await else {
                    break;
                };
                if let Message::Text(text) = msg {
                    let req: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let method = req["method"].as_str().unwrap().to_owned();
                    let id = req["id"].as_u64().unwrap();
                    methods.push(method.clone());
                    let res = if method == "Parawing.startSceneStreamV2" {
                        stream_starts += 1;
                        serde_json::json!({ "wsPath": format!("/rbi/ws?token=t{stream_starts}") })
                    } else {
                        serde_json::json!({})
                    };
                    send_cdp_ok(&mut ws, id, res).await;
                    if method == "Parawing.stopSceneStreamV2" {
                        break;
                    }
                }
            }
            methods
        });

        let v2_task = tokio::spawn(async move {
            let (s1, _) = v2_listener.accept().await.unwrap();
            let mut uri1 = String::new();
            #[allow(clippy::result_large_err)]
            let mut ws1 = tokio_tungstenite::accept_hdr_async(
                s1,
                |req: &server::Request, resp: server::Response| {
                    uri1 = req.uri().to_string();
                    Ok(resp)
                },
            )
            .await
            .unwrap();
            assert_eq!(uri1, "/rbi/ws?token=t1");
            assert!(matches!(
                decode_rbi_v2_packet(&read_ws_binary(&mut ws1).await).unwrap(),
                DecodedRbiV2Packet::CreditGrant {
                    credits_granted: 2,
                    ..
                }
            ));
            ws1.send(Message::Binary(
                encode_reliable_frame_test(1, 1, &ksc2).into(),
            ))
            .await
            .unwrap();
            assert!(matches!(
                decode_rbi_v2_packet(&read_ws_binary(&mut ws1).await).unwrap(),
                DecodedRbiV2Packet::CreditGrant {
                    acked_frame_seq: 1,
                    ..
                }
            ));
            let _ = ws1.close(None).await;

            let (s2, _) = v2_listener.accept().await.unwrap();
            let mut uri2 = String::new();
            #[allow(clippy::result_large_err)]
            let mut ws2 = tokio_tungstenite::accept_hdr_async(
                s2,
                |req: &server::Request, resp: server::Response| {
                    uri2 = req.uri().to_string();
                    Ok(resp)
                },
            )
            .await
            .unwrap();
            let reattach = decode_rbi_v2_packet(&read_ws_binary(&mut ws2).await).unwrap();
            let credit = decode_rbi_v2_packet(&read_ws_binary(&mut ws2).await).unwrap();
            assert!(matches!(
                credit,
                DecodedRbiV2Packet::CreditGrant {
                    acked_frame_seq: 1,
                    ..
                }
            ));
            ws2.send(Message::Binary(
                encode_delta_resync_ack_test(1, 0, &ksc2).into(),
            ))
            .await
            .unwrap();
            while matches!(
                ws2.next().await,
                Some(Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_)))
            ) {}
            (uri2, reattach)
        });

        let (cdp_ws, _) = tokio_tungstenite::connect_async(format!("ws://{cdp_addr}"))
            .await
            .unwrap();
        let args = V2PlayArgs {
            url: "https://example.com".to_owned(),
            session: "sess-1".to_owned(),
            endpoint: V2Endpoint {
                origin_ws: format!("ws://{v2_addr}"),
                headers: Vec::new(),
            },
            mode: Mode::Ansi,
            seconds: Some(Duration::from_millis(450)),
            display: false,
            fps: 30,
            wasm_bytes,
            raw_files: false,
            w: 256,
            h: 256,
            cell: AnsiCell { w: 8, h: 16 },
            display_size: None,
            fallback_size: DisplaySize {
                cell_w: 8.0,
                cell_h: 16.0,
                cols: 32,
                rows: 16,
            },
        };
        let mut next_id = 1;
        let mut queued = VecDeque::new();
        let mut diag = Diagnostics::new(false);
        play_v2(cdp_ws, &mut next_id, &mut queued, args, &mut diag)
            .await
            .unwrap();

        let methods = cdp_task.await.unwrap();
        assert_eq!(
            methods,
            vec![
                "Emulation.setDeviceMetricsOverride",
                "Parawing.startSceneStreamV2",
                "Page.navigate",
                "Parawing.startSceneStreamV2",
                "Parawing.stopSceneStreamV2",
            ]
        );
        let (uri2, reattach) = v2_task.await.unwrap();
        assert_eq!(uri2, "/rbi/ws?token=t2");
        match reattach {
            DecodedRbiV2Packet::ReattachWithTileHashes {
                last_frame_seq,
                known_hashes,
                ..
            } => {
                assert_eq!(last_frame_seq, 1);
                assert_eq!(known_hashes, vec![0xBEEF]);
            }
            other => panic!("expected ReattachWithTileHashes, got {other:?}"),
        }
    }
}
