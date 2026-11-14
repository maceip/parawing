// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Authenticated `0600` Unix-domain NDJSON control socket separating `Host` and `Agent` roles.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Maximum wire size (4 MiB) accepted for a single NDJSON control frame.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Authenticated principal role of a control socket connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Privileged human/host UI channel permitted to issue approvals and credential mutations.
    Host,
    /// Untrusted agent channel restricted to redacted observations and action proposals.
    Agent,
}

impl Role {
    /// Returns the wire identifier (`"host"` or `"agent"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Agent => "agent",
        }
    }
}

/// Inbound lifecycle or protocol event emitted by the control socket server.
#[derive(Clone, Debug)]
pub enum ControlEvent {
    /// Connection completed token authentication for `role`.
    Connect {
        /// Monotonic connection identifier.
        conn_id: u64,
        /// Authenticated channel role.
        role: Role,
    },
    /// Authenticated connection sent a parsed JSON control frame.
    Message {
        /// Monotonic connection identifier.
        conn_id: u64,
        /// Parsed JSON frame object.
        frame: Value,
    },
    /// Authenticated connection closed or disconnected.
    Disconnect {
        /// Monotonic connection identifier.
        conn_id: u64,
    },
}

struct PeerHandle {
    role: Role,
    tx: mpsc::Sender<String>,
}

/// Thread-safe registry of active authenticated control socket connections.
#[derive(Default)]
pub struct ControlHub {
    peers: Mutex<HashMap<u64, PeerHandle>>,
}

impl ControlHub {
    /// Creates an empty connection hub.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an authenticated connection writer channel.
    pub fn register(&self, conn_id: u64, role: Role, tx: mpsc::Sender<String>) {
        if let Ok(mut guard) = self.peers.lock() {
            guard.insert(conn_id, PeerHandle { role, tx });
        }
    }

    /// Removes a connection from the hub.
    pub fn unregister(&self, conn_id: u64) {
        if let Ok(mut guard) = self.peers.lock() {
            guard.remove(&conn_id);
        }
    }

    /// Serializes and queues `frame` as a single NDJSON line to `conn_id`.
    pub fn send(&self, conn_id: u64, frame: &Value) {
        let Ok(mut line) = serde_json::to_string(frame) else {
            return;
        };
        line.push('\n');
        if let Ok(guard) = self.peers.lock() {
            if let Some(peer) = guard.get(&conn_id) {
                let _ = peer.tx.send(line);
            }
        }
    }

    /// Returns active connection IDs matching `role` (or all connections when `None`).
    pub fn broadcast_ids(&self, role: Option<Role>) -> Vec<u64> {
        let Ok(guard) = self.peers.lock() else {
            return Vec::new();
        };
        guard
            .iter()
            .filter(|(_, peer)| role.is_none_or(|wanted| peer.role == wanted))
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Configuration for spawning a Unix-domain NDJSON control socket server.
#[derive(Clone, Debug)]
pub struct ControlServerConfig {
    /// Filesystem path of the `0600` Unix domain socket.
    pub socket_path: PathBuf,
    /// Bearer token required to authenticate as `Role::Host`.
    pub host_token: String,
    /// Bearer token required to authenticate as `Role::Agent`.
    pub agent_token: String,
    /// Engine name advertised in `hello.ok`.
    pub engine_name: String,
    /// Engine version advertised in `hello.ok`.
    pub engine_version: String,
}

/// RAII handle stopping the control socket listener and unlinking its socket on drop.
pub struct ControlServerHandle {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl ControlServerHandle {
    /// Returns the filesystem path of the bound Unix socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Signals listener and client threads to stop and removes the socket file.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for ControlServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Compares two bearer tokens in constant time, rejecting empty expected tokens.
pub fn token_eq(expected: &str, provided: &str) -> bool {
    let a = expected.as_bytes();
    let b = provided.as_bytes();
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for idx in 0..max_len {
        let av = a.get(idx).copied().unwrap_or(0);
        let bv = b.get(idx).copied().unwrap_or(0);
        diff |= usize::from(av ^ bv);
    }
    diff == 0 && !a.is_empty()
}

/// Spawns an authenticated `0600` Unix-domain NDJSON control server thread.
#[cfg(unix)]
pub fn spawn_server(
    config: ControlServerConfig,
    events_tx: mpsc::Sender<ControlEvent>,
    hub: Arc<ControlHub>,
) -> io::Result<ControlServerHandle> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    if let Some(parent) = config.socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let _ = std::fs::remove_file(&config.socket_path);
    let listener = UnixListener::bind(&config.socket_path)?;
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let socket_path = config.socket_path.clone();
    std::thread::Builder::new()
        .name("parawing-control-listener".to_string())
        .spawn(move || accept_loop(listener, config, events_tx, hub, stop_flag))?;

    Ok(ControlServerHandle { socket_path, stop })
}

#[cfg(unix)]
fn accept_loop(
    listener: std::os::unix::net::UnixListener,
    config: ControlServerConfig,
    events_tx: mpsc::Sender<ControlEvent>,
    hub: Arc<ControlHub>,
    stop: Arc<AtomicBool>,
) {
    let next_id = AtomicU64::new(1);
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
                let cfg = config.clone();
                let tx = events_tx.clone();
                let peer_hub = Arc::clone(&hub);
                let peer_stop = Arc::clone(&stop);
                let _ = std::thread::Builder::new()
                    .name(format!("parawing-control-conn-{conn_id}"))
                    .spawn(move || serve_connection(conn_id, stream, cfg, tx, peer_hub, peer_stop));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

#[cfg(unix)]
fn serve_connection(
    conn_id: u64,
    mut stream: std::os::unix::net::UnixStream,
    config: ControlServerConfig,
    events_tx: mpsc::Sender<ControlEvent>,
    hub: Arc<ControlHub>,
    stop: Arc<AtomicBool>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(reader_stream);

    let Some(role) = complete_handshake(&mut reader, &mut stream, &config, &stop) else {
        return;
    };

    let (write_tx, write_rx) = mpsc::channel::<String>();
    hub.register(conn_id, role, write_tx);
    let writer_handle = std::thread::spawn(move || pump_writes(stream, write_rx));
    let _ = events_tx.send(ControlEvent::Connect { conn_id, role });

    pump_reads(conn_id, &mut reader, &events_tx, &hub, &stop);

    hub.unregister(conn_id);
    let _ = events_tx.send(ControlEvent::Disconnect { conn_id });
    let _ = writer_handle.join();
}

#[cfg(unix)]
fn pump_writes(mut stream: std::os::unix::net::UnixStream, rx: mpsc::Receiver<String>) {
    for line in rx {
        if stream.write_all(line.as_bytes()).is_err() || stream.flush().is_err() {
            break;
        }
    }
}

#[cfg(unix)]
fn complete_handshake(
    reader: &mut BufReader<std::os::unix::net::UnixStream>,
    stream: &mut std::os::unix::net::UnixStream,
    config: &ControlServerConfig,
    stop: &AtomicBool,
) -> Option<Role> {
    let line = match read_bounded_line(reader, stop) {
        LineRead::Line(text) => text,
        LineRead::TooLarge => {
            write_direct_error(stream, None, "frame_too_large", "hello frame exceeds 4 MiB");
            return None;
        }
        LineRead::Closed => return None,
    };
    let Ok(hello) = serde_json::from_str::<Value>(&line) else {
        write_direct_error(
            stream,
            None,
            "invalid_frame",
            "hello frame is not valid JSON",
        );
        return None;
    };
    let req_id = hello.get("id").and_then(Value::as_str);
    if hello.get("type").and_then(Value::as_str) != Some("hello") {
        write_direct_error(stream, req_id, "handshake_required", "expected hello frame");
        return None;
    }
    if hello.get("protocol_version").and_then(Value::as_u64) != Some(1) {
        write_direct_error(
            stream,
            req_id,
            "unsupported_protocol",
            "supported protocol_version is 1",
        );
        return None;
    }
    let Some(role) = verify_role_token(&hello, config) else {
        write_direct_error(
            stream,
            req_id,
            "wrong_channel",
            "invalid role or bearer token",
        );
        return None;
    };
    let ok = build_hello_ok(req_id, role, config);
    write_direct_json(stream, &ok).ok()?;
    Some(role)
}

#[cfg(unix)]
fn verify_role_token(hello: &Value, config: &ControlServerConfig) -> Option<Role> {
    let role_str = hello.get("role").and_then(Value::as_str)?;
    let token = hello.get("token").and_then(Value::as_str)?;
    match role_str {
        "host" if token_eq(&config.host_token, token) => Some(Role::Host),
        "agent" if token_eq(&config.agent_token, token) => Some(Role::Agent),
        _ => None,
    }
}

#[cfg(unix)]
fn build_hello_ok(req_id: Option<&str>, role: Role, config: &ControlServerConfig) -> Value {
    json!({
        "type": "hello.ok",
        "id": req_id,
        "protocol_version": 1,
        "role": role.as_str(),
        "engine": {
            "name": config.engine_name,
            "version": config.engine_version,
        },
        "capabilities": [
            "multi_session",
            "blind_credentials",
            "sealed_blackout",
            "tokenized_substitution",
            "webauthn_l3",
            "hash_chained_audit"
        ],
    })
}

#[cfg(unix)]
fn write_direct_error(
    stream: &mut std::os::unix::net::UnixStream,
    req_id: Option<&str>,
    code: &str,
    message: &str,
) {
    let frame = json!({
        "type": "error",
        "id": req_id,
        "code": code,
        "message": message,
        "retryable": false,
    });
    let _ = write_direct_json(stream, &frame);
}

#[cfg(unix)]
fn write_direct_json(stream: &mut std::os::unix::net::UnixStream, frame: &Value) -> io::Result<()> {
    let mut encoded = serde_json::to_string(frame).unwrap_or_default();
    encoded.push('\n');
    stream.write_all(encoded.as_bytes())?;
    stream.flush()
}

#[cfg(unix)]
fn pump_reads(
    conn_id: u64,
    reader: &mut BufReader<std::os::unix::net::UnixStream>,
    events_tx: &mpsc::Sender<ControlEvent>,
    hub: &ControlHub,
    stop: &AtomicBool,
) {
    while !stop.load(Ordering::Relaxed) {
        match read_bounded_line(reader, stop) {
            LineRead::Line(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                forward_or_reject_line(conn_id, &line, events_tx, hub);
            }
            LineRead::TooLarge => {
                hub.send(
                    conn_id,
                    &json!({
                        "type": "error",
                        "code": "frame_too_large",
                        "message": "control frame exceeds 4 MiB limit",
                        "retryable": false,
                    }),
                );
                break;
            }
            LineRead::Closed => break,
        }
    }
}

#[cfg(unix)]
fn forward_or_reject_line(
    conn_id: u64,
    line: &str,
    events_tx: &mpsc::Sender<ControlEvent>,
    hub: &ControlHub,
) {
    match serde_json::from_str::<Value>(line) {
        Ok(frame) if frame.is_object() => {
            let _ = events_tx.send(ControlEvent::Message { conn_id, frame });
        }
        _ => {
            hub.send(
                conn_id,
                &json!({
                    "type": "error",
                    "code": "invalid_frame",
                    "message": "control frame must be a JSON object",
                    "retryable": false,
                }),
            );
        }
    }
}

#[cfg(unix)]
enum LineRead {
    Line(String),
    TooLarge,
    Closed,
}

#[cfg(unix)]
fn read_bounded_line(
    reader: &mut BufReader<std::os::unix::net::UnixStream>,
    stop: &AtomicBool,
) -> LineRead {
    let mut out = Vec::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            return LineRead::Closed;
        }
        match append_available_chunk(reader, &mut out) {
            ChunkStep::Done => {
                return String::from_utf8(out).map_or(LineRead::Closed, LineRead::Line);
            }
            ChunkStep::More => {}
            ChunkStep::TooLarge => return LineRead::TooLarge,
            ChunkStep::Timeout => continue,
            ChunkStep::Closed => {
                if out.is_empty() {
                    return LineRead::Closed;
                }
                return String::from_utf8(out).map_or(LineRead::Closed, LineRead::Line);
            }
        }
    }
}

#[cfg(unix)]
enum ChunkStep {
    Done,
    More,
    TooLarge,
    Timeout,
    Closed,
}

#[cfg(unix)]
fn append_available_chunk(
    reader: &mut BufReader<std::os::unix::net::UnixStream>,
    out: &mut Vec<u8>,
) -> ChunkStep {
    let available = match reader.fill_buf() {
        Ok([]) => return ChunkStep::Closed,
        Ok(slice) => slice,
        Err(err)
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut =>
        {
            return ChunkStep::Timeout;
        }
        Err(err) if err.kind() == io::ErrorKind::Interrupted => return ChunkStep::Timeout,
        Err(_) => return ChunkStep::Closed,
    };

    if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
        if out.len() + newline_pos > MAX_FRAME_BYTES {
            reader.consume(newline_pos + 1);
            return ChunkStep::TooLarge;
        }
        out.extend_from_slice(&available[..newline_pos]);
        reader.consume(newline_pos + 1);
        if out.last() == Some(&b'\r') {
            out.pop();
        }
        return ChunkStep::Done;
    }

    let chunk_len = available.len();
    if out.len() + chunk_len > MAX_FRAME_BYTES {
        reader.consume(chunk_len);
        return ChunkStep::TooLarge;
    }
    out.extend_from_slice(available);
    reader.consume(chunk_len);
    ChunkStep::More
}

/// Formats the current system clock as an ISO-8601 UTC millisecond timestamp.
pub fn now_iso() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = (total_secs / 86_400) as i64;
    let rem = total_secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Encodes `bytes` as standard RFC 4648 base64 with `=` padding.
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(B64_STD[usize::from(b0 >> 2)] as char);
        out.push(B64_STD[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))] as char);
        if chunk.len() > 1 {
            out.push(B64_STD[usize::from(((b1 & 0x0f) << 2) | (b2 >> 6))] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_STD[usize::from(b2 & 0x3f)] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes standard RFC 4648 base64 (both `=`-padded and unpadded), ignoring ASCII whitespace.
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut sextets = Vec::with_capacity(text.len());
    let mut seen_pad = false;
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_pad = true;
            continue;
        }
        if seen_pad {
            return None;
        }
        sextets.push(decode_b64_sextet(byte)?);
    }
    if sextets.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for group in sextets.chunks(4) {
        decode_sextet_group(group, &mut out);
    }
    Some(out)
}

fn decode_b64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_sextet_group(group: &[u8], out: &mut Vec<u8>) {
    out.push((group[0] << 2) | (group[1] >> 4));
    if group.len() > 2 {
        out.push((group[1] << 4) | (group[2] >> 2));
    }
    if group.len() > 3 {
        out.push((group[2] << 6) | group[3]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip_handles_padded_and_unpadded_inputs() {
        for len in 0..=48 {
            let input: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = b64_encode(&input);
            assert_eq!(b64_decode(&encoded).as_deref(), Some(input.as_slice()));
            let unpadded = encoded.trim_end_matches('=');
            assert_eq!(b64_decode(unpadded).as_deref(), Some(input.as_slice()));
        }
        assert_eq!(b64_decode("A"), None);
        assert_eq!(b64_decode("TWFu=A=="), None);
        assert_eq!(b64_decode("bad$char"), None);
    }

    #[test]
    fn token_eq_enforces_exact_non_empty_match() {
        assert!(token_eq("secret-token-123", "secret-token-123"));
        assert!(!token_eq("secret-token-123", "secret-token-124"));
        assert!(!token_eq("secret-token-123", "secret-token"));
        assert!(!token_eq("", ""));
    }

    #[test]
    fn now_iso_emits_rfc3339_utc_timestamp() {
        let stamp = now_iso();
        assert_eq!(stamp.len(), 24);
        assert!(stamp.ends_with('Z'));
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_server_enforces_0600_mode_and_role_tokens() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        static NEXT_CTRL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT_CTRL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .filter(|p| p.join("c.sock").as_os_str().len() < 90)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let dir = base.join(format!("pwc-{pid}-{seq}"));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let sock = dir.join("c.sock");
        let (tx, rx) = mpsc::channel();
        let hub = Arc::new(ControlHub::new());
        let handle = spawn_server(
            ControlServerConfig {
                socket_path: sock.clone(),
                host_token: "host-tok-99".to_string(),
                agent_token: "agent-tok-88".to_string(),
                engine_name: "parawing-authority".to_string(),
                engine_version: "0.1.0".to_string(),
            },
            tx,
            Arc::clone(&hub),
        )
        .expect("spawn control server");

        let mode = std::fs::metadata(&sock)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let mut bad = UnixStream::connect(&sock).expect("connect bad client");
        writeln!(
            bad,
            "{}",
            json!({"type": "hello", "id": "h0", "protocol_version": 1, "role": "host", "token": "wrong"})
        )
        .expect("write bad hello");
        let mut bad_reply = String::new();
        BufReader::new(bad)
            .read_line(&mut bad_reply)
            .expect("read bad reply");
        let bad_json: Value = serde_json::from_str(&bad_reply).expect("parse bad reply");
        assert_eq!(bad_json["code"], "wrong_channel");

        let mut host = UnixStream::connect(&sock).expect("connect host");
        writeln!(
            host,
            "{}",
            json!({"type": "hello", "id": "h1", "protocol_version": 1, "role": "host", "token": "host-tok-99"})
        )
        .expect("write host hello");
        let mut host_reader = BufReader::new(host.try_clone().expect("clone host"));
        let mut ok_line = String::new();
        host_reader.read_line(&mut ok_line).expect("read hello.ok");
        let ok_json: Value = serde_json::from_str(&ok_line).expect("parse hello.ok");
        assert_eq!(ok_json["type"], "hello.ok");
        assert_eq!(ok_json["role"], "host");

        let connect_evt = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("connect event");
        let conn_id = match connect_evt {
            ControlEvent::Connect {
                conn_id,
                role: Role::Host,
            } => conn_id,
            other => panic!("unexpected event: {other:?}"),
        };

        writeln!(host, "{}", json!({"type": "ping", "id": "p1", "seq": 1})).expect("write ping");
        let msg_evt = rx.recv_timeout(Duration::from_secs(2)).expect("msg event");
        match msg_evt {
            ControlEvent::Message {
                conn_id: got_id,
                frame,
            } => {
                assert_eq!(got_id, conn_id);
                assert_eq!(frame["type"], "ping");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        hub.send(conn_id, &json!({"type": "pong", "id": "p1"}));
        let mut pong_line = String::new();
        host_reader.read_line(&mut pong_line).expect("read pong");
        let pong_json: Value = serde_json::from_str(&pong_line).expect("parse pong");
        assert_eq!(pong_json["type"], "pong");

        handle.shutdown();
        assert!(!sock.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
