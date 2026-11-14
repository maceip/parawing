// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! R1-R2 freeze/thaw coordinator with real Linux CRIU CLI driver and signed Tier 1 fallback.

use crate::capsule::{
    enforce_baseline_compatibility, sha256_hex, verify_capsule_hash, CapsuleError, CapsuleManifest,
    RuntimeEnvironmentSpec,
};
use crate::rpc_pipe::{BoxedRead, BoxedWrite, PrwpPipeSession};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use parawing_core_host::native_host::NativeBlitzDocument;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyLease {
    pub lease_id: String,
    pub session_id: String,
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub revoked: bool,
    pub aes256_key: [u8; 32],
}

impl Drop for KeyLease {
    fn drop(&mut self) {
        self.aes256_key.zeroize();
    }
}

impl KeyLease {
    pub fn validate(&self, now_ms: u64, expected_session_id: &str) -> Result<(), FreezeError> {
        if self.revoked {
            return Err(FreezeError::StaleOrExpiredKeyLease(
                "key lease was revoked".to_string(),
            ));
        }
        if now_ms >= self.expires_at_ms {
            return Err(FreezeError::StaleOrExpiredKeyLease(format!(
                "key lease {} expired at {}",
                self.lease_id, self.expires_at_ms
            )));
        }
        if self.session_id != expected_session_id {
            return Err(FreezeError::StaleOrExpiredKeyLease(
                "key lease session mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreezeStateSnapshot {
    pub session_id: String,
    pub target_id: String,
    pub url: String,
    pub html: String,
    pub history: Vec<String>,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub scroll_x: f64,
    pub scroll_y: f64,
    pub session_storage: BTreeMap<String, String>,
    pub non_credential_form_values: BTreeMap<String, String>,
    pub js_state_json: String,
    pub last_input_seq: u32,
    pub acked_scroll_seq: u32,
    pub freeze_wall_ms: u64,
    pub monotonic_offset_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CriuProbe {
    pub available: bool,
    pub path: Option<String>,
    pub os: String,
    pub reason: String,
}

pub fn default_prwp_inherit_fd_labels() -> Vec<String> {
    vec![
        "fd[0]:prwp_stdin".to_string(),
        "fd[1]:prwp_stdout".to_string(),
        "fd[2]:prwp_stderr".to_string(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CriuBackendKind {
    #[default]
    LinuxNative,
    MacosLinuxCapsule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CriuImageRef {
    pub images_dir: String,
    pub args_used: Vec<String>,
    #[serde(default)]
    pub inherit_fd_labels: Vec<String>,
    #[serde(default)]
    pub backend: CriuBackendKind,
    #[serde(default)]
    pub sealed_archive_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealedCriuArchive {
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedCheckpointBundle {
    pub version: u32,
    pub session_id: String,
    pub epoch: u64,
    pub generation: u64,
    pub capsule_hash_hex: String,
    pub key_lease_id: String,
    pub criu_images: Option<CriuImageRef>,
    #[serde(default)]
    pub criu_dump_error: Option<String>,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub signature_b64: String,
    pub signer_pubkey_b64: String,
    pub drained_requests: usize,
    pub cut_requests: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThawViewerMetrics {
    pub thaw_duration_ms: u64,
    pub full_scene_bytes: usize,
    pub wall_clock_step_ms: i64,
    pub continuous_monotonic_offset_ns: u64,
    pub streams_replugged: bool,
}

#[derive(Debug, Clone)]
pub enum ThawOutcome {
    Tier2Criu {
        snapshot: FreezeStateSnapshot,
        full_ksc2_frame: Vec<u8>,
        viewer_metrics: ThawViewerMetrics,
        csprng_reseed_sha256: String,
        criu_restore_args: Vec<String>,
    },
    Tier1Fallback {
        reason: String,
        snapshot: FreezeStateSnapshot,
        full_ksc2_frame: Vec<u8>,
        viewer_metrics: ThawViewerMetrics,
        csprng_reseed_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreezeError {
    Rpc(String),
    Crypto(String),
    Compression(String),
    Signature(String),
    StaleOrExpiredKeyLease(String),
    CriuUnavailable(String),
    CriuExecution(String),
    InvalidBundle(String),
}

impl fmt::Display for FreezeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(m) => write!(f, "freeze RPC error: {m}"),
            Self::Crypto(m) => write!(f, "checkpoint crypto error: {m}"),
            Self::Compression(m) => write!(f, "checkpoint compression error: {m}"),
            Self::Signature(m) => write!(f, "checkpoint signature error: {m}"),
            Self::StaleOrExpiredKeyLease(m) => write!(f, "invalid key lease: {m}"),
            Self::CriuUnavailable(m) => write!(f, "CRIU unavailable: {m}"),
            Self::CriuExecution(m) => write!(f, "CRIU execution failed: {m}"),
            Self::InvalidBundle(m) => write!(f, "invalid checkpoint bundle: {m}"),
        }
    }
}

impl std::error::Error for FreezeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainSummary {
    pub drained: usize,
    pub cut: usize,
}

/// Tracks in-flight broker fetches so freeze waits briefly then cuts holdouts cleanly.
#[derive(Clone, Default)]
pub struct BrokerRequestTracker {
    in_flight: Arc<Mutex<HashMap<u64, bool>>>,
}

impl BrokerRequestTracker {
    pub fn begin(&self, req_id: u64, idempotent: bool) {
        if let Ok(mut map) = self.in_flight.lock() {
            map.insert(req_id, idempotent);
        }
    }

    pub fn complete(&self, req_id: u64) {
        if let Ok(mut map) = self.in_flight.lock() {
            map.remove(&req_id);
        }
    }

    pub fn pending_count(&self) -> usize {
        self.in_flight.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub async fn drain_or_cut(&self, budget: Duration) -> DrainSummary {
        let initial = self.pending_count();
        let deadline = tokio::time::Instant::now() + budget;
        while self.pending_count() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut map = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let cut = map.len();
        map.clear();
        DrainSummary {
            drained: initial.saturating_sub(cut),
            cut,
        }
    }
}

pub fn probe_criu_binary(explicit_path: Option<&Path>) -> CriuProbe {
    let os = std::env::consts::OS.to_string();
    if let Some(p) = explicit_path {
        let ok = p.exists();
        return CriuProbe {
            available: ok && os == "linux",
            path: Some(p.display().to_string()),
            os,
            reason: if ok {
                "explicit path checked".to_string()
            } else {
                "explicit criu path missing".to_string()
            },
        };
    }
    if os != "linux" {
        return CriuProbe {
            available: false,
            path: None,
            os,
            reason: "CRIU requires Linux kernel checkpoint/restore".to_string(),
        };
    }
    for candidate in ["/usr/sbin/criu", "/sbin/criu", "/usr/bin/criu"] {
        if Path::new(candidate).exists() {
            return CriuProbe {
                available: true,
                path: Some(candidate.to_string()),
                os,
                reason: "found Linux criu binary".to_string(),
            };
        }
    }
    CriuProbe {
        available: false,
        path: None,
        os,
        reason: "criu binary not found on Linux PATH".to_string(),
    }
}

/// Real Linux `criu` CLI driver building pre-dump, dump, and restore invocations.
pub struct CriuCliDriver {
    pub criu_bin: PathBuf,
}

impl CriuCliDriver {
    pub fn build_pre_dump_args(
        pid: u32,
        images_dir: &Path,
        prev_dir: Option<&Path>,
    ) -> Vec<String> {
        let mut args = vec![
            "pre-dump".to_string(),
            "--tree".to_string(),
            pid.to_string(),
            "--images-dir".to_string(),
            images_dir.display().to_string(),
        ];
        if let Some(prev) = prev_dir {
            args.push("--prev-images-dir".to_string());
            args.push(prev.display().to_string());
        }
        args
    }

    pub fn build_dump_args(pid: u32, images_dir: &Path, leave_running: bool) -> Vec<String> {
        let mut args = vec![
            "dump".to_string(),
            "--tree".to_string(),
            pid.to_string(),
            "--images-dir".to_string(),
            images_dir.display().to_string(),
            "--ext-unix-sk".to_string(),
            "--shell-job".to_string(),
        ];
        if leave_running {
            args.push("--leave-running".to_string());
        }
        args
    }

    pub fn build_restore_args(images_dir: &Path, inherit_fd_labels: &[String]) -> Vec<String> {
        let mut args = vec![
            "restore".to_string(),
            "--images-dir".to_string(),
            images_dir.display().to_string(),
            "--ext-unix-sk".to_string(),
            "--shell-job".to_string(),
        ];
        for label in inherit_fd_labels {
            args.push("--inherit-fd".to_string());
            args.push(label.clone());
        }
        args
    }

    pub fn run_dump(
        &self,
        pid: u32,
        images_dir: &Path,
        leave_running: bool,
    ) -> Result<Vec<String>, FreezeError> {
        if std::env::consts::OS != "linux" {
            return Err(FreezeError::CriuUnavailable(
                "criu dump is Linux-only".to_string(),
            ));
        }
        if !self.criu_bin.exists() {
            return Err(FreezeError::CriuUnavailable(format!(
                "missing criu binary at {}",
                self.criu_bin.display()
            )));
        }
        let args = Self::build_dump_args(pid, images_dir, leave_running);
        let out = Command::new(&self.criu_bin)
            .args(&args)
            .output()
            .map_err(|e| FreezeError::CriuExecution(format!("spawn criu: {e}")))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(FreezeError::CriuExecution(format!(
                "criu dump exited {}: {}",
                out.status,
                err.trim()
            )));
        }
        Ok(args)
    }

    pub fn run_restore(
        &self,
        images_dir: &Path,
        inherit_fd_labels: &[String],
    ) -> Result<Vec<String>, FreezeError> {
        if std::env::consts::OS != "linux" {
            return Err(FreezeError::CriuUnavailable(
                "criu restore is Linux-only".to_string(),
            ));
        }
        if !self.criu_bin.exists() {
            return Err(FreezeError::CriuUnavailable(format!(
                "missing criu binary at {}",
                self.criu_bin.display()
            )));
        }
        let args = Self::build_restore_args(images_dir, inherit_fd_labels);
        let out = Command::new(&self.criu_bin)
            .args(&args)
            .output()
            .map_err(|e| FreezeError::CriuExecution(format!("spawn criu restore: {e}")))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(FreezeError::CriuExecution(format!(
                "criu restore exited {}: {}",
                out.status,
                err.trim()
            )));
        }
        Ok(args)
    }
}

pub struct FreezeParams<'a> {
    pub rpc: Option<&'a PrwpPipeSession>,
    pub broker: &'a BrokerRequestTracker,
    pub drain_budget: Duration,
    pub manifest: &'a CapsuleManifest,
    pub env: &'a RuntimeEnvironmentSpec,
    pub key_lease: &'a KeyLease,
    pub signer: &'a Ed25519KeyPair,
    pub snapshot: &'a FreezeStateSnapshot,
    pub epoch: u64,
    pub generation: u64,
    pub pid: Option<u32>,
    pub criu_images_dir: Option<&'a Path>,
    pub inherit_fd_labels: Vec<String>,
    pub capsule_target: Option<&'a crate::macos_capsule::CapsuleDumpTarget>,
}

pub async fn freeze_session(
    params: FreezeParams<'_>,
) -> Result<SealedCheckpointBundle, FreezeError> {
    params
        .key_lease
        .validate(params.snapshot.freeze_wall_ms, &params.snapshot.session_id)?;
    if let Some(rpc) = params.rpc {
        rpc.prepare_freeze(Duration::from_secs(5))
            .await
            .map_err(|e| FreezeError::Rpc(e.to_string()))?;
    }
    let drain = params.broker.drain_or_cut(params.drain_budget).await;
    if let Some(rpc) = params.rpc {
        rpc.unplug();
    }

    let labels = if params.inherit_fd_labels.is_empty() {
        default_prwp_inherit_fd_labels()
    } else {
        params.inherit_fd_labels
    };
    let compressed = compress_snapshot(params.snapshot)?;
    let capsule_hash = params.manifest.compute_capsule_hash();
    let capsule_hash_hex = hex_str(&capsule_hash);
    let (criu_ref, criu_dump_error) = match params.capsule_target {
        Some(target) => dump_and_seal_capsule(
            target,
            params.criu_images_dir,
            params.env,
            labels,
            params.key_lease,
            &params.snapshot.session_id,
            params.epoch,
            params.generation,
            &capsule_hash_hex,
        )?,
        None => attempt_criu_dump(params.pid, params.criu_images_dir, params.env, labels),
    };
    let aad = build_aad(
        &params.snapshot.session_id,
        params.epoch,
        params.generation,
        &capsule_hash_hex,
    );
    let (nonce_b64, ciphertext_b64) =
        encrypt_aes256_gcm(&params.key_lease.aes256_key, &aad, &compressed)?;
    let criu_digest = criu_ref
        .as_ref()
        .and_then(|c| c.sealed_archive_sha256.as_deref());
    let sig_input = signing_statement(
        &params.snapshot.session_id,
        params.epoch,
        params.generation,
        &capsule_hash_hex,
        &nonce_b64,
        &ciphertext_b64,
        criu_digest,
    );
    let sig = params.signer.sign(&sig_input);

    Ok(SealedCheckpointBundle {
        version: 1,
        session_id: params.snapshot.session_id.clone(),
        epoch: params.epoch,
        generation: params.generation,
        capsule_hash_hex,
        key_lease_id: params.key_lease.lease_id.clone(),
        criu_images: criu_ref,
        criu_dump_error,
        nonce_b64,
        ciphertext_b64,
        signature_b64: BASE64_STANDARD.encode(sig.as_ref()),
        signer_pubkey_b64: BASE64_STANDARD.encode(params.signer.public_key().as_ref()),
        drained_requests: drain.drained,
        cut_requests: drain.cut,
    })
}

fn attempt_criu_dump(
    pid: Option<u32>,
    dir: Option<&Path>,
    env: &RuntimeEnvironmentSpec,
    inherit_fd_labels: Vec<String>,
) -> (Option<CriuImageRef>, Option<String>) {
    if env.os != "linux" || !env.criu_available {
        let probe = probe_criu_binary(None);
        return (None, Some(probe.reason));
    }
    let (Some(pid), Some(images_dir)) = (pid, dir) else {
        return (
            None,
            Some("CRIU dump skipped: missing child pid or images directory".to_string()),
        );
    };
    let probe = probe_criu_binary(None);
    let Some(criu_path) = probe.path else {
        return (None, Some(probe.reason));
    };
    if let Err(err) = std::fs::create_dir_all(images_dir) {
        return (None, Some(format!("create criu images dir: {err}")));
    }
    let driver = CriuCliDriver {
        criu_bin: PathBuf::from(criu_path),
    };
    match driver.run_dump(pid, images_dir, false) {
        Ok(args) => (
            Some(CriuImageRef {
                images_dir: images_dir.display().to_string(),
                args_used: args,
                inherit_fd_labels,
                backend: CriuBackendKind::LinuxNative,
                sealed_archive_sha256: None,
            }),
            None,
        ),
        Err(err) => (None, Some(err.to_string())),
    }
}

#[allow(clippy::too_many_arguments)]
fn dump_and_seal_capsule(
    target: &crate::macos_capsule::CapsuleDumpTarget,
    dir: Option<&Path>,
    env: &RuntimeEnvironmentSpec,
    inherit_fd_labels: Vec<String>,
    key_lease: &KeyLease,
    session_id: &str,
    epoch: u64,
    generation: u64,
    capsule_hash_hex: &str,
) -> Result<(Option<CriuImageRef>, Option<String>), FreezeError> {
    if env.os != "linux" || !env.criu_available {
        return Ok((
            None,
            Some("capsule CRIU dump skipped: environment lacks CRIU".to_string()),
        ));
    }
    let Some(images_dir) = dir else {
        return Ok((
            None,
            Some("capsule CRIU dump skipped: missing criu_images_dir".to_string()),
        ));
    };
    if let Err(err) = std::fs::create_dir_all(images_dir) {
        return Ok((None, Some(format!("create capsule images dir: {err}"))));
    }
    let (args_used, mut raw_archive) = crate::macos_capsule::dump_capsule_target(target)?;
    let criu_aad = build_criu_aad(session_id, epoch, generation, capsule_hash_hex);
    let enc_res = encrypt_aes256_gcm(&key_lease.aes256_key, &criu_aad, &raw_archive);
    raw_archive.zeroize();
    let (nonce_b64, ciphertext_b64) = enc_res?;
    let sealed_json = serde_json::to_vec(&SealedCriuArchive {
        nonce_b64,
        ciphertext_b64,
    })
    .map_err(|e| FreezeError::Crypto(format!("encode sealed CRIU archive: {e}")))?;
    let enc_path = images_dir.join("sealed-criu.enc");
    std::fs::write(&enc_path, &sealed_json)
        .map_err(|e| FreezeError::Crypto(format!("write sealed-criu.enc: {e}")))?;
    restrict_file_mode(&enc_path);
    let digest = sha256_hex(&sealed_json);
    Ok((
        Some(CriuImageRef {
            images_dir: images_dir.display().to_string(),
            args_used,
            inherit_fd_labels,
            backend: CriuBackendKind::MacosLinuxCapsule,
            sealed_archive_sha256: Some(digest),
        }),
        None,
    ))
}

fn restrict_file_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

pub struct ThawParams<'a> {
    pub bundle: &'a SealedCheckpointBundle,
    pub target_manifest: &'a CapsuleManifest,
    pub target_env: &'a RuntimeEnvironmentSpec,
    pub trusted_signer_pubkey: &'a [u8],
    pub key_lease: &'a KeyLease,
    pub now_wall_ms: u64,
    pub monotonic_elapsed_ms: u64,
    pub replug_rpc: Option<(&'a PrwpPipeSession, BoxedRead, BoxedWrite)>,
    pub replug_parked_rpc: Option<&'a PrwpPipeSession>,
    pub reseed_target_rpc: Option<&'a PrwpPipeSession>,
    pub inherit_fd_labels: Vec<String>,
    pub capsule_restore_out: Option<&'a Mutex<Option<crate::macos_capsule::CapsuleRestoredWorker>>>,
}

pub async fn thaw_session(params: ThawParams<'_>) -> Result<ThawOutcome, FreezeError> {
    let start = std::time::Instant::now();
    params
        .key_lease
        .validate(params.now_wall_ms, &params.bundle.session_id)?;
    verify_bundle_signature(params.bundle, params.trusted_signer_pubkey)?;

    let aad = build_aad(
        &params.bundle.session_id,
        params.bundle.epoch,
        params.bundle.generation,
        &params.bundle.capsule_hash_hex,
    );
    let plaintext = decrypt_aes256_gcm(
        &params.key_lease.aes256_key,
        &aad,
        &params.bundle.nonce_b64,
        &params.bundle.ciphertext_b64,
    )?;
    let snapshot = decompress_snapshot(&plaintext)?;
    let (entropy_hex, reseed_digest) = generate_csprng_reseed()?;

    let mut fallback_reason =
        determine_fallback_reason(params.bundle, params.target_manifest, params.target_env);
    let mut tier2_args = Vec::new();
    if fallback_reason.is_none() {
        match try_criu_restore(
            params.bundle,
            params.key_lease,
            &entropy_hex,
            &reseed_digest,
            &params.inherit_fd_labels,
            params.capsule_restore_out,
        ) {
            Ok(args) => tier2_args = args,
            Err(reason) => fallback_reason = Some(reason),
        }
    }

    let (streams_replugged, rpc_to_reseed) = if let Some((rpc, reader, writer)) = params.replug_rpc
    {
        rpc.replug(reader, writer);
        rpc.wait_handshake(Duration::from_secs(5))
            .await
            .map_err(|e| FreezeError::Rpc(e.to_string()))?;
        (true, params.reseed_target_rpc)
    } else if let Some(rpc) = params.replug_parked_rpc {
        rpc.replug_parked(Duration::from_secs(5))
            .await
            .map_err(|e| FreezeError::Rpc(e.to_string()))?;
        rpc.wait_handshake(Duration::from_secs(5))
            .await
            .map_err(|e| FreezeError::Rpc(e.to_string()))?;
        (true, Some(params.reseed_target_rpc.unwrap_or(rpc)))
    } else {
        (false, params.reseed_target_rpc)
    };

    if let Some(target_rpc) = rpc_to_reseed {
        target_rpc
            .call("reseedPrng", vec![Value::String(entropy_hex)], Vec::new())
            .await
            .map_err(|e| FreezeError::Rpc(format!("reseedPrng on thawed isolate: {e}")))?;
    }

    let mut doc = NativeBlitzDocument::from_html(
        &snapshot.html,
        &snapshot.url,
        snapshot.viewport_width,
        snapshot.viewport_height,
    );
    doc.set_page_scroll(snapshot.scroll_x, snapshot.scroll_y);
    let full_ksc2_frame = doc.render_ksc2(snapshot.acked_scroll_seq, snapshot.last_input_seq, &[]);
    let wall_step = params.now_wall_ms as i64 - snapshot.freeze_wall_ms as i64;
    let continuous_mono = snapshot
        .monotonic_offset_ns
        .saturating_add(params.monotonic_elapsed_ms.saturating_mul(1_000_000));
    let metrics = ThawViewerMetrics {
        thaw_duration_ms: start.elapsed().as_millis() as u64,
        full_scene_bytes: full_ksc2_frame.len(),
        wall_clock_step_ms: wall_step,
        continuous_monotonic_offset_ns: continuous_mono,
        streams_replugged,
    };

    match fallback_reason {
        None => Ok(ThawOutcome::Tier2Criu {
            snapshot,
            full_ksc2_frame,
            viewer_metrics: metrics,
            csprng_reseed_sha256: reseed_digest,
            criu_restore_args: tier2_args,
        }),
        Some(reason) => Ok(ThawOutcome::Tier1Fallback {
            reason,
            snapshot,
            full_ksc2_frame,
            viewer_metrics: metrics,
            csprng_reseed_sha256: reseed_digest,
        }),
    }
}

fn determine_fallback_reason(
    bundle: &SealedCheckpointBundle,
    target_manifest: &CapsuleManifest,
    target_env: &RuntimeEnvironmentSpec,
) -> Option<String> {
    let Ok(expected_bytes) = decode_hex_32(&bundle.capsule_hash_hex) else {
        return Some("invalid capsule_hash hex".to_string());
    };
    if let Err(err @ CapsuleError::CapsuleHashMismatch { .. }) =
        verify_capsule_hash(&expected_bytes, target_manifest)
    {
        return Some(format!("Tier1Fallback: {err}"));
    }
    if let Err(err) = enforce_baseline_compatibility(target_manifest, target_env) {
        return Some(format!("Tier1Fallback: {err}"));
    }
    if bundle.criu_images.is_none() {
        if let Some(err) = &bundle.criu_dump_error {
            return Some(format!("Tier1Fallback: {err}"));
        }
        let probe = probe_criu_binary(None);
        return Some(format!("Tier1Fallback: {}", probe.reason));
    }
    None
}

fn try_criu_restore(
    bundle: &SealedCheckpointBundle,
    key_lease: &KeyLease,
    reseed_entropy_hex: &str,
    reseed_digest: &str,
    override_labels: &[String],
    capsule_restore_out: Option<&Mutex<Option<crate::macos_capsule::CapsuleRestoredWorker>>>,
) -> Result<Vec<String>, String> {
    let Some(img) = &bundle.criu_images else {
        return Err("Tier1Fallback: no Tier 2 CRIU image present".to_string());
    };
    if img.backend == CriuBackendKind::MacosLinuxCapsule {
        return restore_sealed_capsule_criu(
            bundle,
            img,
            key_lease,
            reseed_entropy_hex,
            reseed_digest,
            capsule_restore_out,
        )
        .map_err(|e| format!("Tier1Fallback: {e}"));
    }
    let probe = probe_criu_binary(None);
    if !probe.available {
        return Err(format!("Tier1Fallback: {}", probe.reason));
    }
    let path = PathBuf::from(probe.path.unwrap_or_default());
    let driver = CriuCliDriver { criu_bin: path };
    let labels = if !override_labels.is_empty() {
        override_labels.to_vec()
    } else if !img.inherit_fd_labels.is_empty() {
        img.inherit_fd_labels.clone()
    } else {
        default_prwp_inherit_fd_labels()
    };
    driver
        .run_restore(Path::new(&img.images_dir), &labels)
        .map_err(|e| format!("Tier1Fallback: {e}"))
}

fn restore_sealed_capsule_criu(
    bundle: &SealedCheckpointBundle,
    img: &CriuImageRef,
    key_lease: &KeyLease,
    reseed_entropy_hex: &str,
    reseed_digest: &str,
    capsule_restore_out: Option<&Mutex<Option<crate::macos_capsule::CapsuleRestoredWorker>>>,
) -> Result<Vec<String>, FreezeError> {
    let expected_sha = img.sealed_archive_sha256.as_deref().ok_or_else(|| {
        FreezeError::InvalidBundle("missing sealed CRIU archive digest".to_string())
    })?;
    let enc_path = Path::new(&img.images_dir).join("sealed-criu.enc");
    let raw_enc = std::fs::read(&enc_path)
        .map_err(|e| FreezeError::InvalidBundle(format!("read {}: {e}", enc_path.display())))?;
    let actual_sha = sha256_hex(&raw_enc);
    if actual_sha != expected_sha {
        return Err(FreezeError::Signature(
            "sealed CRIU archive digest mismatch".to_string(),
        ));
    }
    let sealed: SealedCriuArchive = serde_json::from_slice(&raw_enc)
        .map_err(|e| FreezeError::InvalidBundle(format!("bad sealed-criu.enc JSON: {e}")))?;
    let criu_aad = build_criu_aad(
        &bundle.session_id,
        bundle.epoch,
        bundle.generation,
        &bundle.capsule_hash_hex,
    );
    let mut archive = decrypt_aes256_gcm(
        &key_lease.aes256_key,
        &criu_aad,
        &sealed.nonce_b64,
        &sealed.ciphertext_b64,
    )?;
    let restored =
        crate::macos_capsule::restore_capsule_archive(&archive, reseed_entropy_hex, reseed_digest);
    archive.zeroize();
    let (args, worker) = restored?;
    if let Some(slot) = capsule_restore_out {
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(worker);
        }
    }
    Ok(args)
}

pub fn verify_bundle_signature(
    bundle: &SealedCheckpointBundle,
    trusted_pubkey: &[u8],
) -> Result<(), FreezeError> {
    let sig_bytes = BASE64_STANDARD
        .decode(&bundle.signature_b64)
        .map_err(|e| FreezeError::Signature(format!("bad base64 sig: {e}")))?;
    let criu_digest = bundle
        .criu_images
        .as_ref()
        .and_then(|c| c.sealed_archive_sha256.as_deref());
    let stmt = signing_statement(
        &bundle.session_id,
        bundle.epoch,
        bundle.generation,
        &bundle.capsule_hash_hex,
        &bundle.nonce_b64,
        &bundle.ciphertext_b64,
        criu_digest,
    );
    let pk = UnparsedPublicKey::new(&signature::ED25519, trusted_pubkey);
    pk.verify(&stmt, &sig_bytes)
        .map_err(|_| FreezeError::Signature("Ed25519 verification failed".to_string()))
}

fn build_aad(session_id: &str, epoch: u64, generation: u64, capsule_hash_hex: &str) -> Vec<u8> {
    format!("parawing-freeze-v1:{session_id}:{epoch}:{generation}:{capsule_hash_hex}").into_bytes()
}

fn build_criu_aad(
    session_id: &str,
    epoch: u64,
    generation: u64,
    capsule_hash_hex: &str,
) -> Vec<u8> {
    format!("parawing-criu-v1:{session_id}:{epoch}:{generation}:{capsule_hash_hex}").into_bytes()
}

fn signing_statement(
    session_id: &str,
    epoch: u64,
    generation: u64,
    capsule_hash_hex: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    criu_archive_sha256: Option<&str>,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"parawing-checkpoint-sig-v1\0");
    hasher.update(session_id.as_bytes());
    hasher.update(epoch.to_le_bytes());
    hasher.update(generation.to_le_bytes());
    hasher.update(capsule_hash_hex.as_bytes());
    hasher.update(nonce_b64.as_bytes());
    hasher.update(ciphertext_b64.as_bytes());
    if let Some(digest) = criu_archive_sha256 {
        hasher.update(b"\0criu:");
        hasher.update(digest.as_bytes());
    }
    hasher.finalize().to_vec()
}

pub fn encrypt_aes256_gcm(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(String, String), FreezeError> {
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| FreezeError::Crypto(format!("getrandom nonce: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| FreezeError::Crypto(format!("cipher init: {e}")))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| FreezeError::Crypto(format!("encrypt: {e}")))?;
    Ok((
        BASE64_STANDARD.encode(nonce_bytes),
        BASE64_STANDARD.encode(ct),
    ))
}

pub fn decrypt_aes256_gcm(
    key: &[u8; 32],
    aad: &[u8],
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>, FreezeError> {
    let nonce_vec = BASE64_STANDARD
        .decode(nonce_b64)
        .map_err(|e| FreezeError::Crypto(format!("nonce base64: {e}")))?;
    if nonce_vec.len() != 12 {
        return Err(FreezeError::Crypto(
            "invalid AES-GCM nonce length".to_string(),
        ));
    }
    let ct = BASE64_STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| FreezeError::Crypto(format!("ciphertext base64: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| FreezeError::Crypto(format!("cipher init: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce_vec), Payload { msg: &ct, aad })
        .map_err(|_| FreezeError::Crypto("AES-256-GCM authentication failed".to_string()))
}

fn compress_snapshot(snap: &FreezeStateSnapshot) -> Result<Vec<u8>, FreezeError> {
    let json = serde_json::to_vec(snap)
        .map_err(|e| FreezeError::Compression(format!("serialize snapshot: {e}")))?;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&json)
        .map_err(|e| FreezeError::Compression(format!("zlib write: {e}")))?;
    enc.finish()
        .map_err(|e| FreezeError::Compression(format!("zlib finish: {e}")))
}

fn decompress_snapshot(bytes: &[u8]) -> Result<FreezeStateSnapshot, FreezeError> {
    let mut dec = ZlibDecoder::new(bytes);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| FreezeError::Compression(format!("zlib read: {e}")))?;
    serde_json::from_slice(&out)
        .map_err(|e| FreezeError::InvalidBundle(format!("bad snapshot JSON: {e}")))
}

fn generate_csprng_reseed() -> Result<(String, String), FreezeError> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy)
        .map_err(|e| FreezeError::Crypto(format!("csprng reseed: {e}")))?;
    let raw_hex = hex_str(&entropy);
    let digest = sha256_hex(&entropy);
    entropy.zeroize();
    Ok((raw_hex, digest))
}

fn hex_str(bytes: &[u8]) -> String {
    crate::capsule::hex_encode(bytes)
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], ()> {
    if hex.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
        *slot = byte;
    }
    Ok(out)
}

pub fn generate_test_ed25519_keypair() -> Ed25519KeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("pkcs8");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::CpuBaseline;
    use tokio::io::duplex;

    fn sample_lease(expires_at_ms: u64) -> KeyLease {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("random key");
        KeyLease {
            lease_id: "lease-1".to_string(),
            session_id: "sess-1".to_string(),
            epoch: 3,
            issued_at_ms: 1_000,
            expires_at_ms,
            revoked: false,
            aes256_key: key,
        }
    }

    fn sample_snapshot() -> FreezeStateSnapshot {
        let mut form = BTreeMap::new();
        form.insert("#note".to_string(), "draft message".to_string());
        let mut storage = BTreeMap::new();
        storage.insert("step".to_string(), "review".to_string());
        FreezeStateSnapshot {
            session_id: "sess-1".to_string(),
            target_id: "tab-1".to_string(),
            url: "https://app.example.test/form".to_string(),
            html: "<!DOCTYPE html><html><body style='margin:0'><div style='width:200px;height:100px;background:#115599'></div><input id='note' value='draft message'></body></html>".to_string(),
            history: vec!["https://app.example.test/form".to_string()],
            viewport_width: 640,
            viewport_height: 480,
            scroll_x: 0.0,
            scroll_y: 24.0,
            session_storage: storage,
            non_credential_form_values: form,
            js_state_json: r#"{"counter":12}"#.to_string(),
            last_input_seq: 9,
            acked_scroll_seq: 4,
            freeze_wall_ms: 5_000,
            monotonic_offset_ns: 900_000_000,
        }
    }

    #[test]
    fn criu_cli_args_and_probe_are_accurate() {
        let probe = probe_criu_binary(None);
        if std::env::consts::OS != "linux" {
            assert!(!probe.available);
            assert!(probe.reason.contains("Linux"));
        }
        let pre = CriuCliDriver::build_pre_dump_args(
            4242,
            Path::new("/tmp/imgs/2"),
            Some(Path::new("/tmp/imgs/1")),
        );
        assert_eq!(
            pre,
            vec![
                "pre-dump",
                "--tree",
                "4242",
                "--images-dir",
                "/tmp/imgs/2",
                "--prev-images-dir",
                "/tmp/imgs/1",
            ]
        );
        let dump = CriuCliDriver::build_dump_args(4242, Path::new("/tmp/imgs/2"), true);
        assert!(dump.contains(&"--ext-unix-sk".to_string()));
        assert!(dump.contains(&"--leave-running".to_string()));
        let restore = CriuCliDriver::build_restore_args(
            Path::new("/tmp/imgs/2"),
            &["fd[0]:rpc_in".to_string()],
        );
        assert!(restore.contains(&"--inherit-fd".to_string()));
    }

    #[tokio::test]
    async fn freeze_and_thaw_runs_safepoint_drain_unplug_replug_and_honest_tier1_fallback() {
        let signer = generate_test_ed25519_keypair();
        let manifest = CapsuleManifest::new(
            CpuBaseline::Aarch64Armv8Baseline,
            "sha256:bin-abc",
            "sha256:v8-xyz",
            true,
        );
        let env = RuntimeEnvironmentSpec::emulated_baseline(
            CpuBaseline::Aarch64Armv8Baseline,
            cfg!(target_os = "linux"),
        );
        let lease = sample_lease(50_000);
        let snap = sample_snapshot();

        let (c_half, s_half) = duplex(64 * 1024);
        let (cr, cw) = tokio::io::split(c_half);
        let (sr, sw) = tokio::io::split(s_half);
        let host_rpc = PrwpPipeSession::new(256 * 1024);
        let child_rpc = PrwpPipeSession::new(256 * 1024);
        host_rpc.plug_streams(Box::new(cr), Box::new(cw));
        child_rpc.plug_streams(Box::new(sr), Box::new(sw));
        host_rpc
            .wait_handshake(Duration::from_secs(2))
            .await
            .expect("host hs");
        child_rpc
            .wait_handshake(Duration::from_secs(2))
            .await
            .expect("child hs");

        let broker = BrokerRequestTracker::default();
        broker.begin(1, true);
        let broker_done = broker.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            broker_done.complete(1);
        });
        broker.begin(2, false);

        let bundle = freeze_session(FreezeParams {
            rpc: Some(&host_rpc),
            broker: &broker,
            drain_budget: Duration::from_millis(40),
            manifest: &manifest,
            env: &env,
            key_lease: &lease,
            signer: &signer,
            snapshot: &snap,
            epoch: 3,
            generation: 1,
            pid: Some(std::process::id()),
            criu_images_dir: None,
            inherit_fd_labels: default_prwp_inherit_fd_labels(),
            capsule_target: None,
        })
        .await
        .expect("freeze");
        assert_eq!(bundle.drained_requests, 1);
        assert_eq!(bundle.cut_requests, 1);
        assert!(bundle.criu_dump_error.is_some());

        let (c2, s2) = duplex(64 * 1024);
        let (c2r, c2w) = tokio::io::split(c2);
        let (s2r, s2w) = tokio::io::split(s2);
        child_rpc.replug(Box::new(s2r), Box::new(s2w));

        let expired_lease = sample_lease(1_500);
        let expired_err = thaw_session(ThawParams {
            bundle: &bundle,
            target_manifest: &manifest,
            target_env: &env,
            trusted_signer_pubkey: signer.public_key().as_ref(),
            key_lease: &expired_lease,
            now_wall_ms: 10_000,
            monotonic_elapsed_ms: 250,
            replug_rpc: None,
            replug_parked_rpc: None,
            reseed_target_rpc: None,
            inherit_fd_labels: Vec::new(),
            capsule_restore_out: None,
        })
        .await;
        assert!(matches!(
            expired_err,
            Err(FreezeError::StaleOrExpiredKeyLease(_))
        ));

        let outcome = thaw_session(ThawParams {
            bundle: &bundle,
            target_manifest: &manifest,
            target_env: &env,
            trusted_signer_pubkey: signer.public_key().as_ref(),
            key_lease: &lease,
            now_wall_ms: 15_000,
            monotonic_elapsed_ms: 250,
            replug_rpc: Some((&host_rpc, Box::new(c2r), Box::new(c2w))),
            replug_parked_rpc: None,
            reseed_target_rpc: None,
            inherit_fd_labels: Vec::new(),
            capsule_restore_out: None,
        })
        .await
        .expect("thaw");

        match outcome {
            ThawOutcome::Tier1Fallback {
                reason,
                snapshot: restored,
                full_ksc2_frame,
                viewer_metrics,
                csprng_reseed_sha256,
            } => {
                assert!(!reason.is_empty());
                assert_eq!(
                    restored.non_credential_form_values["#note"],
                    "draft message"
                );
                assert!(full_ksc2_frame.starts_with(b"KSC2"));
                assert_eq!(viewer_metrics.wall_clock_step_ms, 10_000);
                assert_eq!(viewer_metrics.continuous_monotonic_offset_ns, 1_150_000_000);
                assert!(viewer_metrics.streams_replugged);
                assert_eq!(csprng_reseed_sha256.len(), 64);
            }
            ThawOutcome::Tier2Criu { .. } => {
                assert_eq!(std::env::consts::OS, "linux");
            }
        }
    }

    #[tokio::test]
    async fn capsule_hash_mismatch_forces_tier1_fallback_even_with_valid_signature() {
        let signer = generate_test_ed25519_keypair();
        let m1 = CapsuleManifest::new(CpuBaseline::X8664V2Baseline, "sha256:v1", "sha256:s1", true);
        let m2 = CapsuleManifest::new(CpuBaseline::X8664V2Baseline, "sha256:v2", "sha256:s1", true);
        let env = RuntimeEnvironmentSpec::emulated_baseline(CpuBaseline::X8664V2Baseline, true);
        let lease = sample_lease(99_000);
        let snap = sample_snapshot();
        let broker = BrokerRequestTracker::default();

        let bundle = freeze_session(FreezeParams {
            rpc: None,
            broker: &broker,
            drain_budget: Duration::from_millis(5),
            manifest: &m1,
            env: &env,
            key_lease: &lease,
            signer: &signer,
            snapshot: &snap,
            epoch: 3,
            generation: 1,
            pid: None,
            criu_images_dir: None,
            inherit_fd_labels: default_prwp_inherit_fd_labels(),
            capsule_target: None,
        })
        .await
        .expect("freeze");

        let outcome = thaw_session(ThawParams {
            bundle: &bundle,
            target_manifest: &m2,
            target_env: &env,
            trusted_signer_pubkey: signer.public_key().as_ref(),
            key_lease: &lease,
            now_wall_ms: 12_000,
            monotonic_elapsed_ms: 50,
            replug_rpc: None,
            replug_parked_rpc: None,
            reseed_target_rpc: None,
            inherit_fd_labels: Vec::new(),
            capsule_restore_out: None,
        })
        .await
        .expect("thaw mismatch");

        match outcome {
            ThawOutcome::Tier1Fallback { reason, .. } => {
                assert!(reason.contains("capsule_hash mismatch"));
            }
            ThawOutcome::Tier2Criu { .. } => {
                panic!("capsule_hash mismatch must not restore Tier 2")
            }
        }
    }
}
