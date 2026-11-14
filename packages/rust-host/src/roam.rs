// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! R3-R6 roaming: AES-GCM pre-copy chunks, intent fencing, epoch leases, and egress streams.

use crate::capsule::sha256_hex;
use crate::freeze_thaw::{decrypt_aes256_gcm, encrypt_aes256_gcm, FreezeError, KeyLease};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io::{Read as _, Write as _};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoamError {
    Crypto(String),
    DigestMismatch {
        page_index: u64,
    },
    StaleEpochFenced {
        stale_epoch: u64,
        current_epoch: u64,
        downgraded_to_viewer: bool,
    },
    StreamNotFound(u64),
    StreamClosedReset(u64),
}

impl fmt::Display for RoamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(m) => write!(f, "roam crypto error: {m}"),
            Self::DigestMismatch { page_index } => {
                write!(f, "pre-copy chunk SHA-256 mismatch at page {page_index}")
            }
            Self::StaleEpochFenced {
                stale_epoch,
                current_epoch,
                ..
            } => write!(
                f,
                "stale epoch {stale_epoch} fenced by epoch {current_epoch}; downgraded to viewer"
            ),
            Self::StreamNotFound(id) => write!(f, "unknown egress stream {id}"),
            Self::StreamClosedReset(id) => {
                write!(f, "egress stream {id} reset on HomeEgress roam")
            }
        }
    }
}

impl std::error::Error for RoamError {}

impl From<FreezeError> for RoamError {
    fn from(err: FreezeError) -> Self {
        Self::Crypto(err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreCopyChunk {
    pub generation: u64,
    pub page_index: u64,
    pub chunk_sha256: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreCopyBatch {
    pub generation: u64,
    pub dirty_chunks: Vec<PreCopyChunk>,
    pub skipped_clean_pages: usize,
}

/// Ships only dirty pages as compressed, AES-256-GCM encrypted, content-addressed chunks.
pub struct PreCopySession {
    session_id: String,
    generation: u64,
    last_complete_generation: u64,
    shipped_hashes: HashMap<u64, String>,
}

impl PreCopySession {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            generation: 0,
            last_complete_generation: 0,
            shipped_hashes: HashMap::new(),
        }
    }

    pub fn last_complete_generation(&self) -> u64 {
        self.last_complete_generation
    }

    pub fn stage_dirty_pages(
        &mut self,
        pages: &[(u64, &[u8])],
        lease: &KeyLease,
    ) -> Result<PreCopyBatch, RoamError> {
        self.generation += 1;
        let generation = self.generation;
        let mut dirty_chunks = Vec::new();
        let mut skipped_clean_pages = 0usize;

        for &(page_index, raw) in pages {
            let hash = sha256_hex(raw);
            if self.shipped_hashes.get(&page_index) == Some(&hash) {
                skipped_clean_pages += 1;
                continue;
            }
            let compressed = zlib_compress(raw)?;
            let aad = precopy_aad(&self.session_id, generation, page_index, &hash);
            let (nonce_b64, ciphertext_b64) =
                encrypt_aes256_gcm(&lease.aes256_key, &aad, &compressed)?;
            self.shipped_hashes.insert(page_index, hash.clone());
            dirty_chunks.push(PreCopyChunk {
                generation,
                page_index,
                chunk_sha256: hash,
                nonce_b64,
                ciphertext_b64,
            });
        }

        self.last_complete_generation = generation;
        Ok(PreCopyBatch {
            generation,
            dirty_chunks,
            skipped_clean_pages,
        })
    }

    pub fn apply_precopy_batch(
        session_id: &str,
        lease: &KeyLease,
        batch: &PreCopyBatch,
        target_pages: &mut BTreeMap<u64, Vec<u8>>,
    ) -> Result<usize, RoamError> {
        let mut applied = 0usize;
        for chunk in &batch.dirty_chunks {
            let aad = precopy_aad(
                session_id,
                chunk.generation,
                chunk.page_index,
                &chunk.chunk_sha256,
            );
            let compressed = decrypt_aes256_gcm(
                &lease.aes256_key,
                &aad,
                &chunk.nonce_b64,
                &chunk.ciphertext_b64,
            )?;
            let plain = zlib_decompress(&compressed)?;
            let actual_hash = sha256_hex(&plain);
            if actual_hash != chunk.chunk_sha256 {
                return Err(RoamError::DigestMismatch {
                    page_index: chunk.page_index,
                });
            }
            target_pages.insert(chunk.page_index, plain);
            applied += 1;
        }
        Ok(applied)
    }
}

fn precopy_aad(session_id: &str, generation: u64, page_index: u64, hash: &str) -> Vec<u8> {
    format!("parawing-precopy-v1:{session_id}:{generation}:{page_index}:{hash}").into_bytes()
}

fn zlib_compress(bytes: &[u8]) -> Result<Vec<u8>, RoamError> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes)
        .map_err(|e| RoamError::Crypto(format!("zlib write: {e}")))?;
    enc.finish()
        .map_err(|e| RoamError::Crypto(format!("zlib finish: {e}")))
}

fn zlib_decompress(bytes: &[u8]) -> Result<Vec<u8>, RoamError> {
    let mut dec = ZlibDecoder::new(bytes);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| RoamError::Crypto(format!("zlib decompress: {e}")))?;
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentRecord {
    pub intent_id: String,
    pub generation: u64,
    pub method: String,
    pub url: String,
    pub request_sha256: String,
    pub idempotent: bool,
    pub committed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbruptLossDecision {
    RestoreExactState {
        generation: u64,
    },
    ForceTier1GetReload {
        blocked_intent_ids: Vec<String>,
        zero_double_submissions: bool,
    },
}

/// Logs pre-flight non-idempotent intents to decide exact thaw vs safe GET reload.
#[derive(Default)]
pub struct IntentCoordinator {
    records: Vec<IntentRecord>,
}

impl IntentCoordinator {
    pub fn record_outbound_intent(
        &mut self,
        intent_id: impl Into<String>,
        generation: u64,
        method: &str,
        url: &str,
        body: &[u8],
    ) {
        let upper = method.to_ascii_uppercase();
        let idempotent = matches!(upper.as_str(), "GET" | "HEAD" | "OPTIONS");
        let mut h = Sha256::new();
        h.update(upper.as_bytes());
        h.update(b":");
        h.update(url.as_bytes());
        h.update(b":");
        h.update(body);
        let digest = crate::capsule::hex_encode(&h.finalize());

        self.records.push(IntentRecord {
            intent_id: intent_id.into(),
            generation,
            method: upper,
            url: url.to_string(),
            request_sha256: digest,
            idempotent,
            committed: false,
        });
    }

    pub fn mark_committed(&mut self, intent_id: &str) -> bool {
        if let Some(rec) = self.records.iter_mut().find(|r| r.intent_id == intent_id) {
            rec.committed = true;
            return true;
        }
        false
    }

    pub fn resolve_abrupt_loss(&self, last_complete_generation: u64) -> AbruptLossDecision {
        let blocked: Vec<String> = self
            .records
            .iter()
            .filter(|r| !r.idempotent && !r.committed && r.generation >= last_complete_generation)
            .map(|r| r.intent_id.clone())
            .collect();

        if blocked.is_empty() {
            AbruptLossDecision::RestoreExactState {
                generation: last_complete_generation,
            }
        } else {
            AbruptLossDecision::ForceTier1GetReload {
                blocked_intent_ids: blocked,
                zero_double_submissions: true,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochLease {
    pub epoch: u64,
    pub owner_node_id: String,
    pub viewer_nodes: BTreeSet<String>,
}

/// Control plane enforcing single-owner increasing epochs and viewer downgrades.
pub struct EpochControlPlane {
    epoch: u64,
    owner_node_id: String,
    viewer_nodes: BTreeSet<String>,
}

impl EpochControlPlane {
    pub fn new(initial_owner: impl Into<String>) -> Self {
        Self {
            epoch: 1,
            owner_node_id: initial_owner.into(),
            viewer_nodes: BTreeSet::new(),
        }
    }

    pub fn current_lease(&self) -> EpochLease {
        EpochLease {
            epoch: self.epoch,
            owner_node_id: self.owner_node_id.clone(),
            viewer_nodes: self.viewer_nodes.clone(),
        }
    }

    pub fn transfer_ownership(&mut self, new_owner: impl Into<String>) -> EpochLease {
        let prev = std::mem::replace(&mut self.owner_node_id, new_owner.into());
        self.viewer_nodes.insert(prev);
        self.viewer_nodes.remove(&self.owner_node_id);
        self.epoch += 1;
        self.current_lease()
    }

    pub fn authorize_mutation(
        &mut self,
        claimed_epoch: u64,
        caller_node_id: &str,
    ) -> Result<(), RoamError> {
        if claimed_epoch != self.epoch || caller_node_id != self.owner_node_id {
            self.viewer_nodes.insert(caller_node_id.to_string());
            return Err(RoamError::StaleEpochFenced {
                stale_epoch: claimed_epoch,
                current_epoch: self.epoch,
                downgraded_to_viewer: true,
            });
        }
        Ok(())
    }

    pub fn is_viewer(&self, node_id: &str) -> bool {
        self.viewer_nodes.contains(node_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    StableEgress,
    HomeEgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StreamKind {
    Http,
    WebSocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StreamState {
    Open,
    BufferingForRoam,
    ClosedReset,
}

#[derive(Debug, Clone)]
pub struct EgressStreamEntry {
    pub stream_id: u64,
    pub site_origin: String,
    pub kind: StreamKind,
    pub mode: EgressMode,
    pub state: StreamState,
    pub buffered_inbound: VecDeque<Vec<u8>>,
    pub delivered_frames: Vec<Vec<u8>>,
    pub reconnect_count: u64,
}

/// Manages open HTTP/WebSocket streams across roam for StableEgress vs HomeEgress.
#[derive(Default)]
pub struct EgressStreamTable {
    next_id: u64,
    streams: HashMap<u64, EgressStreamEntry>,
}

impl EgressStreamTable {
    pub fn open_stream(
        &mut self,
        site_origin: impl Into<String>,
        kind: StreamKind,
        mode: EgressMode,
    ) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.streams.insert(
            id,
            EgressStreamEntry {
                stream_id: id,
                site_origin: site_origin.into(),
                kind,
                mode,
                state: StreamState::Open,
                buffered_inbound: VecDeque::new(),
                delivered_frames: Vec::new(),
                reconnect_count: 0,
            },
        );
        id
    }

    pub fn begin_roam(&mut self) {
        for entry in self.streams.values_mut() {
            if entry.state == StreamState::ClosedReset {
                continue;
            }
            match entry.mode {
                EgressMode::StableEgress => entry.state = StreamState::BufferingForRoam,
                EgressMode::HomeEgress => {
                    entry.state = StreamState::ClosedReset;
                    entry.buffered_inbound.clear();
                }
            }
        }
    }

    pub fn push_external_frame(&mut self, stream_id: u64, data: Vec<u8>) -> Result<(), RoamError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RoamError::StreamNotFound(stream_id))?;
        match entry.state {
            StreamState::Open => {
                entry.delivered_frames.push(data);
                Ok(())
            }
            StreamState::BufferingForRoam => {
                entry.buffered_inbound.push_back(data);
                Ok(())
            }
            StreamState::ClosedReset => Err(RoamError::StreamClosedReset(stream_id)),
        }
    }

    pub fn replug_after_roam(&mut self) -> Vec<u64> {
        let mut replugged = Vec::new();
        for entry in self.streams.values_mut() {
            if entry.mode == EgressMode::StableEgress
                && entry.state == StreamState::BufferingForRoam
            {
                while let Some(frame) = entry.buffered_inbound.pop_front() {
                    entry.delivered_frames.push(frame);
                }
                entry.state = StreamState::Open;
                replugged.push(entry.stream_id);
            }
        }
        replugged
    }

    pub fn entry(&self, stream_id: u64) -> Option<&EgressStreamEntry> {
        self.streams.get(&stream_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_pipe::{build_prwp_deno_v8_script, spawn_deno_worker};
    use tokio::time::Duration;

    fn test_lease() -> KeyLease {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("key");
        KeyLease {
            lease_id: "lease-roam".to_string(),
            session_id: "sess-roam".to_string(),
            epoch: 1,
            issued_at_ms: 100,
            expires_at_ms: 100_000,
            revoked: false,
            aes256_key: key,
        }
    }

    #[test]
    fn precopy_ships_only_dirty_encrypted_chunks_and_verifies_sha256() {
        let lease = test_lease();
        let mut sender = PreCopySession::new("sess-roam");
        let p0 = vec![1u8; 4096];
        let p1 = vec![2u8; 4096];
        let b1 = sender
            .stage_dirty_pages(&[(0, &p0), (1, &p1)], &lease)
            .expect("stage gen 1");
        assert_eq!(b1.dirty_chunks.len(), 2);
        assert_eq!(b1.skipped_clean_pages, 0);

        let mut replica = BTreeMap::new();
        assert_eq!(
            PreCopySession::apply_precopy_batch("sess-roam", &lease, &b1, &mut replica)
                .expect("apply gen 1"),
            2
        );
        assert_eq!(replica[&0], p0);

        let p1_updated = vec![9u8; 4096];
        let b2 = sender
            .stage_dirty_pages(&[(0, &p0), (1, &p1_updated)], &lease)
            .expect("stage gen 2");
        assert_eq!(b2.skipped_clean_pages, 1);
        assert_eq!(b2.dirty_chunks.len(), 1);
        assert_eq!(b2.dirty_chunks[0].page_index, 1);

        let applied2 = PreCopySession::apply_precopy_batch("sess-roam", &lease, &b2, &mut replica)
            .expect("apply gen 2");
        assert_eq!(applied2, 1);
        assert_eq!(replica[&1], p1_updated);
    }

    #[test]
    fn abrupt_loss_decides_exact_restore_vs_zero_double_submit_reload() {
        let mut intents = IntentCoordinator::default();
        intents.record_outbound_intent("i-get", 2, "GET", "https://shop.test/cart", &[]);
        assert_eq!(
            intents.resolve_abrupt_loss(2),
            AbruptLossDecision::RestoreExactState { generation: 2 }
        );

        intents.record_outbound_intent(
            "i-post",
            2,
            "POST",
            "https://shop.test/pay",
            br#"{"amount":500}"#,
        );
        assert_eq!(
            intents.resolve_abrupt_loss(2),
            AbruptLossDecision::ForceTier1GetReload {
                blocked_intent_ids: vec!["i-post".to_string()],
                zero_double_submissions: true,
            }
        );

        assert!(intents.mark_committed("i-post"));
        assert_eq!(
            intents.resolve_abrupt_loss(2),
            AbruptLossDecision::RestoreExactState { generation: 2 }
        );
    }

    #[test]
    fn epoch_control_plane_fences_stale_owner_and_downgrades_to_viewer() {
        let mut cp = EpochControlPlane::new("laptop-a");
        assert!(cp.authorize_mutation(1, "laptop-a").is_ok());

        let lease2 = cp.transfer_ownership("cloud-b");
        assert_eq!(lease2.epoch, 2);
        assert_eq!(lease2.owner_node_id, "cloud-b");
        assert!(cp.is_viewer("laptop-a"));

        let err = cp.authorize_mutation(1, "laptop-a").unwrap_err();
        assert_eq!(
            err,
            RoamError::StaleEpochFenced {
                stale_epoch: 1,
                current_epoch: 2,
                downgraded_to_viewer: true,
            }
        );
    }

    #[tokio::test]
    async fn stable_egress_preserves_open_ws_and_running_timer_across_roam_while_home_resets() {
        let mut worker = spawn_deno_worker(None, build_prwp_deno_v8_script(), &[])
            .await
            .expect("spawn deno");
        worker
            .session
            .call("startInterval", vec![serde_json::json!(10)], vec![])
            .await
            .expect("startInterval");
        worker
            .session
            .call(
                "evalJs",
                vec![serde_json::json!("__state.visited = 123")],
                vec![],
            )
            .await
            .expect("set state");
        tokio::time::sleep(Duration::from_millis(35)).await;
        let state_before = worker
            .session
            .call("getState", vec![], vec![])
            .await
            .expect("getState before");
        let ticks_before = state_before.value["ticks"].as_u64().unwrap_or(0);
        assert!(ticks_before >= 1);

        let mut streams = EgressStreamTable::default();
        let stable_ws = streams.open_stream(
            "https://chat.example.test",
            StreamKind::WebSocket,
            EgressMode::StableEgress,
        );
        let home_ws = streams.open_stream(
            "https://bank.local.test",
            StreamKind::WebSocket,
            EgressMode::HomeEgress,
        );

        let mut cp = EpochControlPlane::new("laptop");
        let lease = test_lease();
        let mut precopy = PreCopySession::new("sess-roam");
        let _batch = precopy
            .stage_dirty_pages(&[(0, state_before.value.to_string().as_bytes())], &lease)
            .expect("precopy");

        streams.begin_roam();
        streams
            .push_external_frame(stable_ws, b"msg-during-roam-1".to_vec())
            .expect("buffered on stable egress");
        streams
            .push_external_frame(stable_ws, b"msg-during-roam-2".to_vec())
            .expect("buffered #2 on stable egress");
        assert!(matches!(
            streams.push_external_frame(home_ws, b"msg-home".to_vec()),
            Err(RoamError::StreamClosedReset(_))
        ));

        let _new_lease = cp.transfer_ownership("cloud");
        let replugged = streams.replug_after_roam();
        assert_eq!(replugged, vec![stable_ws]);

        let stable_entry = streams.entry(stable_ws).expect("stable entry");
        assert_eq!(stable_entry.reconnect_count, 0);
        assert_eq!(stable_entry.state, StreamState::Open);
        assert_eq!(
            stable_entry.delivered_frames,
            vec![b"msg-during-roam-1".to_vec(), b"msg-during-roam-2".to_vec()]
        );
        assert_eq!(
            streams.entry(home_ws).expect("home entry").state,
            StreamState::ClosedReset
        );

        tokio::time::sleep(Duration::from_millis(25)).await;
        let state_after = worker
            .session
            .call("getState", vec![], vec![])
            .await
            .expect("getState after");
        let ticks_after = state_after.value["ticks"].as_u64().unwrap_or(0);
        assert!(ticks_after > ticks_before);
        assert_eq!(
            state_after.value["state"]["visited"],
            serde_json::json!(123)
        );

        worker.shutdown().await;
    }
}
