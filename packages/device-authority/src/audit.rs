// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Tamper-evident SHA-256 hash-chained, secret-redacted supervision audit log.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::control;

/// Environment variable configuring optional append-only JSONL audit persistence.
pub const AUDIT_PATH_ENV: &str = "PARAWING_AUDIT_PATH";

/// Genesis `prev_hash` value anchoring the first record of an `AuditLog`.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Parameters describing one redacted supervision event to append to an `AuditLog`.
#[derive(Clone, Debug, Default)]
pub struct AuditEventInput<'a> {
    /// Session identifier (`s_1`, ...).
    pub session_id: &'a str,
    /// Outcome label (`"opened"`, `"proposed"`, `"executed"`, `"rejected"`, `"error"`, ...).
    pub result: &'a str,
    /// Operation name (`"click"`, `"fill_form"`, `"credential.fill"`, `"passkey.assert"`, ...).
    pub operation: &'a str,
    /// Optional snapshot-local target handle (`el_N`).
    pub target_id: Option<&'a str>,
    /// Optional proposal identifier.
    pub proposal_id: Option<&'a str>,
    /// Pre-dispatch snapshot fingerprint.
    pub before_fingerprint: Option<&'a str>,
    /// Post-dispatch snapshot fingerprint.
    pub after_fingerprint: Option<&'a str>,
    /// Optional screenshot SHA-256 hash.
    pub screenshot_hash: Option<&'a str>,
    /// Actor that authorized or triggered the transition (`"user"`, `"agent"`, `"policy"`).
    pub decided_by: Option<&'a str>,
    /// Control surface (`"socket"`, `"glasses"`, `"ui"`, `"commit_gate"`).
    pub surface: Option<&'a str>,
}

/// Immutable, hash-chained supervision audit record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Human-readable identifier (`a_1`, `a_2`, ...).
    pub audit_id: String,
    /// 1-based monotonic sequence number within the log.
    pub seq: u64,
    /// Session identifier.
    pub session_id: String,
    /// ISO-8601 UTC timestamp.
    pub at: String,
    /// Optional bound proposal ID.
    pub proposal_id: Option<String>,
    /// Operation kind.
    pub operation: String,
    /// Optional target handle.
    pub target_id: Option<String>,
    /// Optional pre-action page fingerprint.
    pub before_fingerprint: Option<String>,
    /// Optional post-action page fingerprint.
    pub after_fingerprint: Option<String>,
    /// Optional screenshot digest.
    pub screenshot_hash: Option<String>,
    /// Optional decision principal.
    pub decided_by: Option<String>,
    /// Optional decision surface.
    pub surface: Option<String>,
    /// Outcome label.
    pub result: String,
    /// Hex SHA-256 `entry_hash` of the previous record (`GENESIS_HASH` for `seq == 1`).
    pub prev_hash: String,
    /// Hex SHA-256 digest committing `prev_hash` and every field of this record.
    pub entry_hash: String,
}

impl AuditEntry {
    /// Recomputes the canonical SHA-256 `entry_hash` for tamper verification.
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        push(&mut hasher, &self.prev_hash);
        push(&mut hasher, &self.audit_id);
        push(&mut hasher, &self.seq.to_string());
        push(&mut hasher, &self.session_id);
        push(&mut hasher, &self.at);
        push_opt(&mut hasher, self.proposal_id.as_deref());
        push(&mut hasher, &self.operation);
        push_opt(&mut hasher, self.target_id.as_deref());
        push_opt(&mut hasher, self.before_fingerprint.as_deref());
        push_opt(&mut hasher, self.after_fingerprint.as_deref());
        push_opt(&mut hasher, self.screenshot_hash.as_deref());
        push_opt(&mut hasher, self.decided_by.as_deref());
        push_opt(&mut hasher, self.surface.as_deref());
        push(&mut hasher, &self.result);
        format!("{:x}", hasher.finalize())
    }
}

fn push(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn push_opt(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(v) => {
            hasher.update([1]);
            push(hasher, v);
        }
        None => hasher.update([0]),
    }
}

/// Append-only hash-chained supervision audit log with optional `0600` JSONL persistence.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    path: Option<PathBuf>,
}

impl AuditLog {
    /// Creates an in-memory `AuditLog`, honoring `PARAWING_AUDIT_PATH` if set.
    pub fn new() -> Self {
        let env_path = std::env::var(AUDIT_PATH_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);
        Self {
            entries: Vec::new(),
            path: env_path,
        }
    }

    /// Creates an `AuditLog` mirroring every appended record to `path` (`0600` JSONL).
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            entries: Vec::new(),
            path: Some(path.into()),
        }
    }

    /// Appends a new hash-chained `AuditEntry` and returns a clone of it.
    pub fn append(&mut self, input: AuditEventInput<'_>) -> AuditEntry {
        let seq = (self.entries.len() as u64) + 1;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());

        let mut entry = AuditEntry {
            audit_id: format!("a_{seq}"),
            seq,
            session_id: input.session_id.to_string(),
            at: control::now_iso(),
            proposal_id: input.proposal_id.map(str::to_string),
            operation: input.operation.to_string(),
            target_id: input.target_id.map(str::to_string),
            before_fingerprint: input.before_fingerprint.map(str::to_string),
            after_fingerprint: input.after_fingerprint.map(str::to_string),
            screenshot_hash: input.screenshot_hash.map(str::to_string),
            decided_by: input.decided_by.map(str::to_string),
            surface: input.surface.map(str::to_string),
            result: input.result.to_string(),
            prev_hash,
            entry_hash: String::new(),
        };
        entry.entry_hash = entry.compute_hash();

        if let Some(ref path) = self.path {
            let _ = append_jsonl(path, &entry);
        }
        self.entries.push(entry.clone());
        entry
    }

    /// Returns all entries recorded in this log.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Returns entries filtered to a specific `session_id`.
    pub fn entries_for_session(&self, session_id: &str) -> Vec<AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.session_id == session_id)
            .cloned()
            .collect()
    }

    /// Verifies the full SHA-256 hash chain, returning `Err(index)` on the first tampered entry.
    pub fn verify_chain(&self) -> Result<(), usize> {
        let mut expected_prev = GENESIS_HASH;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.seq != (idx as u64) + 1 {
                return Err(idx);
            }
            if entry.prev_hash != expected_prev {
                return Err(idx);
            }
            if entry.entry_hash != entry.compute_hash() {
                return Err(idx);
            }
            expected_prev = &entry.entry_hash;
        }
        Ok(())
    }
}

fn append_jsonl(path: &Path, entry: &AuditEntry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let line = serde_json::to_string(entry).map_err(|e| format!("serialize audit: {e}"))?;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("open audit {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("write audit: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_hash_chain_and_detects_tampering() {
        let path =
            std::env::temp_dir().join(format!("parawing-audit-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut log = AuditLog::with_path(&path);
        log.append(AuditEventInput {
            session_id: "s_1",
            result: "opened",
            operation: "session.open",
            decided_by: Some("user"),
            surface: Some("socket"),
            ..Default::default()
        });
        log.append(AuditEventInput {
            session_id: "s_1",
            result: "executed",
            operation: "click",
            target_id: Some("el_1"),
            proposal_id: Some("p_1"),
            before_fingerprint: Some("fp_a"),
            after_fingerprint: Some("fp_b"),
            decided_by: Some("user"),
            surface: Some("glasses"),
            ..Default::default()
        });

        assert_eq!(log.verify_chain(), Ok(()));
        assert_eq!(log.entries()[1].prev_hash, log.entries()[0].entry_hash);

        let mut tampered = log.clone();
        tampered.entries[0].result = "forged".to_string();
        assert_eq!(tampered.verify_chain(), Err(0));

        let mut broken_link = log.clone();
        broken_link.entries[1].prev_hash = GENESIS_HASH.to_string();
        assert_eq!(broken_link.verify_chain(), Err(1));

        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.lines().count(), 2);
        let _ = std::fs::remove_file(&path);
    }
}
