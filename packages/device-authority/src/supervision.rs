// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Engine-agnostic multi-session supervision state machine, proposal gating, and sealed blackout.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::audit::{AuditEntry, AuditEventInput, AuditLog};
use crate::command::{FormFieldCommand, PageCommand};
use crate::control::{self, ControlEvent, ControlHub, Role};
use crate::credentials::{
    BrokerError, CredentialApproval, CredentialBroker, CredentialFieldKind, CredentialFillMode,
    CredentialFillRequest, CredentialMatch, CredentialSink, LocalCredentialBroker,
    LocalPasskeyBroker, PasskeyBroker, PasskeyCeremonyId, PasskeyRequest, PasskeyStatus,
    RegistrationRequest, TokenizedSubstitutionSpec, redact_username,
};
use crate::observe::{ElementSnapshot, PageSnapshot, ValueState};
use crate::recall::{self, RecallStore};

/// Lifecycle state of a supervised browser session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlState {
    /// Agent may observe and submit one action proposal at a time.
    Agent,
    /// Proposal is staged and waiting for an explicit human or policy decision.
    AwaitingDecision,
    /// Sensitive field or challenge requires human intervention (`control.take` or broker).
    ActionRequired,
    /// Human has taken direct interactive control of the target.
    Human,
    /// Agent reported task completion (`task.done`).
    Done,
    /// Human explicitly stopped the session (`stop`).
    Stopped,
    /// Session halted fail-safe (e.g. last `Role::Host` transport disconnected).
    Error,
}

impl ControlState {
    /// Returns the wire state string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::AwaitingDecision => "awaiting_decision",
            Self::ActionRequired => "action_required",
            Self::Human => "human",
            Self::Done => "done",
            Self::Stopped => "stopped",
            Self::Error => "error",
        }
    }

    /// Returns true when the session has permanently ended (`done`, `stopped`, or `error`).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Stopped | Self::Error)
    }
}

/// Destination channel selector for outbound supervision frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutTarget {
    /// Single connection identifier.
    Conn(u64),
    /// All connected `Role::Host` peers.
    Host,
    /// All connected `Role::Agent` peers.
    Agent,
    /// Every connected peer across both roles.
    Both,
}

/// Engine-neutral browser target interface implemented by CDP/WebView hosts.
pub trait WebPageBackend {
    /// Opens a new isolated page target, optionally navigating to `start_url`.
    fn open_target(&mut self, start_url: Option<&str>, background: bool) -> Result<u64, String>;

    /// Closes a previously opened page target.
    fn close_target(&mut self, target_id: u64);

    /// Produces a fresh redacted `PageSnapshot` for `target_id`.
    fn observe_target(&mut self, target_id: u64) -> Option<PageSnapshot>;

    /// Returns all `node_ref` handles ever issued by the current page instance of `target_id`.
    fn known_node_refs(&self, target_id: u64) -> HashSet<String>;

    /// Returns true if `target_id` has backward history entries.
    fn can_go_back(&self, target_id: u64) -> bool;

    /// Returns true if `target_id` has forward history entries.
    fn can_go_forward(&self, target_id: u64) -> bool;

    /// Verifies live hit-test / visibility / enabled state immediately before click dispatch.
    fn check_interactable(
        &self,
        target_id: u64,
        element: &ElementSnapshot,
    ) -> Result<(), &'static str>;

    /// Executes a validated `PageCommand` on `target_id`.
    fn dispatch_command(
        &mut self,
        target_id: u64,
        command: &PageCommand,
        snapshot: &PageSnapshot,
    ) -> Result<(), String>;

    /// Injects a secret field directly into `target_id` during a `Sealed` credential fill.
    fn set_credential_field(
        &mut self,
        target_id: u64,
        field: CredentialFieldKind,
        value: &str,
    ) -> Result<(), BrokerError>;

    /// Optional PNG screenshot capture returning `(png_bytes, sha256_hex, frame_id)`.
    fn capture_screenshot(&mut self, target_id: u64) -> Option<(Vec<u8>, String, u64)> {
        let _ = target_id;
        None
    }
}

/// Prepared blind credential fill bound to a pending proposal.
#[derive(Clone, Debug)]
pub struct CredentialFillPlan {
    /// Validated origin for the credential fill.
    pub origin: String,
    /// Redacted credential match selected for human approval.
    pub chosen: CredentialMatch,
    /// Sensitive field kinds to populate on approval.
    pub fields: Vec<CredentialFieldKind>,
    /// Execution mode (`Sealed` DOM fill or `Tokenized` transport substitution).
    pub mode: CredentialFillMode,
}

/// Staged agent action proposal awaiting human or commit-gate decision.
#[derive(Clone, Debug)]
pub struct PendingProposal {
    /// Unique proposal identifier within the session.
    pub proposal_id: String,
    /// Snapshot numeric identifier (`o_<snapshot_id>`).
    pub snapshot_id: u64,
    /// Page instance identifier bound at proposal time.
    pub page_id: u64,
    /// Snapshot SHA-256 fingerprint bound at proposal time.
    pub fingerprint: String,
    /// Document generation counter bound at proposal time.
    pub generation: u64,
    /// Raw protocol operation JSON object.
    pub operation: Value,
    /// Human-facing rationale or broker prompt.
    pub rationale: String,
    /// Action sensitivity classification (`"observe"`, `"act"`, or `"sensitive"`).
    pub classification: String,
    /// True when explicit human approval is mandatory even under commit-only gating.
    pub requires_approval: bool,
    /// Associated WebAuthn ceremony ID when `operation.kind` is `passkey.*`.
    pub ceremony_id: Option<String>,
    /// Associated credential fill plan when `operation.kind` is `credential.fill`.
    pub credential_fill: Option<CredentialFillPlan>,
}

/// Independent state for one supervised session bound to a `target_id`.
#[derive(Clone, Debug)]
pub struct SupervisionSession {
    /// Session identifier (`s_1`, `s_2`, ...).
    pub id: String,
    /// Backend page target identifier.
    pub target_id: u64,
    /// Human-readable task title.
    pub title: String,
    /// Current lifecycle state.
    pub state: ControlState,
    /// Monotonic outbound session event counter.
    pub event_seq: u64,
    /// Last snapshot observed on this session, used to validate `propose`.
    pub last_snapshot: Option<PageSnapshot>,
    /// Whether `last_snapshot` remains fresh for new proposals.
    pub snapshot_valid: bool,
    /// In-flight proposal awaiting decision, if any.
    pub pending: Option<PendingProposal>,
    /// Proposal IDs ever submitted in this session (prevents replay).
    pub seen_proposals: HashSet<String>,
    /// Proposal IDs whose decisions have already been consumed (single-use).
    pub used_decisions: HashSet<String>,
    /// Active `ActionRequired` reason, if in `ControlState::ActionRequired`.
    pub action_required_kind: Option<String>,
    /// SHA-256 hex digest of the most recent screenshot captured on this session.
    pub last_screenshot_hash: Option<String>,
    /// True when opened as a background session.
    pub background: bool,
    /// Whether navigations to loopback, RFC 1918, or link-local hosts are permitted.
    pub allow_local_network: bool,
    /// `(page_id, generation)` blacked out from `Role::Agent` observation after a `Sealed` fill.
    pub sealed_blackout: Option<(u64, u64)>,
}

/// Parameters identifying a decision on a pending proposal.
#[derive(Clone, Copy, Debug)]
pub struct DecisionInput<'a> {
    /// Target session identifier.
    pub session_id: &'a str,
    /// Proposal identifier being approved or rejected.
    pub proposal_id: &'a str,
    /// Expected snapshot SHA-256 fingerprint.
    pub fingerprint: &'a str,
    /// Expected document generation counter.
    pub generation: u64,
    /// True to approve and execute; false to reject.
    pub approve: bool,
    /// Principal recording the decision (`"user"`, `"policy"`).
    pub decided_by: &'a str,
    /// Control surface (`"socket"`, `"glasses"`, `"ui"`, `"commit_gate"`).
    pub surface: &'a str,
}

#[derive(Clone, Copy, Debug)]
struct ConnState {
    role: Role,
    last_seq: Option<u64>,
}

struct ValidatedProposal {
    rationale: String,
    classification: String,
    requires_approval: bool,
    ceremony_id: Option<String>,
    credential_fill: Option<CredentialFillPlan>,
    target_label: Option<String>,
    target_href: Option<String>,
    target_bounds: Option<Value>,
}

/// Multi-session device authority & supervision engine generic over `WebPageBackend`.
pub struct SupervisionEngine<B: WebPageBackend> {
    backend: B,
    credential_broker: LocalCredentialBroker,
    passkey_broker: LocalPasskeyBroker,
    recall_store: RecallStore,
    audit_log: AuditLog,
    sessions: HashMap<String, SupervisionSession>,
    default_session_id: Option<String>,
    next_session_num: u64,
    conns: HashMap<u64, ConnState>,
    outbox: Vec<(OutTarget, Value)>,
    hub: Option<Arc<ControlHub>>,
    supervise_commits_only: bool,
}

impl<B: WebPageBackend> SupervisionEngine<B> {
    /// Creates a supervision engine backed by macOS Keychain brokers and default stores.
    pub fn new(backend: B) -> Self {
        Self::with_components(
            backend,
            LocalCredentialBroker::new(),
            LocalPasskeyBroker::new(),
            recall::load_store(),
            AuditLog::new(),
        )
    }

    /// Creates an isolated in-memory supervision engine for deterministic tests and sandboxes.
    pub fn in_memory(backend: B) -> Self {
        Self::with_components(
            backend,
            LocalCredentialBroker::in_memory(),
            LocalPasskeyBroker::in_memory(),
            RecallStore::default(),
            AuditLog::default(),
        )
    }

    /// Creates a supervision engine with explicit brokers, recall store, and audit log.
    pub fn with_components(
        backend: B,
        credential_broker: LocalCredentialBroker,
        passkey_broker: LocalPasskeyBroker,
        recall_store: RecallStore,
        audit_log: AuditLog,
    ) -> Self {
        Self {
            backend,
            credential_broker,
            passkey_broker,
            recall_store,
            audit_log,
            sessions: HashMap::new(),
            default_session_id: None,
            next_session_num: 1,
            conns: HashMap::new(),
            outbox: Vec::new(),
            hub: None,
            supervise_commits_only: false,
        }
    }

    /// Attaches a `ControlHub` so `flush_outbox()` delivers frames over Unix sockets.
    pub fn attach_hub(&mut self, hub: Arc<ControlHub>) {
        self.hub = Some(hub);
    }

    /// Configures commit-only gating (auto-approves non-sensitive actions; gates sensitive ones).
    pub fn set_supervise_commits_only(&mut self, enabled: bool) {
        self.supervise_commits_only = enabled;
    }

    /// Borrows the underlying `WebPageBackend`.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutably borrows the underlying `WebPageBackend`.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Borrows the hash-chained `AuditLog`.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Borrows the `LocalCredentialBroker`.
    pub fn credential_broker(&self) -> &LocalCredentialBroker {
        &self.credential_broker
    }

    /// Mutably borrows the `LocalPasskeyBroker`.
    pub fn passkey_broker_mut(&mut self) -> &mut LocalPasskeyBroker {
        &mut self.passkey_broker
    }

    /// Mutably borrows the `RecallStore`.
    pub fn recall_store_mut(&mut self) -> &mut RecallStore {
        &mut self.recall_store
    }

    /// Consumes a one-time `$cred:<token>` substitution table bound to `(ceremony_id, origin)`.
    pub fn take_tokenized_spec(
        &mut self,
        ceremony_id: &str,
        origin: &str,
    ) -> Result<TokenizedSubstitutionSpec, BrokerError> {
        self.credential_broker
            .take_tokenized_spec(ceremony_id, origin)
    }

    /// Looks up a session by identifier.
    pub fn session(&self, session_id: &str) -> Option<&SupervisionSession> {
        self.sessions.get(session_id)
    }

    /// Drains queued `(OutTarget, Value)` frames without requiring a `ControlHub`.
    pub fn drain_outbox(&mut self) -> Vec<(OutTarget, Value)> {
        std::mem::take(&mut self.outbox)
    }

    /// Flushes all queued frames through the attached `ControlHub`, if present.
    pub fn flush_outbox(&mut self) {
        let Some(hub) = self.hub.clone() else {
            return;
        };
        for (target, frame) in self.drain_outbox() {
            let recipients = self.resolve_recipients(target);
            for conn_id in recipients {
                hub.send(conn_id, &frame);
            }
        }
    }

    fn resolve_recipients(&self, target: OutTarget) -> Vec<u64> {
        match target {
            OutTarget::Conn(id) => vec![id],
            OutTarget::Host => self
                .conns
                .iter()
                .filter(|(_, c)| c.role == Role::Host)
                .map(|(id, _)| *id)
                .collect(),
            OutTarget::Agent => self
                .conns
                .iter()
                .filter(|(_, c)| c.role == Role::Agent)
                .map(|(id, _)| *id)
                .collect(),
            OutTarget::Both => self.conns.keys().copied().collect(),
        }
    }

    /// Processes a single `ControlEvent` from the socket transport and flushes outbound frames.
    pub fn handle_event(&mut self, event: ControlEvent) {
        match event {
            ControlEvent::Connect { conn_id, role } => {
                self.conns.insert(
                    conn_id,
                    ConnState {
                        role,
                        last_seq: None,
                    },
                );
            }
            ControlEvent::Message { conn_id, frame } => {
                self.handle_frame(conn_id, frame);
            }
            ControlEvent::Disconnect { conn_id } => {
                self.handle_disconnect(conn_id);
            }
        }
        self.flush_outbox();
    }

    fn handle_disconnect(&mut self, conn_id: u64) {
        let removed = self.conns.remove(&conn_id);
        let lost_last_host = removed.is_some_and(|c| c.role == Role::Host)
            && !self.conns.values().any(|c| c.role == Role::Host);
        if !lost_last_host {
            return;
        }
        let active_ids: Vec<String> = self
            .sessions
            .values()
            .filter(|s| !s.state.is_terminal())
            .map(|s| s.id.clone())
            .collect();
        for sid in active_ids {
            self.fail_session_on_transport_loss(&sid);
        }
    }

    fn fail_session_on_transport_loss(&mut self, session_id: &str) {
        let pending_id = self
            .sessions
            .get_mut(session_id)
            .and_then(|s| s.pending.take().map(|p| p.proposal_id));
        if let Some(pid) = pending_id {
            self.emit_session_event(
                session_id,
                OutTarget::Agent,
                "proposal.invalidated",
                json!({"proposal_id": pid, "reason": "transport_loss"}),
            );
        }
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.state = ControlState::Error;
            session.snapshot_valid = false;
        }
        self.audit_log.append(AuditEventInput {
            session_id,
            result: "error",
            operation: "transport.loss",
            ..AuditEventInput::default()
        });
        self.emit_state_event(session_id, OutTarget::Agent);
    }

    fn emit(&mut self, target: OutTarget, frame: Value) {
        self.outbox.push((target, frame));
    }

    fn emit_session_event(
        &mut self,
        session_id: &str,
        target: OutTarget,
        kind: &str,
        extra: Value,
    ) {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return;
        };
        session.event_seq = session.event_seq.wrapping_add(1);
        let mut frame = json!({
            "v": 1,
            "type": kind,
            "session_id": session.id,
            "event_seq": session.event_seq,
            "state": session.state.as_str(),
            "at": control::now_iso(),
        });
        if let (Value::Object(dst), Value::Object(src)) = (&mut frame, extra) {
            dst.extend(src);
        }
        self.emit(target, frame);
    }

    fn emit_state_event(&mut self, session_id: &str, target: OutTarget) {
        let Some(session) = self.sessions.get(session_id) else {
            return;
        };
        let target_id = session.target_id;
        let (url, title, generation, fingerprint) = match &session.last_snapshot {
            Some(snap) => (
                snap.url.clone(),
                snap.title.clone(),
                snap.document_generation,
                session.snapshot_valid.then(|| snap.fingerprint.clone()),
            ),
            None => (String::new(), String::new(), 0, None),
        };
        self.emit_session_event(
            session_id,
            target,
            "state",
            json!({
                "tab_id": target_id,
                "url": url,
                "title": title,
                "generation": generation,
                "fingerprint": fingerprint,
            }),
        );
    }

    fn refused(&mut self, conn_id: u64, frame: &Value, session_id: Option<&str>, reason: &str) {
        let role = self.conns.get(&conn_id).map(|c| c.role);
        let sid = session_id
            .map(str::to_string)
            .or_else(|| {
                frame
                    .get("session_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .or_else(|| self.default_session_id.clone());
        let body = json!({
            "v": 1,
            "type": "refused",
            "request_id": frame.get("request_id").cloned().unwrap_or(Value::Null),
            "session_id": sid,
            "reason": reason,
            "at": control::now_iso(),
        });
        self.emit(OutTarget::Conn(conn_id), body.clone());
        if role == Some(Role::Agent) {
            self.emit(OutTarget::Host, body);
        }
    }

    /// Returns the static capabilities advertisement frame.
    pub fn capabilities_frame() -> Value {
        json!({
            "v": 1,
            "type": "capabilities",
            "protocol": 1,
            "engine": {"name": "parawing-authority", "version": env!("CARGO_PKG_VERSION")},
            "operations": [
                "observe", "click", "scroll", "navigate", "back", "forward", "reload",
                "type", "select", "fill_form", "replay_recipe", "submit",
                "credential.fill", "passkey.assert", "passkey.register"
            ],
            "passkeys": "supported",
            "passkey_broker": "supported",
            "credential_broker": "supported",
            "sealed_blackout": "supported",
            "tokenized_substitution": "supported",
            "hash_chained_audit": "supported",
            "multiplex_sessions": "supported",
            "background_tabs": "supported",
        })
    }

    fn handle_frame(&mut self, conn_id: u64, frame: Value) {
        let Some(role) = self.check_seq_and_role(conn_id, &frame) else {
            return;
        };
        let Some(kind) = frame
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            self.refused(conn_id, &frame, None, "unsupported_message");
            return;
        };
        if !self.check_channel_permission(conn_id, role, &kind, &frame) {
            return;
        }

        match kind.as_str() {
            "ping" => self.emit(
                OutTarget::Conn(conn_id),
                json!({
                    "v": 1,
                    "type": "pong",
                    "request_id": frame.get("request_id").cloned().unwrap_or(Value::Null),
                    "at": control::now_iso(),
                }),
            ),
            "capabilities.get" => {
                let mut body = Self::capabilities_frame();
                body["request_id"] = frame.get("request_id").cloned().unwrap_or(Value::Null);
                self.emit(OutTarget::Conn(conn_id), body);
            }
            "session.open" => self.do_session_open(conn_id, &frame),
            _ => self.dispatch_session_bound(conn_id, role, &kind, &frame),
        }
    }

    fn check_seq_and_role(&mut self, conn_id: u64, frame: &Value) -> Option<Role> {
        let role = self.conns.get(&conn_id)?.role;
        let Some(seq) = frame.get("seq").and_then(Value::as_u64) else {
            self.refused(conn_id, frame, None, "internal");
            return None;
        };
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            if conn.last_seq.is_some_and(|last| seq <= last) {
                self.refused(conn_id, frame, None, "replayed_seq");
                return None;
            }
            conn.last_seq = Some(seq);
        }
        Some(role)
    }

    fn check_channel_permission(
        &mut self,
        conn_id: u64,
        role: Role,
        kind: &str,
        frame: &Value,
    ) -> bool {
        let host_only = matches!(
            kind,
            "session.open"
                | "session.state"
                | "session.close"
                | "decision"
                | "control.take"
                | "control.release"
                | "stop"
                | "audit.read"
        );
        let agent_only = matches!(kind, "propose" | "task.done");
        if (host_only && role != Role::Host) || (agent_only && role != Role::Agent) {
            self.refused(conn_id, frame, None, "wrong_channel");
            return false;
        }
        true
    }

    fn resolve_session_id(&self, frame: &Value) -> Option<String> {
        if let Some(explicit) = frame.get("session_id").and_then(Value::as_str) {
            return self
                .sessions
                .contains_key(explicit)
                .then(|| explicit.to_string());
        }
        self.default_session_id
            .as_ref()
            .filter(|id| self.sessions.contains_key(*id))
            .cloned()
    }

    fn dispatch_session_bound(&mut self, conn_id: u64, role: Role, kind: &str, frame: &Value) {
        let Some(sid) = self.resolve_session_id(frame) else {
            self.refused(conn_id, frame, None, "wrong_state");
            return;
        };
        match kind {
            "session.state" => self.emit_state_event(&sid, OutTarget::Conn(conn_id)),
            "session.close" => self.do_session_close(conn_id, &sid, frame),
            "observe.request" => self.do_observe(conn_id, role, &sid, frame),
            "propose" => self.do_propose(conn_id, &sid, frame),
            "decision" => self.do_decision(conn_id, &sid, frame),
            "control.take" => self.do_control_transition(conn_id, &sid, frame, "take"),
            "control.release" => self.do_control_transition(conn_id, &sid, frame, "release"),
            "stop" => self.do_control_transition(conn_id, &sid, frame, "stop"),
            "task.done" => self.do_task_done(conn_id, &sid, frame),
            "audit.read" => self.do_audit_read(conn_id, &sid, frame),
            "credential.list" | "credential.describe" | "credential.save" | "credential.delete" => {
                self.do_credential_rpc(conn_id, role, &sid, kind, frame);
            }
            "passkey.publickey" | "passkey.delete" | "passkey.status" | "passkey.cancel" => {
                self.do_passkey_rpc(conn_id, role, &sid, kind, frame);
            }
            _ => self.refused(conn_id, frame, Some(&sid), "unsupported_message"),
        }
    }

    fn do_session_open(&mut self, conn_id: u64, frame: &Value) {
        let Some(title) = frame
            .get("title")
            .and_then(Value::as_str)
            .filter(|t| !t.trim().is_empty())
            .map(str::to_string)
        else {
            self.refused(conn_id, frame, None, "internal");
            return;
        };
        if let Some(decision) = frame
            .get("policy")
            .and_then(|p| p.get("decision"))
            .and_then(Value::as_str)
        {
            if decision != "human_per_action" {
                self.refused(conn_id, frame, None, "capability_unsupported");
                return;
            }
        }
        let background = frame
            .get("background")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let allow_local_network = frame
            .get("policy")
            .and_then(|p| p.get("allow_local_network"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let start_url = match extract_validated_start_url(frame, allow_local_network) {
            Ok(url) => url,
            Err(reason) => {
                self.refused(conn_id, frame, None, reason);
                return;
            }
        };
        let Ok(target_id) = self.backend.open_target(start_url.as_deref(), background) else {
            self.refused(conn_id, frame, None, "internal");
            return;
        };
        let initial_snap = self.backend.observe_target(target_id);
        let generation = initial_snap
            .as_ref()
            .map_or(1, |snap| snap.document_generation);
        let session_id = format!("s_{}", self.next_session_num);
        self.next_session_num = self.next_session_num.wrapping_add(1);
        let session = SupervisionSession {
            id: session_id.clone(),
            target_id,
            title,
            state: ControlState::Agent,
            event_seq: 0,
            last_snapshot: initial_snap,
            snapshot_valid: false,
            pending: None,
            seen_proposals: HashSet::new(),
            used_decisions: HashSet::new(),
            action_required_kind: None,
            last_screenshot_hash: None,
            background,
            allow_local_network,
            sealed_blackout: None,
        };
        self.sessions.insert(session_id.clone(), session);
        if !background || self.default_session_id.is_none() {
            self.default_session_id = Some(session_id.clone());
        }
        self.audit_log.append(AuditEventInput {
            session_id: &session_id,
            result: "opened",
            operation: "session.open",
            decided_by: Some("user"),
            surface: Some("socket"),
            ..AuditEventInput::default()
        });
        self.emit(
            OutTarget::Conn(conn_id),
            json!({
                "v": 1,
                "type": "session.opened",
                "request_id": frame.get("request_id").cloned().unwrap_or(Value::Null),
                "session_id": session_id,
                "tab_id": target_id,
                "state": "agent",
                "generation": generation,
                "capabilities": Self::capabilities_frame(),
                "at": control::now_iso(),
            }),
        );
        self.emit_state_event(&session_id, OutTarget::Both);
    }

    fn do_session_close(&mut self, conn_id: u64, session_id: &str, frame: &Value) {
        let Some(removed) = self.sessions.remove(session_id) else {
            self.refused(conn_id, frame, Some(session_id), "wrong_state");
            return;
        };
        self.backend.close_target(removed.target_id);
        if self.default_session_id.as_deref() == Some(session_id) {
            self.default_session_id = self.sessions.keys().next().cloned();
        }
        self.emit(
            OutTarget::Conn(conn_id),
            json!({
                "v": 1,
                "type": "session.closed",
                "request_id": frame.get("request_id").cloned().unwrap_or(Value::Null),
                "session_id": removed.id,
                "at": control::now_iso(),
            }),
        );
    }

    fn do_observe(&mut self, conn_id: u64, role: Role, session_id: &str, frame: &Value) {
        let (state, target_id, blackout) = {
            let Some(session) = self.sessions.get(session_id) else {
                return;
            };
            (session.state, session.target_id, session.sealed_blackout)
        };
        if state.is_terminal() || (role == Role::Agent && state != ControlState::Agent) {
            self.refused(conn_id, frame, Some(session_id), "wrong_state");
            return;
        }
        let Some(mut snapshot) = self.backend.observe_target(target_id) else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return;
        };
        if let Some((blk_page, blk_gen)) = blackout {
            if snapshot.page_id == blk_page && snapshot.document_generation == blk_gen {
                if role == Role::Agent {
                    self.refused(conn_id, frame, Some(session_id), "sealed_blackout");
                    return;
                }
            } else if let Some(session) = self.sessions.get_mut(session_id) {
                session.sealed_blackout = None;
            }
        }
        attach_recall_metadata(&self.recall_store, &mut snapshot);
        let (screenshot_b64, screenshot_hash, frame_id) =
            self.maybe_capture_screenshot(session_id, target_id, frame);
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_snapshot = Some(snapshot.clone());
            session.snapshot_valid = true;
        }
        self.emit(
            OutTarget::Conn(conn_id),
            json!({
                "v": 1,
                "type": "observe.result",
                "request_id": frame.get("request_id").cloned().unwrap_or(Value::Null),
                "session_id": session_id,
                "snapshot_id": format!("o_{}", snapshot.snapshot_id),
                "tab_id": snapshot.tab_id,
                "page_id": snapshot.page_id,
                "state": state.as_str(),
                "url": snapshot.url,
                "title": snapshot.title,
                "generation": snapshot.document_generation,
                "fingerprint": snapshot.fingerprint,
                "viewport": snapshot.viewport,
                "scroll": snapshot.scroll,
                "text": snapshot.text,
                "elements": snapshot.elements,
                "focused_element_id": snapshot.focused_element_id,
                "form_signature": snapshot.form_signature,
                "matched_recipe_id": snapshot.matched_recipe_id,
                "screenshot_png_b64": screenshot_b64,
                "screenshot_hash": screenshot_hash,
                "frame_id": frame_id,
                "at": control::now_iso(),
            }),
        );
    }

    fn maybe_capture_screenshot(
        &mut self,
        session_id: &str,
        target_id: u64,
        frame: &Value,
    ) -> (Option<String>, Option<String>, Option<u64>) {
        if frame.get("include_screenshot").and_then(Value::as_bool) != Some(true) {
            return (None, None, None);
        }
        let Some((png, hash, frame_id)) = self.backend.capture_screenshot(target_id) else {
            return (None, None, None);
        };
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_screenshot_hash = Some(hash.clone());
        }
        (Some(control::b64_encode(&png)), Some(hash), Some(frame_id))
    }

    fn raise_action_required(&mut self, session_id: &str, kind: &str, page_detail: &str) {
        let shot_hash = self.sessions.get_mut(session_id).and_then(|s| {
            s.state = ControlState::ActionRequired;
            s.action_required_kind = Some(kind.to_string());
            s.snapshot_valid = false;
            s.last_screenshot_hash.clone()
        });
        self.audit_log.append(AuditEventInput {
            session_id,
            result: "action_required",
            operation: kind,
            screenshot_hash: shot_hash.as_deref(),
            ..AuditEventInput::default()
        });
        self.emit_session_event(
            session_id,
            OutTarget::Host,
            "action_required",
            json!({"kind": kind, "page_detail": page_detail}),
        );
        self.emit_state_event(session_id, OutTarget::Agent);
    }

    fn do_propose(&mut self, conn_id: u64, session_id: &str, frame: &Value) {
        let Some(parsed) = self.parse_and_check_proposal_binding(conn_id, session_id, frame) else {
            return;
        };
        let Some(validated) = self.validate_proposal_operation(conn_id, session_id, frame, &parsed)
        else {
            return;
        };
        let op_kind = parsed
            .operation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let target_id_str = parsed
            .operation
            .get("target_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let pending = PendingProposal {
            proposal_id: parsed.proposal_id.clone(),
            snapshot_id: parsed.snapshot_id,
            page_id: parsed.snapshot.page_id,
            fingerprint: parsed.fingerprint.clone(),
            generation: parsed.generation,
            operation: parsed.operation,
            rationale: validated.rationale,
            classification: validated.classification,
            requires_approval: validated.requires_approval,
            ceremony_id: validated.ceremony_id,
            credential_fill: validated.credential_fill,
        };
        let shot_hash = self.sessions.get_mut(session_id).and_then(|s| {
            s.seen_proposals.insert(pending.proposal_id.clone());
            s.state = ControlState::AwaitingDecision;
            s.last_screenshot_hash.clone()
        });
        self.audit_log.append(AuditEventInput {
            session_id,
            result: "proposed",
            operation: &op_kind,
            target_id: target_id_str.as_deref(),
            proposal_id: Some(&pending.proposal_id),
            before_fingerprint: Some(&pending.fingerprint),
            screenshot_hash: shot_hash.as_deref(),
            decided_by: Some("agent"),
            surface: Some("socket"),
            ..AuditEventInput::default()
        });
        if self.supervise_commits_only && !pending.requires_approval {
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.pending = Some(pending);
            }
            let _ = self.decide(DecisionInput {
                session_id,
                proposal_id: &parsed.proposal_id,
                fingerprint: &parsed.fingerprint,
                generation: parsed.generation,
                approve: true,
                decided_by: "policy",
                surface: "commit_gate",
            });
            return;
        }
        let pending_event = json!({
            "proposal_id": pending.proposal_id,
            "snapshot_id": format!("o_{}", pending.snapshot_id),
            "fingerprint": pending.fingerprint,
            "generation": pending.generation,
            "operation": pending.operation,
            "rationale": pending.rationale,
            "classification": pending.classification,
            "requires_glasses": pending.requires_approval,
            "target_label": validated.target_label,
            "target_href": validated.target_href,
            "target_bounds": validated.target_bounds,
        });
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.pending = Some(pending);
        }
        self.emit_session_event(
            session_id,
            OutTarget::Host,
            "proposal.pending",
            pending_event,
        );
        self.emit_state_event(session_id, OutTarget::Both);
    }

    fn parse_and_check_proposal_binding(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
    ) -> Option<ParsedProposalEnvelope> {
        let session = self.sessions.get(session_id)?;
        if session.state == ControlState::AwaitingDecision {
            self.refused(conn_id, frame, Some(session_id), "proposal_pending");
            return None;
        }
        if session.state != ControlState::Agent {
            self.refused(conn_id, frame, Some(session_id), "wrong_state");
            return None;
        }
        let (
            Some(proposal_id),
            Some(snapshot_raw),
            Some(fingerprint),
            Some(generation),
            Some(operation),
            Some(rationale),
        ) = (
            frame.get("proposal_id").and_then(Value::as_str),
            frame.get("snapshot_id").and_then(Value::as_str),
            frame.get("fingerprint").and_then(Value::as_str),
            frame.get("generation").and_then(Value::as_u64),
            frame.get("operation").filter(|o| o.is_object()).cloned(),
            frame.get("rationale").and_then(Value::as_str),
        )
        else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return None;
        };
        if session.seen_proposals.contains(proposal_id) {
            self.refused(conn_id, frame, Some(session_id), "decision_used");
            return None;
        }
        let snapshot_id: u64 = snapshot_raw
            .strip_prefix("o_")
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        let target_id = session.target_id;
        let snapshot_valid = session.snapshot_valid;
        let cached_snap = session.last_snapshot.clone();
        let live_snap = self.backend.observe_target(target_id);
        let Some(live) = live_snap else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return None;
        };
        if generation != live.document_generation {
            self.refused(conn_id, frame, Some(session_id), "stale_generation");
            return None;
        }
        let Some(snapshot) = cached_snap else {
            self.refused(conn_id, frame, Some(session_id), "stale_fingerprint");
            return None;
        };
        if !snapshot_valid
            || snapshot.snapshot_id != snapshot_id
            || snapshot.fingerprint != fingerprint
            || live.fingerprint != fingerprint
        {
            self.refused(conn_id, frame, Some(session_id), "stale_fingerprint");
            return None;
        }
        Some(ParsedProposalEnvelope {
            proposal_id: proposal_id.to_string(),
            snapshot_id,
            fingerprint: fingerprint.to_string(),
            generation,
            operation,
            rationale: rationale.to_string(),
            snapshot,
        })
    }

    fn validate_proposal_operation(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        parsed: &ParsedProposalEnvelope,
    ) -> Option<ValidatedProposal> {
        let snapshot = &parsed.snapshot;
        let operation = &parsed.operation;
        let (target_id, allow_local_network) = {
            let session = self.sessions.get(session_id)?;
            (session.target_id, session.allow_local_network)
        };
        let known_refs = self.backend.known_node_refs(target_id);
        if let Err(reason) = verify_target_ref(operation, &known_refs, snapshot) {
            self.refused(conn_id, frame, Some(session_id), reason);
            return None;
        }
        let target = resolve_target_element(operation, snapshot);
        let mut sensitive = target.is_some_and(is_sensitive_element);
        let mut prompt_override: Option<String> = None;
        let mut ceremony_id: Option<String> = None;
        let mut credential_fill: Option<CredentialFillPlan> = None;
        let op_kind = operation.get("kind").and_then(Value::as_str).unwrap_or("");

        let ok = match op_kind {
            "click" => self.validate_click(conn_id, session_id, frame, target, sensitive),
            "scroll" => self.validate_scroll(conn_id, session_id, frame, operation),
            "navigate" => {
                self.validate_navigate(conn_id, session_id, frame, operation, allow_local_network)
            }
            "back" => self.validate_history(conn_id, session_id, frame, target_id, true),
            "forward" => self.validate_history(conn_id, session_id, frame, target_id, false),
            "reload" => true,
            "type" | "select" => self
                .validate_type_or_select(conn_id, session_id, frame, operation, target, sensitive),
            "fill_form" => self.validate_fill_form(
                conn_id,
                session_id,
                frame,
                parsed,
                &known_refs,
                &mut sensitive,
            ),
            "replay_recipe" => self.validate_replay_recipe(
                conn_id,
                session_id,
                frame,
                operation,
                snapshot,
                &mut sensitive,
            ),
            "submit" => self.validate_submit(conn_id, session_id, frame, target, &mut sensitive),
            "credential.fill" => match self.prepare_credential_fill(
                conn_id,
                session_id,
                frame,
                &parsed.proposal_id,
                parsed.generation,
                operation,
            ) {
                Some((prompt, plan)) => {
                    prompt_override = Some(prompt);
                    credential_fill = Some(plan);
                    sensitive = true;
                    true
                }
                None => false,
            },
            "passkey.assert" | "passkey.register" => {
                match self.prepare_passkey_ceremony(conn_id, session_id, frame, op_kind, operation)
                {
                    Some((cid, prompt)) => {
                        ceremony_id = Some(cid);
                        prompt_override = Some(prompt);
                        sensitive = true;
                        true
                    }
                    None => false,
                }
            }
            _ => {
                self.refused(conn_id, frame, Some(session_id), "capability_unsupported");
                false
            }
        };
        if !ok {
            return None;
        }

        let stage_only = operation
            .get("stage_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let classification = if sensitive {
            "sensitive"
        } else if op_kind == "scroll" {
            "observe"
        } else {
            "act"
        };
        let raw_rationale = frame
            .get("rationale")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Some(ValidatedProposal {
            rationale: prompt_override.unwrap_or_else(|| raw_rationale.to_string()),
            classification: classification.to_string(),
            requires_approval: sensitive && !stage_only,
            ceremony_id,
            credential_fill,
            target_label: target.map(|e| e.label.clone()),
            target_href: target.and_then(|e| e.href.clone()),
            target_bounds: target.and_then(|e| serde_json::to_value(e.bounds).ok()),
        })
    }

    fn validate_click(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        target: Option<&ElementSnapshot>,
        sensitive: bool,
    ) -> bool {
        let Some(el) = target else {
            self.refused(conn_id, frame, Some(session_id), "target_missing");
            return false;
        };
        if let Err(reason) = check_element_visible_enabled(el) {
            self.refused(conn_id, frame, Some(session_id), reason);
            return false;
        }
        if el.kind != "click" {
            if sensitive {
                self.refused(conn_id, frame, Some(session_id), "sensitive_requires_human");
                self.raise_action_required(session_id, "password", &el.label);
            } else {
                self.refused(conn_id, frame, Some(session_id), "capability_unsupported");
            }
            return false;
        }
        true
    }

    fn validate_scroll(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        operation: &Value,
    ) -> bool {
        if operation
            .get("dy")
            .and_then(Value::as_f64)
            .is_some_and(f64::is_finite)
        {
            return true;
        }
        self.refused(conn_id, frame, Some(session_id), "internal");
        false
    }

    fn validate_navigate(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        operation: &Value,
        allow_local_network: bool,
    ) -> bool {
        let Some(raw_url) = operation.get("url").and_then(Value::as_str) else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return false;
        };
        match validate_navigation_url(raw_url, allow_local_network) {
            Ok(_) => true,
            Err(reason) => {
                self.refused(conn_id, frame, Some(session_id), reason);
                false
            }
        }
    }

    fn validate_history(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        target_id: u64,
        back: bool,
    ) -> bool {
        let allowed = if back {
            self.backend.can_go_back(target_id)
        } else {
            self.backend.can_go_forward(target_id)
        };
        if !allowed {
            self.refused(conn_id, frame, Some(session_id), "wrong_state");
        }
        allowed
    }

    fn validate_type_or_select(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        operation: &Value,
        target: Option<&ElementSnapshot>,
        sensitive: bool,
    ) -> bool {
        if sensitive {
            let detail = target.map(|e| e.label.clone()).unwrap_or_default();
            self.refused(conn_id, frame, Some(session_id), "sensitive_requires_human");
            self.raise_action_required(session_id, "password", &detail);
            return false;
        }
        let Some(el) = target else {
            self.refused(conn_id, frame, Some(session_id), "target_missing");
            return false;
        };
        if let Err(reason) = check_element_visible_enabled(el) {
            self.refused(conn_id, frame, Some(session_id), reason);
            return false;
        }
        if PageCommand::from_operation(operation).is_none() {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return false;
        }
        true
    }

    fn validate_fill_form(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        parsed: &ParsedProposalEnvelope,
        known_refs: &HashSet<String>,
        sensitive_out: &mut bool,
    ) -> bool {
        let snapshot = &parsed.snapshot;
        let Some(PageCommand::FillForm { fields }) = PageCommand::from_operation(&parsed.operation)
        else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return false;
        };
        for field in &fields {
            if let Err(reason) =
                validate_single_form_field(field, snapshot, known_refs, sensitive_out)
            {
                self.refused(conn_id, frame, Some(session_id), reason);
                if reason == "sensitive_requires_human" {
                    let label = resolve_form_field_element(field, snapshot)
                        .map(|e| e.label.clone())
                        .unwrap_or_default();
                    self.raise_action_required(session_id, "password", &label);
                }
                return false;
            }
        }
        true
    }

    fn validate_replay_recipe(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        operation: &Value,
        snapshot: &PageSnapshot,
        sensitive_out: &mut bool,
    ) -> bool {
        let Some(PageCommand::ReplayRecipe { recipe_id }) = PageCommand::from_operation(operation)
        else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return false;
        };
        let matched = if !recipe_id.is_empty() {
            recall::get_recipe_in(&self.recall_store, &recipe_id)
        } else {
            recall::find_matching_recipe_in(
                &self.recall_store,
                &snapshot.url,
                snapshot.form_signature.as_deref(),
            )
        };
        let Some(recipe) = matched else {
            self.refused(conn_id, frame, Some(session_id), "target_missing");
            return false;
        };
        if recipe.fields.iter().any(|rf| rf.action == "fill_secret") {
            *sensitive_out = true;
        }
        true
    }

    fn validate_submit(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        target: Option<&ElementSnapshot>,
        sensitive_out: &mut bool,
    ) -> bool {
        let Some(el) = target else {
            self.refused(conn_id, frame, Some(session_id), "target_missing");
            return false;
        };
        if let Err(reason) = check_element_visible_enabled(el) {
            self.refused(conn_id, frame, Some(session_id), reason);
            return false;
        }
        *sensitive_out = true;
        true
    }

    fn prepare_credential_fill(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        proposal_id: &str,
        generation: u64,
        operation: &Value,
    ) -> Option<(String, CredentialFillPlan)> {
        let origin = operation
            .get("origin")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let fields = parse_credential_fields(operation);
        let mode = match operation.get("mode").and_then(Value::as_str) {
            Some("tokenized") => CredentialFillMode::Tokenized,
            _ => CredentialFillMode::Sealed,
        };
        let req = CredentialFillRequest {
            task_id: proposal_id.to_string(),
            origin,
            fields: fields.clone(),
            document_generation: generation,
        };
        let Ok(prompt) = self.credential_broker.describe_fill(req) else {
            self.refused(conn_id, frame, Some(session_id), "credential_refused");
            return None;
        };
        let chosen = match prompt.matches.len() {
            0 => {
                self.refused(conn_id, frame, Some(session_id), "no_matching_credential");
                return None;
            }
            1 => prompt.matches[0].clone(),
            _ => {
                self.refused(conn_id, frame, Some(session_id), "credential_ambiguous");
                return None;
            }
        };
        let text = format!(
            "Fill the saved credential for {} on {}?",
            chosen.username_hint, prompt.registrable_domain
        );
        let plan = CredentialFillPlan {
            origin: prompt.origin,
            chosen,
            fields,
            mode,
        };
        Some((text, plan))
    }

    fn prepare_passkey_ceremony(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        op_kind: &str,
        operation: &Value,
    ) -> Option<(String, String)> {
        let started = if op_kind == "passkey.assert" {
            PasskeyRequest::from_operation(operation)
                .and_then(|req| self.passkey_broker.begin_assertion(req))
        } else {
            RegistrationRequest::from_operation(operation)
                .and_then(|req| self.passkey_broker.begin_registration(req))
        };
        let Ok(id) = started else {
            self.refused(conn_id, frame, Some(session_id), "passkey_refused");
            return None;
        };
        let prompt = match self.passkey_broker.poll_assertion(id.clone()) {
            Ok(PasskeyStatus::AwaitingApproval { prompt, .. }) => prompt,
            _ => format!("{op_kind} awaiting approval"),
        };
        Some((id.0, prompt))
    }

    fn do_decision(&mut self, conn_id: u64, session_id: &str, frame: &Value) {
        let (Some(proposal_id), Some(fingerprint), Some(generation), Some(decision_str)) = (
            frame
                .get("proposal_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            frame
                .get("fingerprint")
                .and_then(Value::as_str)
                .map(str::to_string),
            frame.get("generation").and_then(Value::as_u64),
            frame.get("decision").and_then(Value::as_str),
        ) else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return;
        };
        let approve = match decision_str {
            "approve" => true,
            "reject" => false,
            _ => {
                self.refused(conn_id, frame, Some(session_id), "internal");
                return;
            }
        };
        let decided_by = frame
            .get("decided_by")
            .and_then(Value::as_str)
            .unwrap_or("user")
            .to_string();
        let surface = frame
            .get("surface")
            .and_then(Value::as_str)
            .unwrap_or("socket")
            .to_string();
        if let Err(reason) = self.decide(DecisionInput {
            session_id,
            proposal_id: &proposal_id,
            fingerprint: &fingerprint,
            generation,
            approve,
            decided_by: &decided_by,
            surface: &surface,
        }) {
            self.refused(conn_id, frame, Some(session_id), reason);
        }
    }

    /// Evaluates and executes (or rejects) a single-use decision on a session's pending proposal.
    pub fn decide(&mut self, input: DecisionInput<'_>) -> Result<(), &'static str> {
        let (target_id, pending) = self.consume_pending_decision(&input)?;
        if !input.approve {
            self.finish_rejected_decision(&input, &pending);
            return Ok(());
        }
        let Some(fresh) = self.backend.observe_target(target_id) else {
            return Err("internal");
        };
        if fresh.fingerprint != pending.fingerprint
            || fresh.document_generation != pending.generation
            || fresh.page_id != pending.page_id
        {
            self.finish_stale_decision(&input, &pending, &fresh.fingerprint);
            return Err("stale_fingerprint");
        }
        if let Some(ref plan) = pending.credential_fill {
            return self.execute_credential_fill(&input, target_id, plan, &pending.fingerprint);
        }
        if let Some(ref ceremony_id) = pending.ceremony_id {
            return self.execute_passkey_ceremony(&input, &pending, ceremony_id);
        }
        self.execute_page_command(&input, target_id, &pending, &fresh)
    }

    fn consume_pending_decision(
        &mut self,
        input: &DecisionInput<'_>,
    ) -> Result<(u64, PendingProposal), &'static str> {
        let session = self
            .sessions
            .get_mut(input.session_id)
            .ok_or("wrong_state")?;
        let already_used = session.used_decisions.contains(input.proposal_id);
        let Some(pending_ref) = session.pending.as_ref() else {
            return Err(if already_used {
                "decision_used"
            } else {
                "decision_missing"
            });
        };
        if pending_ref.proposal_id != input.proposal_id {
            return Err("decision_mismatch");
        }
        if already_used {
            return Err("decision_used");
        }
        if input.fingerprint != pending_ref.fingerprint
            || input.generation != pending_ref.generation
        {
            return Err("decision_mismatch");
        }
        session.used_decisions.insert(input.proposal_id.to_string());
        let pending = session.pending.take().ok_or("decision_missing")?;
        Ok((session.target_id, pending))
    }

    fn finish_rejected_decision(&mut self, input: &DecisionInput<'_>, pending: &PendingProposal) {
        let op_kind = pending
            .operation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Some(ref cid) = pending.ceremony_id {
            let id = PasskeyCeremonyId(cid.clone());
            let _ = self
                .passkey_broker
                .cancel_assertion(id.clone())
                .or_else(|_| self.passkey_broker.cancel_registration(id));
        }
        let shot_hash = self.sessions.get_mut(input.session_id).and_then(|s| {
            s.state = ControlState::Agent;
            s.last_screenshot_hash.clone()
        });
        self.audit_log.append(AuditEventInput {
            session_id: input.session_id,
            result: "rejected",
            operation: op_kind,
            proposal_id: Some(input.proposal_id),
            before_fingerprint: Some(&pending.fingerprint),
            screenshot_hash: shot_hash.as_deref(),
            decided_by: Some(input.decided_by),
            surface: Some(input.surface),
            ..AuditEventInput::default()
        });
        self.emit_session_event(
            input.session_id,
            OutTarget::Both,
            "proposal.invalidated",
            json!({"proposal_id": input.proposal_id, "reason": "rejected"}),
        );
        self.emit_state_event(input.session_id, OutTarget::Both);
    }

    fn finish_stale_decision(
        &mut self,
        input: &DecisionInput<'_>,
        pending: &PendingProposal,
        fresh_fp: &str,
    ) {
        let shot_hash = self.sessions.get_mut(input.session_id).and_then(|s| {
            s.state = ControlState::Agent;
            s.snapshot_valid = false;
            s.last_screenshot_hash.clone()
        });
        self.audit_log.append(AuditEventInput {
            session_id: input.session_id,
            result: "refused_stale",
            operation: "",
            proposal_id: Some(input.proposal_id),
            before_fingerprint: Some(&pending.fingerprint),
            after_fingerprint: Some(fresh_fp),
            screenshot_hash: shot_hash.as_deref(),
            decided_by: Some(input.decided_by),
            surface: Some(input.surface),
            ..AuditEventInput::default()
        });
        self.emit_session_event(
            input.session_id,
            OutTarget::Both,
            "proposal.invalidated",
            json!({"proposal_id": input.proposal_id, "reason": "stale_fingerprint"}),
        );
        self.emit_state_event(input.session_id, OutTarget::Both);
    }

    fn execute_credential_fill(
        &mut self,
        input: &DecisionInput<'_>,
        target_id: u64,
        plan: &CredentialFillPlan,
        before_fp: &str,
    ) -> Result<(), &'static str> {
        let approval = CredentialApproval {
            ceremony_id: input.proposal_id.to_string(),
            chosen: Some(plan.chosen.clone()),
            remember: false,
            origin: plan.origin.clone(),
            fields: plan.fields.clone(),
            mode: plan.mode,
        };
        let receipt = {
            let mut sink = BackendCredentialSink {
                backend: &mut self.backend,
                target_id,
            };
            self.credential_broker
                .apply_approved_fill(approval, &mut sink)
                .map_err(|_| "credential_fill_failed")?
        };
        let post_snap = self.backend.observe_target(target_id);
        let shot_hash = self.sessions.get_mut(input.session_id).and_then(|s| {
            s.state = ControlState::Agent;
            s.snapshot_valid = false;
            if receipt.blackout_agent_observation {
                if let Some(ref snap) = post_snap {
                    s.sealed_blackout = Some((snap.page_id, snap.document_generation));
                }
            }
            s.last_screenshot_hash.clone()
        });
        self.audit_log.append(AuditEventInput {
            session_id: input.session_id,
            result: "executed",
            operation: "credential.fill",
            proposal_id: Some(input.proposal_id),
            before_fingerprint: Some(before_fp),
            screenshot_hash: shot_hash.as_deref(),
            decided_by: Some(input.decided_by),
            surface: Some(input.surface),
            ..AuditEventInput::default()
        });
        let filled_names: Vec<&'static str> =
            receipt.filled_fields.iter().map(|k| k.as_str()).collect();
        self.emit(
            OutTarget::Agent,
            json!({
                "v": 1,
                "type": "credential.filled",
                "session_id": input.session_id,
                "proposal_id": input.proposal_id,
                "origin": receipt.origin,
                "account_hint": receipt.account_hint,
                "mode": receipt.mode,
                "blackout_agent_observation": receipt.blackout_agent_observation,
                "filled_fields": filled_names,
                "field_tokens": receipt.field_tokens,
            }),
        );
        self.emit_session_event(
            input.session_id,
            OutTarget::Both,
            "executed",
            json!({
                "proposal_id": input.proposal_id,
                "operation": "credential.fill",
                "operation_detail": {"origin": receipt.origin, "mode": receipt.mode},
                "before_fingerprint": before_fp,
            }),
        );
        self.emit_state_event(input.session_id, OutTarget::Both);
        Ok(())
    }

    fn execute_passkey_ceremony(
        &mut self,
        input: &DecisionInput<'_>,
        pending: &PendingProposal,
        ceremony_id: &str,
    ) -> Result<(), &'static str> {
        let op_kind = pending
            .operation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("passkey");
        let id = PasskeyCeremonyId(ceremony_id.to_string());
        self.passkey_broker
            .approve_ceremony(id.clone(), input.decided_by, input.surface)
            .map_err(|_| "passkey_failed")?;
        let status = self
            .passkey_broker
            .poll_assertion(id.clone())
            .or_else(|_| self.passkey_broker.poll_registration(id))
            .map_err(|_| "passkey_failed")?;
        let shot_hash = self.sessions.get_mut(input.session_id).and_then(|s| {
            s.state = ControlState::Agent;
            s.snapshot_valid = false;
            s.last_screenshot_hash.clone()
        });
        let result_label = match status {
            PasskeyStatus::Complete(_) => "executed",
            _ => "failed",
        };
        self.audit_log.append(AuditEventInput {
            session_id: input.session_id,
            result: result_label,
            operation: op_kind,
            proposal_id: Some(input.proposal_id),
            before_fingerprint: Some(&pending.fingerprint),
            screenshot_hash: shot_hash.as_deref(),
            decided_by: Some(input.decided_by),
            surface: Some(input.surface),
            ..AuditEventInput::default()
        });
        self.emit(
            OutTarget::Agent,
            json!({
                "v": 1,
                "type": "passkey.completed",
                "session_id": input.session_id,
                "proposal_id": input.proposal_id,
                "ceremony_id": ceremony_id,
                "status": status,
            }),
        );
        self.emit_session_event(
            input.session_id,
            OutTarget::Both,
            "executed",
            json!({
                "proposal_id": input.proposal_id,
                "operation": op_kind,
                "ceremony_id": ceremony_id,
                "before_fingerprint": pending.fingerprint,
            }),
        );
        self.emit_state_event(input.session_id, OutTarget::Both);
        Ok(())
    }

    fn execute_page_command(
        &mut self,
        input: &DecisionInput<'_>,
        target_id: u64,
        pending: &PendingProposal,
        fresh: &PageSnapshot,
    ) -> Result<(), &'static str> {
        let Some(command) = PageCommand::from_operation(&pending.operation) else {
            return Err("capability_unsupported");
        };
        let op_kind = command.kind().to_string();
        let target_handle = command.target_id().map(str::to_string);
        if let PageCommand::Click { .. } = command {
            if let Err(reason) = self.verify_click_interactable(target_id, &command, fresh) {
                self.record_not_interactable(
                    input,
                    &op_kind,
                    target_handle.as_deref(),
                    reason,
                    &pending.fingerprint,
                );
                return Err(reason);
            }
        }
        if let PageCommand::FillForm { ref fields } = command {
            if let Some(ref sig) = fresh.form_signature {
                recall::record_recipe_in(&mut self.recall_store, &fresh.url, sig, fields, fresh);
            }
        }
        if self
            .backend
            .dispatch_command(target_id, &command, fresh)
            .is_err()
        {
            return Err("internal");
        }
        let after = self.backend.observe_target(target_id);
        let (after_fp, after_gen) = after
            .as_ref()
            .map(|s| (s.fingerprint.clone(), s.document_generation))
            .unwrap_or((String::new(), pending.generation));
        let shot_hash = self.sessions.get_mut(input.session_id).and_then(|s| {
            s.state = ControlState::Agent;
            s.snapshot_valid = false;
            if let (Some((blk_page, blk_gen)), Some(snap)) = (s.sealed_blackout, after.as_ref()) {
                if snap.page_id != blk_page || snap.document_generation != blk_gen {
                    s.sealed_blackout = None;
                }
            }
            s.last_snapshot = after;
            s.last_screenshot_hash.clone()
        });
        self.audit_log.append(AuditEventInput {
            session_id: input.session_id,
            result: "executed",
            operation: &op_kind,
            target_id: target_handle.as_deref(),
            proposal_id: Some(input.proposal_id),
            before_fingerprint: Some(&pending.fingerprint),
            after_fingerprint: Some(&after_fp),
            screenshot_hash: shot_hash.as_deref(),
            decided_by: Some(input.decided_by),
            surface: Some(input.surface),
        });
        self.emit_session_event(
            input.session_id,
            OutTarget::Both,
            "executed",
            json!({
                "proposal_id": input.proposal_id,
                "operation": op_kind,
                "operation_detail": command.to_operation(),
                "target_id": target_handle,
                "before_fingerprint": pending.fingerprint,
                "after_fingerprint": after_fp,
                "generation": after_gen,
                "input_provenance": "approved_agent",
            }),
        );
        self.emit_state_event(input.session_id, OutTarget::Both);
        Ok(())
    }

    fn verify_click_interactable(
        &self,
        target_id: u64,
        command: &PageCommand,
        fresh: &PageSnapshot,
    ) -> Result<(), &'static str> {
        let element = fresh.elements.iter().find(|e| {
            command.target_ref() == Some(e.node_ref.as_str())
                || command.target_id() == Some(e.id.as_str())
        });
        let Some(el) = element else {
            return Err("target_missing");
        };
        self.backend.check_interactable(target_id, el)
    }

    fn record_not_interactable(
        &mut self,
        input: &DecisionInput<'_>,
        op_kind: &str,
        target_id: Option<&str>,
        reason: &'static str,
        before_fp: &str,
    ) {
        let shot_hash = self.sessions.get_mut(input.session_id).and_then(|s| {
            s.state = ControlState::Agent;
            s.snapshot_valid = false;
            s.last_screenshot_hash.clone()
        });
        self.audit_log.append(AuditEventInput {
            session_id: input.session_id,
            result: "refused_not_interactable",
            operation: op_kind,
            target_id,
            proposal_id: Some(input.proposal_id),
            before_fingerprint: Some(before_fp),
            screenshot_hash: shot_hash.as_deref(),
            decided_by: Some(input.decided_by),
            surface: Some(input.surface),
            ..AuditEventInput::default()
        });
        self.emit_session_event(
            input.session_id,
            OutTarget::Both,
            "proposal.invalidated",
            json!({"proposal_id": input.proposal_id, "reason": reason}),
        );
        self.emit_state_event(input.session_id, OutTarget::Both);
    }

    fn do_control_transition(
        &mut self,
        conn_id: u64,
        session_id: &str,
        frame: &Value,
        action: &str,
    ) {
        let by = frame
            .get("decided_by")
            .and_then(Value::as_str)
            .unwrap_or("user");
        let surface = frame
            .get("surface")
            .and_then(Value::as_str)
            .unwrap_or("socket");
        let ok = match action {
            "take" => self.control_take(session_id, by, surface),
            "release" => self.control_release(session_id, by, surface),
            "stop" => self.control_stop(session_id, by, surface),
            _ => false,
        };
        if !ok {
            self.refused(conn_id, frame, Some(session_id), "wrong_state");
        }
    }

    /// Transitions `session_id` into `ControlState::Human`, cancelling any pending proposal.
    pub fn control_take(&mut self, session_id: &str, by: &str, surface: &str) -> bool {
        let can_take = self
            .sessions
            .get(session_id)
            .is_some_and(|s| !s.state.is_terminal() && s.state != ControlState::Human);
        if !can_take {
            return false;
        }
        let cancelled_pid = self.sessions.get_mut(session_id).and_then(|s| {
            s.state = ControlState::Human;
            s.snapshot_valid = false;
            s.action_required_kind = None;
            s.pending.take().map(|p| p.proposal_id)
        });
        if let Some(pid) = cancelled_pid {
            self.emit_session_event(
                session_id,
                OutTarget::Both,
                "proposal.invalidated",
                json!({"proposal_id": pid, "reason": "human_takeover"}),
            );
        }
        self.audit_log.append(AuditEventInput {
            session_id,
            result: "human",
            operation: "control.take",
            decided_by: Some(by),
            surface: Some(surface),
            ..AuditEventInput::default()
        });
        self.emit_state_event(session_id, OutTarget::Both);
        true
    }

    /// Returns `session_id` from `ControlState::Human` back to `ControlState::Agent`.
    pub fn control_release(&mut self, session_id: &str, by: &str, surface: &str) -> bool {
        let is_human = self
            .sessions
            .get(session_id)
            .is_some_and(|s| s.state == ControlState::Human);
        if !is_human {
            return false;
        }
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.state = ControlState::Agent;
            session.snapshot_valid = false;
        }
        self.audit_log.append(AuditEventInput {
            session_id,
            result: "agent",
            operation: "control.release",
            decided_by: Some(by),
            surface: Some(surface),
            ..AuditEventInput::default()
        });
        self.emit_state_event(session_id, OutTarget::Both);
        true
    }

    /// Permanently stops `session_id` (`ControlState::Stopped`).
    pub fn control_stop(&mut self, session_id: &str, by: &str, surface: &str) -> bool {
        let active = self
            .sessions
            .get(session_id)
            .is_some_and(|s| !s.state.is_terminal());
        if !active {
            return false;
        }
        let cancelled_pid = self.sessions.get_mut(session_id).and_then(|s| {
            s.state = ControlState::Stopped;
            s.snapshot_valid = false;
            s.pending.take().map(|p| p.proposal_id)
        });
        if let Some(pid) = cancelled_pid {
            self.emit_session_event(
                session_id,
                OutTarget::Both,
                "proposal.invalidated",
                json!({"proposal_id": pid, "reason": "stopped"}),
            );
        }
        self.audit_log.append(AuditEventInput {
            session_id,
            result: "stopped",
            operation: "stop",
            decided_by: Some(by),
            surface: Some(surface),
            ..AuditEventInput::default()
        });
        self.emit_state_event(session_id, OutTarget::Both);
        true
    }

    fn do_task_done(&mut self, conn_id: u64, session_id: &str, frame: &Value) {
        let ok = self
            .sessions
            .get(session_id)
            .is_some_and(|s| s.state == ControlState::Agent && s.pending.is_none());
        if !ok {
            self.refused(conn_id, frame, Some(session_id), "wrong_state");
            return;
        }
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.state = ControlState::Done;
            session.snapshot_valid = false;
        }
        self.audit_log.append(AuditEventInput {
            session_id,
            result: "done",
            operation: "task.done",
            decided_by: Some("agent"),
            surface: Some("socket"),
            ..AuditEventInput::default()
        });
        self.emit_state_event(session_id, OutTarget::Both);
    }

    fn do_audit_read(&mut self, conn_id: u64, session_id: &str, frame: &Value) {
        let records: Vec<&AuditEntry> = self
            .audit_log
            .entries()
            .iter()
            .filter(|e| e.session_id == session_id)
            .collect();
        self.emit(
            OutTarget::Conn(conn_id),
            json!({
                "v": 1,
                "type": "audit.result",
                "request_id": frame.get("request_id").cloned().unwrap_or(Value::Null),
                "session_id": session_id,
                "chain_valid": self.audit_log.verify_chain().is_ok(),
                "records": records,
                "at": control::now_iso(),
            }),
        );
    }

    fn do_credential_rpc(
        &mut self,
        conn_id: u64,
        role: Role,
        session_id: &str,
        kind: &str,
        frame: &Value,
    ) {
        let req_id = frame.get("request_id").cloned().unwrap_or(Value::Null);
        match kind {
            "credential.list" => {
                let credentials = self.credential_broker.list().unwrap_or_default();
                self.emit(
                    OutTarget::Conn(conn_id),
                    json!({
                        "v": 1,
                        "type": "credential.list",
                        "request_id": req_id,
                        "credentials": credentials,
                    }),
                );
            }
            "credential.describe" => {
                let req = CredentialFillRequest {
                    task_id: str_or_empty(frame, "task_id"),
                    origin: str_or_empty(frame, "origin"),
                    fields: Vec::new(),
                    document_generation: frame
                        .get("generation")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                };
                let body = match self.credential_broker.describe_fill(req) {
                    Ok(prompt) => json!({
                        "v": 1, "type": "credential.prompt", "request_id": req_id, "prompt": prompt
                    }),
                    Err(err) => json!({
                        "v": 1, "type": "credential.prompt", "request_id": req_id, "error": err.to_string()
                    }),
                };
                self.emit(OutTarget::Conn(conn_id), body);
            }
            "credential.save" => self.do_credential_save(conn_id, role, session_id, frame, req_id),
            "credential.delete" => {
                self.do_credential_delete(conn_id, role, session_id, frame, req_id)
            }
            _ => {}
        }
    }

    fn do_credential_save(
        &mut self,
        conn_id: u64,
        role: Role,
        session_id: &str,
        frame: &Value,
        req_id: Value,
    ) {
        if role != Role::Host {
            self.refused(conn_id, frame, Some(session_id), "wrong_role");
            return;
        }
        let (Some(host), Some(username), Some(secret)) = (
            frame.get("host").and_then(Value::as_str),
            frame.get("username").and_then(Value::as_str),
            frame.get("secret").and_then(Value::as_str),
        ) else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return;
        };
        let body = match self.credential_broker.save_password(host, username, secret) {
            Ok(()) => json!({
                "v": 1,
                "type": "credential.saved",
                "request_id": req_id,
                "host": host,
                "username": redact_username(username),
            }),
            Err(err) => json!({
                "v": 1,
                "type": "credential.saved",
                "request_id": req_id,
                "error": err.to_string(),
            }),
        };
        self.emit(OutTarget::Conn(conn_id), body);
    }

    fn do_credential_delete(
        &mut self,
        conn_id: u64,
        role: Role,
        session_id: &str,
        frame: &Value,
        req_id: Value,
    ) {
        if role != Role::Host {
            self.refused(conn_id, frame, Some(session_id), "wrong_role");
            return;
        }
        let (Some(host), Some(username)) = (
            frame.get("host").and_then(Value::as_str),
            frame.get("username").and_then(Value::as_str),
        ) else {
            self.refused(conn_id, frame, Some(session_id), "internal");
            return;
        };
        let ok = self
            .credential_broker
            .delete_password(host, username)
            .is_ok();
        self.emit(
            OutTarget::Conn(conn_id),
            json!({
                "v": 1,
                "type": "credential.deleted",
                "request_id": req_id,
                "host": host,
                "username": redact_username(username),
                "ok": ok,
            }),
        );
    }

    fn do_passkey_rpc(
        &mut self,
        conn_id: u64,
        role: Role,
        session_id: &str,
        kind: &str,
        frame: &Value,
    ) {
        let req_id = frame.get("request_id").cloned().unwrap_or(Value::Null);
        match kind {
            "passkey.publickey" => {
                if role != Role::Host {
                    self.refused(conn_id, frame, Some(session_id), "wrong_role");
                    return;
                }
                let Some(cid) = frame.get("credential_id").and_then(Value::as_str) else {
                    self.refused(conn_id, frame, Some(session_id), "internal");
                    return;
                };
                let pem = decode_any_b64(cid)
                    .and_then(|bytes| self.passkey_broker.public_key_pem(&bytes).ok())
                    .flatten();
                self.emit(
                    OutTarget::Conn(conn_id),
                    json!({
                        "v": 1,
                        "type": "passkey.publickey",
                        "request_id": req_id,
                        "credential_id": cid,
                        "public_key_pem": pem,
                    }),
                );
            }
            "passkey.delete" => {
                if role != Role::Host {
                    self.refused(conn_id, frame, Some(session_id), "wrong_role");
                    return;
                }
                let Some(cid) = frame.get("credential_id").and_then(Value::as_str) else {
                    self.refused(conn_id, frame, Some(session_id), "internal");
                    return;
                };
                let removed = decode_any_b64(cid)
                    .and_then(|bytes| self.passkey_broker.delete_passkey(&bytes).ok())
                    .unwrap_or(false);
                self.emit(
                    OutTarget::Conn(conn_id),
                    json!({
                        "v": 1,
                        "type": "passkey.deleted",
                        "request_id": req_id,
                        "credential_id": redact_username(cid),
                        "ok": removed,
                    }),
                );
            }
            "passkey.status" => self.do_passkey_status(conn_id, frame, req_id),
            "passkey.cancel" => {
                let cid = str_or_empty(frame, "ceremony_id");
                let id = PasskeyCeremonyId(cid.clone());
                let ok = self
                    .passkey_broker
                    .cancel_assertion(id.clone())
                    .or_else(|_| self.passkey_broker.cancel_registration(id))
                    .is_ok();
                self.emit(
                    OutTarget::Conn(conn_id),
                    json!({
                        "v": 1,
                        "type": "passkey.cancelled",
                        "request_id": req_id,
                        "ceremony_id": cid,
                        "ok": ok,
                    }),
                );
            }
            _ => {}
        }
    }

    fn do_passkey_status(&mut self, conn_id: u64, frame: &Value, req_id: Value) {
        let raw_id = str_or_empty(frame, "ceremony_id");
        let cid = if raw_id.is_empty() {
            self.passkey_broker
                .latest_ceremony_id()
                .map(|id| id.0)
                .unwrap_or_default()
        } else {
            raw_id
        };
        let id = PasskeyCeremonyId(cid.clone());
        let status = self
            .passkey_broker
            .poll_assertion(id.clone())
            .or_else(|err| self.passkey_broker.poll_registration(id).map_err(|_| err));
        let credential_id = match &status {
            Ok(PasskeyStatus::Complete(outcome)) => match outcome.as_ref() {
                crate::credentials::CeremonyOutcome::Registration(c) => Some(c.id.clone()),
                crate::credentials::CeremonyOutcome::Assertion(c) => Some(c.id.clone()),
            },
            _ => None,
        };
        let status_json = match status {
            Ok(st) => serde_json::to_value(st).unwrap_or(Value::Null),
            Err(err) => json!({"failed": err.to_string()}),
        };
        self.emit(
            OutTarget::Conn(conn_id),
            json!({
                "v": 1,
                "type": "passkey.status",
                "request_id": req_id,
                "ceremony_id": cid,
                "credential_id": credential_id,
                "status": status_json,
            }),
        );
    }
}

struct ParsedProposalEnvelope {
    proposal_id: String,
    snapshot_id: u64,
    fingerprint: String,
    generation: u64,
    operation: Value,
    #[allow(dead_code)]
    rationale: String,
    snapshot: PageSnapshot,
}

struct BackendCredentialSink<'a, B: WebPageBackend> {
    backend: &'a mut B,
    target_id: u64,
}

impl<B: WebPageBackend> CredentialSink for BackendCredentialSink<'_, B> {
    fn set_field(&mut self, field: CredentialFieldKind, value: &str) -> Result<(), BrokerError> {
        self.backend
            .set_credential_field(self.target_id, field, value)
    }
}

fn attach_recall_metadata(store: &RecallStore, snapshot: &mut PageSnapshot) {
    let sig = recall::compute_form_signature(&snapshot.elements);
    snapshot.matched_recipe_id =
        recall::find_matching_recipe_in(store, &snapshot.url, sig.as_deref()).map(|r| r.recipe_id);
    snapshot.form_signature = sig;
}

fn verify_target_ref(
    operation: &Value,
    known_refs: &HashSet<String>,
    snapshot: &PageSnapshot,
) -> Result<(), &'static str> {
    let Some(target_ref) = operation.get("target_ref").and_then(Value::as_str) else {
        return Ok(());
    };
    if !known_refs.contains(target_ref) {
        return Err("target_missing");
    }
    if !snapshot.elements.iter().any(|e| e.node_ref == target_ref) {
        return Err("stale_fingerprint");
    }
    Ok(())
}

fn resolve_target_element<'a>(
    operation: &Value,
    snapshot: &'a PageSnapshot,
) -> Option<&'a ElementSnapshot> {
    if let Some(target_ref) = operation.get("target_ref").and_then(Value::as_str) {
        return snapshot.elements.iter().find(|e| e.node_ref == target_ref);
    }
    let target_id = operation.get("target_id").and_then(Value::as_str)?;
    snapshot.elements.iter().find(|e| e.id == target_id)
}

fn resolve_form_field_element<'a>(
    field: &FormFieldCommand,
    snapshot: &'a PageSnapshot,
) -> Option<&'a ElementSnapshot> {
    if let Some(ref tr) = field.target_ref {
        return snapshot.elements.iter().find(|e| &e.node_ref == tr);
    }
    let tid = field.target_id.as_deref()?;
    snapshot.elements.iter().find(|e| e.id == tid)
}

fn validate_single_form_field(
    field: &FormFieldCommand,
    snapshot: &PageSnapshot,
    known_refs: &HashSet<String>,
    sensitive_out: &mut bool,
) -> Result<(), &'static str> {
    if let Some(ref tr) = field.target_ref {
        if !known_refs.contains(tr) {
            return Err("target_missing");
        }
        if !snapshot.elements.iter().any(|e| &e.node_ref == tr) {
            return Err("stale_fingerprint");
        }
    }
    let Some(el) = resolve_form_field_element(field, snapshot) else {
        return Err("target_missing");
    };
    check_element_visible_enabled(el)?;
    if is_sensitive_element(el) {
        *sensitive_out = true;
        if field.action != "fill_secret" {
            return Err("sensitive_requires_human");
        }
    }
    Ok(())
}

fn check_element_visible_enabled(el: &ElementSnapshot) -> Result<(), &'static str> {
    if !el.visible {
        return Err("target_not_visible");
    }
    if !el.enabled {
        return Err("target_disabled");
    }
    Ok(())
}

fn is_sensitive_element(el: &ElementSnapshot) -> bool {
    if el.value_state == ValueState::Sensitive || el.input_type.as_deref() == Some("password") {
        return true;
    }
    let lower = el.label.to_ascii_lowercase();
    ["password", "delete", "purchase", "credit card", "one-time"]
        .iter()
        .any(|kw| lower.contains(kw))
}

fn parse_credential_fields(operation: &Value) -> Vec<CredentialFieldKind> {
    let Some(values) = operation.get("fields").and_then(Value::as_array) else {
        return vec![
            CredentialFieldKind::Username,
            CredentialFieldKind::CurrentPassword,
        ];
    };
    values
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|name| match name {
            "username" => Some(CredentialFieldKind::Username),
            "current_password" => Some(CredentialFieldKind::CurrentPassword),
            "new_password" => Some(CredentialFieldKind::NewPassword),
            "one_time_code" => Some(CredentialFieldKind::OneTimeCode),
            "payment_card" => Some(CredentialFieldKind::PaymentCard),
            _ => None,
        })
        .collect()
}

fn str_or_empty(frame: &Value, key: &str) -> String {
    frame
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn decode_any_b64(raw: &str) -> Option<Vec<u8>> {
    crate::webauthn::b64::b64url_decode(raw).or_else(|| control::b64_decode(raw))
}

fn extract_validated_start_url(
    frame: &Value,
    allow_local_network: bool,
) -> Result<Option<String>, &'static str> {
    let Some(raw) = frame
        .get("start_url")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    else {
        return Ok(None);
    };
    validate_navigation_url(raw, allow_local_network).map(Some)
}

/// Normalizes and validates an `http`/`https` navigation URL against SSRF local-network policy.
pub fn validate_navigation_url(
    raw_url: &str,
    allow_local_network: bool,
) -> Result<String, &'static str> {
    let parsed = Url::parse(raw_url.trim()).map_err(|_| "internal")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("internal");
    }
    if parsed.host_str().is_none() {
        return Err("internal");
    }
    if !allow_local_network && is_local_or_private_url(&parsed) {
        return Err("local_network_forbidden");
    }
    Ok(parsed.to_string())
}

/// Returns true if `url` targets loopback, RFC 1918 private, link-local, or `.local` hosts.
pub fn is_local_or_private_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return true;
    };
    let clean = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if clean == "localhost"
        || clean.ends_with(".localhost")
        || clean.ends_with(".local")
        || clean.ends_with(".internal")
    {
        return true;
    }
    let Ok(ip) = clean.parse::<IpAddr>() else {
        return false;
    };
    is_non_global_ip(ip)
}

fn is_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_global_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_non_global_ipv4(mapped);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_non_global_ipv4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{Bounds, RawDomNode, ScrollSnapshot, SnapshotMetadata, build_snapshot};

    struct TestTarget {
        page_id: u64,
        generation: u64,
        url: String,
        title: String,
        nodes: Vec<RawDomNode>,
        filled_secrets: HashMap<String, String>,
        commands: Vec<PageCommand>,
    }

    #[derive(Default)]
    struct TestPageBackend {
        targets: HashMap<u64, TestTarget>,
        next_target_id: u64,
        next_snapshot_id: u64,
    }

    impl TestPageBackend {
        fn set_nodes(&mut self, target_id: u64, nodes: Vec<RawDomNode>) {
            if let Some(t) = self.targets.get_mut(&target_id) {
                t.nodes = nodes;
                t.generation += 1;
            }
        }
    }

    fn test_element(
        node_id: u64,
        tag: &str,
        text: &str,
        attrs: HashMap<String, String>,
        bounds: Bounds,
    ) -> RawDomNode {
        let children = if text.is_empty() {
            Vec::new()
        } else {
            vec![RawDomNode {
                node_id: node_id * 1000,
                tag: String::new(),
                text: text.to_string(),
                attributes: HashMap::new(),
                live_value: None,
                live_checked: None,
                focussable: false,
                cursor_pointer: false,
                display: "inline".to_string(),
                visibility: "visible".to_string(),
                opacity: "1".to_string(),
                bounds: None,
                children: Vec::new(),
            }]
        };
        RawDomNode {
            node_id,
            tag: tag.to_string(),
            text: String::new(),
            attributes: attrs,
            live_value: None,
            live_checked: None,
            focussable: true,
            cursor_pointer: tag == "button",
            display: "block".to_string(),
            visibility: "visible".to_string(),
            opacity: "1".to_string(),
            bounds: Some(bounds),
            children,
        }
    }

    impl WebPageBackend for TestPageBackend {
        fn open_target(
            &mut self,
            start_url: Option<&str>,
            _background: bool,
        ) -> Result<u64, String> {
            self.next_target_id += 1;
            let id = self.next_target_id;
            let url = start_url.unwrap_or("https://example.com/").to_string();
            let nodes = vec![
                test_element(
                    1,
                    "button",
                    "Continue",
                    HashMap::new(),
                    Bounds {
                        x: 10.0,
                        y: 10.0,
                        width: 100.0,
                        height: 32.0,
                    },
                ),
                test_element(
                    2,
                    "input",
                    "",
                    HashMap::from([
                        ("type".to_string(), "password".to_string()),
                        ("name".to_string(), "password".to_string()),
                        ("aria-label".to_string(), "Password".to_string()),
                    ]),
                    Bounds {
                        x: 10.0,
                        y: 60.0,
                        width: 200.0,
                        height: 30.0,
                    },
                ),
            ];
            self.targets.insert(
                id,
                TestTarget {
                    page_id: id * 100,
                    generation: 1,
                    url,
                    title: format!("Target {id}"),
                    nodes,
                    filled_secrets: HashMap::new(),
                    commands: Vec::new(),
                },
            );
            Ok(id)
        }

        fn close_target(&mut self, target_id: u64) {
            self.targets.remove(&target_id);
        }

        fn observe_target(&mut self, target_id: u64) -> Option<PageSnapshot> {
            let t = self.targets.get(&target_id)?;
            self.next_snapshot_id += 1;
            let root = RawDomNode {
                node_id: 999,
                tag: "body".to_string(),
                text: String::new(),
                attributes: HashMap::new(),
                live_value: None,
                live_checked: None,
                focussable: false,
                cursor_pointer: false,
                display: "block".to_string(),
                visibility: "visible".to_string(),
                opacity: "1".to_string(),
                bounds: Some(Bounds {
                    x: 0.0,
                    y: 0.0,
                    width: 1280.0,
                    height: 800.0,
                }),
                children: t.nodes.clone(),
            };
            Some(build_snapshot(
                &root,
                None,
                ScrollSnapshot {
                    x: 0.0,
                    y: 0.0,
                    height: 800.0,
                },
                SnapshotMetadata {
                    snapshot_id: self.next_snapshot_id,
                    tab_id: target_id,
                    page_id: t.page_id,
                    document_generation: t.generation,
                    url: t.url.clone(),
                    title: t.title.clone(),
                    viewport_width: 1280.0,
                    viewport_height: 800.0,
                    scale: 1.0,
                },
            ))
        }

        fn known_node_refs(&self, target_id: u64) -> HashSet<String> {
            let Some(t) = self.targets.get(&target_id) else {
                return HashSet::new();
            };
            t.nodes
                .iter()
                .map(|n| format!("n{}_{}", t.page_id, n.node_id))
                .collect()
        }

        fn can_go_back(&self, _target_id: u64) -> bool {
            false
        }

        fn can_go_forward(&self, _target_id: u64) -> bool {
            false
        }

        fn check_interactable(
            &self,
            _target_id: u64,
            element: &ElementSnapshot,
        ) -> Result<(), &'static str> {
            check_element_visible_enabled(element)
        }

        fn dispatch_command(
            &mut self,
            target_id: u64,
            command: &PageCommand,
            _snapshot: &PageSnapshot,
        ) -> Result<(), String> {
            let t = self.targets.get_mut(&target_id).ok_or("missing target")?;
            if let PageCommand::Navigate { url } = command {
                t.url = url.clone();
                t.page_id += 1;
            }
            t.generation += 1;
            t.commands.push(command.clone());
            Ok(())
        }

        fn set_credential_field(
            &mut self,
            target_id: u64,
            field: CredentialFieldKind,
            value: &str,
        ) -> Result<(), BrokerError> {
            let t = self
                .targets
                .get_mut(&target_id)
                .ok_or_else(|| BrokerError::NotFound("missing target".to_string()))?;
            t.filled_secrets
                .insert(field.as_str().to_string(), value.to_string());
            t.generation += 1;
            Ok(())
        }
    }

    fn find_frame(out: &[(OutTarget, Value)], kind: &str) -> Option<Value> {
        out.iter()
            .find(|(_, v)| v.get("type").and_then(Value::as_str) == Some(kind))
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn multi_session_foreground_and_background_operate_independently() {
        let mut engine = SupervisionEngine::in_memory(TestPageBackend::default());
        engine.handle_event(ControlEvent::Connect {
            conn_id: 1,
            role: Role::Host,
        });
        engine.handle_event(ControlEvent::Connect {
            conn_id: 2,
            role: Role::Agent,
        });

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "session.open", "seq": 1, "request_id": "r1",
                "title": "Foreground Task", "start_url": "https://alpha.example.com/"
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "session.open", "seq": 2, "request_id": "r2",
                "title": "Background Task", "start_url": "https://beta.example.com/",
                "background": true
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 1, "session_id": "s_1"}),
        });
        let obs1 = find_frame(&engine.drain_outbox(), "observe.result").expect("obs s_1");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 2, "session_id": "s_2"}),
        });
        let obs2 = find_frame(&engine.drain_outbox(), "observe.result").expect("obs s_2");
        assert_eq!(obs1["url"], "https://alpha.example.com/");
        assert_eq!(obs2["url"], "https://beta.example.com/");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 3, "session_id": "s_1",
                "proposal_id": "p_fg", "snapshot_id": obs1["snapshot_id"],
                "fingerprint": obs1["fingerprint"], "generation": obs1["generation"],
                "operation": {"kind": "click", "target_id": "el_1"},
                "rationale": "Click continue on alpha"
            }),
        });
        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 4, "session_id": "s_2",
                "proposal_id": "p_bg", "snapshot_id": obs2["snapshot_id"],
                "fingerprint": obs2["fingerprint"], "generation": obs2["generation"],
                "operation": {"kind": "click", "target_id": "el_1"},
                "rationale": "Click continue on beta"
            }),
        });
        let _ = engine.drain_outbox();
        assert_eq!(
            engine.session("s_1").map(|s| s.state),
            Some(ControlState::AwaitingDecision)
        );
        assert_eq!(
            engine.session("s_2").map(|s| s.state),
            Some(ControlState::AwaitingDecision)
        );

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "decision", "seq": 3, "session_id": "s_2",
                "proposal_id": "p_bg", "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"], "decision": "approve"
            }),
        });
        let out = engine.drain_outbox();
        assert!(find_frame(&out, "executed").is_some());
        assert_eq!(
            engine.session("s_2").map(|s| s.state),
            Some(ControlState::Agent)
        );
        assert_eq!(
            engine.session("s_1").map(|s| s.state),
            Some(ControlState::AwaitingDecision)
        );
        assert_eq!(engine.audit_log().verify_chain(), Ok(()));
    }

    #[test]
    fn sensitive_type_refused_and_sealed_credential_fill_enforces_agent_blackout() {
        let mut engine = SupervisionEngine::in_memory(TestPageBackend::default());
        engine.handle_event(ControlEvent::Connect {
            conn_id: 1,
            role: Role::Host,
        });
        engine.handle_event(ControlEvent::Connect {
            conn_id: 2,
            role: Role::Agent,
        });

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "session.open", "seq": 1,
                "title": "Sign In", "start_url": "https://login.example.com/"
            }),
        });
        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "credential.save", "seq": 2,
                "host": "login.example.com", "username": "alice@example.com", "secret": "s3cr3t!"
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 1}),
        });
        let obs = find_frame(&engine.drain_outbox(), "observe.result").expect("obs");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 2,
                "proposal_id": "p_bad", "snapshot_id": obs["snapshot_id"],
                "fingerprint": obs["fingerprint"], "generation": obs["generation"],
                "operation": {"kind": "type", "target_id": "el_2", "text": "guessed"},
                "rationale": "Try typing into password input"
            }),
        });
        let bad_out = engine.drain_outbox();
        let refused = find_frame(&bad_out, "refused").expect("refused");
        assert_eq!(refused["reason"], "sensitive_requires_human");
        assert!(find_frame(&bad_out, "action_required").is_some());

        assert!(engine.control_take("s_1", "user", "ui"));
        assert!(engine.control_release("s_1", "user", "ui"));
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 3}),
        });
        let obs2 = find_frame(&engine.drain_outbox(), "observe.result").expect("obs2");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 4,
                "proposal_id": "p_fill", "snapshot_id": obs2["snapshot_id"],
                "fingerprint": obs2["fingerprint"], "generation": obs2["generation"],
                "operation": {
                    "kind": "credential.fill",
                    "origin": "https://login.example.com",
                    "fields": ["current_password"],
                    "mode": "sealed"
                },
                "rationale": "Fill saved login"
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "decision", "seq": 3,
                "proposal_id": "p_fill", "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"], "decision": "approve"
            }),
        });
        let fill_out = engine.drain_outbox();
        let filled = find_frame(&fill_out, "credential.filled").expect("credential.filled");
        assert_eq!(filled["account_hint"], "a**@example.com");
        assert_eq!(filled["blackout_agent_observation"], true);
        assert!(!filled.to_string().contains("s3cr3t!"));

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 5}),
        });
        let blk_out = engine.drain_outbox();
        let blk_refused = find_frame(&blk_out, "refused").expect("blackout refused");
        assert_eq!(blk_refused["reason"], "sealed_blackout");

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({"type": "observe.request", "seq": 4}),
        });
        let host_obs =
            find_frame(&engine.drain_outbox(), "observe.result").expect("host can observe");
        assert_eq!(host_obs["url"], "https://login.example.com/");

        engine.backend_mut().set_nodes(1, Vec::new());
        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 6}),
        });
        let post_nav = engine.drain_outbox();
        assert!(find_frame(&post_nav, "observe.result").is_some());
    }

    #[test]
    fn stale_mutation_ssrf_policy_and_host_disconnect_failsafe_enforce_invariants() {
        let mut engine = SupervisionEngine::in_memory(TestPageBackend::default());
        engine.handle_event(ControlEvent::Connect {
            conn_id: 1,
            role: Role::Host,
        });
        engine.handle_event(ControlEvent::Connect {
            conn_id: 2,
            role: Role::Agent,
        });

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "session.open", "seq": 1,
                "title": "Public Web Only",
                "start_url": "https://shop.example.com/",
                "policy": {"allow_local_network": false}
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 1}),
        });
        let obs = find_frame(&engine.drain_outbox(), "observe.result").expect("obs");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 2,
                "proposal_id": "p_ssrf", "snapshot_id": obs["snapshot_id"],
                "fingerprint": obs["fingerprint"], "generation": obs["generation"],
                "operation": {"kind": "navigate", "url": "http://169.254.169.254/latest/meta-data/"},
                "rationale": "Try metadata SSRF"
            }),
        });
        let ssrf_refused = find_frame(&engine.drain_outbox(), "refused").expect("ssrf refused");
        assert_eq!(ssrf_refused["reason"], "local_network_forbidden");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 3,
                "proposal_id": "p_click", "snapshot_id": obs["snapshot_id"],
                "fingerprint": obs["fingerprint"], "generation": obs["generation"],
                "operation": {"kind": "click", "target_id": "el_1"},
                "rationale": "Click continue"
            }),
        });
        let _ = engine.drain_outbox();

        engine.backend_mut().set_nodes(1, Vec::new());
        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "decision", "seq": 2,
                "proposal_id": "p_click", "fingerprint": obs["fingerprint"],
                "generation": obs["generation"], "decision": "approve"
            }),
        });
        let stale_out = engine.drain_outbox();
        let stale_refused = find_frame(&stale_out, "refused").expect("stale refused");
        assert_eq!(stale_refused["reason"], "stale_fingerprint");

        engine.handle_event(ControlEvent::Disconnect { conn_id: 1 });
        assert_eq!(
            engine.session("s_1").map(|s| s.state),
            Some(ControlState::Error)
        );
        assert_eq!(engine.audit_log().verify_chain(), Ok(()));
    }

    #[test]
    fn passkey_registration_and_assertion_ceremonies_gate_on_human_decision() {
        let mut engine = SupervisionEngine::in_memory(TestPageBackend::default());
        engine.handle_event(ControlEvent::Connect {
            conn_id: 1,
            role: Role::Host,
        });
        engine.handle_event(ControlEvent::Connect {
            conn_id: 2,
            role: Role::Agent,
        });
        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "session.open", "seq": 1,
                "title": "Passkey Flow", "start_url": "https://rp.example.com/"
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 1}),
        });
        let obs = find_frame(&engine.drain_outbox(), "observe.result").expect("obs");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 2,
                "proposal_id": "p_reg", "snapshot_id": obs["snapshot_id"],
                "fingerprint": obs["fingerprint"], "generation": obs["generation"],
                "operation": {
                    "kind": "passkey.register",
                    "origin": "https://rp.example.com",
                    "challenge": "Y2hhbGxlbmdlLTEyMzQ1Ng",
                    "rp": {"id": "rp.example.com", "name": "Example RP"},
                    "user": {"id": "dXNlci0x", "name": "alice@example.com", "displayName": "Alice"},
                    "pub_key_cred_params": [{"type": "public-key", "alg": -7}]
                },
                "rationale": "Register passkey"
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "decision", "seq": 2,
                "proposal_id": "p_reg", "fingerprint": obs["fingerprint"],
                "generation": obs["generation"], "decision": "approve"
            }),
        });
        let reg_out = engine.drain_outbox();
        let completed = find_frame(&reg_out, "passkey.completed").expect("passkey.completed");
        let cred_id = completed["status"]["Complete"]["Registration"]["id"]
            .as_str()
            .expect("credential id")
            .to_string();

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({"type": "observe.request", "seq": 3}),
        });
        let obs2 = find_frame(&engine.drain_outbox(), "observe.result").expect("obs2");

        engine.handle_event(ControlEvent::Message {
            conn_id: 2,
            frame: json!({
                "type": "propose", "seq": 4,
                "proposal_id": "p_assert", "snapshot_id": obs2["snapshot_id"],
                "fingerprint": obs2["fingerprint"], "generation": obs2["generation"],
                "operation": {
                    "kind": "passkey.assert",
                    "origin": "https://rp.example.com",
                    "rp_id": "rp.example.com",
                    "challenge": "YXNzZXJ0LWNoYWxsZW5nZQ",
                    "allow_credentials": [{"type": "public-key", "id": cred_id}]
                },
                "rationale": "Sign in with passkey"
            }),
        });
        let _ = engine.drain_outbox();

        engine.handle_event(ControlEvent::Message {
            conn_id: 1,
            frame: json!({
                "type": "decision", "seq": 3,
                "proposal_id": "p_assert", "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"], "decision": "approve"
            }),
        });
        let assert_out = engine.drain_outbox();
        let asserted = find_frame(&assert_out, "passkey.completed").expect("assert completed");
        let sig_b64 = asserted["status"]["Complete"]["Assertion"]["response"]["signature"]
            .as_str()
            .expect("base64url signature");
        let sig_der = crate::webauthn::b64::b64url_decode(sig_b64).expect("decode signature");
        assert!(!sig_der.is_empty());
        assert_eq!(engine.audit_log().verify_chain(), Ok(()));
    }
}
