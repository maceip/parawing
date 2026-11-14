// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Blitz + Deno V8 authority backend bridging `parawing_authority` into `packages/rust-host`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use parawing_core_host::native_host::{NativeClickOutcome, NativeDomNode, NativeFormSubmission};
use parawing_authority::audit::AuditLog;
use parawing_authority::command::{FormFieldCommand, PageCommand};
use parawing_authority::control::{
    self, ControlEvent, ControlHub, ControlServerConfig, ControlServerHandle, Role,
};
use parawing_authority::credentials::{
    BrokerError, CredentialFieldKind, CredentialSink, KeychainPasskeyStore, KeychainPasswordStore,
    LocalCredentialBroker, LocalPasskeyBroker, TokenizedSubstitutionSpec,
};
use parawing_authority::observe::{
    build_snapshot, Bounds, ElementSnapshot, PageSnapshot, RawDomNode, ScrollSnapshot,
    SnapshotMetadata, ValueState,
};
use parawing_authority::recall::{self, FormRecipe, RecallStore, RecipeField};
use parawing_authority::serde_json::Value as AuthValue;
use parawing_authority::supervision::{
    ControlState, DecisionInput, OutTarget, SupervisionEngine, WebPageBackend,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::capsule::CpuBaseline;
use crate::engine_host::{
    build_engine_isolate_script, ensure_rustls_provider, DomOpById, RenderActorHandle,
};
use crate::rpc_pipe::{spawn_deno_worker, DenoWorkerProcess, RpcCallResult};

const BLANK_HTML: &str =
    "<!doctype html><html><head><title>blank</title></head><body></body></html>";
const VIEWPORT_WIDTH: u32 = 1280;
const VIEWPORT_HEIGHT: u32 = 800;

/// Form submission target metadata inspected from live `NativeBlitzDocument` state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectedFormSubmission {
    pub url: String,
    pub origin: String,
    pub method: String,
    pub fields: Vec<(String, String)>,
}

/// Metadata emitted for an outbound form submission executed by `BlitzDenoAuthorityBackend`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionRecord {
    pub url: String,
    pub origin: String,
    pub method: String,
    pub status: u16,
    pub tokenized_substituted: bool,
}

enum IoCmd {
    FetchHtml {
        url: String,
        reply: mpsc::SyncSender<Result<(String, String), String>>,
    },
    SubmitForm {
        url: String,
        method: String,
        fields: Vec<(String, String)>,
        reply: mpsc::SyncSender<Result<(String, u16, String), String>>,
    },
    SpawnWorker {
        target_id: u64,
        render_target_id: String,
        url: String,
        v8_flags: Vec<String>,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    SyncAction {
        target_id: u64,
        payload: Value,
        reply: mpsc::SyncSender<Result<Value, String>>,
    },
    EvalJs {
        target_id: u64,
        expression: String,
        reply: mpsc::SyncSender<Result<Value, String>>,
    },
    CloseWorker {
        target_id: u64,
        reply: mpsc::SyncSender<()>,
    },
    HasWorker {
        target_id: u64,
        reply: mpsc::SyncSender<bool>,
    },
    Shutdown,
}

struct IoActorHandle {
    tx: mpsc::Sender<IoCmd>,
    thread: Option<JoinHandle<()>>,
}

impl IoActorHandle {
    fn spawn(render: RenderActorHandle) -> Result<Self, String> {
        ensure_rustls_provider();
        let (tx, rx) = mpsc::channel::<IoCmd>();
        let (init_tx, init_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let thread = std::thread::Builder::new()
            .name("parawing-authority-io".to_string())
            .spawn(move || run_io_actor(rx, render, init_tx))
            .map_err(|e| format!("spawn authority io thread: {e}"))?;
        init_rx
            .recv()
            .map_err(|_| "authority io thread exited during init".to_string())??;
        Ok(Self {
            tx,
            thread: Some(thread),
        })
    }

    fn fetch_html(&self, url: &str) -> Result<(String, String), String> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(IoCmd::FetchHtml {
                url: url.to_string(),
                reply: tx,
            })
            .map_err(|_| "authority io actor dropped".to_string())?;
        rx.recv()
            .map_err(|_| "authority io actor dropped".to_string())?
    }

    fn submit_form(
        &self,
        url: &str,
        method: &str,
        fields: Vec<(String, String)>,
    ) -> Result<(String, u16, String), String> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(IoCmd::SubmitForm {
                url: url.to_string(),
                method: method.to_string(),
                fields,
                reply: tx,
            })
            .map_err(|_| "authority io actor dropped".to_string())?;
        rx.recv()
            .map_err(|_| "authority io actor dropped".to_string())?
    }

    fn spawn_worker(
        &self,
        target_id: u64,
        render_target_id: &str,
        url: &str,
        v8_flags: &[String],
    ) -> Result<(), String> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(IoCmd::SpawnWorker {
                target_id,
                render_target_id: render_target_id.to_string(),
                url: url.to_string(),
                v8_flags: v8_flags.to_vec(),
                reply: tx,
            })
            .map_err(|_| "authority io actor dropped".to_string())?;
        rx.recv()
            .map_err(|_| "authority io actor dropped".to_string())?
    }

    fn sync_action(&self, target_id: u64, payload: Value) -> Result<Value, String> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(IoCmd::SyncAction {
                target_id,
                payload,
                reply: tx,
            })
            .map_err(|_| "authority io actor dropped".to_string())?;
        rx.recv()
            .map_err(|_| "authority io actor dropped".to_string())?
    }

    fn eval_js(&self, target_id: u64, expression: &str) -> Result<Value, String> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(IoCmd::EvalJs {
                target_id,
                expression: expression.to_string(),
                reply: tx,
            })
            .map_err(|_| "authority io actor dropped".to_string())?;
        rx.recv()
            .map_err(|_| "authority io actor dropped".to_string())?
    }

    fn close_worker(&self, target_id: u64) {
        let (tx, rx) = mpsc::sync_channel(1);
        if self
            .tx
            .send(IoCmd::CloseWorker {
                target_id,
                reply: tx,
            })
            .is_ok()
        {
            let _ = rx.recv();
        }
    }

    fn has_worker(&self, target_id: u64) -> bool {
        let (tx, rx) = mpsc::sync_channel(1);
        if self
            .tx
            .send(IoCmd::HasWorker {
                target_id,
                reply: tx,
            })
            .is_err()
        {
            return false;
        }
        rx.recv().unwrap_or(false)
    }

    fn shutdown(&mut self) {
        let _ = self.tx.send(IoCmd::Shutdown);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for IoActorHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_io_actor(
    rx: mpsc::Receiver<IoCmd>,
    render: RenderActorHandle,
    init_tx: mpsc::SyncSender<Result<(), String>>,
) {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = init_tx.send(Err(format!("tokio runtime: {e}")));
            return;
        }
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = init_tx.send(Err(format!("reqwest client: {e}")));
            return;
        }
    };
    let _ = init_tx.send(Ok(()));
    let mut workers: HashMap<u64, DenoWorkerProcess> = HashMap::new();
    while let Ok(cmd) = rx.recv() {
        if !handle_io_cmd(&rt, &client, &render, &mut workers, cmd) {
            break;
        }
    }
    rt.block_on(async {
        for (_, mut w) in workers {
            w.shutdown().await;
        }
    });
}

fn handle_io_cmd(
    rt: &tokio::runtime::Runtime,
    client: &reqwest::Client,
    render: &RenderActorHandle,
    workers: &mut HashMap<u64, DenoWorkerProcess>,
    cmd: IoCmd,
) -> bool {
    match cmd {
        IoCmd::Shutdown => return false,
        IoCmd::HasWorker { target_id, reply } => {
            let _ = reply.send(workers.contains_key(&target_id));
        }
        IoCmd::CloseWorker { target_id, reply } => {
            if let Some(mut old) = workers.remove(&target_id) {
                rt.block_on(old.shutdown());
            }
            let _ = reply.send(());
        }
        IoCmd::FetchHtml { url, reply } => {
            let _ = reply.send(rt.block_on(http_get_html(client, &url)));
        }
        IoCmd::SubmitForm {
            url,
            method,
            fields,
            reply,
        } => {
            let _ = reply.send(rt.block_on(http_submit_form(client, &url, &method, &fields)));
        }
        IoCmd::SpawnWorker {
            target_id,
            render_target_id,
            url,
            v8_flags,
            reply,
        } => {
            let res = rt.block_on(respawn_deno_worker(
                workers,
                target_id,
                &render_target_id,
                &url,
                &v8_flags,
                render,
            ));
            let _ = reply.send(res);
        }
        IoCmd::SyncAction {
            target_id,
            payload,
            reply,
        } => {
            let res = call_worker_method(rt, workers, target_id, "authoritySync", vec![payload]);
            let _ = reply.send(res);
        }
        IoCmd::EvalJs {
            target_id,
            expression,
            reply,
        } => {
            let res = call_worker_method(
                rt,
                workers,
                target_id,
                "evalJs",
                vec![Value::String(expression)],
            );
            let _ = reply.send(res);
        }
    }
    true
}

async fn http_get_html(client: &reqwest::Client, url: &str) -> Result<(String, String), String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let final_url = resp.url().to_string();
    let html = resp
        .text()
        .await
        .map_err(|e| format!("read GET {url}: {e}"))?;
    Ok((final_url, html))
}

async fn http_submit_form(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    fields: &[(String, String)],
) -> Result<(String, u16, String), String> {
    let resp = if method.eq_ignore_ascii_case("post") {
        client.post(url).form(fields).send().await
    } else {
        client.get(url).query(fields).send().await
    }
    .map_err(|e| format!("{} {url}: {e}", method.to_ascii_uppercase()))?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let html = resp
        .text()
        .await
        .map_err(|e| format!("read {} {url}: {e}", method.to_ascii_uppercase()))?;
    Ok((final_url, status, html))
}

async fn respawn_deno_worker(
    workers: &mut HashMap<u64, DenoWorkerProcess>,
    target_id: u64,
    render_target_id: &str,
    url: &str,
    v8_flags: &[String],
    render: &RenderActorHandle,
) -> Result<(), String> {
    if let Some(mut old) = workers.remove(&target_id) {
        old.shutdown().await;
    }
    let flag_refs: Vec<&str> = v8_flags.iter().map(String::as_str).collect();
    let worker = spawn_deno_worker(None, build_engine_isolate_script(), &flag_refs)
        .await
        .map_err(|e| format!("spawn deno worker: {e}"))?;
    let render_cb = render.clone();
    let tid = render_target_id.to_string();
    worker
        .session
        .set_callback_handler(Arc::new(move |_, method, args, _| {
            let render_inner = render_cb.clone();
            let target_key = tid.clone();
            Box::pin(async move { handle_deno_cb(&render_inner, &target_key, method, args).await })
        }));
    let init = worker
        .session
        .call(
            "authoritySync",
            vec![json!({"action": "navigate", "url": url})],
            Vec::new(),
        )
        .await
        .map_err(|e| format!("init deno worker: {e}"))?;
    let _ = init;
    workers.insert(target_id, worker);
    Ok(())
}

async fn handle_deno_cb(
    render: &RenderActorHandle,
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
    Ok(RpcCallResult {
        value: json!({ "applied": applied }),
        binaries: Vec::new(),
    })
}

fn call_worker_method(
    rt: &tokio::runtime::Runtime,
    workers: &mut HashMap<u64, DenoWorkerProcess>,
    target_id: u64,
    method: &str,
    args: Vec<Value>,
) -> Result<Value, String> {
    let worker = workers
        .get(&target_id)
        .ok_or_else(|| format!("no Deno worker active for target {target_id}"))?;
    let session = &worker.session;
    let res = rt
        .block_on(session.call(method, args, Vec::new()))
        .map_err(|e| format!("deno {method}: {e}"))?;
    Ok(res.value)
}

struct TargetState {
    render_target_id: String,
    current_url: String,
    history: Vec<String>,
    history_index: usize,
    document_generation: u64,
    known_node_refs: HashSet<String>,
    frame_seq: u64,
}

/// Supervised page execution backend powered by `NativeBlitzDocument` + restricted Deno V8 child.
pub struct BlitzDenoAuthorityBackend {
    render: RenderActorHandle,
    owns_render: bool,
    io: IoActorHandle,
    v8_flags: Vec<String>,
    targets: HashMap<u64, TargetState>,
    next_target_id: u64,
    next_snapshot_id: u64,
    active_target_id: Option<u64>,
    staged_specs: Vec<TokenizedSubstitutionSpec>,
    recipes: Vec<FormRecipe>,
    local_recall: RecallStore,
    virtual_pages: HashMap<String, String>,
    submissions: Vec<SubmissionRecord>,
    last_submission_error: Option<String>,
}

impl BlitzDenoAuthorityBackend {
    /// Creates a self-contained backend owning its `RenderActorHandle` and Deno V8 child pool.
    pub fn new() -> Result<Self, String> {
        let render = RenderActorHandle::spawn().map_err(|e| e.to_string())?;
        let flags = crate::capsule::resolved_v8_flags(CpuBaseline::host_default())
            .map_err(|e| e.to_string())?;
        let mut backend = Self::with_render(render, flags)?;
        backend.owns_render = true;
        Ok(backend)
    }

    /// Creates a backend sharing an existing `EngineHostHandle` `RenderActorHandle`.
    pub fn with_render(render: RenderActorHandle, v8_flags: Vec<String>) -> Result<Self, String> {
        let io = IoActorHandle::spawn(render.clone())?;
        Ok(Self {
            render,
            owns_render: false,
            io,
            v8_flags,
            targets: HashMap::new(),
            next_target_id: 1,
            next_snapshot_id: 1,
            active_target_id: None,
            staged_specs: Vec::new(),
            recipes: Vec::new(),
            local_recall: RecallStore::default(),
            virtual_pages: HashMap::new(),
            submissions: Vec::new(),
            last_submission_error: None,
        })
    }

    /// Returns a clone of the underlying `RenderActorHandle`.
    pub fn render_handle(&self) -> RenderActorHandle {
        self.render.clone()
    }

    /// Registers static HTML to serve when navigating to `url` without external network access.
    pub fn register_virtual_page(&mut self, url: &str, html: &str) {
        self.virtual_pages
            .insert(normalize_nav_key(url), html.to_string());
    }

    /// Sets the active target used when `CredentialSink::set_field` is invoked without a target id.
    pub fn set_active_target(&mut self, target_id: u64) {
        self.active_target_id = Some(target_id);
    }

    /// Stages a `TokenizedSubstitutionSpec` for the next matching-origin submission.
    pub fn stage_tokenized_spec(&mut self, spec: TokenizedSubstitutionSpec) {
        self.staged_specs.push(spec);
    }

    /// Synchronizes known `RecallStore` recipes into the backend for `PageCommand::ReplayRecipe`.
    pub fn sync_recall_recipes(&mut self, recipes: &[FormRecipe]) {
        self.recipes = recipes.to_vec();
        self.local_recall.recipes = recipes.to_vec();
    }

    /// Evaluates JS in the target's restricted Deno V8 child and applies emitted DOM ops to Blitz.
    pub fn evaluate_js(&self, target_id: u64, expression: &str) -> Result<Value, String> {
        if !self.targets.contains_key(&target_id) {
            return Err(format!("unknown target {target_id}"));
        }
        self.io.eval_js(target_id, expression)
    }

    /// Loads explicit HTML into an existing open target as a new document generation.
    pub fn load_html(&mut self, target_id: u64, url: &str, html: &str) -> Result<(), String> {
        let state = self
            .targets
            .get_mut(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?;
        let rtid = state.render_target_id.clone();
        self.render
            .navigate_html_sync(&rtid, url, html, VIEWPORT_WIDTH, VIEWPORT_HEIGHT)?;
        self.io
            .spawn_worker(target_id, &rtid, url, &self.v8_flags)?;
        state.current_url = url.to_string();
        state.document_generation += 1;
        state.history.truncate(state.history_index + 1);
        state.history.push(url.to_string());
        state.history_index = state.history.len() - 1;
        self.active_target_id = Some(target_id);
        Ok(())
    }

    /// Returns whether a restricted Deno V8 child worker is live for `target_id`.
    pub fn has_live_deno_worker(&self, target_id: u64) -> bool {
        self.io.has_worker(target_id)
    }

    /// Returns outbound HTTP submission receipts recorded by this backend.
    pub fn submission_records(&self) -> &[SubmissionRecord] {
        &self.submissions
    }

    /// Takes the most recent cross-origin or token error recorded during `Submit`, if any.
    pub fn take_last_submission_error(&mut self) -> Option<String> {
        self.last_submission_error.take()
    }

    /// Inspects `<form>` target URL, origin, method, and fields for `target_id`.
    pub fn inspect_form_submission(
        &self,
        target_id: u64,
        trigger_node_id: Option<u32>,
    ) -> Result<InspectedFormSubmission, String> {
        let state = self
            .targets
            .get(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?;
        let sub = self
            .render
            .with_doc_sync(&state.render_target_id, move |doc, _| {
                doc.inspect_form_submission(trigger_node_id)
            })?;
        let resolved_url = resolve_submission_url(&state.current_url, &sub.action)?;
        let origin = recall::origin_of(&resolved_url);
        Ok(InspectedFormSubmission {
            url: resolved_url,
            origin,
            method: sub.method,
            fields: sub.fields,
        })
    }

    /// Shuts down active Deno child workers and helper actors cleanly.
    pub fn shutdown(&mut self) {
        let ids: Vec<u64> = self.targets.keys().copied().collect();
        for id in ids {
            self.close_target(id);
        }
        self.io.shutdown();
        if self.owns_render {
            self.render.shutdown();
        }
    }

    fn fetch_or_virtual_html(&self, url: &str) -> Result<(String, String), String> {
        if url == "about:blank" {
            return Ok(("about:blank".to_string(), BLANK_HTML.to_string()));
        }
        if let Some(html) = self.virtual_pages.get(&normalize_nav_key(url)) {
            return Ok((url.to_string(), html.clone()));
        }
        self.io.fetch_html(url)
    }

    fn navigate_internal(&mut self, target_id: u64, url: &str, push: bool) -> Result<(), String> {
        let (final_url, html) = self.fetch_or_virtual_html(url)?;
        let rtid = self
            .targets
            .get(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?
            .render_target_id
            .clone();
        self.render.navigate_html_sync(
            &rtid,
            &final_url,
            &html,
            VIEWPORT_WIDTH,
            VIEWPORT_HEIGHT,
        )?;
        self.io
            .spawn_worker(target_id, &rtid, &final_url, &self.v8_flags)?;
        let state = self
            .targets
            .get_mut(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?;
        state.current_url = final_url.clone();
        state.document_generation += 1;
        if push {
            state.history.truncate(state.history_index + 1);
            state.history.push(final_url);
            state.history_index = state.history.len() - 1;
        }
        self.active_target_id = Some(target_id);
        Ok(())
    }

    fn apply_loaded_response(
        &mut self,
        target_id: u64,
        final_url: &str,
        html: &str,
    ) -> Result<(), String> {
        let rtid = self
            .targets
            .get(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?
            .render_target_id
            .clone();
        self.render
            .navigate_html_sync(&rtid, final_url, html, VIEWPORT_WIDTH, VIEWPORT_HEIGHT)?;
        self.io
            .spawn_worker(target_id, &rtid, final_url, &self.v8_flags)?;
        let state = self
            .targets
            .get_mut(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?;
        state.current_url = final_url.to_string();
        state.document_generation += 1;
        state.history.truncate(state.history_index + 1);
        state.history.push(final_url.to_string());
        state.history_index = state.history.len() - 1;
        self.active_target_id = Some(target_id);
        Ok(())
    }

    fn execute_submit(
        &mut self,
        target_id: u64,
        trigger_node_id: Option<u32>,
    ) -> Result<(), String> {
        self.last_submission_error = None;
        let state = self
            .targets
            .get(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?;
        let rtid = state.render_target_id.clone();
        let current_url = state.current_url.clone();
        let sub: NativeFormSubmission = self.render.with_doc_sync(&rtid, move |doc, _| {
            doc.inspect_form_submission(trigger_node_id)
        })?;
        let target_url = resolve_submission_url(&current_url, &sub.action)?;
        let target_origin = recall::origin_of(&target_url);
        let has_tokens = sub.fields.iter().any(|(_, v)| v.starts_with("$cred:"));
        let resolved_fields = if has_tokens {
            match self.substitute_tokenized_fields(&target_origin, &sub.fields) {
                Ok(f) => f,
                Err(err) => {
                    self.last_submission_error = Some(err.clone());
                    return Err(err);
                }
            }
        } else {
            sub.fields.clone()
        };
        if let Some(virt_html) = self
            .virtual_pages
            .get(&normalize_nav_key(&target_url))
            .cloned()
        {
            self.apply_loaded_response(target_id, &target_url, &virt_html)?;
            self.submissions.push(SubmissionRecord {
                url: target_url,
                origin: target_origin,
                method: sub.method,
                status: 200,
                tokenized_substituted: has_tokens,
            });
            return Ok(());
        }
        let (final_url, status, html) =
            self.io
                .submit_form(&target_url, &sub.method, resolved_fields)?;
        self.apply_loaded_response(target_id, &final_url, &html)?;
        self.submissions.push(SubmissionRecord {
            url: final_url,
            origin: target_origin,
            method: sub.method,
            status,
            tokenized_substituted: has_tokens,
        });
        Ok(())
    }

    fn substitute_tokenized_fields(
        &mut self,
        target_origin: &str,
        fields: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String> {
        let mut used_indices = HashSet::new();
        let mut out = Vec::with_capacity(fields.len());
        for (name, val) in fields {
            if !val.starts_with("$cred:") {
                out.push((name.clone(), val.clone()));
                continue;
            }
            let (idx, plaintext) = self.resolve_single_token(val, target_origin)?;
            used_indices.insert(idx);
            out.push((name.clone(), plaintext));
        }
        let mut descending: Vec<usize> = used_indices.into_iter().collect();
        descending.sort_unstable_by(|a, b| b.cmp(a));
        for idx in descending {
            self.staged_specs.remove(idx);
        }
        Ok(out)
    }

    fn resolve_single_token(
        &self,
        token: &str,
        target_origin: &str,
    ) -> Result<(usize, String), String> {
        for (idx, spec) in self.staged_specs.iter().enumerate() {
            if spec.username_token.as_deref() == Some(token) {
                return check_spec_origin(spec, target_origin, idx, spec.username_value.as_deref());
            }
            if spec.secret_token.as_deref() == Some(token) {
                return check_spec_origin(spec, target_origin, idx, spec.secret_value.as_deref());
            }
        }
        Err(format!(
            "cross-origin or unresolved credential token submission to '{target_origin}'"
        ))
    }

    fn apply_form_field(
        &mut self,
        target_id: u64,
        snapshot: &PageSnapshot,
        field: &FormFieldCommand,
    ) -> Result<(), String> {
        let el = resolve_element(
            snapshot,
            field.target_id.as_deref(),
            field.target_ref.as_deref(),
        )?;
        let dom_id = parse_element_dom_id(el)?;
        let rtid = self
            .targets
            .get(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?
            .render_target_id
            .clone();
        let val = field.value.as_deref().unwrap_or("");
        match field.action.as_str() {
            "select" => {
                let value = val.to_string();
                self.render.with_doc_sync(&rtid, move |doc, _| {
                    doc.select_option(dom_id, &value).map(|_| ())
                })?;
            }
            "check" => {
                let checked = parse_truthy_check(val);
                self.render.with_doc_sync(&rtid, move |doc, _| {
                    if doc.set_checkbox_checked(dom_id, checked) {
                        Ok(())
                    } else {
                        Err(format!("set_checkbox_checked failed on node {dom_id}"))
                    }
                })?;
            }
            "type" => {
                let value = val.to_string();
                self.render.with_doc_sync(&rtid, move |doc, _| {
                    if doc.set_input_text(dom_id, &value) {
                        doc.set_focus(dom_id);
                        Ok(())
                    } else {
                        Err(format!("set_input_text failed on node {dom_id}"))
                    }
                })?;
            }
            "fill_secret" => {
                return Err("fill_secret must be executed via credential.fill".to_string());
            }
            other => return Err(format!("unsupported fill_form action '{other}'")),
        }
        Ok(())
    }

    fn apply_recipe_fields(
        &mut self,
        target_id: u64,
        snapshot: &PageSnapshot,
        recipe_id: &str,
    ) -> Result<(), String> {
        let recipe = self
            .find_recipe(recipe_id, snapshot)
            .ok_or_else(|| format!("no matching form recipe '{recipe_id}' for {}", snapshot.url))?;
        for rf in &recipe.fields {
            if rf.action == "fill_secret" {
                continue;
            }
            let Some(el) = match_recipe_field(snapshot, rf) else {
                continue;
            };
            let cmd = FormFieldCommand {
                target_id: Some(el.id.clone()),
                target_ref: Some(el.node_ref.clone()),
                action: rf.action.clone(),
                value: rf.value.clone(),
                origin: None,
                username: None,
                account_id: None,
            };
            self.apply_form_field(target_id, snapshot, &cmd)?;
        }
        let _ = self.io.sync_action(
            target_id,
            json!({"action": "replay_recipe", "recipeId": recipe.recipe_id}),
        );
        Ok(())
    }

    fn find_recipe(&self, recipe_id: &str, snapshot: &PageSnapshot) -> Option<FormRecipe> {
        if !recipe_id.is_empty() {
            return recall::get_recipe_in(&self.local_recall, recipe_id).or_else(|| {
                self.recipes
                    .iter()
                    .find(|r| r.recipe_id == recipe_id)
                    .cloned()
            });
        }
        recall::find_matching_recipe_in(
            &self.local_recall,
            &snapshot.url,
            snapshot.form_signature.as_deref(),
        )
        .or_else(|| {
            let origin = recall::origin_of(&snapshot.url);
            self.recipes
                .iter()
                .find(|r| {
                    r.origin == origin
                        && Some(r.form_signature.as_str()) == snapshot.form_signature.as_deref()
                })
                .cloned()
        })
    }
}

impl Drop for BlitzDenoAuthorityBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl CredentialSink for BlitzDenoAuthorityBackend {
    fn set_field(&mut self, field: CredentialFieldKind, value: &str) -> Result<(), BrokerError> {
        let target_id = self
            .active_target_id
            .ok_or_else(|| BrokerError::NotFound("no active target for credential sink".into()))?;
        self.set_credential_field(target_id, field, value)
    }
}

impl WebPageBackend for BlitzDenoAuthorityBackend {
    fn open_target(&mut self, start_url: Option<&str>, _background: bool) -> Result<u64, String> {
        let target_id = self.next_target_id;
        self.next_target_id += 1;
        let rtid = format!("authority-target-{target_id}");
        let requested = start_url.unwrap_or("about:blank");
        let (final_url, html) = self.fetch_or_virtual_html(requested)?;
        self.render.navigate_html_sync(
            &rtid,
            &final_url,
            &html,
            VIEWPORT_WIDTH,
            VIEWPORT_HEIGHT,
        )?;
        self.io
            .spawn_worker(target_id, &rtid, &final_url, &self.v8_flags)?;
        self.targets.insert(
            target_id,
            TargetState {
                render_target_id: rtid,
                current_url: final_url.clone(),
                history: vec![final_url],
                history_index: 0,
                document_generation: 1,
                known_node_refs: HashSet::new(),
                frame_seq: 0,
            },
        );
        self.active_target_id = Some(target_id);
        Ok(target_id)
    }

    fn close_target(&mut self, target_id: u64) {
        if let Some(state) = self.targets.remove(&target_id) {
            self.render.remove_target_sync(&state.render_target_id);
            self.io.close_worker(target_id);
        }
        if self.active_target_id == Some(target_id) {
            self.active_target_id = self.targets.keys().next().copied();
        }
    }

    fn observe_target(&mut self, target_id: u64) -> Option<PageSnapshot> {
        let (rtid, fallback_url, doc_gen) = {
            let state = self.targets.get(&target_id)?;
            (
                state.render_target_id.clone(),
                state.current_url.clone(),
                state.document_generation,
            )
        };
        let (native, focus_id) = self
            .render
            .with_doc_sync(&rtid, |doc, _| {
                let snap = doc.capture_dom_snapshot();
                let focus = doc.get_focused_node_id();
                Ok((snap, (focus > 0).then_some(focus as u64)))
            })
            .ok()?;
        let raw_root = native
            .root
            .map(|n| convert_dom_node(&n))
            .unwrap_or_default();
        let url = if native.base_url.is_empty() {
            fallback_url
        } else {
            native.base_url
        };
        let snapshot_id = self.next_snapshot_id;
        self.next_snapshot_id += 1;
        let mut snap = build_snapshot(
            &raw_root,
            focus_id,
            ScrollSnapshot {
                x: native.scroll.0,
                y: native.scroll.1,
                height: native.scroll_height,
            },
            SnapshotMetadata {
                snapshot_id,
                tab_id: target_id,
                page_id: target_id,
                document_generation: doc_gen,
                url,
                title: native.title,
                viewport_width: native.viewport.0 as f32,
                viewport_height: native.viewport.1 as f32,
                scale: 1.0,
            },
        );
        snap.form_signature = recall::compute_form_signature(&snap.elements);
        snap.matched_recipe_id = recall::find_matching_recipe_in(
            &self.local_recall,
            &snap.url,
            snap.form_signature.as_deref(),
        )
        .map(|r| r.recipe_id);
        if let Some(state) = self.targets.get_mut(&target_id) {
            state.known_node_refs = snap.elements.iter().map(|e| e.node_ref.clone()).collect();
        }
        Some(snap)
    }

    fn known_node_refs(&self, target_id: u64) -> HashSet<String> {
        self.targets
            .get(&target_id)
            .map(|s| s.known_node_refs.clone())
            .unwrap_or_default()
    }

    fn can_go_back(&self, target_id: u64) -> bool {
        self.targets
            .get(&target_id)
            .is_some_and(|s| s.history_index > 0)
    }

    fn can_go_forward(&self, target_id: u64) -> bool {
        self.targets
            .get(&target_id)
            .is_some_and(|s| s.history_index + 1 < s.history.len())
    }

    fn check_interactable(
        &self,
        target_id: u64,
        element: &ElementSnapshot,
    ) -> Result<(), &'static str> {
        if !element.enabled {
            return Err("target_disabled");
        }
        if !element.visible || element.bounds.width <= 0.0 || element.bounds.height <= 0.0 {
            return Err("target_not_visible");
        }
        let state = self.targets.get(&target_id).ok_or("target_missing")?;
        let dom_id = parse_element_dom_id(element).map_err(|_| "target_missing")?;
        let cx = element.bounds.x + element.bounds.width / 2.0;
        let cy = element.bounds.y + element.bounds.height / 2.0;
        let ok = self
            .render
            .with_doc_sync(&state.render_target_id, move |doc, _| {
                let (sx, sy) = doc.page_scroll();
                let hit = doc.element_from_point((cx + sx) as f32, (cy + sy) as f32);
                Ok(hit > 0 && doc.is_inclusive_ancestor(dom_id, hit as u32))
            })
            .map_err(|_| "internal")?;
        if !ok {
            return Err("element_obscured");
        }
        Ok(())
    }

    fn dispatch_command(
        &mut self,
        target_id: u64,
        command: &PageCommand,
        snapshot: &PageSnapshot,
    ) -> Result<(), String> {
        self.active_target_id = Some(target_id);
        let rtid = self
            .targets
            .get(&target_id)
            .ok_or_else(|| format!("unknown target {target_id}"))?
            .render_target_id
            .clone();
        match command {
            PageCommand::Click {
                target_id: tid,
                target_ref,
            } => {
                let el = resolve_element(snapshot, Some(tid.as_str()), target_ref.as_deref())?;
                let dom_id = parse_element_dom_id(el)?;
                let outcome = self
                    .render
                    .with_doc_sync(&rtid, move |doc, _| doc.click_element(dom_id))?;
                match outcome {
                    NativeClickOutcome::Navigate(href) => {
                        let next_url = resolve_submission_url(&snapshot.url, &href)?;
                        self.navigate_internal(target_id, &next_url, true)?;
                    }
                    NativeClickOutcome::SubmitForm(trigger) => {
                        self.execute_submit(target_id, trigger)?;
                    }
                    _ => {
                        let _ = self
                            .io
                            .sync_action(target_id, json!({"action": "click", "target": el.id}));
                    }
                }
                Ok(())
            }
            PageCommand::Type {
                target_id: tid,
                target_ref,
                text,
            } => {
                let el = resolve_element(snapshot, Some(tid.as_str()), target_ref.as_deref())?;
                let dom_id = parse_element_dom_id(el)?;
                let entered = text.clone();
                self.render.with_doc_sync(&rtid, move |doc, _| {
                    if doc.set_input_text(dom_id, &entered) {
                        doc.set_focus(dom_id);
                        Ok(())
                    } else {
                        Err(format!("set_input_text failed on {dom_id}"))
                    }
                })?;
                let _ = self
                    .io
                    .sync_action(target_id, json!({"action": "type", "target": el.id}));
                Ok(())
            }
            PageCommand::Select {
                target_id: tid,
                target_ref,
                value,
            } => {
                let el = resolve_element(snapshot, Some(tid.as_str()), target_ref.as_deref())?;
                let dom_id = parse_element_dom_id(el)?;
                let opt = value.clone();
                self.render.with_doc_sync(&rtid, move |doc, _| {
                    doc.select_option(dom_id, &opt).map(|_| ())
                })?;
                let _ = self.io.sync_action(
                    target_id,
                    json!({"action": "select", "target": el.id, "value": value}),
                );
                Ok(())
            }
            PageCommand::FillForm { fields } => {
                if let Some(ref sig) = snapshot.form_signature {
                    recall::record_recipe_in(
                        &mut self.local_recall,
                        &snapshot.url,
                        sig,
                        fields,
                        snapshot,
                    );
                }
                for field in fields {
                    self.apply_form_field(target_id, snapshot, field)?;
                }
                let _ = self
                    .io
                    .sync_action(target_id, json!({"action": "fill_form"}));
                Ok(())
            }
            PageCommand::ReplayRecipe { recipe_id } => {
                self.apply_recipe_fields(target_id, snapshot, recipe_id)
            }
            PageCommand::Submit {
                target_id: tid,
                target_ref,
            } => {
                let dom_id = resolve_element(snapshot, Some(tid.as_str()), target_ref.as_deref())
                    .ok()
                    .and_then(|e| parse_element_dom_id(e).ok());
                self.execute_submit(target_id, dom_id)
            }
            PageCommand::Scroll { dy } => {
                let delta = *dy;
                self.render.with_doc_sync(&rtid, move |doc, _| {
                    let (sx, sy) = doc.page_scroll();
                    let next_y = (sy + delta).max(0.0);
                    doc.set_page_scroll(sx, next_y);
                    Ok(())
                })?;
                let _ = self
                    .io
                    .sync_action(target_id, json!({"action": "scroll", "dy": delta}));
                Ok(())
            }
            PageCommand::Navigate { url } => self.navigate_internal(target_id, url, true),
            PageCommand::Back => {
                let url = {
                    let st = self
                        .targets
                        .get_mut(&target_id)
                        .ok_or_else(|| "unknown target".to_string())?;
                    if st.history_index == 0 {
                        return Err("cannot go back".to_string());
                    }
                    st.history_index -= 1;
                    st.history[st.history_index].clone()
                };
                self.navigate_internal(target_id, &url, false)
            }
            PageCommand::Forward => {
                let url = {
                    let st = self
                        .targets
                        .get_mut(&target_id)
                        .ok_or_else(|| "unknown target".to_string())?;
                    if st.history_index + 1 >= st.history.len() {
                        return Err("cannot go forward".to_string());
                    }
                    st.history_index += 1;
                    st.history[st.history_index].clone()
                };
                self.navigate_internal(target_id, &url, false)
            }
            PageCommand::Reload => {
                let url = self
                    .targets
                    .get(&target_id)
                    .map(|s| s.current_url.clone())
                    .ok_or_else(|| "unknown target".to_string())?;
                self.navigate_internal(target_id, &url, false)
            }
        }
    }

    fn set_credential_field(
        &mut self,
        target_id: u64,
        field: CredentialFieldKind,
        value: &str,
    ) -> Result<(), BrokerError> {
        let snap = self
            .observe_target(target_id)
            .ok_or_else(|| BrokerError::NotFound(format!("unknown target {target_id}")))?;
        let target_el = find_credential_target_element(&snap.elements, field).ok_or_else(|| {
            BrokerError::NotFound(format!("no DOM input matching {} field", field.as_str()))
        })?;
        let dom_id = parse_element_dom_id(target_el).map_err(BrokerError::NotFound)?;
        let rtid = self
            .targets
            .get(&target_id)
            .ok_or_else(|| BrokerError::NotFound(format!("unknown target {target_id}")))?
            .render_target_id
            .clone();
        let val = value.to_string();
        self.render
            .with_doc_sync(&rtid, move |doc, _| {
                if doc.set_input_text(dom_id, &val) {
                    doc.set_focus(dom_id);
                    Ok(())
                } else {
                    Err("set_input_text failed".to_string())
                }
            })
            .map_err(BrokerError::Storage)?;
        let _ = self.io.sync_action(
            target_id,
            json!({"action": "sealed_fill", "field": field.as_str()}),
        );
        Ok(())
    }

    fn capture_screenshot(&mut self, target_id: u64) -> Option<(Vec<u8>, String, u64)> {
        let state = self.targets.get_mut(&target_id)?;
        state.frame_seq += 1;
        let frame_id = state.frame_seq;
        let rtid = state.render_target_id.clone();
        let png = self
            .render
            .with_doc_sync(&rtid, |doc, _| doc.paint_png())
            .ok()?;
        let hash = sha256_hex(&png);
        Some((png, hash, frame_id))
    }
}

/// Host supervisor coordinating `SupervisionEngine`, `ControlHub`, Keychain brokers, and audit.
pub struct AuthoritySupervisor {
    pub engine: SupervisionEngine<BlitzDenoAuthorityBackend>,
    hub: Arc<ControlHub>,
    known_sessions: HashSet<String>,
    token_to_ceremony: HashMap<String, (String, String)>,
    outbox_history: Vec<(OutTarget, AuthValue)>,
    socket_server: Option<ControlServerHandle>,
    socket_rx: Option<mpsc::Receiver<ControlEvent>>,
}

impl AuthoritySupervisor {
    /// Creates an in-memory `AuthoritySupervisor` suitable for isolated or parallel tests.
    pub fn in_memory(backend: BlitzDenoAuthorityBackend) -> Self {
        let engine = SupervisionEngine::in_memory(backend);
        Self {
            engine,
            hub: Arc::new(ControlHub::new()),
            known_sessions: HashSet::new(),
            token_to_ceremony: HashMap::new(),
            outbox_history: Vec::new(),
            socket_server: None,
            socket_rx: None,
        }
    }

    /// Creates an `AuthoritySupervisor` wired to macOS Keychain stores with explicit service names.
    pub fn with_keychain(
        backend: BlitzDenoAuthorityBackend,
        password_service: &str,
        passkey_service: &str,
        passkey_account: &str,
    ) -> Self {
        let cred_broker = LocalCredentialBroker::with_stores(
            Box::new(KeychainPasswordStore::with_service(password_service)),
            Box::new(KeychainPasskeyStore::with_service(
                passkey_service,
                passkey_account,
            )),
        );
        let passkey_broker = LocalPasskeyBroker::with_store(Box::new(
            KeychainPasskeyStore::with_service(passkey_service, passkey_account),
        ));
        let engine = SupervisionEngine::with_components(
            backend,
            cred_broker,
            passkey_broker,
            RecallStore::default(),
            AuditLog::new(),
        );
        Self {
            engine,
            hub: Arc::new(ControlHub::new()),
            known_sessions: HashSet::new(),
            token_to_ceremony: HashMap::new(),
            outbox_history: Vec::new(),
            socket_server: None,
            socket_rx: None,
        }
    }

    /// Returns a clone of the shared `ControlHub`.
    pub fn hub(&self) -> Arc<ControlHub> {
        Arc::clone(&self.hub)
    }

    /// Starts the `0600` Unix control socket separating `Role::Host` and `Role::Agent`.
    pub fn start_socket_server(&mut self, config: ControlServerConfig) -> std::io::Result<&Path> {
        let (tx, rx) = mpsc::channel();
        let handle = control::spawn_server(config, tx, Arc::clone(&self.hub))?;
        self.socket_server = Some(handle);
        self.socket_rx = Some(rx);
        Ok(self.socket_server.as_ref().expect("just set").socket_path())
    }

    /// Pumps all queued socket `ControlEvent`s without blocking.
    pub fn pump_socket_events(&mut self) -> usize {
        let mut drained = Vec::new();
        if let Some(ref rx) = self.socket_rx {
            while let Ok(ev) = rx.try_recv() {
                drained.push(ev);
            }
        }
        let count = drained.len();
        for ev in drained {
            self.process_event(ev);
        }
        count
    }

    /// Processes a single `ControlEvent`, handles `$cred:` origin binding, and flushes outbox.
    pub fn process_event(&mut self, event: ControlEvent) {
        let recipes = self.engine.recall_store_mut().recipes.clone();
        self.engine.backend_mut().sync_recall_recipes(&recipes);
        if let ControlEvent::Message { ref frame, .. } = event {
            self.maybe_prepare_tokenized_submit_from_frame(frame);
        }
        self.engine.handle_event(event);
        self.flush_outbox();
        self.recover_orphaned_decisions();
        self.flush_outbox();
    }

    /// Executes `SupervisionEngine::decide` while syncing recall recipes and `$cred:` tokens.
    pub fn decide(&mut self, input: DecisionInput<'_>) -> Result<(), &'static str> {
        let recipes = self.engine.recall_store_mut().recipes.clone();
        self.engine.backend_mut().sync_recall_recipes(&recipes);
        if input.approve {
            let _ = self.prepare_tokenized_submit_for_proposal(input.session_id, input.proposal_id);
        }
        let res = self.engine.decide(input);
        self.flush_outbox();
        self.recover_orphaned_decisions();
        self.flush_outbox();
        res
    }

    /// Redeems a `$cred:<token>` substitution table for an outbound submission, enforcing origin.
    pub fn resolve_tokenized_submission(
        &mut self,
        ceremony_id: &str,
        target_url: &str,
        fields: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String> {
        let origin = recall::origin_of(target_url);
        let spec = self
            .engine
            .take_tokenized_spec(ceremony_id, &origin)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(fields.len());
        for (name, val) in fields {
            if !val.starts_with("$cred:") {
                out.push((name.clone(), val.clone()));
                continue;
            }
            if spec.username_token.as_deref() == Some(val.as_str()) {
                let u = spec
                    .username_value
                    .as_ref()
                    .ok_or("missing username")?
                    .clone();
                out.push((name.clone(), u));
            } else if spec.secret_token.as_deref() == Some(val.as_str()) {
                let s = spec.secret_value.as_ref().ok_or("missing secret")?.clone();
                out.push((name.clone(), s));
            } else {
                return Err(format!("unknown token '{val}' for ceremony {ceremony_id}"));
            }
        }
        Ok(out)
    }

    /// Returns recorded outbox frames delivered by this supervisor.
    pub fn outbox_history(&self) -> &[(OutTarget, AuthValue)] {
        &self.outbox_history
    }

    /// Stops any active Unix socket server cleanly.
    pub fn stop_socket_server(&mut self) {
        if let Some(handle) = self.socket_server.take() {
            handle.shutdown();
        }
        self.socket_rx = None;
    }

    fn flush_outbox(&mut self) {
        for (target, frame) in self.engine.drain_outbox() {
            self.record_outbox_metadata(&frame);
            self.outbox_history.push((target, frame.clone()));
            let recipients = match target {
                OutTarget::Conn(id) => vec![id],
                OutTarget::Host => self.hub.broadcast_ids(Some(Role::Host)),
                OutTarget::Agent => self.hub.broadcast_ids(Some(Role::Agent)),
                OutTarget::Both => self.hub.broadcast_ids(None),
            };
            for conn_id in recipients {
                self.hub.send(conn_id, &frame);
            }
        }
    }

    fn recover_orphaned_decisions(&mut self) {
        let orphaned: Vec<String> = self
            .known_sessions
            .iter()
            .filter(|sid| {
                self.engine.session(sid).is_some_and(|s| {
                    s.state == ControlState::AwaitingDecision && s.pending.is_none()
                })
            })
            .cloned()
            .collect();
        for sid in orphaned {
            let _ = self.engine.control_take(&sid, "host_recovery", "authority");
            let _ = self
                .engine
                .control_release(&sid, "host_recovery", "authority");
        }
    }

    fn record_outbox_metadata(&mut self, frame: &AuthValue) {
        match frame.get("type").and_then(AuthValue::as_str) {
            Some("session.opened") => {
                if let Some(sid) = frame.get("session_id").and_then(AuthValue::as_str) {
                    self.known_sessions.insert(sid.to_string());
                }
            }
            Some("session.closed") => {
                if let Some(sid) = frame.get("session_id").and_then(AuthValue::as_str) {
                    self.known_sessions.remove(sid);
                }
            }
            Some("credential.filled") => self.record_credential_tokens(frame),
            _ => {}
        }
    }

    fn record_credential_tokens(&mut self, frame: &AuthValue) {
        let Some(proposal_id) = frame.get("proposal_id").and_then(AuthValue::as_str) else {
            return;
        };
        let origin = frame
            .get("origin")
            .and_then(AuthValue::as_str)
            .unwrap_or("")
            .to_string();
        let Some(tokens) = frame.get("field_tokens").and_then(AuthValue::as_object) else {
            return;
        };
        for val in tokens.values() {
            if let Some(tok) = val.as_str() {
                self.token_to_ceremony
                    .insert(tok.to_string(), (proposal_id.to_string(), origin.clone()));
            }
        }
    }

    fn maybe_prepare_tokenized_submit_from_frame(&mut self, frame: &AuthValue) {
        if frame.get("type").and_then(AuthValue::as_str) != Some("decision") {
            return;
        }
        if frame.get("decision").and_then(AuthValue::as_str) != Some("approve") {
            return;
        }
        let (Some(sid), Some(pid)) = (
            frame.get("session_id").and_then(AuthValue::as_str),
            frame.get("proposal_id").and_then(AuthValue::as_str),
        ) else {
            return;
        };
        let _ = self.prepare_tokenized_submit_for_proposal(sid, pid);
    }

    fn prepare_tokenized_submit_for_proposal(
        &mut self,
        session_id: &str,
        proposal_id: &str,
    ) -> Result<(), String> {
        let (target_id, op_opt) = {
            let Some(sess) = self.engine.session(session_id) else {
                return Ok(());
            };
            let op = sess
                .pending
                .as_ref()
                .filter(|p| p.proposal_id == proposal_id)
                .map(|p| p.operation.clone());
            (sess.target_id, op)
        };
        let Some(op) = op_opt else {
            return Ok(());
        };
        let Some(cmd) = PageCommand::from_operation(&op) else {
            return Ok(());
        };
        let trigger_node = match &cmd {
            PageCommand::Submit {
                target_id: tid,
                target_ref,
            } => self
                .engine
                .session(session_id)
                .and_then(|s| s.last_snapshot.as_ref())
                .and_then(|snap| {
                    resolve_element(snap, Some(tid.as_str()), target_ref.as_deref()).ok()
                })
                .and_then(|e| parse_element_dom_id(e).ok()),
            _ => return Ok(()),
        };
        let sub = self
            .engine
            .backend()
            .inspect_form_submission(target_id, trigger_node)?;
        let mut seen_ceremonies = HashSet::new();
        for (_, val) in &sub.fields {
            if !val.starts_with("$cred:") {
                continue;
            }
            if let Some((cid, _)) = self.token_to_ceremony.get(val) {
                seen_ceremonies.insert(cid.clone());
            }
        }
        for cid in seen_ceremonies {
            let spec = self
                .engine
                .take_tokenized_spec(&cid, &sub.origin)
                .map_err(|e| e.to_string())?;
            self.engine.backend_mut().stage_tokenized_spec(spec);
        }
        Ok(())
    }
}

impl Drop for AuthoritySupervisor {
    fn drop(&mut self) {
        self.stop_socket_server();
        self.engine.backend_mut().shutdown();
    }
}

/// Active Unix-domain control socket server plus background event-dispatch pump thread.
pub struct AuthoritySocketDaemon {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    server: Option<ControlServerHandle>,
    pump_thread: Option<JoinHandle<()>>,
}

impl AuthoritySocketDaemon {
    /// Binds a `0600` Unix-domain NDJSON control socket and pumps events into `supervisor`.
    pub fn spawn(
        supervisor: Arc<Mutex<AuthoritySupervisor>>,
        config: ControlServerConfig,
    ) -> std::io::Result<Self> {
        let hub = supervisor
            .lock()
            .map_err(|_| std::io::Error::other("lock poisoned"))?
            .hub();
        let (tx, rx) = mpsc::channel();
        let server = control::spawn_server(config, tx, hub)?;
        let socket_path = server.socket_path().to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let pump_thread = std::thread::Builder::new()
            .name("parawing-authority-pump".to_string())
            .spawn(move || pump_socket_loop(rx, &supervisor, &stop_flag))
            .map_err(std::io::Error::other)?;
        Ok(Self {
            socket_path,
            stop,
            server: Some(server),
            pump_thread: Some(pump_thread),
        })
    }

    /// Returns the filesystem path of the bound `0600` Unix socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Stops the socket server and joins the background pump thread.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(srv) = self.server.take() {
            srv.shutdown();
        }
        if let Some(handle) = self.pump_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for AuthoritySocketDaemon {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn pump_socket_loop(
    rx: mpsc::Receiver<ControlEvent>,
    supervisor: &Arc<Mutex<AuthoritySupervisor>>,
    stop: &AtomicBool,
) {
    while !stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(ev) => {
                if let Ok(mut guard) = supervisor.lock() {
                    guard.process_event(ev);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn convert_dom_node(n: &NativeDomNode) -> RawDomNode {
    let mut attributes = HashMap::with_capacity(n.attributes.len());
    for (k, v) in &n.attributes {
        attributes.insert(k.to_ascii_lowercase(), v.clone());
    }
    RawDomNode {
        node_id: u64::from(n.node_id),
        tag: n.tag.clone(),
        text: n.text.clone().unwrap_or_default(),
        attributes,
        live_value: n.live_value.clone(),
        live_checked: n.live_checked,
        focussable: n.focussable,
        cursor_pointer: n.cursor_pointer,
        display: n.display.clone(),
        visibility: n.visibility.clone(),
        opacity: n.opacity.clone(),
        bounds: n.bounds.map(|[x, y, width, height]| Bounds {
            x,
            y,
            width,
            height,
        }),
        children: n.children.iter().map(convert_dom_node).collect(),
    }
}

fn resolve_element<'a>(
    snapshot: &'a PageSnapshot,
    target_id: Option<&str>,
    target_ref: Option<&str>,
) -> Result<&'a ElementSnapshot, String> {
    snapshot
        .elements
        .iter()
        .find(|e| {
            target_ref.is_some_and(|r| e.node_ref == r)
                || target_id.is_some_and(|id| e.id == id || e.node_ref == id)
        })
        .ok_or_else(|| {
            format!("target element not found (target_id={target_id:?}, target_ref={target_ref:?})")
        })
}

fn parse_element_dom_id(el: &ElementSnapshot) -> Result<u32, String> {
    if el.node_id > 0 {
        return Ok(el.node_id as u32);
    }
    if let Some((_, rhs)) = el.node_ref.split_once('_') {
        if let Ok(parsed) = rhs.parse::<u32>() {
            return Ok(parsed);
        }
    }
    Err(format!("invalid node_ref '{}'", el.node_ref))
}

fn resolve_submission_url(base: &str, action: &str) -> Result<String, String> {
    let trimmed = action.trim();
    if trimmed.is_empty() {
        return Ok(base.to_string());
    }
    let parsed_base = Url::parse(base).map_err(|e| format!("base url '{base}': {e}"))?;
    parsed_base
        .join(trimmed)
        .map(|u| u.to_string())
        .map_err(|e| format!("resolve action '{trimmed}' against '{base}': {e}"))
}

fn check_spec_origin(
    spec: &TokenizedSubstitutionSpec,
    target_origin: &str,
    idx: usize,
    value: Option<&str>,
) -> Result<(usize, String), String> {
    if !spec.origin.eq_ignore_ascii_case(target_origin) {
        return Err(format!(
            "tokenized credential bound to '{}' rejected cross-origin target '{target_origin}'",
            spec.origin
        ));
    }
    let secret = value.ok_or_else(|| {
        format!(
            "missing substituted value for bound origin '{}'",
            spec.origin
        )
    })?;
    Ok((idx, secret.to_string()))
}

fn find_credential_target_element(
    elements: &[ElementSnapshot],
    field: CredentialFieldKind,
) -> Option<&ElementSnapshot> {
    match field {
        CredentialFieldKind::CurrentPassword | CredentialFieldKind::NewPassword => elements
            .iter()
            .find(|e| e.tag == "input" && e.input_type.as_deref() == Some("password"))
            .or_else(|| {
                elements.iter().find(|e| {
                    e.tag == "input"
                        && (e.value_state == ValueState::Sensitive
                            || e.label.to_ascii_lowercase().contains("password"))
                })
            }),
        CredentialFieldKind::OneTimeCode => elements.iter().find(|e| {
            e.tag == "input" && matches_field_hint(e, &["otp", "one-time", "totp", "code"])
        }),
        CredentialFieldKind::Username => elements
            .iter()
            .find(|e| {
                e.tag == "input"
                    && is_username_like_type(e.input_type.as_deref())
                    && matches_field_hint(e, &["user", "email", "login", "account", "name"])
            })
            .or_else(|| {
                elements
                    .iter()
                    .find(|e| e.tag == "input" && is_username_like_type(e.input_type.as_deref()))
            }),
        CredentialFieldKind::PaymentCard => elements.iter().find(|e| {
            e.tag == "input" && matches_field_hint(e, &["card", "cc-", "pan", "cvv", "cvc", "exp"])
        }),
        CredentialFieldKind::OtherSensitive => elements
            .iter()
            .find(|e| e.tag == "input" && e.value_state == ValueState::Sensitive)
            .or_else(|| {
                elements
                    .iter()
                    .find(|e| e.tag == "input" && is_username_like_type(e.input_type.as_deref()))
            }),
    }
}

fn is_username_like_type(ty: Option<&str>) -> bool {
    matches!(ty, None | Some("text" | "email" | "tel" | "search" | ""))
}

fn matches_field_hint(el: &ElementSnapshot, hints: &[&str]) -> bool {
    let hay = format!(
        "{} {} {} {}",
        el.name.as_deref().unwrap_or(""),
        el.dom_id.as_deref().unwrap_or(""),
        el.label,
        el.placeholder.as_deref().unwrap_or(""),
    )
    .to_ascii_lowercase();
    hints.iter().any(|h| hay.contains(h))
}

fn match_recipe_field<'a>(
    snapshot: &'a PageSnapshot,
    rf: &RecipeField,
) -> Option<&'a ElementSnapshot> {
    if let Some(ref dom_id) = rf.dom_id {
        if let Some(el) = snapshot
            .elements
            .iter()
            .find(|e| e.dom_id.as_deref() == Some(dom_id.as_str()))
        {
            return Some(el);
        }
    }
    if let Some(ref name) = rf.name {
        if let Some(el) = snapshot
            .elements
            .iter()
            .find(|e| e.name.as_deref() == Some(name.as_str()))
        {
            return Some(el);
        }
    }
    snapshot.elements.iter().find(|e| e.label == rf.label)
}

fn parse_truthy_check(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "on" | "yes" | "checked"
    )
}

fn normalize_nav_key(raw: &str) -> String {
    Url::parse(raw.trim())
        .map(|u| u.to_string())
        .unwrap_or_else(|_| raw.trim().to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use parawing_authority::control::{ControlEvent, ControlServerConfig, Role};
    use parawing_authority::serde_json::{self as auth_serde, json as auth_json, Value as AuthValue};
    use parawing_authority::supervision::{DecisionInput, WebPageBackend};
    use parawing_authority::webauthn::authdata::{AuthenticatorData, FLAG_AT, FLAG_UP, FLAG_UV};
    use parawing_authority::webauthn::b64::b64url_decode;
    use sha2::{Digest, Sha256};

    use crate::engine_host::{
        start_engine_host_with_authority, AuthorityHostConfig, EngineHostConfig, EngineHostHandle,
    };

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let n = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "parawing-auth-test-{prefix}-{}-{n}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { path: dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Clone)]
    struct RecordedHttpRequest {
        method: String,
        path: String,
        body: String,
    }

    #[derive(Clone)]
    struct TestHttpResponse {
        status: u16,
        body: String,
    }

    type HttpRouter = Arc<dyn Fn(&RecordedHttpRequest) -> TestHttpResponse + Send + Sync>;

    struct LoopbackHttpServer {
        addr: String,
        requests: Arc<Mutex<Vec<RecordedHttpRequest>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl LoopbackHttpServer {
        fn start<F>(handler: F) -> Self
        where
            F: Fn(&RecordedHttpRequest) -> TestHttpResponse + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
            listener
                .set_nonblocking(true)
                .expect("set nonblocking listener");
            let port = listener.local_addr().expect("local_addr").port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let router: HttpRouter = Arc::new(handler);
            let reqs_bg = Arc::clone(&requests);
            let stop_bg = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                serve_loop(listener, router, reqs_bg, stop_bg);
            });
            Self {
                addr: format!("http://127.0.0.1:{port}"),
                requests,
                stop,
                thread: Some(thread),
            }
        }

        fn origin(&self) -> &str {
            &self.addr
        }

        fn recorded(&self) -> Vec<RecordedHttpRequest> {
            self.requests.lock().expect("lock requests").clone()
        }
    }

    impl Drop for LoopbackHttpServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr.trim_start_matches("http://"));
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
        }
    }

    fn serve_loop(
        listener: TcpListener,
        router: HttpRouter,
        requests: Arc<Mutex<Vec<RecordedHttpRequest>>>,
        stop: Arc<AtomicBool>,
    ) {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => handle_http_conn(stream, &router, &requests),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    }

    fn handle_http_conn(
        mut stream: TcpStream,
        router: &HttpRouter,
        requests: &Mutex<Vec<RecordedHttpRequest>>,
    ) {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let Some(req) = read_http_request(&mut stream) else {
            return;
        };
        requests.lock().expect("lock recorded").push(req.clone());
        let resp = router(&req);
        let status_text = if resp.status == 200 { "OK" } else { "ERR" };
        let raw = format!(
            "HTTP/1.1 {} {status_text}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp.status,
            resp.body.len(),
            resp.body
        );
        let _ = stream.write_all(raw.as_bytes());
        let _ = stream.flush();
    }

    fn read_http_request(stream: &mut TcpStream) -> Option<RecordedHttpRequest> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        let header_end = loop {
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let mut lines = head.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let content_len = lines
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_len {
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&buf[header_end..header_end + content_len]).to_string();
        Some(RecordedHttpRequest { method, path, body })
    }

    struct SocketClient {
        reader: BufReader<UnixStream>,
        writer: UnixStream,
        seq: u64,
    }

    impl SocketClient {
        fn connect(path: &std::path::Path, role: &str, token: &str) -> Result<Self, AuthValue> {
            let deadline = Instant::now() + Duration::from_secs(3);
            let stream = loop {
                match UnixStream::connect(path) {
                    Ok(s) => break s,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(15));
                    }
                    Err(e) => panic!("connect socket {}: {e}", path.display()),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set socket timeout");
            let writer = stream.try_clone().expect("clone unix stream");
            let mut client = Self {
                reader: BufReader::new(stream),
                writer,
                seq: 0,
            };
            let hello = auth_json!({
                "type": "hello",
                "id": format!("h-{role}"),
                "protocol_version": 1,
                "role": role,
                "token": token,
            });
            client.write_raw(&hello);
            let reply = client.read_frame();
            if reply.get("type").and_then(AuthValue::as_str) == Some("hello.ok") {
                Ok(client)
            } else {
                Err(reply)
            }
        }

        fn send(&mut self, mut frame: AuthValue) {
            self.seq += 1;
            frame["seq"] = auth_json!(self.seq);
            self.write_raw(&frame);
        }

        fn write_raw(&mut self, frame: &AuthValue) {
            let line = format!("{}\n", auth_serde::to_string(frame).expect("json frame"));
            self.writer
                .write_all(line.as_bytes())
                .expect("write unix frame");
            self.writer.flush().expect("flush unix frame");
        }

        fn read_frame(&mut self) -> AuthValue {
            let mut line = String::new();
            self.reader
                .read_line(&mut line)
                .expect("read line from socket");
            assert!(!line.is_empty(), "socket closed unexpectedly");
            auth_serde::from_str(&line).expect("parse NDJSON frame")
        }

        fn recv_type(&mut self, expected: &str) -> AuthValue {
            let deadline = Instant::now() + Duration::from_secs(6);
            loop {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for '{expected}'"
                );
                let frame = self.read_frame();
                if frame.get("type").and_then(AuthValue::as_str) == Some(expected) {
                    return frame;
                }
            }
        }

        fn recv_matching<F>(&mut self, expected: &str, pred: F) -> AuthValue
        where
            F: Fn(&AuthValue) -> bool,
        {
            let deadline = Instant::now() + Duration::from_secs(6);
            loop {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for '{expected}' predicate"
                );
                let frame = self.read_frame();
                if frame.get("type").and_then(AuthValue::as_str) == Some(expected) && pred(&frame) {
                    return frame;
                }
            }
        }
    }

    async fn start_host_with_socket(
        dir: &TempDir,
        host_token: &str,
        agent_token: &str,
    ) -> (EngineHostHandle, PathBuf) {
        let sock_path = dir.path.join("authority.sock");
        let auth_cfg = AuthorityHostConfig {
            use_keychain: false,
            control_socket: Some(ControlServerConfig {
                socket_path: sock_path.clone(),
                host_token: host_token.to_string(),
                agent_token: agent_token.to_string(),
                engine_name: "parawing-test".to_string(),
                engine_version: "0.1.0".to_string(),
            }),
            ..AuthorityHostConfig::default()
        };
        let host = start_engine_host_with_authority(
            EngineHostConfig {
                bind_addr: "127.0.0.1:0".to_string(),
                ..EngineHostConfig::default()
            },
            auth_cfg,
        )
        .await
        .expect("start engine host with authority");
        (host, sock_path)
    }

    fn run_in_memory_event(
        host: &EngineHostHandle,
        conn_id: u64,
        frame: AuthValue,
    ) -> Vec<AuthValue> {
        let arc = host.authority();
        let mut sup = arc.lock().expect("lock supervisor");
        let start = sup.outbox_history().len();
        sup.process_event(ControlEvent::Message { conn_id, frame });
        sup.outbox_history()[start..]
            .iter()
            .map(|(_, f)| f.clone())
            .collect()
    }

    fn find_frame(frames: &[AuthValue], kind: &str) -> Option<AuthValue> {
        frames
            .iter()
            .find(|f| f.get("type").and_then(AuthValue::as_str) == Some(kind))
            .cloned()
    }

    fn element_id_by_dom_id(obs: &AuthValue, dom_id: &str) -> String {
        obs["elements"]
            .as_array()
            .expect("elements array")
            .iter()
            .find(|e| e.get("dom_id").and_then(AuthValue::as_str) == Some(dom_id))
            .and_then(|e| e.get("id").and_then(AuthValue::as_str))
            .unwrap_or_else(|| panic!("missing element dom_id={dom_id} in obs"))
            .to_string()
    }

    fn dom_numeric_id(obs: &AuthValue, dom_id: &str) -> u32 {
        let node_ref = obs["elements"]
            .as_array()
            .expect("elements")
            .iter()
            .find(|e| e.get("dom_id").and_then(AuthValue::as_str) == Some(dom_id))
            .and_then(|e| e.get("node_ref").and_then(AuthValue::as_str))
            .expect("node_ref");
        node_ref
            .split_once('_')
            .and_then(|(_, n)| n.parse::<u32>().ok())
            .expect("numeric node_id")
    }

    fn register_in_memory_conns(host: &EngineHostHandle) {
        let arc = host.authority();
        let mut sup = arc.lock().expect("lock sup");
        sup.process_event(ControlEvent::Connect {
            conn_id: 1,
            role: Role::Host,
        });
        sup.process_event(ControlEvent::Connect {
            conn_id: 2,
            role: Role::Agent,
        });
    }

    fn decode_cbor_uint_arg(bytes: &[u8], pos: &mut usize) -> Option<(u8, u64)> {
        let head = *bytes.get(*pos)?;
        *pos += 1;
        let major = head >> 5;
        let ai = head & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(*bytes.get(*pos)?);
                *pos += 1;
                v
            }
            25 => {
                let slice: [u8; 2] = bytes.get(*pos..*pos + 2)?.try_into().ok()?;
                *pos += 2;
                u64::from(u16::from_be_bytes(slice))
            }
            26 => {
                let slice: [u8; 4] = bytes.get(*pos..*pos + 4)?.try_into().ok()?;
                *pos += 4;
                u64::from(u32::from_be_bytes(slice))
            }
            _ => return None,
        };
        Some((major, arg))
    }

    fn skip_cbor_item(bytes: &[u8], pos: &mut usize) -> Option<()> {
        let (major, arg) = decode_cbor_uint_arg(bytes, pos)?;
        match major {
            0 | 1 | 7 => Some(()),
            2 | 3 => {
                *pos += arg as usize;
                (*pos <= bytes.len()).then_some(())
            }
            4 => {
                for _ in 0..arg {
                    skip_cbor_item(bytes, pos)?;
                }
                Some(())
            }
            5 => {
                for _ in 0..(arg * 2) {
                    skip_cbor_item(bytes, pos)?;
                }
                Some(())
            }
            _ => None,
        }
    }

    fn extract_attestation_auth_data(att_obj: &[u8]) -> Option<Vec<u8>> {
        let mut pos = 0;
        let (major, count) = decode_cbor_uint_arg(att_obj, &mut pos)?;
        if major != 5 {
            return None;
        }
        for _ in 0..count {
            let (km, klen) = decode_cbor_uint_arg(att_obj, &mut pos)?;
            if km != 3 {
                return None;
            }
            let key = std::str::from_utf8(att_obj.get(pos..pos + klen as usize)?).ok()?;
            pos += klen as usize;
            if key == "authData" {
                let (vm, vlen) = decode_cbor_uint_arg(att_obj, &mut pos)?;
                if vm != 2 {
                    return None;
                }
                return Some(att_obj.get(pos..pos + vlen as usize)?.to_vec());
            }
            skip_cbor_item(att_obj, &mut pos)?;
        }
        None
    }

    fn assert_url_form_kv(body: &str) -> HashMap<String, String> {
        url::form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn assert_es256_assertion(
        public_pem: &str,
        expected_rp_id: &str,
        expected_challenge: &str,
        assert_frame: &AuthValue,
    ) -> u32 {
        let resp = &assert_frame["status"]["Complete"]["Assertion"]["response"];
        let auth_b64 = resp["authenticatorData"].as_str().expect("authData b64");
        let client_b64 = resp["clientDataJSON"].as_str().expect("clientData b64");
        let sig_b64 = resp["signature"].as_str().expect("sig b64");
        let auth_bytes = b64url_decode(auth_b64).expect("decode authData");
        let client_bytes = b64url_decode(client_b64).expect("decode clientData");
        let sig_bytes = b64url_decode(sig_b64).expect("decode signature");
        assert!(auth_bytes.len() >= 37);
        assert_eq!(
            auth_bytes[..32],
            AuthenticatorData::rp_id_hash(expected_rp_id)
        );
        let flags = auth_bytes[32];
        assert_ne!(flags & FLAG_UP, 0, "UP flag must be set");
        assert_ne!(flags & FLAG_UV, 0, "UV flag must be set");
        let sign_count =
            u32::from_be_bytes(auth_bytes[33..37].try_into().expect("signCount bytes"));
        let client_json: AuthValue =
            auth_serde::from_slice(&client_bytes).expect("parse clientDataJSON");
        assert_eq!(client_json["challenge"], expected_challenge);
        let client_hash = Sha256::digest(&client_bytes);
        let mut signed = Vec::with_capacity(auth_bytes.len() + 32);
        signed.extend_from_slice(&auth_bytes);
        signed.extend_from_slice(&client_hash);
        let vk = VerifyingKey::from_public_key_pem(public_pem).expect("parse SPKI PEM");
        let sig = Signature::from_der(&sig_bytes).expect("parse DER ES256 sig");
        vk.verify(&signed, &sig)
            .expect("ES256 signature verification");
        sign_count
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_authority_unix_socket_handoff_and_stale_invalidation() {
        let server = LoopbackHttpServer::start(|req| {
            match req.path.as_str() {
            "/app" => TestHttpResponse {
                status: 200,
                body: r#"<!doctype html><html><head><title>Workspace</title></head><body>
                    <input id="note" name="note" type="text" value="init" style="display:block;width:240px;height:36px;">
                    <button id="btn" type="button" style="display:block;width:120px;height:36px;">Action</button>
                    <a id="next" href="/next" style="display:block;width:120px;height:36px;">Next</a>
                </body></html>"#
                    .to_string(),
            },
            "/next" => TestHttpResponse {
                status: 200,
                body: r#"<!doctype html><html><head><title>Next</title></head><body><main>arrived-next</main></body></html>"#
                    .to_string(),
            },
            _ => TestHttpResponse {
                status: 404,
                body: "not found".to_string(),
            },
        }
        });
        let dir = TempDir::new("sock-handoff");
        let (host, sock_path) = start_host_with_socket(&dir, "host-tok", "agent-tok").await;
        let mode = std::fs::metadata(&sock_path)
            .expect("sock metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "control socket must enforce 0600");

        let auth_arc = host.authority();
        let origin = server.origin().to_string();
        let sock_clone = sock_path.clone();
        let res = tokio::task::spawn_blocking(move || {
            let bad = SocketClient::connect(&sock_clone, "host", "wrong-token");
            assert_eq!(bad.err().expect("reject bad token")["code"], "wrong_channel");

            let mut host_cli = SocketClient::connect(&sock_clone, "host", "host-tok")
                .expect("host hello");
            let mut agent_cli = SocketClient::connect(&sock_clone, "agent", "agent-tok")
                .expect("agent hello");

            host_cli.send(auth_json!({
                "type": "session.open",
                "title": "Workspace",
                "start_url": format!("{origin}/app"),
                "policy": {"allow_local_network": true}
            }));
            let opened = host_cli.recv_type("session.opened");
            let sid = opened["session_id"].as_str().expect("sid").to_string();

            agent_cli.send(auth_json!({"type": "observe.request", "session_id": &sid}));
            let obs1 = agent_cli.recv_type("observe.result");
            let note_el = element_id_by_dom_id(&obs1, "note");
            let note_nid = dom_numeric_id(&obs1, "note");

            let target_id = {
                let mut sup = auth_arc.lock().expect("lock sup");
                let tid = sup.engine.session(&sid).expect("sess").target_id;
                assert!(sup.engine.backend().has_live_deno_worker(tid));
                let eval_v = sup
                    .engine
                    .backend()
                    .evaluate_js(tid, "3 + 4")
                    .expect("eval in restricted deno worker");
                assert_eq!(eval_v["ok"], serde_json::json!(true));
                assert_eq!(eval_v["value"], serde_json::json!(7));
                let (png, hash, fid1) = sup
                    .engine
                    .backend_mut()
                    .capture_screenshot(tid)
                    .expect("png screenshot");
                assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
                assert_eq!(hash.len(), 64);
                let (_, _, fid2) = sup
                    .engine
                    .backend_mut()
                    .capture_screenshot(tid)
                    .expect("second screenshot");
                assert!(fid2 > fid1);
                tid
            };

            agent_cli.send(auth_json!({
                "type": "propose",
                "session_id": &sid,
                "proposal_id": "p_stale",
                "snapshot_id": obs1["snapshot_id"],
                "fingerprint": obs1["fingerprint"],
                "generation": obs1["generation"],
                "operation": {"kind": "type", "target_id": &note_el, "text": "stale-attempt"},
                "rationale": "Type note before DOM drift"
            }));
            let _ = host_cli.recv_type("proposal.pending");

            {
                let sup = auth_arc.lock().expect("lock sup");
                let rtid = format!("authority-target-{target_id}");
                sup.engine
                    .backend()
                    .render_handle()
                    .with_doc_sync(&rtid, move |doc, _| {
                        assert!(doc.set_input_text(note_nid, "external-dom-drift"));
                        Ok(())
                    })
                    .expect("mutate blitz DOM");
            }

            host_cli.send(auth_json!({
                "type": "decision",
                "session_id": &sid,
                "proposal_id": "p_stale",
                "fingerprint": obs1["fingerprint"],
                "generation": obs1["generation"],
                "decision": "approve"
            }));
            let inv = agent_cli.recv_type("proposal.invalidated");
            assert_eq!(inv["reason"], "stale_fingerprint");
            assert_eq!(inv["proposal_id"], "p_stale");

            agent_cli.send(auth_json!({"type": "observe.request", "session_id": &sid}));
            let obs2 = agent_cli.recv_type("observe.result");
            assert_ne!(obs2["fingerprint"], obs1["fingerprint"]);
            let note_el2 = element_id_by_dom_id(&obs2, "note");
            agent_cli.send(auth_json!({
                "type": "propose",
                "session_id": &sid,
                "proposal_id": "p_fresh",
                "snapshot_id": obs2["snapshot_id"],
                "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"],
                "operation": {"kind": "type", "target_id": &note_el2, "text": "approved-note"},
                "rationale": "Update note with fresh snapshot"
            }));
            let _ = host_cli.recv_type("proposal.pending");
            host_cli.send(auth_json!({
                "type": "decision",
                "session_id": &sid,
                "proposal_id": "p_fresh",
                "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"],
                "decision": "approve"
            }));
            let _ = host_cli.recv_type("executed");

            {
                let sup = auth_arc.lock().expect("lock sup");
                let rtid = format!("authority-target-{target_id}");
                let val = sup
                    .engine
                    .backend()
                    .render_handle()
                    .with_doc_sync(&rtid, move |doc, _| {
                        Ok(doc.get_input_value(note_nid).unwrap_or_default())
                    })
                    .expect("read live input");
                assert_eq!(val, "approved-note");
            }

            host_cli.send(auth_json!({"type": "control.take", "session_id": &sid}));
            let _ = host_cli.recv_matching("state", |f| f["state"] == "human");

            agent_cli.send(auth_json!({
                "type": "propose",
                "session_id": &sid,
                "proposal_id": "p_blocked",
                "snapshot_id": obs2["snapshot_id"],
                "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"],
                "operation": {"kind": "type", "target_id": &note_el2, "text": "sneaky"},
                "rationale": "Should be refused while host holds control"
            }));
            let refused = agent_cli.recv_type("refused");
            assert_eq!(refused["reason"], "wrong_state");

            {
                let mut sup = auth_arc.lock().expect("lock sup");
                sup.engine
                    .backend_mut()
                    .load_html(
                        target_id,
                        &format!("{origin}/next"),
                        "<!doctype html><html><head><title>Next</title></head><body><main>human-nav</main></body></html>",
                    )
                    .expect("human navigation");
            }

            host_cli.send(auth_json!({"type": "control.release", "session_id": &sid}));
            let _ = host_cli.recv_matching("state", |f| f["state"] == "agent");

            agent_cli.send(auth_json!({"type": "observe.request", "session_id": &sid}));
            let obs3 = agent_cli.recv_type("observe.result");
            assert_eq!(obs3["url"], format!("{origin}/next"));
        })
        .await;
        res.expect("blocking socket handoff test");
        assert_eq!(host.audit_verify_chain(), Ok(()));
        host.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_authority_webauthn_passkey_register_and_assert() {
        let host = start_engine_host_with_authority(
            EngineHostConfig {
                bind_addr: "127.0.0.1:0".to_string(),
                ..EngineHostConfig::default()
            },
            AuthorityHostConfig::default(),
        )
        .await
        .expect("start host");

        register_in_memory_conns(&host);
        {
            let arc = host.authority();
            let mut sup = arc.lock().expect("lock sup");
            sup.engine.backend_mut().register_virtual_page(
                "https://app.example/signin",
                r#"<!doctype html><html><head><title>Passkey</title></head><body>
                <button id="pk" style="display:block;width:140px;height:36px;">Sign In</button>
                </body></html>"#,
            );
        }

        let open_out = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "session.open", "seq": 1,
                "title": "Passkey", "start_url": "https://app.example/signin"
            }),
        );
        let sid = find_frame(&open_out, "session.opened").expect("opened")["session_id"]
            .as_str()
            .expect("sid")
            .to_string();

        let obs1_out = run_in_memory_event(
            &host,
            2,
            auth_json!({"type": "observe.request", "seq": 1, "session_id": &sid}),
        );
        let obs1 = find_frame(&obs1_out, "observe.result").expect("obs1");

        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": 2, "session_id": &sid,
                "proposal_id": "p_reg",
                "snapshot_id": obs1["snapshot_id"],
                "fingerprint": obs1["fingerprint"],
                "generation": obs1["generation"],
                "operation": {
                    "kind": "passkey.register",
                    "origin": "https://app.example",
                    "challenge": "cmVnLWNoYWxsZW5nZS0x",
                    "rp": {"id": "app.example", "name": "Example RP"},
                    "user": {"id": "dXNlci1hZGE", "name": "ada@app.example", "displayName": "Ada"},
                    "pub_key_cred_params": [{"type": "public-key", "alg": -7}]
                },
                "rationale": "Register passkey"
            }),
        );
        let reg_frames = {
            let arc = host.authority();
            let mut sup = arc.lock().expect("lock sup");
            let start = sup.outbox_history().len();
            sup.decide(DecisionInput {
                session_id: &sid,
                proposal_id: "p_reg",
                fingerprint: obs1["fingerprint"].as_str().expect("fp"),
                generation: obs1["generation"].as_u64().expect("gen"),
                approve: true,
                decided_by: "user",
                surface: "host_ui",
            })
            .expect("approve passkey register");
            sup.outbox_history()[start..]
                .iter()
                .map(|(_, f)| f.clone())
                .collect::<Vec<_>>()
        };
        let reg_done = find_frame(&reg_frames, "passkey.completed").expect("passkey.completed");
        let reg_cred = &reg_done["status"]["Complete"]["Registration"];
        let cred_id_b64 = reg_cred["id"].as_str().expect("cred id").to_string();
        let att_b64 = reg_cred["response"]["attestationObject"]
            .as_str()
            .expect("attestationObject");
        let att_bytes = b64url_decode(att_b64).expect("decode attestation");
        let reg_auth_data =
            extract_attestation_auth_data(&att_bytes).expect("extract authData from attestation");
        assert!(reg_auth_data.len() > 37);
        assert_eq!(
            reg_auth_data[..32],
            AuthenticatorData::rp_id_hash("app.example")
        );
        assert_ne!(reg_auth_data[32] & FLAG_UP, 0);
        assert_ne!(reg_auth_data[32] & FLAG_UV, 0);
        assert_ne!(reg_auth_data[32] & FLAG_AT, 0);

        let cred_id_raw = b64url_decode(&cred_id_b64).expect("decode cred id");
        let public_pem = {
            let arc = host.authority();
            let mut sup = arc.lock().expect("lock sup");
            sup.engine
                .passkey_broker_mut()
                .public_key_pem(&cred_id_raw)
                .expect("lookup pubkey")
                .expect("stored pubkey PEM")
        };

        let obs2_out = run_in_memory_event(
            &host,
            2,
            auth_json!({"type": "observe.request", "seq": 3, "session_id": &sid}),
        );
        let obs2 = find_frame(&obs2_out, "observe.result").expect("obs2");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": 4, "session_id": &sid,
                "proposal_id": "p_assert_1",
                "snapshot_id": obs2["snapshot_id"],
                "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"],
                "operation": {
                    "kind": "passkey.assert",
                    "origin": "https://app.example",
                    "rp_id": "app.example",
                    "challenge": "YXNzZXJ0LTE",
                    "allow_credentials": [{"type": "public-key", "id": &cred_id_b64}]
                },
                "rationale": "First assertion"
            }),
        );
        let assert1_out = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": 2, "session_id": &sid,
                "proposal_id": "p_assert_1",
                "fingerprint": obs2["fingerprint"],
                "generation": obs2["generation"],
                "decision": "approve"
            }),
        );
        let a1 = find_frame(&assert1_out, "passkey.completed").expect("assert1");
        let sc1 = assert_es256_assertion(&public_pem, "app.example", "YXNzZXJ0LTE", &a1);

        let obs3_out = run_in_memory_event(
            &host,
            2,
            auth_json!({"type": "observe.request", "seq": 5, "session_id": &sid}),
        );
        let obs3 = find_frame(&obs3_out, "observe.result").expect("obs3");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": 6, "session_id": &sid,
                "proposal_id": "p_assert_2",
                "snapshot_id": obs3["snapshot_id"],
                "fingerprint": obs3["fingerprint"],
                "generation": obs3["generation"],
                "operation": {
                    "kind": "passkey.assert",
                    "origin": "https://app.example",
                    "rp_id": "app.example",
                    "challenge": "YXNzZXJ0LTI",
                    "allow_credentials": [{"type": "public-key", "id": &cred_id_b64}]
                },
                "rationale": "Second assertion for monotonic sign_count"
            }),
        );
        let assert2_out = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": 3, "session_id": &sid,
                "proposal_id": "p_assert_2",
                "fingerprint": obs3["fingerprint"],
                "generation": obs3["generation"],
                "decision": "approve"
            }),
        );
        let a2 = find_frame(&assert2_out, "passkey.completed").expect("assert2");
        let sc2 = assert_es256_assertion(&public_pem, "app.example", "YXNzZXJ0LTI", &a2);
        assert!(
            sc2 > sc1,
            "sign_count must be strictly monotonic ({sc2} > {sc1})"
        );
        assert_eq!(host.audit_verify_chain(), Ok(()));
        host.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_authority_tokenized_sealed_credentials_replay_and_audit() {
        let evil_server = LoopbackHttpServer::start(|_| TestHttpResponse {
            status: 200,
            body: "stolen".to_string(),
        });
        let evil_origin = evil_server.origin().to_string();
        let evil_action = format!("{evil_origin}/steal");
        let origin_server = LoopbackHttpServer::start(move |req| {
            match req.path.as_str() {
            "/login-bad" => TestHttpResponse {
                status: 200,
                body: format!(
                    r#"<!doctype html><html><head><title>Bad Form</title></head><body>
                    <form action="{evil_action}" method="POST">
                      <input id="user" name="username" type="text" style="display:block;width:220px;height:32px;">
                      <input id="pw" name="password" type="password" style="display:block;width:220px;height:32px;">
                      <button id="go" type="submit" style="display:block;width:120px;height:36px;">Submit</button>
                    </form></body></html>"#
                ),
            },
            "/login-ok" => TestHttpResponse {
                status: 200,
                body: r#"<!doctype html><html><head><title>Good Form</title></head><body>
                    <form action="/submit" method="POST">
                      <input id="user" name="username" type="text" style="display:block;width:220px;height:32px;">
                      <input id="pw" name="password" type="password" style="display:block;width:220px;height:32px;">
                      <button id="go" type="submit" style="display:block;width:120px;height:36px;">Submit</button>
                    </form>
                    <a id="home" href="/home" style="display:block;width:120px;height:36px;">Home</a>
                </body></html>"#
                    .to_string(),
            },
            "/submit" => TestHttpResponse {
                status: 200,
                body: "<!doctype html><html><head><title>Done</title></head><body><main>welcome</main></body></html>"
                    .to_string(),
            },
            "/home" => TestHttpResponse {
                status: 200,
                body: r#"<!doctype html><html><head><title>Prefs</title></head><body>
                    <form action="/save">
                      <input id="name" name="display_name" type="text" style="display:block;width:220px;height:32px;">
                      <select id="role" name="role" style="display:block;width:220px;height:32px;">
                        <option value="viewer">Viewer</option>
                        <option value="editor">Editor</option>
                      </select>
                      <input id="tos" name="tos" type="checkbox" style="display:block;width:24px;height:24px;">
                      <button id="save" type="submit" style="display:block;width:120px;height:36px;">Save</button>
                    </form></body></html>"#
                    .to_string(),
            },
            _ => TestHttpResponse {
                status: 404,
                body: "not found".to_string(),
            },
        }
        });
        let base_origin = origin_server.origin().to_string();
        let host = start_engine_host_with_authority(
            EngineHostConfig {
                bind_addr: "127.0.0.1:0".to_string(),
                ..EngineHostConfig::default()
            },
            AuthorityHostConfig::default(),
        )
        .await
        .expect("start host");
        register_in_memory_conns(&host);

        let open_out = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "session.open", "seq": 1,
                "title": "Login", "start_url": format!("{base_origin}/login-bad"),
                "policy": {"allow_local_network": true}
            }),
        );
        let sid = find_frame(&open_out, "session.opened").expect("opened")["session_id"]
            .as_str()
            .expect("sid")
            .to_string();

        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "credential.save", "seq": 2,
                "host": "127.0.0.1", "username": "ada@app.example", "secret": "s3cr3t-parawing-pw"
            }),
        );

        let mut agent_seq = 0u64;
        let mut host_seq = 2u64;
        let mut next_a = || {
            agent_seq += 1;
            agent_seq
        };
        let mut next_h = || {
            host_seq += 1;
            host_seq
        };

        let obs_bad = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_bad");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_tok_bad",
                "snapshot_id": obs_bad["snapshot_id"],
                "fingerprint": obs_bad["fingerprint"],
                "generation": obs_bad["generation"],
                "operation": {
                    "kind": "credential.fill",
                    "origin": &base_origin,
                    "fields": ["username", "current_password"],
                    "mode": "tokenized"
                },
                "rationale": "Request tokenized placeholders"
            }),
        );
        let fill_bad = find_frame(
            &run_in_memory_event(
                &host,
                1,
                auth_json!({
                    "type": "decision", "seq": next_h(), "session_id": &sid,
                    "proposal_id": "p_tok_bad",
                    "fingerprint": obs_bad["fingerprint"],
                    "generation": obs_bad["generation"],
                    "decision": "approve"
                }),
            ),
            "credential.filled",
        )
        .expect("credential.filled");
        let u_tok = fill_bad["field_tokens"]["username"]
            .as_str()
            .expect("u_tok")
            .to_string();
        let p_tok = fill_bad["field_tokens"]["current_password"]
            .as_str()
            .expect("p_tok")
            .to_string();
        assert!(u_tok.starts_with("$cred:"));
        assert!(p_tok.starts_with("$cred:"));
        assert!(!fill_bad.to_string().contains("s3cr3t-parawing-pw"));

        let user_nid = dom_numeric_id(&obs_bad, "user");
        let pw_nid = dom_numeric_id(&obs_bad, "pw");
        {
            let arc = host.authority();
            let sup = arc.lock().expect("lock sup");
            let tid = sup.engine.session(&sid).expect("sess").target_id;
            let rtid = format!("authority-target-{tid}");
            let u_tok_owned = u_tok.clone();
            let p_tok_owned = p_tok.clone();
            sup.engine
                .backend()
                .render_handle()
                .with_doc_sync(&rtid, move |doc, _| {
                    assert!(doc.set_input_text(user_nid, &u_tok_owned));
                    assert!(doc.set_input_text(pw_nid, &p_tok_owned));
                    Ok(())
                })
                .expect("write tokens");
        }
        let obs_after_tok = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_after_tok");
        let pw_snap = obs_after_tok["elements"]
            .as_array()
            .expect("elems")
            .iter()
            .find(|e| e["dom_id"] == "pw")
            .expect("pw element");
        assert_eq!(pw_snap["value_state"], "sensitive");
        assert!(pw_snap["value"].is_null());

        let go_el_fresh = element_id_by_dom_id(&obs_after_tok, "go");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_sub_bad",
                "snapshot_id": obs_after_tok["snapshot_id"],
                "fingerprint": obs_after_tok["fingerprint"],
                "generation": obs_after_tok["generation"],
                "operation": {"kind": "submit", "target_id": &go_el_fresh},
                "rationale": "Attempt cross-origin submit"
            }),
        );
        let sub_bad_out = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_sub_bad",
                "fingerprint": obs_after_tok["fingerprint"],
                "generation": obs_after_tok["generation"],
                "decision": "approve"
            }),
        );
        assert!(find_frame(&sub_bad_out, "refused").is_some());
        assert!(
            evil_server.recorded().is_empty(),
            "cross-origin server must receive 0 requests"
        );
        {
            let arc = host.authority();
            let mut sup = arc.lock().expect("lock sup");
            assert!(sup
                .engine
                .backend_mut()
                .take_last_submission_error()
                .is_some());
        }

        let obs_nav = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_nav");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_nav_ok",
                "snapshot_id": obs_nav["snapshot_id"],
                "fingerprint": obs_nav["fingerprint"],
                "generation": obs_nav["generation"],
                "operation": {"kind": "navigate", "url": format!("{base_origin}/login-ok")},
                "rationale": "Go to same-origin login form"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_nav_ok",
                "fingerprint": obs_nav["fingerprint"],
                "generation": obs_nav["generation"],
                "decision": "approve"
            }),
        );

        let obs_ok = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_ok");
        assert!(host
            .resolve_tokenized_submission(
                "missing-ceremony",
                &format!("{evil_origin}/steal"),
                &[("password".into(), "$cred:x".into())],
            )
            .is_err());

        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_tok_ok",
                "snapshot_id": obs_ok["snapshot_id"],
                "fingerprint": obs_ok["fingerprint"],
                "generation": obs_ok["generation"],
                "operation": {
                    "kind": "credential.fill",
                    "origin": &base_origin,
                    "fields": ["username", "current_password"],
                    "mode": "tokenized"
                },
                "rationale": "Tokenized fill for same-origin submit"
            }),
        );
        let fill_ok = find_frame(
            &run_in_memory_event(
                &host,
                1,
                auth_json!({
                    "type": "decision", "seq": next_h(), "session_id": &sid,
                    "proposal_id": "p_tok_ok",
                    "fingerprint": obs_ok["fingerprint"],
                    "generation": obs_ok["generation"],
                    "decision": "approve"
                }),
            ),
            "credential.filled",
        )
        .expect("fill_ok");
        let u_tok2 = fill_ok["field_tokens"]["username"]
            .as_str()
            .expect("u_tok2");
        let p_tok2 = fill_ok["field_tokens"]["current_password"]
            .as_str()
            .expect("p_tok2")
            .to_string();

        let user_el2 = element_id_by_dom_id(&obs_ok, "user");
        let pw_nid2 = dom_numeric_id(&obs_ok, "pw");
        let go_el2 = element_id_by_dom_id(&obs_ok, "go");
        let obs_pre_type = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_pre_type");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_type_tok_u",
                "snapshot_id": obs_pre_type["snapshot_id"],
                "fingerprint": obs_pre_type["fingerprint"],
                "generation": obs_pre_type["generation"],
                "operation": {"kind": "type", "target_id": &user_el2, "text": u_tok2},
                "rationale": "Place tokenized username"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_type_tok_u",
                "fingerprint": obs_pre_type["fingerprint"],
                "generation": obs_pre_type["generation"],
                "decision": "approve"
            }),
        );
        {
            let arc = host.authority();
            let sup = arc.lock().expect("lock sup");
            let tid = sup.engine.session(&sid).expect("sess").target_id;
            let rtid = format!("authority-target-{tid}");
            let p_tok2_owned = p_tok2.clone();
            sup.engine
                .backend()
                .render_handle()
                .with_doc_sync(&rtid, move |doc, _| {
                    assert!(doc.set_input_text(pw_nid2, &p_tok2_owned));
                    Ok(())
                })
                .expect("write pw token");
        }
        let obs_sub_ok = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_sub_ok");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_sub_ok",
                "snapshot_id": obs_sub_ok["snapshot_id"],
                "fingerprint": obs_sub_ok["fingerprint"],
                "generation": obs_sub_ok["generation"],
                "operation": {"kind": "submit", "target_id": &go_el2},
                "rationale": "Same-origin tokenized submit"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_sub_ok",
                "fingerprint": obs_sub_ok["fingerprint"],
                "generation": obs_sub_ok["generation"],
                "decision": "approve"
            }),
        );

        let recorded_ok = origin_server.recorded();
        let post_req = recorded_ok
            .iter()
            .find(|r| r.method == "POST" && r.path == "/submit")
            .expect("POST /submit received");
        let kv = assert_url_form_kv(&post_req.body);
        assert_eq!(
            kv.get("username").map(String::as_str),
            Some("ada@app.example")
        );
        assert_eq!(
            kv.get("password").map(String::as_str),
            Some("s3cr3t-parawing-pw")
        );
        {
            let arc = host.authority();
            let sup = arc.lock().expect("lock sup");
            assert!(sup
                .engine
                .backend()
                .submission_records()
                .iter()
                .any(|r| r.tokenized_substituted && r.status == 200));
            for (_, frame) in sup.outbox_history() {
                assert!(!frame.to_string().contains("s3cr3t-parawing-pw"));
            }
        }

        let obs_sealed_nav = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_sealed_nav");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_nav_sealed",
                "snapshot_id": obs_sealed_nav["snapshot_id"],
                "fingerprint": obs_sealed_nav["fingerprint"],
                "generation": obs_sealed_nav["generation"],
                "operation": {"kind": "navigate", "url": format!("{base_origin}/login-ok")},
                "rationale": "Navigate to login page for sealed fill"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_nav_sealed",
                "fingerprint": obs_sealed_nav["fingerprint"],
                "generation": obs_sealed_nav["generation"],
                "decision": "approve"
            }),
        );

        let obs_sealed = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_sealed");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_sealed",
                "snapshot_id": obs_sealed["snapshot_id"],
                "fingerprint": obs_sealed["fingerprint"],
                "generation": obs_sealed["generation"],
                "operation": {
                    "kind": "credential.fill",
                    "origin": &base_origin,
                    "fields": ["username", "current_password"],
                    "mode": "sealed"
                },
                "rationale": "Fill sealed credential into DOM"
            }),
        );
        let sealed_out = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_sealed",
                "fingerprint": obs_sealed["fingerprint"],
                "generation": obs_sealed["generation"],
                "decision": "approve"
            }),
        );
        let filled_sealed = find_frame(&sealed_out, "credential.filled").expect("filled_sealed");
        assert_eq!(filled_sealed["blackout_agent_observation"], true);

        let blocked = run_in_memory_event(
            &host,
            2,
            auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
        );
        assert_eq!(
            find_frame(&blocked, "refused").expect("refused")["reason"],
            "sealed_blackout"
        );
        let host_obs = find_frame(
            &run_in_memory_event(
                &host,
                1,
                auth_json!({"type": "observe.request", "seq": next_h(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("host allowed during sealed blackout");
        let host_pw = host_obs["elements"]
            .as_array()
            .expect("elems")
            .iter()
            .find(|e| e["dom_id"] == "pw")
            .expect("pw");
        assert_eq!(host_pw["value_state"], "sensitive");
        assert!(host_pw["value"].is_null());

        let pw_nid3 = dom_numeric_id(&host_obs, "pw");
        {
            let arc = host.authority();
            let sup = arc.lock().expect("lock sup");
            let tid = sup.engine.session(&sid).expect("sess").target_id;
            let rtid = format!("authority-target-{tid}");
            let written = sup
                .engine
                .backend()
                .render_handle()
                .with_doc_sync(&rtid, move |doc, _| Ok(doc.get_input_value(pw_nid3)))
                .expect("read sealed pw");
            assert_eq!(written.as_deref(), Some("s3cr3t-parawing-pw"));
        }

        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_nav_home",
                "snapshot_id": host_obs["snapshot_id"],
                "fingerprint": host_obs["fingerprint"],
                "generation": host_obs["generation"],
                "operation": {"kind": "navigate", "url": format!("{base_origin}/home")},
                "rationale": "Cross-document navigation clears sealed blackout"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_nav_home",
                "fingerprint": host_obs["fingerprint"],
                "generation": host_obs["generation"],
                "decision": "approve"
            }),
        );

        let obs_home = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("agent observe succeeds after cross-doc nav");
        let name_el = element_id_by_dom_id(&obs_home, "name");
        let role_el = element_id_by_dom_id(&obs_home, "role");
        let tos_el = element_id_by_dom_id(&obs_home, "tos");

        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_fill_form",
                "snapshot_id": obs_home["snapshot_id"],
                "fingerprint": obs_home["fingerprint"],
                "generation": obs_home["generation"],
                "operation": {
                    "kind": "fill_form",
                    "fields": [
                        {"target_id": &name_el, "action": "type", "value": "Ada Lovelace"},
                        {"target_id": &role_el, "action": "select", "value": "editor"},
                        {"target_id": &tos_el, "action": "check", "value": "true"}
                    ]
                },
                "rationale": "Fill preferences form to record recipe"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_fill_form",
                "fingerprint": obs_home["fingerprint"],
                "generation": obs_home["generation"],
                "decision": "approve"
            }),
        );

        let obs_reload = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_reload");
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_do_reload",
                "snapshot_id": obs_reload["snapshot_id"],
                "fingerprint": obs_reload["fingerprint"],
                "generation": obs_reload["generation"],
                "operation": {"kind": "reload"},
                "rationale": "Reset inputs before ReplayRecipe"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_do_reload",
                "fingerprint": obs_reload["fingerprint"],
                "generation": obs_reload["generation"],
                "decision": "approve"
            }),
        );

        let obs_replay = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_replay");
        let name_nid = dom_numeric_id(&obs_replay, "name");
        let tos_nid = dom_numeric_id(&obs_replay, "tos");
        let recipe_id = obs_replay["matched_recipe_id"]
            .as_str()
            .expect("matched_recipe_id")
            .to_string();
        let _ = run_in_memory_event(
            &host,
            2,
            auth_json!({
                "type": "propose", "seq": next_a(), "session_id": &sid,
                "proposal_id": "p_replay",
                "snapshot_id": obs_replay["snapshot_id"],
                "fingerprint": obs_replay["fingerprint"],
                "generation": obs_replay["generation"],
                "operation": {"kind": "replay_recipe", "recipe_id": &recipe_id},
                "rationale": "Replay form recipe structurally"
            }),
        );
        let _ = run_in_memory_event(
            &host,
            1,
            auth_json!({
                "type": "decision", "seq": next_h(), "session_id": &sid,
                "proposal_id": "p_replay",
                "fingerprint": obs_replay["fingerprint"],
                "generation": obs_replay["generation"],
                "decision": "approve"
            }),
        );

        let obs_final = find_frame(
            &run_in_memory_event(
                &host,
                2,
                auth_json!({"type": "observe.request", "seq": next_a(), "session_id": &sid}),
            ),
            "observe.result",
        )
        .expect("obs_final");
        let role_final = obs_final["elements"]
            .as_array()
            .expect("elems")
            .iter()
            .find(|e| e["dom_id"] == "role")
            .expect("role");
        assert_eq!(role_final["value"], "editor");
        {
            let arc = host.authority();
            let sup = arc.lock().expect("lock sup");
            let tid = sup.engine.session(&sid).expect("sess").target_id;
            let rtid = format!("authority-target-{tid}");
            let (name_val, tos_checked) = sup
                .engine
                .backend()
                .render_handle()
                .with_doc_sync(&rtid, move |doc, _| {
                    Ok((
                        doc.get_input_value(name_nid).unwrap_or_default(),
                        doc.is_checkbox_or_radio_checked(tos_nid).unwrap_or(false),
                    ))
                })
                .expect("read replayed fields");
            assert_eq!(name_val, "Ada Lovelace");
            assert!(tos_checked);
        }

        assert_eq!(host.audit_verify_chain(), Ok(()));
        host.shutdown().await;
    }
}
