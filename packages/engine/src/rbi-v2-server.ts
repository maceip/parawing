// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Server-side S7 RBI v2 channel manager and 8.8 encrypted client input journal integration.

import type { HandlerRegionInfo, JournalInputCapture } from "@parawing/jsrpc-types/page-script";
import { nanoid } from "nanoid";
import { isAttachedViewer, markInternalHumanRequest, type DispatchCtx } from "./cdp/dispatch.ts";
import { stubQueryDom } from "./cdp/page-session.ts";
import {
  parseCdpRequest,
  type BrowserState,
  type CdpRequest,
  type CdpResponse,
  type TargetState,
} from "./cdp/types.ts";
import {
  ControllerLeaseConflictError,
  type ControllerLeaseRecord,
  type DispatchActorRole,
} from "./policy/controller-lease.ts";
import { PolicyDecisionError } from "./policy/policy-engine.ts";
import { MAX_CONCURRENT_READ_BYTES } from "./read-capped.ts";
import {
  ClientInputJournal,
  classifyFieldSensitivity,
  type RecordJournalOutcome,
  type RejectionReason,
  type ReplayedInputEntry,
  type StableFieldKey,
} from "./rbi-input-journal.ts";
import { asTargetId, type TargetId } from "./session/identities.ts";
import { engineOwnedBytes } from "./rbi-protocol.ts";
import {
  encodeDeltaResyncAckPacket,
  extractKsc2TileMetadata,
  type Ksc2TileMetadata,
  RbiV2PacketKind,
  RbiV2ServerChannel,
  type RbiV2ServerStats,
  type RbiV2Transport,
  type ScrollDatagramV2,
} from "./rbi-v2.ts";

const DEFAULT_V2_FPS = 30;
const MIN_V2_FPS = 1;
const MAX_V2_FPS = 60;
const MAX_FRAME_TRACKING_WINDOW = 64;
const MAX_SERVER_KNOWN_HASHES = 8192;

export interface RbiV2StreamStartResult {
  wsPath: string;
  token: string;
  ackedScrollSeq: number;
  ackedInputSeq: number;
  journalSize: number;
}

export interface RbiV2RecordResult {
  frame: Uint8Array;
  seq: number;
  scrollX: number;
  scrollY: number;
  origin: string;
  handlerRegions: HandlerRegionInfo[];
  ackedScrollSeq: number;
  ackedInputSeq: number;
  error?: string;
}

export interface InputJournalStateSnapshot {
  size: number;
  encryptedCount: number;
  nextInputSeq: number;
  ackedInputSeq: number;
  lastRejectionReason?: RejectionReason;
  replayedCount: number;
  origin: string;
}

interface TargetJournalState {
  journalPromise: Promise<ClientInputJournal>;
  journal: ClientInputJournal | null;
  nextInputSeq: number;
  ackedInputSeq: number;
  ackedScrollSeq: number;
  lastRejectionReason?: RejectionReason;
  navGeneration: number;
  lastPageScript: TargetState["pageScript"];
  lastOrigin: string;
}

interface RbiV2StreamSession {
  token: string;
  ctx: DispatchCtx;
  browser: BrowserState;
  target: TargetState;
  startedByRole: "owner" | "viewer";
  closed: boolean;
  fps: number;
  initialCredits?: number;
  maxCredits?: number;
  wsConnected: boolean;
  wsGeneration: number;
  closeSocket: (() => void) | null;
  sentInitialFrame: boolean;
  nextFrameAt: number;
  outboundPackets: Uint8Array[];
  outboundTextMessages: string[];
  inboundPackets: Uint8Array[];
  inboundTextMessages: string[];
  channel: RbiV2ServerChannel;
  velX: number;
  velY: number;
  pointerButtons: number;
  knownHashes: Set<bigint>;
  frameSeq: number;
  lastSentSeq: number;
  lastSentScrollSeq: number;
  lastSentInputSeq: number;
  frameWatermarks: Map<number, number>;
  frameTileHashes: Map<number, Ksc2TileMetadata>;
  pumpTimer: ReturnType<typeof setTimeout> | null;
  pumpInFlight: boolean;
  pendingPump: boolean;
}

interface BrowserV2State {
  journals: Map<string, TargetJournalState>;
  streams: Map<string, RbiV2StreamSession>;
}

export type ViewerChannelDispatcher = (req: CdpRequest) => Promise<CdpResponse>;

const browserStates = new WeakMap<BrowserState, BrowserV2State>();
const sessionJournalStores = new WeakMap<BrowserState, Map<TargetId, ClientInputJournal>>();
const viewerDispatchers = new WeakMap<BrowserState, ViewerChannelDispatcher>();
const activeStreamTokens = new Map<string, RbiV2StreamSession>();

export function registerSessionClientJournals(
  browser: BrowserState,
  journals: Map<TargetId, ClientInputJournal>,
): void {
  sessionJournalStores.set(browser, journals);
}

export function registerViewerDispatcher(
  browser: BrowserState,
  dispatcher: ViewerChannelDispatcher,
): void {
  viewerDispatchers.set(browser, dispatcher);
}

function getBrowserV2State(browser: BrowserState): BrowserV2State {
  let entry = browserStates.get(browser);
  if (!entry) {
    entry = { journals: new Map(), streams: new Map() };
    browserStates.set(browser, entry);
  }
  return entry;
}

function originOfUrl(url: string | undefined): string {
  if (!url) return "null";
  try {
    const parsed = new URL(url);
    return parsed.origin === "null" ? "null" : parsed.origin;
  } catch {
    return "null";
  }
}

async function ensureJournalState(
  browser: BrowserState,
  target: TargetState,
): Promise<{ state: TargetJournalState; journal: ClientInputJournal }> {
  const bv2 = getBrowserV2State(browser);
  const currentOrigin = originOfUrl(target.url);
  const sessionStore = sessionJournalStores.get(browser);
  const targetBrandId = asTargetId(target.targetId);
  let entry = bv2.journals.get(target.targetId);
  if (!entry) {
    const persisted = sessionStore?.get(targetBrandId);
    const maxStoredSeq = persisted
      ? persisted.encryptedSnapshot().reduce((m, item) => Math.max(m, item.inputSeq), 0)
      : 0;
    const baseAcked = target.lastAckedInputSeq ?? 0;
    entry = {
      journalPromise: persisted ? Promise.resolve(persisted) : ClientInputJournal.create(),
      journal: persisted ?? null,
      nextInputSeq: Math.max(baseAcked, maxStoredSeq),
      ackedInputSeq: baseAcked,
      ackedScrollSeq: 0,
      navGeneration: target.navigateGeneration,
      lastPageScript: target.pageScript,
      lastOrigin: currentOrigin,
    };
    bv2.journals.set(target.targetId, entry);
  }
  const journal = entry.journal ?? (await entry.journalPromise);
  entry.journal = journal;
  if (sessionStore && !sessionStore.has(targetBrandId)) {
    sessionStore.set(targetBrandId, journal);
  }
  const navigated =
    entry.navGeneration !== target.navigateGeneration ||
    entry.lastPageScript !== target.pageScript ||
    (entry.lastOrigin !== "null" && currentOrigin !== entry.lastOrigin);
  if (navigated) {
    journal.clearOnNavigation();
    entry.ackedInputSeq = 0;
    entry.ackedScrollSeq = 0;
    entry.lastRejectionReason = undefined;
    entry.navGeneration = target.navigateGeneration;
    entry.lastPageScript = target.pageScript;
    entry.lastOrigin = currentOrigin;
  } else if (entry.lastOrigin === "null" && currentOrigin !== "null") {
    entry.lastOrigin = currentOrigin;
  }
  return { state: entry, journal };
}

export async function syncJournalAfterTier1Restore(
  browser: BrowserState,
  target: TargetState,
): Promise<void> {
  const bv2 = getBrowserV2State(browser);
  const existing = bv2.journals.get(target.targetId);
  const currentOrigin = originOfUrl(target.url);
  if (existing) {
    existing.navGeneration = target.navigateGeneration;
    existing.lastPageScript = target.pageScript;
    existing.lastOrigin = currentOrigin;
    return;
  }
  await ensureJournalState(browser, target);
}

function packHashesLe(hashes: ReadonlySet<bigint>): Uint8Array {
  if (hashes.size === 0) return new Uint8Array(0);
  const out = new Uint8Array(hashes.size * 8);
  const view = new DataView(out.buffer);
  let off = 0;
  for (const hash of hashes) {
    view.setBigUint64(off, BigInt.asUintN(64, hash), true);
    off += 8;
  }
  return out;
}

function toUint8Array(data: unknown): Uint8Array | null {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return null;
}

function toPlainArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

export async function reapplyJournalEntryToPage(
  target: TargetState,
  item: ReplayedInputEntry,
): Promise<boolean> {
  if (!target.pageScript) return false;
  if (classifyFieldSensitivity(item.field).sensitive) return false;
  const reply = await stubQueryDom(target.pageScript, "restoreEditableField", {
    origin: item.field.origin,
    documentUrl: item.field.documentUrl,
    formId: item.field.formId,
    formAction: item.field.formAction,
    tagName: item.field.tagName,
    inputType: item.field.inputType,
    autocomplete: item.field.autocomplete,
    domPath: item.field.domPath,
    nodeId: item.field.nodeId,
    fieldName: item.field.fieldName,
    fieldId: item.field.fieldId,
    value: item.value,
    selectionStart: item.selectionStart,
    selectionEnd: item.selectionEnd,
  });
  return reply.restored === true;
}

async function applyJournalReplaysToPage(
  target: TargetState,
  entries: ReplayedInputEntry[],
): Promise<number> {
  if (!target.pageScript || entries.length === 0) return 0;
  let restored = 0;
  for (const item of entries) {
    if (await reapplyJournalEntryToPage(target, item)) restored++;
  }
  return restored;
}

export async function recordSceneV2ForTarget(
  browser: BrowserState,
  target: TargetState,
  opts?: {
    knownHashes?: Uint8Array;
    velX?: number;
    velY?: number;
    pumpRaf?: boolean;
    frameAckInputSeq?: number;
  },
): Promise<RbiV2RecordResult> {
  const { state: jState } = await ensureJournalState(browser, target);
  const ackedInputSeq = Math.max(
    jState.ackedInputSeq,
    opts?.frameAckInputSeq ?? jState.nextInputSeq,
  );
  const ps = target.pageScript;
  if (!ps) {
    return {
      frame: new Uint8Array(0),
      seq: 0,
      scrollX: 0,
      scrollY: 0,
      origin: originOfUrl(target.url),
      handlerRegions: [],
      ackedScrollSeq: jState.ackedScrollSeq,
      ackedInputSeq,
      error: "no PageScript",
    };
  }
  const generation = target.navigateGeneration;
  const reply = await stubQueryDom(ps, "recordSceneV2", {
    ackedScrollSeq: jState.ackedScrollSeq,
    ackedInputSeq,
    knownHashes: opts?.knownHashes,
    velX: opts?.velX ?? 0,
    velY: opts?.velY ?? 0,
    pumpRaf: opts?.pumpRaf,
  });
  if (target.navigateGeneration !== generation || target.pageScript !== ps) {
    return {
      frame: new Uint8Array(0),
      seq: 0,
      scrollX: 0,
      scrollY: 0,
      origin: originOfUrl(target.url),
      handlerRegions: [],
      ackedScrollSeq: jState.ackedScrollSeq,
      ackedInputSeq,
      error: "stale scene generation",
    };
  }
  const frame = engineOwnedBytes(reply.frame, MAX_CONCURRENT_READ_BYTES) ?? new Uint8Array(0);
  return {
    frame,
    seq: reply.seq ?? 0,
    scrollX: reply.scrollX ?? 0,
    scrollY: reply.scrollY ?? 0,
    origin: reply.origin ?? originOfUrl(target.url),
    handlerRegions: reply.handlerRegions ?? [],
    ackedScrollSeq: jState.ackedScrollSeq,
    ackedInputSeq,
    error: reply.error,
  };
}

async function replayAndRecordFrame(session: RbiV2StreamSession): Promise<RbiV2RecordResult> {
  const { state: jState, journal } = await ensureJournalState(session.browser, session.target);
  const currentOrigin = originOfUrl(session.target.url);
  if (journal.size() > 0) {
    const entries = await journal.replayUnacked(currentOrigin);
    await applyJournalReplaysToPage(session.target, entries);
  }
  const result = await recordSceneV2ForTarget(session.browser, session.target, {
    knownHashes: packHashesLe(session.knownHashes),
    velX: session.velX,
    velY: session.velY,
    frameAckInputSeq: jState.nextInputSeq,
  });
  jState.ackedInputSeq = Math.max(jState.ackedInputSeq, jState.nextInputSeq);
  return result;
}

async function pumpFrameOnce(session: RbiV2StreamSession, force = false): Promise<void> {
  if (session.closed || !session.wsConnected) return;
  if (session.pumpInFlight) {
    session.pendingPump = true;
    return;
  }
  session.pumpInFlight = true;
  try {
    const { state: jState } = await ensureJournalState(session.browser, session.target);
    const candidateInputSeq = jState.nextInputSeq;
    const result = await recordSceneV2ForTarget(session.browser, session.target, {
      knownHashes: packHashesLe(session.knownHashes),
      velX: session.velX,
      velY: session.velY,
      frameAckInputSeq: candidateInputSeq,
    });
    if (session.closed || result.error || result.frame.byteLength === 0) return;
    const tileMeta = extractKsc2TileMetadata(result.frame);
    const changed =
      force ||
      result.seq !== session.lastSentSeq ||
      result.ackedScrollSeq !== session.lastSentScrollSeq ||
      result.ackedInputSeq !== session.lastSentInputSeq;
    if (!changed) return;
    session.sentInitialFrame = true;
    const interval = Math.max(16, Math.round(1000 / session.fps));
    session.nextFrameAt = Date.now() + interval;
    session.frameSeq++;
    session.lastSentSeq = result.seq;
    session.lastSentScrollSeq = result.ackedScrollSeq;
    session.lastSentInputSeq = result.ackedInputSeq;
    session.frameWatermarks.set(session.frameSeq, candidateInputSeq);
    session.frameTileHashes.set(session.frameSeq, tileMeta);
    trimOldestEntries(session.frameWatermarks, MAX_FRAME_TRACKING_WINDOW);
    trimOldestEntries(session.frameTileHashes, MAX_FRAME_TRACKING_WINDOW);
    session.channel.enqueueReliableFrame({
      frameSeq: session.frameSeq,
      baseSeq: Math.max(0, session.frameSeq - 1),
      tileCount: tileMeta.tileCount,
      payload: result.frame,
    });
  } finally {
    session.pumpInFlight = false;
    if (session.pendingPump && !session.closed) {
      session.pendingPump = false;
      void pumpFrameOnce(session, false);
    }
  }
}

async function runSessionStep(session: RbiV2StreamSession): Promise<void> {
  if (session.inboundPackets.length > 0) {
    const packets = session.inboundPackets.splice(0);
    for (const pkt of packets) {
      await processClientBinaryPacket(session, pkt).catch(() => {});
    }
  }
  if (session.inboundTextMessages.length > 0) {
    const messages = session.inboundTextMessages.splice(0);
    for (const raw of messages) {
      await processViewerTextMessage(session, raw).catch(() => {});
    }
  }
  if (!session.wsConnected) return;
  const now = Date.now();
  const interval = Math.max(16, Math.round(1000 / session.fps));
  if (!session.sentInitialFrame || now >= session.nextFrameAt) {
    const force = !session.sentInitialFrame;
    session.sentInitialFrame = true;
    session.nextFrameAt = now + interval;
    await pumpFrameOnce(session, force);
  }
}

function scheduleSessionTick(session: RbiV2StreamSession): void {
  if (session.closed || session.ctx.browser.wsClosing) return;
  if (session.pumpTimer !== null) clearTimeout(session.pumpTimer);
  session.pumpTimer = setTimeout(() => {
    session.pumpTimer = null;
    if (session.closed || session.ctx.browser.wsClosing) return;
    if (!session.ctx.browser.targets.has(session.target.targetId)) {
      closeStreamSession(session);
      return;
    }
    session.ctx.host.tasks.run(
      runSessionStep(session).finally(() => {
        if (!session.closed && !session.ctx.browser.wsClosing) {
          scheduleSessionTick(session);
        }
      }),
    );
  }, 4);
}

function getActiveLeaseForTarget(session: RbiV2StreamSession): ControllerLeaseRecord | null {
  return (
    session.browser.controllerLeases?.getActiveLease(asTargetId(session.target.targetId)) ?? null
  );
}

function hasAttachedViewer(session: RbiV2StreamSession): boolean {
  if (session.startedByRole === "viewer" || isAttachedViewer(session.ctx)) return true;
  const sid = session.browser.sessionId;
  if (!sid || !session.ctx.sessionManager) return false;
  const rec = session.ctx.sessionManager.get(sid);
  if (!rec) return false;
  for (const conn of rec.connections.values()) {
    if (conn.role === "viewer") return true;
  }
  return false;
}

function evaluateV2CommandPolicy(
  session: RbiV2StreamSession,
  method: string,
  actorRole: DispatchActorRole,
): { allowed: true } | { allowed: false; reason: string } {
  const engine = session.browser.policyEngine;
  if (!engine) return { allowed: true };
  const decision = engine.evaluateCommand({
    method,
    sessionId: session.browser.sessionId,
    targetId: asTargetId(session.target.targetId),
    sealedOrigin: session.target.sealedOrigin ?? null,
    actorRole,
  });
  if (decision.allowed) return { allowed: true };
  return { allowed: false, reason: new PolicyDecisionError(decision).message };
}

async function handleInboundScroll(
  session: RbiV2StreamSession,
  scroll: ScrollDatagramV2,
): Promise<void> {
  if (session.closed) return;
  const targetId = asTargetId(session.target.targetId);
  const activeLease = getActiveLeaseForTarget(session);
  if (!activeLease && hasAttachedViewer(session)) return;
  const actorRole: DispatchActorRole = activeLease ? "human" : (session.ctx.actorRole ?? "agent");
  try {
    session.browser.controllerLeases?.assertAgentDispatchAllowed(
      targetId,
      "Parawing.applyScrollDeltaV2",
      actorRole,
    );
  } catch (err) {
    if (err instanceof ControllerLeaseConflictError) return;
    throw err;
  }
  const policy = evaluateV2CommandPolicy(session, "Parawing.applyScrollDeltaV2", actorRole);
  if (!policy.allowed) return;
  const { state: jState } = await ensureJournalState(session.browser, session.target);
  if (scroll.seq > jState.ackedScrollSeq) jState.ackedScrollSeq = scroll.seq;
  session.velX = scroll.velX;
  session.velY = scroll.velY;
  if (session.target.pageScript) {
    await stubQueryDom(session.target.pageScript, "applyScrollDeltaV2", {
      scrollNodeId: Number(scroll.scrollNodeId),
      x: scroll.x,
      y: scroll.y,
    });
  }
  await pumpFrameOnce(session, true);
}

function trimOldestEntries<K, V>(map: Map<K, V>, maxSize: number): void {
  while (map.size > maxSize) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) break;
    map.delete(oldest);
  }
}

function recordKnownHashes(knownHashes: Set<bigint>, meta: Ksc2TileMetadata): void {
  for (const inv of meta.invalidatedHashes) {
    knownHashes.delete(inv);
  }
  for (const hash of meta.tileHashes) {
    if (hash === 0n) continue;
    knownHashes.delete(hash);
    knownHashes.add(hash);
  }
  while (knownHashes.size > MAX_SERVER_KNOWN_HASHES) {
    const oldest = knownHashes.values().next().value;
    if (oldest === undefined) break;
    knownHashes.delete(oldest);
  }
}

function promoteAckedTileHashes(session: RbiV2StreamSession, ackedFrameSeq: number): void {
  for (const [seq, meta] of session.frameTileHashes) {
    if (seq > ackedFrameSeq) continue;
    recordKnownHashes(session.knownHashes, meta);
    session.frameTileHashes.delete(seq);
  }
}

function pushViewerTextReply(
  session: RbiV2StreamSession,
  id: unknown,
  payload: Record<string, unknown>,
): void {
  session.outboundTextMessages.push(JSON.stringify({ id: id ?? null, ...payload }));
}

function buildHumanViewerCdpRequest(
  session: RbiV2StreamSession,
  msg: Record<string, unknown>,
  activeLease: ControllerLeaseRecord,
): CdpRequest | null {
  const kind = msg["type"];
  const targetSessionId = session.target.sessions.values().next().value;
  let method: string;
  let params: Record<string, unknown>;
  if (kind === "insertText") {
    method = "Input.insertText";
    params = { text: typeof msg["text"] === "string" ? msg["text"] : "" };
  } else if (kind === "keyEvent" || kind === "mouseEvent") {
    method = kind === "keyEvent" ? "Input.dispatchKeyEvent" : "Input.dispatchMouseEvent";
    params =
      msg["params"] && typeof msg["params"] === "object" && !Array.isArray(msg["params"])
        ? (msg["params"] as Record<string, unknown>)
        : {};
  } else if (kind === "releaseControllerLease") {
    const leaseId = typeof msg["leaseId"] === "string" ? msg["leaseId"] : undefined;
    if (leaseId && leaseId !== activeLease.leaseId) return null;
    method = "Parawing.releaseControllerLease";
    params = { leaseId: activeLease.leaseId, targetId: session.target.targetId };
  } else {
    return null;
  }
  const parsed = parseCdpRequest(
    JSON.stringify({ id: -10, method, params, sessionId: targetSessionId }),
  );
  if (!parsed.ok) return null;
  markInternalHumanRequest(parsed.request);
  return parsed.request;
}

async function processViewerTextMessage(session: RbiV2StreamSession, raw: string): Promise<void> {
  if (session.closed) return;
  let msg: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return;
    msg = parsed as Record<string, unknown>;
  } catch {
    return;
  }
  const msgId = msg["id"];
  const activeLease = getActiveLeaseForTarget(session);
  if (!activeLease) {
    pushViewerTextReply(session, msgId, {
      ok: false,
      error: "Active ControllerLease required for ViewerChannelV2 input",
    });
    return;
  }
  const req = buildHumanViewerCdpRequest(session, msg, activeLease);
  if (!req) {
    pushViewerTextReply(session, msgId, { ok: false, error: "Unsupported ViewerChannelV2 input" });
    return;
  }
  const policy = evaluateV2CommandPolicy(session, req.method, "human");
  if (!policy.allowed) {
    pushViewerTextReply(session, msgId, { ok: false, error: policy.reason });
    return;
  }
  const dispatcher = viewerDispatchers.get(session.browser);
  if (!dispatcher) {
    pushViewerTextReply(session, msgId, { ok: false, error: "Viewer dispatcher unavailable" });
    return;
  }
  const resp = await dispatcher(req);
  if ("error" in resp) {
    pushViewerTextReply(session, msgId, { ok: false, error: resp.error.message });
    return;
  }
  pushViewerTextReply(session, msgId, { ok: true, result: resp.result ?? {} });
  await pumpFrameOnce(session, true);
}

async function handleDatagramPointer(
  session: RbiV2StreamSession,
  ptr: { x: number; y: number; buttons: number },
): Promise<void> {
  if (session.closed) return;
  const ps = session.target.pageScript;
  if (!ps) return;
  const activeLease = getActiveLeaseForTarget(session);
  if (!activeLease) return;
  const policy = evaluateV2CommandPolicy(session, "Input.dispatchMouseEvent", "human");
  if (!policy.allowed) return;
  const baseInit = {
    bubbles: true,
    cancelable: false,
    clientX: ptr.x,
    clientY: ptr.y,
    button: 0,
    buttons: ptr.buttons,
    detail: 0,
    deltaX: 0,
    deltaY: 0,
    deltaZ: 0,
    deltaMode: 0,
  };
  await ps.dispatchMouseEvent("mousemove", baseInit);
  const prevDown = (session.pointerButtons & 1) !== 0;
  const nextDown = (ptr.buttons & 1) !== 0;
  session.pointerButtons = ptr.buttons;
  if (!prevDown && nextDown) {
    await ps.dispatchMouseEvent("mousedown", { ...baseInit, cancelable: true, detail: 1 });
    await pumpFrameOnce(session, true);
    return;
  }
  if (prevDown && !nextDown) {
    await ps.dispatchMouseEvent("mouseup", { ...baseInit, cancelable: true, detail: 1 });
    await ps.dispatchMouseEvent("click", { ...baseInit, cancelable: true, detail: 1 });
    await pumpFrameOnce(session, true);
  }
}

async function processClientBinaryPacket(
  session: RbiV2StreamSession,
  bytes: Uint8Array,
): Promise<void> {
  if (session.closed) return;
  const pkt = session.channel.handleClientPacket(bytes);
  if (pkt.kind === RbiV2PacketKind.CreditGrant) {
    const watermark = session.frameWatermarks.get(pkt.ackedFrameSeq);
    if (watermark !== undefined) {
      const { state: jState, journal } = await ensureJournalState(session.browser, session.target);
      journal.acknowledgeServerSeq(watermark);
      if (watermark > jState.ackedInputSeq) jState.ackedInputSeq = watermark;
    }
    promoteAckedTileHashes(session, pkt.ackedFrameSeq);
    await pumpFrameOnce(session, false);
    return;
  }
  if (pkt.kind === RbiV2PacketKind.ReattachWithTileHashes) {
    session.knownHashes = new Set(pkt.knownTileHashes);
    session.frameTileHashes.clear();
    session.velX = pkt.velX;
    session.velY = pkt.velY;
    const result = await replayAndRecordFrame(session);
    if (session.closed || !session.wsConnected) return;
    const tileMeta = extractKsc2TileMetadata(result.frame);
    recordKnownHashes(session.knownHashes, tileMeta);
    session.frameSeq++;
    session.lastSentSeq = result.seq;
    session.lastSentScrollSeq = result.ackedScrollSeq;
    session.lastSentInputSeq = result.ackedInputSeq;
    const ackBytes = encodeDeltaResyncAckPacket({
      resumedFromSeq: pkt.lastFrameSeq,
      prunedKnownTiles: pkt.knownTileHashes.length,
      payload: result.frame,
    });
    session.outboundPackets.push(ackBytes);
    return;
  }
  if (pkt.kind === RbiV2PacketKind.DatagramScroll) {
    const latest = session.channel.takeLatestInboundScroll(pkt.datagram.scrollNodeId);
    if (latest) await handleInboundScroll(session, latest);
    return;
  }
  if (pkt.kind === RbiV2PacketKind.DatagramPointer) {
    const ptr = session.channel.takeLatestInboundPointer();
    if (ptr) await handleDatagramPointer(session, ptr);
  }
}

function closeStreamSession(session: RbiV2StreamSession): void {
  if (session.closed) return;
  session.closed = true;
  session.wsConnected = false;
  activeStreamTokens.delete(session.token);
  if (session.pumpTimer !== null) {
    clearTimeout(session.pumpTimer);
    session.pumpTimer = null;
  }
  const closeSock = session.closeSocket;
  session.closeSocket = null;
  closeSock?.();
  session.outboundPackets.length = 0;
  session.inboundPackets.length = 0;
  session.frameWatermarks.clear();
  session.frameTileHashes.clear();
  const bv2 = browserStates.get(session.browser);
  if (bv2?.streams.get(session.target.targetId) === session) {
    bv2.streams.delete(session.target.targetId);
  }
}

export async function startRbiV2Stream(
  ctx: DispatchCtx,
  target: TargetState,
  opts?: {
    width?: number;
    height?: number;
    fps?: number;
    initialCredits?: number;
    maxCredits?: number;
  },
): Promise<RbiV2StreamStartResult> {
  if (typeof opts?.width === "number" && typeof opts?.height === "number" && target.pageScript) {
    await stubQueryDom(target.pageScript, "setViewport", {
      width: opts.width,
      height: opts.height,
    });
  }
  const { state: jState, journal } = await ensureJournalState(ctx.browser, target);
  const bv2 = getBrowserV2State(ctx.browser);
  const existing = bv2.streams.get(target.targetId);
  if (existing) closeStreamSession(existing);

  const token = nanoid(24);
  const fps = Math.max(MIN_V2_FPS, Math.min(MAX_V2_FPS, Math.round(opts?.fps ?? DEFAULT_V2_FPS)));
  const outboundPackets: Uint8Array[] = [];
  const queueTransport: RbiV2Transport = {
    sendReliable(packet) {
      outboundPackets.push(new Uint8Array(packet));
    },
    sendDatagram(packet) {
      outboundPackets.push(new Uint8Array(packet));
    },
  };
  const channel = new RbiV2ServerChannel(queueTransport, {
    initialCredits: opts?.initialCredits,
    maxCredits: opts?.maxCredits,
  });
  const session: RbiV2StreamSession = {
    token,
    ctx,
    browser: ctx.browser,
    target,
    startedByRole: isAttachedViewer(ctx) || ctx.connectionRole === "viewer" ? "viewer" : "owner",
    closed: false,
    fps,
    initialCredits: opts?.initialCredits,
    maxCredits: opts?.maxCredits,
    wsConnected: false,
    wsGeneration: 0,
    closeSocket: null,
    sentInitialFrame: false,
    nextFrameAt: 0,
    outboundPackets,
    outboundTextMessages: [],
    inboundPackets: [],
    inboundTextMessages: [],
    channel,
    velX: 0,
    velY: 0,
    pointerButtons: 0,
    knownHashes: new Set(),
    frameSeq: 0,
    lastSentSeq: -1,
    lastSentScrollSeq: -1,
    lastSentInputSeq: -1,
    frameWatermarks: new Map(),
    frameTileHashes: new Map(),
    pumpTimer: null,
    pumpInFlight: false,
    pendingPump: false,
  };
  bv2.streams.set(target.targetId, session);
  activeStreamTokens.set(token, session);
  scheduleSessionTick(session);
  return {
    wsPath: `/rbi/ws?token=${token}`,
    token,
    ackedScrollSeq: jState.ackedScrollSeq,
    ackedInputSeq: jState.ackedInputSeq,
    journalSize: journal.size(),
  };
}

export function stopRbiV2Streams(
  browser: BrowserState,
  targetId?: string,
  opts?: { preserveInputJournals?: boolean },
): void {
  const bv2 = browserStates.get(browser);
  if (!bv2) return;
  for (const [id, session] of bv2.streams) {
    if (targetId !== undefined && id !== targetId) continue;
    closeStreamSession(session);
  }
  if (opts?.preserveInputJournals) return;
  const sessionStore = sessionJournalStores.get(browser);
  for (const [id, jState] of bv2.journals) {
    if (targetId !== undefined && id !== targetId) continue;
    jState.journal?.clearOnNavigation();
    bv2.journals.delete(id);
    sessionStore?.delete(asTargetId(id));
  }
}

export function acceptRbiV2WebSocket(req: Request): Response {
  const url = new URL(req.url);
  const token = url.searchParams.get("token") ?? "";
  const session = token ? activeStreamTokens.get(token) : undefined;
  if (!session || session.closed || session.ctx.browser.wsClosing) {
    return new Response("not found", { status: 404 });
  }
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
  server.accept();
  const myGen = ++session.wsGeneration;
  session.wsConnected = true;
  session.sentInitialFrame = false;
  let socketOpen = true;
  let closeRequested = false;
  let flushTimer: ReturnType<typeof setInterval> | null = null;

  const stopSocketLoop = (): void => {
    if (flushTimer !== null) {
      clearInterval(flushTimer);
      flushTimer = null;
    }
  };

  // Signal the socket's own IoContext loop instead of clearing timers across requests.
  const closeSocketNow = (): void => {
    closeRequested = true;
  };

  session.closeSocket?.();
  session.closeSocket = closeSocketNow;

  const flushOutbound = (): void => {
    const shouldClose =
      closeRequested ||
      session.closed ||
      session.ctx.browser.wsClosing ||
      session.wsGeneration !== myGen;
    if (!socketOpen) {
      stopSocketLoop();
      return;
    }
    if (!shouldClose && session.outboundPackets.length > 0 && server.readyState === 1) {
      const batch = session.outboundPackets.splice(0);
      for (const pkt of batch) {
        if (pkt.byteLength === 0) continue;
        server.send(toPlainArrayBuffer(pkt));
      }
    }
    if (!shouldClose && session.outboundTextMessages.length > 0 && server.readyState === 1) {
      const texts = session.outboundTextMessages.splice(0);
      for (const txt of texts) server.send(txt);
    }
    if (shouldClose) {
      stopSocketLoop();
      socketOpen = false;
      try {
        if (server.readyState === 1) server.close(1000, "stream stopped");
      } catch {}
    }
  };

  server.addEventListener("message", (event: MessageEvent) => {
    const raw: unknown = event.data;
    if (typeof raw === "string") {
      if (raw.length > 0) session.inboundTextMessages.push(raw);
      return;
    }
    if (raw instanceof Blob) {
      void raw.arrayBuffer().then((buf) => {
        if (buf.byteLength > 0) session.inboundPackets.push(new Uint8Array(buf));
      });
      return;
    }
    const bytes = toUint8Array(raw);
    if (bytes && bytes.byteLength > 0) session.inboundPackets.push(bytes);
  });
  server.addEventListener("close", () => {
    socketOpen = false;
    stopSocketLoop();
    if (session.closeSocket === closeSocketNow) session.closeSocket = null;
    if (session.wsGeneration === myGen) session.wsConnected = false;
  });
  server.addEventListener("error", () => {
    socketOpen = false;
    stopSocketLoop();
    if (session.closeSocket === closeSocketNow) session.closeSocket = null;
    if (session.wsGeneration === myGen) session.wsConnected = false;
  });

  // Flush queued server packets from within this WebSocket request's IoContext.
  flushTimer = setInterval(flushOutbound, 4);

  return new Response(null, { status: 101, webSocket: client });
}

export async function acknowledgeClientInputSeq(
  browser: BrowserState,
  target: TargetState,
  clientSeq: number,
): Promise<void> {
  if (!Number.isInteger(clientSeq) || clientSeq <= 0) return;
  const { state: jState } = await ensureJournalState(browser, target);
  if (clientSeq > jState.nextInputSeq) {
    jState.nextInputSeq = clientSeq;
  }
}

export async function recordJournalKeyEvent(
  browser: BrowserState,
  target: TargetState,
  capture: JournalInputCapture,
  clientInputSeq?: number,
): Promise<RecordJournalOutcome> {
  const { state: jState, journal } = await ensureJournalState(browser, target);
  const authoritativeOrigin = originOfUrl(target.url || capture.field.documentUrl);
  if (capture.submitTriggered) {
    if (
      clientInputSeq !== undefined &&
      Number.isInteger(clientInputSeq) &&
      clientInputSeq > jState.nextInputSeq
    ) {
      jState.nextInputSeq = clientInputSeq;
    }
    journal.clearOnSubmit({ origin: authoritativeOrigin, formId: capture.field.formId });
    return { recorded: false, reason: "submit-action-excluded" };
  }
  const minSeq = Math.max(jState.nextInputSeq, target.lastAckedInputSeq ?? 0) + 1;
  const seq =
    clientInputSeq !== undefined && Number.isInteger(clientInputSeq) && clientInputSeq > 0
      ? Math.max(clientInputSeq, minSeq)
      : minSeq;
  jState.nextInputSeq = seq;
  const field: StableFieldKey = {
    origin: authoritativeOrigin,
    documentUrl: capture.field.documentUrl || target.url,
    formId: capture.field.formId,
    formAction: capture.field.formAction,
    fieldName: capture.field.fieldName,
    fieldId: capture.field.fieldId,
    tagName: capture.field.tagName,
    inputType: capture.field.inputType,
    autocomplete: capture.field.autocomplete,
    domPath: capture.field.domPath,
    nodeId: capture.field.nodeId,
  };
  const outcome = await journal.recordInput({
    inputSeq: seq,
    field,
    value: capture.value,
    selectionStart: capture.selectionStart,
    selectionEnd: capture.selectionEnd,
    isSubmitAction: capture.submitTriggered,
  });
  if (outcome.reason) jState.lastRejectionReason = outcome.reason;
  return outcome;
}

export async function clearJournalOnSubmit(
  browser: BrowserState,
  target: TargetState,
  formId?: string,
): Promise<void> {
  const bv2 = browserStates.get(browser);
  const entry = bv2?.journals.get(target.targetId);
  if (!entry) return;
  const journal = entry.journal ?? (await entry.journalPromise);
  journal.clearOnSubmit(formId ? { formId } : undefined);
}

export async function clearJournalOnNavigation(
  browser: BrowserState,
  target: TargetState,
): Promise<void> {
  const bv2 = browserStates.get(browser);
  const entry = bv2?.journals.get(target.targetId);
  if (!entry) return;
  const journal = entry.journal ?? (await entry.journalPromise);
  journal.clearOnNavigation();
  entry.ackedInputSeq = 0;
  entry.ackedScrollSeq = 0;
  entry.lastRejectionReason = undefined;
  entry.navGeneration = target.navigateGeneration;
  entry.lastPageScript = target.pageScript;
  entry.lastOrigin = originOfUrl(target.url);
}

export async function getInputJournalState(
  browser: BrowserState,
  target: TargetState,
  opts?: {
    acknowledgeSeq?: number;
    includeEncryptedSnapshot?: boolean;
    replay?: boolean;
  },
): Promise<InputJournalStateSnapshot> {
  const { state: jState, journal } = await ensureJournalState(browser, target);
  if (typeof opts?.acknowledgeSeq === "number") {
    journal.acknowledgeServerSeq(opts.acknowledgeSeq);
    if (opts.acknowledgeSeq > jState.ackedInputSeq) {
      jState.ackedInputSeq = opts.acknowledgeSeq;
    }
    if (opts.acknowledgeSeq > (target.lastAckedInputSeq ?? 0)) {
      target.lastAckedInputSeq = opts.acknowledgeSeq;
    }
  }
  const currentOrigin = originOfUrl(target.url);
  let replayedCount = 0;
  if (opts?.replay && journal.size() > 0) {
    const entries = await journal.replayUnacked(currentOrigin);
    replayedCount = await applyJournalReplaysToPage(target, entries);
  }
  const encryptedCount = opts?.includeEncryptedSnapshot
    ? journal.encryptedSnapshot().length
    : journal.size();
  return {
    size: journal.size(),
    encryptedCount,
    nextInputSeq: jState.nextInputSeq,
    ackedInputSeq: jState.ackedInputSeq,
    lastRejectionReason: jState.lastRejectionReason,
    replayedCount,
    origin: currentOrigin,
  };
}

export function getRbiV2StreamStats(
  browser: BrowserState,
  targetId: string,
): RbiV2ServerStats | null {
  return browserStates.get(browser)?.streams.get(targetId)?.channel?.stats() ?? null;
}
