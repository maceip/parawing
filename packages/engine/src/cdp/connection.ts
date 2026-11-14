// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Owns one CDP session's state, event flow, deadlines, and resource cleanup.

import { nanoid } from "nanoid";
import { dispatch, type DispatchCtx, type EngineCdpCommandExtension } from "./dispatch.ts";
import { traceSpan } from "../tracing.ts";
import { endLocalTraceSession, localTraceEventWrap } from "../tracing-local.ts";
import {
  SKIP_SPECULATIVE_RASTER_HEADER,
  parseCdpRequest,
  type BrowserState,
  type CdpEvent,
  type CdpRequest,
  type CdpResponse,
  type TargetState,
} from "./types.ts";
import {
  ensureBrowserTarget,
  createPageTarget,
  captureTargetVisualState,
  engineMemoryBreakdown,
} from "./target.ts";
import { stubQueryDom } from "./page-session.ts";
import { pumpBackgroundEvents, teardownOopifStubs } from "./page.ts";
import { retireStub } from "./page-script-generation.ts";
import { releaseAllDomHandles } from "./dom-release.ts";
import { cancelAndRemoveTargetWheelQueues } from "./wheel-queue.ts";
import { stopSceneStreams, wakeSceneStream } from "./scene-stream.ts";
import { DynamicWorkerBudget } from "../eval/worker-budget.ts";
import { DedicatedWorkers } from "./dedicated-workers.ts";
import { createCookieJar } from "../cookies.ts";
import {
  NetworkEventTracker,
  registerTracker,
  unregisterTracker,
} from "./network-events-registry.ts";
import { registerCookieJar, unregisterConnectionCookieJars } from "./cookie-jar-registry.ts";
import { disposeWebMcpConnection } from "./webmcp.ts";
import { dropConnectionImages } from "../eval/resource-store.ts";
import { unregisterIsolateLimitListenersFor } from "../eval/limit-registry.ts";
import type { ExternalOutbound } from "../eval/external-outbound.ts";
import { createSandboxOutboundOverride } from "../eval/outbound.ts";
import { unregisterOutboundFilters } from "./outbound-filter-registry.ts";
import {
  registerRequestBlocker,
  unregisterRequestBlocker,
  type RequestBlocker,
} from "../request-blocker.ts";
import { unregisterInterception, drainInterception } from "./fetch-interception.ts";
import {
  ParawingAnalytics,
  SafePerformance,
  SESSION_ID_HEADER,
  emitSessionEnd,
  type SessionEntrypoint,
  type TelemetryFactory,
} from "../observability.ts";
import { resolveConnectionOptions, type EngineHost } from "../host.ts";
import type { PageIsolateCapOverrides } from "../eval/page-script.ts";
import { markArrival } from "./arrival.ts";
import { StyleCache } from "./style-cache.ts";
import type { HostCapabilities } from "../host-capabilities.ts";
import type { HostIsolateLoader } from "../isolate-loader.ts";
import { createWorkersCapabilities } from "../workers-capabilities.ts";
import { createWorkersIsolateLoader } from "../workers-isolate-loader.ts";
import type { AuthorityVaultAndChannel } from "../authority/authority-service.ts";
import type { ApprovalGate } from "../authority/approval-gate.ts";
import type { SignedAuditLog } from "../policy/audit-log.ts";
import { ControllerLeaseManager, type DispatchActorRole } from "../policy/controller-lease.ts";
import { PolicyEngine } from "../policy/policy-engine.ts";
import {
  asConnectionId,
  asSessionId,
  asTargetId,
  asUserId,
  StaleEpochError,
  type ConnectionRole,
  type SessionId,
  type UserId,
} from "../session/identities.ts";
import {
  loadLatestTier1Checkpoint,
  type InputJournalEntry,
  type RestorableTargetAdapter,
  type Tier1TargetSnapshot,
} from "../session/checkpoint.ts";
import {
  SessionManager,
  type ConnectionAttachment,
  type ManagedSessionRecord,
} from "../session/session-manager.ts";
import {
  reapplyJournalEntryToPage,
  registerSessionClientJournals,
  registerViewerDispatcher,
  stopRbiV2Streams,
  syncJournalAfterTier1Restore,
} from "../rbi-v2-server.ts";
import type { KeyLeaseManager } from "../state/key-lease.ts";
import { MemorySessionStore, type SessionStore } from "../state/session-store.ts";
import { WebStoragePersistenceBridge } from "../state/web-storage-bridge.ts";
import {
  registerConnectionPolicy,
  unregisterConnectionSecurity,
} from "./session-security-registry.ts";

const NOISY_CDP_METHODS = new Set<string>([
  "Input.dispatchMouseEvent",
  "Input.dispatchKeyEvent",
  "Page.screencastFrameAck",
]);

const IDLE_SESSION_MS = 10 * 60_000;
const MAX_SESSION_MS = 60 * 60_000;
const BACKGROUND_EVENT_DRAIN_INTERVAL_MS = 200;
const CDP_CONNECTION_ID_LENGTH = 10;
const CDP_DEBUG_SESSION_ID_PREFIX_CHARS = 6;

export interface CdpSessionCloseEvent {
  code?: number;
  reason?: string;
  wasClean?: boolean;
}

export interface CdpSessionErrorEvent {
  message?: string;
  type?: string;
  filename?: string;
  lineno?: number;
  colno?: number;
  error?: { name?: string; message?: string; stack?: string };
}

export interface CdpSessionTransport {
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onMessage(handler: (data: string | ArrayBuffer) => void): void;
  onClose(handler: (ev: CdpSessionCloseEvent) => void): void;
  onError(handler: (ev: CdpSessionErrorEvent) => void): void;
}

export interface CdpSessionOptions {
  host: HostCapabilities;
  isolateLoader: HostIsolateLoader;
  connectionId?: string;
  connectionMode?: "page" | "browser";
  initialLayoutMode?: "full" | "off";
  initialUrl?: string | null;
  debug?: boolean;
  cdpDebug?: boolean;
  skipSpeculativeRaster?: boolean;
  fontDefer?: boolean;
  idleMs?: number;
  maxSessionMs?: number;
  exemptIdleDeadline?: boolean;
  isolateCapOverrides?: PageIsolateCapOverrides;
  commandExtension?: EngineCdpCommandExtension;
  requestBlocker?: RequestBlocker;
  externalOutbound?: ExternalOutbound;
  egress?: ExternalOutbound;
  attributionHeaders?: Record<string, string>;
  entrypoint?: SessionEntrypoint;
  environment?: string;
  buildVersion?: string;
  colo?: string;
  telemetry?: {
    factory?: TelemetryFactory;
    request: Request;
    props: unknown;
    env?: Env;
  };
  onCtx?: (dispatchCtx: DispatchCtx) => void;
  onDispatch?: (dispatch: (req: CdpRequest) => Promise<CdpResponse>) => void;
  sessionManager?: SessionManager;
  sessionId?: SessionId;
  userId?: UserId;
  requestedEpoch?: number;
  delegatedAgent?: boolean;
  policyEngine?: PolicyEngine;
  controllerLeases?: ControllerLeaseManager;
  authority?: AuthorityVaultAndChannel;
  tokenizedVault?: import("../authority/mandates.ts").TokenizedFillVault;
  mandateTracker?: import("../authority/mandates.ts").MandateTracker;
  approvalGate?: ApprovalGate;
  auditLog?: SignedAuditLog;
  keyLease?: KeyLeaseManager;
  sessionStore?: SessionStore;
  connectionRole?: ConnectionRole;
  actorRole?: DispatchActorRole;
  ephemeralRequestIsolates?: boolean;
  relayViewerToOwner?: boolean;
}

interface ViewerRelayItem {
  req: CdpRequest;
  viewerConnectionId: string;
  viewerEpoch?: number;
  viewerEmit?: (event: CdpEvent) => void;
  done: boolean;
  response: CdpResponse | null;
}

interface OwnerViewerRelay {
  queue: ViewerRelayItem[];
}

const browserViewerRelays = new WeakMap<BrowserState, OwnerViewerRelay>();

function dispatchViaOwnerRelay(
  browser: BrowserState,
  req: CdpRequest,
  viewerConnectionId: string,
  viewerEpoch: number | undefined,
  isClosing: () => boolean,
  viewerChannel?: { emit: (event: CdpEvent) => void; flush: () => void },
): Promise<CdpResponse> | null {
  const relay = browserViewerRelays.get(browser);
  if (!relay) return null;
  const item: ViewerRelayItem = {
    req,
    viewerConnectionId,
    viewerEpoch,
    viewerEmit: viewerChannel?.emit,
    done: false,
    response: null,
  };
  relay.queue.push(item);
  return new Promise<CdpResponse>((resolve) => {
    const timer = setInterval(() => {
      viewerChannel?.flush();
      if (!item.done && !isClosing()) return;
      clearInterval(timer);
      viewerChannel?.flush();
      resolve(
        item.response ?? {
          id: req.id,
          error: { code: -32000, message: "Viewer connection closed while awaiting owner relay" },
          sessionId: req.sessionId,
        },
      );
    }, 4);
  });
}

const AGENT_OBSERVATION_PREFIXES = [
  "DOM.",
  "Page.",
  "Runtime.",
  "Network.",
  "CSS.",
  "Log.",
  "Fetch.",
  "Accessibility.",
  "Debugger.",
];

function targetMatchesSession(target: TargetState, sessionId: string): boolean {
  if (target.sessions.has(sessionId)) return true;
  for (const frame of target.frames.values()) {
    if (frame.sessions.has(sessionId)) return true;
  }
  return false;
}

function isTargetSessionPaused(browser: BrowserState, sessionId: string | undefined): boolean {
  for (const target of browser.targets.values()) {
    if (target.type !== "page") continue;
    if (!browser.controllerLeases.isAgentObservationPaused(asTargetId(target.targetId))) continue;
    if (sessionId === undefined || targetMatchesSession(target, sessionId)) return true;
  }
  return false;
}

function shouldDropPausedAgentEvent(browser: BrowserState, event: CdpEvent): boolean {
  const isObservation =
    event.method === "Parawing.sceneFrame" ||
    AGENT_OBSERVATION_PREFIXES.some((prefix) => event.method.startsWith(prefix));
  if (!isObservation) return false;
  return isTargetSessionPaused(browser, event.sessionId);
}

const defaultWorkerdSessionManager = new SessionManager();

export interface CdpSessionHandle {
  readonly connectionId: string;
  readonly closed: Promise<void>;
}

async function applyVisualSnapshotToPageScript(
  target: import("./types.ts").TargetState,
  visual: Parameters<RestorableTargetAdapter["restoreVisualState"]>[0],
): Promise<void> {
  if (!target.pageScript) return;
  try {
    await stubQueryDom(target.pageScript, "setViewport", {
      width: visual.viewport.width,
      height: visual.viewport.height,
    });
    for (const draft of visual.formDrafts) {
      const m = /^node:(\d+)$/.exec(draft.fieldKey);
      if (!m) continue;
      const val = draft.value ?? (draft.checked ? "true" : "");
      await stubQueryDom(target.pageScript, "setControlValueAsUser", {
        nodeId: Number(m[1]),
        value: val,
      });
    }
    if (visual.focusedFieldKey) {
      const fm = /^node:(\d+)$/.exec(visual.focusedFieldKey);
      if (fm) await stubQueryDom(target.pageScript, "focus", { nodeId: Number(fm[1]) });
    }
    if (visual.scrollX !== 0 || visual.scrollY !== 0) {
      await stubQueryDom(target.pageScript, "scrollIntoViewIfNeeded", {
        rect: { x: visual.scrollX, y: visual.scrollY, width: 1, height: 1 },
      });
    }
  } catch {}
}

function bindPersistentRuntimeHooks(
  record: ManagedSessionRecord,
  getCtx: () => DispatchCtx,
  connectionMode: "page" | "browser",
): void {
  record.runtime.resolveTargetAdapter = (snap: Tier1TargetSnapshot): RestorableTargetAdapter => {
    const ctx = getCtx();
    let target = ctx.browser.targets.get(snap.targetId);
    if (!target) {
      target = createPageTarget(ctx, "about:blank", undefined, snap.targetId);
      ctx.emit({
        method: "Target.targetCreated",
        params: { targetInfo: { ...visibleInfo(target, connectionMode) } },
      });
    }
    return {
      targetId: asTargetId(target.targetId),
      invalidateHandlesForRestore(): number {
        target.navigateGeneration += 1;
        target.domEpoch += 1;
        releaseAllDomHandles(target);
        for (const k of target.nextStyleSheetRev.keys()) {
          target.nextStyleSheetRev.set(k, (target.nextStyleSheetRev.get(k) ?? 0) + 1);
        }
        return target.navigateGeneration;
      },
      async navigateGetOnly(restoreUrl: string, pendingUnsafeUrl: string | null): Promise<void> {
        const activeCtx = getCtx();
        target.navigationHistory = snap.history.map((h) => ({
          id: h.id,
          url: h.url,
          userTypedURL: h.url,
          title: h.title,
          transitionType: "typed",
          method: h.method ?? "GET",
        }));
        const maxIdx = Math.max(0, target.navigationHistory.length - 1);
        target.navigationHistoryIndex = Math.max(0, Math.min(snap.historyIndex, maxIdx));
        if (target.navigationHistory.length === 0) {
          target.navigationHistory.push({
            id: 1,
            url: restoreUrl,
            userTypedURL: restoreUrl,
            title: "",
            transitionType: "typed",
            method: "GET",
          });
        }
        const sessionId = target.sessions.values().next().value;
        await dispatch(activeCtx, {
          id: -2,
          method: "Page.navigate",
          params: { url: restoreUrl, _parawingInternal: true },
          sessionId,
        });
        target.pendingUnsafeNavigationUrl = pendingUnsafeUrl;
        target.lastNavigationMethod = "GET";
        target.lastSafeGetUrl = restoreUrl;
        await syncJournalAfterTier1Restore(activeCtx.browser, target);
      },
      async restoreVisualState(visual): Promise<void> {
        target.viewportWidth = visual.viewport.width;
        target.viewportHeight = visual.viewport.height;
        target.lastScrollX = visual.scrollX;
        target.lastScrollY = visual.scrollY;
        target.lastFocusedFieldKey = visual.focusedFieldKey;
        target.lastFormDrafts = [...visual.formDrafts];
        await applyVisualSnapshotToPageScript(target, visual);
      },
      async replayClientInput(entry): Promise<boolean> {
        return reapplyJournalEntryToPage(target, entry);
      },
    };
  };

  record.runtime.onReplayInput = async (entry: InputJournalEntry): Promise<void> => {
    const activeCtx = getCtx();
    const target = activeCtx.browser.targets.get(entry.targetId);
    if (!target || !target.pageScript || !entry.kind.startsWith("Input.")) return;
    const sessionId = target.sessions.values().next().value;
    await dispatch(activeCtx, {
      id: -3,
      method: entry.kind,
      params: entry.payload,
      sessionId,
    } as CdpRequest);
  };

  record.runtime.onSuspendRuntime = async (): Promise<void> => {
    const activeCtx = getCtx();
    const activeBrowser = activeCtx.browser;
    stopSceneStreams(activeBrowser, undefined, { preserveInputJournals: true });
    stopRbiV2Streams(activeBrowser, undefined, { preserveInputJournals: true });
    for (const state of activeBrowser.screencasts.values()) {
      state.stopped = true;
      state.wake?.();
    }
    activeBrowser.screencasts.clear();
    for (const target of activeBrowser.targets.values()) {
      if (target.type !== "page") continue;
      await captureTargetVisualState(target);
      try {
        target.pendingNavAbort?.abort();
      } catch {}
      target.pendingNavAbort = null;
      target.navigateGeneration += 1;
      await cancelAndRemoveTargetWheelQueues(activeBrowser, target.targetId);
      teardownOopifStubs(target, "suspend", activeCtx, {
        budget: activeBrowser.workerBudget,
        tasks: activeCtx.host.tasks,
      });
      await retireStub(target, "wsClosed", "SessionManager.suspend", {
        budget: activeBrowser.workerBudget,
        tasks: activeCtx.host.tasks,
      });
      releaseAllDomHandles(target);
    }
  };
}

/** Runs one host-neutral CDP session over a bidirectional message transport. */
export function handleCdpSession(
  transport: CdpSessionTransport,
  opts: CdpSessionOptions,
): CdpSessionHandle {
  const host = opts.host;
  const connectionId = opts.connectionId ?? nanoid(CDP_CONNECTION_ID_LENGTH);
  const connectionMode = opts.connectionMode ?? "browser";
  const initialLayoutMode = opts.initialLayoutMode ?? "full";
  const initialUrl = opts.initialUrl ?? null;
  const debug = opts.debug ?? false;
  const cdpDebug = opts.cdpDebug ?? false;
  const idleMs = opts.idleMs ?? IDLE_SESSION_MS;
  const maxSessionMs = opts.maxSessionMs ?? MAX_SESSION_MS;
  const isolateCapOverrides = opts.isolateCapOverrides ?? {};

  let resolveClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  host.tasks.run(closed);

  let sendCount = 0;
  let sendBytesTotal = 0;
  let sendFailCount = 0;
  let screencastFramesSent = 0;
  let screencastFrameBytesSent = 0;
  let screencastAcksReceived = 0;
  let wsClosing = false;
  let transportClosed = false;
  let memAtClose: ReturnType<typeof engineMemoryBreakdown> | null = null;

  const transmit = (payload: unknown): void => {
    try {
      const str = JSON.stringify(payload);
      if (
        payload &&
        typeof payload === "object" &&
        (payload as { method?: string }).method === "Page.screencastFrame"
      ) {
        screencastFramesSent++;
        screencastFrameBytesSent += str.length;
        if (screencastFramesSent % 5 === 1) {
          console.log(
            `[parawing-ws] screencastFrame #${screencastFramesSent} ` +
              `bytes=${str.length} totalBytes=${screencastFrameBytesSent} ` +
              `acksReceived=${screencastAcksReceived}`,
          );
        }
      }
      transport.send(str);
      sendCount++;
      sendBytesTotal += str.length;
    } catch (err) {
      sendFailCount++;
      const msg =
        err instanceof Error
          ? `${err.name}: ${err.message}`
          : err && typeof err === "object" && "message" in err
            ? `${(err as { name?: string }).name ?? "Error"}: ${(err as { message?: string }).message ?? ""}`
            : String(err);
      console.error(
        `[parawing-ws] send failed (#${sendFailCount}, ` +
          `sendCount=${sendCount}, totalBytes=${sendBytesTotal}): ${msg}`,
      );
    }
  };

  const send = (payload: unknown): void => {
    if (wsClosing) {
      sendFailCount++;
      return;
    }
    transmit(payload);
  };

  let persistentRecord: ManagedSessionRecord | null = null;
  let connectionEpoch: number | undefined;
  let browser: BrowserState;

  if (opts.sessionManager && opts.sessionId) {
    persistentRecord = opts.sessionManager.get(opts.sessionId) ?? null;
    if (!persistentRecord) {
      const ownerUserId = opts.userId ?? asUserId("anonymous");
      persistentRecord = opts.sessionManager.create({
        sessionId: opts.sessionId,
        userId: ownerUserId,
        store: opts.sessionStore,
        authority: opts.authority,
        auditLog: opts.auditLog,
        keyLease: opts.keyLease,
        approvalGate: opts.approvalGate,
        policyEngine:
          opts.policyEngine ??
          new PolicyEngine({
            delegatedAgent: opts.delegatedAgent ?? false,
            auditLog: opts.auditLog,
          }),
        controllerLeases: opts.controllerLeases,
      });
    }
  }

  const isPersistentSession = Boolean(opts.sessionManager && persistentRecord && opts.sessionId);
  const effectiveUserId = opts.userId ?? persistentRecord?.userId;
  const connId = asConnectionId(connectionId);
  let dispatchCtx!: DispatchCtx;

  const degradeToViewer = (err: StaleEpochError): ConnectionAttachment => {
    const existing = persistentRecord?.connections.get(connId);
    const viewer: ConnectionAttachment = existing ?? {
      connectionId: connId,
      sessionId: opts.sessionId!,
      userId: effectiveUserId!,
      epoch: opts.requestedEpoch ?? persistentRecord?.epoch ?? 0,
      role: "viewer",
      attachedAt: Date.now(),
      emit: (ev) => send(ev),
    };
    if (persistentRecord) persistentRecord.connections.set(connId, viewer);
    send({
      method: "Parawing.sessionAttached",
      params: {
        sessionId: opts.sessionId,
        userId: effectiveUserId,
        connectionId,
        epoch: err.expectedEpoch,
        requestedEpoch: err.receivedEpoch,
        role: "viewer",
        stale: true,
      },
    });
    return viewer;
  };

  let attachment: ConnectionAttachment | null = null;
  let resumePromise: Promise<void> | null = null;
  let willResumeSession = false;
  let willAsyncRestoreTier1 = false;

  if (opts.sessionManager && persistentRecord && opts.sessionId && effectiveUserId) {
    const explicitViewer = opts.connectionRole === "viewer";
    const isLowerEpoch =
      opts.requestedEpoch !== undefined && opts.requestedEpoch < persistentRecord.epoch;
    if (
      !explicitViewer &&
      !isLowerEpoch &&
      (persistentRecord.status === "suspended" || persistentRecord.status === "detached")
    ) {
      willResumeSession = true;
      willAsyncRestoreTier1 =
        persistentRecord.status === "suspended" ||
        (persistentRecord.runtime.targets.size === 0 &&
          loadLatestTier1Checkpoint(persistentRecord.runtime.store) !== undefined);
    } else {
      try {
        attachment = opts.sessionManager.attach({
          sessionId: opts.sessionId,
          userId: effectiveUserId,
          connectionId: connId,
          requestedEpoch: opts.requestedEpoch,
          role: opts.connectionRole,
          emit: (ev) => send(ev),
        });
        if (attachment.role !== "owner") {
          send({
            method: "Parawing.sessionAttached",
            params: {
              sessionId: opts.sessionId,
              userId: effectiveUserId,
              connectionId,
              epoch: attachment.epoch,
              role: "viewer",
              stale: false,
            },
          });
        }
      } catch (err) {
        if (err instanceof StaleEpochError) {
          attachment = degradeToViewer(err);
        } else {
          throw err;
        }
      }
    }
  }
  if (attachment) {
    connectionEpoch = attachment.epoch;
  }

  const analytics = new ParawingAnalytics(
    {
      sessionId: connectionId,
      entrypoint: opts.entrypoint ?? "puppeteer",
      connectionMode,
      environment: opts.environment ?? host.config.environment,
      buildVersion: opts.buildVersion ?? host.config.buildVersion,
      colo: opts.colo ?? "",
    },
    new SafePerformance(host.clock.monotonic),
    opts.telemetry
      ? {
          factory: opts.telemetry.factory,
          request: opts.telemetry.request,
          props: opts.telemetry.props,
          env: opts.telemetry.env,
          tasks: host.tasks,
        }
      : undefined,
  );

  const requestBlocker = opts.requestBlocker;
  if (requestBlocker) registerRequestBlocker(connectionId, requestBlocker);

  if (persistentRecord?.runtime.persistentBrowser) {
    browser = persistentRecord.runtime.persistentBrowser;
  } else {
    const rt = persistentRecord?.runtime;
    const store = rt?.store ?? opts.sessionStore ?? new MemorySessionStore();
    const webStorage = rt?.webStorage ?? new WebStoragePersistenceBridge(store);
    const controllerLeases =
      rt?.controllerLeases ?? opts.controllerLeases ?? new ControllerLeaseManager();
    const policyEngine =
      rt?.policyEngine ??
      opts.policyEngine ??
      new PolicyEngine({
        delegatedAgent: opts.delegatedAgent ?? false,
        auditLog: rt?.auditLog ?? opts.auditLog,
      });

    const emitSinkRef: { current: (event: CdpEvent) => void } = {
      current: (ev) => browser.emitSink(ev),
    };
    const networkEvents = new NetworkEventTracker((ev) => emitSinkRef.current(ev), connectionId);
    const cookies = createCookieJar();
    const workerBudget = new DynamicWorkerBudget();

    browser = {
      targets: rt?.targets ?? new Map(),
      sandboxOutbound: createSandboxOutboundOverride(
        host,
        opts.externalOutbound,
        opts.externalOutbound ? undefined : opts.egress,
      ),
      contexts: new Map(),
      nextBrowserContextId: 1,
      autoAttach: false,
      flatten: false,
      cookies,
      screencasts: new Map(),
      styleCache: new StyleCache(),
      imageCache: new Map(),
      networkEvents,
      layoutMode: initialLayoutMode,
      cdpDebug,
      isolateCapOverrides,
      connectionMode,
      ttyKeyboard: false,
      preNavScripts: new Map<string, string>(),
      learnedInsertedScripts: new Map(),
      pendingBindings: new Set<string>(),
      execContextSeq: 3,
      runtimeEnabledSessions: new Set<string>(),
      rendererManager: null,
      workerBudget,
      dedicatedWorkers: new DedicatedWorkers(workerBudget, host.tasks),
      skipSpeculativeRaster: opts.skipSpeculativeRaster ?? false,
      skipPartialRaster: host.config.disablePartialRaster,
      // Deferred-fonts opt-in. See BrowserState.fontDefer.
      fontDefer: opts.fontDefer ?? false,
      rendererSessionId: null,
      engineSessionId: null,
      wsClosing: false,
      attributionHeaders: opts.attributionHeaders ?? {},
      sessionId: rt?.sessionId ?? opts.sessionId,
      userId: rt?.userId ?? effectiveUserId,
      sessionEpoch: connectionEpoch,
      connectionRole: attachment?.role,
      persistentSession: isPersistentSession,
      delegatedAgent: policyEngine.delegatedAgent,
      policyEngine,
      controllerLeases,
      store,
      webStorage,
      auditLog: rt?.auditLog ?? opts.auditLog,
      authority: rt?.authority ?? opts.authority,
      tokenizedVault: opts.tokenizedVault,
      mandateTracker: opts.mandateTracker,
      approvalGate: rt?.approvalGate ?? opts.approvalGate,
      keyLease: rt?.keyLease ?? opts.keyLease,
      emitSink: send,
    };

    networkEvents.setPolicyHooks({
      isObservationPaused: (sessionIds) => {
        if (sessionIds.length === 0) return isTargetSessionPaused(browser, undefined);
        return sessionIds.some((sid) => isTargetSessionPaused(browser, sid));
      },
      sanitizeHeaders: (headers) => browser.policyEngine.redactHeadersForAgent(headers),
    });

    browser.controllerLeases.subscribe((targetId, active) => {
      if (active) return;
      browser.screencasts.get(targetId)?.wake?.();
      wakeSceneStream(browser, targetId);
      if (browser.wsClosing) return;
      const target = browser.targets.get(targetId);
      if (!target || target.domEnabledSessions.size === 0) return;
      for (const sid of target.domEnabledSessions) {
        browser.emitSink({
          method: "DOM.documentUpdated",
          sessionId: sid.length === 0 ? undefined : sid,
        });
      }
    });

    registerTracker(connectionId, networkEvents);
    registerCookieJar(connectionId, cookies);
    registerConnectionPolicy(connectionId, policyEngine);

    if (rt && attachment?.role === "owner") {
      rt.persistentBrowser = browser;
    }
  }
  if (persistentRecord) {
    registerSessionClientJournals(browser, persistentRecord.runtime.clientJournals);
  }

  const networkEvents = browser.networkEvents;
  const workerBudget = browser.workerBudget;
  const viewerPendingEvents: CdpEvent[] = [];
  const flushViewerPendingEvents = (): void => {
    if (wsClosing || transportClosed || viewerPendingEvents.length === 0) return;
    const batch = viewerPendingEvents.splice(0);
    for (const ev of batch) send(ev);
  };
  const viewerEmit = (event: CdpEvent): void => {
    if (wsClosing || transportClosed) return;
    viewerPendingEvents.push(event);
  };
  const emit = (event: CdpEvent): void => {
    if (wsClosing) return;
    if (attachment?.role === "viewer") {
      send(event);
      return;
    }
    if (shouldDropPausedAgentEvent(browser, event)) return;
    if (browser.emitSink === send) {
      browser.emitSink(event);
    }
  };

  browser.workerBudget.countPageTargets = () => {
    let n = 0;
    for (const t of browser.targets.values()) {
      if (t.type !== "page") continue;
      if (t.pageScriptLease || t.navigateGeneration > 0) n += 1;
    }
    return n;
  };

  dispatchCtx = {
    browser,
    emit,
    isClosed: () => wsClosing,
    commandExtension: opts.commandExtension,
    requestBlocker,
    host,
    isolateLoader: opts.isolateLoader,
    connectionId,
    analytics,
    sessionManager: opts.sessionManager,
    connectionEpoch,
    connectionRole: attachment?.role,
    actorRole: opts.actorRole,
  };

  const tracedDispatch = (req: CdpRequest): Promise<CdpResponse> => {
    if (opts.relayViewerToOwner && attachment?.role === "viewer") {
      const relayed = dispatchViaOwnerRelay(
        browser,
        req,
        connectionId,
        connectionEpoch,
        () => wsClosing || transportClosed,
        { emit: viewerEmit, flush: flushViewerPendingEvents },
      );
      if (relayed) return relayed;
    }
    return NOISY_CDP_METHODS.has(req.method)
      ? dispatch(dispatchCtx, req)
      : traceSpan(host.tracer, "cdp." + req.method, () => dispatch(dispatchCtx, req), {
          connectionId,
        });
  };
  const viewerRelayActive = Boolean(opts.relayViewerToOwner && opts.connectionRole !== "viewer");
  const dispatchFromViewerChannel = (req: CdpRequest): Promise<CdpResponse> => {
    if (viewerRelayActive) {
      const relayed = dispatchViaOwnerRelay(
        browser,
        req,
        connectionId,
        connectionEpoch,
        () => wsClosing || transportClosed,
      );
      if (relayed) return relayed;
    }
    return tracedDispatch(req);
  };

  const activateOwnerConnection = (attached: ConnectionAttachment): void => {
    attachment = attached;
    connectionEpoch = attached.epoch;
    dispatchCtx.connectionEpoch = attached.epoch;
    dispatchCtx.connectionRole = attached.role;
    if (attached.role !== "owner") return;
    browser.emitSink = send;
    browser.sessionEpoch = attached.epoch;
    browser.connectionRole = attached.role;
    browser.wsClosing = false;
    registerTracker(connectionId, browser.networkEvents);
    registerCookieJar(connectionId, browser.cookies);
    registerConnectionPolicy(connectionId, browser.policyEngine);
    if (persistentRecord) {
      persistentRecord.runtime.persistentBrowser = browser;
      bindPersistentRuntimeHooks(persistentRecord, () => dispatchCtx, connectionMode);
      persistentRecord.runtime.onDestroyRuntime = () => {
        teardownConnection();
      };
    }
    if (!browserViewerRelays.has(browser)) {
      browserViewerRelays.set(browser, { queue: [] });
    }
    registerViewerDispatcher(browser, dispatchFromViewerChannel);
  };

  if (!isPersistentSession) {
    browserViewerRelays.set(browser, { queue: [] });
    registerViewerDispatcher(browser, dispatchFromViewerChannel);
  } else if (attachment?.role === "owner") {
    activateOwnerConnection(attachment);
  }

  try {
    opts.onCtx?.(dispatchCtx);
    opts.onDispatch?.(tracedDispatch);
  } catch (err) {
    console.warn("[parawing-ws] in-process consumer threw:", err);
  }

  if (
    willResumeSession &&
    opts.sessionManager &&
    persistentRecord &&
    opts.sessionId &&
    effectiveUserId
  ) {
    const pendingResume = opts.sessionManager.resume({
      sessionId: opts.sessionId,
      userId: effectiveUserId,
      connectionId: connId,
      requestedEpoch: opts.requestedEpoch,
      emit: (ev) => send(ev),
      onAttached: (resumedAttachment) => {
        activateOwnerConnection(resumedAttachment);
      },
    });
    resumePromise = pendingResume.then(
      (res) => {
        attachment = res.attachment;
        connectionEpoch = res.attachment.epoch;
        dispatchCtx.connectionEpoch = connectionEpoch;
        dispatchCtx.connectionRole = res.attachment.role;
        ensureBrowserTarget(dispatchCtx);
        if (![...browser.targets.values()].some((t) => t.type === "page")) {
          const initialPage = createPageTarget(dispatchCtx, "about:blank");
          send({
            method: "Target.targetCreated",
            params: { targetInfo: { ...visibleInfo(initialPage, connectionMode) } },
          });
        }
      },
      (err) => {
        if (err instanceof StaleEpochError) {
          attachment = degradeToViewer(err);
          connectionEpoch = attachment.epoch;
          dispatchCtx.connectionEpoch = connectionEpoch;
          dispatchCtx.connectionRole = attachment.role;
          return;
        }
        throw err;
      },
    );
  } else if (!willAsyncRestoreTier1) {
    if (browser.targets.size === 0) {
      ensureBrowserTarget(dispatchCtx);
      const initialPage = createPageTarget(dispatchCtx, "about:blank");
      send({
        method: "Target.targetCreated",
        params: { targetInfo: { ...visibleInfo(initialPage, connectionMode) } },
      });
    } else {
      for (const existingTarget of browser.targets.values()) {
        if (existingTarget.type !== "page") continue;
        send({
          method: "Target.targetCreated",
          params: { targetInfo: { ...visibleInfo(existingTarget, connectionMode) } },
        });
      }
    }
  }

  const sessionOpenedAt = Date.now();
  let lastClientMessageAt = sessionOpenedAt;
  let deadlineFired = false;

  const closeIfExpired = (): boolean => {
    if (deadlineFired || wsClosing) return deadlineFired;
    const now = Date.now();
    const idleExempt = opts.exemptIdleDeadline === true;
    const reason =
      now - sessionOpenedAt > maxSessionMs
        ? `parawing: session exceeded ${maxSessionMs} ms`
        : !idleExempt && now - lastClientMessageAt > idleMs
          ? `parawing: idle for ${idleMs} ms with no client CDP traffic`
          : null;
    if (reason === null) return false;
    deadlineFired = true;
    console.warn(`[parawing-ws] closing session ${connectionId}: ${reason}`);
    try {
      transport.close(1001, reason);
    } catch {}
    return true;
  };

  const viewerRelayTimer =
    opts.relayViewerToOwner && opts.connectionRole !== "viewer"
      ? setInterval(() => {
          if (wsClosing || (isPersistentSession && attachment?.role !== "owner")) return;
          const relay = browserViewerRelays.get(browser);
          if (!relay || relay.queue.length === 0) return;
          const batch = relay.queue.splice(0);
          for (const item of batch) {
            const viewerCtx: DispatchCtx = {
              ...dispatchCtx,
              emit: item.viewerEmit ?? (() => {}),
              actorConnectionId: item.viewerConnectionId,
              connectionEpoch: item.viewerEpoch,
              connectionRole: "viewer",
            };
            void dispatch(viewerCtx, item.req).then(
              (res) => {
                item.response = res;
                item.done = true;
              },
              (err) => {
                item.response = {
                  id: item.req.id,
                  error: { code: -32000, message: String(err) },
                  sessionId: item.req.sessionId,
                };
                item.done = true;
              },
            );
          }
        }, 8)
      : null;

  const drainTimer = setInterval(() => {
    if (closeIfExpired()) return;
    if (attachment?.role === "viewer") flushViewerPendingEvents();
    if ((isPersistentSession && attachment?.role !== "owner") || browser.targets.size === 0) return;
    browser.controllerLeases.expire();
    networkEvents.drain();
    drainInterception(connectionId);
    for (const t of browser.targets.values()) {
      pumpBackgroundEvents(dispatchCtx, t);
    }
  }, BACKGROUND_EVENT_DRAIN_INTERVAL_MS);

  if (initialUrl !== null) {
    const syntheticReq: CdpRequest = {
      id: -1,
      method: "Page.navigate",
      params: { url: initialUrl },
    };
    void (async () => {
      try {
        const response = await tracedDispatch(syntheticReq);
        if (debug) {
          console.log("[cdp auto-navigate]", initialUrl, "->", JSON.stringify(response));
        }
      } catch (err) {
        console.error("[cdp auto-navigate threw]", err);
      }
    })();
  }

  const rejoinLocalTrace = localTraceEventWrap(host);
  const arrivalClock = () => host.clock.now();

  transport.onMessage((rawData) => {
    // Preserve queue delay for request-boundary timing.
    const arrivedAt = arrivalClock();
    lastClientMessageAt = Date.now();
    void rejoinLocalTrace(async () => {
      if (resumePromise) await resumePromise;
      const parsed = parseCdpRequest(
        typeof rawData === "string" ? rawData : new TextDecoder().decode(rawData),
      );
      if (!parsed.ok) {
        send(parsed.error);
        return;
      }
      const req = parsed.request;
      markArrival(req, arrivedAt);

      if (debug && !NOISY_CDP_METHODS.has(req.method)) {
        console.log(
          "[cdp <-]",
          req.id,
          req.method,
          req.sessionId ? `(s=${req.sessionId.slice(0, CDP_DEBUG_SESSION_ID_PREFIX_CHARS)})` : "",
        );
      }

      if (req.method === "Page.screencastFrameAck") {
        screencastAcksReceived++;
      }

      try {
        const response = await tracedDispatch(req);
        if (attachment?.role === "viewer") flushViewerPendingEvents();
        if (debug && !NOISY_CDP_METHODS.has(req.method)) {
          console.log("[cdp ->]", req.id, req.method, "ok");
        }
        if (req.method === "Parawing.destroySession" && wsClosing && !transportClosed) {
          // Deliver destroySession RPC confirmation even though teardown marked wsClosing.
          transmit(response);
        } else {
          send(response);
        }
        // Chrome exits after it answers Browser.close, which drops the socket. Clients behind
        // a proxy wait for that drop, so `browser.close()` hangs unless the engine closes too.
        if (req.method === "Browser.close" && !("error" in response)) {
          try {
            transport.close(1000, "Browser.close");
          } catch {}
        }
      } catch (err) {
        console.error("[cdp dispatch threw]", req.method, err);
        send({
          id: req.id,
          error: { code: -32000, message: String(err) },
          sessionId: req.sessionId,
        });
      }
    });
  });

  // A socket can terminate with an error, a close, or both. Release everything once, from
  // whichever arrives first; persistent sessions detach on close and tear down only on destroy.
  let tornDown = false;
  let detached = false;

  function teardownConnection(): void {
    if (tornDown) return;
    tornDown = true;
    clearInterval(drainTimer);
    if (viewerRelayTimer !== null) clearInterval(viewerRelayTimer);
    wsClosing = true;
    browser.wsClosing = true;
    stopSceneStreams(browser);
    stopRbiV2Streams(browser);
    for (const state of browser.screencasts.values()) {
      state.stopped = true;
      state.wake?.();
    }
    browser.screencasts.clear();
    if (browser.emitSink === send) {
      browser.emitSink = () => {};
    }
    try {
      browser.rendererManager?.close("engine WS closed");
    } catch {}
    unregisterTracker(connectionId);
    memAtClose = engineMemoryBreakdown(browser);
    networkEvents.dispose();
    unregisterOutboundFilters(connectionId);
    unregisterRequestBlocker(connectionId);
    unregisterConnectionSecurity(connectionId);
    unregisterInterception(connectionId);
    disposeWebMcpConnection(connectionId);
    unregisterConnectionCookieJars(connectionId, browser.contexts.keys());
    dropConnectionImages(connectionId);
    unregisterIsolateLimitListenersFor(connectionId);
    browser.dedicatedWorkers.terminateAll("engine WS closed");
    for (const target of browser.targets.values()) {
      try {
        target.pendingNavAbort?.abort();
      } catch {}
      target.pendingNavAbort = null;
      target.navigateGeneration++;
      void cancelAndRemoveTargetWheelQueues(browser, target.targetId);
      teardownOopifStubs(target, "engine WS closed", undefined, {
        budget: browser.workerBudget,
        tasks: host.tasks,
      });
      void retireStub(target, "wsClosed", "engine WS closed", {
        budget: browser.workerBudget,
        tasks: host.tasks,
      });
      releaseAllDomHandles(target);
    }
    rejoinLocalTrace(() => endLocalTraceSession(host));
    resolveClosed();
  }

  function detachOrTeardownSocket(): void {
    if (!isPersistentSession || !opts.sessionManager || !opts.sessionId) {
      teardownConnection();
      return;
    }
    if (detached) return;
    detached = true;
    clearInterval(drainTimer);
    if (viewerRelayTimer !== null) clearInterval(viewerRelayTimer);
    wsClosing = true;
    if (
      opts.ephemeralRequestIsolates &&
      attachment?.role === "owner" &&
      persistentRecord?.status === "active"
    ) {
      try {
        opts.sessionManager.checkpointSession(opts.sessionId, "detach");
      } catch {}
      stopSceneStreams(browser, undefined, { preserveInputJournals: true });
      stopRbiV2Streams(browser, undefined, { preserveInputJournals: true });
      for (const state of browser.screencasts.values()) {
        state.stopped = true;
        state.wake?.();
      }
      browser.screencasts.clear();
      try {
        browser.rendererManager?.close("session detached");
      } catch {}
      for (const t of browser.targets.values()) {
        if (t.type !== "page") continue;
        try {
          t.pendingNavAbort?.abort();
        } catch {}
        t.pendingNavAbort = null;
        t.navigateGeneration += 1;
        void cancelAndRemoveTargetWheelQueues(browser, t.targetId);
        teardownOopifStubs(t, "session detached", undefined, {
          budget: browser.workerBudget,
          tasks: host.tasks,
        });
        void retireStub(t, "wsClosed", "session detached", {
          budget: browser.workerBudget,
          tasks: host.tasks,
        });
        releaseAllDomHandles(t);
      }
      opts.sessionManager.markForceTier1OnResume(opts.sessionId);
    }
    opts.sessionManager.detach(opts.sessionId, asConnectionId(connectionId));
    if (browser.emitSink === send) {
      browser.emitSink = () => {};
    }
    resolveClosed();
  }

  transport.onClose((closeEv) => {
    transportClosed = true;
    emitSessionEnd(analytics, {
      endReason: "close",
      closeCode: closeEv.code ?? 0,
      wasClean: closeEv.wasClean ? 1 : 0,
      workerLeases: workerBudget.snapshot(),
    });
    detachOrTeardownSocket();
    const mem = memAtClose ?? engineMemoryBreakdown(browser);
    console.log(
      `[parawing-ws] close: code=${closeEv.code} reason="${closeEv.reason}" wasClean=${closeEv.wasClean} ` +
        `sendCount=${sendCount} sendBytesTotal=${sendBytesTotal} ` +
        `sendFailCount=${sendFailCount} ` +
        `screencastFramesSent=${screencastFramesSent} ` +
        `screencastFrameBytesSent=${screencastFrameBytesSent} ` +
        `screencastAcksReceived=${screencastAcksReceived} ` +
        `engineWasmBytes=${mem.wasmBytes} ` +
        `engineWasmDeltaBytes=${mem.wasmDeltaBytes} ` +
        `retainedBodyBytes=${mem.retainedBodyBytes} ` +
        `retainedBodyBytesIsolate=${mem.retainedBodyBytesIsolate} ` +
        `retainedRequestCount=${mem.retainedRequestCount} ` +
        `retainedImageBytes=${mem.retainedImageBytes} ` +
        `retainedImageCount=${mem.retainedImageCount} ` +
        `fontAssetCacheBytes=${mem.fontAssetCacheBytes} ` +
        `engineAccountedBytes=${mem.accountedBytes}`,
    );
  });

  transport.onError((e) => {
    transportClosed = true;
    const msg = e.error?.message ?? e.message ?? "";
    const postClose = wsClosing && msg.includes("Network connection lost");
    if (!wsClosing) {
      emitSessionEnd(analytics, {
        endReason: "error",
        closeCode: 0,
        wasClean: 0,
        workerLeases: workerBudget.snapshot(),
      });
    }
    const detail = {
      message: e.message,
      type: e.type,
      filename: e.filename,
      lineno: e.lineno,
      colno: e.colno,
      error_name: e.error?.name,
      error_message: e.error?.message,
      counters: {
        sendCount,
        sendBytesTotal,
        sendFailCount,
        screencastFramesSent,
        screencastFrameBytesSent,
        screencastAcksReceived,
      },
    };
    if (postClose) {
      console.log(`[parawing-ws] post-close async settled: ${JSON.stringify(detail)}`);
    } else {
      console.error(`[parawing-ws] error: ${JSON.stringify(detail)}`);
    }
    detachOrTeardownSocket();
  });

  return { connectionId, closed };
}

/**
 * Accepts a CDP WebSocket request and returns a 101 response with its session ID.
 * `host.tasks.run` keeps connection state alive until the socket closes or errors.
 */
export async function handleWebSocket(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  onCtx?: (dispatchCtx: DispatchCtx) => void,
  opts?: {
    exemptIdleDeadline?: boolean;
    externalOutbound?: ExternalOutbound;
    onDispatch?: (dispatch: (req: CdpRequest) => Promise<CdpResponse>) => void;
    host?: EngineHost;
  },
): Promise<Response> {
  // Also used as the analytics session ID and log correlation key.
  const connectionId = nanoid(CDP_CONNECTION_ID_LENGTH);
  const options = resolveConnectionOptions(request, connectionId, opts?.host);

  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
  server.accept();

  let initialLayoutMode: "full" | "off" = "full";
  // Optional initialUrl from the `/?url=` inspector redirect; navigate without
  // requiring the inspector user to enter the URL manually.
  let initialUrl: string | null = null;
  let debug = false;
  let cdpDebug = false;
  let idleMs = IDLE_SESSION_MS;
  let maxSessionMs = MAX_SESSION_MS;
  const isolateCapOverrides: PageIsolateCapOverrides = {};
  let connectionMode: "page" | "browser" = "browser";
  let sessionIdParam: SessionId | undefined;
  let userIdParam: UserId | undefined;
  let requestedEpoch: number | undefined;
  let connectionRole: ConnectionRole | undefined;
  let delegatedAgent = false;
  try {
    const wsUrl = new URL(request.url);
    if (wsUrl.pathname.startsWith("/devtools/page/")) {
      connectionMode = "page";
    }
    const ksSessionRaw = wsUrl.searchParams.get("ksSessionId");
    if (ksSessionRaw) sessionIdParam = asSessionId(ksSessionRaw);
    const ksUserRaw = wsUrl.searchParams.get("ksUserId");
    if (ksUserRaw) userIdParam = asUserId(ksUserRaw);
    const ksEpochRaw = Number.parseInt(wsUrl.searchParams.get("ksEpoch") ?? "", 10);
    if (Number.isFinite(ksEpochRaw) && ksEpochRaw > 0) requestedEpoch = ksEpochRaw;
    if (wsUrl.searchParams.get("ksRole") === "viewer") connectionRole = "viewer";
    delegatedAgent = wsUrl.searchParams.get("ksDelegated") === "1";
    const param = wsUrl.searchParams.get("layout");
    if (param === "off" || param === "0" || param === "false") {
      initialLayoutMode = "off";
    }
    const iu = wsUrl.searchParams.get("initialUrl");
    if (iu) {
      try {
        const parsed = new URL(iu);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
          initialUrl = parsed.toString();
        }
      } catch {}
    }
    const dbg = wsUrl.searchParams.get("debug");
    if (dbg === "1" || dbg === "true") debug = true;
    const cdpDbg = wsUrl.searchParams.get("cdpDebug");
    if (cdpDbg === "1" || cdpDbg === "true") cdpDebug = true;
    const cpuCapRaw = Number.parseInt(wsUrl.searchParams.get("ksCpuCapMs") ?? "", 10);
    if (Number.isFinite(cpuCapRaw) && cpuCapRaw > 0) isolateCapOverrides.cpuMs = cpuCapRaw;
    const wallCapRaw = Number.parseInt(wsUrl.searchParams.get("ksWallCapMs") ?? "", 10);
    if (Number.isFinite(wallCapRaw) && wallCapRaw > 0) isolateCapOverrides.wallMs = wallCapRaw;
    const idleRaw = Number.parseInt(wsUrl.searchParams.get("ksIdleMs") ?? "", 10);
    if (Number.isFinite(idleRaw) && idleRaw > 0) idleMs = Math.min(idleMs, idleRaw);
    const maxSessionRaw = Number.parseInt(wsUrl.searchParams.get("ksMaxSessionMs") ?? "", 10);
    if (Number.isFinite(maxSessionRaw) && maxSessionRaw > 0) {
      maxSessionMs = Math.min(maxSessionMs, maxSessionRaw);
    }
  } catch {}

  const host = opts?.host?.createCapabilities?.(env, ctx) ?? createWorkersCapabilities(env, ctx);
  const isolateLoader =
    opts?.host?.createIsolateLoader?.(env, ctx, host) ?? createWorkersIsolateLoader(env, ctx, host);

  const transport: CdpSessionTransport = {
    send: (data) => server.send(data),
    close: (code, reason) => server.close(code, reason),
    onMessage: (handler) => {
      server.addEventListener("message", (event) => {
        handler(event.data as string | ArrayBuffer);
      });
    },
    onClose: (handler) => {
      server.addEventListener("close", (ev) => {
        const closeEv = ev as CloseEvent;
        handler({ code: closeEv.code, reason: closeEv.reason, wasClean: closeEv.wasClean });
      });
    },
    onError: (handler) => {
      server.addEventListener("error", (ev) => {
        const e = ev as ErrorEvent & {
          error?: { name?: string; message?: string; stack?: string };
        };
        handler({
          message: e.message,
          type: e.type,
          filename: e.filename,
          lineno: e.lineno,
          colno: e.colno,
          error: e.error,
        });
      });
    },
  };

  handleCdpSession(transport, {
    host,
    isolateLoader,
    connectionId,
    connectionMode,
    initialLayoutMode,
    initialUrl,
    debug,
    cdpDebug,
    skipSpeculativeRaster: request.headers.get(SKIP_SPECULATIVE_RASTER_HEADER) === "1",
    fontDefer: options.fontDefer,
    idleMs,
    maxSessionMs,
    exemptIdleDeadline: opts?.exemptIdleDeadline,
    isolateCapOverrides,
    // Host bindings belong to this WebSocket's lifetime, not a worker-global cache.
    commandExtension: opts?.host?.createCdpCommandExtension?.(env),
    requestBlocker: opts?.host?.requestBlocker,
    externalOutbound: opts?.externalOutbound,
    egress: opts?.externalOutbound ? undefined : opts?.host?.egress?.(env, ctx),
    attributionHeaders: pickHeaders(request, opts?.host?.attributionHeaders),
    entrypoint: options.entrypoint,
    colo: (request.cf as { colo?: string } | undefined)?.colo ?? "",
    telemetry: {
      factory: opts?.host?.telemetry,
      request,
      props: ctx.props,
      env,
    },
    onCtx,
    onDispatch: opts?.onDispatch,
    sessionManager:
      opts?.host?.sessionManager ?? (sessionIdParam ? defaultWorkerdSessionManager : undefined),
    sessionId: sessionIdParam,
    userId: userIdParam,
    requestedEpoch,
    connectionRole,
    delegatedAgent,
    sessionStore: opts?.host?.createSessionStore?.(connectionId, env),
    ephemeralRequestIsolates: !opts?.host?.sessionManager,
    relayViewerToOwner: true,
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { [SESSION_ID_HEADER]: connectionId },
  });
}

function pickHeaders(request: Request, names: readonly string[] = []): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of names) {
    const v = request.headers.get(name);
    if (v) out[name] = v;
  }
  return out;
}

function visibleInfo(
  t: { targetId: string; type: string; url: string; title: string },
  connectionMode: "page" | "browser",
) {
  return {
    targetId: t.targetId,
    type: t.type,
    title: t.title,
    url: t.url,
    attached: connectionMode === "page" && t.type === "page",
    canAccessOpener: false,
    browserContextId: "default",
  };
}
