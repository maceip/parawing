// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Routes CDP commands to target sessions, domain handlers, and host extensions.

import type { BrowserState, CdpRequest, CdpResponse, EventEmitter, TargetState } from "./types.ts";
import type { RequestBlocker } from "../request-blocker.ts";
import { CDP_COMMAND_UNHANDLED } from "./types.ts";
import {
  handleTarget,
  handleRendererSession,
  handleEngineSession,
  handleOopifSession,
  findOopifFrameBySession,
} from "./target.ts";
import { handlePage } from "./page.ts";
import { handleRuntime } from "./runtime.ts";
import { handleDom } from "./dom.ts";
import { handleNetwork } from "./network.ts";
import { handleLog } from "./log.ts";
import { handleFetch } from "./fetch.ts";
import { handleInput } from "./input.ts";
import { handleParawing } from "./parawing.ts";
import { handleWebMcp } from "./webmcp.ts";
import { handleDebugger } from "./debugger.ts";
import { handleCss } from "./css.ts";
import { handleAccessibility } from "./accessibility.ts";
import { sessionOf } from "./page-session.ts";
import { clampViewport } from "./viewport.ts";
import type { ParawingAnalytics } from "../observability.ts";
import type { HostCapabilities } from "../host-capabilities.ts";
import type { HostIsolateLoader } from "../isolate-loader.ts";
import type { DispatchActorRole } from "../policy/controller-lease.ts";
import { PolicyDecisionError } from "../policy/policy-engine.ts";
import {
  asConnectionId,
  asTargetId,
  StaleEpochError,
  type ConnectionRole,
  type TargetId,
} from "../session/identities.ts";
import type { SessionManager } from "../session/session-manager.ts";

export interface EngineCdpCommandRequest {
  id: number;
  method: string;
  params?: unknown;
  sessionId?: string;
}

export type EngineCdpCommandResult = { handled: true; result: unknown } | { handled: false };

export type EngineCdpCommandExtension = (
  ctx: DispatchCtx,
  req: EngineCdpCommandRequest,
) => Promise<EngineCdpCommandResult>;

export interface DispatchCtx {
  browser: BrowserState;
  emit: EventEmitter;
  isClosed?: () => boolean;
  commandExtension?: EngineCdpCommandExtension;
  /** Host request blocker for this connection; also registered for SandboxOutbound. */
  requestBlocker?: RequestBlocker;
  host: HostCapabilities;
  isolateLoader: HostIsolateLoader;
  connectionId: string;
  actorConnectionId?: string;
  analytics: ParawingAnalytics;
  sessionManager?: SessionManager;
  connectionEpoch?: number;
  connectionRole?: ConnectionRole;
  actorRole?: DispatchActorRole;
}

const VIEWER_READ_ONLY_METHODS = new Set<string>([
  "Browser.getVersion",
  "Target.getTargets",
  "Target.getTargetInfo",
  "Page.getFrameTree",
  "Page.getResourceTree",
  "Page.getNavigationHistory",
  "Page.getLayoutMetrics",
  "Parawing.getSessionInfo",
  "Parawing.getConnectionInfo",
  "Parawing.getControllerLease",
  "Parawing.getPageState",
  "Parawing.getScreencastStatus",
  "Parawing.getLayoutMode",
  "Parawing.getRendererInfo",
  "Parawing.getMemoryStats",
]);

const VIEWER_CHANNEL_METHODS = new Set<string>([
  "Target.attachToTarget",
  "Target.detachFromTarget",
  "Parawing.startSceneStreamV2",
  "Parawing.stopSceneStreamV2",
  "Parawing.recordSceneV2",
  "Parawing.getHandlerRegions",
  "Parawing.getInputJournalState",
  "Parawing.requestControllerLease",
]);

const VIEWER_TAKEOVER_HUMAN_METHODS = new Set<string>([
  "Input.dispatchMouseEvent",
  "Input.dispatchKeyEvent",
  "Input.insertText",
  "Parawing.releaseControllerLease",
  "Parawing.revokeControllerLease",
]);

const TARGET_LESS_COMMANDS = new Set<string>([
  "Browser.getVersion",
  "Target.getTargets",
  "Target.createTarget",
  "Target.createBrowserContext",
  "Target.disposeBrowserContext",
  "Target.getBrowserContexts",
  "Target.setDiscoverTargets",
  "Target.setAutoAttach",
  "Parawing.destroySession",
  "Parawing.checkpointSession",
  "Parawing.suspendSession",
  "Parawing.resumeSession",
  "Parawing.roamSession",
  "Parawing.issueAttestedKeyLease",
  "Parawing.releaseDbscCredential",
  "Parawing.submitApprovalDecision",
  "Parawing.getSessionInfo",
  "Parawing.getConnectionInfo",
]);

function resolveTargetForDispatch(ctx: DispatchCtx, req: CdpRequest): TargetState | null {
  if (req.sessionId) {
    for (const t of ctx.browser.targets.values()) {
      if (t.sessions.has(req.sessionId)) return t;
    }
    const oopif = findOopifFrameBySession(ctx, req.sessionId);
    if (oopif) return oopif.target;
  }
  const paramsObj =
    req.params && typeof req.params === "object" ? (req.params as Record<string, unknown>) : null;
  const explicitTargetId =
    paramsObj && typeof paramsObj["targetId"] === "string" ? paramsObj["targetId"] : null;
  if (explicitTargetId) {
    return ctx.browser.targets.get(explicitTargetId) ?? null;
  }
  if (TARGET_LESS_COMMANDS.has(req.method)) return null;
  for (const t of ctx.browser.targets.values()) {
    if (t.type === "page") return t;
  }
  return null;
}

const internalHumanRequests = new WeakSet<CdpRequest>();

/** Marks an internal request constructed after validating an active human ControllerLease. */
export function markInternalHumanRequest(req: CdpRequest): void {
  internalHumanRequests.add(req);
}

export function isInternalHumanRequest(req: CdpRequest): boolean {
  return internalHumanRequests.has(req);
}

export function isAttachedViewer(ctx: DispatchCtx): boolean {
  if (ctx.sessionManager && ctx.browser.sessionId) {
    const rec = ctx.sessionManager.get(ctx.browser.sessionId);
    const conn = rec?.connections.get(asConnectionId(ctx.actorConnectionId ?? ctx.connectionId));
    if (conn) return conn.role === "viewer";
  }
  return ctx.connectionRole === "viewer";
}

export function hasActiveTakeoverForRequest(
  ctx: DispatchCtx,
  req: CdpRequest,
  targetId: TargetId | null,
): boolean {
  const leases = ctx.browser.controllerLeases;
  if (!leases) return false;
  if (targetId && leases.getActiveLease(targetId) !== null) return true;
  if (
    req.method === "Parawing.releaseControllerLease" ||
    req.method === "Parawing.revokeControllerLease"
  ) {
    const paramsObj =
      req.params && typeof req.params === "object" ? (req.params as Record<string, unknown>) : null;
    const leaseId = typeof paramsObj?.["leaseId"] === "string" ? paramsObj["leaseId"] : "";
    if (leaseId && leases.getLeaseById(leaseId)?.status === "active") return true;
  }
  return false;
}

function isViewerMethodPermitted(method: string, takeoverActive: boolean): boolean {
  if (VIEWER_READ_ONLY_METHODS.has(method) || VIEWER_CHANNEL_METHODS.has(method)) return true;
  return takeoverActive && VIEWER_TAKEOVER_HUMAN_METHODS.has(method);
}

export function resolveDispatchActorRole(
  ctx: DispatchCtx,
  req: CdpRequest,
  viewerConn: boolean,
  takeoverActive: boolean,
): DispatchActorRole {
  const raw = Reflect.get(req, "_actorRole");
  if (
    takeoverActive &&
    (internalHumanRequests.has(req) ||
      raw === "human" ||
      (viewerConn && isViewerMethodPermitted(req.method, true)))
  ) {
    return "human";
  }
  if (raw === "agent") return "agent";
  return ctx.actorRole ?? "agent";
}

export async function dispatch(ctx: DispatchCtx, req: CdpRequest): Promise<CdpResponse> {
  const [domain] = req.method.split(".", 1);

  ctx.browser.networkEvents.drain();

  try {
    const viewerConn = isAttachedViewer(ctx);
    const dispatchTarget = resolveTargetForDispatch(ctx, req);
    const targetId: TargetId | null = dispatchTarget ? asTargetId(dispatchTarget.targetId) : null;
    const takeoverActive = hasActiveTakeoverForRequest(ctx, req, targetId);

    if (
      ctx.browser.persistentSession &&
      ctx.sessionManager &&
      ctx.browser.sessionId &&
      req.method !== "Browser.getVersion"
    ) {
      const callerConnId = asConnectionId(ctx.actorConnectionId ?? ctx.connectionId);
      try {
        ctx.sessionManager.validateEpoch(ctx.browser.sessionId, callerConnId, ctx.connectionEpoch);
      } catch (err) {
        if (!(err instanceof StaleEpochError)) throw err;
        const rec = ctx.sessionManager.get(ctx.browser.sessionId);
        const attached =
          rec !== undefined && rec.status !== "destroyed" && rec.connections.has(callerConnId);
        const permittedInternalHuman = takeoverActive && internalHumanRequests.has(req);
        if (
          !attached ||
          (!isViewerMethodPermitted(req.method, takeoverActive) && !permittedInternalHuman)
        ) {
          throw err;
        }
      }
    }

    const actorRole = resolveDispatchActorRole(ctx, req, viewerConn, takeoverActive);

    if (req.method !== "Browser.getVersion") {
      ctx.browser.controllerLeases?.assertAgentDispatchAllowed(targetId, req.method, actorRole);
      const policyDecision = ctx.browser.policyEngine?.evaluateCommand({
        method: req.method,
        sessionId: ctx.browser.sessionId,
        targetId,
        sealedOrigin: dispatchTarget?.sealedOrigin ?? null,
        actorRole,
      });
      if (policyDecision && !policyDecision.allowed) {
        throw new PolicyDecisionError(policyDecision);
      }
    }

    if (req.method === "Browser.getVersion") {
      return {
        id: req.id,
        result: {
          protocolVersion: "1.3",
          product: "Chrome/145.0.0.0",
          revision: "@parawing",
          userAgent:
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
          jsVersion: "12.0.0",
        },
        sessionId: req.sessionId,
      };
    }
    if (req.sessionId && req.sessionId === ctx.browser.rendererSessionId) {
      const result = await handleRendererSession(ctx, req);
      ctx.browser.networkEvents.drain();
      return { id: req.id, result: result ?? {}, sessionId: req.sessionId };
    }
    if (req.sessionId && req.sessionId === ctx.browser.engineSessionId) {
      const result = await handleEngineSession(ctx, req);
      ctx.browser.networkEvents.drain();
      return { id: req.id, result: result ?? {}, sessionId: req.sessionId };
    }
    if (req.sessionId) {
      const oopif = findOopifFrameBySession(ctx, req.sessionId);
      if (oopif) {
        const result = await handleOopifSession(ctx, req, oopif.target, oopif.frame);
        ctx.browser.networkEvents.drain();
        return { id: req.id, result: result ?? {}, sessionId: req.sessionId };
      }
    }
    let result: unknown;
    switch (domain) {
      case "Target":
        result = await handleTarget(ctx, req);
        break;
      case "Page":
        result = await handlePage(ctx, req);
        break;
      case "Runtime":
        result = await handleRuntime(ctx, req);
        break;
      case "DOM":
        result = await handleDom(ctx, req);
        break;
      case "Network":
      case "Storage":
        result = await handleNetwork(ctx, req);
        break;
      case "Log":
        result = await handleLog(ctx, req);
        break;
      case "Fetch":
        result = await handleFetch(ctx, req);
        break;
      case "Input":
        result = await handleInput(ctx, req, undefined, { replyOnDispatch: true });
        break;
      case "Parawing": {
        result = await handleParawing(ctx, req);
        if (result === CDP_COMMAND_UNHANDLED) {
          // Public handlers win; the host only sees commands they decline.
          const extension = ctx.commandExtension;
          if (!extension) {
            ctx.browser.networkEvents.drain();
            return methodNotFound(req);
          }
          const extended = await extension(ctx, req);
          if (!extended.handled) {
            ctx.browser.networkEvents.drain();
            return methodNotFound(req);
          }
          result = extended.result;
        }
        break;
      }
      case "WebMCP":
        result = await handleWebMcp(ctx, req);
        break;
      case "Debugger":
        result = await handleDebugger(ctx, req);
        break;
      case "CSS":
        result = await handleCss(ctx, req);
        break;
      case "Accessibility":
        result = await handleAccessibility(ctx, req);
        break;
      case "Emulation":
        result = await handleEmulation(ctx, req);
        break;
      // These domains remain unsupported; clients probe them during attach.
      case "Animation":
      case "Audits":
      case "Autofill":
      case "BackgroundService":
      case "Browser":
      case "Cast":
      case "Console":
      case "Database":
      case "DeviceOrientation":
      case "DOMDebugger":
      case "DOMSnapshot":
      case "DOMStorage":
      case "FedCm":
      case "Headless":
      case "HeapProfiler":
      case "IndexedDB":
      case "Inspector":
      case "IO":
      case "LayerTree":
      case "Media":
      case "Memory":
      case "Overlay":
      case "Page-CSP":
      case "Performance":
      case "PerformanceTimeline":
      case "Preload":
      case "Profiler":
      case "Schema":
      case "Security":
      case "ServiceWorker":
      case "Tethering":
      case "Tracing":
      case "WebAudio":
      case "WebAuthn":
        result = {};
        break;
      default:
        return methodNotFound(req);
    }

    ctx.browser.networkEvents.drain();

    return {
      id: req.id,
      result: result ?? {},
      sessionId: req.sessionId,
    };
  } catch (err) {
    ctx.browser.networkEvents.drain();
    const message = err instanceof Error ? err.message : String(err);
    return {
      id: req.id,
      error: { code: -32000, message },
      sessionId: req.sessionId,
    };
  }
}

function methodNotFound(req: CdpRequest): CdpResponse {
  return {
    id: req.id,
    error: { code: -32601, message: `'${req.method}' wasn't found` },
    sessionId: req.sessionId,
  };
}

async function handleEmulation(
  ctx: DispatchCtx,
  req: CdpRequest,
): Promise<Record<string, unknown>> {
  let target: TargetState | null = null;
  if (req.sessionId) {
    for (const t of ctx.browser.targets.values()) {
      if (t.sessions.has(req.sessionId)) {
        target = t;
        break;
      }
    }
  }
  if (!target) {
    for (const t of ctx.browser.targets.values()) {
      if (t.type === "page") {
        target = t;
        break;
      }
    }
  }
  if (!target) return {};

  if (req.method === "Emulation.setDeviceMetricsOverride") {
    const width = typeof req.params?.width === "number" ? req.params.width : NaN;
    const height = typeof req.params?.height === "number" ? req.params.height : NaN;
    if (!Number.isFinite(width) || !Number.isFinite(height)) {
      return {};
    }
    const vp = clampViewport(width, height);
    target.viewportWidth = vp.width;
    target.viewportHeight = vp.height;
    await sessionOf(ctx, target).callIfLive.setViewport({
      width: target.viewportWidth,
      height: target.viewportHeight,
    });
    return {};
  }

  if (req.method === "Emulation.setEmulatedMedia") {
    const media = typeof req.params?.media === "string" ? req.params.media : "";
    const normalised = media === "print" ? "print" : "screen";
    target.emulatedMedia = normalised;
    await sessionOf(ctx, target).callIfLive.setMediaType({
      media: normalised,
    });
    return {};
  }

  if (req.method === "Emulation.setUserAgentOverride") {
    target.userAgentOverride =
      typeof req.params?.userAgent === "string" ? req.params.userAgent : "";
    return {};
  }

  return {};
}
