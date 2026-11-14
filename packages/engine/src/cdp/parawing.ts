// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Handles Parawing CDP methods for scene transfer, engine settings, and diagnostics.

import type { Protocol } from "devtools-protocol";
import type { DispatchCtx } from "./dispatch.ts";
import type { CdpMethod, CdpRequest, CdpResultOf, TargetState } from "./types.ts";
import { CDP_COMMAND_UNHANDLED } from "./types.ts";
import { asConnectionId, asSessionId, asTargetId, asUserId } from "../session/identities.ts";
import { setFrameSealedOrigin } from "./session-security-registry.ts";
import {
  sessionOf,
  stubQueryDom,
  type QueryDomCarrier,
  type QueryDomMethod,
} from "./page-session.ts";
import { captureTargetVisualState, engineMemoryBreakdown } from "./target.ts";
import type { DomObservedField, SignedApprovalDecision } from "../authority/approval-gate.ts";
import {
  wrappedKeyLeaseToWire,
  type SignedCapsuleAttestation,
} from "../authority/capsule-attestation.ts";
import { TokenizedFillVault } from "../authority/mandates.ts";
import { sceneStreamCommand } from "./scene-stream.ts";
import { sceneHostCommand } from "./scene-host.ts";
import {
  getInputJournalState,
  getRbiV2StreamStats,
  recordSceneV2ForTarget,
  startRbiV2Stream,
  stopRbiV2Streams,
} from "../rbi-v2-server.ts";
import {
  MAX_MISSING_RESOURCE_LIST_B64_CHARS,
  MISSING_RESOURCE_LIST_ENTRY_BYTES,
  MISSING_RESOURCE_LIST_HEADER_BYTES,
  MISSING_RESOURCE_LIST_KIND_BYTES,
} from "../rbi-protocol.ts";

function bytesToBase64(bytes: Uint8Array): string {
  return bytes.toBase64();
}
function base64ToBytes(s: string): Uint8Array {
  return Uint8Array.fromBase64(s);
}

function firstPageTarget(ctx: DispatchCtx): TargetState | null {
  for (const t of ctx.browser.targets.values()) {
    if (t.type === "page") return t;
  }
  return null;
}

function splitMissingHashes(missing: Uint8Array): {
  imageHashes: Uint8Array;
  fontDataHashes: Uint8Array;
} {
  if (missing.byteLength < MISSING_RESOURCE_LIST_HEADER_BYTES) {
    return { imageHashes: new Uint8Array(0), fontDataHashes: new Uint8Array(0) };
  }
  const view = new DataView(missing.buffer, missing.byteOffset, missing.byteLength);
  const count = view.getUint32(0, true);
  const images: number[] = [];
  const fonts: number[] = [];
  let off = MISSING_RESOURCE_LIST_HEADER_BYTES;
  for (let i = 0; i < count; i++) {
    if (off + MISSING_RESOURCE_LIST_ENTRY_BYTES > missing.byteLength) break;
    const kind = view.getUint8(off);
    const hashBytes = missing.subarray(
      off + MISSING_RESOURCE_LIST_KIND_BYTES,
      off + MISSING_RESOURCE_LIST_ENTRY_BYTES,
    );
    if (kind === 2) images.push(...hashBytes);
    else if (kind === 3) fonts.push(...hashBytes);
    off += MISSING_RESOURCE_LIST_ENTRY_BYTES;
  }
  return {
    imageHashes: new Uint8Array(images),
    fontDataHashes: new Uint8Array(fonts),
  };
}

function coerceMode(raw: unknown): Protocol.Parawing.LayoutMode {
  if (typeof raw !== "string") return "full";
  const lower = raw.toLowerCase();
  if (lower === "off" || lower === "0" || lower === "false") return "off";
  return "full";
}

function targetIdOf(params: { targetId?: unknown } | undefined): string | null {
  return typeof params?.targetId === "string" ? params.targetId : null;
}

// Target-scoped page methods default to the first page, as the other Parawing methods do.
function pageTargetFor(
  ctx: DispatchCtx,
  params: { targetId?: unknown } | undefined,
): TargetState | null {
  const targetId = targetIdOf(params);
  const target =
    targetId === null ? firstPageTarget(ctx) : (ctx.browser.targets.get(targetId) ?? null);
  return target?.type === "page" ? target : null;
}

function noPageScript(target: TargetState | null): string {
  return target ? "no PageScript" : "target not found";
}

// paintDamageSince always takes a node to leave out; this external id is never minted.
const NO_EXCLUDED_NODE = 0xffff_ffff;

function positiveNodeId(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : null;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

const OUTBOUND_FILTER_FIELDS = [
  "allowRequestPattern",
  "rejectRequestPattern",
  "allowResourceTypes",
  "rejectResourceTypes",
] as const;

function cdpResult<M extends CdpMethod>(
  _req: { method: M },
  result: CdpResultOf<M>,
): CdpResultOf<M> {
  return result;
}

const PAGE_DIAGNOSTIC_OPS = {
  "Parawing.getFontFaces": "getFontFaces",
  "Parawing.getMemprofDump": "getMemprofDump",
  "Parawing.resetMemprof": "resetMemprof",
  "Parawing.boaForceCollect": "boaForceCollect",
  "Parawing.getSceneStats": "getSceneStats",
} as const satisfies Partial<Record<CdpRequest["method"], QueryDomMethod>>;

export async function handleParawing(ctx: DispatchCtx, req: CdpRequest): Promise<unknown> {
  switch (req.method) {
    case "Parawing.getSceneHostManifest":
    case "Parawing.readSceneHost":
      return sceneHostCommand(ctx.host.assets, req, ctx.browser);
    case "Parawing.startSceneStream":
    case "Parawing.stopSceneStream":
    case "Parawing.sceneFrameAck":
    case "Parawing.getSceneResources":
      return sceneStreamCommand(ctx, req);
    case "Parawing.getSessionInfo": {
      const meta = ctx.analytics.meta;
      const sid = ctx.browser.sessionId;
      const managed = sid ? ctx.sessionManager?.get(sid) : undefined;
      const liveConn = managed?.connections.get(
        asConnectionId(ctx.actorConnectionId ?? ctx.connectionId),
      );
      return cdpResult(req, {
        sessionId: meta.sessionId,
        entrypoint: meta.entrypoint,
        connectionMode: meta.connectionMode,
        environment: meta.environment,
        buildVersion: meta.buildVersion,
        colo: meta.colo,
        persistentSessionId: sid ?? null,
        userId: ctx.browser.userId ?? null,
        epoch: liveConn?.epoch ?? managed?.epoch ?? ctx.browser.sessionEpoch ?? null,
        connectionRole: liveConn?.role ?? ctx.connectionRole ?? ctx.browser.connectionRole ?? null,
        delegatedAgent: ctx.browser.delegatedAgent ?? false,
      });
    }

    case "Parawing.setLayoutMode": {
      const mode = coerceMode(req.params?.mode);
      const targetId = targetIdOf(req.params);

      if (targetId === null) {
        ctx.browser.layoutMode = mode;
        const updated: string[] = [];
        for (const t of ctx.browser.targets.values()) {
          t.layoutMode = mode;
          if (t.type === "page") {
            await sessionOf(ctx, t).callIfLive.setLayoutMode({ mode });
          }
          updated.push(t.targetId);
        }
        return cdpResult(req, { mode, scope: "browser", targets: updated });
      }

      const target = ctx.browser.targets.get(targetId);
      if (!target) {
        return cdpResult(req, {
          mode,
          scope: "target",
          targetId,
          error: "target not found",
        });
      }
      target.layoutMode = mode;
      if (target.type === "page" && target.pageScript) {
        try {
          await stubQueryDom(target.pageScript, "setLayoutMode", { mode });
        } catch (err) {
          return cdpResult(req, {
            mode,
            scope: "target",
            targetId,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return cdpResult(req, { mode, scope: "target", targetId });
    }

    case "Parawing.getLayoutMode": {
      const targetId = targetIdOf(req.params);
      if (targetId === null) {
        return cdpResult(req, { mode: ctx.browser.layoutMode });
      }
      const target = ctx.browser.targets.get(targetId);
      if (!target) {
        return cdpResult(req, {
          mode: ctx.browser.layoutMode,
          error: "target not found",
        });
      }
      if (target.type === "page") {
        const reply = await sessionOf(ctx, target).callIfLive.getLayoutMode({});
        if (reply && typeof reply.mode === "string") {
          return cdpResult(req, { mode: reply.mode });
        }
      }
      return cdpResult(req, { mode: target.layoutMode });
    }

    case "Parawing.getRendererInfo": {
      const m = ctx.browser.rendererManager;
      const memory = m ? m.memoryStats() : null;
      return cdpResult(req, {
        enabled: true,
        active: !!m,
        framesRendered: m ? m.framesRendered : 0,
        partialFramesRendered: m ? m.partialFramesRendered : 0,
        relaunchCount: m ? m.relaunchCount : 0,
        rendererWasmBytes: memory ? memory.bytes : null,
        rendererWasmDeltaBytes: memory ? memory.deltaBytes : null,
        initialRes: m ? m.initialResString() : null,
        partialRaster: !ctx.browser.skipPartialRaster,
      });
    }

    case "Parawing.setPartialRaster": {
      const enabled = req.params?.enabled !== false;
      ctx.browser.skipPartialRaster = !enabled;
      return cdpResult(req, { enabled });
    }

    case "Parawing.disposeRenderer": {
      const m = ctx.browser.rendererManager;
      if (m) m.dispose("Parawing.disposeRenderer");
      return cdpResult(req, { disposed: !!m });
    }

    case "Parawing.getNavigatePhases": {
      const targetId = targetIdOf(req.params);
      if (targetId === null) {
        const byTarget: Record<string, Protocol.Parawing.NavigatePhases | null> = {};
        for (const t of ctx.browser.targets.values()) {
          if (t.type !== "page") continue;
          byTarget[t.targetId] = t.lastNavigatePhases;
        }
        return cdpResult(req, { byTarget });
      }
      const target = ctx.browser.targets.get(targetId);
      if (!target) {
        return cdpResult(req, { phases: null, error: "target not found" });
      }
      return cdpResult(req, { phases: target.lastNavigatePhases });
    }

    case "Parawing.hasPendingCriticalResources": {
      const targetId = targetIdOf(req.params);
      const ask = async (
        t: TargetState,
      ): Promise<Protocol.Parawing.PendingCriticalResources | null> => {
        if (t.type !== "page") return null;
        if (!t.pageScript) return { pending: false, error: "no PageScript" };
        try {
          const reply = await stubQueryDom(t.pageScript, "hasPendingCriticalResources", {});
          return { pending: !!reply?.pending, error: reply?.error };
        } catch (err) {
          return {
            pending: false,
            error: err instanceof Error ? err.message : String(err),
          };
        }
      };
      if (targetId === null) {
        const byTarget: Record<string, Protocol.Parawing.PendingCriticalResources | null> = {};
        for (const t of ctx.browser.targets.values()) {
          if (t.type !== "page") continue;
          byTarget[t.targetId] = await ask(t);
        }
        return cdpResult(req, { byTarget });
      }
      const target = ctx.browser.targets.get(targetId);
      if (!target) {
        return cdpResult(req, { pending: false, error: "target not found" });
      }
      return cdpResult(req, (await ask(target)) ?? {});
    }

    case "Parawing.getPageState": {
      const target = pageTargetFor(ctx, req.params);
      if (!target?.pageScript) return cdpResult(req, { error: noPageScript(target) });
      try {
        const reply = await stubQueryDom(target.pageScript, "getPageState", {});
        if (typeof reply?.scrollX === "number" && Number.isFinite(reply.scrollX)) {
          target.lastScrollX = reply.scrollX;
        }
        if (typeof reply?.scrollY === "number" && Number.isFinite(reply.scrollY)) {
          target.lastScrollY = reply.scrollY;
        }
        return cdpResult(req, reply ?? {});
      } catch (err) {
        return cdpResult(req, { error: errorText(err) });
      }
    }

    case "Parawing.setControlValue": {
      const nodeId = positiveNodeId(req.params?.nodeId);
      if (nodeId === null) return cdpResult(req, { changed: false, error: "bad nodeId" });
      const target = pageTargetFor(ctx, req.params);
      if (!target?.pageScript) {
        return cdpResult(req, { changed: false, error: noPageScript(target) });
      }
      try {
        const reply = await stubQueryDom(target.pageScript, "setControlValueAsUser", {
          nodeId,
          value: req.params?.value,
        });
        if (reply?.changed === true && !target.sealedOrigin) {
          const fieldKey = `node:${nodeId}`;
          target.lastFocusedFieldKey = fieldKey;
          const prev = (target.lastFormDrafts ?? []).filter((d) => d.fieldKey !== fieldKey);
          prev.push({
            fieldKey,
            tagName: "INPUT",
            fieldType: "text",
            value: reply.value ?? String(req.params?.value ?? ""),
          });
          target.lastFormDrafts = prev;
        }
        return cdpResult(req, {
          changed: reply?.changed === true,
          value: reply?.value,
          error: reply?.error,
        });
      } catch (err) {
        return cdpResult(req, { changed: false, error: errorText(err) });
      }
    }

    case "Parawing.markPaintDamage": {
      const target = pageTargetFor(ctx, req.params);
      if (!target?.pageScript) return cdpResult(req, { error: noPageScript(target) });
      try {
        await stubQueryDom(target.pageScript, "markPaintDamage", {});
        return cdpResult(req, {});
      } catch (err) {
        return cdpResult(req, { error: errorText(err) });
      }
    }

    case "Parawing.getPaintDamageSince": {
      const raw = req.params?.excludeNodeId;
      const nodeId = raw === undefined ? NO_EXCLUDED_NODE : positiveNodeId(raw);
      if (nodeId === null) {
        return cdpResult(req, { nodeIds: [], overflow: false, error: "bad nodeId" });
      }
      const target = pageTargetFor(ctx, req.params);
      if (!target?.pageScript) {
        return cdpResult(req, { nodeIds: [], overflow: false, error: noPageScript(target) });
      }
      try {
        const reply = await stubQueryDom(target.pageScript, "paintDamageSince", { nodeId });
        return cdpResult(req, {
          nodeIds: Array.isArray(reply?.ids) ? reply.ids : [],
          overflow: reply?.overflow === true,
        });
      } catch (err) {
        return cdpResult(req, { nodeIds: [], overflow: false, error: errorText(err) });
      }
    }

    case "Parawing.getMemoryStats": {
      const targetId = targetIdOf(req.params);
      const askStub = async (stub: QueryDomCarrier) => {
        try {
          const reply = await stubQueryDom(stub, "getMemoryStats", {});
          return {
            wasmBytes: typeof reply?.bytes === "number" ? reply.bytes : 0,
            wasmInitialBytes: typeof reply?.initialBytes === "number" ? reply.initialBytes : 0,
            wasmDeltaBytes: typeof reply?.deltaBytes === "number" ? reply.deltaBytes : 0,
            bridge: reply?.bridge ?? null,
            domFastpath: reply?.domFastpath ?? null,
            domNodes: typeof reply?.domNodes === "number" ? reply.domNodes : null,
            wrappers: reply?.wrappers ?? null,
            paint: reply?.paint ?? null,
            layout: reply?.layout ?? null,
            intersectionObserver: reply?.intersectionObserver ?? null,
            timerWheel: reply?.timerWheel ?? null,
            error: reply?.error,
          };
        } catch (err) {
          return {
            wasmBytes: 0,
            wasmInitialBytes: 0,
            wasmDeltaBytes: 0,
            error: err instanceof Error ? err.message : String(err),
          };
        }
      };
      const ask = async (t: TargetState) => {
        if (t.type !== "page") return null;
        if (!t.pageScript) {
          return {
            wasmBytes: 0,
            wasmInitialBytes: 0,
            wasmDeltaBytes: 0,
            frameWasmBytes: 0,
            frameWasmDeltaBytes: 0,
            error: "no PageScript",
          };
        }
        const children = [...t.frames.values()]
          .map((f) => f.pageScript)
          .filter((s): s is NonNullable<typeof s> => Boolean(s));
        const [own, ...replies] = await Promise.all([
          askStub(t.pageScript),
          ...children.map((s) => askStub(s)),
        ]);
        let frameWasmBytes = 0;
        let frameWasmDeltaBytes = 0;
        for (const child of replies) {
          frameWasmBytes += child.wasmBytes;
          frameWasmDeltaBytes += child.wasmDeltaBytes;
        }
        return { ...own, frameWasmBytes, frameWasmDeltaBytes };
      };
      if (targetId === null) {
        const byTarget: Record<string, Protocol.Parawing.MemoryStats | null> = {};
        let pageScriptBytes = 0;
        let pageScriptDeltaBytes = 0;
        for (const t of ctx.browser.targets.values()) {
          if (t.type !== "page") continue;
          const stats = await ask(t);
          byTarget[t.targetId] = stats;
          if (!stats) continue;
          pageScriptBytes += stats.wasmBytes + stats.frameWasmBytes;
          pageScriptDeltaBytes += stats.wasmDeltaBytes + stats.frameWasmDeltaBytes;
        }
        const engine = engineMemoryBreakdown(ctx.browser);
        const rendererMem = ctx.browser.rendererManager?.memoryStats() ?? null;
        const renderer = {
          wasmBytes: rendererMem?.bytes ?? 0,
          wasmInitialBytes: rendererMem?.initialBytes ?? 0,
          wasmDeltaBytes: rendererMem?.deltaBytes ?? 0,
        };
        return cdpResult(req, {
          byTarget,
          engine,
          renderer,
          isolatesKilled: ctx.browser.workerBudget.isolatesKilled,
          total: {
            bytes: engine.accountedBytes + pageScriptBytes + renderer.wasmBytes,
            deltaBytes: engine.wasmDeltaBytes + pageScriptDeltaBytes + renderer.wasmDeltaBytes,
            engineBytes: engine.accountedBytes,
            pageScriptBytes,
            rendererBytes: renderer.wasmBytes,
          },
        });
      }
      const target = ctx.browser.targets.get(targetId);
      if (!target) {
        return cdpResult(req, { wasmBytes: 0, error: "target not found" });
      }
      return cdpResult(req, (await ask(target)) ?? {});
    }

    case "Parawing.setOutboundFilters": {
      const { compileOutboundFilters, registerOutboundFilters } =
        await import("./outbound-filter-registry.ts");
      const params = req.params ?? {};
      const input: Partial<Record<(typeof OUTBOUND_FILTER_FIELDS)[number], string[]>> = {};
      for (const name of OUTBOUND_FILTER_FIELDS) {
        const value: unknown = params[name];
        if (!Array.isArray(value)) continue;
        const strings = value.filter((s): s is string => typeof s === "string");
        if (strings.length !== value.length) {
          return cdpResult(req, { ok: false, error: `${name} must be an array of strings` });
        }
        input[name] = strings;
      }
      const compiled = compileOutboundFilters(input);
      if (!compiled.ok) {
        return cdpResult(req, { ok: false, error: compiled.error });
      }
      registerOutboundFilters(ctx.connectionId, compiled.filters);
      return cdpResult(req, { ok: true });
    }

    case "Parawing.recordScene": {
      const params = req.params ?? {};
      const targetId = targetIdOf(params);
      const target = targetId ? ctx.browser.targets.get(targetId) : firstPageTarget(ctx);
      if (!target || target.type !== "page") {
        return cdpResult(req, { error: "no page target" });
      }
      if (!target.pageScript) {
        return cdpResult(req, { error: "no PageScript" });
      }
      const args = {
        producer: params.producer,
        sinceSeq: params.sinceSeq,
        omitBackground: params.omitBackground,
        clip: params.clip,
        allowPartial: params.allowPartial,
        allowScrollShift: params.allowScrollShift,
        baseSeq: params.baseSeq,
        inlineResources: params.inlineResources,
        pumpRaf: params.pumpRaf,
        frameIntervalMs: params.frameIntervalMs,
      };
      try {
        const r = await stubQueryDom(target.pageScript, "recordScene", args);
        return cdpResult(req, {
          sceneB64: r.scene && r.scene.length > 0 ? bytesToBase64(r.scene) : "",
          resourceBatchB64:
            r.resourceBatch && r.resourceBatch.length > 0 ? bytesToBase64(r.resourceBatch) : "",
          unchanged: !!r.unchanged,
          seq: r.seq ?? 0,
          partial: !!r.partial,
          clip: r.clip ?? null,
          baseSeq: r.baseSeq ?? -1,
          scrollX: r.scrollX ?? 0,
          scrollY: r.scrollY ?? 0,
          error: r.error,
          damageCount: r.damageCount ?? 0,
          layoutDirty: !!r.layoutDirty,
          skipReason: r.skipReason ?? "",
        });
      } catch (err) {
        return cdpResult(req, {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    case "Parawing.getScreencastStatus": {
      const targetId = targetIdOf(req.params);
      const target = targetId ? ctx.browser.targets.get(targetId) : firstPageTarget(ctx);
      if (!target) {
        return cdpResult(req, { error: "no page target" });
      }
      const sc = ctx.browser.screencasts.get(target.targetId);
      const where = {
        targetId: target.targetId,
        targetUrl: target.url,
        hasPageScript: target.pageScript !== null,
        generation: target.navigateGeneration,
        pageTargets: [...ctx.browser.targets.values()].filter((t) => t.type === "page").length,
      };
      if (!sc) {
        return cdpResult(req, { active: false, ...where });
      }
      return cdpResult(req, {
        active: !sc.stopped,
        framesDropped: sc.framesDropped,
        lastError: sc.lastRenderError ?? "",
        inFlight: sc.frameSeq - sc.lastAckedSeq,
        ...where,
      });
    }

    case "Parawing.getConnectionInfo": {
      return cdpResult(req, { connectionId: ctx.connectionId });
    }

    case "Parawing.getRbiResources": {
      const targetId = targetIdOf(req.params);
      const target = targetId ? ctx.browser.targets.get(targetId) : firstPageTarget(ctx);
      if (!target || target.type !== "page") {
        return cdpResult(req, { error: "no page target" });
      }
      if (!target.pageScript) {
        return cdpResult(req, { error: "no PageScript" });
      }
      const missingB64Param = req.params?.missingB64;
      const missingB64 = typeof missingB64Param === "string" ? missingB64Param : "";
      if (missingB64.length > MAX_MISSING_RESOURCE_LIST_B64_CHARS) {
        return cdpResult(req, { error: "missing list too large" });
      }
      const missing = base64ToBytes(missingB64);
      const { imageHashes, fontDataHashes } = splitMissingHashes(missing);
      try {
        const r = await stubQueryDom(target.pageScript, "getPaintResources", {
          imageHashes,
          fontDataHashes,
        });
        return cdpResult(req, {
          batchB64: r.batch && r.batch.length > 0 ? bytesToBase64(r.batch) : "",
          error: r.error,
        });
      } catch (err) {
        return cdpResult(req, {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    case "Parawing.getFontFaces":
    case "Parawing.getMemprofDump":
    case "Parawing.resetMemprof":
    case "Parawing.boaForceCollect":
    case "Parawing.getSceneStats": {
      const op = PAGE_DIAGNOSTIC_OPS[req.method];
      const targetId = targetIdOf(req.params);
      const ask = async (t: TargetState) => {
        if (t.type !== "page") return null;
        if (!t.pageScript) return { error: "no PageScript" };
        try {
          return await stubQueryDom(t.pageScript, op, {});
        } catch (err) {
          return { error: err instanceof Error ? err.message : String(err) };
        }
      };
      if (targetId === null) {
        const byTarget: Record<string, Awaited<ReturnType<typeof ask>>> = {};
        for (const t of ctx.browser.targets.values()) {
          if (t.type !== "page") continue;
          byTarget[t.targetId] = await ask(t);
        }
        return { byTarget };
      }
      const target = ctx.browser.targets.get(targetId);
      if (!target) return { error: "target not found" };
      return (await ask(target)) ?? {};
    }

    case "Parawing.destroySession": {
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const rawSid = typeof paramsObj["sessionId"] === "string" ? paramsObj["sessionId"] : null;
      const targetSid = rawSid ? asSessionId(rawSid) : ctx.browser.sessionId;
      if (!ctx.sessionManager || !targetSid) {
        return { destroyed: false, sessionId: targetSid ?? "" };
      }
      const destroyed = await ctx.sessionManager.destroy(targetSid);
      return { destroyed, sessionId: targetSid };
    }

    case "Parawing.checkpointSession": {
      const sid = ctx.browser.sessionId;
      if (!ctx.sessionManager || !sid) return { error: "no active persistent session" };
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const rawReason = paramsObj["reason"];
      const reason =
        rawReason === "suspend" || rawReason === "roam" || rawReason === "timer"
          ? rawReason
          : "manual";
      return { checkpoint: ctx.sessionManager.checkpointSession(sid, reason) };
    }

    case "Parawing.requestControllerLease": {
      const target = pageTargetFor(ctx, req.params as { targetId?: unknown } | undefined);
      if (!target) return { error: "target not found" };
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const requesterId =
        typeof paramsObj["requesterId"] === "string" ? paramsObj["requesterId"] : "human";
      const reason = typeof paramsObj["reason"] === "string" ? paramsObj["reason"] : undefined;
      const pauseObservation =
        typeof paramsObj["pauseObservation"] === "boolean" ? paramsObj["pauseObservation"] : true;
      const lease = ctx.browser.controllerLeases.request({
        targetId: asTargetId(target.targetId),
        requesterId,
        reason,
        pauseObservation,
      });
      return { lease };
    }

    case "Parawing.approveControllerLease": {
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const leaseId = typeof paramsObj["leaseId"] === "string" ? paramsObj["leaseId"] : "";
      const ttlMs = typeof paramsObj["ttlMs"] === "number" ? paramsObj["ttlMs"] : undefined;
      const pauseObservation =
        typeof paramsObj["pauseObservation"] === "boolean"
          ? paramsObj["pauseObservation"]
          : undefined;
      return { lease: ctx.browser.controllerLeases.approve(leaseId, { ttlMs, pauseObservation }) };
    }

    case "Parawing.releaseControllerLease": {
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const idOrTarget =
        typeof paramsObj["leaseId"] === "string"
          ? paramsObj["leaseId"]
          : (pageTargetFor(ctx, req.params as { targetId?: unknown } | undefined)?.targetId ?? "");
      return { lease: ctx.browser.controllerLeases.release(idOrTarget) };
    }

    case "Parawing.revokeControllerLease": {
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const idOrTarget =
        typeof paramsObj["leaseId"] === "string"
          ? paramsObj["leaseId"]
          : (pageTargetFor(ctx, req.params as { targetId?: unknown } | undefined)?.targetId ?? "");
      return { lease: ctx.browser.controllerLeases.revoke(idOrTarget) };
    }

    case "Parawing.getControllerLease": {
      const target = pageTargetFor(ctx, req.params as { targetId?: unknown } | undefined);
      if (!target) return { lease: null };
      return { lease: ctx.browser.controllerLeases.getActiveLease(asTargetId(target.targetId)) };
    }

    case "Parawing.performSealedFill": {
      const target = pageTargetFor(ctx, req.params as { targetId?: unknown } | undefined);
      if (!target) return { error: "target not found" };
      const authority = ctx.browser.authority;
      if (!authority) return { error: "authority service unavailable" };
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const nodeId = typeof paramsObj["nodeId"] === "number" ? paramsObj["nodeId"] : null;
      if (nodeId === null) return { error: "nodeId is required" };
      const credentialId =
        typeof paramsObj["credentialId"] === "string" ? paramsObj["credentialId"] : undefined;
      const field = paramsObj["field"] === "username" ? "username" : "password";
      const userId = ctx.browser.userId;
      if (!userId) return { error: "session userId unavailable" };
      const res = await authority.performSealedFill({
        userId,
        credentialId,
        field,
        target: {
          targetId: asTargetId(target.targetId),
          currentUrl: target.url,
          setSealedOrigin(origin: string) {
            target.sealedOrigin = origin;
            setFrameSealedOrigin(ctx.connectionId, target.frameId, origin);
          },
          async injectSecretIntoControl(secret: string): Promise<boolean> {
            const reply = await sessionOf(ctx, target).callIfLive.setControlValueAsUser({
              nodeId,
              value: secret,
            });
            return reply?.changed === true;
          },
        },
      });
      await ctx.browser.auditLog?.append({
        kind: "authority.sealed_fill",
        sessionId: ctx.browser.sessionId,
        targetId: asTargetId(target.targetId),
        detail: {
          credentialId: res.credentialId,
          sealedOrigin: res.sealedOrigin,
          field,
        },
      });
      return res;
    }

    case "Parawing.performTokenizedFill": {
      const target = pageTargetFor(ctx, req.params as { targetId?: unknown } | undefined);
      if (!target) return { error: "target not found" };
      const authority = ctx.browser.authority;
      if (!authority) return { error: "authority service unavailable" };
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const nodeId = typeof paramsObj["nodeId"] === "number" ? paramsObj["nodeId"] : null;
      if (nodeId === null) return { error: "nodeId is required" };
      const credentialId =
        typeof paramsObj["credentialId"] === "string" ? paramsObj["credentialId"] : undefined;
      const field = paramsObj["field"] === "username" ? "username" : "password";
      const userId = ctx.browser.userId;
      if (!userId) return { error: "session userId unavailable" };
      const vault = (ctx.browser.tokenizedVault ??= new TokenizedFillVault(authority));
      const res = await vault.performTokenizedFill({
        userId,
        credentialId,
        field,
        nodeId,
        target: {
          targetId: asTargetId(target.targetId),
          currentUrl: target.url,
          async injectTokenIntoControl(token: string): Promise<boolean> {
            const reply = await sessionOf(ctx, target).callIfLive.setControlValueAsUser({
              nodeId,
              value: token,
            });
            return reply?.changed === true;
          },
        },
      });
      await ctx.browser.auditLog?.append({
        kind: "authority.tokenized_fill",
        sessionId: ctx.browser.sessionId,
        targetId: asTargetId(target.targetId),
        detail: {
          credentialId: res.credentialId,
          boundOrigin: res.boundOrigin,
          tokenPrefix: res.token.slice(0, 12),
          tokenHashHex: res.tokenHashHex,
          field,
        },
      });
      return res;
    }

    case "Parawing.suspendSession": {
      const sid = ctx.browser.sessionId;
      if (!ctx.sessionManager || !sid) return { error: "no active persistent session" };
      for (const t of ctx.browser.targets.values()) {
        if (t.type === "page") await captureTargetVisualState(t);
      }
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const reason = paramsObj["reason"] === "freeze" ? "freeze" : "suspend";
      return { checkpoint: await ctx.sessionManager.suspend(sid, reason) };
    }

    case "Parawing.resumeSession": {
      if (!ctx.sessionManager) return { error: "session manager unavailable" };
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const rawSid = typeof paramsObj["sessionId"] === "string" ? paramsObj["sessionId"] : null;
      const targetSid = rawSid ? asSessionId(rawSid) : ctx.browser.sessionId;
      if (!targetSid) return { error: "sessionId is required" };
      const userId = ctx.browser.userId;
      if (!userId) return { error: "session userId unavailable" };
      const requestedEpoch =
        typeof paramsObj["requestedEpoch"] === "number" ? paramsObj["requestedEpoch"] : undefined;
      const res = await ctx.sessionManager.resume({
        sessionId: targetSid,
        userId,
        connectionId: asConnectionId(ctx.connectionId),
        requestedEpoch,
        emit: ctx.emit,
      });
      ctx.browser.sessionEpoch = res.attachment.epoch;
      ctx.browser.connectionRole = res.attachment.role;
      return {
        tier: res.tier,
        epoch: res.attachment.epoch,
        role: res.attachment.role,
        restoreResult: res.restoreResult,
      };
    }

    case "Parawing.roamSession": {
      return await handleRoamSession(ctx, req);
    }

    case "Parawing.issueAttestedKeyLease": {
      return await handleIssueAttestedKeyLease(ctx, req);
    }

    case "Parawing.releaseDbscCredential": {
      return await handleReleaseDbscCredential(ctx, req);
    }

    case "Parawing.requestActionApproval": {
      const gate = ctx.browser.approvalGate;
      if (!gate) return { error: "approval gate unavailable" };
      const target = pageTargetFor(ctx, req.params as { targetId?: unknown } | undefined);
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const rawAction = paramsObj["action"];
      if (!rawAction || typeof rawAction !== "object") {
        return { error: "action descriptor is required" };
      }
      const actObj = rawAction as Record<string, unknown>;
      const actionUrl = typeof actObj["url"] === "string" ? actObj["url"] : (target?.url ?? "");
      const method = typeof actObj["method"] === "string" ? actObj["method"] : "POST";
      const body = typeof actObj["body"] === "string" ? actObj["body"] : undefined;
      const headers =
        actObj["headers"] && typeof actObj["headers"] === "object"
          ? (actObj["headers"] as Record<string, string>)
          : undefined;
      const domFields = Array.isArray(paramsObj["domFields"])
        ? (paramsObj["domFields"] as DomObservedField[])
        : [];
      const timeoutMs =
        typeof paramsObj["timeoutMs"] === "number" && paramsObj["timeoutMs"] > 0
          ? paramsObj["timeoutMs"]
          : 60_000;
      const outcome = await gate.holdForApproval({
        action: { method, url: actionUrl, headers, body },
        domFields,
        timeoutMs,
        onPrompt: (prompt) => {
          ctx.emit({
            method: "Parawing.approvalRequired",
            params: { targetId: target?.targetId ?? null, ...prompt },
            sessionId: req.sessionId,
          });
        },
      });
      return outcome;
    }

    case "Parawing.submitApprovalDecision": {
      const gate = ctx.browser.approvalGate;
      if (!gate) return { error: "approval gate unavailable" };
      const paramsObj = (req.params ?? {}) as Record<string, unknown>;
      const rawPayload = paramsObj["payload"];
      const signatureBase64 = paramsObj["signatureBase64"];
      if (!rawPayload || typeof rawPayload !== "object" || typeof signatureBase64 !== "string") {
        return { error: "SignedApprovalDecision payload and signatureBase64 are required" };
      }
      const p = rawPayload as Record<string, unknown>;
      if (
        typeof p["requestDigest"] !== "string" ||
        typeof p["nonce"] !== "string" ||
        typeof p["expiresAt"] !== "number" ||
        typeof p["approved"] !== "boolean"
      ) {
        return { error: "invalid SignedApprovalDecision payload fields" };
      }
      const decision: SignedApprovalDecision = {
        payload: {
          requestDigest: p["requestDigest"],
          nonce: p["nonce"],
          expiresAt: p["expiresAt"],
          approved: p["approved"],
        },
        signatureBase64,
      };
      return await gate.resolveWithSignedDecision(decision);
    }

    case "Parawing.startSceneStreamV2": {
      const p = req.params ?? {};
      const target = pageTargetFor(ctx, p);
      if (!target) return cdpResult(req, { error: noPageScript(target) });
      try {
        const started = await startRbiV2Stream(ctx, target, {
          width: typeof p.width === "number" ? p.width : undefined,
          height: typeof p.height === "number" ? p.height : undefined,
          fps: typeof p.fps === "number" ? p.fps : undefined,
          initialCredits: typeof p.initialCredits === "number" ? p.initialCredits : undefined,
          maxCredits: typeof p.maxCredits === "number" ? p.maxCredits : undefined,
        });
        return cdpResult(req, started);
      } catch (err) {
        return cdpResult(req, { error: errorText(err) });
      }
    }

    case "Parawing.stopSceneStreamV2": {
      const target = pageTargetFor(ctx, req.params);
      const stats = target ? getRbiV2StreamStats(ctx.browser, target.targetId) : null;
      stopRbiV2Streams(ctx.browser, target?.targetId ?? targetIdOf(req.params) ?? undefined);
      return cdpResult(req, { stats });
    }

    case "Parawing.recordSceneV2": {
      const p = req.params ?? {};
      const target = pageTargetFor(ctx, p);
      if (!target?.pageScript) {
        return cdpResult(req, {
          frameB64: "",
          seq: 0,
          scrollX: 0,
          scrollY: 0,
          origin: "null",
          ackedScrollSeq: 0,
          ackedInputSeq: 0,
          handlerRegions: [],
          error: noPageScript(target),
        });
      }
      try {
        const knownHashes =
          typeof p.knownHashesB64 === "string" ? base64ToBytes(p.knownHashesB64) : undefined;
        const recorded = await recordSceneV2ForTarget(ctx.browser, target, {
          knownHashes,
          velX: typeof p.velX === "number" ? p.velX : undefined,
          velY: typeof p.velY === "number" ? p.velY : undefined,
          pumpRaf: typeof p.pumpRaf === "boolean" ? p.pumpRaf : undefined,
        });
        return cdpResult(req, {
          frameB64: bytesToBase64(recorded.frame),
          seq: recorded.seq,
          scrollX: recorded.scrollX,
          scrollY: recorded.scrollY,
          origin: recorded.origin,
          ackedScrollSeq: recorded.ackedScrollSeq,
          ackedInputSeq: recorded.ackedInputSeq,
          handlerRegions: recorded.handlerRegions,
          ...(recorded.error ? { error: recorded.error } : {}),
        });
      } catch (err) {
        return cdpResult(req, {
          frameB64: "",
          seq: 0,
          scrollX: 0,
          scrollY: 0,
          origin: "null",
          ackedScrollSeq: 0,
          ackedInputSeq: 0,
          handlerRegions: [],
          error: errorText(err),
        });
      }
    }

    case "Parawing.getHandlerRegions": {
      const target = pageTargetFor(ctx, req.params);
      if (!target?.pageScript) {
        return cdpResult(req, { regions: [], error: noPageScript(target) });
      }
      try {
        const regions = await target.pageScript.getHandlerRegions();
        return cdpResult(req, { regions });
      } catch (err) {
        return cdpResult(req, { regions: [], error: errorText(err) });
      }
    }

    case "Parawing.getInputJournalState": {
      const p = req.params ?? {};
      const target = pageTargetFor(ctx, p);
      if (!target) return cdpResult(req, { error: "target not found" });
      try {
        const snap = await getInputJournalState(ctx.browser, target, {
          acknowledgeSeq: typeof p.acknowledgeSeq === "number" ? p.acknowledgeSeq : undefined,
          includeEncryptedSnapshot:
            typeof p.includeEncryptedSnapshot === "boolean"
              ? p.includeEncryptedSnapshot
              : undefined,
          replay: typeof p.replay === "boolean" ? p.replay : undefined,
        });
        if (typeof p.acknowledgeSeq === "number" && ctx.sessionManager && ctx.browser.sessionId) {
          ctx.sessionManager.recordAckedInput(ctx.browser.sessionId, snap.ackedInputSeq);
        }
        return cdpResult(req, snap);
      } catch (err) {
        return cdpResult(req, { error: errorText(err) });
      }
    }

    default:
      return CDP_COMMAND_UNHANDLED;
  }
}

function asNonEmptyStr(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function asFiniteNum(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function parseSignedAttestationParam(raw: unknown): SignedCapsuleAttestation | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const rawClaims = obj["claims"];
  if (!rawClaims || typeof rawClaims !== "object" || Array.isArray(rawClaims)) return null;
  const c = rawClaims as Record<string, unknown>;
  const capsuleHash = asNonEmptyStr(c["capsuleHash"]);
  const rustTarget = asNonEmptyStr(c["rustTarget"]);
  const baselineId = asNonEmptyStr(c["baselineId"]);
  const pageSize = asFiniteNum(c["pageSize"]);
  const eph = asNonEmptyStr(c["ephemeralP256PubkeySpkiB64"]);
  const nonce = asNonEmptyStr(c["nonce"]);
  const issuedAtMs = asFiniteNum(c["issuedAtMs"]);
  const expiresAtMs = asFiniteNum(c["expiresAtMs"]);
  const claimsSha256Hex = asNonEmptyStr(obj["claimsSha256Hex"]);
  const signerPubkeySpkiB64 = asNonEmptyStr(obj["signerPubkeySpkiB64"]);
  const signatureB64 = asNonEmptyStr(obj["signatureB64"]);
  if (
    !capsuleHash ||
    !rustTarget ||
    !baselineId ||
    pageSize === null ||
    !eph ||
    !nonce ||
    issuedAtMs === null ||
    expiresAtMs === null ||
    !claimsSha256Hex ||
    !signerPubkeySpkiB64 ||
    !signatureB64
  ) {
    return null;
  }
  return {
    claims: {
      capsuleHash,
      rustTarget,
      baselineId,
      pageSize,
      ephemeralP256PubkeySpkiB64: eph,
      nonce,
      issuedAtMs,
      expiresAtMs,
    },
    claimsSha256Hex,
    signerPubkeySpkiB64,
    signatureB64,
  };
}

async function handleIssueAttestedKeyLease(
  ctx: DispatchCtx,
  req: CdpRequest,
): Promise<Record<string, unknown>> {
  if (ctx.browser.connectionRole === "viewer") {
    return { error: "viewer connection cannot request attested key leases" };
  }
  const authority = ctx.browser.authority;
  if (!authority) return { error: "authority service unavailable" };
  const paramsObj = (req.params ?? {}) as Record<string, unknown>;
  const attestation = parseSignedAttestationParam(paramsObj["attestation"]);
  if (!attestation) return { error: "valid A5 attestation parameter is required" };
  const sessionId = asSessionId(
    asNonEmptyStr(paramsObj["sessionId"]) ?? ctx.browser.sessionId ?? "",
  );
  const userId = asUserId(asNonEmptyStr(paramsObj["userId"]) ?? ctx.browser.userId ?? "");
  const ttlMs = asFiniteNum(paramsObj["ttlMs"]) ?? 60_000;
  const epoch = asFiniteNum(paramsObj["epoch"]) ?? ctx.browser.sessionEpoch ?? 1;
  const leaseId = asNonEmptyStr(paramsObj["leaseId"]) ?? undefined;
  const nowMs = asFiniteNum(paramsObj["nowMs"]) ?? undefined;
  if (!sessionId || !userId) {
    return { error: "sessionId and userId are required for attested key lease" };
  }
  try {
    const res = await authority.issueAttestedKeyLease({
      attestation,
      userId,
      sessionId,
      ttlMs,
      epoch,
      leaseId,
      nowMs,
    });
    return {
      payload: res.signedLease.payload,
      signatureBase64: res.signedLease.signatureBase64,
      wrappedRelease: wrappedKeyLeaseToWire(res.wrappedRelease),
    };
  } catch (err) {
    return { error: errorText(err) };
  }
}

async function handleReleaseDbscCredential(
  ctx: DispatchCtx,
  req: CdpRequest,
): Promise<Record<string, unknown>> {
  if (ctx.browser.connectionRole === "viewer") {
    return { error: "viewer connection cannot request DBSC credentials" };
  }
  const authority = ctx.browser.authority;
  if (!authority) return { error: "authority service unavailable" };
  const paramsObj = (req.params ?? {}) as Record<string, unknown>;
  const attestation = parseSignedAttestationParam(paramsObj["attestation"]);
  const dbscSessionId = asNonEmptyStr(paramsObj["dbscSessionId"]);
  const origin = asNonEmptyStr(paramsObj["origin"]);
  const challenge = asNonEmptyStr(paramsObj["challenge"]);
  const nowMs = asFiniteNum(paramsObj["nowMs"]) ?? undefined;
  if (!attestation || !dbscSessionId || !origin || !challenge) {
    return { error: "attestation, dbscSessionId, origin, and challenge are required" };
  }
  try {
    const credential = await authority.releaseAttestedDbsc({
      attestation,
      dbscSessionId,
      origin,
      challenge,
      nowMs,
    });
    return { credential };
  } catch (err) {
    return { error: errorText(err) };
  }
}

async function handleRoamSession(
  ctx: DispatchCtx,
  req: CdpRequest,
): Promise<Record<string, unknown>> {
  const sid = ctx.browser.sessionId;
  const userId = ctx.browser.userId;
  if (!ctx.sessionManager || !sid || !userId) {
    return { error: "no active persistent session" };
  }
  const paramsObj = (req.params ?? {}) as Record<string, unknown>;
  const authority = ctx.browser.authority;
  const attAuthority = authority?.getCapsuleAttestationAuthority() ?? null;
  let wrappedRelease: ReturnType<typeof wrappedKeyLeaseToWire> | undefined;
  if (authority && attAuthority) {
    const attestation = parseSignedAttestationParam(paramsObj["attestation"]);
    if (!attestation) {
      return { error: "A5 capsule attestation is required to roam key leases" };
    }
    try {
      const ttlMs = asFiniteNum(paramsObj["ttlMs"]) ?? 60_000;
      const nowMs = asFiniteNum(paramsObj["nowMs"]) ?? undefined;
      const nextEpoch = (ctx.browser.sessionEpoch ?? 1) + 1;
      const attested = await authority.issueAttestedKeyLease({
        attestation,
        userId,
        sessionId: sid,
        ttlMs,
        epoch: nextEpoch,
        nowMs,
      });
      wrappedRelease = wrappedKeyLeaseToWire(attested.wrappedRelease);
    } catch (err) {
      return { error: errorText(err) };
    }
  }
  for (const t of ctx.browser.targets.values()) {
    if (t.type === "page") await captureTargetVisualState(t);
  }
  const rawConn = paramsObj["newConnectionId"];
  const newConnectionId = asConnectionId(
    typeof rawConn === "string" && rawConn ? rawConn : ctx.connectionId,
  );
  const forceTier1Restore = paramsObj["forceTier1Restore"] === true;
  const res = await ctx.sessionManager.roam({
    sessionId: sid,
    userId,
    newConnectionId,
    emit: ctx.emit,
    forceTier1Restore,
  });
  ctx.browser.sessionEpoch = res.attachment.epoch;
  ctx.browser.connectionRole = res.attachment.role;
  return {
    epoch: res.attachment.epoch,
    role: res.attachment.role,
    checkpoint: res.checkpoint,
    restoreResult: res.restoreResult,
    ...(wrappedRelease ? { wrappedRelease } : {}),
  };
}
