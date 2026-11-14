// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Loads the renderer isolate and serializes frame and PDF rendering calls.

import rendererGlueSource from "../../../renderer-core/pkg/renderer_core.glue.js";
import rendererWasmModule from "../../../renderer-core/pkg/renderer_core_bg.wasm";
import { PAGE_RENDERER_SOURCE } from "@parawing/page-renderer";
import { loadWasmBytesFromVfs } from "./page-script.ts";
import { traceSpan } from "../tracing.ts";
import { localTraceParentProps } from "../tracing-local.ts";
import { getFontBytes, getImageBytes } from "./resource-store.ts";
import { isIsolateGoneError } from "./limit-registry.ts";
import type { HostCapabilities } from "../host-capabilities.ts";
import type { HostIsolateLoader, LoadedIsolate } from "../isolate-loader.ts";
import type { RemoteFetcher } from "@parawing/jsrpc-types/rpc";
import type {
  PageRendererEntrypoint,
  RenderFrameOpts,
  RenderPdfOpts,
  RenderPortStub,
  RenderStage,
  RendererMemoryStats,
} from "@parawing/jsrpc-types/page-renderer";
import type { DynamicWorkerBudget, WorkerLease } from "./worker-budget.ts";

export type { RenderStage };

void rendererWasmModule;

const PAGE_RENDERER_COMPAT_DATE = "2026-09-11";

const PAGE_RENDERER_SUBREQUEST_CAP = 100;
const PAGE_RENDERER_CPU_TIME_MS_CAP = 300_000;

const RENDER_CALL_TIMEOUT_MS = 15_000;
const PDF_CALL_TIMEOUT_MS = 30_000;
const PORT_MINT_TIMEOUT_MS = 5_000;
const MAX_RENDER_RASTER_ATTEMPTS = 2;

type RendererStub = RemoteFetcher<PageRendererEntrypoint>;

class RendererTimeoutError extends Error {}

export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new RendererTimeoutError(`${label}: timeout after ${ms}ms`)),
      ms,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function loadRenderer(
  host: HostCapabilities,
  isolateLoader: HostIsolateLoader,
  connectionId: string,
  attributionHeaders: Record<string, string>,
  initialRes: { width: number; height: number } | null,
): LoadedIsolate<RendererStub> {
  const tailToken = crypto.randomUUID();
  const compat = host.config.workerCompat;
  return isolateLoader.load<RendererStub>({
    kind: "page-renderer",
    entrypoint: "PageRenderer",
    compatibilityDate: compat?.compatibilityDate ?? PAGE_RENDERER_COMPAT_DATE,
    compatibilityFlags: compat?.compatibilityFlags ?? ["no_nodejs_compat", "no_nodejs_compat_v2"],
    mainModule: "renderer.js",
    modules: {
      "renderer.js": PAGE_RENDERER_SOURCE,
      "wasm-glue.js": rendererGlueSource,
      "core_bg.wasm": { wasm: loadWasmBytesFromVfs("renderer_core_bg.wasm") },
    },
    env: {
      KS_TAIL_TOKEN: tailToken,
      ...(initialRes ? { KS_INITIAL_RES: `${initialRes.width}x${initialRes.height}` } : {}),
    },
    ...(host.tracer ? { spanSink: { kind: "renderer", ...localTraceParentProps() } } : {}),
    // Resources arrive through engine callbacks; the renderer has no outbound network path.
    outbound: { mode: "denied" },
    tail: {
      scriptName: `renderer-${connectionId}`,
      ksErrToken: tailToken,
      sessionId: connectionId,
    },
    attributionHeaders,
    attributionScriptName: "parawing-page-renderer",
    limits: {
      cpuMs: PAGE_RENDERER_CPU_TIME_MS_CAP,
      subRequests: PAGE_RENDERER_SUBREQUEST_CAP,
    },
  });
}

export interface RenderPortSource {
  getRenderPort(): Promise<RenderPortStub>;
}

export type RenderFrameOptions = Omit<RenderFrameOpts, "tp" | "scope">;

export interface RenderFrameResult {
  ok: boolean;
  unchanged?: boolean;
  bytes?: Uint8Array;
  error?: string;
  stage?: RenderStage;
  info?: string;
  seq: number;
  scrollX: number;
  scrollY: number;
}

export type RenderPdfOptions = Omit<RenderPdfOpts, "tp" | "scope">;

export interface RenderPdfResult {
  ok: boolean;
  bytes?: Uint8Array;
  error?: string;
  stage?: RenderStage;
  info?: string;
}

export class PageRendererManager {
  private host: HostCapabilities;
  private isolateLoader: HostIsolateLoader;
  private connectionId: string;
  private attributionHeaders: Record<string, string>;
  private loaded: LoadedIsolate<RendererStub> | null = null;
  private stub: RendererStub | null = null;
  private everLoaded = false;
  private initialRes: { width: number; height: number } | null = null;
  private lease: WorkerLease | null = null;
  private budget: DynamicWorkerBudget | null = null;
  private closed = false;
  private lastMemory: RendererMemoryStats | null = null;
  relaunchCount = 0;
  framesRendered = 0;
  partialFramesRendered = 0;
  // Render RPCs mutate one retained partial-frame base, so keep them ordered.
  private queue: Promise<unknown> = Promise.resolve();
  // The renderer cache serves resources that a page reports by hash, so only the isolate that
  // supplied them may use them. One opaque scope per render port source.
  private readonly resourceScopes = new WeakMap<RenderPortSource, string>();

  private resourceScope(source: RenderPortSource): string {
    let scope = this.resourceScopes.get(source);
    if (!scope) {
      scope = crypto.randomUUID();
      this.resourceScopes.set(source, scope);
    }
    return scope;
  }

  constructor(
    host: HostCapabilities,
    isolateLoader: HostIsolateLoader,
    connectionId: string,
    attributionHeaders: Record<string, string> = {},
    budget: DynamicWorkerBudget | null = null,
    initialRes: { width: number; height: number } | null = null,
  ) {
    this.host = host;
    this.isolateLoader = isolateLoader;
    this.connectionId = connectionId;
    this.attributionHeaders = attributionHeaders;
    this.budget = budget;
    this.initialRes = initialRes;
  }

  private ensure(): RendererStub {
    if (this.closed) throw new Error("renderer closed with its connection");
    if (!this.stub) {
      if (this.everLoaded) this.relaunchCount += 1;
      this.everLoaded = true;
      this.lease = this.budget?.acquire("renderer") ?? null;
      this.loaded = traceSpan(this.host.tracer, "init.renderer_spawn", () =>
        loadRenderer(
          this.host,
          this.isolateLoader,
          this.connectionId,
          this.attributionHeaders,
          this.initialRes,
        ),
      );
      this.stub = this.loaded.entrypoint;
    }
    return this.stub;
  }

  private traceParentId(): string | null {
    return this.host.tracer?.getSpanContext()?.spanId ?? null;
  }

  private fetchStoredImage(key: string): Uint8Array {
    let parsed: bigint;
    try {
      parsed = BigInt(key);
    } catch {
      return new Uint8Array(0);
    }
    return getImageBytes(parsed, this.connectionId) ?? new Uint8Array(0);
  }

  private fetchStoredFont(key: string): Uint8Array {
    let parsed: bigint;
    try {
      parsed = BigInt(key);
    } catch {
      return new Uint8Array(0);
    }
    return getFontBytes(parsed, this.connectionId) ?? new Uint8Array(0);
  }

  private async fetchFontAsset(path: string): Promise<Uint8Array> {
    if (!path.startsWith("/fonts/") || path.includes("..")) {
      throw new Error(`fetchFontAsset: refusing path ${path}`);
    }
    const resp = await this.host.assets.fetch(
      new Request(`https://parawing.invalid${path}`, { method: "GET" }),
    );
    if (!resp.ok) {
      throw new Error(`fetchFontAsset: HTTP ${resp.status} for ${path}`);
    }
    return new Uint8Array(await resp.arrayBuffer());
  }

  // What the renderer reported with its last frame or PDF. Asking it directly would start a fresh
  // renderer when the idle one was evicted, or after it was disposed.
  memoryStats(): RendererMemoryStats | null {
    return this.lastMemory;
  }

  initialResString(): string | null {
    return this.initialRes ? `${this.initialRes.width}x${this.initialRes.height}` : null;
  }

  /** Releases the worker lease and requests isolate shutdown without waiting for completion. */
  dispose(reason = "renderer disposed", gone = false): void {
    const loaded = this.loaded;
    this.loaded = null;
    this.stub = null;
    this.lease?.release();
    this.lease = null;
    if (!loaded) return;
    // `gone` means the isolate was evicted: a call on its entrypoint would start a fresh one only
    // for the kill to abort it.
    if (gone) {
      loaded[Symbol.dispose]();
      return;
    }
    this.host.tasks.run(
      loaded
        .terminate(reason)
        .catch(() => {})
        .finally(() => {
          loaded[Symbol.dispose]();
        }),
    );
  }

  // Called when the connection closes: a render still queued then fails instead of loading a
  // renderer that nothing would ever kill.
  close(reason = "renderer closed"): void {
    this.closed = true;
    this.dispose(reason);
  }

  /**
   * Serializes frame renders so calls cannot mutate the retained partial-frame base concurrently.
   * Worker and timeout failures resolve as `ok: false`; timed-out workers are discarded.
   */
  async renderFrame(
    source: RenderPortSource,
    opts: RenderFrameOptions,
  ): Promise<RenderFrameResult> {
    const run = this.queue
      .catch(() => {})
      .then(async () => {
        let lastError = "";
        for (let attempt = 0; attempt < MAX_RENDER_RASTER_ATTEMPTS; attempt++) {
          try {
            const result = await this.renderFrameOnce(source, opts);
            if (result.ok || result.stage !== "raster") return result;
            throw new Error(result.error ?? "renderFrame raster failure");
          } catch (error) {
            lastError = error instanceof Error ? error.message : String(error);
            const gone = isIsolateGoneError(lastError);
            this.dispose(`renderFrame failed: ${lastError}`, gone);
            // A timed-out RPC may still be running, so do not retry against this renderer. An
            // evicted one means workers are scarce, and a reload would evict another.
            if (error instanceof RendererTimeoutError || gone || this.closed) break;
          }
        }
        return {
          ok: false,
          error: lastError,
          seq: 0,
          scrollX: 0,
          scrollY: 0,
        };
      });
    this.queue = run;
    return run;
  }

  private async renderFrameOnce(
    source: RenderPortSource,
    opts: RenderFrameOptions,
  ): Promise<RenderFrameResult> {
    const traceParentId = this.traceParentId();
    let port: RenderPortStub;
    try {
      port = await withTimeout(source.getRenderPort(), PORT_MINT_TIMEOUT_MS, "getRenderPort");
    } catch (error) {
      return {
        ok: false,
        stage: "record",
        error: `getRenderPort failed: ${error instanceof Error ? error.message : String(error)}`,
        seq: 0,
        scrollX: 0,
        scrollY: 0,
      };
    }
    // Load the renderer only once the port exists: when the page is already gone, minting fails
    // and no renderer is spent on it.
    const stub = this.ensure();
    const reply = await withTimeout(
      stub.renderFrame(
        port,
        {
          format: opts.format,
          quality: opts.quality,
          omitBackground: opts.omitBackground,
          ...(typeof opts.sinceSeq === "number" ? { sinceSeq: opts.sinceSeq } : {}),
          ...(opts.clip ? { clip: opts.clip } : {}),
          ...(typeof opts.partialKey === "string" && opts.partialKey
            ? { partialKey: opts.partialKey }
            : {}),
          ...(opts.images ? { images: opts.images } : {}),
          scope: this.resourceScope(source),
          ...(opts.traced ? { traced: true } : {}),
          ...(traceParentId ? { tp: traceParentId } : {}),
        },
        (path: string) => this.fetchFontAsset(path),
        async (key: string) => this.fetchStoredImage(key),
        async (key: string) => this.fetchStoredFont(key),
      ),
      RENDER_CALL_TIMEOUT_MS,
      "renderFrame",
    );
    if (reply.memory) this.lastMemory = reply.memory;
    const seq = typeof reply.seq === "number" ? reply.seq : 0;
    const scrollX = typeof reply.scrollX === "number" ? reply.scrollX : 0;
    const scrollY = typeof reply.scrollY === "number" ? reply.scrollY : 0;
    if (reply.unchanged === true) {
      return { ok: true, unchanged: true, seq, scrollX, scrollY };
    }
    this.logSlowPhases("renderFrame", reply.phases);
    if (reply.error || !(reply.bytes instanceof Uint8Array) || reply.bytes.length === 0) {
      return {
        ok: false,
        stage: reply.stage ?? "raster",
        error: reply.error ?? "renderer returned empty bytes",
        info: reply.info,
        seq,
        scrollX,
        scrollY,
      };
    }
    this.framesRendered += 1;
    if (
      Array.isArray(reply.phases) &&
      reply.phases.some((phase) => typeof phase === "string" && phase.startsWith("rasterPartial="))
    ) {
      this.partialFramesRendered += 1;
    }
    return {
      ok: true,
      bytes: reply.bytes,
      info: reply.info,
      seq,
      scrollX,
      scrollY,
    };
  }

  /** Queues PDF rendering on the shared renderer worker; worker failures resolve as `ok: false`. */
  async renderPdf(source: RenderPortSource, opts: RenderPdfOptions): Promise<RenderPdfResult> {
    const run = this.queue
      .catch(() => {})
      .then(async () => {
        let lastError = "";
        for (let attempt = 0; attempt < MAX_RENDER_RASTER_ATTEMPTS; attempt++) {
          try {
            const result = await this.renderPdfOnce(source, opts);
            if (result.ok || result.stage !== "raster") return result;
            throw new Error(result.error ?? "renderPdf raster failure");
          } catch (error) {
            lastError = error instanceof Error ? error.message : String(error);
            const gone = isIsolateGoneError(lastError);
            this.dispose(`renderPdf failed: ${lastError}`, gone);
            if (error instanceof RendererTimeoutError || gone || this.closed) break;
          }
        }
        return { ok: false, error: lastError };
      });
    this.queue = run;
    return run;
  }

  private async renderPdfOnce(
    source: RenderPortSource,
    opts: RenderPdfOptions,
  ): Promise<RenderPdfResult> {
    const traceParentId = this.traceParentId();
    let port: RenderPortStub;
    try {
      port = await withTimeout(source.getRenderPort(), PORT_MINT_TIMEOUT_MS, "getRenderPort");
    } catch (error) {
      return {
        ok: false,
        stage: "record",
        error: `getRenderPort failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    const stub = this.ensure();
    const reply = await withTimeout(
      stub.renderPdf(
        port,
        {
          paperWidth: opts.paperWidth,
          paperHeight: opts.paperHeight,
          omitBackground: opts.omitBackground,
          marginTop: opts.marginTop,
          marginRight: opts.marginRight,
          marginBottom: opts.marginBottom,
          marginLeft: opts.marginLeft,
          scope: this.resourceScope(source),
          ...(opts.traced ? { traced: true } : {}),
          ...(traceParentId ? { tp: traceParentId } : {}),
        },
        (path: string) => this.fetchFontAsset(path),
        async (key: string) => this.fetchStoredImage(key),
        async (key: string) => this.fetchStoredFont(key),
      ),
      PDF_CALL_TIMEOUT_MS,
      "renderPdf",
    );
    if (reply.memory) this.lastMemory = reply.memory;
    this.logSlowPhases("renderPdf", reply.phases);
    if (reply.error || !(reply.bytes instanceof Uint8Array) || reply.bytes.length === 0) {
      return {
        ok: false,
        stage: reply.stage ?? "raster",
        error: reply.error ?? "renderer returned empty bytes",
        info: reply.info,
      };
    }
    this.framesRendered += 1;
    return { ok: true, bytes: reply.bytes, info: reply.info };
  }

  private logSlowPhases(method: string, phases?: string[]): void {
    if (!Array.isArray(phases)) return;
    const totalMs = phases
      .map((phase) => Number(phase.split("=")[1]?.replace("ms", "")) || 0)
      .reduce((sumMs, phaseMs) => sumMs + phaseMs, 0);
    if (totalMs > 1_000) {
      console.warn(`[pw-rvr] ${method} phases: ${phases.join(" ")}`);
    }
  }
}
