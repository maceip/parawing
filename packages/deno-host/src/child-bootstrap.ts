// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Zero-permission Deno subprocess entrypoint hosting one isolate over PRWP stdin/stdout.

import "./deno-ambient.ts";
import { parse as parseEsm } from "es-module-lexer/js";
import { createRpcSession, markRpcTarget, type RpcSession } from "@parawing/rpc-transport";
import type { IsolateModule } from "@parawing/engine/isolate-loader";
import type { SessionOutboundRequest } from "@parawing/jsrpc-types/page-script";
import {
  RpcTarget,
  WorkerEntrypoint,
  abortIsolate,
  setAbortIsolateHandler,
} from "./workers-compat-shim.ts";
import { createV8RealmEvaluator, type V8RealmEvaluator } from "./v8-realm-evaluator.ts";

const encoder = new TextEncoder();

const STRIPPED_HOST_GLOBALS = [
  "Deno",
  "process",
  "Buffer",
  "global",
  "setImmediate",
  "clearImmediate",
  "caches",
  "Cache",
  "CacheStorage",
  "localStorage",
  "sessionStorage",
  "Storage",
  "BroadcastChannel",
  "Worker",
  "Window",
  "Location",
  "Navigator",
  "NavigatorUAData",
  "location",
] as const;

function stripHostGlobals(): void {
  for (const key of STRIPPED_HOST_GLOBALS) {
    if (!(key in globalThis)) continue;
    try {
      Reflect.deleteProperty(globalThis, key);
    } catch {}
  }
}

interface ChildTailSink {
  log(level: string, message: unknown[], timestamp: number): void;
  exception(ex: { name: string; message: string; stack?: string; timestamp: number }): void;
}

export interface ChildInitPayload {
  kind: string;
  entrypoint: string;
  mainModule: string;
  modules: Record<string, IsolateModule>;
  networkMode: "denied" | "sandbox";
  executionBackend?: "boa" | "v8";
  env?: Record<string, unknown>;
  entrypointProps?: Record<string, unknown>;
  globalOutbound?: (req: SessionOutboundRequest) => Promise<Response>;
  tailSink?: ChildTailSink;
}

const runtime = Deno;
if (!runtime) {
  throw new Error("child-bootstrap must run inside Deno");
}

const rawStdinReadable = runtime.stdin.readable;
const rawStdoutWritable = runtime.stdout.writable;
const writeStderr = (line: string): void => {
  try {
    runtime.stderr.writeSync(encoder.encode(line));
  } catch {}
};
const exitProcess = (code: number): never => runtime.exit(code);

function formatLogArg(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

let activeTailSink: ChildTailSink | null = null;
const pendingLogs: Array<{ level: string; message: unknown[]; timestamp: number }> = [];
const MAX_PENDING_LOGS = 256;

function recordConsole(level: string, args: unknown[]): void {
  const timestamp = Date.now();
  const formatted = args.map(formatLogArg).join(" ");
  writeStderr(`[child:${level}] ${formatted}\n`);
  if (activeTailSink) {
    try {
      void activeTailSink.log(level, args, timestamp);
    } catch {}
    return;
  }
  if (pendingLogs.length < MAX_PENDING_LOGS) {
    pendingLogs.push({ level, message: args, timestamp });
  }
}

console.log = (...args: unknown[]): void => recordConsole("log", args);
console.info = (...args: unknown[]): void => recordConsole("info", args);
console.debug = (...args: unknown[]): void => recordConsole("debug", args);
console.warn = (...args: unknown[]): void => recordConsole("warn", args);
console.error = (...args: unknown[]): void => recordConsole("error", args);
console.trace = (...args: unknown[]): void => recordConsole("debug", args);
console.dir = (item?: unknown): void => recordConsole("log", [item]);

setAbortIsolateHandler((reason: string): never => {
  writeStderr(`[pw-abort] ${reason}\n`);
  return exitProcess(1);
});

globalThis.addEventListener("error", (ev: Event): void => {
  const errEv = ev as ErrorEvent;
  const err = errEv.error as Error | undefined;
  const name = err?.name ?? "Error";
  const message = err?.message ?? errEv.message ?? "Uncaught error";
  const stack = err?.stack;
  writeStderr(`[child:uncaught] ${name}: ${message}\n`);
  if (activeTailSink) {
    try {
      void activeTailSink.exception({
        name,
        message,
        ...(stack !== undefined ? { stack } : {}),
        timestamp: Date.now(),
      });
    } catch {}
  }
});

globalThis.addEventListener("unhandledrejection", (ev: PromiseRejectionEvent): void => {
  const reason = ev.reason;
  const err = reason instanceof Error ? reason : null;
  const name = err?.name ?? "UnhandledRejection";
  const message = err?.message ?? formatLogArg(reason);
  const stack = err?.stack;
  writeStderr(`[child:unhandledrejection] ${name}: ${message}\n`);
  if (activeTailSink) {
    try {
      void activeTailSink.exception({
        name,
        message,
        ...(stack !== undefined ? { stack } : {}),
        timestamp: Date.now(),
      });
    } catch {}
  }
});

function toArrayBuffer(bytes: Uint8Array | ArrayBuffer): ArrayBuffer {
  if (bytes instanceof ArrayBuffer) return bytes;
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}

function installGlobalNetwork(
  mode: "denied" | "sandbox",
  outbound?: (req: SessionOutboundRequest) => Promise<Response>,
): void {
  if (mode === "denied") {
    const deniedFetch: typeof globalThis.fetch = (): Promise<Response> =>
      Promise.reject(new TypeError("parawing: network egress is denied in this isolate"));
    Object.defineProperty(globalThis, "fetch", {
      value: deniedFetch,
      configurable: true,
      writable: true,
    });
    class DeniedWebSocket {
      constructor() {
        throw new TypeError("parawing: WebSocket is denied in this isolate");
      }
    }
    Object.defineProperty(globalThis, "WebSocket", {
      value: DeniedWebSocket,
      configurable: true,
      writable: true,
    });
    return;
  }
  if (!outbound) return;
  const nativeHeadersEntries = (hdrs: Headers): Array<[string, string]> => {
    const out: Array<[string, string]> = [];
    hdrs.forEach((v, k) => out.push([k, v]));
    return out;
  };
  const sandboxedFetch: typeof globalThis.fetch = async (input, init): Promise<Response> => {
    const req = input instanceof Request && !init ? input : new Request(input, init);
    const body = req.body ? await req.arrayBuffer() : null;
    return await outbound({
      url: req.url,
      method: req.method,
      headers: nativeHeadersEntries(req.headers),
      body,
    });
  };
  Object.defineProperty(globalThis, "fetch", {
    value: sandboxedFetch,
    configurable: true,
    writable: true,
  });
}

function resolveModuleKey(
  fromKey: string,
  spec: string,
  moduleKeys: ReadonlySet<string>,
): string | null {
  if (spec === "cloudflare:workers") return "__ks_compat_cloudflare_workers.js";
  if (moduleKeys.has(spec)) return spec;
  if (spec.startsWith("./")) {
    const plain = spec.slice(2);
    if (moduleKeys.has(plain)) return plain;
  }
  if (fromKey.startsWith("http://") || fromKey.startsWith("https://")) {
    try {
      const resolved = new URL(spec, fromKey).toString();
      if (moduleKeys.has(resolved)) return resolved;
    } catch {}
  }
  try {
    const base = new URL(fromKey, "https://pw-module.invalid/");
    const resolved = new URL(spec, base);
    if (resolved.origin === "https://pw-module.invalid") {
      const rel = resolved.pathname.slice(1);
      if (moduleKeys.has(rel)) return rel;
    }
  } catch {}
  return null;
}

interface InternalBridge {
  getWasm(key: string): WebAssembly.Module;
  getData(key: string): ArrayBuffer;
  resolveDynImport(fromKey: string, spec: string): string;
  WorkerEntrypoint: typeof WorkerEntrypoint;
  RpcTarget: typeof RpcTarget;
  abortIsolate: typeof abortIsolate;
}

function createBlobUrl(code: string, blobs: string[]): string {
  const url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
  blobs.push(url);
  return url;
}

async function linkAndInstantiate(payload: ChildInitPayload): Promise<{
  instance: object;
  dispose: () => void;
}> {
  const blobUrls: string[] = [];
  const wasmModules = new Map<string, WebAssembly.Module>();
  const dataBuffers = new Map<string, ArrayBuffer>();
  const rawModules = new Map<string, IsolateModule>(Object.entries(payload.modules));

  for (const [key, mod] of rawModules.entries()) {
    if (typeof mod === "object" && mod !== null) {
      if ("wasm" in mod) {
        wasmModules.set(key, new WebAssembly.Module(toArrayBuffer(mod.wasm)));
      } else if ("data" in mod) {
        dataBuffers.set(key, toArrayBuffer(mod.data));
      }
    }
  }

  const allKeys = new Set<string>([...rawModules.keys(), "__ks_compat_cloudflare_workers.js"]);
  const urlByKey = new Map<string, string>();
  const handoffSym = Symbol("ks.internal.bridge");

  const bridge: InternalBridge = {
    getWasm(key: string): WebAssembly.Module {
      const m = wasmModules.get(key);
      if (!m) throw new Error(`Missing precompiled wasm module: ${key}`);
      return m;
    },
    getData(key: string): ArrayBuffer {
      const buf = dataBuffers.get(key);
      if (!buf) throw new Error(`Missing data module: ${key}`);
      return buf;
    },
    resolveDynImport(fromKey: string, spec: string): string {
      const resolvedKey = resolveModuleKey(fromKey, spec, allKeys);
      const url = resolvedKey ? urlByKey.get(resolvedKey) : undefined;
      if (!url) {
        throw new TypeError(`Cannot find module '${spec}' imported from '${fromKey}'`);
      }
      return url;
    },
    WorkerEntrypoint,
    RpcTarget,
    abortIsolate,
  };

  Object.defineProperty(globalThis, handoffSym, {
    value: bridge,
    configurable: true,
    enumerable: false,
  });
  const registryCode =
    `const syms = Object.getOwnPropertySymbols(globalThis);\n` +
    `const sym = syms.find((s) => s.description === "ks.internal.bridge");\n` +
    `const b = sym ? globalThis[sym] : undefined;\n` +
    `if (sym) delete globalThis[sym];\n` +
    `if (!b) throw new Error("parawing: missing internal module registry");\n` +
    `export const getWasm = b.getWasm;\n` +
    `export const getData = b.getData;\n` +
    `export const resolveDynImport = b.resolveDynImport;\n` +
    `export const WorkerEntrypoint = b.WorkerEntrypoint;\n` +
    `export const RpcTarget = b.RpcTarget;\n` +
    `export const abortIsolate = b.abortIsolate;\n`;
  const registryUrl = createBlobUrl(registryCode, blobUrls);

  // Import registry module now so `handoffSym` is deleted before any user script links.
  await import(registryUrl);

  const cfWorkersUrl = createBlobUrl(
    `export { WorkerEntrypoint, RpcTarget, abortIsolate } from ${JSON.stringify(registryUrl)};\n`,
    blobUrls,
  );
  urlByKey.set("__ks_compat_cloudflare_workers.js", cfWorkersUrl);

  const visiting = new Set<string>();
  const ensureModuleUrl = (key: string): string => {
    const existing = urlByKey.get(key);
    if (existing) return existing;
    if (visiting.has(key)) {
      throw new Error(`Circular ESM dependency involving ${key} is unsupported with blob URLs`);
    }
    visiting.add(key);
    const mod = rawModules.get(key);
    if (mod === undefined) {
      visiting.delete(key);
      throw new Error(`Missing isolate module: ${key}`);
    }
    const url = buildSingleModuleUrl(key, mod);
    visiting.delete(key);
    urlByKey.set(key, url);
    return url;
  };

  const buildSingleModuleUrl = (key: string, mod: IsolateModule): string => {
    if (typeof mod === "object" && mod !== null) {
      if ("wasm" in mod) {
        return createBlobUrl(
          `import { getWasm } from ${JSON.stringify(registryUrl)};\n` +
            `export default getWasm(${JSON.stringify(key)});\n`,
          blobUrls,
        );
      }
      if ("data" in mod) {
        return createBlobUrl(
          `import { getData } from ${JSON.stringify(registryUrl)};\n` +
            `export default getData(${JSON.stringify(key)});\n`,
          blobUrls,
        );
      }
      if ("json" in mod) {
        return createBlobUrl(`export default JSON.parse(${JSON.stringify(mod.json)});\n`, blobUrls);
      }
      if ("text" in mod) {
        return createBlobUrl(`export default ${JSON.stringify(mod.text)};\n`, blobUrls);
      }
      if ("cjs" in mod) {
        const rewritten = rewriteDynamicImportsOnly(key, mod.cjs, false);
        const dynImportDecl =
          rewritten === mod.cjs
            ? ""
            : `import { resolveDynImport as __ksDynResolve } from ${JSON.stringify(registryUrl)};\n`;
        return createBlobUrl(
          `${dynImportDecl}` +
            `const __ksMod = { exports: {} };\n` +
            `const __ksReq = (id) => { throw new Error("require(" + String(id) + ") is not supported in " + ${JSON.stringify(key)}); };\n` +
            `(function (exports, require, module) {\n${rewritten}\n}).call(globalThis, __ksMod.exports, __ksReq, __ksMod);\n` +
            `export default __ksMod.exports;\n` +
            `export const run = __ksMod.exports && __ksMod.exports.run;\n` +
            `//# sourceURL=${key}\n`,
          blobUrls,
        );
      }
    }
    const source = typeof mod === "string" ? mod : mod.js;
    const rewritten = rewriteEsmSource(key, source, allKeys, ensureModuleUrl, registryUrl);
    return createBlobUrl(`${rewritten}\n//# sourceURL=${key}\n`, blobUrls);
  };

  for (const key of rawModules.keys()) {
    ensureModuleUrl(key);
  }

  const mainUrl = urlByKey.get(payload.mainModule);
  if (!mainUrl) {
    throw new Error(`Missing main module: ${payload.mainModule}`);
  }
  const ns = (await import(mainUrl)) as Record<string, unknown>;
  const EntrypointCtor = ns[payload.entrypoint];
  if (typeof EntrypointCtor !== "function") {
    throw new Error(`Missing entrypoint export '${payload.entrypoint}' in ${payload.mainModule}`);
  }

  const waitPromises = new Set<Promise<unknown>>();
  const ctx = {
    props: payload.entrypointProps ?? {},
    waitUntil(promise: Promise<unknown>): void {
      const p = Promise.resolve(promise).catch(() => {});
      waitPromises.add(p);
      void p.finally(() => waitPromises.delete(p));
    },
    passThroughOnException(): void {},
  };
  const instance = Reflect.construct(EntrypointCtor, [ctx, payload.env ?? {}]) as object;
  return {
    instance,
    dispose: (): void => {
      for (const u of blobUrls) {
        try {
          URL.revokeObjectURL(u);
        } catch {}
      }
    },
  };
}

function rewriteDynamicImportsOnly(key: string, source: string, throwOnParseError = true): string {
  let imports: ReturnType<typeof parseEsm>[0];
  try {
    [imports] = parseEsm(source);
  } catch (err) {
    if (throwOnParseError) throw err;
    return source;
  }
  const parts: string[] = [];
  let cursor = 0;
  for (const imp of imports) {
    if (imp.d >= 0) {
      parts.push(
        source.slice(cursor, imp.d),
        `(__ksDynResolve(${JSON.stringify(key)}, `,
        source.slice(imp.s, imp.e),
        ")",
      );
      cursor = imp.e;
    }
  }
  if (cursor === 0) return source;
  parts.push(source.slice(cursor));
  return parts.join("");
}

function rewriteEsmSource(
  key: string,
  source: string,
  moduleKeys: ReadonlySet<string>,
  ensureUrl: (targetKey: string) => string,
  registryUrl: string,
): string {
  const [imports] = parseEsm(source);
  if (imports.length === 0) return source;
  const parts: string[] = [];
  let cursor = 0;
  let needsDynImport = false;
  for (const imp of imports) {
    if (imp.d === -1 && imp.n !== undefined) {
      const resolvedKey = resolveModuleKey(key, imp.n, moduleKeys);
      if (resolvedKey) {
        const targetUrl = ensureUrl(resolvedKey);
        parts.push(source.slice(cursor, imp.s), targetUrl);
        cursor = imp.e;
      }
      continue;
    }
    if (imp.d >= 0) {
      needsDynImport = true;
      parts.push(
        source.slice(cursor, imp.d),
        `(__ksDynResolve(${JSON.stringify(key)}, `,
        source.slice(imp.s, imp.e),
        ")",
      );
      cursor = imp.e;
    }
  }
  parts.push(source.slice(cursor));
  const body = parts.join("");
  if (!needsDynImport) return body;
  return (
    `import { resolveDynImport as __ksDynResolve } from ${JSON.stringify(registryUrl)};\n` + body
  );
}

let activeInstance: object | null = null;
let cleanupLinks: (() => void) | null = null;
let resolveReady!: (instance: object) => void;
let rejectReady!: (err: Error) => void;
const instanceReady = new Promise<object>((resolve, reject) => {
  resolveReady = resolve;
  rejectReady = reject;
});

let sessionRef: RpcSession | null = null;

function flushPendingTailLogs(tailSink: ChildTailSink): void {
  activeTailSink = tailSink;
  while (pendingLogs.length > 0) {
    const item = pendingLogs.shift();
    if (!item) continue;
    try {
      void activeTailSink.log(item.level, item.message, item.timestamp);
    } catch {}
  }
}

let activeV8Evaluator: V8RealmEvaluator | null = null;

async function resolveChildModuleSource(
  specifier: string,
  referrer: string,
  type?: string,
): Promise<{ url: string; source: string; type: "javascript" | "json" }> {
  const url =
    referrer && referrer !== "about:blank" ? new URL(specifier, referrer).toString() : specifier;
  const internals = Reflect.get(globalThis, Symbol.for("parawing.internals"));
  const fetcher =
    internals && typeof internals === "object"
      ? Reflect.get(internals, "fetchModuleSource")
      : undefined;
  if (typeof fetcher !== "function") {
    throw new Error(`Module source loader unavailable for ${url}`);
  }
  const source = String(await fetcher(url, referrer, type));
  return { url, source, type: type === "json" ? "json" : "javascript" };
}

const rpcRoot = markRpcTarget({
  async __ks_init_isolate(payload: ChildInitPayload): Promise<{ ok: true }> {
    if (activeInstance) return { ok: true };
    try {
      if (payload.tailSink) {
        flushPendingTailLogs(payload.tailSink);
      }
      stripHostGlobals();
      installGlobalNetwork(payload.networkMode, payload.globalOutbound);
      if (
        payload.executionBackend === "v8" &&
        (payload.kind === "page-script" || payload.kind === "oopif-frame")
      ) {
        activeV8Evaluator = createV8RealmEvaluator({
          contextName: `parawing-${payload.kind}`,
          loadModuleSource: (req) =>
            resolveChildModuleSource(req.specifier, req.referrer, req.type),
        });
        Reflect.set(globalThis, Symbol.for("parawing.v8RealmEvaluator"), activeV8Evaluator);
      }
      const linked = await linkAndInstantiate(payload);
      activeInstance = linked.instance;
      cleanupLinks = linked.dispose;
      resolveReady(activeInstance);
      return { ok: true };
    } catch (err) {
      activeV8Evaluator?.dispose();
      activeV8Evaluator = null;
      const error = err instanceof Error ? err : new Error(String(err));
      rejectReady(error);
      throw error;
    }
  },
  __ks_dispose(): { ok: true } {
    cleanupLinks?.();
    cleanupLinks = null;
    activeV8Evaluator?.dispose();
    activeV8Evaluator = null;
    queueMicrotask(() => {
      sessionRef?.close();
      exitProcess(0);
    });
    return { ok: true };
  },
});

sessionRef = createRpcSession({
  readable: rawStdinReadable,
  writable: rawStdoutWritable,
  role: "server",
  target: rpcRoot,
  onCall: async (method, args): Promise<unknown> => {
    const instance = await instanceReady;
    const fn = Reflect.get(instance, method);
    if (typeof fn !== "function") {
      throw new Error(`Unknown entrypoint method: ${method}`);
    }
    return await Reflect.apply(fn, instance, args);
  },
  onError: (err): void => {
    writeStderr(`[child:rpc-error] ${err.message}\n`);
  },
});
