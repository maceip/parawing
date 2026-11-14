// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Execution backend seam allowing Boa wasm (Workers) or an isolated native V8 realm (Deno).

import type {
  ArgSpec,
  CallFunctionOnOptions,
  CompileScriptReply,
  EvalOptions,
  EvalResult,
  PropertyDescriptor,
  RunScriptReply,
} from "@parawing/jsrpc-types/page-script";
import { globalizeForBoa } from "./boa-classic.ts";
import { drainEvalResult, type EvalResultBody } from "./eval-results.ts";
import {
  compileScriptEntry,
  getCompiledScript,
  lookupHandle,
  releaseHandle,
  releaseObjectGroup as releaseHandleGroup,
} from "./handles.ts";
import type { RealmEvaluatorBridge } from "./internal-state.js";
import { ksInternals } from "./internals.ts";
import { drainSettleMicrotasks } from "./native-scheduling.ts";
import { packException, packResult } from "./pack.ts";
import { ksGlobalByKey, state } from "./state.ts";
import {
  ks_bridge_ever_minted,
  ks_call_cdp,
  ks_eval_cdp,
  ks_eval_page,
  ks_import,
  ks_run_page_jobs,
} from "./wasm-glue.js";

// Native eval is only a probe; workerd's code-generation EvalError falls back to Boa.
const NATIVE_INDIRECT_EVAL: (source: string) => unknown = globalThis.eval;

export const AsyncFunction = (async () => {}).constructor as new (
  ...args: string[]
) => (...args: unknown[]) => Promise<unknown>;

export const SyncFunction = function () {}.constructor as new (
  ...args: string[]
) => (...args: unknown[]) => unknown;

export interface RunExpressionOpts {
  returnByValue?: boolean;
  awaitPromise?: boolean;
  objectGroup?: string;
}

export interface JsExecutionBackend {
  readonly kind: "boa" | "v8";
  evaluateClassic(source: string, sourceURL?: string): unknown;
  evaluateGlobalClassic(source: string, sourceURL?: string): unknown;
  evaluateModule(url: string, referrer?: string, type?: string): Promise<unknown>;
  compileScript(expression: string, sourceURL: string, persistScript: boolean): CompileScriptReply;
  runCompiledScript(scriptId: string, options: EvalOptions): Promise<RunScriptReply>;
  evalExpression(expression: string, options: RunExpressionOpts): Promise<EvalResult>;
  callFunctionOn(
    functionDeclaration: string,
    argumentSpecs: ArgSpec[],
    options: CallFunctionOnOptions,
  ): Promise<EvalResult>;
  getProperties(
    objectId: string,
    options: { ownProperties?: boolean },
  ): { result: PropertyDescriptor[] };
  releaseObject(objectId: string): void;
  releaseObjectGroup(objectGroup: string): void;
  drainMicrotasks(): Promise<void>;
  pumpTimers(deadlineMs?: number): number;
  nextTimerDelay(): number;
}

export function resolveArgumentSpecs(argumentSpecs: ArgSpec[]): unknown[] {
  const list = Array.isArray(argumentSpecs) ? argumentSpecs : [];
  const out: unknown[] = [];
  for (const spec of list) {
    if (typeof spec === "string") {
      try {
        out.push(JSON.parse(spec));
      } catch {
        out.push(undefined);
      }
      continue;
    }
    if (spec && typeof spec === "object") {
      if (typeof spec.objectId === "string") {
        out.push(lookupHandle(spec.objectId));
        continue;
      }
      if (typeof spec.json === "string") {
        try {
          out.push(JSON.parse(spec.json));
        } catch {
          out.push(undefined);
        }
        continue;
      }
    }
    out.push(undefined);
  }
  return out;
}

export function collectPropertyDescriptors(
  objectValue: unknown,
  ownOnly: boolean,
): PropertyDescriptor[] {
  if (
    objectValue === null ||
    (typeof objectValue !== "object" && typeof objectValue !== "function")
  ) {
    return [];
  }
  const result: PropertyDescriptor[] = [];
  const seen = new Set<string>();
  const collect = function (target: object, isOwn: boolean): void {
    let names: string[];
    try {
      names = Object.getOwnPropertyNames(target);
    } catch {
      return;
    }
    for (const name of names) {
      if (seen.has(name)) continue;
      seen.add(name);
      let descriptor: globalThis.PropertyDescriptor | undefined;
      try {
        descriptor = Object.getOwnPropertyDescriptor(target, name);
      } catch {
        continue;
      }
      if (!descriptor) continue;
      const entry: PropertyDescriptor = {
        name,
        configurable: !!descriptor.configurable,
        enumerable: !!descriptor.enumerable,
        isOwn,
      };
      if ("value" in descriptor) {
        entry.writable = !!descriptor.writable;
        try {
          entry.value = packResult(descriptor.value, false);
        } catch {}
      } else {
        if (typeof descriptor.get === "function") {
          try {
            entry.get = packResult(descriptor.get, false);
          } catch {}
        }
        if (typeof descriptor.set === "function") {
          try {
            entry.set = packResult(descriptor.set, false);
          } catch {}
        }
      }
      result.push(entry);
    }
  };
  collect(objectValue as object, true);
  if (!ownOnly) {
    const MAX_PROTOTYPE_DESCRIPTOR_CHAIN_DEPTH = 6;
    let proto: object | null = null;
    try {
      proto = Object.getPrototypeOf(objectValue);
    } catch {}
    let depth = 0;
    while (proto && depth++ < MAX_PROTOTYPE_DESCRIPTOR_CHAIN_DEPTH) {
      collect(proto, false);
      try {
        proto = Object.getPrototypeOf(proto);
      } catch {
        break;
      }
    }
  }
  return result;
}

function constructErrorByName(errName: string, msg: string): Error {
  if (errName === "TypeError") return new TypeError(msg);
  if (errName === "RangeError") return new RangeError(msg);
  if (errName === "SyntaxError") return new SyntaxError(msg);
  if (errName === "ReferenceError") return new ReferenceError(msg);
  if (errName === "URIError") return new URIError(msg);
  if (errName === "EvalError") return new EvalError(msg);
  const error = new Error(msg);
  if (errName && errName !== "Error") error.name = errName;
  return error;
}

function normalizeBoaThrownError(rawError: unknown, explicitName?: string): Error {
  if (
    rawError instanceof Error &&
    rawError.constructor?.name &&
    rawError.constructor.name !== "Error"
  ) {
    return rawError;
  }
  const rawMsg = rawError instanceof Error ? rawError.message : String(rawError);
  let errName = explicitName || (rawError instanceof Error ? rawError.name : "Error") || "Error";
  let msg = rawMsg || "boa error";
  if (errName === "Error") {
    const match = msg.match(
      /^(?:Uncaught\s+|JsNativeError:\s+|JsError:\s+)*(TypeError|RangeError|SyntaxError|ReferenceError|URIError|EvalError):\s*(.*)$/s,
    );
    if (match && match[1]) {
      errName = match[1];
      msg = match[2] || msg;
    }
  }
  const normalized = constructErrorByName(errName, msg);
  if (rawError instanceof Error && typeof rawError.stack === "string") {
    try {
      normalized.stack = rawError.stack;
    } catch {}
  }
  return normalized;
}

export function packBoaResult(
  raw: unknown,
  returnByValue: boolean,
  objectGroup?: string,
): EvalResultBody {
  if (!returnByValue) return packResult(raw, false, undefined, objectGroup);
  let envelope: {
    k: string;
    j?: string;
    v?: string;
    d?: string;
    message?: string;
    name?: string;
  };
  try {
    envelope = JSON.parse(String(raw));
  } catch {
    return packResult(raw, true, undefined, objectGroup);
  }
  switch (envelope.k) {
    case "throw":
      return packException(normalizeBoaThrownError(envelope.message || "boa error", envelope.name));
    case "undef":
      return packResult(undefined, true, undefined, objectGroup);
    case "big":
      try {
        return packResult(BigInt(envelope.v as string), true, undefined, objectGroup);
      } catch {
        return packResult(envelope.v, true, undefined, objectGroup);
      }
    case "sym":
      return packResult(Symbol(envelope.d || ""), true, undefined, objectGroup);
    case "fn": {
      const syntheticFunction = function boaFunction(): void {};
      try {
        syntheticFunction.toString = () => envelope.d || "function () { [boa] }";
      } catch {}
      return packResult(syntheticFunction, true, undefined, objectGroup);
    }
    default: {
      let value: unknown = null;
      try {
        value = JSON.parse(envelope.j as string);
      } catch {
        value = null;
      }
      return packResult(value, true, undefined, objectGroup);
    }
  }
}

export async function boaEvalFallback(
  expression: string,
  awaitPromise: boolean | undefined,
  returnByValue: boolean,
  objectGroup?: string,
): Promise<EvalResultBody> {
  try {
    const boaResult = await ks_eval_cdp(expression, awaitPromise !== false, returnByValue);
    return packBoaResult(boaResult, returnByValue, objectGroup);
  } catch (error) {
    return packException(normalizeBoaThrownError(error));
  }
}

export class BoaWasmExecutionBackend implements JsExecutionBackend {
  readonly kind = "boa" as const;

  evaluateClassic(source: string): unknown {
    return ks_eval_page(source);
  }

  evaluateGlobalClassic(source: string): unknown {
    return ks_eval_page(globalizeForBoa(source));
  }

  evaluateModule(url: string, referrer?: string, type?: string): Promise<unknown> {
    return Promise.resolve(ks_import(url, referrer ?? state.pageUrl ?? "about:blank", type));
  }

  compileScript(expression: string, sourceURL: string, persistScript: boolean): CompileScriptReply {
    const expr = typeof expression === "string" ? expression : "";
    const url = typeof sourceURL === "string" ? sourceURL : "";
    try {
      // eslint-disable-next-line no-new, no-new-func
      new Function(expr);
    } catch (err) {
      return packException(err);
    }
    if (!persistScript) {
      return { ok: true, scriptId: null };
    }
    const scriptId = compileScriptEntry(expr, url);
    return { ok: true, scriptId };
  }

  async runCompiledScript(scriptId: string, options: EvalOptions): Promise<RunScriptReply> {
    const returnByValue = !!(options && options.returnByValue);
    const awaitPromise = options === undefined ? true : options.awaitPromise !== false;
    const entry = getCompiledScript(scriptId);
    if (!entry) {
      return drainEvalResult(
        packException(new Error(`No script with id ${scriptId} (was the context evicted?)`)),
      );
    }
    let expr = entry.source;
    if (entry.sourceURL) {
      expr = expr + "\n//# sourceURL=" + entry.sourceURL;
    }
    return await this.evalExpression(expr, {
      returnByValue,
      awaitPromise,
      objectGroup: options?.objectGroup,
    });
  }

  async evalExpression(expression: string, options: RunExpressionOpts): Promise<EvalResult> {
    const returnByValue = !!options?.returnByValue;
    const awaitPromise = options === undefined ? true : options.awaitPromise !== false;
    const objectGroup = options?.objectGroup;
    let result: EvalResultBody;
    try {
      const expr = typeof expression === "string" ? expression : "undefined";
      const hasTopLevelAwait = /\bawait\b/.test(expr);
      let value: unknown;
      if (!hasTopLevelAwait) {
        value = NATIVE_INDIRECT_EVAL(expr);
      } else {
        const asyncFunction = new AsyncFunction("return (" + expr + ");");
        value = await asyncFunction();
      }
      if (
        awaitPromise &&
        value !== null &&
        typeof (value as { then?: unknown })?.then === "function"
      ) {
        value = await (value as Promise<unknown>);
      }
      result = packResult(value, returnByValue, undefined, objectGroup);
    } catch (error) {
      if (
        error instanceof Error &&
        error.name === "EvalError" &&
        typeof error.message === "string" &&
        error.message.includes("Code generation from strings disallowed")
      ) {
        result = await boaEvalFallback(
          typeof expression === "string" ? expression : "undefined",
          awaitPromise,
          returnByValue,
          objectGroup,
        );
      } else {
        result = packException(error);
      }
    }
    return drainEvalResult(result);
  }

  async callFunctionOn(
    functionDeclaration: string,
    argumentSpecs: ArgSpec[],
    options: CallFunctionOnOptions,
  ): Promise<EvalResult> {
    const returnByValue = !!(options && options.returnByValue);
    const awaitPromise = options === undefined ? true : options.awaitPromise !== false;
    const thisObjectId =
      options && typeof options.thisObjectId === "string" ? options.thisObjectId : null;
    const objectGroup = options?.objectGroup;
    let result: EvalResultBody;
    const functionSource =
      typeof functionDeclaration === "string" ? functionDeclaration : "undefined";
    const argumentValues = resolveArgumentSpecs(argumentSpecs);
    const thisValue =
      thisObjectId !== null ? (lookupHandle(thisObjectId) ?? globalThis) : globalThis;
    try {
      const factory = new SyncFunction("return (" + functionSource + ");");
      const pageFunction = factory();
      if (typeof pageFunction !== "function") {
        throw new TypeError("functionDeclaration did not evaluate to a function");
      }
      let value = pageFunction.apply(thisValue, argumentValues);
      if (awaitPromise && value && typeof (value as { then?: unknown }).then === "function") {
        value = await (value as Promise<unknown>);
      }
      result = packResult(value, returnByValue, undefined, objectGroup);
    } catch (error) {
      if (
        error instanceof Error &&
        error.name === "EvalError" &&
        typeof error.message === "string" &&
        error.message.includes("Code generation from strings disallowed")
      ) {
        try {
          const boaResult = await ks_call_cdp(
            functionSource,
            thisValue,
            argumentValues,
            awaitPromise,
            returnByValue,
          );
          result = packBoaResult(boaResult, returnByValue, objectGroup);
        } catch (boaError) {
          result = packException(normalizeBoaThrownError(boaError));
        }
      } else {
        result = packException(error);
      }
    }
    return drainEvalResult(result);
  }

  getProperties(
    objectId: string,
    options: { ownProperties?: boolean },
  ): { result: PropertyDescriptor[] } {
    const ownOnly = !options || options.ownProperties !== false;
    return { result: collectPropertyDescriptors(lookupHandle(objectId), ownOnly) };
  }

  releaseObject(objectId: string): void {
    releaseHandle(objectId);
  }

  releaseObjectGroup(objectGroup: string): void {
    releaseHandleGroup(objectGroup);
  }

  async drainMicrotasks(): Promise<void> {
    if (ks_bridge_ever_minted()) {
      try {
        ks_run_page_jobs();
      } catch {}
    }
    await drainSettleMicrotasks();
  }

  pumpTimers(deadlineMs?: number): number {
    return ksInternals.pumpDueTimers?.(deadlineMs) ?? 0;
  }

  nextTimerDelay(): number {
    return ksInternals.nextTimerDelay?.() ?? Infinity;
  }
}

const PAGE_EXPOSED_GLOBAL_KEYS = [
  "document",
  "location",
  "history",
  "navigator",
  "DOMParser",
  "XMLSerializer",
  "Event",
  "CustomEvent",
  "UIEvent",
  "MouseEvent",
  "KeyboardEvent",
  "InputEvent",
  "FocusEvent",
  "PointerEvent",
  "WheelEvent",
  "MessageEvent",
  "ErrorEvent",
  "HashChangeEvent",
  "PopStateEvent",
  "SubmitEvent",
  "FormDataEvent",
  "EventTarget",
  "Node",
  "Element",
  "HTMLElement",
  "SVGElement",
  "Document",
  "HTMLDocument",
  "DocumentFragment",
  "Text",
  "Comment",
  "CharacterData",
  "NodeList",
  "HTMLCollection",
  "DOMTokenList",
  "HTMLFormElement",
  "HTMLInputElement",
  "HTMLButtonElement",
  "HTMLSelectElement",
  "HTMLOptionElement",
  "HTMLTextAreaElement",
  "HTMLAnchorElement",
  "HTMLImageElement",
  "HTMLScriptElement",
  "HTMLIFrameElement",
  "HTMLCanvasElement",
  "DOMException",
  "DOMRect",
  "DOMRectReadOnly",
  "DOMMatrix",
  "DOMMatrixReadOnly",
  "Range",
  "AbstractRange",
  "StaticRange",
  "Selection",
  "MutationObserver",
  "ResizeObserver",
  "IntersectionObserver",
  "FormData",
  "Headers",
  "Request",
  "Response",
  "AbortController",
  "AbortSignal",
  "URL",
  "URLSearchParams",
  "TextEncoder",
  "TextDecoder",
  "Blob",
  "File",
  "ReadableStream",
  "WritableStream",
  "TransformStream",
  "console",
  "performance",
  "crypto",
  "atob",
  "btoa",
  "setTimeout",
  "clearTimeout",
  "setInterval",
  "clearInterval",
  "queueMicrotask",
  "requestAnimationFrame",
  "cancelAnimationFrame",
  "requestIdleCallback",
  "cancelIdleCallback",
  "fetch",
  "getComputedStyle",
  "matchMedia",
  "customElements",
  "CSS",
  "CSSStyleDeclaration",
  "CSSStyleSheet",
  "CSSRule",
  "getSelection",
  "postMessage",
  "structuredClone",
  "WebSocket",
  "EventSource",
  "MessageChannel",
  "MessagePort",
  "Worker",
  "localStorage",
  "sessionStorage",
  "indexedDB",
  "scheduler",
  "innerWidth",
  "innerHeight",
  "outerWidth",
  "outerHeight",
  "devicePixelRatio",
  "scrollX",
  "scrollY",
  "pageXOffset",
  "pageYOffset",
  "scrollTo",
  "scrollBy",
  "__ks_resolve_import_map",
  "__ks_import",
] as const;

const syncedGlobalsByBridge = new WeakMap<RealmEvaluatorBridge, Map<string, unknown>>();

export function syncPageGlobalsToBridge(bridge: RealmEvaluatorBridge): void {
  let last = syncedGlobalsByBridge.get(bridge);
  if (!last) {
    last = new Map<string, unknown>();
    syncedGlobalsByBridge.set(bridge, last);
  }
  const bindings: Record<string, unknown> = {};
  let dirty = false;
  for (const key of PAGE_EXPOSED_GLOBAL_KEYS) {
    const val = ksGlobalByKey[key];
    if (val !== undefined && (!last.has(key) || last.get(key) !== val)) {
      bindings[key] = val;
      last.set(key, val);
      dirty = true;
    }
  }
  if (state.document && last.get("document") !== state.document) {
    bindings.document = state.document;
    last.set("document", state.document);
    dirty = true;
  }
  if (state.window && last.get("__ks_hostWindow") !== state.window) {
    const addListener = Reflect.get(state.window, "addEventListener");
    if (typeof addListener === "function") {
      bindings.addEventListener = addListener.bind(state.window);
    }
    const removeListener = Reflect.get(state.window, "removeEventListener");
    if (typeof removeListener === "function") {
      bindings.removeEventListener = removeListener.bind(state.window);
    }
    const dispatch = Reflect.get(state.window, "dispatchEvent");
    if (typeof dispatch === "function") {
      bindings.dispatchEvent = dispatch.bind(state.window);
    }
    bindings.__ks_hostWindow = state.window;
    last.set("__ks_hostWindow", state.window);
    dirty = true;
  }
  if (dirty) bridge.installGlobals(bindings);
}

export class NativeV8ExecutionBackend implements JsExecutionBackend {
  readonly kind = "v8" as const;
  readonly #bridge: RealmEvaluatorBridge;

  constructor(bridge: RealmEvaluatorBridge) {
    this.#bridge = bridge;
  }

  evaluateClassic(source: string, sourceURL?: string): unknown {
    syncPageGlobalsToBridge(this.#bridge);
    return this.#bridge.evaluateClassic(source, sourceURL);
  }

  evaluateGlobalClassic(source: string, sourceURL?: string): unknown {
    syncPageGlobalsToBridge(this.#bridge);
    return this.#bridge.evaluateClassic(source, sourceURL);
  }

  async evaluateModule(url: string, referrer?: string, type?: string): Promise<unknown> {
    syncPageGlobalsToBridge(this.#bridge);
    if (this.#bridge.evaluateModule) {
      return await this.#bridge.evaluateModule(
        url,
        referrer ?? state.pageUrl ?? "about:blank",
        type,
      );
    }
    return await ks_import(url, referrer ?? state.pageUrl ?? "about:blank", type);
  }

  compileScript(expression: string, sourceURL: string, persistScript: boolean): CompileScriptReply {
    const expr = typeof expression === "string" ? expression : "";
    const url = typeof sourceURL === "string" ? sourceURL : "";
    const compiled = this.#bridge.compileScript(expr, url || undefined);
    if (!compiled.ok) {
      return packException(compiled.error);
    }
    if (!persistScript) {
      return { ok: true, scriptId: null };
    }
    return { ok: true, scriptId: compileScriptEntry(expr, url) };
  }

  async runCompiledScript(scriptId: string, options: EvalOptions): Promise<RunScriptReply> {
    const entry = getCompiledScript(scriptId);
    if (!entry) {
      return drainEvalResult(
        packException(new Error(`No script with id ${scriptId} (was the context evicted?)`)),
      );
    }
    return await this.evalExpression(entry.source, {
      returnByValue: !!options?.returnByValue,
      awaitPromise: options === undefined ? true : options.awaitPromise !== false,
      objectGroup: options?.objectGroup,
    });
  }

  async evalExpression(expression: string, options: RunExpressionOpts): Promise<EvalResult> {
    syncPageGlobalsToBridge(this.#bridge);
    const returnByValue = !!options?.returnByValue;
    const awaitPromise = options === undefined ? true : options.awaitPromise !== false;
    const expr = typeof expression === "string" ? expression : "undefined";
    const raw = await this.#bridge.evalExpression(expr, { awaitPromise });
    await this.drainMicrotasks();
    const packed = raw.ok
      ? packResult(raw.value, returnByValue, undefined, options?.objectGroup)
      : packException(raw.error);
    return drainEvalResult(packed);
  }

  async callFunctionOn(
    functionDeclaration: string,
    argumentSpecs: ArgSpec[],
    options: CallFunctionOnOptions,
  ): Promise<EvalResult> {
    syncPageGlobalsToBridge(this.#bridge);
    const returnByValue = !!options?.returnByValue;
    const awaitPromise = options === undefined ? true : options.awaitPromise !== false;
    const thisObjectId =
      options && typeof options.thisObjectId === "string" ? options.thisObjectId : null;
    const functionSource =
      typeof functionDeclaration === "string" ? functionDeclaration : "undefined";
    const argumentValues = resolveArgumentSpecs(argumentSpecs);
    const thisValue = thisObjectId !== null ? lookupHandle(thisObjectId) : undefined;
    const raw = await this.#bridge.callFunctionOn(functionSource, thisValue, argumentValues, {
      awaitPromise,
    });
    await this.drainMicrotasks();
    const packed = raw.ok
      ? packResult(raw.value, returnByValue, undefined, options?.objectGroup)
      : packException(raw.error);
    return drainEvalResult(packed);
  }

  getProperties(
    objectId: string,
    options: { ownProperties?: boolean },
  ): { result: PropertyDescriptor[] } {
    const ownOnly = !options || options.ownProperties !== false;
    return { result: collectPropertyDescriptors(lookupHandle(objectId), ownOnly) };
  }

  releaseObject(objectId: string): void {
    releaseHandle(objectId);
  }

  releaseObjectGroup(objectGroup: string): void {
    releaseHandleGroup(objectGroup);
  }

  async drainMicrotasks(): Promise<void> {
    if (this.#bridge.drainMicrotasks) {
      await this.#bridge.drainMicrotasks();
    }
    await drainSettleMicrotasks();
  }

  pumpTimers(deadlineMs?: number): number {
    const pageRan = ksInternals.pumpDueTimers?.(deadlineMs) ?? 0;
    const vmRan = this.#bridge.pumpTimers?.(deadlineMs) ?? 0;
    return pageRan + vmRan;
  }

  nextTimerDelay(): number {
    const pageDelay = ksInternals.nextTimerDelay?.() ?? Infinity;
    const vmDelay = this.#bridge.nextTimerDelay?.() ?? Infinity;
    return Math.min(pageDelay, vmDelay);
  }
}

const defaultBoaBackend = new BoaWasmExecutionBackend();
let cachedV8Bridge: RealmEvaluatorBridge | undefined;
let cachedV8Backend: NativeV8ExecutionBackend | undefined;

export function getExecutionBackend(): JsExecutionBackend {
  const bridge = ksInternals.v8RealmEvaluator;
  if (bridge && bridge.kind === "v8") {
    if (cachedV8Bridge !== bridge || !cachedV8Backend) {
      cachedV8Bridge = bridge;
      cachedV8Backend = new NativeV8ExecutionBackend(bridge);
    }
    return cachedV8Backend;
  }
  return defaultBoaBackend;
}
