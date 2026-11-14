// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Isolated node:vm V8 execution realm with a membrane blocking host intrinsic and RPC escapes.

import vm from "node:vm";

export interface RealmEvaluatorRawResult {
  readonly ok: boolean;
  readonly value?: unknown;
  readonly error?: unknown;
}

export interface ModuleLoadRequest {
  readonly specifier: string;
  readonly referrer: string;
  readonly type?: string;
}

export interface ModuleLoadedSource {
  readonly url: string;
  readonly source: string;
  readonly type?: "javascript" | "json";
}

export interface V8RealmEvaluatorOptions {
  readonly contextName?: string;
  readonly loadModuleSource?: (req: ModuleLoadRequest) => Promise<ModuleLoadedSource>;
}

export interface V8RealmEvaluator {
  readonly kind: "v8";
  installGlobals(bindings: Record<string, unknown>): void;
  evaluateClassic(source: string, sourceURL?: string): unknown;
  evaluateModule(url: string, referrer?: string, type?: string): Promise<unknown>;
  compileScript(
    expression: string,
    sourceURL?: string,
  ): { ok: true } | { ok: false; error: unknown };
  evalExpression(
    expression: string,
    options?: { awaitPromise?: boolean; sourceURL?: string },
  ): Promise<RealmEvaluatorRawResult>;
  callFunctionOn(
    functionDeclaration: string,
    thisValue: unknown,
    args: unknown[],
    options?: { awaitPromise?: boolean },
  ): Promise<RealmEvaluatorRawResult>;
  drainMicrotasks(): Promise<void>;
  pumpTimers(deadlineMs?: number): number;
  nextTimerDelay(): number;
  dispose(): void;
}

interface VmIntrinsics {
  globalThis: Record<string, unknown>;
  Function: FunctionConstructor;
  AsyncFunction: FunctionConstructor;
  GeneratorFunction: FunctionConstructor;
  AsyncGeneratorFunction: FunctionConstructor;
  Object: ObjectConstructor;
  Array: ArrayConstructor;
  Promise: PromiseConstructor;
  Error: ErrorConstructor;
  TypeError: TypeErrorConstructor;
  SyntaxError: SyntaxErrorConstructor;
  ReferenceError: ReferenceErrorConstructor;
  RangeError: RangeErrorConstructor;
  eval: (code: string) => unknown;
  makeFunctionTarget: () => Function;
  makeMicrotaskFlusher: () => (cb: () => void) => void;
}

interface TimerRecord {
  id: number;
  callback: () => void;
  due: number;
  intervalMs: number;
  repeats: boolean;
  hostTimer: ReturnType<typeof setTimeout> | null;
}

type SourceTextModuleCtor = new (
  code: string,
  options: {
    context: vm.Context;
    identifier: string;
    importModuleDynamically?: (
      specifier: string,
      referrer: SourceTextModuleInstance,
      importAttributes: Record<string, string>,
    ) => Promise<SourceTextModuleInstance>;
  },
) => SourceTextModuleInstance;

interface SourceTextModuleInstance {
  readonly identifier: string;
  readonly namespace: unknown;
  link(
    linker: (
      specifier: string,
      referencingModule: SourceTextModuleInstance,
      extra: { attributes: Record<string, string> },
    ) => Promise<SourceTextModuleInstance>,
  ): Promise<void>;
  evaluate(): Promise<void>;
}

const INTRINSICS_BOOTSTRAP_SOURCE = `(function () {
  var g = globalThis;
  var AsyncFn = (async function () {}).constructor;
  var GenFn = (function* () {}).constructor;
  var AsyncGenFn = (async function* () {}).constructor;
  return {
    globalThis: g,
    Function: Function,
    AsyncFunction: AsyncFn,
    GeneratorFunction: GenFn,
    AsyncGeneratorFunction: AsyncGenFn,
    Object: Object,
    Array: Array,
    Promise: Promise,
    Error: Error,
    TypeError: TypeError,
    SyntaxError: SyntaxError,
    ReferenceError: ReferenceError,
    RangeError: RangeError,
    eval: eval,
    makeFunctionTarget: function () { return function () {}; },
    makeMicrotaskFlusher: function () {
      return typeof g.queueMicrotask === "function"
        ? g.queueMicrotask.bind(g)
        : function (fn) { Promise.resolve().then(fn); };
    }
  };
})()`;

const BLOCKED_GLOBALS = new Set<string>([
  "Deno",
  "process",
  "Bun",
  "require",
  "module",
  "exports",
  "Buffer",
  "__dirname",
  "__filename",
  "global",
  "__ks_init_isolate",
  "__ks_dispose",
  "globalOutbound",
  "tailSink",
  "Object",
  "Function",
  "Array",
  "Promise",
  "Error",
  "TypeError",
  "SyntaxError",
  "ReferenceError",
  "RangeError",
  "EvalError",
  "URIError",
  "Proxy",
  "Reflect",
  "eval",
  "globalThis",
  "self",
  "window",
]);

function readHostIntrinsics(): {
  FunctionCtor: FunctionConstructor;
  AsyncFunctionCtor: FunctionConstructor;
  GeneratorFunctionCtor: FunctionConstructor;
  AsyncGeneratorFunctionCtor: FunctionConstructor;
  EvalFn: (code: string) => unknown;
} {
  const hostFn = Function;
  const hostAsyncFn = (async () => {}).constructor as FunctionConstructor;
  const hostGenFn = function* () {}.constructor as FunctionConstructor;
  const hostAsyncGenFn = async function* () {}.constructor as FunctionConstructor;
  return {
    FunctionCtor: hostFn,
    AsyncFunctionCtor: hostAsyncFn,
    GeneratorFunctionCtor: hostGenFn,
    AsyncGeneratorFunctionCtor: hostAsyncGenFn,
    EvalFn: eval,
  };
}

function getSourceTextModuleCtor(): SourceTextModuleCtor | null {
  const raw = Reflect.get(vm, "SourceTextModule");
  return typeof raw === "function" ? (raw as SourceTextModuleCtor) : null;
}

class RealmMembrane {
  readonly #intrinsics: VmIntrinsics;
  readonly #intrinsicMap = new Map<unknown, unknown>();
  readonly #hostToVm = new WeakMap<object, unknown>();
  readonly #vmProxyToHost = new WeakMap<object, object>();
  readonly #vmFnToHost = new WeakMap<Function, Function>();
  readonly #hostFnToVm = new WeakMap<Function, Function>();
  readonly #vmOwnedObjects = new WeakSet<object>();

  constructor(intrinsics: VmIntrinsics) {
    this.#intrinsics = intrinsics;
    const host = readHostIntrinsics();
    this.#intrinsicMap.set(host.FunctionCtor, intrinsics.Function);
    this.#intrinsicMap.set(host.FunctionCtor.prototype, intrinsics.Function.prototype);
    this.#intrinsicMap.set(host.AsyncFunctionCtor, intrinsics.AsyncFunction);
    this.#intrinsicMap.set(host.AsyncFunctionCtor.prototype, intrinsics.AsyncFunction.prototype);
    this.#intrinsicMap.set(host.GeneratorFunctionCtor, intrinsics.GeneratorFunction);
    this.#intrinsicMap.set(
      host.GeneratorFunctionCtor.prototype,
      intrinsics.GeneratorFunction.prototype,
    );
    this.#intrinsicMap.set(host.AsyncGeneratorFunctionCtor, intrinsics.AsyncGeneratorFunction);
    this.#intrinsicMap.set(
      host.AsyncGeneratorFunctionCtor.prototype,
      intrinsics.AsyncGeneratorFunction.prototype,
    );
    this.#intrinsicMap.set(host.EvalFn, intrinsics.eval);
  }

  isVmRealmValue(value: object): boolean {
    if (this.#vmOwnedObjects.has(value)) return true;
    const candidate: unknown = value;
    try {
      return (
        candidate instanceof this.#intrinsics.Object ||
        candidate instanceof this.#intrinsics.Array ||
        candidate instanceof this.#intrinsics.Error ||
        candidate instanceof this.#intrinsics.Promise ||
        candidate instanceof this.#intrinsics.Function
      );
    } catch {
      return false;
    }
  }

  wrapErrorToVm(err: unknown): unknown {
    if (err === null || (typeof err !== "object" && typeof err !== "function")) {
      return err;
    }
    if (this.#vmProxyToHost.has(err)) {
      return err;
    }
    if (this.isVmRealmValue(err)) {
      return err;
    }
    if (err instanceof Error || Object.prototype.toString.call(err) === "[object Error]") {
      const e = err as Error;
      const ctor = this.pickVmErrorCtor(e.name);
      const vmErr = new ctor(typeof e.message === "string" ? e.message : String(err));
      try {
        if (e.name && vmErr.name !== e.name) vmErr.name = e.name;
        if (typeof e.stack === "string") vmErr.stack = e.stack;
      } catch {}
      return vmErr;
    }
    return this.wrapToVm(err);
  }

  wrapToVm(value: unknown): unknown {
    if (value === null || (typeof value !== "object" && typeof value !== "function")) {
      return value;
    }
    if (this.#intrinsicMap.has(value)) {
      return this.#intrinsicMap.get(value);
    }
    const obj = value as object;
    if (this.#vmProxyToHost.has(obj)) {
      return obj;
    }
    if (typeof obj === "function" && this.#hostFnToVm.has(obj)) {
      return this.#hostFnToVm.get(obj);
    }
    if (this.isVmRealmValue(obj)) {
      return obj;
    }
    if (this.#hostToVm.has(obj)) {
      return this.#hostToVm.get(obj);
    }
    if (typeof obj === "function") {
      return this.wrapFunctionToVm(obj as Function);
    }
    if (obj instanceof Promise) {
      return this.wrapPromiseToVm(obj);
    }
    return this.wrapObjectToVm(obj);
  }

  unwrapToHost(value: unknown): unknown {
    if (value === null || (typeof value !== "object" && typeof value !== "function")) {
      return value;
    }
    const obj = value as object;
    const rawHost = this.#vmProxyToHost.get(obj);
    if (rawHost !== undefined) {
      return rawHost;
    }
    this.#vmOwnedObjects.add(obj);
    if (typeof obj === "function") {
      return this.wrapVmFunctionToHost(obj as Function);
    }
    return obj;
  }

  private pickVmErrorCtor(name: unknown): ErrorConstructor {
    switch (name) {
      case "TypeError":
        return this.#intrinsics.TypeError;
      case "SyntaxError":
        return this.#intrinsics.SyntaxError;
      case "ReferenceError":
        return this.#intrinsics.ReferenceError;
      case "RangeError":
        return this.#intrinsics.RangeError;
      default:
        return this.#intrinsics.Error;
    }
  }

  private wrapPromiseToVm(promise: Promise<unknown>): Promise<unknown> {
    const wrapped = new this.#intrinsics.Promise((resolve, reject) => {
      promise.then(
        (v) => resolve(this.wrapToVm(v)),
        (e) => reject(this.wrapErrorToVm(e)),
      );
    });
    this.#hostToVm.set(promise, wrapped);
    return wrapped;
  }

  private wrapFunctionToVm(fn: Function): Function {
    const dummy = this.#intrinsics.makeFunctionTarget();
    const membrane = this;
    const proxy = new Proxy(dummy, {
      apply(_target, thisArg, argArray): unknown {
        const hostThis = membrane.unwrapToHost(thisArg);
        const hostArgs = argArray.map((arg) => membrane.unwrapToHost(arg));
        try {
          const result = Reflect.apply(fn, hostThis, hostArgs);
          return membrane.wrapToVm(result);
        } catch (err) {
          throw membrane.wrapErrorToVm(err);
        }
      },
      construct(_target, argArray): object {
        const hostArgs = argArray.map((arg) => membrane.unwrapToHost(arg));
        try {
          const result = Reflect.construct(fn, hostArgs);
          return membrane.wrapToVm(result) as object;
        } catch (err) {
          throw membrane.wrapErrorToVm(err);
        }
      },
      get(target, prop): unknown {
        if (prop === "constructor") {
          return membrane.#intrinsics.Function;
        }
        if (prop === "__proto__") {
          return membrane.#intrinsics.Function.prototype;
        }
        if (prop === "Deno" || prop === "process") {
          return undefined;
        }
        const ownDesc = Reflect.getOwnPropertyDescriptor(target, prop);
        if (ownDesc && !ownDesc.configurable && !ownDesc.writable) {
          return ownDesc.value;
        }
        const raw = Reflect.get(fn, prop, fn);
        return membrane.wrapToVm(raw);
      },
      set(_target, prop, val): boolean {
        return Reflect.set(fn, prop, membrane.unwrapToHost(val), fn);
      },
      has(_target, prop): boolean {
        return Reflect.has(fn, prop);
      },
      ownKeys(): Array<string | symbol> {
        return Reflect.ownKeys(fn);
      },
      getPrototypeOf(): object {
        return membrane.#intrinsics.Function.prototype;
      },
    });
    this.#hostToVm.set(fn, proxy);
    this.#vmProxyToHost.set(proxy, fn);
    return proxy;
  }

  private wrapObjectToVm(obj: object): object {
    const isArr = Array.isArray(obj);
    const dummy = isArr ? this.#intrinsics.Array.from([]) : this.#intrinsics.Object.create(null);
    const membrane = this;
    const proxy = new Proxy(dummy as object, {
      get(target, prop): unknown {
        if (prop === "Deno" || prop === "process") {
          return undefined;
        }
        const targetDesc = Reflect.getOwnPropertyDescriptor(target, prop);
        if (targetDesc && !targetDesc.configurable && !targetDesc.writable) {
          return targetDesc.value;
        }
        const raw = Reflect.get(obj, prop, obj);
        return membrane.wrapToVm(raw);
      },
      set(_target, prop, val): boolean {
        return Reflect.set(obj, prop, membrane.unwrapToHost(val), obj);
      },
      has(_target, prop): boolean {
        if (prop === "Deno" || prop === "process") return false;
        return Reflect.has(obj, prop);
      },
      deleteProperty(_target, prop): boolean {
        return Reflect.deleteProperty(obj, prop);
      },
      ownKeys(): Array<string | symbol> {
        return Reflect.ownKeys(obj);
      },
      getOwnPropertyDescriptor(target, prop): PropertyDescriptor | undefined {
        const desc = Reflect.getOwnPropertyDescriptor(obj, prop);
        if (!desc) return undefined;
        const targetDesc = Reflect.getOwnPropertyDescriptor(target, prop);
        const configurable = targetDesc ? targetDesc.configurable : true;
        const out: PropertyDescriptor = {
          configurable: !!configurable,
          enumerable: !!desc.enumerable,
        };
        if ("value" in desc) {
          out.value = membrane.wrapToVm(desc.value);
          out.writable = targetDesc ? targetDesc.writable : !!desc.writable;
        } else {
          if (desc.get) out.get = membrane.wrapToVm(desc.get) as () => unknown;
          if (desc.set) out.set = membrane.wrapToVm(desc.set) as (v: unknown) => void;
        }
        return out;
      },
      getPrototypeOf(): object | null {
        const proto = Reflect.getPrototypeOf(obj);
        if (proto === null) return null;
        return membrane.wrapToVm(proto) as object;
      },
      setPrototypeOf(_target, proto): boolean {
        const unwrapped = proto === null ? null : (membrane.unwrapToHost(proto) as object);
        return Reflect.setPrototypeOf(obj, unwrapped);
      },
    });
    this.#hostToVm.set(obj, proxy);
    this.#vmProxyToHost.set(proxy, obj);
    return proxy;
  }

  private wrapVmFunctionToHost(vmFn: Function): Function {
    const cached = this.#vmFnToHost.get(vmFn);
    if (cached) return cached;
    const membrane = this;
    const hostWrapper = function (this: unknown, ...args: unknown[]): unknown {
      const vmThis = membrane.wrapToVm(this);
      const vmArgs = args.map((arg) => membrane.wrapToVm(arg));
      try {
        const res = Reflect.apply(vmFn, vmThis, vmArgs);
        return membrane.unwrapToHost(res);
      } catch (err) {
        if (membrane.isVmRealmValue(err as object)) {
          throw err;
        }
        throw err;
      }
    };
    this.#vmFnToHost.set(vmFn, hostWrapper);
    this.#hostFnToVm.set(hostWrapper, vmFn);
    return hostWrapper;
  }
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    return false;
  }
  try {
    return typeof Reflect.get(value, "then") === "function";
  } catch {
    return false;
  }
}

export function createV8RealmEvaluator(options: V8RealmEvaluatorOptions = {}): V8RealmEvaluator {
  const realmGlobal: Record<string, unknown> = Object.create(null);
  const context = vm.createContext(realmGlobal, {
    name: options.contextName ?? "parawing-v8-page-realm",
  });
  const intrinsics = new vm.Script(INTRINSICS_BOOTSTRAP_SOURCE, {
    filename: "parawing-v8-bootstrap.js",
  }).runInContext(context) as VmIntrinsics;
  const membrane = new RealmMembrane(intrinsics);
  const enqueueVmMicrotask = intrinsics.makeMicrotaskFlusher();

  realmGlobal.globalThis = intrinsics.globalThis;
  realmGlobal.self = intrinsics.globalThis;
  realmGlobal.window = intrinsics.globalThis;

  let nextTimerId = 1;
  const timers = new Map<number, TimerRecord>();
  let disposed = false;

  const fireTimer = (id: number): void => {
    const rec = timers.get(id);
    if (!rec || disposed) return;
    if (!rec.repeats) {
      timers.delete(id);
    } else {
      rec.due = Date.now() + rec.intervalMs;
      rec.hostTimer = setTimeout(() => fireTimer(id), rec.intervalMs);
    }
    try {
      rec.callback();
    } catch {}
  };

  const vmSetTimeout = (cb: unknown, delayMs = 0, ...args: unknown[]): number => {
    if (typeof cb !== "function" && typeof cb !== "string") {
      throw new TypeError("Timer callback must be a function");
    }
    const ms = Number.isFinite(Number(delayMs)) ? Math.max(0, Number(delayMs)) : 0;
    const id = nextTimerId++;
    const fn =
      typeof cb === "function"
        ? (): void => {
            Reflect.apply(cb, intrinsics.globalThis, args);
          }
        : (): void => {
            new vm.Script(String(cb)).runInContext(context);
          };
    const rec: TimerRecord = {
      id,
      callback: fn,
      due: Date.now() + ms,
      intervalMs: ms,
      repeats: false,
      hostTimer: null,
    };
    rec.hostTimer = setTimeout(() => fireTimer(id), ms);
    timers.set(id, rec);
    return id;
  };

  const vmSetInterval = (cb: unknown, delayMs = 0, ...args: unknown[]): number => {
    if (typeof cb !== "function") {
      throw new TypeError("Interval callback must be a function");
    }
    const ms = Number.isFinite(Number(delayMs)) ? Math.max(1, Number(delayMs)) : 1;
    const id = nextTimerId++;
    const fn = (): void => {
      Reflect.apply(cb, intrinsics.globalThis, args);
    };
    const rec: TimerRecord = {
      id,
      callback: fn,
      due: Date.now() + ms,
      intervalMs: ms,
      repeats: true,
      hostTimer: null,
    };
    rec.hostTimer = setTimeout(() => fireTimer(id), ms);
    timers.set(id, rec);
    return id;
  };

  const vmClearTimer = (rawId: unknown): void => {
    const id = Number(rawId);
    const rec = timers.get(id);
    if (!rec) return;
    timers.delete(id);
    if (rec.hostTimer !== null) clearTimeout(rec.hostTimer);
  };

  realmGlobal.setTimeout = membrane.wrapToVm(vmSetTimeout);
  realmGlobal.setInterval = membrane.wrapToVm(vmSetInterval);
  realmGlobal.clearTimeout = membrane.wrapToVm(vmClearTimer);
  realmGlobal.clearInterval = membrane.wrapToVm(vmClearTimer);

  const installGlobals = (bindings: Record<string, unknown>): void => {
    for (const [key, value] of Object.entries(bindings)) {
      if (BLOCKED_GLOBALS.has(key) || key === "__ks_hostWindow") continue;
      if (value === undefined) continue;
      try {
        realmGlobal[key] = membrane.wrapToVm(value);
      } catch {}
    }
    const hostWin = bindings.__ks_hostWindow;
    if (hostWin && typeof hostWin === "object") {
      const addListener = Reflect.get(hostWin, "addEventListener");
      if (typeof addListener === "function") {
        realmGlobal.addEventListener = membrane.wrapToVm(addListener.bind(hostWin));
      }
      const removeListener = Reflect.get(hostWin, "removeEventListener");
      if (typeof removeListener === "function") {
        realmGlobal.removeEventListener = membrane.wrapToVm(removeListener.bind(hostWin));
      }
      const dispatch = Reflect.get(hostWin, "dispatchEvent");
      if (typeof dispatch === "function") {
        realmGlobal.dispatchEvent = membrane.wrapToVm(dispatch.bind(hostWin));
      }
    }
  };

  const runClassic = (source: string, sourceURL?: string): unknown => {
    const script = new vm.Script(source, sourceURL ? { filename: sourceURL } : undefined);
    const value = script.runInContext(context);
    return membrane.unwrapToHost(value);
  };

  const compileScript = (
    expression: string,
    sourceURL?: string,
  ): { ok: true } | { ok: false; error: unknown } => {
    try {
      new vm.Script(expression, sourceURL ? { filename: sourceURL } : undefined);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err };
    }
  };

  const evalExpression = async (
    expression: string,
    evalOpts?: { awaitPromise?: boolean; sourceURL?: string },
  ): Promise<RealmEvaluatorRawResult> => {
    const awaitPromise = evalOpts?.awaitPromise !== false;
    const filename = evalOpts?.sourceURL;
    try {
      let rawValue: unknown;
      try {
        rawValue = new vm.Script(expression, filename ? { filename } : undefined).runInContext(
          context,
        );
      } catch (firstErr) {
        const isSyntax =
          firstErr instanceof Error ||
          Object.prototype.toString.call(firstErr) === "[object Error]";
        if (isSyntax && /\bawait\b/.test(expression)) {
          const wrapped = `(async function () { return (${expression}); })()`;
          rawValue = new vm.Script(wrapped, filename ? { filename } : undefined).runInContext(
            context,
          );
        } else {
          throw firstErr;
        }
      }
      if (awaitPromise && isThenable(rawValue)) {
        rawValue = await (rawValue as Promise<unknown>);
      }
      return { ok: true, value: membrane.unwrapToHost(rawValue) };
    } catch (err) {
      return { ok: false, error: err };
    }
  };

  const callFunctionOn = async (
    functionDeclaration: string,
    thisValue: unknown,
    args: unknown[],
    callOpts?: { awaitPromise?: boolean },
  ): Promise<RealmEvaluatorRawResult> => {
    const awaitPromise = callOpts?.awaitPromise !== false;
    try {
      const fnVal = new vm.Script(`(${functionDeclaration})`, {
        filename: "parawing-call-function-on.js",
      }).runInContext(context);
      if (typeof fnVal !== "function") {
        throw new intrinsics.TypeError("functionDeclaration did not evaluate to a function");
      }
      const vmThis = thisValue === undefined ? intrinsics.globalThis : membrane.wrapToVm(thisValue);
      const vmArgs = args.map((arg) => membrane.wrapToVm(arg));
      let result = Reflect.apply(fnVal, vmThis, vmArgs);
      if (awaitPromise && isThenable(result)) {
        result = await (result as Promise<unknown>);
      }
      return { ok: true, value: membrane.unwrapToHost(result) };
    } catch (err) {
      return { ok: false, error: err };
    }
  };

  const moduleCache = new Map<string, Promise<SourceTextModuleInstance>>();

  const loadSourceTextModule = async (
    specifier: string,
    referrer: string,
    type?: string,
  ): Promise<SourceTextModuleInstance> => {
    const StmCtor = getSourceTextModuleCtor();
    if (!StmCtor || !options.loadModuleSource) {
      throw new Error("VM module evaluation unavailable without SourceTextModule and loader");
    }
    const loaded = await options.loadModuleSource({ specifier, referrer, type });
    const cacheKey = `${loaded.type ?? "javascript"}:${loaded.url}`;
    const existing = moduleCache.get(cacheKey);
    if (existing) return await existing;

    const pending = (async (): Promise<SourceTextModuleInstance> => {
      const modSource =
        loaded.type === "json" ? `export default (${loaded.source});` : loaded.source;
      const mod = new StmCtor(modSource, {
        context,
        identifier: loaded.url,
        importModuleDynamically: async (dynSpec, dynRef, attrs) => {
          return await loadSourceTextModule(dynSpec, dynRef.identifier, attrs?.type);
        },
      });
      await mod.link(async (depSpec, depRef, extra) => {
        return await loadSourceTextModule(depSpec, depRef.identifier, extra?.attributes?.type);
      });
      await mod.evaluate();
      return mod;
    })();
    moduleCache.set(cacheKey, pending);
    try {
      return await pending;
    } catch (err) {
      moduleCache.delete(cacheKey);
      throw err;
    }
  };

  const evaluateModule = async (
    url: string,
    referrer = "about:blank",
    type?: string,
  ): Promise<unknown> => {
    const mod = await loadSourceTextModule(url, referrer, type);
    return membrane.unwrapToHost(mod.namespace);
  };

  const drainMicrotasks = async (): Promise<void> => {
    for (let i = 0; i < 4; i++) {
      await new Promise<void>((resolve) => {
        enqueueVmMicrotask(() => resolve());
      });
    }
  };

  const pumpTimers = (deadlineMs?: number): number => {
    const cutoff = deadlineMs ?? Date.now();
    let ran = 0;
    while (timers.size > 0) {
      let earliest: TimerRecord | undefined;
      for (const entry of timers.values()) {
        if (!earliest || entry.due < earliest.due) earliest = entry;
      }
      if (!earliest || earliest.due > cutoff) break;
      if (earliest.hostTimer !== null) clearTimeout(earliest.hostTimer);
      fireTimer(earliest.id);
      ran++;
    }
    return ran;
  };

  const nextTimerDelay = (): number => {
    if (timers.size === 0) return Infinity;
    const now = Date.now();
    let soonest = Infinity;
    for (const entry of timers.values()) {
      const wait = Math.max(0, entry.due - now);
      if (wait < soonest) soonest = wait;
    }
    return soonest;
  };

  const dispose = (): void => {
    disposed = true;
    for (const entry of timers.values()) {
      if (entry.hostTimer !== null) clearTimeout(entry.hostTimer);
    }
    timers.clear();
  };

  return {
    kind: "v8",
    installGlobals,
    evaluateClassic: runClassic,
    evaluateModule,
    compileScript,
    evalExpression,
    callFunctionOn,
    drainMicrotasks,
    pumpTimers,
    nextTimerDelay,
    dispose,
  };
}
