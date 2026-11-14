// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Manages exported RPC capability tables, remote proxies, dup/dispose, and value marshaling.

export const RPC_TARGET_SYMBOL: symbol = Symbol.for("parawing.rpcTarget");

export type WireCapKind = "fn" | "obj";

export interface CapabilityDispatch {
  invoke(capId: number, method: string | null, args: unknown[]): Promise<unknown>;
  dispose(capId: number): void;
}

export function markRpcTarget<T extends object>(target: T): T {
  Reflect.set(target, RPC_TARGET_SYMBOL, true);
  return target;
}

export function isRpcTargetObject(value: unknown): value is object {
  if (typeof value !== "object" || value === null) return false;
  return Reflect.get(value, RPC_TARGET_SYMBOL) === true;
}

interface ExportEntry {
  id: number;
  target: unknown;
  kind: WireCapKind;
  refs: number;
}

interface ImportedState {
  capId: number;
  kind: WireCapKind;
  refs: number;
  disposed: boolean;
}

export interface EncodedPayload {
  encoded: unknown;
  binaries: Uint8Array[];
}

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function toUint8ArrayChunk(val: unknown): Uint8Array {
  if (val instanceof Uint8Array) return val;
  if (val instanceof ArrayBuffer) return new Uint8Array(val);
  if (ArrayBuffer.isView(val)) {
    return new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
  }
  return new TextEncoder().encode(String(val ?? ""));
}

function makeStreamTarget(stream: ReadableStream<unknown>): object {
  let reader: ReadableStreamDefaultReader<unknown> | null = null;
  const cancelStream = (reason?: unknown): Promise<void> => {
    const target = reader ?? stream;
    return target.cancel(reason).catch(() => {});
  };
  return markRpcTarget({
    async read(): Promise<{ done: boolean; value?: Uint8Array }> {
      if (!reader) reader = stream.getReader();
      const chunk = await reader.read();
      if (chunk.done) return { done: true };
      return { done: false, value: toUint8ArrayChunk(chunk.value) };
    },
    async cancel(reason?: unknown): Promise<void> {
      await cancelStream(reason);
    },
    [Symbol.dispose](): void {
      void cancelStream();
    },
  });
}

function makeCallableStub(
  state: ImportedState,
  dispatch: CapabilityDispatch,
  onRelease: () => void,
  dupFn: () => unknown,
): unknown {
  let handleDisposed = false;
  const dispose = (): void => {
    if (handleDisposed) return;
    handleDisposed = true;
    onRelease();
  };
  const fnTarget = (): void => {};
  return new Proxy(fnTarget, {
    apply(_t, _thisArg, argList: unknown[]): Promise<unknown> {
      if (handleDisposed || state.disposed) {
        return Promise.reject(new Error("RPC capability disposed"));
      }
      return dispatch.invoke(state.capId, null, argList);
    },
    get(_t, prop): unknown {
      if (prop === Symbol.dispose) return dispose;
      if (prop === "dup") return dupFn;
      if (prop === "then" || prop === "toJSON") return undefined;
      return undefined;
    },
    has(_t, prop): boolean {
      return prop === Symbol.dispose || prop === "dup";
    },
  });
}

function makeObjectStub(
  state: ImportedState,
  dispatch: CapabilityDispatch,
  onRelease: () => void,
  dupFn: () => unknown,
): unknown {
  let handleDisposed = false;
  const dispose = (): void => {
    if (handleDisposed) return;
    handleDisposed = true;
    onRelease();
  };
  const target: Record<string, unknown> = {};
  return new Proxy(target, {
    get(_t, prop): unknown {
      if (prop === RPC_TARGET_SYMBOL) return true;
      if (prop === Symbol.dispose) return dispose;
      if (prop === "dup") return dupFn;
      if (prop === "then" || prop === "toJSON" || typeof prop === "symbol") {
        return undefined;
      }
      return (...args: unknown[]): Promise<unknown> => {
        if (handleDisposed || state.disposed) {
          return Promise.reject(new Error("RPC capability disposed"));
        }
        return dispatch.invoke(state.capId, prop, args);
      };
    },
    has(_t, prop): boolean {
      if (prop === RPC_TARGET_SYMBOL || prop === Symbol.dispose || prop === "dup") return true;
      return typeof prop === "string" && prop !== "then" && prop !== "toJSON";
    },
  });
}

export class CapabilityTable {
  #nextId = 1;
  #exports = new Map<number, ExportEntry>();
  #dispatch: CapabilityDispatch;

  constructor(dispatch: CapabilityDispatch) {
    this.#dispatch = dispatch;
  }

  exportTarget(target: unknown): { id: number; kind: WireCapKind } {
    const kind: WireCapKind = typeof target === "function" ? "fn" : "obj";
    const id = this.#nextId++;
    this.#exports.set(id, { id, target, kind, refs: 1 });
    return { id, kind };
  }

  getExport(capId: number): { target: unknown; kind: WireCapKind } | undefined {
    const entry = this.#exports.get(capId);
    if (!entry) return undefined;
    return { target: entry.target, kind: entry.kind };
  }

  releaseExport(capId: number): boolean {
    const entry = this.#exports.get(capId);
    if (!entry) return false;
    entry.refs -= 1;
    if (entry.refs > 0) return false;
    this.#exports.delete(capId);
    this.#disposeLocalTarget(entry.target);
    return true;
  }

  exportCount(): number {
    return this.#exports.size;
  }

  disposeAll(): void {
    const entries = [...this.#exports.values()];
    this.#exports.clear();
    for (const entry of entries) {
      this.#disposeLocalTarget(entry.target);
    }
  }

  encodeValue(value: unknown): EncodedPayload {
    const binaries: Uint8Array[] = [];
    const encoded = this.#encodeNode(value, binaries);
    return { encoded, binaries };
  }

  decodeValue(encoded: unknown, binaries: Uint8Array[]): unknown {
    return this.#decodeNode(encoded, binaries);
  }

  createProxy(capId: number, kind: WireCapKind): unknown {
    const state: ImportedState = { capId, kind, refs: 1, disposed: false };
    const dispatch = this.#dispatch;
    const build = (): unknown => {
      const release = (): void => {
        state.refs -= 1;
        if (state.refs === 0 && !state.disposed) {
          state.disposed = true;
          dispatch.dispose(capId);
        }
      };
      const dup = (): unknown => {
        if (state.disposed) {
          throw new Error("Cannot dup() a disposed RPC capability");
        }
        state.refs += 1;
        return build();
      };
      return kind === "fn"
        ? makeCallableStub(state, dispatch, release, dup)
        : makeObjectStub(state, dispatch, release, dup);
    };
    return build();
  }

  #disposeLocalTarget(target: unknown): void {
    if (typeof target !== "object" || target === null) return;
    const fn = Reflect.get(target, Symbol.dispose);
    if (typeof fn !== "function") return;
    try {
      Reflect.apply(fn, target, []);
    } catch {}
  }

  #encodeNode(value: unknown, binaries: Uint8Array[]): unknown {
    if (value === undefined) return { $ks: "undef" };
    if (value === null || typeof value === "boolean" || typeof value === "string") {
      return value;
    }
    if (typeof value === "number") return this.#encodeNumber(value);
    if (typeof value === "bigint") return { $ks: "bigint", v: value.toString() };
    if (typeof value === "function" || isRpcTargetObject(value)) {
      const { id, kind } = this.exportTarget(value);
      return { $ks: "cap", id, kind };
    }
    if (value instanceof Uint8Array) {
      const idx = binaries.length;
      binaries.push(value);
      return { $ks: "bin", i: idx };
    }
    if (value instanceof ArrayBuffer) {
      const idx = binaries.length;
      binaries.push(new Uint8Array(value));
      return { $ks: "ab", i: idx };
    }
    return this.#encodeComposite(value, binaries);
  }

  #encodeNumber(value: number): unknown {
    if (Number.isFinite(value) && !Object.is(value, -0)) return value;
    return { $ks: "num", v: Object.is(value, -0) ? "-0" : String(value) };
  }

  #encodeComposite(value: unknown, binaries: Uint8Array[]): unknown {
    if (value instanceof Date) return { $ks: "date", v: value.getTime() };
    if (value instanceof Error) {
      return {
        $ks: "err",
        name: value.name,
        message: value.message,
        stack: value.stack ?? null,
      };
    }
    if (Array.isArray(value)) {
      return value.map((item) => this.#encodeNode(item, binaries));
    }
    if (typeof Headers !== "undefined" && value instanceof Headers) {
      return { $ks: "hdr", entries: [...value.entries()] };
    }
    if (typeof Response !== "undefined" && value instanceof Response) {
      const streamCapId = value.body ? this.exportTarget(makeStreamTarget(value.body)).id : null;
      return {
        $ks: "resp",
        status: value.status,
        statusText: value.statusText,
        url: value.url,
        headers: [...value.headers.entries()],
        streamCapId,
      };
    }
    if (typeof ReadableStream !== "undefined" && value instanceof ReadableStream) {
      const streamCapId = this.exportTarget(makeStreamTarget(value)).id;
      return { $ks: "rstream", id: streamCapId };
    }
    const source = isPlainRecord(value) ? value : this.#snapshotEnumerable(value);
    return this.#encodeObject(source, binaries);
  }

  #snapshotEnumerable(value: unknown): Record<string, unknown> {
    if (typeof value !== "object" || value === null) return {};
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = v;
    }
    return out;
  }

  #encodeObject(obj: Record<string, unknown>, binaries: Uint8Array[]): unknown {
    const out: Record<string, unknown> = {};
    let hasSentinel = false;
    for (const [key, val] of Object.entries(obj)) {
      if (key === "$ks") hasSentinel = true;
      out[key] = this.#encodeNode(val, binaries);
    }
    if (hasSentinel) return { $ks: "esc", raw: out };
    return out;
  }

  #decodeNode(node: unknown, binaries: Uint8Array[]): unknown {
    if (node === null || typeof node !== "object") return node;
    if (Array.isArray(node)) {
      return node.map((item) => this.#decodeNode(item, binaries));
    }
    const rec = node as Record<string, unknown>;
    const tag = Object.prototype.hasOwnProperty.call(rec, "$ks") ? rec["$ks"] : undefined;
    if (typeof tag === "string") {
      return this.#decodeTagged(tag, rec, binaries);
    }
    return this.#decodeObject(rec, binaries);
  }

  #decodeTagged(tag: string, rec: Record<string, unknown>, binaries: Uint8Array[]): unknown {
    switch (tag) {
      case "undef":
        return undefined;
      case "num":
        return rec["v"] === "-0" ? -0 : Number(rec["v"]);
      case "bigint":
        return BigInt(String(rec["v"]));
      case "date":
        return new Date(Number(rec["v"]));
      case "err":
        return this.#decodeError(rec);
      case "bin":
        return this.#getBinary(rec["i"], binaries);
      case "ab": {
        const u8 = this.#getBinary(rec["i"], binaries);
        return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
      }
      case "cap":
        return this.createProxy(Number(rec["id"]), rec["kind"] === "fn" ? "fn" : "obj");
      case "hdr":
        return this.#decodeHeaders(rec["entries"]);
      case "rstream":
        return this.#decodeStream(Number(rec["id"]));
      case "resp":
        return this.#decodeResponse(rec);
      case "esc":
        return this.#decodeObject(rec["raw"] as Record<string, unknown>, binaries);
      default:
        return this.#decodeObject(rec, binaries);
    }
  }

  #decodeHeaders(raw: unknown): Headers {
    const headers = new Headers();
    if (!Array.isArray(raw)) return headers;
    for (const pair of raw) {
      if (Array.isArray(pair) && pair.length >= 2) {
        headers.append(String(pair[0]), String(pair[1]));
      }
    }
    return headers;
  }

  #decodeStream(capId: number): ReadableStream<Uint8Array> {
    interface StreamStub {
      read(): Promise<{ done: boolean; value?: Uint8Array }>;
      cancel(reason?: unknown): Promise<void>;
      [Symbol.dispose]?: () => void;
    }
    const stub = this.createProxy(capId, "obj") as StreamStub;
    return new ReadableStream<Uint8Array>({
      async pull(controller): Promise<void> {
        const chunk = await stub.read();
        if (chunk.done) {
          controller.close();
          stub[Symbol.dispose]?.();
          return;
        }
        if (chunk.value) controller.enqueue(chunk.value);
      },
      async cancel(reason): Promise<void> {
        try {
          await stub.cancel(reason);
        } finally {
          stub[Symbol.dispose]?.();
        }
      },
    });
  }

  #decodeResponse(rec: Record<string, unknown>): Response {
    const rawStatus = Number(rec["status"]);
    const status =
      Number.isFinite(rawStatus) && rawStatus >= 200 && rawStatus <= 599 ? rawStatus : 200;
    const statusText = typeof rec["statusText"] === "string" ? rec["statusText"] : "";
    const headers = this.#decodeHeaders(rec["headers"]);
    const streamCapId = rec["streamCapId"];
    let body: ReadableStream<Uint8Array> | null = null;
    if (typeof streamCapId === "number") {
      if (NULL_BODY_STATUSES.has(status)) {
        this.#dispatch.dispose(streamCapId);
      } else {
        body = this.#decodeStream(streamCapId);
      }
    }
    const resp = new Response(body, { status, statusText, headers });
    const url = typeof rec["url"] === "string" ? rec["url"] : "";
    if (url && !resp.url) {
      try {
        Object.defineProperty(resp, "url", { value: url, configurable: true, enumerable: true });
      } catch {}
    }
    return resp;
  }

  #decodeError(rec: Record<string, unknown>): Error {
    const name = typeof rec["name"] === "string" ? rec["name"] : "Error";
    const message = typeof rec["message"] === "string" ? rec["message"] : "";
    const err = new Error(message);
    err.name = name;
    if (typeof rec["stack"] === "string") err.stack = rec["stack"];
    return err;
  }

  #getBinary(index: unknown, binaries: Uint8Array[]): Uint8Array {
    const idx = Number(index);
    const bytes = binaries[idx];
    if (!bytes) {
      throw new Error(`Missing PRWP binary chunk at index ${idx}`);
    }
    return bytes;
  }

  #decodeObject(rec: Record<string, unknown>, binaries: Uint8Array[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(rec)) {
      out[key] = this.#decodeNode(val, binaries);
    }
    return out;
  }
}
