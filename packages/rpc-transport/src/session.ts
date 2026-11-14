// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Framed RPC session with capabilities, flow control, cancellation, and freeze/replug.

import { AsyncLocalStorage } from "node:async_hooks";
import type { PackedException } from "@parawing/jsrpc-types/shared";
import {
  DEFAULT_MAX_PAYLOAD_BYTES,
  FrameDecoder,
  FrameFlag,
  FrameType,
  encodeFrame,
  type FrameHeader,
  type FrameTypeCode,
} from "./framing.ts";
import { CapabilityTable, type WireCapKind } from "./capabilities.ts";

export type RpcTransportState =
  | "idle"
  | "handshaking"
  | "open"
  | "freezing"
  | "frozen"
  | "unplugged"
  | "closed";

export interface RpcHandlerContext {
  signal: AbortSignal;
  requestId: number;
}

export interface RpcCallOptions {
  signal?: AbortSignal;
}

export interface RpcSessionOptions {
  readable?: ReadableStream<Uint8Array>;
  writable?: WritableStream<Uint8Array>;
  target?: object;
  onCall?: (method: string, args: unknown[], ctx: RpcHandlerContext) => Promise<unknown> | unknown;
  role?: "client" | "server";
  windowBytes?: number;
  chunkBytes?: number;
  maxPayloadBytes?: number;
  onError?: (err: Error) => void;
}

export interface RpcSessionStats {
  state: RpcTransportState;
  nextOutboundSeq: number;
  lastRecvSeq: number;
  replayRingLength: number;
  sendCredits: number;
  creditsSent: number;
  creditsReceived: number;
  creditWaitCount: number;
  binaryChunksSent: number;
  binaryChunksReceived: number;
}

interface ReplayEntry {
  seq: number;
  bytes: Uint8Array;
  creditCost: number;
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (err: unknown) => void;
  cleanupAbort?: () => void;
}

interface ActiveRemoteCall {
  controller: AbortController;
  canceled: boolean;
}

const DEFAULT_WINDOW_BYTES = 256 * 1024;
const DEFAULT_CHUNK_BYTES = 16 * 1024;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const CALLEE_SIGNAL_ALS = new AsyncLocalStorage<AbortSignal>();
const CLIENT_SIGNAL_ALS = new AsyncLocalStorage<AbortSignal>();

export function currentCallSignal(): AbortSignal | undefined {
  return CALLEE_SIGNAL_ALS.getStore();
}

export function withCallSignal<T>(signal: AbortSignal, fn: () => T): T {
  return CLIENT_SIGNAL_ALS.run(signal, fn);
}

export function bindSignal<T extends object>(target: T, signal: AbortSignal): T {
  return new Proxy(target, {
    get(obj, prop, receiver): unknown {
      const value = Reflect.get(obj, prop, receiver);
      if (typeof value !== "function") return value;
      return (...args: unknown[]): unknown =>
        CLIENT_SIGNAL_ALS.run(signal, () => Reflect.apply(value, obj, args));
    },
  });
}

export function isPackedException(value: unknown): value is PackedException {
  if (typeof value !== "object" || value === null) return false;
  const rec = value as Record<string, unknown>;
  if (rec["ok"] !== false || typeof rec["exception"] !== "object" || rec["exception"] === null) {
    return false;
  }
  const ex = rec["exception"] as Record<string, unknown>;
  return typeof ex["message"] === "string" && typeof ex["className"] === "string";
}

export function packException(err: unknown): PackedException {
  if (isPackedException(err)) return err;
  if (err instanceof Error) {
    return {
      ok: false,
      exception: {
        text: "Uncaught",
        message: err.message,
        stack: err.stack ?? null,
        className: err.name || "Error",
      },
    };
  }
  return {
    ok: false,
    exception: {
      text: "Uncaught",
      message: String(err),
      stack: null,
      className: "Error",
    },
  };
}

export function unpackException(packed: PackedException): Error {
  const { message, stack, className } = packed.exception;
  const err = constructErrorClass(className, message);
  err.name = className || "Error";
  if (typeof stack === "string") err.stack = stack;
  return err;
}

function constructErrorClass(className: string, message: string): Error {
  switch (className) {
    case "TypeError":
      return new TypeError(message);
    case "RangeError":
      return new RangeError(message);
    case "SyntaxError":
      return new SyntaxError(message);
    case "ReferenceError":
      return new ReferenceError(message);
    case "URIError":
      return new URIError(message);
    case "EvalError":
      return new EvalError(message);
    default:
      return new Error(message);
  }
}

function makeAbortError(signal: AbortSignal): Error {
  const reason: unknown = signal.reason;
  if (reason instanceof Error) return reason;
  const err = new Error(typeof reason === "string" ? reason : "The operation was aborted.");
  err.name = "AbortError";
  return err;
}

function encodeJson(value: unknown): Uint8Array {
  return TEXT_ENCODER.encode(JSON.stringify(value));
}

function decodeJson(bytes: Uint8Array): Record<string, unknown> {
  if (bytes.byteLength === 0) return {};
  const parsed: unknown = JSON.parse(TEXT_DECODER.decode(bytes));
  if (typeof parsed === "object" && parsed !== null) {
    return parsed as Record<string, unknown>;
  }
  return {};
}

function buildBinaryChunkPayload(
  blobIndex: number,
  byteOffset: number,
  totalLength: number,
  slice: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(12 + slice.byteLength);
  const view = new DataView(out.buffer, out.byteOffset, 12);
  view.setUint32(0, blobIndex >>> 0, true);
  view.setUint32(4, byteOffset >>> 0, true);
  view.setUint32(8, totalLength >>> 0, true);
  if (slice.byteLength > 0) out.set(slice, 12);
  return out;
}

function phaseFlagOf(frameType: FrameTypeCode): number {
  if (frameType === FrameType.REPLY) return FrameFlag.PHASE_REPLY;
  if (frameType === FrameType.CALLBACK) return FrameFlag.PHASE_CALLBACK;
  return FrameFlag.PHASE_CALL;
}

function phaseKeyOf(flags: number, requestId: number): string {
  if ((flags & FrameFlag.PHASE_REPLY) !== 0) return `r:${requestId}`;
  if ((flags & FrameFlag.PHASE_CALLBACK) !== 0) return `cb:${requestId}`;
  return `c:${requestId}`;
}

export class RpcSession {
  #state: RpcTransportState = "idle";
  #target: object | undefined;
  #onCall: RpcSessionOptions["onCall"];
  #onError: ((err: Error) => void) | undefined;
  #localWindowBytes: number;
  #peerWindowBytes: number;
  #chunkBytes: number;
  #maxPayloadBytes: number;
  #capabilities: CapabilityTable;

  #nextReqId: number;
  #nextOutboundSeq = 1;
  #lastRecvSeq = 0;
  #replayRing: ReplayEntry[] = [];
  #sendQueue: ReplayEntry[] = [];
  #pendingControl: Uint8Array[] = [];
  #sendCredits = 0;
  #uncreditedBytes = 0;
  #lastAckedSeqSent = 0;
  #creditsPaused = false;
  #creditMicrotaskScheduled = false;

  #streamGen = 0;
  #handshakeDone = false;
  #runningPumpGen = 0;
  #reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  #writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  #decoder: FrameDecoder;

  #pendingCalls = new Map<string, PendingCall>();
  #activeRemoteCalls = new Map<string, ActiveRemoteCall>();
  #pendingBinaries = new Map<string, Uint8Array[]>();
  #creditWaiters: Array<() => void> = [];
  #freezeWaiters: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];

  #creditsSent = 0;
  #creditsReceived = 0;
  #creditWaitCount = 0;
  #binaryChunksSent = 0;
  #binaryChunksReceived = 0;

  constructor(options: RpcSessionOptions = {}) {
    this.#target = options.target;
    this.#onCall = options.onCall;
    this.#onError = options.onError;
    this.#localWindowBytes = Math.max(1, options.windowBytes ?? DEFAULT_WINDOW_BYTES);
    this.#peerWindowBytes = this.#localWindowBytes;
    this.#sendCredits = this.#peerWindowBytes;
    this.#chunkBytes = Math.max(1, options.chunkBytes ?? DEFAULT_CHUNK_BYTES);
    this.#maxPayloadBytes = options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;
    this.#nextReqId = options.role === "server" ? 2 : 1;
    this.#decoder = new FrameDecoder(this.#maxPayloadBytes);
    this.#capabilities = new CapabilityTable({
      invoke: (capId, method, args) => this.#invokeCapability(capId, method, args),
      dispose: (capId) => this.#sendDispose(capId),
    });
    if (options.readable && options.writable) {
      this.replug(options.readable, options.writable);
    }
  }

  getStats(): RpcSessionStats {
    return {
      state: this.#state,
      nextOutboundSeq: this.#nextOutboundSeq,
      lastRecvSeq: this.#lastRecvSeq,
      replayRingLength: this.#replayRing.length,
      sendCredits: this.#sendCredits,
      creditsSent: this.#creditsSent,
      creditsReceived: this.#creditsReceived,
      creditWaitCount: this.#creditWaitCount,
      binaryChunksSent: this.#binaryChunksSent,
      binaryChunksReceived: this.#binaryChunksReceived,
    };
  }

  exportRootStub<T extends object>(): T {
    const target = this.#target ?? {};
    const names = this.#collectMethods(target);
    const out: Record<string, unknown> = {};
    for (const name of names) {
      out[name] = (...args: unknown[]): Promise<unknown> => this.call(name, args);
    }
    return out as T;
  }

  proxy<T extends object>(): T {
    return new Proxy<Record<string, unknown>>(
      {},
      {
        get: (_target, prop): unknown => {
          if (prop === "then" || prop === "toJSON" || typeof prop === "symbol") {
            return undefined;
          }
          return (...args: unknown[]): Promise<unknown> => this.call(prop, args);
        },
      },
    ) as T;
  }

  setCreditPaused(paused: boolean): void {
    this.#creditsPaused = paused;
    if (!paused && this.#uncreditedBytes > 0) {
      this.#flushCredit();
    }
  }

  call<T = unknown>(method: string, args: unknown[] = [], options?: RpcCallOptions): Promise<T> {
    if (this.#state === "closed") {
      return Promise.reject(new Error("RPC session is closed"));
    }
    const signal = options?.signal ?? CLIENT_SIGNAL_ALS.getStore();
    if (signal?.aborted) {
      return Promise.reject(makeAbortError(signal));
    }
    const requestId = this.#allocReqId();
    return this.#sendRequestFrame(FrameType.CALL, null, method, args, requestId, signal);
  }

  async prepareFreeze(): Promise<void> {
    if (this.#state === "closed") {
      throw new Error("RPC session is closed");
    }
    if (this.#state === "frozen" || this.#state === "unplugged") return;
    if (this.#state !== "open") {
      throw new Error(`Cannot prepareFreeze while transport state is ${this.#state}`);
    }
    this.#state = "freezing";
    this.#wakeCreditWaiters();
    const waitReady = new Promise<void>((resolve, reject) => {
      this.#freezeWaiters.push({ resolve, reject });
    });
    this.#enqueueControl(
      encodeFrame({
        frameType: FrameType.PREPARE_FREEZE,
        requestId: 0,
        payload: encodeJson({ lastSentSeq: this.#nextOutboundSeq - 1 }),
      }),
    );
    await waitReady;
  }

  unplug(): void {
    if (this.#state === "closed" || this.#state === "unplugged") return;
    this.#streamGen += 1;
    this.#handshakeDone = false;
    this.#state = "unplugged";
    this.#wakeCreditWaiters();
    this.#rejectFreezeWaiters(new Error("RPC session unplugged before FREEZE_READY"));
    this.#detachStreams();
  }

  replug(readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>): void {
    if (this.#state === "closed") {
      throw new Error("Cannot replug a closed RPC session");
    }
    this.#streamGen += 1;
    this.#detachStreams();
    this.#decoder = new FrameDecoder(this.#maxPayloadBytes);
    this.#handshakeDone = false;
    this.#pendingControl.length = 0;
    this.#state = "handshaking";
    this.#reader = readable.getReader();
    this.#writer = writable.getWriter();
    const gen = this.#streamGen;
    this.#enqueueControl(
      encodeFrame({
        frameType: FrameType.HANDSHAKE,
        requestId: 0,
        payload: encodeJson({
          version: 1,
          ackedSeq: this.#lastRecvSeq,
          windowBytes: this.#localWindowBytes,
        }),
      }),
    );
    void this.#readLoop(gen, this.#reader);
    void this.#kickSendPump(gen);
  }

  close(reason = "RPC session closed"): void {
    if (this.#state === "closed") return;
    this.#streamGen += 1;
    this.#state = "closed";
    this.#handshakeDone = false;
    this.#wakeCreditWaiters();
    const err = new Error(reason);
    this.#rejectPendingCalls(err);
    this.#rejectFreezeWaiters(err);
    this.#abortActiveRemoteCalls(err);
    this.#pendingBinaries.clear();
    this.#replayRing.length = 0;
    this.#sendQueue.length = 0;
    this.#pendingControl.length = 0;
    this.#capabilities.disposeAll();
    this.#detachStreams();
  }

  [Symbol.dispose](): void {
    this.close();
  }

  #allocReqId(): number {
    const id = this.#nextReqId;
    this.#nextReqId += 2;
    return id >>> 0;
  }

  #collectMethods(target: object): string[] {
    const names = new Set<string>();
    for (const key of Object.keys(target)) {
      if (typeof Reflect.get(target, key) === "function") names.add(key);
    }
    let proto: object | null = Object.getPrototypeOf(target);
    while (proto && proto !== Object.prototype) {
      for (const name of Object.getOwnPropertyNames(proto)) {
        if (name === "constructor") continue;
        if (typeof Reflect.get(target, name) === "function") names.add(name);
      }
      proto = Object.getPrototypeOf(proto);
    }
    return [...names];
  }

  #invokeCapability(capId: number, method: string | null, args: unknown[]): Promise<unknown> {
    if (this.#state === "closed") {
      return Promise.reject(new Error("RPC session is closed"));
    }
    const signal = CLIENT_SIGNAL_ALS.getStore();
    if (signal?.aborted) {
      return Promise.reject(makeAbortError(signal));
    }
    const requestId = this.#allocReqId();
    return this.#sendRequestFrame(FrameType.CALLBACK, capId, method, args, requestId, signal);
  }

  #sendRequestFrame<T>(
    frameType: typeof FrameType.CALL | typeof FrameType.CALLBACK,
    capId: number | null,
    method: string | null,
    args: unknown[],
    requestId: number,
    signal?: AbortSignal,
  ): Promise<T> {
    const key = frameType === FrameType.CALLBACK ? `cb:${requestId}` : `c:${requestId}`;
    return new Promise<T>((resolve, reject) => {
      const pending: PendingCall = {
        resolve: resolve as (v: unknown) => void,
        reject,
      };
      if (signal) {
        const onAbort = (): void => {
          if (!this.#pendingCalls.delete(key)) return;
          const err = makeAbortError(signal);
          reject(err);
          this.#enqueueReliable(
            FrameType.CANCEL,
            frameType === FrameType.CALLBACK ? FrameFlag.PHASE_CALLBACK : FrameFlag.PHASE_CALL,
            requestId,
            encodeJson({ reason: err.message }),
          );
        };
        signal.addEventListener("abort", onAbort, { once: true });
        pending.cleanupAbort = (): void => signal.removeEventListener("abort", onAbort);
      }
      this.#pendingCalls.set(key, pending);
      const { encoded, binaries } = this.#capabilities.encodeValue(args);
      this.#enqueueBinaryBlobs(frameType, requestId, binaries);
      const body =
        frameType === FrameType.CALLBACK
          ? { c: capId, m: method, a: encoded, bc: binaries.length }
          : { m: method, a: encoded, bc: binaries.length };
      const flags = binaries.length > 0 ? FrameFlag.HAS_BINARY : FrameFlag.NONE;
      this.#enqueueReliable(frameType, flags, requestId, encodeJson(body));
    });
  }

  #enqueueBinaryBlobs(frameType: FrameTypeCode, requestId: number, binaries: Uint8Array[]): void {
    const pFlag = phaseFlagOf(frameType);
    for (let blobIndex = 0; blobIndex < binaries.length; blobIndex++) {
      const blob = binaries[blobIndex]!;
      if (blob.byteLength === 0) {
        const payload = buildBinaryChunkPayload(blobIndex, 0, 0, blob);
        this.#enqueueReliable(FrameType.BINARY_CHUNK, pFlag | FrameFlag.FIN, requestId, payload);
        this.#binaryChunksSent += 1;
        continue;
      }
      let offset = 0;
      while (offset < blob.byteLength) {
        const end = Math.min(offset + this.#chunkBytes, blob.byteLength);
        const slice = blob.subarray(offset, end);
        const fin = end >= blob.byteLength ? FrameFlag.FIN : FrameFlag.NONE;
        const payload = buildBinaryChunkPayload(blobIndex, offset, blob.byteLength, slice);
        this.#enqueueReliable(FrameType.BINARY_CHUNK, pFlag | fin, requestId, payload);
        this.#binaryChunksSent += 1;
        offset = end;
      }
    }
  }

  #sendDispose(capId: number): void {
    if (this.#state === "closed") return;
    this.#enqueueReliable(FrameType.DISPOSE, FrameFlag.NONE, 0, encodeJson({ c: capId }));
  }

  #enqueueReliable(
    frameType: FrameTypeCode,
    flags: number,
    requestId: number,
    payload: Uint8Array,
  ): void {
    const bytes = encodeFrame({ frameType, flags, requestId, payload });
    const entry: ReplayEntry = {
      seq: this.#nextOutboundSeq++,
      bytes,
      creditCost: Math.max(1, payload.byteLength),
    };
    this.#replayRing.push(entry);
    this.#sendQueue.push(entry);
    this.#kickSendPump(this.#streamGen);
  }

  #enqueueControl(bytes: Uint8Array): void {
    this.#pendingControl.push(bytes);
    this.#kickSendPump(this.#streamGen);
  }

  #kickSendPump(gen: number): void {
    if (gen !== this.#streamGen || this.#runningPumpGen === gen) return;
    void this.#runSendPump(gen);
  }

  async #runSendPump(gen: number): Promise<void> {
    if (gen !== this.#streamGen || this.#runningPumpGen === gen) return;
    this.#runningPumpGen = gen;
    try {
      while (gen === this.#streamGen && this.#writer && this.#canPump()) {
        if (this.#pendingControl.length > 0) {
          const ctrl = this.#pendingControl.shift()!;
          await this.#writer.write(ctrl);
          continue;
        }
        if (!this.#handshakeDone || this.#state !== "open" || this.#sendQueue.length === 0) {
          break;
        }
        const next = this.#sendQueue[0]!;
        const needed = Math.min(next.creditCost, this.#peerWindowBytes);
        if (this.#sendCredits < needed) {
          this.#creditWaitCount += 1;
          await this.#waitForCredit(gen);
          continue;
        }
        this.#sendQueue.shift();
        this.#sendCredits = Math.max(0, this.#sendCredits - next.creditCost);
        await this.#writer.write(next.bytes);
      }
    } catch (err) {
      if (gen === this.#streamGen && this.#state !== "closed" && this.#state !== "unplugged") {
        this.#onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    } finally {
      if (this.#runningPumpGen === gen) this.#runningPumpGen = 0;
    }
    if (gen === this.#streamGen && this.#hasRunnableWork()) {
      this.#kickSendPump(gen);
    }
  }

  #canPump(): boolean {
    return this.#state !== "closed" && this.#state !== "unplugged";
  }

  #hasRunnableWork(): boolean {
    if (!this.#writer || !this.#canPump()) return false;
    if (this.#pendingControl.length > 0) return true;
    return this.#handshakeDone && this.#state === "open" && this.#sendQueue.length > 0;
  }

  #waitForCredit(gen: number): Promise<void> {
    return new Promise((resolve) => {
      if (gen !== this.#streamGen) {
        resolve();
        return;
      }
      this.#creditWaiters.push(resolve);
    });
  }

  #wakeCreditWaiters(): void {
    const waiters = this.#creditWaiters.splice(0);
    for (const wake of waiters) wake();
  }

  async #readLoop(gen: number, reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
    try {
      while (gen === this.#streamGen) {
        const { done, value } = await reader.read();
        if (done || gen !== this.#streamGen) break;
        if (!value || value.byteLength === 0) continue;
        const frames = this.#decoder.push(value);
        for (const frame of frames) {
          if (gen !== this.#streamGen) return;
          this.#handleFrame(frame.header, frame.payload);
        }
      }
    } catch (err) {
      if (gen === this.#streamGen && this.#state !== "closed" && this.#state !== "unplugged") {
        this.#onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  #handleFrame(header: FrameHeader, payload: Uint8Array): void {
    if (header.frameType === FrameType.HANDSHAKE) {
      this.#onHandshake(payload);
      return;
    }
    if (header.frameType === FrameType.CREDIT) {
      this.#onCredit(payload);
      return;
    }
    if (header.frameType === FrameType.PREPARE_FREEZE) {
      this.#onPrepareFreeze();
      return;
    }
    if (header.frameType === FrameType.FREEZE_READY) {
      this.#onFreezeReady(payload);
      return;
    }
    this.#lastRecvSeq += 1;
    this.#dispatchReliableFrame(header, payload);
    this.#accountInboundCredit(Math.max(1, payload.byteLength));
  }

  #onHandshake(payload: Uint8Array): void {
    const msg = decodeJson(payload);
    const ackedSeq = typeof msg["ackedSeq"] === "number" ? msg["ackedSeq"] : 0;
    const win = typeof msg["windowBytes"] === "number" ? msg["windowBytes"] : DEFAULT_WINDOW_BYTES;
    this.#peerWindowBytes = Math.max(1, win);
    this.#sendCredits = this.#peerWindowBytes;
    this.#trimReplayRing(ackedSeq);
    this.#sendQueue = [...this.#replayRing];
    this.#handshakeDone = true;
    this.#state = "open";
    this.#wakeCreditWaiters();
    this.#kickSendPump(this.#streamGen);
  }

  #onCredit(payload: Uint8Array): void {
    const msg = decodeJson(payload);
    const ackedSeq = typeof msg["ackedSeq"] === "number" ? msg["ackedSeq"] : 0;
    const bytes = typeof msg["bytes"] === "number" ? msg["bytes"] : 0;
    this.#creditsReceived += 1;
    this.#trimReplayRing(ackedSeq);
    if (bytes > 0) {
      this.#sendCredits = Math.min(this.#peerWindowBytes, this.#sendCredits + bytes);
    }
    this.#wakeCreditWaiters();
    this.#kickSendPump(this.#streamGen);
  }

  #onPrepareFreeze(): void {
    this.#state = "frozen";
    this.#wakeCreditWaiters();
    this.#enqueueControl(
      encodeFrame({
        frameType: FrameType.FREEZE_READY,
        requestId: 0,
        payload: encodeJson({ ackedSeq: this.#lastRecvSeq }),
      }),
    );
  }

  #onFreezeReady(payload: Uint8Array): void {
    const msg = decodeJson(payload);
    const ackedSeq = typeof msg["ackedSeq"] === "number" ? msg["ackedSeq"] : 0;
    this.#trimReplayRing(ackedSeq);
    this.#state = "frozen";
    this.#wakeCreditWaiters();
    const waiters = this.#freezeWaiters.splice(0);
    for (const w of waiters) w.resolve();
  }

  #trimReplayRing(ackedSeq: number): void {
    if (ackedSeq <= 0 || this.#replayRing.length === 0) return;
    let firstKeep = 0;
    while (firstKeep < this.#replayRing.length && this.#replayRing[firstKeep]!.seq <= ackedSeq) {
      firstKeep += 1;
    }
    if (firstKeep > 0) {
      this.#replayRing.splice(0, firstKeep);
    }
  }

  #accountInboundCredit(cost: number): void {
    this.#uncreditedBytes += cost;
    if (this.#creditsPaused) return;
    if (this.#uncreditedBytes >= Math.max(1, this.#localWindowBytes >>> 1)) {
      this.#flushCredit();
      return;
    }
    if (!this.#creditMicrotaskScheduled) {
      this.#creditMicrotaskScheduled = true;
      queueMicrotask(() => {
        this.#creditMicrotaskScheduled = false;
        if (this.#creditsPaused || this.#state === "closed" || this.#state === "unplugged") return;
        if (this.#uncreditedBytes > 0 || this.#lastRecvSeq > this.#lastAckedSeqSent) {
          this.#flushCredit();
        }
      });
    }
  }

  #flushCredit(): void {
    if (!this.#writer || this.#state === "closed" || this.#state === "unplugged") return;
    const bytes = this.#uncreditedBytes;
    const ackedSeq = this.#lastRecvSeq;
    if (bytes === 0 && ackedSeq <= this.#lastAckedSeqSent) return;
    this.#uncreditedBytes = 0;
    this.#lastAckedSeqSent = ackedSeq;
    this.#creditsSent += 1;
    this.#enqueueControl(
      encodeFrame({
        frameType: FrameType.CREDIT,
        requestId: 0,
        payload: encodeJson({ bytes, ackedSeq }),
      }),
    );
  }

  #dispatchReliableFrame(header: FrameHeader, payload: Uint8Array): void {
    switch (header.frameType) {
      case FrameType.BINARY_CHUNK:
        this.#onBinaryChunk(header, payload);
        break;
      case FrameType.CALL:
        this.#onCallFrame(header, payload);
        break;
      case FrameType.CALLBACK:
        this.#onCallbackFrame(header, payload);
        break;
      case FrameType.REPLY:
        this.#onReplyFrame(header, payload);
        break;
      case FrameType.ERROR:
        this.#onErrorFrame(header, payload);
        break;
      case FrameType.CANCEL:
        this.#onCancelFrame(header, payload);
        break;
      case FrameType.DISPOSE:
        this.#onDisposeFrame(payload);
        break;
      default:
        break;
    }
  }

  #onBinaryChunk(header: FrameHeader, payload: Uint8Array): void {
    if (payload.byteLength < 12) return;
    this.#binaryChunksReceived += 1;
    const view = new DataView(payload.buffer, payload.byteOffset, 12);
    const blobIndex = view.getUint32(0, true);
    const byteOffset = view.getUint32(4, true);
    const totalLength = view.getUint32(8, true);
    const slice = payload.subarray(12);
    if (byteOffset + slice.byteLength > totalLength) {
      this.#onError?.(new Error("Corrupt PRWP BINARY_CHUNK bounds"));
      return;
    }
    const key = phaseKeyOf(header.flags, header.requestId);
    let blobs = this.#pendingBinaries.get(key);
    if (!blobs) {
      blobs = [];
      this.#pendingBinaries.set(key, blobs);
    }
    let buf = blobs[blobIndex];
    if (!buf) {
      buf = new Uint8Array(totalLength);
      blobs[blobIndex] = buf;
    }
    if (slice.byteLength > 0) buf.set(slice, byteOffset);
  }

  #takeBinaries(key: string): Uint8Array[] {
    const blobs = this.#pendingBinaries.get(key);
    if (blobs) this.#pendingBinaries.delete(key);
    return blobs ?? [];
  }

  #onCallFrame(header: FrameHeader, payload: Uint8Array): void {
    const msg = decodeJson(payload);
    const binaries = this.#takeBinaries(`c:${header.requestId}`);
    const method = String(msg["m"] ?? "");
    const rawArgs = this.#capabilities.decodeValue(msg["a"], binaries);
    const args = Array.isArray(rawArgs) ? rawArgs : [];
    const activeKey = `call:${header.requestId}`;
    const controller = new AbortController();
    const record: ActiveRemoteCall = { controller, canceled: false };
    this.#activeRemoteCalls.set(activeKey, record);
    void this.#executeIncomingCall(
      header.requestId,
      activeKey,
      record,
      () => {
        return this.#invokeLocalMethod(method, args, {
          signal: controller.signal,
          requestId: header.requestId,
        });
      },
      FrameFlag.PHASE_CALL,
    );
  }

  #onCallbackFrame(header: FrameHeader, payload: Uint8Array): void {
    const msg = decodeJson(payload);
    const binaries = this.#takeBinaries(`cb:${header.requestId}`);
    const capId = Number(msg["c"]);
    const method = typeof msg["m"] === "string" ? msg["m"] : null;
    const rawArgs = this.#capabilities.decodeValue(msg["a"], binaries);
    const args = Array.isArray(rawArgs) ? rawArgs : [];
    const activeKey = `cb:${header.requestId}`;
    const controller = new AbortController();
    const record: ActiveRemoteCall = { controller, canceled: false };
    this.#activeRemoteCalls.set(activeKey, record);
    void this.#executeIncomingCall(
      header.requestId,
      activeKey,
      record,
      () => this.#invokeLocalCap(capId, method, args),
      FrameFlag.PHASE_CALLBACK,
    );
  }

  async #executeIncomingCall(
    requestId: number,
    activeKey: string,
    record: ActiveRemoteCall,
    fn: () => Promise<unknown>,
    phaseFlag: number,
  ): Promise<void> {
    try {
      const value = await CALLEE_SIGNAL_ALS.run(record.controller.signal, fn);
      if (record.canceled || this.#state === "closed") return;
      const { encoded, binaries } = this.#capabilities.encodeValue(value);
      this.#enqueueBinaryBlobs(FrameType.REPLY, requestId, binaries);
      const replyFlags = phaseFlag | (binaries.length > 0 ? FrameFlag.HAS_BINARY : 0);
      this.#enqueueReliable(
        FrameType.REPLY,
        replyFlags,
        requestId,
        encodeJson({ r: encoded, bc: binaries.length }),
      );
    } catch (err) {
      if (record.canceled || this.#state === "closed") return;
      const packed = packException(err);
      this.#enqueueReliable(FrameType.ERROR, phaseFlag, requestId, encodeJson({ e: packed }));
    } finally {
      this.#activeRemoteCalls.delete(activeKey);
    }
  }

  async #invokeLocalMethod(
    method: string,
    args: unknown[],
    ctx: RpcHandlerContext,
  ): Promise<unknown> {
    if (this.#target) {
      const fn = Reflect.get(this.#target, method);
      if (typeof fn === "function") {
        return await Reflect.apply(fn, this.#target, args);
      }
    }
    if (this.#onCall) {
      return await this.#onCall(method, args, ctx);
    }
    throw new Error(`Unknown RPC method: ${method}`);
  }

  async #invokeLocalCap(capId: number, method: string | null, args: unknown[]): Promise<unknown> {
    const entry = this.#capabilities.getExport(capId);
    if (!entry) {
      throw new Error(`Unknown or disposed capability id: ${capId}`);
    }
    if (method === null) {
      if (typeof entry.target !== "function") {
        throw new Error(`Capability ${capId} is not callable`);
      }
      return await Reflect.apply(entry.target, undefined, args);
    }
    const targetObj = entry.target as object;
    const fn = Reflect.get(targetObj, method);
    if (typeof fn !== "function") {
      throw new Error(`Capability ${capId} has no method '${method}'`);
    }
    return await Reflect.apply(fn, targetObj, args);
  }

  #onReplyFrame(header: FrameHeader, payload: Uint8Array): void {
    const key =
      (header.flags & FrameFlag.PHASE_CALLBACK) !== 0
        ? `cb:${header.requestId}`
        : `c:${header.requestId}`;
    const binaries = this.#takeBinaries(`r:${header.requestId}`);
    const pending = this.#pendingCalls.get(key);
    if (!pending) return;
    this.#pendingCalls.delete(key);
    pending.cleanupAbort?.();
    const msg = decodeJson(payload);
    const decoded = this.#capabilities.decodeValue(msg["r"], binaries);
    pending.resolve(decoded);
  }

  #onErrorFrame(header: FrameHeader, payload: Uint8Array): void {
    const key =
      (header.flags & FrameFlag.PHASE_CALLBACK) !== 0
        ? `cb:${header.requestId}`
        : `c:${header.requestId}`;
    this.#takeBinaries(`r:${header.requestId}`);
    const pending = this.#pendingCalls.get(key);
    if (!pending) return;
    this.#pendingCalls.delete(key);
    pending.cleanupAbort?.();
    const msg = decodeJson(payload);
    const packed = msg["e"];
    pending.reject(
      isPackedException(packed) ? unpackException(packed) : new Error("Unknown RPC error"),
    );
  }

  #onCancelFrame(header: FrameHeader, payload: Uint8Array): void {
    const isCb = (header.flags & FrameFlag.PHASE_CALLBACK) !== 0;
    const key = `${isCb ? "cb" : "call"}:${header.requestId}`;
    const record = this.#activeRemoteCalls.get(key);
    if (!record) return;
    record.canceled = true;
    const msg = decodeJson(payload);
    const reason = typeof msg["reason"] === "string" ? msg["reason"] : "The operation was aborted.";
    const err = new Error(reason);
    err.name = "AbortError";
    record.controller.abort(err);
  }

  #onDisposeFrame(payload: Uint8Array): void {
    const msg = decodeJson(payload);
    const capId = Number(msg["c"]);
    this.#capabilities.releaseExport(capId);
  }

  #detachStreams(): void {
    const reader = this.#reader;
    const writer = this.#writer;
    this.#reader = null;
    this.#writer = null;
    if (reader) {
      void reader.cancel().catch(() => {});
    }
    if (writer) {
      try {
        writer.releaseLock();
      } catch {}
    }
  }

  #rejectPendingCalls(err: Error): void {
    const calls = [...this.#pendingCalls.values()];
    this.#pendingCalls.clear();
    for (const c of calls) {
      c.cleanupAbort?.();
      c.reject(err);
    }
  }

  #rejectFreezeWaiters(err: Error): void {
    const waiters = this.#freezeWaiters.splice(0);
    for (const w of waiters) w.reject(err);
  }

  #abortActiveRemoteCalls(err: Error): void {
    const active = [...this.#activeRemoteCalls.values()];
    this.#activeRemoteCalls.clear();
    for (const a of active) {
      a.canceled = true;
      a.controller.abort(err);
    }
  }
}

export function createRpcSession(options: RpcSessionOptions = {}): RpcSession {
  return new RpcSession(options);
}

export interface BidirectionalStreamPair {
  a: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
  b: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
}

export function createStreamPair(): BidirectionalStreamPair {
  const aToB = new TransformStream<Uint8Array, Uint8Array>();
  const bToA = new TransformStream<Uint8Array, Uint8Array>();
  return {
    a: { readable: bToA.readable, writable: aToB.writable },
    b: { readable: aToB.readable, writable: bToA.writable },
  };
}

export type { WireCapKind };
