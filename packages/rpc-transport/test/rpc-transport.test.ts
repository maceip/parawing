// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  FrameDecoder,
  FrameFlag,
  FrameType,
  PRWP_HEADER_BYTES,
  PRWP_MAGIC,
  PRWP_VERSION,
  bindSignal,
  createRpcSession,
  createStreamPair,
  currentCallSignal,
  decodeHeader,
  encodeFrame,
  isPackedException,
  markRpcTarget,
  packException,
  unpackException,
  withCallSignal,
} from "../src/index.ts";
import type { RpcStub } from "@parawing/jsrpc-types/rpc";

describe("PRWP framing", () => {
  it("encodes exact 16-byte LE headers and decodes fragmented 1-byte chunks", () => {
    const payload = new Uint8Array([10, 20, 30, 40, 50]);
    const wire = encodeFrame({
      frameType: FrameType.CALL,
      flags: FrameFlag.HAS_BINARY | FrameFlag.FIN,
      requestId: 0x01020304,
      payload,
    });
    assert.equal(wire.byteLength, PRWP_HEADER_BYTES + payload.byteLength);

    const view = new DataView(wire.buffer, wire.byteOffset, PRWP_HEADER_BYTES);
    assert.equal(view.getUint32(0, true), PRWP_MAGIC);
    assert.equal(view.getUint8(4), PRWP_VERSION);
    assert.equal(view.getUint8(5), FrameType.CALL);
    assert.equal(view.getUint16(6, true), FrameFlag.HAS_BINARY | FrameFlag.FIN);
    assert.equal(view.getUint32(8, true), 0x01020304);
    assert.equal(view.getUint32(12, true), payload.byteLength);

    const hdr = decodeHeader(wire);
    assert.equal(hdr.frameType, FrameType.CALL);

    const decoder = new FrameDecoder();
    const out = [];
    for (let i = 0; i < wire.byteLength; i++) {
      out.push(...decoder.push(wire.subarray(i, i + 1)));
    }
    assert.equal(out.length, 1);
    assert.equal(out[0]!.header.requestId, 0x01020304);
    assert.deepEqual(out[0]!.payload, payload);
  });

  it("rejects invalid magic or unsupported version", () => {
    const bad = encodeFrame({
      frameType: FrameType.HANDSHAKE,
      requestId: 0,
      payload: new Uint8Array(0),
    });
    bad[0] = 0xff;
    assert.throws(() => new FrameDecoder().push(bad), /Invalid PRWP magic/);

    const badVer = encodeFrame({
      frameType: FrameType.HANDSHAKE,
      requestId: 0,
      payload: new Uint8Array(0),
    });
    badVer[4] = 9;
    assert.throws(() => new FrameDecoder().push(badVer), /Unsupported PRWP version/);
  });

  it("enumerates all 11 protocol FrameTypes cleanly", () => {
    assert.deepEqual(Object.keys(FrameType), [
      "HANDSHAKE",
      "CALL",
      "REPLY",
      "CALLBACK",
      "CANCEL",
      "DISPOSE",
      "BINARY_CHUNK",
      "CREDIT",
      "ERROR",
      "PREPARE_FREEZE",
      "FREEZE_READY",
    ]);
  });
});

describe("RpcSession calls, binaries, capabilities, cancellation, errors", () => {
  it("transfers Uint8Array without base64 across calls, replies, and callbacks", async () => {
    const pair = createStreamPair();
    const observedFrameTypes: number[] = [];
    let observedRawBinaryFound = false;

    const pattern = new Uint8Array(4096);
    for (let i = 0; i < pattern.length; i++) pattern[i] = (i * 17 + 3) & 0xff;

    const spyDecoder = new FrameDecoder();
    const tappedBtoAReadable = pair.a.readable.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          for (const frame of spyDecoder.push(chunk)) {
            observedFrameTypes.push(frame.header.frameType);
            if (frame.header.frameType === FrameType.BINARY_CHUNK) {
              const slice = frame.payload.subarray(12);
              if (slice.length > 0 && slice[0] === ((0 * 17 + 3) & 0xff)) {
                observedRawBinaryFound = true;
              }
            }
          }
          controller.enqueue(chunk);
        },
      }),
    );

    const server = createRpcSession({
      readable: pair.b.readable,
      writable: pair.b.writable,
      role: "server",
      chunkBytes: 1024,
      target: {
        async echoWithCallback(
          input: Uint8Array,
          empty: Uint8Array,
          cb: (arg: Uint8Array) => Promise<Uint8Array>,
        ) {
          assert.equal(empty.byteLength, 0);
          assert.deepEqual(input, pattern);
          const echoed = await cb(input.subarray(0, 512));
          const combined = new Uint8Array(echoed.byteLength + 2);
          combined.set(echoed, 0);
          combined[echoed.byteLength] = 0xde;
          combined[echoed.byteLength + 1] = 0xad;
          return { raw: combined, tag: "ok" };
        },
      },
    });
    const client = createRpcSession({
      readable: tappedBtoAReadable,
      writable: pair.a.writable,
      role: "client",
      chunkBytes: 1024,
    });

    const result = await client.call<{ raw: Uint8Array; tag: string }>("echoWithCallback", [
      pattern,
      new Uint8Array(0),
      (slice: Uint8Array) => slice.slice(),
    ]);
    assert.equal(result.tag, "ok");
    assert.equal(result.raw.byteLength, 514);
    assert.deepEqual(result.raw.subarray(0, 512), pattern.subarray(0, 512));
    assert.equal(result.raw[512], 0xde);
    assert.equal(result.raw[513], 0xad);
    assert.ok(observedFrameTypes.includes(FrameType.BINARY_CHUNK));
    assert.ok(observedFrameTypes.includes(FrameType.CALLBACK));
    assert.ok(observedRawBinaryFound);
    assert.ok(server.getStats().binaryChunksSent > 0);
    assert.ok(client.getStats().binaryChunksReceived > 0);

    client.close();
    server.close();
  });

  it("manages RpcTarget objects, callbacks, dup(), and [Symbol.dispose]()", async () => {
    const pair = createStreamPair();
    let targetDisposed = 0;

    interface CounterTarget {
      inc(delta: number): number;
      get(): number;
    }

    const server = createRpcSession({
      readable: pair.b.readable,
      writable: pair.b.writable,
      role: "server",
      target: {
        makeCounter(initial: number) {
          let value = initial;
          const obj = markRpcTarget({
            inc(delta: number) {
              value += delta;
              return value;
            },
            get() {
              return value;
            },
            [Symbol.dispose]() {
              targetDisposed += 1;
            },
          });
          return obj;
        },
      },
    });
    const client = createRpcSession({
      readable: pair.a.readable,
      writable: pair.a.writable,
      role: "client",
    });

    const stub1 = await client.call<RpcStub<CounterTarget>>("makeCounter", [10]);
    const stub2 = stub1.dup!();
    assert.equal(await stub1.inc(5), 15);
    assert.equal(await stub2.get(), 15);

    stub1[Symbol.dispose]();
    await assert.rejects(() => stub1.get(), /disposed/);
    assert.equal(targetDisposed, 0);
    assert.equal(await stub2.inc(3), 18);

    stub2[Symbol.dispose]();
    // Allow async DISPOSE delivery and server ack.
    await new Promise((r) => setTimeout(r, 25));
    assert.equal(targetDisposed, 1);

    client.close();
    server.close();
  });

  it("enforces credit-based backpressure with CREDIT frames", async () => {
    const pair = createStreamPair();
    const server = createRpcSession({
      readable: pair.b.readable,
      writable: pair.b.writable,
      role: "server",
      windowBytes: 512,
      chunkBytes: 128,
      target: {
        sink(data: Uint8Array) {
          return data.byteLength;
        },
      },
    });
    const client = createRpcSession({
      readable: pair.a.readable,
      writable: pair.a.writable,
      role: "client",
      windowBytes: 512,
      chunkBytes: 128,
    });

    server.setCreditPaused(true);
    const large = new Uint8Array(4096).fill(0x5a);
    let settled = false;
    const uploadPromise = client.call<number>("sink", [large]).then((n) => {
      settled = true;
      return n;
    });

    await new Promise((r) => setTimeout(r, 30));
    assert.equal(settled, false);
    assert.ok(client.getStats().creditWaitCount >= 1);

    server.setCreditPaused(false);
    const total = await uploadPromise;
    assert.equal(total, 4096);
    assert.ok(client.getStats().creditsReceived >= 1);
    assert.ok(server.getStats().creditsSent >= 1);

    client.close();
    server.close();
  });

  it("propagates AbortSignal CANCEL frames to callee signal and unpacks Errors", async () => {
    const pair = createStreamPair();
    let calleeAborted = false;
    let resolveAborted!: () => void;
    const abortedSeen = new Promise<void>((resolve) => {
      resolveAborted = resolve;
    });

    const server = createRpcSession({
      readable: pair.b.readable,
      writable: pair.b.writable,
      role: "server",
      target: {
        waitUntilCancelled() {
          const signal = currentCallSignal();
          assert.ok(signal, "callee signal must be attached");
          return new Promise<string>((resolve) => {
            signal.addEventListener("abort", () => {
              calleeAborted = true;
              resolveAborted();
              resolve("aborted-late");
            });
          });
        },
        failType() {
          throw new TypeError("expected failure");
        },
        echoUndefined(x: unknown) {
          return { x, big: 42n };
        },
      },
    });
    const client = createRpcSession({
      readable: pair.a.readable,
      writable: pair.a.writable,
      role: "client",
    });

    const ac = new AbortController();
    const pending = client.call("waitUntilCancelled", [], { signal: ac.signal });
    setTimeout(() => ac.abort(new DOMException("Client gone", "AbortError")), 15);
    await assert.rejects(pending, { name: "AbortError" });
    await abortedSeen;
    assert.equal(calleeAborted, true);

    const ac2 = new AbortController();
    const api = bindSignal(client.proxy<{ waitUntilCancelled(): Promise<string> }>(), ac2.signal);
    const pending2 = withCallSignal(ac2.signal, () => api.waitUntilCancelled());
    ac2.abort("custom cancel");
    await assert.rejects(pending2, /custom cancel/);

    await assert.rejects(
      () => client.call("failType"),
      (err: unknown) => err instanceof TypeError && err.message === "expected failure",
    );

    const packed = packException(new RangeError("oob"));
    assert.equal(isPackedException(packed), true);
    const unpacked = unpackException(packed);
    assert.ok(unpacked instanceof RangeError);
    assert.equal(unpacked.message, "oob");

    const special = await client.call<{ x: unknown; big: bigint }>("echoUndefined", [undefined]);
    assert.equal(special.x, undefined);
    assert.equal(special.big, 42n);

    client.close();
    server.close();
  });
});

describe("RpcSession freeze, unplug, and replug replay", () => {
  it("completes prepareFreeze(), buffers calls while unplugged, and replays on replug", async () => {
    const pair1 = createStreamPair();
    const seenCalls: string[] = [];

    const server = createRpcSession({
      readable: pair1.b.readable,
      writable: pair1.b.writable,
      role: "server",
      target: {
        ping(label: string) {
          seenCalls.push(label);
          return `pong:${label}`;
        },
      },
    });
    const client = createRpcSession({
      readable: pair1.a.readable,
      writable: pair1.a.writable,
      role: "client",
    });

    assert.equal(await client.call("ping", ["one"]), "pong:one");

    await client.prepareFreeze();
    assert.equal(client.getStats().state, "frozen");
    assert.equal(server.getStats().state, "frozen");

    client.unplug();
    server.unplug();
    assert.equal(client.getStats().state, "unplugged");

    // Enqueue calls and binary payloads while unplugged.
    const whileUnplugged = client.call("ping", ["two"]);

    const pair2 = createStreamPair();
    server.replug(pair2.b.readable, pair2.b.writable);
    client.replug(pair2.a.readable, pair2.a.writable);

    assert.equal(await whileUnplugged, "pong:two");
    assert.equal(await client.call("ping", ["three"]), "pong:three");
    assert.deepEqual(seenCalls, ["one", "two", "three"]);

    client.close();
    server.close();
  });

  it("replays lost mid-flight frames via seq ring trimmed by ackedSeq on unplug + replug", async () => {
    let dropClientToServer = false;
    const c2sWire = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        if (!dropClientToServer) controller.enqueue(chunk);
      },
    });
    const s2cWire = new TransformStream<Uint8Array, Uint8Array>();

    const serverSeen: Array<{ n: number; bytesLen: number }> = [];
    let releaseDeferred!: (val: string) => void;
    const deferredReady = new Promise<string>((resolve) => {
      releaseDeferred = resolve;
    });

    const server = createRpcSession({
      readable: c2sWire.readable,
      writable: s2cWire.writable,
      role: "server",
      target: {
        async waitAcrossReplug(tag: string) {
          const done = await deferredReady;
          return `${tag}:${done}`;
        },
        record(n: number, data: Uint8Array) {
          serverSeen.push({ n, bytesLen: data.byteLength });
          return n * 10;
        },
      },
    });
    const client = createRpcSession({
      readable: s2cWire.readable,
      writable: c2sWire.writable,
      role: "client",
    });

    const pre = await client.call<number>("record", [1, new Uint8Array([1, 2])]);
    assert.equal(pre, 10);
    // Allow microtask CREDIT ack so seq 1 is trimmed from replay ring before unplug.
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(client.getStats().replayRingLength, 0);

    // Start one in-flight call on server AND drop wire frames for subsequent calls mid-flight.
    const midFlight = client.call<string>("waitAcrossReplug", ["inflight"]);
    await new Promise((r) => setTimeout(r, 15));

    dropClientToServer = true;
    const lost1 = client.call<number>("record", [2, new Uint8Array([3, 4, 5])]);
    const lost2 = client.call<number>("record", [3, new Uint8Array([6, 7, 8, 9])]);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(serverSeen.length, 1);

    client.unplug();
    server.unplug();

    // Server resolves the mid-flight call while unplugged; reply buffers in server replay ring.
    releaseDeferred("resumed");

    const pair2 = createStreamPair();
    server.replug(pair2.b.readable, pair2.b.writable);
    client.replug(pair2.a.readable, pair2.a.writable);

    assert.equal(await midFlight, "inflight:resumed");
    assert.equal(await lost1, 20);
    assert.equal(await lost2, 30);
    assert.deepEqual(serverSeen, [
      { n: 1, bytesLen: 2 },
      { n: 2, bytesLen: 3 },
      { n: 3, bytesLen: 4 },
    ]);

    client.close();
    server.close();
  });

  it("forwards an imported RpcTarget stub across a second RpcSession", async () => {
    const pairA = createStreamPair();
    const pairB = createStreamPair();

    interface Port {
      echo(bytes: Uint8Array, tag: string): Uint8Array;
    }

    const serverA = createRpcSession({
      readable: pairA.b.readable,
      writable: pairA.b.writable,
      role: "server",
      target: {
        mintPort() {
          return markRpcTarget({
            echo(bytes: Uint8Array, tag: string) {
              const tagBytes = new TextEncoder().encode(`:${tag}`);
              const out = new Uint8Array(bytes.byteLength + tagBytes.byteLength);
              out.set(bytes, 0);
              out.set(tagBytes, bytes.byteLength);
              return out;
            },
          });
        },
      },
    });
    const relayA = createRpcSession({
      readable: pairA.a.readable,
      writable: pairA.a.writable,
      role: "client",
    });
    const serverB = createRpcSession({
      readable: pairB.b.readable,
      writable: pairB.b.writable,
      role: "server",
      target: {
        async usePort(port: RpcStub<Port>, tag: string) {
          const reply = await port.echo(new Uint8Array([0x6f, 0x6b]), tag);
          return new TextDecoder().decode(reply);
        },
      },
    });
    const relayB = createRpcSession({
      readable: pairB.a.readable,
      writable: pairB.a.writable,
      role: "client",
    });

    const port = await relayA.call<RpcStub<Port>>("mintPort", []);
    const result = await relayB.call<string>("usePort", [port, "hop2"]);
    assert.equal(result, "ok:hop2");

    relayA.close();
    relayB.close();
    serverA.close();
    serverB.close();
  });

  it("transfers Response and ReadableStream across sessions", async () => {
    const pair = createStreamPair();
    const server = createRpcSession({
      readable: pair.b.readable,
      writable: pair.b.writable,
      role: "server",
      target: {
        async echoResponse(reqBody: ReadableStream<Uint8Array>, status: number) {
          if (status === 204) {
            return new Response(null, { status: 204, headers: { "x-empty": "yes" } });
          }
          const text = await new Response(reqBody).text();
          const out = new Response(`echo:${text}`, {
            status,
            statusText: "Created",
            headers: [
              ["x-custom", "v1"],
              ["set-cookie", "a=1"],
              ["set-cookie", "b=2"],
            ],
          });
          Object.defineProperty(out, "url", {
            value: "https://example.test/out",
            configurable: true,
          });
          return out;
        },
      },
    });
    const client = createRpcSession({
      readable: pair.a.readable,
      writable: pair.a.writable,
      role: "client",
    });

    const upload = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode("hello "));
        c.enqueue(new TextEncoder().encode("stream"));
        c.close();
      },
    });
    const resp = await client.call<Response>("echoResponse", [upload, 201]);
    assert.equal(resp instanceof Response, true);
    assert.equal(resp.status, 201);
    assert.equal(resp.statusText, "Created");
    assert.equal(resp.url, "https://example.test/out");
    assert.equal(resp.headers.get("x-custom"), "v1");
    assert.deepEqual(resp.headers.getSetCookie(), ["a=1", "b=2"]);
    assert.equal(await resp.text(), "echo:hello stream");

    const emptyResp = await client.call<Response>("echoResponse", [new ReadableStream(), 204]);
    assert.equal(emptyResp.status, 204);
    assert.equal(emptyResp.headers.get("x-empty"), "yes");
    assert.equal(emptyResp.body, null);

    client.close();
    server.close();
  });
});
