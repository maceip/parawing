// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Unit tests for Deno host assets, OTLP tracer, outbound guardrails, and WS upgrades.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createFileAssetCapability } from "../src/file-assets.ts";
import { buildDenoRunArgs } from "../src/deno-isolate-loader.ts";
import { createMinimalOutbound } from "../src/minimal-outbound.ts";
import { OtlpHttpTracer } from "../src/otlp-tracer.ts";
import { acceptWebSocketUpgrade } from "../src/ws-upgrade.ts";

test("FileAssetCapability serves valid files, handles ETag 304, and blocks escapes", async () => {
  const base = mkdtempSync(join(tmpdir(), "pw-assets-test-"));
  const root = join(base, "public");
  const secret = join(base, "secret.txt");
  mkdirSync(join(root, "rbi", "fonts"), { recursive: true });
  writeFileSync(join(root, "rbi", "scene_host.json"), '{"abi":1}', "utf8");
  writeFileSync(join(root, "rbi", "fonts", "a.woff2"), Buffer.from([1, 2, 3, 4]));
  writeFileSync(secret, "top-secret", "utf8");
  symlinkSync(secret, join(root, "escape.txt"));

  try {
    const assets = createFileAssetCapability({ rootDir: root });

    const jsonRes = await assets.fetch(new Request("https://parawing.invalid/rbi/scene_host.json"));
    assert.equal(jsonRes.status, 200);
    assert.match(jsonRes.headers.get("content-type") ?? "", /application\/json/);
    assert.equal(await jsonRes.text(), '{"abi":1}');

    const etag = jsonRes.headers.get("etag");
    assert.ok(etag);
    const notMod = await assets.fetch(
      new Request("https://parawing.invalid/rbi/scene_host.json", {
        headers: { "If-None-Match": etag },
      }),
    );
    assert.equal(notMod.status, 304);

    const headRes = await assets.fetch(
      new Request("https://parawing.invalid/rbi/fonts/a.woff2", { method: "HEAD" }),
    );
    assert.equal(headRes.status, 200);
    assert.equal(headRes.headers.get("content-length"), "4");
    assert.equal((await headRes.arrayBuffer()).byteLength, 0);

    const normTrav = await assets.fetch(new Request("https://parawing.invalid/%2e%2e/secret.txt"));
    assert.equal(normTrav.status, 404);

    const encodedTrav = await assets.fetch(new Request("https://parawing.invalid/..%2fsecret.txt"));
    assert.equal(encodedTrav.status, 403);

    const symRes = await assets.fetch(new Request("https://parawing.invalid/escape.txt"));
    assert.equal(symRes.status, 403);

    const methodRes = await assets.fetch(
      new Request("https://parawing.invalid/rbi/scene_host.json", { method: "POST" }),
    );
    assert.equal(methodRes.status, 405);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("OtlpHttpTracer exports nested spans to OTLP/HTTP endpoint", async () => {
  const receivedBodies: string[] = [];
  const collector = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      receivedBodies.push(Buffer.concat(chunks).toString("utf8"));
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });

  await new Promise<void>((resolve) => collector.listen(0, "127.0.0.1", () => resolve()));
  const addr = collector.address();
  assert.ok(typeof addr === "object" && addr !== null);

  try {
    const tracer = new OtlpHttpTracer({
      endpoint: `http://127.0.0.1:${addr.port}/v1/traces`,
      serviceName: "parawing-test",
    });

    await tracer.enterSpan("outer.op", async (parent) => {
      parent.setTags({ kind: "unit" });
      parent.addLogs({ step: 1 });
      const outerCtx = tracer.getSpanContext();
      assert.ok(outerCtx);
      await tracer.enterSpan("inner.op", async (child) => {
        child.setTags({ ok: true, nested: "yes" });
        const innerCtx = tracer.getSpanContext();
        assert.equal(innerCtx?.traceId, outerCtx.traceId);
        assert.equal(innerCtx?.parentSpanId, outerCtx.spanId);
      });
    });

    await tracer.flush();
    assert.equal(receivedBodies.length, 1);

    const payload = JSON.parse(receivedBodies[0] ?? "{}") as {
      resourceSpans: Array<{
        scopeSpans: Array<{
          spans: Array<{
            traceId: string;
            spanId: string;
            parentSpanId: string;
            name: string;
          }>;
        }>;
      }>;
    };

    const spans = payload.resourceSpans[0]?.scopeSpans[0]?.spans ?? [];
    assert.equal(spans.length, 2);
    const inner = spans.find((s) => s.name === "inner.op");
    const outer = spans.find((s) => s.name === "outer.op");
    assert.ok(inner && outer);
    assert.equal(inner.traceId, outer.traceId);
    assert.equal(inner.parentSpanId, outer.spanId);
    assert.equal(outer.parentSpanId, "");
  } finally {
    collector.closeAllConnections();
    await new Promise<void>((resolve) => collector.close(() => resolve()));
  }
});

test("minimal-outbound enforces scheme, private-network blocking, DNS check, and deadlines", async () => {
  const origin = createServer((req, res) => {
    if (req.url === "/slow") {
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200);
          res.end("late");
        }
      }, 400);
      return;
    }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("origin-ok");
  });

  await new Promise<void>((resolve) => origin.listen(0, "127.0.0.1", () => resolve()));
  const addr = origin.address();
  assert.ok(typeof addr === "object" && addr !== null);

  try {
    const strict = createMinimalOutbound({
      allowPrivateNetwork: false,
      lookupFn: async () => [{ address: "10.20.30.40", family: 4 }],
    });

    const literalBlock = await strict.fetch(new Request(`http://127.0.0.1:${addr.port}/`));
    assert.equal(literalBlock.status, 403);
    assert.equal(literalBlock.headers.get("x-parawing-blocked"), "private-network");

    const localhostBlock = await strict.fetch(new Request(`http://localhost:${addr.port}/`));
    assert.equal(localhostBlock.status, 403);

    const dnsBlock = await strict.fetch(new Request("https://rebind.example.com/"));
    assert.equal(dnsBlock.status, 403);
    assert.match(await dnsBlock.text(), /10\.20\.30\.40/);

    const schemeBlock = await strict.fetch(new Request("file:///etc/passwd"));
    assert.equal(schemeBlock.status, 403);
    assert.equal(schemeBlock.headers.get("x-parawing-blocked"), "unsupported-scheme");

    const permissive = createMinimalOutbound({
      allowPrivateNetwork: true,
      deadlineMs: 60,
    });

    const okRes = await permissive.fetch(new Request(`http://127.0.0.1:${addr.port}/ok`));
    assert.equal(okRes.status, 200);
    assert.equal(await okRes.text(), "origin-ok");

    await assert.rejects(() => permissive.fetch(new Request(`http://127.0.0.1:${addr.port}/slow`)));
  } finally {
    origin.closeAllConnections();
    await new Promise<void>((resolve) => origin.close(() => resolve()));
  }
});

function buildMaskedWsFrame(fin: boolean, opcode: number, payload: Buffer): Buffer {
  const mask = Buffer.from([0x12, 0x34, 0x56, 0x78]);
  const len = payload.length;
  const header =
    len < 126
      ? Buffer.from([(fin ? 0x80 : 0) | opcode, 0x80 | len])
      : Buffer.from([(fin ? 0x80 : 0) | opcode, 0x80 | 126, (len >> 8) & 0xff, len & 0xff]);
  const masked = Buffer.allocUnsafe(len);
  for (let i = 0; i < len; i++) {
    masked[i] = (payload[i] ?? 0) ^ (mask[i & 3] ?? 0);
  }
  return Buffer.concat([header, mask, masked]);
}

function readServerWsFrame(
  buf: Buffer,
): { opcode: number; payload: Buffer; consumed: number } | null {
  if (buf.length < 2) return null;
  const opcode = (buf[0] ?? 0) & 0x0f;
  const len7 = (buf[1] ?? 0) & 0x7f;
  let offset = 2;
  let len = len7;
  if (len7 === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    offset = 4;
  } else if (len7 === 127) {
    if (buf.length < 10) return null;
    len = Number(buf.readBigUInt64BE(2));
    offset = 10;
  }
  if (buf.length < offset + len) return null;
  return { opcode, payload: buf.subarray(offset, offset + len), consumed: offset + len };
}

test("ws-upgrade handles fragmented frames, ping/pong, and >64KB echo", async () => {
  const received: string[] = [];
  const server = createServer();
  const cleanups: Array<() => void> = [];
  server.on("upgrade", (req, socket, head) => {
    const transport = acceptWebSocketUpgrade(req, socket, head);
    assert.ok(transport);
    cleanups.push(() => transport.close());
    transport.onMessage((msg) => {
      if (typeof msg === "string") {
        received.push(msg);
        transport.send(`echo:${msg.length}`);
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  assert.ok(typeof addr === "object" && addr !== null);

  try {
    const sock = createConnection(addr.port, "127.0.0.1");
    await new Promise<void>((resolve) => sock.once("connect", () => resolve()));

    const key = Buffer.from("0123456789abcdef").toString("base64");
    const expectedAccept = createHash("sha1")
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");

    sock.write(
      `GET /devtools/browser HTTP/1.1\r\nHost: 127.0.0.1:${addr.port}\r\n` +
        `Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\n` +
        "Sec-WebSocket-Version: 13\r\n\r\n",
    );

    let rawBuf: Buffer = Buffer.alloc(0);
    let handshakeDone = false;
    const frames: Array<{ opcode: number; text: string }> = [];

    const waitFrames = new Promise<void>((resolve) => {
      sock.on("data", (chunk: Buffer) => {
        rawBuf = Buffer.concat([rawBuf, chunk]);
        if (!handshakeDone) {
          const end = rawBuf.indexOf("\r\n\r\n");
          if (end < 0) return;
          const hdrText = rawBuf.subarray(0, end).toString("latin1");
          assert.match(hdrText, /101 Switching Protocols/);
          assert.ok(hdrText.includes(expectedAccept));
          rawBuf = rawBuf.subarray(end + 4);
          handshakeDone = true;
        }
        while (true) {
          const f = readServerWsFrame(rawBuf);
          if (!f) break;
          rawBuf = rawBuf.subarray(f.consumed);
          frames.push({ opcode: f.opcode, text: f.payload.toString("utf8") });
          if (frames.length >= 2) resolve();
        }
      });
    });

    const largeHalf = Buffer.from("A".repeat(40_000));
    sock.write(buildMaskedWsFrame(false, 0x1, largeHalf));
    sock.write(buildMaskedWsFrame(true, 0x9, Buffer.from("ping-hi")));
    sock.write(buildMaskedWsFrame(true, 0x0, Buffer.from("B".repeat(30_000))));

    await waitFrames;
    const pong = frames.find((f) => f.opcode === 0x0a);
    const echo = frames.find((f) => f.opcode === 0x01);
    assert.equal(pong?.text, "ping-hi");
    assert.equal(echo?.text, "echo:70000");
    assert.equal(received[0]?.length, 70_000);

    sock.destroy();
  } finally {
    for (const cleanup of cleanups) cleanup();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("buildDenoRunArgs passes zero --allow-* flags and enforces --disallow-code-generation-from-strings", () => {
  const defaultArgs = buildDenoRunArgs();
  assert.equal(
    defaultArgs.some((a) => a.startsWith("--allow-")),
    false,
  );
  assert.ok(defaultArgs.includes("--no-code-cache"));
  assert.ok(defaultArgs.includes("--v8-flags=--disallow-code-generation-from-strings"));

  const cappedArgs = buildDenoRunArgs(256);
  assert.equal(
    cappedArgs.some((a) => a.startsWith("--allow-")),
    false,
  );
  assert.ok(
    cappedArgs.includes(
      "--v8-flags=--disallow-code-generation-from-strings,--max-old-space-size=256",
    ),
  );
});
