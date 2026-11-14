// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { deflateSync } from "node:zlib";

import { decodeAndSamplePng, parseKsv2ReliableFrame } from "./verify-release-binaries.mjs";

function makeChunk(type, data) {
  const buf = Buffer.alloc(12 + data.length);
  buf.writeUInt32BE(data.length, 0);
  buf.write(type, 4, "ascii");
  data.copy(buf, 8);
  return buf;
}

function buildSyntheticPng(width, height, pixelFn) {
  const stride = 1 + width * 4;
  const raw = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y += 1) {
    const rowOff = y * stride;
    raw[rowOff] = y % 2 === 0 ? 0 : 1; // Exercise None (0) and Sub (1) PNG filters.
    for (let x = 0; x < width; x += 1) {
      const [r, g, b, a] = pixelFn(x, y);
      const pxOff = rowOff + 1 + x * 4;
      if (raw[rowOff] === 0) {
        raw[pxOff] = r;
        raw[pxOff + 1] = g;
        raw[pxOff + 2] = b;
        raw[pxOff + 3] = a;
      } else {
        const [pr, pg, pb, pa] = x === 0 ? [0, 0, 0, 0] : pixelFn(x - 1, y);
        raw[pxOff] = (r - pr) & 0xff;
        raw[pxOff + 1] = (g - pg) & 0xff;
        raw[pxOff + 2] = (b - pb) & 0xff;
        raw[pxOff + 3] = (a - pa) & 0xff;
      }
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    makeChunk("IHDR", ihdr),
    makeChunk("IDAT", deflateSync(raw)),
    makeChunk("IEND", Buffer.alloc(0)),
  ]);
}

test("decodeAndSamplePng unfilters PNG scanlines and counts red/slate regions", () => {
  const png = buildSyntheticPng(100, 80, (x, y) =>
    x < 50 && y < 40 ? [239, 68, 68, 255] : [15, 23, 42, 255],
  );
  const stats = decodeAndSamplePng(png);
  assert.equal(stats.width, 100);
  assert.equal(stats.height, 80);
  assert.equal(stats.redHeroPixels, 50 * 40);
  assert.equal(stats.slateBgPixels, 100 * 80 - 50 * 40);
});

test("parseKsv2ReliableFrame validates KV2\\x01 header and embedded KSC2 payload", () => {
  const ksc2 = Buffer.from([0x4b, 0x53, 0x43, 0x32, 0x00, 0x01, 0x02, 0x03]);
  const pkt = Buffer.alloc(21 + ksc2.length);
  pkt.set([0x4b, 0x56, 0x32, 0x01], 0);
  pkt[4] = 1;
  pkt.writeUInt32LE(3, 5);
  pkt.writeUInt32LE(2, 9);
  pkt.writeUInt32LE(4, 13);
  pkt.writeUInt32LE(ksc2.length, 17);
  ksc2.copy(pkt, 21);

  const parsed = parseKsv2ReliableFrame(pkt);
  assert.deepEqual(parsed, { frameSeq: 3, baseSeq: 2, tileCount: 4, payloadLen: 8 });
});
