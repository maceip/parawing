#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Mandatory release gate: extracts the release archive into an isolated temp directory outside
// the repository, executes both `parawing-rust-host` and `parawing` CLI against real HTML/CSS,
// Deno V8 JS eval, PNG screenshot rendering, KSC2 scene frames, and capsule attestation checks.

import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { inflateSync } from "node:zlib";

const execFileAsync = promisify(execFile);
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const KSV2_MAGIC = Buffer.from([0x4b, 0x56, 0x32, 0x01]);
const KSC2_MAGIC = Buffer.from([0x4b, 0x53, 0x43, 0x32]);

function paethPredictor(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

/** Decodes an 8-bit PNG buffer into pixel stats using zero external deps.
 * @param {Buffer} pngBuf
 * @returns {{ width: number, height: number, redHeroPixels: number,
 *   slateBgPixels: number }} */
export function decodeAndSamplePng(pngBuf) {
  assert.ok(pngBuf.length >= 33, `PNG too small: ${pngBuf.length} bytes`);
  assert.deepEqual(pngBuf.subarray(0, 8), PNG_MAGIC, "invalid PNG magic signature");

  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  const idatChunks = [];

  while (offset + 8 <= pngBuf.length) {
    const length = pngBuf.readUInt32BE(offset);
    const type = pngBuf.subarray(offset + 4, offset + 8).toString("ascii");
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    assert.ok(dataEnd + 4 <= pngBuf.length, `truncated PNG chunk ${type}`);
    const data = pngBuf.subarray(dataStart, dataEnd);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
    } else if (type === "IDAT") {
      idatChunks.push(data);
    } else if (type === "IEND") {
      break;
    }
    offset = dataEnd + 4;
  }

  assert.ok(width > 0 && height > 0, `invalid PNG dimensions ${width}x${height}`);
  assert.equal(bitDepth, 8, `unsupported PNG bit depth: ${bitDepth}`);
  const bpp = colorType === 6 ? 4 : colorType === 2 ? 3 : colorType === 4 ? 2 : 1;
  const stride = width * bpp;
  const raw = inflateSync(Buffer.concat(idatChunks));
  assert.equal(raw.length, height * (1 + stride), "unexpected decompressed PNG byte length");

  let redHeroPixels = 0;
  let slateBgPixels = 0;
  let prior = Buffer.alloc(stride);

  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (1 + stride);
    const filter = raw[rowStart];
    const row = Buffer.allocUnsafe(stride);
    for (let x = 0; x < stride; x += 1) {
      const val = raw[rowStart + 1 + x];
      const a = x >= bpp ? row[x - bpp] : 0;
      const b = prior[x];
      const c = x >= bpp ? prior[x - bpp] : 0;
      if (filter === 0) row[x] = val;
      else if (filter === 1) row[x] = (val + a) & 0xff;
      else if (filter === 2) row[x] = (val + b) & 0xff;
      else if (filter === 3) row[x] = (val + ((a + b) >> 1)) & 0xff;
      else if (filter === 4) row[x] = (val + paethPredictor(a, b, c)) & 0xff;
      else throw new Error(`unsupported PNG filter type ${filter}`);
    }
    for (let px = 0; px < width; px += 1) {
      const idx = px * bpp;
      const r = row[idx];
      const g = bpp >= 3 ? row[idx + 1] : r;
      const b = bpp >= 3 ? row[idx + 2] : r;
      if (r >= 200 && g <= 90 && b <= 90) redHeroPixels += 1;
      if (r <= 35 && g >= 15 && g <= 50 && b >= 30 && b <= 75) slateBgPixels += 1;
    }
    prior = row;
  }

  return { width, height, redHeroPixels, slateBgPixels };
}

/** Validates a `KV2\x01` server binary frame carrying an embedded `KSC2` scene.
 * @param {Buffer} packet
 * @returns {{ frameSeq: number, baseSeq: number, tileCount: number, payloadLen: number }} */
export function parseKsv2ReliableFrame(packet) {
  assert.ok(packet.length >= 25, `KSV2 packet too short: ${packet.length}`);
  assert.deepEqual(packet.subarray(0, 4), KSV2_MAGIC, "missing KV2\\x01 magic");
  const kind = packet[4];
  assert.equal(kind, 1, `expected ReliableFrame kind=1, got ${kind}`);
  const frameSeq = packet.readUInt32LE(5);
  const baseSeq = packet.readUInt32LE(9);
  const tileCount = packet.readUInt32LE(13);
  const payloadLen = packet.readUInt32LE(17);
  assert.equal(packet.length, 21 + payloadLen, "truncated KSV2 payload");
  const ksc2 = packet.subarray(21);
  assert.deepEqual(ksc2.subarray(0, 4), KSC2_MAGIC, "missing KSC2 scene magic");
  return { frameSeq, baseSeq, tileCount, payloadLen };
}

function buildKsv2CreditGrant(credits, ackedFrameSeq) {
  const buf = Buffer.alloc(13);
  KSV2_MAGIC.copy(buf, 0);
  buf[4] = 2;
  buf.writeUInt32LE(credits, 5);
  buf.writeUInt32LE(ackedFrameSeq, 9);
  return buf;
}

function findDenoBinary() {
  const fromEnv = process.env.PARAWING_DENO_BIN?.trim();
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const candidates = [
    join(homedir(), ".deno/bin/deno"),
    "/usr/local/bin/deno",
    "/opt/homebrew/bin/deno",
    "/usr/bin/deno",
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  try {
    const resolved = execFileSync("which", ["deno"], { encoding: "utf8" }).trim();
    if (resolved && existsSync(resolved)) return resolved;
  } catch {
    // Fall back to default lookup error below.
  }
  throw new Error("Deno binary not found (install Deno 2.x or set PARAWING_DENO_BIN)");
}

function reserveFreePort() {
  return new Promise((resolvePromise, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      server.close((err) => (err ? reject(err) : resolvePromise(port)));
    });
  });
}

async function waitForHostReady(baseUrl, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) return await res.text();
    } catch {
      // Retry until ready or deadline expires.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Timed out waiting for parawing-rust-host at ${baseUrl}/health`);
}

function connectWebSocket(url) {
  return new Promise((resolvePromise, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    const onOpen = () => {
      cleanup();
      resolvePromise(ws);
    };
    const onError = (ev) => {
      cleanup();
      reject(new Error(`WebSocket connection failed to ${url}: ${ev?.message ?? "error"}`));
    };
    const cleanup = () => {
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onError);
    };
    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onError);
  });
}

function cdpRpc(ws, id, method, params = {}, timeoutMs = 15_000) {
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      ws.removeEventListener("message", onMessage);
      reject(new Error(`CDP timeout calling ${method} (id=${id})`));
    }, timeoutMs);
    const onMessage = (ev) => {
      if (typeof ev.data !== "string") return;
      const msg = JSON.parse(ev.data);
      if (msg.id !== id) return;
      clearTimeout(timer);
      ws.removeEventListener("message", onMessage);
      if (msg.error) {
        reject(new Error(`CDP error ${method}: ${JSON.stringify(msg.error)}`));
      } else {
        resolvePromise(msg.result);
      }
    };
    ws.addEventListener("message", onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function toBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (data && typeof data.arrayBuffer === "function") {
    return Buffer.from(await data.arrayBuffer());
  }
  throw new Error(`Unexpected binary message payload: ${typeof data}`);
}

function awaitNextBinaryPacket(ws, predicate, timeoutMs = 15_000) {
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      ws.removeEventListener("message", onMessage);
      reject(new Error("Timed out waiting for matching KV2 binary packet"));
    }, timeoutMs);
    const onMessage = async (ev) => {
      if (typeof ev.data === "string") return;
      try {
        const buf = await toBuffer(ev.data);
        if (predicate(buf)) {
          clearTimeout(timer);
          ws.removeEventListener("message", onMessage);
          resolvePromise(buf);
        }
      } catch (err) {
        clearTimeout(timer);
        ws.removeEventListener("message", onMessage);
        reject(err);
      }
    };
    ws.addEventListener("message", onMessage);
  });
}

/** Verifies a staged directory or tarball of `parawing-rust-host`, `parawing`, and `rbi/`.
 * @param {{ archivePath?: string, stagedDir?: string, expectedVersion: string }} opts
 * @returns {Promise<{ expectedVersion: string, capsuleHash: string, png: Record<string, number>,
 *   ksv2Frame: Record<string, number>, cliFrames: number, cliWireBytes: number }>} */
export async function verifyReleaseBinaries({ archivePath, stagedDir, expectedVersion }) {
  const workDir = mkdtempSync(join(tmpdir(), "parawing-verify-"));
  let extractDir = stagedDir ? resolve(stagedDir) : workDir;
  let hostProc = null;
  let fixtureServer = null;
  const hostLogs = [];

  try {
    if (archivePath) {
      extractDir = join(workDir, "extracted");
      mkdirSync(extractDir, { recursive: true });
      execFileSync("tar", ["-xzf", resolve(archivePath), "-C", extractDir], { stdio: "inherit" });
    }

    const hostBin = join(extractDir, "parawing-rust-host");
    const cliBin = join(extractDir, "parawing");
    assert.ok(existsSync(hostBin), `Missing parawing-rust-host binary in ${extractDir}`);
    assert.ok(existsSync(cliBin), `Missing parawing CLI binary in ${extractDir}`);
    assert.ok(existsSync(join(extractDir, "rbi/scene_host.wasm")), "Missing rbi/scene_host.wasm");
    assert.ok(existsSync(join(extractDir, "rbi/scene_host.json")), "Missing rbi/scene_host.json");

    // 1. Verify embedded versions outside repository working tree.
    const { stdout: hostVerOut } = await execFileAsync(hostBin, ["--version"], {
      cwd: workDir,
      encoding: "utf8",
    });
    assert.equal(hostVerOut.trim(), `parawing-rust-host ${expectedVersion}`);

    const { stdout: cliVerOut } = await execFileAsync(cliBin, ["--version"], {
      cwd: workDir,
      encoding: "utf8",
    });
    assert.equal(cliVerOut.trim(), `parawing ${expectedVersion}`);

    // 2. Start ephemeral HTTP fixture server serving styled HTML.
    const htmlFixture = `<!DOCTYPE html><html><head><title>Parawing Gate</title></head>
<body style="margin:0;background:#0f172a">
  <div id="hero" style="width:240px;height:140px;background:#ef4444;color:#ffffff">initial</div>
</body></html>`;
    fixtureServer = http.createServer((req, res) => {
      if (req.url === "/gate") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(htmlFixture);
        return;
      }
      res.writeHead(404);
      res.end("not found");
    });
    await new Promise((r) => fixtureServer.listen(0, "127.0.0.1", r));
    const fixtureAddr = fixtureServer.address();
    const fixtureUrl = `http://127.0.0.1:${fixtureAddr.port}/gate`;

    // 3. Boot extracted `parawing-rust-host` in an isolated HOME with Deno configured.
    const denoBin = findDenoBinary();
    const hostPort = await reserveFreePort();
    const isolatedHome = join(workDir, "home");
    mkdirSync(isolatedHome, { recursive: true });
    const hostEnv = {
      ...process.env,
      HOME: isolatedHome,
      XDG_CACHE_HOME: join(isolatedHome, ".cache"),
      PARAWING_DENO_BIN: denoBin,
    };
    hostProc = spawn(hostBin, ["--host", "127.0.0.1", "--port", String(hostPort)], {
      cwd: extractDir,
      env: hostEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });
    hostProc.stdout.on("data", (d) => hostLogs.push(d.toString()));
    hostProc.stderr.on("data", (d) => hostLogs.push(d.toString()));

    const hostOrigin = `http://127.0.0.1:${hostPort}`;
    const healthText = await waitForHostReady(hostOrigin);
    assert.match(healthText, /parawing-rust-host: OK/);

    const versionJson = await (await fetch(`${hostOrigin}/json/version`)).json();
    assert.equal(versionJson.Browser, `Parawing-Rust-Host/${expectedVersion}`);

    const manifestJson = await (await fetch(`${hostOrigin}/capsule/manifest`)).json();
    assert.match(manifestJson.capsuleHash, /^[a-f0-9]{64}$/);

    // 4. Exercise CDP nav, Deno V8 eval, Blitz PNG render, KSC2 stream, attestation.
    const cdpWs = await connectWebSocket(`ws://127.0.0.1:${hostPort}/devtools/page/verify-gate`);
    const viewerWs = await connectWebSocket(`ws://127.0.0.1:${hostPort}/viewer/verify-gate`);
    const framePromise = awaitNextBinaryPacket(viewerWs, (buf) => {
      if (buf.length < 25 || buf[4] !== 1) return false;
      const frame = parseKsv2ReliableFrame(buf);
      return frame.tileCount >= 1 && frame.frameSeq >= 2;
    });
    viewerWs.send(buildKsv2CreditGrant(8, 0));

    try {
      const nav = await cdpRpc(cdpWs, 1, "Page.navigate", { url: fixtureUrl });
      assert.equal(nav.url, fixtureUrl);

      const evalRes = await cdpRpc(cdpWs, 2, "Runtime.evaluate", {
        expression: `(() => {
          document.getElementById('hero').textContent = 'verified-42';
          __state.visited = 42;
          let sum = 0;
          for (let i = 1; i <= 100; i++) sum += i;
          return { visited: __state.visited, sum };
        })()`,
      });
      assert.deepEqual(evalRes.result.value.value, { visited: 42, sum: 5050 });

      const doc = await cdpRpc(cdpWs, 3, "DOM.getDocument", {});
      assert.ok(doc.root.outerHTML.includes("verified-42"), "DOM mutation did not propagate");

      const shot = await cdpRpc(cdpWs, 4, "Page.captureScreenshot", {});
      const pngStats = decodeAndSamplePng(Buffer.from(shot.data, "base64"));
      assert.ok(pngStats.width >= 320 && pngStats.height >= 240);
      assert.ok(
        pngStats.redHeroPixels >= 1000,
        `expected >= 1000 #ef4444 pixels, got ${pngStats.redHeroPixels}`,
      );
      assert.ok(
        pngStats.slateBgPixels >= 1000,
        `expected >= 1000 #0f172a pixels, got ${pngStats.slateBgPixels}`,
      );

      const framePacket = await framePromise;
      const ksv2Frame = parseKsv2ReliableFrame(framePacket);

      const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const spkiB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
      const attestation = await cdpRpc(cdpWs, 5, "Parawing.signCapsuleAttestation", {
        ephemeralP256PubkeySpkiB64: spkiB64,
        nonce: randomBytes(16).toString("hex"),
      });
      assert.ok(
        typeof attestation.signatureB64 === "string" && attestation.signatureB64.length > 0,
      );
      const lease = await cdpRpc(cdpWs, 6, "Parawing.issueAttestedKeyLease", {
        attestation,
        leaseId: "release-gate-lease",
        sessionId: "release-gate-session",
      });
      assert.equal(lease.leaseId, "release-gate-lease");

      // 5. Execute the extracted `parawing` CLI against the live local `parawing-rust-host`.
      const cliRun = await execFileAsync(
        cliBin,
        ["--v2", "--no-display", "--debug", "--seconds", "2", fixtureUrl],
        {
          cwd: workDir,
          env: { ...hostEnv, PARAWING_SERVER: hostOrigin },
          encoding: "utf8",
          timeout: 30_000,
        },
      );
      assert.match(cliRun.stderr, /manifest: ABI 4/);
      assert.match(cliRun.stderr, /connected S7 \/rbi\/ws stream/);
      const statsMatch = /parawing-v2: frames=(\d+) wire_bytes=(\d+) width=(\d+) height=(\d+)/.exec(
        cliRun.stdout,
      );
      assert.ok(statsMatch, `missing CLI v2 measurement line; stdout was:\n${cliRun.stdout}`);
      const cliFrames = Number(statsMatch[1]);
      const cliWireBytes = Number(statsMatch[2]);
      assert.ok(cliFrames >= 1, `expected >= 1 composited CLI frame, got ${cliFrames}`);
      assert.ok(cliWireBytes > 0, `expected > 0 CLI wire bytes, got ${cliWireBytes}`);

      return {
        expectedVersion,
        capsuleHash: manifestJson.capsuleHash,
        png: pngStats,
        ksv2Frame,
        cliFrames,
        cliWireBytes,
      };
    } finally {
      cdpWs.close();
      viewerWs.close();
    }
  } catch (err) {
    if (hostLogs.length > 0) {
      console.error("--- parawing-rust-host logs ---\n" + hostLogs.join(""));
    }
    throw err;
  } finally {
    if (hostProc && hostProc.exitCode === null) {
      hostProc.kill("SIGTERM");
      await new Promise((r) => setTimeout(r, 200));
      if (hostProc.exitCode === null) hostProc.kill("SIGKILL");
    }
    if (fixtureServer) {
      await new Promise((r) => fixtureServer.close(() => r()));
    }
    rmSync(workDir, { recursive: true, force: true, maxRetries: 5 });
  }
}

function parseArgs(argv) {
  let archivePath = "";
  let stagedDir = "";
  let expectedVersion = "";
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--archive") archivePath = argv[++i] ?? "";
    else if (arg === "--dir") stagedDir = argv[++i] ?? "";
    else if (arg === "--expected-version") expectedVersion = argv[++i] ?? "";
    else throw new Error(`Unknown option: ${arg}`);
  }
  if ((!archivePath && !stagedDir) || !expectedVersion) {
    throw new Error(
      "Usage: verify-release-binaries.mjs (--archive <tar.gz> | --dir <dir>) --expected-version <X.Y.Z>",
    );
  }
  return { archivePath, stagedDir, expectedVersion };
}

async function main(argv) {
  const opts = parseArgs(argv);
  const summary = await verifyReleaseBinaries(opts);
  console.log(JSON.stringify(summary));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
