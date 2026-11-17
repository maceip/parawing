// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Guest Node.js client executed inside Vivari's in-browser Node VM.
// Instantiates Parawing's `scene_host.wasm` client compositor (`CompositorV2`) in-guest
// and connects over Vivari's Wisp `netRelay` (`host.vivari.internal:8788`) to the
// remote `parawing-rust-host` server running on DigitalOcean.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import readline from "node:readline";

const HOST = process.env.PARAWING_HOST || "host.vivari.internal";
const PORT = Number(process.env.PARAWING_PORT || "8788");
const TARGET_ID = process.env.PARAWING_TARGET_ID || "vivari-co-browser";

const OP_V2_INGEST_FRAME = 20;
const OP_V2_COMPOSITE = 21;
const OP_V2_HIT_TEST = 24;
const KSV2_MAGIC = Buffer.from([0x4b, 0x56, 0x32, 0x01]);
const KSC2_MAGIC = Buffer.from([0x4b, 0x53, 0x43, 0x32]);

function emit(type, payload = {}) {
  process.stdout.write(`__PARAWING_EVT__${JSON.stringify({ type, ...payload })}\n`);
}

function httpGetJson(path) {
  return new Promise((resolvePromise, reject) => {
    const socket = net.connect({ host: HOST, port: PORT });
    const chunks = [];
    const timer = setTimeout(() => {
      socket.destroy(new Error(`HTTP timeout on ${path}`));
    }, 10_000);
    socket.once("connect", () => {
      socket.write(`GET ${path} HTTP/1.0\r\nHost: ${HOST}:${PORT}\r\nConnection: close\r\n\r\n`);
    });
    socket.on("data", (c) => chunks.push(c));
    socket.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.once("close", () => {
      clearTimeout(timer);
      const rawBuf = Buffer.concat(chunks);
      const sep = rawBuf.indexOf("\r\n\r\n");
      if (sep === -1) {
        reject(new Error(`Malformed HTTP response on ${path}`));
        return;
      }
      const head = rawBuf.subarray(0, sep).toString("latin1");
      const body = rawBuf.subarray(sep + 4).toString("utf8");
      if (!head.startsWith("HTTP/1.1 200") && !head.startsWith("HTTP/1.0 200")) {
        reject(new Error(`HTTP error on ${path}: ${head.split("\r\n")[0]}`));
        return;
      }
      try {
        resolvePromise(path === "/health" ? { text: body.trim() } : JSON.parse(body));
      } catch (err) {
        reject(err);
      }
    });
  });
}

// Minimal RFC 6455 client over `node:net` so Vivari's in-browser Node VM dials
// `host.vivari.internal:8788` through the Wisp relay with zero external npm packages.
class NetWebSocket {
  constructor(socket, onText, onBinary, onClose) {
    this.socket = socket;
    this.onText = onText;
    this.onBinary = onBinary;
    this.onClose = onClose;
    this.buf = Buffer.alloc(0);
    this.frags = [];
    this.fragOpcode = 0;
    socket.on("data", (chunk) => this.#drain(chunk));
    socket.on("close", () => this.onClose?.());
    socket.on("error", (err) =>
      emit("log", { level: "error", message: `ws socket: ${err.message}` }),
    );
  }

  /** @param {string} host @param {number} port @param {string} path @returns {Promise<NetWebSocket>} */
  static connect(host, port, path) {
    return new Promise((resolvePromise, reject) => {
      const socket = net.connect({ host, port });
      const key = crypto.randomBytes(16).toString("base64");
      let headBuf = Buffer.alloc(0);
      let upgraded = false;

      const onData = (chunk) => {
        headBuf = Buffer.concat([headBuf, chunk]);
        const end = headBuf.indexOf("\r\n\r\n");
        if (end === -1) return;
        socket.off("data", onData);
        const headerStr = headBuf.subarray(0, end).toString("latin1");
        if (!headerStr.startsWith("HTTP/1.1 101")) {
          socket.destroy();
          reject(new Error(`WebSocket upgrade rejected on ${path}: ${headerStr.split("\r\n")[0]}`));
          return;
        }
        upgraded = true;
        const remainder = headBuf.subarray(end + 4);
        const handlers = { text: null, bin: null, close: null };
        const client = new NetWebSocket(
          socket,
          (t) => handlers.text?.(t),
          (b) => handlers.bin?.(b),
          () => handlers.close?.(),
        );
        client.handlers = handlers;
        if (remainder.length > 0) client.#drain(remainder);
        resolvePromise(client);
      };

      socket.once("connect", () => {
        socket.write(
          `GET ${path} HTTP/1.1\r\n` +
            `Host: ${host}:${port}\r\n` +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Key: ${key}\r\n` +
            "Sec-WebSocket-Version: 13\r\n\r\n",
        );
      });
      socket.on("data", onData);
      socket.once("error", (err) => {
        if (!upgraded) reject(err);
      });
    });
  }

  /** @param {string} str @returns {void} */
  sendText(str) {
    this.#sendFrame(0x1, Buffer.from(str, "utf8"));
  }

  /** @param {Buffer} buf @returns {void} */
  sendBinary(buf) {
    this.#sendFrame(0x2, buf);
  }

  /** @returns {void} */
  close() {
    try {
      this.#sendFrame(0x8, Buffer.alloc(0));
      this.socket.end();
    } catch {}
  }

  #sendFrame(opcode, payload) {
    const mask = crypto.randomBytes(4);
    const len = payload.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(6);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | len;
      mask.copy(header, 2);
    } else if (len < 65536) {
      header = Buffer.alloc(8);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
      mask.copy(header, 4);
    } else {
      header = Buffer.alloc(14);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(len), 2);
      mask.copy(header, 10);
    }
    const masked = Buffer.allocUnsafe(len);
    for (let i = 0; i < len; i += 1) {
      masked[i] = payload[i] ^ mask[i & 3];
    }
    this.socket.write(Buffer.concat([header, masked]));
  }

  #drain(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    while (this.buf.length >= 2) {
      const b0 = this.buf[0];
      const b1 = this.buf[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const isMasked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let offset = 2;
      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        len = Number(this.buf.readBigUInt64BE(2));
        offset = 10;
      }
      const maskLen = isMasked ? 4 : 0;
      if (this.buf.length < offset + maskLen + len) return;
      const payload = Buffer.from(this.buf.subarray(offset + maskLen, offset + maskLen + len));
      if (isMasked) {
        const mask = this.buf.subarray(offset, offset + 4);
        for (let i = 0; i < len; i += 1) payload[i] ^= mask[i & 3];
      }
      this.buf = this.buf.subarray(offset + maskLen + len);

      if (opcode === 0x9) {
        this.#sendFrame(0xa, payload);
        continue;
      }
      if (opcode === 0x8) {
        this.socket.end();
        return;
      }
      if (opcode === 0x0) {
        this.frags.push(payload);
        if (fin) {
          const full = Buffer.concat(this.frags);
          this.frags = [];
          if (this.fragOpcode === 0x1) this.onText?.(full.toString("utf8"));
          else if (this.fragOpcode === 0x2) this.onBinary?.(full);
        }
        continue;
      }
      if (!fin) {
        this.fragOpcode = opcode;
        this.frags = [payload];
        continue;
      }
      if (opcode === 0x1) this.onText?.(payload.toString("utf8"));
      else if (opcode === 0x2) this.onBinary?.(payload);
    }
  }
}

class SceneHostClientWasm {
  constructor(exports) {
    this.exports = exports;
  }

  /** @param {string} wasmPath @returns {Promise<{wasm: SceneHostClientWasm, sha256: string, byteLength: number}>} */
  static async load(wasmPath) {
    const bytes = fs.readFileSync(wasmPath);
    const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
    const { instance } = await WebAssembly.instantiate(bytes, {});
    return { wasm: new SceneHostClientWasm(instance.exports), sha256, byteLength: bytes.length };
  }

  /** @param {number} op @param {Buffer} inputBuf @returns {Buffer} */
  call(op, inputBuf) {
    const { ks_alloc, ks_free, ks_call, memory } = this.exports;
    const inLen = inputBuf.length;
    const inPtr = inLen > 0 ? ks_alloc(inLen) >>> 0 : 0;
    if (inLen > 0) {
      new Uint8Array(memory.buffer, inPtr, inLen).set(inputBuf);
    }
    let packed;
    try {
      packed = BigInt(ks_call(op, inPtr, inLen));
    } finally {
      if (inLen > 0) ks_free(inPtr, inLen);
    }
    const outPtr = Number(packed & 0xffffffffn) >>> 0;
    const outLen = Number((packed >> 32n) & 0xffffffffn) >>> 0;
    if (outLen === 0) return Buffer.alloc(0);
    try {
      return Buffer.from(new Uint8Array(memory.buffer, outPtr, outLen));
    } finally {
      ks_free(outPtr, outLen);
    }
  }

  /** @param {Buffer} ksc2Payload @returns {{png: Buffer, width: number, height: number, tilesCached: number, tilesEvicted: number}} */
  ingestAndCompositePng(ksc2Payload) {
    const statsBuf = this.call(OP_V2_INGEST_FRAME, ksc2Payload);
    const tilesCached = statsBuf.length >= 12 ? statsBuf.readUInt32LE(8) : 0;
    const tilesEvicted = statsBuf.length >= 16 ? statsBuf.readUInt32LE(12) : 0;
    const opts = Buffer.alloc(24);
    opts.writeDoubleLE(performance.now(), 0);
    opts.writeFloatLE(1.0, 8);
    opts.writeFloatLE(0.0, 12);
    opts.writeFloatLE(0.0, 16);
    opts.writeUInt32LE(0, 20); // raw_rgba = 0 -> PNG
    const png = this.call(OP_V2_COMPOSITE, opts);
    let width = 0;
    let height = 0;
    if (png.length >= 24) {
      width = png.readUInt32BE(16);
      height = png.readUInt32BE(20);
    }
    return { png, width, height, tilesCached, tilesEvicted };
  }

  /** @param {number} x @param {number} y @returns {{hit: boolean, cursor?: number, editable?: boolean, nodeId?: number, scrollNodeId?: number, linkUrl?: string}} */
  hitTest(x, y) {
    const req = Buffer.alloc(16);
    req.writeFloatLE(x, 0);
    req.writeFloatLE(y, 4);
    req.writeDoubleLE(performance.now(), 8);
    const out = this.call(OP_V2_HIT_TEST, req);
    if (out.length < 24) return { hit: false };
    const linkLen = out.readUInt32LE(20);
    return {
      hit: out[0] !== 0,
      cursor: out[1],
      editable: out[2] !== 0,
      nodeId: Number(out.readBigUInt64LE(4)),
      scrollNodeId: Number(out.readBigUInt64LE(12)),
      linkUrl: linkLen > 0 ? out.subarray(24, 24 + linkLen).toString("utf8") : "",
    };
  }
}

function buildCreditGrant(credits, ackedFrameSeq) {
  const buf = Buffer.alloc(13);
  KSV2_MAGIC.copy(buf, 0);
  buf[4] = 2;
  buf.writeUInt32LE(credits, 5);
  buf.writeUInt32LE(ackedFrameSeq, 9);
  return buf;
}

const DEFAULT_WELCOME_HTML = `<!DOCTYPE html>
<html>
<head><title>Parawing x Vivari Live Co-Browser</title></head>
<body style="margin:0;padding:28px;background:#0f172a;color:#f8fafc;font-family:sans-serif">
  <div style="padding:20px;background:#1e293b;border:2px solid #38bdf8;margin-bottom:18px">
    <div style="font-size:12px;color:#38bdf8;margin-bottom:6px">SERVER: DIGITALOCEAN DROPLET (BLITZ + DENO V8 + CRIU)</div>
    <h1 id="headline" style="margin:0 0 8px 0;font-size:24px;color:#f8fafc">Parawing Delegated Co-Browser</h1>
    <p id="subhead" style="margin:0;font-size:14px;color:#cbd5e1">Vector KSC2 display-lists streamed over Wisp into Vivari in-browser Node.js + scene_host.wasm.</p>
  </div>
  <div style="display:flex;gap:16px;margin-bottom:18px">
    <div style="flex:1;padding:16px;background:#064e3b;border:1px solid #10b981">
      <div style="font-size:11px;color:#6ee7b7">CLIENT RUNTIME</div>
      <div id="client-tag" style="font-size:16px;font-weight:bold;color:#ecfdf5;margin-top:4px">Vivari Node ${process.version}</div>
    </div>
    <div style="flex:1;padding:16px;background:#312e81;border:1px solid #818cf8">
      <div style="font-size:11px;color:#c7d2fe">SESSION COUNTER</div>
      <div id="counter-box" style="font-size:16px;font-weight:bold;color:#eef2ff;margin-top:4px">ticks: 0</div>
    </div>
  </div>
  <p style="font-size:13px;color:#94a3b8">Links: <a href="https://example.com" style="color:#38bdf8">https://example.com</a></p>
</body>
</html>`;

async function main() {
  emit("boot", {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    pid: process.pid,
  });

  const {
    wasm,
    sha256: wasmSha256,
    byteLength: wasmBytes,
  } = await SceneHostClientWasm.load("/parawing/scene_host.wasm");
  emit("wasmReady", { wasmSha256, wasmBytes });

  const [health, versionInfo, capsuleManifest] = await Promise.all([
    httpGetJson("/health"),
    httpGetJson("/json/version"),
    httpGetJson("/capsule/manifest"),
  ]);
  emit("dropletConnected", {
    health: health.text,
    browser: versionInfo.Browser,
    capsuleHash: capsuleManifest.capsuleHash,
    criuEnabled: capsuleManifest.criuEnabled,
  });

  const cdpWs = await NetWebSocket.connect(HOST, PORT, `/devtools/page/${TARGET_ID}`);
  const viewerWs = await NetWebSocket.connect(HOST, PORT, `/viewer/${TARGET_ID}`);

  let nextRpcId = 1;
  const pendingRpc = new Map();
  let activeLeaseId = "";
  let lastFrozenBundle = null;
  let totalFrames = 0;
  let totalWireBytes = 0;

  cdpWs.handlers.text = (raw) => {
    const msg = JSON.parse(raw);
    const waiter = pendingRpc.get(msg.id);
    if (!waiter) return;
    pendingRpc.delete(msg.id);
    if (msg.error) waiter.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
    else waiter.resolve(msg.result);
  };

  function cdpCall(method, params = {}) {
    const id = nextRpcId++;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        pendingRpc.delete(id);
        reject(new Error(`CDP timeout on ${method}`));
      }, 20_000);
      pendingRpc.set(id, {
        resolve: (res) => {
          clearTimeout(timer);
          resolvePromise(res);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
      cdpWs.sendText(JSON.stringify({ id, method, params }));
    });
  }

  viewerWs.handlers.bin = (packet) => {
    totalWireBytes += packet.length;
    if (packet.length < 25 || !packet.subarray(0, 4).equals(KSV2_MAGIC) || packet[4] !== 1) return;
    const frameSeq = packet.readUInt32LE(5);
    const baseSeq = packet.readUInt32LE(9);
    const tileCount = packet.readUInt32LE(13);
    const payloadLen = packet.readUInt32LE(17);
    const ksc2 = packet.subarray(21, 21 + payloadLen);
    if (!ksc2.subarray(0, 4).equals(KSC2_MAGIC)) return;

    const rendered = wasm.ingestAndCompositePng(ksc2);
    totalFrames += 1;
    viewerWs.sendBinary(buildCreditGrant(4, frameSeq));
    emit("frame", {
      frameSeq,
      baseSeq,
      tileCount,
      ksc2Bytes: payloadLen,
      totalFrames,
      totalWireBytes,
      width: rendered.width,
      height: rendered.height,
      tilesCached: rendered.tilesCached,
      tilesEvicted: rendered.tilesEvicted,
      pngBase64: rendered.png.toString("base64"),
    });
  };

  viewerWs.sendBinary(buildCreditGrant(8, 0));
  await cdpCall("Emulation.setDeviceMetricsOverride", { width: 880, height: 560 });
  await cdpCall("Page.setDocumentContent", { html: DEFAULT_WELCOME_HTML });
  const docSnap = await cdpCall("DOM.getDocument", {});
  emit("navigated", { url: "parawing://welcome", title: docSnap.root.title });

  async function ensureAttestedLease() {
    if (activeLeaseId) return activeLeaseId;
    const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const spkiB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const nonce = crypto.randomBytes(16).toString("hex");
    const attestation = await cdpCall("Parawing.signCapsuleAttestation", {
      ephemeralP256PubkeySpkiB64: spkiB64,
      nonce,
    });
    const leaseId = `vivari-lease-${crypto.randomBytes(4).toString("hex")}`;
    const lease = await cdpCall("Parawing.issueAttestedKeyLease", {
      attestation,
      leaseId,
      sessionId: `vivari-session-${TARGET_ID}`,
      ttlMs: 300_000,
    });
    activeLeaseId = lease.leaseId;
    emit("attested", {
      leaseId: activeLeaseId,
      capsuleHash: attestation.claims?.capsuleHash || capsuleManifest.capsuleHash,
      signaturePrefix: String(attestation.signatureB64 || "").slice(0, 24),
    });
    return activeLeaseId;
  }

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let cmd;
    try {
      cmd = JSON.parse(trimmed);
    } catch {
      return;
    }
    const reqId = cmd.reqId || "";
    try {
      if (cmd.action === "navigate") {
        const res = await cdpCall("Page.navigate", { url: cmd.url });
        const doc = await cdpCall("DOM.getDocument", {});
        emit("navigated", { reqId, url: res.url, title: doc.root.title });
      } else if (cmd.action === "resetWelcome") {
        await cdpCall("Page.setDocumentContent", { html: DEFAULT_WELCOME_HTML });
        const doc = await cdpCall("DOM.getDocument", {});
        emit("navigated", { reqId, url: "parawing://welcome", title: doc.root.title });
      } else if (cmd.action === "evalJs") {
        const evalRes = await cdpCall("Runtime.evaluate", { expression: cmd.expression });
        const doc = await cdpCall("DOM.getDocument", {});
        emit("evalResult", {
          reqId,
          value: evalRes?.result?.value?.value ?? evalRes?.result?.value ?? null,
          title: doc.root.title,
        });
      } else if (cmd.action === "hitTest") {
        const hit = wasm.hitTest(Number(cmd.x) || 0, Number(cmd.y) || 0);
        emit("hitTestResult", { reqId, x: cmd.x, y: cmd.y, ...hit });
        if (cmd.navigateOnLink && hit.linkUrl) {
          const res = await cdpCall("Page.navigate", { url: hit.linkUrl });
          const doc = await cdpCall("DOM.getDocument", {});
          emit("navigated", { reqId, url: res.url, title: doc.root.title });
        }
      } else if (cmd.action === "attest") {
        activeLeaseId = "";
        await ensureAttestedLease();
      } else if (cmd.action === "freeze") {
        const leaseId = await ensureAttestedLease();
        lastFrozenBundle = await cdpCall("Parawing.freezeSession", { leaseId });
        emit("frozen", {
          reqId,
          leaseId,
          backend: lastFrozenBundle?.backend || "capsule",
          bundleSha256: crypto
            .createHash("sha256")
            .update(JSON.stringify(lastFrozenBundle))
            .digest("hex")
            .slice(0, 16),
        });
      } else if (cmd.action === "thaw") {
        if (!lastFrozenBundle) throw new Error("No frozen checkpoint bundle yet; freeze first");
        const leaseId = await ensureAttestedLease();
        const outcome = await cdpCall("Parawing.thawSession", {
          leaseId,
          bundle: lastFrozenBundle,
        });
        const doc = await cdpCall("DOM.getDocument", {});
        emit("thawed", {
          reqId,
          tier: outcome.tier,
          fullSceneBytes: outcome.fullSceneBytes,
          csprngReseedSha256: String(outcome.csprngReseedSha256 || "").slice(0, 16),
          title: doc.root.title,
        });
      }
    } catch (err) {
      emit("commandError", { reqId, action: cmd.action, message: err.message || String(err) });
    }
  });
}

main().catch((err) => {
  emit("fatal", { message: err.stack || err.message || String(err) });
  process.exit(1);
});
