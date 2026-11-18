#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Records the live epoch-fenced Agent Handoff GIF against the DigitalOcean host.
// Drives an autonomous Node agent (`agent-alpha`) over Wisp TLS alongside Chromium
// running the unpacked MV3 Vivari Chrome Extension (`human-vivari`).

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import tls from "node:tls";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const DEMO_ROOT = resolve(REPO_ROOT, "demo");
const EXT_DIST = resolve(DEMO_ROOT, "chrome-extension/dist");
const STATE_PATH = resolve(DEMO_ROOT, ".droplet-state.json");
const OUT_GIF = resolve(REPO_ROOT, ".github/assets/agent_handoff_demo.gif");

const WISP_CONNECT = 0x01;
const WISP_DATA = 0x02;
const WISP_CLOSE = 0x04;
const VV_CONNECTED = 0x15;
const VV_ACK = 0x16;

const rootReq = createRequire(resolve(REPO_ROOT, "package.json"));
const puppeteer = rootReq("puppeteer-core");

function findChromiumForTesting() {
  if (process.env.CHROME_FOR_TESTING_BIN && existsSync(process.env.CHROME_FOR_TESTING_BIN)) {
    return process.env.CHROME_FOR_TESTING_BIN;
  }
  const pwCache = resolve(homedir(), "Library/Caches/ms-playwright");
  if (existsSync(pwCache)) {
    const dirs = readdirSync(pwCache)
      .filter((d) => d.startsWith("chromium-"))
      .sort()
      .reverse();
    for (const dir of dirs) {
      const macArm = resolve(
        pwCache,
        dir,
        "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
      );
      if (existsSync(macArm)) return macArm;
    }
  }
  const linuxPw = resolve(homedir(), ".cache/ms-playwright");
  if (existsSync(linuxPw)) {
    const dirs = readdirSync(linuxPw)
      .filter((d) => d.startsWith("chromium-"))
      .sort()
      .reverse();
    for (const dir of dirs) {
      const bin = resolve(linuxPw, dir, "chrome-linux/chrome");
      if (existsSync(bin)) return bin;
    }
  }
  throw new Error("Google Chrome for Testing binary not found; set CHROME_FOR_TESTING_BIN");
}

function findFfmpeg() {
  for (const candidate of ["/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg", "ffmpeg"]) {
    try {
      execFileSync(candidate, ["-version"], { stdio: "ignore" });
      return candidate;
    } catch {}
  }
  throw new Error("ffmpeg binary not found");
}

function sendMaskedWsFrame(socket, opcode, payload) {
  const mask = crypto.randomBytes(4);
  const len = payload.length;
  let head;
  if (len < 126) {
    head = Buffer.alloc(6);
    head[0] = 0x80 | opcode;
    head[1] = 0x80 | len;
    mask.copy(head, 2);
  } else if (len < 65536) {
    head = Buffer.alloc(8);
    head[0] = 0x80 | opcode;
    head[1] = 0x80 | 126;
    head.writeUInt16BE(len, 2);
    mask.copy(head, 4);
  } else {
    head = Buffer.alloc(14);
    head[0] = 0x80 | opcode;
    head[1] = 0x80 | 127;
    head.writeBigUInt64BE(BigInt(len), 2);
    mask.copy(head, 10);
  }
  const masked = Buffer.allocUnsafe(len);
  for (let i = 0; i < len; i += 1) masked[i] = payload[i] ^ mask[i & 3];
  socket.write(Buffer.concat([head, masked]));
}

// Multiplexed Wisp v1 TLS WebSocket client used by `agent-alpha` to reach
// `host.vivari.internal:8788` on the DigitalOcean droplet over HTTPS port 443.
class WispTlsClient {
  constructor(tlsSocket) {
    this.socket = tlsSocket;
    this.buf = Buffer.alloc(0);
    this.frags = [];
    this.fragOp = 0;
    this.nextStreamId = 1;
    this.streams = new Map();
    tlsSocket.on("data", (chunk) => this.#drainWs(chunk));
  }

  /** @param {string} sslipHost @param {string} httpsOrigin @returns {Promise<WispTlsClient>} */
  static connect(sslipHost, httpsOrigin) {
    return new Promise((resolvePromise, reject) => {
      const sock = tls.connect({ host: sslipHost, port: 443, servername: sslipHost });
      const key = crypto.randomBytes(16).toString("base64");
      let headBuf = Buffer.alloc(0);
      let upgraded = false;

      const onData = (chunk) => {
        headBuf = Buffer.concat([headBuf, chunk]);
        const end = headBuf.indexOf("\r\n\r\n");
        if (end === -1) return;
        sock.off("data", onData);
        const head = headBuf.subarray(0, end).toString("latin1");
        if (!head.startsWith("HTTP/1.1 101")) {
          sock.destroy();
          reject(new Error(`Wisp TLS upgrade failed: ${head.split("\r\n")[0]}`));
          return;
        }
        upgraded = true;
        const client = new WispTlsClient(sock);
        const rem = headBuf.subarray(end + 4);
        if (rem.length > 0) client.#drainWs(rem);
        resolvePromise(client);
      };

      sock.once("secureConnect", () => {
        sock.write(
          "GET /parawing-demo-v1 HTTP/1.1\r\n" +
            `Host: ${sslipHost}\r\n` +
            `Origin: ${httpsOrigin}\r\n` +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Key: ${key}\r\n` +
            "Sec-WebSocket-Version: 13\r\n\r\n",
        );
      });
      sock.on("data", onData);
      sock.once("error", (err) => {
        if (!upgraded) reject(err);
      });
    });
  }

  /** @param {string} host @param {number} port @returns {Promise<{write: (b: Buffer) => void, close: () => void, onData: (fn: (b: Buffer) => void) => void, onClose: (fn: () => void) => void}>} */
  openStream(host = "host.vivari.internal", port = 8788) {
    const id = this.nextStreamId++;
    return new Promise((resolvePromise, reject) => {
      const entry = {
        rxPackets: 0,
        dataCb: null,
        closeCb: null,
        onConnected: () => resolvePromise(api),
        onError: (msg) => reject(new Error(msg)),
      };
      const api = {
        write: (buf) => {
          for (let off = 0; off < buf.length; off += 16384) {
            this.#sendPacket(WISP_DATA, id, buf.subarray(off, off + 16384));
          }
        },
        close: () => {
          this.streams.delete(id);
          this.#sendPacket(WISP_CLOSE, id, Buffer.from([0x02]));
        },
        onData: (fn) => {
          entry.dataCb = fn;
        },
        onClose: (fn) => {
          entry.closeCb = fn;
        },
      };
      this.streams.set(id, entry);
      const hostBuf = Buffer.from(host, "utf8");
      const payload = Buffer.alloc(3 + hostBuf.length);
      payload[0] = 0x01;
      payload.writeUInt16LE(port, 1);
      hostBuf.copy(payload, 3);
      this.#sendPacket(WISP_CONNECT, id, payload);
    });
  }

  /** @param {string} path @returns {Promise<any>} */
  async httpGetJson(path) {
    const stream = await this.openStream();
    return await new Promise((resolvePromise, reject) => {
      const chunks = [];
      stream.onData((c) => chunks.push(c));
      stream.onClose(() => {
        const raw = Buffer.concat(chunks);
        const sep = raw.indexOf("\r\n\r\n");
        if (sep === -1) {
          reject(new Error(`Malformed HTTP response on ${path}`));
          return;
        }
        try {
          resolvePromise(JSON.parse(raw.subarray(sep + 4).toString("utf8")));
        } catch (err) {
          reject(err);
        }
      });
      stream.write(
        Buffer.from(
          `GET ${path} HTTP/1.0\r\nHost: host.vivari.internal:8788\r\nConnection: close\r\n\r\n`,
          "utf8",
        ),
      );
    });
  }

  /** @param {string} path @returns {Promise<{call: (method: string, params?: object) => Promise<any>, close: () => void}>} */
  async openCdp(path) {
    const stream = await this.openStream();
    return await new Promise((resolvePromise, reject) => {
      const key = crypto.randomBytes(16).toString("base64");
      let headBuf = Buffer.alloc(0);
      let wsBuf = Buffer.alloc(0);
      let upgraded = false;
      let nextId = 1;
      const pending = new Map();

      const drainInnerWs = (chunk) => {
        wsBuf = Buffer.concat([wsBuf, chunk]);
        while (wsBuf.length >= 2) {
          const b0 = wsBuf[0];
          const b1 = wsBuf[1];
          const opcode = b0 & 0x0f;
          let len = b1 & 0x7f;
          let off = 2;
          if (len === 126) {
            if (wsBuf.length < 4) return;
            len = wsBuf.readUInt16BE(2);
            off = 4;
          } else if (len === 127) {
            if (wsBuf.length < 10) return;
            len = Number(wsBuf.readBigUInt64BE(2));
            off = 10;
          }
          if (wsBuf.length < off + len) return;
          const payload = wsBuf.subarray(off, off + len);
          wsBuf = wsBuf.subarray(off + len);
          if (opcode === 0x01) {
            const msg = JSON.parse(payload.toString("utf8"));
            const waiter = pending.get(msg.id);
            if (waiter) {
              pending.delete(msg.id);
              if (msg.error)
                waiter.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
              else waiter.resolve(msg.result);
            }
          }
        }
      };

      stream.onData((chunk) => {
        if (!upgraded) {
          headBuf = Buffer.concat([headBuf, chunk]);
          const end = headBuf.indexOf("\r\n\r\n");
          if (end === -1) return;
          const status = headBuf.subarray(0, end).toString("latin1").split("\r\n")[0];
          if (!status.startsWith("HTTP/1.1 101")) {
            stream.close();
            reject(new Error(`CDP upgrade failed on ${path}: ${status}`));
            return;
          }
          upgraded = true;
          const rem = headBuf.subarray(end + 4);
          if (rem.length > 0) drainInnerWs(rem);
          resolvePromise({
            call: (method, params = {}) => {
              const id = nextId++;
              return new Promise((res, rej) => {
                const timer = setTimeout(() => {
                  pending.delete(id);
                  rej(new Error(`CDP timeout on ${method}`));
                }, 15_000);
                pending.set(id, {
                  resolve: (v) => {
                    clearTimeout(timer);
                    res(v);
                  },
                  reject: (e) => {
                    clearTimeout(timer);
                    rej(e);
                  },
                });
                const textBuf = Buffer.from(JSON.stringify({ id, method, params }), "utf8");
                sendMaskedWsFrame({ write: (b) => stream.write(b) }, 0x01, textBuf);
              });
            },
            close: () => stream.close(),
          });
          return;
        }
        drainInnerWs(chunk);
      });

      stream.write(
        Buffer.from(
          `GET ${path} HTTP/1.1\r\n` +
            "Host: host.vivari.internal:8788\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Key: ${key}\r\n` +
            "Sec-WebSocket-Version: 13\r\n\r\n",
          "utf8",
        ),
      );
    });
  }

  /** @returns {void} */
  close() {
    try {
      sendMaskedWsFrame(this.socket, 0x08, Buffer.alloc(0));
      this.socket.end();
    } catch {}
  }

  #sendPacket(type, id, payload) {
    const head = Buffer.alloc(5);
    head[0] = type;
    head.writeUInt32LE(id >>> 0, 1);
    sendMaskedWsFrame(this.socket, 0x02, Buffer.concat([head, payload]));
  }

  #drainWs(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    while (this.buf.length >= 2) {
      const b0 = this.buf[0];
      const b1 = this.buf[1];
      const fin = (b0 & 0x80) !== 0;
      const op = b0 & 0x0f;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        len = Number(this.buf.readBigUInt64BE(2));
        off = 10;
      }
      if (this.buf.length < off + len) return;
      const payload = this.buf.subarray(off, off + len);
      this.buf = this.buf.subarray(off + len);
      if (op === 0x09) {
        sendMaskedWsFrame(this.socket, 0x0a, payload);
        continue;
      }
      if (op === 0x08) {
        this.socket.end();
        return;
      }
      if (op === 0x00) {
        this.frags.push(payload);
        if (fin) {
          const full = Buffer.concat(this.frags);
          this.frags = [];
          if (this.fragOp === 0x02) this.#onWispPacket(full);
        }
        continue;
      }
      if (!fin) {
        this.fragOp = op;
        this.frags = [payload];
        continue;
      }
      if (op === 0x02) this.#onWispPacket(payload);
    }
  }

  #onWispPacket(pkt) {
    if (pkt.length < 5) return;
    const type = pkt[0];
    const id = pkt.readUInt32LE(1);
    const body = pkt.subarray(5);
    const st = this.streams.get(id);
    if (!st) return;
    if (type === VV_CONNECTED) {
      st.onConnected?.();
    } else if (type === WISP_DATA) {
      st.rxPackets = (st.rxPackets + 1) >>> 0;
      const ack = Buffer.alloc(4);
      ack.writeUInt32LE(st.rxPackets, 0);
      this.#sendPacket(VV_ACK, id, ack);
      st.dataCb?.(Buffer.from(body));
    } else if (type === WISP_CLOSE) {
      this.streams.delete(id);
      st.closeCb?.();
    }
  }
}

function buildHandoffSceneHtml(epoch) {
  return `<!DOCTYPE html>
<html>
<head><title>Parawing Agent Handoff — Prod Cutover</title></head>
<body style="margin:0;padding:24px;background:#0f172a;color:#f8fafc;font-family:sans-serif">
  <div id="authority-banner" style="padding:18px 20px;background:#1e293b;border:3px solid #38bdf8;margin-bottom:16px">
    <div id="lease-kicker" style="font-size:13px;font-weight:bold;color:#38bdf8;margin-bottom:6px">EPOCH ${epoch} LEASE · OWNER: AGENT-ALPHA</div>
    <h1 id="stage-title" style="margin:0 0 8px 0;font-size:26px;color:#f8fafc">Step 1/3 — Staging Signed Release Bundle</h1>
    <p id="stage-detail" style="margin:0;font-size:15px;color:#cbd5e1">Autonomous agent preparing production rollout inside isolated Deno V8 + Blitz session.</p>
  </div>
  <div style="display:flex;gap:14px;margin-bottom:16px">
    <div style="flex:1;padding:14px 16px;background:#0f2942;border:1px solid #0284c7">
      <div style="font-size:12px;color:#7dd3fc">ACTIVE EPOCH OWNER</div>
      <div id="dom-owner" style="font-size:18px;font-weight:bold;color:#f0f9ff;margin-top:4px">agent-alpha (Epoch ${epoch})</div>
    </div>
    <div style="flex:1;padding:14px 16px;background:#1e1b4b;border:1px solid #6366f1">
      <div style="font-size:12px;color:#c7d2fe">DENO V8 ISOLATE STATE</div>
      <div id="dom-state" style="font-size:18px;font-weight:bold;color:#eef2ff;margin-top:4px">steps: 1 · humanApproved: false</div>
    </div>
  </div>
  <div style="padding:14px 18px;background:#111827;border:1px solid #334155;font-family:monospace;font-size:14px;color:#e2e8f0">
    <div id="step-1" style="margin-bottom:6px;color:#34d399">[DONE] Step 1/3: Staged release archive parawing-v0.1.11</div>
    <div id="step-2" style="margin-bottom:6px;color:#94a3b8">[ .. ] Step 2/3: Verify 199 SHA-256 dependency patches</div>
    <div id="step-3" style="color:#94a3b8">[GATE] Step 3/3: Production traffic cutover (requires human)</div>
  </div>
</body>
</html>`;
}

async function main() {
  assert.ok(
    existsSync(resolve(EXT_DIST, "manifest.json")),
    "Build demo/chrome-extension/dist first",
  );
  assert.ok(existsSync(STATE_PATH), "Missing demo/.droplet-state.json");
  const dropletState = JSON.parse(readFileSync(STATE_PATH, "utf8"));
  const executablePath = findChromiumForTesting();
  const ffmpegBin = findFfmpeg();
  const userDataDir = mkdtempSync(join(tmpdir(), "parawing-handoff-profile-"));
  const frameDir = mkdtempSync(join(tmpdir(), "parawing-handoff-frames-"));
  const targetId = `handoff-${crypto.randomBytes(3).toString("hex")}`;

  console.log(`[record] Connecting agent-alpha over Wisp TLS to ${dropletState.httpsOrigin}…`);
  const wisp = await WispTlsClient.connect(dropletState.sslipHost, dropletState.httpsOrigin);

  // Claim initial Epoch lease for `agent-alpha` and stage Step 1 on `targetId`.
  const claimWs = await wisp.openCdp(`/devtools/page/${targetId}`);
  const agentLease1 = await claimWs.call("Parawing.transferOwnership", {
    newOwner: "agent-alpha",
  });
  claimWs.close();
  const epoch1 = agentLease1.epoch;
  console.log(`[record] agent-alpha acquired Epoch ${epoch1} on target ${targetId}`);

  const agentWs1 = await wisp.openCdp(
    `/devtools/page/${targetId}?epoch=${epoch1}&nodeId=agent-alpha`,
  );
  await agentWs1.call("Page.setDocumentContent", { html: buildHandoffSceneHtml(epoch1) });
  await agentWs1.call("Runtime.evaluate", {
    expression: `(() => {
      __state.steps = 1;
      __state.humanApproved = false;
      __state.release = "v0.1.11";
      return { steps: __state.steps };
    })()`,
  });

  console.log("[record] Launching Chromium with unpacked Parawing × Vivari MV3 extension…");
  const browser = await puppeteer.launch({
    executablePath,
    headless: "new",
    userDataDir,
    defaultViewport: { width: 1280, height: 740, deviceScaleFactor: 2 },
    args: [
      `--disable-extensions-except=${EXT_DIST}`,
      `--load-extension=${EXT_DIST}`,
      "--no-first-run",
      "--no-default-browser-check",
    ],
  });

  const captured = [];
  let frameIndex = 0;
  async function captureMilestone(page, durationSec, label) {
    await new Promise((r) => setTimeout(r, 120));
    frameIndex += 1;
    const file = resolve(frameDir, `frame-${String(frameIndex).padStart(3, "0")}.png`);
    await page.screenshot({ path: file, type: "png" });
    captured.push({ file, durationSec, label });
    console.log(`[record] Captured #${frameIndex} (${durationSec}s): ${label}`);
  }

  try {
    const swTarget = await browser.waitForTarget(
      (t) => t.type() === "service_worker" && t.url().endsWith("/background.js"),
      { timeout: 20_000 },
    );
    const extId = new URL(swTarget.url()).host;
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 740, deviceScaleFactor: 2 });

    const url =
      `chrome-extension://${extId}/workbench.html` +
      `?origin=${encodeURIComponent(dropletState.httpsOrigin)}` +
      `&target=${encodeURIComponent(targetId)}&join=1`;
    await page.goto(url, { waitUntil: "domcontentloaded" });

    // Wait for Vivari to join `agent-alpha`'s live session as viewer and render Frame #1.
    await page.waitForFunction(
      (expectedEpoch) => {
        const conn = document.getElementById("conn-badge")?.dataset.state;
        const ep = document.getElementById("epoch-badge")?.textContent || "";
        const frames = Number(
          document.getElementById("viewport-canvas")?.dataset.renderedFrames || "0",
        );
        return conn === "connected" && ep === `Epoch ${expectedEpoch} · agent-alpha` && frames >= 1;
      },
      { timeout: 30_000 },
      epoch1,
    );
    await captureMilestone(page, 1.3, `Act 1a: agent-alpha driving Step 1/3 (Epoch ${epoch1})`);

    // Act 1b: `agent-alpha` advances to Step 2/3; KSC2 delta streams live into Vivari.
    let prevFrames = await page.$eval("#viewport-canvas", (el) =>
      Number(el.dataset.renderedFrames || "0"),
    );
    await agentWs1.call("Runtime.evaluate", {
      expression: `(() => {
        __state.steps = 2;
        document.getElementById("stage-title").textContent = "Step 2/3 — Verified 199 SHA-256 Patch Digests";
        document.getElementById("stage-detail").textContent = "OSV + OpenVEX ledger verified zero open CVEs; advancing to production cutover gate.";
        document.getElementById("dom-state").textContent = "steps: 2 · patchesVerified: 199";
        document.getElementById("step-2").setAttribute("style", "margin-bottom:6px;color:#34d399");
        document.getElementById("step-2").textContent = "[DONE] Step 2/3: Verified 199 SHA-256 dependency patches";
        return { steps: __state.steps };
      })()`,
    });
    await page.waitForFunction(
      (prev) =>
        Number(document.getElementById("viewport-canvas")?.dataset.renderedFrames || "0") > prev,
      { timeout: 15_000 },
      prevFrames,
    );
    await captureMilestone(
      page,
      1.3,
      `Act 1b: agent-alpha verified patches Step 2/3 (Epoch ${epoch1})`,
    );

    // Act 1c: `agent-alpha` reaches high-risk production cutover gate & pauses for human.
    prevFrames = await page.$eval("#viewport-canvas", (el) =>
      Number(el.dataset.renderedFrames || "0"),
    );
    await agentWs1.call("Runtime.evaluate", {
      expression: `(() => {
        __state.awaitingHuman = true;
        document.getElementById("authority-banner").setAttribute("style", "padding:18px 20px;background:#451a03;border:3px solid #f59e0b;margin-bottom:16px");
        document.getElementById("lease-kicker").setAttribute("style", "font-size:13px;font-weight:bold;color:#fbbf24;margin-bottom:6px");
        document.getElementById("lease-kicker").textContent = "HUMAN AUTHORITY REQUIRED · EPOCH ${epoch1} PAUSED";
        document.getElementById("stage-title").textContent = "PAUSED AT STEP 3/3 — Confirm Production Cutover";
        document.getElementById("stage-detail").textContent = "Click [Take Control] in Vivari to fence agent-alpha and authorize production traffic switch.";
        document.getElementById("step-3").setAttribute("style", "color:#fbbf24");
        document.getElementById("step-3").textContent = "[WAIT] Step 3/3: Awaiting human supervisor epoch takeover";
        return { awaitingHuman: true };
      })()`,
    });
    await page.waitForFunction(
      (prev) =>
        Number(document.getElementById("viewport-canvas")?.dataset.renderedFrames || "0") > prev,
      { timeout: 15_000 },
      prevFrames,
    );
    await captureMilestone(page, 1.8, "Act 1c: agent-alpha paused at Human Authority Gate");

    // Act 2: Human focuses and clicks `#take-control-btn` -> Epoch increments to `epoch1 + 1`.
    await page.focus("#take-control-btn");
    await captureMilestone(page, 0.7, "Act 2a: Human focuses [Take Control]");

    const epoch2 = epoch1 + 1;
    await page.click("#take-control-btn");
    await page.waitForFunction(
      (expectedEpoch) =>
        document.getElementById("epoch-badge")?.textContent ===
        `Epoch ${expectedEpoch} · human-vivari`,
      { timeout: 15_000 },
      epoch2,
    );

    // Verify real server-side StaleEpochFenced rejection when `agent-alpha` writes on stale socket!
    await assert.rejects(
      () =>
        agentWs1.call("Runtime.evaluate", {
          expression: "__state.unauthorizedMutation = true",
        }),
      /stale epoch .* fenced by epoch/i,
    );
    agentWs1.close();
    console.log(`[record] Verified StaleEpochFenced on agent-alpha Epoch ${epoch1} socket`);
    await captureMilestone(
      page,
      1.4,
      `Act 2b: Ownership transferred -> Epoch ${epoch2} (human-vivari), agent-alpha fenced`,
    );

    // Act 3: Human supervisor stages and executes cutover approval inside Deno V8 sub-isolate.
    const humanApprovalExpr = `(() => {
  __state.steps = 3;
  __state.humanApproved = true;
  document.getElementById('authority-banner').setAttribute('style', 'padding:18px 20px;background:#064e3b;border:3px solid #10b981;margin-bottom:16px');
  document.getElementById('lease-kicker').setAttribute('style', 'font-size:13px;font-weight:bold;color:#6ee7b7;margin-bottom:6px');
  document.getElementById('lease-kicker').textContent = 'EPOCH ${epoch2} LEASE · AUTHORIZED BY HUMAN-VIVARI';
  document.getElementById('stage-title').textContent = 'APPROVED BY HUMAN — Cutover Cleared';
  document.getElementById('stage-detail').textContent = 'Human supervisor approved cutover in Deno V8 isolate; hand back to agent-alpha to finish.';
  document.getElementById('dom-owner').textContent = 'human-vivari (Epoch ${epoch2})';
  document.getElementById('dom-state').textContent = 'steps: 3 · humanApproved: true';
  document.getElementById('step-3').setAttribute('style', 'color:#34d399');
  document.getElementById('step-3').textContent = '[AUTH] Step 3/3: Authorized by human-vivari at Epoch ${epoch2}';
  return { approved: __state.humanApproved, epoch: ${epoch2} };
})()`;

    await page.$eval(
      "#eval-expr",
      (el, val) => {
        el.value = val;
      },
      humanApprovalExpr,
    );
    await page.focus("#eval-btn");
    await captureMilestone(page, 0.8, "Act 3a: Human stages approval in [Run in Droplet Isolate]");

    prevFrames = await page.$eval("#viewport-canvas", (el) =>
      Number(el.dataset.renderedFrames || "0"),
    );
    await page.click("#eval-btn");
    await page.waitForFunction(
      (prev, expectedOut) =>
        Number(document.getElementById("viewport-canvas")?.dataset.renderedFrames || "0") > prev &&
        document.getElementById("eval-output")?.textContent === expectedOut,
      { timeout: 15_000 },
      prevFrames,
      JSON.stringify({ approved: true, epoch: epoch2 }),
    );
    const bannerStats = await page.evaluate(() => {
      const canvas = document.getElementById("viewport-canvas");
      const ctx = canvas.getContext("2d");
      const { data } = ctx.getImageData(24, 24, 750, 145);
      let emeraldPixels = 0;
      let brightGlyphPixels = 0;
      for (let i = 0; i < data.length; i += 4) {
        const r = data[i];
        const g = data[i + 1];
        const b = data[i + 2];
        if (g >= 70 && g > r * 2) emeraldPixels += 1;
        if (r >= 200 && g >= 200 && b >= 200) brightGlyphPixels += 1;
      }
      return { emeraldPixels, brightGlyphPixels };
    });
    console.log("[record] Verified banner & glyph pixels on <canvas>:", bannerStats);
    assert.ok(bannerStats.emeraldPixels > 5000, "Expected emerald banner fill in tile row 0");
    assert.ok(bannerStats.brightGlyphPixels > 400, "Expected rendered text glyphs in tile row 0");
    await captureMilestone(
      page,
      1.8,
      `Act 3b: Human authorized cutover on live KSC2 scene (Epoch ${epoch2})`,
    );

    // Act 4: Human clicks `#handback-btn` -> Epoch increments to `epoch2 + 1` (`agent-alpha`).
    await page.focus("#handback-btn");
    await captureMilestone(page, 0.7, "Act 4a: Human focuses [Hand Off to Agent]");

    const epoch3 = epoch2 + 1;
    await page.click("#handback-btn");
    await page.waitForFunction(
      (expectedEpoch) =>
        document.getElementById("epoch-badge")?.textContent ===
        `Epoch ${expectedEpoch} · agent-alpha`,
      { timeout: 15_000 },
      epoch3,
    );
    await captureMilestone(
      page,
      0.9,
      `Act 4b: Ownership returned -> Epoch ${epoch3} (agent-alpha)`,
    );

    // `agent-alpha` verifies `/roam/epoch`, reconnects pinned to `epoch3`, reads preserved
    // `__state.humanApproved === true` from the Deno V8 isolate, and completes the rollout!
    const liveEpoch = await wisp.httpGetJson("/roam/epoch");
    assert.equal(liveEpoch.epoch, epoch3);
    assert.equal(liveEpoch.ownerNodeId, "agent-alpha");

    prevFrames = await page.$eval("#viewport-canvas", (el) =>
      Number(el.dataset.renderedFrames || "0"),
    );
    const agentWs3 = await wisp.openCdp(
      `/devtools/page/${targetId}?epoch=${epoch3}&nodeId=agent-alpha`,
    );
    const finalEval = await agentWs3.call("Runtime.evaluate", {
      expression: `(() => {
        if (!__state.humanApproved) throw new Error("Missing humanApproved flag");
        __state.steps = 4;
        document.getElementById("authority-banner").setAttribute("style", "padding:18px 20px;background:#1e1b4b;border:3px solid #818cf8;margin-bottom:16px");
        document.getElementById("lease-kicker").setAttribute("style", "font-size:13px;font-weight:bold;color:#a5b4fc;margin-bottom:6px");
        document.getElementById("lease-kicker").textContent = "EPOCH ${epoch3} LEASE · COMPLETED BY AGENT-ALPHA";
        document.getElementById("stage-title").textContent = "ROLLOUT COMPLETE — Parawing v0.1.11 Live";
        document.getElementById("stage-detail").textContent = "Agent-alpha resumed with preserved V8 isolate state (__state.humanApproved = true) and finalized cutover.";
        document.getElementById("dom-owner").textContent = "agent-alpha (Epoch ${epoch3})";
        document.getElementById("dom-state").textContent = "steps: 4 · rollout: LIVE";
        document.getElementById("step-3").textContent = "[LIVE] Step 3/3: Production traffic switched by agent-alpha (Epoch ${epoch3})";
        return { steps: __state.steps, humanApproved: __state.humanApproved };
      })()`,
    });
    assert.deepEqual(finalEval?.result?.value?.value, { steps: 4, humanApproved: true });
    agentWs3.close();

    await page.waitForFunction(
      (prev) =>
        Number(document.getElementById("viewport-canvas")?.dataset.renderedFrames || "0") > prev,
      { timeout: 15_000 },
      prevFrames,
    );
    await captureMilestone(
      page,
      2.4,
      `Act 4c: agent-alpha resumed & completed rollout (Epoch ${epoch3})`,
    );

    // Encode palette-optimized high-DPI GIF with FFmpeg concat demuxer.
    mkdirSync(resolve(REPO_ROOT, ".github/assets"), { recursive: true });
    const concatLines = ["ffconcat version 1.0"];
    for (const item of captured) {
      concatLines.push(`file '${item.file}'`);
      concatLines.push(`duration ${item.durationSec.toFixed(2)}`);
    }
    concatLines.push(`file '${captured[captured.length - 1].file}'`);
    const concatFile = resolve(frameDir, "frames.ffconcat");
    writeFileSync(concatFile, `${concatLines.join("\n")}\n`);

    const vf =
      "fps=8,scale=1120:-1:flags=lanczos,split[s0][s1];" +
      "[s0]palettegen=max_colors=256:stats_mode=diff[p];" +
      "[s1][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle";
    execFileSync(
      ffmpegBin,
      ["-y", "-f", "concat", "-safe", "0", "-i", concatFile, "-vf", vf, "-loop", "0", OUT_GIF],
      { stdio: "inherit" },
    );

    const gifBytes = statSync(OUT_GIF).size;
    assert.ok(gifBytes > 50_000, `Unexpectedly small GIF (${gifBytes} B)`);
    console.log(
      `[record] Encoded ${OUT_GIF} (${(gifBytes / 1024).toFixed(1)} KiB across ${captured.length} live milestones)`,
    );
  } finally {
    wisp.close();
    await browser.close();
    rmSync(userDataDir, { recursive: true, force: true });
    rmSync(frameDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[record] FAILED:", err);
  process.exit(1);
});
