#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Hardened Wisp v1 + Vivari stream-extension WebSocket relay for the DigitalOcean
// demo droplet. Permits outbound guest TCP connections ONLY to `host.vivari.internal:8788`
// (`127.0.0.1:8788`, the local `parawing-rust-host` daemon), preventing open-proxy abuse.

import crypto from "node:crypto";
import http from "node:http";
import net from "node:net";

const WISP_CONNECT = 0x01;
const WISP_DATA = 0x02;
const WISP_CONTINUE = 0x03;
const WISP_CLOSE = 0x04;
const VV_SHUTDOWN = 0x14;
const VV_CONNECTED = 0x15;
const VV_ACK = 0x16;

const CLOSE_VOLUNTARY = 0x02;
const CLOSE_NETWORK = 0x03;
const CLOSE_INVALID = 0x41;
const CLOSE_REFUSED = 0x44;
const CREDIT = 32;
const RELAY_WINDOW = 32;
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const PORT = Number(process.env.RELAY_PORT || "7071");
const TOKEN = process.env.RELAY_TOKEN || "parawing-demo-v1";
const TARGET_HOST = "127.0.0.1";
const TARGET_PORT = Number(process.env.PARAWING_PORT || "8788");
const ALLOWED_ORIGIN = (process.env.ALLOWED_ORIGIN || "").replace(/\/$/, "");

function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

class WsConn {
  constructor(socket, onMessage, onClose) {
    this.socket = socket;
    this.onMessage = onMessage;
    this.onClose = onClose;
    this.buf = Buffer.alloc(0);
    this.frag = null;
    socket.on("data", (c) => this.feed(c));
    socket.on("close", () => this.onClose());
    socket.on("error", () => socket.destroy());
  }

  /** @param {Buffer} chunk @returns {void} */
  feed(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    while (this.buf.length >= 2) {
      const b0 = this.buf[0];
      const b1 = this.buf[1];
      if (!(b1 & 0x80)) {
        this.socket.destroy();
        return;
      }
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
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.subarray(off, off + 4);
      const payload = Buffer.from(this.buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i += 1) payload[i] ^= mask[i & 3];
      this.buf = this.buf.subarray(off + 4 + len);

      if (op === 0x8) {
        this.frame(0x8, Buffer.alloc(0));
        this.socket.end();
        return;
      }
      if (op === 0x9) {
        this.frame(0x0a, payload);
        continue;
      }
      if (op === 0x0a) continue;
      if (op === 0x00) {
        if (!this.frag) {
          this.socket.destroy();
          return;
        }
        this.frag.push(payload);
        if (fin) {
          const full = Buffer.concat(this.frag);
          this.frag = null;
          this.onMessage(full);
        }
        continue;
      }
      if (!fin) {
        this.frag = [payload];
        continue;
      }
      if (op === 0x02) this.onMessage(payload);
    }
  }

  /** @param {Buffer} payload @returns {void} */
  send(payload) {
    this.frame(0x02, payload);
  }

  /** @param {number} op @param {Buffer} payload @returns {void} */
  frame(op, payload) {
    if (this.socket.destroyed) return;
    const n = payload.length;
    let head;
    if (n < 126) head = Buffer.from([0x80 | op, n]);
    else if (n < 65536) {
      head = Buffer.alloc(4);
      head[0] = 0x80 | op;
      head[1] = 126;
      head.writeUInt16BE(n, 2);
    } else {
      head = Buffer.alloc(10);
      head[0] = 0x80 | op;
      head[1] = 127;
      head.writeBigUInt64BE(BigInt(n), 2);
    }
    this.socket.write(Buffer.concat([head, payload]));
  }
}

class RelaySession {
  constructor(ws) {
    this.ws = ws;
    this.streams = new Map();
    this.packet(WISP_CONTINUE, 0, u32le(CREDIT));
  }

  /** @param {number} type @param {number} id @param {Buffer} [payload] @returns {void} */
  packet(type, id, payload = Buffer.alloc(0)) {
    const head = Buffer.alloc(5);
    head[0] = type;
    head.writeUInt32LE(id >>> 0, 1);
    this.ws.send(payload.length > 0 ? Buffer.concat([head, payload]) : head);
  }

  /** @param {Buffer} buf @returns {void} */
  onPacket(buf) {
    if (buf.length < 5) return;
    const type = buf[0];
    const id = buf.readUInt32LE(1);
    const p = buf.subarray(5);
    if (type === WISP_CONNECT) {
      if (p.length < 3 || this.streams.has(id)) {
        this.packet(WISP_CLOSE, id, Buffer.from([CLOSE_INVALID]));
        return;
      }
      const streamType = p[0];
      const port = p.readUInt16LE(1);
      const host = p.subarray(3).toString("utf8");
      if (streamType !== 1 || host !== "host.vivari.internal" || port !== TARGET_PORT) {
        this.packet(WISP_CLOSE, id, Buffer.from([CLOSE_INVALID]));
        return;
      }
      const socket = net.connect({ host: TARGET_HOST, port: TARGET_PORT });
      const st = {
        socket,
        used: 0,
        needDrain: false,
        connected: false,
        sent: 0,
        acked: 0,
        paused: false,
      };
      this.streams.set(id, st);
      socket.on("connect", () => {
        st.connected = true;
        this.packet(VV_CONNECTED, id, Buffer.from(`${TARGET_HOST}:${TARGET_PORT}`, "utf8"));
      });
      socket.on("data", (d) => {
        this.packet(WISP_DATA, id, d);
        st.sent = (st.sent + 1) >>> 0;
        if (!st.paused && (st.sent - st.acked) >>> 0 >= RELAY_WINDOW) {
          st.paused = true;
          socket.pause();
        }
      });
      socket.on("end", () => this.packet(VV_SHUTDOWN, id));
      socket.on("drain", () => {
        st.needDrain = false;
        if (st.used > 0) {
          this.packet(WISP_CONTINUE, id, u32le(CREDIT));
          st.used = 0;
        }
      });
      socket.on("error", () => {
        if (!this.streams.has(id)) return;
        this.streams.delete(id);
        this.packet(WISP_CLOSE, id, Buffer.from([st.connected ? CLOSE_NETWORK : CLOSE_REFUSED]));
      });
      socket.on("close", () => {
        if (!this.streams.has(id)) return;
        this.streams.delete(id);
        this.packet(WISP_CLOSE, id, Buffer.from([CLOSE_VOLUNTARY]));
      });
    } else if (type === WISP_DATA) {
      const st = this.streams.get(id);
      if (!st) return;
      st.used += 1;
      if (!st.socket.write(p)) st.needDrain = true;
      else if (st.used >= CREDIT >> 1) {
        this.packet(WISP_CONTINUE, id, u32le(CREDIT));
        st.used = 0;
      }
    } else if (type === WISP_CLOSE) {
      const st = this.streams.get(id);
      if (st) {
        this.streams.delete(id);
        st.socket.end();
      }
    } else if (type === VV_SHUTDOWN) {
      this.streams.get(id)?.socket.end();
    } else if (type === VV_ACK && p.length >= 4) {
      const st = this.streams.get(id);
      if (!st) return;
      st.acked = p.readUInt32LE(0);
      if (st.paused && (st.sent - st.acked) >>> 0 < RELAY_WINDOW) {
        st.paused = false;
        st.socket.resume();
      }
    }
  }

  /** @returns {void} */
  destroy() {
    for (const st of this.streams.values()) st.socket.destroy();
    this.streams.clear();
  }
}

const server = http.createServer((req, res) => {
  res.writeHead(req.url === "/relay-health" ? 200 : 404, { "content-type": "text/plain" });
  res.end(req.url === "/relay-health" ? "parawing-wisp-relay: OK\n" : "not found\n");
});

server.on("upgrade", (req, socket) => {
  const path = (req.url || "").split("?")[0];
  const origin = String(req.headers.origin || "").replace(/\/$/, "");
  const key = req.headers["sec-websocket-key"];
  if (path !== `/${TOKEN}`) {
    socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    return;
  }
  if (
    ALLOWED_ORIGIN &&
    origin !== ALLOWED_ORIGIN &&
    !origin.startsWith("http://localhost:") &&
    !origin.startsWith("http://127.0.0.1:")
  ) {
    socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    return;
  }
  if (!key || String(req.headers.upgrade || "").toLowerCase() !== "websocket") {
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return;
  }
  const accept = crypto
    .createHash("sha1")
    .update(key + WS_GUID)
    .digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  socket.setNoDelay(true);
  let session = null;
  const ws = new WsConn(
    socket,
    (msg) => session?.onPacket(msg),
    () => session?.destroy(),
  );
  session = new RelaySession(ws);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`parawing-wisp-relay listening on 127.0.0.1:${PORT}/${TOKEN}`);
});
