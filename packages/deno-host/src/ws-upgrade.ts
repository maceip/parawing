// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Minimal RFC 6455 WebSocket upgrade and frame codec over Node HTTP sockets.

import { createHash } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import type {
  CdpSessionCloseEvent,
  CdpSessionErrorEvent,
  CdpSessionTransport,
} from "../dist/engine-bundle.mjs";

const WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME_BYTES = 64 * 1024 * 1024;
const CLOSE_GRACE_MS = 250;

interface ParsedFrame {
  fin: boolean;
  opcode: number;
  payload: Buffer;
  consumed: number;
}

function decodeLengthAndMaskOffset(
  buf: Buffer,
  len7: number,
  masked: boolean,
): { payloadLen: number; headerBytes: number } | "need-more" | "too-large" {
  let offset = 2;
  let payloadLen = len7;
  if (len7 === 126) {
    if (buf.length < offset + 2) return "need-more";
    payloadLen = buf.readUInt16BE(offset);
    offset += 2;
  } else if (len7 === 127) {
    if (buf.length < offset + 8) return "need-more";
    const big = buf.readBigUInt64BE(offset);
    if (big > BigInt(MAX_FRAME_BYTES)) return "too-large";
    payloadLen = Number(big);
    offset += 8;
  }
  if (payloadLen > MAX_FRAME_BYTES) return "too-large";
  return { payloadLen, headerBytes: offset + (masked ? 4 : 0) };
}

function tryParseFrame(buf: Buffer): ParsedFrame | "need-more" | "protocol-error" | "too-large" {
  if (buf.length < 2) return "need-more";
  const b0 = buf[0] ?? 0;
  const b1 = buf[1] ?? 0;
  const fin = (b0 & 0x80) !== 0;
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  if (!masked) return "protocol-error";
  if ((b0 & 0x70) !== 0) return "protocol-error";

  const lenInfo = decodeLengthAndMaskOffset(buf, b1 & 0x7f, masked);
  if (typeof lenInfo === "string") return lenInfo;
  const totalBytes = lenInfo.headerBytes + lenInfo.payloadLen;
  if (buf.length < totalBytes) return "need-more";

  const maskStart = lenInfo.headerBytes - 4;
  const payload = Buffer.allocUnsafe(lenInfo.payloadLen);
  for (let i = 0; i < lenInfo.payloadLen; i++) {
    payload[i] = (buf[lenInfo.headerBytes + i] ?? 0) ^ (buf[maskStart + (i & 3)] ?? 0);
  }
  return { fin, opcode, payload, consumed: totalBytes };
}

function encodeFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length;
  const extBytes = len < 126 ? 0 : len <= 0xffff ? 2 : 8;
  const header = Buffer.allocUnsafe(2 + extBytes);
  header[0] = 0x80 | (opcode & 0x0f);
  if (len < 126) {
    header[1] = len;
  } else if (len <= 0xffff) {
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

function parseClosePayload(payload: Buffer): { code: number; reason: string } {
  if (payload.length < 2) return { code: 1005, reason: "" };
  return {
    code: payload.readUInt16BE(0),
    reason: payload.subarray(2).toString("utf8"),
  };
}

function encodeClosePayload(code: number, reason: string): Buffer {
  const safeCode = code >= 1000 && code <= 4999 ? code : 1000;
  const reasonBytes = Buffer.from(reason, "utf8").subarray(0, 123);
  const out = Buffer.allocUnsafe(2 + reasonBytes.length);
  out.writeUInt16BE(safeCode, 0);
  reasonBytes.copy(out, 2);
  return out;
}

export function acceptWebSocketUpgrade(
  req: IncomingMessage,
  socket: Duplex,
  head: Buffer,
): CdpSessionTransport | null {
  const upgradeHdr = req.headers.upgrade;
  const keyHdr = req.headers["sec-websocket-key"];
  if (
    !upgradeHdr ||
    upgradeHdr.toLowerCase() !== "websocket" ||
    typeof keyHdr !== "string" ||
    !keyHdr
  ) {
    return null;
  }

  const acceptKey = createHash("sha1").update(`${keyHdr.trim()}${WS_MAGIC_GUID}`).digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${acceptKey}\r\n\r\n`,
  );

  let rxBuf: Buffer = Buffer.alloc(0);
  let closed = false;
  let closeSent = false;
  let fragOpcode = 0;
  let fragChunks: Buffer[] = [];
  let fragBytes = 0;

  const messageHandlers: Array<(data: string | ArrayBuffer) => void> = [];
  const closeHandlers: Array<(ev: CdpSessionCloseEvent) => void> = [];
  const errorHandlers: Array<(ev: CdpSessionErrorEvent) => void> = [];
  const earlyMessages: Array<string | ArrayBuffer> = [];

  const emitMessage = (msg: string | ArrayBuffer): void => {
    if (messageHandlers.length === 0) {
      earlyMessages.push(msg);
      return;
    }
    for (const h of messageHandlers) h(msg);
  };

  const emitClose = (code: number, reason: string, wasClean: boolean): void => {
    if (closed) return;
    closed = true;
    for (const h of closeHandlers) h({ code, reason, wasClean });
  };

  const emitError = (err: unknown): void => {
    const message = err instanceof Error ? err.message : String(err);
    const error =
      err instanceof Error ? { name: err.name, message: err.message, stack: err.stack } : undefined;
    for (const h of errorHandlers) h({ message, type: "error", error });
  };

  const closeConnection = (code = 1000, reason = ""): void => {
    if (!closeSent && socket.writable) {
      closeSent = true;
      try {
        socket.write(encodeFrame(0x8, encodeClosePayload(code, reason)));
      } catch {}
    }
    if (!socket.destroyed) {
      socket.end();
      const destroyTimer = setTimeout(() => {
        if (!socket.destroyed) socket.destroy();
      }, CLOSE_GRACE_MS);
      destroyTimer.unref?.();
    }
    emitClose(code, reason, true);
  };

  const dispatchDataMessage = (opcode: number, payload: Buffer): void => {
    if (opcode === 0x1) {
      emitMessage(payload.toString("utf8"));
      return;
    }
    const copy = new Uint8Array(payload).buffer;
    emitMessage(copy);
  };

  const handleControlFrame = (frame: ParsedFrame): void => {
    if (frame.opcode === 0x9) {
      if (socket.writable) socket.write(encodeFrame(0xa, frame.payload));
      return;
    }
    if (frame.opcode === 0x8) {
      const info = parseClosePayload(frame.payload);
      closeConnection(info.code === 1005 ? 1000 : info.code, info.reason);
    }
  };

  const handleDataFrame = (frame: ParsedFrame): boolean => {
    if (frame.opcode !== 0x0) {
      if (fragOpcode !== 0) {
        closeConnection(1002, "unexpected non-continuation frame");
        return false;
      }
      if (frame.opcode !== 0x1 && frame.opcode !== 0x2) {
        closeConnection(1003, "unsupported opcode");
        return false;
      }
      if (frame.fin) {
        dispatchDataMessage(frame.opcode, frame.payload);
        return true;
      }
      fragOpcode = frame.opcode;
      fragChunks = [frame.payload];
      fragBytes = frame.payload.length;
      return true;
    }

    if (fragOpcode === 0) {
      closeConnection(1002, "unexpected continuation frame");
      return false;
    }
    fragBytes += frame.payload.length;
    if (fragBytes > MAX_FRAME_BYTES) {
      closeConnection(1009, "message too large");
      return false;
    }
    fragChunks.push(frame.payload);
    if (frame.fin) {
      const full = Buffer.concat(fragChunks);
      const op = fragOpcode;
      fragOpcode = 0;
      fragChunks = [];
      fragBytes = 0;
      dispatchDataMessage(op, full);
    }
    return true;
  };

  const pumpBuffer = (chunk: Buffer): void => {
    if (closed || chunk.length === 0) return;
    rxBuf = rxBuf.length > 0 ? Buffer.concat([rxBuf, chunk]) : chunk;
    while (!closed && rxBuf.length > 0) {
      const parsed = tryParseFrame(rxBuf);
      if (parsed === "need-more") return;
      if (parsed === "too-large") {
        closeConnection(1009, "frame too large");
        return;
      }
      if (parsed === "protocol-error") {
        closeConnection(1002, "protocol error");
        return;
      }
      rxBuf = rxBuf.subarray(parsed.consumed);
      if ((parsed.opcode & 0x08) !== 0) {
        handleControlFrame(parsed);
        continue;
      }
      if (!handleDataFrame(parsed)) return;
    }
  };

  socket.on("data", pumpBuffer);
  socket.once("end", () => {
    closeConnection(1000, "");
  });
  socket.on("error", (err) => {
    emitError(err);
    emitClose(1006, err.message, false);
  });
  socket.on("close", (hadError) => {
    emitClose(hadError ? 1006 : 1000, "", !hadError);
  });

  if (head.length > 0) {
    queueMicrotask(() => pumpBuffer(head));
  }

  return {
    send(data: string): void {
      if (closed || !socket.writable) return;
      socket.write(encodeFrame(0x1, Buffer.from(data, "utf8")));
    },
    close(code?: number, reason?: string): void {
      closeConnection(code, reason);
    },
    onMessage(handler: (data: string | ArrayBuffer) => void): void {
      messageHandlers.push(handler);
      while (earlyMessages.length > 0) {
        const msg = earlyMessages.shift();
        if (msg !== undefined) handler(msg);
      }
    },
    onClose(handler: (ev: CdpSessionCloseEvent) => void): void {
      closeHandlers.push(handler);
    },
    onError(handler: (ev: CdpSessionErrorEvent) => void): void {
      errorHandlers.push(handler);
    },
  };
}
