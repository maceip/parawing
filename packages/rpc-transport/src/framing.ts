// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Implements the 16-byte little-endian PRWP frame encoder and streaming incremental decoder.

export const PRWP_MAGIC = 0x50525750;
export const PRWP_VERSION = 1;
export const PRWP_HEADER_BYTES = 16;
export const DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;

export const FrameType = {
  HANDSHAKE: 1,
  CALL: 2,
  REPLY: 3,
  CALLBACK: 4,
  CANCEL: 5,
  DISPOSE: 6,
  BINARY_CHUNK: 7,
  CREDIT: 8,
  ERROR: 9,
  PREPARE_FREEZE: 10,
  FREEZE_READY: 11,
} as const;

export type FrameTypeCode = (typeof FrameType)[keyof typeof FrameType];

export const FrameFlag = {
  NONE: 0,
  FIN: 1 << 0,
  HAS_BINARY: 1 << 1,
  PHASE_CALL: 1 << 2,
  PHASE_REPLY: 1 << 3,
  PHASE_CALLBACK: 1 << 4,
} as const;

export interface FrameHeader {
  magic: number;
  version: number;
  frameType: FrameTypeCode;
  flags: number;
  requestId: number;
  payloadLen: number;
}

export interface RpcFrame {
  frameType: FrameTypeCode;
  flags?: number;
  requestId: number;
  payload: Uint8Array;
}

const VALID_FRAME_TYPES = new Set<number>(Object.values(FrameType));

export function isValidFrameType(code: number): code is FrameTypeCode {
  return VALID_FRAME_TYPES.has(code);
}

export function encodeFrame(frame: RpcFrame): Uint8Array {
  const payload = frame.payload;
  const out = new Uint8Array(PRWP_HEADER_BYTES + payload.byteLength);
  const view = new DataView(out.buffer, out.byteOffset, PRWP_HEADER_BYTES);
  view.setUint32(0, PRWP_MAGIC, true);
  view.setUint8(4, PRWP_VERSION);
  view.setUint8(5, frame.frameType);
  view.setUint16(6, (frame.flags ?? FrameFlag.NONE) & 0xffff, true);
  view.setUint32(8, frame.requestId >>> 0, true);
  view.setUint32(12, payload.byteLength >>> 0, true);
  if (payload.byteLength > 0) {
    out.set(payload, PRWP_HEADER_BYTES);
  }
  return out;
}

export function decodeHeader(bytes: Uint8Array, offset = 0): FrameHeader {
  if (bytes.byteLength - offset < PRWP_HEADER_BYTES) {
    throw new Error("PRWP frame header truncated");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, PRWP_HEADER_BYTES);
  const magic = view.getUint32(0, true);
  if (magic !== PRWP_MAGIC) {
    throw new Error(`Invalid PRWP magic: 0x${magic.toString(16)}`);
  }
  const version = view.getUint8(4);
  if (version !== PRWP_VERSION) {
    throw new Error(`Unsupported PRWP version: ${version}`);
  }
  const rawType = view.getUint8(5);
  if (!isValidFrameType(rawType)) {
    throw new Error(`Unknown PRWP frame type: ${rawType}`);
  }
  return {
    magic,
    version,
    frameType: rawType,
    flags: view.getUint16(6, true),
    requestId: view.getUint32(8, true),
    payloadLen: view.getUint32(12, true),
  };
}

export class FrameDecoder {
  #buffer: Uint8Array = new Uint8Array(4096);
  #readPos = 0;
  #writePos = 0;
  #maxPayloadBytes: number;

  constructor(maxPayloadBytes = DEFAULT_MAX_PAYLOAD_BYTES) {
    this.#maxPayloadBytes = maxPayloadBytes;
  }

  push(chunk: Uint8Array): Array<{ header: FrameHeader; payload: Uint8Array }> {
    if (chunk.byteLength > 0) {
      this.#append(chunk);
    }
    const frames: Array<{ header: FrameHeader; payload: Uint8Array }> = [];
    while (this.#available() >= PRWP_HEADER_BYTES) {
      const header = decodeHeader(this.#buffer, this.#readPos);
      if (header.payloadLen > this.#maxPayloadBytes) {
        throw new Error(`PRWP payload ${header.payloadLen} exceeds max ${this.#maxPayloadBytes}`);
      }
      const totalBytes = PRWP_HEADER_BYTES + header.payloadLen;
      if (this.#available() < totalBytes) break;
      const payloadStart = this.#readPos + PRWP_HEADER_BYTES;
      const payload = this.#buffer.slice(payloadStart, payloadStart + header.payloadLen);
      this.#readPos += totalBytes;
      frames.push({ header, payload });
    }
    this.#compactIfNeeded();
    return frames;
  }

  #available(): number {
    return this.#writePos - this.#readPos;
  }

  #append(chunk: Uint8Array): void {
    const needed = chunk.byteLength;
    const freeTail = this.#buffer.byteLength - this.#writePos;
    if (freeTail < needed) {
      this.#compact();
    }
    if (this.#buffer.byteLength - this.#writePos < needed) {
      const current = this.#available();
      let nextSize = Math.max(this.#buffer.byteLength * 2, current + needed);
      if (nextSize < 4096) nextSize = 4096;
      const grown = new Uint8Array(nextSize);
      grown.set(this.#buffer.subarray(this.#readPos, this.#writePos), 0);
      this.#buffer = grown;
      this.#readPos = 0;
      this.#writePos = current;
    }
    this.#buffer.set(chunk, this.#writePos);
    this.#writePos += needed;
  }

  #compact(): void {
    if (this.#readPos === 0) return;
    const len = this.#available();
    if (len > 0) {
      this.#buffer.copyWithin(0, this.#readPos, this.#writePos);
    }
    this.#readPos = 0;
    this.#writePos = len;
  }

  #compactIfNeeded(): void {
    if (this.#readPos === this.#writePos) {
      this.#readPos = 0;
      this.#writePos = 0;
      return;
    }
    if (this.#readPos > this.#buffer.byteLength >>> 1) {
      this.#compact();
    }
  }
}
