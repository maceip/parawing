// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Synchronous NIST SP 800-38D AES-256-GCM AEAD for portable Web Worker stores. */

const SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const RCON = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

export const AES_256_KEY_LENGTH = 32;
export const GCM_NONCE_LENGTH = 12;
export const GCM_TAG_LENGTH = 16;

function expandKey256(key: Uint8Array): Uint8Array {
  if (key.length !== AES_256_KEY_LENGTH) {
    throw new RangeError(`Expected 32-byte AES-256 key, got ${key.length}`);
  }
  const rk = new Uint8Array(240);
  rk.set(key, 0);
  const temp = new Uint8Array(4);

  for (let wordIdx = 8; wordIdx < 60; wordIdx += 1) {
    const prevOff = (wordIdx - 1) * 4;
    temp[0] = rk[prevOff] ?? 0;
    temp[1] = rk[prevOff + 1] ?? 0;
    temp[2] = rk[prevOff + 2] ?? 0;
    temp[3] = rk[prevOff + 3] ?? 0;

    if (wordIdx % 8 === 0) {
      const rot = temp[0] ?? 0;
      temp[0] = SBOX[temp[1] ?? 0] ?? 0;
      temp[1] = SBOX[temp[2] ?? 0] ?? 0;
      temp[2] = SBOX[temp[3] ?? 0] ?? 0;
      temp[3] = SBOX[rot] ?? 0;
      temp[0] = (temp[0] ?? 0) ^ (RCON[wordIdx / 8 - 1] ?? 0);
    } else if (wordIdx % 8 === 4) {
      temp[0] = SBOX[temp[0] ?? 0] ?? 0;
      temp[1] = SBOX[temp[1] ?? 0] ?? 0;
      temp[2] = SBOX[temp[2] ?? 0] ?? 0;
      temp[3] = SBOX[temp[3] ?? 0] ?? 0;
    }

    const baseOff = (wordIdx - 8) * 4;
    const outOff = wordIdx * 4;
    rk[outOff] = (rk[baseOff] ?? 0) ^ (temp[0] ?? 0);
    rk[outOff + 1] = (rk[baseOff + 1] ?? 0) ^ (temp[1] ?? 0);
    rk[outOff + 2] = (rk[baseOff + 2] ?? 0) ^ (temp[2] ?? 0);
    rk[outOff + 3] = (rk[baseOff + 3] ?? 0) ^ (temp[3] ?? 0);
  }
  temp.fill(0);
  return rk;
}

function xtime(value: number): number {
  return ((value << 1) ^ ((value & 0x80) !== 0 ? 0x1b : 0)) & 0xff;
}

function addRoundKey(state: Uint8Array, rk: Uint8Array, round: number): void {
  const off = round * 16;
  for (let i = 0; i < 16; i += 1) {
    state[i] = (state[i] ?? 0) ^ (rk[off + i] ?? 0);
  }
}

function subAndShiftRows(state: Uint8Array): void {
  for (let i = 0; i < 16; i += 1) {
    state[i] = SBOX[state[i] ?? 0] ?? 0;
  }
  const r1 = state[1] ?? 0;
  state[1] = state[5] ?? 0;
  state[5] = state[9] ?? 0;
  state[9] = state[13] ?? 0;
  state[13] = r1;

  const r2a = state[2] ?? 0;
  const r2b = state[6] ?? 0;
  state[2] = state[10] ?? 0;
  state[6] = state[14] ?? 0;
  state[10] = r2a;
  state[14] = r2b;

  const r3 = state[15] ?? 0;
  state[15] = state[11] ?? 0;
  state[11] = state[7] ?? 0;
  state[7] = state[3] ?? 0;
  state[3] = r3;
}

function mixColumns(state: Uint8Array): void {
  for (let col = 0; col < 16; col += 4) {
    const a = state[col] ?? 0;
    const b = state[col + 1] ?? 0;
    const c = state[col + 2] ?? 0;
    const d = state[col + 3] ?? 0;
    const xorAll = a ^ b ^ c ^ d;
    state[col] = a ^ xorAll ^ xtime(a ^ b);
    state[col + 1] = b ^ xorAll ^ xtime(b ^ c);
    state[col + 2] = c ^ xorAll ^ xtime(c ^ d);
    state[col + 3] = d ^ xorAll ^ xtime(d ^ a);
  }
}

function aes256EncryptBlock(rk: Uint8Array, block: Uint8Array, out: Uint8Array): void {
  const state = new Uint8Array(16);
  state.set(block.subarray(0, 16), 0);
  addRoundKey(state, rk, 0);
  for (let round = 1; round < 14; round += 1) {
    subAndShiftRows(state);
    mixColumns(state);
    addRoundKey(state, rk, round);
  }
  subAndShiftRows(state);
  addRoundKey(state, rk, 14);
  out.set(state, 0);
}

function inc32(counterBlock: Uint8Array): void {
  for (let i = 15; i >= 12; i -= 1) {
    const next = ((counterBlock[i] ?? 0) + 1) & 0xff;
    counterBlock[i] = next;
    if (next !== 0) break;
  }
}

function shiftRightOneBit(v: Uint8Array): void {
  let carry = 0;
  for (let i = 0; i < 16; i += 1) {
    const b = v[i] ?? 0;
    v[i] = (b >>> 1) | carry;
    carry = (b & 1) << 7;
  }
}

function mulGf128(x: Uint8Array, y: Uint8Array): Uint8Array {
  const z = new Uint8Array(16);
  const v = y.slice();
  for (let i = 0; i < 128; i += 1) {
    const bit = ((x[i >> 3] ?? 0) >> (7 - (i & 7))) & 1;
    if (bit !== 0) {
      for (let j = 0; j < 16; j += 1) {
        z[j] = (z[j] ?? 0) ^ (v[j] ?? 0);
      }
    }
    const lsb = (v[15] ?? 0) & 1;
    shiftRightOneBit(v);
    if (lsb !== 0) {
      v[0] = (v[0] ?? 0) ^ 0xe1;
    }
  }
  return z;
}

function xorBlock(dst: Uint8Array, src: Uint8Array, srcLen: number): void {
  for (let i = 0; i < srcLen; i += 1) {
    dst[i] = (dst[i] ?? 0) ^ (src[i] ?? 0);
  }
}

function ghashUpdateBytes(acc: Uint8Array, h: Uint8Array, data: Uint8Array): Uint8Array {
  let current = acc;
  for (let off = 0; off < data.length; off += 16) {
    const slice = data.subarray(off, Math.min(off + 16, data.length));
    xorBlock(current, slice, slice.length);
    current = mulGf128(current, h);
  }
  return current;
}

function writeUint64Bits(out: Uint8Array, off: number, byteLen: number): void {
  const bits = BigInt(byteLen) * 8n;
  for (let i = 7; i >= 0; i -= 1) {
    out[off + i] = Number((bits >> BigInt((7 - i) * 8)) & 0xffn);
  }
}

function computeGhash(h: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  let acc: Uint8Array = new Uint8Array(16);
  acc = ghashUpdateBytes(acc, h, aad);
  acc = ghashUpdateBytes(acc, h, ciphertext);
  const lenBlock = new Uint8Array(16);
  writeUint64Bits(lenBlock, 0, aad.length);
  writeUint64Bits(lenBlock, 8, ciphertext.length);
  xorBlock(acc, lenBlock, 16);
  return mulGf128(acc, h);
}

function deriveJ0(h: Uint8Array, nonce: Uint8Array): Uint8Array {
  if (nonce.length === GCM_NONCE_LENGTH) {
    const j0 = new Uint8Array(16);
    j0.set(nonce, 0);
    j0[15] = 1;
    return j0;
  }
  return computeGhash(h, new Uint8Array(0), nonce);
}

function gctr(rk: Uint8Array, icb: Uint8Array, input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.length);
  const cb = icb.slice();
  const keystream = new Uint8Array(16);
  for (let off = 0; off < input.length; off += 16) {
    aes256EncryptBlock(rk, cb, keystream);
    const len = Math.min(16, input.length - off);
    for (let i = 0; i < len; i += 1) {
      out[off + i] = (input[off + i] ?? 0) ^ (keystream[i] ?? 0);
    }
    inc32(cb);
  }
  return out;
}

export interface AesGcmEncrypted {
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

export function encryptAes256Gcm(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): AesGcmEncrypted {
  const rk = expandKey256(key);
  const h = new Uint8Array(16);
  aes256EncryptBlock(rk, new Uint8Array(16), h);
  try {
    const j0 = deriveJ0(h, nonce);
    const icb = j0.slice();
    inc32(icb);
    const ciphertext = gctr(rk, icb, plaintext);
    const s = computeGhash(h, aad, ciphertext);
    const tag = gctr(rk, j0, s);
    return { ciphertext, tag };
  } finally {
    rk.fill(0);
    h.fill(0);
  }
}

export function decryptAes256Gcm(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (tag.length !== GCM_TAG_LENGTH) {
    throw new Error(`Invalid AES-GCM tag length: ${tag.length}`);
  }
  const rk = expandKey256(key);
  const h = new Uint8Array(16);
  aes256EncryptBlock(rk, new Uint8Array(16), h);
  try {
    const j0 = deriveJ0(h, nonce);
    const s = computeGhash(h, aad, ciphertext);
    const expectedTag = gctr(rk, j0, s);
    let diff = 0;
    for (let i = 0; i < GCM_TAG_LENGTH; i += 1) {
      diff |= (expectedTag[i] ?? 0) ^ (tag[i] ?? 0);
    }
    if (diff !== 0) {
      throw new Error("AES-256-GCM authentication tag verification failed");
    }
    const icb = j0.slice();
    inc32(icb);
    return gctr(rk, icb, ciphertext);
  } finally {
    rk.fill(0);
    h.fill(0);
  }
}
