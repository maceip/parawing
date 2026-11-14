// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Authority-leased AES-256 session key manager with expiry/revocation zeroization. */

import type { SessionId, UserId } from "../session/identities.ts";
import { AES_256_KEY_LENGTH } from "./aes256-gcm.ts";

export interface KeyLeasePayload {
  readonly leaseId: string;
  readonly userId: UserId;
  readonly sessionId: SessionId;
  readonly keyDigestHex: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly epoch: number;
}

export interface SignedKeyLease {
  readonly payload: KeyLeasePayload;
  readonly signatureBase64: string;
  readonly keyBytes: Uint8Array;
}

export type KeyLeaseLifecycleState = "active" | "draining" | "expired" | "revoked";

export interface KeyLeaseLifecycleHooks {
  readonly onCheckpoint?: () => void | Promise<void>;
  readonly onFlush?: () => void | Promise<void>;
  readonly onSuspend?: () => void | Promise<void>;
  readonly now?: () => number;
}

export class KeyLeaseExpiredError extends Error {
  readonly leaseId: string;
  readonly reason: "expired" | "revoked";

  constructor(leaseId: string, reason: "expired" | "revoked" = "expired") {
    super(`Key lease ${leaseId} is no longer valid (${reason})`);
    this.name = "KeyLeaseExpiredError";
    this.leaseId = leaseId;
    this.reason = reason;
  }
}

export class KeyLeaseSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyLeaseSignatureError";
  }
}

const TEXT_ENCODER = new TextEncoder();

export function canonicalLeaseBytes(payload: KeyLeasePayload): Uint8Array {
  const canonical = JSON.stringify({
    leaseId: payload.leaseId,
    userId: payload.userId,
    sessionId: payload.sessionId,
    keyDigestHex: payload.keyDigestHex,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    epoch: payload.epoch,
  });
  return TEXT_ENCODER.encode(canonical);
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy);
  const view = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < view.length; i += 1) {
    hex += (view[i] ?? 0).toString(16).padStart(2, "0");
  }
  return hex;
}

export function decodeBase64Bytes(base64: string): Uint8Array {
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function encodeBase64Bytes(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i] ?? 0);
  }
  return btoa(bin);
}

function toArrayBufferViewCopy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

export async function verifySignedKeyLease(
  lease: SignedKeyLease,
  authorityPublicKey: CryptoKey,
): Promise<void> {
  if (lease.keyBytes.length !== AES_256_KEY_LENGTH) {
    throw new KeyLeaseSignatureError(
      `Expected ${AES_256_KEY_LENGTH}-byte AES-256 key, got ${lease.keyBytes.length}`,
    );
  }
  const actualDigest = await sha256Hex(lease.keyBytes);
  if (actualDigest !== lease.payload.keyDigestHex) {
    throw new KeyLeaseSignatureError("Key bytes digest does not match signed key lease payload");
  }
  const sigBytes = toArrayBufferViewCopy(decodeBase64Bytes(lease.signatureBase64));
  const msgBytes = toArrayBufferViewCopy(canonicalLeaseBytes(lease.payload));
  const valid = await crypto.subtle.verify("Ed25519", authorityPublicKey, sigBytes, msgBytes);
  if (!valid) {
    throw new KeyLeaseSignatureError(`Invalid Authority Ed25519 signature on lease`);
  }
}

export class KeyLeaseManager {
  readonly leaseId: string;
  readonly userId: UserId;
  readonly sessionId: SessionId;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly epoch: number;

  private readonly keyBytes: Uint8Array;
  private readonly now: () => number;
  private onCheckpoint?: () => void | Promise<void>;
  private onFlush?: () => void | Promise<void>;
  private onSuspend?: () => void | Promise<void>;
  private lifecycle: KeyLeaseLifecycleState = "active";
  private pendingTermination: Promise<void> | null = null;

  private constructor(lease: SignedKeyLease, hooks: KeyLeaseLifecycleHooks = {}) {
    this.leaseId = lease.payload.leaseId;
    this.userId = lease.payload.userId;
    this.sessionId = lease.payload.sessionId;
    this.issuedAt = lease.payload.issuedAt;
    this.expiresAt = lease.payload.expiresAt;
    this.epoch = lease.payload.epoch;
    this.keyBytes = lease.keyBytes;
    this.onCheckpoint = hooks.onCheckpoint;
    this.onFlush = hooks.onFlush;
    this.onSuspend = hooks.onSuspend;
    this.now = hooks.now ?? ((): number => Date.now());
  }

  /** Verify Ed25519 Authority signature and key digest before activating lease. */
  static async createVerified(
    lease: SignedKeyLease,
    authorityPublicKey: CryptoKey,
    hooks: KeyLeaseLifecycleHooks = {},
  ): Promise<KeyLeaseManager> {
    await verifySignedKeyLease(lease, authorityPublicKey);
    const manager = new KeyLeaseManager(lease, hooks);
    if (manager.now() >= manager.expiresAt) {
      await manager.expire();
    }
    return manager;
  }

  setHooks(hooks: KeyLeaseLifecycleHooks): void {
    if (hooks.onCheckpoint !== undefined) this.onCheckpoint = hooks.onCheckpoint;
    if (hooks.onFlush !== undefined) this.onFlush = hooks.onFlush;
    if (hooks.onSuspend !== undefined) this.onSuspend = hooks.onSuspend;
  }

  get state(): KeyLeaseLifecycleState {
    return this.lifecycle;
  }

  isValid(atTime: number = this.now()): boolean {
    if (this.lifecycle === "expired" || this.lifecycle === "revoked") return false;
    if (this.lifecycle === "draining") return true;
    return atTime < this.expiresAt;
  }

  /** Return key bytes if lease is valid; triggers sync teardown and throws on clock expiry. */
  requireKeyBytes(): Uint8Array {
    if (this.lifecycle === "expired" || this.lifecycle === "revoked") {
      throw new KeyLeaseExpiredError(this.leaseId, this.lifecycle);
    }
    if (this.lifecycle === "active" && this.now() >= this.expiresAt) {
      this.terminateSync("expired");
      throw new KeyLeaseExpiredError(this.leaseId, "expired");
    }
    return this.keyBytes;
  }

  async expire(): Promise<void> {
    await this.terminateAsync("expired");
  }

  async revoke(): Promise<void> {
    await this.terminateAsync("revoked");
  }

  private terminateSync(reason: "expired" | "revoked"): void {
    if (this.lifecycle === "expired" || this.lifecycle === "revoked") return;
    this.lifecycle = "draining";
    try {
      void this.onCheckpoint?.();
      void this.onFlush?.();
    } finally {
      this.keyBytes.fill(0);
      this.lifecycle = reason;
    }
    void this.onSuspend?.();
  }

  private async terminateAsync(reason: "expired" | "revoked"): Promise<void> {
    if (this.lifecycle === "expired" || this.lifecycle === "revoked") return;
    if (this.pendingTermination) {
      await this.pendingTermination;
      return;
    }
    const run = async (): Promise<void> => {
      this.lifecycle = "draining";
      try {
        await this.onCheckpoint?.();
        await this.onFlush?.();
      } finally {
        this.keyBytes.fill(0);
        this.lifecycle = reason;
      }
      await this.onSuspend?.();
    };
    this.pendingTermination = run();
    try {
      await this.pendingTermination;
    } finally {
      this.pendingTermination = null;
    }
  }
}
