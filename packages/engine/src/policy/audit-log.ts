// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** SHA-256 hash-chained, Ed25519-signed audit log mirrored to Authority. */

import type {
  AuthorityVaultAndChannel,
  MirroredAuditRecord,
} from "../authority/authority-service.ts";
import type { SessionId, TargetId, UserId } from "../session/identities.ts";
import { decodeBase64Bytes, sha256Hex } from "../state/key-lease.ts";

export interface AuditEventInput {
  readonly kind: string;
  readonly sessionId?: SessionId;
  readonly userId?: UserId;
  readonly targetId?: TargetId;
  readonly detail?: Record<string, unknown>;
  readonly timestamp?: number;
}

export interface SignedAuditEntry {
  readonly seq: number;
  readonly prevHash: string;
  readonly entryHash: string;
  readonly signatureBase64: string;
  readonly timestamp: number;
  readonly kind: string;
  readonly sessionId?: SessionId;
  readonly userId?: UserId;
  readonly targetId?: TargetId;
  readonly detail: Record<string, unknown>;
}

export interface AuditChainVerificationResult {
  readonly valid: boolean;
  readonly count: number;
  readonly failedSeq?: number;
  readonly reason?: string;
}

export const AUDIT_GENESIS_HASH = "0".repeat(64);
const TEXT_ENCODER = new TextEncoder();

function toArrayBufferCopy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

export function canonicalAuditPayload(fields: {
  readonly seq: number;
  readonly prevHash: string;
  readonly timestamp: number;
  readonly kind: string;
  readonly sessionId?: SessionId;
  readonly userId?: UserId;
  readonly targetId?: TargetId;
  readonly detail: Record<string, unknown>;
}): Uint8Array {
  const json = JSON.stringify({
    seq: fields.seq,
    prevHash: fields.prevHash,
    timestamp: fields.timestamp,
    kind: fields.kind,
    sessionId: fields.sessionId ?? null,
    userId: fields.userId ?? null,
    targetId: fields.targetId ?? null,
    detail: fields.detail,
  });
  return TEXT_ENCODER.encode(json);
}

export async function verifyAuditChain(
  entries: ReadonlyArray<SignedAuditEntry>,
  authorityPublicKey: CryptoKey,
): Promise<AuditChainVerificationResult> {
  let expectedPrevHash = AUDIT_GENESIS_HASH;
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (!entry) break;
    if (entry.seq !== i) {
      return {
        valid: false,
        count: entries.length,
        failedSeq: i,
        reason: `Expected seq ${i}, got ${entry.seq}`,
      };
    }
    if (entry.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        count: entries.length,
        failedSeq: i,
        reason: `prevHash mismatch at seq ${i}`,
      };
    }
    const recomputed = await sha256Hex(
      canonicalAuditPayload({
        seq: entry.seq,
        prevHash: entry.prevHash,
        timestamp: entry.timestamp,
        kind: entry.kind,
        sessionId: entry.sessionId,
        userId: entry.userId,
        targetId: entry.targetId,
        detail: entry.detail,
      }),
    );
    if (recomputed !== entry.entryHash) {
      return {
        valid: false,
        count: entries.length,
        failedSeq: i,
        reason: `entryHash tamper detected at seq ${i}`,
      };
    }
    const validSig = await crypto.subtle.verify(
      "Ed25519",
      authorityPublicKey,
      toArrayBufferCopy(decodeBase64Bytes(entry.signatureBase64)),
      toArrayBufferCopy(TEXT_ENCODER.encode(entry.entryHash)),
    );
    if (!validSig) {
      return {
        valid: false,
        count: entries.length,
        failedSeq: i,
        reason: `Ed25519 signature invalid at seq ${i}`,
      };
    }
    expectedPrevHash = entry.entryHash;
  }
  return { valid: true, count: entries.length };
}

export class SignedAuditLog {
  private readonly authority: AuthorityVaultAndChannel;
  private readonly entries: SignedAuditEntry[] = [];
  private readonly now: () => number;
  private pendingTail: Promise<SignedAuditEntry> | null = null;

  constructor(authority: AuthorityVaultAndChannel, options: { now?: () => number } = {}) {
    this.authority = authority;
    this.now = options.now ?? ((): number => Date.now());
  }

  /** Append event serially so concurrent callers never fork prevHash or seq. */
  append(input: AuditEventInput): Promise<SignedAuditEntry> {
    const run = async (): Promise<SignedAuditEntry> => {
      const seq = this.entries.length;
      const prevHash = seq === 0 ? AUDIT_GENESIS_HASH : (this.entries[seq - 1]?.entryHash ?? "");
      const timestamp = input.timestamp ?? this.now();
      const detail = input.detail ? structuredClone(input.detail) : {};
      const payloadBytes = canonicalAuditPayload({
        seq,
        prevHash,
        timestamp,
        kind: input.kind,
        sessionId: input.sessionId,
        userId: input.userId,
        targetId: input.targetId,
        detail,
      });
      const entryHash = await sha256Hex(payloadBytes);
      const signatureBase64 = await this.authority.signBytes(TEXT_ENCODER.encode(entryHash));
      const entry: SignedAuditEntry = {
        seq,
        prevHash,
        entryHash,
        signatureBase64,
        timestamp,
        kind: input.kind,
        ...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
        ...(input.userId !== undefined ? { userId: input.userId } : {}),
        ...(input.targetId !== undefined ? { targetId: input.targetId } : {}),
        detail,
      };
      this.entries.push(entry);
      const mirrored: MirroredAuditRecord = structuredClone(entry);
      this.authority.receiveAuditMirror(mirrored);
      return entry;
    };

    const next = this.pendingTail ? this.pendingTail.then(run, run) : run();
    this.pendingTail = next;
    return next;
  }

  getEntries(): ReadonlyArray<SignedAuditEntry> {
    return this.entries;
  }

  async verify(): Promise<AuditChainVerificationResult> {
    return verifyAuditChain(this.entries, this.authority.publicKey);
  }
}
