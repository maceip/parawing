// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Authority Ed25519 key service, key-lease issuer, credential vault, and A1 Sealed Fill. */

import {
  CapsuleAttestationError,
  type CapsuleAttestationAuthority,
  type DbscSessionCredential,
  type SignedCapsuleAttestation,
  type WrappedKeyLeaseRelease,
} from "./capsule-attestation.ts";
import type { SessionId, TargetId, UserId } from "../session/identities.ts";
import { AES_256_KEY_LENGTH } from "../state/aes256-gcm.ts";
import {
  canonicalLeaseBytes,
  decodeBase64Bytes,
  encodeBase64Bytes,
  sha256Hex,
  type KeyLeasePayload,
  type SignedKeyLease,
} from "../state/key-lease.ts";

export interface VaultCredentialInput {
  readonly id: string;
  readonly userId: UserId;
  readonly origin: string;
  readonly username: string;
  readonly secret: string;
  readonly label?: string;
}

export interface MaskedVaultCredential {
  readonly id: string;
  readonly userId: UserId;
  readonly origin: string;
  readonly usernameHint: string;
  readonly label: string;
}

export interface SealedFillTargetAdapter {
  readonly targetId: TargetId;
  readonly currentUrl: string;
  setSealedOrigin(origin: string): void;
  injectSecretIntoControl(secret: string): Promise<boolean>;
}

export interface SealedFillResult {
  readonly ok: true;
  readonly targetId: TargetId;
  readonly sealedOrigin: string;
  readonly credentialId: string;
}

export interface MirroredAuditRecord {
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

export class SealedOriginMismatchError extends Error {
  readonly targetOrigin: string | null;
  readonly credentialOrigin: string;

  constructor(targetOrigin: string | null, credentialOrigin: string) {
    super(
      `A1 Sealed Fill origin mismatch: target=${targetOrigin ?? "opaque"}` +
        ` credential=${credentialOrigin}`,
    );
    this.name = "SealedOriginMismatchError";
    this.targetOrigin = targetOrigin;
    this.credentialOrigin = credentialOrigin;
  }
}

export class CredentialNotFoundError extends Error {
  constructor(origin: string, credentialId?: string) {
    super(`No credential bound to origin ${origin}${credentialId ? ` (id=${credentialId})` : ""}`);
    this.name = "CredentialNotFoundError";
  }
}

export function normalizeStrictOrigin(rawUrlOrOrigin: string): string | null {
  try {
    const url = new URL(rawUrlOrOrigin);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.origin === "null") return null;
    return url.origin;
  } catch {
    return null;
  }
}

function toArrayBufferCopy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

function maskUsername(username: string): string {
  if (username.length <= 2) return "**";
  return `${username.slice(0, 2)}***`;
}

export class AuthorityVaultAndChannel {
  readonly keyId: string;
  readonly publicKey: CryptoKey;
  private readonly privateKey: CryptoKey;
  private readonly publicKeySpkiBytes: Uint8Array;
  private readonly credentials = new Map<string, VaultCredentialInput>();
  private readonly issuedLeases = new Map<string, KeyLeasePayload>();
  private readonly revokedLeases = new Set<string>();
  private readonly mirroredAudit: MirroredAuditRecord[] = [];
  private readonly now: () => number;
  private attestationAuthority: CapsuleAttestationAuthority | null;

  private constructor(
    keyId: string,
    keyPair: CryptoKeyPair,
    publicKeySpkiBytes: Uint8Array,
    now: () => number,
    attestationAuthority: CapsuleAttestationAuthority | null = null,
  ) {
    this.keyId = keyId;
    this.publicKey = keyPair.publicKey;
    this.privateKey = keyPair.privateKey;
    this.publicKeySpkiBytes = publicKeySpkiBytes;
    this.now = now;
    this.attestationAuthority = attestationAuthority;
  }

  static async create(
    options: {
      keyId?: string;
      now?: () => number;
      attestationAuthority?: CapsuleAttestationAuthority;
    } = {},
  ): Promise<AuthorityVaultAndChannel> {
    const generated = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ]);
    if (!("privateKey" in generated) || !("publicKey" in generated)) {
      throw new Error("Expected Ed25519 key pair from crypto.subtle.generateKey");
    }
    const spki = await crypto.subtle.exportKey("spki", generated.publicKey);
    if (!(spki instanceof ArrayBuffer)) {
      throw new Error("Expected SPKI public key as ArrayBuffer");
    }
    const keyId = options.keyId ?? `auth-${crypto.randomUUID().slice(0, 8)}`;
    return new AuthorityVaultAndChannel(
      keyId,
      generated,
      new Uint8Array(spki),
      options.now ?? ((): number => Date.now()),
      options.attestationAuthority ?? null,
    );
  }

  setCapsuleAttestationAuthority(attestationAuthority: CapsuleAttestationAuthority | null): void {
    this.attestationAuthority = attestationAuthority;
  }

  getCapsuleAttestationAuthority(): CapsuleAttestationAuthority | null {
    return this.attestationAuthority;
  }

  get publicKeySpkiBase64(): string {
    return encodeBase64Bytes(this.publicKeySpkiBytes);
  }

  async signBytes(message: Uint8Array): Promise<string> {
    const sig = await crypto.subtle.sign("Ed25519", this.privateKey, toArrayBufferCopy(message));
    return encodeBase64Bytes(new Uint8Array(sig));
  }

  async verifyBytes(message: Uint8Array, signatureBase64: string): Promise<boolean> {
    const sigBytes = decodeBase64Bytes(signatureBase64);
    return crypto.subtle.verify(
      "Ed25519",
      this.publicKey,
      toArrayBufferCopy(sigBytes),
      toArrayBufferCopy(message),
    );
  }

  private async buildCandidateLease(params: {
    readonly userId: UserId;
    readonly sessionId: SessionId;
    readonly ttlMs: number;
    readonly epoch?: number;
    readonly leaseId?: string;
  }): Promise<SignedKeyLease> {
    if (params.ttlMs <= 0) {
      throw new RangeError(`Key lease ttlMs must be positive, got ${params.ttlMs}`);
    }
    const keyBytes = new Uint8Array(AES_256_KEY_LENGTH);
    crypto.getRandomValues(keyBytes);
    const keyDigestHex = await sha256Hex(keyBytes);
    const issuedAt = this.now();
    const payload: KeyLeasePayload = {
      leaseId: params.leaseId ?? `lease-${crypto.randomUUID()}`,
      userId: params.userId,
      sessionId: params.sessionId,
      keyDigestHex,
      issuedAt,
      expiresAt: issuedAt + params.ttlMs,
      epoch: params.epoch ?? 1,
    };
    const signatureBase64 = await this.signBytes(canonicalLeaseBytes(payload));
    return { payload, signatureBase64, keyBytes };
  }

  async issueKeyLease(params: {
    readonly userId: UserId;
    readonly sessionId: SessionId;
    readonly ttlMs: number;
    readonly epoch?: number;
    readonly leaseId?: string;
    readonly attestation?: SignedCapsuleAttestation;
  }): Promise<SignedKeyLease> {
    const candidate = await this.buildCandidateLease(params);
    if (this.attestationAuthority) {
      if (!params.attestation) {
        throw new CapsuleAttestationError(
          "invalid-input",
          "A5 capsule attestation is required when attestation authority is configured",
        );
      }
      await this.attestationAuthority.releaseWrappedKeyLease(
        params.attestation,
        candidate,
        this.now(),
      );
    }
    this.issuedLeases.set(candidate.payload.leaseId, candidate.payload);
    return candidate;
  }

  async issueAttestedKeyLease(params: {
    readonly attestation: SignedCapsuleAttestation;
    readonly userId: UserId;
    readonly sessionId: SessionId;
    readonly ttlMs: number;
    readonly epoch?: number;
    readonly leaseId?: string;
    readonly nowMs?: number;
  }): Promise<{
    readonly signedLease: SignedKeyLease;
    readonly wrappedRelease: WrappedKeyLeaseRelease;
  }> {
    if (!this.attestationAuthority) {
      throw new CapsuleAttestationError(
        "invalid-input",
        "Capsule attestation authority is not configured",
      );
    }
    const candidate = await this.buildCandidateLease(params);
    const nowMs = params.nowMs ?? this.now();
    const wrappedRelease = await this.attestationAuthority.releaseWrappedKeyLease(
      params.attestation,
      candidate,
      nowMs,
    );
    this.issuedLeases.set(candidate.payload.leaseId, candidate.payload);
    return { signedLease: candidate, wrappedRelease };
  }

  async releaseAttestedDbsc(params: {
    readonly attestation: SignedCapsuleAttestation;
    readonly dbscSessionId: string;
    readonly origin: string;
    readonly challenge: string;
    readonly nowMs?: number;
  }): Promise<DbscSessionCredential> {
    if (!this.attestationAuthority) {
      throw new CapsuleAttestationError(
        "invalid-input",
        "Capsule attestation authority is not configured",
      );
    }
    return this.attestationAuthority.releaseDbscCredential(
      params.attestation,
      {
        dbscSessionId: params.dbscSessionId,
        origin: params.origin,
        challenge: params.challenge,
      },
      params.nowMs ?? this.now(),
    );
  }

  revokeLease(leaseId: string): void {
    this.revokedLeases.add(leaseId);
  }

  isLeaseRevoked(leaseId: string): boolean {
    return this.revokedLeases.has(leaseId);
  }

  getIssuedLease(leaseId: string): KeyLeasePayload | undefined {
    return this.issuedLeases.get(leaseId);
  }

  storeCredential(input: VaultCredentialInput): MaskedVaultCredential {
    const strictOrigin = normalizeStrictOrigin(input.origin);
    if (!strictOrigin) {
      throw new TypeError(`Invalid credential origin: ${input.origin}`);
    }
    const normalized: VaultCredentialInput = {
      ...input,
      origin: strictOrigin,
      label: input.label ?? input.id,
    };
    this.credentials.set(this.credKey(normalized.userId, normalized.id), normalized);
    return {
      id: normalized.id,
      userId: normalized.userId,
      origin: strictOrigin,
      usernameHint: maskUsername(normalized.username),
      label: normalized.label ?? normalized.id,
    };
  }

  listMaskedCredentials(userId: UserId, originOrUrl: string): MaskedVaultCredential[] {
    const targetOrigin = normalizeStrictOrigin(originOrUrl);
    if (!targetOrigin) return [];
    const out: MaskedVaultCredential[] = [];
    for (const cred of this.credentials.values()) {
      if (cred.userId !== userId || cred.origin !== targetOrigin) continue;
      out.push({
        id: cred.id,
        userId: cred.userId,
        origin: cred.origin,
        usernameHint: maskUsername(cred.username),
        label: cred.label ?? cred.id,
      });
    }
    return out;
  }

  lookupCredentialSecretForOrigin(
    userId: UserId,
    targetUrl: string,
    credentialId?: string,
  ): { credentialId: string; origin: string; username: string; secret: string } {
    const targetOrigin = normalizeStrictOrigin(targetUrl);
    if (!targetOrigin) {
      throw new SealedOriginMismatchError(null, "non-opaque origin");
    }
    if (credentialId) {
      const explicit = this.credentials.get(this.credKey(userId, credentialId));
      if (!explicit) throw new CredentialNotFoundError(targetOrigin, credentialId);
      if (explicit.origin !== targetOrigin) {
        throw new SealedOriginMismatchError(targetOrigin, explicit.origin);
      }
      return {
        credentialId: explicit.id,
        origin: explicit.origin,
        username: explicit.username,
        secret: explicit.secret,
      };
    }
    for (const cred of this.credentials.values()) {
      if (cred.userId === userId && cred.origin === targetOrigin) {
        return {
          credentialId: cred.id,
          origin: cred.origin,
          username: cred.username,
          secret: cred.secret,
        };
      }
    }
    throw new CredentialNotFoundError(targetOrigin);
  }

  /** Perform A1 Sealed Fill: mark target sealed before injecting secret; never return secret. */
  async performSealedFill(params: {
    readonly userId: UserId;
    readonly target: SealedFillTargetAdapter;
    readonly credentialId?: string;
    readonly field?: "password" | "username";
  }): Promise<SealedFillResult> {
    const resolved = this.lookupCredentialSecretForOrigin(
      params.userId,
      params.target.currentUrl,
      params.credentialId,
    );
    params.target.setSealedOrigin(resolved.origin);
    const valueToInject = params.field === "username" ? resolved.username : resolved.secret;
    const filled = await params.target.injectSecretIntoControl(valueToInject);
    if (!filled) {
      throw new Error("A1 Sealed Fill could not inject credential into target control");
    }
    return {
      ok: true,
      targetId: params.target.targetId,
      sealedOrigin: resolved.origin,
      credentialId: resolved.credentialId,
    };
  }

  receiveAuditMirror(entry: MirroredAuditRecord): void {
    this.mirroredAudit.push(structuredClone(entry));
  }

  getMirroredAudit(): readonly MirroredAuditRecord[] {
    return this.mirroredAudit;
  }

  private credKey(userId: UserId, id: string): string {
    return `${userId}\u0000${id}`;
  }
}
