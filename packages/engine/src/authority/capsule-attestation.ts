// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// A5 Ed25519/SHA-256 capsule attestation verifier, ECDH P-256 key-lease wrap, and DBSC credential.

import { decryptAes256Gcm, encryptAes256Gcm } from "../state/aes256-gcm.ts";
import {
  decodeBase64Bytes,
  encodeBase64Bytes,
  sha256Hex,
  type SignedKeyLease,
} from "../state/key-lease.ts";

export const CAPSULE_PINNED_PAGE_SIZE = 4096;
const ATTESTATION_DOMAIN_PREFIX = "PARAWING-A5-CAP-ATTESTATION-V1\0";
const KEY_WRAP_DOMAIN = "PARAWING-A5-ECDH-WRAP-V1\0";
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy.buffer;
}

function concatBytes(parts: ReadonlyArray<Uint8Array>): Uint8Array<ArrayBuffer> {
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const out = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function base64UrlEncode(bytes: Uint8Array): string {
  return encodeBase64Bytes(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(segment: string): Uint8Array {
  const norm = segment.replace(/-/g, "+").replace(/_/g, "/");
  const pad = norm.length % 4 === 0 ? "" : "=".repeat(4 - (norm.length % 4));
  return decodeBase64Bytes(norm + pad);
}

export interface CapsuleAttestationClaims {
  readonly capsuleHash: string;
  readonly rustTarget: string;
  readonly baselineId: string;
  readonly pageSize: number;
  readonly ephemeralP256PubkeySpkiB64: string;
  readonly nonce: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

export interface SignedCapsuleAttestation {
  readonly claims: CapsuleAttestationClaims;
  readonly claimsSha256Hex: string;
  readonly signerPubkeySpkiB64: string;
  readonly signatureB64: string;
}

export interface WrappedKeyLeaseRelease {
  readonly leaseId: string;
  readonly sessionId: string;
  readonly epoch: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly authorityEphemeralP256SpkiB64: string;
  readonly wrapSaltNonceB64: string;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
  readonly iv: Uint8Array;
  readonly claimsSha256Hex: string;
}

export interface DbscSessionCredential {
  readonly dbscSessionId: string;
  readonly origin: string;
  readonly challenge: string;
  readonly devicePubkeySpkiB64: string;
  readonly jwtProof: string;
  readonly claimsSha256Hex: string;
}

export type AttestationFailureCode =
  | "invalid-input"
  | "not-yet-valid"
  | "expired"
  | "nonce-replayed"
  | "capsule-hash-mismatch"
  | "baseline-mismatch"
  | "digest-mismatch"
  | "untrusted-signer"
  | "invalid-signature";

export class CapsuleAttestationError extends Error {
  readonly code: AttestationFailureCode;

  constructor(code: AttestationFailureCode, message: string) {
    super(message);
    this.name = "CapsuleAttestationError";
    this.code = code;
  }
}

export function canonicalAttestationClaimsBytes(
  claims: CapsuleAttestationClaims,
): Uint8Array<ArrayBuffer> {
  const canonical = JSON.stringify({
    capsuleHash: claims.capsuleHash,
    rustTarget: claims.rustTarget,
    baselineId: claims.baselineId,
    pageSize: claims.pageSize,
    ephemeralP256PubkeySpkiB64: claims.ephemeralP256PubkeySpkiB64,
    nonce: claims.nonce,
    issuedAtMs: claims.issuedAtMs,
    expiresAtMs: claims.expiresAtMs,
  });
  return new Uint8Array(toArrayBufferCopy(TEXT_ENCODER.encode(canonical)));
}

export async function signCapsuleAttestation(params: {
  readonly claims: CapsuleAttestationClaims;
  readonly ed25519PrivateKey: CryptoKey;
  readonly ed25519PublicKey: CryptoKey;
}): Promise<SignedCapsuleAttestation> {
  const canonical = canonicalAttestationClaimsBytes(params.claims);
  const claimsSha256Hex = await sha256Hex(canonical);
  const prefix = TEXT_ENCODER.encode(ATTESTATION_DOMAIN_PREFIX);
  const input = concatBytes([prefix, canonical]);
  const sig = await crypto.subtle.sign("Ed25519", params.ed25519PrivateKey, input);
  const spki = await crypto.subtle.exportKey("spki", params.ed25519PublicKey);
  if (!(spki instanceof ArrayBuffer)) {
    throw new CapsuleAttestationError("invalid-input", "Expected ArrayBuffer SPKI public key");
  }
  return {
    claims: params.claims,
    claimsSha256Hex,
    signerPubkeySpkiB64: encodeBase64Bytes(new Uint8Array(spki)),
    signatureB64: encodeBase64Bytes(new Uint8Array(sig)),
  };
}

async function deriveEcdhWrapKey(
  localPrivateKey: CryptoKey,
  peerPublicSpkiB64: string,
  claimsSha256Hex: string,
): Promise<Uint8Array<ArrayBuffer>> {
  const peerBytes = decodeBase64Bytes(peerPublicSpkiB64);
  const peerKey = await crypto.subtle.importKey(
    "spki",
    toArrayBufferCopy(peerBytes),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const ecdhParams = { name: "ECDH", public: peerKey };
  const sharedBits = await crypto.subtle.deriveBits(ecdhParams, localPrivateKey, 256);
  const ikm = concatBytes([
    TEXT_ENCODER.encode(KEY_WRAP_DOMAIN),
    new Uint8Array(sharedBits),
    TEXT_ENCODER.encode(claimsSha256Hex),
  ]);
  const digest = await crypto.subtle.digest("SHA-256", ikm);
  return new Uint8Array(digest);
}

export interface WrappedKeyLeaseReleaseWire {
  readonly leaseId: string;
  readonly sessionId: string;
  readonly epoch: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly authorityEphemeralP256SpkiB64: string;
  readonly wrapSaltNonceB64: string;
  readonly ciphertextB64: string;
  readonly tagB64: string;
  readonly ivB64: string;
  readonly claimsSha256Hex: string;
}

export function wrappedKeyLeaseToWire(release: WrappedKeyLeaseRelease): WrappedKeyLeaseReleaseWire {
  return {
    leaseId: release.leaseId,
    sessionId: release.sessionId,
    epoch: release.epoch,
    issuedAtMs: release.issuedAtMs,
    expiresAtMs: release.expiresAtMs,
    authorityEphemeralP256SpkiB64: release.authorityEphemeralP256SpkiB64,
    wrapSaltNonceB64: release.wrapSaltNonceB64,
    ciphertextB64: encodeBase64Bytes(release.ciphertext),
    tagB64: encodeBase64Bytes(release.tag),
    ivB64: encodeBase64Bytes(release.iv),
    claimsSha256Hex: release.claimsSha256Hex,
  };
}

export function wrappedKeyLeaseFromWire(wire: WrappedKeyLeaseReleaseWire): WrappedKeyLeaseRelease {
  return {
    leaseId: wire.leaseId,
    sessionId: wire.sessionId,
    epoch: wire.epoch,
    issuedAtMs: wire.issuedAtMs,
    expiresAtMs: wire.expiresAtMs,
    authorityEphemeralP256SpkiB64: wire.authorityEphemeralP256SpkiB64,
    wrapSaltNonceB64: wire.wrapSaltNonceB64,
    ciphertext: decodeBase64Bytes(wire.ciphertextB64),
    tag: decodeBase64Bytes(wire.tagB64),
    iv: decodeBase64Bytes(wire.ivB64),
    claimsSha256Hex: wire.claimsSha256Hex,
  };
}

function isJsonRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

function parseJwtJsonSegment(segment: string): Record<string, unknown> | null {
  try {
    const raw: unknown = JSON.parse(TEXT_DECODER.decode(base64UrlDecode(segment)));
    return isJsonRecord(raw) ? raw : null;
  } catch {
    return null;
  }
}

export async function unwrapLeasedAesKey(
  recipientPrivateKey: CryptoKey,
  release: WrappedKeyLeaseRelease,
): Promise<Uint8Array<ArrayBuffer>> {
  const kek = await deriveEcdhWrapKey(
    recipientPrivateKey,
    release.authorityEphemeralP256SpkiB64,
    release.claimsSha256Hex,
  );
  const plain = decryptAes256Gcm(
    kek,
    release.iv,
    release.ciphertext,
    release.tag,
    TEXT_ENCODER.encode(release.claimsSha256Hex),
  );
  return new Uint8Array(toArrayBufferCopy(plain));
}

export async function verifyDbscJwtProof(cred: DbscSessionCredential): Promise<boolean> {
  const parts = cred.jwtProof.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return false;
  const header = parseJwtJsonSegment(parts[0]);
  if (!header || header.alg !== "ES256" || header.typ !== "dbsc+jwt") return false;
  const claims = parseJwtJsonSegment(parts[1]);
  if (!claims) return false;
  if (
    claims.aud !== cred.origin ||
    claims.jti !== cred.challenge ||
    claims.sub !== cred.dbscSessionId ||
    claims.capsuleClaimsSha256 !== cred.claimsSha256Hex ||
    typeof claims.iat !== "number" ||
    !Number.isFinite(claims.iat) ||
    typeof claims.capsuleHash !== "string" ||
    claims.capsuleHash.length !== 64
  ) {
    return false;
  }
  const spki = decodeBase64Bytes(cred.devicePubkeySpkiB64);
  const vk = await crypto.subtle.importKey(
    "spki",
    toArrayBufferCopy(spki),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const sigBytes = base64UrlDecode(parts[2]);
  const input = TEXT_ENCODER.encode(`${parts[0]}.${parts[1]}`);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    vk,
    toArrayBufferCopy(sigBytes),
    toArrayBufferCopy(input),
  );
}

// Authority verifier gating key-lease and DBSC release on verified A5 capsule attestation.
export class CapsuleAttestationAuthority {
  private readonly expectedCapsuleHash: string;
  private readonly expectedRustTarget: string;
  private readonly expectedBaselineId: string;
  private readonly trustedSignerSpkis: Set<string>;
  private readonly seenNonces = new Set<string>();
  private readonly dbscSigningKey: CryptoKey;
  readonly dbscPublicKeySpkiB64: string;

  private constructor(options: {
    readonly expectedCapsuleHash: string;
    readonly expectedRustTarget: string;
    readonly expectedBaselineId: string;
    readonly trustedSignerSpkis: Iterable<string>;
    readonly dbscSigningKey: CryptoKey;
    readonly dbscPublicKeySpkiB64: string;
  }) {
    this.expectedCapsuleHash = options.expectedCapsuleHash;
    this.expectedRustTarget = options.expectedRustTarget;
    this.expectedBaselineId = options.expectedBaselineId;
    this.trustedSignerSpkis = new Set(options.trustedSignerSpkis);
    this.dbscSigningKey = options.dbscSigningKey;
    this.dbscPublicKeySpkiB64 = options.dbscPublicKeySpkiB64;
  }

  static async create(options: {
    readonly expectedCapsuleHash: string;
    readonly expectedRustTarget: string;
    readonly expectedBaselineId: string;
    readonly trustedSignerSpkis: ReadonlyArray<string>;
  }): Promise<CapsuleAttestationAuthority> {
    const dbscPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    if (!("privateKey" in dbscPair) || !("publicKey" in dbscPair)) {
      throw new CapsuleAttestationError("invalid-input", "Expected ECDSA P-256 keypair");
    }
    const spki = await crypto.subtle.exportKey("spki", dbscPair.publicKey);
    if (!(spki instanceof ArrayBuffer)) {
      throw new CapsuleAttestationError("invalid-input", "Expected ArrayBuffer DBSC SPKI");
    }
    return new CapsuleAttestationAuthority({
      expectedCapsuleHash: options.expectedCapsuleHash,
      expectedRustTarget: options.expectedRustTarget,
      expectedBaselineId: options.expectedBaselineId,
      trustedSignerSpkis: options.trustedSignerSpkis,
      dbscSigningKey: dbscPair.privateKey,
      dbscPublicKeySpkiB64: encodeBase64Bytes(new Uint8Array(spki)),
    });
  }

  async verifyAttestation(
    report: SignedCapsuleAttestation,
    nowMs: number,
  ): Promise<CapsuleAttestationClaims> {
    this.validateTimingAndNonce(report.claims, nowMs);
    this.validateManifestMatch(report.claims);
    const canonical = canonicalAttestationClaimsBytes(report.claims);
    if ((await sha256Hex(canonical)) !== report.claimsSha256Hex) {
      throw new CapsuleAttestationError("digest-mismatch", "Attestation claims SHA-256 mismatch");
    }
    await this.verifyEd25519Signature(report, canonical);
    this.seenNonces.add(report.claims.nonce);
    return report.claims;
  }

  async releaseWrappedKeyLease(
    report: SignedCapsuleAttestation,
    lease: SignedKeyLease,
    nowMs: number,
  ): Promise<WrappedKeyLeaseRelease> {
    const verified = await this.verifyAttestation(report, nowMs);
    if (nowMs >= lease.payload.expiresAt) {
      throw new CapsuleAttestationError(
        "expired",
        `Key lease ${lease.payload.leaseId} expired at ${lease.payload.expiresAt}`,
      );
    }
    const authEcdh = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveBits",
    ]);
    if (!("privateKey" in authEcdh) || !("publicKey" in authEcdh)) {
      throw new CapsuleAttestationError("invalid-input", "Expected ECDH P-256 keypair");
    }
    const authSpki = await crypto.subtle.exportKey("spki", authEcdh.publicKey);
    if (!(authSpki instanceof ArrayBuffer)) {
      throw new CapsuleAttestationError("invalid-input", "Expected ArrayBuffer SPKI");
    }
    const kek = await deriveEcdhWrapKey(
      authEcdh.privateKey,
      verified.ephemeralP256PubkeySpkiB64,
      report.claimsSha256Hex,
    );
    const wrapNonce = new Uint8Array(12);
    crypto.getRandomValues(wrapNonce);
    const sealed = encryptAes256Gcm(
      kek,
      wrapNonce,
      lease.keyBytes,
      TEXT_ENCODER.encode(report.claimsSha256Hex),
    );
    return {
      leaseId: lease.payload.leaseId,
      sessionId: lease.payload.sessionId,
      epoch: lease.payload.epoch,
      issuedAtMs: lease.payload.issuedAt,
      expiresAtMs: lease.payload.expiresAt,
      authorityEphemeralP256SpkiB64: encodeBase64Bytes(new Uint8Array(authSpki)),
      wrapSaltNonceB64: encodeBase64Bytes(wrapNonce),
      ciphertext: sealed.ciphertext,
      tag: sealed.tag,
      iv: wrapNonce,
      claimsSha256Hex: report.claimsSha256Hex,
    };
  }

  async releaseDbscCredential(
    report: SignedCapsuleAttestation,
    params: {
      readonly dbscSessionId: string;
      readonly origin: string;
      readonly challenge: string;
    },
    nowMs: number,
  ): Promise<DbscSessionCredential> {
    const verified = await this.verifyAttestation(report, nowMs);
    const hB64 = base64UrlEncode(
      TEXT_ENCODER.encode(JSON.stringify({ alg: "ES256", typ: "dbsc+jwt" })),
    );
    const payload = JSON.stringify({
      aud: params.origin,
      jti: params.challenge,
      sub: params.dbscSessionId,
      iat: Math.floor(nowMs / 1000),
      capsuleClaimsSha256: report.claimsSha256Hex,
      capsuleHash: verified.capsuleHash,
    });
    const pB64 = base64UrlEncode(TEXT_ENCODER.encode(payload));
    const signingInput = `${hB64}.${pB64}`;
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.dbscSigningKey,
      TEXT_ENCODER.encode(signingInput),
    );
    return {
      dbscSessionId: params.dbscSessionId,
      origin: params.origin,
      challenge: params.challenge,
      devicePubkeySpkiB64: this.dbscPublicKeySpkiB64,
      jwtProof: `${signingInput}.${base64UrlEncode(new Uint8Array(sig))}`,
      claimsSha256Hex: report.claimsSha256Hex,
    };
  }

  private validateTimingAndNonce(claims: CapsuleAttestationClaims, nowMs: number): void {
    if (!claims.nonce.trim() || claims.expiresAtMs <= claims.issuedAtMs) {
      throw new CapsuleAttestationError(
        "invalid-input",
        "Attestation requires non-empty nonce and expiresAtMs > issuedAtMs",
      );
    }
    if (nowMs < claims.issuedAtMs) {
      throw new CapsuleAttestationError("not-yet-valid", "Attestation is not yet valid");
    }
    if (nowMs > claims.expiresAtMs) {
      throw new CapsuleAttestationError("expired", "Attestation report has expired");
    }
    if (this.seenNonces.has(claims.nonce)) {
      throw new CapsuleAttestationError("nonce-replayed", `Replayed nonce: ${claims.nonce}`);
    }
  }

  private validateManifestMatch(claims: CapsuleAttestationClaims): void {
    if (claims.capsuleHash !== this.expectedCapsuleHash) {
      throw new CapsuleAttestationError(
        "capsule-hash-mismatch",
        `Expected ${this.expectedCapsuleHash}, got ${claims.capsuleHash}`,
      );
    }
    if (
      claims.rustTarget !== this.expectedRustTarget ||
      claims.baselineId !== this.expectedBaselineId ||
      claims.pageSize !== CAPSULE_PINNED_PAGE_SIZE
    ) {
      throw new CapsuleAttestationError(
        "baseline-mismatch",
        `Baseline mismatch for ${claims.rustTarget}:${claims.baselineId}`,
      );
    }
  }

  private async verifyEd25519Signature(
    report: SignedCapsuleAttestation,
    canonical: Uint8Array<ArrayBuffer>,
  ): Promise<void> {
    if (!this.trustedSignerSpkis.has(report.signerPubkeySpkiB64)) {
      throw new CapsuleAttestationError("untrusted-signer", "Signer public key is not trusted");
    }
    const pubBytes = decodeBase64Bytes(report.signerPubkeySpkiB64);
    const pubKey = await crypto.subtle.importKey(
      "spki",
      toArrayBufferCopy(pubBytes),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const input = concatBytes([TEXT_ENCODER.encode(ATTESTATION_DOMAIN_PREFIX), canonical]);
    const sigBytes = decodeBase64Bytes(report.signatureB64);
    const ok = await crypto.subtle.verify(
      "Ed25519",
      pubKey,
      toArrayBufferCopy(sigBytes),
      toArrayBufferCopy(input),
    );
    if (!ok) {
      throw new CapsuleAttestationError("invalid-signature", "Invalid Ed25519 signature");
    }
  }
}
