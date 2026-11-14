// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Held-action cryptographic approval gate binding digest, DOM-only summary, and Ed25519 sign. */

import { decodeBase64Bytes, sha256Hex } from "../state/key-lease.ts";
import type { AuthorityVaultAndChannel } from "./authority-service.ts";

function toArrayBufferCopy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

export interface HttpActionDescriptor {
  readonly method: string;
  readonly url: string;
  readonly headers?: Record<string, string> | ReadonlyArray<readonly [string, string]>;
  readonly body?: Uint8Array | string | null;
}

export interface DomObservedField {
  readonly label: string;
  readonly value: string;
  readonly fieldType?: string;
}

export interface DomOnlyApprovalSummary {
  readonly targetOrigin: string;
  readonly method: string;
  readonly pathname: string;
  readonly domFields: ReadonlyArray<DomObservedField>;
}

export interface ApprovalDecisionPayload {
  readonly requestDigest: string;
  readonly nonce: string;
  readonly expiresAt: number;
  readonly approved: boolean;
}

export interface SignedApprovalDecision {
  readonly payload: ApprovalDecisionPayload;
  readonly signatureBase64: string;
}

export interface PendingApprovalRequest {
  readonly nonce: string;
  readonly requestDigest: string;
  readonly summary: DomOnlyApprovalSummary;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export type ApprovalOutcome =
  | {
      readonly approved: true;
      readonly requestDigest: string;
      readonly nonce: string;
      readonly reason: "signed-approval";
    }
  | {
      readonly approved: false;
      readonly requestDigest: string;
      readonly nonce: string;
      readonly reason: "denied" | "timeout" | "expired" | "invalid-signature" | "digest-mismatch";
    };

export class ApprovalVerificationError extends Error {
  readonly code: "unknown-nonce" | "expired" | "invalid-signature" | "digest-mismatch" | "denied";

  constructor(
    code: "unknown-nonce" | "expired" | "invalid-signature" | "digest-mismatch" | "denied",
    message: string,
  ) {
    super(message);
    this.name = "ApprovalVerificationError";
    this.code = code;
  }
}

const TEXT_ENCODER = new TextEncoder();

export function normalizeSortedHeaders(
  headers?: Record<string, string> | ReadonlyArray<readonly [string, string]>,
): Array<[string, string]> {
  if (!headers) return [];
  const pairs: Array<[string, string]> = Array.isArray(headers)
    ? headers.map(([k, v]) => [String(k).toLowerCase().trim(), String(v)])
    : Object.entries(headers).map(([k, v]) => [k.toLowerCase().trim(), String(v)]);
  pairs.sort((a, b) => {
    const keyCmp = a[0].localeCompare(b[0]);
    if (keyCmp !== 0) return keyCmp;
    return a[1].localeCompare(b[1]);
  });
  return pairs;
}

export async function computeBodySha256(body?: Uint8Array | string | null): Promise<string> {
  if (body == null) return sha256Hex(new Uint8Array(0));
  if (typeof body === "string") return sha256Hex(TEXT_ENCODER.encode(body));
  return sha256Hex(body);
}

export async function computeHttpActionDigest(action: HttpActionDescriptor): Promise<string> {
  const method = action.method.trim().toUpperCase();
  const parsedUrl = new URL(action.url).toString();
  const sortedHeaders = normalizeSortedHeaders(action.headers);
  const bodySha256 = await computeBodySha256(action.body);
  const canonical = JSON.stringify({ method, url: parsedUrl, sortedHeaders, bodySha256 });
  return sha256Hex(TEXT_ENCODER.encode(canonical));
}

export function buildDomOnlyApprovalSummary(
  action: HttpActionDescriptor,
  domFields: ReadonlyArray<DomObservedField>,
): DomOnlyApprovalSummary {
  const url = new URL(action.url);
  const sanitizedFields: DomObservedField[] = domFields.map((field) => ({
    label: String(field.label),
    value: String(field.value),
    ...(field.fieldType !== undefined ? { fieldType: String(field.fieldType) } : {}),
  }));
  return {
    targetOrigin: url.origin,
    method: action.method.trim().toUpperCase(),
    pathname: url.pathname,
    domFields: sanitizedFields,
  };
}

export function canonicalDecisionBytes(payload: ApprovalDecisionPayload): Uint8Array {
  const json = JSON.stringify({
    requestDigest: payload.requestDigest,
    nonce: payload.nonce,
    expiresAt: payload.expiresAt,
    approved: payload.approved,
  });
  return TEXT_ENCODER.encode(json);
}

interface PendingEntry {
  readonly request: PendingApprovalRequest;
  resolve(outcome: ApprovalOutcome): void;
  readonly timer: ReturnType<typeof setTimeout>;
}

export class ApprovalGate {
  private readonly authority: AuthorityVaultAndChannel;
  private readonly verificationPublicKey?: CryptoKey;
  private readonly now: () => number;
  private readonly pending = new Map<string, PendingEntry>();

  constructor(
    authority: AuthorityVaultAndChannel,
    options: { now?: () => number; verificationPublicKey?: CryptoKey } = {},
  ) {
    this.authority = authority;
    this.verificationPublicKey = options.verificationPublicKey;
    this.now = options.now ?? ((): number => Date.now());
  }

  private async verifySignature(
    payload: ApprovalDecisionPayload,
    signatureBase64: string,
  ): Promise<boolean> {
    const bytes = canonicalDecisionBytes(payload);
    if (this.verificationPublicKey) {
      return crypto.subtle.verify(
        "Ed25519",
        this.verificationPublicKey,
        toArrayBufferCopy(decodeBase64Bytes(signatureBase64)),
        toArrayBufferCopy(bytes),
      );
    }
    return this.authority.verifyBytes(bytes, signatureBase64);
  }

  async signDecision(payload: ApprovalDecisionPayload): Promise<SignedApprovalDecision> {
    const signatureBase64 = await this.authority.signBytes(canonicalDecisionBytes(payload));
    return { payload, signatureBase64 };
  }

  async verifyDecision(
    decision: SignedApprovalDecision,
    expectedDigest: string,
    expectedNonce?: string,
  ): Promise<void> {
    const valid = await this.verifySignature(decision.payload, decision.signatureBase64);
    if (!valid) {
      throw new ApprovalVerificationError(
        "invalid-signature",
        "Authority Ed25519 signature verification failed on approval decision",
      );
    }
    if (decision.payload.requestDigest !== expectedDigest) {
      throw new ApprovalVerificationError(
        "digest-mismatch",
        `Decision requestDigest ${decision.payload.requestDigest} does not match ${expectedDigest}`,
      );
    }
    if (expectedNonce !== undefined && decision.payload.nonce !== expectedNonce) {
      throw new ApprovalVerificationError(
        "unknown-nonce",
        `Decision nonce ${decision.payload.nonce} does not match expected ${expectedNonce}`,
      );
    }
    if (this.now() > decision.payload.expiresAt) {
      throw new ApprovalVerificationError("expired", "Signed approval decision has expired");
    }
    if (!decision.payload.approved) {
      throw new ApprovalVerificationError("denied", "Approval decision explicitly denied action");
    }
  }

  /** Hold action pending human signed decision; defaults to deny on timeout. */
  async holdForApproval(params: {
    readonly action: HttpActionDescriptor;
    readonly domFields: ReadonlyArray<DomObservedField>;
    readonly timeoutMs: number;
    readonly onPrompt?: (request: PendingApprovalRequest) => void;
  }): Promise<ApprovalOutcome> {
    const requestDigest = await computeHttpActionDigest(params.action);
    const summary = buildDomOnlyApprovalSummary(params.action, params.domFields);
    const nonce = crypto.randomUUID();
    const createdAt = this.now();
    const timeoutMs = Math.max(1, params.timeoutMs);
    const expiresAt = createdAt + timeoutMs;
    const request: PendingApprovalRequest = {
      nonce,
      requestDigest,
      summary,
      createdAt,
      expiresAt,
    };

    const outcomePromise = new Promise<ApprovalOutcome>((resolve) => {
      const timer = setTimeout(() => {
        if (!this.pending.has(nonce)) return;
        this.pending.delete(nonce);
        resolve({
          approved: false,
          requestDigest,
          nonce,
          reason: "timeout",
        });
      }, timeoutMs);
      this.pending.set(nonce, { request, resolve, timer });
    });

    params.onPrompt?.(request);
    return outcomePromise;
  }

  getPending(nonce: string): PendingApprovalRequest | undefined {
    return this.pending.get(nonce)?.request;
  }

  async resolveWithSignedDecision(decision: SignedApprovalDecision): Promise<ApprovalOutcome> {
    const entry = this.pending.get(decision.payload.nonce);
    if (!entry) {
      throw new ApprovalVerificationError(
        "unknown-nonce",
        `No pending approval for nonce ${decision.payload.nonce}`,
      );
    }
    const valid = await this.verifySignature(decision.payload, decision.signatureBase64);
    if (!valid) {
      clearTimeout(entry.timer);
      this.pending.delete(decision.payload.nonce);
      const outcome: ApprovalOutcome = {
        approved: false,
        requestDigest: entry.request.requestDigest,
        nonce: decision.payload.nonce,
        reason: "invalid-signature",
      };
      entry.resolve(outcome);
      return outcome;
    }
    if (decision.payload.requestDigest !== entry.request.requestDigest) {
      clearTimeout(entry.timer);
      this.pending.delete(decision.payload.nonce);
      const outcome: ApprovalOutcome = {
        approved: false,
        requestDigest: entry.request.requestDigest,
        nonce: decision.payload.nonce,
        reason: "digest-mismatch",
      };
      entry.resolve(outcome);
      return outcome;
    }
    const currentNow = this.now();
    if (currentNow > decision.payload.expiresAt || currentNow > entry.request.expiresAt) {
      clearTimeout(entry.timer);
      this.pending.delete(decision.payload.nonce);
      const outcome: ApprovalOutcome = {
        approved: false,
        requestDigest: entry.request.requestDigest,
        nonce: decision.payload.nonce,
        reason: "expired",
      };
      entry.resolve(outcome);
      return outcome;
    }
    clearTimeout(entry.timer);
    this.pending.delete(decision.payload.nonce);
    const outcome: ApprovalOutcome = decision.payload.approved
      ? {
          approved: true,
          requestDigest: entry.request.requestDigest,
          nonce: decision.payload.nonce,
          reason: "signed-approval",
        }
      : {
          approved: false,
          requestDigest: entry.request.requestDigest,
          nonce: decision.payload.nonce,
          reason: "denied",
        };
    entry.resolve(outcome);
    return outcome;
  }

  async assertExecutionMatchesDecision(
    action: HttpActionDescriptor,
    decision: SignedApprovalDecision,
    expectedNonce?: string,
  ): Promise<void> {
    const actualDigest = await computeHttpActionDigest(action);
    await this.verifyDecision(decision, actualDigest, expectedNonce);
  }

  cancelPending(
    nonce: string,
    reason: "denied" | "expired" | "timeout" | "invalid-signature" | "digest-mismatch" = "denied",
  ): void {
    const entry = this.pending.get(nonce);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.pending.delete(nonce);
    entry.resolve({
      approved: false,
      requestDigest: entry.request.requestDigest,
      nonce,
      reason,
    });
  }

  cancelAll(): void {
    for (const nonce of [...this.pending.keys()]) {
      this.cancelPending(nonce, "denied");
    }
  }
}
