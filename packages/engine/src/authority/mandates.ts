// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Ed25519-signed A2 Mandates, cumulative spend enforcement, and A2 Tokenized Credential Fill. */

import type { TargetId, UserId } from "../session/identities.ts";
import { sha256Hex } from "../state/key-lease.ts";
import { type AuthorityVaultAndChannel, normalizeStrictOrigin } from "./authority-service.ts";

export type MandateActionClass = "read" | "navigate" | "submit" | "purchase" | "credential_use";

export interface MandatePayload {
  readonly id: string;
  readonly userId: UserId;
  readonly issuerKeyId: string;
  readonly sites: ReadonlyArray<string>;
  readonly actionClasses: ReadonlyArray<MandateActionClass>;
  readonly spendLimitCents: number;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly credentialIds?: ReadonlyArray<string>;
  readonly description?: string;
}

export interface SignedMandate {
  readonly payload: MandatePayload;
  readonly signatureBase64: string;
}

export interface MandateAuthorizationInput {
  readonly url: string;
  readonly method: string;
  readonly actionClass?: MandateActionClass;
  readonly spendCents?: number;
  readonly credentialId?: string;
  readonly nowMs?: number;
}

export interface MaskedTokenRecord {
  readonly tokenPrefix: string;
  readonly tokenHashHex: string;
  readonly userId: UserId;
  readonly targetId: TargetId;
  readonly credentialId: string;
  readonly boundOrigin: string;
  readonly field: "password" | "username";
  readonly nodeId?: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly usedCount: number;
  readonly maxUses: number;
}

export interface TokenizedFillTargetAdapter {
  readonly targetId: TargetId;
  readonly currentUrl: string;
  injectTokenIntoControl(token: string): Promise<boolean>;
}

export interface TokenizedFillResult {
  readonly ok: true;
  readonly targetId: TargetId;
  readonly boundOrigin: string;
  readonly credentialId: string;
  readonly field: "password" | "username";
  readonly token: string;
  readonly tokenHashHex: string;
}

export class MandateVerificationError extends Error {
  readonly code: "invalid-signature" | "expired" | "issuer-mismatch";

  constructor(code: "invalid-signature" | "expired" | "issuer-mismatch", message: string) {
    super(message);
    this.name = "MandateVerificationError";
    this.code = code;
  }
}

export class MandateScopeError extends Error {
  readonly code: "no-mandate" | "site-denied" | "action-denied" | "credential-denied";

  constructor(
    code: "no-mandate" | "site-denied" | "action-denied" | "credential-denied",
    message: string,
  ) {
    super(message);
    this.name = "MandateScopeError";
    this.code = code;
  }
}

export class MandateSpendLimitError extends Error {
  readonly code: "spend-limit-exceeded" | "negative-spend";

  constructor(code: "spend-limit-exceeded" | "negative-spend", message: string) {
    super(message);
    this.name = "MandateSpendLimitError";
    this.code = code;
  }
}

export interface TokenTransformDetails {
  readonly boundOrigin: string;
  readonly credentialId: string;
  readonly targetId: TargetId;
  readonly field: "password" | "username";
  readonly nodeId?: number;
  readonly reason: string;
}

export class TokenTransformedNeedsSealedRetryError extends Error {
  readonly code = "TokenTransformedNeedsSealedRetry" as const;
  readonly details: TokenTransformDetails;

  constructor(details: TokenTransformDetails) {
    super(
      `TokenTransformedNeedsSealedRetry: tokenized credential for ${details.boundOrigin} ` +
        `was transformed (${details.reason}); fallback to A1 Sealed Fill required`,
    );
    this.name = "TokenTransformedNeedsSealedRetryError";
    this.details = details;
  }
}

const TEXT_ENCODER = new TextEncoder();
const TOKEN_PREFIX = "pwtok_";
const PWTOK_PATTERN = /[A-Za-z0-9_-]*pwtok_[0-9a-fA-F_-]{6,}/g;
const CROSS_ORIGIN_STRIPPED_HEADERS = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "cookie2",
] as const;

export function canonicalMandateBytes(payload: MandatePayload): Uint8Array {
  const canonical = JSON.stringify({
    id: payload.id,
    userId: payload.userId,
    issuerKeyId: payload.issuerKeyId,
    sites: [...payload.sites],
    actionClasses: [...payload.actionClasses],
    spendLimitCents: payload.spendLimitCents,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    credentialIds: payload.credentialIds ? [...payload.credentialIds] : null,
    description: payload.description ?? null,
  });
  return TEXT_ENCODER.encode(canonical);
}

export async function signMandate(
  authority: AuthorityVaultAndChannel,
  params: Omit<MandatePayload, "issuerKeyId" | "issuedAt"> & { issuedAt?: number },
): Promise<SignedMandate> {
  if (!Number.isFinite(params.spendLimitCents) || params.spendLimitCents < 0) {
    throw new MandateSpendLimitError("negative-spend", "Mandate spendLimitCents must be >= 0");
  }
  if (params.sites.length === 0) {
    throw new MandateScopeError("site-denied", "Mandate must specify at least one site pattern");
  }
  if (params.actionClasses.length === 0) {
    throw new MandateScopeError(
      "action-denied",
      "Mandate must specify at least one allowed action class",
    );
  }
  const issuedAt = params.issuedAt ?? Date.now();
  if (!Number.isFinite(params.expiresAt) || params.expiresAt <= issuedAt) {
    throw new MandateVerificationError("expired", "Mandate expiresAt must exceed issuedAt");
  }
  const payload: MandatePayload = {
    id: params.id,
    userId: params.userId,
    issuerKeyId: authority.keyId,
    sites: [...params.sites],
    actionClasses: [...params.actionClasses],
    spendLimitCents: params.spendLimitCents,
    issuedAt,
    expiresAt: params.expiresAt,
    credentialIds: params.credentialIds ? [...params.credentialIds] : undefined,
    description: params.description,
  };
  const signatureBase64 = await authority.signBytes(canonicalMandateBytes(payload));
  return { payload, signatureBase64 };
}

function bytesFromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function toArrayBufferView(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(bytes.byteLength);
  const out = new Uint8Array(buf);
  out.set(bytes);
  return out;
}

export async function importEd25519PublicKeyFromSpkiBase64(spkiBase64: string): Promise<CryptoKey> {
  const raw = bytesFromBase64(spkiBase64);
  return crypto.subtle.importKey("spki", raw, { name: "Ed25519" }, true, ["verify"]);
}

export async function verifyMandateWithPublicKey(
  publicKey: CryptoKey,
  expectedKeyId: string,
  mandate: SignedMandate,
  nowMs: number = Date.now(),
): Promise<MandatePayload> {
  if (mandate.payload.issuerKeyId !== expectedKeyId) {
    throw new MandateVerificationError(
      "issuer-mismatch",
      `Mandate issuer ${mandate.payload.issuerKeyId} does not match authority ${expectedKeyId}`,
    );
  }
  let valid = false;
  try {
    const sig = bytesFromBase64(mandate.signatureBase64);
    valid = await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      sig,
      toArrayBufferView(canonicalMandateBytes(mandate.payload)),
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new MandateVerificationError("invalid-signature", "Mandate Ed25519 signature invalid");
  }
  if (nowMs >= mandate.payload.expiresAt) {
    throw new MandateVerificationError(
      "expired",
      `Mandate ${mandate.payload.id} expired at ${mandate.payload.expiresAt}`,
    );
  }
  return mandate.payload;
}

export async function verifyMandate(
  authority: AuthorityVaultAndChannel,
  mandate: SignedMandate,
  nowMs: number = Date.now(),
): Promise<MandatePayload> {
  return verifyMandateWithPublicKey(authority.publicKey, authority.keyId, mandate, nowMs);
}

function matchSingleSitePattern(target: URL, rawPattern: string): boolean {
  const pattern = rawPattern.trim().toLowerCase();
  if (!pattern) return false;
  if (pattern.includes("://")) {
    return matchSchemeSitePattern(target, pattern);
  }
  const targetHost = target.hostname.toLowerCase();
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return base.length > 0 && (targetHost === base || targetHost.endsWith(`.${base}`));
  }
  return targetHost === pattern;
}

function matchSchemeSitePattern(target: URL, pattern: string): boolean {
  const wildMatch = pattern.match(/^(https?):\/\/\*\.([^/:]+)(?::(\d+))?$/);
  if (wildMatch) {
    const scheme = `${wildMatch[1]}:`;
    const base = wildMatch[2] ?? "";
    const port = wildMatch[3] ?? "";
    if (target.protocol !== scheme) return false;
    if (port && target.port !== port) return false;
    const host = target.hostname.toLowerCase();
    return base.length > 0 && (host === base || host.endsWith(`.${base}`));
  }
  const exactOrigin = normalizeStrictOrigin(pattern);
  if (!exactOrigin) return false;
  return target.origin === exactOrigin;
}

export function urlMatchesMandateSites(rawUrl: string, sites: ReadonlyArray<string>): boolean {
  let target: URL;
  try {
    target = new URL(rawUrl);
  } catch {
    return false;
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") return false;
  if (target.origin === "null") return false;
  for (const pattern of sites) {
    if (matchSingleSitePattern(target, pattern)) return true;
  }
  return false;
}

export function inferMandateActionClass(
  method: string,
  explicit?: MandateActionClass,
): MandateActionClass {
  if (explicit) return explicit;
  const upper = method.trim().toUpperCase();
  if (upper === "GET" || upper === "HEAD" || upper === "OPTIONS") return "read";
  return "submit";
}

export class MandateTracker {
  private readonly now: () => number;
  private readonly mandates = new Map<string, MandatePayload>();
  private readonly spentCents = new Map<string, number>();
  private readonly revoked = new Set<string>();

  constructor(options: { readonly now?: () => number } = {}) {
    this.now = options.now ?? (() => Date.now());
  }

  async register(
    authority: AuthorityVaultAndChannel,
    mandate: SignedMandate,
  ): Promise<MandatePayload> {
    const verified = await verifyMandate(authority, mandate, this.now());
    this.mandates.set(verified.id, verified);
    return verified;
  }

  async registerWithPublicKey(
    publicKey: CryptoKey,
    expectedKeyId: string,
    mandate: SignedMandate,
  ): Promise<MandatePayload> {
    const verified = await verifyMandateWithPublicKey(
      publicKey,
      expectedKeyId,
      mandate,
      this.now(),
    );
    this.mandates.set(verified.id, verified);
    return verified;
  }

  revoke(mandateId: string): void {
    this.revoked.add(mandateId);
  }

  getSpentCents(mandateId: string): number {
    return this.spentCents.get(mandateId) ?? 0;
  }

  listActive(nowMs: number = this.now()): MandatePayload[] {
    const out: MandatePayload[] = [];
    for (const m of this.mandates.values()) {
      if (!this.revoked.has(m.id) && nowMs < m.expiresAt) out.push(m);
    }
    return out;
  }

  authorizeRequest(input: MandateAuthorizationInput): MandatePayload {
    const nowMs = input.nowMs ?? this.now();
    const spend = input.spendCents ?? 0;
    if (!Number.isFinite(spend) || spend < 0) {
      throw new MandateSpendLimitError("negative-spend", "Requested spendCents must be >= 0");
    }
    const action = inferMandateActionClass(input.method, input.actionClass);
    const active = this.collectUnrevokedMandates(nowMs);
    const rejection = this.findAuthorizingMandate(
      active,
      input.url,
      action,
      spend,
      input.credentialId,
    );
    if ("mandate" in rejection) {
      const nextSpend = (this.spentCents.get(rejection.mandate.id) ?? 0) + spend;
      this.spentCents.set(rejection.mandate.id, nextSpend);
      return rejection.mandate;
    }
    throw rejection.error;
  }

  revalidateRedirectHop(params: {
    readonly mandateId: string;
    readonly redirectUrl: string;
    readonly method: string;
    readonly actionClass?: MandateActionClass;
    readonly nowMs?: number;
  }): MandatePayload {
    const nowMs = params.nowMs ?? this.now();
    const mandate = this.mandates.get(params.mandateId);
    if (!mandate || this.revoked.has(params.mandateId)) {
      throw new MandateScopeError("no-mandate", `Mandate ${params.mandateId} unavailable`);
    }
    if (nowMs >= mandate.expiresAt) {
      throw new MandateVerificationError(
        "expired",
        `Mandate ${mandate.id} expired before redirect to ${params.redirectUrl}`,
      );
    }
    if (!urlMatchesMandateSites(params.redirectUrl, mandate.sites)) {
      throw new MandateScopeError(
        "site-denied",
        `Redirect target ${params.redirectUrl} violates mandate ${mandate.id} site scope`,
      );
    }
    const action = inferMandateActionClass(params.method, params.actionClass);
    if (!mandate.actionClasses.includes(action)) {
      throw new MandateScopeError(
        "action-denied",
        `Redirect method/action ${action} denied by mandate ${mandate.id}`,
      );
    }
    return mandate;
  }

  releaseSpend(mandateId: string, spendCents: number): void {
    if (!Number.isFinite(spendCents) || spendCents <= 0) return;
    const prev = this.spentCents.get(mandateId) ?? 0;
    this.spentCents.set(mandateId, Math.max(0, prev - spendCents));
  }

  private collectUnrevokedMandates(nowMs: number): MandatePayload[] {
    const out: MandatePayload[] = [];
    for (const mandate of this.mandates.values()) {
      if (this.revoked.has(mandate.id)) continue;
      if (nowMs >= mandate.expiresAt) continue;
      out.push(mandate);
    }
    return out;
  }

  private findAuthorizingMandate(
    active: ReadonlyArray<MandatePayload>,
    url: string,
    action: MandateActionClass,
    spend: number,
    credentialId?: string,
  ): { readonly mandate: MandatePayload } | { readonly error: Error } {
    if (active.length === 0) {
      return {
        error:
          this.mandates.size > 0
            ? new MandateVerificationError("expired", "All registered mandates expired or revoked")
            : new MandateScopeError("no-mandate", "No valid A2 mandate authorizes egress"),
      };
    }
    let lastError: Error | null = null;
    for (const mandate of active) {
      if (!urlMatchesMandateSites(url, mandate.sites)) {
        lastError ??= new MandateScopeError(
          "site-denied",
          `Target ${url} outside mandate ${mandate.id} site scope`,
        );
        continue;
      }
      if (!mandate.actionClasses.includes(action)) {
        lastError ??= new MandateScopeError(
          "action-denied",
          `Action ${action} outside mandate ${mandate.id} actionClasses`,
        );
        continue;
      }
      if (credentialId && mandate.credentialIds && !mandate.credentialIds.includes(credentialId)) {
        lastError ??= new MandateScopeError(
          "credential-denied",
          `Credential ${credentialId} outside mandate ${mandate.id}`,
        );
        continue;
      }
      const remaining = mandate.spendLimitCents - (this.spentCents.get(mandate.id) ?? 0);
      if (spend > remaining) {
        lastError = new MandateSpendLimitError(
          "spend-limit-exceeded",
          `Spend ${spend}c exceeds remaining ${remaining}c on mandate ${mandate.id}`,
        );
        continue;
      }
      return { mandate };
    }
    return {
      error: lastError ?? new MandateScopeError("no-mandate", `Egress denied for ${url}`),
    };
  }
}

interface InternalTokenEntry {
  readonly token: string;
  readonly hexBody: string;
  readonly tokenHashHex: string;
  readonly userId: UserId;
  readonly targetId: TargetId;
  readonly credentialId: string;
  readonly boundOrigin: string;
  readonly field: "password" | "username";
  readonly nodeId?: number;
  readonly secret: string;
  readonly digests: ReadonlyArray<{ readonly label: string; readonly value: string }>;
  readonly createdAt: number;
  readonly expiresAt: number;
  usedCount: number;
  readonly maxUses: number;
}

export function generateCredentialToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return `${TOKEN_PREFIX}${hex}`;
}

async function digestHex(
  algo: "SHA-256" | "SHA-384" | "SHA-512" | "SHA-1",
  raw: string,
): Promise<string> {
  const buf = await crypto.subtle.digest(algo, TEXT_ENCODER.encode(raw));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function digestB64(algo: "SHA-256" | "SHA-512", raw: string): Promise<string> {
  const buf = await crypto.subtle.digest(algo, TEXT_ENCODER.encode(raw));
  let bin = "";
  for (const byte of new Uint8Array(buf)) bin += String.fromCharCode(byte);
  return btoa(bin);
}

export function stripCrossOriginSensitiveHeaders(
  headers: Headers,
  activeTokens: ReadonlyArray<string> = [],
): { readonly headers: Headers; readonly stripped: boolean } {
  const out = new Headers(headers);
  let stripped = false;
  for (const name of CROSS_ORIGIN_STRIPPED_HEADERS) {
    if (out.has(name)) {
      out.delete(name);
      stripped = true;
    }
  }
  for (const [key, val] of out.entries()) {
    const cleaned = redactTokenStrings(val, activeTokens);
    if (cleaned !== val) {
      out.set(key, cleaned);
      stripped = true;
    }
  }
  return { headers: out, stripped };
}

function redactTokenStrings(text: string, activeTokens: ReadonlyArray<string>): string {
  let out = text;
  for (const tok of activeTokens) {
    if (out.includes(tok)) {
      out = out.split(tok).join("");
    }
  }
  out = out.replace(PWTOK_PATTERN, "");
  return out;
}

export class TokenizedFillVault {
  private readonly authority: AuthorityVaultAndChannel;
  private readonly now: () => number;
  private readonly defaultTtlMs: number;
  private readonly entries = new Map<string, InternalTokenEntry>();
  private readonly tokensByTarget = new Map<TargetId, Set<string>>();

  constructor(
    authority: AuthorityVaultAndChannel,
    options: { readonly now?: () => number; readonly defaultTtlMs?: number } = {},
  ) {
    this.authority = authority;
    this.now = options.now ?? (() => Date.now());
    this.defaultTtlMs = options.defaultTtlMs ?? 5 * 60_000;
  }

  async issueToken(params: {
    readonly userId: UserId;
    readonly targetId: TargetId;
    readonly targetUrl: string;
    readonly credentialId?: string;
    readonly field?: "password" | "username";
    readonly nodeId?: number;
    readonly ttlMs?: number;
    readonly maxUses?: number;
  }): Promise<{ readonly token: string; readonly record: MaskedTokenRecord }> {
    const resolved = this.authority.lookupCredentialSecretForOrigin(
      params.userId,
      params.targetUrl,
      params.credentialId,
    );
    const token = generateCredentialToken();
    const hexBody = token.slice(TOKEN_PREFIX.length);
    const tokenHashHex = await sha256Hex(TEXT_ENCODER.encode(token));
    const [sha512Hex, sha1Hex, sha256B64] = await Promise.all([
      digestHex("SHA-512", token),
      digestHex("SHA-1", token),
      digestB64("SHA-256", token),
    ]);
    const digests: Array<{ label: string; value: string }> = [
      { label: "sha256-hex", value: tokenHashHex },
      { label: "sha256-b64", value: sha256B64 },
      { label: "sha512-hex", value: sha512Hex },
      { label: "sha1-hex", value: sha1Hex },
      { label: "base64", value: btoa(token) },
      { label: "reversed", value: token.split("").reverse().join("") },
      { label: "hex-prefix", value: hexBody.slice(0, 12) },
    ];
    const now = this.now();
    const entry: InternalTokenEntry = {
      token,
      hexBody,
      tokenHashHex,
      userId: params.userId,
      targetId: params.targetId,
      credentialId: resolved.credentialId,
      boundOrigin: resolved.origin,
      field: params.field ?? "password",
      nodeId: params.nodeId,
      secret: params.field === "username" ? resolved.username : resolved.secret,
      digests,
      createdAt: now,
      expiresAt: now + (params.ttlMs ?? this.defaultTtlMs),
      usedCount: 0,
      maxUses: params.maxUses ?? 4,
    };
    this.entries.set(token, entry);
    let set = this.tokensByTarget.get(params.targetId);
    if (!set) {
      set = new Set<string>();
      this.tokensByTarget.set(params.targetId, set);
    }
    set.add(token);
    return { token, record: this.toMasked(entry) };
  }

  async performTokenizedFill(params: {
    readonly userId: UserId;
    readonly target: TokenizedFillTargetAdapter;
    readonly credentialId?: string;
    readonly field?: "password" | "username";
    readonly nodeId?: number;
    readonly ttlMs?: number;
    readonly maxUses?: number;
  }): Promise<TokenizedFillResult> {
    const issued = await this.issueToken({
      userId: params.userId,
      targetId: params.target.targetId,
      targetUrl: params.target.currentUrl,
      credentialId: params.credentialId,
      field: params.field,
      nodeId: params.nodeId,
      ttlMs: params.ttlMs,
      maxUses: params.maxUses,
    });
    const filled = await params.target.injectTokenIntoControl(issued.token);
    if (!filled) {
      this.revokeToken(issued.token);
      throw new Error("A2 Tokenized Fill could not inject token into target control");
    }
    return {
      ok: true,
      targetId: params.target.targetId,
      boundOrigin: issued.record.boundOrigin,
      credentialId: issued.record.credentialId,
      field: issued.record.field,
      token: issued.token,
      tokenHashHex: issued.record.tokenHashHex,
    };
  }

  revokeToken(token: string): void {
    const entry = this.entries.get(token);
    if (!entry) return;
    this.entries.delete(token);
    this.tokensByTarget.get(entry.targetId)?.delete(token);
  }

  revokeTargetTokens(targetId: TargetId): void {
    const set = this.tokensByTarget.get(targetId);
    if (!set) return;
    for (const token of set) this.entries.delete(token);
    this.tokensByTarget.delete(targetId);
  }

  listMaskedTokens(targetId?: TargetId): MaskedTokenRecord[] {
    const now = this.now();
    const out: MaskedTokenRecord[] = [];
    for (const entry of this.entries.values()) {
      if (now >= entry.expiresAt) continue;
      if (targetId && entry.targetId !== targetId) continue;
      out.push(this.toMasked(entry));
    }
    return out;
  }

  processOutboundRequest(params: {
    readonly targetUrl: string;
    readonly method: string;
    readonly headers: Headers;
    readonly bodyText: string | null;
    readonly targetId?: TargetId;
    readonly expectTokenSubmit?: boolean;
  }): {
    readonly headers: Headers;
    readonly bodyText: string | null;
    readonly swappedCount: number;
    readonly swappedCredentialIds: string[];
    readonly swappedSecrets: ReadonlyArray<string>;
    readonly strippedCrossOrigin: boolean;
  } {
    const now = this.now();
    const targetOrigin = normalizeStrictOrigin(params.targetUrl);
    const active = this.activeEntries(now);
    const allTokens = active.map((e) => e.token);
    const outHeaders = new Headers(params.headers);
    let outBody = params.bodyText;
    let strippedCrossOrigin = false;

    const foreign = active.filter((e) => e.boundOrigin !== targetOrigin);
    if (foreign.length > 0) {
      const foreignTokens = foreign.map((e) => e.token);
      if (this.headersOrBodyCarryForeignTokens(outHeaders, outBody, foreignTokens)) {
        const res = stripCrossOriginSensitiveHeaders(outHeaders, foreignTokens);
        for (const [k] of [...outHeaders.entries()]) outHeaders.delete(k);
        for (const [k, v] of res.headers.entries()) outHeaders.set(k, v);
        if (outBody !== null) outBody = redactTokenStrings(outBody, foreignTokens);
        strippedCrossOrigin = true;
      }
    }

    const bound = active.filter((e) => targetOrigin !== null && e.boundOrigin === targetOrigin);
    const corpus = this.buildPayloadCorpus(params.targetUrl, outHeaders, outBody);
    const {
      swappedCount,
      swappedCredentialIds,
      swappedSecrets,
      bodyText: nextBody,
    } = this.swapExactBoundTokens(bound, outHeaders, outBody);
    outBody = nextBody;

    if (swappedCount === 0 && bound.length > 0) {
      this.detectTransformedTokenOrThrow(bound, corpus, allTokens, params);
    }

    return {
      headers: outHeaders,
      bodyText: outBody,
      swappedCount,
      swappedCredentialIds,
      swappedSecrets,
      strippedCrossOrigin,
    };
  }

  private toMasked(entry: InternalTokenEntry): MaskedTokenRecord {
    return {
      tokenPrefix: entry.token.slice(0, 12),
      tokenHashHex: entry.tokenHashHex,
      userId: entry.userId,
      targetId: entry.targetId,
      credentialId: entry.credentialId,
      boundOrigin: entry.boundOrigin,
      field: entry.field,
      nodeId: entry.nodeId,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
      usedCount: entry.usedCount,
      maxUses: entry.maxUses,
    };
  }

  private activeEntries(now: number): InternalTokenEntry[] {
    const out: InternalTokenEntry[] = [];
    for (const [tok, entry] of this.entries) {
      if (now >= entry.expiresAt || entry.usedCount >= entry.maxUses) {
        this.entries.delete(tok);
        this.tokensByTarget.get(entry.targetId)?.delete(tok);
        continue;
      }
      out.push(entry);
    }
    return out;
  }

  private headersOrBodyCarryForeignTokens(
    headers: Headers,
    bodyText: string | null,
    foreignTokens: ReadonlyArray<string>,
  ): boolean {
    if (bodyText !== null) {
      for (const tok of foreignTokens) {
        if (bodyText.includes(tok)) return true;
      }
    }
    for (const [, val] of headers.entries()) {
      for (const tok of foreignTokens) {
        if (val.includes(tok)) return true;
      }
    }
    return false;
  }

  private buildPayloadCorpus(url: string, headers: Headers, bodyText: string | null): string {
    const parts: string[] = [];
    try {
      const parsed = new URL(url);
      if (parsed.search) parts.push(parsed.search);
    } catch {}
    for (const [key, val] of headers.entries()) {
      parts.push(`${key}:${val}`);
    }
    if (bodyText) parts.push(bodyText);
    return parts.join("\n");
  }

  private replaceIntactToken(text: string, token: string, secret: string): string {
    if (!text.includes(token)) return text;
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const boundaryRe = new RegExp(`(?<![A-Za-z0-9_-])${escaped}(?![A-Za-z0-9_-])`, "g");
    return text.replace(boundaryRe, () => secret);
  }

  private swapExactBoundTokens(
    bound: ReadonlyArray<InternalTokenEntry>,
    headers: Headers,
    bodyText: string | null,
  ): {
    swappedCount: number;
    swappedCredentialIds: string[];
    swappedSecrets: string[];
    bodyText: string | null;
  } {
    let swappedCount = 0;
    const swappedIds: string[] = [];
    const swappedSecrets: string[] = [];
    let currentBody = bodyText;
    for (const entry of bound) {
      let matched = false;
      for (const [key, val] of [...headers.entries()]) {
        const replaced = this.replaceIntactToken(val, entry.token, entry.secret);
        if (replaced !== val) {
          headers.set(key, replaced);
          matched = true;
        }
      }
      if (currentBody !== null) {
        const swappedBody = this.replaceIntactToken(currentBody, entry.token, entry.secret);
        if (swappedBody !== currentBody) {
          currentBody = swappedBody;
          matched = true;
        }
      }
      if (matched) {
        entry.usedCount++;
        swappedCount++;
        swappedIds.push(entry.credentialId);
        swappedSecrets.push(entry.secret);
      }
    }
    return {
      swappedCount,
      swappedCredentialIds: swappedIds,
      swappedSecrets,
      bodyText: currentBody,
    };
  }

  private detectTransformedTokenOrThrow(
    bound: ReadonlyArray<InternalTokenEntry>,
    corpus: string,
    allValidTokens: ReadonlyArray<string>,
    params: {
      readonly method: string;
      readonly targetId?: TargetId;
      readonly expectTokenSubmit?: boolean;
    },
  ): void {
    const validSet = new Set(allValidTokens);
    const pwtokMatches = corpus.match(PWTOK_PATTERN) ?? [];
    for (const candidate of pwtokMatches) {
      if (validSet.has(candidate)) continue;
      const targetEntry = this.pickEntryForRetry(bound, params.targetId);
      this.revokeToken(targetEntry.token);
      throw new TokenTransformedNeedsSealedRetryError({
        boundOrigin: targetEntry.boundOrigin,
        credentialId: targetEntry.credentialId,
        targetId: targetEntry.targetId,
        field: targetEntry.field,
        nodeId: targetEntry.nodeId,
        reason: `mutated pwtok token ${candidate.slice(0, 12)}...`,
      });
    }

    const lowerCorpus = corpus.toLowerCase();
    for (const entry of bound) {
      for (const d of entry.digests) {
        if (corpus.includes(d.value) || lowerCorpus.includes(d.value.toLowerCase())) {
          this.revokeToken(entry.token);
          throw new TokenTransformedNeedsSealedRetryError({
            boundOrigin: entry.boundOrigin,
            credentialId: entry.credentialId,
            targetId: entry.targetId,
            field: entry.field,
            nodeId: entry.nodeId,
            reason: `detected ${d.label} transform of tokenized credential`,
          });
        }
      }
    }

    const upperMethod = params.method.trim().toUpperCase();
    if (
      params.expectTokenSubmit &&
      (upperMethod === "POST" || upperMethod === "PUT" || upperMethod === "PATCH")
    ) {
      const targetEntry = this.pickEntryForRetry(bound, params.targetId);
      this.revokeToken(targetEntry.token);
      throw new TokenTransformedNeedsSealedRetryError({
        boundOrigin: targetEntry.boundOrigin,
        credentialId: targetEntry.credentialId,
        targetId: targetEntry.targetId,
        field: targetEntry.field,
        nodeId: targetEntry.nodeId,
        reason: "submitted form payload omitted intact pwtok token",
      });
    }
  }

  private pickEntryForRetry(
    bound: ReadonlyArray<InternalTokenEntry>,
    targetId?: TargetId,
  ): InternalTokenEntry {
    if (targetId) {
      const exact = bound.find((e) => e.targetId === targetId);
      if (exact) return exact;
    }
    return bound[0]!;
  }
}
