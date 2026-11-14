// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Isolated Egress Broker core enforcing A2 mandates, SSRF checks, redirects, WBA, and tokens.

import type { LookupAddress } from "node:dns";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import {
  ApprovalGate,
  ApprovalVerificationError,
  type DomObservedField,
  type PendingApprovalRequest,
  type SignedApprovalDecision,
} from "@parawing/engine/approval-gate";
import type { SignedAuditEntry, SignedAuditLog } from "@parawing/engine/audit-log";
import {
  AuthorityVaultAndChannel,
  CredentialNotFoundError,
  SealedOriginMismatchError,
  type MaskedVaultCredential,
  type SealedFillResult,
  type SealedFillTargetAdapter,
  type VaultCredentialInput,
  normalizeStrictOrigin,
} from "@parawing/engine/authority-service";
import type { ExternalOutbound } from "@parawing/engine/external-outbound";
import {
  MandateScopeError,
  MandateSpendLimitError,
  MandateTracker,
  MandateVerificationError,
  TokenTransformedNeedsSealedRetryError,
  TokenizedFillVault,
  importEd25519PublicKeyFromSpkiBase64,
  stripCrossOriginSensitiveHeaders,
  type MandateActionClass,
  type MandatePayload,
  type MaskedTokenRecord,
  type SignedMandate,
  type TokenTransformDetails,
  type TokenizedFillResult,
  type TokenizedFillTargetAdapter,
} from "@parawing/engine/mandates";
import { PolicyDecisionError, PolicyEngine } from "@parawing/engine/policy-engine";
import { addressSpaceOf } from "@parawing/engine/private-network";
import type { TargetId, UserId } from "@parawing/engine/session-identities";
import { traceSpan, type Tracer } from "@parawing/engine/tracing";
import { wbaHeadersFor, type WbaConfigSource } from "@parawing/engine/web-bot-auth";

export {
  ApprovalVerificationError,
  CredentialNotFoundError,
  MandateScopeError,
  MandateSpendLimitError,
  MandateVerificationError,
  PolicyDecisionError,
  SealedOriginMismatchError,
  TokenTransformedNeedsSealedRetryError,
};

export interface EgressRequestMetadata {
  readonly actionClass?: MandateActionClass;
  readonly spendCents?: number;
  readonly credentialId?: string;
  readonly targetId?: TargetId;
  readonly sealedOrigin?: string | null;
  readonly isTopLevelNavigation?: boolean;
  readonly expectTokenSubmit?: boolean;
  readonly requireApproval?: boolean;
  readonly domFields?: ReadonlyArray<DomObservedField>;
  readonly deadlineMs?: number;
}

export interface EgressApprovalCheck {
  readonly url: string;
  readonly method: string;
  readonly actionClass: MandateActionClass;
  readonly spendCents: number;
  readonly headers: Headers;
}

export interface EgressBrokerOptions {
  readonly authority?: AuthorityVaultAndChannel;
  readonly verificationPublicKeySpkiBase64?: string;
  readonly verificationKeyId?: string;
  readonly policyEngine?: PolicyEngine;
  readonly mandateTracker?: MandateTracker;
  readonly requireMandate?: boolean;
  readonly tokenizedVault?: TokenizedFillVault;
  readonly approvalGate?: ApprovalGate;
  readonly auditLog?: SignedAuditLog;
  readonly tracer?: Tracer;
  readonly wbaConfig?: WbaConfigSource;
  readonly requiresApproval?: (
    check: EgressApprovalCheck,
  ) =>
    | boolean
    | { readonly required: boolean; readonly domFields?: ReadonlyArray<DomObservedField> };
  readonly onApprovalPrompt?: (
    pending: PendingApprovalRequest,
  ) => Promise<SignedApprovalDecision | { readonly approved: boolean }>;
  readonly approvalTimeoutMs?: number;
  readonly allowPrivateNetwork?: boolean;
  readonly allowedPrivateOrigins?: ReadonlyArray<string>;
  readonly lookupFn?: (hostname: string) => Promise<readonly LookupAddress[]>;
  readonly fetchFn?: typeof globalThis.fetch;
  readonly deadlineMs?: number;
  readonly maxRedirects?: number;
  readonly now?: () => number;
}

export class EgressBlockedError extends Error {
  readonly code:
    | "invalid-url"
    | "invalid-scheme"
    | "ssrf-blocked"
    | "too-many-redirects"
    | "aborted"
    | "deadline-exceeded"
    | "approval-unavailable";

  constructor(
    code:
      | "invalid-url"
      | "invalid-scheme"
      | "ssrf-blocked"
      | "too-many-redirects"
      | "aborted"
      | "deadline-exceeded"
      | "approval-unavailable",
    message: string,
  ) {
    super(message);
    this.name = "EgressBlockedError";
    this.code = code;
  }
}

export interface EgressBroker {
  fetch(
    input: Request | string | URL,
    init?: RequestInit & { metadata?: EgressRequestMetadata },
  ): Promise<Response>;
  asExternalOutbound(): ExternalOutbound;
  registerMandate(mandate: SignedMandate): Promise<MandatePayload>;
  revokeMandate(mandateId: string): Promise<void>;
  storeCredential(input: VaultCredentialInput): Promise<MaskedVaultCredential>;
  issueToken(params: {
    readonly userId: UserId;
    readonly targetId: TargetId;
    readonly targetUrl: string;
    readonly credentialId?: string;
    readonly field?: "password" | "username";
    readonly nodeId?: number;
    readonly ttlMs?: number;
    readonly maxUses?: number;
  }): Promise<{ readonly token: string; readonly record: MaskedTokenRecord }>;
  performTokenizedFill(params: {
    readonly userId: UserId;
    readonly target: TokenizedFillTargetAdapter;
    readonly credentialId?: string;
    readonly field?: "password" | "username";
    readonly nodeId?: number;
  }): Promise<TokenizedFillResult>;
  performSealedFill(params: {
    readonly userId: UserId;
    readonly target: SealedFillTargetAdapter;
    readonly credentialId?: string;
    readonly field?: "password" | "username";
  }): Promise<SealedFillResult>;
  listMaskedTokens(targetId?: TargetId): Promise<MaskedTokenRecord[]>;
  submitWithSealedFallback(params: {
    readonly request: Request;
    readonly metadata?: EgressRequestMetadata;
    readonly fallbackToSealedFill: (
      err: TokenTransformedNeedsSealedRetryError,
    ) => Promise<{ readonly request: Request; readonly metadata?: EgressRequestMetadata }>;
  }): Promise<{ readonly response: Response; readonly fallbackUsed: boolean }>;
  getAuditTrail(): Promise<readonly SignedAuditEntry[]>;
  close(): Promise<void>;
}

const DEFAULT_DEADLINE_MS = 15_000;
const DEFAULT_MAX_REDIRECTS = 10;
const DEFAULT_APPROVAL_TIMEOUT_MS = 30_000;
const HEADER_PREFIX_META = "x-pw-egress-";
const WBA_HEADER_NAMES = ["signature", "signature-input", "signature-agent"] as const;
const TEXT_DECODER = new TextDecoder();
const TEXT_ENCODER = new TextEncoder();

export function ipAddressSpaceIsPublic(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return false;
  try {
    const normalized = family === 6 ? `http://[${address}]` : `http://${address}`;
    return addressSpaceOf(new URL(normalized)) === "public";
  } catch {
    return false;
  }
}

export async function verifyPublicNetworkTarget(
  url: URL,
  lookupFn: (hostname: string) => Promise<readonly LookupAddress[]>,
): Promise<string | null> {
  if (addressSpaceOf(url) !== "public") {
    return `Private or loopback host blocked by SSRF policy: ${url.hostname}`;
  }
  const host = url.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (isIP(host) !== 0) return null;
  let addresses: readonly LookupAddress[];
  try {
    addresses = await lookupFn(host);
  } catch {
    return `DNS lookup failed for ${url.hostname}`;
  }
  if (addresses.length === 0) {
    return `DNS returned no addresses for ${url.hostname}`;
  }
  for (const entry of addresses) {
    if (!ipAddressSpaceIsPublic(entry.address)) {
      return `Host ${url.hostname} resolved to private/loopback IP ${entry.address}`;
    }
  }
  return null;
}

function parseAllowedOriginSet(origins?: ReadonlyArray<string>): ReadonlySet<string> {
  const out = new Set<string>();
  if (!origins) return out;
  for (const raw of origins) {
    const norm = normalizeStrictOrigin(raw);
    if (norm) out.add(norm);
  }
  return out;
}

function extractInternalMetadata(
  headers: Headers,
  explicit?: EgressRequestMetadata,
): { readonly headers: Headers; readonly metadata: EgressRequestMetadata } {
  const clean = new Headers();
  const fromHeaders: Record<string, string> = {};
  for (const [key, val] of headers.entries()) {
    const lower = key.toLowerCase();
    if (lower.startsWith(HEADER_PREFIX_META)) {
      fromHeaders[lower.slice(HEADER_PREFIX_META.length)] = val;
    } else {
      clean.set(key, val);
    }
  }
  const spendRaw = fromHeaders["spend-cents"];
  const parsedSpend = spendRaw !== undefined ? Number(spendRaw) : undefined;
  const deadlineRaw = fromHeaders["deadline-ms"];
  const parsedDeadline = deadlineRaw !== undefined ? Number(deadlineRaw) : undefined;
  const metadata: EgressRequestMetadata = {
    actionClass:
      explicit?.actionClass ?? (fromHeaders["action-class"] as MandateActionClass | undefined),
    spendCents:
      explicit?.spendCents ??
      (parsedSpend !== undefined && Number.isFinite(parsedSpend) ? parsedSpend : undefined),
    credentialId: explicit?.credentialId ?? fromHeaders["credential-id"],
    targetId: explicit?.targetId ?? (fromHeaders["target-id"] as TargetId | undefined),
    sealedOrigin:
      explicit?.sealedOrigin !== undefined
        ? explicit.sealedOrigin
        : (fromHeaders["sealed-origin"] ?? null),
    isTopLevelNavigation: explicit?.isTopLevelNavigation ?? fromHeaders["top-level-nav"] === "1",
    expectTokenSubmit: explicit?.expectTokenSubmit ?? fromHeaders["expect-token-submit"] === "1",
    requireApproval: explicit?.requireApproval ?? fromHeaders["require-approval"] === "1",
    domFields: explicit?.domFields,
    deadlineMs:
      explicit?.deadlineMs ??
      (parsedDeadline !== undefined && Number.isFinite(parsedDeadline)
        ? parsedDeadline
        : undefined),
  };
  return { headers: clean, metadata };
}

function buildCombinedSignal(
  callerSignal: AbortSignal | undefined | null,
  deadlineMs: number,
): {
  readonly signal: AbortSignal;
  readonly cleanup: () => void;
  readonly didTimeout: () => boolean;
} {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(
      new EgressBlockedError("deadline-exceeded", `Egress timed out after ${deadlineMs}ms`),
    );
  }, deadlineMs);

  const onCallerAbort = (): void => {
    controller.abort(callerSignal?.reason ?? new EgressBlockedError("aborted", "Egress aborted"));
  };
  if (callerSignal) {
    if (callerSignal.aborted) {
      onCallerAbort();
    } else {
      callerSignal.addEventListener("abort", onCallerAbort, { once: true });
    }
  }
  const cleanup = (): void => {
    clearTimeout(timer);
    if (callerSignal) callerSignal.removeEventListener("abort", onCallerAbort);
  };
  return { signal: controller.signal, cleanup, didTimeout: () => timedOut };
}

function scrubUrlCrossOrigin(rawUrl: string, injectedSecrets: ReadonlyArray<string>): string {
  const parsed = new URL(rawUrl);
  if (!parsed.search) return parsed.toString();
  let search = parsed.search;
  for (const secret of injectedSecrets) {
    if (secret && search.includes(secret)) search = search.split(secret).join("");
  }
  search = search.replace(/pwtok_[0-9a-fA-F]{6,}/g, "");
  parsed.search = search;
  return parsed.toString();
}

function stripCrossOriginRedirectPayload(
  rawUrl: string,
  headers: Headers,
  bodyBytes: Uint8Array | null,
  injectedSecrets: ReadonlyArray<string>,
): { readonly url: string; readonly headers: Headers; readonly bodyBytes: Uint8Array | null } {
  const stripped = stripCrossOriginSensitiveHeaders(headers);
  let nextBody = bodyBytes;
  if (nextBody && nextBody.byteLength > 0 && injectedSecrets.length > 0) {
    const text = TEXT_DECODER.decode(nextBody);
    let redacted = text;
    for (const secret of injectedSecrets) {
      if (secret && redacted.includes(secret)) {
        redacted = redacted.split(secret).join("");
      }
    }
    if (redacted !== text) nextBody = TEXT_ENCODER.encode(redacted);
  }
  return {
    url: scrubUrlCrossOrigin(rawUrl, injectedSecrets),
    headers: stripped.headers,
    bodyBytes: nextBody,
  };
}

function setSpanStatusCode(span: unknown, status: number): void {
  if (typeof span !== "object" || span === null || !("setTags" in span)) return;
  const setTags = (span as { setTags?: unknown }).setTags;
  if (typeof setTags === "function") {
    (span as { setTags(tags: Record<string, string | number | boolean>): void }).setTags({
      "http.status_code": status,
    });
  }
}

function nextRedirectMethod(
  status: number,
  currentMethod: string,
): { readonly method: string; readonly dropBody: boolean } {
  const upper = currentMethod.trim().toUpperCase();
  if (status === 303 || ((status === 301 || status === 302) && upper === "POST")) {
    return { method: "GET", dropBody: true };
  }
  return { method: upper, dropBody: upper === "GET" || upper === "HEAD" };
}

export interface SerializedBrokerError {
  readonly __ksBrokerError: true;
  readonly name: string;
  readonly code?: string;
  readonly message: string;
  readonly details?: TokenTransformDetails;
}

export function serializeBrokerError(err: unknown): SerializedBrokerError {
  if (err instanceof TokenTransformedNeedsSealedRetryError) {
    return {
      __ksBrokerError: true,
      name: err.name,
      code: err.code,
      message: err.message,
      details: err.details,
    };
  }
  if (err instanceof SealedOriginMismatchError) {
    return {
      __ksBrokerError: true,
      name: err.name,
      message: err.message,
    };
  }
  if (
    err instanceof MandateVerificationError ||
    err instanceof MandateScopeError ||
    err instanceof MandateSpendLimitError ||
    err instanceof EgressBlockedError ||
    err instanceof ApprovalVerificationError
  ) {
    return {
      __ksBrokerError: true,
      name: err.name,
      code: err.code,
      message: err.message,
    };
  }
  if (err instanceof PolicyDecisionError) {
    return {
      __ksBrokerError: true,
      name: err.name,
      code: err.decision.code,
      message: err.message,
    };
  }
  const msg = err instanceof Error ? err.message : String(err);
  const name = err instanceof Error ? err.name : "Error";
  return { __ksBrokerError: true, name, message: msg };
}

export function deserializeBrokerError(raw: SerializedBrokerError): Error {
  if (raw.name === "TokenTransformedNeedsSealedRetryError" && raw.details) {
    return new TokenTransformedNeedsSealedRetryError(raw.details);
  }
  if (raw.name === "MandateVerificationError" && raw.code) {
    return new MandateVerificationError(raw.code as MandateVerificationError["code"], raw.message);
  }
  if (raw.name === "MandateScopeError" && raw.code) {
    return new MandateScopeError(raw.code as MandateScopeError["code"], raw.message);
  }
  if (raw.name === "MandateSpendLimitError" && raw.code) {
    return new MandateSpendLimitError(raw.code as MandateSpendLimitError["code"], raw.message);
  }
  if (raw.name === "EgressBlockedError" && raw.code) {
    return new EgressBlockedError(raw.code as EgressBlockedError["code"], raw.message);
  }
  if (raw.name === "ApprovalVerificationError" && raw.code) {
    return new ApprovalVerificationError(
      raw.code as ApprovalVerificationError["code"],
      raw.message,
    );
  }
  if (raw.name === "PolicyDecisionError" && raw.code) {
    return new PolicyDecisionError({
      allowed: false,
      code: raw.code as PolicyDecisionError["decision"]["code"],
      reason: raw.message,
    });
  }
  const err = new Error(raw.message);
  err.name = raw.name;
  return err;
}

export function createEgressBroker(options: EgressBrokerOptions = {}): EgressBroker {
  const now = options.now ?? (() => Date.now());
  const ownAuthorityPromise = options.authority
    ? Promise.resolve(options.authority)
    : AuthorityVaultAndChannel.create();
  let initializedVault = options.tokenizedVault ?? null;
  const mandateTracker = options.mandateTracker ?? new MandateTracker({ now });
  const policyEngine = options.policyEngine ?? new PolicyEngine({ auditLog: options.auditLog });
  const allowPrivateNetwork = options.allowPrivateNetwork ?? false;
  const allowedPrivateOrigins = parseAllowedOriginSet(options.allowedPrivateOrigins);
  const lookupFn =
    options.lookupFn ??
    ((hostname: string): Promise<LookupAddress[]> => lookup(hostname, { all: true }));
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const defaultDeadlineMs = options.deadlineMs ?? DEFAULT_DEADLINE_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  let hasRegisteredMandates = mandateTracker.listActive(now()).length > 0;
  let verificationKeyCache: CryptoKey | null = options.authority?.publicKey ?? null;

  const resolveVerificationKey = async (
    authority: AuthorityVaultAndChannel,
  ): Promise<{ key: CryptoKey; keyId: string }> => {
    if (options.verificationPublicKeySpkiBase64) {
      verificationKeyCache ??= await importEd25519PublicKeyFromSpkiBase64(
        options.verificationPublicKeySpkiBase64,
      );
      return {
        key: verificationKeyCache,
        keyId: options.verificationKeyId ?? authority.keyId,
      };
    }
    verificationKeyCache ??= authority.publicKey;
    return { key: verificationKeyCache, keyId: options.verificationKeyId ?? authority.keyId };
  };

  let initializedGate = options.approvalGate ?? null;
  const ensureVault = async (): Promise<{
    authority: AuthorityVaultAndChannel;
    vault: TokenizedFillVault;
    approvalGate: ApprovalGate;
  }> => {
    const authority = await ownAuthorityPromise;
    const verifier = await resolveVerificationKey(authority);
    initializedVault ??= new TokenizedFillVault(authority, { now });
    initializedGate ??= new ApprovalGate(authority, {
      now,
      verificationPublicKey: verifier.key,
    });
    return { authority, vault: initializedVault, approvalGate: initializedGate };
  };

  const checkHopAllowed = async (params: {
    url: string;
    method: string;
    metadata: EgressRequestMetadata;
    mandateId: string | null;
    hop: number;
  }): Promise<URL> => {
    let parsed: URL;
    try {
      parsed = new URL(params.url);
    } catch {
      throw new EgressBlockedError("invalid-url", `Invalid URL: ${params.url}`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new EgressBlockedError("invalid-scheme", `Unsupported URL scheme: ${parsed.protocol}`);
    }
    if (!allowPrivateNetwork && !allowedPrivateOrigins.has(parsed.origin)) {
      const ssrfReason = await verifyPublicNetworkTarget(parsed, lookupFn);
      if (ssrfReason) {
        await options.auditLog?.append({
          kind: "egress.ssrf.blocked",
          targetId: params.metadata.targetId,
          detail: { hop: params.hop, origin: parsed.origin, reason: ssrfReason },
        });
        throw new EgressBlockedError("ssrf-blocked", ssrfReason);
      }
    }
    const policyDecision = policyEngine.evaluateEgress({
      url: parsed,
      method: params.method,
      isTopLevelNavigation: params.metadata.isTopLevelNavigation ?? false,
      sealedOrigin: params.metadata.sealedOrigin,
      targetId: params.metadata.targetId,
    });
    if (!policyDecision.allowed) {
      throw new PolicyDecisionError(policyDecision);
    }
    if (params.hop > 0 && params.mandateId) {
      mandateTracker.revalidateRedirectHop({
        mandateId: params.mandateId,
        redirectUrl: params.url,
        method: params.method,
        actionClass: params.metadata.actionClass,
      });
    }
    return parsed;
  };

  const maybeHoldForApproval = async (params: {
    authority: AuthorityVaultAndChannel;
    approvalGate: ApprovalGate;
    url: string;
    method: string;
    headers: Headers;
    bodyBytes: Uint8Array | null;
    metadata: EgressRequestMetadata;
  }): Promise<void> => {
    const spend = params.metadata.spendCents ?? 0;
    const actionClass =
      params.metadata.actionClass ??
      (params.method === "GET" || params.method === "HEAD" ? "read" : "submit");
    const policyResult = options.requiresApproval?.({
      url: params.url,
      method: params.method,
      actionClass,
      spendCents: spend,
      headers: params.headers,
    });
    const customRequired =
      typeof policyResult === "boolean" ? policyResult : (policyResult?.required ?? false);
    const needed = Boolean(params.metadata.requireApproval || customRequired);
    if (!needed) return;

    const domFields =
      typeof policyResult === "object" && policyResult.domFields
        ? policyResult.domFields
        : (params.metadata.domFields ?? []);
    if (!options.onApprovalPrompt) {
      throw new EgressBlockedError(
        "approval-unavailable",
        "Held egress requires an approval prompt handler",
      );
    }
    const headerRecord: Record<string, string> = {};
    for (const [k, v] of params.headers.entries()) headerRecord[k] = v;
    const dispatchApprovalPrompt = async (pending: PendingApprovalRequest): Promise<void> => {
      try {
        const decision = await options.onApprovalPrompt!(pending);
        const signed =
          "signatureBase64" in decision
            ? decision
            : await params.approvalGate.signDecision({
                requestDigest: pending.requestDigest,
                nonce: pending.nonce,
                expiresAt: pending.expiresAt,
                approved: decision.approved,
              });
        await params.approvalGate.resolveWithSignedDecision(signed);
      } catch {
        params.approvalGate.cancelPending(pending.nonce, "denied");
      }
    };
    const outcome = await params.approvalGate.holdForApproval({
      action: {
        method: params.method,
        url: params.url,
        headers: headerRecord,
        body: params.bodyBytes,
      },
      domFields,
      timeoutMs: options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS,
      onPrompt: (pending) => {
        void dispatchApprovalPrompt(pending);
      },
    });
    if (!outcome.approved) {
      throw new ApprovalVerificationError(
        outcome.reason === "timeout" ? "expired" : outcome.reason,
        `Held egress approval rejected (${outcome.reason})`,
      );
    }
  };

  const runRedirectLoop = async (params: {
    initialUrl: string;
    initialMethod: string;
    initialHeaders: Headers;
    initialBodyBytes: Uint8Array | null;
    metadata: EgressRequestMetadata;
    mandateId: string | null;
    swappedCredentialCount: number;
    swappedSecrets: ReadonlyArray<string>;
    deadlineMs: number;
    signal: AbortSignal;
    didTimeout: () => boolean;
    span: unknown;
  }): Promise<Response> => {
    let currentUrl = params.initialUrl;
    let currentMethod = params.initialMethod;
    let currentHeaders = params.initialHeaders;
    let currentBodyBytes = params.initialBodyBytes;
    let prevOrigin = normalizeStrictOrigin(currentUrl);

    for (let hop = 0; hop <= maxRedirects; hop++) {
      if (params.signal.aborted) {
        throw params.didTimeout()
          ? new EgressBlockedError(
              "deadline-exceeded",
              `Egress deadline (${params.deadlineMs}ms) exceeded`,
            )
          : new EgressBlockedError("aborted", "Egress aborted by signal");
      }
      const parsedHop =
        hop === 0
          ? new URL(currentUrl)
          : await checkHopAllowed({
              url: currentUrl,
              method: currentMethod,
              metadata: params.metadata,
              mandateId: params.mandateId,
              hop,
            });

      const nextOrigin = normalizeStrictOrigin(currentUrl);
      if (hop > 0 && nextOrigin !== prevOrigin) {
        const cleaned = stripCrossOriginRedirectPayload(
          currentUrl,
          currentHeaders,
          currentBodyBytes,
          params.swappedSecrets,
        );
        currentUrl = cleaned.url;
        currentHeaders = cleaned.headers;
        currentBodyBytes = cleaned.bodyBytes;
      }
      prevOrigin = nextOrigin;

      const wireHeaders = new Headers(currentHeaders);
      for (const wbaName of WBA_HEADER_NAMES) wireHeaders.delete(wbaName);
      if (options.wbaConfig) {
        const signed = await wbaHeadersFor(options.wbaConfig, parsedHop.host);
        for (const [k, v] of Object.entries(signed)) wireHeaders.set(k, v);
      }

      const hopReq = new Request(currentUrl, {
        method: currentMethod,
        headers: wireHeaders,
        body:
          currentBodyBytes && currentMethod !== "GET" && currentMethod !== "HEAD"
            ? new Uint8Array(currentBodyBytes)
            : undefined,
        redirect: "manual",
        signal: params.signal,
      });

      let response: Response;
      try {
        response = await fetchFn(hopReq);
      } catch (err) {
        if (params.signal.aborted) {
          throw params.didTimeout()
            ? new EgressBlockedError(
                "deadline-exceeded",
                `Egress deadline (${params.deadlineMs}ms) exceeded`,
              )
            : new EgressBlockedError("aborted", "Egress aborted by signal");
        }
        throw err;
      }

      const location = response.headers.get("location");
      const isRedirect = response.status >= 300 && response.status < 400 && Boolean(location);
      if (!isRedirect || !location) {
        setSpanStatusCode(params.span, response.status);
        await options.auditLog?.append({
          kind: "egress.completed",
          targetId: params.metadata.targetId,
          detail: {
            method: currentMethod,
            origin: parsedHop.origin,
            status: response.status,
            hops: hop,
            mandateId: params.mandateId,
            swappedCredentials: params.swappedCredentialCount,
          },
        });
        return response;
      }

      void response.body?.cancel().catch(() => {});
      if (hop + 1 > maxRedirects) {
        throw new EgressBlockedError(
          "too-many-redirects",
          `Exceeded max redirects (${maxRedirects})`,
        );
      }
      const resolvedNext = new URL(location, currentUrl).toString();
      const redirectMethod = nextRedirectMethod(response.status, currentMethod);
      currentUrl = resolvedNext;
      currentMethod = redirectMethod.method;
      if (redirectMethod.dropBody) {
        currentBodyBytes = null;
        currentHeaders.delete("content-type");
        currentHeaders.delete("content-length");
      }
    }
    throw new EgressBlockedError("too-many-redirects", `Exceeded max redirects (${maxRedirects})`);
  };

  const executeFetch = async (
    input: Request | string | URL,
    init?: RequestInit & { metadata?: EgressRequestMetadata },
  ): Promise<Response> => {
    const req = input instanceof Request ? input : new Request(input, init);
    const { headers: baseHeaders, metadata } = extractInternalMetadata(req.headers, init?.metadata);
    const rawBodyBytes =
      req.method === "GET" || req.method === "HEAD"
        ? null
        : new Uint8Array(await req.clone().arrayBuffer());

    const deadlineMs = metadata.deadlineMs ?? defaultDeadlineMs;
    const { signal, cleanup, didTimeout } = buildCombinedSignal(
      init?.signal ?? req.signal,
      deadlineMs,
    );

    const { authority, vault, approvalGate } = await ensureVault();
    const enforceMandate = Boolean(options.requireMandate || hasRegisteredMandates);
    let reservedMandate: MandatePayload | null = null;
    const spend = metadata.spendCents ?? 0;

    return traceSpan(
      options.tracer,
      "egress.broker.fetch",
      async (span) => {
        try {
          const initialUrl = req.url;
          const initialMethod = req.method.trim().toUpperCase();
          if (enforceMandate) {
            reservedMandate = mandateTracker.authorizeRequest({
              url: initialUrl,
              method: initialMethod,
              actionClass: metadata.actionClass,
              spendCents: spend,
              credentialId: metadata.credentialId,
            });
          }

          await checkHopAllowed({
            url: initialUrl,
            method: initialMethod,
            metadata,
            mandateId: reservedMandate?.id ?? null,
            hop: 0,
          });

          const bodyText =
            rawBodyBytes && rawBodyBytes.byteLength > 0 ? TEXT_DECODER.decode(rawBodyBytes) : null;
          let swapResult: ReturnType<TokenizedFillVault["processOutboundRequest"]>;
          try {
            swapResult = vault.processOutboundRequest({
              targetUrl: initialUrl,
              method: initialMethod,
              headers: baseHeaders,
              bodyText,
              targetId: metadata.targetId,
              expectTokenSubmit: metadata.expectTokenSubmit,
            });
          } catch (err) {
            if (err instanceof TokenTransformedNeedsSealedRetryError) {
              await options.auditLog?.append({
                kind: "egress.token.transformed",
                targetId: err.details.targetId,
                detail: {
                  boundOrigin: err.details.boundOrigin,
                  credentialId: err.details.credentialId,
                  reason: err.details.reason,
                },
              });
            }
            throw err;
          }

          const preparedHeaders = swapResult.headers;
          const preparedBodyBytes =
            swapResult.bodyText !== null && rawBodyBytes !== null
              ? TEXT_ENCODER.encode(swapResult.bodyText)
              : rawBodyBytes;

          await maybeHoldForApproval({
            authority,
            approvalGate,
            url: initialUrl,
            method: initialMethod,
            headers: preparedHeaders,
            bodyBytes: preparedBodyBytes,
            metadata,
          });

          return await runRedirectLoop({
            initialUrl,
            initialMethod,
            initialHeaders: preparedHeaders,
            initialBodyBytes: preparedBodyBytes,
            metadata,
            mandateId: reservedMandate?.id ?? null,
            swappedCredentialCount: swapResult.swappedCredentialIds.length,
            swappedSecrets: swapResult.swappedSecrets,
            deadlineMs,
            signal,
            didTimeout,
            span,
          });
        } catch (err) {
          if (reservedMandate && spend > 0) {
            mandateTracker.releaseSpend(reservedMandate.id, spend);
          }
          throw err;
        } finally {
          cleanup();
        }
      },
      { "egress.method": req.method },
    );
  };

  return {
    fetch: executeFetch,
    asExternalOutbound(): ExternalOutbound {
      return {
        fetch: (request: Request) => executeFetch(request),
      };
    },
    async registerMandate(mandate: SignedMandate): Promise<MandatePayload> {
      const authority = await ownAuthorityPromise;
      const { key, keyId } = await resolveVerificationKey(authority);
      const payload = await mandateTracker.registerWithPublicKey(key, keyId, mandate);
      hasRegisteredMandates = true;
      return payload;
    },
    async revokeMandate(mandateId: string): Promise<void> {
      mandateTracker.revoke(mandateId);
    },
    async storeCredential(input: VaultCredentialInput): Promise<MaskedVaultCredential> {
      const authority = await ownAuthorityPromise;
      return authority.storeCredential(input);
    },
    async issueToken(
      params,
    ): Promise<{ readonly token: string; readonly record: MaskedTokenRecord }> {
      const { vault } = await ensureVault();
      return vault.issueToken(params);
    },
    async performTokenizedFill(params): Promise<TokenizedFillResult> {
      const { vault } = await ensureVault();
      return vault.performTokenizedFill(params);
    },
    async performSealedFill(params): Promise<SealedFillResult> {
      const authority = await ownAuthorityPromise;
      return authority.performSealedFill(params);
    },
    async listMaskedTokens(targetId?: TargetId): Promise<MaskedTokenRecord[]> {
      const { vault } = await ensureVault();
      return vault.listMaskedTokens(targetId);
    },
    async submitWithSealedFallback(params): Promise<{
      readonly response: Response;
      readonly fallbackUsed: boolean;
    }> {
      try {
        const response = await executeFetch(params.request, { metadata: params.metadata });
        return { response, fallbackUsed: false };
      } catch (err) {
        if (!(err instanceof TokenTransformedNeedsSealedRetryError)) {
          throw err;
        }
        const sealedSubmission = await params.fallbackToSealedFill(err);
        const response = await executeFetch(sealedSubmission.request, {
          metadata: {
            ...params.metadata,
            ...sealedSubmission.metadata,
            sealedOrigin: err.details.boundOrigin,
            expectTokenSubmit: false,
          },
        });
        return { response, fallbackUsed: true };
      }
    },
    async getAuditTrail(): Promise<readonly SignedAuditEntry[]> {
      return options.auditLog ? options.auditLog.getEntries() : [];
    },
    async close(): Promise<void> {},
  };
}
