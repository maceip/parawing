// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Standalone isolated and out-of-process Egress Broker enforcing mandates, SSRF, WBA, and A2.

import { spawn, type ChildProcessByStdio } from "node:child_process";
import { dirname, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import type {
  PendingApprovalRequest,
  SignedApprovalDecision,
} from "@parawing/engine/approval-gate";
import type { SignedAuditEntry } from "@parawing/engine/audit-log";
import {
  AuthorityVaultAndChannel,
  type MaskedVaultCredential,
  type SealedFillResult,
  type SealedFillTargetAdapter,
  type VaultCredentialInput,
} from "@parawing/engine/authority-service";
import type { ExternalOutbound } from "@parawing/engine/external-outbound";
import {
  TokenTransformedNeedsSealedRetryError,
  type MandatePayload,
  type MaskedTokenRecord,
  type SignedMandate,
  type TokenizedFillResult,
} from "@parawing/engine/mandates";
import type { PolicyEngineOptions } from "@parawing/engine/policy-engine";
import type { TargetId } from "@parawing/engine/session-identities";
import type { WbaConfigSource } from "@parawing/engine/web-bot-auth";
import { createRpcSession } from "@parawing/rpc-transport";
import {
  ApprovalVerificationError,
  CredentialNotFoundError,
  EgressBlockedError,
  MandateScopeError,
  MandateSpendLimitError,
  MandateVerificationError,
  PolicyDecisionError,
  SealedOriginMismatchError,
  createEgressBroker,
  deserializeBrokerError,
  ipAddressSpaceIsPublic,
  verifyPublicNetworkTarget,
  type EgressApprovalCheck,
  type EgressBroker,
  type EgressBrokerOptions,
  type EgressRequestMetadata,
  type SerializedBrokerError,
} from "./egress-broker-core.ts";
import type {
  BrokerWorkerInitParams,
  SerializedFetchInput,
  WorkerRpcResult,
} from "./egress-broker-worker.ts";

export {
  ApprovalVerificationError,
  CredentialNotFoundError,
  EgressBlockedError,
  MandateScopeError,
  MandateSpendLimitError,
  MandateVerificationError,
  PolicyDecisionError,
  SealedOriginMismatchError,
  TokenTransformedNeedsSealedRetryError,
  createEgressBroker,
  ipAddressSpaceIsPublic,
  verifyPublicNetworkTarget,
  type EgressApprovalCheck,
  type EgressBroker,
  type EgressBrokerOptions,
  type EgressRequestMetadata,
};

export interface OutOfProcessEgressBrokerOptions {
  readonly authority?: AuthorityVaultAndChannel;
  readonly policyOptions?: PolicyEngineOptions;
  readonly requireMandate?: boolean;
  readonly allowPrivateNetwork?: boolean;
  readonly allowedPrivateOrigins?: ReadonlyArray<string>;
  readonly deadlineMs?: number;
  readonly maxRedirects?: number;
  readonly approvalTimeoutMs?: number;
  readonly approvalMethods?: ReadonlyArray<string>;
  readonly requireApprovalSpendAboveCents?: number;
  readonly requireApprovalActionClasses?: ReadonlyArray<string>;
  readonly onApprovalPrompt?: (
    pending: PendingApprovalRequest,
  ) => Promise<SignedApprovalDecision | { readonly approved: boolean }>;
  readonly wbaConfig?: WbaConfigSource;
  readonly workerEntryPath?: string;
}

const DEFAULT_WORKER_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../dist/egress-broker-worker.mjs",
);

const TEXT_ENCODER = new TextEncoder();

function unwrapWorkerResult<T>(raw: unknown): T {
  const res = raw as WorkerRpcResult<T>;
  if (!res || typeof res !== "object" || !("ok" in res)) {
    throw new Error("Invalid response from egress broker worker");
  }
  if (!res.ok) {
    throw deserializeBrokerError(res.error as SerializedBrokerError);
  }
  return res.data;
}

async function signDecisionWithAuthority(
  authority: AuthorityVaultAndChannel,
  pending: PendingApprovalRequest,
  approved: boolean,
): Promise<SignedApprovalDecision> {
  const payload = {
    requestDigest: pending.requestDigest,
    nonce: pending.nonce,
    expiresAt: pending.expiresAt,
    approved,
  };
  const signatureBase64 = await authority.signBytes(TEXT_ENCODER.encode(JSON.stringify(payload)));
  return { payload, signatureBase64 };
}

export async function createOutOfProcessEgressBroker(
  options: OutOfProcessEgressBrokerOptions = {},
): Promise<EgressBroker & { readonly pid: number | undefined }> {
  const authority = options.authority ?? (await AuthorityVaultAndChannel.create());
  const spkiBytes = new Uint8Array(await crypto.subtle.exportKey("spki", authority.publicKey));
  const spkiBase64 = Buffer.from(spkiBytes).toString("base64");
  const workerPath = options.workerEntryPath ?? DEFAULT_WORKER_PATH;

  const child: ChildProcessByStdio<Writable, Readable, Readable> = spawn(
    process.execPath,
    [workerPath],
    {
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const stderrChunks: string[] = [];
  child.stderr.on("data", (chunk: Buffer) => {
    stderrChunks.push(chunk.toString("utf8"));
  });

  const rpc = createRpcSession({
    role: "client",
    readable: Readable.toWeb(child.stdout) as ReadableStream<Uint8Array>,
    writable: Writable.toWeb(child.stdin) as WritableStream<Uint8Array>,
    onCall: async (method, args) => {
      if (method === "promptApproval") {
        const pending = args[0] as PendingApprovalRequest;
        if (!options.onApprovalPrompt) {
          return signDecisionWithAuthority(authority, pending, false);
        }
        const reply = await options.onApprovalPrompt(pending);
        if ("signatureBase64" in reply) return reply;
        return signDecisionWithAuthority(authority, pending, reply.approved);
      }
      throw new Error(`Unknown reverse RPC from broker worker: ${method}`);
    },
  });

  const initParams: BrokerWorkerInitParams = {
    verificationPublicKeySpkiBase64: spkiBase64,
    verificationKeyId: authority.keyId,
    policyOptions: options.policyOptions,
    requireMandate: options.requireMandate,
    allowPrivateNetwork: options.allowPrivateNetwork,
    allowedPrivateOrigins: options.allowedPrivateOrigins,
    deadlineMs: options.deadlineMs,
    maxRedirects: options.maxRedirects,
    approvalTimeoutMs: options.approvalTimeoutMs,
    approvalMethods: options.approvalMethods,
    requireApprovalSpendAboveCents: options.requireApprovalSpendAboveCents,
    requireApprovalActionClasses: options.requireApprovalActionClasses,
    wbaConfig: options.wbaConfig,
  };

  try {
    unwrapWorkerResult(await rpc.call("init", [initParams]));
  } catch (err) {
    child.kill("SIGKILL");
    const stderr = stderrChunks.join("");
    throw new Error(
      `Out-of-process egress broker failed to initialize: ${String(err)}${stderr ? `\n${stderr}` : ""}`,
    );
  }

  let closed = false;

  const executeFetch = async (
    input: Request | string | URL,
    init?: RequestInit & { metadata?: EgressRequestMetadata },
  ): Promise<Response> => {
    const req = input instanceof Request ? input : new Request(input, init);
    const signal = init?.signal ?? req.signal;
    const headers: Array<[string, string]> = [];
    for (const [k, v] of req.headers.entries()) headers.push([k, v]);
    let bodyBase64: string | null = null;
    if (req.method !== "GET" && req.method !== "HEAD") {
      const bytes = new Uint8Array(await req.clone().arrayBuffer());
      if (bytes.byteLength > 0) bodyBase64 = Buffer.from(bytes).toString("base64");
    }
    const spec: SerializedFetchInput = {
      url: req.url,
      method: req.method,
      headers,
      bodyBase64,
      metadata: init?.metadata,
    };
    const raw = await rpc.call("fetch", [spec], { signal });
    const data = unwrapWorkerResult<{
      status: number;
      statusText: string;
      headers: Array<[string, string]>;
      bodyBase64: string;
    }>(raw);
    const outHeaders = new Headers();
    for (const [k, v] of data.headers) outHeaders.append(k, v);
    const respBytes = data.bodyBase64 ? Buffer.from(data.bodyBase64, "base64") : new Uint8Array(0);
    return new Response(respBytes, {
      status: data.status,
      statusText: data.statusText,
      headers: outHeaders,
    });
  };

  const issueTokenRpc = async (params: {
    readonly userId: VaultCredentialInput["userId"];
    readonly targetId: TargetId;
    readonly targetUrl: string;
    readonly credentialId?: string;
    readonly field?: "password" | "username";
    readonly nodeId?: number;
    readonly ttlMs?: number;
    readonly maxUses?: number;
  }): Promise<{ readonly token: string; readonly record: MaskedTokenRecord }> => {
    return unwrapWorkerResult<{ readonly token: string; readonly record: MaskedTokenRecord }>(
      await rpc.call("issueToken", [params]),
    );
  };

  return {
    get pid(): number | undefined {
      return child.pid;
    },
    fetch: executeFetch,
    asExternalOutbound(): ExternalOutbound {
      return {
        fetch: (request: Request) => executeFetch(request),
      };
    },
    async registerMandate(mandate: SignedMandate): Promise<MandatePayload> {
      return unwrapWorkerResult<MandatePayload>(await rpc.call("registerMandate", [mandate]));
    },
    async revokeMandate(mandateId: string): Promise<void> {
      unwrapWorkerResult(await rpc.call("revokeMandate", [mandateId]));
    },
    async storeCredential(input: VaultCredentialInput): Promise<MaskedVaultCredential> {
      authority.storeCredential(input);
      return unwrapWorkerResult<MaskedVaultCredential>(await rpc.call("storeCredential", [input]));
    },
    issueToken: issueTokenRpc,
    async performTokenizedFill(params): Promise<TokenizedFillResult> {
      const issued = await issueTokenRpc({
        userId: params.userId,
        targetId: params.target.targetId,
        targetUrl: params.target.currentUrl,
        credentialId: params.credentialId,
        field: params.field,
        nodeId: params.nodeId,
      });
      const filled = await params.target.injectTokenIntoControl(issued.token);
      if (!filled) {
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
    },
    async performSealedFill(params: {
      readonly userId: VaultCredentialInput["userId"];
      readonly target: SealedFillTargetAdapter;
      readonly credentialId?: string;
      readonly field?: "password" | "username";
    }): Promise<SealedFillResult> {
      return authority.performSealedFill(params);
    },
    async listMaskedTokens(targetId?: TargetId): Promise<MaskedTokenRecord[]> {
      return unwrapWorkerResult<MaskedTokenRecord[]>(
        await rpc.call("listMaskedTokens", [targetId]),
      );
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
      return unwrapWorkerResult<readonly SignedAuditEntry[]>(await rpc.call("getAuditTrail", []));
    },
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      try {
        await Promise.race([
          rpc.call("close", []),
          new Promise((resolve) => setTimeout(resolve, 300)),
        ]);
      } catch {}
      try {
        await rpc.close();
      } catch {}
      if (!child.killed && child.exitCode === null) {
        child.kill("SIGKILL");
      }
    },
  };
}
