// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Out-of-process isolated Egress Broker worker communicating over stdio PRWP frames.

import { Readable, Writable } from "node:stream";
import type {
  PendingApprovalRequest,
  SignedApprovalDecision,
} from "@parawing/engine/approval-gate";
import { SignedAuditLog } from "@parawing/engine/audit-log";
import {
  AuthorityVaultAndChannel,
  type VaultCredentialInput,
} from "@parawing/engine/authority-service";
import type { SignedMandate } from "@parawing/engine/mandates";
import { PolicyEngine, type PolicyEngineOptions } from "@parawing/engine/policy-engine";
import type { TargetId, UserId } from "@parawing/engine/session-identities";
import type { WbaConfigSource } from "@parawing/engine/web-bot-auth";
import { createRpcSession, type RpcHandlerContext, type RpcSession } from "@parawing/rpc-transport";
import {
  createEgressBroker,
  serializeBrokerError,
  type EgressBroker,
  type EgressRequestMetadata,
  type SerializedBrokerError,
} from "./egress-broker-core.ts";

export interface BrokerWorkerInitParams {
  readonly verificationPublicKeySpkiBase64?: string;
  readonly verificationKeyId?: string;
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
  readonly wbaConfig?: WbaConfigSource;
}

export interface SerializedFetchInput {
  readonly url: string;
  readonly method: string;
  readonly headers: Array<[string, string]>;
  readonly bodyBase64: string | null;
  readonly metadata?: EgressRequestMetadata;
}

export type WorkerRpcResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly error: SerializedBrokerError };

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function createWorkerRuntime(): void {
  let broker: EgressBroker | null = null;
  let session!: RpcSession;

  const fail = (err: unknown): { readonly ok: false; readonly error: SerializedBrokerError } => ({
    ok: false,
    error: serializeBrokerError(err),
  });

  const handleInit = async (
    params: BrokerWorkerInitParams,
  ): Promise<WorkerRpcResult<{ ready: true }>> => {
    try {
      const workerAuthority = await AuthorityVaultAndChannel.create();
      const createdAudit = new SignedAuditLog(workerAuthority);
      const policyEngine = params.policyOptions
        ? new PolicyEngine({ ...params.policyOptions, auditLog: createdAudit })
        : new PolicyEngine({ auditLog: createdAudit });
      const spendThreshold = params.requireApprovalSpendAboveCents;
      const approvalActions = new Set(params.requireApprovalActionClasses ?? []);
      const approvalMethods = new Set((params.approvalMethods ?? []).map((m) => m.toUpperCase()));
      const needsApprovalCheck =
        spendThreshold !== undefined || approvalActions.size > 0 || approvalMethods.size > 0;

      broker = createEgressBroker({
        verificationPublicKeySpkiBase64: params.verificationPublicKeySpkiBase64,
        verificationKeyId: params.verificationKeyId,
        policyEngine,
        requireMandate: params.requireMandate,
        auditLog: createdAudit,
        wbaConfig: params.wbaConfig,
        allowPrivateNetwork: params.allowPrivateNetwork,
        allowedPrivateOrigins: params.allowedPrivateOrigins,
        deadlineMs: params.deadlineMs,
        maxRedirects: params.maxRedirects,
        approvalTimeoutMs: params.approvalTimeoutMs,
        requiresApproval: needsApprovalCheck
          ? (check) => {
              if (spendThreshold !== undefined && check.spendCents > spendThreshold) return true;
              if (approvalActions.has(check.actionClass)) return true;
              if (approvalMethods.has(check.method.toUpperCase())) return true;
              return false;
            }
          : undefined,
        onApprovalPrompt: async (pending: PendingApprovalRequest) => {
          const reply = (await session.call("promptApproval", [pending])) as
            | SignedApprovalDecision
            | { approved: boolean };
          return reply;
        },
      });
      return { ok: true, data: { ready: true } };
    } catch (err) {
      return fail(err);
    }
  };

  const requireBroker = (): EgressBroker => {
    if (!broker) throw new Error("Egress broker worker not initialized");
    return broker;
  };

  const handleCall = async (
    method: string,
    args: unknown[],
    ctx: RpcHandlerContext,
  ): Promise<unknown> => {
    if (method === "init") {
      return handleInit((args[0] ?? {}) as BrokerWorkerInitParams);
    }
    if (method === "close") {
      await broker?.close();
      broker = null;
      return { ok: true, data: { closed: true } };
    }
    try {
      const b = requireBroker();
      if (method === "registerMandate") {
        const res = await b.registerMandate(args[0] as SignedMandate);
        return { ok: true, data: res };
      }
      if (method === "revokeMandate") {
        await b.revokeMandate(String(args[0]));
        return { ok: true, data: { revoked: true } };
      }
      if (method === "storeCredential") {
        const res = await b.storeCredential(args[0] as VaultCredentialInput);
        return { ok: true, data: res };
      }
      if (method === "issueToken") {
        const params = args[0] as {
          userId: UserId;
          targetId: TargetId;
          targetUrl: string;
          credentialId?: string;
          field?: "password" | "username";
          nodeId?: number;
          ttlMs?: number;
          maxUses?: number;
        };
        const issued = await b.issueToken(params);
        return { ok: true, data: issued };
      }
      if (method === "listMaskedTokens") {
        const list = await b.listMaskedTokens(args[0] as TargetId | undefined);
        return { ok: true, data: list };
      }
      if (method === "getAuditTrail") {
        const entries = await b.getAuditTrail();
        return { ok: true, data: entries };
      }
      if (method === "fetch") {
        const reqSpec = args[0] as SerializedFetchInput;
        const headers = new Headers();
        for (const [k, v] of reqSpec.headers) headers.append(k, v);
        const body = reqSpec.bodyBase64 ? fromBase64(reqSpec.bodyBase64) : undefined;
        const resp = await b.fetch(
          new Request(reqSpec.url, {
            method: reqSpec.method,
            headers,
            body: body ? new Uint8Array(body) : undefined,
            signal: ctx.signal,
          }),
          { metadata: reqSpec.metadata, signal: ctx.signal },
        );
        const respBytes = new Uint8Array(await resp.arrayBuffer());
        const respHeaders: Array<[string, string]> = [];
        for (const [k, v] of resp.headers.entries()) respHeaders.push([k, v]);
        return {
          ok: true,
          data: {
            status: resp.status,
            statusText: resp.statusText,
            headers: respHeaders,
            bodyBase64: toBase64(respBytes),
          },
        };
      }
      return fail(new Error(`Unknown broker worker method: ${method}`));
    } catch (err) {
      return fail(err);
    }
  };

  session = createRpcSession({
    role: "server",
    readable: Readable.toWeb(process.stdin) as ReadableStream<Uint8Array>,
    writable: Writable.toWeb(process.stdout) as WritableStream<Uint8Array>,
    onCall: handleCall,
  });
}

createWorkerRuntime();
