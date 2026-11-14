// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Bundled @parawing/engine entrypoint for standalone Node/Deno hosts.

import coreWasm from "../../core/pkg/parawing_core_bg.wasm";
import rendererWasm from "../../renderer-core/pkg/renderer_core_bg.wasm";
import {
  PageScriptTail,
  SandboxOutbound,
  SpanSink,
  createMemoryHostCapabilities,
  handleCdpSession,
  notifyIsolateLimit,
  parsePositiveMsCap,
  registerVfsWasmBytes,
  traceSpan,
  type CdpSessionHandle,
  type CdpSessionOptions,
  type CdpSessionTransport,
  type HostCapabilities,
  type OutboundProps,
} from "@parawing/engine/embed";
import { decryptAes256Gcm, encryptAes256Gcm } from "@parawing/engine/aes256-gcm";
import {
  ApprovalGate,
  ApprovalVerificationError,
  computeHttpActionDigest,
} from "@parawing/engine/approval-gate";
import { SignedAuditLog, verifyAuditChain } from "@parawing/engine/audit-log";
import {
  AuthorityVaultAndChannel,
  CredentialNotFoundError,
  SealedOriginMismatchError,
} from "@parawing/engine/authority-service";
import {
  captureTier1Checkpoint,
  filterInputJournalForReplay,
  restoreTier1Checkpoint,
} from "@parawing/engine/checkpoint";
import {
  ControllerLeaseConflictError,
  ControllerLeaseManager,
} from "@parawing/engine/controller-lease";
import {
  EncryptedSessionStore,
  InMemoryCipherBackend,
  buildCipherAad,
  type CipherRowBackend,
} from "@parawing/engine/encrypted-session-store";
import {
  KeyLeaseExpiredError,
  KeyLeaseManager,
  KeyLeaseSignatureError,
  verifySignedKeyLease,
} from "@parawing/engine/key-lease";
import {
  MandateScopeError,
  MandateSpendLimitError,
  MandateTracker,
  MandateVerificationError,
  TokenTransformedNeedsSealedRetryError,
  TokenizedFillVault,
  signMandate,
  verifyMandate,
} from "@parawing/engine/mandates";
import { PolicyDecisionError, PolicyEngine } from "@parawing/engine/policy-engine";
import {
  SessionDestroyedError,
  SessionNotFoundError,
  StaleEpochError,
  asConnectionId,
  asSessionId,
  asTargetId,
  asUserId,
  type ConnectionId,
  type ConnectionRole,
  type SessionId,
  type TargetId,
  type UserId,
} from "@parawing/engine/session-identities";
import { SessionManager } from "@parawing/engine/session-manager";
import {
  MemorySessionStore,
  isStoredBytes,
  isStoredString,
  type SessionStore,
} from "@parawing/engine/session-store";
import { WebStoragePersistenceBridge } from "@parawing/engine/web-storage-bridge";
import type { SpanContext } from "@parawing/engine/tracing";
import { addressSpaceOf, type AddressSpace } from "@parawing/engine/private-network";
import {
  AuthorityWebAuthnAuthenticator,
  HostWebAuthnClient,
  WebAuthnSecurityError,
  verifyWebAuthnAssertion,
} from "@parawing/engine/webauthn";
import { getBundledWasmBytes } from "./wasm-bytes-registry.ts";

if (typeof (Uint8Array.prototype as { toBase64?: unknown }).toBase64 !== "function") {
  Object.defineProperty(Uint8Array.prototype, "toBase64", {
    configurable: true,
    writable: true,
    value(this: Uint8Array): string {
      return Buffer.from(this.buffer, this.byteOffset, this.byteLength).toString("base64");
    },
  });
}
if (typeof (Uint8Array as { fromBase64?: unknown }).fromBase64 !== "function") {
  Object.defineProperty(Uint8Array, "fromBase64", {
    configurable: true,
    writable: true,
    value(value: string): Uint8Array<ArrayBuffer> {
      const buf = Buffer.from(value, "base64");
      const out = new Uint8Array(new ArrayBuffer(buf.length));
      out.set(buf);
      return out;
    },
  });
}

const coreBytes = getBundledWasmBytes(coreWasm);
if (coreBytes) {
  registerVfsWasmBytes("parawing_core_bg.wasm", coreBytes);
}
const rendererBytes = getBundledWasmBytes(rendererWasm);
if (rendererBytes) {
  registerVfsWasmBytes("renderer_core_bg.wasm", rendererBytes);
}

export interface TailLogEntry {
  timestamp: number;
  level: string;
  message: unknown[];
}

export interface TailExceptionEntry {
  timestamp: number;
  name: string;
  message: string;
  stack?: string;
}

export interface ChildTailEvent {
  logs: TailLogEntry[];
  exceptions: TailExceptionEntry[];
  outcome: string;
  cpuTime: number;
  wallTime: number;
}

export interface SpanSinkProps {
  kind: string;
  localTraceParent?: SpanContext;
}

export interface TailProps {
  scriptName: string;
  pageDomain?: string;
  ksErrToken?: string;
  sessionId?: string;
}

export function invokeSandboxOutbound(
  host: HostCapabilities,
  props: OutboundProps | object | undefined,
  request: Request,
): Promise<Response> {
  return SandboxOutbound.handle(host, props as OutboundProps | undefined, request);
}

export function createSpanSinkTarget(
  host: HostCapabilities,
  props: SpanSinkProps,
): { emit(records: string[]): number } {
  const ctx = {
    props,
    waitUntil: (promise: Promise<unknown>): void => host.tasks.run(promise),
    passThroughOnException: (): void => {},
  };
  const instance = Reflect.construct(SpanSink, [ctx, { HOST_TRACER: host.tracer }]) as SpanSink;
  return {
    emit: (records: string[]): number => instance.emit(records),
  };
}

export function dispatchTailEvent(
  host: HostCapabilities,
  props: TailProps,
  item: ChildTailEvent,
): void {
  const ctx = {
    props,
    waitUntil: (promise: Promise<unknown>): void => host.tasks.run(promise),
    passThroughOnException: (): void => {},
  };
  const tail = Reflect.construct(PageScriptTail, [
    ctx,
    { HOST_TRACER: host.tracer },
  ]) as PageScriptTail;
  Reflect.apply(tail.tail, tail, [[item]]);
}

export {
  ApprovalGate,
  ApprovalVerificationError,
  AuthorityVaultAndChannel,
  AuthorityWebAuthnAuthenticator,
  ControllerLeaseConflictError,
  HostWebAuthnClient,
  WebAuthnSecurityError,
  verifyWebAuthnAssertion,
  ControllerLeaseManager,
  CredentialNotFoundError,
  EncryptedSessionStore,
  InMemoryCipherBackend,
  KeyLeaseExpiredError,
  KeyLeaseManager,
  KeyLeaseSignatureError,
  MandateScopeError,
  MandateSpendLimitError,
  MandateTracker,
  MandateVerificationError,
  MemorySessionStore,
  PolicyDecisionError,
  PolicyEngine,
  SealedOriginMismatchError,
  SessionDestroyedError,
  SessionManager,
  SessionNotFoundError,
  SignedAuditLog,
  StaleEpochError,
  TokenTransformedNeedsSealedRetryError,
  TokenizedFillVault,
  WebStoragePersistenceBridge,
  addressSpaceOf,
  asConnectionId,
  asSessionId,
  asTargetId,
  asUserId,
  buildCipherAad,
  captureTier1Checkpoint,
  computeHttpActionDigest,
  createMemoryHostCapabilities,
  decryptAes256Gcm,
  encryptAes256Gcm,
  filterInputJournalForReplay,
  handleCdpSession,
  isStoredBytes,
  isStoredString,
  notifyIsolateLimit,
  parsePositiveMsCap,
  restoreTier1Checkpoint,
  signMandate,
  traceSpan,
  verifyAuditChain,
  verifyMandate,
  verifySignedKeyLease,
};
export type {
  AddressSpace,
  CdpSessionHandle,
  CdpSessionOptions,
  CdpSessionTransport,
  CipherRowBackend,
  ConnectionId,
  ConnectionRole,
  HostCapabilities,
  OutboundProps,
  SessionId,
  SessionStore,
  TargetId,
  UserId,
};
