// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Stable surface for Workers that wrap the engine; anything not exported here is internal.

export {
  ParawingEngine,
  SandboxOutbound,
  PageScriptTail,
  DeniedOutbound,
  SpanSink,
} from "./index.ts";
export { DEFAULT_ENGINE_HOST } from "./host.ts";
export type { EngineHost, ConnectionOptions } from "./host.ts";
export { resolveSessionStore } from "./host.ts";
export { MemorySessionStore, isStoredBytes, isStoredString } from "./state/session-store.ts";
export type { SessionStore, StoreGuard, StoreStats, StoreTable } from "./state/session-store.ts";
export type { BlockableRequest, RequestBlocker, RequestBlockVerdict } from "./request-blocker.ts";
export type { ResourceType } from "./cdp/network-events.ts";
export { SESSION_ID_HEADER, resolveEntrypoint } from "./observability.ts";
export type {
  SessionEntrypoint,
  SessionTelemetry,
  TelemetryEvent,
  TelemetryFactory,
  TelemetryInit,
} from "./observability.ts";
export type { DynamicWorkerKind, WorkerLeaseStats } from "./eval/worker-budget.ts";
export { traceSpan } from "./tracing.ts";
export type { Tracer } from "./tracing.ts";
export { armLocalTracing, localTraceparentHeader } from "./tracing-local.ts";
export { handleCdpSession, handleWebSocket } from "./cdp/connection.ts";
export type {
  CdpSessionCloseEvent,
  CdpSessionErrorEvent,
  CdpSessionHandle,
  CdpSessionOptions,
  CdpSessionTransport,
} from "./cdp/connection.ts";
export { createMemoryHostCapabilities, parsePositiveMsCap } from "./host-capabilities.ts";
export type {
  AssetCapability,
  ClockCapability,
  ConfigCapability,
  HostCapabilities,
  LimitsCapability,
  MemoryHostCapabilitiesOptions,
  TaskCapability,
  WebBotAuthConfig,
  WorkerCompatConfig,
} from "./host-capabilities.ts";
export type {
  HostIsolateLoader,
  IsolateKind,
  IsolateLoadSpec,
  IsolateModule,
  IsolateOutboundSpec,
  IsolateTailSpec,
  LoadedIsolate,
} from "./isolate-loader.ts";
export { parseCdpRequest, SKIP_SPECULATIVE_RASTER_HEADER } from "./cdp/types.ts";
export type { CdpRequest, CdpResponse } from "./cdp/types.ts";
export { arrivalOf } from "./cdp/arrival.ts";
export { ensurePageScript } from "./cdp/dom.ts";
export { handleInput } from "./cdp/input.ts";
export type { HandleInputOptions } from "./cdp/input.ts";
export { buildTree } from "./cdp/accessibility.ts";
export type { AxNode, BuiltTree, DomNode } from "./cdp/accessibility.ts";
export { handlePage, mainFrame } from "./cdp/page.ts";
export { sessionOf } from "./cdp/page-session.ts";
export type { PageSession } from "./cdp/page-session.ts";
export type { DispatchCtx, EngineCdpCommandExtension } from "./cdp/dispatch.ts";
export type { TargetState } from "./cdp/types.ts";
export { makeWallClock } from "./eval/host-clock.ts";
export { isRecord, isStringArray, oneOf } from "./guards.ts";
export { clampSide, clampViewport, MAX_PIXELS, MAX_SIDE, MIN_DIM } from "./cdp/viewport.ts";
export { compileOutboundFilters, shouldBlock } from "./cdp/outbound-filter-registry.ts";
export { rateLimited, warnLimiterFailure, isRateLimitedEntrypoint } from "./rate-limit.ts";
export type { AttributionTailProps } from "./eval/attribution-tail.ts";
export type { ExternalOutbound } from "./eval/external-outbound.ts";
export { registerVfsWasmBytes } from "./eval/page-script.ts";
export type { OutboundProps } from "./eval/outbound.ts";
export { notifyIsolateLimit } from "./eval/limit-registry.ts";
export { classifyOrigin, parsePwErrLine } from "./engine-errors.ts";
export type { ErrorOrigin, TailExceptionReport } from "./engine-errors.ts";
export {
  asConnectionId,
  asSessionId,
  asTargetId,
  asUserId,
  SessionDestroyedError,
  SessionNotFoundError,
  StaleEpochError,
} from "./session/identities.ts";
export type { ConnectionId, SessionId, TargetId, UserId } from "./session/identities.ts";
export { SessionManager } from "./session/session-manager.ts";
export type {
  ConnectionAttachment,
  ManagedSessionRecord,
  ManagedSessionRuntime,
  SessionAttachOptions,
  SessionCreateOptions,
  SessionLifecycleStatus,
} from "./session/session-manager.ts";
export {
  captureTier1Checkpoint,
  filterInputJournalForReplay,
  loadLatestTier1Checkpoint,
  resolveSafeGetRestorePlan,
  restoreTier1Checkpoint,
} from "./session/checkpoint.ts";
export type {
  CapturableTargetInput,
  CheckpointReason,
  InputJournalEntry,
  RestorableTargetAdapter,
  SafeGetRestorePlan,
  Tier1Checkpoint,
  Tier1FormDraft,
  Tier1HistoryEntry,
  Tier1RestoreResult,
  Tier1RestoreTargetOutcome,
  Tier1TargetSnapshot,
} from "./session/checkpoint.ts";
export {
  AES_256_KEY_LENGTH,
  decryptAes256Gcm,
  encryptAes256Gcm,
  GCM_NONCE_LENGTH,
  GCM_TAG_LENGTH,
} from "./state/aes256-gcm.ts";
export type { AesGcmEncrypted } from "./state/aes256-gcm.ts";
export {
  canonicalLeaseBytes,
  KeyLeaseExpiredError,
  KeyLeaseManager,
  KeyLeaseSignatureError,
  sha256Hex,
  verifySignedKeyLease,
} from "./state/key-lease.ts";
export type {
  KeyLeaseLifecycleHooks,
  KeyLeaseLifecycleState,
  KeyLeasePayload,
  SignedKeyLease,
} from "./state/key-lease.ts";
export {
  buildCipherAad,
  EncryptedSessionStore,
  InMemoryCipherBackend,
  portableAesGcmCipher,
} from "./state/encrypted-session-store.ts";
export type {
  CipherEnvelope,
  CipherRowBackend,
  SyncAesGcmCipher,
} from "./state/encrypted-session-store.ts";
export {
  IndexedDbTransactionAbortedError,
  IndexedDbTransactionContext,
  normalizeStorageOrigin,
  WebStoragePersistenceBridge,
} from "./state/web-storage-bridge.ts";
export type {
  IndexedDbDatabaseSnapshot,
  IndexedDbObjectStoreSnapshot,
  IndexedDbOriginSnapshot,
  IndexedDbRecord,
  StringRecord,
  TabSessionStorageSnapshot,
} from "./state/web-storage-bridge.ts";
export {
  AuthorityVaultAndChannel,
  CredentialNotFoundError,
  normalizeStrictOrigin,
  SealedOriginMismatchError,
} from "./authority/authority-service.ts";
export type {
  MaskedVaultCredential,
  MirroredAuditRecord,
  SealedFillResult,
  SealedFillTargetAdapter,
  VaultCredentialInput,
} from "./authority/authority-service.ts";
export {
  ApprovalGate,
  ApprovalVerificationError,
  buildDomOnlyApprovalSummary,
  canonicalDecisionBytes,
  computeBodySha256,
  computeHttpActionDigest,
  normalizeSortedHeaders,
} from "./authority/approval-gate.ts";
export type {
  ApprovalDecisionPayload,
  ApprovalOutcome,
  DomObservedField,
  DomOnlyApprovalSummary,
  HttpActionDescriptor,
  PendingApprovalRequest,
  SignedApprovalDecision,
} from "./authority/approval-gate.ts";
export { ControllerLeaseConflictError, ControllerLeaseManager } from "./policy/controller-lease.ts";
export type {
  ControllerLeaseRecord,
  ControllerLeaseStatus,
  DispatchActorRole,
} from "./policy/controller-lease.ts";
export {
  AUDIT_GENESIS_HASH,
  canonicalAuditPayload,
  SignedAuditLog,
  verifyAuditChain,
} from "./policy/audit-log.ts";
export type {
  AuditChainVerificationResult,
  AuditEventInput,
  SignedAuditEntry,
} from "./policy/audit-log.ts";
export {
  canonicalMandateBytes,
  generateCredentialToken,
  importEd25519PublicKeyFromSpkiBase64,
  inferMandateActionClass,
  MandateScopeError,
  MandateSpendLimitError,
  MandateTracker,
  MandateVerificationError,
  signMandate,
  stripCrossOriginSensitiveHeaders,
  TokenizedFillVault,
  TokenTransformedNeedsSealedRetryError,
  urlMatchesMandateSites,
  verifyMandate,
  verifyMandateWithPublicKey,
} from "./authority/mandates.ts";
export type {
  MandateActionClass,
  MandateAuthorizationInput,
  MandatePayload,
  MaskedTokenRecord,
  SignedMandate,
  TokenizedFillResult,
  TokenizedFillTargetAdapter,
  TokenTransformDetails,
} from "./authority/mandates.ts";
export {
  isSealedBlockedCommand,
  PolicyDecisionError,
  PolicyEngine,
} from "./policy/policy-engine.ts";
export type { PolicyDecision, PolicyEngineOptions } from "./policy/policy-engine.ts";
export {
  AuthorityWebAuthnAuthenticator,
  base64UrlDecode,
  base64UrlEncode,
  buildAuthenticatorData,
  buildClientDataJsonBytes,
  derToP1363Ecdsa,
  encodeCoseEs256PublicKey,
  HostWebAuthnClient,
  p1363ToDerEcdsa,
  validateRpIdAgainstOrigin,
  verifyWebAuthnAssertion,
  WebAuthnSecurityError,
} from "./authority/webauthn.ts";
export type {
  BiometricVerificationContext,
  BiometricVerifyCallback,
  CreateWebAuthnCredentialParams,
  GetWebAuthnAssertionParams,
  WebAuthnAssertionResult,
  WebAuthnCredentialRecord,
  WebAuthnRegistrationResult,
} from "./authority/webauthn.ts";
export {
  CAPSULE_PINNED_PAGE_SIZE,
  CapsuleAttestationAuthority,
  CapsuleAttestationError,
  OrderedPasskeyChain,
  canonicalAttestationClaimsBytes,
  signCapsuleAttestation,
  unwrapLeasedAesKey,
  verifyDbscJwtProof,
} from "./authority/attestation.ts";
export type {
  AttestationFailureCode,
  CapsuleAttestationClaims,
  ChainAssertionResult,
  ChainRegistrationResult,
  DbscSessionCredential,
  ExternalPasskeyProvider,
  PasskeyProviderKind,
  ProviderAttempt,
  SignedCapsuleAttestation,
  WrappedKeyLeaseRelease,
} from "./authority/attestation.ts";
