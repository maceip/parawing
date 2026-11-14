// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Tier 0/1 persistent SessionManager with single-owner monotonic epoch leases. */

import type { ApprovalGate } from "../authority/approval-gate.ts";
import type { AuthorityVaultAndChannel } from "../authority/authority-service.ts";
import type { BrowserState, CdpEvent, TargetState } from "../cdp/types.ts";
import type { ClientInputJournal } from "../rbi-input-journal.ts";
import type { SignedAuditLog } from "../policy/audit-log.ts";
import { ControllerLeaseManager } from "../policy/controller-lease.ts";
import { PolicyDecisionError, PolicyEngine } from "../policy/policy-engine.ts";
import type { KeyLeaseManager } from "../state/key-lease.ts";
import { MemorySessionStore, type SessionStore } from "../state/session-store.ts";
import { WebStoragePersistenceBridge } from "../state/web-storage-bridge.ts";
import {
  captureTier1Checkpoint,
  loadLatestTier1Checkpoint,
  restoreTier1Checkpoint,
  type CheckpointReason,
  type InputJournalEntry,
  type RestorableTargetAdapter,
  type Tier1Checkpoint,
  type Tier1RestoreResult,
  type Tier1TargetSnapshot,
} from "./checkpoint.ts";
import {
  asConnectionId,
  asSessionId,
  asTargetId,
  SessionDestroyedError,
  SessionNotFoundError,
  StaleEpochError,
  type ConnectionId,
  type ConnectionRole,
  type SessionId,
  type TargetId,
  type UserId,
} from "./identities.ts";

const DEFAULT_VIEWPORT_WIDTH = 1280;
const DEFAULT_VIEWPORT_HEIGHT = 720;

export type SessionLifecycleStatus =
  | "created"
  | "active"
  | "detached"
  | "suspended"
  | "roaming"
  | "destroyed";

export interface ConnectionAttachment {
  readonly connectionId: ConnectionId;
  readonly sessionId: SessionId;
  readonly userId: UserId;
  epoch: number;
  role: ConnectionRole;
  attachedAt: number;
  emit?: (event: CdpEvent) => void;
}

export interface ManagedSessionRuntime {
  readonly sessionId: SessionId;
  readonly userId: UserId;
  readonly store: SessionStore;
  readonly webStorage: WebStoragePersistenceBridge;
  readonly controllerLeases: ControllerLeaseManager;
  readonly policyEngine: PolicyEngine;
  readonly authority?: AuthorityVaultAndChannel;
  readonly auditLog?: SignedAuditLog;
  readonly keyLease?: KeyLeaseManager;
  readonly approvalGate?: ApprovalGate;
  readonly targets: Map<TargetId, TargetState>;
  readonly inputJournal: InputJournalEntry[];
  readonly clientJournals: Map<TargetId, ClientInputJournal>;
  persistentBrowser: BrowserState | null;
  forceTier1OnResume?: boolean;
  lastAckedInputSeq: number;
  lastCheckpoint: Tier1Checkpoint | null;
  checkpointTimer: ReturnType<typeof setInterval> | null;
  resolveTargetAdapter?: (target: Tier1TargetSnapshot) => RestorableTargetAdapter;
  onReplayInput?: (entry: InputJournalEntry) => Promise<void> | void;
  onSuspendRuntime?: () => Promise<void> | void;
  onDestroyRuntime?: () => Promise<void> | void;
  onAttachRuntime?: (attachment: ConnectionAttachment) => void;
  onDetachRuntime?: (connectionId: ConnectionId) => void;
}

export interface ManagedSessionRecord {
  readonly sessionId: SessionId;
  readonly userId: UserId;
  status: SessionLifecycleStatus;
  epoch: number;
  ownerConnectionId: ConnectionId | null;
  readonly connections: Map<ConnectionId, ConnectionAttachment>;
  readonly runtime: ManagedSessionRuntime;
  createdAt: number;
  updatedAt: number;
}

export interface SessionCreateOptions {
  readonly userId: UserId;
  readonly sessionId?: SessionId;
  readonly initialEpoch?: number;
  readonly store?: SessionStore;
  readonly authority?: AuthorityVaultAndChannel;
  readonly auditLog?: SignedAuditLog;
  readonly keyLease?: KeyLeaseManager;
  readonly approvalGate?: ApprovalGate;
  readonly policyEngine?: PolicyEngine;
  readonly controllerLeases?: ControllerLeaseManager;
}

export interface SessionAttachOptions {
  readonly sessionId: SessionId;
  readonly userId: UserId;
  readonly connectionId: ConnectionId;
  readonly requestedEpoch?: number;
  readonly role?: ConnectionRole;
  readonly emit?: (event: CdpEvent) => void;
}

export class SessionManager {
  private readonly sessions = new Map<SessionId, ManagedSessionRecord>();
  private readonly now: () => number;

  constructor(options: { readonly now?: () => number } = {}) {
    this.now = options.now ?? ((): number => Date.now());
  }

  create(options: SessionCreateOptions): ManagedSessionRecord {
    const sessionId = options.sessionId ?? asSessionId(`sess-${crypto.randomUUID()}`);
    const existing = this.sessions.get(sessionId);
    if (existing && existing.status !== "destroyed") {
      throw new Error(`Session already exists: ${sessionId}`);
    }
    const store = options.store ?? new MemorySessionStore();
    const policyEngine = options.policyEngine ?? new PolicyEngine({ auditLog: options.auditLog });
    const runtime: ManagedSessionRuntime = {
      sessionId,
      userId: options.userId,
      store,
      webStorage: new WebStoragePersistenceBridge(store),
      controllerLeases: options.controllerLeases ?? new ControllerLeaseManager({ now: this.now }),
      policyEngine,
      authority: options.authority,
      auditLog: options.auditLog,
      keyLease: options.keyLease,
      approvalGate: options.approvalGate,
      targets: new Map(),
      inputJournal: [],
      clientJournals: new Map(),
      persistentBrowser: null,
      lastAckedInputSeq: 0,
      lastCheckpoint: null,
      checkpointTimer: null,
    };
    const ts = this.now();
    const record: ManagedSessionRecord = {
      sessionId,
      userId: options.userId,
      status: "created",
      epoch: options.initialEpoch ?? 0,
      ownerConnectionId: null,
      connections: new Map(),
      runtime,
      createdAt: ts,
      updatedAt: ts,
    };
    this.sessions.set(sessionId, record);
    if (options.keyLease) {
      options.keyLease.setHooks({
        onCheckpoint: () => {
          const current = this.sessions.get(sessionId);
          if (!current || current.status === "destroyed") return;
          this.checkpointSession(sessionId, "key-lease-expire");
        },
        onFlush: () => {
          this.sessions.get(sessionId)?.runtime.store.flush?.();
        },
        onSuspend: async () => {
          const current = this.sessions.get(sessionId);
          if (!current || current.status === "destroyed") return;
          current.status = "suspended";
          await current.runtime.onSuspendRuntime?.();
        },
      });
    }
    return record;
  }

  get(sessionId: SessionId): ManagedSessionRecord | undefined {
    return this.sessions.get(sessionId);
  }

  requireSession(sessionId: SessionId): ManagedSessionRecord {
    const record = this.sessions.get(sessionId);
    if (!record) throw new SessionNotFoundError(sessionId);
    if (record.status === "destroyed") throw new SessionDestroyedError(sessionId);
    return record;
  }

  attach(options: SessionAttachOptions): ConnectionAttachment {
    const record = this.requireSession(options.sessionId);
    if (record.userId !== options.userId) {
      throw new Error(
        `Session ${options.sessionId} owned by ${record.userId}, not ${options.userId}`,
      );
    }
    const attachPolicy = record.runtime.policyEngine.evaluateAttach({
      sessionId: options.sessionId,
      userId: options.userId,
      connectionId: options.connectionId,
    });
    if (!attachPolicy.allowed) {
      throw new PolicyDecisionError(attachPolicy);
    }

    const desiredRole: ConnectionRole = options.role ?? "owner";
    if (desiredRole === "viewer") {
      const viewer: ConnectionAttachment = {
        connectionId: options.connectionId,
        sessionId: options.sessionId,
        userId: options.userId,
        epoch: record.epoch,
        role: "viewer",
        attachedAt: this.now(),
        emit: options.emit,
      };
      record.connections.set(options.connectionId, viewer);
      record.updatedAt = this.now();
      return viewer;
    }

    if (options.requestedEpoch !== undefined && options.requestedEpoch < record.epoch) {
      const stale: ConnectionAttachment = {
        connectionId: options.connectionId,
        sessionId: options.sessionId,
        userId: options.userId,
        epoch: options.requestedEpoch,
        role: "viewer",
        attachedAt: this.now(),
        emit: options.emit,
      };
      record.connections.set(options.connectionId, stale);
      throw new StaleEpochError(
        options.sessionId,
        options.connectionId,
        record.epoch,
        options.requestedEpoch,
      );
    }

    const previousOwnerId = record.ownerConnectionId;
    const nextEpoch = Math.max(record.epoch + 1, options.requestedEpoch ?? record.epoch + 1);
    for (const conn of record.connections.values()) {
      if (conn.connectionId !== options.connectionId && conn.role === "owner") {
        conn.role = "viewer";
      }
    }

    const attachment: ConnectionAttachment = {
      connectionId: options.connectionId,
      sessionId: options.sessionId,
      userId: options.userId,
      epoch: nextEpoch,
      role: "owner",
      attachedAt: this.now(),
      emit: options.emit,
    };
    record.epoch = nextEpoch;
    record.ownerConnectionId = options.connectionId;
    record.status = "active";
    record.updatedAt = attachment.attachedAt;
    record.connections.set(options.connectionId, attachment);
    record.runtime.onAttachRuntime?.(attachment);
    this.emitToConnection(attachment, {
      method: "Parawing.sessionAttached",
      params: {
        sessionId: record.sessionId,
        userId: record.userId,
        connectionId: attachment.connectionId,
        epoch: record.epoch,
        role: attachment.role,
        previousOwnerConnectionId: previousOwnerId,
        warmTargets: record.runtime.targets.size,
      },
    });
    return attachment;
  }

  /** Validate active single-owner epoch; demote stale callers to viewer and throw. */
  validateEpoch(sessionId: SessionId, connectionId: ConnectionId, epoch?: number): void {
    const record = this.requireSession(sessionId);
    const conn = record.connections.get(connectionId);
    const claimedEpoch = epoch ?? conn?.epoch ?? -1;
    if (
      !conn ||
      conn.role !== "owner" ||
      record.ownerConnectionId !== connectionId ||
      claimedEpoch !== record.epoch
    ) {
      if (conn) conn.role = "viewer";
      throw new StaleEpochError(sessionId, connectionId, record.epoch, claimedEpoch);
    }
  }

  detach(sessionId: SessionId, connectionId: ConnectionId): void {
    const record = this.sessions.get(sessionId);
    if (!record || record.status === "destroyed") return;
    const conn = record.connections.get(connectionId);
    record.connections.delete(connectionId);
    if (record.ownerConnectionId === connectionId) {
      record.ownerConnectionId = null;
      if (record.status === "active") {
        record.status = "detached";
      }
    }
    record.updatedAt = this.now();
    record.runtime.onDetachRuntime?.(connectionId);
    if (conn) {
      conn.emit = undefined;
    }
  }

  registerTarget(sessionId: SessionId, target: TargetState): void {
    const record = this.requireSession(sessionId);
    record.runtime.targets.set(asTargetId(target.targetId), target);
  }

  unregisterTarget(sessionId: SessionId, targetId: TargetId): void {
    const record = this.sessions.get(sessionId);
    if (!record) return;
    record.runtime.targets.delete(targetId);
    record.runtime.webStorage.clearTabSessionStorage(targetId);
  }

  listTargets(sessionId: SessionId): TargetState[] {
    const record = this.requireSession(sessionId);
    return [...record.runtime.targets.values()];
  }

  recordAckedInput(sessionId: SessionId, seq: number): void {
    const record = this.requireSession(sessionId);
    if (seq > record.runtime.lastAckedInputSeq) {
      record.runtime.lastAckedInputSeq = seq;
    }
  }

  markForceTier1OnResume(sessionId: SessionId): void {
    const record = this.sessions.get(sessionId);
    if (record && record.status !== "destroyed") {
      record.runtime.forceTier1OnResume = true;
    }
  }

  appendUnackedInput(sessionId: SessionId, entry: InputJournalEntry): void {
    const record = this.requireSession(sessionId);
    record.runtime.inputJournal.push(entry);
  }

  checkpointSession(sessionId: SessionId, reason: CheckpointReason = "manual"): Tier1Checkpoint {
    const record = this.requireSession(sessionId);
    const capturable = [...record.runtime.targets.values()]
      .filter((t) => t.type === "page")
      .map((t) => ({
        targetId: asTargetId(t.targetId),
        url: t.url || "about:blank",
        lastMethod: t.lastNavigationMethod ?? "GET",
        lastSafeGetUrl: t.lastSafeGetUrl ?? null,
        history: t.navigationHistory.map((h) => ({
          id: h.id,
          url: h.url,
          title: h.title,
          method: h.method ?? "GET",
        })),
        historyIndex: t.navigationHistoryIndex,
        scrollX: t.lastScrollX ?? 0,
        scrollY: t.lastScrollY ?? 0,
        viewport: {
          width: t.viewportWidth ?? DEFAULT_VIEWPORT_WIDTH,
          height: t.viewportHeight ?? DEFAULT_VIEWPORT_HEIGHT,
        },
        focusedFieldKey: t.lastFocusedFieldKey ?? null,
        formDrafts: t.lastFormDrafts ?? [],
        sealedOrigin: t.sealedOrigin ?? null,
      }));
    const checkpoint = captureTier1Checkpoint({
      sessionId: record.sessionId,
      userId: record.userId,
      reason,
      lastAckedInputSeq: record.runtime.lastAckedInputSeq,
      targets: capturable,
      webStorage: record.runtime.webStorage,
      store: record.runtime.store,
      now: this.now(),
    });
    record.runtime.lastCheckpoint = checkpoint;
    return checkpoint;
  }

  async suspend(
    sessionId: SessionId,
    reason: CheckpointReason = "suspend",
  ): Promise<Tier1Checkpoint> {
    const record = this.requireSession(sessionId);
    const checkpoint = this.checkpointSession(sessionId, reason);
    this.stopCheckpointTimer(sessionId);
    record.status = "suspended";
    record.updatedAt = this.now();
    await record.runtime.onSuspendRuntime?.();
    this.emitToOwner(record, {
      method: "Parawing.sessionSuspended",
      params: {
        sessionId: record.sessionId,
        userId: record.userId,
        reason,
        checkpointTakenAt: checkpoint.takenAt,
      },
    });
    return checkpoint;
  }

  async resume(params: {
    readonly sessionId: SessionId;
    readonly userId: UserId;
    readonly connectionId: ConnectionId;
    readonly emit?: (event: CdpEvent) => void;
    readonly requestedEpoch?: number;
    readonly onAttached?: (attachment: ConnectionAttachment) => void;
  }): Promise<{
    readonly attachment: ConnectionAttachment;
    readonly tier: 0 | 1;
    readonly restoreResult: Tier1RestoreResult | null;
  }> {
    const record = this.requireSession(params.sessionId);
    const forcedTier1 = record.runtime.forceTier1OnResume === true;
    record.runtime.forceTier1OnResume = false;
    const wasWarm =
      !forcedTier1 &&
      (record.status === "detached" || record.status === "active") &&
      record.runtime.targets.size > 0;
    const attachment = this.attach({
      sessionId: params.sessionId,
      userId: params.userId,
      connectionId: params.connectionId,
      requestedEpoch: params.requestedEpoch,
      emit: params.emit,
    });
    params.onAttached?.(attachment);

    if (wasWarm) {
      this.emitToConnection(attachment, {
        method: "Parawing.sessionResumed",
        params: {
          sessionId: record.sessionId,
          userId: record.userId,
          epoch: attachment.epoch,
          tier: 0,
        },
      });
      return { attachment, tier: 0, restoreResult: null };
    }

    const checkpoint =
      record.runtime.lastCheckpoint ?? loadLatestTier1Checkpoint(record.runtime.store);
    let restoreResult: Tier1RestoreResult | null = null;
    if (checkpoint && record.runtime.resolveTargetAdapter) {
      restoreResult = await restoreTier1Checkpoint({
        checkpoint,
        webStorage: record.runtime.webStorage,
        resolveTargetAdapter: record.runtime.resolveTargetAdapter,
        inputJournal: record.runtime.inputJournal,
        clientInputJournal: record.runtime.clientJournals,
        onReplayInput: record.runtime.onReplayInput,
        emitSessionRestored: (payload) => {
          this.emitToConnection(attachment, {
            method: "Parawing.sessionRestored",
            params: payload,
          });
        },
      });
      record.runtime.inputJournal.length = 0;
    }

    this.emitToConnection(attachment, {
      method: "Parawing.sessionResumed",
      params: {
        sessionId: record.sessionId,
        userId: record.userId,
        epoch: attachment.epoch,
        tier: 1,
      },
    });
    return { attachment, tier: 1, restoreResult };
  }

  async roam(params: {
    readonly sessionId: SessionId;
    readonly userId: UserId;
    readonly newConnectionId: ConnectionId;
    readonly emit?: (event: CdpEvent) => void;
    readonly forceTier1Restore?: boolean;
  }): Promise<{
    readonly attachment: ConnectionAttachment;
    readonly checkpoint: Tier1Checkpoint;
    readonly restoreResult: Tier1RestoreResult | null;
  }> {
    const record = this.requireSession(params.sessionId);
    record.status = "roaming";
    const checkpoint = this.checkpointSession(params.sessionId, "roam");
    const attachment = this.attach({
      sessionId: params.sessionId,
      userId: params.userId,
      connectionId: params.newConnectionId,
      emit: params.emit,
    });

    let restoreResult: Tier1RestoreResult | null = null;
    if (params.forceTier1Restore && record.runtime.resolveTargetAdapter) {
      restoreResult = await restoreTier1Checkpoint({
        checkpoint,
        webStorage: record.runtime.webStorage,
        resolveTargetAdapter: record.runtime.resolveTargetAdapter,
        inputJournal: record.runtime.inputJournal,
        clientInputJournal: record.runtime.clientJournals,
        onReplayInput: record.runtime.onReplayInput,
        emitSessionRestored: (payload) => {
          this.emitToConnection(attachment, {
            method: "Parawing.sessionRestored",
            params: payload,
          });
        },
      });
      record.runtime.inputJournal.length = 0;
    }

    this.emitToConnection(attachment, {
      method: "Parawing.sessionRoamed",
      params: {
        sessionId: record.sessionId,
        userId: record.userId,
        connectionId: attachment.connectionId,
        epoch: attachment.epoch,
        tier: restoreResult ? 1 : 0,
      },
    });
    return { attachment, checkpoint, restoreResult };
  }

  startCheckpointTimer(sessionId: SessionId, intervalMs: number): void {
    const record = this.requireSession(sessionId);
    this.stopCheckpointTimer(sessionId);
    if (intervalMs <= 0) return;
    record.runtime.checkpointTimer = setInterval(() => {
      const current = this.sessions.get(sessionId);
      if (!current || current.status === "destroyed" || current.status === "suspended") {
        this.stopCheckpointTimer(sessionId);
        return;
      }
      try {
        this.checkpointSession(sessionId, "timer");
      } catch {}
    }, intervalMs);
  }

  stopCheckpointTimer(sessionId: SessionId): void {
    const record = this.sessions.get(sessionId);
    if (!record?.runtime.checkpointTimer) return;
    clearInterval(record.runtime.checkpointTimer);
    record.runtime.checkpointTimer = null;
  }

  async destroy(sessionId: SessionId): Promise<boolean> {
    const record = this.sessions.get(sessionId);
    if (!record || record.status === "destroyed") return false;
    this.stopCheckpointTimer(sessionId);
    this.emitToOwner(record, {
      method: "Parawing.sessionDestroyed",
      params: {
        sessionId: record.sessionId,
        userId: record.userId,
      },
    });
    record.status = "destroyed";
    record.ownerConnectionId = null;
    record.updatedAt = this.now();
    await record.runtime.onDestroyRuntime?.();
    try {
      record.runtime.store.clear();
      record.runtime.store.flush?.();
    } catch {}
    if (record.runtime.keyLease) {
      await record.runtime.keyLease.revoke();
    }
    for (const journal of record.runtime.clientJournals.values()) {
      journal.clearOnNavigation(true);
    }
    record.runtime.clientJournals.clear();
    record.runtime.targets.clear();
    record.connections.clear();
    return true;
  }

  generateConnectionId(): ConnectionId {
    return asConnectionId(`conn-${crypto.randomUUID()}`);
  }

  private emitToOwner(record: ManagedSessionRecord, event: CdpEvent): void {
    if (!record.ownerConnectionId) return;
    const owner = record.connections.get(record.ownerConnectionId);
    if (owner) this.emitToConnection(owner, event);
  }

  private emitToConnection(conn: ConnectionAttachment, event: CdpEvent): void {
    try {
      conn.emit?.(event);
    } catch {}
  }
}
