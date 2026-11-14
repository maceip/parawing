// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Human controller takeover lease manager enforced at CDP dispatch and observation streams. */

import type { TargetId } from "../session/identities.ts";

export type ControllerLeaseStatus = "pending" | "active" | "released" | "revoked" | "expired";
export type DispatchActorRole = "agent" | "human";

export interface ControllerLeaseRecord {
  readonly leaseId: string;
  readonly targetId: TargetId;
  readonly requesterId: string;
  readonly reason: string;
  readonly pauseObservation: boolean;
  readonly requestedAt: number;
  readonly approvedAt: number | null;
  readonly expiresAt: number | null;
  readonly status: ControllerLeaseStatus;
}

export class ControllerLeaseConflictError extends Error {
  readonly targetId: TargetId;
  readonly leaseId: string;
  readonly method: string;

  constructor(targetId: TargetId, leaseId: string, method: string) {
    super(
      `CDP method "${method}" rejected: target ${targetId} is under active human controller lease` +
        ` ${leaseId}`,
    );
    this.name = "ControllerLeaseConflictError";
    this.targetId = targetId;
    this.leaseId = leaseId;
    this.method = method;
  }
}

const DEFAULT_LEASE_TTL_MS = 5 * 60 * 1000;

export class ControllerLeaseManager {
  private readonly leasesById = new Map<string, ControllerLeaseRecord>();
  private readonly targetToLeaseId = new Map<TargetId, string>();
  private readonly listeners = new Set<(targetId: TargetId, active: boolean) => void>();
  private readonly now: () => number;

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? ((): number => Date.now());
  }

  subscribe(listener: (targetId: TargetId, active: boolean) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  request(params: {
    readonly targetId: TargetId;
    readonly requesterId: string;
    readonly reason?: string;
    readonly pauseObservation?: boolean;
  }): ControllerLeaseRecord {
    this.expire();
    const record: ControllerLeaseRecord = {
      leaseId: `ctrl-${crypto.randomUUID()}`,
      targetId: params.targetId,
      requesterId: params.requesterId,
      reason: params.reason ?? "human-takeover",
      pauseObservation: params.pauseObservation ?? true,
      requestedAt: this.now(),
      approvedAt: null,
      expiresAt: null,
      status: "pending",
    };
    this.leasesById.set(record.leaseId, record);
    return record;
  }

  approve(
    leaseId: string,
    options: { readonly ttlMs?: number; readonly pauseObservation?: boolean } = {},
  ): ControllerLeaseRecord {
    this.expire();
    const existing = this.leasesById.get(leaseId);
    if (!existing) {
      throw new Error(`Controller lease not found: ${leaseId}`);
    }
    if (existing.status === "revoked" || existing.status === "released") {
      throw new Error(`Controller lease ${leaseId} cannot be approved from ${existing.status}`);
    }
    const currentNow = this.now();
    const ttlMs = options.ttlMs ?? DEFAULT_LEASE_TTL_MS;
    if (ttlMs <= 0) {
      const expiredRecord: ControllerLeaseRecord = {
        ...existing,
        approvedAt: currentNow,
        expiresAt: currentNow,
        status: "expired",
      };
      this.leasesById.set(leaseId, expiredRecord);
      return expiredRecord;
    }

    const previousId = this.targetToLeaseId.get(existing.targetId);
    if (previousId && previousId !== leaseId) {
      this.revoke(previousId);
    }

    const active: ControllerLeaseRecord = {
      ...existing,
      pauseObservation: options.pauseObservation ?? existing.pauseObservation,
      approvedAt: currentNow,
      expiresAt: currentNow + ttlMs,
      status: "active",
    };
    this.leasesById.set(leaseId, active);
    this.targetToLeaseId.set(active.targetId, leaseId);
    this.notify(active.targetId, true);
    return active;
  }

  release(
    targetIdOrLeaseId: TargetId | string,
    requesterId?: string,
  ): ControllerLeaseRecord | null {
    this.expire();
    const record = this.findLease(targetIdOrLeaseId);
    if (!record || record.status !== "active") return null;
    if (requesterId && record.requesterId !== requesterId) {
      throw new Error(
        `Controller lease ${record.leaseId} held by ${record.requesterId}, not ${requesterId}`,
      );
    }
    const next: ControllerLeaseRecord = { ...record, status: "released" };
    this.leasesById.set(record.leaseId, next);
    this.targetToLeaseId.delete(record.targetId);
    this.notify(record.targetId, false);
    return next;
  }

  revoke(targetIdOrLeaseId: TargetId | string): ControllerLeaseRecord | null {
    const record = this.findLease(targetIdOrLeaseId);
    if (!record) return null;
    if (record.status === "revoked" || record.status === "released") return record;
    const next: ControllerLeaseRecord = { ...record, status: "revoked" };
    this.leasesById.set(record.leaseId, next);
    if (this.targetToLeaseId.get(record.targetId) === record.leaseId) {
      this.targetToLeaseId.delete(record.targetId);
      this.notify(record.targetId, false);
    }
    return next;
  }

  expire(atTime: number = this.now()): number {
    let expiredCount = 0;
    for (const [leaseId, record] of this.leasesById) {
      if (record.status !== "active") continue;
      if (record.expiresAt === null || atTime < record.expiresAt) continue;
      const next: ControllerLeaseRecord = { ...record, status: "expired" };
      this.leasesById.set(leaseId, next);
      if (this.targetToLeaseId.get(record.targetId) === leaseId) {
        this.targetToLeaseId.delete(record.targetId);
      }
      this.notify(record.targetId, false);
      expiredCount += 1;
    }
    return expiredCount;
  }

  getActiveLease(targetId: TargetId): ControllerLeaseRecord | null {
    this.expire();
    const leaseId = this.targetToLeaseId.get(targetId);
    if (!leaseId) return null;
    const record = this.leasesById.get(leaseId);
    if (!record || record.status !== "active") {
      this.targetToLeaseId.delete(targetId);
      return null;
    }
    return record;
  }

  getLeaseById(leaseId: string): ControllerLeaseRecord | undefined {
    this.expire();
    return this.leasesById.get(leaseId);
  }

  isAgentObservationPaused(targetId: TargetId | null | undefined): boolean {
    if (!targetId) return false;
    const active = this.getActiveLease(targetId);
    return active !== null && active.pauseObservation;
  }

  assertAgentDispatchAllowed(
    targetId: TargetId | null | undefined,
    method: string,
    actorRole: DispatchActorRole = "agent",
  ): void {
    if (actorRole === "human" || !targetId) return;
    const active = this.getActiveLease(targetId);
    if (active) {
      throw new ControllerLeaseConflictError(targetId, active.leaseId, method);
    }
  }

  private findLease(targetIdOrLeaseId: string): ControllerLeaseRecord | undefined {
    const byId = this.leasesById.get(targetIdOrLeaseId);
    if (byId) return byId;
    const activeId = this.targetToLeaseId.get(targetIdOrLeaseId as TargetId);
    return activeId ? this.leasesById.get(activeId) : undefined;
  }

  private notify(targetId: TargetId, active: boolean): void {
    for (const listener of this.listeners) {
      listener(targetId, active);
    }
  }
}
