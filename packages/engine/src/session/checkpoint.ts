// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Tier 1 logical session checkpoint capture and GET-only safe restore. */

import {
  ClientInputJournal,
  classifyFieldSensitivity,
  type ReplayedInputEntry,
} from "../rbi-input-journal.ts";
import type { SessionStore, StoreGuard } from "../state/session-store.ts";
import type {
  TabSessionStorageSnapshot,
  WebStoragePersistenceBridge,
} from "../state/web-storage-bridge.ts";
import type { SessionId, TargetId, UserId } from "./identities.ts";

export type CheckpointReason =
  | "navigation"
  | "timer"
  | "suspend"
  | "freeze"
  | "roam"
  | "detach"
  | "key-lease-expire"
  | "manual";

export interface Tier1FormDraft {
  readonly fieldKey: string;
  readonly tagName: string;
  readonly fieldType: string;
  readonly value?: string;
  readonly checked?: boolean;
}

export interface Tier1HistoryEntry {
  readonly id: number;
  readonly url: string;
  readonly title: string;
  readonly method?: string;
}

export interface Tier1TargetSnapshot {
  readonly targetId: TargetId;
  readonly url: string;
  readonly lastMethod: string;
  readonly lastSafeGetUrl: string | null;
  readonly history: ReadonlyArray<Tier1HistoryEntry>;
  readonly historyIndex: number;
  readonly scrollX: number;
  readonly scrollY: number;
  readonly viewport: { readonly width: number; readonly height: number };
  readonly focusedFieldKey: string | null;
  readonly sessionStorage: TabSessionStorageSnapshot;
  readonly formDrafts: ReadonlyArray<Tier1FormDraft>;
}

export interface Tier1Checkpoint {
  readonly version: 1;
  readonly sessionId: SessionId;
  readonly userId: UserId;
  readonly takenAt: number;
  readonly reason: CheckpointReason;
  readonly lastAckedInputSeq: number;
  readonly targets: ReadonlyArray<Tier1TargetSnapshot>;
}

export interface InputJournalEntry {
  readonly seq: number;
  readonly targetId: TargetId;
  readonly kind: string;
  readonly payload: unknown;
}

export interface CapturableTargetInput {
  readonly targetId: TargetId;
  readonly url: string;
  readonly lastMethod: string;
  readonly lastSafeGetUrl: string | null;
  readonly history: ReadonlyArray<Tier1HistoryEntry>;
  readonly historyIndex: number;
  readonly scrollX: number;
  readonly scrollY: number;
  readonly viewport: { readonly width: number; readonly height: number };
  readonly focusedFieldKey: string | null;
  readonly formDrafts: ReadonlyArray<Tier1FormDraft>;
  readonly sealedOrigin: string | null;
}

export interface SafeGetRestorePlan {
  readonly restoreUrl: string;
  readonly restoreMethod: "GET";
  readonly pendingUnsafeNavigationUrl: string | null;
}

export interface RestorableTargetAdapter {
  readonly targetId: TargetId;
  invalidateHandlesForRestore(): number;
  navigateGetOnly(url: string, pendingUnsafeUrl: string | null): Promise<void> | void;
  restoreVisualState(params: {
    readonly scrollX: number;
    readonly scrollY: number;
    readonly viewport: { readonly width: number; readonly height: number };
    readonly focusedFieldKey: string | null;
    readonly formDrafts: ReadonlyArray<Tier1FormDraft>;
  }): Promise<void> | void;
  readonly replayClientInput?: (entry: ReplayedInputEntry) => Promise<boolean> | boolean;
}

export interface Tier1RestoreTargetOutcome {
  readonly targetId: TargetId;
  readonly generation: number;
  readonly url: string;
  readonly restoreMethod: "GET";
  readonly pendingUnsafeNavigationUrl: string | null;
}

export interface Tier1RestoreResult {
  readonly sessionId: SessionId;
  readonly userId: UserId;
  readonly reason: CheckpointReason;
  readonly checkpointTakenAt: number;
  readonly targets: ReadonlyArray<Tier1RestoreTargetOutcome>;
  readonly replayedInputSeqs: ReadonlyArray<number>;
  readonly replayedClientInputSeqs?: ReadonlyArray<number>;
}

export const TIER1_CHECKPOINT_TABLE = "ks_tier1_checkpoints";
const LATEST_KEY = "latest";

function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const isTier1Checkpoint: StoreGuard<Tier1Checkpoint> = (value): value is Tier1Checkpoint => {
  if (!isRecordObject(value)) return false;
  return (
    value["version"] === 1 &&
    typeof value["sessionId"] === "string" &&
    typeof value["userId"] === "string" &&
    typeof value["takenAt"] === "number" &&
    typeof value["reason"] === "string" &&
    typeof value["lastAckedInputSeq"] === "number" &&
    Array.isArray(value["targets"])
  );
};

function sanitizeDrafts(
  drafts: ReadonlyArray<Tier1FormDraft>,
  sealedOrigin: string | null,
): Tier1FormDraft[] {
  const out: Tier1FormDraft[] = [];
  for (const draft of drafts) {
    if (sealedOrigin && draft.fieldType.toLowerCase() === "password") continue;
    out.push({ ...draft });
  }
  return out;
}

export function captureTier1Checkpoint(params: {
  readonly sessionId: SessionId;
  readonly userId: UserId;
  readonly reason: CheckpointReason;
  readonly lastAckedInputSeq: number;
  readonly targets: ReadonlyArray<CapturableTargetInput>;
  readonly webStorage?: WebStoragePersistenceBridge;
  readonly store?: SessionStore;
  readonly now?: number;
}): Tier1Checkpoint {
  const targets: Tier1TargetSnapshot[] = params.targets.map((target) => ({
    targetId: target.targetId,
    url: target.url,
    lastMethod: (target.lastMethod || "GET").trim().toUpperCase(),
    lastSafeGetUrl: target.lastSafeGetUrl,
    history: target.history.map((entry) => ({ ...entry })),
    historyIndex: target.historyIndex,
    scrollX: target.scrollX,
    scrollY: target.scrollY,
    viewport: { width: target.viewport.width, height: target.viewport.height },
    focusedFieldKey: target.sealedOrigin ? null : target.focusedFieldKey,
    sessionStorage: params.webStorage
      ? params.webStorage.exportTabSessionStorage(target.targetId)
      : {},
    formDrafts: sanitizeDrafts(target.formDrafts, target.sealedOrigin),
  }));

  const checkpoint: Tier1Checkpoint = {
    version: 1,
    sessionId: params.sessionId,
    userId: params.userId,
    takenAt: params.now ?? Date.now(),
    reason: params.reason,
    lastAckedInputSeq: params.lastAckedInputSeq,
    targets,
  };

  if (params.store) {
    const table = params.store.table(TIER1_CHECKPOINT_TABLE, isTier1Checkpoint);
    table.set(LATEST_KEY, checkpoint);
  }
  return checkpoint;
}

export function loadLatestTier1Checkpoint(store: SessionStore): Tier1Checkpoint | undefined {
  const table = store.table(TIER1_CHECKPOINT_TABLE, isTier1Checkpoint);
  return table.get(LATEST_KEY);
}

export function isRestorableSafeUrl(url: string): boolean {
  if (url === "about:blank") return true;
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "https:" ||
      parsed.protocol === "http:" ||
      parsed.protocol === "about:" ||
      parsed.protocol === "data:"
    );
  } catch {
    return false;
  }
}

export function resolveSafeGetRestorePlan(target: Tier1TargetSnapshot): SafeGetRestorePlan {
  const normalizedMethod = (target.lastMethod || "GET").trim().toUpperCase();
  if (normalizedMethod === "GET" && isRestorableSafeUrl(target.url)) {
    return {
      restoreUrl: target.url,
      restoreMethod: "GET",
      pendingUnsafeNavigationUrl: null,
    };
  }

  if (target.lastSafeGetUrl && isRestorableSafeUrl(target.lastSafeGetUrl)) {
    return {
      restoreUrl: target.lastSafeGetUrl,
      restoreMethod: "GET",
      pendingUnsafeNavigationUrl: target.url,
    };
  }

  const maxIdx = Math.min(target.historyIndex, target.history.length - 1);
  for (let i = maxIdx; i >= 0; i -= 1) {
    const entry = target.history[i];
    if (!entry) continue;
    const entryMethod = (entry.method ?? "GET").trim().toUpperCase();
    if (entryMethod === "GET" && isRestorableSafeUrl(entry.url)) {
      return {
        restoreUrl: entry.url,
        restoreMethod: "GET",
        pendingUnsafeNavigationUrl: target.url,
      };
    }
  }

  return {
    restoreUrl: "about:blank",
    restoreMethod: "GET",
    pendingUnsafeNavigationUrl: target.url,
  };
}

export function filterInputJournalForReplay(
  journal: ReadonlyArray<InputJournalEntry>,
  lastAckedInputSeq: number,
): InputJournalEntry[] {
  return journal
    .filter((entry) => entry.seq > lastAckedInputSeq)
    .slice()
    .sort((a, b) => a.seq - b.seq);
}

function originOfRestoreUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.origin === "null" ? "null" : parsed.origin;
  } catch {
    return "null";
  }
}

function resolveJournalForTarget(
  source: ClientInputJournal | ReadonlyMap<TargetId, ClientInputJournal> | undefined,
  targetId: TargetId,
): ClientInputJournal | undefined {
  if (!source) return undefined;
  return source instanceof ClientInputJournal ? source : source.get(targetId);
}

async function replayClientJournalDeltaForTarget(params: {
  readonly targetId: TargetId;
  readonly restoreUrl: string;
  readonly checkpointSeq: number;
  readonly journal: ClientInputJournal;
  readonly adapter: RestorableTargetAdapter;
  readonly onReplayClientInput?: (
    targetId: TargetId,
    entry: ReplayedInputEntry,
  ) => Promise<boolean | void> | boolean | void;
}): Promise<number[]> {
  const origin = originOfRestoreUrl(params.restoreUrl);
  const deltaEntries = await params.journal.replayDeltaAfter(origin, params.checkpointSeq);
  const appliedSeqs: number[] = [];
  for (const entry of deltaEntries) {
    if (classifyFieldSensitivity(entry.field).sensitive) continue;
    let applied = true;
    if (params.adapter.replayClientInput) {
      applied = (await params.adapter.replayClientInput(entry)) !== false;
    } else if (params.onReplayClientInput) {
      applied = (await params.onReplayClientInput(params.targetId, entry)) !== false;
    }
    if (applied) appliedSeqs.push(entry.inputSeq);
  }
  return appliedSeqs;
}

export async function restoreTier1Checkpoint(params: {
  readonly checkpoint: Tier1Checkpoint;
  readonly webStorage?: WebStoragePersistenceBridge;
  readonly resolveTargetAdapter: (target: Tier1TargetSnapshot) => RestorableTargetAdapter;
  readonly inputJournal?: ReadonlyArray<InputJournalEntry>;
  readonly onReplayInput?: (entry: InputJournalEntry) => Promise<void> | void;
  readonly clientInputJournal?: ClientInputJournal | ReadonlyMap<TargetId, ClientInputJournal>;
  readonly onReplayClientInput?: (
    targetId: TargetId,
    entry: ReplayedInputEntry,
  ) => Promise<boolean | void> | boolean | void;
  readonly emitSessionRestored?: (payload: Tier1RestoreResult) => void;
}): Promise<Tier1RestoreResult> {
  const outcomes: Tier1RestoreTargetOutcome[] = [];
  const replayedClientInputSeqs: number[] = [];

  for (const targetSnap of params.checkpoint.targets) {
    const adapter = params.resolveTargetAdapter(targetSnap);
    const generation = adapter.invalidateHandlesForRestore();

    if (params.webStorage) {
      params.webStorage.importTabSessionStorage(targetSnap.targetId, targetSnap.sessionStorage);
    }

    const plan = resolveSafeGetRestorePlan(targetSnap);
    await adapter.navigateGetOnly(plan.restoreUrl, plan.pendingUnsafeNavigationUrl);
    await adapter.restoreVisualState({
      scrollX: targetSnap.scrollX,
      scrollY: targetSnap.scrollY,
      viewport: targetSnap.viewport,
      focusedFieldKey: targetSnap.focusedFieldKey,
      formDrafts: targetSnap.formDrafts,
    });

    const targetJournal = resolveJournalForTarget(params.clientInputJournal, targetSnap.targetId);
    if (targetJournal) {
      const seqs = await replayClientJournalDeltaForTarget({
        targetId: targetSnap.targetId,
        restoreUrl: plan.restoreUrl,
        checkpointSeq: params.checkpoint.lastAckedInputSeq,
        journal: targetJournal,
        adapter,
        onReplayClientInput: params.onReplayClientInput,
      });
      for (const s of seqs) replayedClientInputSeqs.push(s);
    }

    outcomes.push({
      targetId: targetSnap.targetId,
      generation,
      url: plan.restoreUrl,
      restoreMethod: "GET",
      pendingUnsafeNavigationUrl: plan.pendingUnsafeNavigationUrl,
    });
  }

  const pendingInputs = filterInputJournalForReplay(
    params.inputJournal ?? [],
    params.checkpoint.lastAckedInputSeq,
  );
  const replayedInputSeqs: number[] = [];
  for (const entry of pendingInputs) {
    if (params.onReplayInput) {
      await params.onReplayInput(entry);
    }
    replayedInputSeqs.push(entry.seq);
  }
  const mergedInputSeqs = Array.from(
    new Set([...replayedInputSeqs, ...replayedClientInputSeqs]),
  ).sort((a, b) => a - b);

  const result: Tier1RestoreResult = {
    sessionId: params.checkpoint.sessionId,
    userId: params.checkpoint.userId,
    reason: params.checkpoint.reason,
    checkpointTakenAt: params.checkpoint.takenAt,
    targets: outcomes,
    replayedInputSeqs: mergedInputSeqs,
    ...(params.clientInputJournal ? { replayedClientInputSeqs } : {}),
  };
  params.emitSessionRestored?.(result);
  return result;
}
