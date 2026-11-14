// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Origin-scoped localStorage, per-tab sessionStorage, and transactional IndexedDB store. */

import type { TargetId } from "../session/identities.ts";
import type { SessionStore, StoreGuard, StoreTable } from "./session-store.ts";

export interface IndexedDbRecord {
  readonly key: string | number;
  readonly value: unknown;
}

export interface IndexedDbObjectStoreSnapshot {
  records: IndexedDbRecord[];
}

export interface IndexedDbDatabaseSnapshot {
  version: number;
  stores: Record<string, IndexedDbObjectStoreSnapshot>;
}

export interface IndexedDbOriginSnapshot {
  origin: string;
  databases: Record<string, IndexedDbDatabaseSnapshot>;
}

export type StringRecord = Record<string, string>;
export type TabSessionStorageSnapshot = Record<string, StringRecord>;

const LOCAL_STORAGE_TABLE = "ks_web_local_storage";
const SESSION_STORAGE_TABLE = "ks_web_session_storage";
const INDEXED_DB_TABLE = "ks_web_indexeddb";

function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const isStringRecord: StoreGuard<StringRecord> = (value): value is StringRecord => {
  if (!isRecordObject(value)) return false;
  for (const val of Object.values(value)) {
    if (typeof val !== "string") return false;
  }
  return true;
};

const isTabSessionStorage: StoreGuard<TabSessionStorageSnapshot> = (
  value,
): value is TabSessionStorageSnapshot => {
  if (!isRecordObject(value)) return false;
  for (const inner of Object.values(value)) {
    if (!isStringRecord(inner)) return false;
  }
  return true;
};

const isIndexedDbOriginSnapshot: StoreGuard<IndexedDbOriginSnapshot> = (
  value,
): value is IndexedDbOriginSnapshot => {
  if (!isRecordObject(value)) return false;
  return typeof value["origin"] === "string" && isRecordObject(value["databases"]);
};

export function normalizeStorageOrigin(rawUrlOrOrigin: string): string {
  if (!rawUrlOrOrigin || rawUrlOrOrigin === "null") return "null";
  try {
    const parsed = new URL(rawUrlOrOrigin);
    if (parsed.origin === "null") return "null";
    return parsed.origin;
  } catch {
    return rawUrlOrOrigin;
  }
}

export class IndexedDbTransactionAbortedError extends Error {
  constructor(reason = "IndexedDB transaction aborted") {
    super(reason);
    this.name = "IndexedDbTransactionAbortedError";
  }
}

export class IndexedDbTransactionContext {
  readonly origin: string;
  readonly mode: "readonly" | "readwrite";
  private readonly working: IndexedDbOriginSnapshot;
  private aborted = false;
  private abortReason: string | undefined;

  constructor(origin: string, mode: "readonly" | "readwrite", working: IndexedDbOriginSnapshot) {
    this.origin = origin;
    this.mode = mode;
    this.working = working;
  }

  get isAborted(): boolean {
    return this.aborted;
  }

  abort(reason?: string): never {
    this.aborted = true;
    this.abortReason = reason;
    throw new IndexedDbTransactionAbortedError(reason);
  }

  getAbortedReason(): string | undefined {
    return this.abortReason;
  }

  getRecord(dbName: string, storeName: string, key: string | number): unknown {
    const db = this.working.databases[dbName];
    const store = db?.stores[storeName];
    if (!store) return undefined;
    const hit = store.records.find((r) => r.key === key);
    return hit ? structuredClone(hit.value) : undefined;
  }

  listRecords(dbName: string, storeName: string): IndexedDbRecord[] {
    const db = this.working.databases[dbName];
    const store = db?.stores[storeName];
    if (!store) return [];
    return structuredClone(store.records);
  }

  putRecord(
    dbName: string,
    storeName: string,
    key: string | number,
    value: unknown,
    version = 1,
  ): void {
    this.assertWritable();
    let db = this.working.databases[dbName];
    if (!db) {
      db = { version, stores: {} };
      this.working.databases[dbName] = db;
    } else if (version > db.version) {
      db.version = version;
    }
    let store = db.stores[storeName];
    if (!store) {
      store = { records: [] };
      db.stores[storeName] = store;
    }
    const cloned = structuredClone(value);
    const idx = store.records.findIndex((r) => r.key === key);
    if (idx >= 0) {
      store.records[idx] = { key, value: cloned };
    } else {
      store.records.push({ key, value: cloned });
    }
  }

  deleteRecord(dbName: string, storeName: string, key: string | number): boolean {
    this.assertWritable();
    const store = this.working.databases[dbName]?.stores[storeName];
    if (!store) return false;
    const idx = store.records.findIndex((r) => r.key === key);
    if (idx < 0) return false;
    store.records.splice(idx, 1);
    return true;
  }

  clearStore(dbName: string, storeName: string): void {
    this.assertWritable();
    const store = this.working.databases[dbName]?.stores[storeName];
    if (store) store.records = [];
  }

  snapshot(): IndexedDbOriginSnapshot {
    return structuredClone(this.working);
  }

  private assertWritable(): void {
    if (this.mode !== "readwrite") {
      throw new Error("IndexedDB transaction is readonly");
    }
  }
}

export class WebStoragePersistenceBridge {
  private readonly store: SessionStore;
  private readonly localTable: StoreTable<StringRecord>;
  private readonly sessionTable: StoreTable<TabSessionStorageSnapshot>;
  private readonly idbTable: StoreTable<IndexedDbOriginSnapshot>;

  constructor(store: SessionStore) {
    this.store = store;
    this.localTable = this.store.table(LOCAL_STORAGE_TABLE, isStringRecord);
    this.sessionTable = this.store.table(SESSION_STORAGE_TABLE, isTabSessionStorage);
    this.idbTable = this.store.table(INDEXED_DB_TABLE, isIndexedDbOriginSnapshot);
  }

  getLocalStorage(originOrUrl: string): StringRecord {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return {};
    const existing = this.localTable.get(origin);
    return existing ? { ...existing } : {};
  }

  setLocalStorageItem(originOrUrl: string, key: string, value: string): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") throw new Error("Opaque origin has no localStorage bucket");
    const next = { ...(this.localTable.get(origin) ?? {}), [String(key)]: String(value) };
    this.localTable.set(origin, next);
  }

  removeLocalStorageItem(originOrUrl: string, key: string): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return;
    const current = this.localTable.get(origin);
    if (!current) return;
    const next = { ...current };
    delete next[String(key)];
    this.localTable.set(origin, next);
  }

  replaceLocalStorage(originOrUrl: string, entries: StringRecord): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return;
    this.localTable.set(origin, { ...entries });
  }

  clearLocalStorage(originOrUrl: string): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return;
    this.localTable.delete(origin);
  }

  getSessionStorage(targetId: TargetId, originOrUrl: string): StringRecord {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return {};
    const tab = this.sessionTable.get(targetId);
    const bucket = tab?.[origin];
    return bucket ? { ...bucket } : {};
  }

  setSessionStorageItem(targetId: TargetId, originOrUrl: string, key: string, value: string): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") throw new Error("Opaque origin has no sessionStorage bucket");
    const tab = { ...(this.sessionTable.get(targetId) ?? {}) };
    tab[origin] = { ...(tab[origin] ?? {}), [String(key)]: String(value) };
    this.sessionTable.set(targetId, tab);
  }

  removeSessionStorageItem(targetId: TargetId, originOrUrl: string, key: string): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return;
    const current = this.sessionTable.get(targetId);
    if (!current || !current[origin]) return;
    const nextBucket = { ...current[origin] };
    delete nextBucket[String(key)];
    this.sessionTable.set(targetId, { ...current, [origin]: nextBucket });
  }

  replaceSessionStorage(targetId: TargetId, originOrUrl: string, entries: StringRecord): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return;
    const tab = { ...(this.sessionTable.get(targetId) ?? {}) };
    tab[origin] = { ...entries };
    this.sessionTable.set(targetId, tab);
  }

  exportTabSessionStorage(targetId: TargetId): TabSessionStorageSnapshot {
    return structuredClone(this.sessionTable.get(targetId) ?? {});
  }

  importTabSessionStorage(targetId: TargetId, snapshot: TabSessionStorageSnapshot): void {
    this.sessionTable.set(targetId, structuredClone(snapshot));
  }

  clearTabSessionStorage(targetId: TargetId): void {
    this.sessionTable.delete(targetId);
  }

  getIndexedDbSnapshot(originOrUrl: string): IndexedDbOriginSnapshot {
    const origin = normalizeStorageOrigin(originOrUrl);
    const existing = this.idbTable.get(origin);
    return existing ? structuredClone(existing) : { origin, databases: {} };
  }

  replaceIndexedDbSnapshot(originOrUrl: string, snapshot: IndexedDbOriginSnapshot): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") return;
    this.idbTable.set(origin, structuredClone({ ...snapshot, origin }));
  }

  clearIndexedDb(originOrUrl: string): void {
    const origin = normalizeStorageOrigin(originOrUrl);
    this.idbTable.delete(origin);
  }

  transaction<T>(
    originOrUrl: string,
    mode: "readonly" | "readwrite",
    fn: (tx: IndexedDbTransactionContext) => T,
  ): T {
    const origin = normalizeStorageOrigin(originOrUrl);
    if (origin === "null") {
      throw new Error("Opaque origin has no IndexedDB bucket");
    }
    const base = this.getIndexedDbSnapshot(origin);
    const tx = new IndexedDbTransactionContext(origin, mode, base);
    const result = fn(tx);
    if (mode === "readwrite" && !tx.isAborted) {
      this.idbTable.set(origin, tx.snapshot());
    }
    return result;
  }

  exportAll(): {
    localStorage: Record<string, StringRecord>;
    sessionStorage: Record<string, TabSessionStorageSnapshot>;
    indexedDb: Record<string, IndexedDbOriginSnapshot>;
  } {
    const localStorage: Record<string, StringRecord> = {};
    for (const [origin, data] of this.localTable.entries()) {
      localStorage[origin] = { ...data };
    }
    const sessionStorage: Record<string, TabSessionStorageSnapshot> = {};
    for (const [tabId, snap] of this.sessionTable.entries()) {
      sessionStorage[tabId] = structuredClone(snap);
    }
    const indexedDb: Record<string, IndexedDbOriginSnapshot> = {};
    for (const [origin, snap] of this.idbTable.entries()) {
      indexedDb[origin] = structuredClone(snap);
    }
    return { localStorage, sessionStorage, indexedDb };
  }
}
