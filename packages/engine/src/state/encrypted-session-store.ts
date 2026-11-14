// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** AES-256-GCM encrypted SessionStore backed by a KeyLeaseManager and CipherRowBackend. */

import type { SessionId, UserId } from "../session/identities.ts";
import { decryptAes256Gcm, encryptAes256Gcm, GCM_NONCE_LENGTH } from "./aes256-gcm.ts";
import type { KeyLeaseManager } from "./key-lease.ts";
import type { SessionStore, StoreGuard, StoreStats, StoreTable } from "./session-store.ts";

export interface CipherEnvelope {
  readonly key: string;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
  readonly valueBytes: number;
}

export interface SyncAesGcmCipher {
  encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): { readonly nonce: Uint8Array; readonly ciphertext: Uint8Array; readonly tag: Uint8Array };
  decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    aad: Uint8Array,
  ): Uint8Array;
}

export interface CipherRowBackend {
  readonly backendName: string;
  readonly cipher?: SyncAesGcmCipher;
  getRow(
    userId: UserId,
    sessionId: SessionId,
    table: string,
    key: string,
  ): CipherEnvelope | undefined;
  hasRow(userId: UserId, sessionId: SessionId, table: string, key: string): boolean;
  putRow(userId: UserId, sessionId: SessionId, table: string, row: CipherEnvelope): void;
  deleteRow(userId: UserId, sessionId: SessionId, table: string, key: string): boolean;
  clearTable(userId: UserId, sessionId: SessionId, table: string): void;
  dropTable(userId: UserId, sessionId: SessionId, table: string): void;
  clearSession(userId: UserId, sessionId: SessionId): void;
  listRows(userId: UserId, sessionId: SessionId, table: string): IterableIterator<CipherEnvelope>;
  listKeys(userId: UserId, sessionId: SessionId, table: string): IterableIterator<string>;
  countRows(userId: UserId, sessionId: SessionId, table: string): number;
  listTables(userId: UserId, sessionId: SessionId): string[];
  stats(userId: UserId, sessionId: SessionId): StoreStats;
  flush?(): void;
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const TAG_STRING = 0x01;
const TAG_BYTES = 0x02;
const TAG_JSON = 0x03;

export function buildCipherAad(userId: UserId, table: string, key: string): Uint8Array {
  return TEXT_ENCODER.encode(`${userId}\u0000${table}\u0000${key}`);
}

export const portableAesGcmCipher: SyncAesGcmCipher = {
  encrypt(key, plaintext, aad) {
    const nonce = new Uint8Array(GCM_NONCE_LENGTH);
    crypto.getRandomValues(nonce);
    const { ciphertext, tag } = encryptAes256Gcm(key, nonce, plaintext, aad);
    return { nonce, ciphertext, tag };
  },
  decrypt(key, nonce, ciphertext, tag, aad) {
    return decryptAes256Gcm(key, nonce, ciphertext, tag, aad);
  },
};

function encodeStoredValue(value: unknown): { encoded: Uint8Array; valueBytes: number } {
  if (typeof value === "string") {
    const body = TEXT_ENCODER.encode(value);
    const out = new Uint8Array(1 + body.length);
    out[0] = TAG_STRING;
    out.set(body, 1);
    return { encoded: out, valueBytes: body.byteLength };
  }
  if (value instanceof Uint8Array) {
    const out = new Uint8Array(1 + value.byteLength);
    out[0] = TAG_BYTES;
    out.set(value, 1);
    return { encoded: out, valueBytes: value.byteLength };
  }
  const jsonText = JSON.stringify(value);
  if (jsonText === undefined) {
    throw new TypeError("Cannot serialize undefined value into EncryptedSessionStore");
  }
  const body = TEXT_ENCODER.encode(jsonText);
  const out = new Uint8Array(1 + body.length);
  out[0] = TAG_JSON;
  out.set(body, 1);
  return { encoded: out, valueBytes: body.byteLength };
}

function decodeStoredValue(plaintext: Uint8Array): unknown {
  if (plaintext.length === 0) {
    throw new Error("EncryptedSessionStore plaintext cannot be empty");
  }
  const kind = plaintext[0];
  const body = plaintext.subarray(1);
  if (kind === TAG_STRING) return TEXT_DECODER.decode(body);
  if (kind === TAG_BYTES) return new Uint8Array(body);
  if (kind === TAG_JSON) return JSON.parse(TEXT_DECODER.decode(body)) as unknown;
  throw new Error(`Unknown EncryptedSessionStore payload tag: ${String(kind)}`);
}

export class InMemoryCipherBackend implements CipherRowBackend {
  readonly backendName = "encrypted-memory";
  readonly cipher: SyncAesGcmCipher = portableAesGcmCipher;
  private readonly sessions = new Map<string, Map<string, Map<string, CipherEnvelope>>>();

  private sessionMap(
    userId: UserId,
    sessionId: SessionId,
  ): Map<string, Map<string, CipherEnvelope>> {
    const sk = `${userId}\u0000${sessionId}`;
    let tables = this.sessions.get(sk);
    if (!tables) {
      tables = new Map();
      this.sessions.set(sk, tables);
    }
    return tables;
  }

  private tableMap(
    userId: UserId,
    sessionId: SessionId,
    table: string,
    create: boolean,
  ): Map<string, CipherEnvelope> | undefined {
    const tables = this.sessionMap(userId, sessionId);
    let rows = tables.get(table);
    if (!rows && create) {
      rows = new Map();
      tables.set(table, rows);
    }
    return rows;
  }

  getRow(
    userId: UserId,
    sessionId: SessionId,
    table: string,
    key: string,
  ): CipherEnvelope | undefined {
    return this.tableMap(userId, sessionId, table, false)?.get(key);
  }

  hasRow(userId: UserId, sessionId: SessionId, table: string, key: string): boolean {
    return this.tableMap(userId, sessionId, table, false)?.has(key) ?? false;
  }

  putRow(userId: UserId, sessionId: SessionId, table: string, row: CipherEnvelope): void {
    const rows = this.tableMap(userId, sessionId, table, true);
    rows?.set(row.key, row);
  }

  deleteRow(userId: UserId, sessionId: SessionId, table: string, key: string): boolean {
    return this.tableMap(userId, sessionId, table, false)?.delete(key) ?? false;
  }

  clearTable(userId: UserId, sessionId: SessionId, table: string): void {
    this.tableMap(userId, sessionId, table, false)?.clear();
  }

  dropTable(userId: UserId, sessionId: SessionId, table: string): void {
    const tables = this.sessionMap(userId, sessionId);
    tables.get(table)?.clear();
    tables.delete(table);
  }

  clearSession(userId: UserId, sessionId: SessionId): void {
    const tables = this.sessionMap(userId, sessionId);
    for (const rows of tables.values()) rows.clear();
    tables.clear();
  }

  *listRows(userId: UserId, sessionId: SessionId, table: string): IterableIterator<CipherEnvelope> {
    const rows = this.tableMap(userId, sessionId, table, false);
    if (!rows) return;
    for (const row of rows.values()) yield row;
  }

  *listKeys(userId: UserId, sessionId: SessionId, table: string): IterableIterator<string> {
    const rows = this.tableMap(userId, sessionId, table, false);
    if (!rows) return;
    for (const key of rows.keys()) yield key;
  }

  countRows(userId: UserId, sessionId: SessionId, table: string): number {
    return this.tableMap(userId, sessionId, table, false)?.size ?? 0;
  }

  listTables(userId: UserId, sessionId: SessionId): string[] {
    return [...this.sessionMap(userId, sessionId).keys()];
  }

  stats(userId: UserId, sessionId: SessionId): StoreStats {
    const tables: StoreStats["tables"] = {};
    let valueBytes = 0;
    let keys = 0;
    for (const [name, rows] of this.sessionMap(userId, sessionId)) {
      let bytes = 0;
      for (const row of rows.values()) bytes += row.valueBytes;
      tables[name] = { keys: rows.size, bytes };
      valueBytes += bytes;
      keys += rows.size;
    }
    return { backend: this.backendName, bytes: valueBytes, valueBytes, keys, tables };
  }
}

export class EncryptedSessionStore implements SessionStore {
  readonly backend: string;
  private readonly keyLease: KeyLeaseManager;
  private readonly rowBackend: CipherRowBackend;
  private readonly cipher: SyncAesGcmCipher;

  constructor(
    keyLease: KeyLeaseManager,
    rowBackend: CipherRowBackend = new InMemoryCipherBackend(),
  ) {
    this.keyLease = keyLease;
    this.rowBackend = rowBackend;
    this.cipher = rowBackend.cipher ?? portableAesGcmCipher;
    this.backend = rowBackend.backendName;
  }

  get userId(): UserId {
    return this.keyLease.userId;
  }

  get sessionId(): SessionId {
    return this.keyLease.sessionId;
  }

  stats(): StoreStats {
    this.keyLease.requireKeyBytes();
    return this.rowBackend.stats(this.userId, this.sessionId);
  }

  table<V>(name: string, is: StoreGuard<V>): StoreTable<V> {
    return new EncryptedTable(this, name, is);
  }

  drop(name: string): void {
    this.keyLease.requireKeyBytes();
    this.rowBackend.dropTable(this.userId, this.sessionId, name);
  }

  clear(): void {
    this.keyLease.requireKeyBytes();
    this.rowBackend.clearSession(this.userId, this.sessionId);
  }

  flush(): void {
    this.rowBackend.flush?.();
  }

  decryptRow<V>(table: string, key: string, is: StoreGuard<V>): V | undefined {
    const keyBytes = this.keyLease.requireKeyBytes();
    const row = this.rowBackend.getRow(this.userId, this.sessionId, table, key);
    if (!row) return undefined;
    return this.decryptEnvelope(table, row, keyBytes, is);
  }

  hasRow(table: string, key: string): boolean {
    this.keyLease.requireKeyBytes();
    return this.rowBackend.hasRow(this.userId, this.sessionId, table, key);
  }

  encryptAndPutRow(table: string, key: string, value: unknown): void {
    const keyBytes = this.keyLease.requireKeyBytes();
    const aad = buildCipherAad(this.userId, table, key);
    const { encoded, valueBytes } = encodeStoredValue(value);
    const { nonce, ciphertext, tag } = this.cipher.encrypt(keyBytes, encoded, aad);
    this.rowBackend.putRow(this.userId, this.sessionId, table, {
      key,
      nonce,
      ciphertext,
      tag,
      valueBytes,
    });
  }

  deleteRow(table: string, key: string): boolean {
    this.keyLease.requireKeyBytes();
    return this.rowBackend.deleteRow(this.userId, this.sessionId, table, key);
  }

  clearTable(table: string): void {
    this.keyLease.requireKeyBytes();
    this.rowBackend.clearTable(this.userId, this.sessionId, table);
  }

  countRows(table: string): number {
    this.keyLease.requireKeyBytes();
    return this.rowBackend.countRows(this.userId, this.sessionId, table);
  }

  listKeys(table: string): IterableIterator<string> {
    this.keyLease.requireKeyBytes();
    return this.rowBackend.listKeys(this.userId, this.sessionId, table);
  }

  *listEntries<V>(table: string, is: StoreGuard<V>): IterableIterator<[string, V]> {
    const keyBytes = this.keyLease.requireKeyBytes();
    for (const row of this.rowBackend.listRows(this.userId, this.sessionId, table)) {
      this.keyLease.requireKeyBytes();
      const val = this.decryptEnvelope(table, row, keyBytes, is);
      if (val !== undefined) yield [row.key, val];
    }
  }

  private decryptEnvelope<V>(
    table: string,
    row: CipherEnvelope,
    keyBytes: Uint8Array,
    is: StoreGuard<V>,
  ): V | undefined {
    const aad = buildCipherAad(this.userId, table, row.key);
    const plaintext = this.cipher.decrypt(keyBytes, row.nonce, row.ciphertext, row.tag, aad);
    const decoded = decodeStoredValue(plaintext);
    if (is(decoded)) return decoded;
    console.warn(JSON.stringify({ event: "session_store_row_rejected", table, key: row.key }));
    return undefined;
  }
}

class EncryptedTable<V> implements StoreTable<V> {
  private readonly store: EncryptedSessionStore;
  private readonly name: string;
  private readonly is: StoreGuard<V>;

  constructor(store: EncryptedSessionStore, name: string, is: StoreGuard<V>) {
    this.store = store;
    this.name = name;
    this.is = is;
  }

  get(key: string): V | undefined {
    return this.store.decryptRow(this.name, key, this.is);
  }

  has(key: string): boolean {
    return this.store.hasRow(this.name, key);
  }

  set(key: string, value: V): this {
    this.store.encryptAndPutRow(this.name, key, value);
    return this;
  }

  delete(key: string): boolean {
    return this.store.deleteRow(this.name, key);
  }

  clear(): void {
    this.store.clearTable(this.name);
  }

  get size(): number {
    return this.store.countRows(this.name);
  }

  keys(): IterableIterator<string> {
    return this.store.listKeys(this.name);
  }

  *values(): IterableIterator<V> {
    for (const [, v] of this.entries()) yield v;
  }

  entries(): IterableIterator<[string, V]> {
    return this.store.listEntries(this.name, this.is);
  }
}
