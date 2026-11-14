// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Node built-in sqlite + node:crypto AES-256-GCM persistent backend for EncryptedSessionStore. */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { DatabaseSync, type StatementSync } from "node:sqlite";
import type {
  CipherEnvelope,
  CipherRowBackend,
  SyncAesGcmCipher,
} from "@parawing/engine/encrypted-session-store";
import type { SessionId, UserId } from "@parawing/engine/session-identities";
import type { StoreStats } from "@parawing/engine/session-store";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

export const nodeCryptoAesGcmCipher: SyncAesGcmCipher = {
  encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): { nonce: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array } {
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
    if (aad.byteLength > 0) cipher.setAAD(aad);
    const first = cipher.update(plaintext);
    const last = cipher.final();
    const ciphertext = Buffer.concat([first, last]);
    const tag = cipher.getAuthTag();
    return {
      nonce: new Uint8Array(nonce.buffer, nonce.byteOffset, nonce.byteLength),
      ciphertext: new Uint8Array(ciphertext.buffer, ciphertext.byteOffset, ciphertext.byteLength),
      tag: new Uint8Array(tag.buffer, tag.byteOffset, tag.byteLength),
    };
  },
  decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    aad: Uint8Array,
  ): Uint8Array {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
    if (aad.byteLength > 0) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const first = decipher.update(ciphertext);
    const last = decipher.final();
    const out = Buffer.concat([first, last]);
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
  },
};

function decodeCipherRow(raw: Record<string, unknown> | undefined): CipherEnvelope | undefined {
  if (!raw) return undefined;
  const key = raw["row_key"];
  const nonce = raw["nonce"];
  const ciphertext = raw["ciphertext"];
  const tag = raw["tag"];
  const valueBytes = raw["value_bytes"];
  if (
    typeof key !== "string" ||
    !(nonce instanceof Uint8Array) ||
    !(ciphertext instanceof Uint8Array) ||
    !(tag instanceof Uint8Array) ||
    typeof valueBytes !== "number"
  ) {
    throw new Error("Malformed ks_cipher_rows row returned from SQLite");
  }
  return {
    key,
    nonce: new Uint8Array(nonce),
    ciphertext: new Uint8Array(ciphertext),
    tag: new Uint8Array(tag),
    valueBytes,
  };
}

export class NodeSqliteCipherBackend implements CipherRowBackend {
  readonly backendName = "node-sqlite-aes-256-gcm";
  readonly cipher: SyncAesGcmCipher = nodeCryptoAesGcmCipher;

  private readonly db: DatabaseSync;
  private readonly isMemoryDb: boolean;
  private closed = false;

  private readonly stmtGet: StatementSync;
  private readonly stmtHas: StatementSync;
  private readonly stmtPut: StatementSync;
  private readonly stmtDelete: StatementSync;
  private readonly stmtClearTable: StatementSync;
  private readonly stmtClearSession: StatementSync;
  private readonly stmtListRows: StatementSync;
  private readonly stmtListKeys: StatementSync;
  private readonly stmtCountRows: StatementSync;
  private readonly stmtListTables: StatementSync;
  private readonly stmtStatsTables: StatementSync;
  private readonly stmtPageCount: StatementSync;
  private readonly stmtPageSize: StatementSync;

  constructor(filename: string) {
    this.isMemoryDb = filename === ":memory:" || filename.startsWith("file::memory:");
    this.db = new DatabaseSync(filename);
    if (!this.isMemoryDb) {
      this.db.exec("PRAGMA journal_mode = WAL;");
      this.db.exec("PRAGMA synchronous = FULL;");
    }
    this.db.exec("PRAGMA secure_delete = ON;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ks_cipher_rows (
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        table_name TEXT NOT NULL,
        row_key TEXT NOT NULL,
        seq INTEGER NOT NULL,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL,
        tag BLOB NOT NULL,
        value_bytes INTEGER NOT NULL,
        PRIMARY KEY (user_id, session_id, table_name, row_key)
      );
      CREATE INDEX IF NOT EXISTS ks_cipher_rows_order
        ON ks_cipher_rows (user_id, session_id, table_name, seq);
    `);

    this.stmtGet = this.db.prepare(
      `SELECT row_key, nonce, ciphertext, tag, value_bytes
       FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ? AND table_name = ? AND row_key = ?`,
    );
    this.stmtHas = this.db.prepare(
      `SELECT 1 AS present
       FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ? AND table_name = ? AND row_key = ?`,
    );
    this.stmtPut = this.db.prepare(
      `INSERT INTO ks_cipher_rows (
         user_id, session_id, table_name, row_key, seq, nonce, ciphertext, tag, value_bytes
       ) VALUES (
         ?, ?, ?, ?,
         COALESCE(
           (SELECT seq FROM ks_cipher_rows
            WHERE user_id = ? AND session_id = ? AND table_name = ? AND row_key = ?),
           (SELECT COALESCE(MAX(seq), 0) + 1 FROM ks_cipher_rows
            WHERE user_id = ? AND session_id = ? AND table_name = ?)
         ),
         ?, ?, ?, ?
       )
       ON CONFLICT(user_id, session_id, table_name, row_key)
       DO UPDATE SET
         nonce = excluded.nonce,
         ciphertext = excluded.ciphertext,
         tag = excluded.tag,
         value_bytes = excluded.value_bytes`,
    );
    this.stmtDelete = this.db.prepare(
      `DELETE FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ? AND table_name = ? AND row_key = ?`,
    );
    this.stmtClearTable = this.db.prepare(
      `DELETE FROM ks_cipher_rows WHERE user_id = ? AND session_id = ? AND table_name = ?`,
    );
    this.stmtClearSession = this.db.prepare(
      `DELETE FROM ks_cipher_rows WHERE user_id = ? AND session_id = ?`,
    );
    this.stmtListRows = this.db.prepare(
      `SELECT row_key, nonce, ciphertext, tag, value_bytes
       FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ? AND table_name = ?
       ORDER BY seq ASC`,
    );
    this.stmtListKeys = this.db.prepare(
      `SELECT row_key
       FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ? AND table_name = ?
       ORDER BY seq ASC`,
    );
    this.stmtCountRows = this.db.prepare(
      `SELECT COUNT(*) AS cnt
       FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ? AND table_name = ?`,
    );
    this.stmtListTables = this.db.prepare(
      `SELECT DISTINCT table_name
       FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ?
       ORDER BY table_name ASC`,
    );
    this.stmtStatsTables = this.db.prepare(
      `SELECT table_name, COUNT(*) AS cnt, COALESCE(SUM(value_bytes), 0) AS bytes
       FROM ks_cipher_rows
       WHERE user_id = ? AND session_id = ?
       GROUP BY table_name`,
    );
    this.stmtPageCount = this.db.prepare("PRAGMA page_count;");
    this.stmtPageSize = this.db.prepare("PRAGMA page_size;");
  }

  static buildAad(userId: UserId, table: string, key: string): Buffer {
    return Buffer.from(`${userId}\u0000${table}\u0000${key}`, "utf8");
  }

  getRow(
    userId: UserId,
    sessionId: SessionId,
    table: string,
    key: string,
  ): CipherEnvelope | undefined {
    const raw = this.stmtGet.get(userId, sessionId, table, key);
    return decodeCipherRow(raw);
  }

  hasRow(userId: UserId, sessionId: SessionId, table: string, key: string): boolean {
    return this.stmtHas.get(userId, sessionId, table, key) !== undefined;
  }

  putRow(userId: UserId, sessionId: SessionId, table: string, row: CipherEnvelope): void {
    this.stmtPut.run(
      userId,
      sessionId,
      table,
      row.key,
      userId,
      sessionId,
      table,
      row.key,
      userId,
      sessionId,
      table,
      row.nonce,
      row.ciphertext,
      row.tag,
      row.valueBytes,
    );
  }

  deleteRow(userId: UserId, sessionId: SessionId, table: string, key: string): boolean {
    const res = this.stmtDelete.run(userId, sessionId, table, key);
    return Number(res.changes) > 0;
  }

  clearTable(userId: UserId, sessionId: SessionId, table: string): void {
    this.stmtClearTable.run(userId, sessionId, table);
  }

  dropTable(userId: UserId, sessionId: SessionId, table: string): void {
    this.stmtClearTable.run(userId, sessionId, table);
  }

  clearSession(userId: UserId, sessionId: SessionId): void {
    this.stmtClearSession.run(userId, sessionId);
  }

  *listRows(userId: UserId, sessionId: SessionId, table: string): IterableIterator<CipherEnvelope> {
    const rows = this.stmtListRows.all(userId, sessionId, table);
    for (const raw of rows) {
      const decoded = decodeCipherRow(raw);
      if (decoded) yield decoded;
    }
  }

  *listKeys(userId: UserId, sessionId: SessionId, table: string): IterableIterator<string> {
    const rows = this.stmtListKeys.all(userId, sessionId, table);
    for (const raw of rows) {
      const key = raw["row_key"];
      if (typeof key === "string") yield key;
    }
  }

  countRows(userId: UserId, sessionId: SessionId, table: string): number {
    const raw = this.stmtCountRows.get(userId, sessionId, table);
    const cnt = raw?.["cnt"];
    return typeof cnt === "number" ? cnt : Number(cnt ?? 0);
  }

  listTables(userId: UserId, sessionId: SessionId): string[] {
    const rows = this.stmtListTables.all(userId, sessionId);
    const out: string[] = [];
    for (const raw of rows) {
      const name = raw["table_name"];
      if (typeof name === "string") out.push(name);
    }
    return out;
  }

  stats(userId: UserId, sessionId: SessionId): StoreStats {
    const rows = this.stmtStatsTables.all(userId, sessionId);
    const tables: StoreStats["tables"] = {};
    let valueBytes = 0;
    let keys = 0;
    for (const raw of rows) {
      const name = raw["table_name"];
      const cnt = Number(raw["cnt"] ?? 0);
      const bytes = Number(raw["bytes"] ?? 0);
      if (typeof name === "string") {
        tables[name] = { keys: cnt, bytes };
        valueBytes += bytes;
        keys += cnt;
      }
    }
    const pageCountRow = this.stmtPageCount.get();
    const pageSizeRow = this.stmtPageSize.get();
    const dbBytes =
      Number(pageCountRow?.["page_count"] ?? 0) * Number(pageSizeRow?.["page_size"] ?? 0);
    return {
      backend: this.backendName,
      bytes: dbBytes > 0 ? dbBytes : valueBytes,
      valueBytes,
      keys,
      tables,
    };
  }

  flush(): void {
    if (this.closed || this.isMemoryDb) return;
    this.db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  }

  /** Expose raw SQLite row count across the whole table for persistence verification. */
  rawRowCount(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS cnt FROM ks_cipher_rows;").get();
    return Number(row?.["cnt"] ?? 0);
  }

  /** Return raw cipher metadata for cryptographic inspection in tests. */
  rawEncryptedRow(
    userId: UserId,
    sessionId: SessionId,
    table: string,
    key: string,
  ): CipherEnvelope | undefined {
    return this.getRow(userId, sessionId, table, key);
  }

  close(): void {
    if (this.closed) return;
    this.flush();
    this.db.close();
    this.closed = true;
  }
}
