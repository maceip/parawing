// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  AuthorityVaultAndChannel,
  captureTier1Checkpoint,
  EncryptedSessionStore,
  KeyLeaseExpiredError,
  KeyLeaseManager,
  asSessionId,
  asTargetId,
  asUserId,
} from "../dist/engine-bundle.mjs";
import { NodeSqliteCipherBackend, nodeCryptoAesGcmCipher } from "../src/sqlite-backend.ts";

interface CheckpointRecord {
  readonly version: number;
  readonly sessionId: string;
  readonly reason: string;
  readonly lastAckedInputSeq: number;
  readonly targets: ReadonlyArray<{ readonly url: string }>;
}

function isStringVal(value: unknown): value is string {
  return typeof value === "string";
}

function isBytesVal(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

function isCheckpointVal(value: unknown): value is CheckpointRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string, unknown>)["version"] === 1 &&
    typeof (value as Record<string, unknown>)["sessionId"] === "string"
  );
}

describe("NodeSqliteCipherBackend persistence, delete/clear non-resurrection, and lease expiry", () => {
  it("encrypts rows in SQLite, survives reopen, and never resurrects deleted rows", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "parawing-sqlite-test-"));
    const dbPath = path.join(tmpDir, "session-store.db");
    try {
      const authority = await AuthorityVaultAndChannel.create();
      const userId = asUserId("user-sqlite");
      const sessionId = asSessionId("sess-sqlite");
      const lease = await authority.issueKeyLease({ userId, sessionId, ttlMs: 60_000 });
      const keyManager = await KeyLeaseManager.createVerified(lease, authority.publicKey);

      const backend1 = new NodeSqliteCipherBackend(dbPath);
      const store1 = new EncryptedSessionStore(keyManager, backend1);
      const kv = store1.table("kv", isStringVal);
      const bin = store1.table("bin", isBytesVal);

      kv.set("keep", "persistent-plaintext-marker");
      kv.set("remove-me", "do-not-resurrect-marker");
      bin.set("blob", new Uint8Array([1, 2, 3, 4, 255]));

      const rawBeforeDelete = backend1.rawRowCount();
      assert.equal(rawBeforeDelete, 3);
      const rawRow = backend1.rawEncryptedRow(userId, sessionId, "kv", "keep");
      assert.ok(rawRow);
      assert.equal(
        Buffer.from(rawRow.ciphertext).toString("utf8").includes("persistent-plaintext-marker"),
        false,
      );

      assert.equal(kv.delete("remove-me"), true);
      assert.equal(kv.has("remove-me"), false);
      assert.equal(backend1.rawRowCount(), 2);
      backend1.flush();
      backend1.close();

      // Reopen database on fresh backend and fresh store; deleted key must stay gone.
      const backend2 = new NodeSqliteCipherBackend(dbPath);
      const keyManager2 = await KeyLeaseManager.createVerified(lease, authority.publicKey);
      const store2 = new EncryptedSessionStore(keyManager2, backend2);
      const kv2 = store2.table("kv", isStringVal);
      const bin2 = store2.table("bin", isBytesVal);

      assert.equal(kv2.get("keep"), "persistent-plaintext-marker");
      assert.equal(kv2.get("remove-me"), undefined);
      assert.equal(kv2.has("remove-me"), false);
      assert.deepEqual(Array.from(bin2.get("blob") ?? []), [1, 2, 3, 4, 255]);
      assert.equal(backend2.rawRowCount(), 2);

      // clear() must permanently delete all rows of that table in SQLite.
      kv2.clear();
      backend2.close();

      const backend3 = new NodeSqliteCipherBackend(dbPath);
      const store3 = new EncryptedSessionStore(keyManager2, backend3);
      assert.equal(store3.table("kv", isStringVal).get("keep"), undefined);
      assert.equal(backend3.rawRowCount(), 1);
      store3.drop("bin");
      backend3.close();

      const backend4 = new NodeSqliteCipherBackend(dbPath);
      assert.equal(backend4.rawRowCount(), 0);
      backend4.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("rejects tampered SQLite ciphertext and wrong AAD on nodeCryptoAesGcmCipher", () => {
    const key = new Uint8Array(32).fill(7);
    const aadGood = new TextEncoder().encode("u1 tbl k1");
    const aadWrong = new TextEncoder().encode("u2 tbl k1");
    const plaintext = new TextEncoder().encode("sensitive payload");

    const sealed = nodeCryptoAesGcmCipher.encrypt(key, plaintext, aadGood);
    const opened = nodeCryptoAesGcmCipher.decrypt(
      key,
      sealed.nonce,
      sealed.ciphertext,
      sealed.tag,
      aadGood,
    );
    assert.equal(new TextDecoder().decode(opened), "sensitive payload");

    assert.throws(() =>
      nodeCryptoAesGcmCipher.decrypt(key, sealed.nonce, sealed.ciphertext, sealed.tag, aadWrong),
    );
    const badTag = new Uint8Array(sealed.tag);
    badTag[0] = (badTag[0] ?? 0) ^ 1;
    assert.throws(() =>
      nodeCryptoAesGcmCipher.decrypt(key, sealed.nonce, sealed.ciphertext, badTag, aadGood),
    );
  });

  it("checkpoints Tier 1 snapshot into SQLite before key expiry zeroization and restores with fresh lease", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "parawing-sqlite-lease-"));
    const dbPath = path.join(tmpDir, "lease-checkpoint.db");
    try {
      let clock = 20_000;
      const authority = await AuthorityVaultAndChannel.create({ now: () => clock });
      const userId = asUserId("user-ckpt");
      const sessionId = asSessionId("sess-ckpt");
      const lease1 = await authority.issueKeyLease({ userId, sessionId, ttlMs: 1_000, epoch: 1 });
      const reissuedFromVault = { ...lease1, keyBytes: new Uint8Array(lease1.keyBytes) };

      const backend1 = new NodeSqliteCipherBackend(dbPath);
      let store1!: EncryptedSessionStore;
      const leaseMgr1 = await KeyLeaseManager.createVerified(lease1, authority.publicKey, {
        now: () => clock,
        onCheckpoint: () => {
          captureTier1Checkpoint({
            sessionId,
            userId,
            reason: "key-lease-expire",
            lastAckedInputSeq: 42,
            store: store1,
            now: clock,
            targets: [
              {
                targetId: asTargetId("T-sqlite-1"),
                url: "https://docs.example/page",
                lastMethod: "GET",
                lastSafeGetUrl: "https://docs.example/page",
                history: [{ id: 1, url: "https://docs.example/page", title: "Docs" }],
                historyIndex: 0,
                scrollX: 0,
                scrollY: 120,
                viewport: { width: 1280, height: 800 },
                focusedFieldKey: null,
                sealedOrigin: null,
                formDrafts: [],
              },
            ],
          });
        },
        onFlush: () => {
          backend1.flush();
        },
      });
      store1 = new EncryptedSessionStore(leaseMgr1, backend1);
      const leasedBytes = leaseMgr1.requireKeyBytes();

      // Trigger expiry; checkpoint must have persisted before key buffer was zeroed.
      clock = 21_500;
      assert.throws(() => leaseMgr1.requireKeyBytes(), KeyLeaseExpiredError);
      assert.equal(
        Array.from(leasedBytes).every((b) => b === 0),
        true,
      );
      backend1.close();

      // Reopen SQLite with a vault-reissued lease for the same DEK and recover checkpoint.
      const backend2 = new NodeSqliteCipherBackend(dbPath);
      assert.equal(backend2.rawRowCount(), 1);
      const raw = backend2.rawEncryptedRow(userId, sessionId, "ks_tier1_checkpoints", "latest");
      assert.ok(raw);

      const leaseMgrRestore = await KeyLeaseManager.createVerified(
        reissuedFromVault,
        authority.publicKey,
        { now: () => 20_500 },
      );
      const store2 = new EncryptedSessionStore(leaseMgrRestore, backend2);
      const loaded = store2.table("ks_tier1_checkpoints", isCheckpointVal).get("latest");
      assert.ok(loaded);
      assert.equal(loaded.reason, "key-lease-expire");
      assert.equal(loaded.lastAckedInputSeq, 42);
      assert.equal(loaded.targets[0]?.url, "https://docs.example/page");
      backend2.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
