// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, expect, it, vi } from "vitest";

// The frame isolate wasm is read from /bundle, which unit-test workers omit.
vi.mock("node:fs", () => ({
  default: {
    readdirSync: () => ["parawing_core_bg.wasm"],
    readFileSync: () => new Uint8Array(8),
  },
}));

vi.mock("../src/wasm.ts", () => ({
  scanDocument: () => ({
    title: "",
    baseHref: null,
    metaCsp: [],
    importMaps: [],
    scripts: [],
    iframes: [],
    modulePreloads: [],
  }),
  extractScriptDescriptorsFromDom: () => [],
  createDom: () => ({
    querySelectorAll: () => [],
    free: () => {},
  }),
}));

import { AuthorityVaultAndChannel } from "../src/authority/authority-service.ts";
import {
  CAPSULE_PINNED_PAGE_SIZE,
  CapsuleAttestationAuthority,
  signCapsuleAttestation,
  unwrapLeasedAesKey,
  verifyDbscJwtProof,
  wrappedKeyLeaseFromWire,
  type DbscSessionCredential,
  type WrappedKeyLeaseReleaseWire,
} from "../src/authority/attestation.ts";
import {
  handleCdpSession,
  type CdpSessionCloseEvent,
  type CdpSessionTransport,
} from "../src/cdp/connection.ts";
import { DedicatedWorkers } from "../src/cdp/dedicated-workers.ts";
import type { DispatchCtx } from "../src/cdp/dispatch.ts";
import { NetworkEventTracker } from "../src/cdp/network-events.ts";
import { StyleCache } from "../src/cdp/style-cache.ts";
import { createPageTarget } from "../src/cdp/target.ts";
import type { BrowserState, CdpEvent, TargetState } from "../src/cdp/types.ts";
import { createCookieJar } from "../src/cookies.ts";
import { createSandboxOutboundOverride } from "../src/eval/outbound.ts";
import { DynamicWorkerBudget } from "../src/eval/worker-budget.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import type { HostIsolateLoader } from "../src/isolate-loader.ts";
import { ParawingAnalytics, SafePerformance } from "../src/observability.ts";
import { SignedAuditLog, verifyAuditChain } from "../src/policy/audit-log.ts";
import { ControllerLeaseManager } from "../src/policy/controller-lease.ts";
import { PolicyEngine } from "../src/policy/policy-engine.ts";
import {
  captureTier1Checkpoint,
  loadLatestTier1Checkpoint,
  restoreTier1Checkpoint,
  type RestorableTargetAdapter,
  type Tier1RestoreResult,
  type Tier1TargetSnapshot,
} from "../src/session/checkpoint.ts";
import {
  SessionDestroyedError,
  StaleEpochError,
  asConnectionId,
  asSessionId,
  asTargetId,
  asUserId,
  type TargetId,
} from "../src/session/identities.ts";
import { SessionManager } from "../src/session/session-manager.ts";
import {
  EncryptedSessionStore,
  InMemoryCipherBackend,
} from "../src/state/encrypted-session-store.ts";
import {
  KeyLeaseExpiredError,
  KeyLeaseManager,
  KeyLeaseSignatureError,
} from "../src/state/key-lease.ts";
import { MemorySessionStore, isStoredString } from "../src/state/session-store.ts";
import { WebStoragePersistenceBridge } from "../src/state/web-storage-bridge.ts";

function makeRealTargetState(url: string): TargetState {
  const host = createMemoryHostCapabilities();
  const store = new MemorySessionStore();
  const browser: BrowserState = {
    targets: new Map(),
    sandboxOutbound: createSandboxOutboundOverride(host),
    autoAttach: false,
    flatten: false,
    cookies: createCookieJar(),
    contexts: new Map(),
    nextBrowserContextId: 1,
    screencasts: new Map(),
    styleCache: new StyleCache(),
    imageCache: new Map(),
    networkEvents: new NetworkEventTracker(() => {}, "test-conn"),
    layoutMode: "full",
    cdpDebug: false,
    connectionMode: "browser",
    preNavScripts: new Map(),
    learnedInsertedScripts: new Map(),
    pendingBindings: new Set(),
    execContextSeq: 1,
    runtimeEnabledSessions: new Set(),
    rendererManager: null,
    workerBudget: new DynamicWorkerBudget(),
    dedicatedWorkers: new DedicatedWorkers(new DynamicWorkerBudget(), host.tasks),
    skipSpeculativeRaster: false,
    skipPartialRaster: false,
    fontDefer: false,
    rendererSessionId: null,
    engineSessionId: null,
    wsClosing: false,
    attributionHeaders: {},
    persistentSession: false,
    delegatedAgent: false,
    policyEngine: new PolicyEngine(),
    controllerLeases: new ControllerLeaseManager(),
    store,
    webStorage: new WebStoragePersistenceBridge(store),
    emitSink: () => {},
  };
  const analytics = new ParawingAnalytics(
    {
      sessionId: "test-conn",
      entrypoint: "vitest",
      connectionMode: "browser",
      environment: "test",
      buildVersion: "0.0.0",
      colo: "local",
    },
    new SafePerformance(host.clock.monotonic),
  );
  const ctx: DispatchCtx = {
    browser,
    emit: () => {},
    host,
    isolateLoader: {
      load: () => {
        throw new Error("no isolate expected");
      },
    },
    connectionId: "test-conn",
    analytics,
  };
  return createPageTarget(ctx, url);
}

function createHarnessTransport(): {
  transport: CdpSessionTransport;
  outbound: Array<Record<string, unknown>>;
  sendInbound: (payload: Record<string, unknown>) => void;
  simulateClose: (ev?: CdpSessionCloseEvent) => void;
  wasClosedByEngine: () => boolean;
} {
  const outbound: Array<Record<string, unknown>> = [];
  const messageHandlers: Array<(data: string | ArrayBuffer) => void> = [];
  const closeHandlers: Array<(ev: CdpSessionCloseEvent) => void> = [];
  let closedByEngine = false;

  const transport: CdpSessionTransport = {
    send(data) {
      outbound.push(JSON.parse(data) as Record<string, unknown>);
    },
    close() {
      closedByEngine = true;
    },
    onMessage(handler) {
      messageHandlers.push(handler);
    },
    onClose(handler) {
      closeHandlers.push(handler);
    },
    onError() {},
  };

  return {
    transport,
    outbound,
    sendInbound(payload) {
      const encoded = JSON.stringify(payload);
      for (const h of messageHandlers) h(encoded);
    },
    simulateClose(ev = { code: 1000, reason: "client-closed", wasClean: true }) {
      for (const h of closeHandlers) h(ev);
    },
    wasClosedByEngine() {
      return closedByEngine;
    },
  };
}

describe("KeyLeaseManager and EncryptedSessionStore", () => {
  it("verifies signed key lease, rejects tampering, and zeroes key bytes on expiry", async () => {
    let clock = 10_000;
    const authority = await AuthorityVaultAndChannel.create({ now: () => clock });
    const userId = asUserId("user-1");
    const sessionId = asSessionId("sess-lease");
    const signedLease = await authority.issueKeyLease({
      userId,
      sessionId,
      ttlMs: 5_000,
    });

    const tamperedLease = {
      ...signedLease,
      payload: { ...signedLease.payload, expiresAt: clock + 999_999 },
    };
    await expect(
      KeyLeaseManager.createVerified(tamperedLease, authority.publicKey, { now: () => clock }),
    ).rejects.toThrow(KeyLeaseSignatureError);

    let checkpointCount = 0;
    let flushCount = 0;
    let suspendCount = 0;
    let store!: EncryptedSessionStore;
    const manager = await KeyLeaseManager.createVerified(signedLease, authority.publicKey, {
      now: () => clock,
      onCheckpoint: () => {
        // Must execute while key is still usable so store write succeeds.
        const table = store.table("checkpoint_probe", isStoredString);
        table.set("snap", "saved-before-zeroize");
        checkpointCount += 1;
      },
      onFlush: () => {
        flushCount += 1;
      },
      onSuspend: () => {
        suspendCount += 1;
      },
    });

    const backend = new InMemoryCipherBackend();
    store = new EncryptedSessionStore(manager, backend);
    const notes = store.table("notes", isStoredString);
    notes.set("alpha", "top-secret-alpha");
    notes.set("beta", "top-secret-beta");
    expect(notes.get("alpha")).toBe("top-secret-alpha");

    // Verify underlying ciphertext contains no plaintext and is bound to AAD.
    const rawRow = backend.getRow(userId, sessionId, "notes", "alpha");
    expect(rawRow).toBeDefined();
    expect(Buffer.from(rawRow!.ciphertext).toString("utf8")).not.toContain("top-secret-alpha");

    // Tamper ciphertext and confirm AES-256-GCM authentication tag failure.
    const corrupted = new Uint8Array(rawRow!.ciphertext);
    corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;
    backend.putRow(userId, sessionId, "notes", { ...rawRow!, ciphertext: corrupted });
    expect(() => notes.get("alpha")).toThrow();

    notes.delete("alpha");
    expect(notes.has("alpha")).toBe(false);
    expect(notes.get("beta")).toBe("top-secret-beta");

    // Advance past expiresAt; access triggers checkpoint -> flush -> zeroize -> suspend.
    const keySnapshot = manager.requireKeyBytes();
    clock = 15_001;
    expect(() => notes.get("beta")).toThrow(KeyLeaseExpiredError);
    expect(checkpointCount).toBe(1);
    expect(flushCount).toBe(1);
    expect(suspendCount).toBe(1);
    expect(manager.state).toBe("expired");
    expect(Array.from(keySnapshot).every((b) => b === 0)).toBe(true);
    expect(() => manager.requireKeyBytes()).toThrow(KeyLeaseExpiredError);
  });

  it("handles immediate revocation cleanly and zeroizes key material", async () => {
    const clock = 5_000;
    const authority = await AuthorityVaultAndChannel.create({ now: () => clock });
    const signedLease = await authority.issueKeyLease({
      userId: asUserId("user-rev"),
      sessionId: asSessionId("sess-rev"),
      ttlMs: 60_000,
    });
    const manager = await KeyLeaseManager.createVerified(signedLease, authority.publicKey, {
      now: () => clock,
    });
    const keyRef = manager.requireKeyBytes();
    const store = new EncryptedSessionStore(manager);
    const prefs = store.table("prefs", isStoredString);
    prefs.set("theme", "dark");

    await manager.revoke();
    expect(manager.state).toBe("revoked");
    expect(Array.from(keyRef).every((b) => b === 0)).toBe(true);
    expect(() => prefs.get("theme")).toThrow(KeyLeaseExpiredError);
  });
});

describe("WebStoragePersistenceBridge", () => {
  it("isolates localStorage by origin, isolates sessionStorage per tab, and rolls back IDB", () => {
    const bridge = new WebStoragePersistenceBridge(new MemorySessionStore());
    bridge.setLocalStorageItem("https://app.example/path", "token", "abc");
    bridge.setLocalStorageItem("https://other.example/path", "token", "xyz");
    expect(bridge.getLocalStorage("https://app.example")).toEqual({ token: "abc" });
    expect(bridge.getLocalStorage("https://other.example")).toEqual({ token: "xyz" });

    expect(() => bridge.setLocalStorageItem("null", "k", "v")).toThrow();

    const tabA = asTargetId("tab-a");
    const tabB = asTargetId("tab-b");
    bridge.setSessionStorageItem(tabA, "https://app.example", "draft", "hello-a");
    bridge.setSessionStorageItem(tabB, "https://app.example", "draft", "hello-b");
    expect(bridge.getSessionStorage(tabA, "https://app.example")).toEqual({ draft: "hello-a" });
    expect(bridge.getSessionStorage(tabB, "https://app.example")).toEqual({ draft: "hello-b" });

    bridge.clearTabSessionStorage(tabA);
    expect(bridge.getSessionStorage(tabA, "https://app.example")).toEqual({});
    expect(bridge.getSessionStorage(tabB, "https://app.example")).toEqual({ draft: "hello-b" });

    bridge.transaction("https://app.example", "readwrite", (tx) => {
      tx.putRecord("mail", "messages", 1, { subject: "Committed" });
    });

    expect(() =>
      bridge.transaction("https://app.example", "readwrite", (tx) => {
        tx.putRecord("mail", "messages", 1, { subject: "Overwritten" });
        tx.putRecord("mail", "messages", 2, { subject: "Aborted" });
        tx.abort("simulated failure");
      }),
    ).toThrow();

    const readAfterAbort = bridge.transaction("https://app.example", "readonly", (tx) =>
      tx.listRecords("mail", "messages"),
    );
    expect(readAfterAbort).toEqual([{ key: 1, value: { subject: "Committed" } }]);
  });
});

describe("Tier 1 Logical Checkpoint and GET-only safe restore", () => {
  it("never replays POST navigations, falls back to safe GET, bumps generation, and filters journal", async () => {
    const authority = await AuthorityVaultAndChannel.create();
    const userId = asUserId("user-tier1");
    const sessionId = asSessionId("sess-tier1");
    const lease = await authority.issueKeyLease({ userId, sessionId, ttlMs: 30_000 });
    const leaseMgr = await KeyLeaseManager.createVerified(lease, authority.publicKey);
    const store = new EncryptedSessionStore(leaseMgr);
    const webStorage = new WebStoragePersistenceBridge(store);

    const tab1 = asTargetId("T-post-with-safe");
    const tab2 = asTargetId("T-post-no-safe");
    webStorage.setSessionStorageItem(tab1, "https://shop.test", "cart", "2-items");

    const checkpoint = captureTier1Checkpoint({
      sessionId,
      userId,
      reason: "suspend",
      lastAckedInputSeq: 10,
      webStorage,
      store,
      now: 123_456,
      targets: [
        {
          targetId: tab1,
          url: "https://shop.test/checkout/submit",
          lastMethod: "POST",
          lastSafeGetUrl: "https://shop.test/cart",
          history: [
            { id: 1, url: "https://shop.test/cart", title: "Cart", method: "GET" },
            { id: 2, url: "https://shop.test/checkout/submit", title: "Submit", method: "POST" },
          ],
          historyIndex: 1,
          scrollX: 12,
          scrollY: 340,
          viewport: { width: 1440, height: 900 },
          focusedFieldKey: "promo-code",
          sealedOrigin: "https://shop.test",
          formDrafts: [
            { fieldKey: "promo-code", tagName: "INPUT", fieldType: "text", value: "SAVE10" },
            { fieldKey: "card-pin", tagName: "INPUT", fieldType: "password", value: "9999" },
          ],
        },
        {
          targetId: tab2,
          url: "https://transfer.test/wire",
          lastMethod: "POST",
          lastSafeGetUrl: null,
          history: [{ id: 1, url: "https://transfer.test/wire", title: "Wire", method: "POST" }],
          historyIndex: 0,
          scrollX: 0,
          scrollY: 0,
          viewport: { width: 800, height: 600 },
          focusedFieldKey: null,
          sealedOrigin: null,
          formDrafts: [],
        },
      ],
    });

    expect(checkpoint.targets[0]?.focusedFieldKey).toBeNull();
    expect(checkpoint.targets[0]?.formDrafts).toEqual([
      { fieldKey: "promo-code", tagName: "INPUT", fieldType: "text", value: "SAVE10" },
    ]);
    expect(loadLatestTier1Checkpoint(store)?.sessionId).toBe(sessionId);

    const navCalls: Array<{ targetId: TargetId; url: string; pendingUnsafe: string | null }> = [];
    const generationByTarget = new Map<TargetId, number>([
      [tab1, 3],
      [tab2, 1],
    ]);
    const restoredEvents: Tier1RestoreResult[] = [];
    const replayedSeqs: number[] = [];

    const restored = await restoreTier1Checkpoint({
      checkpoint,
      webStorage,
      resolveTargetAdapter: (snap: Tier1TargetSnapshot): RestorableTargetAdapter => ({
        targetId: snap.targetId,
        invalidateHandlesForRestore(): number {
          const next = (generationByTarget.get(snap.targetId) ?? 0) + 1;
          generationByTarget.set(snap.targetId, next);
          return next;
        },
        async navigateGetOnly(url: string, pendingUnsafeNavigationUrl: string | null) {
          navCalls.push({
            targetId: snap.targetId,
            url,
            pendingUnsafe: pendingUnsafeNavigationUrl,
          });
        },
        async restoreVisualState() {},
      }),
      inputJournal: [
        { seq: 8, targetId: tab1, kind: "key", payload: { key: "a" } },
        { seq: 10, targetId: tab1, kind: "key", payload: { key: "b" } },
        { seq: 12, targetId: tab1, kind: "key", payload: { key: "d" } },
        { seq: 11, targetId: tab1, kind: "key", payload: { key: "c" } },
      ],
      onReplayInput: (entry) => {
        replayedSeqs.push(entry.seq);
      },
      emitSessionRestored: (result) => {
        restoredEvents.push(result);
      },
    });

    expect(navCalls).toEqual([
      {
        targetId: tab1,
        url: "https://shop.test/cart",
        pendingUnsafe: "https://shop.test/checkout/submit",
      },
      {
        targetId: tab2,
        url: "about:blank",
        pendingUnsafe: "https://transfer.test/wire",
      },
    ]);
    expect(generationByTarget.get(tab1)).toBe(4);
    expect(generationByTarget.get(tab2)).toBe(2);
    expect(replayedSeqs).toEqual([11, 12]);
    expect(restored.replayedInputSeqs).toEqual([11, 12]);
    expect(restoredEvents).toHaveLength(1);
    expect(webStorage.getSessionStorage(tab1, "https://shop.test")).toEqual({
      cart: "2-items",
    });
  });
});

describe("SessionManager lifecycle, epoch fencing, roaming, and CDP socket integration", () => {
  it("enforces monotonic epochs, demotes stale connections, supports Tier 0/1 resume and roam", async () => {
    const clock = 1_000;
    const authority = await AuthorityVaultAndChannel.create({ now: () => clock });
    const auditLog = new SignedAuditLog(authority, { now: () => clock });
    const manager = new SessionManager({ now: () => clock });
    const userId = asUserId("user-mgr");
    const sessionId = asSessionId("sess-mgr");

    manager.create({ userId, sessionId, authority, auditLog });
    const conn1 = asConnectionId("conn-1");
    const conn2 = asConnectionId("conn-2");
    const conn1Events: CdpEvent[] = [];
    const conn2Events: CdpEvent[] = [];

    const a1 = manager.attach({
      sessionId,
      userId,
      connectionId: conn1,
      emit: (ev) => conn1Events.push(ev),
    });
    expect(a1.epoch).toBe(1);
    expect(a1.role).toBe("owner");
    expect(() => manager.validateEpoch(sessionId, conn1)).not.toThrow();

    // Register real TargetState and append input journal entries for Tier 1 capture.
    const target = makeRealTargetState("https://portal.test/home");
    const tId = asTargetId(target.targetId);
    manager.registerTarget(sessionId, target);
    manager.recordAckedInput(sessionId, 5);
    manager.appendUnackedInput(sessionId, { seq: 5, targetId: tId, kind: "click", payload: {} });
    manager.appendUnackedInput(sessionId, { seq: 6, targetId: tId, kind: "click", payload: {} });

    // Stale requestedEpoch below current epoch must reject and register as viewer.
    expect(() =>
      manager.attach({
        sessionId,
        userId,
        connectionId: asConnectionId("conn-stale-join"),
        requestedEpoch: 0,
      }),
    ).toThrow(StaleEpochError);

    // Newer connection takes ownership -> epoch 2, conn1 is demoted to viewer.
    const a2 = manager.attach({
      sessionId,
      userId,
      connectionId: conn2,
      emit: (ev) => conn2Events.push(ev),
    });
    expect(a2.epoch).toBe(2);
    expect(() => manager.validateEpoch(sessionId, conn2)).not.toThrow();
    expect(() => manager.validateEpoch(sessionId, conn1)).toThrow(StaleEpochError);
    expect(manager.requireSession(sessionId).connections.get(conn1)?.role).toBe("viewer");

    // Detach conn2 keeps session warm for Tier 0 reconnect.
    manager.detach(sessionId, conn2);
    const tier0 = await manager.resume({
      sessionId,
      userId,
      connectionId: asConnectionId("conn-warm"),
    });
    expect(tier0.tier).toBe(0);
    expect(tier0.restoreResult).toBeNull();
    expect(manager.requireSession(sessionId).runtime.targets.has(tId)).toBe(true);

    // Suspend -> Tier 1 logical restore on resume.
    await manager.suspend(sessionId, "suspend");
    const navigatedUrls: string[] = [];
    const runtime = manager.requireSession(sessionId).runtime;
    runtime.resolveTargetAdapter = (snap) => ({
      targetId: snap.targetId,
      invalidateHandlesForRestore: () => 2,
      async navigateGetOnly(url) {
        navigatedUrls.push(url);
      },
      async restoreVisualState() {},
    });
    const replayed: number[] = [];
    runtime.onReplayInput = (entry) => {
      replayed.push(entry.seq);
    };

    const conn3 = asConnectionId("conn-resumed");
    const conn3Events: CdpEvent[] = [];
    const tier1 = await manager.resume({
      sessionId,
      userId,
      connectionId: conn3,
      emit: (ev) => conn3Events.push(ev),
    });
    expect(tier1.tier).toBe(1);
    expect(navigatedUrls).toEqual(["https://portal.test/home"]);
    expect(replayed).toEqual([6]);
    expect(conn3Events.some((e) => e.method === "Parawing.sessionRestored")).toBe(true);

    // Roam to conn4 with forced Tier 1 restore emits sessionRoamed + sessionRestored.
    const conn4 = asConnectionId("conn-edge-iad");
    const conn4Events: CdpEvent[] = [];
    const roamed = await manager.roam({
      sessionId,
      userId,
      newConnectionId: conn4,
      forceTier1Restore: true,
      emit: (ev) => conn4Events.push(ev),
    });
    expect(roamed.attachment.epoch).toBe(5);
    expect(conn4Events.some((e) => e.method === "Parawing.sessionRoamed")).toBe(true);
    expect(conn4Events.some((e) => e.method === "Parawing.sessionRestored")).toBe(true);

    const destroyed = await manager.destroy(sessionId);
    expect(destroyed).toBe(true);
    expect(() => manager.requireSession(sessionId)).toThrow(SessionDestroyedError);
    expect(await verifyAuditChain(auditLog.getEntries(), authority.publicKey)).toMatchObject({
      valid: true,
    });
  });

  it("wires socket detach vs destroy into handleCdpSession and rejects stale epochs on dispatch", async () => {
    const authority = await AuthorityVaultAndChannel.create();
    const userId = asUserId("user-ws");
    const sessionId = asSessionId("sess-ws");
    const sessionManager = new SessionManager();
    const lease = await authority.issueKeyLease({ userId, sessionId, ttlMs: 60_000 });
    const keyLease = await KeyLeaseManager.createVerified(lease, authority.publicKey);
    const store = new EncryptedSessionStore(keyLease);

    sessionManager.create({ userId, sessionId, authority, keyLease, store });

    const host = createMemoryHostCapabilities();
    const isolateLoader: HostIsolateLoader = {
      load: () => {
        throw new Error("no page isolate expected in Browser.getVersion / Target.createTarget");
      },
    };

    const pageTargetCount = (): number =>
      [...sessionManager.requireSession(sessionId).runtime.targets.values()].filter(
        (t) => t.type === "page",
      ).length;

    const ws1 = createHarnessTransport();
    const cdp1 = handleCdpSession(ws1.transport, {
      host,
      isolateLoader,
      connectionId: "ws-conn-1",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
    });

    // Browser startup creates an initial blank page target; Target.createTarget adds a second.
    expect(pageTargetCount()).toBe(1);
    ws1.sendInbound({ id: 1, method: "Target.createTarget", params: { url: "about:blank" } });
    await vi.waitFor(() => {
      expect(ws1.outbound.some((m) => m.id === 1 && m.result !== undefined)).toBe(true);
    });
    expect(pageTargetCount()).toBe(2);

    // Connect a second client that bumps the monotonic epoch; ws1 is demoted to read-only viewer.
    const ws2 = createHarnessTransport();
    const cdp2 = handleCdpSession(ws2.transport, {
      host,
      isolateLoader,
      connectionId: "ws-conn-2",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
    });

    ws1.sendInbound({ id: 2, method: "Target.getTargets" });
    ws1.sendInbound({ id: 21, method: "Parawing.getSessionInfo" });
    ws1.sendInbound({ id: 22, method: "Target.createTarget", params: { url: "about:blank" } });
    await vi.waitFor(() => {
      expect(ws1.outbound.some((m) => m.id === 22)).toBe(true);
    });
    const viewerTargetsReply = ws1.outbound.find((m) => m.id === 2);
    expect(viewerTargetsReply?.result).toBeDefined();
    const viewerSessionInfo = ws1.outbound.find((m) => m.id === 21)?.result as
      | { connectionRole?: string }
      | undefined;
    expect(viewerSessionInfo?.connectionRole).toBe("viewer");
    const staleReply = ws1.outbound.find((m) => m.id === 22);
    expect(
      String((staleReply?.error as { message?: string } | undefined)?.message ?? ""),
    ).toContain("Stale epoch");

    ws2.sendInbound({ id: 3, method: "Target.getTargets" });
    await vi.waitFor(() => {
      expect(ws2.outbound.some((m) => m.id === 3 && m.result !== undefined)).toBe(true);
    });

    // Closing ws1 only detaches, preserving live targets and store.
    ws1.simulateClose();
    await cdp1.closed;
    expect(pageTargetCount()).toBe(2);
    expect(keyLease.state).toBe("active");

    // Closing ws2 also only detaches; persistent targets survive until explicit destroySession.
    ws2.simulateClose();
    await cdp2.closed;
    expect(pageTargetCount()).toBe(2);

    const ws3 = createHarnessTransport();
    const cdp3 = handleCdpSession(ws3.transport, {
      host,
      isolateLoader,
      connectionId: "ws-conn-3",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
    });
    ws3.sendInbound({ id: 10, method: "Parawing.getSessionInfo" });
    ws3.sendInbound({ id: 11, method: "Parawing.checkpointSession", params: { reason: "manual" } });
    ws3.sendInbound({ id: 12, method: "Parawing.destroySession", params: { reason: "done" } });
    await vi.waitFor(() => {
      expect(ws3.outbound.some((m) => m.id === 12)).toBe(true);
    });
    expect(sessionManager.get(sessionId)?.status).toBe("destroyed");
    expect(keyLease.state).toBe("revoked");
    ws3.simulateClose();
    await cdp3.closed;
  });

  it("degrades lower-epoch attach to viewer cleanly without orphans or owner disruption", async () => {
    const userId = asUserId("user-viewer");
    const sessionId = asSessionId("sess-viewer");
    const sessionManager = new SessionManager();
    const record = sessionManager.create({ userId, sessionId, initialEpoch: 2 });
    const host = createMemoryHostCapabilities();
    const isolateLoader: HostIsolateLoader = {
      load: () => {
        throw new Error("no isolate expected");
      },
    };

    const wsOwner = createHarnessTransport();
    const cdpOwner = handleCdpSession(wsOwner.transport, {
      host,
      isolateLoader,
      connectionId: "conn-owner-v",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      requestedEpoch: 3,
    });

    const wsLower = createHarnessTransport();
    const cdpLower = handleCdpSession(wsLower.transport, {
      host,
      isolateLoader,
      connectionId: "conn-lower-v",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      requestedEpoch: 1,
    });

    await vi.waitFor(() => {
      expect(
        wsLower.outbound.some(
          (m) =>
            m.method === "Parawing.sessionAttached" &&
            (m.params as { role?: string; stale?: boolean } | undefined)?.role === "viewer",
        ),
      ).toBe(true);
    });
    const attachedEv = wsLower.outbound.find((m) => m.method === "Parawing.sessionAttached");
    expect(attachedEv?.params).toMatchObject({
      epoch: 3,
      requestedEpoch: 1,
      role: "viewer",
      stale: true,
    });

    // Viewer can run read-only methods while mutating/checkpoint commands reject with Stale epoch.
    wsLower.sendInbound({ id: 1, method: "Target.getTargets" });
    wsLower.sendInbound({ id: 2, method: "Parawing.getSessionInfo" });
    wsLower.sendInbound({ id: 3, method: "Target.createTarget", params: { url: "about:blank" } });
    wsLower.sendInbound({ id: 4, method: "Parawing.checkpointSession" });
    await vi.waitFor(() => {
      expect(wsLower.outbound.some((m) => m.id === 4)).toBe(true);
    });
    expect(wsLower.outbound.find((m) => m.id === 1)?.result).toBeDefined();
    expect(
      (wsLower.outbound.find((m) => m.id === 2)?.result as { connectionRole?: string } | undefined)
        ?.connectionRole,
    ).toBe("viewer");
    expect(
      String(
        (wsLower.outbound.find((m) => m.id === 3)?.error as { message?: string } | undefined)
          ?.message ?? "",
      ),
    ).toContain("Stale epoch");
    expect(
      String(
        (wsLower.outbound.find((m) => m.id === 4)?.error as { message?: string } | undefined)
          ?.message ?? "",
      ),
    ).toContain("Stale epoch");

    // Closing the lower-epoch viewer leaves zero orphan entry and keeps active owner working.
    wsLower.simulateClose();
    await cdpLower.closed;
    expect(record.connections.has(asConnectionId("conn-lower-v"))).toBe(false);
    expect(record.ownerConnectionId).toBe(asConnectionId("conn-owner-v"));

    wsOwner.sendInbound({ id: 10, method: "Target.createTarget", params: { url: "about:blank" } });
    await vi.waitFor(() => {
      expect(wsOwner.outbound.some((m) => m.id === 10 && m.result !== undefined)).toBe(true);
    });
    wsOwner.simulateClose();
    await cdpOwner.closed;
  });

  it("wires Parawing.suspendSession, SessionManager.resume GET-only restore, input replay, and Parawing.roamSession", async () => {
    const userId = asUserId("user-resume-cdp");
    const sessionId = asSessionId("sess-resume-cdp");
    const sessionManager = new SessionManager();
    const record = sessionManager.create({ userId, sessionId });

    const replayedInputs: Array<Record<string, unknown>> = [];
    const pageStubs = {
      openSession: vi.fn(async () => ({
        call: async (method: string, params: Record<string, unknown>) => {
          if (method === "navigate") {
            return {
              title: "Safe Restored",
              html: "",
              url: "about:blank",
              console: [],
              exceptions: [],
              cookieWrites: [],
              storageWrites: [],
            };
          }
          if (method === "queryDom") return { ok: true, seq: 1, pumped: -1 };
          if (method === "dispatchKeyEvent") {
            const init = params["init"] as Record<string, unknown> | undefined;
            if (init) replayedInputs.push(init);
            return { console: [] };
          }
          if (method === "awaitLoad") return {};
          if (method === "unload") return null;
          return { ok: true };
        },
        close: async () => {},
        makeRenderPort: async () => ({}) as never,
      })),
      killIsolate: vi.fn(async () => {}),
    };
    const host = createMemoryHostCapabilities();
    const isolateLoader: HostIsolateLoader = {
      load: (spec) => ({
        kind: spec.kind,
        entrypoint: pageStubs as never,
        dispose: async () => {},
        terminate: async () => {},
        [Symbol.dispose]: () => {},
      }),
    };

    const ws1 = createHarnessTransport();
    const cdp1 = handleCdpSession(ws1.transport, {
      host,
      isolateLoader,
      connectionId: "conn-sus-1",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
    });

    const target = [...record.runtime.targets.values()].find((t) => t.type === "page")!;
    const preGeneration = target.navigateGeneration;
    target.lastSafeGetUrl = "about:blank";
    target.url = "https://checkout.test/submit";
    target.lastNavigationMethod = "POST";
    target.navigationHistory = [
      {
        id: 1,
        url: "about:blank",
        userTypedURL: "about:blank",
        title: "Safe",
        transitionType: "typed",
        method: "GET",
      },
      {
        id: 2,
        url: "https://checkout.test/submit",
        userTypedURL: "https://checkout.test/submit",
        title: "Submit",
        transitionType: "form_submit",
        method: "POST",
      },
    ];
    target.navigationHistoryIndex = 1;
    target.lastScrollX = 12;
    target.lastScrollY = 140;

    // Suspend captures Tier 1 checkpoint and pauses runtime.
    ws1.sendInbound({ id: 1, method: "Parawing.suspendSession", params: { reason: "suspend" } });
    await vi.waitFor(() => {
      expect(ws1.outbound.some((m) => m.id === 1 && m.result !== undefined)).toBe(true);
    });
    expect(record.status).toBe("suspended");

    // Append an unacked input after suspend/checkpoint to verify replay on resume.
    record.runtime.inputJournal.push({
      seq: 99,
      targetId: asTargetId(target.targetId),
      kind: "Input.insertText",
      payload: { text: "after-suspend" },
    });
    ws1.simulateClose();
    await cdp1.closed;

    // Reconnecting invokes SessionManager.resume(), GET-only restore, handle bump, and replay.
    const ws2 = createHarnessTransport();
    const cdp2 = handleCdpSession(ws2.transport, {
      host,
      isolateLoader,
      connectionId: "conn-sus-2",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
    });

    await vi.waitFor(() => {
      expect(ws2.outbound.some((m) => m.method === "Parawing.sessionRestored")).toBe(true);
      expect(ws2.outbound.some((m) => m.method === "Parawing.sessionResumed")).toBe(true);
    });
    expect(target.navigateGeneration).toBeGreaterThan(preGeneration);
    expect(target.pendingUnsafeNavigationUrl).toBe("https://checkout.test/submit");
    expect(replayedInputs.some((r) => r["text"] === "after-suspend")).toBe(true);

    // Parawing.roamSession transitions via SessionManager.roam and emits Parawing.sessionRoamed.
    ws2.sendInbound({
      id: 2,
      method: "Parawing.roamSession",
      params: { newConnectionId: "conn-roamed-edge", forceTier1Restore: false },
    });
    await vi.waitFor(() => {
      expect(ws2.outbound.some((m) => m.id === 2 && m.result !== undefined)).toBe(true);
    });
    const roamRes = ws2.outbound.find((m) => m.id === 2)?.result as { epoch?: number } | undefined;
    expect(roamRes?.epoch).toBe(3);

    ws2.simulateClose();
    await cdp2.closed;
  });

  it("gates live CDP key leases and Parawing.roamSession when A5 attestation authority is active", async () => {
    const signer = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    if (!("privateKey" in signer) || !("publicKey" in signer)) {
      throw new Error("Expected Ed25519 keypair");
    }
    const signerSpki = await crypto.subtle.exportKey("spki", signer.publicKey);
    if (!(signerSpki instanceof ArrayBuffer)) throw new Error("Expected ArrayBuffer SPKI");
    const signerSpkiB64 = btoa(String.fromCharCode(...new Uint8Array(signerSpki)));
    const expectedHash = "9".repeat(64);
    const attAuthority = await CapsuleAttestationAuthority.create({
      expectedCapsuleHash: expectedHash,
      expectedRustTarget: "aarch64-unknown-linux-musl",
      expectedBaselineId: "aarch64-neon-fp-armv8",
      trustedSignerSpkis: [signerSpkiB64],
    });
    const clock = 5_000;
    const authority = await AuthorityVaultAndChannel.create({
      now: () => clock,
      attestationAuthority: attAuthority,
    });

    const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ]);
    if (!("privateKey" in eph) || !("publicKey" in eph)) {
      throw new Error("Expected ECDH P-256 keypair");
    }
    const ephSpkiBuf = await crypto.subtle.exportKey("spki", eph.publicKey);
    if (!(ephSpkiBuf instanceof ArrayBuffer)) throw new Error("Expected ArrayBuffer ECDH SPKI");
    const ephSpki = btoa(String.fromCharCode(...new Uint8Array(ephSpkiBuf)));
    const makeAtt = async (nonce: string) =>
      signCapsuleAttestation({
        claims: {
          capsuleHash: expectedHash,
          rustTarget: "aarch64-unknown-linux-musl",
          baselineId: "aarch64-neon-fp-armv8",
          pageSize: CAPSULE_PINNED_PAGE_SIZE,
          ephemeralP256PubkeySpkiB64: ephSpki,
          nonce,
          issuedAtMs: 4_000,
          expiresAtMs: 60_000,
        },
        ed25519PrivateKey: signer.privateKey,
        ed25519PublicKey: signer.publicKey,
      });

    const userId = asUserId("user-a5-cdp");
    const sessionId = asSessionId("sess-a5-cdp");
    const initAtt = await makeAtt("nonce-init");
    const initLease = await authority.issueKeyLease({
      userId,
      sessionId,
      ttlMs: 120_000,
      attestation: initAtt,
    });
    const keyLease = await KeyLeaseManager.createVerified(initLease, authority.publicKey, {
      now: () => clock,
    });
    const store = new EncryptedSessionStore(keyLease);
    const sessionManager = new SessionManager({ now: () => clock });
    sessionManager.create({ userId, sessionId, authority, keyLease, store });

    const ws = createHarnessTransport();
    const cdp = handleCdpSession(ws.transport, {
      host: createMemoryHostCapabilities(),
      isolateLoader: {
        load: () => {
          throw new Error("unused");
        },
      },
      connectionId: "conn-a5-1",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
    });

    const tamperedAtt = await makeAtt("nonce-bad-1");
    ws.sendInbound({
      id: 1,
      method: "Parawing.issueAttestedKeyLease",
      params: {
        attestation: {
          ...tamperedAtt,
          claims: { ...tamperedAtt.claims, nonce: "tampered-nonce" },
        },
      },
    });
    ws.sendInbound({ id: 2, method: "Parawing.roamSession", params: { newConnectionId: "c-2" } });

    const goodLeaseAtt = await makeAtt("nonce-cdp-lease");
    ws.sendInbound({
      id: 3,
      method: "Parawing.issueAttestedKeyLease",
      params: { attestation: goodLeaseAtt, ttlMs: 30_000, nowMs: clock },
    });

    const goodDbscAtt = await makeAtt("nonce-cdp-dbsc");
    ws.sendInbound({
      id: 5,
      method: "Parawing.releaseDbscCredential",
      params: {
        attestation: goodDbscAtt,
        dbscSessionId: "dbsc-cdp-1",
        origin: "https://a5.example",
        challenge: "chal-cdp-1",
        nowMs: clock,
      },
    });

    await vi.waitFor(() => {
      expect([1, 2, 3, 5].every((id) => ws.outbound.some((m) => m.id === id))).toBe(true);
    });

    const goodRoamAtt = await makeAtt("nonce-cdp-roam");
    ws.sendInbound({
      id: 4,
      method: "Parawing.roamSession",
      params: { newConnectionId: "conn-a5-2", attestation: goodRoamAtt, nowMs: clock },
    });
    await vi.waitFor(() => {
      expect(ws.outbound.some((m) => m.id === 4)).toBe(true);
    });
    const m4 = ws.outbound.find((m) => m.id === 4);
    expect(m4?.error).toBeUndefined();
    const r1 = ws.outbound.find((m) => m.id === 1)?.result as { error?: string } | undefined;
    expect(r1?.error).toBeDefined();
    const r2 = ws.outbound.find((m) => m.id === 2)?.result as { error?: string } | undefined;
    expect(r2?.error).toContain("A5 capsule attestation is required");

    const r3 = ws.outbound.find((m) => m.id === 3)?.result as
      | { wrappedRelease?: WrappedKeyLeaseReleaseWire; error?: string }
      | undefined;
    expect(r3?.error).toBeUndefined();
    const unwrapped = await unwrapLeasedAesKey(
      eph.privateKey,
      wrappedKeyLeaseFromWire(r3!.wrappedRelease!),
    );
    expect(unwrapped.byteLength).toBe(32);

    const r4 = ws.outbound.find((m) => m.id === 4)?.result as
      | { epoch?: number; wrappedRelease?: WrappedKeyLeaseReleaseWire; error?: string }
      | undefined;
    expect(r4?.error).toBeUndefined();
    expect(r4?.epoch).toBe(2);
    expect(r4?.wrappedRelease?.claimsSha256Hex).toBe(goodRoamAtt.claimsSha256Hex);

    const r5 = ws.outbound.find((m) => m.id === 5)?.result as
      | { credential?: DbscSessionCredential; error?: string }
      | undefined;
    expect(r5?.error).toBeUndefined();
    expect(await verifyDbscJwtProof(r5!.credential!)).toBe(true);

    ws.simulateClose();
    await cdp.closed;
  });
});
