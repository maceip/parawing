// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { JournalInputCapture } from "@parawing/jsrpc-types/page-script";

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
  renderHtmlToImage: () => new Uint8Array([0x89, 0x50, 0x4e, 0x47]),
  createDom: () => ({
    querySelectorAll: () => [],
    free: () => {},
  }),
}));

import {
  handleCdpSession,
  type CdpSessionCloseEvent,
  type CdpSessionTransport,
} from "../src/cdp/connection.ts";
import type { DispatchCtx } from "../src/cdp/dispatch.ts";
import type { BrowserState } from "../src/cdp/types.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import type { HostIsolateLoader } from "../src/isolate-loader.ts";
import { ControllerLeaseManager } from "../src/policy/controller-lease.ts";
import { PolicyEngine } from "../src/policy/policy-engine.ts";
import { recordJournalKeyEvent, stopRbiV2Streams } from "../src/rbi-v2-server.ts";
import { loadLatestTier1Checkpoint } from "../src/session/checkpoint.ts";
import { asConnectionId, asSessionId, asTargetId, asUserId } from "../src/session/identities.ts";
import { SessionManager } from "../src/session/session-manager.ts";

function createTestTransport(): {
  transport: CdpSessionTransport;
  outbound: Array<Record<string, unknown>>;
  sendInbound: (payload: Record<string, unknown>) => void;
  simulateClose: (ev?: CdpSessionCloseEvent) => void;
} {
  const outbound: Array<Record<string, unknown>> = [];
  const messageHandlers: Array<(data: string | ArrayBuffer) => void> = [];
  const closeHandlers: Array<(ev: CdpSessionCloseEvent) => void> = [];

  const transport: CdpSessionTransport = {
    send(data) {
      outbound.push(JSON.parse(data) as Record<string, unknown>);
    },
    close() {},
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
  };
}

function makeFieldCapture(
  overrides: Partial<JournalInputCapture["field"]> & { value: string; submitTriggered?: boolean },
): JournalInputCapture {
  return {
    field: {
      origin: "https://shop.test",
      documentUrl: "https://shop.test/cart",
      formId: "checkout",
      formAction: "https://shop.test/submit-order",
      fieldName: "note",
      fieldId: "draft-note",
      tagName: "INPUT",
      inputType: "text",
      autocomplete: "off",
      domPath: "html>body>form#checkout>input#draft-note",
      nodeId: 101,
      ...overrides,
    },
    value: overrides.value,
    selectionStart: overrides.value.length,
    selectionEnd: overrides.value.length,
    submitTriggered: overrides.submitTriggered === true,
  };
}

function findResult(
  outbound: Array<Record<string, unknown>>,
  id: number,
): Record<string, unknown> | undefined {
  return outbound.find((m) => m.id === id);
}

function createTestOriginOutbound(): { fetch: (req: Request) => Promise<Response> } {
  return {
    fetch: async () =>
      new Response(
        "<!doctype html><html><body><form id='checkout'><input id='draft-note'></form></body></html>",
        {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
        },
      ),
  };
}

describe("Phase 3 + Phase 4 cross-phase integration", () => {
  const browsersToStop: BrowserState[] = [];

  afterEach(() => {
    for (const b of browsersToStop) {
      try {
        stopRbiV2Streams(b);
      } catch {}
    }
    browsersToStop.length = 0;
  });

  it("supports warm Tier 0 reconnect and Tier 1 GET-only restore with ClientInputJournal delta replay", async () => {
    const userId = asUserId("user-p3-p4");
    const sessionId = asSessionId("sess-p3-p4-restore");
    const sessionManager = new SessionManager();
    const record = sessionManager.create({ userId, sessionId });

    const navigatedUrls: string[] = [];
    const restoredEditableCalls: Array<Record<string, unknown>> = [];
    let currentDomNodeId = 101;
    let evalCounter = 0;

    const pageStubs = {
      openSession: vi.fn(async () => ({
        call: async (method: string, params: Record<string, unknown>) => {
          if (method === "navigate") {
            const url = String(params["url"] ?? "about:blank");
            navigatedUrls.push(url);
            return {
              title: "Cart",
              html: "<form id='checkout'><input id='draft-note'></form>",
              url,
              console: [],
              exceptions: [],
              cookieWrites: [],
              storageWrites: [],
            };
          }
          if (method === "queryDom") {
            const qMethod = String(params["method"] ?? "");
            const args = (params["args"] ?? {}) as Record<string, unknown>;
            if (qMethod === "restoreEditableField") {
              const targetMatchesByStableKey =
                args["fieldId"] === "draft-note" &&
                args["domPath"] === "html>body>form#checkout>input#draft-note" &&
                args["origin"] === "https://shop.test";
              if (targetMatchesByStableKey && args["nodeId"] !== currentDomNodeId) {
                restoredEditableCalls.push({ ...args, matchedAfterNodeIdShift: true });
                return { restored: true };
              }
              return { restored: false };
            }
            if (qMethod === "recordSceneV2") {
              return {
                frame: new Uint8Array([0x4b, 0x53, 0x43, 0x32, 1, 0, 0, 0]),
                seq: 1,
                scrollX: 0,
                scrollY: 0,
                origin: "https://shop.test",
                handlerRegions: [],
              };
            }
            return { ok: true, seq: 1, pumped: -1 };
          }
          if (method === "eval") {
            evalCounter++;
            return { value: evalCounter, console: [] };
          }
          if (method === "awaitLoad" || method === "unload") return null;
          return { ok: true };
        },
        close: async () => {},
        makeRenderPort: async () => ({}) as never,
      })),
      killIsolate: vi.fn(async () => {}),
    };

    const host = createMemoryHostCapabilities();
    const externalOutbound = createTestOriginOutbound();
    const isolateLoader: HostIsolateLoader = {
      load: (spec) => ({
        kind: spec.kind,
        entrypoint: pageStubs as never,
        dispose: async () => {},
        terminate: async () => {},
        [Symbol.dispose]: () => {},
      }),
    };

    const ws1 = createTestTransport();
    const ctx1Ref: { current: DispatchCtx | null } = { current: null };
    const cdp1 = handleCdpSession(ws1.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-1",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      onCtx: (ctx) => {
        ctx1Ref.current = ctx;
        browsersToStop.push(ctx.browser);
      },
    });
    const target = [...record.runtime.targets.values()].find((t) => t.type === "page")!;
    const originalTargetId = target.targetId;
    ws1.sendInbound({ id: 1, method: "Page.navigate", params: { url: "https://shop.test/cart" } });
    await vi.waitFor(() => expect(findResult(ws1.outbound, 1)?.result).toBeDefined());
    navigatedUrls.length = 0;

    // Warm Tier 0 disconnect + reconnect preserves live target without Tier 1 reload.
    ws1.simulateClose();
    await cdp1.closed;

    const ws2 = createTestTransport();
    const ctx2Ref: { current: DispatchCtx | null } = { current: null };
    const cdp2 = handleCdpSession(ws2.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-2",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      onCtx: (ctx) => {
        ctx2Ref.current = ctx;
        browsersToStop.push(ctx.browser);
      },
    });
    await vi.waitFor(() => {
      const resumed = ws2.outbound.find((m) => m.method === "Parawing.sessionResumed");
      expect(resumed).toBeDefined();
      expect((resumed?.params as { tier?: number })?.tier).toBe(0);
    });
    expect(navigatedUrls).toEqual([]);
    expect([...record.runtime.targets.values()].some((t) => t.targetId === originalTargetId)).toBe(
      true,
    );

    const browser2 = ctx2Ref.current!.browser;
    target.url = "https://shop.test/cart";
    target.lastSafeGetUrl = "https://shop.test/cart";
    target.lastNavigationMethod = "GET";
    target.navigationHistory = [
      {
        id: 1,
        url: "https://shop.test/cart",
        userTypedURL: "https://shop.test/cart",
        title: "Cart",
        transitionType: "typed",
        method: "GET",
      },
    ];
    target.navigationHistoryIndex = 0;

    // seq=1 is acknowledged before suspend so checkpointSeq === 1.
    const ackedOutcome = await recordJournalKeyEvent(
      browser2,
      target,
      makeFieldCapture({ fieldId: "pre-acked", fieldName: "preAcked", value: "Prior Acked" }),
    );
    expect(ackedOutcome.recorded).toBe(true);
    sessionManager.recordAckedInput(sessionId, 1);
    target.lastAckedInputSeq = 1;

    // Simulate unsafe POST destination after the safe GET cart page.
    target.url = "https://shop.test/submit-order";
    target.lastNavigationMethod = "POST";
    target.navigationHistory.push({
      id: 2,
      url: "https://shop.test/submit-order",
      userTypedURL: "https://shop.test/submit-order",
      title: "Submitting",
      transitionType: "form_submit",
      method: "POST",
    });
    target.navigationHistoryIndex = 1;

    ws2.sendInbound({ id: 2, method: "Parawing.suspendSession", params: { reason: "suspend" } });
    await vi.waitFor(() => expect(findResult(ws2.outbound, 2)?.result).toBeDefined());
    expect(record.status).toBe("suspended");

    // Simulate post-checkpoint delta capture while target url stays on https://shop.test/*.
    target.url = "https://shop.test/cart";
    const postDraftOutcome = await recordJournalKeyEvent(
      browser2,
      target,
      makeFieldCapture({ value: "Leave at back porch", nodeId: 101 }),
    );
    expect(postDraftOutcome.recorded).toBe(true);

    const pwdOutcome = await recordJournalKeyEvent(
      browser2,
      target,
      makeFieldCapture({
        fieldId: "pwd",
        fieldName: "password",
        inputType: "password",
        autocomplete: "current-password",
        domPath: "html>body>form#checkout>input#pwd",
        nodeId: 102,
        value: "secret-pass",
      }),
    );
    expect(pwdOutcome).toEqual({ recorded: false, reason: "password-field" });

    const otpOutcome = await recordJournalKeyEvent(
      browser2,
      target,
      makeFieldCapture({
        fieldId: "otp",
        fieldName: "one_time_code",
        autocomplete: "one-time-code",
        domPath: "html>body>form#checkout>input#otp",
        nodeId: 103,
        value: "123456",
      }),
    );
    expect(otpOutcome).toEqual({ recorded: false, reason: "otp-field" });

    const cardOutcome = await recordJournalKeyEvent(
      browser2,
      target,
      makeFieldCapture({
        fieldId: "card",
        fieldName: "cardnumber",
        autocomplete: "cc-number",
        domPath: "html>body>form#checkout>input#card",
        nodeId: 104,
        value: "4111111111111111",
      }),
    );
    expect(cardOutcome).toEqual({ recorded: false, reason: "payment-card-field" });

    // Inject cross-origin and already-acked records to verify restore-time double-guard.
    const journal = record.runtime.clientJournals.get(asTargetId(originalTargetId))!;
    await journal.recordInput({
      inputSeq: 1,
      field: makeFieldCapture({
        fieldId: "stale-seq",
        fieldName: "stale",
        domPath: "html>body>input#stale",
        value: "stale",
      }).field,
      value: "MustNotReplayOldSeq",
    });
    await journal.recordInput({
      inputSeq: 9,
      field: makeFieldCapture({
        origin: "https://evil.test",
        documentUrl: "https://evil.test/steal",
        fieldId: "evil-field",
        fieldName: "evil",
        domPath: "html>body>input#evil",
        value: "evil",
      }).field,
      value: "CrossOriginMustNotReplay",
    });

    // Reload shifts DOM nodeId from 101 -> 901; StableFieldKey must still match.
    currentDomNodeId = 901;
    navigatedUrls.length = 0;

    ws2.simulateClose();
    await cdp2.closed;

    const ws3 = createTestTransport();
    const cdp3 = handleCdpSession(ws3.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-3",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      onCtx: (ctx) => {
        browsersToStop.push(ctx.browser);
      },
    });
    await vi.waitFor(() => {
      const resumed = ws3.outbound.find((m) => m.method === "Parawing.sessionResumed");
      const restored = ws3.outbound.find((m) => m.method === "Parawing.sessionRestored");
      expect(restored).toBeDefined();
      expect((resumed?.params as { tier?: number })?.tier).toBe(1);
    });

    expect(navigatedUrls).toEqual(["https://shop.test/cart"]);
    expect(target.pendingUnsafeNavigationUrl).toBe("https://shop.test/submit-order");
    expect(restoredEditableCalls).toHaveLength(1);
    expect(restoredEditableCalls[0]).toMatchObject({
      fieldId: "draft-note",
      fieldName: "note",
      domPath: "html>body>form#checkout>input#draft-note",
      value: "Leave at back porch",
      matchedAfterNodeIdShift: true,
    });

    ws3.simulateClose();
    await cdp3.closed;
  });

  it("enforces ControllerLease takeover over ViewerChannel while pausing agent CDP and observation until handback", async () => {
    const userId = asUserId("user-takeover");
    const sessionId = asSessionId("sess-takeover");
    const sessionManager = new SessionManager();
    const record = sessionManager.create({ userId, sessionId });
    const controllerLeases = new ControllerLeaseManager();

    const executedInputs: Array<{ kind: string; payload: Record<string, unknown> }> = [];
    const evalCalls: string[] = [];

    const pageStubs = {
      openSession: vi.fn(async () => ({
        call: async (method: string, params: Record<string, unknown>) => {
          if (method === "navigate") {
            return {
              title: "Takeover",
              html: "<input id='box'>",
              url: String(params["url"] ?? "about:blank"),
              console: [],
              exceptions: [],
              cookieWrites: [],
              storageWrites: [],
            };
          }
          if (method === "eval" || method === "evaluate") {
            evalCalls.push(String(params["expression"] ?? ""));
            return {
              kind: "value",
              type: "string",
              valueJson: '"ok"',
              console: [],
              exceptions: [],
              cookieWrites: [],
              storageWrites: [],
              title: "Takeover",
              url: "https://shop.test/home",
            };
          }
          if (method === "dispatchKeyEvent") {
            executedInputs.push({
              kind: "key",
              payload: (params["init"] as Record<string, unknown>) ?? {},
            });
            return { console: [] };
          }
          if (method === "dispatchMouseEvent") {
            executedInputs.push({
              kind: "mouse",
              payload: (params["init"] as Record<string, unknown>) ?? {},
            });
            return { console: [] };
          }
          if (method === "queryDom") return { ok: true, seq: 1, pumped: -1 };
          if (method === "renderFrame" || method === "renderScene") {
            return { frame: new Uint8Array([1, 2, 3]), width: 800, height: 600 };
          }
          if (method === "awaitLoad" || method === "unload") return null;
          return { ok: true };
        },
        close: async () => {},
        makeRenderPort: async () => ({}) as never,
      })),
      killIsolate: vi.fn(async () => {}),
    };

    const host = createMemoryHostCapabilities();
    const externalOutbound = createTestOriginOutbound();
    const isolateLoader: HostIsolateLoader = {
      load: (spec) => ({
        kind: spec.kind,
        entrypoint: pageStubs as never,
        dispose: async () => {},
        terminate: async () => {},
        [Symbol.dispose]: () => {},
      }),
    };

    const wsAgent = createTestTransport();
    const ctxRef: { current: DispatchCtx | null } = { current: null };
    const cdpAgent = handleCdpSession(wsAgent.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-agent",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      controllerLeases,
      onCtx: (ctx) => {
        ctxRef.current = ctx;
        browsersToStop.push(ctx.browser);
      },
    });
    const target = [...record.runtime.targets.values()].find((t) => t.type === "page")!;
    const targetSessionId = [...target.sessions.values()][0]!;

    wsAgent.sendInbound({
      id: 100,
      method: "Page.navigate",
      params: { url: "https://shop.test/home" },
      sessionId: targetSessionId,
    });
    await vi.waitFor(() => expect(findResult(wsAgent.outbound, 100)?.result).toBeDefined());

    wsAgent.sendInbound({ id: 1, method: "Network.enable", sessionId: targetSessionId });
    wsAgent.sendInbound({ id: 2, method: "Runtime.enable", sessionId: targetSessionId });
    wsAgent.sendInbound({
      id: 3,
      method: "Page.startScreencast",
      params: { format: "png", everyNthFrame: 1 },
      sessionId: targetSessionId,
    });
    wsAgent.sendInbound({
      id: 4,
      method: "Parawing.startSceneStream",
      params: { width: 800, height: 600 },
      sessionId: targetSessionId,
    });
    await vi.waitFor(() => {
      for (const id of [1, 2, 3, 4]) {
        expect(findResult(wsAgent.outbound, id)?.result).toBeDefined();
      }
    });

    const wsViewer = createTestTransport();
    const cdpViewer = handleCdpSession(wsViewer.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-viewer",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      connectionRole: "viewer",
      controllerLeases,
    });
    await vi.waitFor(() => {
      expect(wsViewer.outbound.some((m) => m.method === "Parawing.sessionAttached")).toBe(true);
    });

    // Without an active takeover lease, viewer input mutations are rejected as stale/read-only.
    wsViewer.sendInbound({
      id: 10,
      method: "Input.insertText",
      params: { text: "unauthorized-before-lease" },
      sessionId: targetSessionId,
    });
    await vi.waitFor(() => expect(findResult(wsViewer.outbound, 10)).toBeDefined());
    expect(findResult(wsViewer.outbound, 10)?.error).toBeDefined();

    // Request and approve human takeover lease.
    wsViewer.sendInbound({
      id: 11,
      method: "Parawing.requestControllerLease",
      params: { targetId: target.targetId, requesterId: "human-1", reason: "captcha-step" },
    });
    await vi.waitFor(() => expect(findResult(wsViewer.outbound, 11)?.result).toBeDefined());
    const leaseId = String(
      ((findResult(wsViewer.outbound, 11)?.result as { lease?: { leaseId?: string } })?.lease
        ?.leaseId ?? "") as string,
    );
    expect(leaseId.startsWith("ctrl-")).toBe(true);

    wsAgent.sendInbound({
      id: 5,
      method: "Parawing.approveControllerLease",
      params: { leaseId },
    });
    await vi.waitFor(() => expect(findResult(wsAgent.outbound, 5)?.result).toBeDefined());

    const browser = ctxRef.current!.browser;
    wsAgent.outbound.length = 0;

    // Enqueue network event during takeover; observation must remain suppressed for agent.
    browser.networkEvents.queueRaw({
      method: "Network.requestWillBeSent",
      sessionId: targetSessionId,
      params: {
        requestId: "req-hidden",
        loaderId: target.loaderId,
        documentURL: "https://shop.test/home",
        request: {
          url: "https://shop.test/api/secret",
          method: "GET",
          headers: {},
          initialPriority: "High",
          referrerPolicy: "strict-origin-when-cross-origin",
        },
        timestamp: 1,
        wallTime: 1,
        initiator: { type: "other" },
        redirectHasExtraInfo: false,
      },
    });
    browser.networkEvents.drain();

    // Agent CDP mutations are blocked during takeover.
    wsAgent.sendInbound({
      id: 6,
      method: "Runtime.evaluate",
      params: { expression: "1+1" },
      sessionId: targetSessionId,
    });
    wsAgent.sendInbound({
      id: 7,
      method: "Input.insertText",
      params: { text: "agent-blocked" },
      sessionId: targetSessionId,
    });
    await vi.waitFor(() => {
      expect(findResult(wsAgent.outbound, 6)).toBeDefined();
      expect(findResult(wsAgent.outbound, 7)).toBeDefined();
    });
    expect(
      String((findResult(wsAgent.outbound, 6)?.error as { message?: string })?.message),
    ).toContain("active human controller lease");
    expect(
      String((findResult(wsAgent.outbound, 7)?.error as { message?: string })?.message),
    ).toContain("active human controller lease");
    expect(evalCalls).toHaveLength(0);
    expect(
      wsAgent.outbound.some(
        (m) =>
          m.method === "Network.requestWillBeSent" ||
          m.method === "Runtime.consoleAPICalled" ||
          m.method === "Page.screencastFrame" ||
          m.method === "Parawing.sceneFrame",
      ),
    ).toBe(false);

    // Human viewer dispatches input cleanly over the viewer channel during takeover.
    wsViewer.sendInbound({
      id: 12,
      method: "Input.insertText",
      params: { text: "human-typed" },
      sessionId: targetSessionId,
    });
    wsViewer.sendInbound({
      id: 13,
      method: "Input.dispatchMouseEvent",
      params: { type: "mousePressed", x: 25, y: 35, button: "left", clickCount: 1 },
      sessionId: targetSessionId,
    });
    await vi.waitFor(() => {
      expect(findResult(wsViewer.outbound, 12)?.result).toBeDefined();
      expect(findResult(wsViewer.outbound, 13)?.result).toBeDefined();
    });
    expect(
      executedInputs.some((i) => i.kind === "key" && i.payload["text"] === "human-typed"),
    ).toBe(true);
    expect(executedInputs.some((i) => i.kind === "mouse")).toBe(true);

    // Human releases takeover lease back to agent.
    wsViewer.sendInbound({
      id: 14,
      method: "Parawing.releaseControllerLease",
      params: { leaseId },
    });
    await vi.waitFor(() => expect(findResult(wsViewer.outbound, 14)?.result).toBeDefined());

    // After handback, viewer can no longer inject input and agent regains control.
    wsViewer.sendInbound({
      id: 15,
      method: "Input.insertText",
      params: { text: "blocked-after-handback" },
      sessionId: targetSessionId,
    });
    wsAgent.sendInbound({
      id: 8,
      method: "Runtime.evaluate",
      params: { expression: "2+2" },
      sessionId: targetSessionId,
    });
    await vi.waitFor(() => {
      expect(findResult(wsViewer.outbound, 15)).toBeDefined();
      expect(findResult(wsAgent.outbound, 8)).toBeDefined();
    });
    expect(findResult(wsViewer.outbound, 15)?.error).toBeDefined();
    expect(findResult(wsAgent.outbound, 8)?.result).toBeDefined();
    expect(evalCalls).toEqual(["2+2"]);

    // Subsequent network activity streams to agent again after handback.
    browser.networkEvents.queueRaw({
      method: "Network.requestWillBeSent",
      sessionId: targetSessionId,
      params: {
        requestId: "req-after-handback",
        loaderId: target.loaderId,
        documentURL: "https://shop.test/home",
        request: {
          url: "https://shop.test/api/public",
          method: "GET",
          headers: {},
          initialPriority: "High",
          referrerPolicy: "strict-origin-when-cross-origin",
        },
        timestamp: 2,
        wallTime: 2,
        initiator: { type: "other" },
        redirectHasExtraInfo: false,
      },
    });
    browser.networkEvents.drain();
    expect(wsAgent.outbound.some((m) => m.method === "Network.requestWillBeSent")).toBe(true);

    wsViewer.simulateClose();
    wsAgent.simulateClose();
    await Promise.all([cdpViewer.closed, cdpAgent.closed]);
  });

  it("ignores forged _actorRole='human' on wire CDP without active human takeover", async () => {
    const userId = asUserId("user-forged");
    const sessionId = asSessionId("sess-forged");
    const sessionManager = new SessionManager();
    const controllerLeases = new ControllerLeaseManager();
    const policyEngine = new PolicyEngine({ delegatedAgent: true });
    const record = sessionManager.create({ userId, sessionId, controllerLeases, policyEngine });
    const isolateLoader: HostIsolateLoader = {
      load: (spec) => ({
        kind: spec.kind,
        entrypoint: {
          openSession: vi.fn(async () => ({
            call: async () => ({ ok: true, console: [] }),
            close: async () => {},
            makeRenderPort: async () => ({}) as never,
          })),
          killIsolate: vi.fn(async () => {}),
        } as never,
        dispose: async () => {},
        terminate: async () => {},
        [Symbol.dispose]: () => {},
      }),
    };

    const wsAgent = createTestTransport();
    const cdpAgent = handleCdpSession(wsAgent.transport, {
      host: createMemoryHostCapabilities(),
      isolateLoader,
      externalOutbound: createTestOriginOutbound(),
      connectionId: "conn-forged-agent",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      controllerLeases,
      policyEngine,
      onCtx: (ctx) => browsersToStop.push(ctx.browser),
    });

    const target = [...record.runtime.targets.values()].find((t) => t.type === "page")!;
    target.sealedOrigin = "https://bank.test";
    const targetSessionId = [...target.sessions.values()][0]!;

    // Without an active lease, forged _actorRole='human' is ignored and sealed policy blocks it.
    wsAgent.sendInbound({
      id: 201,
      method: "DOM.getDocument",
      params: {},
      sessionId: targetSessionId,
      _actorRole: "human",
    });
    await vi.waitFor(() => expect(findResult(wsAgent.outbound, 201)).toBeDefined());
    expect(
      String((findResult(wsAgent.outbound, 201)?.error as { message?: string })?.message),
    ).toContain("sealed-target-blocked");

    // Even when a human lease IS active, forged _actorRole on agent WS cannot act as human.
    const lease = controllerLeases.request({
      targetId: asTargetId(target.targetId),
      requesterId: "human-1",
    });
    controllerLeases.approve(lease.leaseId);
    wsAgent.sendInbound({
      id: 202,
      method: "DOM.getDocument",
      params: {},
      sessionId: targetSessionId,
      _actorRole: "human",
    });
    wsAgent.sendInbound({
      id: 203,
      method: "Input.insertText",
      params: { text: "forged" },
      sessionId: targetSessionId,
      _actorRole: "human",
    });
    await vi.waitFor(() => {
      expect(findResult(wsAgent.outbound, 202)).toBeDefined();
      expect(findResult(wsAgent.outbound, 203)).toBeDefined();
    });
    expect(
      String((findResult(wsAgent.outbound, 202)?.error as { message?: string })?.message),
    ).toContain("active human controller lease");
    expect(
      String((findResult(wsAgent.outbound, 203)?.error as { message?: string })?.message),
    ).toContain("active human controller lease");

    wsAgent.simulateClose();
    await cdpAgent.closed;
  });

  it("does not clobber active owner state when async resume fails with StaleEpochError", async () => {
    const userId = asUserId("user-stale-resume");
    const sessionId = asSessionId("sess-stale-resume");
    const sessionManager = new SessionManager();
    const record = sessionManager.create({ userId, sessionId });
    const isolateLoader: HostIsolateLoader = {
      load: (spec) => ({
        kind: spec.kind,
        entrypoint: {
          openSession: vi.fn(async () => ({
            call: async () => ({ ok: true, console: [] }),
            close: async () => {},
            makeRenderPort: async () => ({}) as never,
          })),
          killIsolate: vi.fn(async () => {}),
        } as never,
        dispose: async () => {},
        terminate: async () => {},
        [Symbol.dispose]: () => {},
      }),
    };
    const host = createMemoryHostCapabilities();
    const externalOutbound = createTestOriginOutbound();

    const ws1 = createTestTransport();
    const cdp1 = handleCdpSession(ws1.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-1",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      requestedEpoch: 1,
      onCtx: (ctx) => browsersToStop.push(ctx.browser),
    });
    await sessionManager.suspend(sessionId);
    ws1.simulateClose();
    await cdp1.closed;

    // Delay the stale connection's resume while a newer epoch owner resumes first.
    let releaseStale!: () => void;
    const staleGate = new Promise<void>((resolve) => {
      releaseStale = resolve;
    });
    const origResume = sessionManager.resume.bind(sessionManager);
    let interceptedFirst = false;
    sessionManager.resume = async (params) => {
      if (!interceptedFirst) {
        interceptedFirst = true;
        await staleGate;
      }
      return origResume(params);
    };

    const wsStale = createTestTransport();
    const cdpStale = handleCdpSession(wsStale.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-stale",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      requestedEpoch: 1,
    });

    const wsOwner = createTestTransport();
    const cdpOwner = handleCdpSession(wsOwner.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-real-owner",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      requestedEpoch: 2,
      onCtx: (ctx) => browsersToStop.push(ctx.browser),
    });
    await vi.waitFor(() => {
      expect(record.connections.get(asConnectionId("conn-real-owner"))?.role).toBe("owner");
    });
    const ownerOnDestroy = record.runtime.onDestroyRuntime;

    releaseStale();
    await vi.waitFor(() => {
      expect(
        wsStale.outbound.some(
          (m) =>
            m.method === "Parawing.sessionAttached" &&
            (m.params as { role?: string; stale?: boolean })?.role === "viewer" &&
            (m.params as { role?: string; stale?: boolean })?.stale === true,
        ),
      ).toBe(true);
    });

    // Real owner's emitSink, viewer role separation, and onDestroyRuntime stay intact.
    expect(record.runtime.onDestroyRuntime).toBe(ownerOnDestroy);
    const liveBrowser = record.runtime.persistentBrowser!;
    liveBrowser.emitSink({ method: "Runtime.executionContextsCleared", params: {} });
    expect(wsOwner.outbound.some((m) => m.method === "Runtime.executionContextsCleared")).toBe(
      true,
    );
    expect(wsStale.outbound.some((m) => m.method === "Runtime.executionContextsCleared")).toBe(
      false,
    );

    wsStale.sendInbound({ id: 301, method: "Input.insertText", params: { text: "blocked" } });
    await vi.waitFor(() => expect(findResult(wsStale.outbound, 301)).toBeDefined());
    expect(findResult(wsStale.outbound, 301)?.error).toBeDefined();

    wsStale.simulateClose();
    wsOwner.simulateClose();
    await Promise.all([cdpStale.closed, cdpOwner.closed]);
  });

  it("drops stale ctx.emit from closed owner and creates about:blank for detached empty runtime", async () => {
    const userId = asUserId("user-detached-empty");
    const sessionId = asSessionId("sess-detached-empty");
    const sessionManager = new SessionManager();
    const record = sessionManager.create({ userId, sessionId });
    const isolateLoader: HostIsolateLoader = {
      load: (spec) => ({
        kind: spec.kind,
        entrypoint: {
          openSession: vi.fn(async () => ({
            call: async () => ({ ok: true, console: [] }),
            close: async () => {},
            makeRenderPort: async () => ({}) as never,
          })),
          killIsolate: vi.fn(async () => {}),
        } as never,
        dispose: async () => {},
        terminate: async () => {},
        [Symbol.dispose]: () => {},
      }),
    };
    const host = createMemoryHostCapabilities();
    const externalOutbound = createTestOriginOutbound();

    let ctx1: DispatchCtx | null = null;
    const ws1 = createTestTransport();
    const cdp1 = handleCdpSession(ws1.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-detach-1",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      onCtx: (ctx) => {
        ctx1 = ctx;
        browsersToStop.push(ctx.browser);
      },
    });
    expect(ctx1!.isClosed?.()).toBe(false);

    // Detach with 0 targets and no Tier 1 checkpoint stored in SessionStore.
    record.runtime.targets.clear();
    expect(loadLatestTier1Checkpoint(record.runtime.store)).toBeUndefined();
    ws1.simulateClose();
    await cdp1.closed;
    expect(ctx1!.isClosed?.()).toBe(true);
    expect(record.status).toBe("detached");

    let ctx2: DispatchCtx | null = null;
    const ws2 = createTestTransport();
    const cdp2 = handleCdpSession(ws2.transport, {
      host,
      isolateLoader,
      externalOutbound,
      connectionId: "conn-detach-2",
      connectionMode: "browser",
      sessionManager,
      sessionId,
      userId,
      onCtx: (ctx) => {
        ctx2 = ctx;
        browsersToStop.push(ctx.browser);
      },
    });

    await vi.waitFor(() => {
      const resumed = ws2.outbound.find((m) => m.method === "Parawing.sessionResumed");
      expect(resumed).toBeDefined();
      expect((resumed?.params as { tier?: number })?.tier).toBe(1);
      expect(ws2.outbound.some((m) => m.method === "Parawing.sessionRestored")).toBe(false);
      expect(
        ws2.outbound.some(
          (m) =>
            m.method === "Target.targetCreated" &&
            (m.params as { targetInfo?: { url?: string } })?.targetInfo?.url === "about:blank",
        ),
      ).toBe(true);
    });
    expect(ctx2!.isClosed?.()).toBe(false);

    // Late emission from closed connection #1 (e.g., networkIdle timer) must not hit owner #2.
    ctx1!.emit({
      method: "Page.lifecycleEvent",
      params: { frameId: "f1", loaderId: "l1", name: "networkIdle", timestamp: 1 },
    });
    expect(
      ws2.outbound.some(
        (m) =>
          m.method === "Page.lifecycleEvent" &&
          (m.params as { name?: string })?.name === "networkIdle",
      ),
    ).toBe(false);

    ws2.simulateClose();
    await cdp2.closed;
  });
});
