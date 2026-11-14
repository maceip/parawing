// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { HandlerRegionInfo, JournalInputCapture } from "@parawing/jsrpc-types/page-script";
import { handleParawing } from "../src/cdp/parawing.ts";
import type { DispatchCtx } from "../src/cdp/dispatch.ts";
import type { BrowserState, TargetState } from "../src/cdp/types.ts";
import type { PageScriptStub } from "../src/eval/page-script.ts";
import { ParawingAnalytics, SafePerformance } from "../src/observability.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import type { HostIsolateLoader } from "../src/isolate-loader.ts";
import {
  acceptRbiV2WebSocket,
  acknowledgeClientInputSeq,
  clearJournalOnNavigation,
  clearJournalOnSubmit,
  getInputJournalState,
  recordJournalKeyEvent,
  stopRbiV2Streams,
} from "../src/rbi-v2-server.ts";

interface StubState {
  scrollX: number;
  scrollY: number;
  lastFrameAckInputSeq: number;
  restoredCalls: Array<{ nodeId: number; value: string }>;
  fieldValue: string;
}

function makeFixture(): {
  ctx: DispatchCtx;
  browser: BrowserState;
  target: TargetState;
  stubState: StubState;
} {
  const stubState: StubState = {
    scrollX: 0,
    scrollY: 0,
    lastFrameAckInputSeq: 0,
    restoredCalls: [],
    fieldValue: "draft",
  };
  const handlerRegions: HandlerRegionInfo[] = [
    {
      targetNodeId: 12,
      scrollNodeId: 1,
      x: 10,
      y: 20,
      width: 120,
      height: 80,
      eventMask: 1,
      nonPassive: true,
      coversScrollNode: false,
    },
  ];
  const fakeKsc2 = new Uint8Array([0x4b, 0x53, 0x43, 0x32, 1, 0, 0, 0]);
  const stub = {
    async queryDom(method: string, args: Record<string, unknown>) {
      if (method === "setViewport") return { ok: true };
      if (method === "recordSceneV2") {
        stubState.lastFrameAckInputSeq = Number(args.ackedInputSeq ?? 0);
        return {
          frame: fakeKsc2,
          seq: 1,
          scrollX: stubState.scrollX,
          scrollY: stubState.scrollY,
          origin: "https://app.example",
          handlerRegions,
          error: undefined,
        };
      }
      if (method === "applyScrollDeltaV2") {
        stubState.scrollX = Number(args.x ?? 0);
        stubState.scrollY = Number(args.y ?? 0);
        return { ok: true };
      }
      if (method === "restoreEditableField") {
        const value = String(args.value ?? "");
        const nodeId = Number(args.nodeId ?? 0);
        stubState.fieldValue = value;
        stubState.restoredCalls.push({ nodeId, value });
        return { restored: true };
      }
      return {};
    },
    async getHandlerRegions(): Promise<HandlerRegionInfo[]> {
      return handlerRegions;
    },
  } as PageScriptStub;

  const target = {
    targetId: "t1",
    type: "page",
    url: "https://app.example/form",
    sessions: new Set<string>(),
    frames: new Map(),
    navigateGeneration: 1,
    pageScript: stub,
  } as TargetState;

  const browser = {
    targets: new Map([["t1", target]]),
    wsClosing: false,
  } as BrowserState;

  const isolateLoader: HostIsolateLoader = {
    load() {
      throw new Error("isolateLoader unused in unit fixture");
    },
  };
  const analytics = new ParawingAnalytics(
    {
      sessionId: "s1",
      entrypoint: "puppeteer",
      connectionMode: "browser",
      environment: "test",
      buildVersion: "1",
      colo: "dev",
    },
    new SafePerformance(),
  );
  const ctx: DispatchCtx = {
    browser,
    emit: () => {},
    host: createMemoryHostCapabilities(),
    isolateLoader,
    connectionId: "s1",
    analytics,
  };

  return { ctx, browser, target, stubState };
}

function makeCapture(
  overrides: Partial<JournalInputCapture["field"]> & { value: string; submitTriggered?: boolean },
): JournalInputCapture {
  return {
    field: {
      origin: "https://app.example",
      documentUrl: "https://app.example/form",
      formId: "profile-form",
      fieldName: "displayName",
      fieldId: "name-input",
      tagName: "INPUT",
      inputType: "text",
      autocomplete: "name",
      nodeId: 42,
      ...overrides,
    },
    value: overrides.value,
    selectionStart: overrides.value.length,
    selectionEnd: overrides.value.length,
    submitTriggered: overrides.submitTriggered === true,
  };
}

describe("rbi-v2-server production wiring and input journal lifecycle", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects bare /rbi/ws upgrades without an active stream token", () => {
    const resp = acceptRbiV2WebSocket(new Request("https://ks.invalid/rbi/ws"));
    expect(resp.status).toBe(404);
    const badTok = acceptRbiV2WebSocket(new Request("https://ks.invalid/rbi/ws?token=invalid"));
    expect(badTok.status).toBe(404);
  });

  it("routes Parawing v2 CDP methods and tracks encrypted journal with sensitive exclusion", async () => {
    const { ctx, browser, target, stubState } = makeFixture();

    const regionsRes = (await handleParawing(ctx, {
      id: 1,
      method: "Parawing.getHandlerRegions",
      params: {},
    })) as { regions: HandlerRegionInfo[] };
    expect(regionsRes.regions).toHaveLength(1);
    expect(regionsRes.regions[0]!.nonPassive).toBe(true);

    const recRes = (await handleParawing(ctx, {
      id: 2,
      method: "Parawing.recordSceneV2",
      params: {},
    })) as { frameB64: string; handlerRegions: HandlerRegionInfo[] };
    expect(recRes.frameB64).toBe("S1NDMgEAAAA=");
    expect(recRes.handlerRegions).toHaveLength(1);

    const started = (await handleParawing(ctx, {
      id: 3,
      method: "Parawing.startSceneStreamV2",
      params: { width: 800, height: 600, fps: 30 },
    })) as { wsPath: string; token: string };
    expect(started.wsPath.startsWith("/rbi/ws?token=")).toBe(true);
    expect(started.token.length).toBeGreaterThan(8);

    const safeOutcome = await recordJournalKeyEvent(
      browser,
      target,
      makeCapture({ value: "Alice" }),
    );
    expect(safeOutcome.recorded).toBe(true);

    const pwdOutcome = await recordJournalKeyEvent(
      browser,
      target,
      makeCapture({
        fieldName: "password",
        inputType: "password",
        autocomplete: "current-password",
        nodeId: 43,
        value: "hunter2",
      }),
    );
    expect(pwdOutcome.recorded).toBe(false);
    expect(pwdOutcome.reason).toBe("password-field");

    stubState.fieldValue = "";
    const stateBeforeNav = (await handleParawing(ctx, {
      id: 4,
      method: "Parawing.getInputJournalState",
      params: { includeEncryptedSnapshot: true, replay: true },
    })) as {
      size: number;
      encryptedCount: number;
      replayedCount: number;
      lastRejectionReason?: string;
    };
    expect(stateBeforeNav.size).toBe(1);
    expect(stateBeforeNav.encryptedCount).toBe(1);
    expect(stateBeforeNav.replayedCount).toBe(1);
    expect(stateBeforeNav.lastRejectionReason).toBe("password-field");
    expect(stubState.fieldValue).toBe("Alice");
    expect(stubState.restoredCalls).toEqual([{ nodeId: 42, value: "Alice" }]);

    await clearJournalOnSubmit(browser, target, "profile-form");
    const afterSubmit = await getInputJournalState(browser, target);
    expect(afterSubmit.size).toBe(0);

    await recordJournalKeyEvent(browser, target, makeCapture({ value: "Bob" }), 7);
    const jAfterClientSeq = await getInputJournalState(browser, target);
    expect(jAfterClientSeq.size).toBe(1);
    expect(jAfterClientSeq.nextInputSeq).toBe(7);

    await acknowledgeClientInputSeq(browser, target, 11);
    expect((await getInputJournalState(browser, target)).nextInputSeq).toBe(11);
    await handleParawing(ctx, { id: 5, method: "Parawing.recordSceneV2", params: {} });
    expect(stubState.lastFrameAckInputSeq).toBe(11);

    await clearJournalOnNavigation(browser, target);
    expect((await getInputJournalState(browser, target)).size).toBe(0);

    stopRbiV2Streams(browser);
  });
});
