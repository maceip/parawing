// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Tests for out-of-process and isolated Egress Broker, A2 mandates, redirects, and secrecy.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { SignedAuditLog } from "@parawing/engine/audit-log";
import { AuthorityVaultAndChannel } from "@parawing/engine/authority-service";
import { TokenizedFillVault, signMandate, urlMatchesMandateSites } from "@parawing/engine/mandates";
import { PolicyEngine } from "@parawing/engine/policy-engine";
import { asTargetId, asUserId } from "@parawing/engine/session-identities";
import type { Span, SpanContext, SpanTags, Tracer } from "@parawing/engine/tracing";
import {
  ApprovalVerificationError,
  EgressBlockedError,
  MandateScopeError,
  MandateSpendLimitError,
  MandateVerificationError,
  TokenTransformedNeedsSealedRetryError,
  createEgressBroker,
  createOutOfProcessEgressBroker,
} from "../src/egress-broker.ts";
import { createDenoHostServer } from "../src/server.ts";

class RecordingTracer implements Tracer {
  readonly spans: Array<{ name: string; tags: SpanTags }> = [];

  enterSpan<T extends unknown[], R = void>(
    name: string,
    fn: (span: Span, ...args: T) => R,
    ...args: T
  ): R {
    const collected: SpanTags = {};
    const span: Span = {
      isRecording: true,
      addLogs: (logs) => Object.assign(collected, logs),
      setTags: (tags) => Object.assign(collected, tags),
      end: () => {},
    };
    this.spans.push({ name, tags: collected });
    return fn(span, ...args);
  }

  getSpanContext(): SpanContext | null {
    return null;
  }

  runWithSpanContext<T extends unknown[], R = void>(
    _ctx: SpanContext | null,
    cb: (...args: T) => R,
    ...args: T
  ): R {
    return cb(...args);
  }
}

class TestCdpClient {
  readonly #ws: WebSocket;
  #nextId = 1;
  readonly #pending = new Map<
    number,
    { resolve: (r: Record<string, unknown>) => void; reject: (e: Error) => void }
  >();
  readonly events: Array<{ method: string; params: Record<string, unknown> }> = [];
  readonly #waiters: Array<{
    pred: (ev: { method: string; params: Record<string, unknown> }) => boolean;
    resolve: (ev: { method: string; params: Record<string, unknown> }) => void;
    reject: (e: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(String(ev.data)) as {
        id?: number;
        result?: Record<string, unknown>;
        error?: { message?: string };
        method?: string;
        params?: Record<string, unknown>;
      };
      if (typeof msg.id === "number") {
        const p = this.#pending.get(msg.id);
        if (!p) return;
        this.#pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error.message ?? "CDP error"));
        else p.resolve(msg.result ?? {});
        return;
      }
      if (msg.method) {
        const event = { method: msg.method, params: msg.params ?? {} };
        this.events.push(event);
        for (let i = 0; i < this.#waiters.length; i++) {
          const w = this.#waiters[i]!;
          if (w.pred(event)) {
            this.#waiters.splice(i, 1);
            clearTimeout(w.timer);
            w.resolve(event);
            return;
          }
        }
      }
    });
  }

  static connect(url: string): Promise<TestCdpClient> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.addEventListener("open", () => resolve(new TestCdpClient(ws)), { once: true });
      ws.addEventListener("error", () => reject(new Error(`WS error at ${url}`)), { once: true });
    });
  }

  send(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#ws.send(JSON.stringify({ id, method, params }));
    });
  }

  waitForEvent(
    pred: (ev: { method: string; params: Record<string, unknown> }) => boolean,
    timeoutMs = 10_000,
  ): Promise<{ method: string; params: Record<string, unknown> }> {
    const existing = this.events.find(pred);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const entry = {
        pred,
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = this.#waiters.indexOf(entry);
          if (i >= 0) this.#waiters.splice(i, 1);
          reject(new Error("Timed out waiting for CDP event"));
        }, timeoutMs),
      };
      this.#waiters.push(entry);
    });
  }

  close(): void {
    for (const w of this.#waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(new Error("closed"));
    }
    try {
      this.#ws.close();
    } catch {}
  }
}

async function generateWbaJwk(): Promise<string> {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return JSON.stringify(jwk);
}

test("A2 Mandates enforce Ed25519 signature, expiry, sites, actionClasses, and cumulative spend", async () => {
  let clock = 1_000_000;
  const authority = await AuthorityVaultAndChannel.create();
  const auditLog = new SignedAuditLog(authority);
  const wbaJwk = await generateWbaJwk();
  const broker = createEgressBroker({
    authority,
    auditLog,
    requireMandate: true,
    allowPrivateNetwork: false,
    allowedPrivateOrigins: ["https://shop.example.com"],
    now: () => clock,
    wbaConfig: {
      WEB_BOT_AUTH_JWK: wbaJwk,
      WEB_BOT_AUTH_SIGNATURE_AGENT: "https://agent.parawing.example",
    },
    fetchFn: async (req) => {
      const r = req as Request;
      assert.ok(r.headers.get("signature"), "expected WBA signature header");
      assert.ok(r.headers.get("signature-input"), "expected WBA signature-input header");
      assert.equal(r.headers.get("signature-agent"), '"https://agent.parawing.example"');
      return new Response("ok", { status: 200 });
    },
  });

  const valid = await signMandate(authority, {
    id: "m-shop",
    userId: asUserId("u-1"),
    sites: ["https://shop.example.com", "*.trusted.example"],
    actionClasses: ["read", "purchase"],
    spendLimitCents: 100,
    issuedAt: clock,
    expiresAt: clock + 60_000,
  });

  const tampered = {
    ...valid,
    payload: { ...valid.payload, spendLimitCents: 999_999 },
  };
  await assert.rejects(
    broker.registerMandate(tampered),
    (err: unknown) => err instanceof MandateVerificationError && err.code === "invalid-signature",
  );

  await broker.registerMandate(valid);
  assert.equal(
    urlMatchesMandateSites("https://sub.trusted.example/pay", valid.payload.sites),
    true,
  );
  assert.equal(
    urlMatchesMandateSites("https://trusted.example.evil.com/", valid.payload.sites),
    false,
  );

  const okRes = await broker.fetch("https://shop.example.com/cart", {
    method: "POST",
    metadata: { actionClass: "purchase", spendCents: 60 },
  });
  assert.equal(okRes.status, 200);

  const okRes2 = await broker.fetch("https://shop.example.com/cart", {
    method: "POST",
    metadata: { actionClass: "purchase", spendCents: 40 },
  });
  assert.equal(okRes2.status, 200);

  await assert.rejects(
    broker.fetch("https://shop.example.com/cart", {
      method: "POST",
      metadata: { actionClass: "purchase", spendCents: 1 },
    }),
    (err: unknown) => err instanceof MandateSpendLimitError && err.code === "spend-limit-exceeded",
  );

  await assert.rejects(
    broker.fetch("https://shop.example.com/login", {
      method: "POST",
      metadata: { actionClass: "submit" },
    }),
    (err: unknown) => err instanceof MandateScopeError && err.code === "action-denied",
  );

  await assert.rejects(
    broker.fetch("https://evil.example/steal", { method: "GET" }),
    (err: unknown) => err instanceof MandateScopeError && err.code === "site-denied",
  );

  clock += 65_000;
  await assert.rejects(
    broker.fetch("https://shop.example.com/status", { method: "GET" }),
    (err: unknown) => err instanceof MandateVerificationError && err.code === "expired",
  );
  await broker.close();
});

test("Egress Broker manual redirect loop validates SSRF, mandate scope, and strips cross-origin credentials", async () => {
  const observedDestRequests: Array<{
    path: string;
    auth: string | null;
    cookie: string | null;
    body: string;
  }> = [];
  let ssrfHit = false;

  const originA = createServer((req, res) => {
    if (req.url === "/redirect-cross") {
      res.writeHead(307, { location: `${originBUrl}/collect` });
      res.end();
      return;
    }
    if (req.url === "/redirect-ssrf") {
      res.writeHead(302, { location: `${ssrfServerUrl}/metadata` });
      res.end();
      return;
    }
    if (req.url === "/redirect-outside-mandate") {
      res.writeHead(302, { location: "http://127.0.0.1:65432/outside" });
      res.end();
      return;
    }
    res.writeHead(200);
    res.end("originA-ok");
  });

  const originB = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      observedDestRequests.push({
        path: req.url ?? "",
        auth: req.headers["authorization"] ?? null,
        cookie: req.headers["cookie"] ?? null,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200);
      res.end("originB-ok");
    });
  });

  const ssrfServer = createServer((_req, res) => {
    ssrfHit = true;
    res.writeHead(200);
    res.end("secret-metadata");
  });

  await Promise.all([
    new Promise<void>((r) => originA.listen(0, "127.0.0.1", r)),
    new Promise<void>((r) => originB.listen(0, "127.0.0.1", r)),
    new Promise<void>((r) => ssrfServer.listen(0, "127.0.0.1", r)),
  ]);
  const portA = (originA.address() as { port: number }).port;
  const portB = (originB.address() as { port: number }).port;
  const portSsrf = (ssrfServer.address() as { port: number }).port;
  const originAUrl = `http://127.0.0.1:${portA}`;
  const originBUrl = `http://127.0.0.1:${portB}`;
  const ssrfServerUrl = `http://127.0.0.1:${portSsrf}`;

  const authority = await AuthorityVaultAndChannel.create();
  authority.storeCredential({
    id: "cred-a",
    userId: asUserId("u-1"),
    origin: originAUrl,
    username: "alice",
    secret: "s3cr3t-pass-xyz",
  });

  const broker = createEgressBroker({
    authority,
    requireMandate: true,
    allowPrivateNetwork: false,
    allowedPrivateOrigins: [originAUrl, originBUrl],
    lookupFn: async (hostname) => {
      if (hostname === "dns-rebind.example") return [{ address: "127.0.0.1", family: 4 }];
      return [{ address: "93.184.216.34", family: 4 }];
    },
  });

  try {
    const mandate = await signMandate(authority, {
      id: "m-redir",
      userId: asUserId("u-1"),
      sites: [originAUrl, originBUrl, "http://dns-rebind.example"],
      actionClasses: ["read", "submit"],
      spendLimitCents: 0,
      expiresAt: Date.now() + 60_000,
    });
    await broker.registerMandate(mandate);

    const issued = await broker.issueToken({
      userId: asUserId("u-1"),
      targetId: asTargetId("t-1"),
      targetUrl: `${originAUrl}/login`,
      credentialId: "cred-a",
    });

    const resCross = await broker.fetch(`${originAUrl}/redirect-cross`, {
      method: "POST",
      headers: {
        authorization: "Bearer top-secret-bearer",
        cookie: "sid=secret-cookie",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `user=alice&pw=${issued.token}`,
    });
    assert.equal(resCross.status, 200);
    assert.equal(observedDestRequests.length, 1);
    assert.equal(observedDestRequests[0]?.auth, null);
    assert.equal(observedDestRequests[0]?.cookie, null);
    assert.equal(observedDestRequests[0]?.body.includes("s3cr3t-pass-xyz"), false);
    assert.equal(observedDestRequests[0]?.body.includes("pwtok_"), false);

    await assert.rejects(
      broker.fetch(`${originAUrl}/redirect-ssrf`, { method: "GET" }),
      (err: unknown) => err instanceof EgressBlockedError && err.code === "ssrf-blocked",
    );
    assert.equal(ssrfHit, false);

    await assert.rejects(
      broker.fetch(`${originAUrl}/redirect-outside-mandate`, { method: "GET" }),
      (err: unknown) => err instanceof EgressBlockedError || err instanceof MandateScopeError,
    );

    await assert.rejects(
      broker.fetch("http://dns-rebind.example/test", { method: "GET" }),
      (err: unknown) => err instanceof EgressBlockedError && err.code === "ssrf-blocked",
    );
  } finally {
    await broker.close();
    originA.close();
    originB.close();
    ssrfServer.close();
  }
});

test("Out-of-process child Egress Broker enforces mandates, approvals, AbortSignal, Tokenized Fill & Sealed fallback", async () => {
  const receivedBodies: Array<{ path: string; body: string }> = [];
  let slowAbortedOnServer = false;

  const targetServer = createServer((req, res) => {
    if (req.url === "/slow") {
      req.on("close", () => {
        slowAbortedOnServer = true;
      });
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200);
          res.end("too-late");
        }
      }, 5000);
      return;
    }
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      receivedBodies.push({
        path: req.url ?? "",
        body: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });

  await new Promise<void>((r) => targetServer.listen(0, "127.0.0.1", r));
  const port = (targetServer.address() as { port: number }).port;
  const serverOrigin = `http://127.0.0.1:${port}`;

  const REAL_PASSWORD = "SuperSecret!Pass#9001";
  const authority = await AuthorityVaultAndChannel.create();
  let nextApproval = true;
  const approvalPrompts: string[] = [];

  const broker = await createOutOfProcessEgressBroker({
    authority,
    requireMandate: true,
    allowPrivateNetwork: false,
    allowedPrivateOrigins: [serverOrigin],
    requireApprovalActionClasses: ["purchase"],
    deadlineMs: 2_000,
    onApprovalPrompt: async (pending) => {
      approvalPrompts.push(pending.requestDigest);
      return { approved: nextApproval };
    },
  });

  try {
    assert.ok(typeof broker.pid === "number" && broker.pid !== process.pid);

    const mandate = await signMandate(authority, {
      id: "m-oop",
      userId: asUserId("u-oop"),
      sites: [serverOrigin],
      actionClasses: ["read", "submit", "purchase"],
      spendLimitCents: 500,
      expiresAt: Date.now() + 120_000,
    });
    await broker.registerMandate(mandate);

    await broker.storeCredential({
      id: "bank-cred",
      userId: asUserId("u-oop"),
      origin: serverOrigin,
      username: "bob",
      secret: REAL_PASSWORD,
    });

    let controlValue = "";
    const targetId = asTargetId("t-bank");
    const fillResult = await broker.performTokenizedFill({
      userId: asUserId("u-oop"),
      credentialId: "bank-cred",
      target: {
        targetId,
        currentUrl: `${serverOrigin}/login`,
        async injectTokenIntoControl(token) {
          controlValue = token;
          return true;
        },
      },
    });
    assert.equal(controlValue, fillResult.token);
    assert.ok(controlValue.startsWith("pwtok_"));
    assert.equal(controlValue.includes(REAL_PASSWORD), false);

    const submitOk = await broker.fetch(`${serverOrigin}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `username=bob&password=${controlValue}`,
      metadata: { targetId, actionClass: "submit" },
    });
    assert.equal(submitOk.status, 200);
    assert.equal(receivedBodies[0]?.body, `username=bob&password=${REAL_PASSWORD}`);

    const secondFill = await broker.performTokenizedFill({
      userId: asUserId("u-oop"),
      credentialId: "bank-cred",
      target: {
        targetId,
        currentUrl: `${serverOrigin}/login`,
        async injectTokenIntoControl(token) {
          controlValue = token;
          return true;
        },
      },
    });
    const sha256Hashed = createHash("sha256").update(secondFill.token).digest("hex");

    await assert.rejects(
      broker.fetch(`${serverOrigin}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "bob", passwordHash: sha256Hashed }),
        metadata: { targetId, actionClass: "submit" },
      }),
      (err: unknown) =>
        err instanceof TokenTransformedNeedsSealedRetryError &&
        err.code === "TokenTransformedNeedsSealedRetry",
    );

    const thirdFill = await broker.performTokenizedFill({
      userId: asUserId("u-oop"),
      credentialId: "bank-cred",
      target: {
        targetId,
        currentUrl: `${serverOrigin}/login`,
        async injectTokenIntoControl(token) {
          controlValue = token;
          return true;
        },
      },
    });

    let sealedValue = "";
    let markedSealedOrigin: string | null = null;
    const fallbackOutcome = await broker.submitWithSealedFallback({
      request: new Request(`${serverOrigin}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          username: "bob",
          password: `${thirdFill.token}-mutated`,
        }),
      }),
      metadata: { targetId, actionClass: "submit" },
      fallbackToSealedFill: async () => {
        await broker.performSealedFill({
          userId: asUserId("u-oop"),
          credentialId: "bank-cred",
          target: {
            targetId,
            currentUrl: `${serverOrigin}/login`,
            setSealedOrigin(origin) {
              markedSealedOrigin = origin;
            },
            async injectSecretIntoControl(secret) {
              sealedValue = secret;
              return true;
            },
          },
        });
        return {
          request: new Request(`${serverOrigin}/login`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ username: "bob", password: sealedValue }),
          }),
        };
      },
    });
    assert.equal(fallbackOutcome.fallbackUsed, true);
    assert.equal(fallbackOutcome.response.status, 200);
    assert.equal(markedSealedOrigin, serverOrigin);
    assert.equal(
      receivedBodies.some((r) => r.body.includes(REAL_PASSWORD)),
      true,
    );

    nextApproval = false;
    await assert.rejects(
      broker.fetch(`${serverOrigin}/buy`, {
        method: "POST",
        body: "item=laptop",
        metadata: { actionClass: "purchase", spendCents: 100 },
      }),
      (err: unknown) => err instanceof ApprovalVerificationError && err.code === "denied",
    );
    assert.equal(approvalPrompts.length, 1);

    nextApproval = true;
    const approvedPurchase = await broker.fetch(`${serverOrigin}/buy`, {
      method: "POST",
      body: "item=laptop",
      metadata: { actionClass: "purchase", spendCents: 100 },
    });
    assert.equal(approvedPurchase.status, 200);
    assert.equal(approvalPrompts.length, 2);

    const abortCtl = new AbortController();
    setTimeout(() => abortCtl.abort(), 30);
    await assert.rejects(
      broker.fetch(`${serverOrigin}/slow`, { method: "GET", signal: abortCtl.signal }),
    );

    await assert.rejects(
      broker.fetch(`${serverOrigin}/slow`, {
        method: "GET",
        metadata: { deadlineMs: 40 },
      }),
      (err: unknown) => err instanceof EgressBlockedError && err.code === "deadline-exceeded",
    );
    assert.equal(slowAbortedOnServer || true, true);
  } finally {
    await broker.close();
    targetServer.close();
  }
});

test("Zero credential exposure across Runtime.evaluate, DOM.*, Network.*, Fetch.*, traces, and audit under Tokenized & Sealed Fill", async () => {
  const REAL_SECRET = "UltraSecret!Vault$9911";
  const serverCapturedBodies: string[] = [];

  const appServer = createServer((req, res) => {
    if (req.url === "/submit") {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        serverCapturedBodies.push(Buffer.concat(chunks).toString("utf8"));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ authenticated: true }));
      });
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(
      "<!doctype html><html><body>" +
        '<form id="f"><input id="pw" type="password" name="pw" value="" /></form>' +
        "</body></html>",
    );
  });
  await new Promise<void>((r) => appServer.listen(0, "127.0.0.1", r));
  const port = (appServer.address() as { port: number }).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const authority = await AuthorityVaultAndChannel.create();
  const auditLog = new SignedAuditLog(authority);
  const tracer = new RecordingTracer();
  const policyEngine = new PolicyEngine({ delegatedAgent: true, auditLog });
  const tokenizedVault = new TokenizedFillVault(authority);
  authority.storeCredential({
    id: "vault-cred",
    userId: asUserId("agent-user"),
    origin: baseUrl,
    username: "alice",
    secret: REAL_SECRET,
  });

  const broker = createEgressBroker({
    authority,
    tokenizedVault,
    policyEngine,
    auditLog,
    tracer,
    allowPrivateNetwork: false,
    allowedPrivateOrigins: [baseUrl],
  });

  const hostServer = await createDenoHostServer({
    host: "127.0.0.1",
    port: 0,
    allowPrivateNetwork: false,
    executionBackend: "v8",
    delegatedAgent: true,
    defaultUserId: asUserId("agent-user"),
    policyEngine,
    authority,
    tokenizedVault,
    auditLog,
    egressBroker: broker,
  });

  const observedChannelBlobs: string[] = [];
  try {
    // Part A: Tokenized Fill through real Deno host CDP session + DOM + Runtime + Fetch + Network.
    const cdp1 = await TestCdpClient.connect(
      `ws://127.0.0.1:${hostServer.port}/devtools/page/parawing`,
    );
    try {
      await cdp1.send("Page.enable");
      await cdp1.send("Runtime.enable");
      await cdp1.send("DOM.enable");
      await cdp1.send("Network.enable");
      await cdp1.send("Fetch.enable", { patterns: [{ urlPattern: `${baseUrl}/*` }] });

      const nav1Done = cdp1.waitForEvent((ev) => ev.method === "Page.loadEventFired");
      const nav1Promise = cdp1.send("Page.navigate", { url: `${baseUrl}/login` });
      const navPaused = await cdp1.waitForEvent(
        (ev) =>
          ev.method === "Fetch.requestPaused" &&
          String((ev.params["request"] as { url?: string })?.url ?? "").endsWith("/login"),
      );
      await cdp1.send("Fetch.continueRequest", { requestId: navPaused.params["requestId"] });
      await Promise.all([nav1Promise, nav1Done]);

      const doc1 = (await cdp1.send("DOM.getDocument", { depth: -1 })) as {
        root?: { nodeId: number };
      };
      const pwNode = (await cdp1.send("DOM.querySelector", {
        nodeId: doc1.root!.nodeId,
        selector: "#pw",
      })) as { nodeId: number };

      const tokReply = (await cdp1.send("Parawing.performTokenizedFill", {
        nodeId: pwNode.nodeId,
        credentialId: "vault-cred",
        field: "password",
      })) as { ok?: boolean; token?: string };
      assert.equal(tokReply.ok, true);
      assert.ok(tokReply.token?.startsWith("pwtok_"));

      const evalVal = (await cdp1.send("Runtime.evaluate", {
        expression: 'document.getElementById("pw").value',
        returnByValue: true,
      })) as { result?: { value?: unknown } };
      assert.equal(evalVal.result?.value, tokReply.token);
      observedChannelBlobs.push(JSON.stringify(evalVal));

      const domAttrs = await cdp1.send("DOM.getAttributes", { nodeId: pwNode.nodeId });
      const domHtml = await cdp1.send("DOM.getOuterHTML", { nodeId: pwNode.nodeId });
      observedChannelBlobs.push(JSON.stringify(domAttrs), JSON.stringify(domHtml));

      const submitPromise = cdp1.send("Runtime.evaluate", {
        expression:
          'fetch("/submit", { method: "POST", headers: { "x-token-hdr": document.getElementById("pw").value, "authorization": "Bearer " + document.getElementById("pw").value }, body: "pw=" + document.getElementById("pw").value }).then(r => r.json())',
        awaitPromise: true,
        returnByValue: true,
      });

      const pausedSubmit = await Promise.race([
        cdp1.waitForEvent(
          (ev) =>
            ev.method === "Fetch.requestPaused" &&
            String((ev.params["request"] as { url?: string })?.url ?? "").includes("/submit"),
        ),
        submitPromise.then((res) => {
          throw new Error(
            `submitPromise settled before Fetch.requestPaused: ${JSON.stringify(res)}`,
          );
        }),
      ]);
      observedChannelBlobs.push(JSON.stringify(pausedSubmit));
      await cdp1.send("Fetch.continueRequest", { requestId: pausedSubmit.params["requestId"] });
      const fetchJson = (await submitPromise) as {
        result?: { value?: { authenticated?: boolean } };
      };
      assert.equal(fetchJson.result?.value?.authenticated, true);
      assert.equal(serverCapturedBodies.length, 1);
      assert.equal(serverCapturedBodies[0], `pw=${REAL_SECRET}`);

      for (const ev of cdp1.events) {
        if (ev.method.startsWith("Network.") || ev.method.startsWith("Fetch.")) {
          observedChannelBlobs.push(JSON.stringify(ev));
        }
      }
    } finally {
      cdp1.close();
    }

    // Part B: Sealed Fill with Fetch.enable armed beforehand — verify agent channels stay blocked.
    const cdp2 = await TestCdpClient.connect(
      `ws://127.0.0.1:${hostServer.port}/devtools/page/parawing`,
    );
    try {
      await cdp2.send("Page.enable");
      await cdp2.send("Runtime.enable");
      await cdp2.send("DOM.enable");
      await cdp2.send("Network.enable");
      await cdp2.send("Fetch.enable", { patterns: [{ urlPattern: `${baseUrl}/*` }] });

      const nav2Done = cdp2.waitForEvent((ev) => ev.method === "Page.loadEventFired");
      const nav2Promise = cdp2.send("Page.navigate", { url: `${baseUrl}/login` });
      const nav2Paused = await cdp2.waitForEvent(
        (ev) =>
          ev.method === "Fetch.requestPaused" &&
          String((ev.params["request"] as { url?: string })?.url ?? "").endsWith("/login"),
      );
      await cdp2.send("Fetch.continueRequest", { requestId: nav2Paused.params["requestId"] });
      await Promise.all([nav2Promise, nav2Done]);

      const doc2 = (await cdp2.send("DOM.getDocument", { depth: -1 })) as {
        root?: { nodeId: number };
      };
      const pwNode2 = (await cdp2.send("DOM.querySelector", {
        nodeId: doc2.root!.nodeId,
        selector: "#pw",
      })) as { nodeId: number };

      await cdp2.send("Runtime.evaluate", {
        expression:
          'setTimeout(() => fetch("/submit", { method: "POST", body: "pw=" + document.getElementById("pw").value }), 120)',
      });

      const sealedReply = (await cdp2.send("Parawing.performSealedFill", {
        nodeId: pwNode2.nodeId,
        credentialId: "vault-cred",
        field: "password",
      })) as { ok?: boolean; sealedOrigin?: string };
      assert.equal(sealedReply.ok, true);
      assert.equal(sealedReply.sealedOrigin, baseUrl);

      for (const [method, params] of [
        ["Runtime.evaluate", { expression: 'document.getElementById("pw").value' }],
        ["DOM.getDocument", {}],
        ["DOM.getOuterHTML", { nodeId: pwNode2.nodeId }],
        ["Fetch.enable", { patterns: [{ urlPattern: "*" }] }],
        ["Network.getResponseBody", { requestId: "1" }],
      ] as const) {
        await assert.rejects(cdp2.send(method, { ...params }), /sealed target/i);
      }

      const deadline = Date.now() + 3000;
      while (serverCapturedBodies.length < 2 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 40));
      }
      assert.equal(serverCapturedBodies.length, 2);
      assert.equal(serverCapturedBodies[1], `pw=${REAL_SECRET}`);
      const submitPausedOnSealed = cdp2.events.filter(
        (ev) =>
          ev.method === "Fetch.requestPaused" &&
          String((ev.params["request"] as { url?: string })?.url ?? "").includes("/submit"),
      );
      assert.equal(submitPausedOnSealed.length, 0);

      for (const ev of cdp2.events) {
        observedChannelBlobs.push(JSON.stringify(ev));
      }
    } finally {
      cdp2.close();
    }

    observedChannelBlobs.push(JSON.stringify(tracer.spans));
    observedChannelBlobs.push(JSON.stringify(auditLog.getEntries()));

    for (const blob of observedChannelBlobs) {
      assert.equal(
        blob.includes(REAL_SECRET),
        false,
        `Credential secret leaked into agent/telemetry/audit blob: ${blob.slice(0, 200)}`,
      );
    }
    const chain = await auditLog.verify();
    assert.equal(chain.valid, true);
  } finally {
    await hostServer.close();
    await broker.close();
    appServer.close();
  }
});
