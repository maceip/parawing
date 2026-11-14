// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Real E2E tests driving zero-permission Deno isolates over CDP WebSocket.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import test from "node:test";
import { promisify } from "node:util";
import {
  buildDenoRunArgs,
  createDenoIsolateLoader,
  resolveDenoBinary,
} from "../src/deno-isolate-loader.ts";
import {
  SessionManager,
  asSessionId,
  createMemoryHostCapabilities,
} from "../dist/engine-bundle.mjs";
import { createDenoHostServer } from "../src/server.ts";

const execFileAsync = promisify(execFile);

class CdpClient {
  readonly #ws: WebSocket;
  #nextId = 1;
  readonly #pending = new Map<
    number,
    { resolve: (result: Record<string, unknown>) => void; reject: (err: Error) => void }
  >();
  readonly #events: Array<{ method: string; params: Record<string, unknown> }> = [];
  readonly #eventWaiters: Array<{
    predicate: (ev: { method: string; params: Record<string, unknown> }) => boolean;
    resolve: (ev: { method: string; params: Record<string, unknown> }) => void;
    reject: (err: Error) => void;
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
        const entry = this.#pending.get(msg.id);
        if (!entry) return;
        this.#pending.delete(msg.id);
        if (msg.error) {
          entry.reject(new Error(msg.error.message ?? "CDP error"));
        } else {
          entry.resolve(msg.result ?? {});
        }
        return;
      }
      if (msg.method) {
        const event = { method: msg.method, params: msg.params ?? {} };
        this.#dispatchEvent(event);
      }
    });
    ws.addEventListener("close", () => {
      for (const entry of this.#pending.values()) {
        entry.reject(new Error("CDP WebSocket closed"));
      }
      this.#pending.clear();
    });
  }

  #dispatchEvent(event: { method: string; params: Record<string, unknown> }): void {
    const idx = this.#eventWaiters.findIndex((w) => w.predicate(event));
    if (idx >= 0) {
      const waiter = this.#eventWaiters.splice(idx, 1)[0];
      if (waiter) {
        clearTimeout(waiter.timer);
        waiter.resolve(event);
      }
      return;
    }
    this.#events.push(event);
  }

  static connect(url: string): Promise<CdpClient> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.addEventListener("open", () => resolve(new CdpClient(ws)), { once: true });
      ws.addEventListener(
        "error",
        () => reject(new Error(`Failed to connect CDP WebSocket at ${url}`)),
        { once: true },
      );
    });
  }

  send(
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<Record<string, unknown>> {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      const payload = sessionId ? { id, method, params, sessionId } : { id, method, params };
      this.#ws.send(JSON.stringify(payload));
    });
  }

  recordedEventMethods(): string[] {
    return this.#events.map((ev) => ev.method);
  }

  clearRecordedEvents(): void {
    this.#events.length = 0;
  }

  waitForEvent(
    method: string,
    timeoutMs = 15_000,
    extraPredicate?: (params: Record<string, unknown>) => boolean,
  ): Promise<{ method: string; params: Record<string, unknown> }> {
    const matchFn = (ev: { method: string; params: Record<string, unknown> }): boolean =>
      ev.method === method && (!extraPredicate || extraPredicate(ev.params));
    const queuedIdx = this.#events.findIndex(matchFn);
    if (queuedIdx >= 0) {
      return Promise.resolve(this.#events.splice(queuedIdx, 1)[0]!);
    }
    return new Promise((resolve, reject) => {
      const entry = {
        predicate: matchFn,
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = this.#eventWaiters.indexOf(entry);
          if (i >= 0) this.#eventWaiters.splice(i, 1);
          reject(new Error(`Timed out waiting for CDP event ${method}`));
        }, timeoutMs),
      };
      this.#eventWaiters.push(entry);
    });
  }

  close(): void {
    for (const entry of this.#eventWaiters.splice(0)) {
      clearTimeout(entry.timer);
      entry.reject(new Error("CDP client closed"));
    }
    try {
      this.#ws.close();
    } catch {}
  }
}

test("Deno host serves HTTP/CDP, runs scripts + Worker, and captures real PNG screenshot", async () => {
  const originServer = createServer((req, res) => {
    if (req.url === "/worker.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end("self.onmessage = (ev) => { self.postMessage({ echo: ev.data, sum: 40 + 2 }); };");
      return;
    }
    if (req.url === "/dep.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end('export const depVal = "from-dep";');
      return;
    }
    if (req.url === "/mod.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end(
        'import { depVal } from "/dep.js"; window.__mod = { dep: depVal, evalDeno: typeof Deno };',
      );
      return;
    }
    if (req.url === "/async.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end('window.__async = "async-ok";');
      return;
    }
    if (req.url === "/baked-insert.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end('window.__bakedInsert = "baked-insert-ok";');
      return;
    }
    if (req.url === "/infinite.html") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<!doctype html><html><body><script>while (true) {}</script></body></html>");
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(
      "<!doctype html><html><head><title>DenoHostTest</title>" +
        '<link rel="preload" as="script" href="/baked-insert.js">' +
        "</head>" +
        '<body style="margin:0;background:#123456;">' +
        '<div id="out" style="width:180px;height:60px;background:#abcdef;color:#111111;">before</div>' +
        "<script>" +
        'document.getElementById("out").textContent = "after-dom";' +
        'window.__evalResult = eval("1 + 2");' +
        'window.__fnResult = new Function("return 3 + 4")();' +
        "window.__directDeno = typeof Deno;" +
        'window.__evalDeno = eval("typeof Deno");' +
        'window.__fnDeno = new Function("return typeof Deno")();' +
        'const inserted = document.createElement("script");' +
        'inserted.src = "/baked-insert.js";' +
        "document.body.appendChild(inserted);" +
        'const w = new Worker("/worker.js");' +
        "window.__workerResult = new Promise((resolve) => {" +
        "  w.onmessage = (e) => resolve(e.data);" +
        '  w.postMessage("ping-deno");' +
        "});" +
        "</script>" +
        '<script type="module" src="/mod.js"></script>' +
        '<script async src="/async.js"></script>' +
        "</body></html>",
    );
  });

  await new Promise<void>((resolve) => originServer.listen(0, "127.0.0.1", () => resolve()));
  const originAddr = originServer.address();
  assert.ok(typeof originAddr === "object" && originAddr !== null);
  const originUrl = `http://127.0.0.1:${originAddr.port}`;

  const hostServer = await createDenoHostServer({
    host: "127.0.0.1",
    port: 0,
    allowPrivateNetwork: true,
  });

  try {
    const health = await fetch(`${hostServer.origin}/health`);
    assert.equal(health.status, 200);
    assert.equal(await health.text(), "parawing: OK\n");

    const ver = (await (await fetch(`${hostServer.origin}/json/version`)).json()) as {
      webSocketDebuggerUrl: string;
    };
    assert.equal(ver.webSocketDebuggerUrl, `ws://127.0.0.1:${hostServer.port}/devtools/browser`);

    const cdp = await CdpClient.connect(`ws://127.0.0.1:${hostServer.port}/devtools/page/parawing`);
    try {
      await cdp.send("Page.enable");
      await cdp.send("Runtime.enable");
      await cdp.send("Emulation.setDeviceMetricsOverride", {
        width: 320,
        height: 200,
        deviceScaleFactor: 1,
        mobile: false,
      });

      const loadDone = cdp.waitForEvent("Page.loadEventFired");
      await cdp.send("Page.navigate", { url: `${originUrl}/index.html` });
      await loadDone;

      const domEval = (await cdp.send("Runtime.evaluate", {
        expression: 'document.getElementById("out").textContent',
        returnByValue: true,
      })) as { result?: { value?: unknown } };
      assert.equal(domEval.result?.value, "after-dom");

      const modAndAsyncEval = (await cdp.send("Runtime.evaluate", {
        expression:
          "({ mod: window.__mod, asyncVal: window.__async, bakedInsert: window.__bakedInsert, " +
          "checks: [window.__evalResult, window.__fnResult, window.__directDeno, window.__evalDeno, window.__fnDeno], " +
          "cdpDeno: typeof Deno, cdpProcess: typeof process, arith: 10 + 20 })",
        returnByValue: true,
      })) as { result?: { value?: Record<string, unknown> } };
      assert.deepEqual(modAndAsyncEval.result?.value, {
        mod: { dep: "from-dep", evalDeno: "undefined" },
        asyncVal: "async-ok",
        bakedInsert: "baked-insert-ok",
        checks: [3, 7, "undefined", "undefined", "undefined"],
        cdpDeno: "undefined",
        cdpProcess: "undefined",
        arith: 30,
      });

      const tlaEval = (await cdp.send("Runtime.evaluate", {
        expression: "(async () => await Promise.resolve(99))()",
        awaitPromise: true,
        returnByValue: true,
      })) as { result?: { value?: unknown } };
      assert.equal(tlaEval.result?.value, 99);

      const objHandle = (await cdp.send("Runtime.evaluate", {
        expression: "({ a: 5 })",
        returnByValue: false,
      })) as { result?: { objectId?: string } };
      assert.ok(typeof objHandle.result?.objectId === "string");
      const calledFn = (await cdp.send("Runtime.callFunctionOn", {
        objectId: objHandle.result.objectId,
        functionDeclaration:
          "function(b) { return this.a + b + (typeof Deno === 'undefined' ? 1 : 0); }",
        arguments: [{ value: 36 }],
        returnByValue: true,
      })) as { result?: { value?: unknown } };
      assert.equal(calledFn.result?.value, 42);

      const workerEval = (await cdp.send("Runtime.evaluate", {
        expression: "window.__workerResult",
        awaitPromise: true,
        returnByValue: true,
      })) as { result?: { value?: { echo?: string; sum?: number } } };
      assert.deepEqual(workerEval.result?.value, { echo: "ping-deno", sum: 42 });

      const shot = (await cdp.send("Page.captureScreenshot", { format: "png" })) as {
        data?: string;
      };
      assert.ok(typeof shot.data === "string" && shot.data.length > 100);
      const png = Buffer.from(shot.data, "base64");
      assert.deepEqual([...png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      const ihdrWidth = png.readUInt32BE(16);
      const ihdrHeight = png.readUInt32BE(20);
      assert.equal(ihdrWidth, 320);
      assert.equal(ihdrHeight, 200);
      assert.ok(png.includes(Buffer.from("IDAT")), "PNG must contain IDAT pixel payload");
      assert.ok(png.includes(Buffer.from("IEND")), "PNG must contain IEND trailer");
    } finally {
      cdp.close();
    }

    // Verify wallMs kills a runaway infinite loop inside the page isolate quickly.
    const runawayStart = Date.now();
    const runawayCdp = await CdpClient.connect(
      `ws://127.0.0.1:${hostServer.port}/devtools/page/parawing?ksWallCapMs=300`,
    );
    try {
      await runawayCdp.send("Page.enable");
      await runawayCdp.send("Runtime.enable");
      const crashWaiter = runawayCdp.waitForEvent("Target.targetCrashed", 5_000);
      const navPromise = runawayCdp.send("Page.navigate", { url: `${originUrl}/infinite.html` });
      const [crashResult] = await Promise.all([crashWaiter, navPromise.catch(() => ({}))]);
      assert.equal(crashResult.params["status"], "crashed");
      const elapsedMs = Date.now() - runawayStart;
      assert.ok(
        elapsedMs < 3_000,
        `expected runaway page to terminate rapidly under wallMs, took ${elapsedMs}ms`,
      );
    } finally {
      runawayCdp.close();
    }
  } finally {
    await hostServer.close();
    originServer.closeAllConnections();
    await new Promise<void>((resolve) => originServer.close(() => resolve()));
  }
});

test("zero-perm Deno child blocks fs, TCP, eval codegen, host globals, and denied fetch", async () => {
  const denoFlags = buildDenoRunArgs().slice(0, -1);
  const rawScript =
    'const out = { fsError: "", netError: "", evalError: "" };\n' +
    'try { await Deno.readTextFile("/etc/passwd"); } catch (e) { out.fsError = e.name; }\n' +
    'try { await Deno.connect({ hostname: "127.0.0.1", port: 80 }); } catch (e) { out.netError = e.name; }\n' +
    'try { eval("1+2"); } catch (e) { out.evalError = e.name + ":" + e.message; }\n' +
    "console.log(JSON.stringify(out));\n";
  const rawUrl = `data:text/javascript;base64,${Buffer.from(rawScript, "utf8").toString("base64")}`;
  const { stdout } = await execFileAsync(resolveDenoBinary(), [...denoFlags, rawUrl], {
    env: { DENO_DIR: "/nonexistent-parawing-deno-dir" },
  });
  const rawRes = JSON.parse(stdout.trim()) as {
    fsError: string;
    netError: string;
    evalError: string;
  };
  assert.match(rawRes.fsError, /NotCapable|Permission/);
  assert.match(rawRes.netError, /NotCapable|Permission/);
  assert.match(rawRes.evalError, /EvalError:Code generation from strings disallowed/);

  const host = createMemoryHostCapabilities();
  const loader = createDenoIsolateLoader(host);

  const probeSource = `
    import { WorkerEntrypoint } from "cloudflare:workers";
    export class ProbeEntrypoint extends WorkerEntrypoint {
      async probe() {
        const out = {
          denoType: typeof Deno,
          processType: typeof process,
          bufferType: typeof Buffer,
          evalError: "",
          fnError: "",
          fetchError: "",
          wsError: "",
        };
        try {
          eval("1 + 2");
        } catch (err) {
          out.evalError = err instanceof Error ? err.name + ":" + err.message : String(err);
        }
        try {
          new Function("return 3 + 4")();
        } catch (err) {
          out.fnError = err instanceof Error ? err.name + ":" + err.message : String(err);
        }
        try {
          await fetch("https://example.com/");
        } catch (err) {
          out.fetchError = err instanceof Error ? err.message : String(err);
        }
        try {
          new WebSocket("ws://127.0.0.1:80/");
        } catch (err) {
          out.wsError = err instanceof Error ? err.message : String(err);
        }
        return out;
      }
    }
  `;

  const iso = loader.load<{
    probe(): Promise<{
      denoType: string;
      processType: string;
      bufferType: string;
      evalError: string;
      fnError: string;
      fetchError: string;
      wsError: string;
    }>;
  }>({
    kind: "page-renderer",
    entrypoint: "ProbeEntrypoint",
    compatibilityDate: "2026-01-01",
    compatibilityFlags: ["nodejs_compat"],
    mainModule: "probe.js",
    modules: { "probe.js": { js: probeSource } },
    outbound: { mode: "denied" },
  });

  try {
    const res = await iso.entrypoint.probe();
    assert.equal(res.denoType, "undefined");
    assert.equal(res.processType, "undefined");
    assert.equal(res.bufferType, "undefined");
    assert.match(res.evalError, /EvalError:Code generation from strings disallowed/);
    assert.match(res.fnError, /EvalError:Code generation from strings disallowed/);
    assert.match(res.fetchError, /denied/);
    assert.match(res.wsError, /denied/);
  } finally {
    await iso.terminate("unit probe done");
  }
});

test("deno-isolate-loader wallMs kills while(true){} child via SIGKILL promptly", async () => {
  const host = createMemoryHostCapabilities();
  const loader = createDenoIsolateLoader(host, { gracefulDisposeTimeoutMs: 100 });
  const spinSource = `
    import { WorkerEntrypoint } from "cloudflare:workers";
    export class SpinEntrypoint extends WorkerEntrypoint {
      spin() {
        while (true) {}
      }
    }
  `;
  const startedAt = Date.now();
  const iso = loader.load<{ spin(): Promise<void> }>({
    kind: "page-script",
    entrypoint: "SpinEntrypoint",
    compatibilityDate: "2026-01-01",
    compatibilityFlags: ["nodejs_compat"],
    mainModule: "spin.js",
    modules: { "spin.js": { js: spinSource } },
    outbound: { mode: "denied" },
    limits: { wallMs: 200 },
  });
  await assert.rejects(() => iso.entrypoint.spin());
  const elapsedMs = Date.now() - startedAt;
  assert.ok(elapsedMs < 2_000, `expected SIGKILL within 2000ms, got ${elapsedMs}ms`);
});

test("deno-host server parses ksSessionId/ksUserId/ksEpoch/ksDelegated over real WS upgrades", async () => {
  const hostServer = await createDenoHostServer({
    host: "127.0.0.1",
    port: 0,
    allowPrivateNetwork: true,
  });

  try {
    const wsBase = hostServer.origin.replace(/^http/, "ws");
    const cdpOwner = await CdpClient.connect(
      `${wsBase}/devtools/browser?ksSessionId=deno-sess-e2e&ksUserId=user-deno-1&ksEpoch=2`,
    );
    try {
      const attachedOwner = await cdpOwner.waitForEvent("Parawing.sessionAttached");
      assert.equal(attachedOwner.params["role"], "owner");
      assert.equal(attachedOwner.params["epoch"], 2);
      await cdpOwner.send("Target.createTarget", { url: "about:blank" });

      const cdpLower = await CdpClient.connect(
        `${wsBase}/devtools/browser?ksSessionId=deno-sess-e2e&ksUserId=user-deno-1&ksEpoch=1`,
      );
      try {
        const attachedLower = await cdpLower.waitForEvent("Parawing.sessionAttached");
        assert.equal(attachedLower.params["role"], "viewer");
        assert.equal(attachedLower.params["stale"], true);
        assert.equal(attachedLower.params["epoch"], 2);
        const viewerTargets = await cdpLower.send("Target.getTargets");
        assert.ok(Array.isArray(viewerTargets["targetInfos"]));
        assert.ok((viewerTargets["targetInfos"] as unknown[]).length >= 2);
        await assert.rejects(
          () => cdpLower.send("Target.createTarget", { url: "about:blank" }),
          /Stale epoch/,
        );
      } finally {
        cdpLower.close();
      }
    } finally {
      cdpOwner.close();
    }

    const cdpDel = await CdpClient.connect(
      `${wsBase}/devtools/browser?ksSessionId=deno-sess-del&ksUserId=user-deno-2&ksDelegated=1`,
    );
    try {
      await assert.rejects(() => cdpDel.send("Network.getCookies"), /delegated|denied/i);
    } finally {
      cdpDel.close();
    }

    const cdpReattach = await CdpClient.connect(
      `${wsBase}/devtools/browser?ksSessionId=deno-sess-del&ksUserId=user-deno-2`,
    );
    try {
      const info = await cdpReattach.send("Parawing.getSessionInfo");
      assert.equal(info["persistentSessionId"], "deno-sess-del");
      assert.equal(info["delegatedAgent"], true);
      assert.equal(info["epoch"], 2);
      await cdpReattach.send("Parawing.destroySession", { reason: "e2e done" });
    } finally {
      cdpReattach.close();
    }
  } finally {
    await hostServer.close();
  }
});

async function dispatchDenoKey(
  client: CdpClient,
  sessionId: string,
  elementId: string,
  ch: string,
): Promise<void> {
  await client.send(
    "Runtime.evaluate",
    { expression: `document.getElementById('${elementId}').focus()` },
    sessionId,
  );
  await client.send(
    "Input.dispatchKeyEvent",
    {
      type: "rawKeyDown",
      key: ch,
      code: "KeyX",
      windowsVirtualKeyCode: ch.charCodeAt(0),
      text: ch,
      modifiers: 0,
    },
    sessionId,
  );
}

test("Deno host verifies warm Tier 0 reconnect, Tier 1 journal delta replay, and viewer lease takeover", async () => {
  const formHtml = [
    "<!doctype html><html style='margin:0;padding:0'><body style='margin:0;padding:0'>",
    "<form method='POST' action='/submit'>",
    "<input id='draft' name='note' type='text' oninput=\"console.log('draft:' + this.value)\" ",
    "style='position:absolute;top:20px;left:20px;width:220px;height:28px' />",
    "<input id='pwd' name='password' type='password' autocomplete='current-password' ",
    "style='position:absolute;top:60px;left:20px;width:220px;height:28px' />",
    "</form></body></html>",
  ].join("");
  const originServer = createServer((req, res) => {
    if (req.url === "/form") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(formHtml);
      return;
    }
    res.writeHead(404);
    res.end("not found");
  });
  await new Promise<void>((resolve) => originServer.listen(0, "127.0.0.1", () => resolve()));
  const originAddr = originServer.address();
  const originPort = typeof originAddr === "object" && originAddr ? originAddr.port : 0;
  const formUrl = `http://127.0.0.1:${originPort}/form`;

  const sessionManager = new SessionManager();
  const hostServer = await createDenoHostServer({
    host: "127.0.0.1",
    port: 0,
    allowPrivateNetwork: true,
    sessionManager,
  });
  const wsBase = `ws://${hostServer.host}:${hostServer.port}`;
  const query = "ksSessionId=deno-p34-e2e&ksUserId=user-p34";

  try {
    // 1. Navigate and disconnect; Deno child isolate outlives WS so reconnect hits warm Tier 0.
    const cdp1 = await CdpClient.connect(`${wsBase}/devtools/browser?${query}`);
    const targets1 = (await cdp1.send("Target.getTargets")) as {
      targetInfos: Array<{ targetId: string; type: string }>;
    };
    const pageId = targets1.targetInfos.find((t) => t.type === "page")?.targetId;
    assert.ok(pageId);
    const att1 = await cdp1.send("Target.attachToTarget", { targetId: pageId, flatten: true });
    const sid1 = String(att1["sessionId"] ?? "");
    await cdp1.send(
      "Emulation.setDeviceMetricsOverride",
      { width: 800, height: 600, deviceScaleFactor: 1, mobile: false },
      sid1,
    );
    await cdp1.send("Page.navigate", { url: formUrl }, sid1);
    await cdp1.send(
      "Runtime.evaluate",
      { expression: "window.__warmMarker = 'alive-tier0'" },
      sid1,
    );
    cdp1.close();

    const cdpWarm = await CdpClient.connect(`${wsBase}/devtools/browser?${query}`);
    try {
      await cdpWarm.waitForEvent(
        "Parawing.sessionResumed",
        10_000,
        (params) => params["tier"] === 0,
      );
      const attWarm = await cdpWarm.send("Target.attachToTarget", {
        targetId: pageId,
        flatten: true,
      });
      const warmSid = String(attWarm["sessionId"] ?? "");
      const markerEval = (await cdpWarm.send(
        "Runtime.evaluate",
        { expression: "window.__warmMarker", returnByValue: true },
        warmSid,
      )) as { result?: { value?: unknown } };
      assert.equal(markerEval.result?.value, "alive-tier0");

      // 2. Acknowledge seq=1, type unacked seq=2 + password, suspend -> Tier 1 + delta replay.
      await dispatchDenoKey(cdpWarm, warmSid, "draft", "A");
      const ackState = await cdpWarm.send(
        "Parawing.getInputJournalState",
        { acknowledgeSeq: 1 },
        warmSid,
      );
      assert.equal(ackState["ackedInputSeq"], 1);
      await dispatchDenoKey(cdpWarm, warmSid, "draft", "B");
      await dispatchDenoKey(cdpWarm, warmSid, "pwd", "s");
      const preSuspendJournal = await cdpWarm.send("Parawing.getInputJournalState", {}, warmSid);
      assert.equal(
        preSuspendJournal["size"],
        1,
        `unexpected preSuspendJournal: ${JSON.stringify(preSuspendJournal)}`,
      );
      await cdpWarm.send("Parawing.suspendSession", { reason: "suspend" });
    } finally {
      cdpWarm.close();
    }

    const cdpRestored = await CdpClient.connect(`${wsBase}/devtools/browser?${query}`);
    let cdpViewer: CdpClient | null = null;
    try {
      const restoredEv = await cdpRestored.waitForEvent("Parawing.sessionRestored");
      assert.deepEqual(restoredEv.params["replayedClientInputSeqs"], [2]);
      await cdpRestored.waitForEvent(
        "Parawing.sessionResumed",
        10_000,
        (params) => params["tier"] === 1,
      );
      const att2 = await cdpRestored.send("Target.attachToTarget", {
        targetId: pageId,
        flatten: true,
      });
      const sid2 = String(att2["sessionId"] ?? "");
      const postRestore = (await cdpRestored.send(
        "Runtime.evaluate",
        {
          expression:
            "({ draft: document.getElementById('draft').value, pwd: document.getElementById('pwd').value, marker: window.__warmMarker ?? null })",
          returnByValue: true,
        },
        sid2,
      )) as { result?: { value?: Record<string, unknown> } };
      assert.deepEqual(postRestore.result?.value, { draft: "AB", pwd: "", marker: null });

      // 3. Human takeover over viewer CDP session blocks agent CDP and pauses observation.
      await cdpRestored.send("Runtime.enable", {}, sid2);
      cdpViewer = await CdpClient.connect(`${wsBase}/devtools/browser?${query}&ksRole=viewer`);
      const leaseReq = (await cdpViewer.send("Parawing.requestControllerLease", {
        targetId: pageId,
        requesterId: "human-viewer",
        reason: "deno-takeover",
      })) as { lease?: { leaseId?: string } };
      const leaseId = String(leaseReq.lease?.leaseId ?? "");
      assert.ok(leaseId.startsWith("ctrl-"));
      await cdpRestored.send("Parawing.approveControllerLease", { leaseId });

      cdpRestored.clearRecordedEvents();
      await assert.rejects(
        () =>
          cdpRestored.send(
            "Runtime.evaluate",
            { expression: "document.getElementById('draft').value = 'hijack'" },
            sid2,
          ),
        /active human controller lease/,
      );

      await cdpViewer.send(
        "Input.dispatchMouseEvent",
        { type: "mousePressed", x: 60, y: 30, button: "left", clickCount: 1 },
        sid2,
      );
      await cdpViewer.send(
        "Input.dispatchMouseEvent",
        { type: "mouseReleased", x: 60, y: 30, button: "left", clickCount: 1 },
        sid2,
      );
      await cdpViewer.send("Input.insertText", { text: "!" }, sid2);
      assert.equal(cdpRestored.recordedEventMethods().includes("Runtime.consoleAPICalled"), false);

      await cdpViewer.send("Parawing.releaseControllerLease", { leaseId });
      const afterHandback = (await cdpRestored.send(
        "Runtime.evaluate",
        {
          expression: "console.log('deno-handback'); document.getElementById('draft').value",
          returnByValue: true,
        },
        sid2,
      )) as { result?: { value?: unknown } };
      assert.equal(afterHandback.result?.value, "AB!");
      await cdpRestored.waitForEvent("Runtime.consoleAPICalled");
    } finally {
      await cdpRestored.send("Parawing.destroySession", { reason: "p34 e2e done" }).catch(() => {});
      cdpViewer?.close();
      cdpRestored.close();
    }
  } finally {
    await sessionManager.destroy(asSessionId("deno-p34-e2e")).catch(() => {});
    await hostServer.close();
    originServer.closeAllConnections();
    originServer.close();
  }
});
