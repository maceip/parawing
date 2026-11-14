// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Compatibility and security tests comparing Boa wasm and Native V8 node:vm execution backends.

import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createDenoHostServer } from "../src/server.ts";
import { createV8RealmEvaluator } from "../src/v8-realm-evaluator.ts";

class MiniCdpClient {
  readonly #ws: WebSocket;
  #nextId = 1;
  readonly #pending = new Map<
    number,
    { resolve: (result: Record<string, unknown>) => void; reject: (err: Error) => void }
  >();
  readonly #events: Array<{ method: string; params: Record<string, unknown> }> = [];
  readonly #waiters: Array<{
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
        if (msg.error) entry.reject(new Error(msg.error.message ?? "CDP error"));
        else entry.resolve(msg.result ?? {});
        return;
      }
      if (msg.method) {
        const event = { method: msg.method, params: msg.params ?? {} };
        const idx = this.#waiters.findIndex((w) => w.predicate(event));
        if (idx >= 0) {
          const w = this.#waiters.splice(idx, 1)[0];
          if (w) {
            clearTimeout(w.timer);
            w.resolve(event);
          }
          return;
        }
        this.#events.push(event);
      }
    });
    ws.addEventListener("close", () => {
      for (const entry of this.#pending.values()) {
        entry.reject(new Error("CDP WebSocket closed"));
      }
      this.#pending.clear();
    });
  }

  static connect(url: string): Promise<MiniCdpClient> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.addEventListener("open", () => resolve(new MiniCdpClient(ws)), { once: true });
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

  waitForEvent(
    method: string,
    timeoutMs = 15_000,
  ): Promise<{ method: string; params: Record<string, unknown> }> {
    const idx = this.#events.findIndex((ev) => ev.method === method);
    if (idx >= 0) return Promise.resolve(this.#events.splice(idx, 1)[0]!);
    return new Promise((resolve, reject) => {
      const entry = {
        predicate: (ev: { method: string; params: Record<string, unknown> }) =>
          ev.method === method,
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = this.#waiters.indexOf(entry);
          if (i >= 0) this.#waiters.splice(i, 1);
          reject(new Error(`Timed out waiting for ${method}`));
        }, timeoutMs),
      };
      this.#waiters.push(entry);
    });
  }

  close(): void {
    for (const entry of this.#waiters.splice(0)) {
      clearTimeout(entry.timer);
      entry.reject(new Error("CDP client closed"));
    }
    try {
      this.#ws.close();
    } catch {}
  }
}

test("V8RealmEvaluator membrane blocks host globals, RPC, and constructor escapes", async () => {
  const evaluator = createV8RealmEvaluator();
  class HostWidget {
    label = "widget";
    ping(x: number): number {
      return x + 1;
    }
  }
  const widget = new HostWidget();
  const hostRpc = { secretToken: "host-rpc-cap", readSecret: () => "leak" };
  const throwingHostFn = (): void => {
    throw new TypeError("host boom");
  };
  evaluator.installGlobals({
    widget,
    HostWidget,
    throwingHostFn,
    hostRpcCapability: undefined,
    Deno: { version: "should-not-leak" },
    process: { env: { SECRET: "should-not-leak" } },
    __ks_init_isolate: () => "should-not-leak",
  });

  try {
    const isolation = await evaluator.evalExpression(`
      (() => {
        const directDeno = typeof Deno;
        const directProcess = typeof process;
        const directRequire = typeof require;
        const directGlobal = typeof global;
        const initHook = typeof __ks_init_isolate;
        let escapeProcessErr = "";
        try {
          escapeProcessErr = String(widget.constructor.constructor("return typeof process")());
        } catch (err) {
          escapeProcessErr = err.name + ":" + err.message;
        }
        let fnEscape = "";
        try {
          fnEscape = String(
            Object.getPrototypeOf(throwingHostFn).constructor("return typeof process")(),
          );
        } catch (err) {
          fnEscape = err.name + ":" + err.message;
        }
        let errEscape = "";
        try {
          throwingHostFn();
        } catch (err) {
          errEscape = String(err.constructor.constructor("return typeof process")());
        }
        let ownEscape = "";
        try {
          ownEscape = String((() => {}).constructor("return typeof process")());
        } catch (err) {
          ownEscape = err.name + ":" + err.message;
        }
        const identityOk = widget.ping(41) === 42 && widget instanceof HostWidget;
        return {
          directDeno,
          directProcess,
          directRequire,
          directGlobal,
          initHook,
          escapeProcessErr,
          fnEscape,
          errEscape,
          ownEscape,
          identityOk,
          secretTokenStillMissing: "${hostRpc.secretToken}".length > 0 && typeof secretToken,
        };
      })()
    `);
    assert.equal(isolation.ok, true);
    assert.deepEqual(
      { ...(isolation.value as Record<string, unknown>) },
      {
        directDeno: "undefined",
        directProcess: "undefined",
        directRequire: "undefined",
        directGlobal: "undefined",
        initHook: "undefined",
        escapeProcessErr: "undefined",
        fnEscape: "undefined",
        errEscape: "undefined",
        ownEscape: "undefined",
        identityOk: true,
        secretTokenStillMissing: "undefined",
      },
    );

    const timerCheck = await evaluator.evalExpression(`
      new Promise((resolve) => {
        const order = [];
        const cancelled = setTimeout(() => order.push("bad"), 5);
        clearTimeout(cancelled);
        Promise.resolve().then(() => order.push("micro"));
        setTimeout(() => {
          order.push("timeout");
          resolve(order);
        }, 10);
      })
    `);
    assert.equal(timerCheck.ok, true);
    assert.deepEqual([...(timerCheck.value as unknown[])], ["micro", "timeout"]);

    const compiled = evaluator.compileScript("function (", "bad.js");
    assert.equal(compiled.ok, false);
    assert.ok(compiled.error instanceof Error || String(compiled.error).includes("Syntax"));
  } finally {
    evaluator.dispose();
  }
});

test("Boa and Native V8 produce matching DOM, Promise, Timer, Error, and CDP results", async () => {
  const server = createServer((req, res) => {
    if (req.url === "/dep.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end("export const offset = 8;");
      return;
    }
    if (req.url === "/mod.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end('import { offset } from "/dep.js"; window.__modTotal = 34 + offset;');
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(
      "<!doctype html><html><head><title>Compat</title></head><body>" +
        '<div id="msg">initial</div>' +
        "<script>" +
        "var globalSeed = 19; function computeSeed(n) { return globalSeed + n; }" +
        'document.getElementById("msg").textContent = "from-script-" + computeSeed(2);' +
        "</script>" +
        '<script type="module" src="/mod.js"></script>' +
        "</body></html>",
    );
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  assert.ok(typeof addr === "object" && addr !== null);
  const pageUrl = `http://127.0.0.1:${addr.port}/index.html`;

  const results: Record<string, unknown> = {};
  try {
    for (const backend of ["boa", "v8"] as const) {
      const hostServer = await createDenoHostServer({
        host: "127.0.0.1",
        port: 0,
        allowPrivateNetwork: true,
        executionBackend: backend,
      });
      try {
        const cdp = await MiniCdpClient.connect(
          `ws://127.0.0.1:${hostServer.port}/devtools/page/parawing`,
        );
        try {
          await cdp.send("Page.enable");
          await cdp.send("Runtime.enable");

          const loadDone = cdp.waitForEvent("Page.loadEventFired");
          await cdp.send("Page.navigate", { url: pageUrl });
          await loadDone;

          const domAndGlobals = (await cdp.send("Runtime.evaluate", {
            expression: `({
              msg: document.getElementById("msg").textContent,
              computed: computeSeed(23),
              modTotal: window.__modTotal,
              processType: typeof process,
              denoType: typeof Deno,
              ctorEscape: (() => {
                try {
                  return String(document.constructor.constructor("return typeof process")());
                } catch (e) {
                  return e.name;
                }
              })()
            })`,
            returnByValue: true,
          })) as { result?: { value?: unknown }; exceptionDetails?: unknown };
          assert.equal(domAndGlobals.exceptionDetails, undefined);

          const asyncRes = (await cdp.send("Runtime.evaluate", {
            expression: `new Promise((resolve) => {
              const seq = [];
              const bad = setTimeout(() => seq.push("cancelled"), 5);
              clearTimeout(bad);
              Promise.resolve().then(() => seq.push("microtask"));
              setTimeout(() => { seq.push("timeout"); resolve(seq); }, 10);
            })`,
            awaitPromise: true,
            returnByValue: true,
          })) as { result?: { value?: unknown }; exceptionDetails?: unknown };
          assert.equal(asyncRes.exceptionDetails, undefined);

          const syncErr = (await cdp.send("Runtime.evaluate", {
            expression: '(() => { throw new TypeError("compat-boom"); })()',
            returnByValue: true,
          })) as {
            exceptionDetails?: { exception?: { className?: string; description?: string } };
          };

          const handleEval = (await cdp.send("Runtime.evaluate", {
            expression:
              '({ count: 10, label: "item", add(n) { this.count += n; return this.count; } })',
            returnByValue: false,
            objectGroup: "compat-group",
          })) as { result?: { type?: string; objectId?: string } };
          const objectId = handleEval.result?.objectId;
          assert.ok(objectId && objectId.startsWith("ps:"));

          const callRes = (await cdp.send("Runtime.callFunctionOn", {
            objectId,
            functionDeclaration: "function(delta) { return this.add(delta); }",
            arguments: [{ value: 5 }],
            returnByValue: true,
          })) as { result?: { value?: unknown } };

          const propsRes = (await cdp.send("Runtime.getProperties", {
            objectId,
            ownProperties: true,
          })) as { result?: Array<{ name: string; isOwn?: boolean; value?: { value?: unknown } }> };
          const ownNames = (propsRes.result ?? []).map((d) => d.name).sort();

          await cdp.send("Runtime.releaseObjectGroup", { objectGroup: "compat-group" });
          const afterRelease = (await cdp.send("Runtime.getProperties", {
            objectId,
            ownProperties: true,
          })) as { result?: unknown[] };

          const badCompile = (await cdp.send("Runtime.compileScript", {
            expression: "const x = (",
            sourceURL: "broken.js",
            persistScript: true,
          })) as { scriptId?: string; exceptionDetails?: unknown };

          const goodCompile = (await cdp.send("Runtime.compileScript", {
            expression: "window.__compiledVal = 7 * 9; window.__compiledVal;",
            sourceURL: "good.js",
            persistScript: true,
          })) as { scriptId?: string };
          assert.ok(goodCompile.scriptId);
          const runCompiled = (await cdp.send("Runtime.runScript", {
            scriptId: goodCompile.scriptId,
            returnByValue: true,
          })) as { result?: { value?: unknown } };

          results[backend] = {
            domAndGlobals: domAndGlobals.result?.value,
            asyncSeq: asyncRes.result?.value,
            syncErrClass: syncErr.exceptionDetails?.exception?.className,
            syncErrHasMsg: String(syncErr.exceptionDetails?.exception?.description ?? "").includes(
              "compat-boom",
            ),
            callResult: callRes.result?.value,
            ownNames,
            propsAfterReleaseCount: (afterRelease.result ?? []).length,
            badCompileHasException: Boolean(badCompile.exceptionDetails),
            badCompileScriptId: badCompile.scriptId ?? null,
            runCompiledValue: runCompiled.result?.value,
          };
        } finally {
          cdp.close();
        }
      } finally {
        await hostServer.close();
      }
    }
    assert.deepEqual(results["v8"], {
      domAndGlobals: {
        msg: "from-script-21",
        computed: 42,
        modTotal: 42,
        processType: "undefined",
        denoType: "undefined",
        ctorEscape: "undefined",
      },
      asyncSeq: ["microtask", "timeout"],
      syncErrClass: "TypeError",
      syncErrHasMsg: true,
      callResult: 15,
      ownNames: ["add", "count", "label"],
      propsAfterReleaseCount: 0,
      badCompileHasException: true,
      badCompileScriptId: null,
      runCompiledValue: 63,
    });
    assert.deepEqual(results["v8"], results["boa"]);
  } finally {
    server.close();
  }
});
