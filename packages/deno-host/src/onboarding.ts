// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Turnkey Parawing browser onboarding SDK and CLI: spawn a Parawing host, open a persistent
// session, browse and interact over CDP, disconnect cleanly, and reconnect to warm/cold state.

import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createDenoHostServer, type DenoHostServerOptions } from "./server.ts";

export interface ParawingViewport {
  width: number;
  height: number;
  deviceScaleFactor?: number;
  mobile?: boolean;
}

export interface ParawingPageSummary {
  href: string;
  title: string;
  scrollX: number;
  scrollY: number;
  seq: number;
}

export interface OpenParawingSessionOptions {
  sessionId?: string;
  userId?: string;
  epoch?: number;
  role?: "owner" | "viewer";
  delegatedAgent?: boolean;
  viewport?: ParawingViewport;
  timeoutMs?: number;
}

export interface ConnectParawingSessionOptions extends OpenParawingSessionOptions {
  wsEndpoint: string;
  expectReconnect?: boolean;
}

export interface SpawnParawingBrowserOptions extends DenoHostServerOptions {
  mode?: "subprocess" | "in-process";
  startupTimeoutMs?: number;
}

interface CdpEvent {
  method: string;
  params: Record<string, unknown>;
  sessionId?: string;
}

interface PendingRpc {
  resolve: (result: Record<string, unknown>) => void;
  reject: (err: Error) => void;
}

interface EventWaiter {
  predicate: (ev: CdpEvent) => boolean;
  resolve: (ev: CdpEvent) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const DEFAULT_VIEWPORT: ParawingViewport = {
  width: 1280,
  height: 800,
  deviceScaleFactor: 1,
  mobile: false,
};

class RawCdpSocket {
  readonly #ws: WebSocket;
  #nextId = 1;
  #closed = false;
  readonly #closePromise: Promise<void>;
  readonly #pending = new Map<number, PendingRpc>();
  readonly #events: CdpEvent[] = [];
  readonly #waiters: EventWaiter[] = [];

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    this.#closePromise = new Promise<void>((resolveClose) => {
      ws.addEventListener("close", () => {
        this.#closed = true;
        for (const entry of this.#pending.values()) {
          entry.reject(new Error("Parawing CDP WebSocket closed"));
        }
        this.#pending.clear();
        resolveClose();
      });
    });
    ws.addEventListener("message", (ev) => this.#onMessage(String(ev.data)));
  }

  static connect(url: string, timeoutMs = 15_000): Promise<RawCdpSocket> {
    return new Promise((resolveConn, rejectConn) => {
      const ws = new WebSocket(url);
      const timer = setTimeout(() => {
        try {
          ws.close();
        } catch {}
        rejectConn(new Error(`Timed out connecting to Parawing CDP at ${url}`));
      }, timeoutMs);
      ws.addEventListener(
        "open",
        () => {
          clearTimeout(timer);
          resolveConn(new RawCdpSocket(ws));
        },
        { once: true },
      );
      ws.addEventListener(
        "error",
        () => {
          clearTimeout(timer);
          rejectConn(new Error(`Failed to connect to Parawing CDP at ${url}`));
        },
        { once: true },
      );
    });
  }

  get connected(): boolean {
    return !this.#closed && this.#ws.readyState === WebSocket.OPEN;
  }

  #onMessage(raw: string): void {
    const msg = JSON.parse(raw) as {
      id?: number;
      result?: Record<string, unknown>;
      error?: { message?: string };
      method?: string;
      params?: Record<string, unknown>;
      sessionId?: string;
    };
    if (typeof msg.id === "number") {
      const entry = this.#pending.get(msg.id);
      if (!entry) return;
      this.#pending.delete(msg.id);
      if (msg.error) entry.reject(new Error(msg.error.message ?? "CDP command failed"));
      else entry.resolve(msg.result ?? {});
      return;
    }
    if (msg.method) {
      this.#dispatchEvent({
        method: msg.method,
        params: msg.params ?? {},
        sessionId: msg.sessionId,
      });
    }
  }

  #dispatchEvent(ev: CdpEvent): void {
    const idx = this.#waiters.findIndex((w) => w.predicate(ev));
    if (idx >= 0) {
      const waiter = this.#waiters.splice(idx, 1)[0];
      if (waiter) {
        clearTimeout(waiter.timer);
        waiter.resolve(ev);
      }
      return;
    }
    this.#events.push(ev);
  }

  recordedEvents(method?: string): CdpEvent[] {
    return method ? this.#events.filter((e) => e.method === method) : [...this.#events];
  }

  send(
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<Record<string, unknown>> {
    if (!this.connected) {
      return Promise.reject(new Error(`Cannot send ${method}: session is disconnected`));
    }
    const id = this.#nextId++;
    return new Promise((resolveRpc, rejectRpc) => {
      this.#pending.set(id, { resolve: resolveRpc, reject: rejectRpc });
      const payload = sessionId ? { id, method, params, sessionId } : { id, method, params };
      this.#ws.send(JSON.stringify(payload));
    });
  }

  waitForEvent(
    method: string,
    timeoutMs = 15_000,
    predicate?: (ev: CdpEvent) => boolean,
  ): Promise<CdpEvent> {
    const matches = (ev: CdpEvent): boolean =>
      ev.method === method && (!predicate || predicate(ev));
    const queuedIdx = this.#events.findIndex(matches);
    if (queuedIdx >= 0) {
      return Promise.resolve(this.#events.splice(queuedIdx, 1)[0]!);
    }
    return new Promise((resolveEv, rejectEv) => {
      const waiter: EventWaiter = {
        predicate: matches,
        resolve: resolveEv,
        reject: rejectEv,
        timer: setTimeout(() => {
          const pos = this.#waiters.indexOf(waiter);
          if (pos >= 0) this.#waiters.splice(pos, 1);
          rejectEv(new Error(`Timed out waiting for CDP event ${method}`));
        }, timeoutMs),
      };
      this.#waiters.push(waiter);
    });
  }

  async close(): Promise<void> {
    for (const w of this.#waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(new Error("CDP client disconnected"));
    }
    if (this.#closed || this.#ws.readyState === WebSocket.CLOSED) return;
    try {
      this.#ws.close();
    } catch {
      return;
    }
    await this.#closePromise;
  }
}

function buildSessionWsUrl(baseWsEndpoint: string, opts: OpenParawingSessionOptions): string {
  const url = new URL(baseWsEndpoint);
  if (opts.sessionId) url.searchParams.set("ksSessionId", opts.sessionId);
  if (opts.userId) url.searchParams.set("ksUserId", opts.userId);
  if (typeof opts.epoch === "number") url.searchParams.set("ksEpoch", String(opts.epoch));
  if (opts.role) url.searchParams.set("ksRole", opts.role);
  if (opts.delegatedAgent !== undefined) {
    url.searchParams.set("ksDelegated", opts.delegatedAgent ? "1" : "0");
  }
  return url.toString();
}

export class ParawingBrowserSession {
  readonly sessionId: string;
  readonly userId: string;
  readonly targetId: string;
  readonly cdpSessionId: string;
  readonly resumedTier: 0 | 1 | null;
  readonly replayedInputSeqs: readonly number[];
  readonly #socket: RawCdpSocket;

  constructor(init: {
    socket: RawCdpSocket;
    sessionId: string;
    userId: string;
    targetId: string;
    cdpSessionId: string;
    resumedTier: 0 | 1 | null;
    replayedInputSeqs: readonly number[];
  }) {
    this.#socket = init.socket;
    this.sessionId = init.sessionId;
    this.userId = init.userId;
    this.targetId = init.targetId;
    this.cdpSessionId = init.cdpSessionId;
    this.resumedTier = init.resumedTier;
    this.replayedInputSeqs = init.replayedInputSeqs;
  }

  get connected(): boolean {
    return this.#socket.connected;
  }

  sendCdp(
    method: string,
    params: Record<string, unknown> = {},
    targetScoped = true,
  ): Promise<Record<string, unknown>> {
    return this.#socket.send(method, params, targetScoped ? this.cdpSessionId : undefined);
  }

  async goto(url: string, timeoutMs = 15_000): Promise<ParawingPageSummary> {
    const loadPromise = this.#socket.waitForEvent(
      "Page.loadEventFired",
      timeoutMs,
      (ev) => !ev.sessionId || ev.sessionId === this.cdpSessionId,
    );
    const navRes = await this.sendCdp("Page.navigate", { url });
    if (typeof navRes["errorText"] === "string" && navRes["errorText"]) {
      loadPromise.catch(() => {});
      throw new Error(`Page.navigate failed: ${navRes["errorText"]}`);
    }
    await loadPromise;
    return this.getPageState();
  }

  async getPageState(): Promise<ParawingPageSummary> {
    const raw = await this.sendCdp("Parawing.getPageState", { targetId: this.targetId });
    if (typeof raw["error"] === "string" && raw["error"]) {
      throw new Error(`Parawing.getPageState failed: ${raw["error"]}`);
    }
    return {
      href: String(raw["href"] ?? ""),
      title: String(raw["title"] ?? ""),
      scrollX: Number(raw["scrollX"] ?? 0),
      scrollY: Number(raw["scrollY"] ?? 0),
      seq: Number(raw["seq"] ?? 0),
    };
  }

  async evaluate<T = unknown>(expression: string): Promise<T> {
    const res = (await this.sendCdp("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    })) as {
      result?: { value?: T };
      exceptionDetails?: { text?: string; exception?: { description?: string } };
    };
    if (res.exceptionDetails) {
      const detail =
        res.exceptionDetails.exception?.description ??
        res.exceptionDetails.text ??
        "Runtime.evaluate threw";
      throw new Error(detail);
    }
    return res.result?.value as T;
  }

  async #queryNodeId(selector: string): Promise<number> {
    const doc = (await this.sendCdp("DOM.getDocument", { depth: 0 })) as {
      root?: { nodeId?: number };
    };
    if (typeof doc.root?.nodeId !== "number") {
      throw new Error("DOM.getDocument returned no root nodeId");
    }
    const found = await this.sendCdp("DOM.querySelector", {
      nodeId: doc.root.nodeId,
      selector,
    });
    const nodeId = Number(found["nodeId"] ?? 0);
    if (!nodeId) throw new Error(`Selector not found in document: ${selector}`);
    return nodeId;
  }

  async fill(
    selector: string,
    value: string,
  ): Promise<{ changed: boolean; value?: unknown; error?: string }> {
    const nodeId = await this.#queryNodeId(selector);
    const res = await this.sendCdp("Parawing.setControlValue", {
      targetId: this.targetId,
      nodeId,
      value,
    });
    return {
      changed: Boolean(res["changed"]),
      value: res["value"],
      ...(typeof res["error"] === "string" ? { error: res["error"] } : {}),
    };
  }

  async typeKeys(selector: string, text: string): Promise<void> {
    const nodeId = await this.#queryNodeId(selector);
    await this.sendCdp("DOM.focus", { nodeId });
    await this.evaluate(`document.querySelector(${JSON.stringify(selector)})?.focus()`);
    for (const ch of text) {
      await this.sendCdp("Input.dispatchKeyEvent", {
        type: "rawKeyDown",
        key: ch,
        code: `Key${ch.toUpperCase()}`,
        windowsVirtualKeyCode: ch.charCodeAt(0),
        text: ch,
        modifiers: 0,
      });
    }
  }

  async click(selector: string): Promise<void> {
    const nodeId = await this.#queryNodeId(selector);
    const box = (await this.sendCdp("DOM.getBoxModel", { nodeId })) as {
      model?: { border?: number[] };
    };
    const border = box.model?.border;
    if (!Array.isArray(border) || border.length < 6) {
      throw new Error(`Could not resolve layout box for ${selector}`);
    }
    const x = ((border[0] ?? 0) + (border[2] ?? 0)) / 2;
    const y = ((border[1] ?? 0) + (border[5] ?? 0)) / 2;
    await this.sendCdp("Input.dispatchMouseEvent", {
      type: "mousePressed",
      x,
      y,
      button: "left",
      clickCount: 1,
    });
    await this.sendCdp("Input.dispatchMouseEvent", {
      type: "mouseReleased",
      x,
      y,
      button: "left",
      clickCount: 1,
    });
  }

  async acknowledgeInputSeq(seq: number): Promise<number> {
    const state = await this.sendCdp("Parawing.getInputJournalState", { acknowledgeSeq: seq });
    return Number(state["ackedInputSeq"] ?? 0);
  }

  async acknowledgeLatestInput(): Promise<number> {
    const snap = await this.sendCdp("Parawing.getInputJournalState", {});
    const latestSeq = Math.max(0, Number(snap["nextInputSeq"] ?? 1) - 1);
    return this.acknowledgeInputSeq(latestSeq);
  }

  async getSessionInfo(): Promise<Record<string, unknown>> {
    return this.sendCdp("Parawing.getSessionInfo", {}, false);
  }

  async screenshot(): Promise<Uint8Array> {
    const res = await this.sendCdp("Page.captureScreenshot", { format: "png" });
    const b64 = String(res["data"] ?? "");
    if (!b64) throw new Error("Page.captureScreenshot returned empty payload");
    return new Uint8Array(Buffer.from(b64, "base64"));
  }

  async suspend(reason = "client-suspend"): Promise<Record<string, unknown>> {
    return this.sendCdp("Parawing.suspendSession", { reason }, false);
  }

  async disconnect(): Promise<void> {
    await this.#socket.close();
  }

  async destroySession(reason = "session-complete"): Promise<void> {
    if (this.connected) {
      await this.sendCdp("Parawing.destroySession", { reason }, false).catch(() => {});
    }
    await this.#socket.close();
  }
}

async function resolveFirstPageTargetId(socket: RawCdpSocket): Promise<string> {
  const targets = (await socket.send("Target.getTargets")) as {
    targetInfos?: Array<{ targetId?: string; type?: string }>;
  };
  const existing = (targets.targetInfos ?? []).find((t) => t.type === "page")?.targetId;
  if (existing) return existing;
  const created = await socket.send("Target.createTarget", { url: "about:blank" });
  return String(created["targetId"] ?? "");
}

export async function connectParawingSession(
  options: ConnectParawingSessionOptions,
): Promise<ParawingBrowserSession> {
  const sessionId = options.sessionId ?? `pw-sess-${randomUUID()}`;
  const userId = options.userId ?? "parawing-user";
  const timeoutMs = options.timeoutMs ?? 15_000;
  const wsUrl = buildSessionWsUrl(options.wsEndpoint, { ...options, sessionId, userId });
  const socket = await RawCdpSocket.connect(wsUrl, timeoutMs);
  try {
    let resumedTier: 0 | 1 | null = null;
    let replayedInputSeqs: number[] = [];
    if (options.expectReconnect) {
      const resumedEv = await socket.waitForEvent("Parawing.sessionResumed", timeoutMs);
      const rawTier = resumedEv.params["tier"];
      resumedTier = rawTier === 0 || rawTier === 1 ? rawTier : null;
      const restored = socket.recordedEvents("Parawing.sessionRestored")[0];
      const rawSeqs = restored?.params["replayedClientInputSeqs"];
      if (Array.isArray(rawSeqs)) {
        replayedInputSeqs = rawSeqs.map((v) => Number(v)).filter(Number.isFinite);
      }
    }
    const targetId = await resolveFirstPageTargetId(socket);
    const attached = await socket.send("Target.attachToTarget", { targetId, flatten: true });
    const cdpSessionId = String(attached["sessionId"] ?? "");
    const vp = options.viewport ?? DEFAULT_VIEWPORT;
    await socket.send("Page.enable", {}, cdpSessionId);
    await socket.send("Runtime.enable", {}, cdpSessionId);
    if (!options.expectReconnect || resumedTier === 1) {
      await socket.send(
        "Emulation.setDeviceMetricsOverride",
        {
          width: vp.width,
          height: vp.height,
          deviceScaleFactor: vp.deviceScaleFactor ?? 1,
          mobile: vp.mobile ?? false,
        },
        cdpSessionId,
      );
    }
    return new ParawingBrowserSession({
      socket,
      sessionId,
      userId,
      targetId,
      cdpSessionId,
      resumedTier,
      replayedInputSeqs,
    });
  } catch (err) {
    await socket.close();
    throw err;
  }
}

export interface SpawnedParawingBrowser {
  readonly pid: number | null;
  readonly origin: string;
  readonly wsEndpoint: string;
  openSession(options?: OpenParawingSessionOptions): Promise<ParawingBrowserSession>;
  reconnectSession(
    options: OpenParawingSessionOptions & { sessionId: string },
  ): Promise<ParawingBrowserSession>;
  close(): Promise<void>;
}

async function waitForHealthReady(origin: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${origin}/health`);
      if (resp.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`Parawing host at ${origin} failed /health readiness within ${timeoutMs}ms`);
}

function stopChildProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolveStop) => {
    const killTimer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {}
    }, 2_000);
    child.once("exit", () => {
      clearTimeout(killTimer);
      resolveStop();
    });
    try {
      child.kill("SIGTERM");
    } catch {
      clearTimeout(killTimer);
      resolveStop();
    }
  });
}

async function spawnSubprocessHost(
  options: SpawnParawingBrowserOptions,
): Promise<{ pid: number | null; origin: string; close: () => Promise<void> }> {
  const timeoutMs = options.startupTimeoutMs ?? 20_000;
  const serverScript = fileURLToPath(new URL("./server.ts", import.meta.url));
  const pkgDir = resolve(dirname(serverScript), "..");
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PARAWING_HOST: options.host ?? "127.0.0.1",
    PARAWING_PORT: String(options.port ?? 0),
    PARAWING_ALLOW_PRIVATE_NETWORK: options.allowPrivateNetwork ? "1" : "0",
    ...(options.publicDir ? { PARAWING_PUBLIC_DIR: options.publicDir } : {}),
    ...(options.denoBin ? { PARAWING_DENO_BIN: options.denoBin } : {}),
  };
  const child = spawn(process.execPath, [serverScript], {
    cwd: pkgDir,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const origin = await new Promise<string>((resolveOrigin, rejectOrigin) => {
    let stdoutBuf = "";
    let stderrBuf = "";
    const timer = setTimeout(() => {
      rejectOrigin(
        new Error(`Timed out spawning Parawing browser subprocess. stderr: ${stderrBuf.trim()}`),
      );
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf8");
      const match = /listening on (https?:\/\/[^\s]+)/.exec(stdoutBuf);
      if (match?.[1]) {
        clearTimeout(timer);
        resolveOrigin(match[1]);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBuf += chunk.toString("utf8");
    });
    child.once("exit", (code, sig) => {
      clearTimeout(timer);
      rejectOrigin(
        new Error(
          `Parawing browser subprocess exited early (code=${code}, signal=${sig}): ${stderrBuf.trim()}`,
        ),
      );
    });
  }).catch(async (err) => {
    await stopChildProcess(child);
    throw err;
  });

  await waitForHealthReady(origin, timeoutMs);
  return {
    pid: child.pid ?? null,
    origin,
    close: () => stopChildProcess(child),
  };
}

export async function spawnParawingBrowser(
  options: SpawnParawingBrowserOptions = {},
): Promise<SpawnedParawingBrowser> {
  const mode = options.mode ?? "subprocess";
  const backing =
    mode === "in-process"
      ? await createDenoHostServer({ ...options, port: options.port ?? 0 }).then((srv) => ({
          pid: null,
          origin: srv.origin,
          close: () => srv.close(),
        }))
      : await spawnSubprocessHost(options);
  const wsEndpoint = `${backing.origin.replace(/^http/, "ws")}/devtools/browser`;

  return {
    pid: backing.pid,
    origin: backing.origin,
    wsEndpoint,
    openSession: (sessionOpts = {}) =>
      connectParawingSession({
        ...sessionOpts,
        wsEndpoint,
        expectReconnect: false,
      }),
    reconnectSession: (sessionOpts) =>
      connectParawingSession({
        ...sessionOpts,
        wsEndpoint,
        expectReconnect: true,
      }),
    close: () => backing.close(),
  };
}

async function runCliSmoke(argv: string[]): Promise<void> {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(
      "Usage: node packages/deno-host/src/onboarding.ts <url> [--session <id>] [--user <id>]\n",
    );
    return;
  }
  const url = argv.find((a) => !a.startsWith("-")) ?? "https://example.com/";
  const sessIdx = argv.indexOf("--session");
  const userIdx = argv.indexOf("--user");
  const sessionId =
    sessIdx >= 0 && argv[sessIdx + 1] ? argv[sessIdx + 1]! : `onboard-${Date.now()}`;
  const userId = userIdx >= 0 && argv[userIdx + 1] ? argv[userIdx + 1]! : "cli-operator";
  const browser = await spawnParawingBrowser({ allowPrivateNetwork: true });
  try {
    const first = await browser.openSession({ sessionId, userId });
    const nav = await first.goto(url);
    await first.disconnect();
    const second = await browser.reconnectSession({ sessionId, userId });
    const resumed = await second.getPageState();
    process.stdout.write(
      JSON.stringify(
        {
          spawnedPid: browser.pid,
          origin: browser.origin,
          sessionId,
          initialTitle: nav.title,
          resumedTier: second.resumedTier,
          resumedHref: resumed.href,
        },
        null,
        2,
      ) + "\n",
    );
    await second.destroySession("cli-smoke-complete");
  } finally {
    await browser.close();
  }
}

const isEntrypoint =
  typeof process.argv[1] === "string" &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
  runCliSmoke(process.argv.slice(2)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
