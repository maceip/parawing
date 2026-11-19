// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Hermetic unit and WebSocket session tests for the AOL-locked Parawing showcase server
// (`aol-showcase-server.ts`), verifying URL policy enforcement, scrolling, and Tier 0 reconnect.

import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import test from "node:test";
import { normalizeAndValidateAolUrl, startAolShowcaseServer } from "../src/aol-showcase-server.ts";

interface WsJsonMessage {
  type: string;
  [key: string]: unknown;
}

class TestShowcaseClient {
  readonly #ws: WebSocket;
  readonly #messages: WsJsonMessage[] = [];
  readonly #waiters: Array<{
    pred: (msg: WsJsonMessage) => boolean;
    resolve: (msg: WsJsonMessage) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    ws.addEventListener("message", (ev) => {
      const parsed = JSON.parse(String(ev.data)) as WsJsonMessage;
      if (parsed.type === "error") {
        const err = new Error(`Showcase server error: ${String(parsed["message"] ?? "")}`);
        for (const w of this.#waiters.splice(0)) {
          clearTimeout(w.timer);
          w.reject(err);
        }
        return;
      }
      for (let i = 0; i < this.#waiters.length; i++) {
        const w = this.#waiters[i]!;
        if (w.pred(parsed)) {
          this.#waiters.splice(i, 1);
          clearTimeout(w.timer);
          w.resolve(parsed);
          return;
        }
      }
      this.#messages.push(parsed);
    });
  }

  static async connect(url: string): Promise<TestShowcaseClient> {
    const ws = new WebSocket(url);
    const client = new TestShowcaseClient(ws);
    await new Promise<void>((resolveOpen, rejectOpen) => {
      ws.addEventListener("open", () => resolveOpen(), { once: true });
      ws.addEventListener("error", () => rejectOpen(new Error(`WS failed: ${url}`)), {
        once: true,
      });
    });
    return client;
  }

  waitFor(pred: (msg: WsJsonMessage) => boolean, timeoutMs = 20_000): Promise<WsJsonMessage> {
    const idx = this.#messages.findIndex(pred);
    if (idx !== -1) {
      const [hit] = this.#messages.splice(idx, 1);
      return Promise.resolve(hit!);
    }
    return new Promise<WsJsonMessage>((resolveWait, rejectWait) => {
      const timer = setTimeout(() => {
        rejectWait(new Error("Timed out waiting for showcase WS message"));
      }, timeoutMs);
      this.#waiters.push({ pred, resolve: resolveWait, reject: rejectWait, timer });
    });
  }

  send(payload: Record<string, unknown>): void {
    this.#ws.send(JSON.stringify(payload));
  }

  async close(): Promise<void> {
    if (this.#ws.readyState === WebSocket.CLOSED) return;
    const closed = new Promise<void>((r) => this.#ws.addEventListener("close", () => r()));
    this.#ws.close();
    await closed;
  }
}

test("normalizeAndValidateAolUrl enforces strict aol.com / *.aol.com policy", () => {
  const bare = normalizeAndValidateAolUrl("aol.com");
  assert.equal(bare.ok, true);
  if (bare.ok) assert.equal(bare.url, "https://www.aol.com/");

  const news = normalizeAndValidateAolUrl("https://www.aol.com/news/");
  assert.equal(news.ok, true);
  if (news.ok) assert.equal(news.url, "https://www.aol.com/news/");

  const sub = normalizeAndValidateAolUrl("http://finance.aol.com/markets");
  assert.equal(sub.ok, true);
  if (sub.ok) assert.equal(sub.url, "https://finance.aol.com/markets");

  for (const forbidden of [
    "",
    "https://example.com/",
    "google.com",
    "https://aol.com.evil.com/phish",
    "https://not-aol.com/",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "https://www.aol.com:8443/",
  ]) {
    const res = normalizeAndValidateAolUrl(forbidden);
    assert.equal(res.ok, false, `Expected ${forbidden} to be rejected`);
  }
});

test("startAolShowcaseServer streams PNG frames, blocks non-AOL URLs, and warm-reconnects", async () => {
  const fixture = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.url === "/news") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        "<!doctype html><html><body style='margin:0;background:#fff;color:#111'>" +
          "<h1>AOL News Section</h1><div style='height:2200px'>Tall feed</div></body></html>",
      );
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(
      "<!doctype html><html><body style='margin:0;background:#f8fafc;color:#0f172a'>" +
        "<h1>AOL Home Fixture</h1><a id='news-link' href='/news' " +
        "style='display:block;width:240px;height:48px'>Read News</a>" +
        "<div style='height:2400px'>Scrollable stories</div></body></html>",
    );
  });
  await new Promise<void>((r) => fixture.listen(0, "127.0.0.1", () => r()));
  const fixtureAddr = fixture.address();
  assert.ok(typeof fixtureAddr === "object" && fixtureAddr !== null);
  const fixtureOrigin = `http://127.0.0.1:${fixtureAddr.port}`;

  const showcase = await startAolShowcaseServer({
    host: "127.0.0.1",
    port: 0,
    region: "sfo2",
    defaultUrl: `${fixtureOrigin}/`,
    allowLocalTestOrigin: fixtureOrigin,
  });

  try {
    const statusRes = await fetch(`${showcase.origin}/showcase/status`);
    assert.equal(statusRes.status, 200);
    const statusJson = (await statusRes.json()) as { ok: boolean; policy: string };
    assert.equal(statusJson.ok, true);
    assert.equal(statusJson.policy, "aol.com-only");

    const wsUrl = `${showcase.origin.replace(/^http/, "ws")}/showcase/ws?sessionId=aol-hermetic-1`;
    const client1 = await TestShowcaseClient.connect(wsUrl);
    const conn1 = await client1.waitFor((m) => m.type === "connected");
    assert.equal(conn1["reconnected"], false);

    const frame1 = await client1.waitFor((m) => m.type === "frame");
    const png1 = Buffer.from(String(frame1["pngBase64"] ?? ""), "base64");
    assert.ok(png1.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])));

    client1.send({ type: "navigate", url: "https://example.com/" });
    const blocked = await client1.waitFor((m) => m.type === "policyBlocked");
    assert.equal(blocked["blockedNavigations"], 1);
    assert.match(String(blocked["reason"]), /locked exclusively to aol\.com/);

    client1.send({ type: "scroll", deltaX: 0, deltaY: 260 });
    const scrolled = await client1.waitFor((m) => m.type === "frame" && m["reason"] === "scroll");
    const pageAfterScroll = scrolled["page"] as { scrollY: number };
    assert.ok(pageAfterScroll.scrollY > 0, `Expected scrollY > 0, got ${pageAfterScroll.scrollY}`);

    await client1.close();

    const client2 = await TestShowcaseClient.connect(wsUrl);
    const conn2 = await client2.waitFor((m) => m.type === "connected");
    assert.equal(conn2["reconnected"], true);
    assert.equal(conn2["resumedTier"], 0);
    const frameReconnect = await client2.waitFor(
      (m) => m.type === "frame" && m["reason"] === "reconnected",
    );
    const pageAfterReconnect = frameReconnect["page"] as { scrollY: number };
    assert.equal(pageAfterReconnect.scrollY, pageAfterScroll.scrollY);
    await client2.close();
  } finally {
    await showcase.close();
    await new Promise<void>((r) => fixture.close(() => r()));
  }
});
