// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// End-to-end test for Parawing browser onboarding: spawns a real Parawing host subprocess,
// browses an interactive onboarding app, disconnects, and reconnects across Tier 0 and Tier 1.

import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import test from "node:test";
import { spawnParawingBrowser } from "../src/onboarding.ts";

interface ActivationRecord {
  org: string;
  region: string;
  cookieHeader: string;
}

interface MockOnboardingPortal {
  origin: string;
  activations: ActivationRecord[];
  close(): Promise<void>;
}

const ONBOARDING_HTML = [
  "<!doctype html><html><head><meta charset='utf-8'><title>Parawing Onboarding Portal</title></head>",
  "<body style='margin:0;padding:24px;font-family:sans-serif;background:#f4f7fb;color:#101828'>",
  "<h1 style='margin:0 0 12px'>Workspace Onboarding</h1>",
  "<div id='status-banner' style='margin-bottom:16px;font-weight:700'>step-1:ready</div>",
  "<form id='onboard-form' action='/onboarding' method='GET' style='position:relative;height:220px'>",
  "<input id='org-input' name='org' type='text' ",
  "style='position:absolute;top:0;left:0;width:240px;height:32px' />",
  "<select id='region-select' name='region' ",
  "style='position:absolute;top:44px;left:0;width:240px;height:32px'>",
  "<option value='us-west'>US West</option>",
  "<option value='eu-central'>EU Central</option>",
  "</select>",
  "<input id='notes-input' name='notes' type='text' ",
  "style='position:absolute;top:88px;left:0;width:240px;height:32px' />",
  "<button id='save-step1' type='button' ",
  "style='position:absolute;top:136px;left:0;width:140px;height:36px'>Continue</button>",
  "<button id='finish-btn' type='button' ",
  "style='position:absolute;top:136px;left:156px;width:160px;height:36px'>Activate</button>",
  "</form>",
  "<script>",
  "document.getElementById('save-step1').addEventListener('click', () => {",
  "  const org = document.getElementById('org-input').value;",
  "  const region = document.getElementById('region-select').value;",
  "  window.__onboardingHeap = { step: 2, org, region };",
  "  document.getElementById('status-banner').textContent = 'step-2:' + org + ':' + region;",
  "});",
  "document.getElementById('finish-btn').addEventListener('click', async () => {",
  "  const state = window.__onboardingHeap || { org: 'none', region: 'none' };",
  "  const res = await fetch('/api/activate', {",
  "    method: 'POST',",
  "    headers: { 'content-type': 'application/json' },",
  "    body: JSON.stringify(state),",
  "  });",
  "  const data = await res.json();",
  "  window.__activationReceipt = data;",
  "  document.getElementById('status-banner').textContent =",
  "    'activated:' + data.org + ':' + data.region + ':ticket=' + data.ticketValid;",
  "});",
  "</script></body></html>",
].join("");

function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolveBody(Buffer.concat(chunks).toString("utf8")));
    req.on("error", rejectBody);
  });
}

// RYAN EXPLICIT MOCK/FALLBACK AUTHORIZATION: "ok please mock and implement and then use in
// our test a \"browser onboarding\" e2e where you spawn it, browse to something disconnect
// and reconnect"
async function startMockOnboardingPortal(): Promise<MockOnboardingPortal> {
  const activations: ActivationRecord[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      if (req.method === "GET" && req.url?.startsWith("/onboarding")) {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "set-cookie": "pw_onboard_ticket=ticket-live-1; Path=/",
        });
        res.end(ONBOARDING_HTML);
        return;
      }
      if (req.method === "POST" && req.url === "/api/activate") {
        const raw = await readRequestBody(req);
        const parsed = JSON.parse(raw || "{}") as { org?: string; region?: string };
        const cookieHeader = String(req.headers.cookie ?? "");
        const record: ActivationRecord = {
          org: String(parsed.org ?? ""),
          region: String(parsed.region ?? ""),
          cookieHeader,
        };
        activations.push(record);
        const payload = JSON.stringify({
          activated: true,
          org: record.org,
          region: record.region,
          ticketValid: cookieHeader.includes("pw_onboard_ticket=ticket-live-1"),
        });
        res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
        res.end(payload);
        return;
      }
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("not found");
    })();
  });

  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", () => resolveListen()));
  const addr = server.address();
  assert.ok(typeof addr === "object" && addr !== null);
  return {
    origin: `http://127.0.0.1:${addr.port}`,
    activations,
    close: () =>
      new Promise<void>((resolveClose) => {
        server.closeAllConnections();
        server.close(() => resolveClose());
      }),
  };
}

test("browser onboarding e2e spawns Parawing subprocess, browses, disconnects, and reconnects across Tier 0 and Tier 1", async () => {
  const portal = await startMockOnboardingPortal();
  const browser = await spawnParawingBrowser({
    mode: "subprocess",
    allowPrivateNetwork: true,
  });

  const sessionId = "onboard-e2e-session";
  const userId = "agent-onboard";

  try {
    assert.ok(
      typeof browser.pid === "number" && browser.pid > 0 && browser.pid !== process.pid,
      `expected distinct child OS PID, got ${browser.pid}`,
    );

    // 1. Open persistent session, browse to onboarding portal, fill Step 1, and click Continue.
    const session1 = await browser.openSession({ sessionId, userId });
    assert.equal(session1.connected, true);
    assert.equal(session1.resumedTier, null);

    const initialPage = await session1.goto(`${portal.origin}/onboarding`);
    assert.equal(initialPage.title, "Parawing Onboarding Portal");

    const orgFill = await session1.fill("#org-input", "parawing-labs");
    assert.equal(orgFill.changed, true);
    const regionFill = await session1.fill("#region-select", "eu-central");
    assert.equal(regionFill.changed, true);
    await session1.click("#save-step1");

    const step1Banner = await session1.evaluate<string>(
      "document.getElementById('status-banner').textContent",
    );
    assert.equal(step1Banner, "step-2:parawing-labs:eu-central");

    // 2. Disconnect client WebSocket completely while the spawned Parawing browser stays alive.
    await session1.disconnect();
    assert.equal(session1.connected, false);
    await assert.rejects(() => session1.getPageState(), /disconnected/);

    // 3. Reconnect (warm Tier 0): live Deno V8 heap, DOM, and session cookie remain intact.
    const session2 = await browser.reconnectSession({ sessionId, userId });
    try {
      assert.equal(session2.resumedTier, 0);
      const preserved = await session2.evaluate<{
        banner: string;
        heap: { step: number; org: string; region: string };
        cookie: string;
      }>(
        "({ banner: document.getElementById('status-banner').textContent, " +
          "heap: window.__onboardingHeap, cookie: document.cookie })",
      );
      assert.deepEqual(preserved.heap, {
        step: 2,
        org: "parawing-labs",
        region: "eu-central",
      });
      assert.equal(preserved.banner, "step-2:parawing-labs:eu-central");
      assert.match(preserved.cookie, /pw_onboard_ticket=ticket-live-1/);

      await session2.click("#finish-btn");
      const receipt = await session2.evaluate<{
        activated: boolean;
        org: string;
        region: string;
        ticketValid: boolean;
      }>(
        "new Promise((resolve) => {" +
          "  const poll = () => window.__activationReceipt ? resolve(window.__activationReceipt) : setTimeout(poll, 20);" +
          "  poll();" +
          "})",
      );
      assert.deepEqual(receipt, {
        activated: true,
        org: "parawing-labs",
        region: "eu-central",
        ticketValid: true,
      });
      assert.equal(portal.activations.length, 1);
      assert.equal(portal.activations[0]?.org, "parawing-labs");

      const png = await session2.screenshot();
      assert.deepEqual([...png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
      assert.equal(view.getUint32(16, false), 1280);
      assert.equal(view.getUint32(20, false), 800);

      // 4. Fill notes, suspend (terminates V8 isolate after Tier 1 checkpoint), and reconnect.
      const notesFill = await session2.fill("#notes-input", "ready-for-prod");
      assert.equal(notesFill.changed, true);
      await session2.suspend("cold-handoff");
      await session2.disconnect();

      const session3 = await browser.reconnectSession({ sessionId, userId });
      try {
        assert.equal(session3.resumedTier, 1);
        const restoredState = await session3.evaluate<{
          org: string;
          region: string;
          notes: string;
          heapCleared: boolean;
        }>(
          "({ org: document.getElementById('org-input').value, " +
            "region: document.getElementById('region-select').value, " +
            "notes: document.getElementById('notes-input').value, " +
            "heapCleared: typeof window.__onboardingHeap === 'undefined' })",
        );
        assert.deepEqual(restoredState, {
          org: "parawing-labs",
          region: "eu-central",
          notes: "ready-for-prod",
          heapCleared: true,
        });
        const info = await session3.getSessionInfo();
        assert.equal(info["persistentSessionId"], sessionId);
      } finally {
        await session3.destroySession("onboarding-e2e-complete");
      }
    } finally {
      await session2.disconnect();
    }
  } finally {
    await browser.close();
    await portal.close();
  }
});
