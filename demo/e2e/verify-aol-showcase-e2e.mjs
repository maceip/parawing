#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Automated Chromium E2E test for the default GitHub Pages landing demo (`dist-pages/index.html`)
// connected live over WSS to the AOL-locked DigitalOcean SFO2 droplet (`64-225-124-165.sslip.io`).

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { extname, join, resolve } from "node:path";
import { buildSecurityPages } from "../../scripts/build-security-pages.mjs";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const rootReq = createRequire(resolve(REPO_ROOT, "package.json"));
const puppeteer = rootReq("puppeteer-core");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
};

function findBrowserBin() {
  if (process.env.CHROME_BIN && existsSync(process.env.CHROME_BIN)) return process.env.CHROME_BIN;
  const pwCache = resolve(homedir(), "Library/Caches/ms-playwright");
  if (existsSync(pwCache)) {
    const dirs = readdirSync(pwCache)
      .filter((d) => d.startsWith("chromium-"))
      .sort()
      .reverse();
    for (const dir of dirs) {
      const macArm = resolve(
        pwCache,
        dir,
        "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
      );
      if (existsSync(macArm)) return macArm;
    }
  }
  const retail = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  if (existsSync(retail)) return retail;
  throw new Error("Chromium binary not found");
}

function serveStaticDir(dir) {
  return new Promise((resolvePromise) => {
    const server = http.createServer((req, res) => {
      const urlPath = (req.url || "/").split("?")[0];
      const rel = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
      const filePath = resolve(dir, rel);
      if (!filePath.startsWith(dir) || !existsSync(filePath)) {
        res.writeHead(404);
        res.end("not found");
        return;
      }
      res.writeHead(200, {
        "content-type": MIME[extname(filePath).toLowerCase()] || "application/octet-stream",
      });
      res.end(readFileSync(filePath));
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolvePromise({ server, baseUrl: `http://127.0.0.1:${addr.port}` });
    });
  });
}

async function main() {
  const screenshotOut = process.argv.includes("--screenshot")
    ? resolve(process.argv[process.argv.indexOf("--screenshot") + 1])
    : null;

  const buildInfo = buildSecurityPages();
  const { server, baseUrl } = await serveStaticDir(buildInfo.outDir);
  const userDataDir = mkdtempSync(join(tmpdir(), "parawing-aol-showcase-e2e-"));
  const browser = await puppeteer.launch({
    executablePath: findBrowserBin(),
    headless: "new",
    userDataDir,
    defaultViewport: { width: 1360, height: 980 },
  });

  try {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on("pageerror", (err) => pageErrors.push(String(err?.message ?? err)));

    // 1. Open `/` (default GitHub Pages landing page) and verify overlay + zero bottom cards.
    await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
    const layout = await page.evaluate(() => {
      const bodyBg = getComputedStyle(document.body).backgroundColor;
      const chassis = document.querySelector(".hc-browser");
      const cs = getComputedStyle(chassis);
      const vp = document.getElementById("viewport-wrap").getBoundingClientRect();
      const ov = document.querySelector(".hc-viewport-overlay").getBoundingClientRect();
      return {
        bodyBg,
        chassisBg: cs.backgroundColor,
        chassisColor: cs.color,
        chassisBorder: `${cs.borderTopWidth} ${cs.borderTopStyle} ${cs.borderTopColor}`,
        bottomPastelCards: document.querySelectorAll(".pastel-cards, .pastel-card").length,
        overlayInsideViewport:
          ov.top >= vp.top && ov.bottom <= vp.bottom && ov.left >= vp.left && ov.right <= vp.right,
        quickOverlayButtons: document.querySelectorAll(".hc-quick-overlay button").length,
      };
    });
    assert.equal(layout.bodyBg, "rgb(250, 246, 240)");
    assert.equal(layout.chassisBg, "rgb(10, 12, 16)");
    assert.equal(layout.chassisColor, "rgb(255, 255, 255)");
    assert.equal(layout.chassisBorder, "2px solid rgb(0, 0, 0)");
    assert.equal(layout.bottomPastelCards, 0);
    assert.equal(layout.overlayInsideViewport, true);
    assert.equal(layout.quickOverlayButtons, 3);

    // 2. Wait for live WSS bootstrap + autonomous agent moving its mouse and clicking on aol.com!
    await page.waitForFunction(
      () => {
        const c = document.getElementById("browser-canvas");
        const cursor = document.getElementById("agent-cursor");
        return (
          Number(c?.getAttribute("data-frames") || "0") >= 2 &&
          Number(cursor?.getAttribute("data-moves") || "0") >= 1 &&
          Number(cursor?.getAttribute("data-clicks") || "0") >= 1
        );
      },
      { timeout: 45_000 },
    );

    const agentLiveState = await page.evaluate(() => {
      const c = document.getElementById("browser-canvas");
      const cursor = document.getElementById("agent-cursor");
      const ctx = c.getContext("2d");
      const { data } = ctx.getImageData(0, 0, c.width, c.height);
      const distinctColors = new Set();
      for (let i = 0; i < data.length; i += 4 * 97) {
        distinctColors.add(`${data[i]},${data[i + 1]},${data[i + 2]}`);
        if (distinctColors.size > 40) break;
      }
      return {
        badge: document.getElementById("conn-badge")?.textContent?.trim() || "",
        currentUrl: c.getAttribute("data-current-url") || "",
        cursorActive: cursor.getAttribute("data-active"),
        moves: Number(cursor.getAttribute("data-moves") || "0"),
        clicks: Number(cursor.getAttribute("data-clicks") || "0"),
        takeControlLabel: document.getElementById("take-control-btn")?.textContent?.trim() || "",
        distinctSampledColors: distinctColors.size,
      };
    });
    assert.match(agentLiveState.badge, /Live · SFO2/);
    assert.equal(agentLiveState.cursorActive, "true");
    assert.ok(agentLiveState.moves >= 1);
    assert.ok(agentLiveState.clicks >= 1);
    assert.equal(agentLiveState.takeControlLabel, "■ Take Control");
    assert.ok(agentLiveState.distinctSampledColors > 12);

    if (screenshotOut) {
      await page.screenshot({ path: screenshotOut, fullPage: true });
    }

    // 3. Click `■ Take Control` stop button -> verify epoch-fenced human takeover stops the agent!
    await page.click("#take-control-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("take-control-btn")?.getAttribute("data-controller") === "human",
      { timeout: 15_000 },
    );
    const afterTakeover = await page.evaluate(() => ({
      controller: document.getElementById("take-control-btn")?.getAttribute("data-controller"),
      epoch: Number(document.getElementById("take-control-btn")?.getAttribute("data-epoch") || "0"),
      btnText: document.getElementById("take-control-btn")?.textContent?.trim() || "",
      cursorActive: document.getElementById("agent-cursor")?.getAttribute("data-active"),
      movesAtTakeover: Number(
        document.getElementById("agent-cursor")?.getAttribute("data-moves") || "0",
      ),
    }));
    assert.equal(afterTakeover.controller, "human");
    assert.ok(afterTakeover.epoch >= 2);
    assert.equal(afterTakeover.btnText, "▶ Resume Agent");
    assert.equal(afterTakeover.cursorActive, "false");

    await new Promise((r) => setTimeout(r, 2_200));
    const movesAfterPause = await page.$eval("#agent-cursor", (el) =>
      Number(el.getAttribute("data-moves") || "0"),
    );
    assert.equal(movesAfterPause, afterTakeover.movesAtTakeover);

    // 4. Exercise all 3 in-browser overlay scenario buttons + wheel scroll + toolbar nav.
    await page.click("#test-block-btn");
    await page.waitForFunction(() => document.getElementById("policy-banner")?.hidden === false, {
      timeout: 10_000,
    });
    const blockBanner = await page.evaluate(() => ({
      text: document.getElementById("policy-banner-text")?.textContent?.trim() || "",
      policyTelemetry: document.getElementById("policy-telemetry")?.textContent?.trim() || "",
    }));
    assert.match(blockBanner.text, /locked exclusively to aol\.com/);
    assert.match(blockBanner.policyTelemetry, /^1 blocked navs/);

    await page.click("#dismiss-policy-btn");
    assert.equal(await page.$eval("#policy-banner", (el) => el.hidden), true);

    await page.click("#load-news-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("browser-canvas")?.getAttribute("data-current-url") ===
        "https://www.aol.com/news/",
      { timeout: 35_000 },
    );

    const canvasCenter = await page.$eval("#browser-canvas", (el) => {
      const r = el.getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 3 };
    });
    await page.mouse.move(canvasCenter.x, canvasCenter.y);
    await page.mouse.wheel({ deltaY: 420 });
    await page.waitForFunction(
      () =>
        Number(document.getElementById("browser-canvas")?.getAttribute("data-scroll-y") || "0") > 0,
      { timeout: 15_000 },
    );

    await page.click("#card-reconnect-btn");
    await page.waitForFunction(
      () =>
        (document.getElementById("conn-badge")?.textContent || "").includes(
          "Reconnected (Tier 0) · SFO2",
        ),
      { timeout: 25_000 },
    );

    // 5. Hand control back via `▶ Resume Agent` and verify epoch advances again.
    const epochBeforeResume = await page.$eval("#take-control-btn", (el) =>
      Number(el.getAttribute("data-epoch") || "0"),
    );
    await page.click("#take-control-btn");
    await page.waitForFunction(
      (prevEpoch) => {
        const btn = document.getElementById("take-control-btn");
        return (
          btn?.getAttribute("data-controller") === "agent" &&
          Number(btn?.getAttribute("data-epoch") || "0") > prevEpoch
        );
      },
      { timeout: 15_000 },
      epochBeforeResume,
    );

    // 6. Verify live DigitalOcean status JSON reflects real agent actions & human takeovers.
    const statusRes = await fetch("https://64-225-124-165.sslip.io/showcase/status");
    assert.equal(statusRes.status, 200);
    const statusJson = await statusRes.json();
    assert.equal(statusJson.ok, true);
    assert.equal(statusJson.policy, "aol.com-only");
    assert.ok(statusJson.agentActions >= 1);
    assert.ok(statusJson.humanTakeovers >= 1);
    assert.ok(statusJson.blockedNavigations >= 1);
    assert.deepEqual(pageErrors, []);

    console.log("[aol-showcase:e2e] DEFAULT LANDING + AGENT CURSOR + TAKE CONTROL VERIFIED:", {
      dropletStatus: statusJson,
    });
  } finally {
    await browser.close();
    server.close();
    rmSync(userDataDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[aol-showcase:e2e] FAILED:", err);
  process.exit(1);
});
