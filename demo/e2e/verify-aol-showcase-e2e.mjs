#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Automated Chromium E2E test for the pastel GitHub Pages showcase (`dist-pages/showcase.html`)
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
    defaultViewport: { width: 1360, height: 1080 },
  });

  try {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on("pageerror", (err) => pageErrors.push(String(err?.message ?? err)));

    await page.goto(`${baseUrl}/showcase.html`, { waitUntil: "domcontentloaded" });

    // 1. Verify pastel soft-tone page vs stark high-contrast Parawing browser tokens.
    const styles = await page.evaluate(() => {
      const bodyBg = getComputedStyle(document.body).backgroundColor;
      const chassis = document.querySelector(".hc-browser");
      const cs = getComputedStyle(chassis);
      return {
        bodyBg,
        chassisBg: cs.backgroundColor,
        chassisColor: cs.color,
        chassisBorder: `${cs.borderTopWidth} ${cs.borderTopStyle} ${cs.borderTopColor}`,
      };
    });
    assert.equal(styles.bodyBg, "rgb(250, 246, 240)");
    assert.equal(styles.chassisBg, "rgb(10, 12, 16)");
    assert.equal(styles.chassisColor, "rgb(255, 255, 255)");
    assert.equal(styles.chassisBorder, "2px solid rgb(0, 0, 0)");

    // 2. Wait for live WSS connection + first Blitz-rendered frame of https://www.aol.com/.
    await page.waitForFunction(
      () => {
        const c = document.getElementById("browser-canvas");
        return Number(c?.getAttribute("data-frames") || "0") >= 1;
      },
      { timeout: 35_000 },
    );

    const initialRender = await page.evaluate(() => {
      const c = document.getElementById("browser-canvas");
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
        frames: Number(c.getAttribute("data-frames") || "0"),
        distinctSampledColors: distinctColors.size,
      };
    });
    assert.match(initialRender.badge, /Live · SFO2/);
    assert.equal(initialRender.currentUrl, "https://www.aol.com/");
    assert.ok(
      initialRender.distinctSampledColors > 12,
      `Expected rich live AOL pixels on canvas, sampled ${initialRender.distinctSampledColors} colors`,
    );

    if (screenshotOut) {
      await page.screenshot({ path: screenshotOut, fullPage: true });
    }

    // 3. Exercise non-AOL domain lock (`Try loading example.com`) + Dismiss button.
    await page.click("#test-block-btn");
    await page.waitForFunction(() => document.getElementById("policy-banner")?.hidden === false, {
      timeout: 10_000,
    });
    const blockBanner = await page.evaluate(() => ({
      text: document.getElementById("policy-banner-text")?.textContent?.trim() || "",
      policyTelemetry: document.getElementById("policy-telemetry")?.textContent?.trim() || "",
      stillOnUrl: document.getElementById("browser-canvas")?.getAttribute("data-current-url") || "",
    }));
    assert.match(blockBanner.text, /locked exclusively to aol\.com/);
    assert.match(blockBanner.policyTelemetry, /^1 blocked navs/);
    assert.equal(blockBanner.stillOnUrl, "https://www.aol.com/");

    await page.click("#dismiss-policy-btn");
    const bannerHidden = await page.$eval("#policy-banner", (el) => el.hidden);
    assert.equal(bannerHidden, true);

    // 4. Exercise wheel scrolling on the canvas and assert server-side scrollY advances.
    const canvasBox = await page.$eval("#browser-canvas", (el) => {
      const r = el.getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    });
    await page.mouse.move(canvasBox.x, canvasBox.y);
    await page.mouse.wheel({ deltaY: 420 });
    await page.waitForFunction(
      () =>
        Number(document.getElementById("browser-canvas")?.getAttribute("data-scroll-y") || "0") > 0,
      { timeout: 15_000 },
    );

    // 5. Exercise `Load aol.com/news/` card button + Back / Forward / Reload toolbar buttons.
    await page.click("#load-news-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("browser-canvas")?.getAttribute("data-current-url") ===
        "https://www.aol.com/news/",
      { timeout: 35_000 },
    );
    const backDisabledOnNews = await page.$eval("#back-btn", (el) => el.disabled);
    assert.equal(backDisabledOnNews, false);

    await page.click("#back-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("browser-canvas")?.getAttribute("data-current-url") ===
        "https://www.aol.com/",
      { timeout: 35_000 },
    );
    const forwardDisabledAfterBack = await page.$eval("#forward-btn", (el) => el.disabled);
    assert.equal(forwardDisabledAfterBack, false);

    await page.click("#forward-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("browser-canvas")?.getAttribute("data-current-url") ===
        "https://www.aol.com/news/",
      { timeout: 35_000 },
    );

    const framesBeforeReload = await page.$eval("#browser-canvas", (el) =>
      Number(el.getAttribute("data-frames") || "0"),
    );
    await page.click("#reload-btn");
    await page.waitForFunction(
      (prev) =>
        Number(document.getElementById("browser-canvas")?.getAttribute("data-frames") || "0") >
        prev,
      { timeout: 35_000 },
      framesBeforeReload,
    );

    // 6. Exercise Disconnect + Warm Tier 0 Reconnect against the DigitalOcean droplet.
    await page.click("#session-toggle-btn");
    await page.waitForFunction(
      () => document.getElementById("conn-badge")?.getAttribute("data-state") === "disconnected",
      { timeout: 10_000 },
    );
    await page.click("#session-toggle-btn");
    await page.waitForFunction(
      () =>
        (document.getElementById("conn-badge")?.textContent || "").includes(
          "Reconnected (Tier 0) · SFO2",
        ),
      { timeout: 20_000 },
    );

    // 7. Confirm remote DigitalOcean status endpoint reflects real rendered frames & blocked navs.
    const statusRes = await fetch("https://64-225-124-165.sslip.io/showcase/status");
    assert.equal(statusRes.status, 200);
    const statusJson = await statusRes.json();
    assert.equal(statusJson.ok, true);
    assert.equal(statusJson.policy, "aol.com-only");
    assert.ok(statusJson.framesRendered >= 4);
    assert.ok(statusJson.blockedNavigations >= 1);
    assert.deepEqual(pageErrors, []);

    console.log("[aol-showcase:e2e] ALL LIVE CONTROLS & DO DROPLET POLICY GATES VERIFIED:", {
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
