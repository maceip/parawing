#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Automated Chromium E2E test for `demo/chrome-extension/dist` against the live
// DigitalOcean `parawing-rust-host` droplet. Launches Chromium with `--load-extension`,
// boots Vivari's in-browser Node VM, and exercises every interactive UI control.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const DEMO_ROOT = resolve(REPO_ROOT, "demo");
const EXT_DIST = resolve(DEMO_ROOT, "chrome-extension/dist");
const STATE_PATH = resolve(DEMO_ROOT, ".droplet-state.json");

const rootReq = createRequire(resolve(REPO_ROOT, "package.json"));
const puppeteer = rootReq("puppeteer-core");

function findChromiumForTesting() {
  if (process.env.CHROME_FOR_TESTING_BIN && existsSync(process.env.CHROME_FOR_TESTING_BIN)) {
    return process.env.CHROME_FOR_TESTING_BIN;
  }
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
  const linuxPw = resolve(homedir(), ".cache/ms-playwright");
  if (existsSync(linuxPw)) {
    const dirs = readdirSync(linuxPw)
      .filter((d) => d.startsWith("chromium-"))
      .sort()
      .reverse();
    for (const dir of dirs) {
      const bin = resolve(linuxPw, dir, "chrome-linux/chrome");
      if (existsSync(bin)) return bin;
    }
  }
  throw new Error("Google Chrome for Testing binary not found; set CHROME_FOR_TESTING_BIN");
}

async function main() {
  assert.ok(
    existsSync(resolve(EXT_DIST, "manifest.json")),
    "Build demo/chrome-extension/dist first",
  );
  assert.ok(existsSync(STATE_PATH), "Missing demo/.droplet-state.json");
  const dropletState = JSON.parse(readFileSync(STATE_PATH, "utf8"));
  const executablePath = findChromiumForTesting();
  const userDataDir = mkdtempSync(join(tmpdir(), "parawing-vivari-ext-e2e-"));

  console.log(`[e2e] Launching Chromium (${executablePath}) with unpacked MV3 extension…`);
  const browser = await puppeteer.launch({
    executablePath,
    headless: "new",
    userDataDir,
    defaultViewport: { width: 1440, height: 900 },
    args: [
      `--disable-extensions-except=${EXT_DIST}`,
      `--load-extension=${EXT_DIST}`,
      "--no-first-run",
      "--no-default-browser-check",
    ],
  });

  try {
    // 1. Discover the real MV3 extension ID from its active service worker target.
    const swTarget = await browser.waitForTarget(
      (t) => t.type() === "service_worker" && t.url().endsWith("/background.js"),
      { timeout: 20_000 },
    );
    const extId = new URL(swTarget.url()).host;
    assert.ok(extId.length >= 16, `Unexpected extension ID: ${extId}`);
    console.log(`[e2e] Loaded MV3 extension ID: ${extId}`);

    // 2. Open a real HTTP tab so `[Co-Browse Active Tab]` has a live browser tab to read.
    const externalTab = await browser.newPage();
    await externalTab.goto(`${dropletState.httpsOrigin}/status`, { waitUntil: "domcontentloaded" });

    // 3. Open the Chrome Extension workbench (`chrome-extension://<id>/workbench.html`).
    const page = await browser.newPage();
    const pageErrors = [];
    page.on("pageerror", (err) => {
      const msg = err && typeof err === "object" && "message" in err ? err.message : String(err);
      console.error("[e2e:pageerror]", msg);
      pageErrors.push(msg);
    });
    page.on("console", (msg) => {
      if (msg.type() === "error" || msg.type() === "warn") {
        console.log(`[e2e:console:${msg.type()}]`, msg.text());
      }
    });

    const workbenchUrl = `chrome-extension://${extId}/workbench.html?origin=${encodeURIComponent(dropletState.httpsOrigin)}`;
    await page.goto(workbenchUrl, { waitUntil: "domcontentloaded" });

    const isolated = await page.evaluate(() => window.crossOriginIsolated);
    assert.equal(isolated, true, "Extension workbench page must be crossOriginIsolated");

    // 4. Wait for Vivari's in-browser Node.js VM to boot, instantiate scene_host.wasm,
    //    connect to the DigitalOcean droplet, and paint the initial KSC2 frame onto <canvas>.
    try {
      await page.waitForFunction(
        () => {
          const badge = document.getElementById("conn-badge");
          if (badge?.dataset.state === "error") return true;
          const canvas = document.getElementById("viewport-canvas");
          return (
            badge?.dataset.state === "connected" &&
            Number(canvas?.dataset.renderedFrames || "0") >= 1
          );
        },
        { timeout: 30_000 },
      );
      const badgeState = await page.$eval("#conn-badge", (el) => el.dataset.state);
      if (badgeState === "error") {
        throw new Error("Workbench entered error state during boot");
      }
    } catch (waitErr) {
      const diag = await page.evaluate(() => ({
        badge: document.getElementById("conn-badge")?.dataset.state,
        badgeText: document.getElementById("conn-badge")?.textContent,
        log: document.getElementById("event-log")?.textContent,
        frameSrc: document.getElementById("vivari-frame")?.getAttribute("src"),
      }));
      const frameTexts = await Promise.all(
        page.frames().map(async (f) => {
          try {
            return { url: f.url(), body: await f.evaluate(() => document.body?.innerText || "") };
          } catch (e) {
            return { url: f.url(), err: String(e) };
          }
        }),
      );
      console.error("[e2e:diag]", JSON.stringify({ diag, frameTexts }, null, 2));
      throw waitErr;
    }

    const initialMetrics = await page.evaluate(() => {
      const canvas = document.getElementById("viewport-canvas");
      const ctx2d = canvas.getContext("2d");
      const { data, width, height } = ctx2d.getImageData(0, 0, canvas.width, canvas.height);
      let nonZeroPixels = 0;
      let slateOrCardPixels = 0;
      for (let i = 0; i < data.length; i += 16) {
        const r = data[i];
        const g = data[i + 1];
        const b = data[i + 2];
        const a = data[i + 3];
        if (a > 0 && (r > 0 || g > 0 || b > 0)) nonZeroPixels += 1;
        if (b >= 30 && g >= 15) slateOrCardPixels += 1;
      }
      return {
        vivari: document.getElementById("metric-vivari")?.textContent?.trim(),
        host: document.getElementById("metric-host")?.textContent?.trim(),
        capsule: document.getElementById("metric-capsule")?.textContent?.trim(),
        frames: Number(document.getElementById("metric-frames")?.textContent || "0"),
        pid: document.getElementById("vivari-pid")?.textContent?.trim(),
        width,
        height,
        nonZeroPixels,
        slateOrCardPixels,
      };
    });
    console.log("[e2e] Initial Vivari + DigitalOcean state:", initialMetrics);
    assert.match(initialMetrics.vivari, /^Node v\d+/);
    assert.match(initialMetrics.host, /^Parawing-Rust-Host\/0\.1\./);
    assert.ok(initialMetrics.frames >= 1);
    assert.ok(
      initialMetrics.nonZeroPixels > 5000,
      "Expected non-blank client-composited KSC2 canvas",
    );
    assert.ok(initialMetrics.slateOrCardPixels > 1000);

    // 5. Exercise Agent Handoff (`#handback-btn` -> StaleEpochFenced -> `#take-control-btn`)
    //    and Deno V8 sub-isolate JS evaluation on the DigitalOcean droplet.
    const initialEpochText = await page.$eval("#epoch-badge", (el) => el.textContent || "");
    assert.match(initialEpochText, /^Epoch \d+ · human-vivari$/);

    await page.click("#handback-btn");
    await page.waitForFunction(
      () => {
        const badge = document.getElementById("epoch-badge")?.textContent || "";
        const takeBtn = document.getElementById("take-control-btn");
        return badge.endsWith("· agent-alpha") && Boolean(takeBtn && !takeBtn.disabled);
      },
      { timeout: 15_000 },
    );

    await page.click("#eval-btn");
    await page.waitForFunction(
      () => (document.getElementById("eval-output")?.textContent || "").includes("epoch fenced"),
      { timeout: 15_000 },
    );

    await page.click("#take-control-btn");
    await page.waitForFunction(
      () => {
        const badge = document.getElementById("epoch-badge")?.textContent || "";
        const handbackBtn = document.getElementById("handback-btn");
        return badge.endsWith("· human-vivari") && Boolean(handbackBtn && !handbackBtn.disabled);
      },
      { timeout: 15_000 },
    );

    await page.click("#eval-btn");
    await page.waitForFunction(
      () => document.getElementById("eval-output")?.textContent === '{"ticks":1}',
      { timeout: 15_000 },
    );
    await page.click("#eval-btn");
    await page.waitForFunction(
      () => document.getElementById("eval-output")?.textContent === '{"ticks":2}',
      { timeout: 15_000 },
    );

    // 6. Exercise 0-RTT client-side `scene_host.wasm` canvas hit-testing.
    await page.click("#viewport-canvas", { offset: { x: 120, y: 90 } });
    await page.waitForFunction(
      () => {
        const text = document.getElementById("hit-readout")?.textContent || "";
        return text.startsWith("node=") || text.startsWith("miss @");
      },
      { timeout: 10_000 },
    );

    // 7. Exercise Capsule Attestation & Lease, Freeze on DigitalOcean, and Thaw!
    await page.click("#attest-btn");
    await page.waitForFunction(
      () => (document.getElementById("lease-badge")?.textContent || "").startsWith("vivari-lease-"),
      { timeout: 15_000 },
    );

    await page.click("#freeze-btn");
    await page.waitForFunction(
      () =>
        !document.getElementById("thaw-btn")?.disabled &&
        (document.getElementById("continuity-readout")?.textContent || "").startsWith("Frozen"),
      { timeout: 25_000 },
    );

    await page.click("#thaw-btn");
    await page.waitForFunction(
      () => (document.getElementById("continuity-readout")?.textContent || "").startsWith("Thawed"),
      { timeout: 25_000 },
    );

    // 8. Exercise Remote URL Navigation, Co-Browse Active Tab, and Welcome Scene.
    await page.click("#nav-btn");
    await page.waitForFunction(
      () => (document.getElementById("page-title")?.textContent || "").includes("Example Domain"),
      { timeout: 20_000 },
    );

    await page.click("#active-tab-btn");
    await page.waitForFunction(
      (sslipHost) =>
        (document.getElementById("viewport-url")?.textContent || "").includes(sslipHost),
      { timeout: 20_000 },
      dropletState.sslipHost,
    );

    await page.click("#welcome-btn");
    await page.waitForFunction(
      () => document.getElementById("viewport-url")?.textContent === "parawing://welcome",
      { timeout: 15_000 },
    );

    // 9. Exercise both draggable split-pane resizers, Clear log, and Reconnect button.
    const splitterBox = await page.$eval("#splitter-left", (el) => {
      const r = el.getBoundingClientRect();
      return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
    });
    await page.mouse.move(splitterBox.x, splitterBox.y);
    await page.mouse.down();
    await page.mouse.move(splitterBox.x + 44, splitterBox.y);
    await page.mouse.up();
    const resizedWidth = await page.evaluate(() =>
      document.documentElement.style.getPropertyValue("--left-w"),
    );
    assert.equal(resizedWidth, "340px");

    const rightBox = await page.$eval("#splitter-right", (el) => {
      const r = el.getBoundingClientRect();
      return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
    });
    await page.mouse.move(rightBox.x, rightBox.y);
    await page.mouse.down();
    await page.mouse.move(rightBox.x - 30, rightBox.y);
    await page.mouse.up();
    const resizedRight = await page.evaluate(() =>
      document.documentElement.style.getPropertyValue("--right-w"),
    );
    assert.equal(resizedRight, "350px");

    await page.click("#clear-log-btn");
    const clearedLog = await page.$eval("#event-log", (el) => el.textContent);
    assert.equal(clearedLog, "");

    const framesBeforeReconnect = await page.$eval("#viewport-canvas", (el) =>
      Number(el.dataset.renderedFrames || "0"),
    );
    await page.click("#connect-btn");
    await page.waitForFunction(
      (prevFrames) => {
        const badge = document.getElementById("conn-badge");
        const canvas = document.getElementById("viewport-canvas");
        return (
          badge?.dataset.state === "connected" &&
          Number(canvas?.dataset.renderedFrames || "0") > prevFrames
        );
      },
      { timeout: 30_000 },
      framesBeforeReconnect,
    );
    const persistedOrigin = await page.evaluate(async () => {
      const stored = await chrome.storage.local.get(["dropletOrigin"]);
      return stored.dropletOrigin;
    });
    assert.equal(persistedOrigin, dropletState.httpsOrigin);
    assert.deepEqual(pageErrors, []);

    const finalState = await page.evaluate(() => ({
      continuity: document.getElementById("continuity-readout")?.textContent,
      frames: Number(document.getElementById("metric-frames")?.textContent || "0"),
      bytes: document.getElementById("metric-bytes")?.textContent,
      tiles: document.getElementById("metric-tiles")?.textContent,
    }));
    console.log("[e2e] ALL CONTROLS VERIFIED END-TO-END:", {
      extId,
      droplet: dropletState.httpsOrigin,
      ...finalState,
    });
  } finally {
    await browser.close();
    rmSync(userDataDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[e2e] FAILED:", err);
  process.exit(1);
});
