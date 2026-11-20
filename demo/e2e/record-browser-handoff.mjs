#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Records `.github/assets/agent_handoff_demo.gif` from the live GitHub Pages co-browser demo
// connected over WSS to the AOL-locked DigitalOcean SFO2 droplet (`64-225-124-165.sslip.io`).

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { extname, join, resolve } from "node:path";
import { buildSecurityPages } from "../../scripts/build-security-pages.mjs";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const OUT_GIF = resolve(REPO_ROOT, ".github/assets/agent_handoff_demo.gif");
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

function findFfmpeg() {
  for (const candidate of ["/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg", "ffmpeg"]) {
    try {
      execFileSync(candidate, ["-version"], { stdio: "ignore" });
      return candidate;
    } catch {}
  }
  throw new Error("ffmpeg binary not found");
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const ffmpegBin = findFfmpeg();
  const buildInfo = buildSecurityPages();
  const { server, baseUrl } = await serveStaticDir(buildInfo.outDir);
  const userDataDir = mkdtempSync(join(tmpdir(), "parawing-browser-gif-profile-"));
  const frameDir = mkdtempSync(join(tmpdir(), "parawing-browser-gif-frames-"));

  const browser = await puppeteer.launch({
    executablePath: findBrowserBin(),
    headless: "new",
    userDataDir,
    defaultViewport: { width: 1340, height: 1120, deviceScaleFactor: 1 },
  });

  try {
    const page = await browser.newPage();
    await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });

    // Wait for initial live AOL frame on the canvas before starting capture.
    await page.waitForFunction(
      () =>
        Number(document.getElementById("browser-canvas")?.getAttribute("data-frames") || "0") >= 1,
      { timeout: 35_000 },
    );

    const clip = await page.evaluate(() => {
      const el = document.querySelector(".hc-browser");
      const r = el.getBoundingClientRect();
      const pad = 18;
      const x = Math.max(0, Math.floor(r.left - pad));
      const y = Math.max(0, Math.floor(r.top - pad));
      const width = Math.min(window.innerWidth - x, Math.ceil(r.width + pad * 2));
      const height = Math.min(window.innerHeight - y, Math.ceil(r.height + pad * 2));
      return { x, y, width: width - (width % 2), height: height - (height % 2) };
    });

    // Visible emerald ring for human clicks so viewers distinguish human clicks from agent pointer.
    await page.evaluate(() => {
      const dot = document.createElement("div");
      dot.id = "demo-human-click";
      dot.style.cssText =
        "position:fixed;left:0;top:0;width:30px;height:30px;margin:-15px 0 0 -15px;" +
        "border-radius:9999px;border:3px solid #34d399;background:rgba(52,211,153,0.28);" +
        "pointer-events:none;z-index:9999;opacity:0;transition:opacity 180ms ease,transform 220ms ease;";
      document.body.appendChild(dot);
      window.__showHumanRing = (x, y, on) => {
        dot.style.left = `${x}px`;
        dot.style.top = `${y}px`;
        dot.style.opacity = on ? "1" : "0";
        dot.style.transform = on ? "scale(1)" : "scale(1.4)";
      };
    });

    const captured = [];
    let frameIdx = 0;
    const snap = async (durationSec) => {
      const file = join(frameDir, `f-${String(frameIdx).padStart(4, "0")}.png`);
      frameIdx += 1;
      await page.screenshot({ path: file, clip });
      captured.push({ file, durationSec });
    };

    const snapBurst = async (count, intervalMs, frameDurationSec = 0.08) => {
      for (let i = 0; i < count; i += 1) {
        await snap(frameDurationSec);
        if (i + 1 < count) await sleep(intervalMs);
      }
    };

    const humanClickWithBurst = async (selector) => {
      const pt = await page.$eval(selector, (el) => {
        const r = el.getBoundingClientRect();
        return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) };
      });
      await page.evaluate(({ x, y }) => window.__showHumanRing(x, y, true), pt);
      await snap(0.18);
      await page.mouse.click(pt.x, pt.y);
      await snap(0.14);
      await page.evaluate(({ x, y }) => window.__showHumanRing(x, y, false), pt);
    };

    // Opening beat on live https://www.aol.com/ before agent's first glide.
    await snap(0.55);

    // Act 1: Capture smooth burst as autonomous agent glides its mouse and clicks a real AOL story!
    await page.waitForFunction(
      () => Number(document.getElementById("agent-cursor")?.getAttribute("data-moves") || "0") >= 1,
      { timeout: 20_000 },
    );
    await snapBurst(10, 85, 0.085);

    await page.waitForFunction(
      () =>
        Number(document.getElementById("agent-cursor")?.getAttribute("data-clicks") || "0") >= 1 &&
        Number(document.getElementById("browser-canvas")?.getAttribute("data-frames") || "0") >= 2,
      { timeout: 35_000 },
    );
    await snap(0.85);

    // Wait for agent's second casual action (scrolling down the AOL article) and capture burst!
    const movesAfterFirstClick = await page.$eval("#agent-cursor", (el) =>
      Number(el.getAttribute("data-moves") || "0"),
    );
    const framesAfterFirstClick = await page.$eval("#browser-canvas", (el) =>
      Number(el.getAttribute("data-frames") || "0"),
    );
    await page.waitForFunction(
      (prevMoves) =>
        Number(document.getElementById("agent-cursor")?.getAttribute("data-moves") || "0") >
        prevMoves,
      { timeout: 20_000 },
      movesAfterFirstClick,
    );
    await snapBurst(7, 85, 0.085);
    await page.waitForFunction(
      (prevFrames) =>
        Number(document.getElementById("browser-canvas")?.getAttribute("data-frames") || "0") >
        prevFrames,
      { timeout: 20_000 },
      framesAfterFirstClick,
    );
    await snap(0.85);

    // Act 2: Human clicks `■ Take Control` -> Epoch #2 human takeover!
    await humanClickWithBurst("#take-control-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("take-control-btn")?.getAttribute("data-controller") === "human",
      { timeout: 15_000 },
    );
    await snap(0.95);

    // Human tests `Try example.com` -> server-side policy rejection banner!
    await humanClickWithBurst("#test-block-btn");
    await page.waitForFunction(() => document.getElementById("policy-banner")?.hidden === false, {
      timeout: 10_000,
    });
    await snap(1.05);

    // Human navigates to `aol.com/news/`.
    await humanClickWithBurst("#load-news-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("browser-canvas")?.getAttribute("data-current-url") ===
        "https://www.aol.com/news/",
      { timeout: 35_000 },
    );
    await snap(0.9);

    // Act 3: Human clicks `▶ Resume Agent` -> Epoch #3 autonomous agent resumes on aol.com/news/!
    const movesBeforeResume = await page.$eval("#agent-cursor", (el) =>
      Number(el.getAttribute("data-moves") || "0"),
    );
    await humanClickWithBurst("#take-control-btn");
    await page.waitForFunction(
      () =>
        document.getElementById("take-control-btn")?.getAttribute("data-controller") === "agent",
      { timeout: 15_000 },
    );
    await snap(0.45);
    await page.waitForFunction(
      (prevMoves) =>
        Number(document.getElementById("agent-cursor")?.getAttribute("data-moves") || "0") >
        prevMoves,
      { timeout: 20_000 },
      movesBeforeResume,
    );
    await snapBurst(8, 85, 0.085);
    await snap(1.1);

    const concatLines = ["ffconcat version 1.0"];
    for (const item of captured) {
      concatLines.push(`file '${item.file}'`);
      concatLines.push(`duration ${item.durationSec.toFixed(3)}`);
    }
    concatLines.push(`file '${captured[captured.length - 1].file}'`);
    const concatFile = resolve(frameDir, "frames.ffconcat");
    writeFileSync(concatFile, `${concatLines.join("\n")}\n`);

    mkdirSync(resolve(REPO_ROOT, ".github/assets"), { recursive: true });
    const vf =
      "fps=12,scale=1040:-1:flags=lanczos,split[s0][s1];" +
      "[s0]palettegen=max_colors=256:stats_mode=diff[p];" +
      "[s1][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle";
    execFileSync(
      ffmpegBin,
      ["-y", "-f", "concat", "-safe", "0", "-i", concatFile, "-vf", vf, "-loop", "0", OUT_GIF],
      { stdio: "inherit" },
    );

    const gifBytes = statSync(OUT_GIF).size;
    assert.ok(gifBytes > 80_000, `Unexpectedly small GIF (${gifBytes} B)`);
    console.log(
      `[record:browser-handoff] Encoded ${OUT_GIF} (${(gifBytes / 1024).toFixed(1)} KiB across ${captured.length} live frames)`,
    );
  } finally {
    await browser.close();
    server.close();
    rmSync(userDataDir, { recursive: true, force: true });
    rmSync(frameDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[record:browser-handoff] FAILED:", err);
  process.exit(1);
});
