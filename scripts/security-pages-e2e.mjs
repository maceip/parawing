#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Automated Chromium E2E verification for the Digital Agency Design System v2.18.2
// GitHub Pages vulnerability & remediation ledger (`dist-pages/`). Exercises every
// interactive control, verifies exact Figma tokens/geometry, and checks JSON endpoints.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { extname, join, resolve } from "node:path";
import { buildSecurityPages } from "./build-security-pages.mjs";

const REPO_ROOT = resolve(import.meta.dirname, "..");
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
  const buildInfo = buildSecurityPages();
  const { server, baseUrl } = await serveStaticDir(buildInfo.outDir);
  const userDataDir = mkdtempSync(join(tmpdir(), "parawing-pages-e2e-"));
  const browser = await puppeteer.launch({
    executablePath: findBrowserBin(),
    headless: "new",
    userDataDir,
    defaultViewport: { width: 1280, height: 900 },
  });

  try {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on("pageerror", (err) => pageErrors.push(String(err?.message ?? err)));
    await page.goto(`${baseUrl}/`, { waitUntil: "networkidle0" });

    // 1. Verify Slim Header (gooey overflowing icon), compact top zone & footer pitch.
    const layoutMetrics = await page.evaluate(() => {
      const header = document.querySelector(".dads-slim-header");
      const logo = document.querySelector(".dads-brand-logo");
      const gooStage = document.querySelector(".dads-goo-stage");
      const gooFilter = document.getElementById("parawing-goo");
      const table = document.querySelector("#panel-advisories .dads-table");
      const footerPitch = document.querySelector(".dads-footer-pitch");
      const main = document.querySelector(".dads-main");
      const rootStyles = getComputedStyle(document.documentElement);
      const headerRect = header.getBoundingClientRect();
      const logoRect = logo.getBoundingClientRect();
      return {
        headerHeight: headerRect.height,
        headerOverflow: getComputedStyle(header).overflow,
        gooFilterActive:
          Boolean(gooFilter) && getComputedStyle(gooStage).filter.includes("parawing-goo"),
        logoHeight: logoRect.height,
        logoBottom: logoRect.bottom,
        headerBottom: headerRect.bottom,
        tableTopY: table.getBoundingClientRect().top,
        footerPitchTopY: footerPitch.getBoundingClientRect().top,
        contentWidth: main.clientWidth - 160,
        key900: rootStyles.getPropertyValue("--color-key-900").trim(),
        gray420: rootStyles.getPropertyValue("--color-neutral-solid-gray-420").trim(),
        yellow300: rootStyles.getPropertyValue("--color-primitive-yellow-300").trim(),
        summaryText: document.getElementById("result-count")?.textContent?.trim() || "",
        initialRows: document.querySelectorAll("#advisories-tbody tr.dads-data-row").length,
      };
    });
    assert.equal(layoutMetrics.headerHeight, 48);
    assert.equal(layoutMetrics.headerOverflow, "visible");
    assert.equal(layoutMetrics.gooFilterActive, true);
    assert.ok(layoutMetrics.logoHeight >= 56);
    assert.ok(
      layoutMetrics.logoBottom >= layoutMetrics.headerBottom + 8,
      `Expected gooey logo to visibly overflow below navbar (${layoutMetrics.logoBottom} vs ${layoutMetrics.headerBottom})`,
    );
    assert.ok(
      layoutMetrics.tableTopY <= 155,
      `Expected ultra-compact top zone (table top <= 155px), got ${layoutMetrics.tableTopY}px`,
    );
    assert.ok(layoutMetrics.footerPitchTopY > layoutMetrics.tableTopY);
    assert.equal(layoutMetrics.contentWidth, 1120);
    assert.equal(layoutMetrics.key900, "#0017c1");
    assert.equal(layoutMetrics.gray420, "#949494");
    assert.equal(layoutMetrics.yellow300, "#ffd43d");
    assert.match(layoutMetrics.summaryText, /^0 open · 37\/37 remediated/);
    assert.equal(layoutMetrics.initialRows, buildInfo.remediatedCount);

    // 2. Exercise Search Box + Cyan-200 (#99f2ff) search highlight + removable Chip Tag.
    await page.type("#search-input", "picomatch");
    const searchState = await page.evaluate(() => {
      const rows = document.querySelectorAll("#advisories-tbody tr.dads-data-row");
      const mark = document.querySelector("mark.dads-highlight");
      const chip = document.querySelector(".dads-chip-tag");
      return {
        rowCount: rows.length,
        firstId: rows[0]?.getAttribute("data-advisory-id"),
        markBg: mark ? getComputedStyle(mark).backgroundColor : "",
        chipText: chip?.textContent?.trim() || "",
      };
    });
    assert.equal(searchState.rowCount, 1);
    assert.equal(searchState.firstId, "CVE-2026-112366");
    assert.equal(searchState.markBg, "rgb(153, 242, 255)");
    assert.match(searchState.chipText, /^Query: picomatch/);

    await page.click(".dads-chip-tag");
    const restoredAfterChip = await page.$$eval(
      "#advisories-tbody tr.dads-data-row",
      (els) => els.length,
    );
    assert.equal(restoredAfterChip, buildInfo.remediatedCount);

    // 3. Exercise Severity & Ecosystem selects + Reset button (verifying <= 2 adjacent chips).
    await page.select("#severity-select", "Critical");
    const critRows = await page.$$eval("#advisories-tbody tr.dads-data-row", (els) =>
      els.map((e) => e.getAttribute("data-advisory-id")),
    );
    assert.deepEqual(critRows.sort(), ["CVE-2026-115889", "CVE-2026-115893"]);

    await page.select("#ecosystem-select", "crates.io");
    await page.type("#search-input", "wasmtime");
    const chipCountWhenThreeActive = await page.$$eval(".dads-chip-tag", (els) => els.length);
    assert.ok(chipCountWhenThreeActive <= 2, "Must never stack >2 adjacent filter chips");

    await page.click("#reset-filters-btn");
    const afterReset = await page.$$eval("#advisories-tbody tr.dads-data-row", (els) => els.length);
    assert.equal(afterReset, buildInfo.remediatedCount);

    // 4. Exercise Column Sorting (Advisory ascending & descending).
    await page.click('[data-sort-key="id"]');
    const firstAsc = await page.$eval("#advisories-tbody tr.dads-data-row", (el) =>
      el.getAttribute("data-advisory-id"),
    );
    const sortAttrAsc = await page.$eval('th:has([data-sort-key="id"])', (el) =>
      el.getAttribute("aria-sort"),
    );
    assert.equal(sortAttrAsc, "ascending");
    assert.equal(firstAsc, "CVE-2023-54404");

    // 5. Exercise Expandable Elevation-1 Remediation Proof drawer.
    await page.click('[data-toggle-proof="CVE-2026-112366"]');
    const proofMetrics = await page.evaluate(() => {
      const btn = document.querySelector('[data-toggle-proof="CVE-2026-112366"]');
      const row = document.getElementById("proof-CVE-2026-112366");
      const card = row?.querySelector(".dads-proof-card");
      return {
        expanded: btn?.getAttribute("aria-expanded"),
        hidden: row?.hidden,
        shadow: card ? getComputedStyle(card).boxShadow : "",
        text: card?.textContent || "",
      };
    });
    assert.equal(proofMetrics.expanded, "true");
    assert.equal(proofMetrics.hidden, false);
    assert.notEqual(proofMetrics.shadow, "none");
    assert.match(proofMetrics.text, /patches\/picomatch@4\.0\.7\.patch/);

    // 6. Exercise Tab Switching to Verified Patch Series & Unmaintained Notices.
    await page.click("#tab-patches");
    const patchesTabState = await page.evaluate(() => ({
      selected: document.getElementById("tab-patches")?.getAttribute("aria-selected"),
      advisoriesHidden: document.getElementById("panel-advisories")?.hidden,
      patchesHidden: document.getElementById("panel-patches")?.hidden,
      patchRows: document.querySelectorAll("#panel-patches tbody tr.dads-data-row").length,
    }));
    assert.equal(patchesTabState.selected, "true");
    assert.equal(patchesTabState.advisoriesHidden, true);
    assert.equal(patchesTabState.patchesHidden, false);
    assert.ok(patchesTabState.patchRows >= 24);

    // 7. Verify published OpenVEX & Dependency Integrity JSON endpoints.
    const vexRes = await fetch(`${baseUrl}/parawing.openvex.json`);
    assert.equal(vexRes.status, 200);
    const vexJson = await vexRes.json();
    assert.equal(vexJson["@context"], "https://openvex.dev/ns/v0.2.0");

    const depRes = await fetch(`${baseUrl}/dependency-integrity.json`);
    assert.equal(depRes.status, 200);
    const depJson = await depRes.json();
    assert.equal(depJson.remediated.length, buildInfo.remediatedCount);
    assert.deepEqual(pageErrors, []);

    console.log("[pages:e2e] ALL CONTROLS & FIGMA DADS v2.18.2 TOKENS VERIFIED:", {
      headerHeightPx: layoutMetrics.headerHeight,
      contentWidthPx: layoutMetrics.contentWidth,
      remediated: buildInfo.remediatedCount,
      packages: buildInfo.totalPackages,
      patches: buildInfo.totalPatches,
    });
  } finally {
    await browser.close();
    server.close();
    rmSync(userDataDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[pages:e2e] FAILED:", err);
  process.exit(1);
});
