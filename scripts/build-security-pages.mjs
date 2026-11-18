#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deterministically verifies Parawing's locked dependency graph, SHA-256 patch series, and
// remediated vulnerability ledger, then builds the static GitHub Pages site (`dist-pages/`).

import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { extractDependencyInventory } from "./deps/inventory.mjs";
import { verifyOfflineAdvisoryLock } from "./deps/osv-scanner.mjs";
import { loadPatchesManifest, verifyAllPatchesAndOverrides } from "./deps/patch-verifier.mjs";
import { buildOpenVexDocument } from "./deps/reporter.mjs";

const CANONICAL_URL = "https://maceip.github.io/parawing/";
const REPO_URL = "https://github.com/maceip/parawing";
const SEVERITY_RANK = { Critical: 5, High: 4, Soundness: 3, Moderate: 2, Low: 1 };

function resolveRootDir(explicit) {
  if (explicit) return resolve(explicit);
  if (process.env.BUILD_WORKSPACE_DIRECTORY) return resolve(process.env.BUILD_WORKSPACE_DIRECTORY);
  return resolve(import.meta.dirname, "..");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityChipClass(severity) {
  if (severity === "Critical" || severity === "High") return "dads-chip-label dads-chip-red";
  if (severity === "Soundness" || severity === "Moderate")
    return "dads-chip-label dads-chip-orange";
  return "dads-chip-label dads-chip-yellow";
}

function verifyRemediatedLedger(rootDir, ledger) {
  const errors = [];
  if (!Array.isArray(ledger.remediated) || ledger.remediated.length === 0) {
    errors.push("deps/remediated-advisories.json must contain non-empty remediated array");
    return errors;
  }
  const seen = new Set();
  for (const item of ledger.remediated) {
    if (seen.has(item.id)) errors.push(`Duplicate remediated advisory ID: ${item.id}`);
    seen.add(item.id);
    if (item.patchPath) {
      const abs = join(rootDir, item.patchPath);
      if (!existsSync(abs)) {
        errors.push(`Missing patch file referenced by ${item.id}: ${item.patchPath}`);
      } else {
        const digest = createHash("sha256").update(readFileSync(abs)).digest("hex");
        if (digest !== item.patchSha256) {
          errors.push(`SHA-256 mismatch on ${item.patchPath} for ${item.id}`);
        }
      }
    }
  }
  return errors;
}

function renderInitialAdvisoryRows(items) {
  const sorted = [...items].sort((a, b) => {
    const diff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
    return diff !== 0 ? diff : b.commitDate.localeCompare(a.commitDate);
  });
  return sorted
    .map((item) => {
      const detailId = `proof-${item.id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
      const commitUrl = `${REPO_URL}/commit/${encodeURIComponent(item.commitSha)}`;
      const aliasesText =
        item.aliases && item.aliases.length > 0 ? item.aliases.join(", ") : "None";
      const patchInfo = item.patchPath
        ? `<span class="dads-mono">${escapeHtml(item.patchPath)}</span> (sha256: <span class="dads-mono">${escapeHtml(item.patchSha256.slice(0, 16))}…</span>)`
        : `Lockfile floor enforced at <span class="dads-mono">${escapeHtml(item.remediatedVersion)}</span>`;
      return `
        <tr class="dads-data-row" data-advisory-id="${escapeHtml(item.id)}" data-expanded="false">
          <td class="dads-mono"><a href="${escapeHtml(item.advisoryUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.id)}</a></td>
          <td class="dads-mono">${escapeHtml(`${item.package}@${item.remediatedVersion}`)}</td>
          <td>${escapeHtml(item.ecosystem)}</td>
          <td><span class="${severityChipClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
          <td><span class="dads-chip-label dads-chip-green">Remediated</span></td>
          <td>${escapeHtml(item.mechanism)} · <a class="dads-mono" href="${commitUrl}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.commitSha)}</a></td>
          <td>
            <button
              type="button"
              class="dads-btn dads-btn-outlined dads-btn-xs"
              data-toggle-proof="${escapeHtml(item.id)}"
              aria-expanded="false"
              aria-controls="${detailId}"
            >Proof</button>
          </td>
        </tr>
        <tr id="${detailId}" class="dads-detail-row" hidden>
          <td colspan="7">
            <div class="dads-proof-card">
              <dl class="dads-proof-grid">
                <div>
                  <dt>Summary</dt>
                  <dd>${escapeHtml(item.summary)}</dd>
                </div>
                <div>
                  <dt>Vulnerable Range → Remediated Version</dt>
                  <dd class="dads-mono">${escapeHtml(item.vulnerableRange)} → ${escapeHtml(item.remediatedVersion)} (${escapeHtml(item.commitDate)})</dd>
                </div>
                <div>
                  <dt>Cryptographic / Lockfile Proof</dt>
                  <dd>${patchInfo}</dd>
                </div>
                <div>
                  <dt>Aliases &amp; Verification Gates</dt>
                  <dd class="dads-mono">${escapeHtml(aliasesText)} · ${(item.verificationTargets || []).map(escapeHtml).join(", ")}</dd>
                </div>
              </dl>
            </div>
          </td>
        </tr>`;
    })
    .join("");
}

function renderPatchSeriesRows(manifest) {
  const cargoRows = (manifest.cargoPatches || []).map((entry) => {
    const mit =
      (entry.mitigates || []).length > 0 ? entry.mitigates.join(", ") : "Engine spec / hardening";
    const targets = (entry.verificationTargets || []).join(", ");
    return `
      <tr class="dads-data-row">
        <td class="dads-mono"><a href="${escapeHtml(entry.upstreamRepo)}" target="_blank" rel="noopener noreferrer">${escapeHtml(entry.crate)}@${escapeHtml(entry.version)}</a></td>
        <td>crates.io (vendored)</td>
        <td class="dads-mono">${entry.patches.length}</td>
        <td class="dads-mono">${escapeHtml(entry.seriesSha8)}</td>
        <td class="dads-mono">${escapeHtml(mit)}</td>
        <td class="dads-mono">${escapeHtml(targets)}</td>
      </tr>`;
  });
  const npmRows = (manifest.npmPatches || []).map((entry) => {
    const mit = (entry.mitigates || []).join(", ");
    const targets = (entry.verificationTargets || []).join(", ");
    return `
      <tr class="dads-data-row">
        <td class="dads-mono">${escapeHtml(entry.package)}@${escapeHtml(entry.version)}</td>
        <td>npm (patchedDependencies)</td>
        <td class="dads-mono">1</td>
        <td class="dads-mono">${escapeHtml(entry.sha256.slice(0, 8))}</td>
        <td class="dads-mono">${escapeHtml(mit)}</td>
        <td class="dads-mono">${escapeHtml(targets)}</td>
      </tr>`;
  });
  return [...cargoRows, ...npmRows].join("");
}

function renderUnmaintainedRows(manifest) {
  return (manifest.trackedUnmaintained || [])
    .map(
      (item) => `
      <tr class="dads-data-row">
        <td class="dads-mono"><a href="https://osv.dev/vulnerability/${escapeHtml(item.advisoryId)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.advisoryId)}</a></td>
        <td class="dads-mono">${escapeHtml(item.package)}</td>
        <td><span class="dads-chip-label dads-chip-gray">Not Affected</span></td>
        <td>${escapeHtml(item.reason)}</td>
        <td class="dads-mono">${escapeHtml(item.reviewBy.slice(0, 10))}</td>
      </tr>`,
    )
    .join("");
}

/** @param {{ rootDir?: string, outDir?: string }} [options] @returns {{ outDir: string, remediatedCount: number, totalPackages: number, totalPatches: number }} */
export function buildSecurityPages(options = {}) {
  const rootDir = resolveRootDir(options.rootDir);
  const outDir = resolve(options.outDir || join(rootDir, "dist-pages"));

  const version = readFileSync(join(rootDir, "VERSION"), "utf8").trim();
  const inventory = extractDependencyInventory(rootDir);
  const manifest = loadPatchesManifest(rootDir);
  const patchCheck = verifyAllPatchesAndOverrides(rootDir, inventory.packages);
  const advisoryCheck = verifyOfflineAdvisoryLock(rootDir, inventory, manifest);
  const remediatedDoc = JSON.parse(
    readFileSync(join(rootDir, "deps/remediated-advisories.json"), "utf8"),
  );
  const ledgerErrors = verifyRemediatedLedger(rootDir, remediatedDoc);

  const allErrors = [...patchCheck.errors, ...advisoryCheck.errors, ...ledgerErrors];
  if (allErrors.length > 0) {
    throw new Error(`Security Pages gate failed:\n  - ${allErrors.join("\n  - ")}`);
  }

  const fixedTimestamp = `${remediatedDoc.remediated[0].commitDate}T00:00:00Z`;
  const openVex = buildOpenVexDocument({
    version,
    created: fixedTimestamp,
    resolvedAdvisories: advisoryCheck.resolved || [],
  });

  const patchSeriesCount =
    (manifest.cargoPatches?.length || 0) + (manifest.npmPatches?.length || 0);
  const clientPayload = {
    version,
    repoUrl: REPO_URL,
    inventoryDigest: inventory.digest,
    counts: inventory.counts,
    patchSummary: patchCheck.summary,
    remediated: remediatedDoc.remediated,
  };

  const title = "Parawing — Vulnerability Discovery & Remediation Ledger";
  const description =
    "Attested Rust/Blitz, Deno V8, and CRIU delegated co-browser engine: deterministic OSV, OpenVEX, and SHA-256 patch remediation ledger.";
  const ogImage = `${CANONICAL_URL}favicon.png`;

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escapeHtml(title)}</title>
    <meta name="description" content="${escapeHtml(description)}" />
    <meta name="robots" content="index, follow" />
    <meta name="theme-color" content="#0017c1" />
    <link rel="canonical" href="${CANONICAL_URL}" />
    <link rel="icon" type="image/png" href="./favicon.png" />
    <meta property="og:type" content="website" />
    <meta property="og:title" content="${escapeHtml(title)}" />
    <meta property="og:description" content="${escapeHtml(description)}" />
    <meta property="og:url" content="${CANONICAL_URL}" />
    <meta property="og:image" content="${ogImage}" />
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content="${escapeHtml(title)}" />
    <meta name="twitter:description" content="${escapeHtml(description)}" />
    <meta name="twitter:image" content="${ogImage}" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;700&family=Noto+Sans+Mono:wght@400;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="./styles.css" />
  </head>
  <body>
    <header class="dads-slim-header">
      <div class="dads-shell dads-slim-header-inner">
        <a class="dads-brand" href="${REPO_URL}">
          <span class="dads-brand-logo-wrap" aria-hidden="true">
            <img class="dads-brand-logo" src="./favicon.png" width="56" height="56" alt="" />
          </span>
          <span>Parawing v${escapeHtml(version)}</span>
        </a>
        <div class="dads-header-tabs" role="tablist" aria-label="Security ledger views">
          <button
            type="button"
            id="tab-advisories"
            class="dads-tab"
            role="tab"
            aria-selected="true"
            aria-controls="panel-advisories"
          >
            Remediated Advisories (${remediatedDoc.remediated.length})
          </button>
          <button
            type="button"
            id="tab-patches"
            class="dads-tab"
            role="tab"
            aria-selected="false"
            aria-controls="panel-patches"
          >
            Patch Series &amp; Notices (${patchSeriesCount + (manifest.trackedUnmaintained?.length || 0)})
          </button>
        </div>
      </div>
    </header>

    <main class="dads-shell dads-main">
      <section id="panel-advisories" role="tabpanel" aria-labelledby="tab-advisories">
        <div class="dads-table-controls">
          <div class="dads-toolbar-title">
            <h1>Vulnerabilities Discovered &amp; Remediated</h1>
            <span
              id="result-count"
              class="dads-heading-meta"
              aria-live="polite"
              data-open="0"
              data-total-deps="${inventory.counts.total}"
              data-total-patches="${patchCheck.summary.totalPatchFiles}"
            >0 open · ${remediatedDoc.remediated.length}/${remediatedDoc.remediated.length} remediated · ${inventory.counts.total} deps · ${patchCheck.summary.totalPatchFiles} patches</span>
          </div>
          <div class="dads-filter-actions">
            <label for="search-input" class="sr-only">Search advisory ID, package, or summary</label>
            <input
              id="search-input"
              class="dads-input"
              type="search"
              placeholder="Search CVE, package, commit…"
              autocomplete="off"
            />
            <label for="severity-select" class="sr-only">Filter by severity</label>
            <select id="severity-select" class="dads-select">
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Soundness">Soundness</option>
              <option value="Moderate">Moderate</option>
              <option value="Low">Low</option>
            </select>
            <label for="ecosystem-select" class="sr-only">Filter by ecosystem</label>
            <select id="ecosystem-select" class="dads-select">
              <option value="all">All Ecosystems</option>
              <option value="crates.io">crates.io</option>
              <option value="npm">npm</option>
            </select>
            <span class="dads-v-divider" aria-hidden="true"></span>
            <button type="button" id="reset-filters-btn" class="dads-btn dads-btn-outlined dads-btn-xs">
              Reset
            </button>
          </div>
        </div>

        <div id="active-filters" class="dads-active-filters" hidden></div>

        <div class="dads-table-wrap">
          <table class="dads-table">
            <thead>
              <tr>
                <th scope="col" aria-sort="none">
                  <button type="button" class="dads-sort-btn" data-sort-key="id">
                    Advisory <span data-sort-indicator aria-hidden="true">↕</span>
                  </button>
                </th>
                <th scope="col" aria-sort="none">
                  <button type="button" class="dads-sort-btn" data-sort-key="package">
                    Package <span data-sort-indicator aria-hidden="true">↕</span>
                  </button>
                </th>
                <th scope="col">Ecosystem</th>
                <th scope="col" aria-sort="descending">
                  <button type="button" class="dads-sort-btn" data-sort-key="severity">
                    Severity <span data-sort-indicator aria-hidden="true">▼</span>
                  </button>
                </th>
                <th scope="col">Status</th>
                <th scope="col" aria-sort="none">
                  <button type="button" class="dads-sort-btn" data-sort-key="date">
                    Remediation <span data-sort-indicator aria-hidden="true">↕</span>
                  </button>
                </th>
                <th scope="col">Evidence</th>
              </tr>
            </thead>
            <tbody id="advisories-tbody">${renderInitialAdvisoryRows(remediatedDoc.remediated)}</tbody>
          </table>
        </div>
      </section>

      <section id="panel-patches" role="tabpanel" aria-labelledby="tab-patches" hidden>
        <div class="dads-table-wrap" style="margin-bottom: 32px">
          <table class="dads-table">
            <thead>
              <tr>
                <th scope="col">Patched Package</th>
                <th scope="col">Substrate</th>
                <th scope="col">Patch Count</th>
                <th scope="col">Series Digest</th>
                <th scope="col">Advisories / Scope</th>
                <th scope="col">Bazel Verification Gates</th>
              </tr>
            </thead>
            <tbody>${renderPatchSeriesRows(manifest)}</tbody>
          </table>
        </div>

        <div class="dads-page-heading">
          <h2 style="margin: 0; font-size: 20px">Tracked Unmaintained Transitive Notices (Zero Known Bugs)</h2>
        </div>
        <div class="dads-table-wrap">
          <table class="dads-table">
            <thead>
              <tr>
                <th scope="col">Notice ID</th>
                <th scope="col">Crate</th>
                <th scope="col">VEX Status</th>
                <th scope="col">Impact Justification</th>
                <th scope="col">Review Deadline</th>
              </tr>
            </thead>
            <tbody>${renderUnmaintainedRows(manifest)}</tbody>
          </table>
        </div>
      </section>

      <hr class="dads-divider" />
      <footer class="dads-footer">
        <div class="dads-footer-top">
          <p class="dads-footer-pitch">
            <strong>Delegated Agent Co-Browser Engine</strong> — Rust/Blitz KSC2 vector streaming, zero-permission Deno V8 isolates, and CRIU session continuity with attested zero-CVE builds.
          </p>
          <nav class="dads-utility-nav" aria-label="Primary resources">
            <a href="./parawing.openvex.json">OpenVEX v0.2.0</a>
            <a href="${REPO_URL}/releases/latest">Releases</a>
          </nav>
        </div>
        <div class="dads-footer-meta">
          <span>Inventory SHA-256: <span class="dads-mono">${escapeHtml(inventory.digest.slice(0, 16))}…</span> (<a href="./dependency-integrity.json">dependency-integrity.json</a>, LLM relied upon: false).</span>
          <span>Design tokens: Digital Agency Design System v2.18.2.</span>
        </div>
      </footer>
    </main>

    <script>window.__PARAWING_SECURITY_LEDGER__ = ${JSON.stringify(clientPayload).replace(/</g, "\\u003c")};</script>
    <script type="module" src="./app.js"></script>
  </body>
</html>
`;

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "index.html"), html);
  copyFileSync(join(rootDir, "pages/styles.css"), join(outDir, "styles.css"));
  copyFileSync(join(rootDir, "pages/app.js"), join(outDir, "app.js"));
  copyFileSync(join(rootDir, ".github/assets/parawing_logo.png"), join(outDir, "favicon.png"));
  writeFileSync(join(outDir, "parawing.openvex.json"), `${JSON.stringify(openVex, null, 2)}\n`);
  writeFileSync(
    join(outDir, "dependency-integrity.json"),
    `${JSON.stringify(clientPayload, null, 2)}\n`,
  );
  writeFileSync(join(outDir, ".nojekyll"), "");

  return {
    outDir,
    remediatedCount: remediatedDoc.remediated.length,
    totalPackages: inventory.counts.total,
    totalPatches: patchCheck.summary.totalPatchFiles,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const outIdx = process.argv.indexOf("--out-dir");
  const outDir = outIdx !== -1 && process.argv[outIdx + 1] ? process.argv[outIdx + 1] : undefined;
  const result = buildSecurityPages({ outDir });
  process.stdout.write(
    `[pages:build] OK -> ${result.outDir} (${result.remediatedCount} remediated advisories, ${result.totalPackages} packages, ${result.totalPatches} patches)\n`,
  );
}
