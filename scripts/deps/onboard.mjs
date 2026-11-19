// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Turnkey repository onboarding (`init`), zero-config live audit (`audit`), patch SHA-256 refresh
// (`refresh`), time-bounded OpenVEX waiver enrollment (`waive`), and status inspection (`status`).

import { createHash } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { extractDependencyInventory } from "./inventory.mjs";
import {
  VALID_VEX_JUSTIFICATIONS,
  evaluateAdvisories,
  queryOsvLive,
  verifyOfflineAdvisoryLock,
} from "./osv-scanner.mjs";
import {
  createEmptyManifest,
  loadPatchesManifest,
  sha256Hex,
  verifyAllPatchesAndOverrides,
} from "./patch-verifier.mjs";
import { buildOpenVexDocument, renderMarkdownReport } from "./reporter.mjs";

const SPECIAL_PATCH_DIRS = new Set(["playwright", "puppeteer"]);

function writeFileCreatingParents(absPath, content) {
  mkdirSync(dirname(absPath), { recursive: true });
  writeFileSync(absPath, content);
}

function readRepoVersion(rootDir) {
  const versionPath = join(rootDir, "VERSION");
  if (existsSync(versionPath)) return readFileSync(versionPath, "utf8").trim() || "0.0.0";
  const pkgPath = join(rootDir, "package.json");
  if (existsSync(pkgPath)) {
    return JSON.parse(readFileSync(pkgPath, "utf8"))?.version || "0.0.0";
  }
  return "0.0.0";
}

function computeSeriesSha8(absPatchPaths) {
  const hash = createHash("sha256");
  hash.update("format:2\0");
  for (const absPath of absPatchPaths) {
    hash.update(basename(absPath));
    hash.update("\0");
    hash.update(readFileSync(absPath));
    hash.update("\0");
  }
  return hash.digest("hex").slice(0, 8);
}

function extractPatchSubject(rawText, fileName) {
  const match = /^Subject:\s*(?:\[PATCH[^\]]*\]\s*)?(.+)$/m.exec(rawText);
  return match ? match[1].trim() : fileName.replace(/^\d+-/, "").replace(/\.patch$/, "");
}

function parseOverrideRule(selector, replacement) {
  if (typeof replacement !== "string" || replacement === "-") return null;
  const match = /^(@?[^@]+)@.*<\s*([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)\s*$/.exec(selector);
  if (!match) return null;
  const cleanRep = replacement.replace(/^[\^~>=<\s]+/, "");
  return {
    package: match[1],
    selector,
    replacement,
    minSafeVersion: cleanRep || match[2],
    mitigates: [],
  };
}

function parseCargoPatchPaths(rootDir) {
  const map = new Map();
  const cargoPath = join(rootDir, "Cargo.toml");
  if (!existsSync(cargoPath)) return map;
  let inPatch = false;
  for (const line of readFileSync(cargoPath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("[")) {
      inPatch = trimmed === "[patch.crates-io]";
      continue;
    }
    const match = /^([A-Za-z0-9_-]+)\s*=\s*\{\s*path\s*=\s*"([^"]+)"\s*\}/.exec(trimmed);
    if (inPatch && match) map.set(match[1], match[2]);
  }
  return map;
}

function syncNpmPatchesInManifest(rootDir, manifest) {
  const pkgPath = join(rootDir, "package.json");
  if (!existsSync(pkgPath)) return 0;
  const pkgJson = JSON.parse(readFileSync(pkgPath, "utf8"));
  const declared = pkgJson?.pnpm?.patchedDependencies || {};
  const existingByKey = new Map(
    (manifest.npmPatches || []).map((e) => [`${e.package}@${e.version}`, e]),
  );
  const updated = [];
  for (const [spec, relPath] of Object.entries(declared)) {
    const atIdx = spec.lastIndexOf("@");
    if (atIdx <= 0) continue;
    const pkgName = spec.slice(0, atIdx);
    const version = spec.slice(atIdx + 1);
    const absPatch = join(rootDir, String(relPath));
    const digest = existsSync(absPatch) ? sha256Hex(readFileSync(absPatch)) : "";
    const prev = existingByKey.get(spec);
    updated.push({
      package: pkgName,
      version,
      path: String(relPath),
      sha256: digest,
      mitigates: prev?.mitigates || [],
      verificationTargets: prev?.verificationTargets || [],
    });
  }
  manifest.npmPatches = updated;
  return updated.length;
}

function refreshCargoSeriesEntry(rootDir, entry) {
  const seriesDir = join(rootDir, "scripts/patches", `${entry.crate}-${entry.version}`);
  if (!existsSync(seriesDir)) return 0;
  const files = readdirSync(seriesDir)
    .filter((f) => f.endsWith(".patch"))
    .sort();
  const absPaths = files.map((f) => join(seriesDir, f));
  entry.seriesSha8 = computeSeriesSha8(absPaths);
  entry.patches = files.map((file) => {
    const raw = readFileSync(join(seriesDir, file));
    return {
      file,
      sha256: sha256Hex(raw),
      subject: extractPatchSubject(raw.toString("utf8"), file),
    };
  });
  return files.length;
}

function discoverInitialCargoSeries(rootDir) {
  const patchesRoot = join(rootDir, "scripts/patches");
  if (!existsSync(patchesRoot)) return [];
  const cargoPaths = parseCargoPatchPaths(rootDir);
  const series = [];
  for (const dirent of readdirSync(patchesRoot, { withFileTypes: true })) {
    if (!dirent.isDirectory() || SPECIAL_PATCH_DIRS.has(dirent.name)) continue;
    const dashIdx = dirent.name.lastIndexOf("-");
    if (dashIdx <= 0) continue;
    const crate = dirent.name.slice(0, dashIdx);
    const version = dirent.name.slice(dashIdx + 1);
    const entry = {
      crate,
      version,
      upstreamRepo: "",
      tarballSha256: "",
      seriesSha8: "",
      mitigates: [],
      verificationTargets: [],
      patches: [],
    };
    const customPath = cargoPaths.get(crate);
    if (customPath && customPath !== `packages/core/target/vendor-patched/${dirent.name}`) {
      entry.cargoPath = customPath;
    }
    refreshCargoSeriesEntry(rootDir, entry);
    if (entry.patches.length > 0) series.push(entry);
  }
  return series;
}

/** @param {string} rootDir @param {any} manifest @returns {number} */
export function refreshManifestInPlace(rootDir, manifest) {
  let count = syncNpmPatchesInManifest(rootDir, manifest);
  for (const entry of manifest.cargoPatches || []) {
    count += refreshCargoSeriesEntry(rootDir, entry);
  }
  for (const aux of manifest.auxiliaryPatches || []) {
    const abs = join(rootDir, aux.path);
    if (existsSync(abs)) {
      aux.sha256 = sha256Hex(readFileSync(abs));
      count += 1;
    }
  }
  return count;
}

function buildInitialManifest(rootDir) {
  const manifest = createEmptyManifest();
  const pkgPath = join(rootDir, "package.json");
  if (existsSync(pkgPath)) {
    const pkgJson = JSON.parse(readFileSync(pkgPath, "utf8"));
    for (const [sel, rep] of Object.entries(pkgJson?.pnpm?.overrides || {})) {
      const rule = parseOverrideRule(sel, rep);
      if (rule) manifest.npmOverrides.push(rule);
    }
  }
  manifest.cargoPatches = discoverInitialCargoSeries(rootDir);
  refreshManifestInPlace(rootDir, manifest);
  return manifest;
}

function renderCiWorkflowYaml() {
  return [
    "name: Dependency Integrity",
    "",
    "on:",
    "  pull_request:",
    "  push:",
    "    branches: [main, master]",
    "  workflow_dispatch:",
    "",
    "permissions:",
    "  contents: read",
    "",
    "jobs:",
    "  dependency-integrity:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - name: Verify dependency integrity & OSV advisories",
    "        uses: maceip/parawing/.github/actions/dependency-integrity@main",
    "        with:",
    "          mode: online",
    '          vex-out: "${{ runner.temp }}/dependency-integrity.openvex.json"',
    "",
  ].join("\n");
}

function formatRemediationHint(adv) {
  const fix = (adv.fixedVersions || [])[0];
  const upg = fix ? `upgrade ${adv.packageName} -> ${fix}, patch in-tree, or ` : "";
  const flag = adv.kind === "unmaintained" ? "--unmaintained" : "--justification <vex>";
  return `  -> ${adv.id} (${adv.packageName}@${adv.packageVersion}): ${upg}waive via \`cli.mjs waive ${adv.id} --package ${adv.packageName} ${flag} --reason "..."\``;
}

/** @param {any} opts @returns {Promise<number>} */
export async function runInitCommand(opts) {
  const manifestPath = join(opts.rootDir, "deps/patches-manifest.json");
  const manifest = existsSync(manifestPath)
    ? loadPatchesManifest(opts.rootDir)
    : buildInitialManifest(opts.rootDir);
  const hashedPatches = refreshManifestInPlace(opts.rootDir, manifest);
  writeFileCreatingParents(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  const remediatedPath = join(opts.rootDir, "deps/remediated-advisories.json");
  if (!existsSync(remediatedPath)) {
    writeFileCreatingParents(
      remediatedPath,
      `${JSON.stringify({ schemaVersion: 1, remediated: [] }, null, 2)}\n`,
    );
  }

  const inventory = extractDependencyInventory(opts.rootDir);
  const query = opts.queryFn || queryOsvLive;
  const advisories = opts.offline ? [] : await query(inventory.packages);
  const lockDoc = {
    schemaVersion: 1,
    source: opts.offline ? "offline-bootstrap" : "https://api.osv.dev/v1/querybatch",
    inventoryDigest: inventory.digest,
    counts: inventory.counts,
    advisories,
  };
  writeFileCreatingParents(
    join(opts.rootDir, "deps/advisory-lock.json"),
    `${JSON.stringify(lockDoc, null, 2)}\n`,
  );

  if (opts.ci) {
    const wfPath = join(opts.rootDir, ".github/workflows/dependency-integrity.yml");
    if (!existsSync(wfPath) || opts.force) {
      writeFileCreatingParents(wfPath, renderCiWorkflowYaml());
    }
  }

  const patchCheck = verifyAllPatchesAndOverrides(opts.rootDir, inventory.packages, manifest);
  const advCheck = evaluateAdvisories(advisories, manifest);
  const errors = [...patchCheck.errors, ...advCheck.errors];
  process.stdout.write(
    `[deps:init] Configured ${opts.rootDir}: ${inventory.counts.total} deps locked, ${hashedPatches} patches hashed${opts.ci ? ", CI workflow ready" : ""}.\n`,
  );
  if (errors.length === 0) return 0;
  for (const err of errors) process.stderr.write(`[deps:init] ACTION NEEDED: ${err}\n`);
  for (const adv of (advCheck.resolved || []).filter((a) => a.status === "unmitigated")) {
    process.stderr.write(`${formatRemediationHint(adv)}\n`);
  }
  return 1;
}

/** @param {any} opts @returns {number} */
export function runRefreshCommand(opts) {
  const manifest = loadPatchesManifest(opts.rootDir);
  const count = refreshManifestInPlace(opts.rootDir, manifest);
  writeFileCreatingParents(
    join(opts.rootDir, "deps/patches-manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  process.stdout.write(`[deps:refresh] OK: refreshed SHA-256 digests for ${count} patch files.\n`);
  return 0;
}

/** @param {any} opts @returns {number} */
export function runWaiveCommand(opts) {
  if (!opts.advisoryId || !opts.packageName || !opts.reason) {
    process.stderr.write(
      "[deps:waive] Usage: cli.mjs waive <ADVISORY_ID> --package <pkg> (--justification <vex> | --unmaintained) --reason <text> [--days 90]\n",
    );
    return 2;
  }
  const manifest = loadPatchesManifest(opts.rootDir);
  const days = opts.days > 0 ? opts.days : opts.unmaintained ? 180 : 90;
  const deadline = new Date(Date.now() + days * 86_400_000).toISOString();
  if (opts.unmaintained) {
    const rest = (manifest.trackedUnmaintained || []).filter(
      (u) => !(u.advisoryId === opts.advisoryId && u.package === opts.packageName),
    );
    manifest.trackedUnmaintained = [
      ...rest,
      {
        advisoryId: opts.advisoryId,
        package: opts.packageName,
        reason: opts.reason,
        reviewBy: deadline,
      },
    ];
  } else {
    if (!VALID_VEX_JUSTIFICATIONS.has(opts.justification)) {
      process.stderr.write(
        `[deps:waive] Invalid --justification ${JSON.stringify(opts.justification)}. Valid: ${[...VALID_VEX_JUSTIFICATIONS].join(", ")}\n`,
      );
      return 2;
    }
    const rest = (manifest.waivers || []).filter(
      (w) => !(w.advisoryId === opts.advisoryId && w.package === opts.packageName),
    );
    manifest.waivers = [
      ...rest,
      {
        advisoryId: opts.advisoryId,
        package: opts.packageName,
        justification: opts.justification,
        reason: opts.reason,
        expiresAt: deadline,
      },
    ];
  }
  writeFileCreatingParents(
    join(opts.rootDir, "deps/patches-manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  process.stdout.write(
    `[deps:waive] Recorded ${opts.advisoryId} for ${opts.packageName} until ${deadline.slice(0, 10)}.\n`,
  );
  return 0;
}

/** @param {any} opts @returns {Promise<number>} */
export async function runAuditCommand(opts) {
  const inventory = extractDependencyInventory(opts.rootDir);
  const manifestPath = join(opts.rootDir, "deps/patches-manifest.json");
  const hasManifest = existsSync(manifestPath);
  const manifest = hasManifest ? loadPatchesManifest(opts.rootDir) : createEmptyManifest();
  const patchCheck = hasManifest
    ? verifyAllPatchesAndOverrides(opts.rootDir, inventory.packages, manifest)
    : {
        ok: true,
        errors: [],
        summary: {
          cargoSeries: 0,
          auxiliaryPatches: 0,
          npmPatches: 0,
          totalPatchFiles: 0,
          npmSecurityOverrides: 0,
        },
      };
  const query = opts.queryFn || queryOsvLive;
  const advisoryCheck = evaluateAdvisories(await query(inventory.packages), manifest);
  const version = readRepoVersion(opts.rootDir);
  const md = renderMarkdownReport({
    version,
    inventory,
    manifest,
    patchCheck,
    advisoryCheck,
  });
  if (opts.mdOut) writeFileCreatingParents(opts.mdOut, md);
  if (opts.vexOut) {
    const vex = buildOpenVexDocument({
      version,
      resolvedAdvisories: advisoryCheck.resolved || [],
    });
    writeFileCreatingParents(opts.vexOut, `${JSON.stringify(vex, null, 2)}\n`);
  }
  if (opts.jsonOut) {
    writeFileCreatingParents(
      opts.jsonOut,
      `${JSON.stringify({ ok: patchCheck.ok && advisoryCheck.ok, inventoryDigest: inventory.digest, counts: inventory.counts, advisories: advisoryCheck.resolved }, null, 2)}\n`,
    );
  }
  const errors = [...patchCheck.errors, ...advisoryCheck.errors];
  if (errors.length > 0) {
    for (const err of errors) process.stderr.write(`[deps:audit] ERROR: ${err}\n`);
    return 1;
  }
  process.stdout.write(
    `[deps:audit] PASS: ${inventory.counts.total} deps audited (${inventory.counts.osvQueryable} OSV-queryable), 0 unmitigated bugs.\n`,
  );
  return 0;
}

/** @param {any} opts @returns {number} */
export function runStatusCommand(opts) {
  const inventory = extractDependencyInventory(opts.rootDir);
  const manifestPath = join(opts.rootDir, "deps/patches-manifest.json");
  if (!existsSync(manifestPath)) {
    process.stdout.write(
      `[deps:status] UNINITIALIZED (${opts.rootDir}): discovered ${inventory.counts.total} locked deps. Run \`pnpm run deps:init -- --ci\` (or \`node scripts/deps/cli.mjs init --ci\`) to onboard.\n`,
    );
    return 1;
  }
  const manifest = loadPatchesManifest(opts.rootDir);
  const patchCheck = verifyAllPatchesAndOverrides(opts.rootDir, inventory.packages, manifest);
  const advCheck = verifyOfflineAdvisoryLock(opts.rootDir, inventory, manifest);
  const ok = patchCheck.ok && advCheck.ok;
  process.stdout.write(
    `[deps:status] ${ok ? "PASS" : "ACTION NEEDED"} (${opts.rootDir})\n` +
      `  Inventory : ${inventory.counts.total} deps (sha256:${inventory.digest.slice(0, 16)}…)\n` +
      `  Patches   : ${patchCheck.summary.totalPatchFiles} files, ${patchCheck.summary.npmSecurityOverrides} overrides (${patchCheck.ok ? "verified" : `${patchCheck.errors.length} errors`})\n` +
      `  Advisories: ${(advCheck.resolved || []).length} tracked, ${advCheck.errors.length} issues, ${(manifest.waivers || []).length} active waivers\n`,
  );
  for (const err of [...patchCheck.errors, ...advCheck.errors]) {
    process.stderr.write(`  ! ${err}\n`);
  }
  return ok ? 0 : 1;
}

/** @returns {string} */
export function renderHelpText() {
  return [
    "Parawing Dependency Integrity CLI — Deterministic OSV, SHA-256 Patch & OpenVEX Gate",
    "",
    "Quickstart (Activate in Any Repo):",
    "  node scripts/deps/cli.mjs audit [--root <dir>]          Zero-config live OSV + OpenVEX audit",
    "  node scripts/deps/cli.mjs init [--root <dir>] [--ci]    Scaffold deps/* lockfiles + GitHub Action",
    "",
    "Daily Commands:",
    "  status                               Show lock digest, patch parity, and advisory state",
    "  verify [--online]                    Offline lock + SHA-256 patch gate (--online queries OSV.dev)",
    "  sync [--refresh-patches]             Re-query OSV.dev and update deps/advisory-lock.json",
    "  refresh                              Recompute SHA-256 digests in deps/patches-manifest.json",
    "  waive <ID> --package <p> ...         Record time-bounded OpenVEX v0.2.0 waiver or review date",
    "  report [--vex-out <f>] [--md-out <f>] Emit OpenVEX v0.2.0, Markdown, and JSON reports",
    "  triage [ID] [--llm auto|embedded|remote] Optional non-authoritative LLM reachability summary",
    "",
    "Flags:",
    "  --root <dir>     Target repository root (defaults to current working directory)",
    "  --ci             Write .github/workflows/dependency-integrity.yml during `init`",
    "  --vex-out <path> Write OpenVEX v0.2.0 JSON attestation",
    "  --md-out <path>  Write Markdown summary (e.g. $GITHUB_STEP_SUMMARY)",
    "  --json-out <path> Write machine-readable JSON verdict",
    "",
  ].join("\n");
}
