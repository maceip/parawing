#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// CLI entry point for dependency onboarding (`init`, `audit`, `status`), SHA-256 patch management
// (`refresh`, `waive`), verification (`verify`, `sync`), and OpenVEX/Markdown reporting (`report`).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { extractDependencyInventory } from "./inventory.mjs";
import { runOptionalLlmTriage } from "./llm-assist.mjs";
import {
  refreshManifestInPlace,
  renderHelpText,
  runAuditCommand,
  runInitCommand,
  runRefreshCommand,
  runStatusCommand,
  runWaiveCommand,
} from "./onboard.mjs";
import { evaluateAdvisories, queryOsvLive, verifyOfflineAdvisoryLock } from "./osv-scanner.mjs";
import { loadPatchesManifest, verifyAllPatchesAndOverrides } from "./patch-verifier.mjs";
import { buildOpenVexDocument, renderMarkdownReport } from "./reporter.mjs";

const REPO_MARKERS = [
  "deps/patches-manifest.json",
  "Cargo.lock",
  "pnpm-lock.yaml",
  "package-lock.json",
  "go.sum",
  "uv.lock",
  "requirements.txt",
  "MODULE.bazel",
  "package.json",
  ".git",
];

function hasRepoMarker(dir) {
  return REPO_MARKERS.some((rel) => existsSync(join(dir, rel)));
}

function resolveWorkspaceRoot(explicit) {
  if (explicit) return resolve(explicit);
  if (process.env.BUILD_WORKSPACE_DIRECTORY) return resolve(process.env.BUILD_WORKSPACE_DIRECTORY);
  const cwd = resolve(process.cwd());
  if (existsSync(join(cwd, "deps/patches-manifest.json"))) return cwd;
  if (hasRepoMarker(cwd)) return cwd;
  const bazelParent = resolve(cwd, "../../..");
  if (existsSync(join(bazelParent, "deps/patches-manifest.json"))) return bazelParent;
  return resolve(import.meta.dirname, "../..");
}

function consumeFlagValue(argv, index) {
  return argv[index + 1] ? argv[index + 1] : "";
}

function parseCliArgs(argv) {
  let explicitRoot = "";
  const opts = {
    cmd: "verify",
    help: false,
    rootDir: "",
    online: false,
    offline: false,
    ci: false,
    force: false,
    refreshPatches: false,
    unmaintained: false,
    llm: "none",
    advisoryId: "",
    packageName: "",
    justification: "",
    reason: "",
    days: 0,
    mdOut: "",
    jsonOut: "",
    vexOut: "",
  };
  const positional = [];
  const valueFlags = new Map([
    ["--root", (v) => (explicitRoot = v)],
    ["--llm", (v) => (opts.llm = v)],
    ["--package", (v) => (opts.packageName = v)],
    ["--justification", (v) => (opts.justification = v)],
    ["--reason", (v) => (opts.reason = v)],
    ["--days", (v) => (opts.days = Number(v) || 0)],
    ["--md-out", (v) => (opts.mdOut = resolve(v))],
    ["--json-out", (v) => (opts.jsonOut = resolve(v))],
    ["--vex-out", (v) => (opts.vexOut = resolve(v))],
  ]);
  const boolFlags = new Map([
    ["-h", () => (opts.help = true)],
    ["--help", () => (opts.help = true)],
    ["--online", () => (opts.online = true)],
    ["--offline", () => (opts.offline = true)],
    ["--ci", () => (opts.ci = true)],
    ["--force", () => (opts.force = true)],
    ["--refresh-patches", () => (opts.refreshPatches = true)],
    ["--unmaintained", () => (opts.unmaintained = true)],
  ]);
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (boolFlags.has(arg)) {
      boolFlags.get(arg)();
      continue;
    }
    const setter = valueFlags.get(arg);
    const val = setter ? consumeFlagValue(argv, i) : "";
    if (setter && val) {
      setter(val);
      i += 1;
      continue;
    }
    positional.push(arg);
  }
  opts.rootDir = resolveWorkspaceRoot(explicitRoot);
  if (positional[0]) opts.cmd = positional[0];
  if (positional[1]) opts.advisoryId = positional[1];
  return opts;
}

function readParawingVersion(rootDir) {
  const versionPath = join(rootDir, "VERSION");
  if (!existsSync(versionPath)) return "0.0.0";
  return readFileSync(versionPath, "utf8").trim() || "0.0.0";
}

function writeOutputFile(filePath, content) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, content);
}

function buildLlmPrompt(advisories, filterId) {
  const target = filterId
    ? advisories.filter((a) => a.id === filterId || (a.aliases || []).includes(filterId))
    : advisories;
  const payload = target.slice(0, 12).map((a) => ({
    id: a.id,
    kind: a.kind,
    pkg: `${a.packageName}@${a.packageVersion}`,
    status: a.status,
    summary: a.summary,
    fixedVersions: a.fixedVersions,
  }));
  return `Analyze these Parawing dependency advisories and summarize empirical reachability and remediation:\n${JSON.stringify(payload, null, 2)}`;
}

async function runSyncCommand(opts) {
  const manifest = loadPatchesManifest(opts.rootDir);
  if (opts.refreshPatches) {
    refreshManifestInPlace(opts.rootDir, manifest);
    writeOutputFile(
      join(opts.rootDir, "deps/patches-manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
  }
  const inventory = extractDependencyInventory(opts.rootDir);
  const patchCheck = verifyAllPatchesAndOverrides(opts.rootDir, inventory.packages, manifest);
  const query = opts.queryFn || queryOsvLive;
  const liveAdvisories = await query(inventory.packages);
  const advisoryCheck = evaluateAdvisories(liveAdvisories, manifest);
  const lockDoc = {
    schemaVersion: 1,
    source: "https://api.osv.dev/v1/querybatch",
    inventoryDigest: inventory.digest,
    counts: inventory.counts,
    advisories: liveAdvisories,
  };
  writeOutputFile(
    join(opts.rootDir, "deps/advisory-lock.json"),
    `${JSON.stringify(lockDoc, null, 2)}\n`,
  );
  const allErrors = [...patchCheck.errors, ...advisoryCheck.errors];
  if (allErrors.length > 0) {
    for (const err of allErrors) process.stderr.write(`[deps:sync] ERROR: ${err}\n`);
    return 1;
  }
  process.stdout.write(
    `[deps:sync] OK: ${inventory.counts.total} packages, ${liveAdvisories.length} advisories resolved, 0 unmitigated bugs.\n`,
  );
  return 0;
}

async function evaluateCurrentState(opts) {
  const inventory = extractDependencyInventory(opts.rootDir);
  const manifest = loadPatchesManifest(opts.rootDir);
  const patchCheck = verifyAllPatchesAndOverrides(opts.rootDir, inventory.packages, manifest);
  const query = opts.queryFn || queryOsvLive;
  const advisoryCheck = opts.online
    ? evaluateAdvisories(await query(inventory.packages), manifest)
    : verifyOfflineAdvisoryLock(opts.rootDir, inventory, manifest);
  const llmResult = await runOptionalLlmTriage({
    mode: opts.llm,
    prompt: buildLlmPrompt(advisoryCheck.resolved || [], opts.advisoryId),
  });
  return {
    version: readParawingVersion(opts.rootDir),
    inventory,
    manifest,
    patchCheck,
    advisoryCheck,
    llmResult,
  };
}

function emitRequestedArtifacts(opts, state) {
  const md = renderMarkdownReport(state);
  const vex = buildOpenVexDocument({
    version: state.version,
    resolvedAdvisories: state.advisoryCheck.resolved || [],
  });
  if (opts.mdOut) writeOutputFile(opts.mdOut, md);
  if (opts.vexOut) writeOutputFile(opts.vexOut, `${JSON.stringify(vex, null, 2)}\n`);
  if (opts.jsonOut) {
    const jsonDoc = {
      ok: state.patchCheck.ok && state.advisoryCheck.ok,
      reliedUponLlm: false,
      version: state.version,
      inventoryDigest: state.inventory.digest,
      counts: state.inventory.counts,
      patchSummary: state.patchCheck.summary,
      advisories: state.advisoryCheck.resolved,
      errors: [...state.patchCheck.errors, ...state.advisoryCheck.errors],
      llmTriage: state.llmResult,
    };
    writeOutputFile(opts.jsonOut, `${JSON.stringify(jsonDoc, null, 2)}\n`);
  }
  return md;
}

/** @param {string[]} argv @param {{ queryFn?: Function }} [hooks] @returns {Promise<number>} */
export async function runDepsCli(argv, hooks = {}) {
  const opts = { ...parseCliArgs(argv), ...hooks };
  if (opts.help || opts.cmd === "help") {
    process.stdout.write(renderHelpText());
    return 0;
  }
  if (opts.cmd === "init" || opts.cmd === "onboard") return runInitCommand(opts);
  if (opts.cmd === "status") return runStatusCommand(opts);
  if (opts.cmd === "audit") return runAuditCommand(opts);
  if (opts.cmd === "refresh") return runRefreshCommand(opts);
  if (opts.cmd === "waive") return runWaiveCommand(opts);
  if (opts.cmd === "sync") return runSyncCommand(opts);
  const state = await evaluateCurrentState(opts);
  const md = emitRequestedArtifacts(opts, state);
  if ((opts.cmd === "report" || opts.cmd === "triage") && !opts.mdOut) {
    process.stdout.write(md);
  }
  const allErrors = [...state.patchCheck.errors, ...state.advisoryCheck.errors];
  if (allErrors.length > 0) {
    for (const err of allErrors) process.stderr.write(`[deps:${opts.cmd}] ERROR: ${err}\n`);
    return 1;
  }
  if (opts.cmd === "verify") {
    process.stdout.write(
      `[deps:verify] PASS: ${state.inventory.counts.total} deps, ${state.patchCheck.summary.totalPatchFiles} patches verified, 0 unmitigated bugs.\n`,
    );
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const code = await runDepsCli(process.argv.slice(2));
  process.exit(code);
}
