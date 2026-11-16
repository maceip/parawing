#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// CLI entry point for Parawing dependency patching, verification, VEX/Markdown reporting, and
// optional (never relied-upon) embedded or remote LLM advisory triage.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { extractDependencyInventory } from "./inventory.mjs";
import { runOptionalLlmTriage } from "./llm-assist.mjs";
import { evaluateAdvisories, queryOsvLive, verifyOfflineAdvisoryLock } from "./osv-scanner.mjs";
import { loadPatchesManifest, verifyAllPatchesAndOverrides } from "./patch-verifier.mjs";
import { buildOpenVexDocument, renderMarkdownReport } from "./reporter.mjs";

function parseCliArgs(argv) {
  const opts = {
    cmd: "verify",
    rootDir: process.env.BUILD_WORKSPACE_DIRECTORY || resolve(import.meta.dirname, "../.."),
    online: false,
    llm: "none",
    advisoryId: "",
    mdOut: "",
    jsonOut: "",
    vexOut: "",
  };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--online") opts.online = true;
    else if (arg === "--root" && argv[i + 1]) opts.rootDir = resolve(argv[(i += 1)]);
    else if (arg === "--llm" && argv[i + 1]) opts.llm = argv[(i += 1)];
    else if (arg === "--md-out" && argv[i + 1]) opts.mdOut = resolve(argv[(i += 1)]);
    else if (arg === "--json-out" && argv[i + 1]) opts.jsonOut = resolve(argv[(i += 1)]);
    else if (arg === "--vex-out" && argv[i + 1]) opts.vexOut = resolve(argv[(i += 1)]);
    else positional.push(arg);
  }
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
  const inventory = extractDependencyInventory(opts.rootDir);
  const manifest = loadPatchesManifest(opts.rootDir);
  const patchCheck = verifyAllPatchesAndOverrides(opts.rootDir, inventory.packages);
  const liveAdvisories = await queryOsvLive(inventory.packages);
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
  const patchCheck = verifyAllPatchesAndOverrides(opts.rootDir, inventory.packages);
  const advisoryCheck = opts.online
    ? evaluateAdvisories(await queryOsvLive(inventory.packages), manifest)
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

/** @param {string[]} argv @returns {Promise<number>} */
export async function runDepsCli(argv) {
  const opts = parseCliArgs(argv);
  if (opts.cmd === "sync") return runSyncCommand(opts);
  const state = await evaluateCurrentState(opts);
  const md = emitRequestedArtifacts(opts, state);
  if (opts.cmd === "report" || opts.cmd === "triage") {
    if (!opts.mdOut) process.stdout.write(md);
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
