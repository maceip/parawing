// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deterministic verifier for vendor patch series, cross-manifest parity, patch SHA-256 hashes,
// pnpm security overrides, and Bazel/npm/file regression test target links.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { compareSemver } from "./semver.mjs";

const CONFLICT_RE = /^(?:<<<<<<<|=======|>>>>>>>)(?:\s|$)/m;
const SPECIAL_PATCH_DIRS = new Set(["playwright", "puppeteer"]);

/** @param {Buffer | string} content @returns {string} */
export function sha256Hex(content) {
  return createHash("sha256").update(content).digest("hex");
}

/** @returns {any} */
export function createEmptyManifest() {
  return {
    schemaVersion: 1,
    cargoPatches: [],
    auxiliaryPatches: [],
    npmOverrides: [],
    npmPatches: [],
    waivers: [],
    trackedUnmaintained: [],
  };
}

/** @param {string} rootDir @returns {any} */
export function loadPatchesManifest(rootDir) {
  const manifestPath = join(rootDir, "deps/patches-manifest.json");
  if (!existsSync(manifestPath)) {
    throw new Error(
      `Missing canonical patch manifest: ${manifestPath} (run \`node scripts/deps/cli.mjs init\`)`,
    );
  }
  return JSON.parse(readFileSync(manifestPath, "utf8"));
}

function parseCargoPatchSection(tomlText) {
  const entries = new Map();
  let inPatch = false;
  for (const line of tomlText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("[")) {
      inPatch = trimmed === "[patch.crates-io]";
      continue;
    }
    if (!inPatch || !trimmed || trimmed.startsWith("#")) continue;
    const match = /^([A-Za-z0-9_-]+)\s*=\s*\{\s*path\s*=\s*"([^"]+)"\s*\}/.exec(trimmed);
    if (match) entries.set(match[1], match[2]);
  }
  return entries;
}

function parseModulePatchedShas(moduleText) {
  const entries = new Map();
  const block = /cargo_workspaces\.patched\(([\s\S]*?)\n\)/.exec(moduleText);
  if (!block) return entries;
  for (const match of block[1].matchAll(/"([^"]+)"\s*:\s*"([0-9a-f]{64})"/g)) {
    entries.set(match[1], match[2]);
  }
  return entries;
}

function parseReadmeProvenance(readmeText) {
  const keys = new Set();
  const rowRe = /^\|\s*`([A-Za-z0-9_-]+)`\s*\|\s*`([^`]+)`\s*\|/gm;
  for (const match of readmeText.matchAll(rowRe)) {
    keys.add(`${match[1]}-${match[2]}`);
  }
  return keys;
}

function verifySinglePatchFile(absPath, relPath, expectedSha, requireGitHeaders, errors) {
  if (!existsSync(absPath)) {
    errors.push(`Missing patch file: ${relPath}`);
    return;
  }
  const rawBytes = readFileSync(absPath);
  const actualSha = sha256Hex(rawBytes);
  if (actualSha !== expectedSha) {
    errors.push(`Patch SHA-256 mismatch for ${relPath}: expected ${expectedSha}, got ${actualSha}`);
  }
  const text = rawBytes.toString("utf8");
  if (CONFLICT_RE.test(text)) {
    errors.push(`Merge conflict marker found in ${relPath}`);
  }
  if (!text.includes("@@ ")) {
    errors.push(`Patch file contains no unified diff hunk (@@): ${relPath}`);
  }
  if (!requireGitHeaders) return;
  if (!/^From:\s+.+/m.test(text) || !/^Subject:\s+.+/m.test(text)) {
    errors.push(`Git format-patch header (From/Subject) missing in ${relPath}`);
  }
}

function verifyBazelTargetExists(rootDir, label, errors) {
  const match = /^\/\/([^:]*):([A-Za-z0-9_.-]+)$/.exec(label);
  if (!match) {
    errors.push(`Invalid Bazel verification target label: ${label}`);
    return;
  }
  const [, pkgPath, targetName] = match;
  const buildPath = pkgPath ? join(rootDir, pkgPath, "BUILD.bazel") : join(rootDir, "BUILD.bazel");
  if (!existsSync(buildPath)) {
    errors.push(`Missing BUILD.bazel for verification target ${label}`);
    return;
  }
  const buildText = readFileSync(buildPath, "utf8");
  if (!buildText.includes(`"${targetName}"`)) {
    errors.push(`Target ${label} not declared in ${pkgPath || "."}/BUILD.bazel`);
  }
}

function verifyVerificationTarget(rootDir, target, pkgJson, errors) {
  if (target.startsWith("//")) {
    verifyBazelTargetExists(rootDir, target, errors);
    return;
  }
  if (target.startsWith("npm:")) {
    const scriptName = target.slice(4);
    if (!pkgJson?.scripts?.[scriptName]) {
      errors.push(`package.json scripts[${JSON.stringify(scriptName)}] missing for ${target}`);
    }
    return;
  }
  if (target.startsWith("file:")) {
    const relFile = target.slice(5);
    if (!relFile || !existsSync(join(rootDir, relFile))) {
      errors.push(`Verification file missing for ${target}`);
    }
    return;
  }
  errors.push(
    `Unsupported verificationTarget ${target} (use //pkg:target, npm:<script>, or file:<path>)`,
  );
}

function checkCargoWorkspaceParity(entry, key, ctx, errors) {
  if (ctx.hasRootCargo) {
    const actualRoot = ctx.rootPatches.get(entry.crate);
    const expectedRoot = entry.cargoPath || `packages/core/target/vendor-patched/${key}`;
    if (actualRoot !== expectedRoot) {
      errors.push(`Cargo.toml [patch.crates-io] missing or mismatched for ${key}`);
    }
  }
  if (
    ctx.hasHostCargo &&
    ctx.hostPatches.get(entry.crate) !== `../core/target/vendor-patched/${key}`
  ) {
    errors.push(`packages/rust-host/Cargo.toml [patch.crates-io] missing or mismatched for ${key}`);
  }
  if (ctx.hasModuleBazel && ctx.moduleShas.get(key) !== entry.tarballSha256) {
    errors.push(`MODULE.bazel sha256 mismatch for ${key}`);
  }
  if (ctx.hasPatchesReadme && !ctx.readmeKeys.has(key)) {
    errors.push(`scripts/patches/README.md Provenance table missing ${key}`);
  }
}

function verifyCargoSeriesEntry(rootDir, entry, ctx, errors) {
  const key = `${entry.crate}-${entry.version}`;
  checkCargoWorkspaceParity(entry, key, ctx, errors);
  const seriesDir = join(rootDir, "scripts/patches", key);
  if (!existsSync(seriesDir)) {
    errors.push(`Missing patch series directory: scripts/patches/${key}`);
    return;
  }
  const diskPatches = readdirSync(seriesDir)
    .filter((f) => f.endsWith(".patch"))
    .sort();
  const manifestFiles = entry.patches.map((p) => p.file);
  if (JSON.stringify(diskPatches) !== JSON.stringify(manifestFiles)) {
    errors.push(`Patch file list drift in scripts/patches/${key}`);
  }
  for (const patch of entry.patches) {
    const rel = `scripts/patches/${key}/${patch.file}`;
    verifySinglePatchFile(join(rootDir, rel), rel, patch.sha256, true, errors);
  }
  for (const target of entry.verificationTargets || []) {
    verifyVerificationTarget(rootDir, target, ctx.pkgJson, errors);
  }
  if ((entry.mitigates || []).length > 0 && (entry.verificationTargets || []).length === 0) {
    errors.push(`Security-patched crate ${key} must declare at least one verificationTarget`);
  }
}

function verifyNoOrphanCargoEntries(rootDir, manifestSet, ctx, errors) {
  for (const crate of ctx.rootPatches.keys()) {
    if (!manifestSet.has(crate)) errors.push(`Unindexed Cargo.toml patch entry: ${crate}`);
  }
  for (const crate of ctx.hostPatches.keys()) {
    if (!manifestSet.has(crate)) errors.push(`Unindexed rust-host Cargo.toml patch: ${crate}`);
  }
  for (const key of ctx.moduleShas.keys()) {
    if (!ctx.manifestKeys.has(key)) errors.push(`Unindexed MODULE.bazel patched crate: ${key}`);
  }
  const patchesRoot = join(rootDir, "scripts/patches");
  if (!existsSync(patchesRoot)) return;
  for (const dirent of readdirSync(patchesRoot, { withFileTypes: true })) {
    if (!dirent.isDirectory() || SPECIAL_PATCH_DIRS.has(dirent.name)) continue;
    if (!ctx.manifestKeys.has(dirent.name)) {
      errors.push(`Unindexed patch directory on disk: scripts/patches/${dirent.name}`);
    }
  }
}

function verifyNpmOverrides(pkgJson, manifestOverrides, inventoryPackages, errors) {
  const declared = pkgJson?.pnpm?.overrides || {};
  for (const rule of manifestOverrides || []) {
    if (declared[rule.selector] !== rule.replacement) {
      errors.push(
        `package.json pnpm.overrides[${JSON.stringify(rule.selector)}] expected ${JSON.stringify(rule.replacement)}`,
      );
    }
    const matching = inventoryPackages.filter(
      (p) => p.ecosystem === "npm" && p.name === rule.package,
    );
    for (const locked of matching) {
      if (compareSemver(locked.version, rule.minSafeVersion) < 0) {
        errors.push(
          `pnpm-lock.yaml resolved ${locked.name}@${locked.version} below minSafeVersion ${rule.minSafeVersion}`,
        );
      }
    }
  }
}

function verifyNpmPatches(rootDir, pkgJson, npmPatches, errors) {
  const declared = pkgJson?.pnpm?.patchedDependencies || {};
  const indexed = new Set();
  for (const entry of npmPatches || []) {
    const key = `${entry.package}@${entry.version}`;
    indexed.add(key);
    if (declared[key] !== entry.path) {
      errors.push(
        `package.json pnpm.patchedDependencies[${JSON.stringify(key)}] expected ${JSON.stringify(entry.path)}`,
      );
    }
    verifySinglePatchFile(join(rootDir, entry.path), entry.path, entry.sha256, false, errors);
    for (const target of entry.verificationTargets || []) {
      verifyVerificationTarget(rootDir, target, pkgJson, errors);
    }
    if ((entry.mitigates || []).length > 0 && (entry.verificationTargets || []).length === 0) {
      errors.push(`Security-patched npm package ${key} must declare a verificationTarget`);
    }
  }
  for (const key of Object.keys(declared)) {
    if (!indexed.has(key)) {
      errors.push(`Unindexed package.json pnpm.patchedDependencies entry: ${key}`);
    }
  }
}

function buildVerifierContext(rootDir, manifest) {
  const rootCargoPath = join(rootDir, "Cargo.toml");
  const hostCargoPath = join(rootDir, "packages/rust-host/Cargo.toml");
  const moduleBazelPath = join(rootDir, "MODULE.bazel");
  const patchesReadmePath = join(rootDir, "scripts/patches/README.md");
  const pkgJsonPath = join(rootDir, "package.json");
  return {
    hasRootCargo: existsSync(rootCargoPath),
    hasHostCargo: existsSync(hostCargoPath),
    hasModuleBazel: existsSync(moduleBazelPath),
    hasPatchesReadme: existsSync(patchesReadmePath),
    rootPatches: existsSync(rootCargoPath)
      ? parseCargoPatchSection(readFileSync(rootCargoPath, "utf8"))
      : new Map(),
    hostPatches: existsSync(hostCargoPath)
      ? parseCargoPatchSection(readFileSync(hostCargoPath, "utf8"))
      : new Map(),
    moduleShas: existsSync(moduleBazelPath)
      ? parseModulePatchedShas(readFileSync(moduleBazelPath, "utf8"))
      : new Map(),
    readmeKeys: existsSync(patchesReadmePath)
      ? parseReadmeProvenance(readFileSync(patchesReadmePath, "utf8"))
      : new Set(),
    pkgJson: existsSync(pkgJsonPath) ? JSON.parse(readFileSync(pkgJsonPath, "utf8")) : {},
    manifestKeys: new Set((manifest.cargoPatches || []).map((e) => `${e.crate}-${e.version}`)),
  };
}

/**
 * @param {string} rootDir
 * @param {Array<any>} inventoryPackages
 * @param {any} [explicitManifest]
 * @returns {{ ok: boolean, errors: string[], summary: Record<string, number> }}
 */
export function verifyAllPatchesAndOverrides(rootDir, inventoryPackages, explicitManifest) {
  const errors = [];
  const manifest = explicitManifest || loadPatchesManifest(rootDir);
  const ctx = buildVerifierContext(rootDir, manifest);
  const cargoPatches = manifest.cargoPatches || [];
  const manifestCrateNames = new Set(cargoPatches.map((e) => e.crate));
  for (const entry of cargoPatches) {
    verifyCargoSeriesEntry(rootDir, entry, ctx, errors);
  }
  verifyNoOrphanCargoEntries(rootDir, manifestCrateNames, ctx, errors);
  for (const aux of manifest.auxiliaryPatches || []) {
    verifySinglePatchFile(join(rootDir, aux.path), aux.path, aux.sha256, false, errors);
  }
  verifyNpmOverrides(ctx.pkgJson, manifest.npmOverrides, inventoryPackages, errors);
  verifyNpmPatches(rootDir, ctx.pkgJson, manifest.npmPatches, errors);
  const totalPatchFiles =
    cargoPatches.reduce((acc, e) => acc + e.patches.length, 0) +
    (manifest.auxiliaryPatches || []).length +
    (manifest.npmPatches || []).length;
  return {
    ok: errors.length === 0,
    errors,
    summary: {
      cargoSeries: cargoPatches.length,
      auxiliaryPatches: (manifest.auxiliaryPatches || []).length,
      npmPatches: (manifest.npmPatches || []).length,
      totalPatchFiles,
      npmSecurityOverrides: (manifest.npmOverrides || []).length,
    },
  };
}
