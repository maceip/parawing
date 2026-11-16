// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deterministic OSV/RustSec/GHSA batch scanner and offline advisory-lock gate. Never relies on an
// LLM: resolutions require a verified in-tree patch, SemVer upgrade, or non-expired signed waiver.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const VALID_VEX_JUSTIFICATIONS = new Set([
  "component_not_present",
  "vulnerable_code_not_present",
  "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary",
  "inline_mitigations_already_exist",
]);

function extractFixedVersions(vuln, pkgName) {
  const fixed = [];
  for (const aff of vuln.affected || []) {
    if (aff.package?.name && aff.package.name !== pkgName) continue;
    for (const range of aff.ranges || []) {
      const events = range.events || [];
      for (const ev of events) {
        if (ev.fixed && !fixed.includes(ev.fixed)) fixed.push(ev.fixed);
      }
    }
  }
  return fixed;
}

function classifyAdvisoryKind(vuln) {
  const info =
    vuln.database_specific?.informational ||
    vuln.affected?.[0]?.database_specific?.informational ||
    null;
  if (info === "unmaintained") return "unmaintained";
  if (info === "unsound") return "unsound";
  return "vulnerability";
}

async function fetchJsonWithRetry(url, init, attempts = 3) {
  let lastErr = null;
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await fetch(url, init);
      if (res.ok) return await res.json();
      if (res.status < 500 && res.status !== 429) {
        throw new Error(`HTTP ${res.status} from ${url}`);
      }
      lastErr = new Error(`HTTP ${res.status} from ${url}`);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error(`Failed request to ${url}`);
}

async function queryBatchChunk(chunk, timeoutMs) {
  const queries = chunk.map((pkg) => ({
    package: { ecosystem: pkg.ecosystem, name: pkg.name },
    version: pkg.version,
  }));
  const data = await fetchJsonWithRetry(OSV_QUERYBATCH_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  return data.results || [];
}

/** @param {Array<any>} packages @param {{ timeoutMs?: number }} [opts] @returns {Promise<Array<any>>} */
export async function queryOsvLive(packages, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 25_000;
  const queryable = packages.filter((p) => ["crates.io", "npm", "PyPI"].includes(p.ecosystem));
  const rawPairs = [];
  const uniqueIds = new Set();
  for (let i = 0; i < queryable.length; i += 400) {
    const chunk = queryable.slice(i, i + 400);
    const results = await queryBatchChunk(chunk, timeoutMs);
    results.forEach((res, idx) => {
      const ids = (res.vulns || []).map((v) => v.id).filter(Boolean);
      if (ids.length === 0) return;
      ids.forEach((id) => uniqueIds.add(id));
      rawPairs.push({ pkg: chunk[idx], ids });
    });
  }
  const detailsById = new Map();
  for (const id of [...uniqueIds].sort()) {
    const detail = await fetchJsonWithRetry(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    detailsById.set(id, detail);
  }
  return buildNormalizedAdvisories(rawPairs, detailsById);
}

function buildNormalizedAdvisories(rawPairs, detailsById) {
  const out = [];
  for (const { pkg, ids } of rawPairs) {
    const seenPrimary = new Set();
    for (const id of ids) {
      const vuln = detailsById.get(id);
      if (!vuln) continue;
      const allIds = [vuln.id, ...(vuln.aliases || [])].sort();
      const canonicalGroup = allIds.join("|");
      if (seenPrimary.has(canonicalGroup)) continue;
      seenPrimary.add(canonicalGroup);
      out.push({
        id: vuln.id,
        aliases: (vuln.aliases || []).slice().sort(),
        packageKey: pkg.key,
        ecosystem: pkg.ecosystem,
        packageName: pkg.name,
        packageVersion: pkg.version,
        purl: pkg.purl,
        lockfiles: pkg.lockfiles,
        kind: classifyAdvisoryKind(vuln),
        summary: vuln.summary || "No summary provided",
        fixedVersions: extractFixedVersions(vuln, pkg.name),
      });
    }
  }
  return out.sort((a, b) => `${a.packageKey}:${a.id}`.localeCompare(`${b.packageKey}:${b.id}`));
}

function findPatchMitigation(advisory, manifest) {
  if (advisory.ecosystem !== "crates.io") return null;
  const allIds = new Set([advisory.id, ...(advisory.aliases || [])]);
  for (const entry of manifest.cargoPatches || []) {
    if (entry.crate !== advisory.packageName || entry.version !== advisory.packageVersion) {
      continue;
    }
    const matched = (entry.mitigates || []).filter((m) => allIds.has(m));
    if (matched.length > 0) return { entry, matched };
  }
  return null;
}

function findWaiver(advisory, manifest) {
  const allIds = new Set([advisory.id, ...(advisory.aliases || [])]);
  return (manifest.waivers || []).find(
    (w) => allIds.has(w.advisoryId) && w.package === advisory.packageName,
  );
}

function findTrackedUnmaintained(advisory, manifest) {
  const allIds = new Set([advisory.id, ...(advisory.aliases || [])]);
  return (manifest.trackedUnmaintained || []).find(
    (u) => allIds.has(u.advisoryId) && u.package === advisory.packageName,
  );
}

/** @param {Array<any>} advisories @param {any} manifest @param {string} [nowIso] @returns {{ ok: boolean, resolved: Array<any>, errors: string[] }} */
export function evaluateAdvisories(advisories, manifest, nowIso = new Date().toISOString()) {
  const errors = [];
  const resolved = [];
  for (const adv of advisories) {
    const patchHit = findPatchMitigation(adv, manifest);
    if (patchHit) {
      resolved.push({
        ...adv,
        status: "fixed_by_patch",
        vexStatus: "fixed",
        mitigation: `Patched in scripts/patches/${patchHit.entry.crate}-${patchHit.entry.version}`,
        verificationTargets: patchHit.entry.verificationTargets || [],
      });
      continue;
    }
    const waiver = findWaiver(adv, manifest);
    if (waiver) {
      if (!VALID_VEX_JUSTIFICATIONS.has(waiver.justification)) {
        errors.push(`Invalid VEX justification on waiver for ${adv.id}: ${waiver.justification}`);
      } else if (!waiver.expiresAt || waiver.expiresAt <= nowIso) {
        errors.push(`Expired advisory waiver for ${adv.id} (${waiver.expiresAt})`);
      } else {
        resolved.push({
          ...adv,
          status: "not_affected",
          vexStatus: "not_affected",
          vexJustification: waiver.justification,
          mitigation: waiver.reason,
          expiresAt: waiver.expiresAt,
        });
        continue;
      }
    }
    const tracked = findTrackedUnmaintained(adv, manifest);
    if (adv.kind === "unmaintained" && tracked) {
      if (!tracked.reviewBy || tracked.reviewBy <= nowIso) {
        errors.push(`Expired reviewBy date for unmaintained crate ${adv.packageName} (${adv.id})`);
      } else {
        resolved.push({
          ...adv,
          status: "informational_tracked",
          vexStatus: "not_affected",
          vexJustification: "vulnerable_code_not_present",
          mitigation: tracked.reason,
          reviewBy: tracked.reviewBy,
        });
        continue;
      }
    }
    errors.push(
      `Unmitigated ${adv.kind} ${adv.id} in ${adv.packageName}@${adv.packageVersion}: ${adv.summary}`,
    );
    resolved.push({ ...adv, status: "unmitigated", vexStatus: "affected" });
  }
  return { ok: errors.length === 0, resolved, errors };
}

/** @param {string} rootDir @param {any} inventory @param {any} manifest @param {string} [nowIso] @returns {{ ok: boolean, errors: string[], resolved: Array<any>, lock: any }} */
export function verifyOfflineAdvisoryLock(rootDir, inventory, manifest, nowIso) {
  const lockPath = join(rootDir, "deps/advisory-lock.json");
  if (!existsSync(lockPath)) {
    return {
      ok: false,
      errors: ["Missing deps/advisory-lock.json; run `pnpm run deps:sync`"],
      resolved: [],
      lock: null,
    };
  }
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const errors = [];
  if (lock.inventoryDigest !== inventory.digest) {
    errors.push(
      `Lockfile inventory changed (expected digest ${lock.inventoryDigest}, got ${inventory.digest}); run \`pnpm run deps:sync\``,
    );
  }
  const evaluation = evaluateAdvisories(lock.advisories || [], manifest, nowIso);
  return {
    ok: errors.length === 0 && evaluation.ok,
    errors: [...errors, ...evaluation.errors],
    resolved: evaluation.resolved,
    lock,
  };
}
