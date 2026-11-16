// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deterministic SemVer parsing, ordering, pnpm override constraint evaluation, and OSV range
// matching with zero external dependencies.

const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;

/** @param {string} raw @returns {{ major: number, minor: number, patch: number, prerelease: string[] } | null} */
export function parseSemver(raw) {
  if (typeof raw !== "string") return null;
  const match = SEMVER_RE.exec(raw.trim());
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split(".") : [],
  };
}

function comparePreIdentifiers(aIds, bIds) {
  if (aIds.length === 0 && bIds.length === 0) return 0;
  if (aIds.length === 0) return 1;
  if (bIds.length === 0) return -1;
  const limit = Math.max(aIds.length, bIds.length);
  for (let i = 0; i < limit; i += 1) {
    if (i >= aIds.length) return -1;
    if (i >= bIds.length) return 1;
    const aPart = aIds[i];
    const bPart = bIds[i];
    if (aPart === bPart) continue;
    const aNum = /^\d+$/.test(aPart);
    const bNum = /^\d+$/.test(bPart);
    if (aNum && bNum) return Number(aPart) < Number(bPart) ? -1 : 1;
    if (aNum !== bNum) return aNum ? -1 : 1;
    return aPart < bPart ? -1 : 1;
  }
  return 0;
}

/** @param {string} a @param {string} b @returns {number} */
export function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return String(a).localeCompare(String(b));
  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;
  return comparePreIdentifiers(pa.prerelease, pb.prerelease);
}

function expandCaretUpperBound(ver) {
  if (ver.major > 0) return `${ver.major + 1}.0.0-0`;
  if (ver.minor > 0) return `0.${ver.minor + 1}.0-0`;
  return `0.0.${ver.patch + 1}-0`;
}

function checkAtom(version, atom) {
  const trimmed = atom.trim();
  if (!trimmed || trimmed === "*") return true;
  if (trimmed.startsWith("^")) {
    const base = parseSemver(trimmed.slice(1));
    if (!base) return false;
    return (
      compareSemver(version, trimmed.slice(1)) >= 0 &&
      compareSemver(version, expandCaretUpperBound(base)) < 0
    );
  }
  if (trimmed.startsWith("~")) {
    const base = parseSemver(trimmed.slice(1));
    if (!base) return false;
    const upper = `${base.major}.${base.minor + 1}.0-0`;
    return compareSemver(version, trimmed.slice(1)) >= 0 && compareSemver(version, upper) < 0;
  }
  const opMatch = /^(>=|<=|>|<|=)?\s*(.+)$/.exec(trimmed);
  if (!opMatch) return false;
  const op = opMatch[1] || "=";
  const cmp = compareSemver(version, opMatch[2]);
  if (op === ">=") return cmp >= 0;
  if (op === "<=") return cmp <= 0;
  if (op === ">") return cmp > 0;
  if (op === "<") return cmp < 0;
  return cmp === 0;
}

/** @param {string} version @param {string} constraint @returns {boolean} */
export function satisfiesConstraint(version, constraint) {
  if (!parseSemver(version) || typeof constraint !== "string") return false;
  const disjuncts = constraint
    .split("||")
    .map((part) => part.trim())
    .filter(Boolean);
  if (disjuncts.length === 0) return false;
  for (const branch of disjuncts) {
    const atoms = branch.match(/(?:>=|<=|>|<|=|\^|~)?\s*v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/g);
    if (!atoms || atoms.length === 0) continue;
    if (atoms.every((atom) => checkAtom(version, atom))) return true;
  }
  return false;
}

/** @param {string} version @param {Array<Record<string, string>>} events @returns {boolean} */
export function isVersionAffectedByOsvEvents(version, events) {
  if (!parseSemver(version) || !Array.isArray(events) || events.length === 0) return false;
  let affected = false;
  for (const event of events) {
    if (event.introduced !== undefined) {
      const floor = event.introduced === "0" ? "0.0.0-0" : event.introduced;
      if (compareSemver(version, floor) >= 0) affected = true;
    }
    if (event.fixed !== undefined && compareSemver(version, event.fixed) >= 0) {
      affected = false;
    }
    if (event.last_affected !== undefined && compareSemver(version, event.last_affected) > 0) {
      affected = false;
    }
  }
  return affected;
}
