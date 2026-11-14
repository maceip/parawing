#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Reads and bumps the canonical Parawing version in `VERSION` and root `package.json`.
// Keeps Cargo/Bazel/pnpm lockfiles untouched so cached dependency trees remain valid.

import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const VALID_KINDS = new Set(["patch", "minor", "major", "none"]);

/** @param {string} raw @returns {[number, number, number]} */
export function parseSemver(raw) {
  const trimmed = raw.trim();
  const match = SEMVER_RE.exec(trimmed);
  if (!match) {
    throw new Error(`Invalid semantic version "${trimmed}" (expected X.Y.Z)`);
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** @param {string} current @param {string} [kind] @returns {string} */
export function bumpSemver(current, kind = "patch") {
  if (!VALID_KINDS.has(kind)) {
    throw new Error(`Invalid bump kind "${kind}" (expected patch, minor, major, or none)`);
  }
  const [major, minor, patch] = parseSemver(current);
  if (kind === "none") return `${major}.${minor}.${patch}`;
  if (kind === "major") return `${major + 1}.0.0`;
  if (kind === "minor") return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

/** Updates `VERSION` and root `package.json` when the target version differs.
 * @param {{ rootDir: string, bump?: string, setVersion?: string | null }} opts
 * @returns {{ previousVersion: string, version: string, tag: string, changed: boolean }} */
export function bumpWorkspaceVersion({ rootDir, bump = "patch", setVersion = null }) {
  const versionPath = resolve(rootDir, "VERSION");
  const packageJsonPath = resolve(rootDir, "package.json");
  const previousParts = parseSemver(readFileSync(versionPath, "utf8"));
  const previousVersion = previousParts.join(".");
  const version = setVersion
    ? parseSemver(setVersion).join(".")
    : bumpSemver(previousVersion, bump);

  const pkgText = readFileSync(packageJsonPath, "utf8");
  const pkg = JSON.parse(pkgText);
  const needsVersionWrite = version !== previousVersion;
  const needsPackageWrite = pkg.version !== version;
  const changed = needsVersionWrite || needsPackageWrite;

  if (needsVersionWrite) {
    writeFileSync(versionPath, `${version}\n`, "utf8");
  }
  if (needsPackageWrite) {
    pkg.version = version;
    writeFileSync(packageJsonPath, `${JSON.stringify(pkg, null, 2)}\n`, "utf8");
  }
  return {
    previousVersion,
    version,
    tag: `v${version}`,
    changed,
  };
}

function parseArgs(argv) {
  let rootDir = resolve(import.meta.dirname, "..");
  let bump = "patch";
  let setVersion = null;
  let githubOutput = process.env.GITHUB_OUTPUT || "";
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--bump") {
      bump = argv[++i] ?? "";
    } else if (arg === "--set") {
      setVersion = argv[++i] ?? "";
    } else if (arg === "--current") {
      bump = "none";
    } else if (arg === "--root") {
      rootDir = resolve(argv[++i] ?? "");
    } else if (arg === "--github-output") {
      githubOutput = argv[++i] ?? "";
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  return { rootDir, bump, setVersion, githubOutput };
}

function main(argv) {
  const opts = parseArgs(argv);
  const result = bumpWorkspaceVersion(opts);
  if (opts.githubOutput) {
    const lines = [
      `previous_version=${result.previousVersion}`,
      `version=${result.version}`,
      `tag=${result.tag}`,
      `changed=${result.changed}`,
    ];
    appendFileSync(opts.githubOutput, `${lines.join("\n")}\n`, "utf8");
  }
  console.log(JSON.stringify(result));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2));
}
