// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deterministic multi-ecosystem dependency graph and digest extractor covering Cargo lockfiles,
// pnpm-lock.yaml, MODULE.bazel external pins, and capsule container toolchain pins.

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseCargoLock, parsePnpmLock } from "../generate-sbom.mjs";

export const ALL_CARGO_LOCKFILES = [
  "Cargo.lock",
  "packages/rust-host/Cargo.lock",
  "packages/parawing-cli/Cargo.lock",
  "packages/device-authority/Cargo.lock",
  "scripts/memprof-rewriter/Cargo.lock",
  "scripts/lint/rust-check/Cargo.lock",
];

function encodeNpmPurl(name, version) {
  const encoded = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encoded}@${version}`;
}

function collectCargoPackages(rootDir, patchedTarballShas) {
  const byKey = new Map();
  for (const relLock of ALL_CARGO_LOCKFILES) {
    const absLock = join(rootDir, relLock);
    if (!existsSync(absLock)) continue;
    const parsed = parseCargoLock(readFileSync(absLock, "utf8"));
    for (const pkg of parsed) {
      const patchKey = `${pkg.name}-${pkg.version}`;
      const patchedSha = patchedTarballShas.get(patchKey) || "";
      const isRegistry = pkg.source.startsWith("registry+");
      if (!isRegistry && !patchedSha) continue;
      const key = `crates.io:${pkg.name}@${pkg.version}`;
      const existing = byKey.get(key);
      if (existing) {
        if (!existing.lockfiles.includes(relLock)) existing.lockfiles.push(relLock);
        continue;
      }
      byKey.set(key, {
        key,
        ecosystem: "crates.io",
        name: pkg.name,
        version: pkg.version,
        purl: `pkg:cargo/${pkg.name}@${pkg.version}`,
        checksum: pkg.checksum || patchedSha,
        patched: Boolean(patchedSha),
        lockfiles: [relLock],
      });
    }
  }
  return [...byKey.values()];
}

function collectNpmPackages(rootDir) {
  const lockPath = join(rootDir, "pnpm-lock.yaml");
  if (!existsSync(lockPath)) return [];
  const parsed = parsePnpmLock(readFileSync(lockPath, "utf8"));
  const out = [];
  for (const pkg of parsed.packages.values()) {
    out.push({
      key: `npm:${pkg.name}@${pkg.version}`,
      ecosystem: "npm",
      name: pkg.name,
      version: pkg.version,
      purl: encodeNpmPurl(pkg.name, pkg.version),
      checksum: pkg.checksum ? `${pkg.checksum.algorithm}:${pkg.checksum.checksumValue}` : "",
      patched: false,
      lockfiles: ["pnpm-lock.yaml"],
    });
  }
  return out;
}

function parseHttpArchives(moduleText) {
  const pins = [];
  const blockRe = /http_archive\(\s*([\s\S]*?)\n\)/g;
  for (const match of moduleText.matchAll(blockRe)) {
    const body = match[1];
    const nameMatch = /name\s*=\s*"([^"]+)"/.exec(body);
    const shaMatch = /sha256\s*=\s*"([0-9a-f]{64})"/.exec(body);
    if (!nameMatch || !shaMatch) continue;
    const archiveName = nameMatch[1];
    if (archiveName === "pyyaml") {
      pins.push({
        key: "PyPI:PyYAML@6.0.1",
        ecosystem: "PyPI",
        name: "PyYAML",
        version: "6.0.1",
        purl: "pkg:pypi/pyyaml@6.0.1",
        checksum: shaMatch[1],
        patched: false,
        lockfiles: ["MODULE.bazel"],
      });
      continue;
    }
    pins.push({
      key: `bazel-archive:${archiveName}`,
      ecosystem: "bazel-archive",
      name: archiveName,
      version: shaMatch[1].slice(0, 12),
      purl: `pkg:generic/${archiveName}?checksum=sha256:${shaMatch[1]}`,
      checksum: shaMatch[1],
      patched: false,
      lockfiles: ["MODULE.bazel"],
    });
  }
  return pins;
}

function collectBazelAndToolchainPins(rootDir) {
  const modulePath = join(rootDir, "MODULE.bazel");
  if (!existsSync(modulePath)) return [];
  const text = readFileSync(modulePath, "utf8");
  const out = [];
  const depRe = /bazel_dep\(\s*name\s*=\s*"([^"]+)"\s*,\s*version\s*=\s*"([^"]+)"\s*\)/g;
  for (const match of text.matchAll(depRe)) {
    const [, name, version] = match;
    out.push({
      key: `bazel:${name}@${version}`,
      ecosystem: "bazel",
      name,
      version,
      purl: `pkg:bazel/${name}@${version}`,
      checksum: "",
      patched: name === "rules_rust",
      lockfiles: ["MODULE.bazel"],
    });
  }
  const nodeMatch = /node\.toolchain\(node_version\s*=\s*"([^"]+)"\)/.exec(text);
  if (nodeMatch) {
    out.push({
      key: `toolchain:nodejs@${nodeMatch[1]}`,
      ecosystem: "toolchain",
      name: "nodejs",
      version: nodeMatch[1],
      purl: `pkg:generic/nodejs@${nodeMatch[1]}`,
      checksum: "",
      patched: false,
      lockfiles: ["MODULE.bazel"],
    });
  }
  const rustMatch = /RUST_NIGHTLY\s*=\s*"([^"]+)"/.exec(text);
  if (rustMatch) {
    out.push({
      key: `toolchain:rust@${rustMatch[1]}`,
      ecosystem: "toolchain",
      name: "rust-toolchain",
      version: rustMatch[1],
      purl: `pkg:generic/rust-toolchain@${encodeURIComponent(rustMatch[1])}`,
      checksum: "",
      patched: false,
      lockfiles: ["MODULE.bazel"],
    });
  }
  return [...out, ...parseHttpArchives(text)];
}

function readPatchedShasFromModule(rootDir) {
  const map = new Map();
  const modulePath = join(rootDir, "MODULE.bazel");
  if (!existsSync(modulePath)) return map;
  const text = readFileSync(modulePath, "utf8");
  const blockMatch = /cargo_workspaces\.patched\(([\s\S]*?)\n\)/.exec(text);
  if (!blockMatch) return map;
  const entryRe = /"([^"]+)"\s*:\s*"([0-9a-f]{64})"/g;
  for (const match of blockMatch[1].matchAll(entryRe)) {
    map.set(match[1], match[2]);
  }
  return map;
}

/** @param {Array<{ key: string, checksum: string, lockfiles: string[] }>} packages @returns {string} */
export function computeInventoryDigest(packages) {
  const hash = createHash("sha256");
  const sorted = [...packages].sort((a, b) => a.key.localeCompare(b.key));
  for (const pkg of sorted) {
    const locks = [...pkg.lockfiles].sort().join(",");
    hash.update(`${pkg.key}|${pkg.checksum}|${locks}\n`);
  }
  return hash.digest("hex");
}

/** @param {string} rootDir @returns {{ packages: Array<any>, digest: string, counts: Record<string, number> }} */
export function extractDependencyInventory(rootDir) {
  const patchedTarballShas = readPatchedShasFromModule(rootDir);
  const cargo = collectCargoPackages(rootDir, patchedTarballShas);
  const npm = collectNpmPackages(rootDir);
  const bazel = collectBazelAndToolchainPins(rootDir);
  const packages = [...cargo, ...npm, ...bazel].sort((a, b) => a.key.localeCompare(b.key));
  const counts = {
    total: packages.length,
    cargo: cargo.length,
    npm: npm.length,
    bazelAndToolchains: bazel.length,
    osvQueryable: packages.filter((p) => ["crates.io", "npm", "PyPI"].includes(p.ecosystem)).length,
  };
  return {
    packages,
    digest: computeInventoryDigest(packages),
    counts,
  };
}
