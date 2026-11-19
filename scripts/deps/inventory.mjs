// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deterministic multi-ecosystem dependency graph and digest extractor covering Cargo, pnpm, npm,
// Go, Python (uv/pip), and Bazel MODULE.bazel external/toolchain pins.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
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

const IGNORED_WALK_DIRS = new Set([
  ".cache",
  ".cargo",
  ".git",
  ".hg",
  ".limrun",
  ".playwright",
  ".pnpm-store",
  ".puppeteer",
  ".turbo",
  ".wpt",
  ".wrangler",
  "dist",
  "dist-pages",
  "node_modules",
  "output",
  "target",
  "vendor",
]);

function discoverLockfiles(rootDir, fileNames) {
  const wanted = new Set(fileNames);
  const found = [];
  const visit = (absDir, relPrefix) => {
    if (!existsSync(absDir)) return;
    for (const entry of readdirSync(absDir, { withFileTypes: true })) {
      if (entry.name.startsWith("bazel-") || IGNORED_WALK_DIRS.has(entry.name)) continue;
      const relPath = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        visit(join(absDir, entry.name), relPath);
      } else if (wanted.has(entry.name)) {
        found.push(relPath);
      }
    }
  };
  visit(rootDir, "");
  return found.sort();
}

function encodeNpmPurl(name, version) {
  const encoded = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encoded}@${version}`;
}

function upsertPackage(byKey, pkg, relLock) {
  const existing = byKey.get(pkg.key);
  if (existing) {
    if (!existing.lockfiles.includes(relLock)) existing.lockfiles.push(relLock);
    return;
  }
  byKey.set(pkg.key, { ...pkg, lockfiles: [relLock] });
}

function collectCargoPackages(rootDir, patchedTarballShas) {
  const byKey = new Map();
  const lockPaths = new Set([
    ...ALL_CARGO_LOCKFILES.filter((rel) => existsSync(join(rootDir, rel))),
    ...discoverLockfiles(rootDir, ["Cargo.lock"]),
  ]);
  for (const relLock of lockPaths) {
    const parsed = parseCargoLock(readFileSync(join(rootDir, relLock), "utf8"));
    for (const pkg of parsed) {
      const patchedSha = patchedTarballShas.get(`${pkg.name}-${pkg.version}`) || "";
      if (!pkg.source.startsWith("registry+") && !patchedSha) continue;
      upsertPackage(
        byKey,
        {
          key: `crates.io:${pkg.name}@${pkg.version}`,
          ecosystem: "crates.io",
          name: pkg.name,
          version: pkg.version,
          purl: `pkg:cargo/${pkg.name}@${pkg.version}`,
          checksum: pkg.checksum || patchedSha,
          patched: Boolean(patchedSha),
        },
        relLock,
      );
    }
  }
  return [...byKey.values()];
}

function parsePackageLockPackages(rawText) {
  const doc = JSON.parse(rawText);
  const entries = Object.entries(doc.packages || {});
  const out = [];
  for (const [pkgPath, meta] of entries) {
    if (!pkgPath || !meta || typeof meta !== "object" || !meta.version || meta.link) continue;
    const marker = "node_modules/";
    const idx = pkgPath.lastIndexOf(marker);
    if (idx === -1) continue;
    const name = meta.name || pkgPath.slice(idx + marker.length);
    if (!name) continue;
    out.push({ name, version: String(meta.version), checksum: String(meta.integrity || "") });
  }
  return out;
}

function collectNpmPackages(rootDir) {
  const pkgJsonPath = join(rootDir, "package.json");
  const patchedDeps = existsSync(pkgJsonPath)
    ? Object.keys(JSON.parse(readFileSync(pkgJsonPath, "utf8"))?.pnpm?.patchedDependencies || {})
    : [];
  const patchedSet = new Set(patchedDeps);
  const byKey = new Map();
  for (const relLock of discoverLockfiles(rootDir, ["pnpm-lock.yaml"])) {
    const parsed = parsePnpmLock(readFileSync(join(rootDir, relLock), "utf8"));
    for (const pkg of parsed.packages.values()) {
      const checksum = pkg.checksum
        ? `${pkg.checksum.algorithm}:${pkg.checksum.checksumValue}`
        : "";
      upsertPackage(
        byKey,
        {
          key: `npm:${pkg.name}@${pkg.version}`,
          ecosystem: "npm",
          name: pkg.name,
          version: pkg.version,
          purl: encodeNpmPurl(pkg.name, pkg.version),
          checksum,
          patched: patchedSet.has(`${pkg.name}@${pkg.version}`),
        },
        relLock,
      );
    }
  }
  for (const relLock of discoverLockfiles(rootDir, ["package-lock.json"])) {
    for (const pkg of parsePackageLockPackages(readFileSync(join(rootDir, relLock), "utf8"))) {
      upsertPackage(
        byKey,
        {
          key: `npm:${pkg.name}@${pkg.version}`,
          ecosystem: "npm",
          name: pkg.name,
          version: pkg.version,
          purl: encodeNpmPurl(pkg.name, pkg.version),
          checksum: pkg.checksum,
          patched: patchedSet.has(`${pkg.name}@${pkg.version}`),
        },
        relLock,
      );
    }
  }
  return [...byKey.values()];
}

function collectGoPackages(rootDir) {
  const byKey = new Map();
  for (const relLock of discoverLockfiles(rootDir, ["go.sum"])) {
    const lines = readFileSync(join(rootDir, relLock), "utf8").split(/\r?\n/);
    for (const line of lines) {
      const match = /^(\S+)\s+(v[^\s/]+)\s+(h1:\S+)$/.exec(line.trim());
      if (!match) continue;
      const [, modName, rawVer, digest] = match;
      const version = rawVer.replace(/^v/, "").replace(/\+incompatible$/, "");
      upsertPackage(
        byKey,
        {
          key: `Go:${modName}@${version}`,
          ecosystem: "Go",
          name: modName,
          version,
          purl: `pkg:golang/${modName}@${rawVer}`,
          checksum: digest,
          patched: false,
        },
        relLock,
      );
    }
  }
  return [...byKey.values()];
}

function parseUvLock(text) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const sdistSha = /sha256:([0-9a-f]{64})/.exec(block)?.[1] || "";
    if (name && version) out.push({ name, version, checksum: sdistSha });
  }
  return out;
}

function parseRequirementsTxt(text) {
  const out = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    const match = /^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)/.exec(line);
    if (!match) continue;
    const sha = /--hash=sha256:([0-9a-f]{64})/.exec(rawLine)?.[1] || "";
    out.push({ name: match[1], version: match[2], checksum: sha });
  }
  return out;
}

function collectPypiPackages(rootDir) {
  const byKey = new Map();
  for (const relLock of discoverLockfiles(rootDir, ["uv.lock", "requirements.txt"])) {
    const raw = readFileSync(join(rootDir, relLock), "utf8");
    const pkgs = relLock.endsWith("uv.lock") ? parseUvLock(raw) : parseRequirementsTxt(raw);
    for (const pkg of pkgs) {
      upsertPackage(
        byKey,
        {
          key: `PyPI:${pkg.name}@${pkg.version}`,
          ecosystem: "PyPI",
          name: pkg.name,
          version: pkg.version,
          purl: `pkg:pypi/${pkg.name.toLowerCase()}@${pkg.version}`,
          checksum: pkg.checksum,
          patched: false,
        },
        relLock,
      );
    }
  }
  return [...byKey.values()];
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

/**
 * @param {Array<{ key: string, checksum: string, lockfiles: string[] }>} packages
 * @returns {string}
 */
export function computeInventoryDigest(packages) {
  const hash = createHash("sha256");
  const sorted = [...packages].sort((a, b) => a.key.localeCompare(b.key));
  for (const pkg of sorted) {
    const locks = [...pkg.lockfiles].sort().join(",");
    hash.update(`${pkg.key}|${pkg.checksum}|${locks}\n`);
  }
  return hash.digest("hex");
}

/**
 * @param {string} rootDir
 * @returns {{ packages: Array<any>, digest: string, counts: Record<string, number> }}
 */
export function extractDependencyInventory(rootDir) {
  const patchedTarballShas = readPatchedShasFromModule(rootDir);
  const cargo = collectCargoPackages(rootDir, patchedTarballShas);
  const npm = collectNpmPackages(rootDir);
  const go = collectGoPackages(rootDir);
  const pypi = collectPypiPackages(rootDir);
  const bazel = collectBazelAndToolchainPins(rootDir);
  const packages = [...cargo, ...npm, ...go, ...pypi, ...bazel].sort((a, b) =>
    a.key.localeCompare(b.key),
  );
  const counts = {
    total: packages.length,
    cargo: cargo.length,
    npm: npm.length,
    bazelAndToolchains: bazel.length,
    osvQueryable: packages.filter((p) => ["crates.io", "npm", "PyPI", "Go"].includes(p.ecosystem))
      .length,
  };
  if (go.length > 0) counts.go = go.length;
  if (pypi.length > 0) counts.pypi = pypi.length;
  return {
    packages,
    digest: computeInventoryDigest(packages),
    counts,
  };
}
