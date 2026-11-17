#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Generates a full, dependency-tagged SPDX 2.3 JSON SBOM covering Parawing Cargo lockfiles,
// vendored crate patches, and pnpm workspace dependencies.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const CARGO_LOCKFILES = [
  "packages/parawing-cli/Cargo.lock",
  "packages/rust-host/Cargo.lock",
  "packages/device-authority/Cargo.lock",
  "scripts/memprof-rewriter/Cargo.lock",
  "scripts/lint/rust-check/Cargo.lock",
  "Cargo.lock",
];

const LOCAL_CARGO_MANIFESTS = [
  "packages/parawing-cli/Cargo.toml",
  "packages/rust-host/Cargo.toml",
  "packages/device-authority/Cargo.toml",
  "packages/core/Cargo.toml",
  "packages/renderer-core/Cargo.toml",
  "packages/scene-host-wasm/Cargo.toml",
];

const WORKSPACE_CRATES = new Set([
  "parawing",
  "parawing-rust-host",
  "parawing-authority",
  "parawing-core",
  "parawing-renderer-core",
  "scene-host-wasm",
]);

const SPDX_ID_RE = /^SPDXRef-[A-Za-z0-9.-]+$/;
const SAFE_SPDX_LICENSE_RE = /^[A-Za-z0-9.() +-]+$/;

function unquoteYamlKey(raw) {
  const trimmed = raw.trim();
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function makeSpdxIdAllocator() {
  const used = new Set(["SPDXRef-DOCUMENT"]);
  return (rawLabel) => {
    const clean = rawLabel.replace(/[^A-Za-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "pkg";
    let candidate = `SPDXRef-${clean}`;
    if (!used.has(candidate)) {
      used.add(candidate);
      return candidate;
    }
    let counter = 2;
    while (used.has(`${candidate}-${counter}`)) {
      counter += 1;
    }
    const unique = `${candidate}-${counter}`;
    used.add(unique);
    return unique;
  };
}

/** @param {string} rawLicense @returns {string} */
export function normalizeSpdxLicense(rawLicense) {
  if (!rawLicense || typeof rawLicense !== "string") return "NOASSERTION";
  const normalized = rawLicense.trim().replace(/\s*\/\s*/g, " OR ");
  if (!normalized || normalized.toUpperCase() === "NONE") return "NOASSERTION";
  return SAFE_SPDX_LICENSE_RE.test(normalized) ? normalized : "NOASSERTION";
}

function readLocalCargoLicenses(rootDir) {
  const out = new Map();
  for (const relPath of LOCAL_CARGO_MANIFESTS) {
    const full = join(rootDir, relPath);
    if (!existsSync(full)) continue;
    const text = readFileSync(full, "utf8");
    const nameMatch = /^name\s*=\s*"([^"]+)"/m.exec(text);
    const licenseMatch = /^license\s*=\s*"([^"]+)"/m.exec(text);
    if (nameMatch && licenseMatch) {
      out.set(nameMatch[1], normalizeSpdxLicense(licenseMatch[1]));
    }
  }
  // Matches the declared clarify rule in `.config/about.toml`.
  out.set("icy_sixel", "MIT");
  return out;
}

function readVendorPatches(rootDir) {
  const patchesRoot = join(rootDir, "scripts/patches");
  const patchMap = new Map();
  if (!existsSync(patchesRoot)) return patchMap;
  for (const entry of readdirSync(patchesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const files = readdirSync(join(patchesRoot, entry.name))
      .filter((f) => f.endsWith(".patch"))
      .sort();
    if (files.length === 0) continue;
    patchMap.set(entry.name, files);
  }
  return patchMap;
}

function readPatchManifestMeta(rootDir) {
  const manifestPath = join(rootDir, "deps/patches-manifest.json");
  const metaMap = new Map();
  if (!existsSync(manifestPath)) return metaMap;
  const parsed = JSON.parse(readFileSync(manifestPath, "utf8"));
  for (const entry of parsed.cargoPatches || []) {
    metaMap.set(`${entry.crate}-${entry.version}`, entry);
  }
  for (const entry of parsed.npmPatches || []) {
    metaMap.set(`npm:${entry.package}@${entry.version}`, entry);
  }
  return metaMap;
}

/** Parses a Cargo.lock string into package metadata and dependency names.
 * @param {string} tomlText
 * @returns {Array<{ name: string, version: string, source: string,
 *   checksum: string, dependencies: string[] }>} */
export function parseCargoLock(tomlText) {
  const packages = [];
  let current = null;
  let inDeps = false;

  const flush = () => {
    if (current?.name && current?.version) {
      packages.push(current);
    }
    current = null;
    inDeps = false;
  };

  for (const line of tomlText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "[[package]]") {
      flush();
      current = { name: "", version: "", source: "", checksum: "", dependencies: [] };
      continue;
    }
    if (!current) continue;
    if (trimmed.startsWith("[")) {
      flush();
      continue;
    }
    if (inDeps) {
      if (trimmed.startsWith("]")) {
        inDeps = false;
        continue;
      }
      const depMatch = /^"([^"]+)"/.exec(trimmed);
      if (depMatch) current.dependencies.push(depMatch[1]);
      continue;
    }
    const kv = /^([a-z_]+)\s*=\s*(.+)$/.exec(trimmed);
    if (!kv) continue;
    const [, key, rawVal] = kv;
    if (key === "dependencies") {
      if (rawVal.trim().startsWith("[") && !rawVal.includes("]")) {
        inDeps = true;
      } else {
        for (const match of rawVal.matchAll(/"([^"]+)"/g)) {
          current.dependencies.push(match[1]);
        }
      }
      continue;
    }
    const strMatch = /^"(.*)"$/.exec(rawVal.trim());
    if (
      strMatch &&
      (key === "name" || key === "version" || key === "source" || key === "checksum")
    ) {
      current[key] = strMatch[1];
    }
  }
  flush();
  return packages;
}

function resolveCargoDepKey(depSpec, localPkgByName, globalPkgByName) {
  const parts = depSpec.trim().split(/\s+/);
  const name = parts[0];
  const explicitVersion = parts[1] && !parts[1].startsWith("(") ? parts[1] : null;
  if (explicitVersion) {
    const exactKey = `cargo:${name}@${explicitVersion}`;
    if (localPkgByName.get(name)?.includes(exactKey)) return exactKey;
    if (globalPkgByName.get(name)?.includes(exactKey)) return exactKey;
  }
  const localCandidates = localPkgByName.get(name);
  if (localCandidates && localCandidates.length > 0) return localCandidates[0];
  const globalCandidates = globalPkgByName.get(name);
  return globalCandidates && globalCandidates.length > 0 ? globalCandidates[0] : null;
}

function encodeNpmPurl(name, version) {
  const encodedName = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encodedName}@${version}`;
}

function parseNpmKey(rawKey) {
  const clean = unquoteYamlKey(rawKey);
  const parenAt = clean.indexOf("(");
  const base = parenAt > 0 ? clean.slice(0, parenAt) : clean;
  const atIdx = base.lastIndexOf("@");
  if (atIdx <= 0) return null;
  const name = base.slice(0, atIdx);
  const version = base.slice(atIdx + 1);
  if (!name || !version) return null;
  return { name, version };
}

function parseIntegrityHex(rawIntegrity) {
  const match = /^(sha512|sha256|sha1)-([A-Za-z0-9+/=]+)$/.exec(rawIntegrity.trim());
  if (!match) return null;
  const alg = match[1].toUpperCase();
  const hex = Buffer.from(match[2], "base64").toString("hex");
  const expectedLen = alg === "SHA512" ? 128 : alg === "SHA256" ? 64 : 40;
  if (hex.length !== expectedLen) return null;
  return { algorithm: alg, checksumValue: hex };
}

function handlePackagesSection(state, indent, trimmed) {
  if (indent === 2 && trimmed.endsWith(":")) {
    const parsed = parseNpmKey(trimmed.slice(0, -1));
    state.currentPkgKey = parsed ? state.ensureNpmPkg(parsed.name, parsed.version).key : "";
    return;
  }
  if (indent === 4 && state.currentPkgKey) {
    const intMatch = /integrity:\s*([^\s,}]+)/.exec(trimmed);
    const parsedHex = intMatch ? parseIntegrityHex(intMatch[1]) : null;
    if (parsedHex) state.packages.get(state.currentPkgKey).checksum = parsedHex;
  }
}

function handleSnapshotsSection(state, indent, trimmed) {
  if (indent === 2 && trimmed.includes(":")) {
    const parsed = parseNpmKey(trimmed.replace(/:\s*(\{\})?$/, ""));
    state.snapshotPkgKey = parsed ? `npm:${parsed.name}@${parsed.version}` : "";
    state.inSnapshotDeps = false;
    return;
  }
  if (indent === 4) {
    state.inSnapshotDeps = trimmed === "dependencies:" || trimmed === "optionalDependencies:";
    return;
  }
  if (indent !== 6 || !state.inSnapshotDeps || !state.snapshotPkgKey) return;
  const sep = trimmed.indexOf(":");
  if (sep <= 0) return;
  const depName = unquoteYamlKey(trimmed.slice(0, sep));
  const depVer = unquoteYamlKey(trimmed.slice(sep + 1))
    .split("(")[0]
    .trim();
  if (!depVer || depVer.startsWith("link:")) return;
  const target = state.ensureNpmPkg(depName, depVer).key;
  state.edges.push([state.snapshotPkgKey, target]);
}

function handleImportersSection(state, indent, trimmed) {
  if (indent === 2 && trimmed.endsWith(":")) {
    state.currentImporter = unquoteYamlKey(trimmed.slice(0, -1).replace(/:$/, ""));
    state.importerGroup = "";
    return;
  }
  if (indent === 4 && trimmed.endsWith(":")) {
    const group = trimmed.slice(0, -1);
    const isDepGroup =
      group === "dependencies" || group === "optionalDependencies" || group === "devDependencies";
    state.importerGroup = isDepGroup ? group : "";
    return;
  }
  if (indent < 6 || !state.importerGroup || !state.currentImporter) return;
  const verMatch = /^version:\s*(.+)$/.exec(trimmed);
  if (!verMatch) {
    if (indent === 6 && trimmed.endsWith(":")) {
      state.currentPkgKey = unquoteYamlKey(trimmed.slice(0, -1));
    }
    return;
  }
  const ver = unquoteYamlKey(verMatch[1]).split("(")[0].trim();
  if (!ver || ver.startsWith("link:") || !state.currentPkgKey) return;
  const target = state.ensureNpmPkg(state.currentPkgKey, ver);
  target.importers.add(state.currentImporter);
  state.rootDirectKeys.add(target.key);
}

/** Parses pnpm-lock.yaml packages, snapshot edges, and workspace importers.
 * @param {string} yamlText
 * @returns {{ packages: Map<string, any>, edges: Array<[string, string]>,
 *   rootDirectKeys: Set<string> }} */
export function parsePnpmLock(yamlText) {
  const packages = new Map();
  const edges = [];
  const rootDirectKeys = new Set();

  const ensureNpmPkg = (name, version) => {
    const key = `npm:${name}@${version}`;
    if (!packages.has(key)) {
      packages.set(key, { key, name, version, checksum: null, importers: new Set() });
    }
    return packages.get(key);
  };

  const state = {
    packages,
    edges,
    rootDirectKeys,
    ensureNpmPkg,
    section: "",
    currentImporter: "",
    importerGroup: "",
    currentPkgKey: "",
    snapshotPkgKey: "",
    inSnapshotDeps: false,
  };

  for (const line of yamlText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;

    if (indent === 0) {
      state.section = trimmed.replace(/:.*$/, "");
      state.currentImporter = "";
      state.importerGroup = "";
      state.currentPkgKey = "";
      state.snapshotPkgKey = "";
      state.inSnapshotDeps = false;
      continue;
    }

    if (state.section === "packages") handlePackagesSection(state, indent, trimmed);
    else if (state.section === "snapshots") handleSnapshotsSection(state, indent, trimmed);
    else if (state.section === "importers") handleImportersSection(state, indent, trimmed);
  }

  return { packages, edges, rootDirectKeys };
}

/** Validates required SPDX 2.3 JSON invariants before attesting or uploading.
 * @param {Record<string, any>} doc @returns {void} */
export function validateSbomDocument(doc) {
  if (doc.spdxVersion !== "SPDX-2.3") {
    throw new Error(`Invalid spdxVersion: ${String(doc.spdxVersion)}`);
  }
  if (doc.dataLicense !== "CC0-1.0") {
    throw new Error(`Invalid dataLicense: ${String(doc.dataLicense)}`);
  }
  if (doc.SPDXID !== "SPDXRef-DOCUMENT") {
    throw new Error(`Invalid document SPDXID: ${String(doc.SPDXID)}`);
  }
  const created = doc.creationInfo?.created;
  if (typeof created !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(created)) {
    throw new Error(`Invalid creationInfo.created timestamp: ${String(created)}`);
  }
  const packages = Array.isArray(doc.packages) ? doc.packages : [];
  if (packages.length < 2) {
    throw new Error(`SBOM contains too few packages: ${packages.length}`);
  }
  const knownIds = new Set(["SPDXRef-DOCUMENT"]);
  for (const pkg of packages) {
    if (typeof pkg.SPDXID !== "string" || !SPDX_ID_RE.test(pkg.SPDXID)) {
      throw new Error(`Invalid package SPDXID: ${String(pkg.SPDXID)}`);
    }
    if (knownIds.has(pkg.SPDXID)) {
      throw new Error(`Duplicate package SPDXID: ${pkg.SPDXID}`);
    }
    knownIds.add(pkg.SPDXID);
    const hasPurl =
      Array.isArray(pkg.externalRefs) &&
      pkg.externalRefs.some(
        (ref) => ref.referenceType === "purl" && typeof ref.referenceLocator === "string",
      );
    if (!hasPurl) {
      throw new Error(`Package ${pkg.SPDXID} (${pkg.name}) is missing a PURL externalRef tag`);
    }
    if (Array.isArray(pkg.checksums)) {
      for (const csum of pkg.checksums) {
        if (!/^[a-f0-9]+$/.test(csum.checksumValue)) {
          throw new Error(`Non-hex checksum on ${pkg.SPDXID}: ${csum.checksumValue}`);
        }
      }
    }
  }
  const relationships = Array.isArray(doc.relationships) ? doc.relationships : [];
  for (const rel of relationships) {
    if (!knownIds.has(rel.spdxElementId) || !knownIds.has(rel.relatedSpdxElement)) {
      throw new Error(
        `Dangling relationship ${String(rel.spdxElementId)} -> ${String(rel.relatedSpdxElement)}`,
      );
    }
  }
}

/** Generates an SPDX 2.3 JSON SBOM for Parawing Cargo crates and npm packages.
 * @param {{ rootDir: string, archivePath: string, version: string, target: string,
 *   repo?: string, created?: string }} opts
 * @returns {{ doc: Record<string, any>, stats: Record<string, number> }} */
export function generateSbom({
  rootDir,
  archivePath,
  version,
  target,
  repo = "maceip/parawing",
  created = new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
}) {
  const absRoot = resolve(rootDir);
  const absArchive = resolve(archivePath);
  const archiveBytes = readFileSync(absArchive);
  const archiveSha256 = createHash("sha256").update(archiveBytes).digest("hex");
  const nextSpdxId = makeSpdxIdAllocator();
  const localLicenses = readLocalCargoLicenses(absRoot);
  const vendorPatches = readVendorPatches(absRoot);
  const patchMetaMap = readPatchManifestMeta(absRoot);

  const cargoPackages = new Map();
  const cargoKeysByName = new Map();
  const rawCargoDeps = [];

  for (const relLock of CARGO_LOCKFILES) {
    const full = join(absRoot, relLock);
    if (!existsSync(full)) continue;
    const localKeysByName = new Map();
    const lockEntries = parseCargoLock(readFileSync(full, "utf8"));
    for (const pkg of lockEntries) {
      const key = `cargo:${pkg.name}@${pkg.version}`;
      const localList = localKeysByName.get(pkg.name) ?? [];
      if (!localList.includes(key)) localList.push(key);
      localKeysByName.set(pkg.name, localList);

      if (!cargoPackages.has(key)) {
        const spdxId = nextSpdxId(`cargo-${pkg.name}-${pkg.version}`);
        cargoPackages.set(key, {
          key,
          spdxId,
          name: pkg.name,
          version: pkg.version,
          source: pkg.source,
          checksum: pkg.checksum,
          lockfiles: new Set([relLock]),
        });
        const list = cargoKeysByName.get(pkg.name) ?? [];
        list.push(key);
        cargoKeysByName.set(pkg.name, list);
      } else {
        cargoPackages.get(key).lockfiles.add(relLock);
        if (!cargoPackages.get(key).checksum && pkg.checksum) {
          cargoPackages.get(key).checksum = pkg.checksum;
        }
      }
      for (const depSpec of pkg.dependencies) {
        rawCargoDeps.push([key, depSpec, localKeysByName]);
      }
    }
  }

  const pnpmPath = join(absRoot, "pnpm-lock.yaml");
  const pnpmParsed = existsSync(pnpmPath)
    ? parsePnpmLock(readFileSync(pnpmPath, "utf8"))
    : { packages: new Map(), edges: [], rootDirectKeys: new Set() };

  const archiveFileName = `parawing-v${version}-${target}.tar.gz`;
  const downloadBase = `https://github.com/${repo}/releases/download/v${version}/${archiveFileName}`;
  const rootPkgId = "SPDXRef-Package-parawing-release";

  const spdxPackages = [
    {
      name: "parawing",
      SPDXID: rootPkgId,
      versionInfo: version,
      downloadLocation: downloadBase,
      filesAnalyzed: false,
      licenseConcluded: "Apache-2.0",
      licenseDeclared: "Apache-2.0",
      copyrightText: "Copyright (c) 2026 Cloudflare, Inc. and Parawing contributors",
      checksums: [{ algorithm: "SHA256", checksumValue: archiveSha256 }],
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: `pkg:generic/parawing@${version}?arch=${encodeURIComponent(target)}`,
        },
      ],
      comment: `release_archive=${archiveFileName}; target=${target}`,
    },
  ];

  const relationships = [
    {
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: rootPkgId,
    },
  ];

  for (const pkg of cargoPackages.values()) {
    const patchKey = `${pkg.name}-${pkg.version}`;
    const patchFiles = vendorPatches.get(patchKey) ?? [];
    const declaredLicense = localLicenses.get(pkg.name) ?? "NOASSERTION";
    const isRegistry = pkg.source.startsWith("registry+");
    const downloadLocation = isRegistry
      ? `https://crates.io/api/v1/crates/${pkg.name}/${pkg.version}/download`
      : "NOASSERTION";
    const commentParts = [
      "ecosystem=cargo",
      `lockfiles=${[...pkg.lockfiles].sort().join(",")}`,
      `origin=${patchFiles.length > 0 ? "vendored-patched" : isRegistry ? "crates.io" : "workspace"}`,
    ];
    if (patchFiles.length > 0) {
      commentParts.push(`vendor_patches=${patchFiles.join(",")}`);
    }
    const patchMeta = patchMetaMap.get(patchKey);
    if (patchMeta?.seriesSha8) {
      commentParts.push(`patch_series_sha8=${patchMeta.seriesSha8}`);
    }
    if (patchMeta?.mitigates?.length > 0) {
      commentParts.push(`mitigates=${patchMeta.mitigates.join(",")}`);
    }
    const resolvedSha = pkg.checksum || patchMeta?.tarballSha256 || "";
    const entry = {
      name: pkg.name,
      SPDXID: pkg.spdxId,
      versionInfo: pkg.version,
      downloadLocation,
      filesAnalyzed: false,
      licenseConcluded: declaredLicense,
      licenseDeclared: declaredLicense,
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: `pkg:cargo/${pkg.name}@${pkg.version}`,
        },
      ],
      comment: commentParts.join("; "),
    };
    if (/^[a-f0-9]{64}$/.test(resolvedSha)) {
      entry.checksums = [{ algorithm: "SHA256", checksumValue: resolvedSha }];
    }
    spdxPackages.push(entry);

    if (WORKSPACE_CRATES.has(pkg.name) || patchFiles.length > 0) {
      relationships.push({
        spdxElementId: rootPkgId,
        relationshipType: "CONTAINS",
        relatedSpdxElement: pkg.spdxId,
      });
    }
  }

  for (const pkg of pnpmParsed.packages.values()) {
    pkg.spdxId = nextSpdxId(`npm-${pkg.name}-${pkg.version}`);
    const npmPatch = patchMetaMap.get(`npm:${pkg.name}@${pkg.version}`);
    const npmComments = ["ecosystem=npm", "lockfile=pnpm-lock.yaml"];
    if (pkg.importers.size > 0) {
      npmComments.push(`importers=${[...pkg.importers].sort().join(",")}`);
    }
    if (npmPatch) {
      npmComments.push(`npm_patch=${npmPatch.path}`);
      npmComments.push(`patch_sha8=${String(npmPatch.sha256 || "").slice(0, 8)}`);
      if (npmPatch.mitigates?.length > 0) {
        npmComments.push(`mitigates=${npmPatch.mitigates.join(",")}`);
      }
    }
    const entry = {
      name: pkg.name,
      SPDXID: pkg.spdxId,
      versionInfo: pkg.version,
      downloadLocation: "https://registry.npmjs.org",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: encodeNpmPurl(pkg.name, pkg.version),
        },
      ],
      comment: npmComments.join("; "),
    };
    if (pkg.checksum) {
      entry.checksums = [pkg.checksum];
    }
    spdxPackages.push(entry);
    if (pnpmParsed.rootDirectKeys.has(pkg.key)) {
      relationships.push({
        spdxElementId: rootPkgId,
        relationshipType: "CONTAINS",
        relatedSpdxElement: pkg.spdxId,
      });
    }
  }

  const seenEdges = new Set();
  const addEdge = (fromId, relType, toId) => {
    const key = `${fromId}|${relType}|${toId}`;
    if (seenEdges.has(key) || fromId === toId) return;
    seenEdges.add(key);
    relationships.push({
      spdxElementId: fromId,
      relationshipType: relType,
      relatedSpdxElement: toId,
    });
  };

  for (const [parentKey, depSpec, localKeysByName] of rawCargoDeps) {
    const targetKey = resolveCargoDepKey(depSpec, localKeysByName, cargoKeysByName);
    const parent = cargoPackages.get(parentKey);
    const targetPkg = targetKey ? cargoPackages.get(targetKey) : null;
    if (parent && targetPkg) {
      addEdge(parent.spdxId, "DEPENDS_ON", targetPkg.spdxId);
    }
  }

  for (const [parentKey, targetKey] of pnpmParsed.edges) {
    const parent = pnpmParsed.packages.get(parentKey);
    const targetPkg = pnpmParsed.packages.get(targetKey);
    if (parent?.spdxId && targetPkg?.spdxId) {
      addEdge(parent.spdxId, "DEPENDS_ON", targetPkg.spdxId);
    }
  }

  const doc = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `parawing-v${version}-${target}`,
    documentNamespace: `${downloadBase}.spdx.json#${archiveSha256}`,
    creationInfo: {
      created,
      creators: [`Tool: parawing-sbom-generator-${version}`, "Organization: Parawing"],
      comment: `Full tagged dependency SBOM covering Cargo (${cargoPackages.size} crates) and npm (${pnpmParsed.packages.size} packages)`,
    },
    packages: spdxPackages,
    relationships,
  };
  validateSbomDocument(doc);
  return {
    doc,
    stats: {
      totalPackages: spdxPackages.length,
      cargoPackages: cargoPackages.size,
      npmPackages: pnpmParsed.packages.size,
      patchedVendorCrates: vendorPatches.size,
      relationships: relationships.length,
    },
  };
}

function parseArgs(argv) {
  const opts = {
    rootDir: resolve(import.meta.dirname, ".."),
    archivePath: "",
    version: "",
    target: "",
    repo: "maceip/parawing",
    outputPath: "",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--root") opts.rootDir = resolve(argv[++i] ?? "");
    else if (arg === "--archive") opts.archivePath = resolve(argv[++i] ?? "");
    else if (arg === "--version") opts.version = argv[++i] ?? "";
    else if (arg === "--target") opts.target = argv[++i] ?? "";
    else if (arg === "--repo") opts.repo = argv[++i] ?? "";
    else if (arg === "--output") opts.outputPath = resolve(argv[++i] ?? "");
    else throw new Error(`Unknown option: ${arg}`);
  }
  if (!opts.archivePath || !opts.version || !opts.target || !opts.outputPath) {
    throw new Error(
      "Usage: generate-sbom.mjs --archive <path> --version <X.Y.Z> --target <triple> --output <spdx.json> [--repo <owner/repo>] [--root <dir>]",
    );
  }
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);
  const { doc, stats } = generateSbom(opts);
  mkdirSync(dirname(opts.outputPath), { recursive: true });
  writeFileSync(opts.outputPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8");
  console.log(JSON.stringify({ output: opts.outputPath, ...stats }));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2));
}
