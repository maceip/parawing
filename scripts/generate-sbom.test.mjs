// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  generateSbom,
  normalizeSpdxLicense,
  parseCargoLock,
  parsePnpmLock,
  validateSbomDocument,
} from "./generate-sbom.mjs";

test("parseCargoLock, parsePnpmLock, and normalizeSpdxLicense parse lockfiles cleanly", () => {
  assert.equal(normalizeSpdxLicense("MIT/Apache-2.0"), "MIT OR Apache-2.0");
  assert.equal(normalizeSpdxLicense("Apache-2.0"), "Apache-2.0");
  assert.equal(normalizeSpdxLicense("BAD;LICENSE"), "NOASSERTION");

  const cargo = parseCargoLock(`
version = 4

[[package]]
name = "parawing"
version = "0.1.0"
dependencies = [
 "tokio",
]

[[package]]
name = "tokio"
version = "1.50.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`);
  assert.equal(cargo.length, 2);
  assert.deepEqual(cargo[0].dependencies, ["tokio"]);
  assert.equal(cargo[1].checksum.length, 64);

  const pnpm = parsePnpmLock(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/pkg':
        specifier: ^1.0.0
        version: 1.0.0
packages:
  '@scope/pkg@1.0.0':
    resolution: {integrity: sha512-AQID}
  'leaf@2.0.0':
    resolution: {integrity: sha512-BAUG}
snapshots:
  '@scope/pkg@1.0.0':
    dependencies:
      leaf: 2.0.0
`);
  assert.equal(pnpm.packages.size, 2);
  assert.equal(pnpm.edges.length, 1);
  assert.equal(pnpm.rootDirectKeys.has("npm:@scope/pkg@1.0.0"), true);
});

test("generateSbom produces valid tagged SPDX 2.3 JSON across Cargo, patches, and pnpm", () => {
  const dir = mkdtempSync(join(tmpdir(), "parawing-sbom-"));
  try {
    mkdirSync(join(dir, "packages/parawing-cli"), { recursive: true });
    mkdirSync(join(dir, "packages/rust-host"), { recursive: true });
    mkdirSync(join(dir, "packages/device-authority"), { recursive: true });
    mkdirSync(join(dir, "scripts/patches/blitz-dom-0.3.0"), { recursive: true });
    writeFileSync(join(dir, "scripts/patches/blitz-dom-0.3.0/0001-fix.patch"), "diff");
    writeFileSync(
      join(dir, "packages/parawing-cli/Cargo.toml"),
      '[package]\nname = "parawing"\nversion = "0.1.0"\nlicense = "Apache-2.0"\n',
    );
    writeFileSync(
      join(dir, "Cargo.lock"),
      `[[package]]
name = "blitz-dom"
version = "0.3.0"
dependencies = []
`,
    );
    writeFileSync(
      join(dir, "packages/parawing-cli/Cargo.lock"),
      `[[package]]
name = "parawing"
version = "0.1.0"
dependencies = [
 "tokio",
]

[[package]]
name = "tokio"
version = "1.50.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
`,
    );
    const sha512DigestB64 = Buffer.alloc(64, 7).toString("base64");
    writeFileSync(
      join(dir, "pnpm-lock.yaml"),
      `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/widget':
        specifier: ^1.0.0
        version: 1.0.0
packages:
  '@scope/widget@1.0.0':
    resolution: {integrity: sha512-${sha512DigestB64}}
snapshots:
  '@scope/widget@1.0.0': {}
`,
    );
    const archive = join(dir, "parawing.tar.gz");
    writeFileSync(archive, "release-archive-bytes");

    const { doc, stats } = generateSbom({
      rootDir: dir,
      archivePath: archive,
      version: "0.1.1",
      target: "aarch64-apple-darwin",
      created: "2026-11-14T12:00:00Z",
    });

    validateSbomDocument(doc);
    assert.equal(stats.cargoPackages, 3);
    assert.equal(stats.npmPackages, 1);
    assert.equal(stats.patchedVendorCrates, 1);

    const blitzPkg = doc.packages.find((p) => p.name === "blitz-dom");
    assert.ok(blitzPkg);
    assert.match(blitzPkg.comment, /vendor_patches=0001-fix\.patch/);
    assert.equal(blitzPkg.externalRefs[0].referenceLocator, "pkg:cargo/blitz-dom@0.3.0");

    const scopedNpm = doc.packages.find((p) => p.name === "@scope/widget");
    assert.ok(scopedNpm);
    assert.equal(scopedNpm.externalRefs[0].referenceLocator, "pkg:npm/%40scope/widget@1.0.0");
    assert.equal(scopedNpm.checksums[0].algorithm, "SHA512");
    assert.equal(scopedNpm.checksums[0].checksumValue.length, 128);

    const dependsOnEdges = doc.relationships.filter((r) => r.relationshipType === "DEPENDS_ON");
    assert.equal(dependsOnEdges.length, 1);
    const outPath = join(dir, "sbom.spdx.json");
    writeFileSync(outPath, JSON.stringify(doc));
    assert.equal(JSON.parse(readFileSync(outPath, "utf8")).spdxVersion, "SPDX-2.3");
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  }
});
