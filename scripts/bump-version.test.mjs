// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { bumpSemver, bumpWorkspaceVersion, parseSemver } from "./bump-version.mjs";

test("parseSemver and bumpSemver handle patch, minor, major, none, and errors", () => {
  assert.deepEqual(parseSemver("0.1.0\n"), [0, 1, 0]);
  assert.equal(bumpSemver("0.1.0", "patch"), "0.1.1");
  assert.equal(bumpSemver("0.1.9", "minor"), "0.2.0");
  assert.equal(bumpSemver("1.2.3", "major"), "2.0.0");
  assert.equal(bumpSemver("1.2.3", "none"), "1.2.3");
  assert.throws(() => parseSemver("v0.1.0"), /Invalid semantic version/);
  assert.throws(() => parseSemver("01.1.0"), /Invalid semantic version/);
  assert.throws(() => bumpSemver("0.1.0", "prerelease"), /Invalid bump kind/);
});

test("bumpWorkspaceVersion updates VERSION, package.json, and GITHUB_OUTPUT", () => {
  const dir = mkdtempSync(join(tmpdir(), "parawing-bump-"));
  const outputPath = join(dir, "github-output.txt");
  const script = new URL("./bump-version.mjs", import.meta.url).pathname;
  try {
    writeFileSync(join(dir, "VERSION"), "0.1.0\n");
    writeFileSync(
      join(dir, "package.json"),
      `${JSON.stringify({ name: "parawing", private: true, version: "0.1.0" }, null, 2)}\n`,
    );

    const noop = bumpWorkspaceVersion({ rootDir: dir, bump: "none" });
    assert.deepEqual(noop, {
      previousVersion: "0.1.0",
      version: "0.1.0",
      tag: "v0.1.0",
      changed: false,
    });

    execFileSync(
      process.execPath,
      [script, "--root", dir, "--bump", "patch", "--github-output", outputPath],
      { encoding: "utf8" },
    );
    assert.equal(readFileSync(join(dir, "VERSION"), "utf8"), "0.1.1\n");
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    assert.equal(pkg.version, "0.1.1");

    const ghOut = readFileSync(outputPath, "utf8");
    assert.match(ghOut, /^previous_version=0\.1\.0$/m);
    assert.match(ghOut, /^version=0\.1\.1$/m);
    assert.match(ghOut, /^tag=v0\.1\.1$/m);
    assert.match(ghOut, /^changed=true$/m);

    const setRes = bumpWorkspaceVersion({ rootDir: dir, setVersion: "2.0.0" });
    assert.equal(setRes.version, "2.0.0");
    assert.equal(readFileSync(join(dir, "VERSION"), "utf8"), "2.0.0\n");
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  }
});
