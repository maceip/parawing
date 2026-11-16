// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { extractDependencyInventory } from "./deps/inventory.mjs";
import { runOptionalLlmTriage } from "./deps/llm-assist.mjs";
import { evaluateAdvisories, verifyOfflineAdvisoryLock } from "./deps/osv-scanner.mjs";
import { sha256Hex, verifyAllPatchesAndOverrides } from "./deps/patch-verifier.mjs";
import { buildOpenVexDocument, renderMarkdownReport } from "./deps/reporter.mjs";
import {
  compareSemver,
  isVersionAffectedByOsvEvents,
  satisfiesConstraint,
} from "./deps/semver.mjs";

const VALID_GIT_PATCH = [
  "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001",
  "From: Parawing Security <sec@parawing.invalid>",
  "Date: Mon, 16 Nov 2026 00:00:00 +0000",
  "Subject: [PATCH] Fix soundness bug",
  "",
  "Detach node before dropping key.",
  "---",
  "diff --git a/src/lib.rs b/src/lib.rs",
  "--- a/src/lib.rs",
  "+++ b/src/lib.rs",
  "@@ -1,1 +1,1 @@",
  "-old",
  "+new",
  "",
].join("\n");

function createSyntheticRepo(t) {
  const root = mkdtempSync(join(tmpdir(), "parawing-deps-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "deps"), { recursive: true });
  mkdirSync(join(root, "packages/core"), { recursive: true });
  mkdirSync(join(root, "packages/rust-host"), { recursive: true });
  mkdirSync(join(root, "scripts/patches/lru-0.12.5"), { recursive: true });
  const patchSha = sha256Hex(Buffer.from(VALID_GIT_PATCH, "utf8"));
  const tarballSha = "234cf4f4a04dc1f57e24b96cc0cd600cf2af460d4161ac5ecdd0af8e1f3b2a38";
  writeFileSync(join(root, "VERSION"), "0.1.6\n");
  writeFileSync(join(root, "scripts/patches/lru-0.12.5/0001-fix.patch"), VALID_GIT_PATCH);
  writeFileSync(
    join(root, "scripts/patches/README.md"),
    "| Crate | Version |\n| `lru` | `0.12.5` |\n",
  );
  writeFileSync(
    join(root, "Cargo.toml"),
    '[workspace]\n[patch.crates-io]\nlru = { path = "packages/core/target/vendor-patched/lru-0.12.5" }\n',
  );
  writeFileSync(
    join(root, "packages/rust-host/Cargo.toml"),
    '[package]\nname = "parawing-rust-host"\n[patch.crates-io]\nlru = { path = "../core/target/vendor-patched/lru-0.12.5" }\n',
  );
  writeFileSync(join(root, "packages/core/BUILD.bazel"), 'rust_test(name = "core_test")\n');
  writeFileSync(
    join(root, "MODULE.bazel"),
    `cargo_workspaces.patched(\n  sha256 = {\n    "lru-0.12.5": "${tarballSha}",\n  },\n)\n`,
  );
  writeFileSync(
    join(root, "Cargo.lock"),
    'version = 4\n\n[[package]]\nname = "lru"\nversion = "0.12.5"\n',
  );
  const integrityB64 = Buffer.alloc(64, 9).toString("base64");
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({
      name: "parawing",
      pnpm: { overrides: { "hono@>=4.0.0 <4.13.16": "^4.13.19" } },
    }),
  );
  writeFileSync(
    join(root, "pnpm-lock.yaml"),
    `lockfileVersion: '9.0'\npackages:\n  'hono@4.13.19':\n    resolution: {integrity: sha512-${integrityB64}}\n`,
  );
  const manifest = {
    schemaVersion: 1,
    cargoPatches: [
      {
        crate: "lru",
        version: "0.12.5",
        upstreamRepo: "https://github.com/jeromefroe/lru-rs",
        tarballSha256: tarballSha,
        seriesSha8: "deadbeef",
        mitigates: ["RUSTSEC-2026-0253"],
        verificationTargets: ["//packages/core:core_test"],
        patches: [{ file: "0001-fix.patch", sha256: patchSha, subject: "Fix soundness bug" }],
      },
    ],
    auxiliaryPatches: [],
    npmOverrides: [
      {
        package: "hono",
        selector: "hono@>=4.0.0 <4.13.16",
        replacement: "^4.13.19",
        minSafeVersion: "4.13.16",
        mitigates: ["GHSA-h7mg-cq63-vhpq"],
      },
    ],
    waivers: [],
    trackedUnmaintained: [
      {
        advisoryId: "RUSTSEC-2024-0436",
        package: "paste",
        reason: "Compile-time macro only",
        reviewBy: "2028-01-01T00:00:00Z",
      },
    ],
  };
  writeFileSync(join(root, "deps/patches-manifest.json"), JSON.stringify(manifest, null, 2));
  return { root, manifest };
}

test("semver comparison, override constraints, and OSV range events evaluate deterministically", () => {
  assert.equal(compareSemver("0.12.5", "0.16.3"), -1);
  assert.equal(compareSemver("4.13.19", "4.13.16"), 1);
  assert.equal(compareSemver("1.0.0-beta.2", "1.0.0"), -1);
  assert.equal(satisfiesConstraint("4.13.12", ">=4.0.0 <4.13.16"), true);
  assert.equal(satisfiesConstraint("4.13.19", ">=4.0.0 <4.13.16"), false);
  assert.equal(satisfiesConstraint("4.13.19", "^4.13.16"), true);
  const events = [{ introduced: "0" }, { fixed: "0.18.2" }];
  assert.equal(isVersionAffectedByOsvEvents("0.12.5", events), true);
  assert.equal(isVersionAffectedByOsvEvents("0.18.2", events), false);
});

test("patch verifier passes clean repo and catches tampered patch, conflict marker, and override bypass", (t) => {
  const { root } = createSyntheticRepo(t);
  const inventory = extractDependencyInventory(root);
  const clean = verifyAllPatchesAndOverrides(root, inventory.packages);
  assert.equal(clean.ok, true, clean.errors.join("\n"));

  writeFileSync(
    join(root, "scripts/patches/lru-0.12.5/0001-fix.patch"),
    `${VALID_GIT_PATCH}\n<<<<<<< HEAD\n`,
  );
  const tampered = verifyAllPatchesAndOverrides(root, inventory.packages);
  assert.equal(tampered.ok, false);
  assert.equal(
    tampered.errors.some((e) => e.includes("SHA-256 mismatch")),
    true,
  );
  assert.equal(
    tampered.errors.some((e) => e.includes("conflict marker")),
    true,
  );

  writeFileSync(join(root, "scripts/patches/lru-0.12.5/0001-fix.patch"), VALID_GIT_PATCH);
  const regressedInventory = [
    ...inventory.packages,
    { ecosystem: "npm", name: "hono", version: "4.13.12" },
  ];
  const overrideFail = verifyAllPatchesAndOverrides(root, regressedInventory);
  assert.equal(overrideFail.ok, false);
  assert.equal(
    overrideFail.errors.some((e) => e.includes("below minSafeVersion 4.13.16")),
    true,
  );
});

test("advisory evaluator resolves patched bugs, tracks unmaintained, and fails unmitigated CVEs", (t) => {
  const { root, manifest } = createSyntheticRepo(t);
  const inventory = extractDependencyInventory(root);
  const advisories = [
    {
      id: "RUSTSEC-2026-0253",
      aliases: [],
      packageKey: "crates.io:lru@0.12.5",
      ecosystem: "crates.io",
      packageName: "lru",
      packageVersion: "0.12.5",
      purl: "pkg:cargo/lru@0.12.5",
      kind: "unsound",
      summary: "LruCache::pop panic safety",
      fixedVersions: ["0.18.2"],
    },
    {
      id: "RUSTSEC-2024-0436",
      aliases: [],
      packageKey: "crates.io:paste@1.0.15",
      ecosystem: "crates.io",
      packageName: "paste",
      packageVersion: "1.0.15",
      purl: "pkg:cargo/paste@1.0.15",
      kind: "unmaintained",
      summary: "paste unmaintained",
      fixedVersions: [],
    },
  ];
  writeFileSync(
    join(root, "deps/advisory-lock.json"),
    JSON.stringify({ inventoryDigest: inventory.digest, advisories }, null, 2),
  );
  const okRes = verifyOfflineAdvisoryLock(root, inventory, manifest, "2026-11-16T00:00:00Z");
  assert.equal(okRes.ok, true, okRes.errors.join("\n"));

  const vex = buildOpenVexDocument({
    version: "0.1.6",
    created: "2026-11-16T00:00:00Z",
    resolvedAdvisories: okRes.resolved,
  });
  assert.equal(vex["@context"], "https://openvex.dev/ns/v0.2.0");
  assert.equal(vex.statements[0].status, "fixed");

  const unmitigated = evaluateAdvisories(
    [
      ...advisories,
      {
        id: "CVE-2026-99999",
        aliases: [],
        packageKey: "npm:hono@4.13.12",
        ecosystem: "npm",
        packageName: "hono",
        packageVersion: "4.13.12",
        purl: "pkg:npm/hono@4.13.12",
        kind: "vulnerability",
        summary: "Middleware bypass",
        fixedVersions: ["4.13.16"],
      },
    ],
    manifest,
    "2026-11-16T00:00:00Z",
  );
  assert.equal(unmitigated.ok, false);
  assert.match(unmitigated.errors[0], /Unmitigated vulnerability CVE-2026-99999/);
});

test("embedded and remote LLM triage assistants remain strictly advisory and never relied upon", async (t) => {
  const disabled = await runOptionalLlmTriage({ mode: "none", prompt: "test" });
  assert.equal(disabled.status, "disabled");
  assert.equal(disabled.reliedUpon, false);
  assert.equal(disabled.verified, false);

  const dir = mkdtempSync(join(tmpdir(), "parawing-llm-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binPath = join(dir, "mock-llama-cli");
  const modelPath = join(dir, "model.gguf");
  writeFileSync(modelPath, "gguf");
  writeFileSync(
    binPath,
    `#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({summary:"Patched in lru",reachability:"parley->lru",recommendedAction:"Keep patch until lru 0.19",candidatePatchPlan:"done"}));\n`,
    { mode: 0o755 },
  );

  const embedded = await runOptionalLlmTriage({
    mode: "embedded",
    prompt: "analyze lru",
    env: { PARAWING_DEPS_LLM_BIN: binPath, PARAWING_DEPS_LLM_MODEL_PATH: modelPath },
  });
  assert.equal(embedded.status, "completed");
  assert.equal(embedded.reliedUpon, false);
  assert.equal(embedded.verified, false);
  assert.equal(embedded.analysis.summary, "Patched in lru");

  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        choices: [
          {
            message: {
              content: JSON.stringify({
                summary: "Remote triage ok",
                reachability: "none",
                recommendedAction: "verified",
              }),
            },
          },
        ],
      }),
    );
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  t.after(() => server.close());
  const port = server.address().port;

  const remote = await runOptionalLlmTriage({
    mode: "remote",
    prompt: "analyze",
    env: {
      PARAWING_DEPS_LLM_URL: `http://127.0.0.1:${port}/v1/chat/completions`,
      PARAWING_DEPS_LLM_MODEL: "test-model",
    },
  });
  assert.equal(remote.status, "completed");
  assert.equal(remote.reliedUpon, false);
  assert.equal(remote.analysis.summary, "Remote triage ok");

  const brokenRemote = await runOptionalLlmTriage({
    mode: "remote",
    prompt: "analyze",
    env: { PARAWING_DEPS_LLM_URL: "http://127.0.0.1:1/unreachable", PARAWING_DEPS_LLM_MODEL: "m" },
    timeoutMs: 500,
  });
  assert.equal(brokenRemote.status, "unavailable");
  assert.equal(brokenRemote.reliedUpon, false);

  const md = renderMarkdownReport({
    version: "0.1.6",
    inventory: { digest: "abc", counts: { total: 2, cargo: 1, npm: 1, bazelAndToolchains: 0 } },
    patchCheck: {
      ok: true,
      summary: { totalPatchFiles: 1, cargoSeries: 1, auxiliaryPatches: 0, npmSecurityOverrides: 1 },
    },
    advisoryCheck: { ok: true, resolved: [] },
    manifest: { cargoPatches: [] },
    llmResult: remote,
  });
  assert.match(md, /Advisory-Only, Never Authoritative/);
});
