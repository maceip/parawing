#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Builds `demo/vivari-client/dist` (Vivari in-browser Node runtime + Parawing
// `scene_host.wasm` client) and stages the unpacked MV3 Chrome Extension in
// `demo/chrome-extension/dist`.

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const VIVARI_ROOT = process.env.VIVARI_ROOT || resolve(REPO_ROOT, "../vivari");
const DEMO_ROOT = resolve(REPO_ROOT, "demo");
const VIVARI_CLIENT_DIR = resolve(DEMO_ROOT, "vivari-client");
const EXT_SRC_DIR = resolve(DEMO_ROOT, "chrome-extension");
const EXT_DIST_DIR = resolve(EXT_SRC_DIR, "dist");
const SCENE_HOST_WASM = resolve(REPO_ROOT, "packages/engine/public/rbi/scene_host.wasm");
const LOGO_SRC = resolve(REPO_ROOT, ".github/assets/parawing_logo.png");

async function loadDeps() {
  const rootReq = createRequire(resolve(REPO_ROOT, "package.json"));
  const engineReq = createRequire(resolve(REPO_ROOT, "packages/engine/package.json"));
  const vitestReq = createRequire(engineReq.resolve("vitest/package.json"));
  const { build } = await import(pathToFileURL(vitestReq.resolve("vite")).href);
  const { PNG } = rootReq("pngjs");
  return { build, PNG };
}

function resizePng(PNG, srcPng, outSize) {
  const dst = new PNG({ width: outSize, height: outSize });
  for (let y = 0; y < outSize; y += 1) {
    const sy = Math.min(srcPng.height - 1, Math.floor(((y + 0.5) * srcPng.height) / outSize));
    for (let x = 0; x < outSize; x += 1) {
      const sx = Math.min(srcPng.width - 1, Math.floor(((x + 0.5) * srcPng.width) / outSize));
      const sIdx = (sy * srcPng.width + sx) * 4;
      const dIdx = (y * outSize + x) * 4;
      dst.data[dIdx] = srcPng.data[sIdx];
      dst.data[dIdx + 1] = srcPng.data[sIdx + 1];
      dst.data[dIdx + 2] = srcPng.data[sIdx + 2];
      dst.data[dIdx + 3] = srcPng.data[sIdx + 3];
    }
  }
  return PNG.sync.write(dst);
}

async function main() {
  if (!existsSync(VIVARI_ROOT)) {
    throw new Error(`Missing Vivari checkout at ${VIVARI_ROOT}; set VIVARI_ROOT`);
  }
  if (!existsSync(SCENE_HOST_WASM)) {
    throw new Error(`Missing ${SCENE_HOST_WASM}; run pnpm run build first`);
  }
  if (!existsSync(LOGO_SRC)) {
    throw new Error(`Missing logo asset at ${LOGO_SRC}`);
  }
  const { build, PNG } = await loadDeps();

  console.log("[demo:build] Bundling Vivari + Parawing scene_host.wasm client…");
  const vivariOutDir = resolve(VIVARI_CLIENT_DIR, "dist");
  await build({
    configFile: false,
    root: VIVARI_CLIENT_DIR,
    base: "./",
    resolve: {
      alias: {
        "@vivari/core": resolve(VIVARI_ROOT, "packages/core/src/index.ts"),
        "node:module": resolve(VIVARI_CLIENT_DIR, "node-module-stub.js"),
      },
    },
    worker: {
      format: "es",
    },
    build: {
      outDir: vivariOutDir,
      emptyOutDir: true,
      target: "es2022",
    },
  });
  copyFileSync(SCENE_HOST_WASM, resolve(vivariOutDir, "scene_host.wasm"));
  const fontsSrcDir = resolve(REPO_ROOT, "packages/engine/public/fonts");
  const fontsOutDir = resolve(vivariOutDir, "fonts");
  mkdirSync(fontsOutDir, { recursive: true });
  for (const fontName of ["NotoSans.ttf", "NotoSansMono.ttf", "NotoSerif.ttf"]) {
    const src = resolve(fontsSrcDir, fontName);
    if (existsSync(src)) {
      copyFileSync(src, resolve(fontsOutDir, fontName));
    }
  }

  console.log("[demo:build] Staging MV3 Chrome Extension into demo/chrome-extension/dist…");
  rmSync(EXT_DIST_DIR, { recursive: true, force: true });
  mkdirSync(resolve(EXT_DIST_DIR, "icons"), { recursive: true });

  for (const file of readdirSync(EXT_SRC_DIR)) {
    if (file === "dist" || file === "icons") continue;
    copyFileSync(resolve(EXT_SRC_DIR, file), resolve(EXT_DIST_DIR, file));
  }

  const srcPng = PNG.sync.read(readFileSync(LOGO_SRC));
  for (const size of [16, 48, 128]) {
    writeFileSync(resolve(EXT_DIST_DIR, `icons/icon${size}.png`), resizePng(PNG, srcPng, size));
  }

  console.log("[demo:build] OK ->", EXT_DIST_DIR);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
