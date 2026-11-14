// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Safely serves static public assets (fonts, RBI, inspector) from the local filesystem.

import { existsSync, realpathSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve } from "node:path";
import type { AssetCapability } from "@parawing/engine/host-capabilities";

export interface FileAssetCapabilityOptions {
  rootDir?: string;
}

const MIME_BY_EXT: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".otf": "font/otf",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
  ".woff2": "font/woff2",
};

export function resolveDefaultPublicDir(): string {
  const fromEnv = process.env["PARAWING_PUBLIC_DIR"];
  if (fromEnv && existsSync(fromEnv)) return resolve(fromEnv);
  const candidates = [
    resolve(import.meta.dirname, "../../engine/public"),
    resolve(import.meta.dirname, "../../../packages/engine/public"),
    resolve(process.cwd(), "../engine/public"),
    resolve(process.cwd(), "packages/engine/public"),
  ];
  for (const dir of candidates) {
    if (existsSync(dir)) return dir;
  }
  return candidates[0]!;
}

function isInsideRoot(rootReal: string, targetReal: string): boolean {
  const rel = relative(rootReal, targetReal);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

function decodeRequestPath(pathname: string): string | null {
  if (pathname.includes("\0")) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (decoded.includes("\0")) return null;
  const trimmed = decoded.replace(/^\/+/, "");
  if (!trimmed || trimmed.split("/").some((seg) => seg === "." || seg === "..")) {
    return null;
  }
  return trimmed;
}

export function createFileAssetCapability(
  options: FileAssetCapabilityOptions = {},
): AssetCapability {
  const configuredRoot = resolve(options.rootDir ?? resolveDefaultPublicDir());
  const rootReal = existsSync(configuredRoot) ? realpathSync(configuredRoot) : configuredRoot;

  return {
    async fetch(request: Request): Promise<Response> {
      const method = request.method.toUpperCase();
      if (method !== "GET" && method !== "HEAD") {
        return new Response("Method Not Allowed", {
          status: 405,
          headers: { allow: "GET, HEAD" },
        });
      }
      const url = new URL(request.url);
      const relPath = decodeRequestPath(url.pathname);
      if (!relPath) {
        return new Response("Forbidden", { status: 403 });
      }
      const candidate = resolve(rootReal, relPath);
      if (!isInsideRoot(rootReal, candidate)) {
        return new Response("Forbidden", { status: 403 });
      }
      let realPath: string;
      try {
        realPath = realpathSync(candidate);
      } catch {
        return new Response("Not Found", { status: 404 });
      }
      if (!isInsideRoot(rootReal, realPath)) {
        return new Response("Forbidden", { status: 403 });
      }
      let stat;
      try {
        stat = statSync(realPath);
      } catch {
        return new Response("Not Found", { status: 404 });
      }
      if (!stat.isFile()) {
        return new Response("Not Found", { status: 404 });
      }

      const etag = `W/"${stat.size}-${Math.floor(stat.mtimeMs)}"`;
      const headers = new Headers({
        "content-type": MIME_BY_EXT[extname(realPath).toLowerCase()] ?? "application/octet-stream",
        "content-length": String(stat.size),
        etag,
        "cache-control": "public, max-age=3600",
      });

      if (request.headers.get("if-none-match") === etag) {
        return new Response(null, { status: 304, headers });
      }
      if (method === "HEAD") {
        return new Response(null, { status: 200, headers });
      }
      const bytes = await readFile(realPath);
      return new Response(bytes, { status: 200, headers });
    },
  };
}
