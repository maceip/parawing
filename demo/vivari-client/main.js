// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Boots `@vivari/core` inside a cross-origin-isolated frame, mounts Parawing's
// `scene_host.wasm` and `guest-parawing-client.mjs` into Vivari's VFS, spawns
// `node /parawing/client.mjs` in-browser, and bridges structured events/commands
// with the parent Chrome Extension workbench.

import { Vivari, isCrossOriginIsolated } from "@vivari/core";
import guestClientSource from "./guest-parawing-client.mjs?raw";

const statusEl = document.getElementById("status");

function postToExtension(type, payload = {}) {
  if (window.parent && window.parent !== window) {
    window.parent.postMessage({ source: "parawing-vivari-frame", type, ...payload }, "*");
  }
}

function resolveWispRelayUrl() {
  const params = new URLSearchParams(window.location.search);
  const explicit = params.get("relay");
  if (explicit && (explicit.startsWith("ws://") || explicit.startsWith("wss://"))) {
    return explicit;
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/parawing-demo-v1`;
}

async function bootClientInVivari() {
  if (!isCrossOriginIsolated()) {
    throw new Error("Cross-origin isolation (COOP/COEP) is not active on this Vivari host frame");
  }
  const netRelay = resolveWispRelayUrl();
  statusEl.textContent = `Booting Vivari kernel (relay: ${netRelay})…`;
  postToExtension("vivariStatus", { phase: "booting", netRelay, crossOriginIsolated: true });

  const wasmRes = await fetch("./scene_host.wasm");
  if (!wasmRes.ok) {
    throw new Error(`Failed to fetch ./scene_host.wasm: HTTP ${wasmRes.status}`);
  }
  const wasmBytes = new Uint8Array(await wasmRes.arrayBuffer());

  const fontFiles = [
    "NotoSans.ttf",
    "NotoSansMono.ttf",
    "NotoSerif.ttf",
    "DejaVuSans.ttf",
    "DejaVuSans-Bold.ttf",
    "DejaVuSansMono.ttf",
    "DejaVuSansMono-Bold.ttf",
  ];
  const fontDirectory = {};
  await Promise.all(
    fontFiles.map(async (name) => {
      try {
        const res = await fetch(`./fonts/${name}`);
        if (!res.ok) return;
        const buf = new Uint8Array(await res.arrayBuffer());
        if (buf.byteLength > 0) {
          fontDirectory[name] = { file: { contents: buf } };
        }
      } catch {}
    }),
  );

  const vivari = await Vivari.boot({
    serviceWorkerUrl: false,
    netRelay,
    defaultProcessRuntimeMs: 0,
  });

  await vivari.mount({
    parawing: {
      directory: {
        "package.json": {
          file: {
            contents: JSON.stringify({ name: "parawing-vivari-guest", type: "module" }, null, 2),
          },
        },
        "scene_host.wasm": {
          file: { contents: wasmBytes },
        },
        fonts: {
          directory: fontDirectory,
        },
        "client.mjs": {
          file: { contents: guestClientSource },
        },
      },
    },
  });

  const searchParams = new URLSearchParams(window.location.search);
  const targetId = searchParams.get("target") || `ext-${Math.random().toString(36).slice(2, 8)}`;
  const joinExisting = searchParams.get("join") === "1" ? "1" : "0";
  const nodeId = searchParams.get("nodeId") || "human-vivari";
  const proc = await vivari.spawn("node", ["/parawing/client.mjs"], {
    cwd: "/parawing",
    env: {
      PARAWING_TARGET_ID: targetId,
      PARAWING_JOIN: joinExisting,
      PARAWING_NODE_ID: nodeId,
    },
  });

  const stdinWriter = proc.input.getWriter();
  window.addEventListener("message", (ev) => {
    const data = ev.data;
    if (!data || data.source !== "parawing-extension" || !data.command) return;
    stdinWriter.write(`${JSON.stringify(data.command)}\n`).catch((err) => {
      postToExtension("vivariError", { message: `stdin write failed: ${err.message}` });
    });
  });

  statusEl.textContent = `Vivari Node PID ${proc.pid} active`;
  postToExtension("vivariSpawned", { pid: proc.pid, targetId });

  let lineBuf = "";
  for await (const chunk of proc.output) {
    postToExtension("vivariRawOutput", { chunk });
    lineBuf += chunk;
    let idx = lineBuf.indexOf("\n");
    while (idx !== -1) {
      const line = lineBuf.slice(0, idx).replace(/\r$/, "");
      lineBuf = lineBuf.slice(idx + 1);
      if (line.startsWith("__PARAWING_EVT__")) {
        try {
          const evt = JSON.parse(line.slice("__PARAWING_EVT__".length));
          postToExtension("parawingEvent", { event: evt });
        } catch (err) {
          postToExtension("vivariError", { message: `bad guest event JSON: ${err.message}` });
        }
      } else if (line.trim()) {
        postToExtension("vivariGuestLine", { line });
      }
      idx = lineBuf.indexOf("\n");
    }
  }

  const exitCode = await proc.exit;
  statusEl.textContent = `Vivari guest exited (${exitCode})`;
  postToExtension("vivariExited", { exitCode });
}

bootClientInVivari().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  statusEl.textContent = `Vivari boot error: ${message}`;
  postToExtension("vivariError", { message });
});
