// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Chrome Extension workbench controller: manages the cross-origin-isolated Vivari
// iframe, renders client-composited KSC2 frames onto `<canvas>`, forwards user
// interactions into Vivari's in-browser Node.js process, and persists droplet settings.

const DEFAULT_DROPLET_ORIGIN = "https://167-99-170-67.sslip.io";

const els = {
  connBadge: document.getElementById("conn-badge"),
  endpointForm: document.getElementById("endpoint-form"),
  dropletOrigin: document.getElementById("droplet-origin"),
  activeTabBtn: document.getElementById("active-tab-btn"),
  welcomeBtn: document.getElementById("welcome-btn"),
  epochBadge: document.getElementById("epoch-badge"),
  takeControlBtn: document.getElementById("take-control-btn"),
  handbackBtn: document.getElementById("handback-btn"),
  epochReadout: document.getElementById("epoch-readout"),
  navForm: document.getElementById("nav-form"),
  navUrl: document.getElementById("nav-url"),
  pageTitle: document.getElementById("page-title"),
  evalForm: document.getElementById("eval-form"),
  evalExpr: document.getElementById("eval-expr"),
  evalOutput: document.getElementById("eval-output"),
  attestBtn: document.getElementById("attest-btn"),
  freezeBtn: document.getElementById("freeze-btn"),
  thawBtn: document.getElementById("thaw-btn"),
  leaseBadge: document.getElementById("lease-badge"),
  continuityReadout: document.getElementById("continuity-readout"),
  metricVivari: document.getElementById("metric-vivari"),
  metricHost: document.getElementById("metric-host"),
  metricCapsule: document.getElementById("metric-capsule"),
  metricFrames: document.getElementById("metric-frames"),
  metricBytes: document.getElementById("metric-bytes"),
  metricTiles: document.getElementById("metric-tiles"),
  viewportUrl: document.getElementById("viewport-url"),
  hitReadout: document.getElementById("hit-readout"),
  canvas: document.getElementById("viewport-canvas"),
  vivariFrame: document.getElementById("vivari-frame"),
  vivariPid: document.getElementById("vivari-pid"),
  eventLog: document.getElementById("event-log"),
  clearLogBtn: document.getElementById("clear-log-btn"),
  workbenchGrid: document.getElementById("workbench-grid"),
  splitterLeft: document.getElementById("splitter-left"),
  splitterRight: document.getElementById("splitter-right"),
};

const ctx = els.canvas.getContext("2d");
const initialParams = new URLSearchParams(window.location.search);
const pinnedTargetId = initialParams.get("target") || "";
const joinExistingTarget = initialParams.get("join") === "1";
let reqCounter = 1;
let activeTargetOrigin = DEFAULT_DROPLET_ORIGIN;

function appendLog(line) {
  const stamp = new Date().toISOString().slice(11, 23);
  els.eventLog.textContent += `[${stamp}] ${line}\n`;
  if (els.eventLog.textContent.length > 64_000) {
    els.eventLog.textContent = els.eventLog.textContent.slice(-48_000);
  }
  els.eventLog.scrollTop = els.eventLog.scrollHeight;
}

function setBadge(state, label) {
  els.connBadge.dataset.state = state;
  els.connBadge.textContent = label;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

function sendGuestCommand(action, payload = {}) {
  const win = els.vivariFrame.contentWindow;
  if (!win) {
    appendLog(`WARN: Vivari frame not ready for ${action}`);
    return "";
  }
  const reqId = `r-${reqCounter++}`;
  win.postMessage(
    {
      source: "parawing-extension",
      command: { reqId, action, ...payload },
    },
    "*",
  );
  return reqId;
}

function drawPngBase64(pngBase64, width, height) {
  const img = new Image();
  img.onload = () => {
    if (width > 0 && height > 0 && (els.canvas.width !== width || els.canvas.height !== height)) {
      els.canvas.width = width;
      els.canvas.height = height;
    }
    ctx.clearRect(0, 0, els.canvas.width, els.canvas.height);
    ctx.drawImage(img, 0, 0);
    els.canvas.dataset.renderedFrames = String(
      Number(els.canvas.dataset.renderedFrames || "0") + 1,
    );
  };
  img.src = `data:image/png;base64,${pngBase64}`;
}

function renderEpochLease(evt) {
  const selfNodeId = evt.selfNodeId || "human-vivari";
  const isHumanOwner = evt.ownerNodeId === selfNodeId;
  els.epochBadge.dataset.state = isHumanOwner ? "connected" : "connecting";
  els.epochBadge.textContent = `Epoch ${evt.epoch} · ${evt.ownerNodeId}`;
  els.takeControlBtn.disabled = isHumanOwner;
  els.handbackBtn.disabled = !isHumanOwner;
  const viewers =
    Array.isArray(evt.viewerNodes) && evt.viewerNodes.length > 0
      ? evt.viewerNodes.join(", ")
      : "none";
  els.epochReadout.textContent = `Owner: ${evt.ownerNodeId} · viewers: ${viewers}`;
}

function handleParawingEvent(evt) {
  switch (evt.type) {
    case "boot":
      els.metricVivari.textContent = `Node ${evt.nodeVersion} (${evt.platform}/${evt.arch})`;
      appendLog(`Vivari guest booted: Node ${evt.nodeVersion} PID=${evt.pid}`);
      break;
    case "wasmReady":
      appendLog(
        `Loaded client scene_host.wasm (${formatBytes(evt.wasmBytes)}, sha256=${evt.wasmSha256.slice(0, 12)}…)`,
      );
      break;
    case "dropletConnected":
      setBadge("connected", "Connected");
      els.metricHost.textContent = evt.browser;
      els.metricCapsule.textContent = `${evt.capsuleHash.slice(0, 12)}…`;
      appendLog(
        `Droplet connected: ${evt.browser} (CRIU=${evt.criuEnabled}, capsule=${evt.capsuleHash.slice(0, 16)}…)`,
      );
      break;
    case "epochState":
      renderEpochLease(evt);
      appendLog(
        `Epoch #${evt.epoch} lease -> owner=${evt.ownerNodeId} viewers=[${(evt.viewerNodes || []).join(", ")}]`,
      );
      break;
    case "handoff":
      renderEpochLease(evt);
      appendLog(
        `HANDOFF -> Epoch #${evt.epoch} owner=${evt.ownerNodeId} (fenced viewers: [${(evt.viewerNodes || []).join(", ")}])`,
      );
      break;
    case "frame":
      els.metricFrames.textContent = String(evt.totalFrames);
      els.metricBytes.textContent = formatBytes(evt.totalWireBytes);
      els.metricTiles.textContent = `${evt.tilesCached} cached (${evt.tileCount} in frame)`;
      drawPngBase64(evt.pngBase64, evt.width, evt.height);
      appendLog(
        `KSC2 frame #${evt.frameSeq}: ${evt.ksc2Bytes} B vector scene -> ${evt.width}×${evt.height} RGBA via scene_host.wasm`,
      );
      break;
    case "navigated":
      els.viewportUrl.textContent = evt.url;
      els.pageTitle.textContent = evt.title || "Untitled";
      appendLog(`Navigated -> ${evt.url} ("${evt.title || ""}")`);
      break;
    case "evalResult":
      els.evalOutput.textContent = JSON.stringify(evt.value);
      if (evt.title) els.pageTitle.textContent = evt.title;
      appendLog(`Isolate eval -> ${JSON.stringify(evt.value)}`);
      break;
    case "hitTestResult":
      els.hitReadout.textContent = evt.hit
        ? `node=${evt.nodeId}${evt.linkUrl ? ` link=${evt.linkUrl}` : ""}`
        : `miss @ (${Math.round(evt.x)}, ${Math.round(evt.y)})`;
      appendLog(
        `Wasm hit-test (${Math.round(evt.x)}, ${Math.round(evt.y)}) -> ${JSON.stringify(evt)}`,
      );
      break;
    case "attested":
      els.leaseBadge.textContent = evt.leaseId;
      els.continuityReadout.textContent = `Lease ${evt.leaseId} (sig ${evt.signaturePrefix}…)`;
      appendLog(`Attested capsule lease issued: ${evt.leaseId}`);
      break;
    case "frozen":
      els.thawBtn.disabled = false;
      els.continuityReadout.textContent = `Frozen (${evt.backend}) sha256=${evt.bundleSha256}…`;
      appendLog(`Session frozen on droplet (${evt.backend}): bundle=${evt.bundleSha256}…`);
      break;
    case "thawed":
      els.continuityReadout.textContent = `Thawed (${evt.tier}) ${evt.fullSceneBytes} B KSC2`;
      if (evt.title) els.pageTitle.textContent = evt.title;
      appendLog(
        `Session thawed (${evt.tier}): ${evt.fullSceneBytes} B scene, reseed=${evt.csprngReseedSha256}…`,
      );
      break;
    case "commandError":
      els.evalOutput.textContent = `Error: ${evt.message}`;
      appendLog(`ERROR (${evt.action}): ${evt.message}`);
      break;
    case "fatal":
      setBadge("error", "Guest Error");
      appendLog(`FATAL: ${evt.message}`);
      break;
  }
}

window.addEventListener("message", (ev) => {
  const msg = ev.data;
  if (!msg || msg.source !== "parawing-vivari-frame") return;
  if (msg.type === "vivariStatus") {
    setBadge("connecting", "Vivari Booting");
    appendLog(`Vivari host isolated=${msg.crossOriginIsolated}, relay=${msg.netRelay}`);
  } else if (msg.type === "vivariSpawned") {
    els.vivariPid.textContent = `PID ${msg.pid}`;
  } else if (msg.type === "parawingEvent") {
    handleParawingEvent(msg.event);
  } else if (msg.type === "vivariGuestLine") {
    appendLog(`[guest] ${msg.line}`);
  } else if (msg.type === "vivariError") {
    setBadge("error", "Error");
    appendLog(`Vivari error: ${msg.message}`);
  } else if (msg.type === "vivariExited") {
    setBadge("error", `Exited (${msg.exitCode})`);
    appendLog(`Vivari guest exited with code ${msg.exitCode}`);
  }
});

function connectToOrigin(rawOrigin) {
  const clean = rawOrigin.trim().replace(/\/+$/, "");
  activeTargetOrigin = clean;
  els.dropletOrigin.value = clean;
  setBadge("connecting", "Connecting");
  els.thawBtn.disabled = true;
  const proto = clean.startsWith("https://") ? "wss://" : "ws://";
  const hostPart = clean.replace(/^https?:\/\//, "");
  const relayUrl = `${proto}${hostPart}/parawing-demo-v1`;
  const frameParams = new URLSearchParams({
    relay: relayUrl,
    t: String(Date.now()),
  });
  if (pinnedTargetId) frameParams.set("target", pinnedTargetId);
  if (joinExistingTarget) frameParams.set("join", "1");
  const frameUrl = `${clean}/vivari/index.html?${frameParams.toString()}`;
  appendLog(`Loading Vivari client frame from ${clean}/vivari/`);
  els.vivariFrame.src = frameUrl;
  if (globalThis.chrome?.storage?.local) {
    chrome.storage.local.set({ dropletOrigin: clean });
  }
}

els.endpointForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  connectToOrigin(els.dropletOrigin.value);
});

els.welcomeBtn.addEventListener("click", () => {
  sendGuestCommand("resetWelcome");
});

els.activeTabBtn.addEventListener("click", async () => {
  if (!globalThis.chrome?.runtime?.sendMessage) return;
  const res = await chrome.runtime.sendMessage({ type: "GET_LATEST_HTTP_TAB" });
  if (res?.url) {
    els.navUrl.value = res.url;
    sendGuestCommand("navigate", { url: res.url });
  } else {
    appendLog("No open http/https tab found to co-browse.");
  }
});

els.navForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  sendGuestCommand("navigate", { url: els.navUrl.value.trim() });
});

els.evalForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  sendGuestCommand("evalJs", { expression: els.evalExpr.value });
});

els.takeControlBtn.addEventListener("click", () => {
  sendGuestCommand("handoff", { newOwner: "human-vivari" });
});
els.handbackBtn.addEventListener("click", () => {
  sendGuestCommand("handoff", { newOwner: "agent-alpha" });
});
els.attestBtn.addEventListener("click", () => sendGuestCommand("attest"));
els.freezeBtn.addEventListener("click", () => sendGuestCommand("freeze"));
els.thawBtn.addEventListener("click", () => sendGuestCommand("thaw"));
els.clearLogBtn.addEventListener("click", () => {
  els.eventLog.textContent = "";
});

els.canvas.addEventListener("click", (ev) => {
  const rect = els.canvas.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return;
  const scaleX = els.canvas.width / rect.width;
  const scaleY = els.canvas.height / rect.height;
  const x = (ev.clientX - rect.left) * scaleX;
  const y = (ev.clientY - rect.top) * scaleY;
  sendGuestCommand("hitTest", { x, y, navigateOnLink: true });
});

function installSplitter(splitterEl, cssVar, defaultPx, invertDelta) {
  splitterEl.addEventListener("dblclick", () => {
    document.documentElement.style.setProperty(cssVar, `${defaultPx}px`);
  });
  splitterEl.addEventListener("pointerdown", (downEv) => {
    downEv.preventDefault();
    splitterEl.setPointerCapture(downEv.pointerId);
    const startX = downEv.clientX;
    const current =
      parseFloat(getComputedStyle(document.documentElement).getPropertyValue(cssVar)) || defaultPx;
    const onMove = (moveEv) => {
      const delta = (moveEv.clientX - startX) * (invertDelta ? -1 : 1);
      const clamped = Math.max(220, Math.min(520, Math.round(current + delta)));
      document.documentElement.style.setProperty(cssVar, `${clamped}px`);
    };
    const onUp = (upEv) => {
      splitterEl.releasePointerCapture(upEv.pointerId);
      splitterEl.removeEventListener("pointermove", onMove);
      splitterEl.removeEventListener("pointerup", onUp);
    };
    splitterEl.addEventListener("pointermove", onMove);
    splitterEl.addEventListener("pointerup", onUp);
  });
}

installSplitter(els.splitterLeft, "--left-w", 296, false);
installSplitter(els.splitterRight, "--right-w", 320, true);

async function init() {
  const urlOverride = new URLSearchParams(window.location.search).get("origin");
  if (urlOverride) {
    connectToOrigin(urlOverride);
    return;
  }
  if (globalThis.chrome?.storage?.local) {
    const stored = await chrome.storage.local.get(["dropletOrigin"]);
    connectToOrigin(stored?.dropletOrigin || activeTargetOrigin);
  } else {
    connectToOrigin(activeTargetOrigin);
  }
}

init();
