// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Client controller for the pastel GitHub Pages landing demo: drives the high-contrast Parawing
// co-browser, animated agent cursor, Take Control handoff, and in-browser scenario overlay.

const cfg = globalThis.__PARAWING_SHOWCASE_CONFIG__ || {
  serverOrigin: "https://64-225-124-165.sslip.io",
  dropletRegion: "sfo2",
};

const params = new URLSearchParams(window.location.search);
const activeOrigin = (params.get("server") || cfg.serverOrigin).replace(/\/$/, "");
const wsProto = activeOrigin.startsWith("https:") ? "wss:" : "ws:";
const wsHost = activeOrigin.replace(/^https?:\/\//, "");

const els = {
  hostMeta: document.getElementById("droplet-meta"),
  connBadge: document.getElementById("conn-badge"),
  sessionToggleBtn: document.getElementById("session-toggle-btn"),
  backBtn: document.getElementById("back-btn"),
  forwardBtn: document.getElementById("forward-btn"),
  reloadBtn: document.getElementById("reload-btn"),
  urlForm: document.getElementById("url-form"),
  urlInput: document.getElementById("url-input"),
  goBtn: document.getElementById("go-btn"),
  policyBanner: document.getElementById("policy-banner"),
  policyBannerText: document.getElementById("policy-banner-text"),
  dismissPolicyBtn: document.getElementById("dismiss-policy-btn"),
  viewportWrap: document.getElementById("viewport-wrap"),
  canvas: document.getElementById("browser-canvas"),
  agentCursor: document.getElementById("agent-cursor"),
  agentCursorTag: document.getElementById("agent-cursor-tag"),
  clickRipple: document.getElementById("agent-click-ripple"),
  agentStatusText: document.getElementById("agent-status-text"),
  takeControlBtn: document.getElementById("take-control-btn"),
  loadingOverlay: document.getElementById("loading-overlay"),
  loadingText: document.getElementById("loading-text"),
  engineTelemetry: document.getElementById("engine-telemetry"),
  policyTelemetry: document.getElementById("policy-telemetry"),
  loadNewsBtn: document.getElementById("load-news-btn"),
  testBlockBtn: document.getElementById("test-block-btn"),
  cardReconnectBtn: document.getElementById("card-reconnect-btn"),
};

const ctx2d = els.canvas.getContext("2d");

const state = {
  ws: null,
  sessionId: `aol-${Math.random().toString(36).slice(2, 12)}`,
  connected: false,
  manualDisconnect: false,
  pendingCommand: null,
  controller: "agent",
  epoch: 1,
  cursorX: 640,
  cursorY: 260,
  agentMoves: 0,
  agentClicks: 0,
  frameCount: 0,
  lastResumedTier: null,
  blockedNavigations: 0,
  blockedSubresources: 0,
  wheelQueued: false,
  wheelAccX: 0,
  wheelAccY: 0,
  wheelLastX: 640,
  wheelLastY: 380,
};

function setConnBadge(mode, text) {
  els.connBadge.setAttribute("data-state", mode);
  els.connBadge.textContent = text;
}

function showLoading(message) {
  els.loadingText.textContent = message;
  els.loadingOverlay.hidden = false;
}

function hideLoading() {
  els.loadingOverlay.hidden = true;
}

function showPolicyBlock(reason) {
  els.policyBannerText.textContent = reason;
  els.policyBanner.hidden = false;
}

function syncCursorTransform() {
  const rect = els.canvas.getBoundingClientRect();
  const scaleX = rect.width > 0 ? rect.width / els.canvas.width : 1;
  const scaleY = rect.height > 0 ? rect.height / els.canvas.height : 1;
  const pxX = Math.round(state.cursorX * scaleX);
  const pxY = Math.round(state.cursorY * scaleY);
  els.agentCursor.style.transform = `translate3d(${pxX}px, ${pxY}px, 0)`;
  els.agentCursor.setAttribute("data-x", String(state.cursorX));
  els.agentCursor.setAttribute("data-y", String(state.cursorY));
}

function triggerClickRipple(logicalX, logicalY) {
  const rect = els.canvas.getBoundingClientRect();
  const scaleX = rect.width > 0 ? rect.width / els.canvas.width : 1;
  const scaleY = rect.height > 0 ? rect.height / els.canvas.height : 1;
  const pxX = Math.round(logicalX * scaleX);
  const pxY = Math.round(logicalY * scaleY);
  els.clickRipple.style.setProperty("--ripple-x", `${pxX}px`);
  els.clickRipple.style.setProperty("--ripple-y", `${pxY}px`);
  els.clickRipple.setAttribute("data-animating", "false");
  void els.clickRipple.offsetWidth;
  els.clickRipple.setAttribute("data-animating", "true");

  els.agentCursor.setAttribute("data-clicking", "true");
  setTimeout(() => {
    els.agentCursor.setAttribute("data-clicking", "false");
  }, 190);
}

function applyControlState(controller, epoch, statusNote) {
  state.controller = controller === "human" ? "human" : "agent";
  if (typeof epoch === "number" && Number.isFinite(epoch)) {
    state.epoch = epoch;
  }
  const isAgent = state.controller === "agent";
  els.agentStatusText.setAttribute("data-controller", state.controller);
  els.takeControlBtn.setAttribute("data-controller", state.controller);
  els.takeControlBtn.setAttribute("data-epoch", String(state.epoch));
  els.agentCursor.setAttribute("data-active", isAgent && state.connected ? "true" : "false");

  if (isAgent) {
    els.takeControlBtn.textContent = "■ Take Control";
    els.agentStatusText.textContent = statusNote || "Agent casually browsing aol.com";
  } else {
    els.takeControlBtn.textContent = "▶ Resume Agent";
    els.agentStatusText.textContent = statusNote || `You have control · Epoch #${state.epoch}`;
  }
  els.hostMeta.textContent = `Host: ${wsHost} · Epoch #${state.epoch}`;
}

function sendCommand(payload) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return false;
  state.ws.send(JSON.stringify(payload));
  return true;
}

function sendOrQueueCommand(payload) {
  if (sendCommand(payload)) return;
  state.pendingCommand = payload;
  connectSocket();
}

function renderPngBase64ToCanvas(pngBase64) {
  return new Promise((resolveDraw, rejectDraw) => {
    const img = new Image();
    img.onload = () => {
      ctx2d.clearRect(0, 0, els.canvas.width, els.canvas.height);
      ctx2d.drawImage(img, 0, 0, els.canvas.width, els.canvas.height);
      resolveDraw();
    };
    img.onerror = () => rejectDraw(new Error("Failed to decode Parawing PNG frame"));
    img.src = `data:image/png;base64,${pngBase64}`;
  });
}

function updateTelemetry(msg) {
  const scrollY = Math.round(msg.page?.scrollY ?? 0);
  const seq = msg.page?.seq ?? 0;
  const tierNote = state.lastResumedTier !== null ? ` · resumed Tier ${state.lastResumedTier}` : "";
  els.engineTelemetry.textContent = `Blitz + Deno V8 · ${msg.width}×${msg.height} · scrollY ${scrollY}px · seq #${seq} · Epoch #${state.epoch} (${msg.renderMs}ms${tierNote})`;
  state.blockedNavigations = msg.policy?.blockedNavigations ?? state.blockedNavigations;
  state.blockedSubresources = msg.policy?.blockedSubresources ?? state.blockedSubresources;
  els.policyTelemetry.textContent = `${state.blockedNavigations} blocked navs · ${state.blockedSubresources} non-AOL requests blocked`;
}

function connectSocket() {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) return;
  state.manualDisconnect = false;
  setConnBadge("connecting", "Connecting…");
  if (state.frameCount === 0) {
    showLoading("Connecting to DigitalOcean Parawing host (aol.com-only)…");
  }

  const query = new URLSearchParams({ sessionId: state.sessionId });
  if (params.get("agent") === "0") query.set("agent", "0");
  const url = `${wsProto}//${wsHost}/showcase/ws?${query.toString()}`;
  const ws = new WebSocket(url);
  state.ws = ws;

  ws.addEventListener("message", async (ev) => {
    const msg = JSON.parse(String(ev.data));
    if (msg.type === "connected") {
      state.connected = true;
      state.sessionId = msg.sessionId || state.sessionId;
      if (msg.resumedTier === 0 || msg.resumedTier === 1) {
        state.lastResumedTier = msg.resumedTier;
      }
      if (msg.cursor && typeof msg.cursor.x === "number" && typeof msg.cursor.y === "number") {
        state.cursorX = msg.cursor.x;
        state.cursorY = msg.cursor.y;
        syncCursorTransform();
      }
      const badgeLabel = msg.reconnected
        ? `Reconnected (Tier ${msg.resumedTier ?? 0}) · ${String(msg.region || cfg.dropletRegion).toUpperCase()}`
        : `Live · ${String(msg.region || cfg.dropletRegion).toUpperCase()}`;
      setConnBadge("connected", badgeLabel);
      els.sessionToggleBtn.textContent = "Disconnect";
      applyControlState(msg.controller || state.controller, msg.epoch ?? state.epoch);
      if (state.pendingCommand) {
        const next = state.pendingCommand;
        state.pendingCommand = null;
        sendCommand(next);
      }
      return;
    }

    if (msg.type === "controlState") {
      applyControlState(msg.controller, msg.epoch);
      return;
    }

    if (msg.type === "agentCursor") {
      if (state.controller !== "agent") return;
      state.cursorX = Number(msg.x) || state.cursorX;
      state.cursorY = Number(msg.y) || state.cursorY;
      state.agentMoves += 1;
      els.agentCursor.setAttribute("data-moves", String(state.agentMoves));
      els.agentCursor.setAttribute("data-active", "true");
      syncCursorTransform();

      const shortLabel = String(msg.label || "aol.com").slice(0, 38);
      if (msg.phase === "click") {
        state.agentClicks += 1;
        els.agentCursor.setAttribute("data-clicks", String(state.agentClicks));
        els.agentCursorTag.textContent = `Agent · Clicking "${shortLabel}"`;
        els.agentStatusText.textContent = `Agent clicked: "${shortLabel}"`;
        triggerClickRipple(state.cursorX, state.cursorY);
      } else if (msg.phase === "scroll") {
        els.agentCursorTag.textContent = `Agent · ${shortLabel}`;
        els.agentStatusText.textContent = `Agent · ${shortLabel}`;
      } else {
        els.agentCursorTag.textContent = `Agent · "${shortLabel}"`;
        els.agentStatusText.textContent = `Agent moving to "${shortLabel}"`;
      }
      return;
    }

    if (msg.type === "loading") {
      if (state.frameCount === 0) {
        showLoading(`Rendering ${msg.url} in Blitz + Deno V8…`);
      } else if (msg.actor === "agent" && state.controller === "agent") {
        els.agentStatusText.textContent = "Agent loading AOL story…";
      }
      return;
    }

    if (msg.type === "frame") {
      await renderPngBase64ToCanvas(msg.pngBase64);
      state.frameCount += 1;
      if (typeof msg.epoch === "number") state.epoch = msg.epoch;
      if (msg.controller) {
        applyControlState(
          msg.controller,
          state.epoch,
          msg.controller === "agent" ? els.agentStatusText.textContent : undefined,
        );
      }
      els.canvas.setAttribute("data-frames", String(state.frameCount));
      els.canvas.setAttribute("data-current-url", String(msg.page?.href || ""));
      els.canvas.setAttribute("data-scroll-y", String(Math.round(msg.page?.scrollY ?? 0)));
      if (document.activeElement !== els.urlInput && msg.page?.href) {
        els.urlInput.value = msg.page.href;
      }
      els.backBtn.disabled = !msg.canGoBack;
      els.forwardBtn.disabled = !msg.canGoForward;
      updateTelemetry(msg);
      syncCursorTransform();
      hideLoading();
      return;
    }

    if (msg.type === "policyBlocked") {
      hideLoading();
      state.blockedNavigations = msg.blockedNavigations ?? state.blockedNavigations + 1;
      els.policyTelemetry.textContent = `${state.blockedNavigations} blocked navs · ${state.blockedSubresources} non-AOL requests blocked`;
      showPolicyBlock(msg.reason || `Blocked non-AOL URL: ${msg.blockedUrl}`);
      return;
    }

    if (msg.type === "error") {
      hideLoading();
      showPolicyBlock(`Engine error: ${msg.message}`);
    }
  });

  ws.addEventListener("close", () => {
    state.connected = false;
    els.agentCursor.setAttribute("data-active", "false");
    els.sessionToggleBtn.textContent = "Reconnect";
    setConnBadge(
      "disconnected",
      state.manualDisconnect ? "Disconnected (session warm on DO)" : "Connection closed",
    );
    hideLoading();
  });

  ws.addEventListener("error", () => {
    setConnBadge("error", "Host unreachable");
    hideLoading();
  });
}

function disconnectSocketManually() {
  state.manualDisconnect = true;
  if (state.ws) {
    state.ws.close();
    state.ws = null;
  }
}

els.takeControlBtn.addEventListener("click", () => {
  if (state.controller === "agent") {
    els.agentCursor.setAttribute("data-active", "false");
    els.agentStatusText.textContent = "Taking control…";
    sendOrQueueCommand({ type: "takeControl" });
  } else {
    els.agentStatusText.textContent = "Resuming agent…";
    sendOrQueueCommand({ type: "resumeAgent" });
  }
});

els.sessionToggleBtn.addEventListener("click", () => {
  if (state.connected) {
    disconnectSocketManually();
  } else {
    connectSocket();
  }
});

els.urlForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  els.policyBanner.hidden = true;
  sendOrQueueCommand({ type: "navigate", url: els.urlInput.value.trim() });
});

els.backBtn.addEventListener("click", () => sendCommand({ type: "back" }));
els.forwardBtn.addEventListener("click", () => sendCommand({ type: "forward" }));
els.reloadBtn.addEventListener("click", () => sendOrQueueCommand({ type: "reload" }));
els.dismissPolicyBtn.addEventListener("click", () => {
  els.policyBanner.hidden = true;
});

els.canvas.addEventListener("click", (ev) => {
  if (!state.connected) return;
  const rect = els.canvas.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return;
  const x = Math.round(((ev.clientX - rect.left) / rect.width) * els.canvas.width);
  const y = Math.round(((ev.clientY - rect.top) / rect.height) * els.canvas.height);
  els.policyBanner.hidden = true;
  sendCommand({ type: "click", x, y });
});

els.canvas.addEventListener(
  "wheel",
  (ev) => {
    if (!state.connected) return;
    ev.preventDefault();
    const rect = els.canvas.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      state.wheelLastX = Math.round(((ev.clientX - rect.left) / rect.width) * els.canvas.width);
      state.wheelLastY = Math.round(((ev.clientY - rect.top) / rect.height) * els.canvas.height);
    }
    state.wheelAccX += ev.deltaX;
    state.wheelAccY += ev.deltaY;
    if (state.wheelQueued) return;
    state.wheelQueued = true;
    setTimeout(() => {
      const dx = Math.round(state.wheelAccX);
      const dy = Math.round(state.wheelAccY);
      state.wheelAccX = 0;
      state.wheelAccY = 0;
      state.wheelQueued = false;
      if (dx !== 0 || dy !== 0) {
        sendCommand({
          type: "scroll",
          x: state.wheelLastX,
          y: state.wheelLastY,
          deltaX: dx,
          deltaY: dy,
        });
      }
    }, 120);
  },
  { passive: false },
);

els.loadNewsBtn.addEventListener("click", () => {
  els.policyBanner.hidden = true;
  els.urlInput.value = "https://www.aol.com/news/";
  sendOrQueueCommand({ type: "navigate", url: "https://www.aol.com/news/" });
});

els.testBlockBtn.addEventListener("click", () => {
  els.urlInput.value = "https://example.com/";
  sendOrQueueCommand({ type: "navigate", url: "https://example.com/" });
});

els.cardReconnectBtn.addEventListener("click", () => {
  disconnectSocketManually();
  setTimeout(() => {
    connectSocket();
  }, 350);
});

if (typeof ResizeObserver === "function") {
  new ResizeObserver(() => syncCursorTransform()).observe(els.canvas);
}

syncCursorTransform();
connectSocket();
