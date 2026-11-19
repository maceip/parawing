// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Dedicated DigitalOcean showcase server hosting Parawing (Blitz + zero-perm Deno V8 isolates)
// strictly locked to `aol.com` (`*.aol.com`) at both the session gateway and engine egress layers.

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import type { Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import type { ExternalOutbound } from "@parawing/engine/external-outbound";
import { createMinimalOutbound } from "./minimal-outbound.ts";
import {
  connectParawingSession,
  type ParawingBrowserSession,
  type ParawingPageSummary,
} from "./onboarding.ts";
import { createDenoHostServer } from "./server.ts";
import { acceptWebSocketUpgrade } from "./ws-upgrade.ts";

const VIEWPORT_WIDTH = 1280;
const VIEWPORT_HEIGHT = 760;
const SESSION_IDLE_TTL_MS = 5 * 60_000;
const MAX_SESSIONS = 16;

interface PolicyStats {
  allowedRequests: number;
  blockedSubresources: number;
  blockedNavigations: number;
}

interface StoredShowcaseSession {
  id: string;
  history: string[];
  historyIndex: number;
  lastActiveAt: number;
  bootstrapped: boolean;
  activeDisconnect: Promise<void> | null;
  stats: PolicyStats;
}

export function normalizeAndValidateAolUrl(
  rawInput: string,
): { ok: true; url: string } | { ok: false; blockedUrl: string; reason: string } {
  const trimmed = String(rawInput ?? "").trim();
  if (!trimmed) {
    return {
      ok: false,
      blockedUrl: "",
      reason: "Enter an aol.com URL (for example, https://www.aol.com/news/).",
    };
  }
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return {
      ok: false,
      blockedUrl: trimmed,
      reason: `Invalid URL "${trimmed}". Only https://*.aol.com URLs are permitted.`,
    };
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return {
      ok: false,
      blockedUrl: trimmed,
      reason: `Blocked scheme "${parsed.protocol}" — droplet policy permits only https://*.aol.com.`,
    };
  }
  if (parsed.port && parsed.port !== "443" && parsed.port !== "80") {
    return {
      ok: false,
      blockedUrl: trimmed,
      reason: `Blocked port ":${parsed.port}" — droplet policy permits only standard HTTPS on aol.com.`,
    };
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (host !== "aol.com" && !host.endsWith(".aol.com")) {
    return {
      ok: false,
      blockedUrl: parsed.toString(),
      reason: `Blocked "${host}" — this DigitalOcean Parawing host is locked exclusively to aol.com.`,
    };
  }
  parsed.protocol = "https:";
  if (parsed.hostname.toLowerCase() === "aol.com") {
    parsed.hostname = "www.aol.com";
  }
  return { ok: true, url: parsed.toString() };
}

function isAllowedSubresourceHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  return (
    h === "aol.com" || h.endsWith(".aol.com") || h.endsWith(".aolcdn.com") || h === "s.yimg.com"
  );
}

function createAolLockedOutbound(
  globalCounters: { allowed: number; blockedSubresources: number },
  allowLocalTestOrigin?: string,
): ExternalOutbound {
  const publicOutbound = createMinimalOutbound({
    allowPrivateNetwork: false,
    deadlineMs: 12_000,
  });
  const localOutbound = allowLocalTestOrigin
    ? createMinimalOutbound({ allowPrivateNetwork: true, deadlineMs: 12_000 })
    : null;

  return {
    async fetch(request: Request): Promise<Response> {
      let parsed: URL;
      try {
        parsed = new URL(request.url);
      } catch {
        globalCounters.blockedSubresources += 1;
        return new Response("invalid url", { status: 403 });
      }
      if (allowLocalTestOrigin && parsed.origin === allowLocalTestOrigin && localOutbound) {
        globalCounters.allowed += 1;
        return localOutbound.fetch(request);
      }
      const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
      if (!isAllowedSubresourceHost(host)) {
        globalCounters.blockedSubresources += 1;
        return new Response("blocked by aol.com-only egress policy", {
          status: 403,
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "x-parawing-blocked": "aol-only-policy",
          },
        });
      }
      // Keep AOL's React 19 SSR DOM intact when third-party ad/CMP domains are blocked.
      if (host.endsWith(".aolcdn.com") && parsed.pathname.endsWith(".js")) {
        globalCounters.allowed += 1;
        return new Response("", {
          status: 200,
          headers: { "content-type": "application/javascript; charset=utf-8" },
        });
      }
      globalCounters.allowed += 1;
      return publicOutbound.fetch(request);
    },
  };
}

function setCorsHeaders(req: IncomingMessage, res: ServerResponse): void {
  const origin = req.headers.origin ?? "*";
  res.setHeader("access-control-allow-origin", origin);
  res.setHeader("access-control-allow-methods", "GET, OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type");
  res.setHeader("vary", "Origin");
}

function sendJson(req: IncomingMessage, res: ServerResponse, status: number, body: unknown): void {
  setCorsHeaders(req, res);
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(payload)),
  });
  res.end(payload);
}

export interface StartAolShowcaseServerOptions {
  host?: string;
  port?: number;
  region?: string;
  publicDir?: string;
  denoBin?: string;
  defaultUrl?: string;
  allowLocalTestOrigin?: string;
}

export interface RunningAolShowcaseServer {
  readonly port: number;
  readonly origin: string;
  readonly engineOrigin: string;
  close(): Promise<void>;
}

export async function startAolShowcaseServer(
  options: StartAolShowcaseServerOptions = {},
): Promise<RunningAolShowcaseServer> {
  const bindHost = options.host ?? process.env["SHOWCASE_HOST"] ?? "127.0.0.1";
  const bindPort = options.port ?? Number(process.env["SHOWCASE_PORT"] ?? 7080);
  const region = options.region ?? process.env["SHOWCASE_REGION"] ?? "sfo2";
  const defaultUrl = options.defaultUrl ?? "https://www.aol.com/";
  const allowLocalTestOrigin = options.allowLocalTestOrigin;

  const globalCounters = {
    allowed: 0,
    blockedSubresources: 0,
    blockedNavigations: 0,
    framesRendered: 0,
  };

  const denoServer = await createDenoHostServer({
    host: "127.0.0.1",
    port: 0,
    publicDir: options.publicDir ?? process.env["PARAWING_PUBLIC_DIR"],
    denoBin: options.denoBin,
    executionBackend: "v8",
    pageWallMsCap: null,
    pageCpuMsCap: null,
    externalOutbound: createAolLockedOutbound(globalCounters, allowLocalTestOrigin),
  });
  const engineWsEndpoint = `${denoServer.origin.replace(/^http/, "ws")}/devtools/browser`;

  const sessions = new Map<string, StoredShowcaseSession>();
  const activeSockets = new Set<Duplex>();

  const validateTargetUrl = (rawUrl: string) => {
    if (allowLocalTestOrigin && rawUrl.startsWith(allowLocalTestOrigin)) {
      return { ok: true as const, url: rawUrl };
    }
    return normalizeAndValidateAolUrl(rawUrl);
  };

  const reapIdleSessions = async (): Promise<void> => {
    const cutoff = Date.now() - SESSION_IDLE_TTL_MS;
    for (const [sid, meta] of sessions) {
      if (meta.lastActiveAt >= cutoff) continue;
      sessions.delete(sid);
      try {
        const temp = await connectParawingSession({
          wsEndpoint: engineWsEndpoint,
          sessionId: sid,
          userId: "showcase-visitor",
          expectReconnect: true,
          timeoutMs: 4_000,
        });
        await temp.destroySession("idle-expired");
      } catch {}
    }
  };
  const reapTimer = setInterval(() => void reapIdleSessions(), 60_000);
  reapTimer.unref?.();

  const httpServer = createServer((req, res) => {
    if (req.method === "OPTIONS") {
      setCorsHeaders(req, res);
      res.writeHead(204);
      res.end();
      return;
    }
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (url.pathname === "/health" || url.pathname === "/showcase/status") {
      sendJson(req, res, 200, {
        ok: true,
        service: "parawing-aol-showcase",
        engine: "Parawing Blitz + Deno V8",
        policy: "aol.com-only",
        allowedDomains: ["aol.com", "*.aol.com"],
        region,
        viewport: { width: VIEWPORT_WIDTH, height: VIEWPORT_HEIGHT },
        activeSessions: sessions.size,
        framesRendered: globalCounters.framesRendered,
        allowedRequests: globalCounters.allowed,
        blockedSubresources: globalCounters.blockedSubresources,
        blockedNavigations: globalCounters.blockedNavigations,
      });
      return;
    }
    sendJson(req, res, 404, { ok: false, error: "not found" });
  });

  httpServer.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (url.pathname !== "/showcase/ws") {
      socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
      return;
    }
    const transport = acceptWebSocketUpgrade(req, socket, head);
    if (!transport) {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return;
    }
    activeSockets.add(socket);
    socket.once("close", () => activeSockets.delete(socket));

    const requestedId = url.searchParams.get("sessionId")?.trim() ?? "";
    const safeSessionId =
      requestedId && /^[a-zA-Z0-9_-]{6,64}$/.test(requestedId)
        ? requestedId
        : `aol-${randomUUID().slice(0, 12)}`;

    let closed = false;
    let pwSession: ParawingBrowserSession | null = null;
    let lastRenderedSeq = -1;
    const repaintTimers = new Set<ReturnType<typeof setTimeout>>();

    const sendWs = (payload: Record<string, unknown>): void => {
      if (closed) return;
      try {
        transport.send(JSON.stringify(payload));
      } catch {}
    };

    const clearRepaintTimers = (): void => {
      for (const t of repaintTimers) clearTimeout(t);
      repaintTimers.clear();
    };

    const captureAndSendFrame = async (
      meta: StoredShowcaseSession,
      reason: string,
      resumedTier: 0 | 1 | null = null,
    ): Promise<ParawingPageSummary | null> => {
      if (closed || !pwSession?.connected) return null;
      const t0 = performance.now();
      const pageState = await pwSession.getPageState();
      const png = await pwSession.screenshot();
      const renderMs = Math.round(performance.now() - t0);
      lastRenderedSeq = pageState.seq;
      globalCounters.framesRendered += 1;
      sendWs({
        type: "frame",
        reason,
        sessionId: meta.id,
        resumedTier,
        renderMs,
        width: VIEWPORT_WIDTH,
        height: VIEWPORT_HEIGHT,
        page: pageState,
        canGoBack: meta.historyIndex > 0,
        canGoForward: meta.historyIndex < meta.history.length - 1,
        policy: {
          mode: "aol.com-only",
          region,
          blockedNavigations: meta.stats.blockedNavigations,
          blockedSubresources: globalCounters.blockedSubresources,
        },
        pngBase64: Buffer.from(png).toString("base64"),
      });
      return pageState;
    };

    const scheduleProgressiveRepaints = (meta: StoredShowcaseSession): void => {
      clearRepaintTimers();
      for (const delayMs of [750, 1900]) {
        const timer = setTimeout(() => {
          repaintTimers.delete(timer);
          void enqueue(async () => {
            if (closed || !pwSession?.connected) return;
            const st = await pwSession.getPageState();
            if (st.seq !== lastRenderedSeq) {
              await captureAndSendFrame(meta, "progressive-assets");
            }
          });
        }, delayMs);
        repaintTimers.add(timer);
      }
    };

    let queue = Promise.resolve();
    const enqueue = (fn: () => Promise<void>): Promise<void> => {
      queue = queue.then(fn).catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        sendWs({ type: "error", message });
      });
      return queue;
    };

    const navigateAllowed = async (
      meta: StoredShowcaseSession,
      targetUrl: string,
      pushHistory: boolean,
    ): Promise<void> => {
      if (!pwSession) return;
      sendWs({ type: "loading", url: targetUrl });
      const navState = await pwSession.goto(targetUrl, 25_000);
      const finalCheck = validateTargetUrl(navState.href || targetUrl);
      if (!finalCheck.ok) {
        meta.stats.blockedNavigations += 1;
        globalCounters.blockedNavigations += 1;
        const fallbackUrl = meta.history[meta.historyIndex] ?? defaultUrl;
        await pwSession.goto(fallbackUrl, 20_000);
        sendWs({
          type: "policyBlocked",
          blockedUrl: navState.href,
          reason: finalCheck.reason,
          blockedNavigations: meta.stats.blockedNavigations,
        });
        await captureAndSendFrame(meta, "policy-revert");
        return;
      }
      if (pushHistory) {
        meta.history = meta.history.slice(0, meta.historyIndex + 1);
        meta.history.push(finalCheck.url);
        meta.historyIndex = meta.history.length - 1;
      }
      await captureAndSendFrame(meta, "navigate");
      scheduleProgressiveRepaints(meta);
    };

    void enqueue(async () => {
      if (!sessions.has(safeSessionId) && sessions.size >= MAX_SESSIONS) {
        const oldest = [...sessions.values()].sort((a, b) => a.lastActiveAt - b.lastActiveAt)[0];
        if (oldest) sessions.delete(oldest.id);
      }
      const existing = sessions.get(safeSessionId);
      if (existing?.activeDisconnect) {
        await existing.activeDisconnect;
      }
      const isReconnect = Boolean(existing?.bootstrapped);
      const meta: StoredShowcaseSession = existing ?? {
        id: safeSessionId,
        history: [],
        historyIndex: -1,
        lastActiveAt: Date.now(),
        bootstrapped: false,
        activeDisconnect: null,
        stats: { allowedRequests: 0, blockedSubresources: 0, blockedNavigations: 0 },
      };
      meta.lastActiveAt = Date.now();
      sessions.set(safeSessionId, meta);

      pwSession = await connectParawingSession({
        wsEndpoint: engineWsEndpoint,
        sessionId: safeSessionId,
        userId: "showcase-visitor",
        expectReconnect: isReconnect,
        viewport: { width: VIEWPORT_WIDTH, height: VIEWPORT_HEIGHT },
        timeoutMs: 25_000,
      });

      sendWs({
        type: "connected",
        sessionId: safeSessionId,
        reconnected: isReconnect,
        resumedTier: pwSession.resumedTier,
        region,
        policy: "aol.com-only",
      });

      if (!meta.bootstrapped) {
        meta.bootstrapped = true;
        await navigateAllowed(meta, defaultUrl, true);
      } else {
        await captureAndSendFrame(meta, "reconnected", pwSession.resumedTier);
      }
    });

    transport.onMessage((raw) => {
      let cmd: Record<string, unknown>;
      try {
        const str = typeof raw === "string" ? raw : Buffer.from(raw).toString("utf8");
        cmd = JSON.parse(str) as Record<string, unknown>;
      } catch {
        return;
      }
      const meta = sessions.get(safeSessionId);
      if (!meta) return;
      meta.lastActiveAt = Date.now();

      void enqueue(async () => {
        if (closed || !pwSession?.connected) return;
        const kind = String(cmd["type"] ?? "");

        if (kind === "navigate") {
          const verdict = validateTargetUrl(String(cmd["url"] ?? ""));
          if (!verdict.ok) {
            meta.stats.blockedNavigations += 1;
            globalCounters.blockedNavigations += 1;
            sendWs({
              type: "policyBlocked",
              blockedUrl: verdict.blockedUrl,
              reason: verdict.reason,
              blockedNavigations: meta.stats.blockedNavigations,
            });
            return;
          }
          await navigateAllowed(meta, verdict.url, true);
          return;
        }

        if (kind === "reload") {
          const current = meta.history[meta.historyIndex] ?? defaultUrl;
          await navigateAllowed(meta, current, false);
          return;
        }

        if (kind === "back" && meta.historyIndex > 0) {
          meta.historyIndex -= 1;
          await navigateAllowed(meta, meta.history[meta.historyIndex]!, false);
          return;
        }

        if (kind === "forward" && meta.historyIndex < meta.history.length - 1) {
          meta.historyIndex += 1;
          await navigateAllowed(meta, meta.history[meta.historyIndex]!, false);
          return;
        }

        if (kind === "scroll") {
          const x = Math.max(
            0,
            Math.min(VIEWPORT_WIDTH - 1, Math.round(Number(cmd["x"]) || VIEWPORT_WIDTH / 2)),
          );
          const y = Math.max(
            0,
            Math.min(VIEWPORT_HEIGHT - 1, Math.round(Number(cmd["y"]) || VIEWPORT_HEIGHT / 2)),
          );
          const deltaX = Math.max(-1200, Math.min(1200, Number(cmd["deltaX"]) || 0));
          const deltaY = Math.max(-1600, Math.min(1600, Number(cmd["deltaY"]) || 0));
          const beforeScroll = await pwSession.getPageState();
          await pwSession.sendCdp("Input.dispatchMouseEvent", {
            type: "mouseWheel",
            x,
            y,
            deltaX,
            deltaY,
          });
          const afterWheel = await pwSession.getPageState();
          if (
            (deltaY !== 0 && afterWheel.scrollY === beforeScroll.scrollY) ||
            (deltaX !== 0 && afterWheel.scrollX === beforeScroll.scrollX)
          ) {
            await pwSession.evaluate(`window.scrollBy(${deltaX}, ${deltaY})`);
          }
          await captureAndSendFrame(meta, "scroll");
          scheduleProgressiveRepaints(meta);
          return;
        }

        if (kind === "click") {
          const x = Math.max(0, Math.min(VIEWPORT_WIDTH - 1, Math.round(Number(cmd["x"]) || 0)));
          const y = Math.max(0, Math.min(VIEWPORT_HEIGHT - 1, Math.round(Number(cmd["y"]) || 0)));
          const hitHref = await pwSession.evaluate<string>(
            `(() => {` +
              `const el = document.elementFromPoint(${x}, ${y});` +
              `const a = el && el.closest ? el.closest("a[href]") : null;` +
              `return a ? a.href : "";` +
              `})()`,
          );
          if (hitHref) {
            const verdict = validateTargetUrl(hitHref);
            if (!verdict.ok) {
              meta.stats.blockedNavigations += 1;
              globalCounters.blockedNavigations += 1;
              sendWs({
                type: "policyBlocked",
                blockedUrl: verdict.blockedUrl,
                reason: verdict.reason,
                blockedNavigations: meta.stats.blockedNavigations,
              });
              return;
            }
            await navigateAllowed(meta, verdict.url, true);
            return;
          }
          await pwSession.sendCdp("Input.dispatchMouseEvent", {
            type: "mousePressed",
            x,
            y,
            button: "left",
            clickCount: 1,
          });
          await pwSession.sendCdp("Input.dispatchMouseEvent", {
            type: "mouseReleased",
            x,
            y,
            button: "left",
            clickCount: 1,
          });
          await captureAndSendFrame(meta, "click");
        }
      });
    });

    transport.onClose(() => {
      closed = true;
      clearRepaintTimers();
      if (pwSession) {
        const meta = sessions.get(safeSessionId);
        const disconnecting = pwSession
          .disconnect()
          .catch(() => {})
          .finally(() => {
            if (meta?.activeDisconnect === disconnecting) {
              meta.activeDisconnect = null;
            }
          });
        if (meta) meta.activeDisconnect = disconnecting;
      }
    });
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    httpServer.once("error", rejectListen);
    httpServer.listen(bindPort, bindHost, () => {
      httpServer.off("error", rejectListen);
      resolveListen();
    });
  });

  const addr = httpServer.address();
  const actualPort = typeof addr === "object" && addr !== null ? addr.port : bindPort;

  return {
    port: actualPort,
    origin: `http://${bindHost}:${actualPort}`,
    engineOrigin: denoServer.origin,
    async close(): Promise<void> {
      clearInterval(reapTimer);
      for (const sock of activeSockets) {
        if (!sock.destroyed) sock.destroy();
      }
      httpServer.closeAllConnections();
      await new Promise<void>((r) => httpServer.close(() => r()));
      const remainingIds = [...sessions.keys()];
      sessions.clear();
      for (const sid of remainingIds) {
        try {
          const temp = await connectParawingSession({
            wsEndpoint: engineWsEndpoint,
            sessionId: sid,
            userId: "showcase-visitor",
            expectReconnect: true,
            timeoutMs: 3_000,
          });
          await temp.destroySession("server-close");
        } catch {}
      }
      await denoServer.close();
    },
  };
}

const isEntrypoint =
  typeof process.argv[1] === "string" &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
  startAolShowcaseServer()
    .then((srv) => {
      const shutdown = (): void => {
        void srv.close().finally(() => process.exit(0));
      };
      process.once("SIGTERM", shutdown);
      process.once("SIGINT", shutdown);
      console.log(`parawing-aol-showcase listening on ${srv.origin} (engine ${srv.engineOrigin})`);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
