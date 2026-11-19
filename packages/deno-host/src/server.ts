// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Standalone HTTP and CDP WebSocket server hosting Parawing on zero-perm Deno isolates.

import { existsSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import type { Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import type { ExternalOutbound } from "@parawing/engine/external-outbound";
import {
  SessionManager,
  asSessionId,
  asUserId,
  createMemoryHostCapabilities,
  handleCdpSession,
  parsePositiveMsCap,
  traceSpan,
  type ApprovalGate,
  type AuthorityVaultAndChannel,
  type CdpSessionHandle,
  type ControllerLeaseManager,
  type HostCapabilities,
  type KeyLeaseManager,
  type MandateTracker,
  type PolicyEngine,
  type SessionId,
  type SessionStore,
  type SignedAuditLog,
  type TokenizedFillVault,
  type UserId,
} from "../dist/engine-bundle.mjs";
import { createDenoIsolateLoader } from "./deno-isolate-loader.ts";
import type { EgressBroker } from "./egress-broker.ts";
import { createFileAssetCapability } from "./file-assets.ts";
import { createMinimalOutbound } from "./minimal-outbound.ts";
import { OtlpHttpTracer } from "./otlp-tracer.ts";
import { acceptWebSocketUpgrade } from "./ws-upgrade.ts";

export interface DenoHostServerOptions {
  host?: string;
  port?: number;
  publicDir?: string;
  allowPrivateNetwork?: boolean;
  pageCpuMsCap?: number | null;
  pageWallMsCap?: number | null;
  otlpEndpoint?: string;
  traceAll?: boolean;
  externalOutbound?: ExternalOutbound;
  denoBin?: string;
  maxOldSpaceSizeMb?: number;
  egressDeadlineMs?: number;
  executionBackend?: "boa" | "v8";
  disablePartialRaster?: boolean;
  inspectorBaseUrl?: string;
  inspectorFallbackUrl?: string;
  sessionManager?: SessionManager;
  defaultUserId?: UserId;
  delegatedAgent?: boolean;
  policyEngine?: PolicyEngine;
  controllerLeases?: ControllerLeaseManager;
  authority?: AuthorityVaultAndChannel;
  tokenizedVault?: TokenizedFillVault;
  mandateTracker?: MandateTracker;
  egressBroker?: EgressBroker;
  approvalGate?: ApprovalGate;
  auditLog?: SignedAuditLog;
  keyLease?: KeyLeaseManager;
  sessionStore?: SessionStore;
}

export interface DenoHostServer {
  readonly port: number;
  readonly host: string;
  readonly origin: string;
  close(): Promise<void>;
}

const VERSION_INFO = {
  Browser: "Parawing/0.0.1",
  "Protocol-Version": "1.3",
  "User-Agent":
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
  "V8-Version": "12.0.0",
  "WebKit-Version": "537.36",
};

const CHROME_BUNDLED_INSPECTOR_URL = "devtools://devtools/bundled/inspector.html";
const requireFromHere = createRequire(import.meta.url);

function resolvePublicDir(explicit?: string): string {
  if (explicit) return explicit;
  const cwdEnginePublic = resolve(process.cwd(), "../engine/public");
  if (existsSync(resolve(cwdEnginePublic, "rbi"))) return cwdEnginePublic;
  const pkgEngineDir = dirname(requireFromHere.resolve("@parawing/engine/package.json"));
  const pkgPublic = resolve(pkgEngineDir, "public");
  if (existsSync(pkgPublic)) return pkgPublic;
  return cwdEnginePublic;
}

function sendJson(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(body)),
  });
  res.end(body);
}

function sendText(
  res: ServerResponse,
  status: number,
  text: string,
  contentType = "text/plain; charset=utf-8",
): void {
  res.writeHead(status, {
    "content-type": contentType,
    "content-length": String(Buffer.byteLength(text)),
  });
  res.end(text);
}

async function writeFetchResponse(res: ServerResponse, resp: Response): Promise<void> {
  const headers: Record<string, string> = {};
  resp.headers.forEach((v, k) => {
    headers[k] = v;
  });
  if (resp.status === 304 || resp.status === 204 || resp.status === 205) {
    res.writeHead(resp.status, headers);
    res.end();
    return;
  }
  const buf = Buffer.from(await resp.arrayBuffer());
  headers["content-length"] = String(buf.length);
  res.writeHead(resp.status, headers);
  res.end(buf);
}

function parseWsOptions(url: URL): {
  connectionMode: "page" | "browser";
  initialLayoutMode: "full" | "off";
  initialUrl: string | null;
  debug: boolean;
  cdpDebug: boolean;
  isolateCapOverrides: { cpuMs?: number; wallMs?: number };
  idleMs?: number;
  maxSessionMs?: number;
  sessionId?: SessionId;
  userId?: UserId;
  requestedEpoch?: number;
  connectionRole?: "owner" | "viewer";
  delegatedAgent?: boolean;
} {
  const connectionMode = url.pathname.startsWith("/devtools/page/") ? "page" : "browser";
  const layout = url.searchParams.get("layout");
  const initialLayoutMode =
    layout === "off" || layout === "0" || layout === "false" ? "off" : "full";
  let initialUrl: string | null = null;
  const iu = url.searchParams.get("initialUrl");
  if (iu) {
    try {
      const parsed = new URL(iu);
      if (parsed.protocol === "http:" || parsed.protocol === "https:")
        initialUrl = parsed.toString();
    } catch {}
  }
  const isolateCapOverrides: { cpuMs?: number; wallMs?: number } = {};
  const cpuRaw = Number.parseInt(url.searchParams.get("ksCpuCapMs") ?? "", 10);
  if (Number.isFinite(cpuRaw) && cpuRaw > 0) isolateCapOverrides.cpuMs = cpuRaw;
  const wallRaw = Number.parseInt(url.searchParams.get("ksWallCapMs") ?? "", 10);
  if (Number.isFinite(wallRaw) && wallRaw > 0) isolateCapOverrides.wallMs = wallRaw;
  const idleRaw = Number.parseInt(url.searchParams.get("ksIdleMs") ?? "", 10);
  const maxSessionRaw = Number.parseInt(url.searchParams.get("ksMaxSessionMs") ?? "", 10);
  const rawSessionId = url.searchParams.get("ksSessionId")?.trim();
  const rawUserId = url.searchParams.get("ksUserId")?.trim();
  const rawEpochStr = url.searchParams.get("ksEpoch")?.trim();
  const epochParsed =
    rawEpochStr !== undefined && /^\d+$/.test(rawEpochStr) ? Number(rawEpochStr) : NaN;
  const rawDelegated = url.searchParams.get("ksDelegated");
  const rawRole = url.searchParams.get("ksRole");
  return {
    connectionMode,
    initialLayoutMode,
    initialUrl,
    debug: url.searchParams.get("debug") === "1" || url.searchParams.get("debug") === "true",
    cdpDebug:
      url.searchParams.get("cdpDebug") === "1" || url.searchParams.get("cdpDebug") === "true",
    isolateCapOverrides,
    ...(Number.isFinite(idleRaw) && idleRaw > 0 ? { idleMs: idleRaw } : {}),
    ...(Number.isFinite(maxSessionRaw) && maxSessionRaw > 0 ? { maxSessionMs: maxSessionRaw } : {}),
    ...(rawSessionId ? { sessionId: asSessionId(rawSessionId) } : {}),
    ...(rawUserId ? { userId: asUserId(rawUserId) } : {}),
    ...(Number.isInteger(epochParsed) && epochParsed >= 0 ? { requestedEpoch: epochParsed } : {}),
    ...(rawRole === "viewer" ? { connectionRole: "viewer" as const } : {}),
    ...(rawDelegated !== null
      ? { delegatedAgent: rawDelegated === "1" || rawDelegated === "true" }
      : {}),
  };
}

function rejectUpgrade(socket: Duplex, status: number, message: string): void {
  socket.write(
    `HTTP/1.1 ${status} ${message}\r\n` +
      "Connection: close\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      `Content-Length: ${Buffer.byteLength(message)}\r\n\r\n${message}`,
  );
  socket.destroy();
}

export async function createDenoHostServer(
  options: DenoHostServerOptions = {},
): Promise<DenoHostServer> {
  const bindHost = options.host ?? process.env["PARAWING_HOST"] ?? "127.0.0.1";
  const requestedPort = options.port ?? Number(process.env["PARAWING_PORT"] ?? 8787);
  const publicDir = resolvePublicDir(options.publicDir);
  const allowPrivateNetwork =
    options.allowPrivateNetwork ?? process.env["PARAWING_ALLOW_PRIVATE_NETWORK"] === "1";

  const otlpEndpoint = options.otlpEndpoint ?? process.env["PARAWING_OTLP_ENDPOINT"] ?? "";
  const traceAll = options.traceAll ?? process.env["PARAWING_TRACE_ALL"] === "1";
  const tracer =
    otlpEndpoint && traceAll ? new OtlpHttpTracer({ endpoint: otlpEndpoint }) : undefined;

  const assets = createFileAssetCapability({ rootDir: publicDir });
  const pendingTasks = new Set<Promise<unknown>>();
  const activeSessions = new Set<CdpSessionHandle>();
  const activeSockets = new Set<Duplex>();
  const sharedSessionManager = options.sessionManager ?? new SessionManager();

  const hostCaps: HostCapabilities = createMemoryHostCapabilities({
    assets,
    tasks: {
      run(promise: Promise<unknown>): void {
        pendingTasks.add(promise);
        void promise
          .catch(() => {})
          .finally(() => {
            pendingTasks.delete(promise);
          });
      },
    },
    limits: {
      pageCpuMsCap:
        options.pageCpuMsCap ?? parsePositiveMsCap(process.env["PARAWING_PAGE_CPU_MS_CAP"]),
      pageWallMsCap:
        options.pageWallMsCap ?? parsePositiveMsCap(process.env["PARAWING_PAGE_WALL_MS_CAP"]),
    },
    config: {
      environment: "deno-host",
      buildVersion: "0.0.1",
      allowPrivateNetwork,
      disablePartialRaster: options.disablePartialRaster ?? false,
      inspectorBaseUrl: options.inspectorBaseUrl,
      inspectorFallbackUrl: options.inspectorFallbackUrl,
      otlpEndpoint: otlpEndpoint || undefined,
      traceAll,
    },
    tracer,
  });

  const minimalOutbound = createMinimalOutbound({
    allowPrivateNetwork,
    deadlineMs: options.egressDeadlineMs,
  });

  const serveRbiAsset = async (
    req: IncomingMessage,
    res: ServerResponse,
    assetPath: string,
    contentType?: string,
  ): Promise<void> => {
    const reqHeaders = new Headers();
    const ifNoneMatch = req.headers["if-none-match"];
    if (typeof ifNoneMatch === "string") reqHeaders.set("If-None-Match", ifNoneMatch);
    const assetResp = await assets.fetch(
      new Request(`https://parawing.invalid${assetPath}`, {
        method: req.method ?? "GET",
        headers: reqHeaders,
      }),
    );
    if (assetResp.status !== 200 && assetResp.status !== 304) {
      sendText(res, 404, "not found");
      return;
    }
    const headers = new Headers(assetResp.headers);
    if (contentType) headers.set("content-type", contentType);
    const body = assetResp.status === 304 ? null : await assetResp.arrayBuffer();
    await writeFetchResponse(res, new Response(body, { status: assetResp.status, headers }));
  };

  let boundPort = requestedPort;
  const httpServer = createServer((req, res) => {
    void (async (): Promise<void> => {
      const hostHeader = req.headers.host ?? `${bindHost}:${boundPort}`;
      const url = new URL(req.url ?? "/", `http://${hostHeader}`);
      if (url.pathname === "/health") {
        sendText(res, 200, "parawing: OK\n");
        return;
      }
      if (url.pathname === "/json/version" || url.pathname === "/json/version/") {
        sendJson(res, 200, {
          ...VERSION_INFO,
          webSocketDebuggerUrl: `ws://${hostHeader}/devtools/browser`,
        });
        return;
      }
      if (
        url.pathname === "/json" ||
        url.pathname === "/json/list" ||
        url.pathname === "/json/list/"
      ) {
        const base = (options.inspectorBaseUrl ?? CHROME_BUNDLED_INSPECTOR_URL).replace(/\/$/, "");
        sendJson(res, 200, [
          {
            id: "parawing",
            type: "page",
            title: "parawing",
            url: "about:blank",
            description: "parawing headless target",
            webSocketDebuggerUrl: `ws://${hostHeader}/devtools/page/parawing`,
            faviconUrl: `http://${hostHeader}/favicon.ico`,
            devtoolsFrontendUrl: `${base}?ws=${hostHeader}/devtools/page/parawing`,
          },
        ]);
        return;
      }
      if (url.pathname === "/json/protocol") {
        sendJson(res, 200, {});
        return;
      }
      if (url.pathname === "/rbi/scene_host.wasm") {
        await serveRbiAsset(req, res, "/rbi/scene_host.wasm", "application/wasm");
        return;
      }
      if (url.pathname === "/rbi/scene_host.json") {
        await serveRbiAsset(req, res, "/rbi/scene_host.json", "application/json; charset=utf-8");
        return;
      }
      if (url.pathname.startsWith("/rbi/fonts/")) {
        await serveRbiAsset(req, res, url.pathname.slice("/rbi".length));
        return;
      }
      sendText(res, 404, "not found");
    })().catch((err) => {
      const msg = err instanceof Error ? err.message : String(err);
      if (!res.headersSent) sendText(res, 500, msg);
    });
  });

  httpServer.on("upgrade", (req, socket, head) => {
    const hostHeader = req.headers.host ?? `${bindHost}:${boundPort}`;
    const url = new URL(req.url ?? "/", `http://${hostHeader}`);
    const isBrowserWs = url.pathname === "/devtools/browser";
    const isPageWs = url.pathname.startsWith("/devtools/page/");
    if (!isBrowserWs && !isPageWs) {
      rejectUpgrade(socket, 404, "Not Found");
      return;
    }

    const transport = acceptWebSocketUpgrade(req, socket, head);
    if (!transport) {
      rejectUpgrade(socket, 400, "Bad WebSocket Upgrade");
      return;
    }

    activeSockets.add(socket);
    socket.once("close", () => activeSockets.delete(socket));

    const wsOpts = parseWsOptions(url);
    const isolateLoader = createDenoIsolateLoader(hostCaps, {
      denoBin: options.denoBin,
      maxOldSpaceSizeMb: options.maxOldSpaceSizeMb,
      executionBackend: options.executionBackend,
    });
    const sessionManagerForWs =
      options.sessionManager ?? (wsOpts.sessionId ? sharedSessionManager : undefined);
    let session: CdpSessionHandle;
    try {
      session = traceSpan(hostCaps.tracer, "ws.connect", () =>
        handleCdpSession(transport, {
          host: hostCaps,
          isolateLoader,
          connectionMode: wsOpts.connectionMode,
          initialLayoutMode: wsOpts.initialLayoutMode,
          initialUrl: wsOpts.initialUrl,
          debug: wsOpts.debug,
          cdpDebug: wsOpts.cdpDebug,
          skipSpeculativeRaster: req.headers["x-parawing-skip-speculative-raster"] === "1",
          idleMs: wsOpts.idleMs,
          maxSessionMs: wsOpts.maxSessionMs,
          isolateCapOverrides: wsOpts.isolateCapOverrides,
          externalOutbound: options.externalOutbound,
          egress: options.externalOutbound
            ? undefined
            : options.egressBroker
              ? options.egressBroker.asExternalOutbound()
              : minimalOutbound,
          environment: "deno-host",
          buildVersion: "0.0.1",
          sessionManager: sessionManagerForWs,
          sessionId: wsOpts.sessionId,
          userId: wsOpts.userId ?? options.defaultUserId,
          requestedEpoch: wsOpts.requestedEpoch,
          connectionRole: wsOpts.connectionRole,
          delegatedAgent: wsOpts.delegatedAgent ?? options.delegatedAgent,
          policyEngine: options.policyEngine,
          controllerLeases: options.controllerLeases,
          authority: options.authority,
          tokenizedVault: options.tokenizedVault,
          mandateTracker: options.mandateTracker,
          approvalGate: options.approvalGate,
          auditLog: options.auditLog,
          keyLease: options.keyLease,
          sessionStore: options.sessionStore,
        }),
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      transport.close(1008, msg.slice(0, 120));
      return;
    }

    activeSessions.add(session);
    void session.closed.finally(() => activeSessions.delete(session));
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    httpServer.once("error", rejectListen);
    httpServer.listen(requestedPort, bindHost, () => {
      httpServer.off("error", rejectListen);
      resolveListen();
    });
  });

  const addr = httpServer.address();
  boundPort = typeof addr === "object" && addr !== null ? addr.port : requestedPort;

  return {
    port: boundPort,
    host: bindHost,
    origin: `http://${bindHost}:${boundPort}`,
    async close(): Promise<void> {
      for (const sock of activeSockets) {
        if (!sock.destroyed) sock.destroy();
      }
      httpServer.closeAllConnections();
      await Promise.allSettled([...activeSessions].map((s) => s.closed));
      await new Promise<void>((resolveClose) => {
        httpServer.close(() => resolveClose());
      });
      await Promise.allSettled([...pendingTasks]);
      if (tracer) await tracer.flush();
    },
  };
}

export async function startDenoHostServer(
  options: DenoHostServerOptions = {},
): Promise<DenoHostServer> {
  return createDenoHostServer(options);
}

export {
  ParawingBrowserSession,
  connectParawingSession,
  spawnParawingBrowser,
  type ConnectParawingSessionOptions,
  type OpenParawingSessionOptions,
  type ParawingPageSummary,
  type ParawingViewport,
  type SpawnParawingBrowserOptions,
  type SpawnedParawingBrowser,
} from "./onboarding.ts";

const isEntrypoint =
  typeof process.argv[1] === "string" &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
  createDenoHostServer({
    publicDir: process.env["PARAWING_PUBLIC_DIR"] || undefined,
  })
    .then((server) => {
      let shuttingDown = false;
      const shutdown = (): void => {
        if (shuttingDown) return;
        shuttingDown = true;
        void server.close().finally(() => process.exit(0));
      };
      process.once("SIGTERM", shutdown);
      process.once("SIGINT", shutdown);
      console.log(`@parawing/deno-host listening on ${server.origin}`);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
