// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Implements CDP Network commands for cookies, headers, and request tracking.

import type { CdpRequest, TargetState } from "./types.ts";
import {
  hasActiveTakeoverForRequest,
  isAttachedViewer,
  resolveDispatchActorRole,
  type DispatchCtx,
} from "./dispatch.ts";
import { entryToCdp, setCdpCookie } from "../cookies.ts";
import { jarForContextId, jarForTarget } from "./target.ts";
import type { DispatchActorRole } from "../policy/controller-lease.ts";
import { PolicyDecisionError } from "../policy/policy-engine.ts";
import { asTargetId } from "../session/identities.ts";

function resolveActorRole(
  ctx: DispatchCtx,
  req: CdpRequest,
  target: TargetState | undefined,
): DispatchActorRole {
  const tid = target ? asTargetId(target.targetId) : null;
  return resolveDispatchActorRole(
    ctx,
    req,
    isAttachedViewer(ctx),
    hasActiveTakeoverForRequest(ctx, req, tid),
  );
}

function inferCookieOrigin(raw: unknown, fallbackUrl?: string): string {
  if (raw && typeof raw === "object") {
    const rec = raw as Record<string, unknown>;
    if (typeof rec["url"] === "string" && rec["url"]) return rec["url"];
    if (typeof rec["domain"] === "string" && rec["domain"]) {
      const host = rec["domain"].startsWith(".") ? rec["domain"].slice(1) : rec["domain"];
      const scheme = rec["secure"] === false ? "http" : "https";
      return `${scheme}://${host}`;
    }
  }
  return fallbackUrl ?? "";
}

function assertCookieStorage(
  ctx: DispatchCtx,
  target: TargetState | undefined,
  req: CdpRequest,
  operation: "read" | "write" | "clear",
  origin: string,
): void {
  if (!origin) return;
  const decision = ctx.browser.policyEngine?.evaluateStorage({
    operation,
    storageKind: "cookie",
    origin,
    sealedOrigin: target?.sealedOrigin,
    actorRole: resolveActorRole(ctx, req, target),
  });
  if (decision && !decision.allowed) {
    throw new PolicyDecisionError(decision);
  }
}

function canReadCookieEntry(
  ctx: DispatchCtx,
  target: TargetState | undefined,
  req: CdpRequest,
  host: string,
  secure: boolean,
): boolean {
  const cleanHost = host.startsWith(".") ? host.slice(1) : host;
  if (!cleanHost) return true;
  const decision = ctx.browser.policyEngine?.evaluateStorage({
    operation: "read",
    storageKind: "cookie",
    origin: `${secure ? "https" : "http"}://${cleanHost}`,
    sealedOrigin: target?.sealedOrigin,
    actorRole: resolveActorRole(ctx, req, target),
  });
  return decision?.allowed ?? true;
}

export async function handleNetwork(ctx: DispatchCtx, req: CdpRequest): Promise<unknown> {
  switch (req.method) {
    case "Network.enable":
      ctx.browser.networkEvents.setEnabled(req.sessionId, true, {
        maxTotalBufferSize: req.params?.maxTotalBufferSize,
        maxResourceBufferSize: req.params?.maxResourceBufferSize,
      });
      return {};

    case "Network.disable":
      ctx.browser.networkEvents.setEnabled(req.sessionId, false);
      return {};

    case "Network.setCacheDisabled":
    case "Network.setBypassServiceWorker":
      return {};

    case "Network.setUserAgentOverride": {
      const ua = typeof req.params?.userAgent === "string" ? req.params.userAgent : "";
      const resolved = resolveNetworkTarget(ctx, req.sessionId);
      if (resolved) resolved.userAgentOverride = ua;
      return {};
    }

    case "Network.setExtraHTTPHeaders": {
      const headers = req.params?.headers ?? {};
      const sanitized: Record<string, string> = {};
      for (const [k, v] of Object.entries(headers)) {
        if (typeof k !== "string" || typeof v !== "string") continue;
        if (k.toLowerCase().startsWith("x-parawing-")) continue;
        sanitized[k] = v;
      }
      const resolved = resolveNetworkTarget(ctx, req.sessionId);
      if (resolved) resolved.extraHttpHeaders = sanitized;
      return {};
    }

    case "Network.getAllCookies": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      const jar = jarForTarget(ctx, target);
      const visible = jar
        .getAll()
        .filter((c) => canReadCookieEntry(ctx, target, req, c.host, c.secure));
      return { cookies: visible.map(entryToCdp) };
    }

    case "Network.getCookies": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      const jar = jarForTarget(ctx, target);
      const urls = req.params?.urls;
      if (!urls || urls.length === 0) {
        const visible = jar
          .getAll()
          .filter((c) => canReadCookieEntry(ctx, target, req, c.host, c.secure));
        return { cookies: visible.map(entryToCdp) };
      }
      const seen = new Set<string>();
      const out = [];
      for (const u of urls) {
        assertCookieStorage(ctx, target, req, "read", u);
        for (const c of jar.getForUrl(u)) {
          const key = c.host + "\\u0000" + c.path + "\\u0000" + c.name;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push(entryToCdp(c));
        }
      }
      return { cookies: out };
    }

    case "Network.setCookie": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      assertCookieStorage(ctx, target, req, "write", inferCookieOrigin(req.params, target?.url));
      const jar = jarForTarget(ctx, target);
      return { success: setCdpCookie(jar, req.params) !== null };
    }

    case "Network.setCookies": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      const jar = jarForTarget(ctx, target);
      const list: unknown = req.params?.cookies;
      if (Array.isArray(list)) {
        for (const c of list) {
          assertCookieStorage(ctx, target, req, "write", inferCookieOrigin(c, target?.url));
          setCdpCookie(jar, c);
        }
      }
      return {};
    }

    case "Network.deleteCookies": {
      const p = req.params!;
      if (!p.name) return {};
      const target = resolveNetworkTarget(ctx, req.sessionId);
      assertCookieStorage(ctx, target, req, "clear", inferCookieOrigin(p, target?.url));
      const jar = jarForTarget(ctx, target);
      jar.remove({
        name: p.name,
        url: p.url,
        domain: p.domain,
        path: p.path,
      });
      return {};
    }

    case "Network.clearBrowserCookies": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      if (target?.url) {
        assertCookieStorage(ctx, target, req, "clear", target.url);
      }
      const jar = jarForTarget(ctx, target);
      jar.clear();
      return {};
    }

    case "Storage.getCookies": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      const sjar = jarForContextId(ctx, req.params?.browserContextId);
      const visible = sjar
        .getAll()
        .filter((c) => canReadCookieEntry(ctx, target, req, c.host, c.secure));
      return { cookies: visible.map(entryToCdp) };
    }

    case "Storage.setCookies": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      const sjar = jarForContextId(ctx, req.params?.browserContextId);
      const list: unknown = req.params?.cookies;
      if (Array.isArray(list)) {
        for (const c of list) {
          assertCookieStorage(ctx, target, req, "write", inferCookieOrigin(c, target?.url));
          setCdpCookie(sjar, c);
        }
      }
      return {};
    }

    case "Storage.clearCookies": {
      const target = resolveNetworkTarget(ctx, req.sessionId);
      if (target?.url) {
        assertCookieStorage(ctx, target, req, "clear", target.url);
      }
      jarForContextId(ctx, req.params?.browserContextId).clear();
      return {};
    }

    case "Network.clearBrowserCache":
      return {};

    case "Network.emulateNetworkConditionsByRule":
      return { ruleIds: [] };

    case "Network.getResponseBody": {
      const requestId = req.params!.requestId;
      const tracker = ctx.browser.networkEvents;
      // Chrome rejects an id it never issued. Parawing keeps fewer bodies than Chrome, so a known
      // request whose body it dropped answers empty rather than failing a read Chrome would serve.
      if (!requestId || !tracker.knowsRequest(requestId)) {
        throw new Error("No resource with given identifier found");
      }
      return tracker.getResponseBody(requestId) ?? { body: "", base64Encoded: false };
    }

    default:
      return {};
  }
}

export function effectiveExtraHeaders(t: TargetState): Record<string, string> {
  if (!t.userAgentOverride) return t.extraHttpHeaders;
  const merged: Record<string, string> = {};
  for (const [k, v] of Object.entries(t.extraHttpHeaders)) {
    if (k.toLowerCase() === "user-agent") continue;
    merged[k] = v;
  }
  merged["user-agent"] = t.userAgentOverride;
  return merged;
}

function resolveNetworkTarget(
  ctx: DispatchCtx,
  sessionId: string | undefined,
): TargetState | undefined {
  if (sessionId) {
    for (const t of ctx.browser.targets.values()) {
      if (t.sessions.has(sessionId)) return t;
    }
  }
  for (const t of ctx.browser.targets.values()) {
    if (t.type === "page") return t;
  }
  return undefined;
}
