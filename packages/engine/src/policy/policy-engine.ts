// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** PolicyEngine enforcing attach, command, storage, egress, and delegated redaction rules. */

import { normalizeStrictOrigin } from "../authority/authority-service.ts";
import type { ConnectionId, SessionId, TargetId, UserId } from "../session/identities.ts";
import type { SignedAuditLog } from "./audit-log.ts";
import type { DispatchActorRole } from "./controller-lease.ts";

export interface PolicyDecision {
  readonly allowed: boolean;
  readonly reason: string;
  readonly code:
    | "ok"
    | "delegated-cookie-access-denied"
    | "sealed-target-blocked"
    | "method-blocked"
    | "origin-denied"
    | "top-level-navigation-denied"
    | "opaque-origin-storage-denied"
    | "attach-denied";
}

export interface PolicyEngineOptions {
  readonly delegatedAgent?: boolean;
  readonly allowedOrigins?: ReadonlyArray<string>;
  readonly blockedHostnames?: ReadonlyArray<string>;
  readonly blockedEgressMethods?: ReadonlyArray<string>;
  readonly blockedCommandMethods?: ReadonlyArray<string>;
  readonly allowTopLevelNavigation?: boolean;
  readonly blockedTopLevelNavigationMethods?: ReadonlyArray<string>;
  readonly auditLog?: SignedAuditLog;
}

const DELEGATED_COOKIE_GETTER_METHODS = new Set([
  "Network.getCookies",
  "Network.getAllCookies",
  "Storage.getCookies",
]);

const SEALED_BLOCKED_EXACT_METHODS = new Set([
  "Runtime.evaluate",
  "Runtime.callFunctionOn",
  "Runtime.getProperties",
  "Runtime.compileScript",
  "Runtime.runScript",
  "Network.getResponseBody",
  "Page.captureScreenshot",
  "Page.startScreencast",
  "Page.printToPDF",
  "Page.setDocumentContent",
  "Parawing.startSceneStream",
  "Parawing.screenshot",
  "Parawing.recordScene",
  "Parawing.setControlValue",
  "Debugger.getScriptSource",
]);

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "cookie2",
  "set-cookie",
  "set-cookie2",
]);

export function isSealedBlockedCommand(method: string): boolean {
  if (SEALED_BLOCKED_EXACT_METHODS.has(method)) return true;
  return (
    method.startsWith("DOM.") ||
    method.startsWith("Accessibility.") ||
    method.startsWith("CSS.") ||
    method.startsWith("Fetch.")
  );
}

export class PolicyDecisionError extends Error {
  readonly decision: PolicyDecision;

  constructor(decision: PolicyDecision) {
    super(`Policy denied (${decision.code}): ${decision.reason}`);
    this.name = "PolicyDecisionError";
    this.decision = decision;
  }
}

export class PolicyEngine {
  readonly delegatedAgent: boolean;
  private readonly allowedOrigins: ReadonlySet<string> | null;
  private readonly blockedHostnames: ReadonlySet<string>;
  private readonly blockedEgressMethods: ReadonlySet<string>;
  private readonly blockedCommandMethods: ReadonlySet<string>;
  private readonly allowTopLevelNavigation: boolean;
  private readonly blockedTopLevelNavigationMethods: ReadonlySet<string>;
  private readonly auditLog?: SignedAuditLog;

  constructor(options: PolicyEngineOptions = {}) {
    this.delegatedAgent = options.delegatedAgent ?? false;
    this.allowedOrigins = options.allowedOrigins
      ? new Set(
          options.allowedOrigins
            .map((o) => normalizeStrictOrigin(o))
            .filter((o): o is string => o !== null),
        )
      : null;
    this.blockedHostnames = new Set((options.blockedHostnames ?? []).map((h) => h.toLowerCase()));
    this.blockedEgressMethods = new Set(
      (options.blockedEgressMethods ?? []).map((m) => m.trim().toUpperCase()),
    );
    this.blockedCommandMethods = new Set(options.blockedCommandMethods ?? []);
    this.allowTopLevelNavigation = options.allowTopLevelNavigation ?? true;
    this.blockedTopLevelNavigationMethods = new Set(
      (options.blockedTopLevelNavigationMethods ?? []).map((m) => m.trim().toUpperCase()),
    );
    this.auditLog = options.auditLog;
  }

  evaluateAttach(input: {
    readonly sessionId: SessionId;
    readonly userId: UserId;
    readonly connectionId: ConnectionId;
    readonly actorRole?: DispatchActorRole;
  }): PolicyDecision {
    if (!input.sessionId || !input.userId || !input.connectionId) {
      return {
        allowed: false,
        code: "attach-denied",
        reason: "Session attachment requires userId, sessionId, and connectionId",
      };
    }
    return { allowed: true, code: "ok", reason: "attach permitted" };
  }

  evaluateCommand(input: {
    readonly method: string;
    readonly sessionId?: SessionId;
    readonly targetId?: TargetId | null;
    readonly sealedOrigin?: string | null;
    readonly actorRole?: DispatchActorRole;
  }): PolicyDecision {
    const actor = input.actorRole ?? "agent";
    if (
      this.delegatedAgent &&
      actor === "agent" &&
      DELEGATED_COOKIE_GETTER_METHODS.has(input.method)
    ) {
      const decision: PolicyDecision = {
        allowed: false,
        code: "delegated-cookie-access-denied",
        reason: `${input.method} is blocked for delegated agents`,
      };
      void this.auditLog?.append({
        kind: "policy.command.denied",
        sessionId: input.sessionId,
        targetId: input.targetId ?? undefined,
        detail: { method: input.method, code: decision.code },
      });
      return decision;
    }

    if (input.sealedOrigin && actor === "agent" && isSealedBlockedCommand(input.method)) {
      const decision: PolicyDecision = {
        allowed: false,
        code: "sealed-target-blocked",
        reason: `${input.method} blocked on A1 sealed target (${input.sealedOrigin})`,
      };
      void this.auditLog?.append({
        kind: "policy.sealed.blocked",
        sessionId: input.sessionId,
        targetId: input.targetId ?? undefined,
        detail: { method: input.method, sealedOrigin: input.sealedOrigin },
      });
      return decision;
    }

    if (actor === "agent" && this.blockedCommandMethods.has(input.method)) {
      return {
        allowed: false,
        code: "method-blocked",
        reason: `CDP method ${input.method} denied by policy`,
      };
    }

    return { allowed: true, code: "ok", reason: "command permitted" };
  }

  evaluateStorage(input: {
    readonly operation: "read" | "write" | "clear";
    readonly storageKind: "localStorage" | "sessionStorage" | "indexedDB" | "cookie";
    readonly origin: string;
    readonly sealedOrigin?: string | null;
    readonly actorRole?: DispatchActorRole;
  }): PolicyDecision {
    const strict = normalizeStrictOrigin(input.origin);
    if (!strict && input.storageKind !== "cookie") {
      return {
        allowed: false,
        code: "opaque-origin-storage-denied",
        reason: `Storage ${input.storageKind} unavailable for opaque origin`,
      };
    }
    if (
      strict &&
      input.sealedOrigin &&
      (input.actorRole ?? "agent") === "agent" &&
      strict !== input.sealedOrigin
    ) {
      return {
        allowed: false,
        code: "sealed-target-blocked",
        reason: `Sealed origin ${input.sealedOrigin} forbids agent storage ${input.operation} on ${strict}`,
      };
    }
    if (strict && this.allowedOrigins && !this.allowedOrigins.has(strict)) {
      return {
        allowed: false,
        code: "origin-denied",
        reason: `Storage origin ${strict} not in allowedOrigins`,
      };
    }
    return { allowed: true, code: "ok", reason: "storage permitted" };
  }

  evaluateEgress(input: {
    readonly url: string | URL;
    readonly method?: string;
    readonly isTopLevelNavigation: boolean;
    readonly sealedOrigin?: string | null;
    readonly sessionId?: SessionId;
    readonly targetId?: TargetId;
  }): PolicyDecision {
    const actualMethod = (input.method ?? "GET").trim().toUpperCase();
    const parsed = typeof input.url === "string" ? new URL(input.url) : input.url;
    const strictOrigin = parsed.origin === "null" ? null : parsed.origin;
    const hostname = parsed.hostname.toLowerCase();

    if (input.isTopLevelNavigation && !this.allowTopLevelNavigation) {
      return {
        allowed: false,
        code: "top-level-navigation-denied",
        reason: "Top-level navigation forbidden by policy",
      };
    }
    if (input.isTopLevelNavigation && this.blockedTopLevelNavigationMethods.has(actualMethod)) {
      return {
        allowed: false,
        code: "top-level-navigation-denied",
        reason: `Top-level navigation method ${actualMethod} forbidden by policy`,
      };
    }
    if (this.blockedEgressMethods.has(actualMethod)) {
      return {
        allowed: false,
        code: "method-blocked",
        reason: `HTTP method ${actualMethod} forbidden by policy`,
      };
    }
    if (this.blockedHostnames.has(hostname)) {
      return {
        allowed: false,
        code: "origin-denied",
        reason: `Host ${hostname} denied by egress policy`,
      };
    }
    if (this.allowedOrigins && (!strictOrigin || !this.allowedOrigins.has(strictOrigin))) {
      return {
        allowed: false,
        code: "origin-denied",
        reason: `Origin ${strictOrigin ?? "null"} not in allowedOrigins`,
      };
    }

    if (input.sealedOrigin) {
      const sameOrigin = strictOrigin !== null && strictOrigin === input.sealedOrigin;
      const safeTopLevelGet =
        input.isTopLevelNavigation && (actualMethod === "GET" || actualMethod === "HEAD");
      if (!sameOrigin && !safeTopLevelGet) {
        const decision: PolicyDecision = {
          allowed: false,
          code: "sealed-target-blocked",
          reason:
            `A1 sealed origin ${input.sealedOrigin} forbids cross-origin ${actualMethod} egress` +
            ` to ${strictOrigin ?? parsed.href}`,
        };
        void this.auditLog?.append({
          kind: "policy.egress.sealed_blocked",
          sessionId: input.sessionId,
          targetId: input.targetId,
          detail: { method: actualMethod, url: parsed.href, sealedOrigin: input.sealedOrigin },
        });
        return decision;
      }
    }

    return { allowed: true, code: "ok", reason: "egress permitted" };
  }

  /** Redact authorization and cookie headers ONLY when delegatedAgent is true. */
  redactHeadersForAgent<T extends Record<string, string>>(headers: T): Record<string, string> {
    if (!this.delegatedAgent) {
      return { ...headers };
    }
    const out: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
      out[name] = SENSITIVE_HEADER_NAMES.has(name.toLowerCase()) ? "[REDACTED]" : value;
    }
    return out;
  }
}
