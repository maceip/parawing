// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Per-connection security policy and A1 sealed-origin registry shared with SandboxOutbound. */

import type { PolicyEngine } from "../policy/policy-engine.ts";

interface ConnectionSecurityEntry {
  policyEngine?: PolicyEngine;
  readonly sealedOriginByFrameOrPage: Map<string, string>;
}

const registry = new Map<string, ConnectionSecurityEntry>();

function ensureEntry(connectionId: string): ConnectionSecurityEntry {
  let entry = registry.get(connectionId);
  if (!entry) {
    entry = { sealedOriginByFrameOrPage: new Map() };
    registry.set(connectionId, entry);
  }
  return entry;
}

export function registerConnectionPolicy(connectionId: string, policyEngine: PolicyEngine): void {
  if (!connectionId) return;
  ensureEntry(connectionId).policyEngine = policyEngine;
}

export function getConnectionPolicy(connectionId: string): PolicyEngine | undefined {
  if (!connectionId) return undefined;
  return registry.get(connectionId)?.policyEngine;
}

export function setFrameSealedOrigin(
  connectionId: string,
  frameOrTargetKey: string,
  sealedOrigin: string | null,
): void {
  if (!connectionId || !frameOrTargetKey) return;
  const entry = ensureEntry(connectionId);
  if (sealedOrigin === null) {
    entry.sealedOriginByFrameOrPage.delete(frameOrTargetKey);
    return;
  }
  entry.sealedOriginByFrameOrPage.set(frameOrTargetKey, sealedOrigin);
}

export function getFrameSealedOrigin(
  connectionId: string,
  frameId: string,
  pageOrigin?: string,
): string | null {
  if (!connectionId) return null;
  const entry = registry.get(connectionId);
  if (!entry) return null;
  if (frameId && entry.sealedOriginByFrameOrPage.has(frameId)) {
    return entry.sealedOriginByFrameOrPage.get(frameId) ?? null;
  }
  if (pageOrigin && entry.sealedOriginByFrameOrPage.has(pageOrigin)) {
    return entry.sealedOriginByFrameOrPage.get(pageOrigin) ?? null;
  }
  return null;
}

export function unregisterConnectionSecurity(connectionId: string): void {
  if (!connectionId) return;
  registry.delete(connectionId);
}
