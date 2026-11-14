// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

/** Nominal session-layer identity types and continuity errors. */

export type UserId = string & { readonly __brand: "UserId" };
export type SessionId = string & { readonly __brand: "SessionId" };
export type ConnectionId = string & { readonly __brand: "ConnectionId" };
export type TargetId = string & { readonly __brand: "TargetId" };

export type ConnectionRole = "owner" | "viewer";

function parseBrandedId(raw: string, label: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return trimmed;
}

export function asUserId(raw: string): UserId {
  return parseBrandedId(raw, "UserId") as UserId;
}

export function asSessionId(raw: string): SessionId {
  return parseBrandedId(raw, "SessionId") as SessionId;
}

export function asConnectionId(raw: string): ConnectionId {
  return parseBrandedId(raw, "ConnectionId") as ConnectionId;
}

export function asTargetId(raw: string): TargetId {
  return parseBrandedId(raw, "TargetId") as TargetId;
}

export class StaleEpochError extends Error {
  readonly sessionId: SessionId;
  readonly connectionId: ConnectionId;
  readonly expectedEpoch: number;
  readonly receivedEpoch: number;
  readonly role: ConnectionRole = "viewer";

  constructor(
    sessionId: SessionId,
    connectionId: ConnectionId,
    expectedEpoch: number,
    receivedEpoch: number,
  ) {
    super(
      `Stale epoch ${receivedEpoch} for session ${sessionId} on connection ${connectionId}` +
        ` (active epoch ${expectedEpoch}); connection demoted to viewer`,
    );
    this.name = "StaleEpochError";
    this.sessionId = sessionId;
    this.connectionId = connectionId;
    this.expectedEpoch = expectedEpoch;
    this.receivedEpoch = receivedEpoch;
  }
}

export class SessionNotFoundError extends Error {
  readonly sessionId: SessionId;

  constructor(sessionId: SessionId) {
    super(`Session not found: ${sessionId}`);
    this.name = "SessionNotFoundError";
    this.sessionId = sessionId;
  }
}

export class SessionDestroyedError extends Error {
  readonly sessionId: SessionId;

  constructor(sessionId: SessionId) {
    super(`Session already destroyed: ${sessionId}`);
    this.name = "SessionDestroyedError";
    this.sessionId = sessionId;
  }
}
