// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Minimal host egress enforcing URL schemes, private-network blocking, and deadlines.

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { LookupAddress } from "node:dns";
import type { ExternalOutbound } from "@parawing/engine/external-outbound";
import { addressSpaceOf } from "../dist/engine-bundle.mjs";

export interface MinimalOutboundOptions {
  allowPrivateNetwork?: boolean;
  deadlineMs?: number;
  fetchFn?: typeof globalThis.fetch;
  lookupFn?: (hostname: string) => Promise<readonly LookupAddress[]>;
}

type DuplexRequestInit = RequestInit & { duplex?: "half" };

const DEFAULT_DEADLINE_MS = 15_000;

function cancelStream(stream: ReadableStream<Uint8Array> | null): void {
  if (stream) void stream.cancel().catch(() => {});
}

function blockedResponse(reason: string, message: string): Response {
  return new Response(message, {
    status: 403,
    headers: {
      "x-parawing-blocked": reason,
      "content-type": "text/plain;charset=utf-8",
    },
  });
}

function ipAddressSpaceIsPublic(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return false;
  try {
    const normalized = family === 6 ? `http://[${address}]` : `http://${address}`;
    return addressSpaceOf(new URL(normalized)) === "public";
  } catch {
    return false;
  }
}

async function checkTargetPublic(
  url: URL,
  lookupFn: (hostname: string) => Promise<readonly LookupAddress[]>,
): Promise<string | null> {
  if (addressSpaceOf(url) !== "public") {
    return `parawing: blocked private or loopback host ${url.hostname}`;
  }
  const host = url.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (isIP(host) !== 0) return null;

  // Resolve hostnames up front to catch CNAME/A/AAAA answers pointing into private ranges.
  let addresses: readonly LookupAddress[];
  try {
    addresses = await lookupFn(host);
  } catch {
    return `parawing: DNS lookup failed for ${url.hostname}`;
  }
  if (addresses.length === 0) {
    return `parawing: DNS returned no addresses for ${url.hostname}`;
  }
  for (const entry of addresses) {
    if (!ipAddressSpaceIsPublic(entry.address)) {
      return `parawing: ${url.hostname} resolved to non-public address ${entry.address}`;
    }
  }
  return null;
}

export function createMinimalOutbound(options: MinimalOutboundOptions = {}): ExternalOutbound {
  const allowPrivateNetwork = options.allowPrivateNetwork ?? false;
  const deadlineMs = options.deadlineMs ?? DEFAULT_DEADLINE_MS;
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const lookupFn =
    options.lookupFn ??
    ((hostname: string): Promise<LookupAddress[]> => lookup(hostname, { all: true }));

  return {
    async fetch(request: Request): Promise<Response> {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        cancelStream(request.body);
        return blockedResponse("invalid-url", "parawing: invalid outbound URL");
      }

      if (url.protocol !== "http:" && url.protocol !== "https:") {
        cancelStream(request.body);
        return blockedResponse(
          "unsupported-scheme",
          `parawing: unsupported scheme ${url.protocol}`,
        );
      }

      if (!allowPrivateNetwork) {
        const denial = await checkTargetPublic(url, lookupFn);
        if (denial !== null) {
          cancelStream(request.body);
          return blockedResponse("private-network", denial);
        }
      }

      const timeoutSig = AbortSignal.timeout(deadlineMs);
      const signal = request.signal ? AbortSignal.any([request.signal, timeoutSig]) : timeoutSig;
      const init: DuplexRequestInit = {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: "manual",
        signal,
      };
      if (request.body !== null) {
        init.duplex = "half";
      }

      try {
        return await fetchFn(new Request(url.toString(), init));
      } catch (err) {
        cancelStream(request.body);
        throw err;
      }
    },
  };
}
