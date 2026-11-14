// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Rejects requests sent through the renderer's outbound binding with HTTP 403.

import { WorkerEntrypoint } from "cloudflare:workers";

export class DeniedOutbound extends WorkerEntrypoint {
  override async fetch(request: Request): Promise<Response> {
    console.warn(`[parawing-renderer] outbound denied: ${request.url}`);
    return new Response("parawing: renderer egress denied", {
      status: 403,
      headers: {
        "x-parawing-blocked": "renderer-no-egress",
        "content-type": "text/plain;charset=utf-8",
      },
    });
  }
}
