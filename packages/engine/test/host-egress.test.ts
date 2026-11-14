// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, it, expect } from "vitest";
import type { ExternalOutbound } from "../src/eval/external-outbound.ts";
import { createSandboxOutboundOverride } from "../src/eval/outbound.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";

const host = createMemoryHostCapabilities({
  assets: { fetch: async () => new Response(null, { status: 404 }) },
});

function recorder(name: string): ExternalOutbound & { seen: Request[] } {
  const seen: Request[] = [];
  return {
    seen,
    async fetch(request) {
      seen.push(request);
      return new Response(name, { headers: { "content-type": "text/plain" } });
    },
  };
}

describe("host egress", () => {
  it("carries the engine-shaped request for parent and final fetches", async () => {
    const egress = recorder("egress");
    const outbound = createSandboxOutboundOverride(host, undefined, egress);
    expect(outbound.external).toBe(false);

    const parent = outbound.parent({ pageOrigin: "https://page.example" });
    const resp = await parent.fetch(
      new Request("https://page.example/app.js", {
        headers: { "x-parawing-resource-type": "Script" },
      }),
    );
    expect(await resp.text()).toBe("egress");
    const [sent] = egress.seen;
    expect(sent?.url).toBe("https://page.example/app.js");
    expect(sent?.headers.get("x-parawing-resource-type")).toBeNull();
    expect(sent?.headers.get("user-agent")).toBeTruthy();

    await outbound.final(new Request("https://cdn.example/final"));
    expect(egress.seen.map((request) => request.url)).toContain("https://cdn.example/final");
  });

  it("yields to an external outbound", async () => {
    const egress = recorder("egress");
    const external = recorder("external");
    const outbound = createSandboxOutboundOverride(host, external, egress);
    expect(outbound.external).toBe(true);

    const resp = await outbound
      .parent({ pageOrigin: "https://page.example" })
      .fetch(new Request("https://page.example/app.js"));
    expect(await resp.text()).toBe("external");
    await outbound.final(new Request("https://cdn.example/final"));
    expect(egress.seen).toHaveLength(0);
    expect(external.seen).toHaveLength(2);
  });
});
