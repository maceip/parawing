// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, expect, it, vi } from "vitest";

// The frame isolate wasm is read from /bundle, which unit-test workers omit.
vi.mock("node:fs", () => ({
  default: {
    readdirSync: () => ["parawing_core_bg.wasm"],
    readFileSync: () => new Uint8Array(8),
  },
}));

import { SANDBOX_ALLOW_ALL } from "@parawing/script-gate";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import { createWorkersIsolateLoader } from "../src/workers-isolate-loader.ts";
import type { HostIsolateLoader, IsolateLoadSpec } from "../src/isolate-loader.ts";
import { spawnFramePageScript } from "../src/eval/page-script.ts";
import { createSandboxOutboundOverride } from "../src/eval/outbound.ts";
import {
  handleCdpSession,
  type CdpSessionCloseEvent,
  type CdpSessionTransport,
} from "../src/cdp/connection.ts";

describe("createMemoryHostCapabilities", () => {
  it("provides host-neutral defaults with literal undefined tracer", async () => {
    const host = createMemoryHostCapabilities();
    expect(host.tracer).toBeUndefined();
    expect(host.limits).toEqual({ pageCpuMsCap: null, pageWallMsCap: null });
    expect(host.config.environment).toBe("");
    const res = await host.assets.fetch(new Request("https://assets.local/font.woff2"));
    expect(res.status).toBe(404);
    expect(typeof host.clock.now()).toBe("number");
  });
});

describe("createWorkersIsolateLoader", () => {
  it("wires ctx.exports bindings, workerCompat overrides, and isolate termination", async () => {
    const loadedCodes: WorkerLoaderWorkerCode[] = [];
    const kills: string[] = [];
    let disposed = 0;
    const stubEntrypoint = {
      killIsolate: vi.fn(async (reason?: string) => {
        kills.push(reason ?? "");
      }),
      [Symbol.dispose]: () => {
        disposed += 1;
      },
    };
    // oxlint-disable-next-line parawing/no-chained-type-assertions -- partial WorkerStub fixture.
    const stub = {
      fetch: async () => new Response("unused"),
      connect: () => {
        throw new Error("unused");
      },
      queue: async () => {},
      scheduled: async () => {},
      tail: async () => {},
      tailStream: async () => {
        throw new Error("unused");
      },
      getEntrypoint: () => stubEntrypoint,
    } as unknown as WorkerStub;

    const host = createMemoryHostCapabilities({
      config: {
        workerCompat: {
          compatibilityDate: "2026-06-01",
          compatibilityFlags: ["override_flag"],
        },
      },
    });

    // oxlint-disable-next-line parawing/no-chained-type-assertions -- partial Workers exports fixture.
    const exportsFixture = {
      SandboxOutbound: ({ props }: { props: unknown }) => ({ tag: "sandbox", props }),
      DeniedOutbound: () => ({ tag: "denied" }),
      PageScriptTail: ({ props }: { props: unknown }) => ({ tag: "tail", props }),
      AttributionTail: ({ props }: { props: unknown }) => ({ tag: "attr", props }),
      SpanSink: ({ props }: { props: unknown }) => ({ tag: "sink", props }),
    } as unknown as Cloudflare.Exports;

    const loader = createWorkersIsolateLoader(
      {
        LOADER: {
          get: () => {
            throw new Error("get unused");
          },
          load: (code) => {
            loadedCodes.push(code);
            return stub;
          },
        },
      },
      { exports: exportsFixture },
      host,
    );

    const loaded = loader.load<typeof stubEntrypoint>({
      kind: "page-renderer",
      compatibilityDate: "2025-01-01",
      compatibilityFlags: ["base_flag"],
      mainModule: "renderer.js",
      modules: { "renderer.js": "export default {};" },
      entrypoint: "RendererEntrypoint",
      outbound: { mode: "denied" },
      tail: { scriptName: "renderer-1", sessionId: "conn-1" },
      attributionHeaders: { "x-attr": "yes" },
      attributionScriptName: "parawing-page-renderer",
      spanSink: { kind: "renderer" },
    });

    expect(loaded.kind).toBe("page-renderer");
    expect(loadedCodes).toHaveLength(1);
    expect(loadedCodes[0]?.compatibilityDate).toBe("2026-06-01");
    expect(loadedCodes[0]?.compatibilityFlags).toEqual(["override_flag"]);
    expect(loadedCodes[0]?.env).toEqual({});
    expect(loadedCodes[0]?.tails).toHaveLength(2);

    await loaded.terminate("closed");
    await loaded.terminate("duplicate");
    expect(kills).toEqual(["closed"]);

    loaded[Symbol.dispose]();
    expect(disposed).toBe(1);
  });

  it("passes kind 'oopif-frame' when spawning an OOPIF frame isolate", () => {
    const specs: IsolateLoadSpec[] = [];
    const entrypoint = { openSession: () => new Promise(() => {}) };
    const isolateLoader: HostIsolateLoader = {
      load: ((spec: IsolateLoadSpec) => {
        specs.push(spec);
        return {
          kind: spec.kind,
          entrypoint,
          async terminate() {},
          [Symbol.dispose]() {},
        };
      }) as HostIsolateLoader["load"],
    };
    const host = createMemoryHostCapabilities();
    const sandboxOutbound = createSandboxOutboundOverride(host, {
      fetch: async () => new Response("ok"),
    });
    spawnFramePageScript(host, isolateLoader, {
      connectionId: "c1",
      targetId: "T1",
      frameId: "F1",
      frameLoaderId: "L1",
      frameUrl: "https://frame.test/",
      sandbox: SANDBOX_ALLOW_ALL,
      cookieKey: "c1",
      sandboxOutbound,
    });
    expect(specs).toHaveLength(1);
    expect(specs[0]?.kind).toBe("oopif-frame");
  });
});

describe("handleCdpSession", () => {
  it("runs a CDP session over a host-neutral transport without Workers globals", async () => {
    const outboundMessages: Array<Record<string, unknown>> = [];
    const messageHandlers: Array<(data: string | ArrayBuffer) => void> = [];
    const closeHandlers: Array<(ev: CdpSessionCloseEvent) => void> = [];
    let closedByEngine = false;

    const transport: CdpSessionTransport = {
      send(data) {
        outboundMessages.push(JSON.parse(data) as Record<string, unknown>);
      },
      close() {
        closedByEngine = true;
      },
      onMessage(handler) {
        messageHandlers.push(handler);
      },
      onClose(handler) {
        closeHandlers.push(handler);
      },
      onError() {},
    };

    const host = createMemoryHostCapabilities();
    const isolateLoader: HostIsolateLoader = {
      load: () => {
        throw new Error("no isolate should load for Browser.getVersion");
      },
    };

    const session = handleCdpSession(transport, {
      host,
      isolateLoader,
      connectionId: "neutral-1",
      connectionMode: "browser",
    });

    expect(session.connectionId).toBe("neutral-1");
    for (const h of messageHandlers) {
      h(JSON.stringify({ id: 1, method: "Browser.getVersion" }));
      h(JSON.stringify({ id: 2, method: "Target.createTarget", params: { url: "about:blank" } }));
    }

    await vi.waitFor(() => {
      expect(outboundMessages.some((m) => m.id === 1)).toBe(true);
      expect(outboundMessages.some((m) => m.id === 2)).toBe(true);
    });

    const versionReply = outboundMessages.find((m) => m.id === 1);
    expect(versionReply?.result).toBeDefined();

    for (const h of closeHandlers) h({ code: 1000, reason: "done", wasClean: true });
    await session.closed;
    expect(closedByEngine).toBe(false);
  });
});
