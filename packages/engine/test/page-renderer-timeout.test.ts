// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../src/eval/page-script.ts", () => ({
  loadWasmBytesFromVfs: () => new Uint8Array(0),
}));

import type { RenderPortStub } from "@parawing/jsrpc-types/page-renderer";
import { PageRendererManager } from "../src/eval/page-renderer.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import type { HostIsolateLoader, IsolateLoadSpec } from "../src/isolate-loader.ts";

function harness(
  renderFrame: () => Promise<unknown>,
  getRenderPort: () => Promise<RenderPortStub> = async () => ({}) as RenderPortStub,
) {
  const counts = { loads: 0, kills: 0 };
  const stub = { renderFrame };
  const isolateLoader: HostIsolateLoader = {
    load: ((spec: IsolateLoadSpec) => {
      counts.loads += 1;
      return {
        kind: spec.kind,
        entrypoint: stub,
        async terminate() {
          counts.kills += 1;
        },
        [Symbol.dispose]() {},
      };
    }) as HostIsolateLoader["load"],
  };
  const host = createMemoryHostCapabilities({
    assets: {
      fetch: () => {
        throw new Error("harness: assets.fetch unused");
      },
    },
  });
  const manager = new PageRendererManager(host, isolateLoader, "test-connection");
  const source = { getRenderPort };
  const render = () =>
    manager.renderFrame(source, {
      format: "jpeg",
      quality: 80,
      omitBackground: false,
    });
  return { counts, render, manager };
}

describe("renderer retry policy", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not retry a renderFrame that never returns", async () => {
    const { counts, render } = harness(() => new Promise(() => {}));
    const p = render();
    await vi.advanceTimersByTimeAsync(40_000);
    const r = await p;
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/timeout/);
    expect(counts.kills).toBe(1);
    expect(counts.loads).toBe(1);
  });

  it("still retries a raster-stage failure reply", async () => {
    const { counts, render } = harness(async () => ({
      error: "boom",
      stage: "raster",
    }));
    const p = render();
    await vi.advanceTimersByTimeAsync(40_000);
    const r = await p;
    expect(r.ok).toBe(false);
    expect(counts.loads).toBe(2);
  });

  it("does not relaunch on a record-stage failure reply", async () => {
    const { counts, render } = harness(async () => ({
      error: "dying generation",
      stage: "record",
    }));
    const p = render();
    await vi.advanceTimersByTimeAsync(40_000);
    const r = await p;
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("record");
    expect(counts.loads).toBe(1);
    expect(counts.kills).toBe(0);
  });
});

describe("renderer eviction and close", () => {
  it("neither kills nor reloads a renderer the runtime evicted", async () => {
    const { counts, render } = harness(() =>
      Promise.reject(new Error("Too many dynamic workers.")),
    );
    const r = await render();
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/Too many dynamic workers/);
    expect(counts.loads, "a reload would evict another worker").toBe(1);
    expect(counts.kills, "a kill would start a fresh isolate").toBe(0);
  });

  it("loads no renderer when the page's render port cannot be minted", async () => {
    const { counts, render } = harness(
      async () => ({ bytes: new Uint8Array([1]) }),
      () => Promise.reject(new Error("PageScript session is dead (retired)")),
    );
    const r = await render();
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("record");
    expect(counts.loads).toBe(0);
  });

  it("fails a render queued after close instead of loading a renderer", async () => {
    const { counts, render, manager } = harness(async () => ({ bytes: new Uint8Array([1]) }));
    expect((await render()).ok).toBe(true);
    manager.close("connection closed");
    const r = await render();
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/closed/);
    expect(counts.loads).toBe(1);
    expect(counts.kills).toBe(1);
  });
});

describe("renderer memory stats", () => {
  it("reports what the renderer sent with its last frame, without calling it", async () => {
    const memory = { bytes: 3_000_000, initialBytes: 2_000_000, deltaBytes: 1_000_000 };
    const { counts, render, manager } = harness(async () => ({
      bytes: new Uint8Array([1]),
      memory,
    }));
    expect(manager.memoryStats()).toBeNull();
    expect((await render()).ok).toBe(true);
    manager.dispose("done");
    expect(manager.memoryStats(), "still known once the renderer is gone").toEqual(memory);
    expect(counts.loads).toBe(1);
  });
});
