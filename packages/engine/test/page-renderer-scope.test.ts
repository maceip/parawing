// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, expect, it, vi } from "vitest";

vi.mock("../src/eval/page-script.ts", () => ({
  loadWasmBytesFromVfs: () => new Uint8Array(0),
}));

import type { RenderFrameOpts, RenderPortStub } from "@parawing/jsrpc-types/page-renderer";
import { PageRendererManager } from "../src/eval/page-renderer.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import type { HostIsolateLoader, IsolateLoadSpec } from "../src/isolate-loader.ts";

// The renderer cache serves resources a page reports by hash, so a render RPC may only use the
// resources of the isolate that supplied it.
describe("renderer resource scope", () => {
  it("binds each render RPC to the supplying source", async () => {
    const scopes: Array<string | undefined> = [];
    const record = () => async (_port: RenderPortStub, opts: RenderFrameOpts) => {
      scopes.push(opts.scope);
      return { bytes: new Uint8Array([1]), seq: 1, scrollX: 0, scrollY: 0 };
    };
    const stub = { renderFrame: record(), renderPdf: record() };
    const isolateLoader: HostIsolateLoader = {
      load: ((spec: IsolateLoadSpec) => ({
        kind: spec.kind,
        entrypoint: stub,
        async terminate() {},
        [Symbol.dispose]() {},
      })) as HostIsolateLoader["load"],
    };
    const manager = new PageRendererManager(
      createMemoryHostCapabilities(),
      isolateLoader,
      "test-connection",
    );
    const source = () => ({ getRenderPort: async () => ({}) as RenderPortStub });
    const [a, b] = [source(), source()];
    const frame = { format: "jpeg", quality: 80, omitBackground: false };
    const pdf = {
      paperWidth: 8.5,
      paperHeight: 11,
      omitBackground: false,
      marginTop: 0,
      marginRight: 0,
      marginBottom: 0,
      marginLeft: 0,
    };
    const results = await Promise.all([
      manager.renderFrame(a, frame),
      manager.renderFrame(b, frame),
      manager.renderPdf(a, pdf),
      manager.renderFrame(a, frame),
    ]);
    expect(results.map((result) => result.ok)).toEqual([true, true, true, true]);
    const [aFrame, bFrame, aPdf, aFrameAgain] = scopes;
    expect(aFrame, "every render RPC carries a scope").toBeTruthy();
    expect(aPdf).toBe(aFrame);
    expect(aFrameAgain).toBe(aFrame);
    expect(bFrame).not.toBe(aFrame);
  });
});
