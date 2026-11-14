// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { expect, it, vi } from "vitest";

// The isolate's wasm is read from the bundle, which a unit test worker does not have.
vi.mock("node:fs", () => ({
  default: {
    readdirSync: () => ["parawing_core_bg.wasm"],
    readFileSync: () => new Uint8Array(8),
  },
}));
import type { CallerOutboundProps, SandboxOutboundOverride } from "../src/eval/outbound.ts";
import { createMemoryHostCapabilities } from "../src/host-capabilities.ts";
import type { HostIsolateLoader, IsolateLoadSpec } from "../src/isolate-loader.ts";
import { SANDBOX_ALLOW_ALL } from "@parawing/script-gate";
import { spawnFramePageScript } from "../src/eval/page-script.ts";

it("seals a frame isolate's outbound with its browser context's cookie jar", () => {
  const sealed: CallerOutboundProps[] = [];
  // oxlint-disable-next-line parawing/no-chained-type-assertions -- only the props capture is needed.
  const sandboxOutbound = {
    external: false,
    loadedProps: (props: CallerOutboundProps) => {
      sealed.push(props);
      return props;
    },
    session: (props: CallerOutboundProps) => {
      sealed.push(props);
      return async () => new Response(null);
    },
  } as unknown as SandboxOutboundOverride;
  const entrypoint = { openSession: () => new Promise(() => {}) };
  const isolateLoader: HostIsolateLoader = {
    load: ((spec: IsolateLoadSpec) => ({
      kind: spec.kind,
      entrypoint,
      async terminate() {},
      [Symbol.dispose]() {},
    })) as HostIsolateLoader["load"],
  };
  spawnFramePageScript(createMemoryHostCapabilities(), isolateLoader, {
    connectionId: "conn",
    targetId: "T",
    frameId: "F",
    frameLoaderId: "L",
    frameUrl: "https://frame.test/",
    sandbox: SANDBOX_ALLOW_ALL,
    cookieKey: "conn:context-1",
    sandboxOutbound,
  });
  expect(sealed.map((p) => p.cookieKey)).toEqual(["conn:context-1", "conn:context-1"]);
});
